//! Live round trip of JWTs through the proxy listener, against a local
//! OpenID Connect provider.
//!
//! Ignored by default: it needs `docker`, the Keycloak image, `curl`
//! and `script` (for a pseudo-terminal, since the mapping is written
//! at one).
//!
//! ```text
//! WIRKEN_TEST_OIDC_IMAGE=<image>   optional; quay.io/keycloak/keycloak:26.8.2
//! cargo test -p wirken-cli --test proxy_oidc_live_round_trip -- --ignored --nocapture
//! ```
//!
//! Keycloak runs on loopback with a realm of four clients, each of
//! which gets its own access token by client credentials: one with the
//! audience and a mapped claim, one the same with a one-second
//! lifetime, one for another audience, and one whose claim and subject
//! are mapped to nothing. `wirken run` serves the listener with that
//! realm as its issuer and fetches its keys from the realm's discovery
//! document. `curl` presents each token as a client would. The chain,
//! `sessions verify` and the answers are checked against each other,
//! and then the provider is stopped and the gateway started again: with
//! no keys to be had, the token that was accepted is refused.
//!
//! A second realm carries the token exchange (RFC 8693): a client for
//! the person, one for the gateway allowed the standard token exchange,
//! and the downstream. An HTTP MCP server on loopback, signed with an
//! `exchange` block, records the bearer of each call. A call made at
//! the MCP endpoint with the person's token reaches it as the token
//! Keycloak exchanged that one for, and a token Wirken issued does not
//! reach it at all.
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wirken_audit::{PROXY_SESSION, ProxyRefusal, SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-oidc-live-round-trip-passphrase";
const DEFAULT_IMAGE: &str = "quay.io/keycloak/keycloak:26.8.2";
const AUDIENCE: &str = "wirken-proxy";
const BODY: &str = r#"{"model":"m","messages":[{"role":"user","content":"hello"}]}"#;

fn wirken(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wirken"));
    command
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1");
    command
}

/// Run `wirken <args>` at a pseudo-terminal, as an operator would.
fn at_terminal(data: &Path, args: &[&str]) -> String {
    let line = std::iter::once(env!("CARGO_BIN_EXE_wirken").to_string())
        .chain(args.iter().map(|a| format!("'{a}'")))
        .collect::<Vec<_>>()
        .join(" ");
    let out = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("script(1)");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn stop(mut gateway: common::KillOnDrop) {
    // SAFETY: `kill` takes a pid and a signal and touches no memory;
    // the pid is this test's own child, still unreaped.
    unsafe {
        libc::kill(gateway.id() as libc::pid_t, libc::SIGINT);
    }
    let _ = gateway.wait();
}

fn rows(data: &Path, session: &str) -> Vec<SessionEvent> {
    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let handle = log.handle_for(SessionId::new(session.to_string()));
    log.get_since(&handle, 0)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect()
}

fn lanes(data: &Path) -> Vec<String> {
    wirken_audit::SqliteSessionLog::open(&data.join("audit.db"))
        .unwrap()
        .list_session_ids()
        .unwrap()
}

/// An OpenAI-shaped provider that answers every request with the same
/// completion and counts them.
fn scripted_provider() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"id":"c1","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (port, calls)
}

/// A Keycloak container, removed when dropped.
struct Provider {
    name: String,
    port: u16,
}

impl Provider {
    fn issuer(&self) -> String {
        format!("http://127.0.0.1:{}/realms/wirken", self.port)
    }

    fn remove(&self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// An access token for `client`, by client credentials.
    fn token(&self, client: &str) -> String {
        let out = Command::new("curl")
            .args([
                "-sS",
                "-d",
                "grant_type=client_credentials",
                "-d",
                &format!("client_id={client}"),
                "-d",
                &format!("client_secret={client}-secret"),
                &format!("{}/protocol/openid-connect/token", self.issuer()),
            ])
            .output()
            .expect("curl");
        let answer: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
        answer["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("no access token for {client}: {answer}"))
            .to_string()
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.remove();
    }
}

/// One client of the realm: its audience, the value of its `team`
/// claim, and its token lifetime in seconds where it has its own.
fn client(id: &str, audience: &str, team: &str, lifespan: Option<u32>) -> serde_json::Value {
    let mut client = serde_json::json!({
        "clientId": id, "enabled": true, "publicClient": false,
        "secret": format!("{id}-secret"),
        "serviceAccountsEnabled": true, "standardFlowEnabled": false,
        "directAccessGrantsEnabled": false, "protocol": "openid-connect",
        "protocolMappers": [
            {"name": "audience", "protocol": "openid-connect",
             "protocolMapper": "oidc-audience-mapper",
             "config": {"included.custom.audience": audience,
                        "access.token.claim": "true", "id.token.claim": "false"}},
            {"name": "team", "protocol": "openid-connect",
             "protocolMapper": "oidc-hardcoded-claim-mapper",
             "config": {"claim.name": "team", "claim.value": team,
                        "jsonType.label": "String", "access.token.claim": "true",
                        "id.token.claim": "false", "userinfo.token.claim": "false"}},
        ],
    });
    if let Some(seconds) = lifespan {
        client["attributes"] = serde_json::json!({"access.token.lifespan": seconds.to_string()});
    }
    client
}

fn start_provider(dir: &Path) -> Provider {
    start_provider_with(
        dir,
        vec![
            client("wirken-ok", AUDIENCE, "engineers", None),
            client("wirken-short", AUDIENCE, "engineers", Some(1)),
            client(
                "wirken-other-audience",
                "another-service",
                "engineers",
                None,
            ),
            client("wirken-unmapped", AUDIENCE, "visitors", None),
        ],
    )
}

fn start_provider_with(dir: &Path, clients: Vec<serde_json::Value>) -> Provider {
    let image = std::env::var("WIRKEN_TEST_OIDC_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    let realm = dir.join("realm.json");
    std::fs::write(
        &realm,
        serde_json::json!({
            "realm": "wirken", "enabled": true, "accessTokenLifespan": 300,
            "clients": clients,
        })
        .to_string(),
    )
    .unwrap();
    // The container's user reads the file through the mount.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&realm, std::fs::Permissions::from_mode(0o644)).unwrap();

    let provider = Provider {
        name: format!("wirken-oidc-live-{}", std::process::id()),
        port: free_port(),
    };
    provider.remove();
    let started = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &provider.name,
            "-p",
            &format!("127.0.0.1:{}:8080", provider.port),
            "-v",
            &format!(
                "{}:/opt/keycloak/data/import/realm.json:ro",
                realm.display()
            ),
            &image,
            "start-dev",
            "--import-realm",
        ])
        .stdout(Stdio::null())
        .status()
        .expect("docker");
    assert!(started.success(), "docker run {image}");
    let discovery = format!("{}/.well-known/openid-configuration", provider.issuer());
    let up = Instant::now();
    loop {
        let answered = Command::new("curl")
            .args(["-fsS", "-o", "/dev/null", &discovery])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if answered {
            return provider;
        }
        assert!(
            up.elapsed() < Duration::from_secs(180),
            "the provider answers at {discovery}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// POST a chat completion with `token` as the bearer. Returns the
/// status and the answer.
fn post(base: &str, token: &str) -> (u16, serde_json::Value) {
    let out = Command::new("curl")
        .args([
            "-sS",
            "-w",
            "\n%{http_code}",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            BODY,
            &format!("{base}/v1/chat/completions"),
        ])
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').expect("a status line");
    (
        status.trim().parse().expect("a status"),
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    )
}

/// The claims of a JWT, read without checking anything: what the test
/// compares the rows with.
fn claims(jwt: &str) -> serde_json::Value {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1).expect("three parts");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}

fn start_gateway(data: &Path, proxy_port: u16) -> common::KillOnDrop {
    let gateway = common::KillOnDrop(
        wirken(data)
            .args(["run", "-p", &free_port().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let up = Instant::now();
    while TcpStream::connect(("127.0.0.1", proxy_port)).is_err() {
        assert!(up.elapsed() < Duration::from_secs(60), "the listener is up");
        std::thread::sleep(Duration::from_millis(200));
    }
    gateway
}

/// The refusals on the `gateway-proxy` lane, each with the identity on
/// its row.
fn refusals(data: &Path) -> Vec<(ProxyRefusal, Option<wirken_audit::ProxyIdentity>)> {
    rows(data, PROXY_SESSION)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::ProxyRefused {
                reason, identity, ..
            } => Some((reason, identity)),
            _ => None,
        })
        .collect()
}

#[test]
#[ignore = "live: needs docker, the Keycloak image, curl and script"]
fn jwts_of_a_local_provider_are_accepted_or_refused_each_for_its_reason() {
    // A short path: the gateway's sockets live under the data directory.
    let root = tempfile::Builder::new()
        .prefix("wko")
        .tempdir_in("/tmp")
        .unwrap();
    let data = root.path().join("d");
    let served = root.path().join("idp");
    for dir in [&data, &served] {
        std::fs::create_dir_all(dir).unwrap();
    }

    let provider = start_provider(&served);
    let issuer = provider.issuer();
    let (upstream_port, upstream_calls) = scripted_provider();
    let proxy_port = free_port();
    std::fs::write(
        data.join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("proxy.json"),
        serde_json::json!({
            "bind": format!("127.0.0.1:{proxy_port}"),
            "upstreams": {"scripted": {
                "provider": "ollama",
                "base_url": format!("http://127.0.0.1:{upstream_port}/v1"),
            }},
            "oidc": {
                "issuer": issuer,
                "audience": AUDIENCE,
                "grant_claim": "team",
                "max_token_lifetime_secs": 600,
                "clock_skew_secs": 1,
            },
        })
        .to_string(),
    )
    .unwrap();

    // The operator's mapping: the claim value `engineers` gets the
    // grant set of that name.
    let said = at_terminal(
        &data,
        &[
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--upstream",
            "scripted",
        ],
    );
    assert!(said.contains("Wrote grant set engineers"), "{said}");
    let said = at_terminal(
        &data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--claim-value",
            "engineers",
        ],
    );
    assert!(said.contains("Mapped claim engineers"), "{said}");

    let gateway = start_gateway(&data, proxy_port);
    let base = format!("http://127.0.0.1:{proxy_port}");
    let calls = || upstream_calls.load(std::sync::atomic::Ordering::SeqCst);

    // 1. Accepted: the audience is right and the claim is mapped.
    let accepted = provider.token("wirken-ok");
    let (status, answer) = post(&base, &accepted);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["choices"][0]["message"]["content"], "hi");
    assert_eq!(calls(), 1);

    let presented = claims(&accepted);
    let subject = presented["sub"].as_str().unwrap();
    let lane = lanes(&data)
        .into_iter()
        .find(|l| l.starts_with("proxy-u"))
        .expect("the subject's lane");
    // The signed heads the gateway writes on the lane aside.
    let recorded: Vec<SessionEvent> = rows(&data, &lane)
        .into_iter()
        .filter(|e| !matches!(e, SessionEvent::ChainHead { .. }))
        .collect();
    let [
        SessionEvent::ProxyRequest {
            token_id,
            token_name,
            identity,
            ..
        },
        SessionEvent::ProxyResponse {
            identity: answered,
            status: provider_status,
            ..
        },
    ] = recorded.as_slice()
    else {
        panic!("{recorded:?}");
    };
    assert_eq!(*provider_status, 200);
    assert_eq!(token_name, "engineers");
    let identity = identity.as_ref().expect("who called");
    assert_eq!(answered.as_ref(), Some(identity));
    assert_eq!(identity.issuer, issuer);
    assert_eq!(identity.grant_set.as_deref(), Some("engineers"));
    assert_eq!(identity.jti.as_deref(), presented["jti"].as_str());
    let hash = identity.subject_hash.as_deref().expect("a keyed hash");
    assert_eq!(hash.len(), 64);
    assert!(identity.subject.is_none());
    // The lane and the id are the subject's hash, not the subject.
    assert_eq!(token_id, &format!("u{}", &hash[..16]));
    assert!(lane.starts_with(&format!("proxy-{token_id}-")), "{lane}");

    // 2. Expired: a one-second token, presented after its time.
    let short = provider.token("wirken-short");
    std::thread::sleep(Duration::from_secs(4));
    let (status, answer) = post(&base, &short);
    assert_eq!(status, 401, "{answer}");
    assert_eq!(answer["error"]["code"], "jwt_expired");

    // 3. Another audience. A second apart: refusals of callers with
    //    no grants are recorded at most one a second.
    std::thread::sleep(Duration::from_millis(1200));
    let (status, answer) = post(&base, &provider.token("wirken-other-audience"));
    assert_eq!(status, 401, "{answer}");
    assert_eq!(answer["error"]["code"], "jwt_wrong_audience");

    // 4. Valid, and mapped to nothing.
    std::thread::sleep(Duration::from_millis(1200));
    let unmapped = provider.token("wirken-unmapped");
    let (status, answer) = post(&base, &unmapped);
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "jwt_no_grant");

    // None of the three was forwarded.
    assert_eq!(calls(), 1);

    let refused = refusals(&data);
    let reasons: Vec<ProxyRefusal> = refused.iter().map(|(reason, _)| *reason).collect();
    assert_eq!(
        reasons,
        [
            ProxyRefusal::JwtExpired,
            ProxyRefusal::JwtWrongAudience,
            ProxyRefusal::JwtNoGrant,
        ]
    );
    // A JWT that failed says nothing of who sent it; the one that was
    // verified and given nothing does.
    assert!(refused[0].1.is_none() && refused[1].1.is_none());
    let nobody = refused[2].1.as_ref().expect("whose it was");
    assert_eq!(nobody.issuer, issuer);
    assert_eq!(nobody.grant_set, None);
    assert_eq!(nobody.jti.as_deref(), claims(&unmapped)["jti"].as_str());
    assert_ne!(nobody.subject_hash.as_deref(), Some(hash));

    // No JWT, no part of one, and no subject is on any row.
    let unmapped_subject = claims(&unmapped)["sub"].as_str().unwrap().to_string();
    for lane in lanes(&data) {
        for row in rows(&data, &lane) {
            let text = serde_json::to_string(&row).unwrap();
            for token in [&accepted, &short, &unmapped] {
                for part in token.split('.') {
                    assert!(!text.contains(part), "a row holds part of a JWT: {text}");
                }
            }
            assert!(!text.contains(subject), "{text}");
            assert!(!text.contains(&unmapped_subject), "{text}");
        }
    }

    // The subject's chain verifies.
    stop(gateway);
    let verified = wirken(&data)
        .args(["sessions", "verify", &lane])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );

    // 5. The provider is gone and the gateway starts again with no
    //    keys: the token accepted above, still within its time, is
    //    refused, and nothing is forwarded.
    provider.remove();
    let gateway = start_gateway(&data, proxy_port);
    let (status, answer) = post(&base, &accepted);
    assert_eq!(status, 503, "{answer}");
    assert_eq!(answer["error"]["code"], "jwt_keys_unavailable");
    assert_eq!(calls(), 1);
    assert_eq!(
        refusals(&data).last().map(|(reason, _)| *reason),
        Some(ProxyRefusal::JwtKeysUnavailable)
    );
    stop(gateway);
}

/// The audience the gateway exchanges a caller's token for, and the
/// client it is at the provider to do so.
const DOWNSTREAM: &str = "downstream-api";
const EXCHANGE_CLIENT: &str = "wirken-exchange";
const TOOL: &str = "mcp_crm_lookup";

/// A client of the realm that the token exchange needs: the gateway's
/// own, allowed the standard token exchange and given the downstream as
/// an audience it may ask for, or the downstream itself.
fn exchange_clients() -> Vec<serde_json::Value> {
    let audience = |name: &str, to: &str| {
        serde_json::json!({
            "name": name, "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": to,
                       "access.token.claim": "true", "id.token.claim": "false"},
        })
    };
    // The person's client: its tokens are for the proxy and name the
    // gateway's exchange client as an audience too, which the
    // provider asks of a subject token it exchanges.
    let mut person = client("wirken-person", AUDIENCE, "engineers", None);
    person["protocolMappers"]
        .as_array_mut()
        .unwrap()
        .push(audience("exchanger", EXCHANGE_CLIENT));
    vec![
        person,
        serde_json::json!({
            "clientId": EXCHANGE_CLIENT, "enabled": true, "publicClient": false,
            "secret": "exchange-secret", "serviceAccountsEnabled": false,
            "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
            "protocol": "openid-connect",
            "attributes": {"standard.token.exchange.enabled": "true"},
            "protocolMappers": [audience("downstream", DOWNSTREAM)],
        }),
        serde_json::json!({
            "clientId": DOWNSTREAM, "enabled": true, "publicClient": false,
            "secret": "downstream-secret", "serviceAccountsEnabled": false,
            "standardFlowEnabled": false, "protocol": "openid-connect",
        }),
    ]
}

/// An HTTP MCP server on loopback with one tool, `lookup`. It answers
/// `initialize` and `tools/list` with no credential, as the proxy asks
/// them at start, and records the `Authorization` header of each
/// `tools/call`.
fn downstream_server() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = calls.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut raw = Vec::new();
            let mut buf = [0u8; 8192];
            let (head, body) = loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break (String::new(), String::new()),
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                }
                let text = String::from_utf8_lossy(&raw).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break (head.to_string(), body.to_string());
                    }
                }
            };
            let message: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let result = match message["method"].as_str().unwrap_or_default() {
                "initialize" => serde_json::json!({
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "crm", "version": "1"},
                }),
                "tools/list" => serde_json::json!({"tools": [{
                    "name": "lookup", "description": "Look a customer up",
                    "inputSchema": {"type": "object", "properties": {}},
                }]}),
                "tools/call" => {
                    let authorization = head.lines().find_map(|l| {
                        l.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                            .map(|(_, value)| value.trim().to_string())
                    });
                    recorded.lock().unwrap().push(authorization);
                    serde_json::json!({"content": [{"type": "text", "text": "customer 42"}]})
                }
                _ => serde_json::json!({}),
            };
            let answer = match message.get("id") {
                Some(id) => {
                    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
                }
                None => String::new(),
            };
            let status = if answer.is_empty() {
                "202 Accepted"
            } else {
                "200 OK"
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                )
                .as_bytes(),
            );
        }
    });
    (port, calls)
}

/// POST one JSON-RPC message to the MCP endpoint with `token`. Returns
/// the session id the answer carries and the answer.
fn mcp(
    base: &str,
    token: &str,
    session: Option<&str>,
    message: serde_json::Value,
) -> (Option<String>, serde_json::Value) {
    let mut args = vec![
        "-sS".to_string(),
        "-D".into(),
        "-".into(),
        "-H".into(),
        format!("Authorization: Bearer {token}"),
        "-H".into(),
        "Content-Type: application/json".into(),
        "-H".into(),
        "Accept: application/json, text/event-stream".into(),
        "-d".into(),
        message.to_string(),
    ];
    if let Some(session) = session {
        args.extend(["-H".into(), format!("Mcp-Session-Id: {session}")]);
    }
    args.push(format!("{base}/mcp"));
    let out = Command::new("curl").args(&args).output().expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let session = head.lines().find_map(|l| {
        l.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("mcp-session-id"))
            .map(|(_, value)| value.trim().to_string())
    });
    (
        session,
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    )
}

fn initialize(base: &str, token: &str) -> String {
    let (session, answer) = mcp(
        base,
        token,
        None,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "curl", "version": "0"}}}),
    );
    session.unwrap_or_else(|| panic!("no session: {answer}"))
}

/// Call the tool on `session`, approving it at the operator's terminal
/// when the gate asks.
fn call_approved(data: &Path, base: &str, token: &str, session: &str) -> serde_json::Value {
    let (base, token, session) = (base.to_string(), token.to_string(), session.to_string());
    let call = std::thread::spawn(move || {
        mcp(
            &base,
            &token,
            Some(&session),
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "crm_lookup", "arguments": {}}}),
        )
        .1
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while !call.is_finished() && Instant::now() < deadline {
        let out = wirken(data)
            .args(["permissions", "pending", "list"])
            .output()
            .unwrap();
        let listed = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(id) = listed
            .lines()
            .filter(|line| line.contains(TOOL))
            .find_map(|line| line.split_whitespace().next())
        {
            assert!(
                wirken(data)
                    .args(["permissions", "pending", "approve", id])
                    .stdout(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    call.join().unwrap()
}

/// A JWT of the local provider reaches an MCP server whose signed entry
/// asks for an exchange as a token the provider exchanged it for
/// (RFC 8693): the downstream sees the same subject, its own audience,
/// and the gateway's exchange client as the party it was issued to. The
/// exchange is one row; a second call uses the token held and writes
/// none. A token Wirken issued is refused for that server, and neither
/// token is on any row.
#[test]
#[ignore = "live: needs docker, the Keycloak image, curl and script"]
fn a_jwt_reaches_a_downstream_as_the_token_the_provider_exchanged_it_for() {
    let root = tempfile::Builder::new()
        .prefix("wkx")
        .tempdir_in("/tmp")
        .unwrap();
    let data = root.path().join("d");
    let served = root.path().join("idp");
    for dir in [&data, &served] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let provider = start_provider_with(&served, exchange_clients());
    let issuer = provider.issuer();
    let (downstream_port, downstream_calls) = downstream_server();
    let proxy_port = free_port();
    std::fs::write(
        data.join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("proxy.json"),
        serde_json::json!({
            "bind": format!("127.0.0.1:{proxy_port}"),
            // Inference is not used here; the listener needs somewhere
            // to forward to.
            "upstreams": {"unused": {"provider": "ollama", "base_url": "http://127.0.0.1:9/v1"}},
            "oidc": {
                "issuer": issuer,
                "audience": AUDIENCE,
                "grant_claim": "team",
                "max_token_lifetime_secs": 600,
                "exchange": {"client_id": EXCHANGE_CLIENT, "client_secret": "idp-exchange-secret"},
            },
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        data.join("mcp.json"),
        serde_json::json!({"servers": {"crm": {
            "transport": "http",
            "url": format!("http://127.0.0.1:{downstream_port}/mcp"),
            "exchange": {"audience": DOWNSTREAM},
        }}})
        .to_string(),
    )
    .unwrap();
    assert!(
        wirken(&data)
            .args(["mcp", "sign", "crm"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    // The exchange client's secret, for the provider's token endpoint
    // and nowhere else.
    let mut add = wirken(&data)
        .args([
            "credentials",
            "add",
            "idp-exchange-secret",
            "--stdin",
            "--token-exchange",
            &format!("127.0.0.1:{}", provider.port),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(b"exchange-secret\n")
        .unwrap();
    assert!(add.wait().unwrap().success());

    let said = at_terminal(
        &data,
        &[
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--mcp-server",
            "crm",
        ],
    );
    assert!(said.contains("Wrote grant set engineers"), "{said}");
    let said = at_terminal(
        &data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--claim-value",
            "engineers",
        ],
    );
    assert!(said.contains("Mapped claim engineers"), "{said}");
    let issued = at_terminal(
        &data,
        &["proxy", "token", "issue", "desk", "--mcp-server", "crm"],
    );
    let hand_issued = issued
        .split_whitespace()
        .find(|word| word.starts_with("wkp_"))
        .unwrap_or_else(|| panic!("no token in: {issued}"))
        .to_string();

    let gateway = start_gateway(&data, proxy_port);
    let base = format!("http://127.0.0.1:{proxy_port}");

    // 1. Two calls with the person's JWT, on one session.
    let person = provider.token("wirken-person");
    let session = initialize(&base, &person);
    for _ in 0..2 {
        let answer = call_approved(&data, &base, &person, &session);
        assert_eq!(answer["result"]["isError"], false, "{answer}");
        assert_eq!(
            answer["result"]["content"][0]["text"], "customer 42",
            "{answer}"
        );
    }
    let seen = downstream_calls.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    let exchanged = seen[0]
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))
        .expect("a bearer on the call")
        .to_string();
    assert_eq!(seen[1].as_deref(), seen[0].as_deref(), "the held token");
    assert_ne!(exchanged, person);
    let (theirs, ours) = (claims(&person), claims(&exchanged));
    assert_eq!(ours["iss"], issuer);
    assert_eq!(ours["sub"], theirs["sub"]);
    assert_eq!(ours["azp"], EXCHANGE_CLIENT);
    let audience = &ours["aud"];
    assert!(
        audience == DOWNSTREAM
            || audience
                .as_array()
                .is_some_and(|a| a.contains(&DOWNSTREAM.into())),
        "{ours}"
    );

    // 2. A token Wirken issued is refused for the server, and the
    //    downstream is not called.
    let desk = initialize(&base, &hand_issued);
    let (_, answer) = mcp(
        &base,
        &hand_issued,
        Some(&desk),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "crm_lookup", "arguments": {}}}),
    );
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("names no person")),
        "{answer}"
    );
    assert_eq!(downstream_calls.lock().unwrap().len(), 2);

    // The rows: one exchange, on the subject's lane, before the calls.
    let lane = lanes(&data)
        .into_iter()
        .find(|l| l.starts_with("proxy-u") && l.matches('-').count() >= 2)
        .expect("the subject's session lane");
    let recorded = rows(&data, &lane);
    let exchanges: Vec<&SessionEvent> = recorded
        .iter()
        .filter(|e| matches!(e, SessionEvent::ProxyTokenExchanged { .. }))
        .collect();
    let [
        SessionEvent::ProxyTokenExchanged {
            server,
            audience,
            identity,
            expires_at,
            ..
        },
    ] = exchanges[..]
    else {
        panic!("{recorded:?}");
    };
    assert_eq!((server.as_str(), audience.as_str()), ("crm", DOWNSTREAM));
    assert_eq!(identity.issuer, issuer);
    assert_eq!(identity.grant_set.as_deref(), Some("engineers"));
    assert_eq!(
        expires_at.as_second(),
        ours["exp"].as_i64().unwrap(),
        "the expiry the provider gave"
    );
    let calls = recorded
        .iter()
        .filter(|e| matches!(e, SessionEvent::ProxyToolCall { success: true, .. }))
        .count();
    assert_eq!(calls, 2);

    // Neither token, nor any part of one, nor the subject, is on a row.
    let subject = theirs["sub"].as_str().unwrap();
    for lane in lanes(&data) {
        for row in rows(&data, &lane) {
            let text = serde_json::to_string(&row).unwrap();
            for token in [&person, &exchanged, &hand_issued] {
                for part in token.split('.').filter(|p| p.len() > 8) {
                    assert!(!text.contains(part), "a row holds part of a token: {text}");
                }
            }
            assert!(!text.contains(subject), "{text}");
        }
    }

    stop(gateway);
    let verified = wirken(&data)
        .args(["sessions", "verify", &lane])
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&verified.stdout).into_owned();
    assert!(verified.status.success(), "{report}");
    assert!(report.contains("tokens exchanged: 1"), "{report}");
}
