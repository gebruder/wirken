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
    let image = std::env::var("WIRKEN_TEST_OIDC_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    let realm = dir.join("realm.json");
    std::fs::write(
        &realm,
        serde_json::json!({
            "realm": "wirken", "enabled": true, "accessTokenLifespan": 300,
            "clients": [
                client("wirken-ok", AUDIENCE, "engineers", None),
                client("wirken-short", AUDIENCE, "engineers", Some(1)),
                client("wirken-other-audience", "another-service", "engineers", None),
                client("wirken-unmapped", AUDIENCE, "visitors", None),
            ],
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
