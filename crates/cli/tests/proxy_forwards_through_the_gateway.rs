//! `wirken run` serves the inference proxy from `proxy.json`: a client
//! with an issued token is forwarded to the upstream with the key the
//! vault holds for it, a key bound to another origin is not sent, and
//! the lane the calls are recorded on verifies and exports.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wirken_audit::{ProxyRefusal, SessionEvent, SessionId, SessionLog};
use wirken_gateway::proxy::{PROXY_TOKENS_FILE, ProxyTokenStore, TokenGrant};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-gateway-test-passphrase";
const PROVIDER_KEY: &str = "sk-upstream-key-0123456789abcdef";
const ANSWER: &str = r#"{"id":"c1","choices":[{"message":{"role":"assistant","content":"pong"}}],"usage":{"prompt_tokens":9,"completion_tokens":2}}"#;

/// A provider on a loopback port: keeps each request and answers with
/// [`ANSWER`].
fn provider() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(Vec::new()));
    let kept = got.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let kept = kept.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
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
                kept.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{ANSWER}",
                    ANSWER.len()
                );
            });
        }
    });
    (base, got)
}

fn wirken(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wirken"));
    command
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1");
    command
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn stop(mut gateway: Child) {
    // SAFETY: kill(2) on the child this test spawned and still holds.
    unsafe {
        libc::kill(gateway.id() as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while gateway.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// The lanes of a token's conversations, in the order each was
/// opened.
fn conversation_lanes(data: &Path, token_id: &str) -> Vec<String> {
    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let prefix = format!("proxy-{token_id}-");
    let mut lanes: Vec<(i64, String)> = log
        .list_session_ids()
        .unwrap()
        .into_iter()
        .filter(|id| id.starts_with(&prefix))
        .map(|id| {
            let handle = log.handle_for(SessionId::new(id.clone()));
            (log.get_since(&handle, 0).unwrap()[0].id, id)
        })
        .collect();
    lanes.sort();
    lanes.into_iter().map(|(_, id)| id).collect()
}

/// Start `wirken run` on `data` and wait until it is serving. Returns
/// it with what it printed.
fn start_gateway(data: &Path) -> (Child, Vec<String>) {
    let mut gateway = wirken(data)
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_LIVE_RELOAD_INTERVAL_S", "3600")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = gateway.stdout.take().unwrap();
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut output = Vec::new();
    while !output.iter().any(|l: &String| l.contains("Wirken running")) {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => output.push(line),
            Err(_) => {
                stop(gateway);
                panic!("gateway never came up:\n{}", output.join("\n"));
            }
        }
    }
    (gateway, output)
}

fn rows(data: &Path, session: &str) -> Vec<SessionEvent> {
    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let lane = log.handle_for(SessionId::new(session.to_string()));
    log.get_since(&lane, 0)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_holder_is_forwarded_with_the_vaults_key_and_the_lane_verifies_and_exports() {
    let (upstream, got) = provider();
    let (elsewhere, got_elsewhere) = provider();
    let data = tempfile::tempdir().unwrap();
    let data = data.path();
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
            "upstreams": {
                "main": {"provider": "custom", "base_url": upstream, "credential": "custom-api-key"},
                // The same key, named for an origin it is not stored for.
                "elsewhere": {"provider": "custom", "base_url": elsewhere, "credential": "custom-api-key"}
            }
        })
        .to_string(),
    )
    .unwrap();
    // The provider key, allowed to the first upstream's origin only.
    let mut add = wirken(data)
        .args([
            "credentials",
            "add",
            "custom-api-key",
            "--stdin",
            "--provider",
            "custom",
            "--base-url",
            &upstream,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(PROVIDER_KEY.as_bytes())
        .unwrap();
    assert!(add.wait().unwrap().success());

    let tokens = ProxyTokenStore::open(&data.join(PROXY_TOKENS_FILE)).unwrap();
    let issue = |name: &str, upstream: &str| {
        tokens
            .issue(&TokenGrant {
                name: name.into(),
                upstreams: vec![upstream.into()],
                ..Default::default()
            })
            .unwrap()
    };
    let (main, main_token) = issue("main-client", "main");
    let (other, other_token) = issue("other-client", "elsewhere");
    drop(tokens);

    let (gateway, output) = start_gateway(data);
    let listed = output.iter().any(|l| {
        l.contains(&format!(
            "Proxy: http://127.0.0.1:{proxy_port} (2 upstreams)"
        ))
    });

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{proxy_port}/v1/chat/completions");
    let body = r#"{"model":"m","messages":[{"role":"user","content":"ping"}]}"#;
    let ok = client
        .post(&url)
        .bearer_auth(&main_token)
        .body(body)
        .send()
        .await
        .unwrap();
    let ok_status = ok.status();
    let ok_text = ok.text().await.unwrap();
    let refused = client
        .post(&url)
        .bearer_auth(&other_token)
        .body(body)
        .send()
        .await
        .unwrap();
    let refused_status = refused.status();
    let refused_text = refused.text().await.unwrap();
    // Revoked from another process while the gateway runs: the next
    // request with the token is refused, with no restart.
    ProxyTokenStore::open(&data.join(PROXY_TOKENS_FILE))
        .unwrap()
        .revoke("main-client")
        .unwrap()
        .expect("a live token");
    let revoked = client
        .post(&url)
        .bearer_auth(&main_token)
        .body(body)
        .send()
        .await
        .unwrap();
    let revoked_status = revoked.status();
    stop(gateway);

    assert!(listed, "{output:?}");
    assert_eq!(revoked_status, 401);
    assert_eq!(ok_status, 200, "{ok_text}");
    assert_eq!(ok_text, ANSWER);
    let got = got.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert!(
        got[0]
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {PROVIDER_KEY}")),
        "{}",
        got[0]
    );
    assert!(got[0].ends_with(body));
    assert!(!got[0].contains(&main_token));

    // The key is stored for the first upstream's origin. The second
    // upstream names it and is not sent it, or anything.
    assert_eq!(refused_status, 502, "{refused_text}");
    assert!(
        refused_text.contains("credential_refused"),
        "{refused_text}"
    );
    assert!(got_elsewhere.lock().unwrap().is_empty());
    assert!(
        rows(data, &format!("proxy-{}", other.id))
            .iter()
            .any(|e| matches!(
                e,
                SessionEvent::ProxyRefused {
                    reason: ProxyRefusal::CredentialRefused,
                    ..
                }
            ))
    );

    // The forwarded call is on its conversation's lane; the refusal of
    // the revoked token is on the token's own.
    let lanes = conversation_lanes(data, &main.id);
    assert_eq!(lanes.len(), 1, "{lanes:?}");
    let lane = lanes[0].clone();
    assert!(
        rows(data, &format!("proxy-{}", main.id))
            .iter()
            .any(|e| matches!(
                e,
                SessionEvent::ProxyRefused {
                    reason: ProxyRefusal::RevokedToken,
                    ..
                }
            ))
    );
    let all = rows(data, &lane);
    // The lane's rows are covered by signed heads: one when it opens,
    // one when the gateway stops.
    let heads = all
        .iter()
        .filter(
            |e| matches!(e, SessionEvent::ChainHead { signature, .. } if !signature.0.is_empty()),
        )
        .count();
    assert!(heads >= 2, "{all:?}");
    let made: Vec<SessionEvent> = all
        .into_iter()
        .filter(|e| !matches!(e, SessionEvent::ChainHead { .. }))
        .collect();
    assert!(
        matches!(
            made.as_slice(),
            [
                SessionEvent::ProxyRequest { credential_id: Some(credential), .. },
                SessionEvent::ProxyResponse { status: 200, input_tokens: Some(9), output_tokens: Some(2), complete: true, .. },
                ..
            ] if credential == "custom-api-key"
        ),
        "{made:?}"
    );
    for file in ["audit.db", "audit.db-wal"] {
        if let Ok(bytes) = std::fs::read(data.join(file)) {
            for secret in [PROVIDER_KEY, main_token.rsplit('_').next().unwrap()] {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "{file} holds a key or a token"
                );
            }
        }
    }

    // With no archive configured the lane verifies from the chain
    // alone, and nothing is read from anywhere else.
    let verify = wirken(data)
        .args(["sessions", "verify", &lane])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&verify.stdout);
    assert_eq!(verify.status.code(), Some(0), "{text}");
    assert!(
        text.contains("calls: 1 forwarded, 1 answered, 0 refused"),
        "{text}"
    );
    assert!(text.contains("chain: OK"), "{text}");
    assert!(text.contains("archive: not configured"), "{text}");

    // The export is a valid trajectory. Without bodies the call is a
    // step with its metrics and hashes.
    let export = wirken(data)
        .args(["sessions", "export", &lane, "--format", "atif"])
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&export.stdout).unwrap();
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    assert_eq!(document["schema_version"], "ATIF-v1.8");
    assert_eq!(document["session_id"], lane.as_str());
    let steps = document["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["message"], "");
    assert_eq!(steps[0]["metrics"]["prompt_tokens"], 9);
    assert_eq!(steps[0]["extra"]["wirken"]["request_body"], "not_available");

    // A lane with no rows is not verified or exported.
    let empty = wirken(data)
        .args(["sessions", "verify", "proxy-00000000"])
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(4));
    let none = wirken(data)
        .args(["sessions", "export", "proxy-00000000", "--format", "atif"])
        .output()
        .unwrap();
    assert_eq!(none.status.code(), Some(4));
}

/// Where the test below finds an S3-compatible server with Object
/// Lock. Without the endpoint it passes without running, unless
/// [`REQUIRE_S3_ENV`] is `1`, as it is in the CI job that starts one.
const S3_ENDPOINT_ENV: &str = "WIRKEN_TEST_S3_ENDPOINT";
const S3_ACCESS_ENV: &str = "WIRKEN_TEST_S3_ACCESS_KEY";
const S3_SECRET_ENV: &str = "WIRKEN_TEST_S3_SECRET_KEY";
const REQUIRE_S3_ENV: &str = "WIRKEN_TEST_REQUIRE_S3";

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
        .expect("script, for a pseudo-terminal");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "wirken {args:?}: {text}");
    text
}

/// One token carries two unrelated conversations, with the archive on
/// a real bucket under Object Lock. Each conversation is its own
/// session: it verifies against the bucket and exports as its own
/// trajectory. Redacting one session makes every body of it
/// unreadable and leaves the other session as it was.
#[tokio::test(flavor = "multi_thread")]
async fn two_conversations_are_two_sessions_and_one_is_redacted_whole() {
    let Ok(endpoint) = std::env::var(S3_ENDPOINT_ENV) else {
        assert!(
            std::env::var(REQUIRE_S3_ENV).as_deref() != Ok("1"),
            "{REQUIRE_S3_ENV}=1 and {S3_ENDPOINT_ENV} names no server"
        );
        eprintln!("skipping: {S3_ENDPOINT_ENV} names no S3-compatible server");
        return;
    };
    let access = std::env::var(S3_ACCESS_ENV).expect(S3_ACCESS_ENV);
    let secret = std::env::var(S3_SECRET_ENV).expect(S3_SECRET_ENV);
    let s3_host = endpoint
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/').to_string())
        .unwrap();
    let bucket = format!("wirken-e2e-{}", uuid::Uuid::new_v4().simple());
    {
        let url = url::Url::parse(&format!("{endpoint}/{bucket}")).unwrap();
        let extra = [(
            "x-amz-bucket-object-lock-enabled".to_string(),
            "true".to_string(),
        )];
        let headers = wirken_agent::sigv4::sign_with_headers(
            &access,
            &secret,
            None,
            "us-east-1",
            "s3",
            "PUT",
            &url,
            b"",
            &extra,
        );
        let mut request = reqwest::Client::new().put(url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let created = request.send().await.unwrap();
        assert!(
            created.status().is_success(),
            "create bucket: {}",
            created.status()
        );
    }

    let (upstream, _) = provider();
    let data = tempfile::tempdir().unwrap();
    let data = data.path();
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
            "upstreams": {"main": {"provider": "custom", "base_url": upstream}},
            "archive": {
                "endpoint": endpoint,
                "bucket": bucket,
                "retention_days": 1,
                "credential": "proxy-archive-credentials"
            }
        })
        .to_string(),
    )
    .unwrap();
    let mut add = wirken(data)
        .args([
            "credentials",
            "add",
            "proxy-archive-credentials",
            "--stdin",
            "--host",
            &s3_host,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(format!("{access}:{secret}").as_bytes())
        .unwrap();
    assert!(add.wait().unwrap().success());

    let issued = at_terminal(
        data,
        &["proxy", "token", "issue", "shared", "--upstream", "main"],
    );
    let token = issued
        .split_whitespace()
        .find(|w| w.starts_with("wkp_"))
        .unwrap_or_else(|| panic!("no token in: {issued}"))
        .to_string();
    let token_id = token.split('_').nth(1).unwrap().to_string();

    let (gateway, output) = start_gateway(data);
    assert!(
        output
            .iter()
            .any(|l| l.contains(&format!("archive {bucket}"))),
        "{output:?}"
    );
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{proxy_port}/v1/chat/completions");
    let alpha_one =
        r#"{"model":"m","messages":[{"role":"user","content":"ALPHA-SECRET first question"}]}"#;
    let beta = r#"{"model":"m","messages":[{"role":"user","content":"BETA-TOPIC unrelated"}]}"#;
    let alpha_two = r#"{"model":"m","messages":[{"role":"user","content":"ALPHA-SECRET first question"},{"role":"assistant","content":"pong"},{"role":"user","content":"ALPHA-SECRET follow-up"}]}"#;
    for body in [alpha_one, beta, alpha_two] {
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), ANSWER);
    }
    stop(gateway);

    // Two conversations, two sessions.
    let lanes = conversation_lanes(data, &token_id);
    assert_eq!(lanes.len(), 2, "{lanes:?}");
    let (alpha, other) = (&lanes[0], &lanes[1]);
    let listing = wirken(data)
        .args(["proxy", "sessions", "--token", "shared"])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    assert!(
        listing.contains(alpha.as_str()) && listing.contains("2 calls"),
        "{listing}"
    );
    assert!(
        listing.contains(other.as_str()) && listing.contains("1 call "),
        "{listing}"
    );

    let verify = |lane: &str| -> (Option<i32>, String) {
        let out = wirken(data)
            .args(["sessions", "verify", lane])
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let export = |lane: &str| -> serde_json::Value {
        let out = wirken(data)
            .args(["sessions", "export", lane, "--format", "atif"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            wirken_audit::atif::validate(&document),
            Vec::<String>::new()
        );
        document
    };
    let said = |document: &serde_json::Value| -> Vec<String> {
        document["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                format!(
                    "{}:{}",
                    s["source"].as_str().unwrap(),
                    s["message"].as_str().unwrap()
                )
            })
            .collect()
    };

    // The answer is the same bytes for every call, so one response
    // object serves all three: four bodies named in the first session,
    // three objects behind them.
    let (code, text) = verify(alpha);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("4 named, 4 match their row, 0 redacted, 0 failed"),
        "{text}"
    );
    let (code, text) = verify(other);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("2 named, 2 match their row, 0 redacted, 0 failed"),
        "{text}"
    );

    // Each session is one trajectory holding its own conversation and
    // nothing of the other.
    assert_eq!(
        said(&export(alpha)),
        [
            "user:ALPHA-SECRET first question",
            "agent:pong",
            "user:ALPHA-SECRET follow-up",
            "agent:pong",
        ]
    );
    assert_eq!(
        said(&export(other)),
        ["user:BETA-TOPIC unrelated", "agent:pong"]
    );

    // A search reads the archived bodies: the first session's question
    // is found in both of its requests, each cited by its row, and the
    // other session's in its own.
    let search = |text: &str| -> serde_json::Value {
        let out = wirken(data)
            .args(["sessions", "search", text, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let cited = |found: &serde_json::Value| -> Vec<(String, String)> {
        found["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h["session"].as_str().unwrap().to_string(),
                    h["found_in"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let found = search("alpha-secret");
    assert_eq!(found["archive"], "configured");
    assert_eq!(
        cited(&found),
        vec![
            (alpha.clone(), "request_body".to_string()),
            (alpha.clone(), "request_body".to_string()),
        ]
    );
    let hit = &found["hits"][0];
    let request_row = {
        let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
        log.get_since(&log.handle_for(SessionId::new(alpha.clone())), 0)
            .unwrap()
            .into_iter()
            .find(|r| r.seq == hit["seq"].as_u64().unwrap())
            .unwrap()
    };
    let SessionEvent::ProxyRequest { request_sha256, .. } = &request_row.event else {
        panic!("the hit cites a request row: {:?}", request_row.event);
    };
    assert_eq!(hit["body_sha256"], request_sha256.0);
    assert_eq!(hit["chain_hash"], request_row.hash.0);
    assert!(
        hit["snippet"]
            .as_str()
            .unwrap()
            .contains("ALPHA-SECRET first question")
    );
    assert_eq!(
        cited(&search("beta-topic")),
        vec![(other.clone(), "request_body".to_string())]
    );
    // The answer is in each call's response body, and in the request
    // that repeats it.
    let found = search("pong");
    let places: Vec<&str> = found["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["found_in"].as_str().unwrap())
        .collect();
    assert_eq!(places.iter().filter(|p| **p == "response_body").count(), 3);
    assert_eq!(places.iter().filter(|p| **p == "request_body").count(), 1);

    // The search kept text for each body it read, and none of it is
    // readable in the key store's files.
    let index_rows = |hash: Option<&str>| -> i64 {
        let db = rusqlite::Connection::open(data.join("proxy_archive_keys.db")).unwrap();
        match hash {
            Some(hash) => db
                .query_row(
                    "SELECT count(*) FROM body_text WHERE sha256 = ?1",
                    [hash],
                    |r| r.get(0),
                )
                .unwrap(),
            None => db
                .query_row("SELECT count(*) FROM body_text", [], |r| r.get(0))
                .unwrap(),
        }
    };
    let at_rest = |needle: &str| -> bool {
        std::fs::read_dir(data)
            .unwrap()
            .flatten()
            .filter(|f| {
                f.file_name()
                    .to_string_lossy()
                    .starts_with("proxy_archive_keys.db")
            })
            .any(|f| {
                std::fs::read(f.path())
                    .unwrap()
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
            })
    };
    assert_eq!(index_rows(None), 4, "three requests and one answer");
    assert_eq!(index_rows(Some(&request_sha256.0)), 1);
    for needle in ["ALPHA-SECRET", "BETA-TOPIC", "pong"] {
        assert!(!at_rest(needle), "{needle} is in the index in the clear");
    }

    // One command redacts every body of the first session.
    let redacted = at_terminal(
        data,
        &[
            "proxy",
            "archive",
            "redact",
            "--session",
            alpha,
            "--reason",
            "e2e",
        ],
    );
    assert!(redacted.contains("3 archived bodies"), "{redacted}");
    let (code, text) = verify(alpha);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("4 named, 0 match their row, 4 redacted, 0 failed"),
        "{text}"
    );
    // The redacted bodies are found by no search, and the index holds
    // no entry for them. The other session's request is still found.
    let found = search("alpha-secret");
    assert!(found["hits"].as_array().unwrap().is_empty(), "{found}");
    assert_eq!(found["bodies_unavailable"], 0);
    assert!(search("pong")["hits"].as_array().unwrap().is_empty());
    assert_eq!(index_rows(Some(&request_sha256.0)), 0);
    assert_eq!(index_rows(None), 1, "the other session's request");
    assert!(!at_rest("ALPHA-SECRET"));
    assert_eq!(
        cited(&search("beta-topic")),
        vec![(other.clone(), "request_body".to_string())]
    );

    let after = export(alpha);
    assert!(!after.to_string().contains("ALPHA-SECRET"), "{after}");
    assert_eq!(said(&after), ["agent:", "agent:"]);
    let redactions: Vec<SessionEvent> = rows(data, wirken_audit::PROXY_SESSION)
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                SessionEvent::ProxyArchiveRedacted { session: Some(session), reason, .. }
                    if session == alpha && reason == "e2e"
            )
        })
        .collect();
    assert_eq!(redactions.len(), 3, "{redactions:?}");

    // The other session keeps its own request. Its answer was the
    // same bytes as the redacted session's, the one object both rows
    // named, so that body is gone for it too.
    let (code, text) = verify(other);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("2 named, 1 match their row, 1 redacted, 0 failed"),
        "{text}"
    );
    assert_eq!(
        said(&export(other)),
        ["user:BETA-TOPIC unrelated", "agent:"]
    );
}
