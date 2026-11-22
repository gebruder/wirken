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

    let lane = format!("proxy-{}", main.id);
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
        text.contains("calls: 1 forwarded, 1 answered, 1 refused"),
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
