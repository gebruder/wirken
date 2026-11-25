//! Live round trip of real clients through the inference proxy,
//! against a local model, with the archive on a local S3-compatible
//! server.
//!
//! Ignored by default: it needs a running Ollama with a model pulled,
//! an S3-compatible server with Object Lock on loopback, `curl`, and
//! `script` (for a pseudo-terminal, since tokens are issued and bodies
//! redacted at one).
//!
//! ```text
//! WIRKEN_LIVE_OLLAMA_MODEL=<a pulled model>
//! WIRKEN_TEST_S3_ENDPOINT=http://127.0.0.1:19000
//! WIRKEN_TEST_S3_ACCESS_KEY=...  WIRKEN_TEST_S3_SECRET_KEY=...
//! WIRKEN_LIVE_AGENT_CLI=<path>   optional: a coding-agent CLI that
//!                                speaks the Anthropic shape and takes
//!                                `-p <prompt> --model <model>`
//! cargo test -p wirken-cli --test proxy_live_round_trip -- --ignored --nocapture
//! ```
//!
//! `wirken run` serves the listener. `curl` sends an OpenAI-shaped
//! streamed call and an Anthropic-shaped call with the token as its
//! API key; the optional agent CLI is pointed at the listener by its
//! base-URL variable. Then the chain, the bucket, `sessions verify`,
//! `sessions export --format atif` and `proxy archive redact` are
//! checked against each other.
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use wirken_audit::{SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-live-round-trip-passphrase";

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
        .expect("script");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "wirken {args:?}: {text}");
    text
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn stop(mut gateway: common::KillOnDrop) {
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

fn curl(url: &str, headers: &[String], body: &str) -> Output {
    let mut command = Command::new("curl");
    command.args(["-sS", "-N", "--max-time", "300", "-X", "POST", url]);
    for header in headers {
        command.args(["-H", header]);
    }
    command.args(["-d", body]).output().expect("curl")
}

/// Create `bucket` with Object Lock on the test server.
async fn create_bucket(endpoint: &str, access: &str, secret: &str, bucket: &str) {
    let url = url::Url::parse(&format!("{endpoint}/{bucket}")).unwrap();
    let extra = [(
        "x-amz-bucket-object-lock-enabled".to_string(),
        "true".to_string(),
    )];
    let headers = wirken_agent::sigv4::sign_with_headers(
        access,
        secret,
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
    let response = request.send().await.unwrap();
    assert!(
        response.status().is_success(),
        "create bucket: {}",
        response.status()
    );
}

#[ignore = "live: needs Ollama with a model, an S3-compatible server with Object Lock, curl and script"]
#[tokio::test(flavor = "multi_thread")]
async fn real_clients_go_through_the_proxy_and_the_archive_matches_the_chain() {
    let model = std::env::var("WIRKEN_LIVE_OLLAMA_MODEL").expect("WIRKEN_LIVE_OLLAMA_MODEL");
    let endpoint = std::env::var("WIRKEN_TEST_S3_ENDPOINT").expect("WIRKEN_TEST_S3_ENDPOINT");
    let access = std::env::var("WIRKEN_TEST_S3_ACCESS_KEY").expect("WIRKEN_TEST_S3_ACCESS_KEY");
    let secret = std::env::var("WIRKEN_TEST_S3_SECRET_KEY").expect("WIRKEN_TEST_S3_SECRET_KEY");
    let s3_host = endpoint
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/').to_string())
        .unwrap();
    let bucket = format!("wirken-live-{}", uuid::Uuid::new_v4().simple());
    create_bucket(&endpoint, &access, &secret, &bucket).await;

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
                "local": {"provider": "ollama", "base_url": "http://localhost:11434/v1"}
            },
            "archive": {
                "endpoint": endpoint,
                "bucket": bucket,
                "prefix": "live/",
                "retention_days": 1,
                "credential": "proxy-archive-credentials"
            }
        })
        .to_string(),
    )
    .unwrap();

    // The bucket credentials, bound to the bucket's host.
    let mut add = wirken(data)
        .args([
            "credentials",
            "add",
            "proxy-archive-credentials",
            "--stdin",
            "--archive",
            &s3_host,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(format!("{access}:{secret}").as_bytes())
        .unwrap();
    assert!(add.wait().unwrap().success());

    // A token, issued the way an operator issues one. A call ceiling
    // keeps a runaway client bounded.
    let issued = at_terminal(
        data,
        &[
            "proxy",
            "token",
            "issue",
            "live-client",
            "--upstream",
            "local",
            "--model",
            &model,
            "--ceiling-calls",
            "40",
        ],
    );
    let token = issued
        .split_whitespace()
        .find(|w| w.starts_with("wkp_"))
        .unwrap_or_else(|| panic!("no token in: {issued}"))
        .to_string();
    let token_id = token.split('_').nth(1).unwrap().to_string();
    let lane = format!("proxy-{token_id}");

    let mut gateway = common::KillOnDrop(
        wirken(data)
            .args(["run", "--port", &free_port().to_string()])
            .env("WIRKEN_LIVE_RELOAD_INTERVAL_S", "3600")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = gateway.stdout.take().unwrap();
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(120);
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
    assert!(
        output
            .iter()
            .any(|l| l.contains(&format!("Proxy: http://127.0.0.1:{proxy_port}"))),
        "{output:?}"
    );
    let base = format!("http://127.0.0.1:{proxy_port}");

    // 1. An OpenAI-shaped streamed call, the token as the bearer key.
    let marker = "wirken-live-marker-7f3a";
    let chat_body = serde_json::json!({
        "model": model,
        "stream": true,
        "stream_options": {"include_usage": true},
        "messages": [{"role": "user", "content": format!("Reply with one short sentence. ({marker})")}]
    })
    .to_string();
    let chat = curl(
        &format!("{base}/v1/chat/completions"),
        &[
            format!("Authorization: Bearer {token}"),
            "Content-Type: application/json".into(),
        ],
        &chat_body,
    );
    let chat_text = String::from_utf8_lossy(&chat.stdout).into_owned();
    assert!(
        chat.status.success() && chat_text.contains("data: "),
        "{chat_text}"
    );

    // 2. An Anthropic-shaped call, the token as x-api-key, on a lane
    //    of its own.
    let messages_body = serde_json::json!({
        "model": model,
        "max_tokens": 200,
        "messages": [{"role": "user", "content": "Name one prime number."}]
    })
    .to_string();
    let messages = curl(
        &format!("{base}/v1/messages"),
        &[
            format!("x-api-key: {token}"),
            "anthropic-version: 2023-06-01".into(),
            "content-type: application/json".into(),
            "x-wirken-session: anthropic-shape".into(),
        ],
        &messages_body,
    );
    let messages_text = String::from_utf8_lossy(&messages.stdout).into_owned();
    assert!(
        messages_text.contains("\"type\":\"message\""),
        "{messages_text}"
    );

    // 3. Refusals: a model the token does not allow, and no token.
    let refused = curl(
        &format!("{base}/v1/chat/completions"),
        &[format!("Authorization: Bearer {token}")],
        r#"{"model":"some-other-model","messages":[]}"#,
    );
    assert!(String::from_utf8_lossy(&refused.stdout).contains("model_not_allowed"));
    let stranger = curl(
        &format!("{base}/v1/chat/completions"),
        &["Authorization: Bearer sk-not-a-wirken-token".into()],
        r#"{"model":"m","messages":[]}"#,
    );
    assert!(String::from_utf8_lossy(&stranger.stdout).contains("unknown_token"));

    // 4. Optionally, a coding-agent CLI pointed at the listener.
    let agent_cli = std::env::var("WIRKEN_LIVE_AGENT_CLI").ok();
    if let Some(cli) = &agent_cli {
        let home = tempfile::tempdir().unwrap();
        let out = Command::new("timeout")
            .args([
                "600",
                cli,
                "-p",
                "Reply with the single word: pong",
                "--model",
                &model,
            ])
            .env("ANTHROPIC_BASE_URL", &base)
            .env("ANTHROPIC_API_KEY", &token)
            .env("ANTHROPIC_CUSTOM_HEADERS", "x-wirken-session: agent-cli")
            .env("HOME", home.path())
            .env("DISABLE_TELEMETRY", "1")
            .current_dir(home.path())
            .stdin(Stdio::null())
            .output()
            .expect("agent cli");
        eprintln!(
            "agent cli: exit={:?} stdout={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout)
                .chars()
                .take(300)
                .collect::<String>(),
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>(),
        );
    }

    stop(gateway);

    // The chain: each call a request row and a response row with the
    // hash of the body as exchanged, both archived.
    // The first call had no session label: its conversation has a
    // lane of its own, named by the proxy. Refusals are on the token's.
    let token_lane = lane.clone();
    let lane = {
        let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
        let prefix = format!("{token_lane}-c");
        log.list_session_ids()
            .unwrap()
            .into_iter()
            .find(|id| id.starts_with(&prefix) && id.len() == prefix.len() + 12)
            .expect("the conversation's lane")
    };
    let anthropic_lane = format!("{token_lane}-anthropic-shape");
    let agent_lane = format!("{token_lane}-agent-cli");
    let chat_rows = rows(data, &lane);
    let (request_sha, response_sha) = chat_rows
        .iter()
        .find_map(|e| match e {
            SessionEvent::ProxyRequest {
                request_id,
                token_id: id,
                provider,
                model: asked,
                stream,
                request_sha256,
                archived,
                ..
            } => {
                assert_eq!(
                    (id, provider.as_str(), asked),
                    (&token_id, "ollama", &model)
                );
                assert!(*stream && *archived);
                let answered = chat_rows.iter().find_map(|e| match e {
                    SessionEvent::ProxyResponse {
                        request_id: answered,
                        status,
                        response_sha256,
                        response_bytes,
                        complete,
                        archived,
                        input_tokens,
                        output_tokens,
                        ..
                    } if answered == request_id => {
                        assert_eq!(*status, 200);
                        assert!(*complete && *archived);
                        assert_eq!(*response_bytes, chat.stdout.len() as u64);
                        assert!(input_tokens.is_some() && output_tokens.is_some());
                        Some(response_sha256.0.clone())
                    }
                    _ => None,
                })?;
                Some((request_sha256.0.clone(), answered))
            }
            _ => None,
        })
        .expect("a forwarded and answered call");
    use sha2::{Digest, Sha256};
    let hex = |bytes: &[u8]| -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    assert_eq!(
        request_sha,
        hex(chat_body.as_bytes()),
        "the request as the client sent it"
    );
    assert_eq!(
        response_sha,
        hex(&chat.stdout),
        "the response as the client received it"
    );
    assert!(
        rows(data, &token_lane).iter().any(|e| matches!(
            e,
            SessionEvent::ProxyRefused {
                reason: wirken_audit::ProxyRefusal::ModelNotAllowed,
                ..
            }
        )),
        "{chat_rows:?}"
    );
    assert!(
        rows(data, wirken_audit::PROXY_SESSION)
            .iter()
            .any(|e| matches!(
                e,
                SessionEvent::ProxyRefused {
                    reason: wirken_audit::ProxyRefusal::UnknownToken,
                    ..
                }
            ))
    );
    assert!(rows(data, &anthropic_lane).iter().any(|e| matches!(
        e,
        SessionEvent::ProxyRequest {
            shape: wirken_audit::ProxyShape::AnthropicMessages,
            ..
        }
    )));
    // The token's issue is a row on the operator lane, without the
    // token.
    let operator =
        serde_json::to_string(&rows(data, wirken_audit::OPERATOR_COMMANDS_SESSION)).unwrap();
    assert!(operator.contains("proxy token issue") && operator.contains("live-client"));
    for file in ["audit.db", "audit.db-wal", "proxy_tokens.db"] {
        if let Ok(bytes) = std::fs::read(data.join(file)) {
            let secret = token.rsplit('_').next().unwrap().as_bytes();
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret),
                "{file} holds the token"
            );
        }
    }

    // sessions verify reads each archived body back and compares.
    let verify = |lane: &str, extra: &[&str]| -> (Option<i32>, String) {
        let out = wirken(data)
            .args(["sessions", "verify", lane])
            .args(extra)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (code, text) = verify(&lane, &[]);
    eprintln!("verify:\n{text}");
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("chain: OK"), "{text}");
    assert!(
        text.contains("2 named, 2 match their row, 0 redacted, 0 failed"),
        "{text}"
    );
    let (code, text) = verify(&lane, &["--skip-archive"]);
    assert_eq!(code, Some(0));
    assert!(text.contains("archive: skipped"), "{text}");

    // The export is a valid trajectory holding the conversation.
    let export = |lane: &str, file: &Path| -> serde_json::Value {
        let out = wirken(data)
            .args(["sessions", "export", lane, "--format", "atif", "--output"])
            .arg(file)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    };
    let out_dir = std::env::var("WIRKEN_LIVE_EXPORT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| data.to_path_buf());
    let document = export(&lane, &out_dir.join("proxied-openai.atif.json"));
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    assert_eq!(document["schema_version"], "ATIF-v1.8");
    let steps = document["steps"].as_array().unwrap();
    assert_eq!(steps[0]["source"], "user");
    assert!(steps[0]["message"].as_str().unwrap().contains(marker));
    assert_eq!(steps[1]["source"], "agent");
    assert_eq!(steps[1]["model_name"], model.as_str());
    assert!(steps[1]["metrics"]["prompt_tokens"].as_u64().unwrap() > 0);
    assert_eq!(
        steps[1]["extra"]["wirken"]["response_sha256"],
        response_sha.as_str()
    );
    let said = format!("{}{}", steps[1]["message"], steps[1]["reasoning_content"]);
    assert!(said.len() > 4, "the answer has no text: {}", steps[1]);
    let anthropic = export(
        &anthropic_lane,
        &out_dir.join("proxied-anthropic.atif.json"),
    );
    assert_eq!(
        wirken_audit::atif::validate(&anthropic),
        Vec::<String>::new()
    );
    assert_eq!(anthropic["steps"][0]["message"], "Name one prime number.");
    if agent_cli.is_some() {
        let made = rows(data, &agent_lane);
        eprintln!("agent cli rows: {}", made.len());
        if !made.is_empty() {
            let doc = export(&agent_lane, &out_dir.join("proxied-agent-cli.atif.json"));
            assert_eq!(wirken_audit::atif::validate(&doc), Vec::<String>::new());
            eprintln!(
                "agent cli steps: {}",
                doc["steps"].as_array().unwrap().len()
            );
        }
    }

    // Redacting the request body: its key is destroyed at a terminal,
    // the object stays locked, verify counts it as redacted, and the
    // export no longer has the prompt.
    let redacted = at_terminal(
        data,
        &[
            "proxy",
            "archive",
            "redact",
            &request_sha,
            "--reason",
            "live test",
        ],
    );
    assert!(redacted.contains("Destroyed 1 key"), "{redacted}");
    let (code, text) = verify(&lane, &[]);
    eprintln!("verify after redaction:\n{text}");
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("2 named, 1 match their row, 1 redacted, 0 failed"),
        "{text}"
    );
    let document = export(&lane, &data.join("after-redaction.json"));
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    let steps = document["steps"].as_array().unwrap();
    assert!(
        steps.iter().all(|s| s["source"] != "user"),
        "the redacted prompt is still a step"
    );
    let last = steps.last().unwrap();
    assert_eq!(last["extra"]["wirken"]["request_body"], "redacted");
    assert_eq!(last["extra"]["wirken"]["response_body"], "exported");

    // An answer can quote its prompt. Redacting the response as well
    // leaves the call as a step with its metrics and nothing said.
    at_terminal(
        data,
        &[
            "proxy",
            "archive",
            "redact",
            &response_sha,
            "--reason",
            "live test",
        ],
    );
    let (code, text) = verify(&lane, &[]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("2 named, 0 match their row, 2 redacted, 0 failed"),
        "{text}"
    );
    let document = export(&lane, &data.join("after-both.json"));
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    assert!(
        !document.to_string().contains(marker),
        "redacted text was exported"
    );
    let steps = document["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["message"], "");
    assert!(steps[0]["metrics"]["prompt_tokens"].as_u64().unwrap() > 0);
    assert!(
        rows(data, wirken_audit::PROXY_SESSION)
            .iter()
            .any(|e| matches!(
                e,
                SessionEvent::ProxyArchiveRedacted { sha256, reason, .. }
                    if sha256.0 == request_sha && reason == "live test"
            ))
    );
}
