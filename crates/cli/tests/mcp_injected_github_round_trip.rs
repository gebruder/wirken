//! Live round-trip through a signed GitHub MCP entry with an injected
//! credential, against the real service.
//!
//! Ignored by default: it needs a GitHub token, a private scratch
//! repository the token can open issues in, the server's image pulled,
//! and a statically linked `wirken` for the sidecar and the relay.
//!
//! ```text
//! WIRKEN_LIVE_GITHUB_TOKEN=...            a token for api.github.com
//! WIRKEN_LIVE_GITHUB_REPO=owner/name      a private scratch repository
//! WIRKEN_SIDECAR_BINARY=/path/to/wirken   a static build of this tree
//! WIRKEN_LIVE_SANDBOX_MODE=exec-only      or gvisor, to run under runsc
//! cargo test -p wirken-cli --test mcp_injected_github_round_trip -- --ignored --nocapture
//! ```
//!
//! `wirken run` starts the proxy, which starts the server in its
//! container under the loopback relay. The test calls three tools over
//! the proxy socket, as an agent does: a read, a read of a repository
//! that was renamed, and a write. Then it checks what the container
//! held, what the runtime reports of it, and what the chain recorded.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wirken_audit::{SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "injected-round-trip-passphrase";

/// GitHub MCP server v2.2.0, by digest.
const IMAGE: &str = "ghcr.io/github/github-mcp-server@sha256:040c4e99810076035eb1d9beb4b4a96fcf589c43cefed6ff51a46a553eb4e174";

fn wirken(data: &Path, args: &[&str], stdin: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(args)
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "wirken {args:?} failed");
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

#[ignore = "live: needs a GitHub token, a scratch repository, the server image and a static binary"]
#[tokio::test(flavor = "multi_thread")]
async fn an_injected_github_server_reads_follows_a_rename_and_writes() {
    let token = std::env::var("WIRKEN_LIVE_GITHUB_TOKEN").expect("WIRKEN_LIVE_GITHUB_TOKEN");
    let repo = std::env::var("WIRKEN_LIVE_GITHUB_REPO").expect("WIRKEN_LIVE_GITHUB_REPO");
    let (owner, name) = repo.split_once('/').expect("owner/name");
    let binary = std::env::var("WIRKEN_SIDECAR_BINARY").expect("WIRKEN_SIDECAR_BINARY");
    let mode = std::env::var("WIRKEN_LIVE_SANDBOX_MODE").unwrap_or_else(|_| "exec-only".into());
    let image = std::env::var("WIRKEN_LIVE_GITHUB_IMAGE").unwrap_or_else(|_| IMAGE.into());

    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    std::fs::write(
        data.path().join("sandbox.json"),
        serde_json::json!({"mode": mode, "sidecar_binary": binary}).to_string(),
    )
    .unwrap();
    // The signed-URL hosts are listed as they would be in use; nothing
    // here fetches one. `api.github.com` is listed to show that the
    // direct route stays closed even so.
    let mcp = serde_json::json!({ "servers": { "github": {
        "command": "/server/github-mcp-server",
        "args": ["stdio"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "vault:github-token"},
        "sandbox": {
            "image": image,
            "egress": {"hosts": ["api.github.com", "*.blob.core.windows.net"]},
            "inject": {
                "credential_env": "GITHUB_PERSONAL_ACCESS_TOKEN",
                "host": "api.github.com",
                "header": "Authorization",
                "scheme": "Bearer",
                "base_url_env": "GITHUB_HOST",
                "paths": [
                    {"from": "/api/v3/", "to": "/"},
                    {"from": "/api/graphql", "to": "/graphql"}
                ]
            }
        }
    }}});
    std::fs::write(data.path().join("mcp.json"), mcp.to_string()).unwrap();
    wirken(data.path(), &["mcp", "sign", "github"], "");
    wirken(
        data.path(),
        &[
            "credentials",
            "add",
            "github-token",
            "--stdin",
            "--mcp-server",
            "github",
        ],
        &token,
    );

    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("WIRKEN_LIVE_RELOAD_INTERVAL_S", "3600")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
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

    let identity = wirken_agent::AgentIdentity::load_from(
        "default",
        &wirken_agent::identity::identity_dir(data.path(), "default").join("identity.key"),
    )
    .unwrap();
    let mut client = wirken_agent::mcp::McpProxyClient::connect(
        &data.path().join("sockets").join("mcp-proxy.sock"),
        "default",
        &identity,
    )
    .await
    .unwrap();
    client.load_tools().await.unwrap();

    let me = client.execute("mcp_github_get_me", "{}").await.unwrap();
    let renamed = client
        .execute(
            "mcp_github_list_commits",
            r#"{"owner":"atom","repo":"electron","perPage":1}"#,
        )
        .await
        .unwrap();
    let written = client
        .execute(
            "mcp_github_issue_write",
            &serde_json::json!({
                "method": "create",
                "owner": owner,
                "repo": name,
                "title": format!("Injected round-trip under {mode}"),
            })
            .to_string(),
        )
        .await
        .unwrap();

    // While the server still runs: what its container holds, as the
    // runtime reports it.
    let started = rows(
        data.path(),
        wirken_mcp_proxy::mcp_registry::MCP_SENTINEL_SESSION,
    )
    .into_iter()
    .find_map(|e| match e {
        SessionEvent::McpServerSandboxed {
            container_id,
            secrets_injected,
            secrets_as_files,
            secrets_in_env,
            inject_host,
            runtime,
            ..
        } => Some((
            container_id,
            secrets_injected,
            secrets_as_files,
            secrets_in_env,
            inject_host,
            runtime,
        )),
        _ => None,
    });
    let inspected = started.as_ref().map(|(id, ..)| {
        let out = Command::new("docker")
            .args(["inspect", id])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    });

    client.shutdown().await;
    stop(gateway);

    eprintln!("mode={mode}");
    eprintln!(
        "get_me: success={} {}",
        me.success,
        &me.output[..me.output.len().min(60)]
    );
    eprintln!(
        "renamed repository: success={} {}",
        renamed.success,
        &renamed.output[..renamed.output.len().min(90)]
    );
    eprintln!(
        "write: success={} {}",
        written.success,
        &written.output[..written.output.len().min(160)]
    );

    assert!(me.success, "get_me: {}", me.output);
    assert!(me.output.contains("\"login\""), "{}", me.output);
    assert!(renamed.success, "renamed repository: {}", renamed.output);
    assert!(
        renamed.output.contains("electron/electron"),
        "{}",
        renamed.output
    );
    assert!(written.success, "write: {}", written.output);
    assert!(written.output.contains(&repo), "{}", written.output);

    let (_, injected, as_files, in_env, host, runtime) = started.expect("a start row");
    eprintln!("start row: injected={injected:?} host={host:?} runtime={runtime:?}");
    assert_eq!(injected, ["GITHUB_PERSONAL_ACCESS_TOKEN"]);
    assert!(as_files.is_empty() && in_env.is_empty());
    assert_eq!(host.as_deref(), Some("api.github.com"));
    let inspected = inspected.unwrap();
    assert!(!inspected.contains(&token), "the runtime reports the token");
    assert!(inspected.contains("GITHUB_PERSONAL_ACCESS_TOKEN=wirken-placeholder-"));
    assert!(inspected.contains("GITHUB_HOST=http://127.0.0.1:3180"));
    let wanted_runtime = if mode == "gvisor" { "runsc" } else { "runc" };
    assert!(
        inspected.contains(&format!("\"Runtime\": \"{wanted_runtime}\"")),
        "not started by {wanted_runtime}"
    );

    let lane = rows(
        data.path(),
        wirken_mcp_proxy::mcp_registry::MCP_SENTINEL_SESSION,
    );
    let requests: Vec<(String, String)> = lane
        .iter()
        .filter_map(|e| match e {
            SessionEvent::McpCredentialInjected {
                credential,
                host,
                method,
                path,
                server_name,
                ..
            } => {
                assert_eq!(
                    (credential.as_str(), host.as_str(), server_name.as_str()),
                    ("github-token", "api.github.com", "github")
                );
                Some((method.clone(), path.clone()))
            }
            _ => None,
        })
        .collect();
    eprintln!("injected requests: {requests:?}");
    assert!(requests.contains(&("GET".to_string(), "/user".to_string())));
    assert!(
        requests
            .iter()
            .any(|(m, p)| m == "GET" && p.starts_with("/repositories/")),
        "no followed redirect among {requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|(m, p)| m == "POST" && (p == "/graphql" || p.ends_with("/issues"))),
        "no write among {requests:?}"
    );
    let refused: Vec<&SessionEvent> = lane
        .iter()
        .filter(|e| matches!(e, SessionEvent::McpInjectRefused { .. }))
        .collect();
    eprintln!("refused requests: {refused:?}");
    let verdicts: Vec<String> = lane
        .iter()
        .filter_map(|e| match e {
            SessionEvent::SandboxEgressVerdict {
                host,
                allowed,
                reason,
                ..
            } => Some(format!("{host} allowed={allowed} reason={reason:?}")),
            _ => None,
        })
        .collect();
    eprintln!("egress verdicts: {verdicts:?}");
    assert!(
        !verdicts
            .iter()
            .any(|v| v.starts_with("api.github.com allowed=true")),
        "the direct route to the bound host was open"
    );

    // The value is in no row on any lane.
    for file in ["audit.db", "audit.db-wal"] {
        if let Ok(bytes) = std::fs::read(data.path().join(file)) {
            assert!(
                !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                "{file} carries the token"
            );
        }
    }
}
