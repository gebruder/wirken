//! A credential rotated in the vault reaches the MCP proxy without a
//! restart.
//!
//! `wirken run` hands the proxy a bearer token at spawn. The operator
//! rotates it with `wirken credentials rotate` and the server starts
//! accepting only the new value: the next call is refused with a 401,
//! the proxy asks the gateway for the token's current value, and the
//! call after that succeeds, with the same gateway and proxy processes
//! throughout. The gateway records the fetch by credential name.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wirken_audit::{MCP_CREDENTIAL_SESSION, SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-refetch-test-passphrase";

/// An HTTP MCP server on a loopback port that accepts one bearer token
/// at a time and answers 401 to any other. Records the `Authorization`
/// header of every `tools/call`.
struct Server {
    url: String,
    accepted: Arc<Mutex<String>>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(token: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let accepted = Arc::new(Mutex::new(token.to_string()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (want, seen) = (accepted.clone(), calls.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (want, seen) = (want.clone(), seen.clone());
                std::thread::spawn(move || answer(stream, &want, &seen));
            }
        });
        Self {
            url,
            accepted,
            calls,
        }
    }
}

fn answer(stream: std::net::TcpStream, want: &Mutex<String>, seen: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let (mut length, mut auth) = (0usize, String::new());
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header == "\r\n" || header.is_empty() {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse().unwrap();
        }
        if lower.starts_with("authorization:") {
            auth = header["authorization:".len()..].trim().to_string();
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let method = request["method"].as_str().unwrap_or_default();
    if method == "tools/call" {
        seen.lock().unwrap().push(auth.clone());
    }

    let mut stream = stream;
    if auth != format!("Bearer {}", want.lock().unwrap()) {
        let body = r#"{"error":"invalid_token"}"#;
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer error=\"invalid_token\"\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        return;
    }
    let result = match method {
        "initialize" => serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "remote", "version": "1"},
        }),
        "tools/list" => serde_json::json!({"tools": [{
            "name": "whoami",
            "description": "Says who called.",
            "inputSchema": {"type": "object", "properties": {}},
        }]}),
        "tools/call" => serde_json::json!({"content": [{"type": "text", "text": "called"}]}),
        _ => {
            let _ = write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            return;
        }
    };
    let body =
        serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
}

fn wirken(data: &Path, args: &[&str], stdin: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(args)
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

/// The MCP proxies running under `gateway`.
fn proxies(gateway: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{gateway}/task"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let children = std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
        for pid in children.split_whitespace().filter_map(|p| p.parse().ok()) {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if String::from_utf8_lossy(&cmdline).contains("mcp-proxy") {
                out.push(pid);
            }
        }
    }
    out
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

#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_bearer_token_reaches_the_proxy_after_one_refused_call() {
    let server = Server::start("tok-1");
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    wirken(
        data.path(),
        &["credentials", "add", "linear-token", "--stdin"],
        "tok-1",
    );
    let mcp = serde_json::json!({ "servers": { "remote": {
        "transport": "http",
        "url": server.url,
        "auth": {"type": "bearer", "credential": "vault:linear-token"},
    }}});
    std::fs::write(data.path().join("mcp.json"), mcp.to_string()).unwrap();

    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
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
    let proxy_before = proxies(gateway.id());

    // The agent's side of the proxy socket, as the gateway connects it.
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

    let first = client.execute("mcp_remote_whoami", "{}").await.unwrap();

    // The operator rotates the token; the server takes only the new one.
    wirken(
        data.path(),
        &["credentials", "rotate", "linear-token", "--stdin"],
        "tok-2",
    );
    *server.accepted.lock().unwrap() = "tok-2".to_string();

    let refused = client.execute("mcp_remote_whoami", "{}").await.unwrap();
    let after = client.execute("mcp_remote_whoami", "{}").await.unwrap();
    let proxy_after = proxies(gateway.id());
    client.shutdown().await;
    let gateway_still_running = gateway.try_wait().unwrap().is_none();
    stop(gateway);

    assert!(first.success, "first call: {}", first.output);
    assert!(!refused.success, "the call after the rotation succeeded");
    assert!(refused.output.contains("401"), "{}", refused.output);
    assert!(after.success, "the call after the fetch: {}", after.output);
    assert_eq!(after.output, "called");
    assert_eq!(
        *server.calls.lock().unwrap(),
        ["Bearer tok-1", "Bearer tok-1", "Bearer tok-2"],
        "the token each call carried"
    );
    assert!(gateway_still_running, "the gateway exited during the test");
    assert_eq!(proxy_before.len(), 1, "one MCP proxy under the gateway");
    assert_eq!(proxy_before, proxy_after, "the proxy was restarted");

    let log = wirken_audit::SqliteSessionLog::open(&data.path().join("audit.db")).unwrap();
    let lane = log.handle_for(SessionId::new(MCP_CREDENTIAL_SESSION));
    let rows: Vec<SessionEvent> = log
        .get_since(&lane, 0)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        // The lane's signed start and end heads.
        .filter(|e| !matches!(e, SessionEvent::ChainHead { .. }))
        .collect();
    assert!(
        matches!(rows.as_slice(), [SessionEvent::McpCredentialRefetched { credential }] if credential == "linear-token"),
        "{rows:?}"
    );
    let json = serde_json::to_string(&rows).unwrap();
    assert!(!json.contains("tok-"), "the row carries a value: {json}");
}
