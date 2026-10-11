//! `wirken run` stops on SIGTERM and on Ctrl-C (SIGINT) the same way: it
//! runs its shutdown, which asks the MCP proxy to stop its servers, the
//! proxy exits with it, and the gateway itself exits once its audit log
//! is flushed. A gateway that died on SIGTERM left the proxy running,
//! and every container the proxy had started with it; one that ran its
//! shutdown never returned from the flush.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Children of `pid`, read from every task's `children` list.
fn children(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for task in tasks.flatten() {
        if let Ok(list) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(
                list.split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
    out
}

fn cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
        .unwrap_or_default()
}

/// Whether `pid` is still a live process: present and not a zombie.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| {
            !s.rsplit(')')
                .next()
                .unwrap_or_default()
                .trim_start()
                .starts_with('Z')
        })
        .unwrap_or(false)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start the gateway, send it `signal` once it says it is running, and
/// check that it stops its MCP proxy and then exits by itself.
fn stops_on(signal: libc::c_int) {
    let data = tempfile::tempdir().unwrap();
    // Nothing listens on the discard port; the gateway starts anyway.
    std::fs::write(
        data.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data.path())
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = gateway.id();

    let (lines_tx, lines) = std::sync::mpsc::channel();
    let stdout = gateway.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !output.iter().any(|l: &String| l.contains("Wirken running")) {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| {
                let _ = gateway.kill();
                panic!("gateway never came up:\n{}", output.join("\n"))
            });
        output.push(line);
    }

    let proxies: Vec<u32> = children(pid)
        .into_iter()
        .filter(|c| cmdline(*c).contains("mcp-proxy"))
        .collect();
    assert!(!proxies.is_empty(), "no MCP proxy under the gateway");

    // SAFETY: kill(2) on the child this test spawned and still holds.
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = gateway.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = gateway.kill();
            let _ = gateway.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    output.extend(lines.try_iter());
    let output = output.join("\n");

    let survivors: Vec<u32> = proxies.iter().copied().filter(|p| alive(*p)).collect();
    assert!(
        survivors.is_empty(),
        "MCP proxy {survivors:?} outlived the gateway"
    );
    let status = status.unwrap_or_else(|| panic!("gateway did not exit:\n{output}"));
    assert!(status.success(), "{status:?}\n{output}");
    assert!(output.contains("Shutting down"), "{output}");
    assert!(output.contains("Wirken stopped."), "{output}");
}

#[test]
fn sigterm_stops_the_proxy_and_the_gateway() {
    stops_on(libc::SIGTERM);
}

#[test]
fn ctrl_c_stops_the_proxy_and_the_gateway() {
    stops_on(libc::SIGINT);
}

/// The image the contained stub server runs in, as the proxy's live
/// container tests use.
const STUB_IMAGE: &str = "debian:bookworm-slim";

/// A stdio MCP server in `sh`: answers `initialize`, and any other
/// request with an empty tool list.
const STUB_SERVER: &str = r#"while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -n "$id" ] || continue
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"stub","version":"0"}}}\n' "$id" ;;
    *) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}\n' "$id" ;;
  esac
done"#;

/// Whether a Docker daemon answers and has the stub's image.
fn docker_has_stub_image() -> bool {
    Command::new("docker")
        .args(["image", "inspect", STUB_IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn container_exists(id: &str) -> bool {
    Command::new("docker")
        .args(["container", "inspect", id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The container id the proxy recorded for the stub server, once it
/// has started it.
fn sandboxed_container(data: &std::path::Path) -> Option<String> {
    use wirken_audit::SessionLog as _;
    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).ok()?;
    let lane = log.handle_for(wirken_audit::SessionId::new("gateway-mcp"));
    log.get_since(&lane, 0)
        .ok()?
        .into_iter()
        .find_map(|row| match row.event {
            wirken_audit::SessionEvent::McpServerSandboxed { container_id, .. } => {
                Some(container_id)
            }
            _ => None,
        })
}

/// A gateway killed outright runs no shutdown, so nothing asks its MCP
/// proxy to stop. The proxy notices the gateway gone, the connection
/// it holds on the gateway's refresh socket closing, and stops its
/// servers and exits within the gateway's 10-second grace. With Docker
/// and the stub's image present, a contained server is configured and
/// its container is removed in that time too; without them, only the
/// proxy is checked.
#[test]
fn sigkill_of_the_gateway_stops_the_proxy_and_removes_its_containers() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let contained = docker_has_stub_image();
    if contained {
        let config = serde_json::json!({
            "servers": {
                "stub": {
                    "command": "sh",
                    "args": ["-c", STUB_SERVER],
                    "sandbox": { "image": STUB_IMAGE },
                }
            }
        });
        std::fs::write(data.path().join("mcp.json"), config.to_string()).unwrap();
    } else {
        eprintln!("no Docker or no {STUB_IMAGE}: checking the proxy only");
    }

    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data.path())
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = gateway.id();
    let (lines_tx, lines) = std::sync::mpsc::channel();
    let stdout = gateway.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !output.iter().any(|l: &String| l.contains("Wirken running")) {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| {
                let _ = gateway.kill();
                panic!("gateway never came up:\n{}", output.join("\n"))
            });
        output.push(line);
    }

    let proxies: Vec<u32> = children(pid)
        .into_iter()
        .filter(|c| cmdline(*c).contains("mcp-proxy"))
        .collect();
    assert!(!proxies.is_empty(), "no MCP proxy under the gateway");
    let container = contained.then(|| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(id) = sandboxed_container(data.path()) {
                break id;
            }
            if Instant::now() > deadline {
                let _ = gateway.kill();
                panic!("the stub server's container never started");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    if let Some(id) = &container {
        assert!(container_exists(id), "container {id} is not running");
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let gone = |proxies: &[u32], container: &Option<String>| {
        proxies.iter().all(|p| !alive(*p))
            && container.as_deref().is_none_or(|id| !container_exists(id))
    };
    while !gone(&proxies, &container) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let survivors: Vec<u32> = proxies.iter().copied().filter(|p| alive(*p)).collect();
    let left = container
        .as_deref()
        .filter(|id| container_exists(id))
        .map(str::to_string);
    // Clean up before failing, so a failure leaves nothing running.
    for p in &survivors {
        // SAFETY: kill(2) on a proxy this test's gateway started.
        unsafe {
            libc::kill(*p as libc::pid_t, libc::SIGKILL);
        }
    }
    if let Some(id) = &left {
        let _ = Command::new("docker").args(["rm", "-f", id]).status();
    }
    assert!(
        survivors.is_empty(),
        "MCP proxy {survivors:?} outlived a killed gateway"
    );
    assert!(
        left.is_none(),
        "container {left:?} outlived a killed gateway"
    );
}
