//! `wirken run` takes SIGTERM the way it takes Ctrl-C: it runs
//! its shutdown, which asks the MCP proxy to stop its servers, and the
//! proxy exits with it. A gateway that died on SIGTERM left the proxy
//! running, and every container the proxy had started with it.
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

#[test]
fn sigterm_runs_the_shutdown_and_takes_the_mcp_proxy_with_it() {
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
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while proxies.iter().any(|p| alive(*p)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    output.extend(lines.try_iter());
    let survivors: Vec<u32> = proxies.iter().copied().filter(|p| alive(*p)).collect();
    // This test is about the proxy; the gateway is stopped once that is
    // checked.
    let _ = gateway.kill();
    let _ = gateway.wait();

    assert!(
        survivors.is_empty(),
        "MCP proxy {survivors:?} outlived SIGTERM"
    );
    assert!(
        output.iter().any(|l| l.contains("Shutting down")),
        "{}",
        output.join("\n")
    );
}
