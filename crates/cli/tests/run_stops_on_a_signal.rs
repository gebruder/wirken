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
