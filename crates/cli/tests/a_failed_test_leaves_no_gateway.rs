//! A test that fails while it holds a running gateway leaves no gateway
//! behind. `std::process::Child` neither kills nor reaps on drop, so a
//! panic between `spawn` and the test's own stop used to leave `wirken
//! run` alive after the test binary exited, orphaned, on a data
//! directory its `TempDir` had already removed. Tests hold their
//! gateways in `common::KillOnDrop`, which kills and reaps on drop.
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A gateway on `data`, returned once it says it is running.
fn running_gateway(data: &std::path::Path) -> Child {
    std::fs::write(
        data.join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = gateway.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line.contains("Wirken running") => return gateway,
            Ok(_) => {}
            Err(_) => {
                let _ = gateway.kill();
                let _ = gateway.wait();
                panic!("the gateway never came up");
            }
        }
    }
}

/// Whether `pid` is a live process, not a zombie awaiting its reaper.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| {
            let state = stat.rsplit(')').next().unwrap_or("").trim_start();
            !state.starts_with('Z')
        })
        .unwrap_or(false)
}

fn gone_within(pid: u32, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    while alive(pid) {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[test]
fn a_gateway_held_by_a_test_that_panics_is_stopped() {
    // A bare `Child`, as the tests held their gateways before: the
    // panic unwinds past it and the gateway keeps running.
    let data = tempfile::tempdir().unwrap();
    let bare = running_gateway(data.path());
    let bare_pid = bare.id();
    let unwound = std::thread::spawn(move || {
        let _gateway = bare;
        panic!("an assertion failed while the gateway ran");
    })
    .join();
    assert!(unwound.is_err());
    let leaked = !gone_within(bare_pid, Duration::from_secs(2));
    // SAFETY: kill(2) on the gateway this test started, which the
    // thread above dropped without stopping.
    unsafe {
        libc::kill(bare_pid as libc::pid_t, libc::SIGKILL);
    }
    assert!(
        leaked,
        "a bare Child no longer outlives a panic; the guard may be unneeded"
    );

    // The same failure with the gateway in the guard: it is stopped and
    // reaped as the panic unwinds.
    let data = tempfile::tempdir().unwrap();
    let guarded = common::KillOnDrop(running_gateway(data.path()));
    let guarded_pid = guarded.id();
    let unwound = std::thread::spawn(move || {
        let _gateway = guarded;
        panic!("an assertion failed while the gateway ran");
    })
    .join();
    assert!(unwound.is_err());
    assert!(
        gone_within(guarded_pid, Duration::from_secs(10)),
        "the gateway {guarded_pid} outlived the test that held it"
    );
}
