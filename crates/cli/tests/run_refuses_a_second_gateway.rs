//! One gateway to a data directory: a second `wirken run` on a directory
//! a running gateway holds refuses to start, names that gateway's
//! process, and leaves its socket where it is.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run(data: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wirken"));
    command
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null());
    command
}

#[test]
fn a_second_gateway_on_a_live_data_directory_refuses_to_start() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let mut first = run(data.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (lines_tx, lines) = std::sync::mpsc::channel();
    let stdout = first.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| {
                let _ = first.kill();
                panic!("the first gateway never came up")
            });
        if line.contains("Wirken running") {
            break;
        }
    }
    let socket = data.path().join("sockets").join("gateway.sock");
    let inode = |path: &std::path::Path| {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).unwrap().ino()
    };
    let before = inode(&socket);

    let second = run(data.path()).output().unwrap();
    let said = String::from_utf8_lossy(&second.stderr).into_owned();
    assert!(!second.status.success(), "the second gateway started");
    assert!(said.contains("already running"), "{said}");
    assert!(said.contains(&format!("process {}", first.id())), "{said}");

    // The first gateway is as it was: alive, on the socket it bound.
    assert!(
        first.try_wait().unwrap().is_none(),
        "the first gateway died"
    );
    assert_eq!(inode(&socket), before, "the socket was replaced");

    // SAFETY: kill(2) on the child this test spawned and still holds.
    unsafe {
        libc::kill(first.id() as libc::pid_t, libc::SIGTERM);
    }
    let _ = first.wait();
}
