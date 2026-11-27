//! `wirken chat` exits when its terminal goes away, with or without the
//! SIGHUP the kernel sends a session leader. Once a tty hangs up,
//! crossterm's poll spins on the EOF read and never returns, so the key
//! reader thread is left to the process exit.
#![cfg(target_os = "linux")]

mod common;

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A gateway on `data`, once it says it is running.
fn gateway(data: &std::path::Path) -> common::KillOnDrop {
    std::fs::write(
        data.join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let mut gateway = common::KillOnDrop(
        common::wirken(data)
            .args(["run", "--port", &free_port().to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (lines_tx, lines) = std::sync::mpsc::channel();
    let stdout = gateway.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut output = Vec::new();
    while !output.iter().any(|l: &String| l.contains("Wirken running")) {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("gateway never came up:\n{}", output.join("\n")));
        output.push(line);
    }
    gateway
}

/// A new pty: the master, and the slave opened for the child.
fn open_pty() -> (File, File) {
    // SAFETY: posix_openpt/grantpt/unlockpt/ptsname_r on a fd this
    // function owns; the name buffer is sized and NUL-terminated by libc.
    unsafe {
        // Close-on-exec: a child holding the master would keep the
        // terminal up after the test drops it.
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        assert!(master >= 0, "posix_openpt");
        assert_eq!(libc::grantpt(master), 0, "grantpt");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt");
        let mut name = [0 as libc::c_char; 128];
        assert_eq!(
            libc::ptsname_r(master, name.as_mut_ptr(), name.len()),
            0,
            "ptsname_r"
        );
        let path = std::ffi::CStr::from_ptr(name.as_ptr()).to_str().unwrap();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        (File::from_raw_fd(master), slave)
    }
}

/// Read `master` until `deadline`, or until it fails.
fn drain_until(master: &mut File, seen: &mut Vec<u8>, deadline: Instant) {
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let mut fd = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for a fd `master` owns.
        if unsafe { libc::poll(&mut fd, 1, 50) } <= 0 {
            continue;
        }
        match master.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
}

/// Start the chat on a pty, close the pty once the chat holds the
/// screen, and check that the chat exits by itself.
fn exits_on_hangup(controlling_terminal: bool) {
    let data = tempfile::tempdir().unwrap();
    let _gateway = gateway(data.path());
    let (mut master, slave) = open_pty();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wirken"));
    cmd.arg("chat")
        .env("WIRKEN_DATA_DIR", data.path())
        .env("NO_COLOR", "1")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: setsid and ioctl are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if controlling_terminal && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut chat = common::KillOnDrop(cmd.spawn().unwrap());
    drop(cmd);

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !seen.windows(8).any(|w| w == b"\x1b[?1049h") && Instant::now() < deadline {
        drain_until(
            &mut master,
            &mut seen,
            Instant::now() + Duration::from_millis(100),
        );
    }
    assert!(
        seen.windows(8).any(|w| w == b"\x1b[?1049h"),
        "the chat never took the screen:\n{}",
        String::from_utf8_lossy(&seen)
    );
    // A few frames, then the terminal goes away.
    drain_until(
        &mut master,
        &mut seen,
        Instant::now() + Duration::from_millis(500),
    );
    drop(master);

    let deadline = Instant::now() + Duration::from_secs(10);
    while chat.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "the chat was still running 10s after its terminal hung up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn chat_exits_on_sighup_when_its_terminal_hangs_up() {
    exits_on_hangup(true);
}

#[test]
fn chat_exits_without_a_signal_when_its_terminal_hangs_up() {
    exits_on_hangup(false);
}
