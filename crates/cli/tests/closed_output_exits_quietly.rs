//! A command whose stdout is closed before it prints, as by `| head`,
//! exits 141 with nothing on stderr, as a process the pipe signal ended
//! would, rather than reporting a panic.
#![cfg(unix)]

mod common;

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use common::wirken;

#[test]
fn a_closed_stdout_is_exit_141_not_a_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut child = wirken(tmp.path())
        .args(["agents", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(141),
        "{:?}: {stderr}",
        out.status.signal()
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}
