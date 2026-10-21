//! `wirken chat` is a screen. Run from a script, with stdin and stdout
//! not a terminal, it refuses before it reads any configuration,
//! connects anywhere or starts anything, and says what to use instead.

#![cfg(unix)]

mod common;

use common::wirken;

#[test]
fn chat_without_a_terminal_refuses_and_points_to_ask() {
    let tmp = tempfile::tempdir().unwrap();
    let out = wirken(tmp.path()).arg("chat").output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("wirken ask -m"), "{err}");
    assert!(
        !tmp.path().join("provider.json").exists(),
        "no setup ran from a script"
    );
}
