//! `WIRKEN_LIVE_RELOAD_INTERVAL_S` is checked when `wirken run`
//! starts. A zero, an interval past the hour, or a value that is not a
//! whole number of seconds stops the gateway before it has started
//! anything, with the variable and the value in the message. It is not
//! read as the default.
#![cfg(unix)]

use std::process::{Command, Stdio};

/// `wirken run` on an empty data directory with the interval set to
/// `value`. Returns whether it exited with success, its stderr, and
/// whether the data directory was left empty.
fn run_with(value: &str) -> (bool, String, bool) {
    let data = tempfile::tempdir().unwrap();
    let dir = data.path().join("data");
    let output = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", "0"])
        .env("WIRKEN_DATA_DIR", &dir)
        .env("WIRKEN_LIVE_RELOAD_INTERVAL_S", value)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        !dir.exists(),
    )
}

#[test]
fn a_zero_or_nonsensical_interval_stops_the_gateway_before_it_starts() {
    for value in ["0", "3601", "2.5", "soon", ""] {
        let (ok, stderr, untouched) = run_with(value);
        assert!(!ok, "{value:?} was accepted");
        assert!(
            stderr.contains("WIRKEN_LIVE_RELOAD_INTERVAL_S")
                && stderr.contains(&format!("{value:?}")),
            "{value:?}: {stderr}"
        );
        assert!(
            untouched,
            "{value:?}: the gateway made its data directory before refusing"
        );
    }
}
