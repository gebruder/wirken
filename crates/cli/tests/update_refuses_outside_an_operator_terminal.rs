//! `wirken update` installs and rolls back only for an operator at a
//! terminal, outside any Wirken `exec`. Both refusals come before any
//! network request: a refused run never fetches, so it never records a
//! manifest either.
//!
//! Driven through the binary with stdin closed, which is how a script,
//! a service manager or a model's `exec` would run it.

mod common;

use common::wirken;

fn run(data: &std::path::Path, args: &[&str], exec_marker: bool) -> (bool, String) {
    let mut cmd = wirken(data);
    cmd.arg("update").args(args);
    if exec_marker {
        cmd.env("WIRKEN_EXEC", "1");
    } else {
        cmd.env_remove("WIRKEN_EXEC");
    }
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[cfg(not(windows))]
#[test]
fn a_non_terminal_install_or_rollback_is_refused_before_any_fetch() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &[][..],
        &["--rollback"][..],
        &["--to", "2.2.0", "--allow-downgrade"][..],
    ] {
        let (ok, err) = run(tmp.path(), args, false);
        assert!(!ok, "{args:?} was not refused");
        assert!(err.contains("stdin is not one"), "{args:?}: {err}");
    }
    assert!(
        !tmp.path().join("update").exists(),
        "a refused run fetched a manifest"
    );
}

#[cfg(not(windows))]
#[test]
fn a_run_inside_a_wirken_exec_is_refused_first() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [&[][..], &["--rollback"][..]] {
        let (ok, err) = run(tmp.path(), args, true);
        assert!(!ok);
        assert!(err.contains("inside a Wirken exec"), "{args:?}: {err}");
    }
}
