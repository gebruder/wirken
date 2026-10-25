//! `wirken approvers` writes the approver allowlist the gateway reads on
//! every decision. Each add and remove is a row on the signed
//! `gateway-approvers` lane; every subcommand refuses under the `exec`
//! marker and records the refusal there, so an agent's own command
//! cannot change who may approve its calls.
//!
//! Driven through the binary with stdin closed.

mod common;

use common::wirken;

fn run(data: &std::path::Path, args: &[&str], exec_marker: bool) -> (bool, String, String) {
    let mut cmd = wirken(data);
    cmd.arg("approvers").args(args);
    if exec_marker {
        cmd.env("WIRKEN_EXEC", "1");
    } else {
        cmd.env_remove("WIRKEN_EXEC");
    }
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `(kind, adapter_id, user_id, invocation)` of a row.
type Row = (String, Option<String>, Option<String>, Option<String>);

/// Every row on the approvers lane other than chain heads, in order.
fn rows(data: &std::path::Path) -> Vec<Row> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.kind'), json_extract(payload, '$.adapter_id'),
                json_extract(payload, '$.user_id'), json_extract(payload, '$.invocation')
           FROM session_events
          WHERE session_id = 'gateway-approvers'
            AND json_extract(payload, '$.kind') != 'chain_head'
          ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn sealed(data: &std::path::Path) -> bool {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let last: String = db
        .query_row(
            "SELECT json_extract(payload, '$.kind') FROM session_events
              WHERE session_id = 'gateway-approvers' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    last == "chain_head"
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

#[cfg(not(windows))]
#[test]
fn add_and_remove_leave_sealed_rows_and_need_no_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, out, err) = run(
        data,
        &["add", "telegram", "12345", "--display", "me"],
        false,
    );
    assert!(ok, "{err}");
    assert!(out.contains("It applies to the next decision"), "{out}");
    assert!(!out.contains("Restart"), "{out}");
    assert!(sealed(data));

    let (ok, out, _) = run(data, &["list"], false);
    assert!(ok);
    assert!(
        out.contains("telegram") && out.contains("12345") && out.contains("me"),
        "{out}"
    );

    // A Telegram group's chat id is negative, and is taken as it is.
    let (ok, _, err) = run(data, &["set-chat", "telegram", "-100123456789"], false);
    assert!(ok, "{err}");
    let (ok, out, _) = run(data, &["show-chat", "telegram"], false);
    assert!(ok);
    assert!(out.contains("'-100123456789'"), "{out}");

    let (ok, out, err) = run(data, &["remove", "telegram", "12345"], false);
    assert!(ok, "{err}");
    assert!(out.contains("Approver removed"), "{out}");
    let (ok, out, _) = run(data, &["remove", "telegram", "12345"], false);
    assert!(ok);
    assert!(out.contains("No approver matching"), "{out}");
    assert!(sealed(data));

    assert_eq!(
        rows(data),
        vec![
            ("approver_added".into(), s("telegram"), s("12345"), None),
            ("approver_removed".into(), s("telegram"), s("12345"), None),
        ]
    );
}

/// Every subcommand refuses under the exec marker before it opens the
/// allowlist, and each refusal is an `operator_command_refused` row on
/// the sealed lane naming what was asked for.
#[cfg(not(windows))]
#[test]
fn every_subcommand_refuses_inside_a_wirken_exec() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["add", "telegram", "1"][..],
        &["remove", "telegram", "1"][..],
        &["list"][..],
        &["set-chat", "telegram", "-100"][..],
        &["show-chat", "telegram"][..],
    ] {
        let (ok, _, err) = run(tmp.path(), args, true);
        assert!(!ok, "{args:?} ran inside an exec");
        assert!(err.contains("inside a Wirken exec"), "{args:?}: {err}");
    }
    assert!(!tmp.path().join("approvers.db").exists());
    let refused = |inv: &str| ("operator_command_refused".to_string(), None, None, s(inv));
    assert_eq!(
        rows(tmp.path()),
        vec![
            refused("add"),
            refused("remove"),
            refused("list"),
            refused("set-chat"),
            refused("show-chat"),
        ]
    );
    assert!(sealed(tmp.path()));
}
