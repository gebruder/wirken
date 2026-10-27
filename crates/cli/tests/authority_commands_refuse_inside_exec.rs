//! Commands that change authority refuse to run inside a Wirken `exec`,
//! and each refusal is a row on the operator lane.

mod common;

use common::wirken;

/// Every authority-changing invocation, with arguments it would accept.
const INVOCATIONS: &[(&str, &str, &[&str])] = &[
    (
        "permissions",
        "approve",
        &[
            "permissions",
            "approve",
            "shell:ls",
            "--channel",
            "telegram",
        ],
    ),
    (
        "permissions",
        "revoke",
        &["permissions", "revoke", "shell:ls", "--channel", "telegram"],
    ),
    (
        "permissions",
        "pending approve",
        &["permissions", "pending", "approve", "req-1"],
    ),
    (
        "permissions",
        "pending deny",
        &["permissions", "pending", "deny", "req-1"],
    ),
    ("skills", "install", &["skills", "install", "/nonexistent"]),
    (
        "skills",
        "trust-root",
        &["skills", "trust-root", "/nonexistent"],
    ),
    ("skills", "restore-bundled", &["skills", "restore-bundled"]),
    ("mcp", "sign", &["mcp", "sign", "server"]),
    ("credentials", "remove", &["credentials", "remove", "entry"]),
    ("audit", "acknowledge", &["audit", "acknowledge", "--all"]),
    ("agents", "remove", &["agents", "remove", "default"]),
    ("agents", "bind", &["agents", "bind", "default", "telegram"]),
    ("channel", "remove", &["channel", "remove", "telegram"]),
];

fn refusals(data: &std::path::Path) -> Vec<(String, String, String)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.command'), json_extract(payload, '$.invocation'),
                json_extract(payload, '$.reason')
           FROM session_events
          WHERE session_id = 'gateway-operator'
            AND json_extract(payload, '$.kind') = 'operator_command_refused'
          ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[cfg(not(windows))]
#[test]
fn authority_commands_refuse_inside_exec_and_record_it() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    for (_, _, args) in INVOCATIONS {
        let out = wirken(data)
            .args(*args)
            .env("WIRKEN_EXEC", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} ran inside exec");
        assert!(
            stderr.contains("refuses to run inside a Wirken exec"),
            "{args:?}: {stderr}"
        );
    }

    let expected: Vec<_> = INVOCATIONS
        .iter()
        .map(|(command, invocation, _)| {
            (
                command.to_string(),
                invocation.to_string(),
                "inside_exec".to_string(),
            )
        })
        .collect();
    assert_eq!(refusals(data), expected);
    assert!(
        !data.join("permissions.db").exists(),
        "a refused command opened the permission store"
    );
}

#[cfg(not(windows))]
#[test]
fn a_read_runs_inside_exec() {
    let tmp = tempfile::tempdir().unwrap();
    let out = wirken(tmp.path())
        .args(["permissions", "list"])
        .env("WIRKEN_EXEC", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
