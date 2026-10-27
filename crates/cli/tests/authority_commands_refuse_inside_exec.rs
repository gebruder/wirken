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
    ("vault", "reset", &["vault", "reset"]),
    ("vault", "migrate", &["vault", "migrate"]),
    ("cron", "create", &["cron", "create", "0 * * * *", "hello"]),
    ("cron", "delete", &["cron", "delete", "job-1"]),
    ("cron", "pause", &["cron", "pause", "job-1"]),
    ("cron", "resume", &["cron", "resume", "job-1"]),
    (
        "hooks",
        "register",
        &["hooks", "register", "guard", "00", "--type", "veto"],
    ),
    ("hooks", "unregister", &["hooks", "unregister", "guard"]),
    ("persona", "create", &["persona", "create", "p1"]),
    (
        "persona",
        "edit",
        &["persona", "edit", "p1", "--model", "m"],
    ),
    ("persona", "delete", &["persona", "delete", "p1"]),
    ("preset", "install", &["preset", "install", "zirkel"]),
    ("preset", "schedule", &["preset", "schedule", "zirkel"]),
    ("preset", "unschedule", &["preset", "unschedule", "zirkel"]),
    ("webchat", "open", &["webchat", "open"]),
    (
        "zirkel",
        "bind",
        &[
            "zirkel",
            "bind",
            "--channel",
            "signal",
            "--conversation",
            "c",
        ],
    ),
    ("zirkel", "unbind", &["zirkel", "unbind"]),
    ("setup", "", &["setup"]),
    ("import", "", &["import", "/nonexistent/archive.zip"]),
    (
        "zirkel",
        "auth-set",
        &["zirkel", "auth-set", "--source", "congress-gov"],
    ),
];

fn refusals(data: &std::path::Path) -> Vec<(String, String, String)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let has_rows: bool = db
        .query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE name = 'session_events'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    if !has_rows {
        return Vec::new();
    }
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
        assert!(!stderr.contains("  refuses"), "{args:?}: {stderr}");
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
fn reads_and_sessions_close_run_inside_exec() {
    for args in [
        &["permissions", "list"][..],
        &["cron", "list"],
        &["hooks", "list"],
        &["persona", "list"],
        &["preset", "list"],
        &["zirkel", "status"],
        &["sessions", "close", "no-such-session"],
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let out = wirken(tmp.path())
            .args(args)
            .env("WIRKEN_EXEC", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("refuses to run inside a Wirken exec"),
            "{args:?}: {stderr}"
        );
        assert!(refusals(tmp.path()).is_empty(), "{args:?}");
    }
}
