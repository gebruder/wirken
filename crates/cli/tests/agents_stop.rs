//! `wirken agents stop` and `resume` with no gateway running: the state
//! lands in the permission store, the grants `--revoke-all` names go,
//! and each command is one sealed row on the operator lane.

mod common;

use std::path::Path;

use common::wirken;

fn run(data: &Path, args: &[&str]) -> (bool, String) {
    let out = wirken(data)
        .env_remove("WIRKEN_EXEC")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn stopped(data: &Path) -> Vec<String> {
    let db = rusqlite::Connection::open(data.join("permissions.db")).unwrap();
    db.prepare("SELECT agent_id FROM stopped_agents ORDER BY agent_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn grants(data: &Path) -> i64 {
    let db = rusqlite::Connection::open(data.join("permissions.db")).unwrap();
    db.query_row("SELECT count(*) FROM approvals", [], |r| r.get(0))
        .unwrap()
}

/// `(kind, payload)` of each row on the operator lane, in order.
fn operator_rows(data: &Path) -> Vec<(String, serde_json::Value)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.kind'), payload FROM session_events
          WHERE session_id = 'gateway-operator' ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
    .unwrap()
    .map(|r| {
        let (kind, payload) = r.unwrap();
        (kind, serde_json::from_str(&payload).unwrap())
    })
    .collect()
}

#[cfg(not(windows))]
#[test]
fn stop_and_resume_hold_without_a_gateway_and_leave_sealed_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, out) = run(
        data,
        &[
            "permissions",
            "approve",
            "shell:ls",
            "--channel",
            "telegram",
        ],
    );
    assert!(ok, "{out}");
    assert_eq!(grants(data), 1);

    let (ok, out) = run(data, &["agents", "stop", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("Agent 'default' stopped"), "{out}");
    assert_eq!(stopped(data), ["default"]);
    assert_eq!(
        grants(data),
        1,
        "a stop without --revoke-all keeps the grants"
    );

    let (ok, out) = run(data, &["agents", "stop", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("already stopped"), "{out}");

    let (ok, out) = run(data, &["agents", "stop", "default", "--revoke-all"]);
    assert!(ok, "{out}");
    assert!(out.contains("Removed 1 persisted grant"), "{out}");
    assert_eq!(grants(data), 0);

    let (ok, out) = run(data, &["agents", "resume", "default"]);
    assert!(ok, "{out}");
    assert!(stopped(data).is_empty());
    let (ok, out) = run(data, &["agents", "resume", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("is not stopped"), "{out}");

    let (ok, out) = run(data, &["agents", "stop", "nobody"]);
    assert!(!ok, "{out}");
    assert!(stopped(data).is_empty());

    let rows = operator_rows(data);
    let kinds: Vec<&str> = rows
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| *k != "chain_head" && *k != "operator_command")
        .collect();
    assert_eq!(kinds, ["agent_stopped", "agent_stopped", "agent_resumed"]);
    let revoked: Vec<_> = rows
        .iter()
        .filter(|(k, _)| k == "agent_stopped")
        .map(|(_, p)| p["grants_revoked"].as_u64().unwrap())
        .collect();
    assert_eq!(revoked, [0, 1]);
    assert_eq!(rows.last().unwrap().0, "chain_head", "the lane is sealed");
}
