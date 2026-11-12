//! `wirken audit log --all` writes every row the log holds. Without it
//! the command writes the newest 50, which is its default.

mod common;

use common::wirken;
use wirken_audit::{AuditLog, SessionId, SessionLog, TrustLevel};

fn rows_printed(data: &std::path::Path, extra: &[&str]) -> usize {
    let mut args = vec!["audit", "log", "--format", "json"];
    args.extend_from_slice(extra);
    let out = wirken(data).args(&args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    parsed["events"].as_array().expect("events").len()
}

#[test]
fn all_exports_every_row_and_the_default_stays_fifty() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    let db = data.join("audit.db");
    {
        let log = AuditLog::open(&db).unwrap();
        let inner = log.session_log();
        let handle = inner.handle_for(SessionId::new("default/webchat/c-1"));
        for i in 0..120 {
            inner
                .append(
                    &handle,
                    TrustLevel::User,
                    wirken_audit::SessionEvent::UserMessage {
                        content: format!("message {i}"),
                        inbound_id: None,
                        adapter_id: None,
                        sender_id: None,
                    },
                )
                .unwrap();
        }
    }
    let held: i64 = rusqlite::Connection::open(&db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    let held = held as usize;
    assert!(held >= 120, "{held}");

    assert_eq!(rows_printed(data, &[]), 50);
    assert_eq!(rows_printed(data, &["--all"]), held);

    let both = wirken(data)
        .args(["audit", "log", "--all", "-n", "5"])
        .output()
        .unwrap();
    assert!(!both.status.success(), "--all and -n are exclusive");
}
