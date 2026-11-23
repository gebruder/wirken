//! `wirken proxy archive redact --session` takes the rows of a session's
//! tool calls with the archived bodies: what a client's tool call said
//! is on the chain, and after the redaction no search and no export
//! finds it, while the chain still verifies and says what was removed.
#![cfg(target_os = "linux")]

mod common;

use std::process::{Command, Stdio};

use common::wirken;
use wirken_audit::{
    AuditSigningKey, ChainHeadReason, SessionEvent, SessionId, SessionLog, SqliteSessionLog,
};

const LANE: &str = "proxy-0a0a0a0a-work";
const OTHER: &str = "proxy-0a0a0a0a-other";

fn event(value: serde_json::Value) -> SessionEvent {
    serde_json::from_value(value).unwrap()
}

/// A signed chain as the gateway writes one: two lanes, each with a
/// client's tool call whose arguments and output name a heron.
fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let signer = std::sync::Arc::new(AuditSigningKey::load_or_create(tmp.path()).unwrap());
    let log = SqliteSessionLog::open_with_signer(&tmp.path().join("audit.db"), signer).unwrap();
    for (lane, note) in [(LANE, "heron-one"), (OTHER, "heron-two")] {
        let handle = log.handle_for(SessionId::new(lane.to_string()));
        for value in [
            serde_json::json!({"kind":"assistant_tool_calls","agent_id":"default",
                "sender_id":"proxy-token:0a0a0a0a",
                "calls":[{"id":"toolu_1","name":"mcp_notes_read",
                          "arguments": format!("{{\"name\":\"{note}\"}}")}]}),
            serde_json::json!({"kind":"permission_approved","action_key":"mcp:mcp_notes_read",
                "agent_id":"default","approved_by":"operator:test","scope":"one_shot",
                "approved_via":{"kind":"cli"}}),
            serde_json::json!({"kind":"tool_result","call_id":"toolu_1",
                "tool_name":"mcp_notes_read","output": format!("the {note} note"),
                "success":true,"agent_id":"default"}),
        ] {
            log.append(&handle, wirken_audit::TrustLevel::System, event(value))
                .unwrap();
        }
        log.emit_chain_head(&handle, ChainHeadReason::SessionEnd)
            .unwrap();
    }
    tmp
}

fn at_terminal(data: &std::path::Path, args: &[&str]) -> String {
    let line = std::iter::once(env!("CARGO_BIN_EXE_wirken").to_string())
        .chain(args.iter().map(|a| format!("'{a}'")))
        .collect::<Vec<_>>()
        .join(" ");
    let out = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", data)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("script, for a pseudo-terminal");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn search(data: &std::path::Path, text: &str) -> Vec<String> {
    let out = wirken(data)
        .args(["sessions", "search", text, "--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let found: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    found["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["session"].as_str().unwrap().to_string())
        .collect()
}

fn export(data: &std::path::Path, lane: &str) -> String {
    let out = wirken(data)
        .args(["sessions", "export", lane, "--format", "atif"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    document.to_string()
}

#[test]
fn redacting_a_session_takes_its_tool_call_rows() {
    let tmp = fixture();
    let data = tmp.path();
    assert_eq!(search(data, "heron-one"), vec![LANE, LANE]);
    assert!(export(data, LANE).contains("heron-one"));

    let said = at_terminal(
        data,
        &[
            "proxy",
            "archive",
            "redact",
            "--session",
            LANE,
            "--reason",
            "subject request",
        ],
    );
    assert!(said.contains("2 rows of tool calls rewritten"), "{said}");

    // Nothing of the call is found or exported, by its arguments or its
    // output. The other session is as it was.
    assert!(search(data, "heron-one").is_empty());
    assert!(search(data, "heron").iter().all(|lane| lane == OTHER));
    let exported = export(data, LANE);
    assert!(!exported.contains("heron"), "{exported}");
    assert!(
        exported.contains("mcp_notes_read"),
        "the call is still there"
    );
    assert_eq!(search(data, "heron-two"), vec![OTHER, OTHER]);

    // The chain verifies, and says which rows were rewritten, by whom
    // and why. The rows keep the call's id, tool and outcome.
    let verify = wirken(data)
        .args(["sessions", "verify", LANE])
        .output()
        .unwrap();
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("chain: OK"));
    let audit = wirken(data)
        .args(["audit", "verify", "--require-signed"])
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "{}",
        String::from_utf8_lossy(&audit.stdout)
    );

    let log = SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let rows = log
        .get_since(&log.handle_for(SessionId::new(LANE.to_string())), 0)
        .unwrap();
    let records: Vec<_> = rows
        .iter()
        .filter_map(|row| match &row.event {
            SessionEvent::ChainHead {
                redaction: Some(record),
                ..
            } => Some(record.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![0, 3]
    );
    assert!(records.iter().all(|r| r.reason == "subject request"));
    assert!(records.iter().all(|r| !r.operator.is_empty()));
    assert!(rows.iter().any(|row| matches!(
        &row.event,
        SessionEvent::ToolResult { call_id, tool_name, output, success: true, .. }
            if call_id == "toolu_1" && tool_name == "mcp_notes_read" && output == "[redacted]"
    )));

    // A second redaction rewrites nothing more.
    let again = at_terminal(
        data,
        &[
            "proxy",
            "archive",
            "redact",
            "--session",
            LANE,
            "--reason",
            "again",
        ],
    );
    assert!(!again.contains("rewritten"), "{again}");
}
