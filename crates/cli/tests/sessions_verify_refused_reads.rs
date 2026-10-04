//! `wirken sessions verify` never re-executes a workspace read today's
//! gates refuse.
//!
//! A read refused when the session ran is recorded as a refusal, and a
//! refusal today agrees with it. A read that succeeded then, under
//! permissions that no longer hold, is not run again: running it is the
//! read policy now refuses, so the row is unverifiable.

mod common;

use std::path::Path;
use std::process::Output;

use common::{ScriptedModel, register_agent, wirken, write_skill_reading};

/// The model reads `secret.txt` from the workspace root, then replies.
fn reads_secret() -> ScriptedModel {
    ScriptedModel::start(vec![
        serde_json::json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "secret.txt"}}}],
        }),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ])
}

fn setup(data: &Path, agent: &str, model: &ScriptedModel, read_paths: &[&str]) {
    register_agent(data, agent, model);
    let workspace = data.join("agents").join(agent).join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("secret.txt"), "recorded contents\n").unwrap();
    write_skill_reading(
        &data.join("skills/reader"),
        "reader",
        &["read_file"],
        read_paths,
        "Reads files.",
    );
    let out = wirken(data)
        .args(["ask", "--agent", agent, "-m", "read the secret"])
        .output()
        .unwrap();
    assert!(out.status.success(), "ask failed: {}", text(&out));
}

fn verify(data: &Path, session: &str) -> Output {
    wirken(data)
        .args(["sessions", "verify", session])
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Refused when recorded, refused today: the row verifies, and the
/// file is never read.
#[test]
fn a_recorded_refusal_agrees_with_todays_refusal() {
    let data = tempfile::tempdir().unwrap();
    let model = reads_secret();
    setup(data.path(), "narrow", &model, &["<workspace>/open"]);

    let out = verify(data.path(), "narrow");
    let report = text(&out);
    assert_eq!(out.status.code(), Some(0), "{report}");
    assert!(report.contains("events_divergent:    0"), "{report}");
    assert!(!report.contains("reads not re-executed"), "{report}");
}

/// Allowed when recorded, refused today: the read is not run again.
/// The file changed since, so a re-execution would surface as a
/// divergence; the row is unverifiable with the reason instead.
#[test]
fn a_recorded_read_policy_now_refuses_is_unverifiable() {
    let data = tempfile::tempdir().unwrap();
    let model = reads_secret();
    setup(data.path(), "narrowed", &model, &["<workspace>"]);
    std::fs::write(
        data.path().join("agents/narrowed/workspace/secret.txt"),
        "changed since the session\n",
    )
    .unwrap();
    write_skill_reading(
        &data.path().join("skills/reader"),
        "reader",
        &["read_file"],
        &["<workspace>/open"],
        "Reads files.",
    );

    let out = verify(data.path(), "narrowed");
    let report = text(&out);
    assert!(report.contains("events_divergent:    0"), "{report}");
    assert!(
        report.contains("reads not re-executed: 1 (policy now refuses this path)"),
        "{report}"
    );
    assert!(report.contains("chain:               OK"), "{report}");
}
