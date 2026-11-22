//! `wirken sessions export --format atif` writes a session an agent
//! ran as a valid trajectory: the user's message and the agent's
//! answer, in order, with the model that gave it.

mod common;

use common::{ScriptedModel, register_agent, wirken};

#[test]
fn an_agent_session_is_exported_as_a_valid_trajectory() {
    let data = tempfile::tempdir().unwrap();
    let model = ScriptedModel::start(vec![
        serde_json::json!({"role": "assistant", "content": "Nothing to do here."}),
    ]);
    register_agent(data.path(), "narrow", &model);
    let out = wirken(data.path())
        .args(["ask", "--agent", "narrow", "-m", "what is here?"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ask failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The session the ask ran on, read from the log.
    let conn = rusqlite::Connection::open(data.path().join("audit.db")).unwrap();
    let session: String = conn
        .query_row(
            "SELECT session_id FROM session_events WHERE payload LIKE '%\"kind\":\"user_message\"%' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);

    let file = data.path().join("session.atif.json");
    let out = wirken(data.path())
        .args([
            "sessions", "export", &session, "--format", "atif", "--output",
        ])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        wirken_audit::atif::validate(&document),
        Vec::<String>::new()
    );
    assert_eq!(document["schema_version"], "ATIF-v1.8");
    assert_eq!(document["session_id"], session.as_str());
    assert_eq!(document["agent"]["name"], "wirken");
    assert_eq!(document["extra"]["wirken"]["kind"], "agent");
    let steps = document["steps"].as_array().unwrap();
    let said: Vec<(&str, &str)> = steps
        .iter()
        .map(|s| {
            (
                s["source"].as_str().unwrap(),
                s["message"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        said,
        [("user", "what is here?"), ("agent", "Nothing to do here.")]
    );
    assert!(steps[1]["model_name"].is_string());

    // Another format is not one this command writes.
    let other = wirken(data.path())
        .args(["sessions", "export", &session, "--format", "jsonl"])
        .output()
        .unwrap();
    assert!(!other.status.success());
}
