//! `wirken sessions verify` rebuilds the tool set a session was
//! offered the way the agent was built when it ran, so a session
//! recorded correctly verifies clean.
//!
//! Each case records a real session through `wirken ask` against a
//! scripted model, then verifies it through the CLI with nothing
//! running: no gateway, and the model already gone.

mod common;

use std::path::Path;
use std::process::Output;

use common::{ScriptedModel, register_agent, wirken, write_skill};

/// A tool call, then a reply: two `LlmRequest` rows, each with a
/// `tools_hash`, and one deterministic tool result to re-execute.
fn two_turn_model() -> ScriptedModel {
    ScriptedModel::start(vec![
        serde_json::json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "list_files", "arguments": {"path": "."}}}],
        }),
        serde_json::json!({"role": "assistant", "content": "The workspace is empty."}),
    ])
}

fn ask(data: &Path, agent: &str) {
    let out = wirken(data)
        .args(["ask", "--agent", agent, "-m", "what is in the workspace?"])
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

/// The shape slackbot had: a configured agent whose shared skills
/// narrow its tools. Before verify attached them it recomputed the
/// full surface and reported every `tools_hash` divergent.
#[test]
fn a_configured_agent_session_verifies_clean() {
    let data = tempfile::tempdir().unwrap();
    let model = two_turn_model();
    register_agent(data.path(), "kept", &model);
    write_skill(
        &data.path().join("skills/listing"),
        "listing",
        &["list_files"],
        "Lists the workspace.",
    );
    write_skill(
        &data.path().join("agents/kept/skills/reading"),
        "reading",
        &["read_file"],
        "Reads a file.",
    );
    ask(data.path(), "kept");

    let out = verify(data.path(), "kept");
    let report = text(&out);
    assert_eq!(out.status.code(), Some(0), "{report}");
    assert!(report.contains("events_divergent:    0"), "{report}");
    assert!(report.contains("chain:               OK"), "{report}");
}

/// The `provider.json` default agent, built from the shared skills.
#[test]
fn a_default_agent_session_verifies_clean() {
    let data = tempfile::tempdir().unwrap();
    let model = two_turn_model();
    std::fs::write(
        data.path().join("provider.json"),
        serde_json::json!({
            "provider": "ollama",
            "model": "scripted",
            "base_url": model.base_url,
        })
        .to_string(),
    )
    .unwrap();
    write_skill(
        &data.path().join("skills/listing"),
        "listing",
        &["list_files"],
        "Lists the workspace.",
    );
    ask(data.path(), "default");

    let out = verify(data.path(), "default");
    let report = text(&out);
    assert_eq!(out.status.code(), Some(0), "{report}");
    assert!(report.contains("events_divergent:    0"), "{report}");
}

/// With MCP servers configured, the offered set included definitions
/// that only the running servers know. Verify says it cannot rebuild
/// them, exits with its own code, and calls nothing divergent.
#[test]
fn an_mcp_agent_tools_hash_is_unverifiable_not_divergent() {
    let data = tempfile::tempdir().unwrap();
    let model = two_turn_model();
    register_agent(data.path(), "with-mcp", &model);
    write_skill(
        &data.path().join("skills/listing"),
        "listing",
        &["list_files"],
        "Lists the workspace.",
    );
    ask(data.path(), "with-mcp");
    std::fs::write(
        data.path().join("mcp.json"),
        r#"{"servers": {"files": {"command": "/usr/bin/true"}}}"#,
    )
    .unwrap();

    let out = verify(data.path(), "with-mcp");
    let report = text(&out);
    assert_eq!(out.status.code(), Some(6), "{report}");
    assert!(report.contains("events_divergent:    0"), "{report}");
    assert!(report.contains("tools_hash unverifiable: 2"), "{report}");
    assert!(report.contains("MCP servers configured"), "{report}");
    assert!(report.contains("chain:               OK"), "{report}");
}
