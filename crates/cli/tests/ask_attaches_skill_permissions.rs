//! `wirken ask` builds its agent the way `wirken run` does: the
//! agent's own skills, the shared skills and its preset, attached so
//! their permission blocks narrow what the model is offered.
//!
//! Driven through the binary against a scripted model, so what is
//! asserted is the request the model actually received.

mod common;

use common::{ScriptedModel, offered_tools, register_agent, system_prompt, wirken, write_skill};

#[test]
fn ask_offers_only_the_tools_attached_skills_allow() {
    let data = tempfile::tempdir().unwrap();
    let model = ScriptedModel::start(vec![
        serde_json::json!({"role": "assistant", "content": "Nothing to do."}),
    ]);
    register_agent(data.path(), "narrow", &model);
    // One skill of the agent's own and one shared, each allowing a
    // single tool. Loading the shared directory must add to the
    // agent's skills, not replace them.
    write_skill(
        &data.path().join("agents/narrow/skills/own-listing"),
        "own-listing",
        &["list_files"],
        "MARKER-OWN-SKILL",
    );
    write_skill(
        &data.path().join("skills/shared-reading"),
        "shared-reading",
        &["read_file"],
        "MARKER-SHARED-SKILL",
    );

    let out = wirken(data.path())
        .args(["ask", "--agent", "narrow", "-m", "what is here?"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ask failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let received = model.received();
    let request = received
        .iter()
        .find(|r| r.path.ends_with("/api/chat"))
        .unwrap_or_else(|| panic!("no chat request reached the model: {received:?}"));
    assert_eq!(
        offered_tools(&request.body),
        vec!["list_files".to_string(), "read_file".to_string()],
        "the model is offered the union of the attached skills' tools.allow and nothing else"
    );
    let prompt = system_prompt(&request.body);
    assert!(
        prompt.contains("MARKER-OWN-SKILL"),
        "the agent's own skill survives the shared-skills load"
    );
    assert!(prompt.contains("MARKER-SHARED-SKILL"));
}
