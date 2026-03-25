use std::path::PathBuf;
use tempfile::TempDir;

use crate::conversation::{Conversation, Role};
use crate::llm::{LlmConfig, LlmResponse};
use crate::skill::{Skill, SkillLoader};
use crate::tool::ToolRegistry;

// ---------------------------------------------------------------------------
// Conversation
// ---------------------------------------------------------------------------

#[test]
fn conversation_add_messages() {
    let mut conv = Conversation::new(10_000);
    conv.add_user_message("Hello");
    conv.add_assistant_message("Hi there!");

    assert_eq!(conv.len(), 2);
    assert_eq!(conv.messages()[0].role, Role::User);
    assert_eq!(conv.messages()[1].role, Role::Assistant);
}

#[test]
fn conversation_system_prompt() {
    let mut conv = Conversation::new(10_000);
    conv.set_system_prompt("You are a helpful assistant.");
    conv.add_user_message("Hello");

    assert_eq!(conv.len(), 2);
    assert_eq!(conv.messages()[0].role, Role::System);
    assert_eq!(conv.messages()[0].content, "You are a helpful assistant.");
}

#[test]
fn conversation_system_prompt_replaced() {
    let mut conv = Conversation::new(10_000);
    conv.set_system_prompt("First prompt");
    conv.set_system_prompt("Second prompt");

    let system_msgs: Vec<_> = conv
        .messages()
        .iter()
        .filter(|m| m.role == Role::System)
        .collect();
    assert_eq!(system_msgs.len(), 1);
    assert_eq!(system_msgs[0].content, "Second prompt");
}

#[test]
fn conversation_tool_calls() {
    let mut conv = Conversation::new(10_000);
    conv.add_user_message("What's the weather?");

    conv.add_assistant_tool_calls(vec![crate::conversation::ToolCallRequest {
        id: "call_1".into(),
        name: "exec".into(),
        arguments: r#"{"command":"curl wttr.in/London"}"#.into(),
    }]);

    conv.add_tool_result("call_1", "Sunny, 22°C");

    assert_eq!(conv.len(), 3);
    assert_eq!(conv.messages()[2].role, Role::Tool);
    assert_eq!(conv.messages()[2].content, "Sunny, 22°C");
}

#[test]
fn conversation_compact() {
    let mut conv = Conversation::new(100); // Very small budget
    conv.set_system_prompt("system");

    for i in 0..50 {
        conv.add_user_message(&format!("message {i}"));
        conv.add_assistant_message(&format!("response {i}"));
    }

    assert!(conv.over_budget());
    conv.compact();

    // System prompt should be preserved
    assert_eq!(conv.messages()[0].role, Role::System);
    // Should be smaller now
    assert!(conv.len() < 101);
}

#[test]
fn conversation_approx_tokens() {
    let mut conv = Conversation::new(10_000);
    conv.add_user_message("hello world"); // 11 chars ≈ 3 tokens
    assert!(conv.approx_tokens() > 0);
    assert!(conv.approx_tokens() < 100);
}

#[test]
fn conversation_clear() {
    let mut conv = Conversation::new(10_000);
    conv.set_system_prompt("system");
    conv.add_user_message("hello");
    conv.clear();
    assert!(conv.is_empty());
}

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

#[test]
fn load_skill_from_markdown() {
    let tmp = TempDir::new().unwrap();
    let skill_dir = tmp.path().join("weather");
    std::fs::create_dir(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: weather
description: "Get current weather via wttr.in"
metadata: { "openclaw": { "emoji": "☔", "requires": { "bins": ["curl"] } } }
---

# Weather Skill

Use `curl wttr.in/{city}` to get current weather.

## Examples

- "What's the weather in London?"
- "Temperature in Tokyo"
"#,
    )
    .unwrap();

    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "weather");
    assert_eq!(skills[0].description, "Get current weather via wttr.in");
    assert_eq!(skills[0].required_bins, vec!["curl"]);
    assert!(skills[0].body.contains("Weather Skill"));
}

#[test]
fn load_skill_no_frontmatter() {
    let tmp = TempDir::new().unwrap();
    let skill_dir = tmp.path().join("notes");
    std::fs::create_dir(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        "# Just a plain skill\n\nNo frontmatter here.",
    )
    .unwrap();

    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "notes"); // Falls back to directory name
    assert!(skills[0].body.contains("Just a plain skill"));
}

#[test]
fn load_skill_no_required_bins() {
    let tmp = TempDir::new().unwrap();
    let skill_dir = tmp.path().join("summarize");
    std::fs::create_dir(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: summarize
description: "Summarize text"
---

Summarize the given text concisely.
"#,
    )
    .unwrap();

    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert_eq!(skills.len(), 1);
    assert!(skills[0].required_bins.is_empty());
    assert!(skills[0].available); // No bins required = always available
}

#[test]
fn load_skill_missing_bin() {
    let tmp = TempDir::new().unwrap();
    let skill_dir = tmp.path().join("impossible");
    std::fs::create_dir(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: impossible
description: "Needs a nonexistent binary"
metadata: { "openclaw": { "requires": { "bins": ["nonexistent_binary_xyz_999"] } } }
---

This skill requires a binary that doesn't exist.
"#,
    )
    .unwrap();

    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert_eq!(skills.len(), 1);
    assert!(!skills[0].available);
}

#[test]
fn load_multiple_skills() {
    let tmp = TempDir::new().unwrap();

    for name in &["alpha", "beta", "gamma"] {
        let dir = tmp.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: skill {name}\n---\n\nBody of {name}."),
        )
        .unwrap();
    }

    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert_eq!(skills.len(), 3);
    // Sorted by name
    assert_eq!(skills[0].name, "alpha");
    assert_eq!(skills[1].name, "beta");
    assert_eq!(skills[2].name, "gamma");
}

#[test]
fn load_empty_dir() {
    let tmp = TempDir::new().unwrap();
    let skills = SkillLoader::load_dir(tmp.path()).unwrap();
    assert!(skills.is_empty());
}

#[test]
fn load_nonexistent_dir() {
    let skills = SkillLoader::load_dir(&PathBuf::from("/nonexistent/path")).unwrap();
    assert!(skills.is_empty());
}

#[test]
fn skill_prompt_generation() {
    let skills = vec![
        Skill {
            name: "weather".into(),
            description: "Get weather".into(),
            required_bins: vec!["curl".into()],
            body: "Use curl wttr.in".into(),
            path: PathBuf::new(),
            available: true,
        },
        Skill {
            name: "unavailable".into(),
            description: "Not available".into(),
            required_bins: vec!["nonexistent".into()],
            body: "Should not appear".into(),
            path: PathBuf::new(),
            available: false,
        },
    ];

    let prompt = SkillLoader::build_prompt(&skills);
    assert!(prompt.contains("weather"));
    assert!(prompt.contains("Use curl wttr.in"));
    assert!(!prompt.contains("unavailable"));
    assert!(!prompt.contains("Should not appear"));
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tool_exec_command() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf());

    let result = tools
        .execute("exec", r#"{"command":"echo hello world"}"#)
        .await
        .unwrap();
    assert!(result.success);
    assert!(result.output.contains("hello world"));
}

#[tokio::test]
async fn tool_exec_failing_command() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf());

    let result = tools
        .execute("exec", r#"{"command":"false"}"#)
        .await
        .unwrap();
    assert!(!result.success);
}

#[tokio::test]
async fn tool_read_write_file() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf());

    // Write
    let write_result = tools
        .execute(
            "write_file",
            r#"{"path":"test.txt","content":"hello from wirken"}"#,
        )
        .await
        .unwrap();
    assert!(write_result.success);
    assert!(write_result.output.contains("17 bytes"));

    // Read
    let read_result = tools
        .execute("read_file", r#"{"path":"test.txt"}"#)
        .await
        .unwrap();
    assert!(read_result.success);
    assert_eq!(read_result.output, "hello from wirken");
}

#[tokio::test]
async fn tool_read_nonexistent() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf());

    let result = tools
        .execute("read_file", r#"{"path":"nope.txt"}"#)
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result.output.contains("Error reading"));
}

#[tokio::test]
async fn tool_list_files() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("a.txt"), "").unwrap();
    std::fs::write(tmp.path().join("b.txt"), "").unwrap();
    std::fs::create_dir(tmp.path().join("subdir")).unwrap();

    let tools = ToolRegistry::new(tmp.path().to_path_buf());
    let result = tools
        .execute("list_files", r#"{"path":"."}"#)
        .await
        .unwrap();
    assert!(result.success);
    assert!(result.output.contains("a.txt"));
    assert!(result.output.contains("b.txt"));
    assert!(result.output.contains("subdir/"));
}

#[tokio::test]
async fn tool_not_found() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf());

    let result = tools.execute("nonexistent_tool", "{}").await;
    assert!(result.is_err());
}

#[test]
fn tool_definitions_include_all_builtins() {
    let tools = ToolRegistry::new(PathBuf::from("/tmp"));
    let defs = tools.definitions();

    let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"exec"));
    assert!(names.contains(&"read_file"));
    assert!(names.contains(&"write_file"));
    assert!(names.contains(&"list_files"));
}

// ---------------------------------------------------------------------------
// LLM config
// ---------------------------------------------------------------------------

#[test]
fn llm_config_openai() {
    let config = LlmConfig::openai("gpt-4o");
    assert_eq!(config.provider, "openai");
    assert_eq!(config.model, "gpt-4o");
    assert!(config.base_url.contains("openai.com"));
}

#[test]
fn llm_config_ollama() {
    let config = LlmConfig::ollama("llama3");
    assert_eq!(config.provider, "ollama");
    assert_eq!(config.model, "llama3");
    assert!(config.base_url.contains("localhost:11434"));
}

#[test]
fn llm_config_anthropic() {
    let config = LlmConfig::anthropic("claude-sonnet-4-20250514");
    assert_eq!(config.provider, "anthropic");
    assert!(config.base_url.contains("anthropic.com"));
}

#[test]
fn llm_config_custom() {
    let config = LlmConfig::custom("http://my-server:8080/v1", "my-model");
    assert_eq!(config.provider, "custom");
    assert_eq!(config.base_url, "http://my-server:8080/v1");
}

// ---------------------------------------------------------------------------
// LLM response parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_text_response() {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Hello! How can I help?"
            }
        }]
    });

    let response = crate::llm::parse_completion_response(&body).unwrap();
    match response {
        LlmResponse::Text(text) => assert_eq!(text, "Hello! How can I help?"),
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn parse_tool_call_response() {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                        "name": "exec",
                        "arguments": "{\"command\":\"date\"}"
                    }
                }]
            }
        }]
    });

    let response = crate::llm::parse_completion_response(&body).unwrap();
    match response {
        LlmResponse::ToolCalls(calls) => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id, "call_abc123");
            assert_eq!(calls[0].name, "exec");
            assert!(calls[0].arguments.contains("date"));
        }
        other => panic!("expected ToolCalls, got {other:?}"),
    }
}

#[test]
fn parse_empty_response() {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": ""
            }
        }]
    });

    let response = crate::llm::parse_completion_response(&body).unwrap();
    assert!(matches!(response, LlmResponse::Empty));
}

// ---------------------------------------------------------------------------
// Anthropic response parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_anthropic_text_response() {
    let body = serde_json::json!({
        "content": [{
            "type": "text",
            "text": "Hello! How can I help you today?"
        }],
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "end_turn"
    });

    let response = crate::llm::parse_anthropic_response(&body).unwrap();
    match response {
        LlmResponse::Text(text) => assert_eq!(text, "Hello! How can I help you today?"),
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn parse_anthropic_tool_use_response() {
    let body = serde_json::json!({
        "content": [{
            "type": "tool_use",
            "id": "toolu_01A",
            "name": "exec",
            "input": {"command": "date"}
        }],
        "stop_reason": "tool_use"
    });

    let response = crate::llm::parse_anthropic_response(&body).unwrap();
    match response {
        LlmResponse::ToolCalls(calls) => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id, "toolu_01A");
            assert_eq!(calls[0].name, "exec");
            assert!(calls[0].arguments.contains("date"));
        }
        other => panic!("expected ToolCalls, got {other:?}"),
    }
}

#[test]
fn parse_anthropic_mixed_response() {
    let body = serde_json::json!({
        "content": [
            {"type": "text", "text": "Let me check. "},
            {"type": "tool_use", "id": "toolu_01B", "name": "exec", "input": {"command": "date"}}
        ],
        "stop_reason": "tool_use"
    });

    // Tool calls take priority over text
    let response = crate::llm::parse_anthropic_response(&body).unwrap();
    assert!(matches!(response, LlmResponse::ToolCalls(_)));
}

// ---------------------------------------------------------------------------
// Agent runtime (unit — no live LLM)
// ---------------------------------------------------------------------------

#[test]
fn agent_loads_skills() {
    let tmp = TempDir::new().unwrap();

    // Create workspace
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();

    // Create skills
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir(&skills_dir).unwrap();
    let weather = skills_dir.join("weather");
    std::fs::create_dir(&weather).unwrap();
    std::fs::write(
        weather.join("SKILL.md"),
        "---\nname: weather\ndescription: get weather\n---\nUse curl wttr.in",
    )
    .unwrap();

    let mut agent = crate::runtime::Agent::new(
        "test-agent".into(),
        workspace,
        LlmConfig::ollama("test"),
        None,
    );

    let count = agent.load_skills(&skills_dir).unwrap();
    assert_eq!(count, 1);
    assert_eq!(agent.skills().len(), 1);
    assert_eq!(agent.skills()[0].name, "weather");
}

#[test]
fn agent_conversation_tracking() {
    let tmp = TempDir::new().unwrap();

    let agent = crate::runtime::Agent::new(
        "test".into(),
        tmp.path().to_path_buf(),
        LlmConfig::ollama("test"),
        None,
    );

    // System prompt is set on creation
    assert!(agent.conversation_len() > 0);
}
