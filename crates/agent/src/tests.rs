use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

use crate::conversation::{Conversation, Role};
use crate::llm::{LlmConfig, LlmResponse};
use crate::skill::{Skill, SkillLoader};
use crate::tool::{ToolConfig, ToolRegistry};
use wirken_audit::{SessionLog, SqliteSessionLog};

/// Test helper: in-memory session log shared by every test that
/// constructs an Agent. Item 2 slice 1 made the session log a
/// required dependency of `Agent::new`. Tests that don't care about
/// the log just hand the agent a fresh in-memory store.
fn test_session_log() -> Arc<dyn SessionLog> {
    Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"))
}

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

    conv.add_tool_result("call_1", "exec", "Sunny, 22°C");

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
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());

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
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());

    let result = tools
        .execute("exec", r#"{"command":"false"}"#)
        .await
        .unwrap();
    assert!(!result.success);
}

#[tokio::test]
async fn tool_read_write_file() {
    let tmp = TempDir::new().unwrap();
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());

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
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());

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

    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());
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
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), ToolConfig::default());

    let result = tools.execute("nonexistent_tool", "{}").await;
    assert!(result.is_err());
}

#[test]
fn tool_definitions_include_all_builtins() {
    let tools = ToolRegistry::new(PathBuf::from("/tmp"), ToolConfig::default());
    let defs = tools.definitions();

    let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"exec"));
    assert!(names.contains(&"read_file"));
    assert!(names.contains(&"write_file"));
    assert!(names.contains(&"list_files"));
    assert!(names.contains(&"web_search"));
    assert!(names.contains(&"generate_image"));
}

#[tokio::test]
async fn generate_image_requires_api_key() {
    let tmp = TempDir::new().unwrap();
    let config = ToolConfig {
        api_key: None,
        provider: Some("openai".into()),
        base_url: Some("https://api.openai.com/v1".into()),
        sandbox: Default::default(),
    };
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), config);

    let result = tools
        .execute("generate_image", r#"{"prompt":"a cat"}"#)
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result.output.contains("API key"));
}

#[tokio::test]
async fn generate_image_requires_openai_provider() {
    let tmp = TempDir::new().unwrap();
    let config = ToolConfig {
        api_key: Some("test-key".into()),
        provider: Some("anthropic".into()),
        base_url: Some("https://api.anthropic.com/v1".into()),
        sandbox: Default::default(),
    };
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), config);

    let result = tools
        .execute("generate_image", r#"{"prompt":"a cat"}"#)
        .await
        .unwrap();
    assert!(!result.success);
    assert!(result.output.contains("not supported"));
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
// Gemini response parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_gemini_text_response() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [{"text": "Hello from Gemini!"}],
                "role": "model"
            }
        }]
    });

    let response = crate::llm::parse_gemini_response(&body).unwrap();
    match response {
        LlmResponse::Text(text) => assert_eq!(text, "Hello from Gemini!"),
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn parse_gemini_function_call_response() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "name": "exec",
                        "args": {"command": "date"}
                    }
                }],
                "role": "model"
            }
        }]
    });

    let response = crate::llm::parse_gemini_response(&body).unwrap();
    match response {
        LlmResponse::ToolCalls(calls) => {
            assert_eq!(calls.len(), 1);
            assert!(calls[0].id.starts_with("gemini_"));
            assert_eq!(calls[0].name, "exec");
            assert!(calls[0].arguments.contains("date"));
        }
        other => panic!("expected ToolCalls, got {other:?}"),
    }
}

#[test]
fn parse_gemini_mixed_response() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [
                    {"text": "Let me run that."},
                    {"functionCall": {"name": "exec", "args": {"command": "ls"}}}
                ],
                "role": "model"
            }
        }]
    });

    let response = crate::llm::parse_gemini_response(&body).unwrap();
    assert!(matches!(response, LlmResponse::ToolCalls(_)));
}

#[test]
fn parse_gemini_empty_response() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [{"text": ""}],
                "role": "model"
            }
        }]
    });

    let response = crate::llm::parse_gemini_response(&body).unwrap();
    assert!(matches!(response, LlmResponse::Empty));
}

// ---------------------------------------------------------------------------
// Bedrock response parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_bedrock_text_response() {
    let body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Hello from Bedrock!"}]
            }
        },
        "stopReason": "end_turn"
    });

    let response = crate::llm::parse_bedrock_response(&body).unwrap();
    match response {
        LlmResponse::Text(text) => assert_eq!(text, "Hello from Bedrock!"),
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn parse_bedrock_tool_use_response() {
    let body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{
                    "toolUse": {
                        "toolUseId": "tooluse_abc123",
                        "name": "exec",
                        "input": {"command": "date"}
                    }
                }]
            }
        },
        "stopReason": "tool_use"
    });

    let response = crate::llm::parse_bedrock_response(&body).unwrap();
    match response {
        LlmResponse::ToolCalls(calls) => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id, "tooluse_abc123");
            assert_eq!(calls[0].name, "exec");
            assert!(calls[0].arguments.contains("date"));
        }
        other => panic!("expected ToolCalls, got {other:?}"),
    }
}

#[test]
fn parse_bedrock_mixed_response() {
    let body = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "Let me check."},
                    {"toolUse": {"toolUseId": "tu_1", "name": "exec", "input": {"command": "ls"}}}
                ]
            }
        },
        "stopReason": "tool_use"
    });

    let response = crate::llm::parse_bedrock_response(&body).unwrap();
    assert!(matches!(response, LlmResponse::ToolCalls(_)));
}

// ---------------------------------------------------------------------------
// LlmConfig constructors for new providers
// ---------------------------------------------------------------------------

#[test]
fn llm_config_gemini() {
    let config = LlmConfig::gemini("gemini-2.0-flash");
    assert_eq!(config.provider, "gemini");
    assert_eq!(config.model, "gemini-2.0-flash");
    assert!(
        config
            .base_url
            .contains("generativelanguage.googleapis.com")
    );
    assert!(config.region.is_none());
}

#[test]
fn llm_config_bedrock() {
    let config = LlmConfig::bedrock("anthropic.claude-sonnet-4-20250514-v2:0", "us-west-2");
    assert_eq!(config.provider, "bedrock");
    assert_eq!(config.model, "anthropic.claude-sonnet-4-20250514-v2:0");
    assert!(config.base_url.contains("us-west-2"));
    assert_eq!(config.region.as_deref(), Some("us-west-2"));
}

#[test]
fn llm_config_from_provider_preserves_name() {
    let config = LlmConfig::from_provider(
        "anthropic",
        "https://api.anthropic.com/v1",
        "claude-sonnet-4-20250514",
    );
    assert_eq!(config.provider, "anthropic");
    assert_eq!(config.base_url, "https://api.anthropic.com/v1");
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
        test_session_log(),
    )
    .unwrap();

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
        test_session_log(),
    )
    .unwrap();

    // System prompt is set on creation
    assert!(agent.conversation_len() > 0);
}

// ---------------------------------------------------------------------------
// Item 2 slice 1: durability writes to the session log
// ---------------------------------------------------------------------------

mod durability {
    use std::sync::Arc;

    use tempfile::TempDir;
    use wirken_audit::{
        SessionEvent, SessionId, SessionLog, SessionVerifyResult, SqliteSessionLog, ToolCallRecord,
        TrustLevel,
    };

    use crate::conversation::ToolCallRequest;
    use crate::llm::LlmConfig;

    fn fresh_agent_with_log() -> (crate::runtime::Agent, Arc<dyn SessionLog>) {
        let tmp = TempDir::new().unwrap();
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let agent = crate::runtime::Agent::new(
            "durability-test".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();
        (agent, log)
    }

    #[test]
    fn agent_creates_handle_for_its_own_id() {
        let (agent, log) = fresh_agent_with_log();
        // The agent's session id is its own id. Mint an independent
        // handle from the same log and verify the session is empty
        // before we write anything.
        let h = log.handle_for(SessionId::new(agent.id.clone()));
        assert_eq!(log.last_index(&h).unwrap(), None);
    }

    #[test]
    fn log_event_appends_to_agent_session() {
        let (agent, log) = fresh_agent_with_log();
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "hello".into(),
                    inbound_id: None,
                },
            )
            .unwrap();

        let h = log.handle_for(SessionId::new(agent.id.clone()));
        assert_eq!(log.last_index(&h).unwrap(), Some(0));
        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows.len(), 1);
        match &rows[0].event {
            SessionEvent::UserMessage { content, .. } => assert_eq!(content, "hello"),
            other => panic!("expected UserMessage, got {other:?}"),
        }
        assert_eq!(rows[0].trust, TrustLevel::User);
    }

    #[test]
    fn full_turn_event_sequence_round_trips_in_order() {
        // Simulate the exact sequence process_message would write
        // for one user turn that triggers a single tool call round.
        let (agent, log) = fresh_agent_with_log();

        let calls = vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: r#"{"command":"ls"}"#.into(),
        }];

        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "list files".into(),
                    inbound_id: None,
                },
            )
            .unwrap();
        agent
            .log_event(
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: crate::runtime::Agent::calls_to_records(&calls),
                },
            )
            .unwrap();
        agent
            .log_event(
                TrustLevel::Tool,
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "exec".into(),
                    output: "a.txt\nb.txt".into(),
                    success: true,
                },
            )
            .unwrap();
        agent
            .log_event(
                TrustLevel::System,
                SessionEvent::AssistantMessage {
                    content: "two files".into(),
                },
            )
            .unwrap();

        let h = log.handle_for(SessionId::new(agent.id.clone()));
        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows.len(), 4);

        assert!(matches!(rows[0].event, SessionEvent::UserMessage { .. }));
        assert!(matches!(
            rows[1].event,
            SessionEvent::AssistantToolCalls { .. }
        ));
        assert!(matches!(rows[2].event, SessionEvent::ToolResult { .. }));
        assert!(matches!(
            rows[3].event,
            SessionEvent::AssistantMessage { .. }
        ));

        // Whole chain verifies.
        assert_eq!(
            log.verify(&h).unwrap(),
            SessionVerifyResult::Ok { rows_verified: 4 }
        );
    }

    #[test]
    fn calls_to_records_preserves_fields() {
        let calls = vec![
            ToolCallRequest {
                id: "c1".into(),
                name: "read_file".into(),
                arguments: r#"{"path":"a"}"#.into(),
            },
            ToolCallRequest {
                id: "c2".into(),
                name: "exec".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            },
        ];
        let records = crate::runtime::Agent::calls_to_records(&calls);
        assert_eq!(
            records,
            vec![
                ToolCallRecord {
                    id: "c1".into(),
                    name: "read_file".into(),
                    arguments: r#"{"path":"a"}"#.into(),
                },
                ToolCallRecord {
                    id: "c2".into(),
                    name: "exec".into(),
                    arguments: r#"{"command":"ls"}"#.into(),
                },
            ]
        );
    }

    #[test]
    fn two_agents_have_isolated_sessions() {
        // Two agents share the same session log but have different
        // ids. Their session events are kept apart by the per-session
        // partitioning.
        let tmp = TempDir::new().unwrap();
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());

        let a = crate::runtime::Agent::new(
            "alpha".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();
        let b = crate::runtime::Agent::new(
            "beta".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();

        a.log_event(
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "from alpha".into(),
                inbound_id: None,
            },
        )
        .unwrap();
        b.log_event(
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "from beta".into(),
                inbound_id: None,
            },
        )
        .unwrap();

        let ha = log.handle_for(SessionId::new("alpha"));
        let hb = log.handle_for(SessionId::new("beta"));

        let rows_a = log.get_since(&ha, 0).unwrap();
        let rows_b = log.get_since(&hb, 0).unwrap();
        assert_eq!(rows_a.len(), 1);
        assert_eq!(rows_b.len(), 1);

        match (&rows_a[0].event, &rows_b[0].event) {
            (
                SessionEvent::UserMessage { content: ca, .. },
                SessionEvent::UserMessage { content: cb, .. },
            ) => {
                assert_eq!(ca, "from alpha");
                assert_eq!(cb, "from beta");
            }
            _ => panic!("expected user messages on both"),
        }
    }

    #[test]
    fn session_log_for_test_returns_same_arc() {
        // Sanity: the test accessor returns the same Arc the agent
        // was constructed with, not a clone of the inner data.
        let (agent, log) = fresh_agent_with_log();
        let inner = agent.session_log_for_test();
        assert!(Arc::ptr_eq(inner, &log));
    }
}

// ---------------------------------------------------------------------------
// Item 2 slice 2: wake / refuse-and-surface / factory
// ---------------------------------------------------------------------------

mod wake {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use tempfile::TempDir;
    use wirken_audit::{
        SessionEvent, SessionId, SessionLog, SqliteSessionLog, ToolCallRecord, TrustLevel,
    };

    use crate::factory::{AgentFactory, AgentStaticConfig, CacheMode, session_id_for};
    use crate::llm::LlmConfig;
    use crate::runtime::PARTIAL_RESULT_LOST_SENTINEL;

    fn make_log() -> Arc<dyn SessionLog> {
        Arc::new(SqliteSessionLog::open_in_memory().unwrap())
    }

    fn make_factory(agent_id: &str, log: Arc<dyn SessionLog>) -> (Arc<AgentFactory>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mut configs = HashMap::new();
        configs.insert(
            agent_id.to_string(),
            AgentStaticConfig {
                agent_id: agent_id.to_string(),
                workspace: tmp.path().to_path_buf(),
                llm_config: LlmConfig::ollama("test"),
                api_key: None,
                skills: Vec::new(),
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: None,
                allowed_subagents: Default::default(),
            },
        );
        (AgentFactory::new(configs, log, None), tmp)
    }

    fn seed_user_message(log: &dyn SessionLog, session: &str, content: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: content.into(),
                inbound_id: None,
            },
        )
        .unwrap();
    }

    fn seed_assistant_message(log: &dyn SessionLog, session: &str, content: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::AssistantMessage {
                content: content.into(),
            },
        )
        .unwrap();
    }

    fn seed_tool_calls(log: &dyn SessionLog, session: &str, calls: Vec<ToolCallRecord>) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::AssistantToolCalls { calls },
        )
        .unwrap();
    }

    fn seed_tool_result(
        log: &dyn SessionLog,
        session: &str,
        call_id: &str,
        tool_name: &str,
        output: &str,
    ) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::Tool,
            SessionEvent::ToolResult {
                call_id: call_id.into(),
                tool_name: tool_name.into(),
                output: output.into(),
                success: true,
            },
        )
        .unwrap();
    }

    // ---- session_id_for ----------------------------------------------

    #[test]
    fn session_id_for_format() {
        assert_eq!(session_id_for("work", "slack", "C0123"), "work/slack/C0123");
    }

    // ---- empty session ----------------------------------------------

    #[tokio::test]
    async fn wake_empty_session_yields_system_prompt_only() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-empty", log.clone());

        let session = "agent-empty/test/conv-1";
        let agent_arc = factory.wake("agent-empty", session).unwrap();
        let agent = agent_arc.lock().await;
        // System prompt is the only message in the conversation.
        assert_eq!(agent.conversation_len(), 1);
    }

    // ---- replay round-trip ------------------------------------------

    #[tokio::test]
    async fn wake_replays_full_turn_into_conversation() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-replay", log.clone());

        let session = "agent-replay/test/conv-1";
        // Pre-seed a complete turn into the session log.
        seed_user_message(&*log, session, "list files");
        seed_tool_calls(
            &*log,
            session,
            vec![ToolCallRecord {
                id: "c1".into(),
                name: "exec".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            }],
        );
        seed_tool_result(&*log, session, "c1", "exec", "a.txt\nb.txt");
        seed_assistant_message(&*log, session, "two files");

        let agent_arc = factory.wake("agent-replay", session).unwrap();
        let agent = agent_arc.lock().await;
        // System prompt + user + assistant tool_calls + tool result + assistant text = 5
        assert_eq!(agent.conversation_len(), 5);
    }

    // ---- refuse-and-surface -----------------------------------------

    #[tokio::test]
    async fn wake_synthesizes_partial_result_for_missing_tool_result() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-partial", log.clone());

        let session = "agent-partial/test/conv-1";
        // User asked, the LLM emitted two tool calls, only one
        // returned a result before the (simulated) crash.
        seed_user_message(&*log, session, "do two things");
        seed_tool_calls(
            &*log,
            session,
            vec![
                ToolCallRecord {
                    id: "c1".into(),
                    name: "exec".into(),
                    arguments: r#"{"command":"ls"}"#.into(),
                },
                ToolCallRecord {
                    id: "c2".into(),
                    name: "read_file".into(),
                    arguments: r#"{"path":"a.txt"}"#.into(),
                },
            ],
        );
        seed_tool_result(&*log, session, "c1", "exec", "ok");
        // c2 is missing — wake() should synthesize a failure.

        let _agent_arc = factory.wake("agent-partial", session).unwrap();

        // Read the session log directly to confirm the synthetic
        // ToolResult was written.
        let h = log.handle_for(SessionId::new(session));
        let rows = log.get_since(&h, 0).unwrap();
        let tool_results: Vec<_> = rows
            .iter()
            .filter_map(|r| match &r.event {
                SessionEvent::ToolResult {
                    call_id,
                    output,
                    success,
                    ..
                } => Some((call_id.clone(), output.clone(), *success)),
                _ => None,
            })
            .collect();
        assert_eq!(tool_results.len(), 2);
        // c1 is the original (successful) result.
        assert_eq!(tool_results[0].0, "c1");
        assert!(tool_results[0].2);
        // c2 is the synthesized failure with the sentinel prefix.
        assert_eq!(tool_results[1].0, "c2");
        assert!(!tool_results[1].2);
        assert!(tool_results[1].1.starts_with(PARTIAL_RESULT_LOST_SENTINEL));
    }

    #[tokio::test]
    async fn wake_does_nothing_when_all_tool_results_present() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-complete", log.clone());

        let session = "agent-complete/test/conv-1";
        seed_user_message(&*log, session, "task");
        seed_tool_calls(
            &*log,
            session,
            vec![ToolCallRecord {
                id: "c1".into(),
                name: "exec".into(),
                arguments: "{}".into(),
            }],
        );
        seed_tool_result(&*log, session, "c1", "exec", "done");

        let _ = factory.wake("agent-complete", session).unwrap();

        let h = log.handle_for(SessionId::new(session));
        let rows = log.get_since(&h, 0).unwrap();
        // No synthetic event added.
        let tool_result_count = rows
            .iter()
            .filter(|r| matches!(r.event, SessionEvent::ToolResult { .. }))
            .count();
        assert_eq!(tool_result_count, 1);
    }

    // ---- per-session isolation --------------------------------------

    #[tokio::test]
    async fn two_sessions_for_same_agent_have_isolated_conversations() {
        let log = make_log();
        let (factory, _tmp) = make_factory("multi-conv", log.clone());

        let s1 = "multi-conv/slack/c-1";
        let s2 = "multi-conv/slack/c-2";

        seed_user_message(&*log, s1, "from s1");
        seed_assistant_message(&*log, s1, "reply 1");
        seed_user_message(&*log, s2, "from s2");

        let a1 = factory.wake("multi-conv", s1).unwrap();
        let a2 = factory.wake("multi-conv", s2).unwrap();
        let a1_lock = a1.lock().await;
        let a2_lock = a2.lock().await;
        // s1: system + user + assistant = 3
        assert_eq!(a1_lock.conversation_len(), 3);
        // s2: system + user = 2
        assert_eq!(a2_lock.conversation_len(), 2);
    }

    // ---- LRU cache --------------------------------------------------

    #[tokio::test]
    async fn factory_returns_same_arc_for_repeated_wakes() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-cache", log);

        let session = "agent-cache/test/conv-1";
        let a = factory.wake("agent-cache", session).unwrap();
        let b = factory.wake("agent-cache", session).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn unknown_agent_id_errors() {
        let log = make_log();
        let (factory, _tmp) = make_factory("known", log);
        let result = factory.wake("not-known", "x/y/z");
        assert!(result.is_err());
    }

    // ---- inbound dedup ----------------------------------------------

    #[tokio::test]
    async fn dedup_replays_prior_response_for_same_inbound_id() {
        // Pre-seed a session with one full turn (UserMessage with
        // inbound_id followed by AssistantMessage), then construct
        // an Agent against it and call process_message with the
        // same inbound_id. The dedup path should return the prior
        // response without invoking the LLM.
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-dedup", log.clone());
        let session = "agent-dedup/test/conv-1";

        // Seed: UserMessage{inbound_id=msg-1} + AssistantMessage{prior reply}
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "first".into(),
                inbound_id: Some("msg-1".into()),
            },
        )
        .unwrap();
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::AssistantMessage {
                content: "prior reply".into(),
            },
        )
        .unwrap();

        let agent_arc = factory.wake("agent-dedup", session).unwrap();
        let mut agent = agent_arc.lock().await;
        let result = agent
            .process_message("first", "msg-1".into())
            .await
            .unwrap();
        assert_eq!(result.response, "prior reply");
    }

    #[tokio::test]
    async fn dedup_returns_interrupted_marker_when_prior_assistant_missing() {
        let log = make_log();
        let (factory, _tmp) = make_factory("agent-interrupted", log.clone());
        let session = "agent-interrupted/test/conv-1";

        // Seed: UserMessage with inbound_id but no following
        // AssistantMessage — simulates a crash mid-turn.
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "first".into(),
                inbound_id: Some("msg-2".into()),
            },
        )
        .unwrap();

        let agent_arc = factory.wake("agent-interrupted", session).unwrap();
        let mut agent = agent_arc.lock().await;
        let result = agent
            .process_message("first", "msg-2".into())
            .await
            .unwrap();
        assert!(result.response.contains("did not complete"));
    }

    // ---- WIRKEN_CACHE_MODE=drop ------------------------------------

    #[tokio::test]
    async fn drop_mode_does_not_cache() {
        // CacheMode::Drop is passed explicitly via with_options so
        // parallel tests don't fight over a shared env var.
        let log = make_log();
        let mut configs = HashMap::new();
        configs.insert(
            "agent-drop".to_string(),
            AgentStaticConfig {
                agent_id: "agent-drop".to_string(),
                workspace: PathBuf::from("/tmp"),
                llm_config: LlmConfig::ollama("test"),
                api_key: None,
                skills: Vec::new(),
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: None,
                allowed_subagents: Default::default(),
            },
        );
        let factory = AgentFactory::with_options(configs, log, None, CacheMode::Drop, 64);

        let session = "agent-drop/test/conv-1";
        let a = factory.wake("agent-drop", session).unwrap();
        let b = factory.wake("agent-drop", session).unwrap();
        // In drop mode, every wake reconstructs — distinct Arcs.
        assert!(!Arc::ptr_eq(&a, &b));
    }
}

// ---------------------------------------------------------------------------
// Item 6 slice 1: multi-agent orchestration / spawn_subagent
// ---------------------------------------------------------------------------

mod subagent {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use tempfile::TempDir;
    use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
    use wirken_gateway::agent_config::SubagentCeiling;
    use wirken_gateway::permissions::PermissionTier;

    use crate::error::AgentError;
    use crate::factory::{AgentFactory, AgentStaticConfig};
    use crate::llm::LlmConfig;
    use crate::runtime::Agent;

    fn make_log() -> Arc<dyn SessionLog> {
        Arc::new(SqliteSessionLog::open_in_memory().unwrap())
    }

    /// Build a factory holding a parent and one child agent. The
    /// parent's `allowed_subagents` is empty by default — the
    /// caller seeds it via `factory_with_ceiling` for spawn tests.
    fn factory_with_ceiling(
        parent_id: &str,
        child_id: &str,
        ceiling: Option<SubagentCeiling>,
        log: Arc<dyn SessionLog>,
    ) -> (Arc<AgentFactory>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mut configs = HashMap::new();
        let mut parent_ceilings = BTreeMap::new();
        if let Some(c) = ceiling {
            parent_ceilings.insert(child_id.to_string(), c);
        }
        configs.insert(
            parent_id.to_string(),
            AgentStaticConfig {
                agent_id: parent_id.to_string(),
                workspace: tmp.path().to_path_buf(),
                llm_config: LlmConfig::ollama("test"),
                api_key: None,
                skills: Vec::new(),
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: None,
                allowed_subagents: parent_ceilings,
            },
        );
        configs.insert(
            child_id.to_string(),
            AgentStaticConfig {
                agent_id: child_id.to_string(),
                workspace: tmp.path().to_path_buf(),
                llm_config: LlmConfig::ollama("test"),
                api_key: None,
                skills: Vec::new(),
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: None,
                allowed_subagents: BTreeMap::new(),
            },
        );
        (AgentFactory::new(configs, log, None), tmp)
    }

    fn parse_envelope(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("envelope parse failed: {e} — {s}"))
    }

    // ---- AgentConfig serde -----------------------------------------

    #[test]
    fn subagent_ceiling_round_trips_through_json() {
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into(), "web_search".into()],
            max_permission_tier: PermissionTier::Tier2,
            max_rounds: 5,
            max_runtime_secs: 30,
        };
        let mut map = BTreeMap::new();
        map.insert("researcher".to_string(), ceiling);
        let json = serde_json::to_string(&map).unwrap();
        let back: BTreeMap<String, SubagentCeiling> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        let r = back.get("researcher").unwrap();
        assert_eq!(r.tool_allowlist, vec!["read_file", "web_search"]);
        assert_eq!(r.max_permission_tier, PermissionTier::Tier2);
        assert_eq!(r.max_rounds, 5);
        assert_eq!(r.max_runtime_secs, 30);
    }

    // ---- spawn_subagent rejection paths ----------------------------

    #[tokio::test]
    async fn spawn_returns_error_envelope_when_agent_id_not_in_allowlist() {
        let log = make_log();
        // Parent has no ceilings, so any spawn attempt is refused.
        let (factory, _tmp) = factory_with_ceiling("parent", "child", None, log.clone());

        let parent = factory.wake("parent", "parent/test/conv-1").unwrap();
        let mut agent = parent.lock().await;

        let args = serde_json::json!({"agent_id":"child", "prompt":"do work"}).to_string();
        let result = agent.spawn_subagent_intercept(&args).await.unwrap();
        let env = parse_envelope(&result.output);
        assert_eq!(env["status"], "error");
        assert!(
            env["output"]
                .as_str()
                .unwrap()
                .contains("not in allowed_subagents"),
            "envelope: {result:?}"
        );
        assert!(!result.success);
    }

    #[tokio::test]
    async fn spawn_returns_error_envelope_when_no_factory_bound() {
        // Standalone Agent (not waked from a factory) cannot spawn.
        let tmp = TempDir::new().unwrap();
        let log = make_log();
        let mut agent = Agent::new(
            "solo".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log,
        )
        .unwrap();

        let args = serde_json::json!({"agent_id":"child", "prompt":"do work"}).to_string();
        let result = agent.spawn_subagent_intercept(&args).await.unwrap();
        let env = parse_envelope(&result.output);
        assert_eq!(env["status"], "error");
        assert!(
            env["output"]
                .as_str()
                .unwrap()
                .contains("agent has no factory bound"),
            "envelope: {result:?}"
        );
    }

    #[tokio::test]
    async fn spawn_returns_depth_exceeded_at_cap() {
        let log = make_log();
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into()],
            max_permission_tier: PermissionTier::Tier1,
            max_rounds: 1,
            max_runtime_secs: 5,
        };
        let (factory, _tmp) = factory_with_ceiling("parent", "child", Some(ceiling), log.clone());

        let parent = factory.wake("parent", "parent/test/conv-1").unwrap();
        let mut agent = parent.lock().await;
        // Pretend this agent is already nested 4 deep.
        agent.set_subagent_depth_for_test(4);

        let args = serde_json::json!({"agent_id":"child", "prompt":"hi"}).to_string();
        let result = agent.spawn_subagent_intercept(&args).await.unwrap();
        let env = parse_envelope(&result.output);
        assert_eq!(env["status"], "depth_exceeded");
    }

    #[tokio::test]
    async fn spawn_returns_invalid_args_error_for_garbage_payload() {
        let log = make_log();
        let (factory, _tmp) = factory_with_ceiling("parent", "child", None, log);
        let parent = factory.wake("parent", "parent/test/conv-1").unwrap();
        let mut agent = parent.lock().await;
        let result = agent.spawn_subagent_intercept("{not json").await.unwrap();
        let env = parse_envelope(&result.output);
        assert_eq!(env["status"], "error");
    }

    // ---- spawn_subagent success-path bookkeeping --------------------
    //
    // The child wakes against an Ollama LlmConfig pointed at a
    // non-routable URL, so the actual LLM call inside the child
    // fails immediately. The parent intercept catches the error
    // and produces `status: "error"` — but along the way it
    // performs all the bookkeeping the slice 1 design demands
    // (audit events, child session id, tool intersection). Those
    // are exactly the behaviors these tests assert on.

    #[tokio::test]
    async fn spawn_writes_subagent_spawned_and_result_events() {
        let log = make_log();
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into()],
            max_permission_tier: PermissionTier::Tier1,
            max_rounds: 1,
            max_runtime_secs: 5,
        };
        let (factory, _tmp) = factory_with_ceiling("parent", "child", Some(ceiling), log.clone());

        let parent_session = "parent/test/conv-1";
        let parent = factory.wake("parent", parent_session).unwrap();
        let mut agent = parent.lock().await;

        let args = serde_json::json!({"agent_id":"child", "prompt":"hi"}).to_string();
        let _ = agent.spawn_subagent_intercept(&args).await.unwrap();

        let h = log.handle_for(SessionId::new(parent_session));
        let rows = log.get_since(&h, 0).unwrap();

        let spawned: Vec<&SessionEvent> = rows
            .iter()
            .map(|r| &r.event)
            .filter(|e| matches!(e, SessionEvent::SubagentSpawned { .. }))
            .collect();
        let results: Vec<&SessionEvent> = rows
            .iter()
            .map(|r| &r.event)
            .filter(|e| matches!(e, SessionEvent::SubagentResult { .. }))
            .collect();

        assert_eq!(spawned.len(), 1, "expected exactly one SubagentSpawned");
        assert_eq!(results.len(), 1, "expected exactly one SubagentResult");

        // SubagentSpawned must come BEFORE SubagentResult — order
        // matters for crash recovery.
        let spawn_idx = rows
            .iter()
            .position(|r| matches!(r.event, SessionEvent::SubagentSpawned { .. }))
            .unwrap();
        let result_idx = rows
            .iter()
            .position(|r| matches!(r.event, SessionEvent::SubagentResult { .. }))
            .unwrap();
        assert!(spawn_idx < result_idx);
    }

    #[tokio::test]
    async fn spawn_intersects_tool_request_with_ceiling() {
        let log = make_log();
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into(), "web_search".into()],
            max_permission_tier: PermissionTier::Tier1,
            max_rounds: 1,
            max_runtime_secs: 5,
        };
        let (factory, _tmp) = factory_with_ceiling("parent", "child", Some(ceiling), log.clone());

        let parent_session = "parent/test/conv-2";
        let parent = factory.wake("parent", parent_session).unwrap();
        let mut agent = parent.lock().await;

        // LLM asks for [read_file, exec, web_search]; ceiling
        // allows [read_file, web_search]. Intersection = the two
        // shared names; `exec` is silently dropped.
        let args = serde_json::json!({
            "agent_id": "child",
            "prompt": "hi",
            "tools": ["read_file", "exec", "web_search"],
        })
        .to_string();
        let _ = agent.spawn_subagent_intercept(&args).await.unwrap();

        let h = log.handle_for(SessionId::new(parent_session));
        let rows = log.get_since(&h, 0).unwrap();
        let spawned = rows
            .iter()
            .find_map(|r| match &r.event {
                SessionEvent::SubagentSpawned { tools_granted, .. } => Some(tools_granted),
                _ => None,
            })
            .expect("SubagentSpawned event must be present");
        let mut sorted = spawned.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["read_file".to_string(), "web_search".into()]);
    }

    #[tokio::test]
    async fn child_session_is_isolated_from_parent() {
        let log = make_log();
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into()],
            max_permission_tier: PermissionTier::Tier1,
            max_rounds: 1,
            max_runtime_secs: 5,
        };
        let (factory, _tmp) = factory_with_ceiling("parent", "child", Some(ceiling), log.clone());

        let parent_session = "parent/test/conv-3";
        let parent = factory.wake("parent", parent_session).unwrap();
        let mut agent = parent.lock().await;

        let args = serde_json::json!({"agent_id":"child", "prompt":"hi"}).to_string();
        let _ = agent.spawn_subagent_intercept(&args).await.unwrap();

        // Parent session: only the spawn audit events, no child
        // user/assistant events.
        let h = log.handle_for(SessionId::new(parent_session));
        let parent_rows = log.get_since(&h, 0).unwrap();
        let parent_user_msgs = parent_rows
            .iter()
            .filter(|r| matches!(r.event, SessionEvent::UserMessage { .. }))
            .count();
        assert_eq!(parent_user_msgs, 0, "parent saw no UserMessage events");

        // Child session id is reproducible and distinct from the
        // parent's.
        let child_session_id = format!("{parent_session}#sub-0");
        let child_h = log.handle_for(SessionId::new(child_session_id));
        let child_rows = log.get_since(&child_h, 0).unwrap();
        // The child wrote at least its UserMessage event before
        // the LLM call failed.
        let child_user_msgs = child_rows
            .iter()
            .filter(|r| matches!(r.event, SessionEvent::UserMessage { .. }))
            .count();
        assert_eq!(child_user_msgs, 1, "child wrote exactly one UserMessage");
    }

    #[tokio::test]
    async fn child_session_id_increments_per_spawn_in_same_session() {
        let log = make_log();
        let ceiling = SubagentCeiling {
            tool_allowlist: vec!["read_file".into()],
            max_permission_tier: PermissionTier::Tier1,
            max_rounds: 1,
            max_runtime_secs: 5,
        };
        let (factory, _tmp) = factory_with_ceiling("parent", "child", Some(ceiling), log.clone());

        let parent_session = "parent/test/conv-4";
        let parent = factory.wake("parent", parent_session).unwrap();
        let mut agent = parent.lock().await;

        let args = serde_json::json!({"agent_id":"child", "prompt":"first"}).to_string();
        let _ = agent.spawn_subagent_intercept(&args).await.unwrap();
        let _ = agent.spawn_subagent_intercept(&args).await.unwrap();

        let h = log.handle_for(SessionId::new(parent_session));
        let rows = log.get_since(&h, 0).unwrap();
        let spawned_ids: Vec<String> = rows
            .iter()
            .filter_map(|r| match &r.event {
                SessionEvent::SubagentSpawned {
                    child_session_id, ..
                } => Some(child_session_id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(spawned_ids.len(), 2);
        assert_eq!(spawned_ids[0], format!("{parent_session}#sub-0"));
        assert_eq!(spawned_ids[1], format!("{parent_session}#sub-1"));
    }

    // ---- max_rounds budget plumbing ---------------------------------

    #[tokio::test]
    async fn process_message_inner_returns_rounds_exceeded_when_budget_zero() {
        // budget = 0 means the very first round trips the
        // post-increment check `rounds > budget` immediately.
        let tmp = TempDir::new().unwrap();
        let log = make_log();
        let mut agent = Agent::new(
            "budget".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log,
        )
        .unwrap();

        let result = agent
            .process_message_inner("hello", "test-1".into(), Some(0))
            .await;
        match result {
            Err(AgentError::RoundsExceeded { rounds }) => {
                assert_eq!(rounds, 0, "no rounds completed under a zero budget");
            }
            Err(other) => panic!("expected RoundsExceeded, got error {other:?}"),
            Ok(_) => panic!("expected RoundsExceeded, got Ok"),
        }
    }

    // ---- tool def visibility ----------------------------------------

    #[tokio::test]
    async fn spawn_tool_def_omitted_when_allowed_subagents_empty() {
        // No ceilings → tool def should not be present in the
        // child's exposed defs. We test this indirectly by reading
        // the agent's tool registry definitions plus the conditional
        // append in `process_message_inner`. Since `spawn_subagent`
        // is appended only inside the harness loop (not in the
        // ToolRegistry), we assert via the registry that there is
        // no built-in by that name.
        let log = make_log();
        let (factory, _tmp) = factory_with_ceiling("parent", "child", None, log);
        let parent = factory.wake("parent", "parent/test/conv-5").unwrap();
        let agent = parent.lock().await;
        // Sanity: with no ceilings the agent reports zero allowed children.
        // (This is the precondition the harness uses to omit the tool.)
        assert_eq!(agent.subagent_depth_for_test(), 0);
        // The built-in registry never contains spawn_subagent on
        // its own — slice 1 keeps it as a harness-injected def.
        let tool_names: Vec<String> = crate::tool::ToolRegistry::new(
            std::env::temp_dir(),
            crate::tool::ToolConfig::default(),
        )
        .definitions()
        .into_iter()
        .map(|d| d.name)
        .collect();
        assert!(
            !tool_names.iter().any(|n| n == "spawn_subagent"),
            "spawn_subagent must be a harness-injected def, not a registry built-in"
        );
    }
}

// ---------------------------------------------------------------------------
// Sandbox modes
// ---------------------------------------------------------------------------

#[test]
fn sandbox_mode_from_str_config() {
    use crate::sandbox::SandboxMode;

    assert_eq!(SandboxMode::from_str_config("off"), SandboxMode::Off);
    assert_eq!(SandboxMode::from_str_config(""), SandboxMode::Off);
    assert_eq!(
        SandboxMode::from_str_config("exec-only"),
        SandboxMode::ExecOnly
    );
    assert_eq!(SandboxMode::from_str_config("gvisor"), SandboxMode::GVisor);
    // Unknown falls back to Off
    assert_eq!(SandboxMode::from_str_config("invalid"), SandboxMode::Off);
}

#[test]
fn sandbox_mode_gvisor_runtime_name() {
    use crate::sandbox::SandboxMode;

    // Off and ExecOnly use default Docker runtime (runc)
    assert_eq!(SandboxMode::Off.runtime_name(), None);
    assert_eq!(SandboxMode::ExecOnly.runtime_name(), None);
    // GVisor uses runsc
    assert_eq!(
        SandboxMode::GVisor.runtime_name(),
        Some("runsc".to_string())
    );
}

#[test]
fn sandbox_config_defaults() {
    use crate::sandbox::{SandboxConfig, SandboxMode};

    let config = SandboxConfig::default();
    assert_eq!(config.mode, SandboxMode::Off);
    assert!(!config.network);
    assert_eq!(config.timeout_secs, 300);
}

#[tokio::test]
async fn sandbox_construction_is_lazy() {
    use crate::sandbox::{SandboxConfig, SandboxMode};

    // Constructing a registry with a non-Off sandbox mode must not touch
    // Docker. The OnceCell stays uninitialized until the first sandboxed
    // tool call. This holds even when Docker is reachable on the host.
    let tmp = TempDir::new().unwrap();
    let config = ToolConfig {
        sandbox: SandboxConfig {
            mode: SandboxMode::GVisor,
            ..Default::default()
        },
        ..Default::default()
    };
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), config);
    assert!(
        !tools.sandbox_initialized(),
        "sandbox must not be provisioned at construction time"
    );
}

#[tokio::test]
async fn sandbox_falls_through_to_host_when_unavailable() {
    use crate::sandbox::{SandboxConfig, SandboxMode, detect_runtime};

    // This test asserts the fall-through behaviour when Docker is not
    // available: the first exec attempt provisions (and fails), and
    // subsequent calls reuse the failed cell without retrying. We can only
    // observe this on a host without Docker; on hosts with Docker the call
    // would succeed in the sandbox and the assertion below would not apply.
    if detect_runtime().await.is_some() {
        eprintln!("skipping: Docker is available on this host");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let config = ToolConfig {
        sandbox: SandboxConfig {
            mode: SandboxMode::ExecOnly,
            ..Default::default()
        },
        ..Default::default()
    };
    let tools = ToolRegistry::new(tmp.path().to_path_buf(), config);
    assert!(!tools.sandbox_initialized());

    // First exec — sandbox provisioning is attempted, fails (no Docker),
    // and falls through to host execution. The OnceCell is now set to None.
    let r1 = tools
        .execute("exec", r#"{"command": "echo first"}"#)
        .await
        .unwrap();
    assert!(r1.success);
    assert!(r1.output.contains("first"));
    assert!(
        tools.sandbox_initialized(),
        "first exec must initialize the cell"
    );

    // Second exec — the cell is already set to None, no retry, host exec.
    let r2 = tools
        .execute("exec", r#"{"command": "echo second"}"#)
        .await
        .unwrap();
    assert!(r2.success);
    assert!(r2.output.contains("second"));
    assert!(tools.sandbox_initialized());
}

#[test]
fn sandbox_gvisor_constraints_match_docker() {
    use crate::sandbox::{SandboxConfig, SandboxMode};

    // Both ExecOnly and GVisor should use the same resource limits.
    // The difference is only the OCI runtime — limits are constants in sandbox.rs.
    let docker_config = SandboxConfig {
        mode: SandboxMode::ExecOnly,
        ..Default::default()
    };
    let gvisor_config = SandboxConfig {
        mode: SandboxMode::GVisor,
        ..Default::default()
    };

    assert_eq!(docker_config.image, gvisor_config.image);
    assert_eq!(docker_config.timeout_secs, gvisor_config.timeout_secs);
    assert_eq!(docker_config.network, gvisor_config.network);
}

// ---------------------------------------------------------------------------
// tool_to_action mapping
// ---------------------------------------------------------------------------

#[test]
fn tool_to_action_exec() {
    use crate::tool::tool_to_action;
    use wirken_gateway::permissions::Action;

    let args = serde_json::json!({"command": "curl https://example.com"});
    let action = tool_to_action("exec", &args).unwrap();
    assert!(matches!(action, Action::ShellExec { pattern } if pattern == "curl"));
}

#[test]
fn tool_to_action_exec_empty_command() {
    use crate::tool::tool_to_action;
    use wirken_gateway::permissions::Action;

    let args = serde_json::json!({"command": ""});
    let action = tool_to_action("exec", &args).unwrap();
    assert!(matches!(action, Action::ShellExec { pattern } if pattern.is_empty()));
}

#[test]
fn tool_to_action_read_file() {
    use crate::tool::tool_to_action;
    use wirken_gateway::permissions::Action;

    let args = serde_json::json!({"path": "README.md"});
    let action = tool_to_action("read_file", &args).unwrap();
    assert!(matches!(action, Action::WorkspaceFileAccess));
}

#[test]
fn tool_to_action_web_search() {
    use crate::tool::tool_to_action;
    use wirken_gateway::permissions::Action;

    let args = serde_json::json!({"query": "rust async"});
    let action = tool_to_action("web_search", &args).unwrap();
    assert!(matches!(action, Action::WebSearch));
}

#[test]
fn tool_to_action_generate_image() {
    use crate::tool::tool_to_action;
    use wirken_gateway::permissions::Action;

    let args = serde_json::json!({"prompt": "a cat"});
    let action = tool_to_action("generate_image", &args).unwrap();
    assert!(matches!(action, Action::NetworkRequest { .. }));
}

#[test]
fn tool_to_action_unknown_returns_none() {
    use crate::tool::tool_to_action;

    let args = serde_json::json!({});
    assert!(tool_to_action("some_mcp_tool", &args).is_none());
}

// ---------------------------------------------------------------------------
// MCP proxy client end-to-end (against the in-process proxy server)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_proxy_client_connects_and_reports_no_servers() {
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use wirken_mcp_proxy::mcp_registry::ProxyRegistry;
    use wirken_mcp_proxy::server;

    use crate::identity::AgentIdentity;
    use crate::mcp::McpProxyClient;

    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    // Generate an identity and register its pubkey with the proxy
    // before spawning the server. The handshake requires the
    // server to already know the agent's key.
    let identity = AgentIdentity::generate("test-agent");
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&identity.public_key_bytes()).unwrap();
    let mut reg = ProxyRegistry::new();
    reg.register_identity("test-agent", pubkey);

    // Start a proxy server in-process with the registered identity.
    // The server::serve loop binds the socket and accepts
    // connections; we abort it at the end of the test.
    let server_socket = socket_path.clone();
    let registry = Arc::new(Mutex::new(reg));
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, registry).await;
    });

    // McpProxyClient::connect already retries the socket, so we don't
    // need to wait for the file ourselves — it will appear within the
    // 5s connect window.
    let mut client = McpProxyClient::connect(&socket_path, "test-agent", &identity)
        .await
        .expect("connect to in-process proxy");
    assert!(!client.has_servers());
    assert_eq!(client.definitions().len(), 0);

    client.shutdown().await;
    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Permission tier labels
// ---------------------------------------------------------------------------

#[test]
fn permission_tier_labels() {
    use wirken_gateway::permissions::PermissionTier;

    assert_eq!(PermissionTier::Tier1.label(), "tier1");
    assert_eq!(PermissionTier::Tier2.label(), "tier2");
    assert_eq!(PermissionTier::Tier3.label(), "tier3");
}

// ---------------------------------------------------------------------------
// Permission denial context
// ---------------------------------------------------------------------------

#[test]
fn denial_context_display() {
    use crate::error::PermissionDenialContext;
    use wirken_gateway::permissions::{Action, PermissionTier};

    let ctx = PermissionDenialContext {
        tool_name: "exec".into(),
        action: Action::ShellExec {
            pattern: "curl".into(),
        },
        requested_tier: PermissionTier::Tier2,
        agent_id: "default".into(),
        trigger_message: Some("fetch that URL".into()),
    };

    let display = format!("{ctx}");
    assert!(display.contains("exec"));
    assert!(display.contains("tier2"));
    assert!(display.contains("ShellExec"));
}

#[test]
fn process_result_empty_denials() {
    use crate::runtime::ProcessResult;

    let result = ProcessResult {
        response: "hello".into(),
        denials: Vec::new(),
    };
    assert_eq!(result.response, "hello");
    assert!(result.denials.is_empty());
}

// ---------------------------------------------------------------------------
// Identity (item 8)
// ---------------------------------------------------------------------------

mod identity_tests {
    use super::TempDir;
    use crate::identity::{AgentIdentity, identity_dir, verify};

    #[test]
    fn generate_produces_distinct_keys() {
        let a = AgentIdentity::generate("a");
        let b = AgentIdentity::generate("b");
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let id = AgentIdentity::generate("test");
        let msg = b"hello, world";
        let sig = id.sign(msg);
        verify(&id.verifying_key(), msg, &sig).expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let id = AgentIdentity::generate("test");
        let sig = id.sign(b"first");
        assert!(verify(&id.verifying_key(), b"second", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = AgentIdentity::generate("signer");
        let other = AgentIdentity::generate("other");
        let sig = signer.sign(b"msg");
        assert!(verify(&other.verifying_key(), b"msg", &sig).is_err());
    }

    #[test]
    fn load_or_create_persists_and_reloads_same_key() {
        let tmp = TempDir::new().unwrap();
        let dir = identity_dir(tmp.path(), "agent-A");

        let first = AgentIdentity::load_or_create("agent-A", &dir).unwrap();
        let pk1 = first.public_key_bytes();
        // Sign the same message twice — Ed25519 is deterministic so
        // signatures should be identical across reloads.
        let sig1 = first.sign(b"determinism check");
        drop(first);

        let second = AgentIdentity::load_or_create("agent-A", &dir).unwrap();
        let pk2 = second.public_key_bytes();
        let sig2 = second.sign(b"determinism check");

        assert_eq!(pk1, pk2);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let dir = identity_dir(tmp.path(), "perms");
        AgentIdentity::load_or_create("perms", &dir).unwrap();

        let secret_path = dir.join("identity.key");
        let meta = std::fs::metadata(&secret_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[test]
    fn load_from_rejects_wrong_length() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bad.key");
        // 31 bytes hex-encoded, one short.
        std::fs::write(&path, "00".repeat(31)).unwrap();
        assert!(AgentIdentity::load_from("a", &path).is_err());
    }
}

// ---------------------------------------------------------------------------
// Attestation (item 8)
// ---------------------------------------------------------------------------

mod attestation_tests {
    use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, TrustLevel};

    use crate::attestation::{
        AttestationVerifyResult, attest_session, verify_session_attestations,
    };
    use crate::identity::AgentIdentity;

    fn user_msg(s: &str) -> SessionEvent {
        SessionEvent::UserMessage {
            content: s.into(),
            inbound_id: None,
        }
    }

    fn fresh_log_with_events(
        n: usize,
    ) -> (
        SqliteSessionLog,
        wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    ) {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("sess-T"));
        for i in 0..n {
            log.append(&h, TrustLevel::User, user_msg(&format!("e{i}")))
                .unwrap();
        }
        (log, h)
    }

    #[test]
    fn attest_empty_session_returns_none() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("empty"));
        let id = AgentIdentity::generate("a");
        let result = attest_session(&log, &h, &id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn attest_then_verify_round_trip() {
        let (log, h) = fresh_log_with_events(5);
        let id = AgentIdentity::generate("a");

        let attest_seq = attest_session(&log, &h, &id).unwrap().unwrap();
        // Attestation event becomes seq 5 (0..=4 user messages, then 5).
        assert_eq!(attest_seq, 5);

        let result = verify_session_attestations(&log, &h, &id.verifying_key()).unwrap();
        match result {
            AttestationVerifyResult::Ok {
                attestations_verified,
                chain_rows_verified,
            } => {
                assert_eq!(attestations_verified, 1);
                assert_eq!(chain_rows_verified, 6); // 5 user msgs + 1 attestation
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn empty_session_verifies_with_zero_attestations() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("empty"));
        let id = AgentIdentity::generate("a");
        let result = verify_session_attestations(&log, &h, &id.verifying_key()).unwrap();
        assert_eq!(
            result,
            AttestationVerifyResult::Ok {
                attestations_verified: 0,
                chain_rows_verified: 0,
            }
        );
    }

    #[test]
    fn session_with_no_attestations_verifies_with_zero() {
        let (log, h) = fresh_log_with_events(3);
        let id = AgentIdentity::generate("a");
        let result = verify_session_attestations(&log, &h, &id.verifying_key()).unwrap();
        assert_eq!(
            result,
            AttestationVerifyResult::Ok {
                attestations_verified: 0,
                chain_rows_verified: 3,
            }
        );
    }

    #[test]
    fn multiple_attestations_all_verify() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("multi"));
        let id = AgentIdentity::generate("a");

        for i in 0..3 {
            log.append(&h, TrustLevel::User, user_msg(&format!("a{i}")))
                .unwrap();
            attest_session(&log, &h, &id).unwrap();
        }

        let result = verify_session_attestations(&log, &h, &id.verifying_key()).unwrap();
        assert_eq!(
            result,
            AttestationVerifyResult::Ok {
                attestations_verified: 3,
                chain_rows_verified: 6,
            }
        );
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let (log, h) = fresh_log_with_events(2);
        let signer = AgentIdentity::generate("signer");
        let other = AgentIdentity::generate("other");

        attest_session(&log, &h, &signer).unwrap();

        let result = verify_session_attestations(&log, &h, &other.verifying_key()).unwrap();
        match result {
            AttestationVerifyResult::Broken { reason, .. } => {
                assert!(
                    reason.contains("pubkey mismatch"),
                    "expected pubkey mismatch, got {reason}"
                );
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    // Note: chain tampering detection is exercised exhaustively in
    // crates/audit/src/tests.rs::session::verify_detects_payload_tampering
    // and verify_detects_chain_hash_tampering. verify_session_attestations
    // forwards SessionLog::verify's result transparently, so we don't
    // duplicate the corruption-via-raw-connection tests at this layer
    // — wirken-agent doesn't depend on rusqlite and shouldn't.

    #[test]
    fn attestation_event_participates_in_chain() {
        // After attesting, the chain head moves to the attestation
        // event. A subsequent regular append builds on top of it,
        // and the whole chain (including the attestation) verifies.
        let (log, h) = fresh_log_with_events(2);
        let id = AgentIdentity::generate("a");

        attest_session(&log, &h, &id).unwrap();
        log.append(&h, TrustLevel::User, user_msg("after attest"))
            .unwrap();

        // Underlying chain is still intact.
        match log.verify(&h).unwrap() {
            wirken_audit::SessionVerifyResult::Ok { rows_verified } => {
                assert_eq!(rows_verified, 4); // 2 + 1 attest + 1 user
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Attestation still verifies.
        let result = verify_session_attestations(&log, &h, &id.verifying_key()).unwrap();
        assert_eq!(
            result,
            AttestationVerifyResult::Ok {
                attestations_verified: 1,
                chain_rows_verified: 4,
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Item 8 slice 2: auto-attestation trigger from the harness loop
// ---------------------------------------------------------------------------

mod auto_attest {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;
    use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, TrustLevel};

    use crate::attestation::{AttestationVerifyResult, verify_session_attestations};
    use crate::identity::AgentIdentity;
    use crate::llm::LlmConfig;
    use crate::runtime::Agent;

    fn fresh_agent_with_identity() -> (Agent, Arc<dyn SessionLog>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let mut agent = Agent::new(
            "auto-attest".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();
        agent.attach_identity(AgentIdentity::generate("auto-attest"));
        (agent, log, tmp)
    }

    fn count_attestations(log: &dyn SessionLog, session: &str) -> usize {
        let h = log.handle_for(SessionId::new(session));
        log.get_since(&h, 0)
            .unwrap()
            .iter()
            .filter(|r| matches!(r.event, SessionEvent::Attestation { .. }))
            .count()
    }

    #[tokio::test]
    async fn maybe_attest_is_noop_without_identity() {
        let tmp = TempDir::new().unwrap();
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let mut agent = Agent::new(
            "no-id".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();

        // Seed an event so the session isn't empty.
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "hi".into(),
                    inbound_id: None,
                },
            )
            .unwrap();

        let result = agent.maybe_attest().await.unwrap();
        assert!(result.is_none(), "no identity → maybe_attest is a no-op");
        assert_eq!(count_attestations(&*log, "no-id"), 0);
    }

    #[tokio::test]
    async fn maybe_attest_is_noop_on_empty_session() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        let result = agent.maybe_attest().await.unwrap();
        assert!(result.is_none());
        assert_eq!(count_attestations(&*log, "auto-attest"), 0);
    }

    #[tokio::test]
    async fn first_turn_is_always_attested() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        // Seed at least one event so attest_session has something
        // to sign.
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "first".into(),
                    inbound_id: None,
                },
            )
            .unwrap();

        let result = agent.maybe_attest().await.unwrap();
        assert!(result.is_some(), "first turn must trigger attestation");
        assert_eq!(count_attestations(&*log, "auto-attest"), 1);
    }

    #[tokio::test]
    async fn second_turn_below_threshold_is_not_attested() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        // Seed and trigger the first attestation.
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "first".into(),
                    inbound_id: None,
                },
            )
            .unwrap();
        agent.maybe_attest().await.unwrap();
        assert_eq!(count_attestations(&*log, "auto-attest"), 1);

        // Add a few more events but stay well under the 20-event
        // threshold and well within the 30-second window.
        for i in 0..5 {
            agent
                .log_event(
                    TrustLevel::User,
                    SessionEvent::UserMessage {
                        content: format!("msg {i}"),
                        inbound_id: None,
                    },
                )
                .unwrap();
        }

        let result = agent.maybe_attest().await.unwrap();
        assert!(
            result.is_none(),
            "second-turn under both thresholds should not attest"
        );
        // Still just the one attestation from the first turn.
        assert_eq!(count_attestations(&*log, "auto-attest"), 1);
    }

    #[tokio::test]
    async fn crossing_event_threshold_triggers_re_attest() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        // First turn → first attestation.
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "first".into(),
                    inbound_id: None,
                },
            )
            .unwrap();
        agent.maybe_attest().await.unwrap();
        assert_eq!(count_attestations(&*log, "auto-attest"), 1);

        // Pump >= ATTEST_EVERY_N_EVENTS new events into the session.
        for i in 0..25 {
            agent
                .log_event(
                    TrustLevel::User,
                    SessionEvent::UserMessage {
                        content: format!("event {i}"),
                        inbound_id: None,
                    },
                )
                .unwrap();
        }

        let result = agent.maybe_attest().await.unwrap();
        assert!(
            result.is_some(),
            "crossing the event threshold must re-attest"
        );
        assert_eq!(count_attestations(&*log, "auto-attest"), 2);
    }

    #[tokio::test]
    async fn crossing_time_threshold_triggers_re_attest() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "first".into(),
                    inbound_id: None,
                },
            )
            .unwrap();
        agent.maybe_attest().await.unwrap();
        assert_eq!(count_attestations(&*log, "auto-attest"), 1);

        // Backdate the cached last_attestation by more than 30s.
        let stale = SystemTime::now() - Duration::from_secs(60);
        // The seq from the first attestation is 1 (after the user
        // message at seq 0). Set both fields explicitly.
        agent.set_last_attestation_for_test(1, stale);

        // Add one event and check.
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "second".into(),
                    inbound_id: None,
                },
            )
            .unwrap();

        let result = agent.maybe_attest().await.unwrap();
        assert!(
            result.is_some(),
            "crossing the time threshold must re-attest"
        );
        assert_eq!(count_attestations(&*log, "auto-attest"), 2);
    }

    #[tokio::test]
    async fn auto_signed_session_verifies_with_the_attached_key() {
        let (mut agent, log, _tmp) = fresh_agent_with_identity();
        let id_clone = agent.identity_for_test().unwrap().clone();
        agent
            .log_event(
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "hi".into(),
                    inbound_id: None,
                },
            )
            .unwrap();
        agent.maybe_attest().await.unwrap();

        let h = log.handle_for(SessionId::new("auto-attest"));
        let result = verify_session_attestations(&*log, &h, &id_clone.verifying_key()).unwrap();
        assert_eq!(
            result,
            AttestationVerifyResult::Ok {
                attestations_verified: 1,
                chain_rows_verified: 2,
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Item 4 slice 1: ContextEngine — token budgeting and trimming
// ---------------------------------------------------------------------------

mod context_engine {
    use std::sync::Arc;

    use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, TrustLevel};

    use crate::context::ContextEngine;
    use crate::conversation::{Conversation, Role, ToolCallRequest};
    use crate::error::AgentError;
    use crate::llm::LlmConfig;
    use crate::tool::ToolDef;

    fn fresh_log_and_handle() -> (
        Arc<dyn SessionLog>,
        wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    ) {
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let h = log.handle_for(SessionId::new("ctx-test"));
        (log, h)
    }

    fn empty_tool_defs() -> Vec<ToolDef> {
        Vec::new()
    }

    #[test]
    fn for_model_applies_safety_factor() {
        let mut cfg = LlmConfig::ollama("test");
        cfg.context_window = 1_000;
        let engine = ContextEngine::for_model(&cfg);
        // 1000 * 0.80 = 800
        assert_eq!(engine.budget_tokens(), 800);
    }

    #[test]
    fn empty_conversation_no_op() {
        let engine = ContextEngine::for_test(1_000, 3);
        let mut conv = Conversation::new(0);
        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();
        // Nothing trimmed → no Compaction event written.
        let rows = log.get_since(&h, 0).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn small_conversation_under_budget_no_op() {
        let engine = ContextEngine::for_test(10_000, 3);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("you are an agent");
        conv.add_user_message("hello");
        conv.add_assistant_message("hi there");
        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();
        // Conversation unchanged.
        assert_eq!(conv.len(), 3);
        // No Compaction event written.
        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows.len(), 0);
    }

    #[test]
    fn large_tool_result_trimmed_first() {
        // Conversation: system + user1 + assistant1 + tool_result_huge
        // + user2 + assistant2. With min_recent_turns=1 the tail
        // (user2 + assistant2) is protected. The huge tool result
        // is the only thing eligible to trim.
        let engine = ContextEngine::for_test(200, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("first user");
        conv.add_assistant_tool_calls(vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: "{}".into(),
        }]);
        // Make the tool result the dominant cost.
        let huge_output = "x".repeat(20_000);
        conv.add_tool_result("c1", "exec", &huge_output);
        conv.add_user_message("second user");
        conv.add_assistant_message("second assistant");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .expect("fit should succeed");

        // The tool result message itself is still present (preserves
        // tool_call_id binding) but its content is now a placeholder.
        let messages = conv.messages();
        let tool_msg = messages
            .iter()
            .find(|m| m.role == Role::Tool && m.tool_call_id.as_deref() == Some("c1"))
            .expect("tool result message must remain");
        assert!(
            tool_msg.content.starts_with("[trimmed:"),
            "expected placeholder, got: {}",
            tool_msg.content
        );

        // System prompt + last user + last assistant are intact.
        assert_eq!(messages[0].role, Role::System);
        let last_user = messages
            .iter()
            .rev()
            .find(|m| m.role == Role::User)
            .unwrap();
        assert_eq!(last_user.content, "second user");

        // A Compaction event was written.
        let rows = log.get_since(&h, 0).unwrap();
        let compaction_count = rows
            .iter()
            .filter(|r| matches!(r.event, SessionEvent::Compaction { .. }))
            .count();
        assert_eq!(compaction_count, 1);
    }

    #[test]
    fn system_prompt_never_trimmed() {
        // Tiny budget. System prompt is large enough to test that
        // it's protected from trimming.
        let engine = ContextEngine::for_test(50, 1);
        let mut conv = Conversation::new(0);
        let large_sys = "you are an agent ".repeat(50);
        conv.set_system_prompt(&large_sys);
        conv.add_user_message("hello");
        conv.add_assistant_message("hi");
        let (log, h) = fresh_log_and_handle();

        // The system prompt + tail won't fit even after trimming,
        // so this should error with ContextOverflow.
        let result = engine.fit(&mut conv, &empty_tool_defs(), &*log, &h);
        assert!(matches!(result, Err(AgentError::ContextOverflow { .. })));

        // System prompt content untouched.
        assert_eq!(conv.messages()[0].role, Role::System);
        assert_eq!(conv.messages()[0].content, large_sys);
    }

    #[test]
    fn most_recent_turns_protected() {
        // min_recent_turns = 2 protects the last two user messages
        // and everything after each.
        let engine = ContextEngine::for_test(10_000, 2);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_message("a1");
        conv.add_user_message("u2");
        conv.add_assistant_message("a2");
        conv.add_user_message("u3");
        conv.add_assistant_message("a3");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        // Under budget anyway → no trims.
        assert_eq!(conv.len(), 7);
    }

    #[test]
    fn assistant_text_trimmed_after_tool_results() {
        // No tool results in this conversation. With a tight budget
        // the engine should fall through to trimming oldest
        // assistant text. min_recent_turns=1 protects only the last
        // user-assistant pair.
        let engine = ContextEngine::for_test(80, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_message(&"old assistant ".repeat(40));
        conv.add_user_message("u2");
        conv.add_assistant_message("recent assistant");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        // The first assistant message got trimmed; the second is
        // intact (it's in the protected tail). Use role-based lookup
        // since slice 2α may inject a Compaction message at position 1.
        let assistant_msgs: Vec<&crate::conversation::Message> = conv
            .messages()
            .iter()
            .filter(|m| m.role == Role::Assistant)
            .collect();
        assert_eq!(assistant_msgs.len(), 2);
        assert!(
            assistant_msgs[0]
                .content
                .starts_with("[trimmed earlier turn:")
        );
        assert_eq!(assistant_msgs[1].content, "recent assistant");
    }

    #[test]
    fn context_overflow_when_floor_does_not_fit() {
        // Tiny budget; even the protected floor is too big.
        let engine = ContextEngine::for_test(20, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("a fairly long system prompt that doesn't fit");
        conv.add_user_message("a fairly long user message that doesn't fit either");
        conv.add_assistant_message("and an assistant reply that pushes us over");

        let (log, h) = fresh_log_and_handle();
        let result = engine.fit(&mut conv, &empty_tool_defs(), &*log, &h);
        assert!(matches!(result, Err(AgentError::ContextOverflow { .. })));
    }

    #[test]
    fn compaction_event_payload_has_expected_fields() {
        let engine = ContextEngine::for_test(100, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_tool_calls(vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: "{}".into(),
        }]);
        conv.add_tool_result("c1", "exec", &"y".repeat(5_000));
        conv.add_user_message("u2");
        conv.add_assistant_message("a2");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        let rows = log.get_since(&h, 0).unwrap();
        let compaction = rows
            .iter()
            .find_map(|r| match &r.event {
                SessionEvent::Compaction {
                    spans,
                    extracts,
                    via_model,
                } => Some((spans, extracts, via_model)),
                _ => None,
            })
            .expect("compaction event must be present");

        assert!(!compaction.0.is_empty());
        assert!(!*compaction.2); // via_model: false
        let extracts = compaction.1;
        assert!(extracts.get("trimmed_bytes").is_some());
        assert!(extracts.get("kept_messages").is_some());
        assert!(extracts.get("dropped_messages").is_some());

        // The compaction event itself is logged at TrustLevel::Compaction.
        let row = rows
            .iter()
            .find(|r| matches!(r.event, SessionEvent::Compaction { .. }))
            .unwrap();
        assert_eq!(row.trust, TrustLevel::Compaction);
    }

    #[test]
    fn tool_call_pairing_preserved_after_trim() {
        // Trimming a tool result must NEVER produce an orphan
        // assistant tool_calls without a matching tool message.
        let engine = ContextEngine::for_test(100, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_tool_calls(vec![
            ToolCallRequest {
                id: "c1".into(),
                name: "exec".into(),
                arguments: "{}".into(),
            },
            ToolCallRequest {
                id: "c2".into(),
                name: "read_file".into(),
                arguments: "{}".into(),
            },
        ]);
        conv.add_tool_result("c1", "exec", &"a".repeat(10_000));
        conv.add_tool_result("c2", "read_file", &"b".repeat(10_000));
        conv.add_user_message("u2");
        conv.add_assistant_message("done");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        // Both tool result messages are still present (just with
        // placeholder content), so the assistant tool_calls binding
        // is intact.
        let tool_msgs: Vec<&crate::conversation::Message> = conv
            .messages()
            .iter()
            .filter(|m| m.role == Role::Tool)
            .collect();
        assert_eq!(tool_msgs.len(), 2);
        assert_eq!(tool_msgs[0].tool_call_id.as_deref(), Some("c1"));
        assert_eq!(tool_msgs[1].tool_call_id.as_deref(), Some("c2"));
    }

    // Slice 1 of item 10 tests live in their own module below.

    // -----------------------------------------------------------------
    // Item 4 slice 2 (alpha): Role::Compaction projection
    // -----------------------------------------------------------------

    #[test]
    fn compaction_role_serde_roundtrip() {
        use crate::conversation::Message;
        let msg = Message {
            role: Role::Compaction,
            content: "earlier turns trimmed".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains("\"compaction\""),
            "expected lowercase 'compaction' role in JSON, got: {json}"
        );
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role, Role::Compaction);
        assert_eq!(back.content, "earlier turns trimmed");
    }

    #[test]
    fn compaction_summary_returns_none_for_fresh_session() {
        let engine = ContextEngine::for_test(10_000, 1);
        let (log, h) = fresh_log_and_handle();
        let summary = engine.compaction_summary_message(&*log, &h).unwrap();
        assert!(summary.is_none());
    }

    #[test]
    fn compaction_summary_returns_some_after_trim() {
        let engine = ContextEngine::for_test(200, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_tool_calls(vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: "{}".into(),
        }]);
        conv.add_tool_result("c1", "exec", &"x".repeat(20_000));
        conv.add_user_message("u2");
        conv.add_assistant_message("a2");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        let summary = engine
            .compaction_summary_message(&*log, &h)
            .unwrap()
            .expect("expected a summary message after a trim");
        assert_eq!(summary.role, Role::Compaction);
        assert!(summary.content.contains("1 trim round"));
        assert!(summary.content.contains("byte(s) reclaimed"));
        assert!(
            !summary
                .content
                .contains("at least one summary used a model call"),
            "via_model: false should not flag the model-note"
        );
    }

    #[test]
    fn fit_injects_compaction_at_position_one() {
        let engine = ContextEngine::for_test(200, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_tool_calls(vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: "{}".into(),
        }]);
        conv.add_tool_result("c1", "exec", &"x".repeat(20_000));
        conv.add_user_message("u2");
        conv.add_assistant_message("a2");

        let (log, h) = fresh_log_and_handle();
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        let messages = conv.messages();
        assert_eq!(messages[0].role, Role::System);
        assert_eq!(
            messages[1].role,
            Role::Compaction,
            "Compaction message must sit at position 1, right after system"
        );
    }

    #[test]
    fn fit_does_not_duplicate_compaction_across_calls() {
        let engine = ContextEngine::for_test(200, 1);
        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("u1");
        conv.add_assistant_tool_calls(vec![ToolCallRequest {
            id: "c1".into(),
            name: "exec".into(),
            arguments: "{}".into(),
        }]);
        conv.add_tool_result("c1", "exec", &"x".repeat(20_000));
        conv.add_user_message("u2");
        conv.add_assistant_message("a2");

        let (log, h) = fresh_log_and_handle();
        // First fit triggers a trim and injects a Compaction.
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();
        let after_first = conv
            .messages()
            .iter()
            .filter(|m| m.role == Role::Compaction)
            .count();
        assert_eq!(after_first, 1);

        // Second fit (no new trim needed since the budget is now met)
        // must still leave exactly one Compaction message in place,
        // not stack a second one on top.
        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();
        let after_second = conv
            .messages()
            .iter()
            .filter(|m| m.role == Role::Compaction)
            .count();
        assert_eq!(
            after_second, 1,
            "running fit() twice must not duplicate the Compaction summary"
        );
    }

    #[test]
    fn fit_under_budget_still_injects_existing_summary() {
        // Pre-seed the session log with a Compaction event from a
        // hypothetical earlier turn. fit() runs under budget and must
        // still surface the running summary on this turn.
        let engine = ContextEngine::for_test(10_000, 1);
        let (log, h) = fresh_log_and_handle();
        log.append(
            &h,
            TrustLevel::Compaction,
            SessionEvent::Compaction {
                spans: vec![3, 4],
                extracts: serde_json::json!({
                    "trimmed_bytes": 4_242_u64,
                    "kept_messages": 5_u64,
                    "dropped_messages": 2_u64,
                    "via_model": false,
                }),
                via_model: false,
            },
        )
        .unwrap();

        let mut conv = Conversation::new(0);
        conv.set_system_prompt("sys");
        conv.add_user_message("hello");

        engine
            .fit(&mut conv, &empty_tool_defs(), &*log, &h)
            .unwrap();

        let compaction_msgs: Vec<_> = conv
            .messages()
            .iter()
            .filter(|m| m.role == Role::Compaction)
            .collect();
        assert_eq!(compaction_msgs.len(), 1);
        assert!(compaction_msgs[0].content.contains("4242 byte(s)"));
        assert!(compaction_msgs[0].content.contains("2 message(s) dropped"));
    }

    #[test]
    fn message_to_json_wraps_compaction_in_fence_as_system() {
        use crate::conversation::Message;
        use crate::llm::message_to_json;

        let msg = Message {
            role: Role::Compaction,
            content: "harness aggregate".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        };
        let json = message_to_json(&msg);
        assert_eq!(json["role"], "system");
        let content = json["content"].as_str().unwrap();
        assert!(content.starts_with(crate::conversation::COMPACTION_FENCE_OPEN));
        assert!(content.ends_with(crate::conversation::COMPACTION_FENCE_CLOSE));
        assert!(content.contains("harness aggregate"));
    }

    #[test]
    fn default_system_prompt_explains_compaction_fence() {
        let prompt = crate::runtime::default_system_prompt();
        assert!(
            prompt.contains("<|compaction|>"),
            "default system prompt must teach the model what the fence is"
        );
        assert!(prompt.contains("harness"));
    }

    #[test]
    fn tool_def_ordering_is_stable() {
        // The slice 1 sort happens in process_message and
        // process_message_stream, not in ContextEngine itself. This
        // test asserts the contract: a sorted slice in produces a
        // sorted slice out.
        let mut tools = [
            ToolDef {
                name: "zebra".into(),
                description: "z".into(),
                parameters: serde_json::json!({}),
            },
            ToolDef {
                name: "apple".into(),
                description: "a".into(),
                parameters: serde_json::json!({}),
            },
            ToolDef {
                name: "mango".into(),
                description: "m".into(),
                parameters: serde_json::json!({}),
            },
        ];
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(tools[0].name, "apple");
        assert_eq!(tools[1].name, "mango");
        assert_eq!(tools[2].name, "zebra");
    }
}

// ---------------------------------------------------------------------------
// Item 10 slice 1: reproducible replay / verify
// ---------------------------------------------------------------------------

mod verify {
    use std::sync::Arc;

    use tempfile::TempDir;
    use wirken_audit::{
        HashHex, SessionEvent, SessionId, SessionLog, SqliteSessionLog, ToolCallRecord, TrustLevel,
    };

    use crate::context::ContextEngine;
    use crate::conversation::Conversation;
    use crate::llm::LlmConfig;
    use crate::runtime::{Agent, compute_messages_hash, compute_tools_hash};
    use crate::tool::is_deterministic_tool;

    fn fresh_agent_and_log() -> (Agent, Arc<dyn SessionLog>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let agent = Agent::new(
            "verify-test".into(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            log.clone(),
        )
        .unwrap();
        (agent, log, tmp)
    }

    /// Build a hash that matches what the engine would produce for
    /// a given conversation snapshot, AFTER fit() has been applied.
    fn hash_after_fit(
        engine: &ContextEngine,
        conv: &Conversation,
        tools: &[crate::tool::ToolDef],
    ) -> HashHex {
        let mut copy = conv.clone();
        let dryrun_log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let dryrun_handle = dryrun_log.handle_for(SessionId::new("dryrun"));
        engine
            .fit(&mut copy, tools, &*dryrun_log, &dryrun_handle)
            .unwrap();
        compute_messages_hash(copy.messages())
    }

    fn seed_user_message(log: &dyn SessionLog, session: &str, content: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: content.into(),
                inbound_id: None,
            },
        )
        .unwrap();
    }

    fn seed_assistant_message(log: &dyn SessionLog, session: &str, content: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::AssistantMessage {
                content: content.into(),
            },
        )
        .unwrap();
    }

    fn seed_system_prompt(log: &dyn SessionLog, session: &str, content: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::SystemPromptSet {
                content: content.into(),
            },
        )
        .unwrap();
    }

    fn seed_llm_request(
        log: &dyn SessionLog,
        session: &str,
        request_id: &str,
        messages_hash: HashHex,
        tools_hash: HashHex,
    ) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::LlmRequest {
                provider: "ollama".into(),
                model: "test".into(),
                request_id: request_id.into(),
                tools_hash,
                messages_hash,
            },
        )
        .unwrap();
    }

    fn seed_llm_response(log: &dyn SessionLog, session: &str, request_id: &str) {
        let h = log.handle_for(SessionId::new(session));
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::LlmResponse {
                request_id: request_id.into(),
                finish_reason: "text".into(),
                tokens_in: 0,
                tokens_out: 0,
                latency_ms: 1,
            },
        )
        .unwrap();
    }

    // ---- helper sanity ---------------------------------------------

    #[test]
    fn deterministic_tool_set() {
        assert!(is_deterministic_tool("read_file"));
        assert!(is_deterministic_tool("list_files"));
        assert!(!is_deterministic_tool("exec"));
        assert!(!is_deterministic_tool("write_file"));
        assert!(!is_deterministic_tool("web_search"));
        assert!(!is_deterministic_tool("generate_image"));
        assert!(!is_deterministic_tool("mcp_anything"));
    }

    #[test]
    fn empty_session_verifies_clean() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, _log, _tmp) = fresh_agent_and_log();
            let report = agent.verify().await.unwrap();
            assert!(report.is_fully_clean());
            assert_eq!(report.events_total, 0);
            assert_eq!(report.events_verified, 0);
            assert_eq!(report.events_unverifiable, 0);
        });
    }

    #[test]
    fn user_assistant_only_session_verifies_clean() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            seed_user_message(&*log, "verify-test", "hi");
            seed_assistant_message(&*log, "verify-test", "hello back");

            let report = agent.verify().await.unwrap();
            assert!(report.is_consistent());
            assert_eq!(report.events_total, 2);
            assert_eq!(report.events_verified, 2);
            assert_eq!(report.events_unverifiable, 0);
            assert!(report.events_divergent.is_empty());
        });
    }

    #[test]
    fn llm_request_with_correct_hashes_verifies() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();

            // Simulate one full turn: SystemPromptSet → user →
            // LlmRequest → LlmResponse → assistant. The
            // SystemPromptSet event is required so the verifier can
            // reconstruct the prompt that was hashed.
            let prompt = crate::runtime::default_system_prompt();
            seed_system_prompt(&*log, "verify-test", &prompt);
            seed_user_message(&*log, "verify-test", "hi");

            // Reproduce the messages_hash the verifier will compute:
            // build the same conversation, run fit(), hash it.
            let mut conv = Conversation::new(100_000);
            conv.set_system_prompt(&prompt);
            conv.add_user_message("hi");

            let engine = ContextEngine::for_model(&LlmConfig::ollama("test"));
            let tools = agent_snapshot_tools(&agent).await;
            let messages_hash = hash_after_fit(&engine, &conv, &tools);
            let tools_hash = compute_tools_hash(&tools);

            seed_llm_request(&*log, "verify-test", "req-1", messages_hash, tools_hash);
            seed_llm_response(&*log, "verify-test", "req-1");
            seed_assistant_message(&*log, "verify-test", "hello back");

            let report = agent.verify().await.unwrap();
            assert!(report.is_consistent(), "report: {report:?}");
            // 5 events: SystemPromptSet + user + LlmRequest + LlmResponse + assistant
            assert_eq!(report.events_total, 5);
            // LlmResponse is always unverifiable.
            assert_eq!(report.events_unverifiable, 1);
            // SystemPromptSet + user + LlmRequest + assistant verified
            assert_eq!(report.events_verified, 4);
        });
    }

    async fn agent_snapshot_tools(_agent: &Agent) -> Vec<crate::tool::ToolDef> {
        // Match Agent::snapshot_tool_defs exactly: when the LLM
        // config has tools_enabled = false (e.g., Ollama), the
        // agent sends no tool defs to the model and the tools_hash
        // is the hash of an empty Vec. This test uses Ollama, so
        // return empty.
        Vec::new()
    }

    #[test]
    fn llm_request_with_wrong_messages_hash_diverges() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            // Item 10 follow-up: divergence detection requires a
            // recorded SystemPromptSet — without one the LlmRequest
            // is unverifiable, not divergent.
            seed_system_prompt(
                &*log,
                "verify-test",
                &crate::runtime::default_system_prompt(),
            );
            seed_user_message(&*log, "verify-test", "hi");
            // Deliberately wrong hash.
            seed_llm_request(
                &*log,
                "verify-test",
                "req-1",
                HashHex("0".repeat(64)),
                HashHex("0".repeat(64)),
            );

            let report = agent.verify().await.unwrap();
            assert!(!report.is_consistent());
            // At least one divergence on the LlmRequest event.
            assert!(
                report
                    .events_divergent
                    .iter()
                    .any(|d| d.kind == "messages_hash")
            );
        });
    }

    #[test]
    fn llm_response_always_unverifiable() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            // Just one LlmResponse with no surrounding events.
            seed_llm_response(&*log, "verify-test", "req-orphan");

            let report = agent.verify().await.unwrap();
            assert_eq!(report.events_total, 1);
            assert_eq!(report.events_unverifiable, 1);
            assert!(report.events_divergent.is_empty());
            // is_consistent() — chain ok, no divergences.
            assert!(report.is_consistent());
            // is_fully_clean() — no, because there's an
            // unverifiable event.
            assert!(!report.is_fully_clean());
        });
    }

    #[test]
    fn deterministic_tool_re_executes_and_matches() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, tmp) = fresh_agent_and_log();
            // Create a file the read_file tool will inspect.
            let path = tmp.path().join("note.txt");
            std::fs::write(&path, "hello from disk").unwrap();

            // Seed a conversation that read it. The conversation
            // structure must include AssistantToolCalls before
            // ToolResult so the verifier can find the arguments.
            seed_user_message(&*log, "verify-test", "read note");
            let h = log.handle_for(SessionId::new("verify-test"));
            log.append(
                &h,
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: vec![ToolCallRecord {
                        id: "c1".into(),
                        name: "read_file".into(),
                        arguments: serde_json::json!({ "path": "note.txt" }).to_string(),
                    }],
                },
            )
            .unwrap();
            log.append(
                &h,
                TrustLevel::Tool,
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "read_file".into(),
                    output: "hello from disk".into(),
                    success: true,
                },
            )
            .unwrap();

            let report = agent.verify().await.unwrap();
            assert!(report.is_consistent(), "report: {report:?}");
            assert!(report.events_divergent.is_empty());
            // user + tool_calls + tool_result all verified
            assert_eq!(report.events_verified, 3);
        });
    }

    #[test]
    fn deterministic_tool_diverges_when_workspace_changed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, tmp) = fresh_agent_and_log();
            // The recorded output is "OLD" but the workspace now
            // says "NEW".
            std::fs::write(tmp.path().join("note.txt"), "NEW").unwrap();

            seed_user_message(&*log, "verify-test", "read note");
            let h = log.handle_for(SessionId::new("verify-test"));
            log.append(
                &h,
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: vec![ToolCallRecord {
                        id: "c1".into(),
                        name: "read_file".into(),
                        arguments: serde_json::json!({ "path": "note.txt" }).to_string(),
                    }],
                },
            )
            .unwrap();
            log.append(
                &h,
                TrustLevel::Tool,
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "read_file".into(),
                    output: "OLD".into(),
                    success: true,
                },
            )
            .unwrap();

            let report = agent.verify().await.unwrap();
            assert_eq!(report.events_divergent.len(), 1);
            let div = &report.events_divergent[0];
            assert_eq!(div.kind, "tool_result");
            assert_eq!(div.expected, "OLD");
            assert!(div.found.contains("NEW"));
        });
    }

    #[test]
    fn non_deterministic_tool_is_unverifiable() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            seed_user_message(&*log, "verify-test", "run something");
            let h = log.handle_for(SessionId::new("verify-test"));
            log.append(
                &h,
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: vec![ToolCallRecord {
                        id: "c1".into(),
                        name: "exec".into(),
                        arguments: serde_json::json!({"command":"date"}).to_string(),
                    }],
                },
            )
            .unwrap();
            log.append(
                &h,
                TrustLevel::Tool,
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "exec".into(),
                    output: "Wed Apr 9 12:34:56 UTC 2026".into(),
                    success: true,
                },
            )
            .unwrap();

            let report = agent.verify().await.unwrap();
            // exec is non-deterministic → unverifiable, not divergent.
            assert!(report.events_divergent.is_empty());
            assert!(report.events_unverifiable >= 1);
        });
    }

    // Chain-break short-circuit is tested through Agent::verify's
    // forwarding behavior — the underlying SessionLog::verify is
    // exhaustively tested in crates/audit/src/tests.rs::session::
    // verify_detects_payload_tampering and
    // verify_detects_chain_hash_tampering. We don't duplicate the
    // raw-connection corruption tests at this layer because
    // wirken-agent doesn't depend on rusqlite.

    // -----------------------------------------------------------------
    // Item 10 follow-up: SystemPromptSet recording and verification
    // -----------------------------------------------------------------

    #[test]
    fn legacy_session_without_prompt_event_marks_llm_request_unverifiable() {
        // A session that has an LlmRequest but no preceding
        // SystemPromptSet event (the way item 10 slice 1 wrote
        // sessions before this fix). The verifier cannot reproduce
        // the prompt that was hashed, so the LlmRequest must be
        // reported as unverifiable, NOT divergent.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            seed_user_message(&*log, "verify-test", "hi");
            seed_llm_request(
                &*log,
                "verify-test",
                "req-1",
                HashHex("0".repeat(64)),
                HashHex("0".repeat(64)),
            );

            let report = agent.verify().await.unwrap();
            // No divergence — the verifier punts on LlmRequests
            // without a recorded prompt.
            assert!(
                report.events_divergent.is_empty(),
                "expected no divergences for legacy session, got {:?}",
                report.events_divergent
            );
            // The LlmRequest counts as unverifiable.
            assert!(report.events_unverifiable >= 1);
        });
    }

    #[test]
    fn drifted_default_prompt_does_not_invalidate_recorded_session() {
        // Simulate a session recorded under one prompt, then
        // verified after the agent's own `self.system_prompt` has
        // moved on. The recorded SystemPromptSet must take
        // precedence over the agent's current default.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (agent, log, _tmp) = fresh_agent_and_log();
            // Record under an OLD prompt that does NOT match the
            // agent's current default_system_prompt.
            let old_prompt = "you are a small old bot";
            seed_system_prompt(&*log, "verify-test", old_prompt);
            seed_user_message(&*log, "verify-test", "hi");

            // Compute the messages_hash the verifier should expect:
            // it must rebuild the conversation with the OLD prompt,
            // not the agent's current default.
            let mut conv = Conversation::new(100_000);
            conv.set_system_prompt(old_prompt);
            conv.add_user_message("hi");

            let engine = ContextEngine::for_model(&LlmConfig::ollama("test"));
            let tools = agent_snapshot_tools(&agent).await;
            let messages_hash = hash_after_fit(&engine, &conv, &tools);
            let tools_hash = compute_tools_hash(&tools);

            seed_llm_request(&*log, "verify-test", "req-1", messages_hash, tools_hash);

            let report = agent.verify().await.unwrap();
            assert!(
                report.events_divergent.is_empty(),
                "expected no divergences when verifier uses recorded prompt, got {:?}",
                report.events_divergent
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Item 10 follow-up: SystemPromptSet write side and replay
// ---------------------------------------------------------------------------

mod system_prompt_event {
    use std::sync::Arc;

    use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};

    use crate::conversation::{Conversation, Role};

    fn make_log() -> Arc<dyn SessionLog> {
        Arc::new(SqliteSessionLog::open_in_memory().unwrap())
    }

    #[test]
    fn replay_from_log_applies_recorded_prompt() {
        // A session log with a SystemPromptSet event followed by a
        // user message. After replay the conversation's first
        // message should be the recorded prompt, not whatever
        // the caller pre-set.
        let log = make_log();
        let h = log.handle_for(SessionId::new("test"));
        log.append(
            &h,
            wirken_audit::TrustLevel::System,
            SessionEvent::SystemPromptSet {
                content: "harness-recorded prompt".into(),
            },
        )
        .unwrap();
        log.append(
            &h,
            wirken_audit::TrustLevel::User,
            SessionEvent::UserMessage {
                content: "hi".into(),
                inbound_id: None,
            },
        )
        .unwrap();

        let mut conv = Conversation::new(100_000);
        conv.set_system_prompt("stale fallback prompt");
        conv.replay_from_log(&*log, &h).unwrap();

        let messages = conv.messages();
        assert_eq!(messages[0].role, Role::System);
        assert_eq!(messages[0].content, "harness-recorded prompt");
        assert_eq!(messages[1].role, Role::User);
    }

    #[test]
    fn most_recent_recorded_prompt_wins_during_replay() {
        // Multiple SystemPromptSet events in the same session —
        // simulates a skill being installed mid-session, or the
        // default prompt drifting between binary versions. Replay
        // should reflect the latest one.
        let log = make_log();
        let h = log.handle_for(SessionId::new("test"));
        log.append(
            &h,
            wirken_audit::TrustLevel::System,
            SessionEvent::SystemPromptSet {
                content: "first".into(),
            },
        )
        .unwrap();
        log.append(
            &h,
            wirken_audit::TrustLevel::User,
            SessionEvent::UserMessage {
                content: "early".into(),
                inbound_id: None,
            },
        )
        .unwrap();
        log.append(
            &h,
            wirken_audit::TrustLevel::System,
            SessionEvent::SystemPromptSet {
                content: "second".into(),
            },
        )
        .unwrap();
        log.append(
            &h,
            wirken_audit::TrustLevel::User,
            SessionEvent::UserMessage {
                content: "later".into(),
                inbound_id: None,
            },
        )
        .unwrap();

        let mut conv = Conversation::new(100_000);
        conv.replay_from_log(&*log, &h).unwrap();
        assert_eq!(conv.messages()[0].content, "second");
    }
}
