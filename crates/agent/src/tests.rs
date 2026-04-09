use std::path::PathBuf;
use tempfile::TempDir;

use crate::conversation::{Conversation, Role};
use crate::llm::{LlmConfig, LlmResponse};
use crate::skill::{Skill, SkillLoader};
use crate::tool::{ToolConfig, ToolRegistry};

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
    )
    .unwrap();

    // System prompt is set on creation
    assert!(agent.conversation_len() > 0);
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

    use crate::mcp::McpProxyClient;

    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    // Start a proxy server in-process with an empty registry. The
    // server::serve loop binds the socket and accepts connections; we
    // abort it at the end of the test.
    let server_socket = socket_path.clone();
    let registry = Arc::new(Mutex::new(ProxyRegistry::new()));
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, registry).await;
    });

    // McpProxyClient::connect already retries the socket, so we don't
    // need to wait for the file ourselves — it will appear within the
    // 5s connect window.
    let mut client = McpProxyClient::connect(&socket_path, "test-agent")
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
        SessionEvent::UserMessage { content: s.into() }
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
