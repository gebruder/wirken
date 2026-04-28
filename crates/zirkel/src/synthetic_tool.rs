//! Synthetic tool calls as a structured-output channel.
//!
//! ## Why this exists
//!
//! C-LLM scoring and theme naming need structured LLM output. The
//! existing [`wirken_agent::llm::LlmClient`] does not (yet) plumb a
//! `response_format` / JSON-mode knob through any provider; its only
//! structured output path is the `tool_calls` mechanism that's
//! already wired end-to-end. Per the C-LLM pre-checks (Path B),
//! Zirkel uses synthetic tools — tools the orchestrator knows the
//! LLM will never actually execute — as a structured-output channel.
//! The LLM "calls" the tool with strongly-typed arguments; the
//! orchestrator parses the call's `arguments` JSON into the
//! caller-chosen Rust type.
//!
//! ## This is a Zirkel-internal idiom
//!
//! The `zirkel_`-prefixed tool names (`zirkel_score_candidate`,
//! `zirkel_name_theme`) mark this as Zirkel-specific, not a
//! Wirken-wide convention. Future skills should not reach for this
//! pattern casually. **A third consumer doing the same thing is the
//! signal to extract real JSON-mode support into `LlmClient`** —
//! provider-by-provider work, but the right shape once there are
//! multiple real consumers.
//!
//! Until then, the synthetic-tool channel is good enough for two
//! Zirkel call sites, and adding generic JSON mode to LlmClient
//! preemptively would shape that surface around an uncommitted
//! second-consumer boundary.
//!
//! ## Risk: weaker tool-calling models
//!
//! The OpenAI / Anthropic / Gemini tool-calling APIs are strict
//! enough that a competent model called with this synthetic tool
//! and a clear prompt will reliably emit a tool call. Local Ollama
//! models with weaker tool support may sometimes return text
//! instead, producing [`SyntheticToolError::ExpectedToolCallGotText`].
//! The default Ollama model for Zirkel (`llama3.1:8b`) handles this
//! reliably; weaker models are not currently supported.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use wirken_agent::conversation::{Message, Role};
use wirken_agent::error::AgentError;
use wirken_agent::llm::{LlmClient, LlmResponse};
use wirken_agent::tool::ToolDef;

/// Tool def for `zirkel_score_candidate` — used by the LLM relevance
/// scorer. Output type: [`ScoreCandidateArgs`].
pub fn score_candidate_tool() -> ToolDef {
    ToolDef {
        name: "zirkel_score_candidate".to_string(),
        description: "Return a structured relevance score for the candidate item against the user's interests. \
                      You MUST call this tool with the score, why-surfaced rationale, and matched keyword. \
                      Do not respond with text.".to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Relevance score 0–100. 0 = irrelevant. 50 = matches a user interest broadly. 100 = directly addresses a user keyword in a substantive way."
                },
                "why_surfaced": {
                    "type": "string",
                    "description": "One-line rationale (≤140 chars). Cite the matched user interest by name and how the candidate's content relates to it."
                },
                "matched_keyword": {
                    "type": "string",
                    "description": "The single user keyword that best characterizes the match. Must be one of the user keywords provided in the prompt."
                }
            },
            "required": ["score", "why_surfaced", "matched_keyword"]
        }),
    }
}

/// Output shape for [`score_candidate_tool`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ScoreCandidateArgs {
    pub score: u32,
    pub why_surfaced: String,
    pub matched_keyword: String,
}

/// Tool def for `zirkel_name_theme` — used by the theme naming pass.
/// Output type: [`NameThemeArgs`].
pub fn name_theme_tool() -> ToolDef {
    ToolDef {
        name: "zirkel_name_theme".to_string(),
        description: "Return a 2–5 word theme name for a cluster of related candidates. \
                      You MUST call this tool. Do not respond with text or quotes."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "2–5 word theme name. Examples: 'FTC enforcement', 'EU AI Act', 'biometric privacy in employment'. No cluster ids, no jargon, no quotes."
                }
            },
            "required": ["name"]
        }),
    }
}

/// Output shape for [`name_theme_tool`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NameThemeArgs {
    pub name: String,
}

#[derive(Debug, Error)]
pub enum SyntheticToolError {
    #[error("LLM call failed: {0}")]
    Llm(#[source] AgentError),
    #[error("expected a tool call to '{expected}' but the LLM responded with text: {text}")]
    ExpectedToolCallGotText { expected: String, text: String },
    #[error("LLM returned an empty response")]
    EmptyResponse,
    #[error("LLM made tool calls but none were to '{expected}'; calls: {actual:?}")]
    ToolNotCalled {
        expected: String,
        actual: Vec<String>,
    },
    #[error("could not parse '{tool}' arguments as the expected shape: {error}; raw: {raw}")]
    ParseArguments {
        tool: String,
        error: String,
        raw: String,
    },
}

/// Run a structured-output LLM call. Builds a 2-message conversation
/// (system + user), passes the supplied synthetic tool, and parses
/// the LLM's tool-call arguments into `T`.
///
/// `T` must `derive(Deserialize)` matching the tool's `parameters`
/// JSON schema.
pub async fn call_structured<T: DeserializeOwned>(
    llm: &LlmClient,
    api_key: Option<&str>,
    system_prompt: &str,
    user_prompt: &str,
    tool: ToolDef,
) -> Result<T, SyntheticToolError> {
    let tool_name = tool.name.clone();
    let messages = vec![
        Message {
            role: Role::System,
            content: system_prompt.to_string(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        },
        Message {
            role: Role::User,
            content: user_prompt.to_string(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        },
    ];
    let resp = llm
        .complete(&messages, &[tool], api_key)
        .await
        .map_err(SyntheticToolError::Llm)?;
    match resp {
        LlmResponse::ToolCalls(calls) => {
            let actual: Vec<String> = calls.iter().map(|c| c.name.clone()).collect();
            let call = calls.iter().find(|c| c.name == tool_name).ok_or_else(|| {
                SyntheticToolError::ToolNotCalled {
                    expected: tool_name.clone(),
                    actual,
                }
            })?;
            serde_json::from_str::<T>(&call.arguments).map_err(|e| {
                SyntheticToolError::ParseArguments {
                    tool: tool_name,
                    error: e.to_string(),
                    raw: call.arguments.clone(),
                }
            })
        }
        LlmResponse::Text(t) => Err(SyntheticToolError::ExpectedToolCallGotText {
            expected: tool_name,
            text: t,
        }),
        LlmResponse::Empty => Err(SyntheticToolError::EmptyResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_candidate_tool_def_has_required_fields() {
        let tool = score_candidate_tool();
        assert_eq!(tool.name, "zirkel_score_candidate");
        let required = tool
            .parameters
            .get("required")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(required.contains(&"score".to_string()));
        assert!(required.contains(&"why_surfaced".to_string()));
        assert!(required.contains(&"matched_keyword".to_string()));
    }

    #[test]
    fn name_theme_tool_def_requires_name() {
        let tool = name_theme_tool();
        assert_eq!(tool.name, "zirkel_name_theme");
        let required = tool
            .parameters
            .get("required")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].as_str().unwrap(), "name");
    }

    #[test]
    fn score_args_round_trip_through_serde() {
        let json = r#"{"score": 75, "why_surfaced": "matched 'BIPA' — biometric enforcement", "matched_keyword": "BIPA"}"#;
        let parsed: ScoreCandidateArgs = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.score, 75);
        assert_eq!(parsed.matched_keyword, "BIPA");
        assert!(parsed.why_surfaced.contains("biometric"));
    }

    #[test]
    fn theme_name_args_round_trip() {
        let json = r#"{"name": "FTC enforcement"}"#;
        let parsed: NameThemeArgs = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, "FTC enforcement");
    }

    // Live LlmClient end-to-end is exercised by the orchestrator-
    // level test in `crate::orchestrator::tests` against a mocked
    // OpenAI-compatible HTTP server. Unit-testing call_structured in
    // isolation would require either spinning up a similar server
    // here or refactoring LlmClient to accept an injected transport;
    // the orchestrator integration test gives better coverage for
    // less code.
}
