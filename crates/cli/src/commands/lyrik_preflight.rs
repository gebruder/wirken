//! Tool-call preflight for the Lyrik runner.
//!
//! Runs once at run start against the same dispatch path the real
//! audit uses (`LlmClient::complete`), against the model pin in the
//! target's `.lyrik/config.json`. Sends a trivial prompt with one
//! tool defined and an instruction to call it; classifies the
//! response and either passes the run through or fails closed.
//!
//! Fail-closed rather than degrade-and-continue (the
//! `lyrik.scanner.unavailable` shape) because a model that cannot
//! emit tool calls produces a worthless audit. Three observed
//! failure cases on local Ollama models:
//!
//! - `provider_rejected`: Ollama returns HTTP 4xx with
//!   `does not support tools` (gemma2:9b, gemma3:12b on stock
//!   Modelfiles).
//! - `tool_call_as_text`: the model emits a tool-call-shaped JSON
//!   object in message content instead of as a structured tool_call
//!   (qwen2.5-coder variants whose FIM template short-circuits the
//!   tool-call section).
//! - `no_tool_call`: the model emits prose or empty content with no
//!   tool call attempted (small models that drop the loop entirely).
//!
//! The probe shares no state with the rest of the run; a `LlmClient`
//! is built fresh from the resolved pin so the verdict reflects what
//! the agent runtime would see.

use anyhow::Result;
use serde_json::json;
use wirken_agent::AgentError;
use wirken_agent::conversation::{Message, Role};
use wirken_agent::llm::{LlmClient, LlmConfig, LlmResponse, Usage};
use wirken_agent::tool::ToolDef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Pass,
    Fail { case: FailCase, detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailCase {
    /// HTTP 4xx from the provider, e.g. Ollama's "does not support tools".
    ProviderRejected,
    /// Tool-call-shaped JSON appeared in `content` instead of `tool_calls`.
    ToolCallAsText,
    /// No structured tool_calls and no tool-call-shaped JSON in content.
    NoToolCall,
    /// Structured tool_calls came back but `arguments` failed to parse.
    UnparseableArguments,
}

impl FailCase {
    pub fn as_str(self) -> &'static str {
        match self {
            FailCase::ProviderRejected => "provider_rejected",
            FailCase::ToolCallAsText => "tool_call_as_text",
            FailCase::NoToolCall => "no_tool_call",
            FailCase::UnparseableArguments => "unparseable_arguments",
        }
    }
}

const PROBE_TOOL_NAME: &str = "probe_ping";

/// Run the probe and classify the response. Errors that are not a
/// classification verdict (network failure, malformed response,
/// non-4xx provider error) propagate as `Err`.
pub async fn probe_tool_calling(
    llm_config: &LlmConfig,
    api_key: Option<&str>,
) -> Result<ProbeOutcome> {
    let client = LlmClient::new(llm_config.clone())
        .map_err(|e| anyhow::anyhow!("preflight: build llm client: {e}"))?;
    let messages = vec![Message {
        role: Role::User,
        content: format!(
            "Call the `{PROBE_TOOL_NAME}` tool with `marker: \"ok\"` so I can verify tool-call wiring. Respond by calling the tool; do not reply in prose."
        ),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    }];
    let tools = vec![ToolDef {
        name: PROBE_TOOL_NAME.into(),
        description: "Acknowledge a probe call by echoing the marker string.".into(),
        parameters: json!({
            "type": "object",
            "properties": {"marker": {"type": "string"}},
            "required": ["marker"]
        }),
    }];

    let result = client.complete(&messages, &tools, api_key).await;
    classify(result)
}

/// Map a raw `complete()` result to a [`ProbeOutcome`]. Extracted so
/// the classification can be unit-tested without a real provider.
pub fn classify(result: Result<(LlmResponse, Option<Usage>), AgentError>) -> Result<ProbeOutcome> {
    match result {
        Ok((LlmResponse::ToolCalls(calls), _)) => {
            let Some(c) = calls.first() else {
                return Ok(ProbeOutcome::Fail {
                    case: FailCase::NoToolCall,
                    detail: "structured tool_calls list was empty".into(),
                });
            };
            match serde_json::from_str::<serde_json::Value>(&c.arguments) {
                Ok(_) => Ok(ProbeOutcome::Pass),
                Err(e) => Ok(ProbeOutcome::Fail {
                    case: FailCase::UnparseableArguments,
                    detail: format!(
                        "structured tool_call returned with unparseable arguments: {e}; raw: {:?}",
                        truncate(&c.arguments, 200)
                    ),
                }),
            }
        }
        Ok((LlmResponse::Text(s), _)) => {
            let toolish = s.contains("\"name\"") && s.contains("\"arguments\"");
            Ok(ProbeOutcome::Fail {
                case: if toolish {
                    FailCase::ToolCallAsText
                } else {
                    FailCase::NoToolCall
                },
                detail: format!(
                    "model returned text content ({} chars): {:?}",
                    s.len(),
                    truncate(&s, 200)
                ),
            })
        }
        Ok((LlmResponse::Empty, _)) => Ok(ProbeOutcome::Fail {
            case: FailCase::NoToolCall,
            detail: "model returned no content and no tool_calls".into(),
        }),
        Err(AgentError::Llm(msg)) if msg.starts_with("HTTP 4") => Ok(ProbeOutcome::Fail {
            case: FailCase::ProviderRejected,
            detail: msg,
        }),
        Err(e) => Err(anyhow::anyhow!("preflight: {e}")),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.into()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_agent::conversation::ToolCallRequest;

    #[test]
    fn parseable_tool_call_passes() {
        let resp = LlmResponse::ToolCalls(vec![ToolCallRequest {
            id: "1".into(),
            name: "probe_ping".into(),
            arguments: r#"{"marker": "ok"}"#.into(),
        }]);
        assert_eq!(classify(Ok((resp, None))).unwrap(), ProbeOutcome::Pass);
    }

    #[test]
    fn empty_tool_call_list_is_no_tool_call() {
        let resp = LlmResponse::ToolCalls(vec![]);
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::NoToolCall),
            ProbeOutcome::Pass => panic!("empty tool call list must fail"),
        }
    }

    #[test]
    fn tool_call_with_bad_args_is_unparseable() {
        let resp = LlmResponse::ToolCalls(vec![ToolCallRequest {
            id: "1".into(),
            name: "probe_ping".into(),
            arguments: r#"{marker: "ok"#.into(),
        }]);
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::UnparseableArguments),
            ProbeOutcome::Pass => panic!("bad args must fail"),
        }
    }

    #[test]
    fn tool_shaped_text_is_tool_call_as_text() {
        let resp =
            LlmResponse::Text(r#"{"name": "probe_ping", "arguments": {"marker": "ok"}}"#.into());
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::ToolCallAsText),
            ProbeOutcome::Pass => panic!("text-shaped tool call must fail"),
        }
    }

    #[test]
    fn fenced_tool_shaped_text_is_tool_call_as_text() {
        let resp = LlmResponse::Text(
            "```json\n{\n  \"name\": \"probe_ping\",\n  \"arguments\": {\"marker\": \"ok\"}\n}\n```"
                .into(),
        );
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::ToolCallAsText),
            ProbeOutcome::Pass => panic!("fenced text-shaped tool call must fail"),
        }
    }

    #[test]
    fn plain_prose_is_no_tool_call() {
        let resp = LlmResponse::Text("I'll get right on that".into());
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::NoToolCall),
            ProbeOutcome::Pass => panic!("prose must fail"),
        }
    }

    #[test]
    fn empty_response_is_no_tool_call() {
        let resp = LlmResponse::Empty;
        let out = classify(Ok((resp, None))).unwrap();
        match out {
            ProbeOutcome::Fail { case, .. } => assert_eq!(case, FailCase::NoToolCall),
            ProbeOutcome::Pass => panic!("empty must fail"),
        }
    }

    #[test]
    fn http_400_is_provider_rejected() {
        let err = AgentError::Llm(
            "HTTP 400 Bad Request: {\"error\":\"registry.ollama.ai/library/gemma2:9b does not support tools\"}".into(),
        );
        let out = classify(Err(err)).unwrap();
        match out {
            ProbeOutcome::Fail { case, detail } => {
                assert_eq!(case, FailCase::ProviderRejected);
                assert!(detail.contains("does not support tools"));
            }
            ProbeOutcome::Pass => panic!("HTTP 400 must fail"),
        }
    }

    #[test]
    fn http_500_propagates_as_error() {
        let err = AgentError::Llm("HTTP 503 Service Unavailable".into());
        assert!(classify(Err(err)).is_err());
    }

    #[test]
    fn network_error_propagates_as_error() {
        let err = AgentError::Http("connection refused".into());
        assert!(classify(Err(err)).is_err());
    }

    #[test]
    fn truncate_handles_multibyte_boundary() {
        let s = "x".repeat(50) + "é" + &"y".repeat(50);
        let out = truncate(&s, 50);
        assert!(out.ends_with("..."));
        assert!(out.len() <= 53);
    }
}
