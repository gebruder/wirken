use serde::{Deserialize, Serialize};

use crate::conversation::{Message, Role, ToolCallRequest};
use crate::error::AgentError;
use crate::tool::ToolDef;

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name: "openai", "anthropic", "ollama", "custom"
    pub provider: String,
    /// Model ID (e.g., "gpt-4o", "claude-sonnet-4-20250514", "llama3")
    pub model: String,
    /// API base URL
    pub base_url: String,
    /// Max tokens in response
    pub max_tokens: u32,
    /// Temperature (0.0 - 2.0)
    pub temperature: f32,
}

impl LlmConfig {
    /// OpenAI defaults
    pub fn openai(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: "https://api.openai.com/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
        }
    }

    /// Anthropic defaults
    pub fn anthropic(model: &str) -> Self {
        Self {
            provider: "anthropic".into(),
            model: model.into(),
            base_url: "https://api.anthropic.com/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
        }
    }

    /// Ollama defaults (local)
    pub fn ollama(model: &str) -> Self {
        Self {
            provider: "ollama".into(),
            model: model.into(),
            base_url: "http://localhost:11434/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
        }
    }

    /// Custom OpenAI-compatible endpoint
    pub fn custom(base_url: &str, model: &str) -> Self {
        Self {
            provider: "custom".into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: 4096,
            temperature: 0.7,
        }
    }
}

/// Response from the LLM.
#[derive(Debug, Clone)]
pub enum LlmResponse {
    /// Text response — the assistant replied with content.
    Text(String),
    /// Tool calls — the assistant wants to call tools.
    ToolCalls(Vec<ToolCallRequest>),
    /// Empty response (shouldn't happen but handle gracefully).
    Empty,
}

/// LLM client that makes completion requests.
/// Currently supports OpenAI-compatible APIs (OpenAI, Ollama, custom).
pub struct LlmClient {
    config: LlmConfig,
    http: reqwest::Client,
}

impl LlmClient {
    /// Create a new LLM client.
    pub fn new(config: LlmConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Send a chat completion request.
    /// The API key is passed in as a parameter — the client never stores it.
    pub async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        let url = format!("{}/chat/completions", self.config.base_url);

        // Build request body (OpenAI format — works for OpenAI, Ollama, and compatible APIs)
        let messages_json: Vec<serde_json::Value> = messages.iter()
            .map(|m| message_to_json(m))
            .collect();

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages_json,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        });

        // Add tools if any
        if !tools.is_empty() {
            let tools_json: Vec<serde_json::Value> = tools.iter()
                .map(|t| serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                }))
                .collect();
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let mut request = self.http.post(&url)
            .header("Content-Type", "application/json")
            .json(&body);

        // Set auth header if API key provided
        if let Some(key) = api_key {
            if self.config.provider == "anthropic" {
                request = request.header("x-api-key", key)
                    .header("anthropic-version", "2023-06-01");
            } else {
                request = request.header("Authorization", format!("Bearer {key}"));
            }
        }

        let response = request.send().await
            .map_err(|e| AgentError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response.json().await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        parse_completion_response(&response_body)
    }

    /// Get the current config.
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }
}

fn message_to_json(msg: &Message) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "role": msg.role,
        "content": msg.content,
    });

    if let Some(ref tool_call_id) = msg.tool_call_id {
        obj["tool_call_id"] = serde_json::Value::String(tool_call_id.clone());
    }

    if let Some(ref tool_calls) = msg.tool_calls {
        let calls: Vec<serde_json::Value> = tool_calls.iter()
            .map(|tc| serde_json::json!({
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.name,
                    "arguments": tc.arguments,
                }
            }))
            .collect();
        obj["tool_calls"] = serde_json::Value::Array(calls);
    }

    obj
}

pub fn parse_completion_response(body: &serde_json::Value) -> Result<LlmResponse, AgentError> {
    let choice = body.get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| AgentError::Llm("no choices in response".into()))?;

    let message = choice.get("message")
        .ok_or_else(|| AgentError::Llm("no message in choice".into()))?;

    // Check for tool calls
    if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
        let calls: Vec<ToolCallRequest> = tool_calls.iter()
            .filter_map(|tc| {
                let id = tc.get("id")?.as_str()?.to_string();
                let func = tc.get("function")?;
                let name = func.get("name")?.as_str()?.to_string();
                let arguments = func.get("arguments")?.as_str()?.to_string();
                Some(ToolCallRequest { id, name, arguments })
            })
            .collect();

        if !calls.is_empty() {
            return Ok(LlmResponse::ToolCalls(calls));
        }
    }

    // Text response
    if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
        if !content.is_empty() {
            return Ok(LlmResponse::Text(content.to_string()));
        }
    }

    Ok(LlmResponse::Empty)
}

/// Build the tool definitions in OpenAI function calling format.
pub fn tools_to_json(tools: &[ToolDef]) -> Vec<serde_json::Value> {
    tools.iter()
        .map(|t| serde_json::json!({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            }
        }))
        .collect()
}
