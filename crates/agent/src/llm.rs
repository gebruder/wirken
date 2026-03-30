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
    /// Enforces HTTPS for non-localhost endpoints to prevent API key leakage.
    pub fn new(config: LlmConfig) -> Result<Self, AgentError> {
        let is_localhost = config.base_url.starts_with("http://localhost")
            || config.base_url.starts_with("http://127.0.0.1")
            || config.base_url.starts_with("http://[::1]");

        if !config.base_url.starts_with("https://") && !is_localhost {
            return Err(AgentError::Http(format!(
                "LLM endpoint must use HTTPS (got {}). Use HTTPS or localhost.",
                config.base_url
            )));
        }

        let http = reqwest::Client::builder()
            .https_only(!is_localhost)
            .build()
            .map_err(|e| AgentError::Http(format!("HTTP client: {e}")))?;

        Ok(Self { config, http })
    }

    /// Send a chat completion request.
    /// The API key is passed in as a parameter — the client never stores it.
    pub async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        if self.config.provider == "anthropic" {
            return self.complete_anthropic(messages, tools, api_key).await;
        }
        self.complete_openai(messages, tools, api_key).await
    }

    /// OpenAI-compatible completion (OpenAI, Ollama, custom endpoints).
    async fn complete_openai(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        let url = format!("{}/chat/completions", self.config.base_url);

        let messages_json: Vec<serde_json::Value> = messages.iter().map(message_to_json).collect();

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages_json,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        });

        if !tools.is_empty() {
            let tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let mut request = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body);

        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {key}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| AgentError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        parse_completion_response(&response_body)
    }

    /// Anthropic Messages API completion.
    async fn complete_anthropic(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        let url = format!("{}/messages", self.config.base_url);

        // Anthropic separates system prompt from messages
        let system_prompt: String = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");

        let messages_json: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| {
                let role = match m.role {
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "user", // Anthropic: tool results go in user messages
                    Role::System => unreachable!(),
                };
                let mut obj = serde_json::json!({
                    "role": role,
                    "content": m.content,
                });
                // Tool results: wrap in tool_result content block
                if m.role == Role::Tool
                    && let Some(ref id) = m.tool_call_id
                {
                    obj = serde_json::json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": m.content,
                        }]
                    });
                }
                obj
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages_json,
            "max_tokens": self.config.max_tokens,
        });

        if !system_prompt.is_empty() {
            body["system"] = serde_json::Value::String(system_prompt);
        }

        if !tools.is_empty() {
            let tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.parameters,
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let mut request = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("anthropic-version", "2023-06-01");

        if let Some(key) = api_key {
            request = request.header("x-api-key", key);
        }

        let request = request.json(&body);

        let response = request
            .send()
            .await
            .map_err(|e| AgentError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        parse_anthropic_response(&response_body)
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
        let calls: Vec<serde_json::Value> = tool_calls
            .iter()
            .map(|tc| {
                serde_json::json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                })
            })
            .collect();
        obj["tool_calls"] = serde_json::Value::Array(calls);
    }

    obj
}

pub fn parse_completion_response(body: &serde_json::Value) -> Result<LlmResponse, AgentError> {
    let choice = body
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| AgentError::Llm("no choices in response".into()))?;

    let message = choice
        .get("message")
        .ok_or_else(|| AgentError::Llm("no message in choice".into()))?;

    // Check for tool calls
    if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
        let calls: Vec<ToolCallRequest> = tool_calls
            .iter()
            .filter_map(|tc| {
                let id = tc.get("id")?.as_str()?.to_string();
                let func = tc.get("function")?;
                let name = func.get("name")?.as_str()?.to_string();
                let arguments = func.get("arguments")?.as_str()?.to_string();
                Some(ToolCallRequest {
                    id,
                    name,
                    arguments,
                })
            })
            .collect();

        if !calls.is_empty() {
            return Ok(LlmResponse::ToolCalls(calls));
        }
    }

    // Text response
    if let Some(content) = message.get("content").and_then(|c| c.as_str())
        && !content.is_empty()
    {
        return Ok(LlmResponse::Text(content.to_string()));
    }

    Ok(LlmResponse::Empty)
}

/// Parse an Anthropic Messages API response.
pub fn parse_anthropic_response(body: &serde_json::Value) -> Result<LlmResponse, AgentError> {
    let content = body
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no content array in Anthropic response".into()))?;

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in content {
        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match block_type {
            "text" => {
                if let Some(text) = block.get("text").and_then(|t| t.as_str())
                    && !text.is_empty()
                {
                    text_parts.push(text.to_string());
                }
            }
            "tool_use" => {
                let id = block
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = block.get("input").unwrap_or(&serde_json::Value::Null);
                let arguments = input.to_string();
                tool_calls.push(ToolCallRequest {
                    id,
                    name,
                    arguments,
                });
            }
            _ => {}
        }
    }

    if !tool_calls.is_empty() {
        return Ok(LlmResponse::ToolCalls(tool_calls));
    }

    if !text_parts.is_empty() {
        return Ok(LlmResponse::Text(text_parts.join("")));
    }

    Ok(LlmResponse::Empty)
}

/// Build the tool definitions in OpenAI function calling format.
pub fn tools_to_json(tools: &[ToolDef]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            })
        })
        .collect()
}
