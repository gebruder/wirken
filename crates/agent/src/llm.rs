use serde::{Deserialize, Serialize};

use crate::conversation::{Message, Role, ToolCallRequest};
use crate::error::AgentError;
use crate::tool::ToolDef;

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name: "openai", "anthropic", "gemini", "bedrock", "ollama", "custom"
    pub provider: String,
    /// Model ID (e.g., "gpt-4o", "claude-sonnet-4-20250514", "gemini-2.0-flash")
    pub model: String,
    /// API base URL
    pub base_url: String,
    /// Max tokens in response
    pub max_tokens: u32,
    /// Temperature (0.0 - 2.0)
    pub temperature: f32,
    /// AWS region for Bedrock. Ignored for other providers.
    #[serde(default)]
    pub region: Option<String>,
    /// Whether to send tool definitions to the LLM. Defaults to true for
    /// providers with reliable tool support, false for local models.
    #[serde(default = "default_tools_enabled")]
    pub tools_enabled: bool,
}

fn default_tools_enabled() -> bool {
    true
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
            region: None,
            tools_enabled: true,
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
            region: None,
            tools_enabled: true,
        }
    }

    /// Google Gemini defaults
    pub fn gemini(model: &str) -> Self {
        Self {
            provider: "gemini".into(),
            model: model.into(),
            base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
        }
    }

    /// AWS Bedrock defaults
    pub fn bedrock(model: &str, region: &str) -> Self {
        Self {
            provider: "bedrock".into(),
            model: model.into(),
            base_url: format!("https://bedrock-runtime.{region}.amazonaws.com"),
            max_tokens: 4096,
            temperature: 0.7,
            region: Some(region.into()),
            tools_enabled: true,
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
            region: None,
            tools_enabled: false,
        }
    }

    /// Tinfoil confidential inference (OpenAI-compatible, hardware enclaves)
    pub fn tinfoil(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: "https://inference.tinfoil.sh/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
        }
    }

    /// Privatemode confidential inference (OpenAI-compatible via local proxy)
    pub fn privatemode(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: "http://localhost:8080/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
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
            region: None,
            tools_enabled: true,
        }
    }

    /// Construct from explicit provider, base_url, and model.
    /// Preserves the provider name for correct dispatch.
    pub fn from_provider(provider: &str, base_url: &str, model: &str) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: provider != "ollama",
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
            .timeout(std::time::Duration::from_secs(300))
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
        match self.config.provider.as_str() {
            "anthropic" => self.complete_anthropic(messages, tools, api_key).await,
            "gemini" => self.complete_gemini(messages, tools, api_key).await,
            "bedrock" => self.complete_bedrock(messages, tools, api_key).await,
            _ => self.complete_openai(messages, tools, api_key).await,
        }
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
            "stream": false,
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
                if m.role == Role::Tool
                    && let Some(ref id) = m.tool_call_id
                {
                    serde_json::json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": m.content,
                        }]
                    })
                } else if m.role == Role::Assistant
                    && let Some(ref tool_calls) = m.tool_calls
                {
                    let mut blocks: Vec<serde_json::Value> = Vec::new();
                    if !m.content.is_empty() {
                        blocks.push(serde_json::json!({"type": "text", "text": m.content}));
                    }
                    for tc in tool_calls {
                        let input: serde_json::Value =
                            serde_json::from_str(&tc.arguments).unwrap_or(serde_json::json!({}));
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": input,
                        }));
                    }
                    serde_json::json!({
                        "role": "assistant",
                        "content": blocks,
                    })
                } else {
                    serde_json::json!({
                        "role": role,
                        "content": m.content,
                    })
                }
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

    /// Google Gemini generateContent API.
    async fn complete_gemini(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        let key = api_key.ok_or_else(|| AgentError::Llm("Gemini requires an API key".into()))?;
        let url = format!(
            "{}/models/{}:generateContent",
            self.config.base_url, self.config.model
        );

        // Extract system prompt
        let system_text: String = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");

        // Build contents array
        let contents: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| {
                let role = match m.role {
                    Role::User => "user",
                    Role::Assistant => "model",
                    Role::Tool => "user",
                    Role::System => unreachable!(),
                };
                let parts = if m.role == Role::Tool
                    && m.tool_call_id.is_some()
                    && let Some(ref name) = m.tool_name
                {
                    // Tool result -> functionResponse
                    let response_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "functionResponse": {
                            "name": name,
                            "response": response_val,
                        }
                    }])
                } else if m.role == Role::Tool {
                    // Tool result without structured info — use tool_name or call ID
                    let fn_name = m
                        .tool_name
                        .as_deref()
                        .or(m.tool_call_id.as_deref())
                        .unwrap_or("unknown");
                    let response_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "functionResponse": {
                            "name": fn_name,
                            "response": response_val,
                        }
                    }])
                } else {
                    serde_json::json!([{"text": m.content}])
                };
                serde_json::json!({
                    "role": role,
                    "parts": parts,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            },
        });

        if !system_text.is_empty() {
            body["systemInstruction"] = serde_json::json!({
                "parts": [{"text": system_text}]
            });
        }

        if !tools.is_empty() {
            let decls: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    })
                })
                .collect();
            body["tools"] = serde_json::json!([{
                "functionDeclarations": decls,
            }]);
        }

        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", key)
            .json(&body)
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

        parse_gemini_response(&response_body)
    }

    /// AWS Bedrock Converse API.
    async fn complete_bedrock(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<LlmResponse, AgentError> {
        let credentials =
            api_key.ok_or_else(|| AgentError::Llm("Bedrock requires AWS credentials".into()))?;

        // Parse access_key_id:secret_access_key[:session_token]
        let parts: Vec<&str> = credentials.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(AgentError::Llm(
                "Bedrock credentials must be access_key_id:secret_access_key".into(),
            ));
        }
        let access_key = parts[0];
        let secret_key = parts[1];
        let session_token = parts.get(2).copied();

        let region = self
            .config
            .region
            .as_deref()
            .or_else(|| {
                // Extract region from base_url
                self.config
                    .base_url
                    .strip_prefix("https://bedrock-runtime.")
                    .and_then(|s| s.strip_suffix(".amazonaws.com"))
            })
            .ok_or_else(|| AgentError::Llm("Bedrock requires a region".into()))?;

        let url = format!(
            "{}/model/{}/converse",
            self.config.base_url, self.config.model
        );

        // Extract system prompt
        let system_blocks: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| serde_json::json!({"text": m.content}))
            .collect();

        // Build messages array
        let bedrock_messages: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| {
                let role = match m.role {
                    Role::User | Role::Tool => "user",
                    Role::Assistant => "assistant",
                    Role::System => unreachable!(),
                };
                let content = if m.role == Role::Tool
                    && let Some(ref id) = m.tool_call_id
                {
                    let result_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "toolResult": {
                            "toolUseId": id,
                            "content": [{"json": result_val}],
                        }
                    }])
                } else {
                    serde_json::json!([{"text": m.content}])
                };
                serde_json::json!({
                    "role": role,
                    "content": content,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "messages": bedrock_messages,
            "inferenceConfig": {
                "maxTokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            },
        });

        if !system_blocks.is_empty() {
            body["system"] = serde_json::Value::Array(system_blocks);
        }

        if !tools.is_empty() {
            let tool_specs: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "toolSpec": {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": {"json": t.parameters},
                        }
                    })
                })
                .collect();
            body["toolConfig"] = serde_json::json!({
                "tools": tool_specs,
            });
        }

        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| AgentError::Llm(format!("serialize request: {e}")))?;

        let parsed_url =
            url::Url::parse(&url).map_err(|e| AgentError::Llm(format!("invalid URL: {e}")))?;

        let auth_headers = crate::sigv4::sign(
            access_key,
            secret_key,
            session_token,
            region,
            "bedrock",
            "POST",
            &parsed_url,
            &body_bytes,
        );

        let mut request = self
            .http
            .post(&url)
            .header("Content-Type", "application/json");

        for (name, value) in &auth_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .body(body_bytes)
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

        parse_bedrock_response(&response_body)
    }

    /// Get the current config.
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }

    /// Get the HTTP client (for streaming).
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http
    }
}

pub(crate) fn message_to_json(msg: &Message) -> serde_json::Value {
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

/// Parse a Google Gemini generateContent response.
pub fn parse_gemini_response(body: &serde_json::Value) -> Result<LlmResponse, AgentError> {
    let parts = body
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .ok_or_else(|| AgentError::Llm("no candidates/content/parts in Gemini response".into()))?;

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for part in parts {
        if let Some(text) = part.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            text_parts.push(text.to_string());
        }

        if let Some(fc) = part.get("functionCall") {
            let name = fc
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args = fc.get("args").unwrap_or(&serde_json::Value::Null);
            // Gemini doesn't return tool call IDs — generate one
            let id = format!("gemini_{}", uuid::Uuid::new_v4());
            tool_calls.push(ToolCallRequest {
                id,
                name,
                arguments: args.to_string(),
            });
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

/// Parse an AWS Bedrock Converse API response.
pub fn parse_bedrock_response(body: &serde_json::Value) -> Result<LlmResponse, AgentError> {
    let content = body
        .get("output")
        .and_then(|o| o.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no output/message/content in Bedrock response".into()))?;

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in content {
        if let Some(text) = block.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            text_parts.push(text.to_string());
        }

        if let Some(tu) = block.get("toolUse") {
            let id = tu
                .get("toolUseId")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let name = tu
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let input = tu.get("input").unwrap_or(&serde_json::Value::Null);
            tool_calls.push(ToolCallRequest {
                id,
                name,
                arguments: input.to_string(),
            });
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
