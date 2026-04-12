//! Streaming LLM completions via Server-Sent Events (SSE).

use futures_util::StreamExt;

use crate::conversation::{Message, Role, ToolCallRequest};
use crate::error::AgentError;
use crate::llm::{LlmClient, LlmResponse};
use crate::tool::ToolDef;

/// Events emitted during a streaming completion.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A chunk of text from the assistant.
    TextDelta(String),
    /// The complete response, matching non-streaming behavior.
    Done(LlmResponse),
    /// An error during streaming.
    Error(String),
}

impl LlmClient {
    /// Stream a completion request, sending events to the provided channel.
    /// Falls back to non-streaming for providers that don't support it yet.
    pub async fn complete_stream(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<LlmResponse, AgentError> {
        match self.config().provider.as_str() {
            "openai" | "ollama" | "custom" => {
                self.stream_openai(messages, tools, api_key, &tx).await
            }
            "anthropic" => self.stream_anthropic(messages, tools, api_key, &tx).await,
            _ => {
                // Fall back to non-streaming
                let response = self.complete(messages, tools, api_key).await?;
                if let LlmResponse::Text(ref text) = response {
                    let _ = tx.send(StreamEvent::TextDelta(text.clone())).await;
                }
                let _ = tx.send(StreamEvent::Done(response.clone())).await;
                Ok(response)
            }
        }
    }

    async fn stream_openai(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
        tx: &tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<LlmResponse, AgentError> {
        let url = format!("{}/chat/completions", self.config().base_url);

        let messages_json: Vec<serde_json::Value> =
            messages.iter().map(super::llm::message_to_json).collect();

        let mut body = serde_json::json!({
            "model": self.config().model,
            "messages": messages_json,
            "max_tokens": self.config().max_tokens,
            "temperature": self.config().temperature,
            "stream": true,
        });

        if !tools.is_empty() {
            let tools_json = super::llm::tools_to_json(tools);
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let mut request = self
            .http_client()
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

        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut full_text = String::new();
        let mut tool_calls: Vec<PartialToolCall> = Vec::new();

        'stream: while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| AgentError::Http(format!("stream read: {e}")))?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));

            // Process complete SSE lines
            while let Some(pos) = buffer.find("\n\n") {
                let event_block = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                for line in event_block.lines() {
                    if let Some(data) = line.strip_prefix("data: ") {
                        if data == "[DONE]" {
                            break 'stream;
                        }

                        let parsed: serde_json::Value = match serde_json::from_str(data) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        if let Some(delta) = parsed
                            .get("choices")
                            .and_then(|c| c.as_array())
                            .and_then(|a| a.first())
                            .and_then(|c| c.get("delta"))
                        {
                            if let Some(content) = delta.get("content").and_then(|c| c.as_str())
                                && !content.is_empty()
                            {
                                full_text.push_str(content);
                                let _ = tx.send(StreamEvent::TextDelta(content.to_string())).await;
                            }

                            if let Some(tc_array) =
                                delta.get("tool_calls").and_then(|t| t.as_array())
                            {
                                for tc in tc_array {
                                    let index =
                                        tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0)
                                            as usize;

                                    while tool_calls.len() <= index {
                                        tool_calls.push(PartialToolCall::default());
                                    }

                                    if let Some(id) = tc.get("id").and_then(|i| i.as_str()) {
                                        tool_calls[index].id = id.to_string();
                                    }
                                    if let Some(func) = tc.get("function") {
                                        if let Some(name) =
                                            func.get("name").and_then(|n| n.as_str())
                                        {
                                            tool_calls[index].name = name.to_string();
                                        }
                                        if let Some(args) =
                                            func.get("arguments").and_then(|a| a.as_str())
                                        {
                                            tool_calls[index].arguments.push_str(args);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let response = if !tool_calls.is_empty() {
            let calls: Vec<ToolCallRequest> = tool_calls
                .into_iter()
                .filter(|tc| !tc.name.is_empty())
                .map(|tc| ToolCallRequest {
                    id: tc.id,
                    name: tc.name,
                    arguments: tc.arguments,
                })
                .collect();
            LlmResponse::ToolCalls(calls)
        } else if !full_text.is_empty() {
            LlmResponse::Text(full_text)
        } else {
            LlmResponse::Empty
        };

        let _ = tx.send(StreamEvent::Done(response.clone())).await;
        Ok(response)
    }

    async fn stream_anthropic(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
        tx: &tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<LlmResponse, AgentError> {
        let url = format!("{}/messages", self.config().base_url);

        // Item 4 slice 2: Role::Compaction is folded into the
        // system prompt with the fence wrapper, same as the
        // non-streaming Anthropic path.
        let system_prompt: String = messages
            .iter()
            .filter(|m| m.role == Role::System || m.role == Role::Compaction)
            .map(|m| {
                if m.role == Role::Compaction {
                    format!(
                        "{}\n{}\n{}",
                        crate::conversation::COMPACTION_FENCE_OPEN,
                        m.content,
                        crate::conversation::COMPACTION_FENCE_CLOSE,
                    )
                } else {
                    m.content.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let messages_json: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System && m.role != Role::Compaction)
            .map(|m| {
                let role = match m.role {
                    Role::User | Role::Tool => "user",
                    Role::Assistant => "assistant",
                    Role::System | Role::Compaction => unreachable!(),
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
            "model": self.config().model,
            "messages": messages_json,
            "max_tokens": self.config().max_tokens,
            "stream": true,
        });

        // Item 4 slice 3: same cache_control treatment as the
        // non-streaming path. See complete_anthropic.
        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!([{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }]);
        }

        if !tools.is_empty() {
            let mut tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.parameters,
                    })
                })
                .collect();
            if let Some(last) = tools_json.last_mut() {
                last["cache_control"] = serde_json::json!({"type": "ephemeral"});
            }
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let mut request = self
            .http_client()
            .post(&url)
            .header("Content-Type", "application/json")
            .header("anthropic-version", "2023-06-01");

        if let Some(key) = api_key {
            request = request.header("x-api-key", key);
        }

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut text_parts = Vec::new();
        let mut tool_calls: Vec<ToolCallRequest> = Vec::new();
        let mut current_tool_input = String::new();
        let mut current_tool_id = String::new();
        let mut current_tool_name = String::new();
        let mut in_tool_block = false;

        'stream: while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| AgentError::Http(format!("stream read: {e}")))?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));

            while let Some(pos) = buffer.find("\n\n") {
                let event_block = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut event_type = "";
                let mut event_data = String::new();

                for line in event_block.lines() {
                    if let Some(et) = line.strip_prefix("event: ") {
                        event_type = match et.trim() {
                            "content_block_start" => "content_block_start",
                            "content_block_delta" => "content_block_delta",
                            "content_block_stop" => "content_block_stop",
                            "message_stop" => "message_stop",
                            _ => "",
                        };
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        event_data = d.to_string();
                    }
                }

                if event_data.is_empty() {
                    continue;
                }

                let data: serde_json::Value = match serde_json::from_str(&event_data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                match event_type {
                    "content_block_start" => {
                        if let Some(block) = data.get("content_block") {
                            let bt = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            if bt == "tool_use" {
                                in_tool_block = true;
                                current_tool_id = block
                                    .get("id")
                                    .and_then(|i| i.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                current_tool_name = block
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                current_tool_input.clear();
                            } else {
                                in_tool_block = false;
                            }
                        }
                    }
                    "content_block_delta" => {
                        if let Some(delta) = data.get("delta") {
                            let dt = delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            if dt == "text_delta"
                                && let Some(text) = delta.get("text").and_then(|t| t.as_str())
                                && !text.is_empty()
                            {
                                text_parts.push(text.to_string());
                                let _ = tx.send(StreamEvent::TextDelta(text.to_string())).await;
                            } else if dt == "input_json_delta"
                                && let Some(partial) =
                                    delta.get("partial_json").and_then(|p| p.as_str())
                            {
                                current_tool_input.push_str(partial);
                            }
                        }
                    }
                    "content_block_stop" => {
                        if in_tool_block && !current_tool_name.is_empty() {
                            tool_calls.push(ToolCallRequest {
                                id: current_tool_id.clone(),
                                name: current_tool_name.clone(),
                                arguments: current_tool_input.clone(),
                            });
                            in_tool_block = false;
                        }
                    }
                    "message_stop" => break 'stream,
                    _ => {}
                }
            }
        }

        let response = if !tool_calls.is_empty() {
            LlmResponse::ToolCalls(tool_calls)
        } else if !text_parts.is_empty() {
            LlmResponse::Text(text_parts.join(""))
        } else {
            LlmResponse::Empty
        };

        let _ = tx.send(StreamEvent::Done(response.clone())).await;
        Ok(response)
    }
}

#[derive(Default)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
}
