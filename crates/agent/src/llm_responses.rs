//! The OpenAI Responses API, as the `chatgpt` provider speaks it.
//!
//! A ChatGPT plan token (Sign in with ChatGPT, see
//! `wirken_mcp_proxy::oauth`) is accepted on `POST /v1/responses` and
//! nowhere else, under rules the route enforces
//! (<https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations>):
//! every request streams, stores nothing, carries its history as an
//! `input` array, puts the system prompt in `instructions` (a system
//! item is rejected), and may not set `temperature`, `max_output_tokens`
//! or a handful of other fields. Function tools are allowed, which is
//! all the agent's tool loop needs.
//!
//! One path serves both of the client's entry points: `complete_stream`
//! forwards text deltas as they arrive, and `complete` runs the same
//! stream into a dropped channel and returns the assembled response, so
//! the adapters, cron and `wirken ask` get the non-streaming shape they
//! expect. A request is a success only once `response.completed` has
//! been seen; a stream that ends before it is an error, not a reply.

use futures_util::StreamExt;

use crate::conversation::{
    COMPACTION_FENCE_CLOSE, COMPACTION_FENCE_OPEN, Message, Role, ToolCallRequest,
};
use crate::error::AgentError;
use crate::llm::{LlmClient, LlmConfig, LlmResponse, Usage};
use crate::llm_stream::{StreamEvent, sse_field};
use crate::tool::ToolDef;

/// The provider name the client dispatches on.
pub const PROVIDER: &str = "chatgpt";

/// The error code the route answers once the plan, or the weekly cap
/// the user set for this app, is used up. A request that got it must
/// not be retried: the limit resets on the user's schedule, not ours,
/// and every retry spends attention the user capped on purpose.
pub const USAGE_LIMIT_CODE: &str = "subscription_sharing_usage_limit_exceeded";

/// Where the user manages the app's share of their plan.
pub const MANAGE_USAGE: &str = "chatgpt.com/settings/usage";

/// Same cap as the chat-completions stream: a response that grows past
/// it without an event boundary is a runaway, not a reply.
const MAX_SSE_BUFFER_BYTES: usize = 1024 * 1024;

/// The JSON body of one request. The conversation maps onto the
/// route's `input` items; the first system message is the
/// `instructions`; a compaction summary is a developer message, since
/// the route rejects system items and developer carries the same
/// precedence; nothing the route refuses is sent.
pub(crate) fn build_responses_request_body(
    config: &LlmConfig,
    messages: &[Message],
    tools: &[ToolDef],
) -> serde_json::Value {
    let mut instructions: Vec<&str> = Vec::new();
    let mut input: Vec<serde_json::Value> = Vec::new();
    for msg in messages {
        match msg.role {
            Role::System => instructions.push(msg.content.as_str()),
            Role::Compaction => input.push(serde_json::json!({
                "role": "developer",
                "content": format!(
                    "{COMPACTION_FENCE_OPEN}\n{}\n{COMPACTION_FENCE_CLOSE}",
                    msg.content
                ),
            })),
            Role::User => input.push(serde_json::json!({
                "role": "user",
                "content": msg.content,
            })),
            Role::Assistant => {
                if !msg.content.is_empty() {
                    input.push(serde_json::json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [{ "type": "output_text", "text": msg.content }],
                    }));
                }
                for call in msg.tool_calls.iter().flatten() {
                    input.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": call.id,
                        "name": call.name,
                        "arguments": call.arguments,
                    }));
                }
            }
            Role::Tool => input.push(serde_json::json!({
                "type": "function_call_output",
                "call_id": msg.tool_call_id.clone().unwrap_or_default(),
                "output": msg.content,
            })),
        }
    }

    let mut body = serde_json::json!({
        "model": config.model,
        "input": input,
        "store": false,
        "stream": true,
    });
    if !instructions.is_empty() {
        body["instructions"] = serde_json::Value::String(instructions.join("\n\n"));
    }
    if !tools.is_empty() {
        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                    "strict": false,
                })
            })
            .collect();
        body["tools"] = serde_json::Value::Array(tools_json);
    }
    body
}

/// The error for a body that names the plan usage limit, or `None`.
/// Read by the retry loop so the limit short-circuits a 429 that
/// would otherwise be retried as a rate limit.
pub(crate) fn plan_usage_limit(body: &str) -> Option<AgentError> {
    body.contains(USAGE_LIMIT_CODE).then(|| {
        AgentError::Llm(format!(
            "ChatGPT plan usage limit reached ({USAGE_LIMIT_CODE}); the request was not retried. \
             The plan, or the weekly cap set for this app, resets on its own schedule: see \
             {MANAGE_USAGE}."
        ))
    })
}

/// The error for a non-success status, naming the route's error code
/// and message when the body carries them.
fn http_error(status: reqwest::StatusCode, body: &str) -> AgentError {
    if let Some(err) = plan_usage_limit(body) {
        return err;
    }
    let (code, message) = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let err = v.get("error")?;
            Some((
                err.get("code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                err.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string(),
            ))
        })
        .unwrap_or_default();
    if code.is_empty() && message.is_empty() {
        AgentError::Llm(format!("HTTP {status}: {body}"))
    } else {
        AgentError::Llm(format!("HTTP {status} {code}: {message}"))
    }
}

/// A function call the stream is still filling in, keyed by the
/// output item that carries it.
#[derive(Default)]
struct PartialCall {
    item_id: String,
    call_id: String,
    name: String,
    arguments: String,
}

/// Token usage off a completed response.
fn usage_of(response: &serde_json::Value) -> Option<Usage> {
    let u = response.get("usage")?;
    let count =
        |v: &serde_json::Value, key: &str| v.get(key).and_then(|n| n.as_u64()).unwrap_or(0) as u32;
    Some(Usage {
        input_tokens: count(u, "input_tokens"),
        output_tokens: count(u, "output_tokens"),
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: u
            .get("input_tokens_details")
            .map(|d| count(d, "cached_tokens"))
            .unwrap_or(0),
    })
}

/// The `code: message` of an error object, for a failed response.
fn error_text(error: Option<&serde_json::Value>) -> String {
    let code = error
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("unknown");
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    format!("{code}: {message}")
}

impl LlmClient {
    /// One turn on the plan route, assembled from its stream. The
    /// deltas go nowhere; `complete_stream` is the entry point that
    /// forwards them.
    pub(crate) async fn complete_responses(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        self.stream_responses(messages, tools, api_key, &tx).await
    }

    /// One turn on the plan route, text deltas forwarded to `tx` as
    /// they arrive, the assembled response returned once the stream
    /// has completed.
    pub(crate) async fn stream_responses(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
        tx: &tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let api_key = api_key.ok_or_else(|| {
            AgentError::Llm(format!(
                "{PROVIDER} provider requires a plan token; none was passed to complete()"
            ))
        })?;
        let url = format!("{}/responses", self.config().base_url);
        let body = build_responses_request_body(self.config(), messages, tools);

        let response = self
            .send_with_retry(|| {
                self.http_client()
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {api_key}"))
                    .json(&body)
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(http_error(status, &text));
        }

        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut full_text = String::new();
        let mut calls: Vec<PartialCall> = Vec::new();
        let mut usage: Option<Usage> = None;
        let mut completed = false;

        'stream: while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| AgentError::Http(format!("stream read: {e}")))?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));
            if buffer.len() > MAX_SSE_BUFFER_BYTES {
                return Err(AgentError::Http(format!(
                    "SSE accumulation exceeded {MAX_SSE_BUFFER_BYTES} bytes without an event \
                     boundary; refusing to grow further (hostile or buggy upstream?)"
                )));
            }

            while let Some((block, rest)) = buffer.split_once("\n\n") {
                let event_block = block.to_string();
                buffer = rest.to_string();

                for line in event_block.lines() {
                    let Some(data) = sse_field(line, "data") else {
                        continue;
                    };
                    let Ok(event) = serde_json::from_str::<serde_json::Value>(data) else {
                        continue;
                    };
                    let kind = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match kind {
                        "response.output_text.delta" => {
                            if let Some(delta) = event.get("delta").and_then(|d| d.as_str())
                                && !delta.is_empty()
                            {
                                full_text.push_str(delta);
                                let _ = tx.send(StreamEvent::TextDelta(delta.to_string())).await;
                            }
                        }
                        "response.output_item.added" | "response.output_item.done" => {
                            let Some(item) = event.get("item") else {
                                continue;
                            };
                            if item.get("type").and_then(|t| t.as_str()) != Some("function_call") {
                                continue;
                            }
                            let item_id = item
                                .get("id")
                                .and_then(|i| i.as_str())
                                .unwrap_or("")
                                .to_string();
                            let slot = match calls.iter_mut().find(|c| c.item_id == item_id) {
                                Some(existing) => existing,
                                None => {
                                    calls.push(PartialCall {
                                        item_id,
                                        ..Default::default()
                                    });
                                    calls.last_mut().expect("just pushed")
                                }
                            };
                            if let Some(call_id) = item.get("call_id").and_then(|c| c.as_str()) {
                                slot.call_id = call_id.to_string();
                            }
                            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                slot.name = name.to_string();
                            }
                            // The done item carries the whole argument
                            // string; the added one an empty start.
                            if kind == "response.output_item.done"
                                && let Some(args) = item.get("arguments").and_then(|a| a.as_str())
                            {
                                slot.arguments = args.to_string();
                            }
                        }
                        "response.function_call_arguments.delta" => {
                            let item_id =
                                event.get("item_id").and_then(|i| i.as_str()).unwrap_or("");
                            if let Some(delta) = event.get("delta").and_then(|d| d.as_str())
                                && let Some(slot) = calls.iter_mut().find(|c| c.item_id == item_id)
                            {
                                slot.arguments.push_str(delta);
                            }
                        }
                        "response.function_call_arguments.done" => {
                            let item_id =
                                event.get("item_id").and_then(|i| i.as_str()).unwrap_or("");
                            if let Some(args) = event.get("arguments").and_then(|a| a.as_str())
                                && let Some(slot) = calls.iter_mut().find(|c| c.item_id == item_id)
                            {
                                slot.arguments = args.to_string();
                            }
                        }
                        "response.completed" => {
                            usage = event.get("response").and_then(usage_of);
                            completed = true;
                            break 'stream;
                        }
                        "response.failed" => {
                            let error = event.get("response").and_then(|r| r.get("error"));
                            let text = error_text(error);
                            return Err(plan_usage_limit(&text).unwrap_or_else(|| {
                                AgentError::Llm(format!("response failed: {text}"))
                            }));
                        }
                        "response.incomplete" => {
                            let reason = event
                                .get("response")
                                .and_then(|r| r.get("incomplete_details"))
                                .and_then(|d| d.get("reason"))
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown");
                            return Err(AgentError::Llm(format!("response incomplete: {reason}")));
                        }
                        "error" => {
                            return Err(AgentError::Llm(format!(
                                "stream error: {}",
                                error_text(Some(&event))
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }

        if !completed {
            return Err(AgentError::Http(
                "stream ended before response.completed; the reply is not usable".into(),
            ));
        }

        let calls: Vec<ToolCallRequest> = calls
            .into_iter()
            .filter(|c| !c.name.is_empty())
            .map(|c| ToolCallRequest {
                id: c.call_id,
                name: c.name,
                arguments: c.arguments,
            })
            .collect();
        let response = if !calls.is_empty() {
            LlmResponse::ToolCalls {
                calls,
                text: Some(full_text.clone()).filter(|t| !t.is_empty()),
            }
        } else if !full_text.is_empty() {
            LlmResponse::Text(full_text)
        } else {
            LlmResponse::Empty
        };
        let _ = tx.send(StreamEvent::Done(response.clone())).await;
        Ok((response, usage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn msg(role: Role, content: &str) -> Message {
        Message {
            role,
            content: content.into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }
    }

    fn config(base_url: &str) -> LlmConfig {
        LlmConfig::from_provider(PROVIDER, base_url, "gpt-test")
    }

    #[test]
    fn the_request_body_maps_the_conversation_and_sends_nothing_the_route_refuses() {
        let mut assistant = msg(Role::Assistant, "Reading it.");
        assistant.tool_calls = Some(vec![ToolCallRequest {
            id: "call_1".into(),
            name: "read_file".into(),
            arguments: r#"{"path":"a.txt"}"#.into(),
        }]);
        let mut result = msg(Role::Tool, "contents");
        result.tool_call_id = Some("call_1".into());
        let messages = vec![
            msg(Role::System, "Be brief."),
            msg(Role::Compaction, "earlier: hello"),
            msg(Role::User, "read a.txt"),
            assistant,
            result,
        ];
        let tools = vec![ToolDef {
            name: "read_file".into(),
            description: "Read a file".into(),
            parameters: serde_json::json!({"type":"object"}),
        }];
        let cfg = config("https://api.openai.com/v1");
        let body = build_responses_request_body(&cfg, &messages, &tools);

        assert_eq!(body["model"], "gpt-test");
        assert_eq!(body["instructions"], "Be brief.");
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
        for refused in [
            "temperature",
            "max_tokens",
            "max_output_tokens",
            "top_p",
            "user",
            "metadata",
        ] {
            assert!(body.get(refused).is_none(), "{refused} must not be sent");
        }
        let input = body["input"].as_array().unwrap();
        assert_eq!(input.len(), 5, "{input:?}");
        assert_eq!(input[0]["role"], "developer");
        let fenced = input[0]["content"].as_str().unwrap();
        assert!(
            fenced.starts_with(COMPACTION_FENCE_OPEN) && fenced.ends_with(COMPACTION_FENCE_CLOSE)
        );
        assert_eq!(
            input[1],
            serde_json::json!({"role":"user","content":"read a.txt"})
        );
        assert_eq!(input[2]["type"], "message");
        assert_eq!(input[2]["role"], "assistant");
        assert_eq!(input[2]["content"][0]["type"], "output_text");
        assert_eq!(input[2]["content"][0]["text"], "Reading it.");
        assert_eq!(
            input[3],
            serde_json::json!({"type":"function_call","call_id":"call_1","name":"read_file","arguments":r#"{"path":"a.txt"}"#})
        );
        assert_eq!(
            input[4],
            serde_json::json!({"type":"function_call_output","call_id":"call_1","output":"contents"})
        );
        assert!(
            input.iter().all(|i| i["role"] != "system"),
            "no system items"
        );
        assert_eq!(
            body["tools"][0],
            serde_json::json!({"type":"function","name":"read_file","description":"Read a file","parameters":{"type":"object"},"strict":false})
        );
    }

    #[test]
    fn without_tools_or_instructions_the_body_omits_them() {
        let body =
            build_responses_request_body(&config("https://x"), &[msg(Role::User, "hi")], &[]);
        assert!(body.get("tools").is_none());
        assert!(body.get("instructions").is_none());
    }

    /// Reads one HTTP request in full, headers and body.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&raw);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let wanted = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if body.len() >= wanted {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    /// A loopback server answering every request with `status` and
    /// `body`, recording each request it saw.
    async fn stub(
        status: &'static str,
        content_type: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let request = read_request(&mut socket).await;
                record.lock().unwrap().push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.flush().await.unwrap();
            }
        });
        (format!("http://{addr}/v1"), seen)
    }

    const TEXT_STREAM: &str = "\
event: response.created\n\
data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n\
event: response.output_item.added\n\
data: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"status\":\"in_progress\",\"content\":[]}}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"Hello\"}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"sequence_number\":3,\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\", world\"}\n\n\
event: response.output_text.done\n\
data: {\"type\":\"response.output_text.done\",\"sequence_number\":4,\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"text\":\"Hello, world\"}\n\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"sequence_number\":5,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":12,\"input_tokens_details\":{\"cached_tokens\":4},\"output_tokens\":5,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":17}}}\n\n";

    #[tokio::test]
    async fn a_streamed_text_reply_is_assembled_and_usage_read_from_completed() {
        let (base_url, seen) = stub("200 OK", "text/event-stream", TEXT_STREAM).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamEvent>(16);
        let (response, usage) = client
            .complete_stream(&[msg(Role::User, "hi")], &[], Some("plan-token"), tx)
            .await
            .expect("stream completes");

        assert!(
            matches!(response, LlmResponse::Text(ref t) if t == "Hello, world"),
            "{response:?}"
        );
        let usage = usage.expect("usage on completed");
        assert_eq!(
            (
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_input_tokens
            ),
            (12, 5, 4)
        );
        let mut deltas = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let StreamEvent::TextDelta(piece) = event {
                deltas.push(piece);
            }
        }
        assert_eq!(deltas, vec!["Hello", ", world"]);

        let request = seen.lock().unwrap()[0].clone();
        assert!(request.starts_with("POST /v1/responses "), "{request}");
        assert!(
            request.contains("Authorization: Bearer plan-token")
                || request.contains("authorization: Bearer plan-token"),
            "{request}"
        );
        let (_, body) = request.split_once("\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
        assert!(body.get("temperature").is_none());
    }

    const CALL_STREAM: &str = "\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_2\"}}\n\n\
data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\n\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"Reading two files.\"}\n\n\
data: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"status\":\"in_progress\",\"call_id\":\"call_a\",\"name\":\"read_file\",\"arguments\":\"\"}}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":1,\"delta\":\"{\\\"path\\\":\"}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":1,\"delta\":\"\\\"a.txt\\\"}\"}\n\n\
data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"fc_1\",\"output_index\":1,\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}\n\n\
data: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"status\":\"completed\",\"call_id\":\"call_a\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}}\n\n\
data: {\"type\":\"response.output_item.added\",\"output_index\":2,\"item\":{\"id\":\"fc_2\",\"type\":\"function_call\",\"call_id\":\"call_b\",\"name\":\"read_file\",\"arguments\":\"\"}}\n\n\
data: {\"type\":\"response.output_item.done\",\"output_index\":2,\"item\":{\"id\":\"fc_2\",\"type\":\"function_call\",\"status\":\"completed\",\"call_id\":\"call_b\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"b.txt\\\"}\"}}\n\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_2\",\"status\":\"completed\",\"usage\":{\"input_tokens\":30,\"output_tokens\":20,\"total_tokens\":50}}}\n\n";

    #[tokio::test]
    async fn streamed_function_calls_are_assembled_with_their_call_ids_beside_the_text() {
        let (base_url, _) = stub("200 OK", "text/event-stream", CALL_STREAM).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let (response, usage) = client
            .complete(&[msg(Role::User, "read both")], &[], Some("plan-token"))
            .await
            .expect("completes");
        match response {
            LlmResponse::ToolCalls { calls, text } => {
                assert_eq!(text.as_deref(), Some("Reading two files."));
                assert_eq!(calls.len(), 2);
                assert_eq!(
                    (
                        calls[0].id.as_str(),
                        calls[0].name.as_str(),
                        calls[0].arguments.as_str()
                    ),
                    ("call_a", "read_file", r#"{"path":"a.txt"}"#)
                );
                assert_eq!(
                    (calls[1].id.as_str(), calls[1].arguments.as_str()),
                    ("call_b", r#"{"path":"b.txt"}"#)
                );
            }
            other => panic!("expected ToolCalls, got {other:?}"),
        }
        let usage = usage.unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_input_tokens
            ),
            (30, 20, 0)
        );
    }

    #[tokio::test]
    async fn a_failed_response_is_an_error_naming_the_code() {
        const FAILED: &str = "\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_3\"}}\n\n\
data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_3\",\"status\":\"failed\",\"error\":{\"code\":\"server_error\",\"message\":\"upstream went away\"}}}\n\n";
        let (base_url, _) = stub("200 OK", "text/event-stream", FAILED).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], Some("t"))
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("server_error") && text.contains("upstream went away"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_usage_limit_mid_stream_is_the_usage_limit_error() {
        const LIMIT: &str = "\
data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_4\",\"status\":\"failed\",\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\",\"message\":\"limit\"}}}\n\n";
        let (base_url, _) = stub("200 OK", "text/event-stream", LIMIT).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], Some("t"))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains(MANAGE_USAGE), "{err}");
    }

    #[tokio::test]
    async fn a_stream_that_ends_before_completed_is_an_error() {
        const CUT: &str = "\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_5\"}}\n\n\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"partial\"}\n\n";
        let (base_url, _) = stub("200 OK", "text/event-stream", CUT).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], Some("t"))
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("before response.completed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_usage_limit_429_is_not_retried_and_names_the_usage_page() {
        const BODY: &str = r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"You have hit your usage limit","type":"insufficient_quota"}}"#;
        let (base_url, seen) = stub("429 Too Many Requests", "application/json", BODY).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], Some("t"))
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains(USAGE_LIMIT_CODE) && text.contains(MANAGE_USAGE),
            "{text}"
        );
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "a plan limit is never retried"
        );
    }

    #[tokio::test]
    async fn an_http_error_names_the_route_code() {
        const BODY: &str = r#"{"error":{"code":"subscription_sharing_user_not_eligible","message":"This account cannot share its plan"}}"#;
        let (base_url, _) = stub("403 Forbidden", "application/json", BODY).await;
        let client = LlmClient::new(config(&base_url)).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], Some("t"))
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("403")
                && text.contains("subscription_sharing_user_not_eligible")
                && text.contains("cannot share"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_plan_route_needs_a_token() {
        let client = LlmClient::new(config("https://api.openai.com/v1")).unwrap();
        let err = client
            .complete(&[msg(Role::User, "hi")], &[], None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("requires a plan token"), "{err}");
    }
}
