//! The Responses API, as an agent in plan mode speaks it.
//!
//! A plan token is accepted on `POST /v1/responses` under rules the
//! route enforces: every request streams and stores nothing, history
//! travels as the `input` array, the system prompt goes in
//! `instructions` (a system item is refused), and a list of fields the
//! route does not take is left out entirely. Function tools are grouped
//! in one namespace. The route is pinned with the rest of the plan
//! endpoints ([`crate::plan_auth::API_BASE`]); the agent's `base_url`
//! does not reach it.
//!
//! One path serves both of the client's entry points: `complete_stream`
//! forwards text deltas as they arrive, and `complete` reads the same
//! stream to its end, so adapters, cron and `wirken ask` get the whole
//! reply. A request succeeds only on `response.completed`; a stream
//! that stops before it is an error, never a partial reply.
//!
//! Errors keep the HTTP status, the error code and the provider's
//! `x-request-id`, in [`PlanRouteError`] and so in the failed call's
//! audit row. A usage limit is never retried; a 503 is retried a
//! bounded number of times. Only this path reads a 429's body.

use futures_util::StreamExt;

use crate::conversation::{
    COMPACTION_FENCE_CLOSE, COMPACTION_FENCE_OPEN, Message, Role, ToolCallRequest,
};
use crate::error::AgentError;
use crate::llm::{LlmClient, LlmConfig, LlmResponse, Usage};
use crate::llm_stream::{StreamEvent, sse_field};
use crate::plan_auth::{PlanTokenSource, USAGE_URL};
use crate::recovery::{MAX_RATE_LIMIT_RETRIES, RetryDecision, classify_429};
use crate::tool::ToolDef;

/// The namespace every function tool is grouped under.
pub const TOOL_NAMESPACE: &str = "agent";
/// The namespace's description, which the route requires and shows the
/// model.
pub const TOOL_NAMESPACE_DESCRIPTION: &str = "Tools this agent can call.";

/// The waits between attempts after a 503 (usage availability or
/// account information temporarily unavailable, or the route itself).
pub const UNAVAILABLE_BACKOFF: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(4),
];

/// Same cap as the chat-completions stream: an event that grows past it
/// without a boundary is a runaway, not a reply.
const MAX_SSE_BUFFER_BYTES: usize = 1024 * 1024;

/// What the provider said about a failed plan request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanFailure {
    /// The HTTP status. `None` for a failure inside a stream that
    /// opened with 200.
    pub status: Option<u16>,
    /// The error code, when the body or event carried one.
    pub code: Option<String>,
    /// The request field the error names.
    pub param: Option<String>,
    /// The provider's `x-request-id`.
    pub request_id: Option<String>,
    /// The provider's message or `detail`, as diagnostic text.
    pub message: Option<String>,
}

impl std::fmt::Display for PlanFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if let Some(status) = self.status {
            parts.push(format!("HTTP {status}"));
        }
        if let Some(code) = &self.code {
            parts.push(format!("code {code}"));
        }
        if let Some(param) = &self.param {
            parts.push(format!("param {param}"));
        }
        if let Some(id) = &self.request_id {
            parts.push(format!("request id {id}"));
        }
        write!(f, "[{}]", parts.join(", "))?;
        if let Some(message) = &self.message {
            let short: String = message.chars().take(300).collect();
            write!(f, " {short}")?;
        }
        Ok(())
    }
}

/// A failed request on the plan route, one variant per recovery the
/// provider documents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanRouteError {
    /// `subscription_sharing_usage_limit_exceeded`. Never retried.
    #[error(
        "Usage limit reached. Review your plan or this app's limit in ChatGPT settings. \
         Manage usage: {USAGE_URL}. Not retried. {0}"
    )]
    UsageLimitExceeded(PlanFailure),
    /// `subscription_sharing_usage_unavailable`.
    #[error("plan usage could not be checked; the credential is kept, try again later. {0}")]
    UsageUnavailable(PlanFailure),
    /// `subscription_sharing_user_not_eligible`.
    #[error(
        "plan usage is not available for this account, workspace or policy; the request is not \
         repeated. {0}"
    )]
    UserNotEligible(PlanFailure),
    /// `subscription_sharing_unsupported_capability`.
    #[error(
        "the plan route does not support part of this request (see param); it is not retried \
         unchanged. {0}"
    )]
    UnsupportedCapability(PlanFailure),
    /// `subscription_sharing_route_not_supported`.
    #[error("the plan route does not serve this method and endpoint. {0}")]
    RouteNotSupported(PlanFailure),
    /// `subscription_sharing_invalid_user`.
    #[error(
        "the provider could not validate the signed-in account; if it persists, sign in again \
         with `wirken credentials authorize`. {0}"
    )]
    InvalidUser(PlanFailure),
    /// `subscription_sharing_user_unavailable`.
    #[error("account information is temporarily unavailable; the credential is kept. {0}")]
    UserUnavailable(PlanFailure),
    /// `chatpass_v2_scope_not_authorized`,
    /// `chatpass_v2_invalid_authorization_context`.
    #[error(
        "the signed permission does not authorize this request; check the sign-in's client and \
         grant. {0}"
    )]
    PermissionContext(PlanFailure),
    /// A refusal before the request started, with a `detail` body and
    /// no error code.
    #[error("the request was not admitted to the plan route. {0}")]
    Admission(PlanFailure),
    /// `response.incomplete`.
    #[error("the response did not complete ({reason}). {failure}")]
    Incomplete {
        reason: String,
        failure: PlanFailure,
    },
    /// The stream ended without `response.completed`.
    #[error("the stream ended before response.completed; the reply is not used. {0}")]
    StreamCut(PlanFailure),
    /// Anything else the route refused.
    #[error("plan request failed. {0}")]
    Failed(PlanFailure),
}

impl PlanRouteError {
    /// The variant for `failure`'s error code.
    pub fn classify(failure: PlanFailure) -> Self {
        match failure.code.as_deref() {
            Some("subscription_sharing_usage_limit_exceeded") => Self::UsageLimitExceeded(failure),
            Some("subscription_sharing_usage_unavailable") => Self::UsageUnavailable(failure),
            Some("subscription_sharing_user_not_eligible") => Self::UserNotEligible(failure),
            Some("subscription_sharing_unsupported_capability") => {
                Self::UnsupportedCapability(failure)
            }
            Some("subscription_sharing_route_not_supported") => Self::RouteNotSupported(failure),
            Some("subscription_sharing_invalid_user") => Self::InvalidUser(failure),
            Some("subscription_sharing_user_unavailable") => Self::UserUnavailable(failure),
            Some(code) if code.starts_with("chatpass_v2_") => Self::PermissionContext(failure),
            _ => Self::Failed(failure),
        }
    }

    /// The provider's details, whichever variant.
    pub fn failure(&self) -> &PlanFailure {
        match self {
            Self::UsageLimitExceeded(f)
            | Self::UsageUnavailable(f)
            | Self::UserNotEligible(f)
            | Self::UnsupportedCapability(f)
            | Self::RouteNotSupported(f)
            | Self::InvalidUser(f)
            | Self::UserUnavailable(f)
            | Self::PermissionContext(f)
            | Self::Admission(f)
            | Self::StreamCut(f)
            | Self::Failed(f) => f,
            Self::Incomplete { failure, .. } => failure,
        }
    }

    /// Whether this is the usage limit.
    pub fn is_usage_limit(&self) -> bool {
        matches!(self, Self::UsageLimitExceeded(_))
    }
}

/// The error for a non-2xx answer: the API's error object when the body
/// carries one, a `detail` body as a refusal before the request
/// started, anything else as text.
pub(crate) fn http_failure(status: u16, body: &str, request_id: Option<String>) -> PlanRouteError {
    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let text = |v: Option<&serde_json::Value>| v.and_then(|s| s.as_str()).map(String::from);
    if let Some(error) = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .filter(|e| e.is_object())
    {
        return PlanRouteError::classify(PlanFailure {
            status: Some(status),
            code: text(error.get("code")),
            param: text(error.get("param")),
            request_id,
            message: text(error.get("message")),
        });
    }
    if let Some(detail) = parsed.as_ref().and_then(|v| v.get("detail")) {
        return PlanRouteError::Admission(PlanFailure {
            status: Some(status),
            request_id,
            message: Some(
                detail
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| detail.to_string()),
            ),
            ..Default::default()
        });
    }
    PlanRouteError::Failed(PlanFailure {
        status: Some(status),
        request_id,
        message: (!body.is_empty()).then(|| body.to_string()),
        ..Default::default()
    })
}

/// The JSON body of one request.
///
/// System messages become `instructions`, joined in order; nothing is
/// sent with the system role. A compaction summary is a developer
/// message, fenced as the other providers fence it. Assistant turns
/// carry their text and then their function calls; tool results are
/// `function_call_output` items. `store` is false and `stream` true on
/// every request, and none of the fields the route refuses is set:
/// no temperature, output cap, `top_p`, user, metadata or previous
/// response id.
pub fn build_plan_request_body(
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
                        "role": "assistant",
                        "content": msg.content,
                    }));
                }
                // Every tool this client offers is in one namespace,
                // and a replayed call names it beside the plain name.
                for call in msg.tool_calls.iter().flatten() {
                    input.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": call.id,
                        "namespace": TOOL_NAMESPACE,
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
        let functions: Vec<serde_json::Value> = tools
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
        body["tools"] = serde_json::json!([{
            "type": "namespace",
            "name": TOOL_NAMESPACE,
            "description": TOOL_NAMESPACE_DESCRIPTION,
            "tools": functions,
        }]);
    }
    body
}

/// A function call the stream is still filling in, keyed by the output
/// item (`fc_...`) that carries it. Argument deltas name the item, not
/// the call id.
#[derive(Default)]
struct PartialCall {
    item_id: String,
    call_id: String,
    name: String,
    arguments: String,
}

/// The tool name a function call item names, without the namespace
/// qualifier when the item carries one.
fn call_name(item: &serde_json::Value) -> Option<String> {
    let name = item.get("name").and_then(|n| n.as_str())?;
    // The route sends the plain name and the namespace in its own
    // field. A name qualified with the namespace is read as the plain
    // one too.
    let namespace = item
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or(TOOL_NAMESPACE);
    let plain = name
        .strip_prefix(namespace)
        .and_then(|rest| rest.strip_prefix('.'));
    Some(plain.unwrap_or(name).to_string())
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

/// The failure an error object inside the stream describes.
fn stream_failure(error: Option<&serde_json::Value>, request_id: &Option<String>) -> PlanFailure {
    let text = |key: &str| {
        error
            .and_then(|e| e.get(key))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    PlanFailure {
        status: None,
        code: text("code"),
        param: text("param"),
        request_id: request_id.clone(),
        message: text("message"),
    }
}

/// The models the signed-in account may use, as `/models` lists them
/// for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanModel {
    /// What a request's `model` takes.
    pub slug: String,
    /// What a picker shows.
    pub display_name: String,
}

/// The models a `/models` body lists for display: the `models` array's
/// entries with `visibility` `"list"`, in the order the server gave.
pub fn parse_plan_models(body: &serde_json::Value) -> Vec<PlanModel> {
    body.get("models")
        .and_then(|m| m.as_array())
        .map(|models| {
            models
                .iter()
                .filter(|m| m.get("visibility").and_then(|v| v.as_str()) == Some("list"))
                .filter_map(|m| {
                    let slug = m.get("slug").and_then(|s| s.as_str())?.to_string();
                    let display_name = m
                        .get("display_name")
                        .and_then(|d| d.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| slug.clone());
                    Some(PlanModel { slug, display_name })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The signed-in account's model catalogue, read with `source`'s
/// current bearer.
pub async fn list_plan_models(source: &PlanTokenSource) -> Result<Vec<PlanModel>, String> {
    let bearer = source.bearer().await.map_err(|e| e.to_string())?;
    let http = crate::plan_auth::http_client(source.endpoints())?;
    let response = http
        .get(format!("{}/models", source.endpoints().api_base()))
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(|e| format!("models: {e}"))?;
    let status = response.status();
    let request_id = header(&response, "x-request-id");
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(http_failure(status.as_u16(), &body, request_id).to_string());
    }
    let body: serde_json::Value = response.json().await.map_err(|e| format!("models: {e}"))?;
    Ok(parse_plan_models(&body))
}

fn header(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

impl LlmClient {
    /// One turn on the plan route. Text deltas go to `tx` when there is
    /// one; the assembled response is returned once the stream has
    /// completed.
    pub(crate) async fn complete_plan(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        tx: Option<&tokio::sync::mpsc::Sender<StreamEvent>>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let source = self.plan_source().ok_or_else(|| {
            AgentError::Llm(
                "this agent runs in plan mode and has no plan credential attached; nothing was \
                 sent"
                    .into(),
            )
        })?;
        let url = format!("{}/responses", self.plan_endpoints().api_base());
        let body = build_plan_request_body(self.config(), messages, tools);

        let mut attempt: u32 = 1;
        let mut unavailable: usize = 0;
        loop {
            let bearer = source.bearer().await?;
            let response = self
                .http_client()
                .post(&url)
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .bearer_auth(&bearer)
                .json(&body)
                .send()
                .await
                .map_err(|e| AgentError::Http(format!("plan request: {e}")))?;
            let status = response.status();
            let request_id = header(&response, "x-request-id");
            if status.is_success() {
                return self.read_plan_stream(response, request_id, tx).await;
            }
            let retry_after = header(&response, "retry-after");
            let text = response.text().await.unwrap_or_default();
            let error = http_failure(status.as_u16(), &text, request_id);
            let delay = match status.as_u16() {
                _ if error.is_usage_limit() => None,
                429 if attempt < MAX_RATE_LIMIT_RETRIES => {
                    match classify_429(429, retry_after.as_deref(), attempt) {
                        RetryDecision::Retry { delay_ms } => {
                            Some(std::time::Duration::from_millis(delay_ms))
                        }
                        RetryDecision::NoRetry => None,
                    }
                }
                503 => {
                    let wait = self.plan_unavailable_backoff().get(unavailable).copied();
                    unavailable += 1;
                    wait
                }
                _ => None,
            };
            match delay {
                Some(wait) => {
                    tracing::warn!(
                        status = status.as_u16(),
                        attempt,
                        "plan request refused ({error}); retrying"
                    );
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                }
                None => return Err(AgentError::PlanRoute(Box::new(error))),
            }
        }
    }

    async fn read_plan_stream(
        &self,
        response: reqwest::Response,
        request_id: Option<String>,
        tx: Option<&tokio::sync::mpsc::Sender<StreamEvent>>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let fail = |e: PlanRouteError| AgentError::PlanRoute(Box::new(e));
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut full_text = String::new();
        let mut calls: Vec<PartialCall> = Vec::new();
        let mut usage: Option<Usage> = None;
        let mut completed = false;

        'stream: while let Some(chunk) = stream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(e) => {
                    return Err(fail(PlanRouteError::StreamCut(PlanFailure {
                        request_id: request_id.clone(),
                        message: Some(format!("stream read: {e}")),
                        ..Default::default()
                    })));
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&bytes));
            // Normalize CRLF framing so an event boundary is always a
            // blank line.
            if buffer.contains('\r') {
                buffer = buffer.replace("\r\n", "\n");
            }
            if buffer.len() > MAX_SSE_BUFFER_BYTES {
                return Err(AgentError::Http(format!(
                    "SSE accumulation exceeded {MAX_SSE_BUFFER_BYTES} bytes without an event \
                     boundary; refusing to grow further"
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
                                if let Some(tx) = tx {
                                    let _ =
                                        tx.send(StreamEvent::TextDelta(delta.to_string())).await;
                                }
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
                            let slot = match calls.iter().position(|c| c.item_id == item_id) {
                                Some(i) => &mut calls[i],
                                None => {
                                    calls.push(PartialCall {
                                        item_id,
                                        ..Default::default()
                                    });
                                    let last = calls.len() - 1;
                                    &mut calls[last]
                                }
                            };
                            if let Some(call_id) = item.get("call_id").and_then(|c| c.as_str()) {
                                slot.call_id = call_id.to_string();
                            }
                            if let Some(name) = call_name(item) {
                                slot.name = name;
                            }
                            // `added` opens the item with an empty
                            // argument string; `done` carries the whole
                            // of it.
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
                            return Err(fail(PlanRouteError::classify(stream_failure(
                                error,
                                &request_id,
                            ))));
                        }
                        "response.incomplete" => {
                            let reason = event
                                .get("response")
                                .and_then(|r| r.get("incomplete_details"))
                                .and_then(|d| d.get("reason"))
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            return Err(fail(PlanRouteError::Incomplete {
                                reason,
                                failure: PlanFailure {
                                    request_id: request_id.clone(),
                                    ..Default::default()
                                },
                            }));
                        }
                        "error" => {
                            let error = event.get("error").or(Some(&event));
                            return Err(fail(PlanRouteError::classify(stream_failure(
                                error,
                                &request_id,
                            ))));
                        }
                        _ => {}
                    }
                }
            }
        }

        if !completed {
            return Err(fail(PlanRouteError::StreamCut(PlanFailure {
                request_id,
                ..Default::default()
            })));
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
        if let Some(tx) = tx {
            let _ = tx.send(StreamEvent::Done(response.clone())).await;
        }
        Ok((response, usage))
    }
}

#[cfg(test)]
#[path = "llm_responses_tests.rs"]
mod tests;
