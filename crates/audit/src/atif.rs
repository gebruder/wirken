//! Export of a session as an ATIF trajectory, and a validator for the
//! format.
//!
//! ATIF, the Agent Trajectory Interchange Format, is one JSON document
//! per trajectory: an `agent`, and `steps` whose source is `system`,
//! `user` or `agent`, each agent step carrying its tool calls, their
//! results and its token metrics. This module writes version 1.8.
//!
//! Two kinds of session are exported:
//!
//! * A session an agent ran. Its rows hold the conversation: each user
//!   message, each assistant message with its tool calls, each tool
//!   result, and the usage of each model call.
//! * A session of proxied calls. Its rows hold hashes, not content. The
//!   conversation is read from the request and response bodies the
//!   caller supplies by hash, where it has them. A call whose bodies
//!   are not supplied is still a step, with its metrics and hashes and
//!   an empty message.
//!
//! Redaction is honored by construction: rows are exported as the
//! chain holds them now, so a rewritten row is exported as rewritten,
//! and a body the caller could not read is not in the document. Steps
//! from a rewritten row, tool output a hook replaced, and bodies whose
//! key was destroyed are marked in `extra`.
//!
//! [`validate`] checks a document against the format's rules as its
//! reference models state them: required fields and their types, no
//! unknown fields, sequential step ids, fields that belong to agent
//! steps only, and observation results that name a tool call of their
//! own step.

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value, json};
use wirken_time::TimestampExt as _;

use crate::session_log::{ProxyShape, SessionEvent, StoredSessionEvent};

/// The version this module writes.
pub const SCHEMA_VERSION: &str = "ATIF-v1.8";

/// Every version [`validate`] accepts.
const KNOWN_VERSIONS: &[&str] = &[
    "ATIF-v1.0",
    "ATIF-v1.1",
    "ATIF-v1.2",
    "ATIF-v1.3",
    "ATIF-v1.4",
    "ATIF-v1.5",
    "ATIF-v1.6",
    "ATIF-v1.7",
    "ATIF-v1.8",
];

/// A proxied body, as the caller could get it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// The body, as exchanged.
    Plain(Vec<u8>),
    /// Archived, and made unreadable since.
    Redacted,
    /// Not archived, or not readable here.
    Unavailable,
}

impl Body {
    fn label(&self) -> &'static str {
        match self {
            Body::Plain(_) => "exported",
            Body::Redacted => "redacted",
            Body::Unavailable => "not_available",
        }
    }
}

/// What the exporter names itself as.
#[derive(Debug, Clone)]
pub struct Producer<'a> {
    pub name: &'a str,
    pub version: &'a str,
}

fn step(
    source: &str,
    row: &StoredSessionEvent,
    message: &str,
    stable: String,
) -> Map<String, Value> {
    let mut step = Map::new();
    step.insert("step_id".into(), json!(0));
    step.insert("timestamp".into(), json!(row.ts.to_rfc3339_z()));
    step.insert("source".into(), json!(source));
    step.insert("message".into(), json!(message));
    step.insert(
        "extra".into(),
        json!({ "stable_step_id": stable, "seq": row.seq }),
    );
    step
}

fn extra_mut(step: &mut Map<String, Value>) -> &mut Map<String, Value> {
    step.entry("extra")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("extra is an object")
}

/// A tool call's arguments as an object: the parsed JSON when that is
/// one, otherwise the text under `input`.
fn arguments(raw: &str) -> Value {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) => Value::Object(object),
        _ => json!({ "input": raw }),
    }
}

fn tool_call(id: &str, name: &str, arguments: Value) -> Value {
    json!({ "tool_call_id": id, "function_name": name, "arguments": arguments })
}

/// Attach a tool result to the step that made the call, or, when no
/// step did, as a system step of its own.
fn observe(
    steps: &mut Vec<Map<String, Value>>,
    calls: &HashMap<String, usize>,
    row: &StoredSessionEvent,
    stable: String,
    call_id: Option<&str>,
    content: &str,
    extra: Option<Value>,
) {
    let mut result = Map::new();
    let at = call_id.and_then(|id| calls.get(id).copied());
    if let (Some(id), Some(_)) = (call_id, at) {
        result.insert("source_call_id".into(), json!(id));
    }
    result.insert("content".into(), json!(content));
    if let Some(extra) = extra {
        result.insert("extra".into(), extra);
    }
    let index = match at {
        Some(index) => index,
        None => {
            let mut orphan = step("system", row, "", stable);
            if let Some(id) = call_id {
                extra_mut(&mut orphan).insert("tool_call_id".into(), json!(id));
            }
            steps.push(orphan);
            steps.len() - 1
        }
    };
    let observation = steps[index]
        .entry("observation")
        .or_insert_with(|| json!({ "results": [] }));
    if let Some(results) = observation["results"].as_array_mut() {
        results.push(Value::Object(result));
    }
}

/// Token metrics in the format's accounting: the prompt count holds
/// cached tokens too.
#[derive(Debug, Clone, Copy, Default)]
struct Usage {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_creation: u64,
    cost_micros: Option<u64>,
    /// Whether `input` already counts the cached tokens.
    input_includes_cache: bool,
}

impl Usage {
    fn prompt(&self) -> u64 {
        if self.input_includes_cache {
            self.input
        } else {
            self.input + self.cache_read + self.cache_creation
        }
    }

    fn metrics(&self) -> Value {
        let mut metrics = Map::new();
        metrics.insert("prompt_tokens".into(), json!(self.prompt()));
        metrics.insert("completion_tokens".into(), json!(self.output));
        if self.cache_read > 0 {
            metrics.insert("cached_tokens".into(), json!(self.cache_read));
        }
        if let Some(micros) = self.cost_micros {
            metrics.insert("cost_usd".into(), json!(micros as f64 / 1e6));
        }
        if self.cache_creation > 0 {
            metrics.insert(
                "extra".into(),
                json!({ "cache_creation_input_tokens": self.cache_creation }),
            );
        }
        Value::Object(metrics)
    }
}

#[derive(Default)]
struct Totals {
    prompt: u64,
    completion: u64,
    cached: u64,
    cost_micros: u64,
    priced: bool,
    any: bool,
}

impl Totals {
    fn add(&mut self, usage: &Usage) {
        self.any = true;
        self.prompt += usage.prompt();
        self.completion += usage.output;
        self.cached += usage.cache_read;
        if let Some(micros) = usage.cost_micros {
            self.cost_micros += micros;
            self.priced = true;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    session_id: &str,
    producer: &Producer<'_>,
    kind: &str,
    rows: &[StoredSessionEvent],
    mut steps: Vec<Map<String, Value>>,
    model: Option<String>,
    totals: Totals,
    notes: &str,
) -> Value {
    for (index, step) in steps.iter_mut().enumerate() {
        step.insert("step_id".into(), json!(index + 1));
    }
    let mut agent = Map::new();
    agent.insert("name".into(), json!(producer.name));
    agent.insert("version".into(), json!(producer.version));
    if let Some(model) = model {
        agent.insert("model_name".into(), json!(model));
    }
    let mut root = Map::new();
    root.insert("schema_version".into(), json!(SCHEMA_VERSION));
    root.insert("session_id".into(), json!(session_id));
    root.insert("agent".into(), Value::Object(agent));
    root.insert("notes".into(), json!(notes));
    if totals.any {
        let mut metrics = Map::new();
        metrics.insert("total_prompt_tokens".into(), json!(totals.prompt));
        metrics.insert("total_completion_tokens".into(), json!(totals.completion));
        metrics.insert("total_cached_tokens".into(), json!(totals.cached));
        if totals.priced {
            metrics.insert(
                "total_cost_usd".into(),
                json!(totals.cost_micros as f64 / 1e6),
            );
        }
        metrics.insert("total_steps".into(), json!(steps.len()));
        root.insert("final_metrics".into(), Value::Object(metrics));
    }
    root.insert(
        "extra".into(),
        json!({ "wirken": {
            "kind": kind,
            "rows": rows.len(),
            "first_seq": rows.first().map(|r| r.seq),
            "last_seq": rows.last().map(|r| r.seq),
        }}),
    );
    root.insert(
        "steps".into(),
        Value::Array(steps.into_iter().map(Value::Object).collect()),
    );
    Value::Object(root)
}

/// The rows a redaction rewrote, by sequence number.
fn rewritten(rows: &[StoredSessionEvent]) -> BTreeSet<u64> {
    rows.iter()
        .filter_map(|row| match &row.event {
            SessionEvent::ChainHead {
                redaction: Some(record),
                ..
            } => Some(record.seq),
            _ => None,
        })
        .collect()
}

/// Export the rows of one session. A session with proxied calls is
/// exported from them and from `bodies`, keyed by the SHA-256 on each
/// row; any other session from its conversation rows.
pub fn export(
    session_id: &str,
    rows: &[StoredSessionEvent],
    bodies: &HashMap<String, Body>,
    producer: &Producer<'_>,
) -> Value {
    let proxied = rows
        .iter()
        .any(|r| matches!(r.event, SessionEvent::ProxyRequest { .. }));
    if proxied {
        export_proxied(session_id, rows, bodies, producer)
    } else {
        export_agent(session_id, rows, producer)
    }
}

fn export_agent(session_id: &str, rows: &[StoredSessionEvent], producer: &Producer<'_>) -> Value {
    let rewritten = rewritten(rows);
    let replaced_output: BTreeSet<&str> = rows
        .iter()
        .filter_map(|row| match &row.event {
            SessionEvent::ToolOutputRedacted { call_id, .. } => Some(call_id.as_str()),
            _ => None,
        })
        .collect();
    let mut steps: Vec<Map<String, Value>> = Vec::new();
    let mut calls: HashMap<String, usize> = HashMap::new();
    let mut model: Option<String> = None;
    let mut first_model: Option<String> = None;
    let mut pending: Option<Usage> = None;
    let mut totals = Totals::default();

    for row in rows {
        let stable = format!("seq-{}", row.seq);
        let mut pushed = false;
        match &row.event {
            SessionEvent::UserMessage { content, .. } => {
                steps.push(step("user", row, content, stable));
                pushed = true;
            }
            SessionEvent::LlmRequest { model: name, .. } => {
                model = Some(name.clone());
                first_model.get_or_insert_with(|| name.clone());
            }
            SessionEvent::LlmResponse {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                total_cost_usd_micros,
                ..
            } => {
                pending = Some(Usage {
                    input: u64::from(*input_tokens),
                    output: u64::from(*output_tokens),
                    cache_read: u64::from(*cache_read_input_tokens),
                    cache_creation: u64::from(*cache_creation_input_tokens),
                    cost_micros: *total_cost_usd_micros,
                    input_includes_cache: false,
                });
            }
            SessionEvent::AssistantMessage { content, .. } => {
                let mut agent = step("agent", row, content, stable);
                agent_fields(&mut agent, &model, pending.take(), &mut totals);
                steps.push(agent);
                pushed = true;
            }
            SessionEvent::AssistantToolCalls {
                calls: made,
                text,
                reasoning,
                ..
            } => {
                let mut agent = step("agent", row, text.as_deref().unwrap_or(""), stable);
                agent_fields(&mut agent, &model, pending.take(), &mut totals);
                if let Some(reasoning) = reasoning {
                    agent.insert("reasoning_content".into(), json!(reasoning));
                }
                agent.insert(
                    "tool_calls".into(),
                    Value::Array(
                        made.iter()
                            .map(|c| tool_call(&c.id, &c.name, arguments(&c.arguments)))
                            .collect(),
                    ),
                );
                for call in made {
                    calls.insert(call.id.clone(), steps.len());
                }
                steps.push(agent);
                pushed = true;
            }
            SessionEvent::ToolResult {
                call_id,
                tool_name,
                output,
                success,
                ..
            } => {
                let mut extra = Map::new();
                extra.insert("tool_name".into(), json!(tool_name));
                extra.insert("success".into(), json!(success));
                extra.insert("seq".into(), json!(row.seq));
                if replaced_output.contains(call_id.as_str()) {
                    extra.insert("output_replaced_by_hook".into(), json!(true));
                }
                if rewritten.contains(&row.seq) {
                    extra.insert("redacted".into(), json!(true));
                }
                observe(
                    &mut steps,
                    &calls,
                    row,
                    stable,
                    Some(call_id),
                    output,
                    Some(Value::Object(extra)),
                );
            }
            _ => {}
        }
        if pushed
            && rewritten.contains(&row.seq)
            && let Some(last) = steps.last_mut()
        {
            extra_mut(last).insert("redacted".into(), json!(true));
        }
    }
    finish(
        session_id,
        producer,
        "agent",
        rows,
        steps,
        first_model,
        totals,
        "Exported from the session's chain. System prompts and tool definitions are not on \
         the chain, which holds their hashes, and are not in this document.",
    )
}

fn agent_fields(
    agent: &mut Map<String, Value>,
    model: &Option<String>,
    usage: Option<Usage>,
    totals: &mut Totals,
) {
    if let Some(model) = model {
        agent.insert("model_name".into(), json!(model));
    }
    if let Some(usage) = usage {
        totals.add(&usage);
        agent.insert("metrics".into(), usage.metrics());
        agent.insert("llm_call_count".into(), json!(1));
    }
}

// --- proxied sessions -------------------------------------------------

/// One message of a proxied conversation, in either provider's shape.
#[derive(Debug, Clone, PartialEq)]
enum Turn {
    System(String),
    User(String),
    Assistant {
        text: String,
        reasoning: Option<String>,
        calls: Vec<(String, String, Value)>,
    },
    ToolResult {
        call_id: Option<String>,
        content: String,
    },
}

/// The text of a content value: a string, or the text parts of a list
/// with a placeholder for each part that is not text.
fn text_of(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| match part["type"].as_str() {
                Some("text" | "input_text" | "output_text") => {
                    part["text"].as_str().map(str::to_string)
                }
                Some("tool_use" | "tool_result" | "thinking" | "redacted_thinking") => None,
                Some(other) => Some(format!("[{other}]")),
                None => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The turns one request message stands for.
fn message_turns(shape: ProxyShape, message: &Value) -> Vec<Turn> {
    let role = message["role"].as_str().unwrap_or("");
    let content = &message["content"];
    match (shape, role) {
        (_, "system" | "developer") => vec![Turn::System(text_of(content))],
        (ProxyShape::OpenaiChat, "tool") => vec![Turn::ToolResult {
            call_id: message["tool_call_id"].as_str().map(str::to_string),
            content: text_of(content),
        }],
        (ProxyShape::OpenaiChat, "assistant") => vec![Turn::Assistant {
            text: text_of(content),
            reasoning: message["reasoning_content"]
                .as_str()
                .or_else(|| message["reasoning"].as_str())
                .map(str::to_string),
            calls: message["tool_calls"]
                .as_array()
                .map(|calls| calls.iter().filter_map(openai_call).collect())
                .unwrap_or_default(),
        }],
        (ProxyShape::AnthropicMessages, "assistant") => vec![anthropic_assistant(content)],
        (ProxyShape::AnthropicMessages, _) => {
            let mut turns: Vec<Turn> = content
                .as_array()
                .map(|parts| {
                    parts
                        .iter()
                        .filter(|p| p["type"] == "tool_result")
                        .map(|p| Turn::ToolResult {
                            call_id: p["tool_use_id"].as_str().map(str::to_string),
                            content: text_of(&p["content"]),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let text = text_of(content);
            if !text.is_empty() || turns.is_empty() {
                turns.push(Turn::User(text));
            }
            turns
        }
        _ => vec![Turn::User(text_of(content))],
    }
}

fn openai_call(call: &Value) -> Option<(String, String, Value)> {
    Some((
        call["id"].as_str()?.to_string(),
        call["function"]["name"].as_str()?.to_string(),
        arguments(call["function"]["arguments"].as_str().unwrap_or("")),
    ))
}

fn anthropic_assistant(content: &Value) -> Turn {
    let parts = content.as_array().map(Vec::as_slice).unwrap_or_default();
    let reasoning: Vec<&str> = parts
        .iter()
        .filter(|p| p["type"] == "thinking")
        .filter_map(|p| p["thinking"].as_str())
        .collect();
    Turn::Assistant {
        text: text_of(content),
        reasoning: (!reasoning.is_empty()).then(|| reasoning.join("\n")),
        calls: parts
            .iter()
            .filter(|p| p["type"] == "tool_use")
            .filter_map(|p| {
                Some((
                    p["id"].as_str()?.to_string(),
                    p["name"].as_str()?.to_string(),
                    match &p["input"] {
                        Value::Object(input) => Value::Object(input.clone()),
                        other => json!({ "input": other }),
                    },
                ))
            })
            .collect(),
    }
}

/// A message as it is compared between requests: without the
/// `cache_control` markers a client moves from turn to turn, which
/// change an earlier message's bytes and nothing it says.
fn comparable(message: &Value) -> Value {
    match message {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| key.as_str() != "cache_control")
                .map(|(key, value)| (key.clone(), comparable(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(comparable).collect()),
        other => other.clone(),
    }
}

/// The messages of a request body, the system prompt first: the raw
/// values, for telling what an earlier request already carried.
fn request_messages(shape: ProxyShape, body: &Value) -> Vec<Value> {
    let mut messages = Vec::new();
    if shape == ProxyShape::AnthropicMessages && !body["system"].is_null() {
        messages.push(json!({ "role": "system", "content": body["system"] }));
    }
    if let Some(list) = body["messages"].as_array() {
        messages.extend(list.iter().cloned());
    }
    messages
}

/// One hash for each prefix of a request's `messages`: the first names
/// the conversation so far after one message, the last after all of
/// them. A request continues an earlier one exactly when the earlier
/// request's last hash is among this request's hashes, which is how
/// the proxy tells one conversation from another on a token that
/// carries several. A system prompt outside `messages` is not part of
/// it. Empty for a body with no messages.
pub fn conversation_chain(body: &Value) -> Vec<String> {
    use sha2::{Digest, Sha256};
    let mut state: Vec<u8> = b"wirken-proxy-conversation/v1".to_vec();
    body["messages"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|message| {
            let mut hasher = Sha256::new();
            hasher.update(&state);
            hasher.update(comparable(message).to_string().as_bytes());
            state = hasher.finalize().to_vec();
            state.iter().map(|b| format!("{b:02x}")).collect()
        })
        .collect()
}

/// The assistant turn a response body holds, whether it is one JSON
/// document or a stream of events.
fn response_turn(shape: ProxyShape, body: &[u8]) -> Option<Turn> {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return match shape {
            ProxyShape::OpenaiChat => {
                let message = &value["choices"][0]["message"];
                message
                    .is_object()
                    .then(|| message_turns(shape, message).into_iter().next())
                    .flatten()
            }
            ProxyShape::AnthropicMessages => value["content"]
                .is_array()
                .then(|| anthropic_assistant(&value["content"])),
        };
    }
    let text = std::str::from_utf8(body).ok()?;
    let events: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .collect();
    if events.is_empty() {
        return None;
    }
    let (mut said, mut reasoning) = (String::new(), String::new());
    // A tool call's id, name and argument text, by its index in the
    // stream.
    let mut calls: Vec<(String, String, String)> = Vec::new();
    let slot = |calls: &mut Vec<(String, String, String)>, index: usize| {
        while calls.len() <= index {
            calls.push(Default::default());
        }
        index
    };
    // Anthropic numbers content blocks, text and tool calls together.
    let mut block_call: HashMap<u64, usize> = HashMap::new();
    for event in &events {
        match shape {
            ProxyShape::OpenaiChat => {
                let delta = &event["choices"][0]["delta"];
                if let Some(text) = delta["content"].as_str() {
                    said.push_str(text);
                }
                for key in ["reasoning_content", "reasoning"] {
                    if let Some(text) = delta[key].as_str() {
                        reasoning.push_str(text);
                    }
                }
                for call in delta["tool_calls"].as_array().into_iter().flatten() {
                    let index = slot(&mut calls, call["index"].as_u64().unwrap_or(0) as usize);
                    if let Some(id) = call["id"].as_str() {
                        calls[index].0 = id.to_string();
                    }
                    if let Some(name) = call["function"]["name"].as_str() {
                        calls[index].1.push_str(name);
                    }
                    if let Some(part) = call["function"]["arguments"].as_str() {
                        calls[index].2.push_str(part);
                    }
                }
            }
            ProxyShape::AnthropicMessages => match event["type"].as_str() {
                Some("content_block_start") => {
                    let block = &event["content_block"];
                    if block["type"] == "tool_use" {
                        let next = calls.len();
                        let index = slot(&mut calls, next);
                        calls[index].0 = block["id"].as_str().unwrap_or("").to_string();
                        calls[index].1 = block["name"].as_str().unwrap_or("").to_string();
                        block_call.insert(event["index"].as_u64().unwrap_or(0), index);
                    } else if let Some(text) = block["text"].as_str() {
                        said.push_str(text);
                    }
                }
                Some("content_block_delta") => {
                    let delta = &event["delta"];
                    if let Some(text) = delta["text"].as_str() {
                        said.push_str(text);
                    }
                    if let Some(text) = delta["thinking"].as_str() {
                        reasoning.push_str(text);
                    }
                    if let Some(part) = delta["partial_json"].as_str()
                        && let Some(index) = block_call.get(&event["index"].as_u64().unwrap_or(0))
                    {
                        calls[*index].2.push_str(part);
                    }
                }
                _ => {}
            },
        }
    }
    Some(Turn::Assistant {
        text: said,
        reasoning: (!reasoning.is_empty()).then_some(reasoning),
        calls: calls
            .into_iter()
            .filter(|(id, name, _)| !id.is_empty() && !name.is_empty())
            .map(|(id, name, raw)| {
                let args = if raw.is_empty() {
                    json!({})
                } else {
                    arguments(&raw)
                };
                (id, name, args)
            })
            .collect(),
    })
}

fn export_proxied(
    session_id: &str,
    rows: &[StoredSessionEvent],
    bodies: &HashMap<String, Body>,
    producer: &Producer<'_>,
) -> Value {
    let mut steps: Vec<Map<String, Value>> = Vec::new();
    let mut calls: HashMap<String, usize> = HashMap::new();
    let mut totals = Totals::default();
    let mut first_model: Option<String> = None;
    // The messages of the request before this one, and whether its
    // answer became a step: what the next request repeats.
    let mut carried: Vec<Value> = Vec::new();
    let mut answered = false;
    // The request rows still waiting for their answer, by request id.
    let mut open: HashMap<&str, (&StoredSessionEvent, ProxyShape, &str)> = HashMap::new();
    let unavailable = Body::Unavailable;

    for row in rows {
        match &row.event {
            SessionEvent::ProxyRequest {
                request_id,
                model,
                shape,
                request_sha256,
                upstream,
                provider,
                token_id,
                ..
            } => {
                first_model.get_or_insert_with(|| model.clone());
                open.insert(request_id.as_str(), (row, *shape, model.as_str()));
                let body = bodies.get(&request_sha256.0).unwrap_or(&unavailable);
                let Body::Plain(bytes) = body else {
                    // Nothing to read: the call is still shown, by the
                    // step its answer makes.
                    carried.clear();
                    answered = false;
                    continue;
                };
                let Ok(parsed) = serde_json::from_slice::<Value>(bytes) else {
                    continue;
                };
                let messages = request_messages(*shape, &parsed);
                // A request repeats the conversation so far. What it
                // adds starts after the messages the last request had
                // and the answer to it.
                let repeats = messages.len() >= carried.len()
                    && messages
                        .iter()
                        .zip(&carried)
                        .all(|(a, b)| comparable(a) == comparable(b));
                let skip = if repeats && !carried.is_empty() {
                    let reply = usize::from(
                        answered
                            && messages
                                .get(carried.len())
                                .is_some_and(|m| m["role"] == "assistant"),
                    );
                    carried.len() + reply
                } else {
                    0
                };
                for (index, message) in messages.iter().enumerate().skip(skip) {
                    for (part, turn) in message_turns(*shape, message).into_iter().enumerate() {
                        let stable = format!("seq-{}-m{index}-{part}", row.seq);
                        match turn {
                            Turn::System(text) => steps.push(step("system", row, &text, stable)),
                            Turn::User(text) => steps.push(step("user", row, &text, stable)),
                            Turn::Assistant {
                                text,
                                reasoning,
                                calls: made,
                            } => {
                                // An assistant turn the client sent
                                // back: one this proxy did not see made.
                                let mut agent = step("agent", row, &text, stable);
                                if let Some(reasoning) = reasoning {
                                    agent.insert("reasoning_content".into(), json!(reasoning));
                                }
                                push_calls(&mut agent, &mut calls, steps.len(), made);
                                agent.insert("is_copied_context".into(), json!(true));
                                steps.push(agent);
                            }
                            Turn::ToolResult { call_id, content } => observe(
                                &mut steps,
                                &calls,
                                row,
                                stable,
                                call_id.as_deref(),
                                &content,
                                None,
                            ),
                        }
                    }
                }
                if skip == 0
                    && let Some(first) = steps
                        .iter_mut()
                        .rev()
                        .find(|s| s["extra"]["seq"] == row.seq)
                {
                    extra_mut(first).insert(
                        "wirken".into(),
                        json!({ "upstream": upstream, "provider": provider, "token_id": token_id }),
                    );
                }
                carried = messages;
                answered = false;
            }
            SessionEvent::ProxyResponse {
                request_id,
                status,
                latency_ms,
                input_tokens,
                output_tokens,
                cache_read_input_tokens,
                cache_creation_input_tokens,
                total_cost_usd_micros,
                response_sha256,
                complete,
                ..
            } => {
                let Some((request, shape, model)) = open.remove(request_id.as_str()) else {
                    continue;
                };
                let SessionEvent::ProxyRequest { request_sha256, .. } = &request.event else {
                    continue;
                };
                let request_body = bodies.get(&request_sha256.0).unwrap_or(&unavailable);
                let response_body = bodies.get(&response_sha256.0).unwrap_or(&unavailable);
                let turn = match response_body {
                    Body::Plain(bytes) if (200..300).contains(status) => {
                        response_turn(shape, bytes)
                    }
                    _ => None,
                };
                let (text, reasoning, made) = match turn {
                    Some(Turn::Assistant {
                        text,
                        reasoning,
                        calls,
                    }) => (text, reasoning, calls),
                    _ => (String::new(), None, Vec::new()),
                };
                let mut agent = step("agent", row, &text, format!("seq-{}", row.seq));
                agent.insert("model_name".into(), json!(model));
                if let Some(reasoning) = reasoning {
                    agent.insert("reasoning_content".into(), json!(reasoning));
                }
                push_calls(&mut agent, &mut calls, steps.len(), made);
                agent.insert("llm_call_count".into(), json!(1));
                if input_tokens.is_some() || output_tokens.is_some() {
                    let usage = Usage {
                        input: u64::from(input_tokens.unwrap_or(0)),
                        output: u64::from(output_tokens.unwrap_or(0)),
                        cache_read: u64::from(cache_read_input_tokens.unwrap_or(0)),
                        cache_creation: u64::from(cache_creation_input_tokens.unwrap_or(0)),
                        cost_micros: *total_cost_usd_micros,
                        input_includes_cache: shape == ProxyShape::OpenaiChat,
                    };
                    totals.add(&usage);
                    agent.insert("metrics".into(), usage.metrics());
                }
                extra_mut(&mut agent).insert(
                    "wirken".into(),
                    json!({
                        "request_id": request_id,
                        "request_seq": request.seq,
                        "request_sha256": request_sha256.0,
                        "response_sha256": response_sha256.0,
                        "request_body": request_body.label(),
                        "response_body": response_body.label(),
                        "status": status,
                        "latency_ms": latency_ms,
                        "complete": complete,
                    }),
                );
                steps.push(agent);
                answered = matches!(response_body, Body::Plain(_));
            }
            // A tool call the client made at the MCP endpoint, which
            // the gateway ran. One the model's answer already carries,
            // by the id of its tool use, stays on that step; any other
            // is a step of its own.
            SessionEvent::AssistantToolCalls { calls: made, .. } => {
                let unseen: Vec<_> = made.iter().filter(|c| !calls.contains_key(&c.id)).collect();
                if !unseen.is_empty() {
                    let mut agent = step("agent", row, "", format!("seq-{}", row.seq));
                    agent.insert(
                        "tool_calls".into(),
                        Value::Array(
                            unseen
                                .iter()
                                .map(|c| tool_call(&c.id, &c.name, arguments(&c.arguments)))
                                .collect(),
                        ),
                    );
                    extra_mut(&mut agent).insert("wirken".into(), json!({ "mcp_endpoint": true }));
                    for call in unseen {
                        calls.insert(call.id.clone(), steps.len());
                    }
                    steps.push(agent);
                }
            }
            // What the gateway recorded the tool returning. The result
            // the client later sends its model is a second entry, with
            // no `recorded_by`.
            SessionEvent::ToolResult {
                call_id,
                tool_name,
                output,
                success,
                ..
            } => observe(
                &mut steps,
                &calls,
                row,
                format!("seq-{}", row.seq),
                Some(call_id),
                output,
                Some(json!({
                    "tool_name": tool_name,
                    "success": success,
                    "seq": row.seq,
                    "recorded_by": "wirken",
                })),
            ),
            _ => {}
        }
    }
    finish(
        session_id,
        producer,
        "proxied",
        rows,
        steps,
        first_model,
        totals,
        "Exported from proxied calls. The chain holds a hash of each request and response \
         body; the messages here are read from archived bodies, and a call whose bodies were \
         not available is a step with its metrics and an empty message.",
    )
}

fn push_calls(
    agent: &mut Map<String, Value>,
    calls: &mut HashMap<String, usize>,
    index: usize,
    made: Vec<(String, String, Value)>,
) {
    if made.is_empty() {
        return;
    }
    for (id, _, _) in &made {
        calls.insert(id.clone(), index);
    }
    agent.insert(
        "tool_calls".into(),
        Value::Array(
            made.into_iter()
                .map(|(id, name, args)| tool_call(&id, &name, args))
                .collect(),
        ),
    );
}

// --- validation -------------------------------------------------------

struct Check {
    errors: Vec<String>,
}

impl Check {
    fn fail(&mut self, path: &str, what: impl std::fmt::Display) {
        self.errors.push(format!("{path}: {what}"));
    }

    /// `value` as an object with only the `known` keys.
    fn object<'v>(
        &mut self,
        path: &str,
        value: &'v Value,
        known: &[&str],
    ) -> Option<&'v Map<String, Value>> {
        let Some(object) = value.as_object() else {
            self.fail(path, "is not an object");
            return None;
        };
        for key in object.keys() {
            if !known.contains(&key.as_str()) {
                self.fail(path, format!("unknown field '{key}'"));
            }
        }
        Some(object)
    }

    fn string(&mut self, path: &str, object: &Map<String, Value>, key: &str, required: bool) {
        match object.get(key) {
            Some(Value::String(_)) => {}
            Some(Value::Null) | None if !required => {}
            None | Some(Value::Null) => self.fail(path, format!("'{key}' is required")),
            Some(_) => self.fail(path, format!("'{key}' is not a string")),
        }
    }

    fn integer(&mut self, path: &str, object: &Map<String, Value>, key: &str, min: Option<i64>) {
        match object.get(key) {
            None | Some(Value::Null) => {}
            Some(value) => match value.as_i64() {
                Some(n) if min.is_none_or(|m| n >= m) => {}
                Some(_) => self.fail(path, format!("'{key}' is below its minimum")),
                None => self.fail(path, format!("'{key}' is not an integer")),
            },
        }
    }

    fn number(&mut self, path: &str, object: &Map<String, Value>, key: &str) {
        if let Some(value) = object.get(key)
            && !value.is_null()
            && !value.is_number()
        {
            self.fail(path, format!("'{key}' is not a number"));
        }
    }

    fn dict(&mut self, path: &str, object: &Map<String, Value>, key: &str) {
        if let Some(value) = object.get(key)
            && !value.is_null()
            && !value.is_object()
        {
            self.fail(path, format!("'{key}' is not an object"));
        }
    }

    /// A message or a result's content: a string, or content parts.
    fn content(&mut self, path: &str, value: &Value) {
        match value {
            Value::String(_) => {}
            Value::Array(parts) => {
                for (i, part) in parts.iter().enumerate() {
                    let path = format!("{path}[{i}]");
                    let Some(part) = self.object(&path, part, &["type", "text", "source"]) else {
                        continue;
                    };
                    let (text, source) = (
                        part.get("text").filter(|v| !v.is_null()),
                        part.get("source").filter(|v| !v.is_null()),
                    );
                    match part.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            if !text.is_some_and(Value::is_string) {
                                self.fail(&path, "'text' is required when type='text'");
                            }
                            if source.is_some() {
                                self.fail(&path, "'source' is not allowed when type='text'");
                            }
                        }
                        Some(kind @ ("image" | "audio")) => {
                            if text.is_some() {
                                self.fail(
                                    &path,
                                    format!("'text' is not allowed when type='{kind}'"),
                                );
                            }
                            let Some(source) = source else {
                                self.fail(
                                    &path,
                                    format!("'source' is required when type='{kind}'"),
                                );
                                continue;
                            };
                            let known: &[&str] = if kind == "image" {
                                &["media_type", "path"]
                            } else {
                                &["media_type", "path", "duration_sec"]
                            };
                            if let Some(source) =
                                self.object(&format!("{path}.source"), source, known)
                            {
                                self.string(&path, source, "path", true);
                                let media = source.get("media_type").and_then(Value::as_str);
                                if !media.is_some_and(|m| m.starts_with(&format!("{kind}/"))) {
                                    self.fail(&path, format!("the source is not {kind} media"));
                                }
                            }
                        }
                        _ => self.fail(&path, "'type' is not text, image or audio"),
                    }
                }
            }
            _ => self.fail(path, "is neither a string nor a list of content parts"),
        }
    }

    fn step(&mut self, path: &str, value: &Value, expected_id: usize) {
        const FIELDS: &[&str] = &[
            "step_id",
            "timestamp",
            "source",
            "model_name",
            "reasoning_effort",
            "message",
            "reasoning_content",
            "tool_calls",
            "observation",
            "metrics",
            "is_copied_context",
            "llm_call_count",
            "extra",
        ];
        let Some(step) = self.object(path, value, FIELDS) else {
            return;
        };
        match step.get("step_id").and_then(Value::as_i64) {
            Some(id) if id == expected_id as i64 => {}
            Some(id) => self.fail(
                path,
                format!("step_id: expected {expected_id} (sequential from 1), got {id}"),
            ),
            None => self.fail(path, "'step_id' is required and is an integer"),
        }
        if let Some(Value::String(ts)) = step.get("timestamp")
            && ts
                .replace('Z', "+00:00")
                .parse::<wirken_time::Timestamp>()
                .is_err()
        {
            self.fail(path, format!("invalid ISO 8601 timestamp {ts:?}"));
        }
        self.string(path, step, "timestamp", false);
        let source = step.get("source").and_then(Value::as_str);
        if !matches!(source, Some("system" | "user" | "agent")) {
            self.fail(path, "'source' is not system, user or agent");
        }
        match step.get("message") {
            Some(message) if !message.is_null() => {
                self.content(&format!("{path}.message"), message)
            }
            _ => self.fail(path, "'message' is required"),
        }
        self.string(path, step, "model_name", false);
        self.string(path, step, "reasoning_content", false);
        if let Some(effort) = step.get("reasoning_effort")
            && !(effort.is_null() || effort.is_string() || effort.is_number())
        {
            self.fail(path, "'reasoning_effort' is neither a string nor a number");
        }
        self.integer(path, step, "llm_call_count", Some(0));
        if let Some(flag) = step.get("is_copied_context")
            && !(flag.is_null() || flag.is_boolean())
        {
            self.fail(path, "'is_copied_context' is not a boolean");
        }
        self.dict(path, step, "extra");
        let present = |key: &str| step.get(key).is_some_and(|v| !v.is_null());
        if source != Some("agent") {
            for field in [
                "model_name",
                "reasoning_effort",
                "reasoning_content",
                "tool_calls",
                "metrics",
            ] {
                if present(field) {
                    self.fail(
                        path,
                        format!(
                            "field '{field}' is only applicable when source is 'agent', but \
                             source is '{}'",
                            source.unwrap_or("")
                        ),
                    );
                }
            }
        } else if step.get("llm_call_count").and_then(Value::as_i64) == Some(0) {
            for field in ["metrics", "reasoning_content"] {
                if present(field) {
                    self.fail(
                        path,
                        format!("field '{field}' must be absent when llm_call_count is 0"),
                    );
                }
            }
        }

        let mut call_ids: Vec<&str> = Vec::new();
        match step.get("tool_calls") {
            None | Some(Value::Null) => {}
            Some(Value::Array(calls)) => {
                for (i, call) in calls.iter().enumerate() {
                    let path = format!("{path}.tool_calls[{i}]");
                    let known = ["tool_call_id", "function_name", "arguments", "extra"];
                    if let Some(call) = self.object(&path, call, &known) {
                        self.string(&path, call, "tool_call_id", true);
                        self.string(&path, call, "function_name", true);
                        if !call.get("arguments").is_some_and(Value::is_object) {
                            self.fail(&path, "'arguments' is required and is an object");
                        }
                        self.dict(&path, call, "extra");
                        if let Some(id) = call.get("tool_call_id").and_then(Value::as_str) {
                            call_ids.push(id);
                        }
                    }
                }
            }
            Some(_) => self.fail(path, "'tool_calls' is not a list"),
        }

        if let Some(metrics) = step.get("metrics").filter(|v| !v.is_null()) {
            let path = format!("{path}.metrics");
            let known = [
                "prompt_tokens",
                "completion_tokens",
                "cached_tokens",
                "cost_usd",
                "prompt_token_ids",
                "completion_token_ids",
                "logprobs",
                "extra",
            ];
            if let Some(metrics) = self.object(&path, metrics, &known) {
                for key in ["prompt_tokens", "completion_tokens", "cached_tokens"] {
                    self.integer(&path, metrics, key, None);
                }
                self.number(&path, metrics, "cost_usd");
                self.dict(&path, metrics, "extra");
            }
        }

        if let Some(observation) = step.get("observation").filter(|v| !v.is_null()) {
            let path = format!("{path}.observation");
            let Some(observation) = self.object(&path, observation, &["results"]) else {
                return;
            };
            let Some(results) = observation.get("results").and_then(Value::as_array) else {
                self.fail(&path, "'results' is required and is a list");
                return;
            };
            for (i, result) in results.iter().enumerate() {
                let path = format!("{path}.results[{i}]");
                let known = [
                    "source_call_id",
                    "content",
                    "subagent_trajectory_ref",
                    "extra",
                ];
                let Some(result) = self.object(&path, result, &known) else {
                    continue;
                };
                self.string(&path, result, "source_call_id", false);
                self.dict(&path, result, "extra");
                if let Some(content) = result.get("content").filter(|v| !v.is_null()) {
                    self.content(&format!("{path}.content"), content);
                }
                if let Some(id) = result.get("source_call_id").and_then(Value::as_str)
                    && !call_ids.contains(&id)
                {
                    self.fail(
                        &path,
                        format!(
                            "source_call_id '{id}' is not found in step {expected_id}'s tool_calls"
                        ),
                    );
                }
                match result.get("subagent_trajectory_ref") {
                    None | Some(Value::Null) => {}
                    Some(Value::Array(refs)) => {
                        for (j, reference) in refs.iter().enumerate() {
                            let path = format!("{path}.subagent_trajectory_ref[{j}]");
                            let known = ["trajectory_id", "session_id", "trajectory_path", "extra"];
                            if let Some(reference) = self.object(&path, reference, &known) {
                                let set =
                                    |key: &str| reference.get(key).is_some_and(Value::is_string);
                                if !set("trajectory_id") && !set("trajectory_path") {
                                    self.fail(&path, "must set trajectory_id or trajectory_path");
                                }
                            }
                        }
                    }
                    Some(_) => self.fail(&path, "'subagent_trajectory_ref' is not a list"),
                }
            }
        }
    }

    fn trajectory(&mut self, path: &str, value: &Value) {
        const FIELDS: &[&str] = &[
            "schema_version",
            "session_id",
            "trajectory_id",
            "agent",
            "steps",
            "notes",
            "final_metrics",
            "continued_trajectory_ref",
            "extra",
            "subagent_trajectories",
        ];
        let Some(root) = self.object(path, value, FIELDS) else {
            return;
        };
        match root.get("schema_version").and_then(Value::as_str) {
            Some(version) if KNOWN_VERSIONS.contains(&version) => {}
            Some(version) => self.fail(path, format!("schema_version {version:?} is not known")),
            None => self.fail(path, "'schema_version' is required"),
        }
        for key in [
            "session_id",
            "trajectory_id",
            "notes",
            "continued_trajectory_ref",
        ] {
            self.string(path, root, key, false);
        }
        self.dict(path, root, "extra");

        match root.get("agent") {
            Some(agent) => {
                let path = format!("{path}.agent");
                let known = ["name", "version", "model_name", "tool_definitions", "extra"];
                if let Some(agent) = self.object(&path, agent, &known) {
                    self.string(&path, agent, "name", true);
                    self.string(&path, agent, "version", true);
                    self.string(&path, agent, "model_name", false);
                    self.dict(&path, agent, "extra");
                    if let Some(tools) = agent.get("tool_definitions")
                        && !(tools.is_null()
                            || tools
                                .as_array()
                                .is_some_and(|t| t.iter().all(Value::is_object)))
                    {
                        self.fail(&path, "'tool_definitions' is not a list of objects");
                    }
                }
            }
            None => self.fail(path, "'agent' is required"),
        }

        match root.get("steps").and_then(Value::as_array) {
            Some(steps) => {
                for (i, step) in steps.iter().enumerate() {
                    self.step(&format!("{path}.steps[{i}]"), step, i + 1);
                }
            }
            None => self.fail(path, "'steps' is required and is a list"),
        }

        if let Some(metrics) = root.get("final_metrics").filter(|v| !v.is_null()) {
            let path = format!("{path}.final_metrics");
            let known = [
                "total_prompt_tokens",
                "total_completion_tokens",
                "total_cached_tokens",
                "total_cost_usd",
                "total_steps",
                "extra",
            ];
            if let Some(metrics) = self.object(&path, metrics, &known) {
                for key in [
                    "total_prompt_tokens",
                    "total_completion_tokens",
                    "total_cached_tokens",
                ] {
                    self.integer(&path, metrics, key, None);
                }
                self.integer(&path, metrics, "total_steps", Some(0));
                self.number(&path, metrics, "total_cost_usd");
                self.dict(&path, metrics, "extra");
            }
        }

        match root.get("subagent_trajectories") {
            None | Some(Value::Null) => {}
            Some(Value::Array(subagents)) => {
                let mut seen: Vec<&str> = Vec::new();
                for (i, sub) in subagents.iter().enumerate() {
                    let path = format!("{path}.subagent_trajectories[{i}]");
                    match sub["trajectory_id"].as_str() {
                        Some(id) if seen.contains(&id) => {
                            self.fail(&path, format!("trajectory_id {id:?} is not unique"));
                        }
                        Some(id) => seen.push(id),
                        None => {
                            self.fail(&path, "trajectory_id is required for embedded subagents")
                        }
                    }
                    self.trajectory(&path, sub);
                }
            }
            Some(_) => self.fail(path, "'subagent_trajectories' is not a list"),
        }
    }
}

/// Every way `document` departs from the format. Empty for a valid
/// trajectory.
pub fn validate(document: &Value) -> Vec<String> {
    let mut check = Check { errors: Vec::new() };
    check.trajectory("trajectory", document);
    check.errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_log::{HashHex, SessionId, TrustLevel};

    const PRODUCER: Producer<'static> = Producer {
        name: "wirken",
        version: "0.0.0-test",
    };

    /// Rows for one session from their serialized form, numbered from
    /// one.
    fn rows(events: Vec<Value>) -> Vec<StoredSessionEvent> {
        events
            .into_iter()
            .enumerate()
            .map(|(i, event)| StoredSessionEvent {
                id: i as i64 + 1,
                session_id: SessionId::new("s"),
                seq: i as u64 + 1,
                ts: "2026-11-22T10:00:00Z".parse().unwrap(),
                trust: TrustLevel::System,
                event: serde_json::from_value(event.clone())
                    .unwrap_or_else(|e| panic!("{event}: {e}")),
                leaf_hash: HashHex(String::new()),
                prev_hash: HashHex(String::new()),
                hash: HashHex(String::new()),
            })
            .collect()
    }

    fn sha(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn llm_request(model: &str) -> Value {
        json!({"kind":"llm_request","provider":"p","model":model,"request_id":"r",
               "tools_hash":"00","messages_hash":"00","agent_id":"a"})
    }

    fn llm_response(input: u32, output: u32, cache_read: u32, micros: Option<u64>) -> Value {
        json!({"kind":"llm_response","request_id":"r","finish_reason":"stop",
               "input_tokens":input,"output_tokens":output,
               "cache_read_input_tokens":cache_read,"latency_ms":5,"agent_id":"a",
               "total_cost_usd_micros":micros})
    }

    fn agent_session() -> Vec<StoredSessionEvent> {
        rows(vec![
            json!({"kind":"user_message","content":"what time is it"}),
            llm_request("model-a"),
            llm_response(100, 20, 40, Some(1500)),
            json!({"kind":"assistant_tool_calls","agent_id":"a","text":"Checking.",
                   "reasoning":"I should run date.",
                   "calls":[{"id":"c1","name":"exec","arguments":"{\"command\": \"date\"}"},
                            {"id":"c2","name":"apply_patch","arguments":"not json"}]}),
            json!({"kind":"tool_result","call_id":"c1","tool_name":"exec",
                   "output":"Sun Nov 22","success":true,"agent_id":"a"}),
            json!({"kind":"tool_result","call_id":"c2","tool_name":"apply_patch",
                   "output":"failed","success":false,"agent_id":"a"}),
            llm_request("model-a"),
            llm_response(160, 8, 0, None),
            json!({"kind":"assistant_message","content":"It is Sunday.","agent_id":"a"}),
        ])
    }

    /// An agent session becomes user and agent steps in order, each
    /// tool result under the step that made the call, each model
    /// call's usage on the step it produced, and the document is valid.
    #[test]
    fn an_agent_session_exports_as_a_valid_trajectory() {
        let doc = export("a/terminal/1", &agent_session(), &HashMap::new(), &PRODUCER);
        assert_eq!(validate(&doc), Vec::<String>::new());
        // For checking the document with another validator.
        if let Ok(dir) = std::env::var("WIRKEN_TEST_ATIF_OUT") {
            let path = std::path::Path::new(&dir).join("agent-session.atif.json");
            std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
        }
        assert_eq!(doc["schema_version"], "ATIF-v1.8");
        assert_eq!(doc["session_id"], "a/terminal/1");
        assert_eq!(doc["agent"]["name"], "wirken");
        assert_eq!(doc["agent"]["model_name"], "model-a");
        assert_eq!(doc["extra"]["wirken"]["kind"], "agent");

        let steps = doc["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0]["source"], "user");
        assert_eq!(steps[0]["message"], "what time is it");
        assert_eq!(steps[0]["extra"]["stable_step_id"], "seq-1");
        assert_eq!(steps[0]["timestamp"], "2026-11-22T10:00:00Z");

        let tool_step = &steps[1];
        assert_eq!(tool_step["source"], "agent");
        assert_eq!(tool_step["message"], "Checking.");
        assert_eq!(tool_step["reasoning_content"], "I should run date.");
        assert_eq!(tool_step["model_name"], "model-a");
        assert_eq!(tool_step["llm_call_count"], 1);
        assert_eq!(tool_step["tool_calls"][0]["arguments"]["command"], "date");
        // Arguments that are not a JSON object are carried as text.
        assert_eq!(tool_step["tool_calls"][1]["arguments"]["input"], "not json");
        // The prompt count holds the cached tokens too.
        assert_eq!(tool_step["metrics"]["prompt_tokens"], 140);
        assert_eq!(tool_step["metrics"]["cached_tokens"], 40);
        assert_eq!(tool_step["metrics"]["completion_tokens"], 20);
        assert_eq!(tool_step["metrics"]["cost_usd"], 0.0015);
        let results = tool_step["observation"]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["source_call_id"], "c1");
        assert_eq!(results[0]["content"], "Sun Nov 22");
        assert_eq!(results[1]["extra"]["success"], false);

        assert_eq!(steps[2]["message"], "It is Sunday.");
        assert!(steps[2]["metrics"].get("cost_usd").is_none());
        assert_eq!(doc["final_metrics"]["total_prompt_tokens"], 300);
        assert_eq!(doc["final_metrics"]["total_completion_tokens"], 28);
        assert_eq!(doc["final_metrics"]["total_steps"], 3);
        for (i, step) in steps.iter().enumerate() {
            assert_eq!(step["step_id"], i + 1);
        }
    }

    /// A row a redaction rewrote is exported as the chain holds it
    /// now, and marked. Tool output a hook replaced is marked too. The
    /// removed text is in neither.
    #[test]
    fn a_rewritten_row_and_replaced_output_are_exported_as_they_stand_and_marked() {
        let mut events = vec![
            json!({"kind":"user_message","content":"[redacted by operator]"}),
            llm_request("m"),
            json!({"kind":"assistant_tool_calls","agent_id":"a",
                   "calls":[{"id":"c1","name":"exec","arguments":"{}"}]}),
            json!({"kind":"tool_result","call_id":"c1","tool_name":"exec",
                   "output":"[replaced by hook]","success":true,"agent_id":"a"}),
            json!({"kind":"tool_output_redacted","call_id":"c1","hook_id":"h","reason":"pii",
                   "original_sha256":"00","original_size":10,"redacted_sha256":"11",
                   "redacted_size":5,"agent_id":"a"}),
        ];
        events.push(json!({"kind":"chain_head","reason":"redaction",
            "sequence_range_start":1,"sequence_range_end":5,"prev_chain_hash":"00",
            "current_chain_hash":"11","signature":"aa","signing_pubkey":"bb",
            "schema_version":3,
            "redaction":{"seq":1,"original_leaf_hash":"00","redacted_leaf_hash":"11",
                         "operator":"uid:1000","reason":"request"}}));
        let doc = export("a", &rows(events), &HashMap::new(), &PRODUCER);
        assert_eq!(validate(&doc), Vec::<String>::new());
        let steps = doc["steps"].as_array().unwrap();
        assert_eq!(steps[0]["message"], "[redacted by operator]");
        assert_eq!(steps[0]["extra"]["redacted"], true);
        let result = &steps[1]["observation"]["results"][0];
        assert_eq!(result["content"], "[replaced by hook]");
        assert_eq!(result["extra"]["output_replaced_by_hook"], true);
        assert!(steps[1]["extra"].get("redacted").is_none());
    }

    fn proxy_request(id: &str, shape: &str, body: &[u8], archived: bool) -> Value {
        json!({"kind":"proxy_request","request_id":id,"token_id":"tok1","token_name":"laptop",
               "upstream":"local","provider":"ollama","model":"model-p","shape":shape,
               "stream":true,"request_sha256":sha(body),"request_bytes":body.len(),
               "archived":archived})
    }

    fn proxy_response(id: &str, body: &[u8], input: Option<u32>, output: Option<u32>) -> Value {
        json!({"kind":"proxy_response","request_id":id,"token_id":"tok1","status":200,
               "latency_ms":12,"input_tokens":input,"output_tokens":output,
               "response_sha256":sha(body),"response_bytes":body.len(),"complete":true,
               "archived":true})
    }

    fn bodies(list: &[&[u8]]) -> HashMap<String, Body> {
        list.iter()
            .map(|b| (sha(b), Body::Plain(b.to_vec())))
            .collect()
    }

    /// A proxied Anthropic conversation of two calls, the second
    /// repeating the first and adding a tool result: each message is a
    /// step once, the streamed answers are read event by event, and
    /// the tool result sits under the step whose call it answers.
    #[test]
    fn a_proxied_anthropic_stream_exports_each_message_once() {
        let first = br#"{"model":"model-p","stream":true,"system":"Be brief.",
            "messages":[{"role":"user","content":"list files"}]}"#;
        let first_answer = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":30}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Look\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ing.\"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu1\",\"name\":\"ls\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\".\\\"}\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":12}}\n\n",
        )
        .as_bytes();
        let second = br#"{"model":"model-p","stream":true,"system":"Be brief.",
            "messages":[{"role":"user","content":"list files"},
              {"role":"assistant","content":[{"type":"text","text":"Looking."},
                 {"type":"tool_use","id":"tu1","name":"ls","input":{"path":"."}}]},
              {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"a.txt"}]}]}"#;
        let second_answer =
            br#"{"content":[{"type":"text","text":"One file: a.txt"}],"usage":{"input_tokens":50,"output_tokens":6}}"#;

        let session = rows(vec![
            proxy_request("r1", "anthropic_messages", first, true),
            proxy_response("r1", first_answer, Some(30), Some(12)),
            proxy_request("r2", "anthropic_messages", second, true),
            proxy_response("r2", second_answer, Some(50), Some(6)),
        ]);
        let doc = export(
            "proxy-tok1",
            &session,
            &bodies(&[first, first_answer, second, second_answer]),
            &PRODUCER,
        );
        assert_eq!(validate(&doc), Vec::<String>::new());
        assert_eq!(doc["extra"]["wirken"]["kind"], "proxied");
        let steps = doc["steps"].as_array().unwrap();
        let shape: Vec<(&str, &str)> = steps
            .iter()
            .map(|s| {
                (
                    s["source"].as_str().unwrap(),
                    s["message"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                ("system", "Be brief."),
                ("user", "list files"),
                ("agent", "Looking."),
                ("agent", "One file: a.txt"),
            ]
        );
        let called = &steps[2];
        assert_eq!(called["tool_calls"][0]["tool_call_id"], "tu1");
        assert_eq!(called["tool_calls"][0]["function_name"], "ls");
        assert_eq!(called["tool_calls"][0]["arguments"]["path"], ".");
        assert_eq!(called["observation"]["results"][0]["source_call_id"], "tu1");
        assert_eq!(called["observation"]["results"][0]["content"], "a.txt");
        assert_eq!(called["metrics"]["prompt_tokens"], 30);
        assert_eq!(called["model_name"], "model-p");
        assert_eq!(called["extra"]["wirken"]["request_sha256"], sha(first));
        assert_eq!(called["extra"]["wirken"]["response_body"], "exported");
        assert_eq!(doc["final_metrics"]["total_prompt_tokens"], 80);
        assert_eq!(doc["final_metrics"]["total_completion_tokens"], 18);
    }

    /// Tool calls the client made at the MCP endpoint are in a proxied
    /// session's trajectory: one the model's answer carries, by its
    /// tool-use id, gets the recorded result on the model's step, beside
    /// the result the client sent back; one with no such id is a step.
    #[test]
    fn tool_calls_run_at_the_mcp_endpoint_are_in_a_proxied_trajectory() {
        let first = br#"{"model":"model-p","messages":[{"role":"user","content":"read it"}]}"#;
        let first_answer = br#"{"content":[{"type":"tool_use","id":"tu1","name":"files_read","input":{"path":"a.txt"}}],"usage":{"input_tokens":5,"output_tokens":2}}"#;
        let second = br#"{"model":"model-p","messages":[{"role":"user","content":"read it"},
              {"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"files_read","input":{"path":"a.txt"}}]},
              {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"hello"}]}]}"#;
        let second_answer =
            br#"{"content":[{"type":"text","text":"It says hello"}],"usage":{"input_tokens":9,"output_tokens":3}}"#;
        let tool_calls = |id: &str| {
            json!({"kind":"assistant_tool_calls","agent_id":"default",
                   "calls":[{"id":id,"name":"mcp_files_read","arguments":"{\"path\":\"a.txt\"}"}]})
        };
        let tool_result = |id: &str, output: &str| {
            json!({"kind":"tool_result","call_id":id,"tool_name":"mcp_files_read",
                   "output":output,"success":true,"agent_id":"default"})
        };
        let session = rows(vec![
            proxy_request("r1", "anthropic_messages", first, false),
            proxy_response("r1", first_answer, Some(5), Some(2)),
            tool_calls("tu1"),
            tool_result("tu1", "hello"),
            proxy_request("r2", "anthropic_messages", second, false),
            proxy_response("r2", second_answer, Some(9), Some(3)),
            tool_calls("mcp-0a1b"),
            tool_result("mcp-0a1b", "hello again"),
        ]);
        let doc = export(
            "proxy-tok1-work",
            &session,
            &bodies(&[first, first_answer, second, second_answer]),
            &PRODUCER,
        );
        assert_eq!(validate(&doc), Vec::<String>::new());
        let steps = doc["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4, "{steps:#?}");

        let asked = &steps[1];
        assert_eq!(asked["tool_calls"].as_array().unwrap().len(), 1);
        assert_eq!(asked["tool_calls"][0]["tool_call_id"], "tu1");
        let results = asked["observation"]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["content"], "hello");
        assert_eq!(results[0]["extra"]["recorded_by"], "wirken");
        assert_eq!(results[0]["extra"]["tool_name"], "mcp_files_read");
        assert_eq!(results[1]["content"], "hello");
        assert!(results[1]["extra"]["recorded_by"].is_null());

        let alone = &steps[3];
        assert_eq!(alone["source"], "agent");
        assert_eq!(alone["extra"]["wirken"]["mcp_endpoint"], true);
        assert_eq!(alone["tool_calls"][0]["tool_call_id"], "mcp-0a1b");
        assert_eq!(alone["tool_calls"][0]["function_name"], "mcp_files_read");
        assert_eq!(alone["observation"]["results"][0]["content"], "hello again");
    }

    /// An OpenAI-shaped call: the system and user messages, a tool
    /// round the client carried in its history, and the streamed
    /// answer with its tool call assembled from the pieces.
    #[test]
    fn a_proxied_openai_call_exports_its_history_and_streamed_answer() {
        let request = br#"{"model":"model-p","messages":[
            {"role":"system","content":"You are terse."},
            {"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"x"}}]},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c9","type":"function","function":{"name":"ls","arguments":"{\"p\":1}"}}]},
            {"role":"tool","tool_call_id":"c9","content":"a.txt"}]}"#;
        let answer = concat!(
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Fo\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"und.\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c10\",\"function\":{\"name\":\"cat\",\"arguments\":\"{\\\"f\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"a.txt\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":9,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();
        let mut response = proxy_response("r1", answer, Some(40), Some(9));
        response["cache_read_input_tokens"] = json!(10);
        let session = rows(vec![
            proxy_request("r1", "openai_chat", request, true),
            response,
        ]);
        let doc = export(
            "proxy-tok1",
            &session,
            &bodies(&[request, answer]),
            &PRODUCER,
        );
        assert_eq!(validate(&doc), Vec::<String>::new());
        let steps = doc["steps"].as_array().unwrap();
        assert_eq!(steps[0]["source"], "system");
        assert_eq!(steps[1]["message"], "look\n[image_url]");
        // The assistant turn the client sent back is copied context.
        assert_eq!(steps[2]["is_copied_context"], true);
        assert_eq!(steps[2]["tool_calls"][0]["arguments"]["p"], 1);
        assert_eq!(steps[2]["observation"]["results"][0]["content"], "a.txt");
        let last = &steps[3];
        assert_eq!(last["message"], "Found.");
        assert_eq!(last["tool_calls"][0]["tool_call_id"], "c10");
        assert_eq!(last["tool_calls"][0]["arguments"]["f"], "a.txt");
        // This provider's prompt count already holds the cached tokens.
        assert_eq!(last["metrics"]["prompt_tokens"], 40);
        assert_eq!(last["metrics"]["cached_tokens"], 10);
        assert!(last.get("is_copied_context").is_none());
    }

    /// A call whose bodies are not available, or were made unreadable,
    /// is one step with its metrics and hashes and no message.
    #[test]
    fn a_call_without_readable_bodies_is_a_step_with_no_message() {
        let (request, answer) = (b"the request".as_slice(), b"the answer".as_slice());
        let session = rows(vec![
            proxy_request("r1", "openai_chat", request, false),
            proxy_response("r1", answer, Some(7), Some(3)),
        ]);
        for (held, label) in [
            (HashMap::new(), "not_available"),
            (
                HashMap::from([
                    (sha(request), Body::Redacted),
                    (sha(answer), Body::Redacted),
                ]),
                "redacted",
            ),
        ] {
            let doc = export("proxy-tok1", &session, &held, &PRODUCER);
            assert_eq!(validate(&doc), Vec::<String>::new());
            let steps = doc["steps"].as_array().unwrap();
            assert_eq!(steps.len(), 1, "{label}");
            assert_eq!(steps[0]["message"], "");
            assert_eq!(steps[0]["metrics"]["prompt_tokens"], 7);
            assert_eq!(steps[0]["extra"]["wirken"]["request_body"], label);
            assert_eq!(steps[0]["extra"]["wirken"]["response_body"], label);
            assert_eq!(steps[0]["extra"]["wirken"]["response_sha256"], sha(answer));
            let text = doc.to_string();
            assert!(!text.contains("the request") && !text.contains("the answer"));
        }
    }

    /// Each rule of the format, broken one at a time in a valid
    /// document, is reported.
    #[test]
    fn the_validator_reports_each_broken_rule() {
        let valid = export("a", &agent_session(), &HashMap::new(), &PRODUCER);
        assert!(validate(&valid).is_empty());
        type Break = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Break)> = vec![
            (
                "schema_version",
                Box::new(|d| d["schema_version"] = json!("ATIF-v9")),
            ),
            (
                "'schema_version' is required",
                Box::new(|d| {
                    d.as_object_mut().unwrap().remove("schema_version");
                }),
            ),
            (
                "'agent' is required",
                Box::new(|d| {
                    d.as_object_mut().unwrap().remove("agent");
                }),
            ),
            (
                "'name' is required",
                Box::new(|d| {
                    d["agent"].as_object_mut().unwrap().remove("name");
                }),
            ),
            (
                "'steps' is required",
                Box::new(|d| d["steps"] = json!("none")),
            ),
            (
                "unknown field 'surprise'",
                Box::new(|d| d["surprise"] = json!(1)),
            ),
            (
                "unknown field 'role'",
                Box::new(|d| d["steps"][0]["role"] = json!("user")),
            ),
            (
                "expected 2 (sequential from 1), got 5",
                Box::new(|d| d["steps"][1]["step_id"] = json!(5)),
            ),
            (
                "'source' is not system, user or agent",
                Box::new(|d| d["steps"][0]["source"] = json!("tool")),
            ),
            (
                "'message' is required",
                Box::new(|d| {
                    d["steps"][0].as_object_mut().unwrap().remove("message");
                }),
            ),
            (
                "only applicable when source is 'agent'",
                Box::new(|d| d["steps"][0]["model_name"] = json!("m")),
            ),
            (
                "only applicable when source is 'agent'",
                Box::new(|d| d["steps"][0]["metrics"] = json!({})),
            ),
            (
                "must be absent when llm_call_count is 0",
                Box::new(|d| d["steps"][1]["llm_call_count"] = json!(0)),
            ),
            (
                "invalid ISO 8601 timestamp",
                Box::new(|d| d["steps"][0]["timestamp"] = json!("yesterday")),
            ),
            (
                "'arguments' is required and is an object",
                Box::new(|d| d["steps"][1]["tool_calls"][0]["arguments"] = json!("{}")),
            ),
            (
                "'tool_call_id' is required",
                Box::new(|d| {
                    d["steps"][1]["tool_calls"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("tool_call_id");
                }),
            ),
            (
                "source_call_id 'nope' is not found in step 2's tool_calls",
                Box::new(|d| {
                    d["steps"][1]["observation"]["results"][0]["source_call_id"] = json!("nope")
                }),
            ),
            (
                "'results' is required",
                Box::new(|d| d["steps"][1]["observation"] = json!({})),
            ),
            (
                "'prompt_tokens' is not an integer",
                Box::new(|d| d["steps"][1]["metrics"]["prompt_tokens"] = json!("many")),
            ),
            (
                "unknown field 'tokens'",
                Box::new(|d| d["steps"][1]["metrics"]["tokens"] = json!(1)),
            ),
            (
                "'text' is required when type='text'",
                Box::new(|d| d["steps"][0]["message"] = json!([{"type":"text"}])),
            ),
            (
                "the source is not image media",
                Box::new(|d| {
                    d["steps"][0]["message"] =
                        json!([{"type":"image","source":{"media_type":"audio/wav","path":"a"}}])
                }),
            ),
            (
                "trajectory_id is required for embedded subagents",
                Box::new(|d| {
                    let mut sub = d.clone();
                    sub.as_object_mut().unwrap().remove("subagent_trajectories");
                    d["subagent_trajectories"] = json!([sub]);
                }),
            ),
            (
                "must set trajectory_id or trajectory_path",
                Box::new(|d| {
                    d["steps"][1]["observation"]["results"][0]["subagent_trajectory_ref"] =
                        json!([{"session_id":"s"}])
                }),
            ),
            (
                "'total_steps' is below its minimum",
                Box::new(|d| d["final_metrics"]["total_steps"] = json!(-1)),
            ),
        ];
        for (says, breaks) in cases {
            let mut doc = valid.clone();
            breaks(&mut doc);
            let errors = validate(&doc);
            assert!(
                errors.iter().any(|e| e.contains(says)),
                "{says:?} not among {errors:?}"
            );
        }
    }

    /// Trajectories other producers wrote, named in the environment as
    /// paths separated by `:`, are valid here too. Passes without
    /// running when none is named.
    #[test]
    fn trajectories_named_in_the_environment_are_valid() {
        let Ok(paths) = std::env::var("WIRKEN_TEST_ATIF_FILES") else {
            return;
        };
        for path in paths.split(':').filter(|p| !p.is_empty()) {
            let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
            let doc: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(validate(&doc), Vec::<String>::new(), "{path}");
        }
    }

    /// A request that extends an earlier one carries the earlier
    /// request's last hash among its own; an unrelated one does not. A
    /// cache marker moved onto an earlier message changes nothing.
    #[test]
    fn a_conversation_chain_tells_a_continuation_from_another_conversation() {
        let first = json!({"messages":[{"role":"user","content":"hello"}]});
        let second = json!({"system":"changed","messages":[
            {"role":"user","content":"hello"},
            {"role":"assistant","content":"hi"},
            {"role":"user","content":"more"}]});
        let marked = json!({"messages":[
            {"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}]}]});
        let unmarked = json!({"messages":[
            {"role":"user","content":[{"type":"text","text":"hello"}]}]});
        let other = json!({"messages":[{"role":"user","content":"something else"}]});

        let (a, b) = (conversation_chain(&first), conversation_chain(&second));
        assert_eq!((a.len(), b.len()), (1, 3));
        assert_eq!(a[0], b[0]);
        assert!(b.contains(a.last().unwrap()));
        assert!(!conversation_chain(&other).contains(a.last().unwrap()));
        assert_eq!(conversation_chain(&marked), conversation_chain(&unmarked));
        assert!(conversation_chain(&json!({"model":"m"})).is_empty());
    }
}
