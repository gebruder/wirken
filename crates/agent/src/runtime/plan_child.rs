//! A turn run by a child process on the operator's own plan.
//!
//! On this route Wirken makes no model call and holds no credential.
//! The operator names a command-line agent they installed and signed in
//! to themselves; a turn starts it as a child process in headless mode,
//! hands it the system prompt and the message, and serves it this
//! agent's tools over the Model Context Protocol. The child runs the
//! model loop. Every tool it calls arrives here and goes through
//! [`Agent::execute_and_record_tool`], so the tier gate, the approval
//! gate, the sandbox envelope, leak detection and the session-log rows
//! are the ones a call gets on any other route.
//!
//! What Wirken does not see is the model call itself. The child reports
//! each one on its output stream, and a row is written from the report:
//! an `LlmResponse` with [`wirken_audit::ReportedCall`] set and no
//! `LlmRequest`.
//!
//! The child is held to Wirken's tools. It is started with its built-in
//! tools off, the operator's and the working directory's settings not
//! loaded, and one tool server, this one. Its first message lists the
//! tools it has; a turn whose list names any other tool is refused
//! before anything is asked of the model, and so is one that says an
//! API key is in use. A step whose reported model is not the pinned one
//! fails the turn.
//!
//! The child starts in an empty directory of its own, never in the
//! workspace, so nothing a workspace carries is read as its
//! configuration.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use wirken_audit::{ReportedCall, SessionEvent, TrustLevel};

use super::{
    Agent, InboundContext, InterceptorOutcome, PermissionDenialContext, ProcessResult,
    SPAWN_SUBAGENT_TOOL,
};
use crate::conversation::{Role, ToolCallRequest};
use crate::error::AgentError;
use crate::llm::StopReason;
use crate::tool::ToolDef;

/// The agent binary a turn is run by, and how it reaches this
/// process's tools.
#[derive(Debug, Clone)]
pub struct PlanChild {
    /// The operator's installed agent binary.
    pub binary: PathBuf,
    /// A command that joins its standard input and output to a Unix
    /// socket: the program, then its arguments. The socket's path is
    /// appended as the last argument. The child starts it as its one
    /// tool server.
    pub bridge: Vec<String>,
}

/// The base URL an [`crate::llm::LlmConfig`] on this route carries. It
/// is not an endpoint: nothing is sent to it.
pub const PLAN_CHILD_BASE_URL: &str = "https://plan-child.invalid";

/// The name the tool server is given to the child, which prefixes each
/// of its tools with it.
const SERVER: &str = "wirken";

/// [`ReportedCall::by`] on this route's rows.
pub const REPORTED_BY: &str = "child";

/// The key sources a child may report: none, or its own sign-in.
const KEYLESS_SOURCES: &[&str] = &["none", "oauth"];

/// How much of the child's standard error an error message quotes.
const STDERR_TAIL: usize = 2000;

/// How much of an earlier turn's message a later turn's prompt carries.
const EARLIER_MESSAGE_CHARS: usize = 4000;

/// The directory the child starts in, under its own. The name is what
/// the child shows the model as its working directory.
const CHILD_CWD: &str = "not-the-workspace";

/// What the system prompt handed to a child ends with. The child tells
/// the model the directory it was started in, which is an empty one of
/// its own; without this the model takes that for where the files are
/// and spends calls on it.
pub const WHERE_THE_FILES_ARE: &str = "## Where the files are\n\n\
The files you are asked about are in the workspace your tools act on. Give every tool a path \
relative to the workspace root, such as `src/main.rs`. `exec` runs its command at the workspace \
root. The directory this process was started in, and any working directory shown to you, is an \
empty scratch directory outside the workspace: your tools cannot read it and nothing you need \
is in it. Never use its path.";

fn tool_prefix() -> String {
    format!("mcp__{SERVER}__")
}

/// The child's arguments. The prompt is not among them: it goes on
/// standard input.
pub fn child_args(
    model: &str,
    system_prompt_file: &Path,
    tool_server_config: &Path,
    max_turns: usize,
) -> Vec<String> {
    let mut args: Vec<String> = [
        "--print",
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--no-session-persistence",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--permission-mode",
        "dontAsk",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // No built-in tool, and no settings file of the operator's or of
    // the directory it starts in: neither can add a tool or a hook.
    args.extend(["--tools".to_string(), String::new()]);
    args.extend(["--setting-sources".to_string(), String::new()]);
    args.extend(["--model".to_string(), model.to_string()]);
    args.extend(["--max-turns".to_string(), max_turns.to_string()]);
    args.extend([
        "--system-prompt-file".to_string(),
        system_prompt_file.display().to_string(),
    ]);
    args.extend([
        "--mcp-config".to_string(),
        tool_server_config.display().to_string(),
    ]);
    args.extend(["--allowedTools".to_string(), format!("{}*", tool_prefix())]);
    args
}

/// Whether an inherited environment variable is withheld from the
/// child: one that would put its calls on an API key or another
/// provider's account, and the vault passphrase.
pub fn withheld_from_child(name: &str) -> bool {
    name.starts_with("ANTHROPIC_")
        || name.starts_with("AWS_BEARER_TOKEN")
        || [
            "_USE_BEDROCK",
            "_USE_VERTEX",
            "_USE_FOUNDRY",
            "_USE_ANTHROPIC_AWS",
        ]
        .iter()
        .any(|s| name.ends_with(s))
        || name == "WIRKEN_VAULT_PASSPHRASE"
}

/// Whether `reported` is the pinned model: the pin itself, or the pin
/// with the release date the provider appends to it.
pub fn model_matches_pin(pin: &str, reported: &str) -> bool {
    if reported == pin {
        return true;
    }
    reported
        .strip_prefix(pin)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|date| date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()))
}

/// One model call, as the child reported it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Step {
    pub id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub stop_reason: Option<String>,
}

/// How the child said its run ended.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub is_error: bool,
    pub subtype: String,
    pub text: String,
    /// Every model its usage summary names.
    pub models: Vec<String>,
    /// The usage summary itself: what the child says each model was
    /// sent and wrote over the whole run.
    pub usage: Vec<ModelUsage>,
    /// What the child says the run cost, its own estimate at API
    /// rates, in USD micros.
    pub reported_cost_usd_micros: Option<u64>,
    /// How long the child says it spent waiting on the model over the
    /// run, in milliseconds.
    pub reported_api_millis: Option<u64>,
}

/// One model's line of the child's usage summary.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ModelUsage {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    /// The child's own cost figure for the model, in USD micros.
    pub reported_cost_usd_micros: Option<u64>,
}

/// What an agent's turns on this route came to, as estimates at the
/// pricing table's API rates. Nothing here was billed.
///
/// There are two estimates. One is the sum over the steps as they
/// were reported, which is what the rows carry. The other prices the
/// usage summary the child gives when a turn ends, which is the
/// child's final count: where a step's output count was a placeholder,
/// the summary has the real one. The second corrects the first.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct PlanChildCost {
    /// Turns begun, and those that ended with a usage summary.
    pub turns: u32,
    pub turns_summarized: u32,
    /// Steps reported, and those whose model has no price entry.
    pub steps: u32,
    pub steps_unpriced: u32,
    /// The steps' estimates, summed.
    pub steps_estimated_usd_micros: u64,
    /// The usage summaries priced at the same rates, summed. `None`
    /// when no turn gave one or one names a model with no price entry.
    pub summary_estimated_usd_micros: Option<u64>,
    /// The child's own cost figures, summed. `None` when it gave none.
    pub child_reported_usd_micros: Option<u64>,
    /// Model time as the steps' rows have it, summed: for each call,
    /// from when the child could next ask the model to the end of the
    /// reply.
    pub model_millis: u64,
    /// The child's own figure for the time it spent waiting on the
    /// model, summed over the turns that gave one.
    pub child_reported_api_millis: Option<u64>,
}

impl PlanChildCost {
    /// The estimate to go by: the priced summaries when every turn
    /// gave one, the steps' sum otherwise.
    pub fn corrected_usd_micros(&self) -> u64 {
        match self.summary_estimated_usd_micros {
            Some(summary) if self.turns_summarized == self.turns => summary,
            _ => self.steps_estimated_usd_micros,
        }
    }

    /// The corrected estimate less the steps' sum.
    pub fn correction_usd_micros(&self) -> i64 {
        self.corrected_usd_micros() as i64 - self.steps_estimated_usd_micros as i64
    }
}

fn usd_micros(usd: Option<f64>) -> Option<u64> {
    usd.filter(|c| c.is_finite() && *c >= 0.0)
        .map(|c| (c * 1e6).round() as u64)
}

/// What one line of the child's output stream came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Reported {
    /// The opening message: the tools, tool servers and model the
    /// child has and what it authenticates with, as it said them, and
    /// why the turn is refused on it, when it is.
    Opened(Opening),
    /// A model call began: the child has the start of its reply.
    Began(String),
    /// A model call finished.
    Step(Step),
    /// Text the model wrote, beside its tool calls or as its reply.
    Text(String),
    /// The run ended.
    Ended(Outcome),
}

/// A child's opening message, as it goes on the chain.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Opening {
    pub tools: Vec<String>,
    pub servers: Option<Vec<wirken_audit::ChildToolServer>>,
    pub key_source: Option<String>,
    pub model: Option<String>,
    pub refused: Option<String>,
}

/// A model name the child gives a message it wrote itself, an error
/// notice for one, which no model answered.
const SYNTHETIC_MODEL: &str = "<synthetic>";

/// The child's output stream, read a line at a time.
#[derive(Debug, Default)]
pub struct Stream {
    pin: String,
    opened: bool,
    /// Calls begun and not yet reported.
    open: HashMap<String, Step>,
    order: Vec<String>,
    done: HashSet<String>,
    /// The call the stream events are currently describing.
    streaming: Option<String>,
}

fn usage_into(step: &mut Step, usage: &Value) {
    let read = |k: &str| usage.get(k).and_then(Value::as_u64);
    if let Some(n) = read("input_tokens") {
        step.input_tokens = n;
    }
    // A reply's output count grows as it streams; the last is the
    // whole.
    if let Some(n) = read("output_tokens") {
        step.output_tokens = step.output_tokens.max(n);
    }
    if let Some(n) = read("cache_creation_input_tokens") {
        step.cache_creation_input_tokens = n;
    }
    if let Some(n) = read("cache_read_input_tokens") {
        step.cache_read_input_tokens = n;
    }
}

impl Stream {
    pub fn new(pin: &str) -> Self {
        Self {
            pin: pin.to_string(),
            ..Self::default()
        }
    }

    fn check_model(&self, reported: &str) -> Result<(), String> {
        if model_matches_pin(&self.pin, reported) {
            Ok(())
        } else {
            Err(format!(
                "the child process reported the model `{reported}` where the pin is `{}`",
                self.pin
            ))
        }
    }

    fn begin(&mut self, id: &str, model: &str) -> &mut Step {
        if !self.open.contains_key(id) {
            self.order.push(id.to_string());
        }
        let step = self.open.entry(id.to_string()).or_default();
        step.id = id.to_string();
        step.model = model.to_string();
        step
    }

    fn finish(&mut self, id: &str) -> Option<Step> {
        let step = self.open.remove(id)?;
        self.order.retain(|o| o != id);
        self.done.insert(id.to_string());
        Some(step)
    }

    /// Every call begun and not yet reported, oldest first.
    fn finish_all(&mut self) -> Vec<Step> {
        let ids = std::mem::take(&mut self.order);
        ids.iter().filter_map(|id| self.finish(id)).collect()
    }

    /// Read one line. An error is a reason to end the turn: a tool
    /// that is not Wirken's, an API key, a model that is not the pin,
    /// or a stream that does not open with its opening message.
    pub fn line(&mut self, line: &str) -> Result<Vec<Reported>, String> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return Ok(Vec::new());
        };
        let kind = msg.get("type").and_then(Value::as_str).unwrap_or("");
        if kind == "system" {
            if msg.get("subtype").and_then(Value::as_str) != Some("init") {
                return Ok(Vec::new());
            }
            return Ok(vec![self.opening(&msg)]);
        }
        if !self.opened && matches!(kind, "assistant" | "user" | "stream_event" | "result") {
            return Err(format!(
                "the child process sent a `{kind}` message before its opening message, so the \
                 tools it has are not known"
            ));
        }
        match kind {
            "stream_event" => self.stream_event(&msg),
            "assistant" => self.assistant(&msg),
            "result" => self.result(&msg),
            _ => Ok(Vec::new()),
        }
    }

    /// Read the opening message. It is always reported, so it goes on
    /// the chain; `refused` on it says why the turn does not go on.
    fn opening(&mut self, msg: &Value) -> Reported {
        let mut opening = Opening {
            tools: msg
                .get("tools")
                .and_then(Value::as_array)
                .map(|tools| {
                    tools
                        .iter()
                        .map(|t| t.as_str().unwrap_or("<not a name>").to_string())
                        .collect()
                })
                .unwrap_or_default(),
            servers: msg
                .get("mcp_servers")
                .and_then(Value::as_array)
                .map(|servers| {
                    servers
                        .iter()
                        .map(|server| {
                            let field = |k: &str| {
                                server
                                    .get(k)
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string()
                            };
                            wirken_audit::ChildToolServer {
                                name: field("name"),
                                status: field("status"),
                            }
                        })
                        .collect()
                }),
            key_source: msg
                .get("apiKeySource")
                .and_then(Value::as_str)
                .map(String::from),
            model: msg.get("model").and_then(Value::as_str).map(String::from),
            refused: None,
        };
        opening.refused = self.refusal(msg, &opening);
        self.opened = opening.refused.is_none();
        Reported::Opened(opening)
    }

    /// Why a turn does not go on from this opening message.
    fn refusal(&self, msg: &Value, opening: &Opening) -> Option<String> {
        if msg.get("tools").and_then(Value::as_array).is_none() {
            return Some(
                "the child process's opening message lists no tools, so the tools it has are \
                 not known"
                    .to_string(),
            );
        }
        let prefix = tool_prefix();
        let foreign: Vec<&str> = opening
            .tools
            .iter()
            .map(String::as_str)
            .filter(|t| !t.starts_with(&prefix))
            .collect();
        if !foreign.is_empty() {
            return Some(format!(
                "the child process has tools that are not Wirken's ({}); the run is refused",
                foreign.join(", ")
            ));
        }
        for server in opening.servers.iter().flatten() {
            if server.name != SERVER {
                return Some(format!(
                    "the child process has a tool server that is not Wirken's ({}); the run is \
                     refused",
                    server.name
                ));
            }
            if server.status != "connected" {
                return Some(format!(
                    "the child process did not reach Wirken's tool server (status {})",
                    server.status
                ));
            }
        }
        if let Some(source) = &opening.key_source
            && !KEYLESS_SOURCES.contains(&source.as_str())
        {
            return Some(format!(
                "the child process says it authenticates with an API key (source `{source}`), \
                 not its own sign-in; the run is refused"
            ));
        }
        opening
            .model
            .as_deref()
            .and_then(|model| self.check_model(model).err())
    }

    fn stream_event(&mut self, msg: &Value) -> Result<Vec<Reported>, String> {
        // A sub-agent's events carry its parent call. The child has no
        // tool that starts one; were there one, its calls are still
        // reported from its messages.
        let Some(event) = msg.get("event") else {
            return Ok(Vec::new());
        };
        match event.get("type").and_then(Value::as_str).unwrap_or("") {
            "message_start" => {
                let Some(message) = event.get("message") else {
                    return Ok(Vec::new());
                };
                let id = message.get("id").and_then(Value::as_str).unwrap_or("");
                let model = message.get("model").and_then(Value::as_str).unwrap_or("");
                if id.is_empty() || model == SYNTHETIC_MODEL {
                    return Ok(Vec::new());
                }
                let step = self.begin(id, model);
                if let Some(usage) = message.get("usage") {
                    usage_into(step, usage);
                }
                self.streaming = Some(id.to_string());
                if let Err(e) = self.check_model(model) {
                    return Ok(self.mismatch(id, e));
                }
                Ok(vec![Reported::Began(id.to_string())])
            }
            "message_delta" => {
                if let Some(id) = self.streaming.clone()
                    && let Some(step) = self.open.get_mut(&id)
                {
                    if let Some(usage) = event.get("usage") {
                        usage_into(step, usage);
                    }
                    if let Some(stop) = event
                        .get("delta")
                        .and_then(|d| d.get("stop_reason"))
                        .and_then(Value::as_str)
                    {
                        step.stop_reason = Some(stop.to_string());
                    }
                }
                Ok(Vec::new())
            }
            "message_stop" => Ok(self
                .streaming
                .take()
                .and_then(|id| self.finish(&id))
                .map(Reported::Step)
                .into_iter()
                .collect()),
            _ => Ok(Vec::new()),
        }
    }

    /// A step whose model is not the pin: reported, so its row is
    /// written, with the reason the turn then fails.
    fn mismatch(&mut self, id: &str, reason: String) -> Vec<Reported> {
        let mut out: Vec<Reported> = self.finish(id).map(Reported::Step).into_iter().collect();
        out.push(Reported::Ended(Outcome {
            is_error: true,
            subtype: "model_mismatch".to_string(),
            text: reason,
            ..Outcome::default()
        }));
        out
    }

    fn assistant(&mut self, msg: &Value) -> Result<Vec<Reported>, String> {
        let Some(message) = msg.get("message") else {
            return Ok(Vec::new());
        };
        let id = message.get("id").and_then(Value::as_str).unwrap_or("");
        let model = message.get("model").and_then(Value::as_str).unwrap_or("");
        let mut out = Vec::new();
        if let Some(blocks) = message.get("content").and_then(Value::as_array) {
            for block in blocks {
                if block.get("type").and_then(Value::as_str) == Some("text")
                    && let Some(text) = block.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    out.push(Reported::Text(text.to_string()));
                }
            }
        }
        if id.is_empty() || model == SYNTHETIC_MODEL || self.done.contains(id) {
            return Ok(out);
        }
        // A new message closes the ones before it that no stream event
        // closed.
        let new = !self.open.contains_key(id);
        if new {
            out.extend(self.finish_all().into_iter().map(Reported::Step));
        }
        let step = self.begin(id, model);
        if let Some(usage) = message.get("usage") {
            usage_into(step, usage);
        }
        if let Some(stop) = message.get("stop_reason").and_then(Value::as_str) {
            step.stop_reason = Some(stop.to_string());
        }
        match self.check_model(model) {
            Err(e) => out.extend(self.mismatch(id, e)),
            Ok(()) if new => out.push(Reported::Began(id.to_string())),
            Ok(()) => {}
        }
        Ok(out)
    }

    fn result(&mut self, msg: &Value) -> Result<Vec<Reported>, String> {
        let mut out: Vec<Reported> = self.finish_all().into_iter().map(Reported::Step).collect();
        let usage: Vec<ModelUsage> = msg
            .get("modelUsage")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(model, u)| {
                        let n = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
                        ModelUsage {
                            model: model.clone(),
                            input_tokens: n("inputTokens"),
                            output_tokens: n("outputTokens"),
                            cache_creation_input_tokens: n("cacheCreationInputTokens"),
                            cache_read_input_tokens: n("cacheReadInputTokens"),
                            reported_cost_usd_micros: usd_micros(
                                u.get("costUSD").and_then(Value::as_f64),
                            ),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let models: Vec<String> = usage.iter().map(|u| u.model.clone()).collect();
        let subtype = msg
            .get("subtype")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut outcome = Outcome {
            is_error: msg
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || (!subtype.is_empty() && subtype != "success"),
            subtype,
            text: msg
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            models,
            usage,
            reported_cost_usd_micros: usd_micros(msg.get("total_cost_usd").and_then(Value::as_f64)),
            reported_api_millis: msg.get("duration_api_ms").and_then(Value::as_u64),
        };
        if let Some(other) = outcome
            .models
            .iter()
            .find(|m| !model_matches_pin(&self.pin, m))
        {
            outcome.text = format!(
                "the child process's usage summary names the model `{other}` where the pin is \
                 `{}`",
                self.pin
            );
            outcome.is_error = true;
            outcome.subtype = "model_mismatch".to_string();
        }
        out.push(Reported::Ended(outcome));
        Ok(out)
    }
}

/// A tool call the child made, with where its answer goes.
struct ToolRequest {
    id: Option<String>,
    name: String,
    arguments: Value,
    reply: oneshot::Sender<(String, bool)>,
}

fn rpc_result(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

fn tool_list(defs: &[ToolDef]) -> Value {
    let tools: Vec<Value> = defs
        .iter()
        .map(|d| {
            let schema = if d.parameters.is_object() {
                d.parameters.clone()
            } else {
                json!({"type": "object"})
            };
            json!({"name": d.name, "description": d.description, "inputSchema": schema})
        })
        .collect();
    json!({ "tools": tools })
}

/// Answer one tool server connection: the protocol's opening exchange
/// and tool list here, each tool call handed to the turn.
async fn serve_connection(
    stream: tokio::net::UnixStream,
    tools: Arc<Value>,
    calls: mpsc::Sender<ToolRequest>,
) {
    let (read, write) = stream.into_split();
    let write = Arc::new(tokio::sync::Mutex::new(write));
    let send = |write: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>, line: String| async move {
        let mut w = write.lock().await;
        let _ = w.write_all(line.as_bytes()).await;
        let _ = w.write_all(b"\n").await;
        let _ = w.flush().await;
    };
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // A message with no id is a notification and gets no answer.
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "initialize" => {
                let version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-06-18");
                let result = json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER, "version": env!("CARGO_PKG_VERSION")},
                });
                send(write.clone(), rpc_result(&id, result)).await;
            }
            "ping" => send(write.clone(), rpc_result(&id, json!({}))).await,
            "tools/list" => send(write.clone(), rpc_result(&id, (*tools).clone())).await,
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let call_id = params
                    .get("_meta")
                    .and_then(Value::as_object)
                    .and_then(|m| {
                        m.iter()
                            .find(|(k, _)| k.to_ascii_lowercase().ends_with("tooluseid"))
                            .and_then(|(_, v)| v.as_str())
                    })
                    .map(String::from);
                let (reply, answer) = oneshot::channel();
                let request = ToolRequest {
                    id: call_id,
                    name,
                    arguments,
                    reply,
                };
                let calls = calls.clone();
                let write = write.clone();
                // Each call is answered when the turn has run it, so a
                // second call sent meanwhile is read and queued.
                tokio::spawn(async move {
                    let line = if calls.send(request).await.is_err() {
                        rpc_error(&id, -32000, "the turn has ended")
                    } else {
                        match answer.await {
                            Ok((text, is_error)) => rpc_result(
                                &id,
                                json!({
                                    "content": [{"type": "text", "text": text}],
                                    "isError": is_error,
                                }),
                            ),
                            Err(_) => rpc_error(&id, -32000, "the turn has ended"),
                        }
                    };
                    send(write, line).await;
                });
            }
            _ => send(write.clone(), rpc_error(&id, -32601, "method not found")).await,
        }
    }
}

/// The child's own directory: where it starts, and where the files and
/// the socket it is given live. Owner-only, removed when the turn
/// ends.
struct ChildDir(PathBuf);

impl ChildDir {
    fn create() -> Result<Self, AgentError> {
        let path = std::env::temp_dir().join(format!("wirken-child-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|e| AgentError::Tool(format!("create the child's directory: {e}")))?;
        Ok(Self(path))
    }
}

impl Drop for ChildDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cut(text: &str, chars: usize) -> String {
    if text.chars().count() <= chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(chars).collect();
    out.push_str(" [cut]");
    out
}

fn tail(text: &str, chars: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(chars)).collect()
}

impl Agent {
    /// Run this agent's turns through `child`.
    pub fn set_plan_child(&mut self, child: PlanChild) {
        self.plan_child = Some(child);
    }

    /// The message a child is given: the turn's own, after what the
    /// conversation already holds. A child keeps nothing between
    /// turns, so a later turn carries the earlier ones.
    fn child_prompt(&self, message: &str) -> String {
        let earlier: Vec<String> = self
            .conversation
            .messages()
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| {
                let who = match m.role {
                    Role::User => "user".to_string(),
                    Role::Assistant => match &m.tool_calls {
                        Some(calls) => format!(
                            "assistant, calling {}",
                            calls
                                .iter()
                                .map(|c| c.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        None => "assistant".to_string(),
                    },
                    Role::Tool => format!("result of {}", m.tool_name.as_deref().unwrap_or("tool")),
                    Role::System => "system".to_string(),
                    Role::Compaction => "summary of earlier turns".to_string(),
                };
                format!("[{who}]\n{}", cut(&m.content, EARLIER_MESSAGE_CHARS))
            })
            .collect();
        if earlier.is_empty() {
            return message.to_string();
        }
        format!(
            "Earlier in this conversation, oldest first:\n\n{}\n\nThe message to act on \
             now:\n\n{message}",
            earlier.join("\n\n")
        )
    }

    /// The run's cost on this route so far, as estimates.
    pub fn plan_child_cost(&self) -> &PlanChildCost {
        &self.plan_child_cost
    }

    /// What `tokens` cost at the table's rates for this agent's pinned
    /// model. A reported model is the pin, or the turn has failed, so
    /// the pin is what the table is asked for.
    fn child_estimate(&self, input: u64, output: u64, written: u64, read: u64) -> Option<u64> {
        let n = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        super::estimate_at_api_rates(
            &self.llm.config().provider,
            &self.llm.config().model,
            n(input),
            n(output),
            n(written),
            n(read),
        )
    }

    fn reported_row(
        &self,
        step: &Step,
        key_source: &Option<String>,
        latency_ms: u64,
    ) -> SessionEvent {
        let stop = step.stop_reason.as_deref();
        let tokens = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        SessionEvent::LlmResponse {
            request_id: step.id.clone(),
            finish_reason: if stop == Some("tool_use") {
                "tool_calls"
            } else {
                "text"
            }
            .to_string(),
            stop_reason: stop.map(|raw| StopReason::from_provider(raw).as_str().to_string()),
            stop_reason_raw: step.stop_reason.clone(),
            input_tokens: tokens(step.input_tokens),
            output_tokens: tokens(step.output_tokens),
            cache_creation_input_tokens: tokens(step.cache_creation_input_tokens),
            cache_read_input_tokens: tokens(step.cache_read_input_tokens),
            latency_ms,
            agent_id: self.audited_agent_id(),
            credential_id: None,
            input_cost_usd_micros: None,
            output_cost_usd_micros: None,
            total_cost_usd_micros: None,
            sender_id: self.current_inbound.sender_id.clone(),
            step: self.call_step.clone(),
            reported: Some(ReportedCall {
                by: REPORTED_BY.to_string(),
                model: step.model.clone(),
                key_source: key_source.clone(),
            }),
            estimated_cost_usd_micros: self.child_estimate(
                step.input_tokens,
                step.output_tokens,
                step.cache_creation_input_tokens,
                step.cache_read_input_tokens,
            ),
        }
    }

    /// One turn, run by the child. The counterpart of
    /// [`Agent::process_message_turn`] on this route.
    pub(super) async fn process_message_turn_by_child(
        &mut self,
        child: PlanChild,
        user_message: &str,
        inbound_id: String,
        inbound: InboundContext,
    ) -> Result<ProcessResult, AgentError> {
        if let Some(replay) = self.dedup_inbound(&inbound_id)? {
            return Ok(replay);
        }
        self.begin_turn(&inbound);
        if let Some(notice) = self.refuse_leaked_message(user_message) {
            return Ok(ProcessResult {
                response: notice,
                denials: Vec::new(),
            });
        }
        self.tool_validation_failures.clear();
        self.maybe_log_system_prompt()?;

        // The pre-model interceptors, as on any turn: a slash command
        // that names a skill is expanded here, and one an interceptor
        // answers itself needs no child.
        let user_message = match self.apply_interceptors(user_message)? {
            InterceptorOutcome::Continue(s) => s,
            InterceptorOutcome::Handled {
                reply,
                audit_events,
            } => {
                self.current_trigger = Some(reply.clone());
                self.log_event(
                    TrustLevel::User,
                    SessionEvent::UserMessage {
                        content: user_message.to_string(),
                        inbound_id: Some(inbound_id),
                        adapter_id: inbound.adapter_id.clone(),
                        sender_id: inbound.sender_id.clone(),
                    },
                )?;
                for event in audit_events {
                    self.log_event(TrustLevel::System, event)?;
                }
                self.log_event(
                    TrustLevel::System,
                    SessionEvent::AssistantMessage {
                        content: reply.clone(),
                        agent_id: self.audited_agent_id(),
                    },
                )?;
                return Ok(ProcessResult {
                    response: reply,
                    denials: Vec::new(),
                });
            }
        };
        let prompt = self.child_prompt(&user_message);
        self.current_trigger = Some(user_message.clone());
        self.conversation.add_user_message(&user_message);
        self.log_event(
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: user_message,
                inbound_id: Some(inbound_id),
                adapter_id: inbound.adapter_id.clone(),
                sender_id: inbound.sender_id.clone(),
            },
        )?;

        // The tools this agent has, less the one that starts another
        // agent: a child's turn does not fan out.
        let mcp_defs = self.turn_mcp_defs().await;
        let tool_defs: Vec<ToolDef> = self
            .build_turn_tool_defs(mcp_defs)
            .iter()
            .filter(|d| d.name != SPAWN_SUBAGENT_TOOL)
            .cloned()
            .collect();

        self.last_turn_denials.clear();
        self.last_turn_rounds = 0;
        self.last_turn_exhausted = false;
        if let Some(block_msg) = self.check_budget(None)? {
            return Ok(ProcessResult {
                response: block_msg,
                denials: Vec::new(),
            });
        }
        self.check_inference_or_deny()?;

        let pin = self.llm.config().model.clone();
        let system_prompt = self
            .conversation
            .messages()
            .first()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .unwrap_or_default();

        // The child's directory, with what it is handed.
        let dir = ChildDir::create()?;
        let io = |what: &str, e: std::io::Error| AgentError::Tool(format!("{what}: {e}"));
        let system_prompt_file = dir.0.join("system-prompt.txt");
        std::fs::write(
            &system_prompt_file,
            format!("{system_prompt}\n\n{WHERE_THE_FILES_ARE}\n"),
        )
        .map_err(|e| io("write the child's system prompt", e))?;
        let socket = dir.0.join("tools.sock");
        let listener = tokio::net::UnixListener::bind(&socket)
            .map_err(|e| io("open the tool server's socket", e))?;
        let Some((bridge, bridge_args)) = child.bridge.split_first() else {
            return Err(AgentError::Tool(
                "the child route has no bridge command".to_string(),
            ));
        };
        let mut server_args: Vec<String> = bridge_args.to_vec();
        server_args.push(socket.display().to_string());
        let config_file = dir.0.join("tool-server.json");
        std::fs::write(
            &config_file,
            json!({"mcpServers": {SERVER: {
                "type": "stdio", "command": bridge, "args": server_args,
            }}})
            .to_string(),
        )
        .map_err(|e| io("write the tool server's configuration", e))?;
        let cwd = dir.0.join(CHILD_CWD);
        std::fs::create_dir(&cwd).map_err(|e| io("create the child's working directory", e))?;

        let (calls_tx, mut calls) = mpsc::channel::<ToolRequest>(16);
        let tools = Arc::new(tool_list(&tool_defs));
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_connection(stream, tools.clone(), calls_tx.clone()));
            }
        });
        // Ends the server with the turn, however the turn ends.
        struct AbortOnDrop(tokio::task::JoinHandle<()>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _server = AbortOnDrop(server);

        let mut command = tokio::process::Command::new(&child.binary);
        command
            .args(child_args(
                &pin,
                &system_prompt_file,
                &config_file,
                self.max_tool_rounds,
            ))
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(withheld_from_child) {
                command.env_remove(&name);
            }
        }
        let mut process = command.spawn().map_err(|e| {
            AgentError::Tool(format!(
                "start the child process {}: {e}",
                child.binary.display()
            ))
        })?;
        if let Some(mut stdin) = process.stdin.take() {
            let prompt = prompt.clone();
            tokio::spawn(async move {
                let _ = stdin.write_all(prompt.as_bytes()).await;
                let _ = stdin.shutdown().await;
            });
        }
        let stderr_text = Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(stderr) = process.stderr.take() {
            let sink = stderr_text.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let mut held = sink.lock().unwrap_or_else(|e| e.into_inner());
                    held.push_str(&line);
                    held.push('\n');
                    let kept = tail(&held, STDERR_TAIL);
                    *held = kept;
                }
            });
        }
        let stdout = process
            .stdout
            .take()
            .ok_or_else(|| AgentError::Tool("the child process has no output".to_string()))?;
        let mut lines = BufReader::new(stdout).lines();

        self.plan_child_cost.turns += 1;
        let mut stream = Stream::new(&pin);
        let mut key_source: Option<String> = None;
        let mut denials: Vec<PermissionDenialContext> = Vec::new();
        let mut outcome: Option<Outcome> = None;
        let mut pending_text: Option<String> = None;
        let mut last_stop: Option<String> = None;
        let mut steps = 0usize;
        // A call's time runs from when the child could next ask the
        // model, which is its start, the end of the reply before or the
        // answer to a tool call, whichever came last, to the end of the
        // call's own reply. The child starts a tool call as soon as the
        // reply has named it, before the reply ends, so the start is
        // fixed when the reply begins: an answer given inside a reply
        // moves the next call's start, never this one's.
        let mut could_ask = Instant::now();
        let mut began: HashMap<String, Instant> = HashMap::new();

        while outcome.is_none() {
            tokio::select! {
                // What the child has said is read before a tool call it
                // made is served: a step by another model is seen, and
                // ends the turn, before that step's call runs.
                biased;
                line = lines.next_line() => {
                    let Ok(Some(line)) = line else { break };
                    let reported = stream.line(&line).map_err(AgentError::Tool)?;
                    for item in reported {
                        match item {
                            Reported::Opened(opening) => {
                                // On the chain before anything else the
                                // child does, and when it is refused.
                                self.log_event(
                                    TrustLevel::System,
                                    SessionEvent::ChildOpened {
                                        agent_id: self.audited_agent_id(),
                                        step: self.call_step.clone(),
                                        tools: opening.tools,
                                        servers: opening.servers,
                                        key_source: opening.key_source.clone(),
                                        model: opening.model,
                                        refused: opening.refused.clone(),
                                    },
                                )?;
                                if let Some(reason) = opening.refused {
                                    return Err(AgentError::Tool(reason));
                                }
                                key_source = opening.key_source;
                            }
                            Reported::Text(text) => {
                                pending_text = Some(self.withhold_leaked_reply(text).0);
                            }
                            Reported::Began(id) => {
                                began.entry(id).or_insert(could_ask);
                            }
                            Reported::Step(step) => {
                                steps += 1;
                                self.last_turn_rounds = steps;
                                let ended = Instant::now();
                                let started = began.remove(&step.id).unwrap_or(could_ask);
                                let latency_ms = ended.duration_since(started).as_millis() as u64;
                                could_ask = ended;
                                self.plan_child_cost.model_millis += latency_ms;
                                last_stop = step.stop_reason.clone();
                                self.plan_child_cost.steps += 1;
                                match self.child_estimate(
                                    step.input_tokens,
                                    step.output_tokens,
                                    step.cache_creation_input_tokens,
                                    step.cache_read_input_tokens,
                                ) {
                                    Some(e) => self.plan_child_cost.steps_estimated_usd_micros += e,
                                    None => self.plan_child_cost.steps_unpriced += 1,
                                }
                                self.log_event(
                                    TrustLevel::System,
                                    self.reported_row(&step, &key_source, latency_ms),
                                )?;
                            }
                            Reported::Ended(ended) => outcome = Some(ended),
                        }
                    }
                }
                Some(request) = calls.recv() => {
                    let call = ToolCallRequest {
                        id: request
                            .id
                            .unwrap_or_else(|| format!("call-{}", uuid::Uuid::new_v4())),
                        name: request.name,
                        arguments: request.arguments.to_string(),
                    };
                    let (checked, refused) = self.refuse_leaked_arguments(vec![call]).await;
                    let Some(call) = checked.into_iter().next() else { continue };
                    let text = pending_text.take();
                    self.current_assistant_text = text.clone();
                    self.conversation.add_assistant_tool_calls(vec![call.clone()]);
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantToolCalls {
                            calls: Self::calls_to_records(std::slice::from_ref(&call)),
                            text,
                            reasoning: None,
                            agent_id: self.audited_agent_id(),
                            adapter_id: self.current_inbound.adapter_id.clone(),
                            sender_id: self.current_inbound.sender_id.clone(),
                            step: self.call_step.clone(),
                        },
                    )?;
                    let result = match refused.get(&call.id) {
                        Some(credential) => super::refused_tool_result(credential),
                        None => self.execute_and_record_tool(&call, &mut denials).await?,
                    };
                    self.conversation
                        .add_tool_result(&call.id, &call.name, &result.output);
                    self.record_tool_result(&call.id, &call.name, &result)?;
                    let _ = request.reply.send((result.output, !result.success));
                    could_ask = Instant::now();
                }
            }
        }

        let stderr_tail = || {
            let held = stderr_text.lock().unwrap_or_else(|e| e.into_inner());
            match held.trim() {
                "" => String::new(),
                text => format!(": {text}"),
            }
        };
        let Some(outcome) = outcome else {
            let status = process.wait().await.ok();
            return Err(AgentError::Tool(format!(
                "the child process ended without a result ({}){}",
                status.map_or("status unknown".to_string(), |s| s.to_string()),
                stderr_tail()
            )));
        };
        // The child's own count of the turn, priced at the same rates,
        // and its own cost figure.
        if !outcome.usage.is_empty() {
            let priced: Option<u64> = outcome
                .usage
                .iter()
                .map(|u| {
                    self.child_estimate(
                        u.input_tokens,
                        u.output_tokens,
                        u.cache_creation_input_tokens,
                        u.cache_read_input_tokens,
                    )
                })
                .sum();
            let cost = &mut self.plan_child_cost;
            cost.summary_estimated_usd_micros = match (cost.turns_summarized, priced) {
                (0, p) => p,
                (_, Some(p)) => cost.summary_estimated_usd_micros.map(|s| s + p),
                (_, None) => None,
            };
            cost.turns_summarized += 1;
        }
        if let Some(millis) = outcome.reported_api_millis {
            let cost = &mut self.plan_child_cost;
            cost.child_reported_api_millis =
                Some(cost.child_reported_api_millis.unwrap_or(0) + millis);
        }
        if let Some(reported) = outcome.reported_cost_usd_micros {
            let cost = &mut self.plan_child_cost;
            cost.child_reported_usd_micros =
                Some(cost.child_reported_usd_micros.unwrap_or(0) + reported);
        }
        // The result is the child's last word. One that was stopped on
        // a step it should not have made is still running; end it.
        let _ = process.start_kill();
        let _ = process.wait().await;
        self.llm.set_stop_reason(last_stop.as_deref());

        if outcome.subtype == "error_max_turns" {
            self.last_turn_exhausted = true;
            return Err(AgentError::Tool(format!(
                "exceeded {} tool call rounds; possible loop",
                self.max_tool_rounds
            )));
        }
        if outcome.is_error {
            let text = match outcome.text.trim() {
                "" => format!("the child process ended with `{}`", outcome.subtype),
                text => text.to_string(),
            };
            let (text, _) = self.withhold_leaked_reply(text);
            return Err(AgentError::Tool(format!(
                "the child process's run failed: {text}"
            )));
        }

        let (text, _) = self.withhold_leaked_reply(outcome.text);
        self.conversation.add_assistant_message(&text);
        self.log_event(
            TrustLevel::System,
            SessionEvent::AssistantMessage {
                content: text.clone(),
                agent_id: self.audited_agent_id(),
            },
        )?;
        let _ = self.maybe_attest().await?;
        Ok(ProcessResult {
            response: text,
            denials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "pinned-model-4-5";

    fn opening(tools: &[&str]) -> String {
        json!({
            "type": "system", "subtype": "init", "tools": tools,
            "mcp_servers": [{"name": "wirken", "status": "connected"}],
            "model": PIN, "apiKeySource": "none",
        })
        .to_string()
    }

    /// The flags the child is started with: headless, the stream
    /// format, the pinned model, one tool server and no other, no
    /// built-in tool, no settings source, no stored session, and
    /// neither a fallback model nor the mode that skips the sign-in.
    #[test]
    fn the_child_is_started_with_wirkens_tools_and_nothing_else() {
        let args = child_args(
            PIN,
            Path::new("/d/system-prompt.txt"),
            Path::new("/d/tool-server.json"),
            40,
        );
        let after = |flag: &str| {
            let at = args.iter().position(|a| a == flag).expect(flag);
            args[at + 1].as_str()
        };
        assert!(args.contains(&"--print".to_string()));
        assert_eq!(after("--output-format"), "stream-json");
        assert_eq!(after("--model"), PIN);
        assert_eq!(after("--max-turns"), "40");
        assert_eq!(after("--system-prompt-file"), "/d/system-prompt.txt");
        assert_eq!(after("--mcp-config"), "/d/tool-server.json");
        assert_eq!(after("--tools"), "");
        assert_eq!(after("--setting-sources"), "");
        assert_eq!(after("--permission-mode"), "dontAsk");
        assert_eq!(after("--allowedTools"), "mcp__wirken__*");
        for flag in [
            "--no-session-persistence",
            "--strict-mcp-config",
            "--disable-slash-commands",
        ] {
            assert!(args.contains(&flag.to_string()), "{flag}");
        }
        for absent in [
            "--fallback-model",
            "--bare",
            "--dangerously-skip-permissions",
        ] {
            assert!(!args.contains(&absent.to_string()), "{absent}");
        }
    }

    #[test]
    fn variables_that_would_bill_a_key_are_withheld_from_the_child() {
        for name in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "X_USE_BEDROCK",
            "X_USE_VERTEX",
            "WIRKEN_VAULT_PASSPHRASE",
        ] {
            assert!(withheld_from_child(name), "{name}");
        }
        for name in ["PATH", "HOME", "XDG_CONFIG_HOME", "WIRKEN_DATA_DIR"] {
            assert!(!withheld_from_child(name), "{name}");
        }
    }

    #[test]
    fn a_reported_model_is_the_pin_or_the_pin_with_its_release_date() {
        assert!(model_matches_pin(PIN, PIN));
        assert!(model_matches_pin(PIN, "pinned-model-4-5-20251001"));
        for other in [
            "pinned-model-4-6",
            "pinned-model-4-5-preview",
            "pinned-model-4-5-2025100",
            "pinned-model-4",
            "",
        ] {
            assert!(!model_matches_pin(PIN, other), "{other}");
        }
    }

    /// The opening message is read before anything else is, and a tool
    /// that is not Wirken's, another tool server, or an API key ends
    /// the turn there.
    #[test]
    fn an_opening_message_with_anything_but_wirkens_tools_is_refused() {
        let opened = |line: &str| match Stream::new(PIN).line(line).unwrap().remove(0) {
            Reported::Opened(opening) => opening,
            other => panic!("{other:?}"),
        };
        let ok = opened(&opening(&["mcp__wirken__read_file", "mcp__wirken__exec"]));
        assert_eq!(ok.refused, None);
        assert_eq!(ok.tools, ["mcp__wirken__read_file", "mcp__wirken__exec"]);
        assert_eq!(
            ok.servers,
            Some(vec![wirken_audit::ChildToolServer {
                name: "wirken".to_string(),
                status: "connected".to_string(),
            }])
        );
        assert_eq!(ok.key_source.as_deref(), Some("none"));
        assert_eq!(ok.model.as_deref(), Some(PIN));

        // A refused opening still says what the child had.
        let foreign = opened(&opening(&[
            "mcp__wirken__read_file",
            "Bash",
            "mcp__other__x",
        ]));
        assert_eq!(foreign.tools.len(), 3);
        let err = foreign.refused.unwrap();
        assert!(err.contains("not Wirken's (Bash, mcp__other__x)"), "{err}");

        let mut keyed: Value = serde_json::from_str(&opening(&[])).unwrap();
        keyed["apiKeySource"] = "user".into();
        let err = opened(&keyed.to_string()).refused.unwrap();
        assert!(err.contains("API key (source `user`)"), "{err}");

        let mut other_model: Value = serde_json::from_str(&opening(&[])).unwrap();
        other_model["model"] = "another-model".into();
        assert!(opened(&other_model.to_string()).refused.is_some());

        // After a refused opening nothing else is read as a turn.
        let mut s = Stream::new(PIN);
        s.line(&opening(&["Bash"])).unwrap();
        assert!(s.line(r#"{"type":"result","subtype":"success"}"#).is_err());

        let err = Stream::new(PIN)
            .line(r#"{"type":"assistant","message":{"id":"m1","model":"x","content":[]}}"#)
            .unwrap_err();
        assert!(err.contains("before its opening message"), "{err}");
    }

    /// A step is reported once, from its stream events when the child
    /// sends them and from its message otherwise, with the tokens and
    /// stop word the child gave.
    #[test]
    fn each_step_is_reported_once_with_its_model_tokens_and_stop_word() {
        let mut s = Stream::new(PIN);
        s.line(&opening(&["mcp__wirken__read_file"])).unwrap();
        let ev = |event: Value| json!({"type": "stream_event", "event": event}).to_string();
        assert_eq!(
            s.line(&ev(json!({"type": "message_start", "message": {
                "id": "m1", "model": "pinned-model-4-5-20251001",
                "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "output_tokens": 1},
            }}))),
            Ok(vec![Reported::Began("m1".to_string())])
        );
        // The message itself, sent before its stream ends, adds text
        // and no second step.
        assert_eq!(
            s.line(
                &json!({"type": "assistant", "message": {
                    "id": "m1", "model": "pinned-model-4-5-20251001",
                    "content": [{"type": "text", "text": "reading"}, {"type": "tool_use"}],
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                }})
                .to_string()
            ),
            Ok(vec![Reported::Text("reading".to_string())])
        );
        s.line(&ev(json!({"type": "message_delta",
            "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 42}})))
            .unwrap();
        assert_eq!(
            s.line(&ev(json!({"type": "message_stop"}))),
            Ok(vec![Reported::Step(Step {
                id: "m1".to_string(),
                model: "pinned-model-4-5-20251001".to_string(),
                input_tokens: 10,
                output_tokens: 42,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 90,
                stop_reason: Some("tool_use".to_string()),
            })])
        );

        // A step with no stream events is reported when the run ends.
        s.line(
            &json!({"type": "assistant", "message": {
                "id": "m2", "model": PIN, "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "done"}],
                "usage": {"input_tokens": 7, "output_tokens": 3},
            }})
            .to_string(),
        )
        .unwrap();
        let end = s
            .line(
                &json!({"type": "result", "subtype": "success", "is_error": false,
                    "result": "done", "modelUsage": {"pinned-model-4-5-20251001": {}}})
                .to_string(),
            )
            .unwrap();
        assert!(
            matches!(&end[0], Reported::Step(step) if step.id == "m2" && step.output_tokens == 3)
        );
        assert_eq!(
            end[1],
            Reported::Ended(Outcome {
                is_error: false,
                subtype: "success".to_string(),
                text: "done".to_string(),
                models: vec!["pinned-model-4-5-20251001".to_string()],
                usage: vec![ModelUsage {
                    model: "pinned-model-4-5-20251001".to_string(),
                    ..ModelUsage::default()
                }],
                reported_cost_usd_micros: None,
                reported_api_millis: None,
            })
        );
    }

    /// A step by another model is reported, so it is on the chain, and
    /// ends the run as an error naming both models. So does a usage
    /// summary that names another model.
    #[test]
    fn a_step_or_a_summary_naming_another_model_ends_the_run() {
        let mut s = Stream::new(PIN);
        s.line(&opening(&[])).unwrap();
        let out = s
            .line(
                &json!({"type": "assistant", "message": {
                    "id": "m1", "model": "another-model", "content": [],
                    "usage": {"input_tokens": 5, "output_tokens": 2},
                }})
                .to_string(),
            )
            .unwrap();
        assert!(matches!(&out[0], Reported::Step(step) if step.model == "another-model"));
        let Reported::Ended(ended) = &out[1] else {
            panic!("{out:?}");
        };
        assert!(ended.is_error);
        assert!(
            ended
                .text
                .contains("reported the model `another-model` where the pin is `pinned-model-4-5`"),
            "{}",
            ended.text
        );

        let mut s = Stream::new(PIN);
        s.line(&opening(&[])).unwrap();
        let out = s
            .line(
                &json!({"type": "result", "subtype": "success", "result": "ok",
                    "modelUsage": {PIN: {}, "another-model": {}}})
                .to_string(),
            )
            .unwrap();
        let Reported::Ended(ended) = &out[0] else {
            panic!("{out:?}");
        };
        assert!(ended.is_error && ended.text.contains("usage summary names the model"));
    }

    /// A message the child wrote itself, as it does for a usage limit,
    /// is no model step.
    #[test]
    fn a_message_no_model_answered_is_not_a_step() {
        let mut s = Stream::new(PIN);
        s.line(&opening(&[])).unwrap();
        let out = s
            .line(
                &json!({"type": "assistant", "message": {
                    "id": "x", "model": "<synthetic>",
                    "content": [{"type": "text", "text": "limit reached"}],
                }})
                .to_string(),
            )
            .unwrap();
        assert_eq!(out, vec![Reported::Text("limit reached".to_string())]);
        let end = s
            .line(
                r#"{"type":"result","subtype":"success","is_error":true,"result":"limit reached"}"#,
            )
            .unwrap();
        assert!(matches!(&end[0], Reported::Ended(o) if o.is_error));
    }
}
