//! Projects `SessionEvent` rows into OpenTelemetry GenAI spans for
//! the OTel exporter (`crate::otel_exporter`).
//!
//! ## Model
//!
//! The projector buffers spans per (session, run) until the run
//! terminates, then emits all spans for the run as a single batch.
//! "Root closes last" is a hard projector invariant: the
//! `invoke_agent` root span holds the run's input and output
//! messages, the run's duration, and the per-run identity
//! attributes, so it cannot emit until the terminating
//! `AssistantMessage` arrives. Children buffer alongside it and
//! emit in the same batch.
//!
//! Wirken processes each session sequentially (one inbound message
//! wakes the agent, runs to a final assistant message, terminates),
//! so a session has at most one in-flight run buffer at a time.
//!
//! ## Module status
//!
//! Active development on issue #130. The `invoke_agent` root,
//! `chat`, `execute_tool`, and `output_messages` spans are
//! implemented. The root carries its full mandatory all-span
//! attribute set (`gen_ai.operation.name`, input and output
//! message bodies, `client.address`, `server.address`,
//! `server.port`, `microsoft.channel.name` with an `internal`
//! fallback for adapter-less runs, `gen_ai.conversation.id`,
//! `microsoft.session.id` as a per-wake UUIDv4, `user.id` via the
//! [`crate::UserResolver`], plus whatever the active
//! [`crate::FederatedIdentity::span_attributes`] returns). `chat`
//! children pair `LlmRequest` and `LlmResponse` rows by
//! `request_id`. `execute_tool` children pair `AssistantToolCalls`
//! and `ToolResult` rows by `call_id`, with `tool.type` resolved
//! through the gateway's name-prefix dispatch contract (see
//! [`Self::tool_type_for`]). The `output_messages` child carries
//! `gen_ai.output.messages` from the closing `AssistantMessage`
//! additively to the root's own copy (per the verified OTel
//! GenAI semconv reference, output messages live on both
//! `invoke_agent` and `output_messages`). Remaining branches
//! (error-status, agent-to-agent) land in follow-up commits.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::TryRng;

use crate::otel_exporter::OtelConfig;
use crate::session_log::{SessionEvent, SessionId, ToolCallRecord};
use crate::user_resolver::{UserResolver, format_uuid_v4_shape};

/// 16-byte OTLP trace identifier, serialized as 32 lowercase hex
/// characters. The Agent 365 ingestion endpoint expects hex-encoded
/// trace ids on the wire; generic OTLP collectors accept the same
/// shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceId(String);

impl TraceId {
    /// Generate a fresh random trace id.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng()
            .try_fill_bytes(&mut bytes)
            .expect("OS RNG must not fail when filling a 16-byte OTel trace id");
        Self(hex_encode(&bytes))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// 8-byte OTLP span identifier, serialized as 16 lowercase hex
/// characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanId(String);

impl SpanId {
    /// Generate a fresh random span id.
    pub fn random() -> Self {
        let mut bytes = [0u8; 8];
        rand::rng()
            .try_fill_bytes(&mut bytes)
            .expect("OS RNG must not fail when filling an 8-byte OTel span id");
        Self(hex_encode(&bytes))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Generate a fresh random UUIDv4-shape string, used for the
/// `microsoft.session.id` attribute the projector stamps on every
/// span emitted in one run.
fn random_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::rng()
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG must not fail when filling 16 bytes for a UUIDv4 microsoft.session.id");
    format_uuid_v4_shape(bytes)
}

/// OTLP span status code. Carried as the documented integer value
/// because the Agent 365 ingestion endpoint expects integer
/// `status.code` on the wire even though OTLP/HTTP+JSON would also
/// accept the symbolic form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanStatus {
    Unset = 0,
    Ok = 1,
    Error = 2,
}

/// OTLP span kind. Same integer-on-wire convention as
/// [`SpanStatus`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanKind {
    Internal = 1,
    Server = 2,
    Client = 3,
    Producer = 4,
    Consumer = 5,
}

/// One OTLP span, projected from one or more `SessionEvent` rows.
///
/// Attribute values are kept as `String` pairs because the Agent 365
/// ingestion endpoint requires every attribute value emitted as
/// `stringValue`, including numeric fields like token counts. A
/// naive OTLP SDK that emits `intValue`/`doubleValue` for numeric
/// attributes produces spans Agent 365 rejects at ingestion, which
/// is the reason this projector hand-builds the OTLP/HTTP+JSON
/// envelope rather than depending on the OpenTelemetry SDK.
#[derive(Clone, Debug)]
pub struct Span {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub name: String,
    pub kind: SpanKind,
    pub start_time_unix_nano: u128,
    pub end_time_unix_nano: u128,
    pub status: SpanStatus,
    pub attributes: Vec<(String, String)>,
}

/// Per-session in-flight run state held by the projector between
/// the opening `UserMessage` and the closing `AssistantMessage`.
struct RunBuffer {
    trace_id: TraceId,
    root_span_id: SpanId,
    started_at_nanos: u128,
    user_message: String,
    adapter_id: Option<String>,
    sender_id: Option<String>,
    /// `microsoft.session.id` value for every span in this run.
    /// One UUIDv4 allocated when the run opens; stamped identically
    /// on the root and every child so cross-span correlation in
    /// Defender pivots cleanly at run granularity.
    session_id_uuid: String,
    /// Completed `LlmRequest` and `LlmResponse` pairs, in arrival
    /// order. One entry produces one `chat` span at `close_run`
    /// time once identity attributes are available.
    chat_calls: Vec<ChatCall>,
    /// `LlmRequest` rows whose paired `LlmResponse` has not yet
    /// arrived, keyed by the `request_id` the pair shares. A
    /// `LlmResponse` arriving with no matching entry is logged
    /// and dropped (orphan response); pending entries still in
    /// this map at `close_run` are also logged and dropped
    /// (unpaired request).
    pending_chat_requests: HashMap<String, PendingChat>,
    /// Completed `AssistantToolCalls` and `ToolResult` pairs, in
    /// arrival order. One entry produces one `execute_tool` span
    /// at `close_run` time.
    execute_tool_calls: Vec<ExecuteToolCall>,
    /// `ToolCallRecord` entries from `AssistantToolCalls` whose
    /// paired `ToolResult` has not yet arrived, keyed by the
    /// `call_id` the pair shares. Same orphan and unpaired
    /// semantics as `pending_chat_requests`.
    pending_execute_tools: HashMap<String, PendingExecuteTool>,
}

/// `LlmRequest` row buffered while waiting for its paired
/// `LlmResponse`. Carries the projector-allocated `SpanId` and
/// start timestamp so a fresh `SpanId` is not minted on the
/// response side; the pair shares one span on the wire.
struct PendingChat {
    span_id: SpanId,
    started_at_nanos: u128,
    provider: String,
    model: String,
}

/// One completed `LlmRequest` and `LlmResponse` pair, ready to
/// project into a `chat` span at `close_run` time.
struct ChatCall {
    span_id: SpanId,
    started_at_nanos: u128,
    ended_at_nanos: u128,
    provider: String,
    model: String,
    input_tokens: u32,
    output_tokens: u32,
}

/// `ToolCallRecord` from an `AssistantToolCalls` row buffered
/// while waiting for its paired `ToolResult`. Carries the
/// projector-allocated `SpanId` and start timestamp so the pair
/// shares one span on the wire.
struct PendingExecuteTool {
    span_id: SpanId,
    started_at_nanos: u128,
    tool_name: String,
    tool_arguments: String,
}

/// One completed `AssistantToolCalls` and `ToolResult` pair,
/// ready to project into an `execute_tool` span at `close_run`
/// time.
struct ExecuteToolCall {
    span_id: SpanId,
    started_at_nanos: u128,
    ended_at_nanos: u128,
    tool_name: String,
    tool_arguments: String,
    tool_call_id: String,
    tool_result: String,
    success: bool,
}

/// Projects `SessionEvent` rows into OTel GenAI spans.
///
/// Holds in-memory run buffers keyed by [`SessionId`]. State is not
/// persisted: an exporter restart drops in-flight runs and resumes
/// at the cursor the operator chose (typically the chain head). The
/// SQLite session log is the source of truth; the projector is a
/// pure derivation.
pub struct OtelProjector {
    config: OtelConfig,
    user_resolver: Arc<dyn UserResolver>,
    runs: HashMap<SessionId, RunBuffer>,
}

impl OtelProjector {
    /// Construct a projector against a config and a user resolver.
    ///
    /// The user resolver fills the `user.id` attribute on each
    /// `invoke_agent` root from the run's `(adapter_id, sender_id)`
    /// pair. Wirken's chat-platform callers have no real Microsoft
    /// Entra identity by construction, so the resolver synthesizes
    /// a stable per-caller value; see [`crate::UserResolver`] for
    /// the contract and [`crate::DeterministicUserResolver`] for the
    /// development default.
    pub fn new(config: OtelConfig, user_resolver: Arc<dyn UserResolver>) -> Self {
        Self {
            config,
            user_resolver,
            runs: HashMap::new(),
        }
    }

    /// Project one `SessionEvent` for a given session and timestamp.
    ///
    /// Returns spans only when a run terminates (an
    /// `AssistantMessage` closes the buffer); otherwise returns an
    /// empty `Vec`. The caller hands the returned spans to the OTel
    /// exporter's batcher.
    ///
    /// `identity_attributes` are the run-wide attribute pairs
    /// returned by the active [`crate::FederatedIdentity::span_attributes`].
    /// They are stamped on every span emitted in the run.
    pub fn project(
        &mut self,
        event: &SessionEvent,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        identity_attributes: &[(String, String)],
    ) -> Vec<Span> {
        match event {
            SessionEvent::UserMessage {
                content,
                adapter_id,
                sender_id,
                ..
            } => {
                self.open_run(
                    session_id,
                    timestamp,
                    content.clone(),
                    adapter_id.clone(),
                    sender_id.clone(),
                );
                Vec::new()
            }
            SessionEvent::AssistantMessage { content, .. } => {
                self.close_run(session_id, timestamp, content, identity_attributes)
            }
            SessionEvent::LlmRequest {
                request_id,
                provider,
                model,
                ..
            } => {
                self.start_chat(session_id, timestamp, request_id, provider, model);
                Vec::new()
            }
            SessionEvent::LlmResponse {
                request_id,
                input_tokens,
                output_tokens,
                ..
            } => {
                self.finish_chat(
                    session_id,
                    timestamp,
                    request_id,
                    *input_tokens,
                    *output_tokens,
                );
                Vec::new()
            }
            SessionEvent::AssistantToolCalls { calls, .. } => {
                self.start_execute_tools(session_id, timestamp, calls);
                Vec::new()
            }
            SessionEvent::ToolResult {
                call_id,
                tool_name,
                output,
                success,
                ..
            } => {
                self.finish_execute_tool(
                    session_id, timestamp, call_id, tool_name, output, *success,
                );
                Vec::new()
            }
            // Remaining child variants (SubagentSpawned for
            // agent-to-agent, PermissionDenied for error status,
            // dedicated output_messages span) project in follow-up
            // commits on issue #130.
            _ => Vec::new(),
        }
    }

    /// Number of in-flight run buffers. Test seam.
    pub fn in_flight_run_count(&self) -> usize {
        self.runs.len()
    }

    fn open_run(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        user_message: String,
        adapter_id: Option<String>,
        sender_id: Option<String>,
    ) {
        let buf = RunBuffer {
            trace_id: TraceId::random(),
            root_span_id: SpanId::random(),
            started_at_nanos: datetime_to_unix_nanos(timestamp),
            user_message,
            adapter_id,
            sender_id,
            session_id_uuid: random_uuid_v4(),
            chat_calls: Vec::new(),
            pending_chat_requests: HashMap::new(),
            execute_tool_calls: Vec::new(),
            pending_execute_tools: HashMap::new(),
        };
        if self.runs.insert(session_id.clone(), buf).is_some() {
            tracing::warn!(
                session_id = %session_id,
                "OtelProjector dropped an in-flight run buffer because a fresh UserMessage opened a new run before the prior AssistantMessage closed it",
            );
        }
    }

    fn start_chat(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        request_id: &str,
        provider: &str,
        model: &str,
    ) {
        let Some(buf) = self.runs.get_mut(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                request_id,
                "OtelProjector saw an LlmRequest with no open run buffer; chat span will not be produced",
            );
            return;
        };
        let pending = PendingChat {
            span_id: SpanId::random(),
            started_at_nanos: datetime_to_unix_nanos(timestamp),
            provider: provider.to_string(),
            model: model.to_string(),
        };
        if buf
            .pending_chat_requests
            .insert(request_id.to_string(), pending)
            .is_some()
        {
            tracing::warn!(
                session_id = %session_id,
                request_id,
                "OtelProjector saw a duplicate LlmRequest for the same request_id; previous pending entry replaced",
            );
        }
    }

    fn finish_chat(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        request_id: &str,
        input_tokens: u32,
        output_tokens: u32,
    ) {
        let Some(buf) = self.runs.get_mut(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                request_id,
                "OtelProjector saw an LlmResponse with no open run buffer; chat span will not be produced",
            );
            return;
        };
        let Some(pending) = buf.pending_chat_requests.remove(request_id) else {
            tracing::warn!(
                session_id = %session_id,
                request_id,
                "OtelProjector saw an LlmResponse with no matching LlmRequest; orphan response is dropped",
            );
            return;
        };
        buf.chat_calls.push(ChatCall {
            span_id: pending.span_id,
            started_at_nanos: pending.started_at_nanos,
            ended_at_nanos: datetime_to_unix_nanos(timestamp),
            provider: pending.provider,
            model: pending.model,
            input_tokens,
            output_tokens,
        });
    }

    fn start_execute_tools(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        calls: &[ToolCallRecord],
    ) {
        let Some(buf) = self.runs.get_mut(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                tool_call_count = calls.len(),
                "OtelProjector saw an AssistantToolCalls with no open run buffer; execute_tool spans will not be produced",
            );
            return;
        };
        let started_at_nanos = datetime_to_unix_nanos(timestamp);
        for call in calls {
            let pending = PendingExecuteTool {
                span_id: SpanId::random(),
                started_at_nanos,
                tool_name: call.name.clone(),
                tool_arguments: call.arguments.clone(),
            };
            if buf
                .pending_execute_tools
                .insert(call.id.clone(), pending)
                .is_some()
            {
                tracing::warn!(
                    session_id = %session_id,
                    call_id = %call.id,
                    "OtelProjector saw a duplicate tool call_id in AssistantToolCalls; previous pending entry replaced",
                );
            }
        }
    }

    fn finish_execute_tool(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        call_id: &str,
        tool_name: &str,
        output: &str,
        success: bool,
    ) {
        let Some(buf) = self.runs.get_mut(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                call_id,
                "OtelProjector saw a ToolResult with no open run buffer; execute_tool span will not be produced",
            );
            return;
        };
        let Some(pending) = buf.pending_execute_tools.remove(call_id) else {
            tracing::warn!(
                session_id = %session_id,
                call_id,
                tool_name,
                "OtelProjector saw a ToolResult with no matching AssistantToolCalls.call_id; orphan result dropped",
            );
            return;
        };
        buf.execute_tool_calls.push(ExecuteToolCall {
            span_id: pending.span_id,
            started_at_nanos: pending.started_at_nanos,
            ended_at_nanos: datetime_to_unix_nanos(timestamp),
            tool_name: pending.tool_name,
            tool_arguments: pending.tool_arguments,
            tool_call_id: call_id.to_string(),
            tool_result: output.to_string(),
            success,
        });
    }

    fn close_run(
        &mut self,
        session_id: &SessionId,
        timestamp: DateTime<Utc>,
        assistant_message: &str,
        identity_attributes: &[(String, String)],
    ) -> Vec<Span> {
        let Some(buf) = self.runs.remove(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                "OtelProjector saw an AssistantMessage with no open run buffer; the span is dropped because the projector has no input/output pairing to root against",
            );
            return Vec::new();
        };

        // Warn on unpaired LlmRequest entries: pending entries
        // still in the map at run close had no matching
        // LlmResponse arrive. Drop them rather than emit an
        // incomplete chat span.
        for request_id in buf.pending_chat_requests.keys() {
            tracing::warn!(
                session_id = %session_id,
                request_id = %request_id,
                "OtelProjector run closed with an unpaired LlmRequest; chat span dropped",
            );
        }
        // Same posture for unpaired AssistantToolCalls entries.
        for call_id in buf.pending_execute_tools.keys() {
            tracing::warn!(
                session_id = %session_id,
                call_id = %call_id,
                "OtelProjector run closed with an unpaired tool call; execute_tool span dropped",
            );
        }

        let ended_at_nanos = datetime_to_unix_nanos(timestamp);

        // Build children first; root closes last.
        let mut emit: Vec<Span> = buf
            .chat_calls
            .iter()
            .map(|call| self.build_chat_span(&buf, call, session_id, identity_attributes))
            .collect();
        emit.extend(
            buf.execute_tool_calls.iter().map(|call| {
                self.build_execute_tool_span(&buf, call, session_id, identity_attributes)
            }),
        );

        emit.push(self.build_output_messages_span(
            &buf,
            session_id,
            ended_at_nanos,
            assistant_message,
            identity_attributes,
        ));

        let root = self.build_root_span(
            &buf,
            session_id,
            ended_at_nanos,
            assistant_message,
            identity_attributes,
        );
        emit.push(root);
        emit
    }

    /// Map a tool name to the `tool.type` enum value Microsoft's
    /// closed enumeration expects. Mirrors the gateway's actual
    /// dispatch contract at
    /// `crates/agent/src/runtime.rs::execute_tool`: tool names
    /// prefixed `mcp_` are routed to the MCP proxy client at
    /// execution time, so the same prefix identifies them as
    /// `MCP Server` for Defender's `ExecuteToolByMCPServer`
    /// ActionType. Everything else (built-in tools, Wasm skills,
    /// `exec`, `web_search`, `generate_image`) runs in-process at
    /// the gateway and is reported as `function` for Defender's
    /// `ExecuteToolByGateway` ActionType. Microsoft's enum has no
    /// Wasm-skill category; `function` is the documented catch-all
    /// for runtime-executed tools.
    fn tool_type_for(tool_name: &str) -> &'static str {
        if tool_name.starts_with("mcp_") {
            "MCP Server"
        } else {
            "function"
        }
    }

    /// Run-correlation attributes carried by every span class
    /// (root, `chat`, `execute_tool`, `output_messages`, and the
    /// upcoming error and agent-to-agent branches). Returned in a
    /// fresh `Vec` the caller extends with class-specific
    /// attributes.
    ///
    /// The mandatory-on-every-span set: `microsoft.channel.name`
    /// with the per-adapter override map applied,
    /// `gen_ai.conversation.id` from the wirken session id,
    /// `microsoft.session.id` as the per-wake UUIDv4 the run
    /// allocated, plus the `FederatedIdentity`-supplied attrs
    /// (`microsoft.tenant.id`, `gen_ai.agent.id`,
    /// `gen_ai.agent.name`, `microsoft.a365.agent.blueprint.id`
    /// when the active identity provides them).
    fn run_wide_attrs(
        &self,
        buf: &RunBuffer,
        session_id: &SessionId,
        identity_attributes: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut attrs: Vec<(String, String)> = vec![
            (
                "microsoft.channel.name".to_string(),
                self.channel_name_for(buf.adapter_id.as_deref()),
            ),
            (
                "gen_ai.conversation.id".to_string(),
                session_id.as_str().to_string(),
            ),
            (
                "microsoft.session.id".to_string(),
                buf.session_id_uuid.clone(),
            ),
        ];
        attrs.extend(identity_attributes.iter().cloned());
        attrs
    }

    /// Run-wide attributes plus the IA/ET/CH-specific addressing
    /// trio (`client.address`, `server.address`, `server.port`).
    /// `invoke_agent`, `execute_tool`, and `chat` are the three
    /// span classes the verified reference marks as requiring
    /// these; `output_messages` does not.
    fn ia_et_ch_base_attrs(
        &self,
        buf: &RunBuffer,
        session_id: &SessionId,
        identity_attributes: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut attrs = self.run_wide_attrs(buf, session_id, identity_attributes);
        attrs.extend([
            ("client.address".to_string(), "0.0.0.0".to_string()),
            (
                "server.address".to_string(),
                self.config.server_address.clone(),
            ),
            (
                "server.port".to_string(),
                self.config.server_port.to_string(),
            ),
        ]);
        attrs
    }

    fn build_root_span(
        &self,
        buf: &RunBuffer,
        session_id: &SessionId,
        ended_at_nanos: u128,
        assistant_message: &str,
        identity_attributes: &[(String, String)],
    ) -> Span {
        let mut attributes = self.ia_et_ch_base_attrs(buf, session_id, identity_attributes);
        attributes.extend([
            (
                "gen_ai.operation.name".to_string(),
                "invoke_agent".to_string(),
            ),
            (
                "gen_ai.input.messages".to_string(),
                buf.user_message.clone(),
            ),
            (
                "gen_ai.output.messages".to_string(),
                assistant_message.to_string(),
            ),
            (
                "user.id".to_string(),
                self.user_resolver
                    .resolve_user(buf.adapter_id.as_deref(), buf.sender_id.as_deref())
                    .as_str()
                    .to_string(),
            ),
        ]);

        Span {
            trace_id: buf.trace_id.clone(),
            span_id: buf.root_span_id.clone(),
            parent_span_id: None,
            name: "invoke_agent".to_string(),
            kind: SpanKind::Internal,
            start_time_unix_nano: buf.started_at_nanos,
            end_time_unix_nano: ended_at_nanos,
            status: SpanStatus::Ok,
            attributes,
        }
    }

    fn build_output_messages_span(
        &self,
        buf: &RunBuffer,
        session_id: &SessionId,
        ended_at_nanos: u128,
        assistant_message: &str,
        identity_attributes: &[(String, String)],
    ) -> Span {
        // output_messages is not in the IA/ET/CH set; the
        // addressing trio is omitted. The verified reference puts
        // `gen_ai.output.messages` both here AND on the
        // `invoke_agent` root; the dedicated child is additive,
        // not a relocation.
        let mut attributes = self.run_wide_attrs(buf, session_id, identity_attributes);
        attributes.extend([
            (
                "gen_ai.operation.name".to_string(),
                "output_messages".to_string(),
            ),
            (
                "gen_ai.output.messages".to_string(),
                assistant_message.to_string(),
            ),
        ]);

        Span {
            trace_id: buf.trace_id.clone(),
            span_id: SpanId::random(),
            parent_span_id: Some(buf.root_span_id.clone()),
            name: "output_messages".to_string(),
            // Instantaneous span: the moment the agent emitted its
            // final output. Wirken's chain marks this as a single
            // `AssistantMessage` row; start and end coincide.
            kind: SpanKind::Internal,
            start_time_unix_nano: ended_at_nanos,
            end_time_unix_nano: ended_at_nanos,
            status: SpanStatus::Ok,
            attributes,
        }
    }

    fn build_execute_tool_span(
        &self,
        buf: &RunBuffer,
        call: &ExecuteToolCall,
        session_id: &SessionId,
        identity_attributes: &[(String, String)],
    ) -> Span {
        let mut attributes = self.ia_et_ch_base_attrs(buf, session_id, identity_attributes);
        attributes.extend([
            (
                "gen_ai.operation.name".to_string(),
                "execute_tool".to_string(),
            ),
            ("tool.name".to_string(), call.tool_name.clone()),
            (
                "tool.type".to_string(),
                Self::tool_type_for(&call.tool_name).to_string(),
            ),
            ("tool.call.id".to_string(), call.tool_call_id.clone()),
            (
                "tool.call.arguments".to_string(),
                call.tool_arguments.clone(),
            ),
            ("tool.call.result".to_string(), call.tool_result.clone()),
        ]);

        let status = if call.success {
            SpanStatus::Ok
        } else {
            SpanStatus::Error
        };

        Span {
            trace_id: buf.trace_id.clone(),
            span_id: call.span_id.clone(),
            parent_span_id: Some(buf.root_span_id.clone()),
            name: "execute_tool".to_string(),
            // `Internal` for execute_tool: from the agent's
            // perspective the call is in-process (built-in tool,
            // Wasm skill, or local MCP proxy), not a direct
            // outbound HTTPS call. Defender's ActionType split
            // between gateway and MCP server dispatch is carried
            // by `tool.type`, not span.kind.
            kind: SpanKind::Internal,
            start_time_unix_nano: call.started_at_nanos,
            end_time_unix_nano: call.ended_at_nanos,
            status,
            attributes,
        }
    }

    fn build_chat_span(
        &self,
        buf: &RunBuffer,
        call: &ChatCall,
        session_id: &SessionId,
        identity_attributes: &[(String, String)],
    ) -> Span {
        let mut attributes = self.ia_et_ch_base_attrs(buf, session_id, identity_attributes);
        attributes.extend([
            ("gen_ai.operation.name".to_string(), "chat".to_string()),
            ("gen_ai.request.model".to_string(), call.model.clone()),
            ("gen_ai.provider.name".to_string(), call.provider.clone()),
            (
                "gen_ai.usage.input_tokens".to_string(),
                call.input_tokens.to_string(),
            ),
            (
                "gen_ai.usage.output_tokens".to_string(),
                call.output_tokens.to_string(),
            ),
        ]);

        Span {
            trace_id: buf.trace_id.clone(),
            span_id: call.span_id.clone(),
            parent_span_id: Some(buf.root_span_id.clone()),
            // Chat spans represent an outbound LLM call; OTel
            // GenAI semconv uses `Client` kind for these.
            name: "chat".to_string(),
            kind: SpanKind::Client,
            start_time_unix_nano: call.started_at_nanos,
            end_time_unix_nano: call.ended_at_nanos,
            status: SpanStatus::Ok,
            attributes,
        }
    }

    /// Resolve the `microsoft.channel.name` value for a given
    /// adapter id. The default override map renames `teams` to
    /// `msteams` so the Microsoft Teams adapter lands in Defender's
    /// built-in channel pivot; other adapters pass through their
    /// own name. Adapter-less runs (subagent recursion, CLI, cron)
    /// stamp the literal `internal` because the attribute is
    /// mandatory on every span and the value must be deterministic.
    fn channel_name_for(&self, adapter_id: Option<&str>) -> String {
        match adapter_id {
            Some(adapter) => self
                .config
                .channel_name_overrides
                .get(adapter)
                .cloned()
                .unwrap_or_else(|| adapter.to_string()),
            None => "internal".to_string(),
        }
    }
}

fn datetime_to_unix_nanos(ts: DateTime<Utc>) -> u128 {
    let secs = ts.timestamp() as i128;
    let nanos = ts.timestamp_subsec_nanos() as i128;
    (secs * 1_000_000_000 + nanos) as u128
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::user_resolver::{DeterministicUserResolver, UserId};

    /// A `UserResolver` that records its inputs so the projector
    /// can be asserted to forward the exact `(adapter_id, sender_id)`
    /// pair from the `SessionEvent::UserMessage` rather than
    /// placeholder values.
    struct RecordingUserResolver {
        captured: Mutex<Vec<(Option<String>, Option<String>)>>,
    }

    impl RecordingUserResolver {
        fn new() -> Self {
            Self {
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl UserResolver for RecordingUserResolver {
        fn resolve_user(&self, adapter_id: Option<&str>, sender_id: Option<&str>) -> UserId {
            self.captured
                .lock()
                .expect("captured Mutex must not be poisoned")
                .push((adapter_id.map(String::from), sender_id.map(String::from)));
            UserId::new("00000000-0000-4000-8000-000000000000")
        }
    }

    fn at(seconds_since_epoch: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(seconds_since_epoch, 0).unwrap()
    }

    fn user_message(content: &str, adapter: Option<&str>) -> SessionEvent {
        SessionEvent::UserMessage {
            content: content.to_string(),
            inbound_id: None,
            adapter_id: adapter.map(str::to_string),
            sender_id: None,
        }
    }

    fn user_message_with_sender(
        content: &str,
        adapter: Option<&str>,
        sender: Option<&str>,
    ) -> SessionEvent {
        SessionEvent::UserMessage {
            content: content.to_string(),
            inbound_id: None,
            adapter_id: adapter.map(str::to_string),
            sender_id: sender.map(str::to_string),
        }
    }

    fn assistant_message(content: &str) -> SessionEvent {
        SessionEvent::AssistantMessage {
            content: content.to_string(),
            agent_id: "default".to_string(),
        }
    }

    fn llm_request(request_id: &str, provider: &str, model: &str) -> SessionEvent {
        SessionEvent::LlmRequest {
            provider: provider.to_string(),
            model: model.to_string(),
            request_id: request_id.to_string(),
            tools_hash: crate::session_log::HashHex::from_bytes(&[0u8; 32]),
            messages_hash: crate::session_log::HashHex::from_bytes(&[0u8; 32]),
            agent_id: "default".to_string(),
            credential_id: None,
        }
    }

    fn llm_response(request_id: &str, input_tokens: u32, output_tokens: u32) -> SessionEvent {
        SessionEvent::LlmResponse {
            request_id: request_id.to_string(),
            finish_reason: "stop".to_string(),
            input_tokens,
            output_tokens,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            latency_ms: 1000,
            agent_id: "default".to_string(),
            credential_id: None,
            input_cost_usd_micros: None,
            output_cost_usd_micros: None,
            total_cost_usd_micros: None,
        }
    }

    fn assistant_tool_calls(calls: &[(&str, &str, &str)]) -> SessionEvent {
        SessionEvent::AssistantToolCalls {
            calls: calls
                .iter()
                .map(|(id, name, args)| ToolCallRecord {
                    id: (*id).to_string(),
                    name: (*name).to_string(),
                    arguments: (*args).to_string(),
                })
                .collect(),
            agent_id: "default".to_string(),
            adapter_id: None,
            sender_id: None,
        }
    }

    fn tool_result(call_id: &str, tool_name: &str, output: &str, success: bool) -> SessionEvent {
        SessionEvent::ToolResult {
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            output: output.to_string(),
            success,
            agent_id: "default".to_string(),
            adapter_id: None,
            sender_id: None,
        }
    }

    fn chat_spans(spans: &[Span]) -> Vec<&Span> {
        spans.iter().filter(|s| s.name == "chat").collect()
    }

    fn execute_tool_spans(spans: &[Span]) -> Vec<&Span> {
        spans.iter().filter(|s| s.name == "execute_tool").collect()
    }

    fn output_messages_spans(spans: &[Span]) -> Vec<&Span> {
        spans
            .iter()
            .filter(|s| s.name == "output_messages")
            .collect()
    }

    fn root_span(spans: &[Span]) -> &Span {
        spans
            .iter()
            .find(|s| s.name == "invoke_agent")
            .expect("invoke_agent root must be present in emitted spans")
    }

    fn projector() -> OtelProjector {
        OtelProjector::new(OtelConfig::default(), Arc::new(DeterministicUserResolver))
    }

    fn projector_with_server(addr: &str, port: u16) -> OtelProjector {
        let config = OtelConfig {
            server_address: addr.to_string(),
            server_port: port,
            ..OtelConfig::default()
        };
        OtelProjector::new(config, Arc::new(DeterministicUserResolver))
    }

    fn attrs(span: &Span) -> HashMap<String, String> {
        span.attributes.iter().cloned().collect()
    }

    #[test]
    fn user_message_opens_run_and_emits_nothing() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        let spans = p.project(
            &user_message("hello", Some("telegram")),
            &session,
            at(1_700_000_000),
            &[],
        );
        assert!(spans.is_empty());
        assert_eq!(p.in_flight_run_count(), 1);
    }

    #[test]
    fn assistant_message_closes_run_and_emits_invoke_agent_root() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(
            &user_message("what is the weather", Some("slack")),
            &session,
            at(1_700_000_000),
            &[],
        );
        let spans = p.project(
            &assistant_message("sunny"),
            &session,
            at(1_700_000_010),
            &[],
        );
        // Run close emits the canonical pair: output_messages
        // child plus invoke_agent root.
        assert_eq!(spans.len(), 2);
        let span = root_span(&spans);
        assert_eq!(span.name, "invoke_agent");
        assert_eq!(span.kind, SpanKind::Internal);
        assert_eq!(span.status, SpanStatus::Ok);
        assert!(span.parent_span_id.is_none());
        assert_eq!(span.start_time_unix_nano, 1_700_000_000 * 1_000_000_000);
        assert_eq!(span.end_time_unix_nano, 1_700_000_010 * 1_000_000_000);
        assert_eq!(p.in_flight_run_count(), 0);
    }

    #[test]
    fn root_span_carries_invoke_agent_operation_name_attribute() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(100), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(101), &[]);
        assert_eq!(
            attrs(root_span(&spans)).get("gen_ai.operation.name"),
            Some(&"invoke_agent".to_string())
        );
    }

    #[test]
    fn root_span_carries_input_and_output_message_attributes() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("question text", None), &session, at(100), &[]);
        let spans = p.project(&assistant_message("answer text"), &session, at(101), &[]);
        let a = attrs(root_span(&spans));
        assert_eq!(
            a.get("gen_ai.input.messages"),
            Some(&"question text".to_string())
        );
        assert_eq!(
            a.get("gen_ai.output.messages"),
            Some(&"answer text".to_string())
        );
    }

    #[test]
    fn root_span_carries_client_address_placeholder_for_chat_callers() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("telegram")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(root_span(&spans)).get("client.address"),
            Some(&"0.0.0.0".to_string())
        );
    }

    #[test]
    fn root_span_carries_server_address_and_port_from_config_as_strings() {
        let mut p = projector_with_server("gateway.example.internal", 18790);
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let a = attrs(root_span(&spans));
        assert_eq!(
            a.get("server.address"),
            Some(&"gateway.example.internal".to_string())
        );
        // server.port is stamped as a string because every OTel
        // attribute value must be stringValue for Agent 365.
        assert_eq!(a.get("server.port"), Some(&"18790".to_string()));
    }

    #[test]
    fn root_span_carries_gen_ai_conversation_id_matching_session_id() {
        let mut p = projector();
        let session = SessionId::new("sess-thread-42");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(&spans[0]).get("gen_ai.conversation.id"),
            Some(&"sess-thread-42".to_string())
        );
    }

    #[test]
    fn root_span_carries_microsoft_session_id_in_uuid_shape() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let ms_session = attrs(&spans[0])
            .get("microsoft.session.id")
            .cloned()
            .expect("root must carry microsoft.session.id");
        // 8-4-4-4-12 layout, 36 chars with dashes.
        assert_eq!(ms_session.len(), 36);
        assert_eq!(&ms_session[14..15], "4", "version nibble must be 4");
    }

    #[test]
    fn microsoft_session_id_differs_across_runs_in_same_session() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q1", None), &session, at(0), &[]);
        let spans_a = p.project(&assistant_message("a1"), &session, at(1), &[]);
        p.project(&user_message("q2", None), &session, at(2), &[]);
        let spans_b = p.project(&assistant_message("a2"), &session, at(3), &[]);
        let id_a = attrs(&spans_a[0]).get("microsoft.session.id").cloned();
        let id_b = attrs(&spans_b[0]).get("microsoft.session.id").cloned();
        assert!(id_a.is_some());
        assert!(id_b.is_some());
        assert_ne!(
            id_a, id_b,
            "each agent wake must allocate its own microsoft.session.id"
        );
    }

    #[test]
    fn root_span_carries_user_id_via_resolver_for_chat_caller() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(
            &user_message_with_sender("q", Some("telegram"), Some("user-42")),
            &session,
            at(0),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let root = root_span(&spans);
        let user_id = attrs(root)
            .get("user.id")
            .cloned()
            .expect("root must carry user.id");
        // Deterministic resolver produces a UUIDv4-shape string.
        assert_eq!(user_id.len(), 36);
        // No wirken-namespaced fallback should remain on the root.
        assert!(
            !attrs(root).contains_key("wirken.sender.id"),
            "wirken.sender.id placeholder should not appear once user.id is wired",
        );
    }

    #[test]
    fn user_id_is_stable_per_caller_across_runs() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(
            &user_message_with_sender("q1", Some("telegram"), Some("user-42")),
            &session,
            at(0),
            &[],
        );
        let spans_a = p.project(&assistant_message("a1"), &session, at(1), &[]);
        p.project(
            &user_message_with_sender("q2", Some("telegram"), Some("user-42")),
            &session,
            at(2),
            &[],
        );
        let spans_b = p.project(&assistant_message("a2"), &session, at(3), &[]);
        let id_a = attrs(&spans_a[0]).get("user.id").cloned();
        let id_b = attrs(&spans_b[0]).get("user.id").cloned();
        assert_eq!(
            id_a, id_b,
            "same (adapter, sender) must resolve to the same user.id across runs",
        );
    }

    #[test]
    fn teams_adapter_renames_channel_to_msteams_via_default_override() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("teams")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(&spans[0]).get("microsoft.channel.name"),
            Some(&"msteams".to_string())
        );
    }

    #[test]
    fn non_teams_adapter_emits_literal_adapter_id_as_channel_name() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("discord")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(&spans[0]).get("microsoft.channel.name"),
            Some(&"discord".to_string())
        );
    }

    #[test]
    fn adapter_less_run_stamps_internal_channel_name_default() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(&spans[0]).get("microsoft.channel.name"),
            Some(&"internal".to_string()),
            "adapter-less runs (subagent, CLI) must carry the internal default for the mandatory channel.name attribute",
        );
    }

    #[test]
    fn identity_attributes_append_to_root_span() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let identity = vec![
            ("gen_ai.agent.id".to_string(), "agent-uuid".to_string()),
            ("gen_ai.agent.name".to_string(), "wirken".to_string()),
            ("microsoft.tenant.id".to_string(), "tenant-uuid".to_string()),
            (
                "microsoft.a365.agent.blueprint.id".to_string(),
                "agent-uuid".to_string(),
            ),
        ];
        let spans = p.project(&assistant_message("a"), &session, at(1), &identity);
        let a = attrs(&spans[0]);
        assert_eq!(a.get("gen_ai.agent.id"), Some(&"agent-uuid".to_string()));
        assert_eq!(a.get("gen_ai.agent.name"), Some(&"wirken".to_string()));
        assert_eq!(
            a.get("microsoft.tenant.id"),
            Some(&"tenant-uuid".to_string())
        );
        assert_eq!(
            a.get("microsoft.a365.agent.blueprint.id"),
            Some(&"agent-uuid".to_string())
        );
    }

    #[test]
    fn assistant_message_with_no_open_run_returns_empty() {
        let mut p = projector();
        let session = SessionId::new("sess-orphan");
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert!(spans.is_empty());
        assert_eq!(p.in_flight_run_count(), 0);
    }

    #[test]
    fn user_message_overwrites_in_flight_run_for_same_session() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("first", None), &session, at(0), &[]);
        p.project(&user_message("second", None), &session, at(1), &[]);
        assert_eq!(p.in_flight_run_count(), 1);
        let spans = p.project(&assistant_message("a"), &session, at(2), &[]);
        assert_eq!(
            attrs(root_span(&spans)).get("gen_ai.input.messages"),
            Some(&"second".to_string())
        );
    }

    #[test]
    fn trace_id_is_thirty_two_lowercase_hex_chars() {
        let id = TraceId::random();
        let hex = id.as_hex();
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn span_id_is_sixteen_lowercase_hex_chars() {
        let id = SpanId::random();
        let hex = id.as_hex();
        assert_eq!(hex.len(), 16);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn trace_and_span_ids_are_random_across_calls() {
        let trace_a = TraceId::random();
        let trace_b = TraceId::random();
        let span_a = SpanId::random();
        let span_b = SpanId::random();
        // 16 bytes and 8 bytes are plenty of entropy to make
        // collisions astronomically unlikely.
        assert_ne!(trace_a, trace_b);
        assert_ne!(span_a, span_b);
    }

    #[test]
    fn datetime_to_unix_nanos_combines_seconds_and_subsecond_nanos() {
        let ts = DateTime::<Utc>::from_timestamp(1_700_000_000, 250_000_000).unwrap();
        let nanos = datetime_to_unix_nanos(ts);
        assert_eq!(nanos, 1_700_000_000 * 1_000_000_000 + 250_000_000);
    }

    #[test]
    fn root_span_omits_microsoft_identity_attrs_when_identity_returns_empty() {
        // The three Microsoft-namespaced identity attributes
        // Agent 365 enforces (`microsoft.tenant.id`, `gen_ai.agent.id`,
        // `gen_ai.agent.name`, `microsoft.a365.agent.blueprint.id`)
        // ride in via `FederatedIdentity::span_attributes`. The
        // projector must not synthesize them; against a Jaeger or
        // Keycloak target where the identity returns no Microsoft
        // attrs, the root span legitimately omits them.
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("telegram")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let a = attrs(&spans[0]);
        assert!(!a.contains_key("microsoft.tenant.id"));
        assert!(!a.contains_key("gen_ai.agent.id"));
        assert!(!a.contains_key("gen_ai.agent.name"));
        assert!(!a.contains_key("microsoft.a365.agent.blueprint.id"));
    }

    #[test]
    fn resolver_receives_exact_adapter_and_sender_from_user_message_event() {
        let recorder = Arc::new(RecordingUserResolver::new());
        let mut p = OtelProjector::new(OtelConfig::default(), recorder.clone());
        let session = SessionId::new("sess-1");
        p.project(
            &user_message_with_sender("q", Some("telegram"), Some("user-42")),
            &session,
            at(0),
            &[],
        );
        p.project(&assistant_message("a"), &session, at(1), &[]);
        let captured = recorder
            .captured
            .lock()
            .expect("captured Mutex must not be poisoned");
        assert_eq!(captured.len(), 1, "resolver must be called once per run");
        assert_eq!(
            captured[0],
            (Some("telegram".to_string()), Some("user-42".to_string())),
            "resolver must be called with the exact (adapter_id, sender_id) the SessionEvent::UserMessage carried, not placeholders",
        );
    }

    #[test]
    fn paired_llm_request_and_response_produce_one_chat_span_parented_to_root() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("slack")), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 100, 50), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);

        // chat child + output_messages child + invoke_agent root.
        assert_eq!(spans.len(), 3);
        let chats = chat_spans(&spans);
        assert_eq!(chats.len(), 1);
        let chat = chats[0];
        let root = root_span(&spans);

        assert_eq!(chat.kind, SpanKind::Client);
        assert_eq!(chat.parent_span_id.as_ref(), Some(&root.span_id));
        assert_eq!(chat.trace_id, root.trace_id);
        assert_eq!(chat.start_time_unix_nano, 1_000_000_000);
        assert_eq!(chat.end_time_unix_nano, 2_000_000_000);
    }

    #[test]
    fn chat_span_carries_gen_ai_operation_name_chat() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "ollama", "llama3.2"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 0, 0), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(
            attrs(chat_spans(&spans)[0]).get("gen_ai.operation.name"),
            Some(&"chat".to_string())
        );
    }

    #[test]
    fn chat_span_carries_model_and_provider_from_llm_request() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "claude-sonnet-4-6"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 0, 0), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let a = attrs(chat_spans(&spans)[0]);
        assert_eq!(
            a.get("gen_ai.request.model"),
            Some(&"claude-sonnet-4-6".to_string())
        );
        assert_eq!(
            a.get("gen_ai.provider.name"),
            Some(&"anthropic".to_string())
        );
    }

    #[test]
    fn chat_span_emits_token_counts_as_stringified_integers() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 1234, 567), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let a = attrs(chat_spans(&spans)[0]);
        // Token counts are integers in SessionEvent but must
        // serialize as stringValue for Agent 365.
        assert_eq!(
            a.get("gen_ai.usage.input_tokens"),
            Some(&"1234".to_string())
        );
        assert_eq!(
            a.get("gen_ai.usage.output_tokens"),
            Some(&"567".to_string())
        );
    }

    #[test]
    fn chat_span_inherits_run_wide_attrs_from_root() {
        let mut p = projector_with_server("gateway.example.internal", 18790);
        let session = SessionId::new("sess-thread-42");
        p.project(&user_message("q", Some("teams")), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 1, 1), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let chat_attrs = attrs(chat_spans(&spans)[0]);

        assert_eq!(
            chat_attrs.get("client.address"),
            Some(&"0.0.0.0".to_string())
        );
        assert_eq!(
            chat_attrs.get("server.address"),
            Some(&"gateway.example.internal".to_string())
        );
        assert_eq!(chat_attrs.get("server.port"), Some(&"18790".to_string()));
        assert_eq!(
            chat_attrs.get("microsoft.channel.name"),
            Some(&"msteams".to_string())
        );
        assert_eq!(
            chat_attrs.get("gen_ai.conversation.id"),
            Some(&"sess-thread-42".to_string())
        );
        let root_attrs = attrs(root_span(&spans));
        assert_eq!(
            chat_attrs.get("microsoft.session.id"),
            root_attrs.get("microsoft.session.id"),
            "chat must share the run's microsoft.session.id with the root",
        );
    }

    #[test]
    fn chat_span_omits_root_only_attributes() {
        // Root-only attributes (gen_ai.input.messages,
        // gen_ai.output.messages, user.id) must not appear on chat
        // child spans. user.id specifically is mandatory on root
        // only; placing it on every span would multiply Defender
        // pivot results and confuse cross-span correlation.
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(
            &user_message_with_sender("q", Some("telegram"), Some("user-42")),
            &session,
            at(0),
            &[],
        );
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 1, 1), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let chat_attrs = attrs(chat_spans(&spans)[0]);
        assert!(!chat_attrs.contains_key("gen_ai.input.messages"));
        assert!(!chat_attrs.contains_key("gen_ai.output.messages"));
        assert!(!chat_attrs.contains_key("user.id"));
    }

    #[test]
    fn multiple_paired_llm_calls_produce_distinct_chat_spans_under_one_root() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 10, 5), &session, at(2), &[]);
        p.project(
            &llm_request("req-2", "anthropic", "sonnet"),
            &session,
            at(3),
            &[],
        );
        p.project(&llm_response("req-2", 20, 10), &session, at(4), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(5), &[]);

        let chats = chat_spans(&spans);
        assert_eq!(chats.len(), 2);
        assert_ne!(
            chats[0].span_id, chats[1].span_id,
            "each chat call mints a distinct span_id",
        );
        let root = root_span(&spans);
        assert_eq!(chats[0].trace_id, root.trace_id);
        assert_eq!(chats[1].trace_id, root.trace_id);
        assert_eq!(chats[0].parent_span_id.as_ref(), Some(&root.span_id));
        assert_eq!(chats[1].parent_span_id.as_ref(), Some(&root.span_id));
    }

    #[test]
    fn orphan_llm_response_with_no_matching_request_is_dropped() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(&llm_response("req-unknown", 1, 1), &session, at(1), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(2), &[]);
        assert!(chat_spans(&spans).is_empty());
    }

    #[test]
    fn unpaired_llm_request_at_run_close_is_dropped() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-orphan", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(2), &[]);
        // No chat span is produced for a request that never
        // paired with a response. The output_messages child and
        // the invoke_agent root still emit unconditionally.
        assert!(chat_spans(&spans).is_empty());
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn paired_tool_call_and_result_produce_one_execute_tool_span_parented_to_root() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("slack")), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{\"q\":\"hi\"}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "result body", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let tools = execute_tool_spans(&spans);
        assert_eq!(tools.len(), 1);
        let tool = tools[0];
        let root = root_span(&spans);
        assert_eq!(tool.kind, SpanKind::Internal);
        assert_eq!(tool.parent_span_id.as_ref(), Some(&root.span_id));
        assert_eq!(tool.trace_id, root.trace_id);
        assert_eq!(tool.start_time_unix_nano, 1_000_000_000);
        assert_eq!(tool.end_time_unix_nano, 2_000_000_000);
    }

    #[test]
    fn execute_tool_span_carries_tool_name_call_id_arguments_and_result() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-xyz", "web_search", "{\"q\":\"hi\"}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-xyz", "web_search", "ok body", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let a = attrs(execute_tool_spans(&spans)[0]);
        assert_eq!(a.get("tool.name"), Some(&"web_search".to_string()));
        assert_eq!(a.get("tool.call.id"), Some(&"call-xyz".to_string()));
        assert_eq!(
            a.get("tool.call.arguments"),
            Some(&"{\"q\":\"hi\"}".to_string())
        );
        assert_eq!(a.get("tool.call.result"), Some(&"ok body".to_string()));
    }

    #[test]
    fn execute_tool_span_carries_gen_ai_operation_name_execute_tool() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "ok", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(
            attrs(execute_tool_spans(&spans)[0]).get("gen_ai.operation.name"),
            Some(&"execute_tool".to_string())
        );
    }

    #[test]
    fn execute_tool_span_marks_function_tool_type_for_non_mcp_prefix() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "ok", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(
            attrs(execute_tool_spans(&spans)[0]).get("tool.type"),
            Some(&"function".to_string()),
            "non-mcp_ prefixed names dispatch in-process at the gateway; Defender derives ExecuteToolByGateway from tool.type=function",
        );
    }

    #[test]
    fn execute_tool_span_marks_mcp_server_tool_type_for_mcp_prefix() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "mcp_github_create_issue", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "mcp_github_create_issue", "ok", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(
            attrs(execute_tool_spans(&spans)[0]).get("tool.type"),
            Some(&"MCP Server".to_string()),
            "mcp_ prefixed names are routed to the MCP proxy at agent/src/runtime.rs::execute_tool; Defender derives ExecuteToolByMCPServer from tool.type=MCP Server",
        );
    }

    #[test]
    fn execute_tool_span_status_is_error_when_tool_result_success_is_false() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "boom", false),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(execute_tool_spans(&spans)[0].status, SpanStatus::Error);
    }

    #[test]
    fn execute_tool_span_status_is_ok_when_tool_result_success_is_true() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "ok", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(execute_tool_spans(&spans)[0].status, SpanStatus::Ok);
    }

    #[test]
    fn multiple_tool_calls_in_one_assistant_batch_produce_distinct_execute_tool_spans() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[
                ("call-1", "web_search", "{\"q\":\"a\"}"),
                ("call-2", "workspace_files", "{\"path\":\"x\"}"),
            ]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "r1", true),
            &session,
            at(2),
            &[],
        );
        p.project(
            &tool_result("call-2", "workspace_files", "r2", true),
            &session,
            at(3),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(4), &[]);
        let tools = execute_tool_spans(&spans);
        assert_eq!(tools.len(), 2);
        assert_ne!(tools[0].span_id, tools[1].span_id);
        let root = root_span(&spans);
        assert_eq!(tools[0].parent_span_id.as_ref(), Some(&root.span_id));
        assert_eq!(tools[1].parent_span_id.as_ref(), Some(&root.span_id));
        // tool.name comes from the AssistantToolCalls record, not
        // from the ToolResult, so each tool span carries the
        // distinct call's name.
        let a0 = attrs(tools[0]);
        let a1 = attrs(tools[1]);
        let names: Vec<&str> = [a0.get("tool.name"), a1.get("tool.name")]
            .iter()
            .filter_map(|o| o.map(String::as_str))
            .collect();
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"workspace_files"));
    }

    #[test]
    fn orphan_tool_result_with_no_matching_assistant_call_is_dropped() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &tool_result("call-unknown", "web_search", "result", true),
            &session,
            at(1),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(2), &[]);
        assert!(execute_tool_spans(&spans).is_empty());
    }

    #[test]
    fn unpaired_tool_call_at_run_close_is_dropped() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-orphan", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(2), &[]);
        assert!(execute_tool_spans(&spans).is_empty());
        // No execute_tool span emitted for the unpaired call; the
        // output_messages child and invoke_agent root still emit.
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn execute_tool_span_inherits_run_wide_attrs_from_root() {
        let mut p = projector_with_server("gateway.internal", 18790);
        let session = SessionId::new("sess-thread-7");
        p.project(&user_message("q", Some("teams")), &session, at(0), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(1),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "ok", true),
            &session,
            at(2),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        let tool_attrs = attrs(execute_tool_spans(&spans)[0]);
        let root_attrs = attrs(root_span(&spans));
        assert_eq!(
            tool_attrs.get("microsoft.channel.name"),
            Some(&"msteams".to_string())
        );
        assert_eq!(
            tool_attrs.get("server.address"),
            Some(&"gateway.internal".to_string())
        );
        assert_eq!(tool_attrs.get("server.port"), Some(&"18790".to_string()));
        assert_eq!(
            tool_attrs.get("gen_ai.conversation.id"),
            Some(&"sess-thread-7".to_string())
        );
        assert_eq!(
            tool_attrs.get("microsoft.session.id"),
            root_attrs.get("microsoft.session.id"),
        );
    }

    #[test]
    fn run_close_emits_output_messages_child_parented_to_root() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("final answer"), &session, at(1), &[]);
        let oms = output_messages_spans(&spans);
        assert_eq!(oms.len(), 1);
        let om = oms[0];
        let root = root_span(&spans);
        assert_eq!(om.parent_span_id.as_ref(), Some(&root.span_id));
        assert_eq!(om.trace_id, root.trace_id);
        assert_eq!(om.kind, SpanKind::Internal);
        assert_eq!(om.status, SpanStatus::Ok);
        // Instantaneous span: start equals end at the
        // AssistantMessage moment.
        assert_eq!(om.start_time_unix_nano, 1_000_000_000);
        assert_eq!(om.end_time_unix_nano, 1_000_000_000);
    }

    #[test]
    fn output_messages_span_carries_gen_ai_operation_name_output_messages() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        assert_eq!(
            attrs(output_messages_spans(&spans)[0]).get("gen_ai.operation.name"),
            Some(&"output_messages".to_string())
        );
    }

    #[test]
    fn output_messages_span_carries_gen_ai_output_messages_attribute() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(
            &assistant_message("final answer body"),
            &session,
            at(1),
            &[],
        );
        assert_eq!(
            attrs(output_messages_spans(&spans)[0]).get("gen_ai.output.messages"),
            Some(&"final answer body".to_string())
        );
    }

    #[test]
    fn output_messages_span_inherits_run_wide_attrs() {
        let mut p = projector_with_server("gateway.example.internal", 18790);
        let session = SessionId::new("sess-thread-99");
        let identity = vec![
            ("gen_ai.agent.id".to_string(), "agent-uuid".to_string()),
            ("microsoft.tenant.id".to_string(), "tenant-uuid".to_string()),
        ];
        p.project(
            &user_message("q", Some("teams")),
            &session,
            at(0),
            &identity,
        );
        let spans = p.project(&assistant_message("a"), &session, at(1), &identity);
        let om_attrs = attrs(output_messages_spans(&spans)[0]);
        assert_eq!(
            om_attrs.get("microsoft.channel.name"),
            Some(&"msteams".to_string())
        );
        assert_eq!(
            om_attrs.get("gen_ai.conversation.id"),
            Some(&"sess-thread-99".to_string())
        );
        assert!(om_attrs.contains_key("microsoft.session.id"));
        assert_eq!(
            om_attrs.get("gen_ai.agent.id"),
            Some(&"agent-uuid".to_string())
        );
        assert_eq!(
            om_attrs.get("microsoft.tenant.id"),
            Some(&"tenant-uuid".to_string())
        );
    }

    #[test]
    fn output_messages_span_omits_ia_et_ch_addressing_trio() {
        // output_messages is not in the IA/ET/CH set per the
        // verified reference; the addressing trio
        // (client.address, server.address, server.port) belongs
        // on the root, chat, and execute_tool spans only.
        let mut p = projector_with_server("gateway.example", 18790);
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("telegram")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let om_attrs = attrs(output_messages_spans(&spans)[0]);
        assert!(
            !om_attrs.contains_key("client.address"),
            "output_messages is outside the IA/ET/CH set; client.address must not be stamped",
        );
        assert!(!om_attrs.contains_key("server.address"));
        assert!(!om_attrs.contains_key("server.port"));
    }

    #[test]
    fn output_messages_span_omits_root_only_attributes() {
        // user.id is mandatory on invoke_agent only; the
        // input.messages attribute is also root-only (the output
        // message lives on both root and output_messages per the
        // verified reference, but the input lives only on root).
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(
            &user_message_with_sender("q", Some("telegram"), Some("user-42")),
            &session,
            at(0),
            &[],
        );
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let om_attrs = attrs(output_messages_spans(&spans)[0]);
        assert!(!om_attrs.contains_key("user.id"));
        assert!(!om_attrs.contains_key("gen_ai.input.messages"));
    }

    #[test]
    fn root_keeps_gen_ai_output_messages_alongside_output_messages_child() {
        // The verified OTel GenAI semconv reference treats
        // gen_ai.output.messages as mandatory on invoke_agent and
        // present on output_messages. The dedicated child is
        // additive to the root attribute, not a relocation.
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("final answer"), &session, at(1), &[]);
        let root_attrs = attrs(root_span(&spans));
        assert_eq!(
            root_attrs.get("gen_ai.output.messages"),
            Some(&"final answer".to_string()),
            "the invoke_agent root must keep gen_ai.output.messages even after the output_messages child is emitted",
        );
        let om_attrs = attrs(output_messages_spans(&spans)[0]);
        assert_eq!(
            om_attrs.get("gen_ai.output.messages"),
            Some(&"final answer".to_string()),
            "the output_messages child carries the same value",
        );
    }

    #[test]
    fn output_messages_span_emits_before_root_in_emit_order() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let om_pos = spans
            .iter()
            .position(|s| s.name == "output_messages")
            .unwrap();
        let root_pos = spans.iter().position(|s| s.name == "invoke_agent").unwrap();
        assert!(
            om_pos < root_pos,
            "output_messages must precede the invoke_agent root in emit order; root closes last",
        );
    }

    #[test]
    fn full_canonical_tree_emits_root_chat_execute_tool_and_output_messages() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 10, 5), &session, at(2), &[]);
        p.project(
            &assistant_tool_calls(&[("call-1", "web_search", "{}")]),
            &session,
            at(3),
            &[],
        );
        p.project(
            &tool_result("call-1", "web_search", "ok", true),
            &session,
            at(4),
            &[],
        );
        let spans = p.project(&assistant_message("final"), &session, at(5), &[]);

        assert_eq!(spans.iter().filter(|s| s.name == "invoke_agent").count(), 1);
        assert_eq!(spans.iter().filter(|s| s.name == "chat").count(), 1);
        assert_eq!(spans.iter().filter(|s| s.name == "execute_tool").count(), 1);
        assert_eq!(
            spans.iter().filter(|s| s.name == "output_messages").count(),
            1
        );

        let root = root_span(&spans);
        assert!(root.parent_span_id.is_none());
        for span in spans.iter().filter(|s| s.name != "invoke_agent") {
            assert_eq!(
                span.parent_span_id.as_ref(),
                Some(&root.span_id),
                "every non-root span must parent to the invoke_agent root: span name {}",
                span.name,
            );
            assert_eq!(span.trace_id, root.trace_id);
        }
    }

    #[test]
    fn tool_type_for_classifies_prefix_correctly() {
        assert_eq!(OtelProjector::tool_type_for("web_search"), "function");
        assert_eq!(OtelProjector::tool_type_for("workspace_files"), "function");
        assert_eq!(OtelProjector::tool_type_for("exec"), "function");
        assert_eq!(OtelProjector::tool_type_for("wasm_my_skill"), "function");
        assert_eq!(
            OtelProjector::tool_type_for("mcp_github_issue"),
            "MCP Server"
        );
        assert_eq!(OtelProjector::tool_type_for("mcp_x_y_z"), "MCP Server");
    }

    #[test]
    fn root_emits_last_after_all_chat_children() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(
            &llm_request("req-1", "anthropic", "sonnet"),
            &session,
            at(1),
            &[],
        );
        p.project(&llm_response("req-1", 1, 1), &session, at(2), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(3), &[]);
        assert_eq!(
            spans.last().map(|s| s.name.as_str()),
            Some("invoke_agent"),
            "root must be the last span in the emit Vec so consumers reading sequentially see children before the closing root",
        );
    }

    #[test]
    fn resolver_receives_none_for_adapter_less_run() {
        let recorder = Arc::new(RecordingUserResolver::new());
        let mut p = OtelProjector::new(OtelConfig::default(), recorder.clone());
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        p.project(&assistant_message("a"), &session, at(1), &[]);
        let captured = recorder
            .captured
            .lock()
            .expect("captured Mutex must not be poisoned");
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0],
            (None, None),
            "subagent and CLI runs have no adapter or sender; the resolver must receive None not a synthesized placeholder",
        );
    }
}
