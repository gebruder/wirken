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
//! Active development on issue #130. The `invoke_agent` root span
//! carries its full mandatory all-span attribute set:
//! `gen_ai.operation.name`, input and output message bodies,
//! `client.address`, `server.address`, `server.port`,
//! `microsoft.channel.name` (with the `internal` fallback for
//! adapter-less runs), `gen_ai.conversation.id`,
//! `microsoft.session.id` as a per-wake UUIDv4, `user.id` via the
//! [`crate::UserResolver`], plus whatever the active
//! [`crate::FederatedIdentity::span_attributes`] returns
//! (`microsoft.tenant.id`, `gen_ai.agent.id`, `gen_ai.agent.name`,
//! `microsoft.a365.agent.blueprint.id`). Child span projection
//! (`chat`, `execute_tool`, `output_messages`, error-status,
//! agent-to-agent) lands in follow-up commits.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::TryRng;

use crate::otel_exporter::OtelConfig;
use crate::session_log::{SessionEvent, SessionId};
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
    children: Vec<Span>,
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
            // Child span variants (LlmRequest/LlmResponse for chat,
            // AssistantToolCalls/ToolResult for execute_tool,
            // SubagentSpawned for agent-to-agent, PermissionDenied
            // for error status) project in follow-up commits on
            // issue #130.
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
            children: Vec::new(),
        };
        if self.runs.insert(session_id.clone(), buf).is_some() {
            tracing::warn!(
                session_id = %session_id,
                "OtelProjector dropped an in-flight run buffer because a fresh UserMessage opened a new run before the prior AssistantMessage closed it",
            );
        }
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

        let ended_at_nanos = datetime_to_unix_nanos(timestamp);
        let root = self.build_root_span(
            &buf,
            session_id,
            ended_at_nanos,
            assistant_message,
            identity_attributes,
        );
        let mut emit = buf.children;
        emit.push(root);
        emit
    }

    fn build_root_span(
        &self,
        buf: &RunBuffer,
        session_id: &SessionId,
        ended_at_nanos: u128,
        assistant_message: &str,
        identity_attributes: &[(String, String)],
    ) -> Span {
        // `client.address` placeholder for chat-platform callers
        // without a network address. The documented fallback is a
        // literal `0.0.0.0`; this applies to every wirken adapter
        // except direct HTTP callers.
        let mut attributes: Vec<(String, String)> = vec![
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
            ("client.address".to_string(), "0.0.0.0".to_string()),
            (
                "server.address".to_string(),
                self.config.server_address.clone(),
            ),
            (
                "server.port".to_string(),
                self.config.server_port.to_string(),
            ),
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
            (
                "user.id".to_string(),
                self.user_resolver
                    .resolve_user(buf.adapter_id.as_deref(), buf.sender_id.as_deref())
                    .as_str()
                    .to_string(),
            ),
        ];
        attributes.extend(identity_attributes.iter().cloned());

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
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
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
            attrs(&spans[0]).get("gen_ai.operation.name"),
            Some(&"invoke_agent".to_string())
        );
    }

    #[test]
    fn root_span_carries_input_and_output_message_attributes() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("question text", None), &session, at(100), &[]);
        let spans = p.project(&assistant_message("answer text"), &session, at(101), &[]);
        let a = attrs(&spans[0]);
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
            attrs(&spans[0]).get("client.address"),
            Some(&"0.0.0.0".to_string())
        );
    }

    #[test]
    fn root_span_carries_server_address_and_port_from_config_as_strings() {
        let mut p = projector_with_server("gateway.example.internal", 18790);
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let a = attrs(&spans[0]);
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
        let user_id = attrs(&spans[0])
            .get("user.id")
            .cloned()
            .expect("root must carry user.id");
        // Deterministic resolver produces a UUIDv4-shape string.
        assert_eq!(user_id.len(), 36);
        // No wirken-namespaced fallback should remain on the root.
        assert!(
            !attrs(&spans[0]).contains_key("wirken.sender.id"),
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
            attrs(&spans[0]).get("gen_ai.input.messages"),
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
