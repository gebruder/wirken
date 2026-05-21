//! Projects `SessionEvent` rows into OpenTelemetry GenAI spans for
//! the OTel exporter (`crate::otel_exporter`).
//!
//! ## Model
//!
//! The projector buffers spans per (session, run) until the run
//! terminates, then emits all spans for the run as a single batch.
//! "Root closes last" is a hard projector invariant: the
//! `invoke_agent` root span holds the run's input and output
//! messages and the run's duration, so it cannot emit until the
//! terminating `AssistantMessage` arrives. Children buffer alongside
//! it and emit in the same batch.
//!
//! Wirken processes each session sequentially (one inbound message
//! wakes the agent, runs to a final assistant message, terminates),
//! so a session has at most one in-flight run buffer at a time.
//!
//! ## Module status
//!
//! Second commit on issue #130. Lands the projector types
//! (`Span`, `TraceId`, `SpanId`, `SpanKind`, `SpanStatus`), the run
//! buffer, and the `invoke_agent` root projection driven by
//! `UserMessage` start and `AssistantMessage` close. Child span
//! projection (`chat`, `execute_tool`, `output_messages`, error,
//! agent-to-agent) lands in follow-up commits.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rand::TryRng;

use crate::otel_exporter::OtelConfig;
use crate::session_log::{SessionEvent, SessionId};

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
    runs: HashMap<SessionId, RunBuffer>,
}

impl OtelProjector {
    pub fn new(config: OtelConfig) -> Self {
        Self {
            config,
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
    /// returned by the active [`crate::FederatedIdentity`]. They are
    /// stamped on every span emitted in the run.
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
        let root =
            self.build_root_span(&buf, ended_at_nanos, assistant_message, identity_attributes);
        let mut emit = buf.children;
        emit.push(root);
        emit
    }

    fn build_root_span(
        &self,
        buf: &RunBuffer,
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
        ];
        if let Some(adapter) = &buf.adapter_id {
            let channel = self
                .config
                .channel_name_overrides
                .get(adapter)
                .cloned()
                .unwrap_or_else(|| adapter.clone());
            attributes.push(("microsoft.channel.name".to_string(), channel));
        }
        if let Some(sender) = &buf.sender_id {
            // Sender id is carried as a wirken-namespaced attribute
            // until the UserResolver lands in issue #132; that
            // ticket replaces this placeholder with `user.id`
            // resolved against the resolver precedence chain.
            attributes.push(("wirken.sender.id".to_string(), sender.clone()));
        }
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
}

fn datetime_to_unix_nanos(ts: DateTime<Utc>) -> u128 {
    let secs = ts.timestamp() as i128;
    let nanos = ts.timestamp_subsec_nanos() as i128;
    (secs * 1_000_000_000 + nanos) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn assistant_message(content: &str) -> SessionEvent {
        SessionEvent::AssistantMessage {
            content: content.to_string(),
            agent_id: "default".to_string(),
        }
    }

    fn projector() -> OtelProjector {
        OtelProjector::new(OtelConfig::default())
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
        let span = &spans[0];
        let op = span
            .attributes
            .iter()
            .find(|(k, _)| k == "gen_ai.operation.name")
            .expect("invoke_agent root must carry gen_ai.operation.name");
        assert_eq!(op.1, "invoke_agent");
    }

    #[test]
    fn root_span_carries_input_and_output_message_attributes() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("question text", None), &session, at(100), &[]);
        let spans = p.project(&assistant_message("answer text"), &session, at(101), &[]);
        let span = &spans[0];
        let input = span
            .attributes
            .iter()
            .find(|(k, _)| k == "gen_ai.input.messages")
            .map(|(_, v)| v.as_str());
        let output = span
            .attributes
            .iter()
            .find(|(k, _)| k == "gen_ai.output.messages")
            .map(|(_, v)| v.as_str());
        assert_eq!(input, Some("question text"));
        assert_eq!(output, Some("answer text"));
    }

    #[test]
    fn root_span_carries_client_address_placeholder_for_chat_callers() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("telegram")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let span = &spans[0];
        let client_addr = span
            .attributes
            .iter()
            .find(|(k, _)| k == "client.address")
            .map(|(_, v)| v.as_str());
        assert_eq!(client_addr, Some("0.0.0.0"));
    }

    #[test]
    fn teams_adapter_renames_channel_to_msteams_via_default_override() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("teams")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let channel = spans[0]
            .attributes
            .iter()
            .find(|(k, _)| k == "microsoft.channel.name")
            .map(|(_, v)| v.as_str());
        assert_eq!(channel, Some("msteams"));
    }

    #[test]
    fn non_teams_adapter_emits_literal_adapter_id_as_channel_name() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", Some("discord")), &session, at(0), &[]);
        let spans = p.project(&assistant_message("a"), &session, at(1), &[]);
        let channel = spans[0]
            .attributes
            .iter()
            .find(|(k, _)| k == "microsoft.channel.name")
            .map(|(_, v)| v.as_str());
        assert_eq!(channel, Some("discord"));
    }

    #[test]
    fn identity_attributes_append_to_root_span() {
        let mut p = projector();
        let session = SessionId::new("sess-1");
        p.project(&user_message("q", None), &session, at(0), &[]);
        let identity = vec![
            ("gen_ai.agent.id".to_string(), "agent-uuid".to_string()),
            ("microsoft.tenant.id".to_string(), "tenant-uuid".to_string()),
        ];
        let spans = p.project(&assistant_message("a"), &session, at(1), &identity);
        let attrs: HashMap<String, String> = spans[0].attributes.iter().cloned().collect();
        assert_eq!(
            attrs.get("gen_ai.agent.id"),
            Some(&"agent-uuid".to_string())
        );
        assert_eq!(
            attrs.get("microsoft.tenant.id"),
            Some(&"tenant-uuid".to_string())
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
        let input = spans[0]
            .attributes
            .iter()
            .find(|(k, _)| k == "gen_ai.input.messages")
            .map(|(_, v)| v.as_str());
        assert_eq!(input, Some("second"));
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
}
