use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

/// Who triggered an audit event. Splits the pre-1.2.0 free-form
/// `actor: String` into a typed kind + an id so SIEM consumers can
/// group on `actor_kind` without parsing a free-text field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A human-equivalent identity: platform sender (Slack uid,
    /// Telegram user id, `webchat-user`), CLI operator, anything that
    /// is not the gateway, an agent, or a registered service.
    User,
    /// A running agent identified by its agent_id.
    Agent,
    /// A wirken-internal service: gateway, orchestrator, audit
    /// subsystem, webchat ingress.
    Service,
}

/// Known service literals that the pre-1.2.0 wire shape carried in the
/// `actor` field. Used by the back-compat deserializer to assign
/// [`ActorKind::Service`] to old rows; everything else maps to
/// [`ActorKind::User`] because the pre-1.2.0 inbound path put platform
/// sender ids in that field directly.
const SERVICE_LITERALS: &[&str] = &["gateway", "orchestrator", "audit", "webchat-user"];

fn classify_legacy_actor(actor: &str) -> ActorKind {
    if SERVICE_LITERALS.contains(&actor) {
        ActorKind::Service
    } else {
        ActorKind::User
    }
}

/// A single audit event to be logged.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Timestamp of the event.
    pub ts: DateTime<Utc>,
    /// Kind of the actor that triggered the event.
    pub actor_kind: ActorKind,
    /// Stable id of the actor (sender id, agent id, service literal).
    pub actor_id: String,
    /// Action performed (e.g., "exec", "message.send", "credential.access").
    pub action: String,
    /// Target of the action (e.g., file path, channel name, credential name).
    pub target: String,
    /// Channel the event is associated with. `None` for events that
    /// are not channel-scoped (gateway lifecycle, vault ops, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Session id. `None` for events outside a session context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Arbitrary JSON detail payload.
    pub detail: serde_json::Value,
}

/// Deserialize-side wire shape. Accepts both the 1.2.0+ form
/// (`actor_kind` + `actor_id`, `channel`/`session` as `Option`) and
/// the pre-1.2.0 form (single `actor: String`, empty strings on
/// `channel`/`session`). Old rows get a heuristic `actor_kind`
/// (`Service` for known service literals, `User` for everything else
/// — a misclassification on an old row is acceptable because the row
/// hashes are already sealed).
#[derive(Deserialize)]
struct AuditEventWire {
    ts: DateTime<Utc>,
    #[serde(default)]
    actor_kind: Option<ActorKind>,
    #[serde(default)]
    actor_id: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    action: String,
    target: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    detail: serde_json::Value,
}

impl<'de> Deserialize<'de> for AuditEvent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = AuditEventWire::deserialize(d)?;
        let (actor_kind, actor_id) = match (w.actor_kind, w.actor_id, w.actor) {
            (Some(kind), Some(id), _) => (kind, id),
            (Some(kind), None, Some(legacy)) => (kind, legacy),
            (Some(kind), None, None) => (kind, String::new()),
            (None, Some(id), _) => (classify_legacy_actor(&id), id),
            (None, None, Some(legacy)) => (classify_legacy_actor(&legacy), legacy),
            (None, None, None) => (ActorKind::Service, String::new()),
        };
        let channel = w.channel.filter(|s| !s.is_empty());
        let session = w.session.filter(|s| !s.is_empty());
        Ok(AuditEvent {
            ts: w.ts,
            actor_kind,
            actor_id,
            action: w.action,
            target: w.target,
            channel,
            session,
            detail: w.detail,
        })
    }
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(
        actor_kind: ActorKind,
        actor_id: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            ts: Utc::now(),
            actor_kind,
            actor_id: actor_id.into(),
            action: action.into(),
            target: target.into(),
            channel: None,
            session: None,
            detail: serde_json::Value::Null,
        }
    }

    /// Set the channel for this event.
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// Set the session for this event.
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    /// Set the detail payload for this event.
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = detail;
        self
    }
}

/// A stored audit event with its ID and hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    #[serde(flatten)]
    pub event: AuditEvent,
    pub hash: String,
}
