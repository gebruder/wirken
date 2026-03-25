use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit event to be logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp of the event.
    pub ts: DateTime<Utc>,
    /// Actor that triggered the event (client ID, adapter name, etc.).
    pub actor: String,
    /// Action performed (e.g., "exec", "message.send", "credential.access").
    pub action: String,
    /// Target of the action (e.g., file path, channel name, credential name).
    pub target: String,
    /// Channel the event is associated with (empty string if not channel-specific).
    pub channel: String,
    /// Session ID (empty string if not session-specific).
    pub session: String,
    /// Arbitrary JSON detail payload.
    pub detail: serde_json::Value,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            ts: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            channel: String::new(),
            session: String::new(),
            detail: serde_json::Value::Null,
        }
    }

    /// Set the channel for this event.
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    /// Set the session for this event.
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = session.into();
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
