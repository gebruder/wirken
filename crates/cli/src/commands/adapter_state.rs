//! An adapter's connection state as the audit log records it.
//!
//! The gateway records each adapter's lifecycle as typed events on the
//! `gateway-adapters` lane: `adapter_connect`, `adapter_disconnect`,
//! `adapter_restart` and `adapter_restart_abandoned`, each naming its
//! adapter. Logs written before those events existed hold the same four
//! as legacy rows (`adapter.connect` and so on, with the adapter id as
//! the target), and both are read: the newest row per adapter, of either
//! shape, is its state. Row ids are global, so newest is highest id.
//!
//! The gateway's own `gateway.start` and `gateway.stop` rows bound it: a
//! gateway row newer than an adapter's last row means that adapter has
//! not connected since, whatever its last row says, which covers a stop
//! whose disconnect row was lost on the way out.
//!
//! Read from the log, not from the gateway: the registry's `connected`
//! flag lives in the gateway's memory and reads `false` in any other
//! process. A gateway killed without a `gateway.stop` row leaves its
//! last recorded states standing.

use std::collections::HashMap;

use chrono::{DateTime, SecondsFormat, Utc};
use wirken_audit::{AuditError, SessionEvent, SqliteSessionLog, StoredEvent};

/// The typed lifecycle events, by kind.
const LIFECYCLE_KINDS: [&str; 4] = [
    "adapter_connect",
    "adapter_disconnect",
    "adapter_restart",
    "adapter_restart_abandoned",
];

/// The same four as legacy rows, in logs written before the typed
/// events.
const LEGACY_LIFECYCLE_ACTIONS: [&str; 4] = [
    "adapter.connect",
    "adapter.disconnect",
    "adapter.restart",
    "adapter.restart_abandoned",
];

/// The rows that record the gateway starting and stopping.
const GATEWAY_ACTIONS: [&str; 2] = ["gateway.start", "gateway.stop"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterState {
    Connected,
    Disconnected {
        since: DateTime<Utc>,
    },
    Restarting {
        attempt: u64,
    },
    Abandoned {
        attempts: u64,
    },
    /// No lifecycle row for this adapter.
    NoRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterStatus {
    pub state: AdapterState,
    /// When the row the state comes from was written.
    pub recorded_at: Option<DateTime<Utc>>,
}

impl AdapterStatus {
    const NO_RECORD: Self = Self {
        state: AdapterState::NoRecord,
        recorded_at: None,
    };

    /// The state as `wirken channel list` and the webchat status show
    /// it.
    pub fn label(&self) -> String {
        match &self.state {
            AdapterState::Connected => "connected".into(),
            AdapterState::Disconnected { since } => format!("disconnected (since {})", ts(since)),
            AdapterState::Restarting { attempt } => format!("restarting (attempt {attempt})"),
            AdapterState::Abandoned { attempts } => format!("abandoned (attempts {attempts})"),
            AdapterState::NoRecord => "no record".into(),
        }
    }

    /// When the state was recorded, or `-` for no record.
    pub fn recorded(&self) -> String {
        self.recorded_at
            .as_ref()
            .map(ts)
            .unwrap_or_else(|| "-".into())
    }

    pub fn is_connected(&self) -> bool {
        self.state == AdapterState::Connected
    }
}

fn ts(at: &DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// One adapter's newest lifecycle row, of either shape: its row id,
/// when it was written, and the state it records.
#[derive(Debug, Clone)]
struct Recorded {
    id: i64,
    at: DateTime<Utc>,
    state: AdapterState,
}

impl Recorded {
    /// A typed lifecycle event, with the adapter it names.
    fn typed(id: i64, at: DateTime<Utc>, event: &SessionEvent) -> Option<(String, Self)> {
        let (adapter_id, state) = match event {
            SessionEvent::AdapterConnect { adapter_id, .. } => {
                (adapter_id, AdapterState::Connected)
            }
            SessionEvent::AdapterDisconnect { adapter_id, .. } => {
                (adapter_id, AdapterState::Disconnected { since: at })
            }
            SessionEvent::AdapterRestart {
                adapter_id,
                attempt,
                ..
            } => (adapter_id, AdapterState::Restarting { attempt: *attempt }),
            SessionEvent::AdapterRestartAbandoned {
                adapter_id,
                attempts,
                ..
            } => (
                adapter_id,
                AdapterState::Abandoned {
                    attempts: u64::from(*attempts),
                },
            ),
            _ => return None,
        };
        Some((adapter_id.clone(), Self { id, at, state }))
    }

    /// A legacy lifecycle row, whose target is the adapter.
    fn legacy(row: &StoredEvent) -> (String, Self) {
        let count = |field: &str| row.event.detail[field].as_u64().unwrap_or(0);
        let at = row.event.ts;
        let state = match row.event.action.as_str() {
            "adapter.connect" => AdapterState::Connected,
            "adapter.restart" => AdapterState::Restarting {
                attempt: count("attempt"),
            },
            "adapter.restart_abandoned" => AdapterState::Abandoned {
                attempts: count("attempts"),
            },
            _ => AdapterState::Disconnected { since: at },
        };
        (
            row.event.target.clone(),
            Self {
                id: row.id,
                at,
                state,
            },
        )
    }
}

/// Every adapter's status recorded in `log`, by adapter id.
pub struct AdapterStatuses {
    by_adapter: HashMap<String, Recorded>,
    gateway: Option<StoredEvent>,
}

impl AdapterStatuses {
    pub fn read(log: &SqliteSessionLog) -> Result<Self, AuditError> {
        let mut by_adapter: HashMap<String, Recorded> = HashMap::new();
        let mut keep_newest = |adapter_id: String, recorded: Recorded| {
            let newer = by_adapter
                .get(&adapter_id)
                .is_none_or(|held| recorded.id > held.id);
            if newer {
                by_adapter.insert(adapter_id, recorded);
            }
        };
        for row in log.latest_legacy_per_target(&LEGACY_LIFECYCLE_ACTIONS)? {
            let (adapter_id, recorded) = Recorded::legacy(&row);
            keep_newest(adapter_id, recorded);
        }
        for row in log.latest_events_per_field(&LIFECYCLE_KINDS, "adapter_id")? {
            if let Some((adapter_id, recorded)) = Recorded::typed(row.id, row.ts, &row.event) {
                keep_newest(adapter_id, recorded);
            }
        }
        let gateway = log
            .latest_legacy_per_target(&GATEWAY_ACTIONS)?
            .into_iter()
            .max_by_key(|row| row.id);
        Ok(Self {
            by_adapter,
            gateway,
        })
    }

    /// No rows at all, for a log that cannot be opened.
    pub fn none() -> Self {
        Self {
            by_adapter: HashMap::new(),
            gateway: None,
        }
    }

    /// The statuses recorded in the audit log at `db`. A log that does
    /// not exist yet is not created; it, or one that cannot be read,
    /// reads as no record for every adapter.
    pub fn read_path(db: &std::path::Path) -> Self {
        if !db.exists() {
            return Self::none();
        }
        SqliteSessionLog::open(db)
            .ok()
            .and_then(|log| Self::read(&log).ok())
            .unwrap_or_else(Self::none)
    }

    pub fn of(&self, adapter_id: &str) -> AdapterStatus {
        let Some(recorded) = self.by_adapter.get(adapter_id) else {
            return AdapterStatus::NO_RECORD;
        };
        if let Some(gateway) = &self.gateway
            && gateway.id > recorded.id
        {
            return AdapterStatus {
                state: AdapterState::Disconnected {
                    since: gateway.event.ts,
                },
                recorded_at: Some(gateway.event.ts),
            };
        }
        AdapterStatus {
            state: recorded.state.clone(),
            recorded_at: Some(recorded.at),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wirken_audit::{
        ADAPTER_LIFECYCLE_SESSION, ActorKind, AdapterDisconnectReason, AdapterRestartCause,
        SessionId, SessionLog, TrustLevel,
    };

    /// One row of a fixture log: a typed lifecycle event, or a legacy row
    /// as logs written before the typed events hold them.
    pub(crate) enum Row {
        Typed(Box<SessionEvent>),
        Legacy(&'static str, &'static str, serde_json::Value),
    }

    pub(crate) fn connect(adapter: &str) -> Row {
        Row::Typed(Box::new(SessionEvent::AdapterConnect {
            adapter_id: adapter.into(),
            channel: adapter.into(),
            pubkey_fingerprint: "fp".into(),
        }))
    }

    pub(crate) fn disconnect(adapter: &str) -> Row {
        Row::Typed(Box::new(SessionEvent::AdapterDisconnect {
            adapter_id: adapter.into(),
            channel: adapter.into(),
            pubkey_fingerprint: "fp".into(),
            reason: AdapterDisconnectReason::Ended,
        }))
    }

    pub(crate) fn restart(adapter: &str, attempt: u64) -> Row {
        Row::Typed(Box::new(SessionEvent::AdapterRestart {
            adapter_id: adapter.into(),
            channel: adapter.into(),
            attempt,
            cause: AdapterRestartCause::ConnectionEnded,
            exit: "signal: 9 (SIGKILL)".into(),
            delay_ms: 1000,
            connected_for_ms: Some(10),
        }))
    }

    pub(crate) fn abandoned(adapter: &str, attempts: u32) -> Row {
        Row::Typed(Box::new(SessionEvent::AdapterRestartAbandoned {
            adapter_id: adapter.into(),
            channel: adapter.into(),
            attempts,
            last_cause: AdapterRestartCause::ProcessExited,
            last_exit: "exit status: 3".into(),
        }))
    }

    fn gateway(action: &'static str) -> Row {
        Row::Legacy(action, "daemon", serde_json::json!({}))
    }

    /// A log under a temporary directory holding `rows` in order, read
    /// back as `wirken channel list` reads it.
    pub(crate) async fn statuses(rows: Vec<Row>) -> AdapterStatuses {
        let tmp = tempfile::TempDir::new().unwrap();
        let log = SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap();
        let lane = log.handle_for(SessionId::new(ADAPTER_LIFECYCLE_SESSION));
        let system = log.handle_for(SessionId::new("system"));
        for row in rows {
            match row {
                Row::Typed(event) => {
                    log.append(&lane, TrustLevel::System, *event).unwrap();
                }
                Row::Legacy(action, target, detail) => {
                    log.append(
                        &system,
                        TrustLevel::System,
                        SessionEvent::AuditLegacy {
                            actor_kind: ActorKind::Service,
                            actor_id: "gateway".into(),
                            action: action.into(),
                            target: target.into(),
                            channel: None,
                            detail,
                        },
                    )
                    .unwrap();
                }
            }
        }
        AdapterStatuses::read(&log).unwrap()
    }

    #[tokio::test]
    async fn each_row_sequence_reads_as_its_state() {
        let s = statuses(vec![
            connect("telegram"),
            connect("slack"),
            disconnect("slack"),
            connect("discord"),
            disconnect("discord"),
            restart("discord", 2),
            restart("matrix", 7),
            abandoned("matrix", 8),
            Row::Legacy("message.inbound", "signal", serde_json::json!({})),
        ])
        .await;

        assert_eq!(s.of("telegram").label(), "connected");
        let slack = s.of("slack");
        let since = slack.recorded();
        assert_eq!(slack.label(), format!("disconnected (since {since})"));
        assert!(since.ends_with('Z') && since.len() == 20, "{since}");
        assert_eq!(s.of("discord").label(), "restarting (attempt 2)");
        assert_eq!(s.of("matrix").label(), "abandoned (attempts 8)");
        assert_eq!(s.of("signal").label(), "no record");
        assert_eq!(s.of("signal").recorded(), "-");
        assert!(s.of("telegram").is_connected());
        assert!(!s.of("slack").is_connected());
    }

    /// A log written before the typed events, then by a gateway that
    /// writes them: the newest row of either shape decides, so an
    /// existing log keeps reading.
    #[tokio::test]
    async fn legacy_rows_followed_by_typed_events_read_as_the_newest() {
        let s = statuses(vec![
            Row::Legacy("adapter.connect", "telegram", serde_json::json!({})),
            Row::Legacy("adapter.connect", "slack", serde_json::json!({})),
            Row::Legacy("adapter.disconnect", "slack", serde_json::json!({})),
            Row::Legacy(
                "adapter.restart",
                "matrix",
                serde_json::json!({"attempt": 3}),
            ),
            Row::Legacy("adapter.connect", "discord", serde_json::json!({})),
            // The upgraded gateway's typed events.
            disconnect("telegram"),
            connect("slack"),
            abandoned("matrix", 8),
        ])
        .await;
        assert!(s.of("telegram").label().starts_with("disconnected (since "));
        assert_eq!(s.of("slack").label(), "connected");
        assert_eq!(s.of("matrix").label(), "abandoned (attempts 8)");
        // Only a legacy row for discord: it still reads.
        assert_eq!(s.of("discord").label(), "connected");
    }

    /// The other order cannot happen on one log, but the rule is the
    /// same: the higher row id wins, whatever its shape.
    #[tokio::test]
    async fn a_legacy_row_newer_than_a_typed_event_still_wins() {
        let s = statuses(vec![
            connect("telegram"),
            Row::Legacy(
                "adapter.restart",
                "telegram",
                serde_json::json!({"attempt": 5}),
            ),
        ])
        .await;
        assert_eq!(s.of("telegram").label(), "restarting (attempt 5)");
    }

    #[tokio::test]
    async fn a_gateway_stop_after_the_last_row_reads_as_disconnected() {
        let s = statuses(vec![
            gateway("gateway.start"),
            connect("telegram"),
            gateway("gateway.stop"),
        ])
        .await;
        let status = s.of("telegram");
        assert_eq!(
            status.label(),
            format!("disconnected (since {})", status.recorded())
        );
    }

    #[tokio::test]
    async fn a_gateway_start_with_no_connect_since_reads_as_disconnected() {
        let s = statuses(vec![connect("telegram"), gateway("gateway.start")]).await;
        assert!(s.of("telegram").label().starts_with("disconnected (since "));
    }

    #[tokio::test]
    async fn a_connect_after_the_gateway_start_reads_as_connected() {
        let s = statuses(vec![
            gateway("gateway.stop"),
            gateway("gateway.start"),
            connect("telegram"),
        ])
        .await;
        assert_eq!(s.of("telegram").label(), "connected");
    }
}
