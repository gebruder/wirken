//! An adapter's connection state as the audit log records it.
//!
//! The gateway records each adapter's lifecycle as legacy rows:
//! `adapter.connect`, `adapter.disconnect`, `adapter.restart` and
//! `adapter.restart_abandoned`, each with the adapter id as its target.
//! The newest of those rows per adapter is its state. The gateway's own
//! `gateway.start` and `gateway.stop` rows bound it: a gateway row newer
//! than an adapter's last row means that adapter has not connected
//! since, whatever its last row says, which covers a stop whose
//! `adapter.disconnect` row was lost on the way out.
//!
//! Read from the log, not from the gateway: the registry's `connected`
//! flag lives in the gateway's memory and reads `false` in any other
//! process. A gateway killed without a `gateway.stop` row leaves its
//! last recorded states standing.

use std::collections::HashMap;

use chrono::{DateTime, SecondsFormat, Utc};
use wirken_audit::{AuditError, SqliteSessionLog, StoredEvent};

/// The rows that record an adapter's connection, newest wins.
const LIFECYCLE_ACTIONS: [&str; 4] = [
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

/// Every adapter's status recorded in `log`, by adapter id.
pub struct AdapterStatuses {
    by_adapter: HashMap<String, StoredEvent>,
    gateway: Option<StoredEvent>,
}

impl AdapterStatuses {
    pub fn read(log: &SqliteSessionLog) -> Result<Self, AuditError> {
        let by_adapter = log
            .latest_legacy_per_target(&LIFECYCLE_ACTIONS)?
            .into_iter()
            .map(|row| (row.event.target.clone(), row))
            .collect();
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
        let Some(row) = self.by_adapter.get(adapter_id) else {
            return AdapterStatus::NO_RECORD;
        };
        if let Some(gateway) = &self.gateway
            && gateway.id > row.id
        {
            return AdapterStatus {
                state: AdapterState::Disconnected {
                    since: gateway.event.ts,
                },
                recorded_at: Some(gateway.event.ts),
            };
        }
        let count = |field: &str| row.event.detail[field].as_u64().unwrap_or(0);
        let state = match row.event.action.as_str() {
            "adapter.connect" => AdapterState::Connected,
            "adapter.restart" => AdapterState::Restarting {
                attempt: count("attempt"),
            },
            "adapter.restart_abandoned" => AdapterState::Abandoned {
                attempts: count("attempts"),
            },
            _ => AdapterState::Disconnected {
                since: row.event.ts,
            },
        };
        AdapterStatus {
            state,
            recorded_at: Some(row.event.ts),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    use wirken_audit::{ActorKind, AuditEvent, AuditWriter};

    /// A log under a temporary directory holding `rows`, written through
    /// the audit writer as the gateway writes them, then read back.
    pub(crate) async fn statuses(rows: &[(&str, &str, serde_json::Value)]) -> AdapterStatuses {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let (writer, handle) = AuditWriter::new(&db).unwrap();
        let writer = Arc::new(writer);
        for (action, target, detail) in rows {
            writer
                .log(
                    AuditEvent::new(ActorKind::Service, "gateway", *action, *target)
                        .with_detail(detail.clone()),
                )
                .await
                .unwrap();
        }
        drop(writer);
        handle.await.unwrap();
        AdapterStatuses::read(&SqliteSessionLog::open(&db).unwrap()).unwrap()
    }

    fn none() -> serde_json::Value {
        serde_json::json!({})
    }

    #[tokio::test]
    async fn each_row_sequence_reads_as_its_state() {
        let s = statuses(&[
            ("adapter.connect", "telegram", none()),
            ("adapter.connect", "slack", none()),
            ("adapter.disconnect", "slack", none()),
            ("adapter.connect", "discord", none()),
            ("adapter.disconnect", "discord", none()),
            (
                "adapter.restart",
                "discord",
                serde_json::json!({"attempt": 2}),
            ),
            (
                "adapter.restart",
                "matrix",
                serde_json::json!({"attempt": 7}),
            ),
            (
                "adapter.restart_abandoned",
                "matrix",
                serde_json::json!({"attempts": 8}),
            ),
            ("message.inbound", "signal", none()),
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

    #[tokio::test]
    async fn a_gateway_stop_after_the_last_row_reads_as_disconnected() {
        let s = statuses(&[
            ("gateway.start", "daemon", none()),
            ("adapter.connect", "telegram", none()),
            ("gateway.stop", "daemon", none()),
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
        let s = statuses(&[
            ("adapter.connect", "telegram", none()),
            ("gateway.start", "daemon", none()),
        ])
        .await;
        assert!(s.of("telegram").label().starts_with("disconnected (since "));
    }

    #[tokio::test]
    async fn a_connect_after_the_gateway_start_reads_as_connected() {
        let s = statuses(&[
            ("gateway.stop", "daemon", none()),
            ("gateway.start", "daemon", none()),
            ("adapter.connect", "telegram", none()),
        ])
        .await;
        assert_eq!(s.of("telegram").label(), "connected");
    }
}
