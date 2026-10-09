//! Deprecated: adapter lifecycle events in the legacy SIEM shape.
//!
//! The gateway records an adapter's connection and restarts as typed
//! events, `adapter_connect`, `adapter_disconnect`, `adapter_restart`
//! and `adapter_restart_abandoned`, and the typed pipe forwards them.
//! They used to be legacy rows, `adapter.connect` and so on, which the
//! legacy pipe forwarded. A deployment that forwards only the legacy
//! pipe would otherwise stop hearing about its adapters, so while typed
//! forwarding is off this shim reads the four typed events off the
//! chain and forwards each in its old legacy shape.
//!
//! It writes nothing: the chain holds the typed events only. The typed
//! events are the supported path; the shim exists so a legacy-only
//! deployment keeps its adapter rows until it moves over.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::event::{ActorKind, AuditEvent};
use crate::session_log::{
    AdapterDisconnectReason, SessionEvent, SqliteSessionLog, StoredSessionEvent,
};
use crate::siem::{SiemConfig, SiemForwarder};

/// Rows read per pass.
const BATCH_LIMIT: i64 = 1000;

/// Whether `config` gets the shim: only when typed forwarding is off,
/// so a deployment never receives an adapter event in both shapes.
pub fn wanted(config: &SiemConfig) -> bool {
    !config.typed_forwarding_opted_in()
}

/// The legacy row a typed adapter lifecycle event used to be: the same
/// action, the adapter id as the target and in the detail, and the
/// detail fields the legacy row carried. `None` for every other event.
pub fn legacy_row(stored: &StoredSessionEvent) -> Option<AuditEvent> {
    let (action, adapter_id, channel, detail) = match &stored.event {
        SessionEvent::AdapterConnect {
            adapter_id,
            channel,
            pubkey_fingerprint,
        } => (
            "adapter.connect",
            adapter_id,
            channel,
            serde_json::json!({
                "adapter_id": adapter_id,
                "adapter_pubkey_fingerprint": pubkey_fingerprint,
            }),
        ),
        SessionEvent::AdapterDisconnect {
            adapter_id,
            channel,
            pubkey_fingerprint,
            reason,
        } => (
            "adapter.disconnect",
            adapter_id,
            channel,
            serde_json::json!({
                "adapter_id": adapter_id,
                "adapter_pubkey_fingerprint": pubkey_fingerprint,
                "reason": match reason {
                    AdapterDisconnectReason::Ended => "ended",
                    AdapterDisconnectReason::Panic => "panic",
                },
            }),
        ),
        SessionEvent::AdapterRestart {
            adapter_id,
            channel,
            attempt,
            cause,
            exit,
            delay_ms,
            connected_for_ms,
        } => (
            "adapter.restart",
            adapter_id,
            channel,
            serde_json::json!({
                "adapter_id": adapter_id,
                "attempt": attempt,
                "delay_ms": delay_ms,
                "cause": cause.as_str(),
                "exit": exit,
                "connected_ms": connected_for_ms,
            }),
        ),
        SessionEvent::AdapterRestartAbandoned {
            adapter_id,
            channel,
            attempts,
            last_cause,
            last_exit,
        } => (
            "adapter.restart_abandoned",
            adapter_id,
            channel,
            serde_json::json!({
                "adapter_id": adapter_id,
                "attempts": attempts,
                "last_cause": last_cause.as_str(),
                "last_exit": last_exit,
            }),
        ),
        _ => return None,
    };
    let mut row = AuditEvent::new(ActorKind::Service, "gateway", action, adapter_id)
        .with_channel(channel)
        .with_detail(detail);
    row.ts = stored.ts;
    Some(row)
}

/// One pass: read the rows after `cursor`, forward the lifecycle events
/// among them in the legacy shape, and move `cursor` past every row
/// read. A failed forward is logged by the forwarder and dropped, as
/// the legacy pipe drops a failed batch.
pub async fn run_one_pass(
    log: &SqliteSessionLog,
    forwarder: &SiemForwarder,
    cursor: &mut i64,
) -> Result<(), String> {
    let rows = log
        .get_events_after(*cursor, BATCH_LIMIT)
        .map_err(|e| format!("get_events_after start={cursor}: {e}"))?;
    let Some(last) = rows.last() else {
        return Ok(());
    };
    let new_high = last.id;
    let legacy: Vec<AuditEvent> = rows.iter().filter_map(legacy_row).collect();
    if !legacy.is_empty() {
        forwarder.forward(&legacy).await;
    }
    *cursor = new_high;
    Ok(())
}

/// The shim's worker. It forwards the lifecycle events written after
/// it starts, every `poll`, and once more when shut down, so the
/// disconnects written while the gateway stops still go out.
pub struct LegacyLifecycleShim {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl LegacyLifecycleShim {
    pub fn spawn(log: Arc<SqliteSessionLog>, forwarder: SiemForwarder, poll: Duration) -> Self {
        let (tx, mut rx) = oneshot::channel();
        // Events already on the chain went out before this start, by
        // this shim or as legacy rows, and are not sent again.
        let mut cursor = log.last_event_id().unwrap_or(0);
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(poll);
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        let _ = run_one_pass(&log, &forwarder, &mut cursor).await;
                        break;
                    }
                    _ = tick.tick() => {
                        if let Err(e) = run_one_pass(&log, &forwarder, &mut cursor).await {
                            tracing::warn!("legacy lifecycle shim pass failed: {e}");
                        }
                    }
                }
            }
        });
        Self {
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// Signal shutdown. The worker runs one last pass and exits.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Wait for the worker to exit. Call after [`Self::shutdown`].
    pub async fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_log::{
        ADAPTER_LIFECYCLE_SESSION, AdapterRestartCause, HashHex, SessionId, SessionLog, TrustLevel,
    };
    use crate::siem::SiemTarget;
    use std::sync::Mutex;

    fn lifecycle() -> Vec<SessionEvent> {
        vec![
            SessionEvent::AdapterConnect {
                adapter_id: "telegram".into(),
                channel: "telegram".into(),
                pubkey_fingerprint: "fp".into(),
            },
            SessionEvent::AdapterDisconnect {
                adapter_id: "telegram".into(),
                channel: "telegram".into(),
                pubkey_fingerprint: "fp".into(),
                reason: AdapterDisconnectReason::Panic,
            },
            SessionEvent::AdapterRestart {
                adapter_id: "telegram".into(),
                channel: "telegram".into(),
                attempt: 2,
                cause: AdapterRestartCause::ConnectionPanicked,
                exit: "signal: 9 (SIGKILL)".into(),
                delay_ms: 2000,
                connected_for_ms: Some(1500),
            },
            SessionEvent::AdapterRestartAbandoned {
                adapter_id: "telegram".into(),
                channel: "telegram".into(),
                attempts: 8,
                last_cause: AdapterRestartCause::ProcessExited,
                last_exit: "exit status: 3".into(),
            },
        ]
    }

    fn stored(event: SessionEvent) -> StoredSessionEvent {
        StoredSessionEvent {
            id: 1,
            session_id: SessionId::new(ADAPTER_LIFECYCLE_SESSION),
            seq: 0,
            ts: "2026-10-09T10:00:00Z".parse().unwrap(),
            trust: TrustLevel::System,
            event,
            leaf_hash: HashHex(String::new()),
            prev_hash: HashHex(String::new()),
            hash: HashHex(String::new()),
        }
    }

    /// Each typed event renders as the legacy row it used to be.
    #[test]
    fn each_lifecycle_event_renders_in_the_legacy_shape() {
        let rows: Vec<AuditEvent> = lifecycle()
            .into_iter()
            .map(|e| legacy_row(&stored(e)).unwrap())
            .collect();
        let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "adapter.connect",
                "adapter.disconnect",
                "adapter.restart",
                "adapter.restart_abandoned"
            ]
        );
        for row in &rows {
            assert_eq!(row.target, "telegram");
            assert_eq!(row.channel.as_deref(), Some("telegram"));
            assert_eq!(row.actor_id, "gateway");
            assert_eq!(row.detail["adapter_id"], "telegram");
            assert_eq!(row.ts.to_rfc3339(), "2026-10-09T10:00:00+00:00");
        }
        assert_eq!(rows[0].detail["adapter_pubkey_fingerprint"], "fp");
        assert_eq!(rows[1].detail["reason"], "panic");
        assert_eq!(rows[2].detail["attempt"], 2);
        assert_eq!(rows[2].detail["cause"], "connection_panicked");
        assert_eq!(rows[2].detail["exit"], "signal: 9 (SIGKILL)");
        assert_eq!(rows[2].detail["delay_ms"], 2000);
        assert_eq!(rows[2].detail["connected_ms"], 1500);
        assert_eq!(rows[3].detail["attempts"], 8);
        assert_eq!(rows[3].detail["last_cause"], "process_exited");
        assert_eq!(rows[3].detail["last_exit"], "exit status: 3");
    }

    #[test]
    fn any_other_event_has_no_legacy_shape() {
        let other = SessionEvent::UserMessage {
            content: "hi".into(),
            inbound_id: None,
            adapter_id: None,
            sender_id: None,
        };
        assert!(legacy_row(&stored(other)).is_none());
    }

    /// A webhook receiver on a loopback port that records each POST body.
    async fn receiver() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 8192];
                let body_start = loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break None;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(i + 4);
                    }
                };
                let Some(body_start) = body_start else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..body_start]).to_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                while request.len() < body_start + length {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                if let Ok(body) = serde_json::from_slice(&request[body_start..]) {
                    seen.lock().unwrap().push(body);
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        (endpoint, bodies)
    }

    fn webhook(endpoint: &str, typed: bool) -> SiemConfig {
        SiemConfig {
            target: SiemTarget::Webhook,
            endpoint: endpoint.into(),
            api_key: String::new(),
            service: "wirken".into(),
            environment: "test".into(),
            hmac_secret: None,
            sentinel_typed: None,
            typed_include_variants: None,
            typed_exclude_variants: None,
            typed_forwarding_enabled: typed.then_some(true),
            typed_poll_interval_ms: None,
        }
    }

    /// Run the pipes `config` gets, the way the gateway decides them,
    /// over a log the four events are written to after they start, and
    /// return every entry the receiver got.
    async fn delivered(typed: bool) -> Vec<serde_json::Value> {
        let (endpoint, bodies) = receiver().await;
        let config = webhook(&endpoint, typed);
        let log = Arc::new(SqliteSessionLog::open_in_memory().unwrap());

        let mut shim = wanted(&config).then(|| {
            LegacyLifecycleShim::spawn(
                log.clone(),
                SiemForwarder::new(config.clone()).unwrap(),
                Duration::from_secs(3600),
            )
        });
        let lane = log.handle_for(SessionId::new(ADAPTER_LIFECYCLE_SESSION));
        for event in lifecycle() {
            log.append(&lane, TrustLevel::System, event).unwrap();
        }
        if config.typed_forwarding_opted_in() {
            let sink = crate::siem_typed::HttpTypedSink::new(config.clone());
            let mut cursor = 0;
            crate::siem_typed::run_one_pass(&log, &sink, &config, &mut cursor)
                .await
                .unwrap();
        }
        if let Some(shim) = shim.as_mut() {
            // Shutdown runs the last pass, which sends what was written.
            shim.shutdown();
            shim.join().await;
        }

        let bodies = bodies.lock().unwrap().clone();
        bodies
            .into_iter()
            .flat_map(|b| b.as_array().cloned().unwrap_or_default())
            .collect()
    }

    #[tokio::test]
    async fn a_legacy_only_configuration_receives_the_old_shape() {
        let entries = delivered(false).await;
        let actions: Vec<&str> = entries
            .iter()
            .filter_map(|e| e["action"].as_str())
            .collect();
        assert_eq!(
            actions,
            [
                "adapter.connect",
                "adapter.disconnect",
                "adapter.restart",
                "adapter.restart_abandoned"
            ],
            "{entries:?}"
        );
        for entry in &entries {
            assert_eq!(entry["target"], "telegram");
            assert_eq!(entry["detail"]["adapter_id"], "telegram");
            assert!(entry.get("kind").is_none(), "no typed entry: {entry}");
        }
        assert_eq!(entries[1]["detail"]["reason"], "panic");
        assert_eq!(entries[2]["detail"]["attempt"], 2);
        assert_eq!(entries[3]["detail"]["attempts"], 8);
    }

    #[tokio::test]
    async fn a_typed_configuration_receives_the_typed_events_only() {
        let entries = delivered(true).await;
        let kinds: Vec<&str> = entries.iter().filter_map(|e| e["kind"].as_str()).collect();
        assert_eq!(
            kinds,
            [
                "adapter_connect",
                "adapter_disconnect",
                "adapter_restart",
                "adapter_restart_abandoned"
            ],
            "{entries:?}"
        );
        for entry in &entries {
            assert!(entry.get("action").is_none(), "no legacy shape: {entry}");
        }
    }
}
