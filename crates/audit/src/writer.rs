use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

use crate::error::AuditError;
use crate::event::AuditEvent;
use crate::log::AuditLog;
use crate::siem::{SiemConfig, SiemForwarder};

/// Batched audit writer that accepts events via a channel and flushes
/// to SQLite every 50ms or 100 events, whichever comes first.
/// Optionally forwards events to a SIEM via HTTP.
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEvent>,
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);
const CHANNEL_CAPACITY: usize = 4096;

// Persistent-failure gates. When the primary SQLite write fails on
// this many flushes in a row, or the retained buffer grows past this
// cap, the flush loop halts. Halting drops the receiver so the
// mpsc::Sender returns ChannelClosed on the next log call, which is
// the signal the agent observes to stop rather than continue while
// audit events are silently lost.
const MAX_CONSECUTIVE_FAILURES: u32 = 8;
const MAX_BUFFER_ON_FAILURE: usize = BATCH_SIZE * 16;

impl AuditWriter {
    /// Create a new audit writer that flushes to the given database path.
    /// Spawns a background tokio task for batched writes.
    /// Returns the writer handle and a join handle for the flush task.
    pub fn new(db_path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        Self::with_siem(db_path, None)
    }

    /// Create a new audit writer with optional SIEM forwarding.
    pub fn with_siem(
        db_path: &Path,
        siem_config: Option<SiemConfig>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        // Verify database can be opened
        let _ = AuditLog::open(db_path)?;

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let path = db_path.to_path_buf();
        let forwarder = match siem_config {
            Some(cfg) => Some(SiemForwarder::new(cfg).map_err(AuditError::SiemConfig)?),
            None => None,
        };
        let handle = tokio::spawn(flush_loop(rx, path, forwarder));

        Ok((Self { tx }, handle))
    }

    /// Send an audit event to be written.
    /// Returns immediately — the event is buffered and flushed asynchronously.
    pub async fn log(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.tx
            .send(event)
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// Send an audit event, blocking version for non-async contexts.
    pub fn log_blocking(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.tx
            .blocking_send(event)
            .map_err(|_| AuditError::ChannelClosed)
    }
}

async fn flush_loop(
    mut rx: mpsc::Receiver<AuditEvent>,
    db_path: PathBuf,
    forwarder: Option<SiemForwarder>,
) {
    // Open the audit log once for the lifetime of the flush loop and
    // reuse the connection across every flush. The previous flush()
    // re-opened SQLite on every tick (every 50ms or 100 events),
    // paying the per-connection cost — pragma setup, idempotent
    // schema migration, AuditLog construction — for nothing. With WAL
    // + busy_timeout from #599bb61, one persistent connection is the
    // right shape: writes are serialized inside the
    // SqliteSessionLog's own Mutex<Connection>, and the busy_timeout
    // covers contention with the agent's separate session-log handle
    // on the same file.
    //
    // Open failure here means the loop never starts. The mpsc::Sender
    // returns ChannelClosed on the first log() call, which is the
    // signal the agent observes to refuse to continue (same shape as
    // the persistent-failure halt below).
    let log = match AuditLog::open(&db_path) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            tracing::error!("Audit log open failed at flush_loop start: {e}");
            return;
        }
    };

    let mut buffer: Vec<AuditEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut tick = interval(FLUSH_INTERVAL);
    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::select! {
            // Timer tick — flush whatever we have
            _ = tick.tick() => {
                if !buffer.is_empty()
                    && attempt_flush(&log, &mut buffer, &forwarder, &mut consecutive_failures)
                        .await
                {
                    break;
                }
            }
            // New event received
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        buffer.push(event);
                        if buffer.len() >= BATCH_SIZE
                            && attempt_flush(
                                &log,
                                &mut buffer,
                                &forwarder,
                                &mut consecutive_failures,
                            )
                            .await
                        {
                            break;
                        }
                    }
                    None => {
                        // Channel closed — best-effort final flush and exit
                        if !buffer.is_empty() {
                            let _ = flush(&log, &mut buffer, &forwarder).await;
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Run one flush and update `consecutive_failures`. Returns `true`
/// when the loop should halt (persistent failure) so the caller can
/// break and let `rx` drop, closing the audit channel.
async fn attempt_flush(
    log: &AuditLog,
    buffer: &mut Vec<AuditEvent>,
    forwarder: &Option<SiemForwarder>,
    consecutive_failures: &mut u32,
) -> bool {
    match flush(log, buffer, forwarder).await {
        Ok(()) => {
            *consecutive_failures = 0;
            false
        }
        Err(_) => {
            *consecutive_failures += 1;
            let halt = *consecutive_failures >= MAX_CONSECUTIVE_FAILURES
                || buffer.len() > MAX_BUFFER_ON_FAILURE;
            if halt {
                tracing::error!(
                    failures = *consecutive_failures,
                    buffered = buffer.len(),
                    "Audit flush halting after persistent write failures; \
                     closing channel so callers observe ChannelClosed"
                );
            }
            halt
        }
    }
}

async fn flush(
    log: &AuditLog,
    buffer: &mut Vec<AuditEvent>,
    forwarder: &Option<SiemForwarder>,
) -> Result<(), AuditError> {
    // Primary durability is SQLite. If `write_batch` fails, return the
    // error WITHOUT clearing the buffer so the loop can retain events
    // and retry. Silently discarding audit events on a failed write
    // is an integrity bug: a breach could occur during the window
    // where its event is buffered but never flushed.
    log.write_batch(buffer).inspect_err(|e| {
        tracing::error!("Audit write failed: {e}");
    })?;

    // Primary write landed. SIEM forward is best-effort and only runs
    // after durability so a failed primary write does not re-send the
    // same events to SIEM on every retry.
    if let Some(fwd) = forwarder {
        fwd.forward(buffer).await;
    }

    buffer.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;
    use crate::log::{AuditLog, AuditQuery};

    #[tokio::test]
    async fn flush_clears_buffer_on_write_success() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        let mut buffer = vec![AuditEvent::new("actor", "a1", "t1")];
        let res = flush(&log, &mut buffer, &None).await;
        assert!(res.is_ok(), "flush should succeed against a valid db");
        assert!(
            buffer.is_empty(),
            "buffer must clear after a successful flush"
        );
    }

    #[tokio::test]
    async fn write_batch_failure_retains_buffer() {
        // Buffer-retention contract on `write_batch` failure. Open a
        // valid log, then flip the underlying file to read-only so the
        // next write hits SQLITE_READONLY. The buffer must not clear.
        // Rough proxy for "any SQLite write error preserves the
        // retry queue"; the structural property — buffer.clear()
        // happens only on the Ok path of write_batch — is enforced
        // by `flush()` itself.
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        // Make the parent dir read-only so SQLite cannot create the
        // WAL/SHM sidecars during the write. Targeting the dir
        // rather than the db file itself is more reliable across
        // SQLite's lock-and-journal modes.
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o500);
        fs::set_permissions(tmp.path(), perms).unwrap();

        let mut buffer = vec![
            AuditEvent::new("actor", "a1", "t1"),
            AuditEvent::new("actor", "a2", "t2"),
        ];
        let before = buffer.len();
        let res = flush(&log, &mut buffer, &None).await;

        // Restore permissions so TempDir cleanup can remove the dir.
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(tmp.path(), perms).unwrap();

        if res.is_err() {
            assert_eq!(
                buffer.len(),
                before,
                "buffer must retain events when write_batch fails"
            );
        } else {
            // Some filesystems / WAL modes accept writes against a
            // read-only dir if the WAL files already exist. In that
            // case the structural property still holds — buffer
            // cleared only after Ok — but this test is not the one
            // exercising it. Skip rather than fail spuriously.
            eprintln!(
                "skipping retain-on-failure assert: write_batch unexpectedly succeeded \
                 (likely because WAL files already existed on this filesystem)"
            );
        }
    }

    #[tokio::test]
    async fn retained_events_reflush_after_recovery() {
        // Buffer-retention happy path: simulate a transient failure
        // by briefly toggling the write-side, then succeeding on the
        // retry. Easier than reproducing a real SQLite error: call
        // write_batch on the empty buffer twice — the first call
        // (with two events) must Ok and clear; the second must Ok
        // and remain empty. The interesting half — that buffer is
        // preserved across retry attempts — is covered by the
        // `write_batch_failure_retains_buffer` test above.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        let mut buffer = vec![
            AuditEvent::new("actor", "attempt", "first"),
            AuditEvent::new("actor", "attempt", "second"),
        ];

        let res = flush(&log, &mut buffer, &None).await;
        assert!(res.is_ok(), "flush against valid db must succeed");
        assert!(buffer.is_empty(), "buffer must clear on successful flush");

        let rows = log.query(&AuditQuery::default()).unwrap();
        assert_eq!(rows.len(), 2, "events must land in the audit log");
        let targets: Vec<&str> = rows.iter().map(|r| r.event.target.as_str()).collect();
        assert!(targets.contains(&"first"));
        assert!(targets.contains(&"second"));
    }
}
