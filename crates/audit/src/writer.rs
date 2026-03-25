use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

use crate::error::AuditError;
use crate::event::AuditEvent;
use crate::log::AuditLog;

/// Batched audit writer that accepts events via a channel and flushes
/// to SQLite every 50ms or 100 events, whichever comes first.
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEvent>,
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);
const CHANNEL_CAPACITY: usize = 4096;

impl AuditWriter {
    /// Create a new audit writer that flushes to the given database path.
    /// Spawns a background tokio task for batched writes.
    /// Returns the writer handle and a join handle for the flush task.
    pub fn new(db_path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        // Verify database can be opened
        let _ = AuditLog::open(db_path)?;

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let path = db_path.to_path_buf();
        let handle = tokio::spawn(flush_loop(rx, path));

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

async fn flush_loop(mut rx: mpsc::Receiver<AuditEvent>, db_path: PathBuf) {
    let mut buffer: Vec<AuditEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut tick = interval(FLUSH_INTERVAL);

    loop {
        tokio::select! {
            // Timer tick — flush whatever we have
            _ = tick.tick() => {
                if !buffer.is_empty() {
                    flush(&db_path, &mut buffer);
                }
            }
            // New event received
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        buffer.push(event);
                        if buffer.len() >= BATCH_SIZE {
                            flush(&db_path, &mut buffer);
                        }
                    }
                    None => {
                        // Channel closed — flush remaining and exit
                        if !buffer.is_empty() {
                            flush(&db_path, &mut buffer);
                        }
                        break;
                    }
                }
            }
        }
    }
}

fn flush(db_path: &Path, buffer: &mut Vec<AuditEvent>) {
    match AuditLog::open(db_path) {
        Ok(log) => {
            if let Err(e) = log.write_batch(buffer) {
                tracing::error!("Audit flush failed: {e}");
                // Events are lost on flush failure — acceptable per spec
            }
        }
        Err(e) => {
            tracing::error!("Audit log open failed: {e}");
        }
    }
    buffer.clear();
}
