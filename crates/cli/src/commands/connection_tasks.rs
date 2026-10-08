//! The per-connection tasks `wirken run` spawns, held so shutdown can
//! stop them.
//!
//! Each accept loop hands every accepted connection to a task of its
//! own: an adapter's message loop, a webchat request, an orchestrator
//! push, a permissions or hooks caller. Aborting the accept loop stops
//! new connections and leaves those tasks running, so a turn in flight
//! kept appending to its session after shutdown had sealed it, and kept
//! the process alive until the turn ended.
//!
//! Spawned through [`ConnectionTasks::spawn`], they are aborted and
//! waited out by [`ConnectionTasks::shutdown`]. Shutdown calls it after
//! the accept loops are stopped and before the session chains are
//! sealed, so nothing appends after a seal.
//!
//! A task that panics is recorded when it is reaped: an error log line
//! and a `connection.panic` row carrying the kind of connection and the
//! panic message. Reaping happens on the next spawn and at shutdown, so
//! the row follows the panic by as long as the next connection takes
//! to arrive.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::task::{Id, JoinError, JoinSet};
use wirken_audit::{ActorKind, AuditEvent, AuditWriter};

/// Longest panic message, in bytes, carried into the audit row. A
/// slicing panic quotes the string it was slicing, which can be message
/// text; the bound keeps one panic from writing an arbitrary amount of
/// it to the chain.
const PANIC_MESSAGE_MAX: usize = 512;

#[derive(Clone)]
pub struct ConnectionTasks {
    set: Arc<Mutex<JoinSet<()>>>,
    /// The kind of connection each live task serves, by task id.
    kinds: Arc<Mutex<HashMap<Id, &'static str>>>,
    audit: Arc<AuditWriter>,
}

impl ConnectionTasks {
    pub fn new(audit: Arc<AuditWriter>) -> Self {
        Self {
            set: Arc::default(),
            kinds: Arc::default(),
            audit,
        }
    }

    /// Run `task` as a tracked connection task serving a connection of
    /// `kind`. Tasks that have already finished are reaped first, so the
    /// set holds only live ones, and any that panicked are recorded.
    pub fn spawn<F>(&self, kind: &'static str, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut set = self.set.lock().unwrap();
        while let Some(result) = set.try_join_next_with_id() {
            if let Some(event) = self.reaped(result) {
                let audit = self.audit.clone();
                tokio::spawn(async move {
                    if let Err(e) = audit.log(event).await {
                        tracing::error!("connection.panic audit write failed: {e}");
                    }
                });
            }
        }
        let id = set.spawn(task).id();
        self.kinds.lock().unwrap().insert(id, kind);
    }

    /// Abort every tracked task and wait until each has stopped. A
    /// task stops at its next await, so when this returns none of them
    /// is running. A task that had already panicked is recorded.
    pub async fn shutdown(&self) {
        let mut set = std::mem::take(&mut *self.set.lock().unwrap());
        set.abort_all();
        while let Some(result) = set.join_next_with_id().await {
            if let Some(event) = self.reaped(result)
                && let Err(e) = self.audit.log(event).await
            {
                tracing::error!("connection.panic audit write failed: {e}");
            }
        }
    }

    /// Forget a reaped task's kind and, if it panicked, log the panic
    /// and return the row that records it. A task aborted by shutdown
    /// is not a panic and returns nothing.
    fn reaped(&self, result: Result<(Id, ()), JoinError>) -> Option<AuditEvent> {
        let id = match &result {
            Ok((id, ())) => *id,
            Err(e) => e.id(),
        };
        let kind = self.kinds.lock().unwrap().remove(&id).unwrap_or("unknown");
        let err = result.err()?;
        if !err.is_panic() {
            return None;
        }
        let message = panic_message(err.into_panic());
        tracing::error!(kind, "connection task panicked: {message}");
        Some(
            AuditEvent::new(ActorKind::Service, "gateway", "connection.panic", kind).with_detail(
                serde_json::json!({
                    "kind": kind,
                    "panic": message,
                }),
            ),
        )
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.set.lock().unwrap().len()
    }
}

/// The message a panic was raised with, cut to [`PANIC_MESSAGE_MAX`]
/// bytes at a character boundary.
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    let full = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        return "<panic payload is not a string>".to_string();
    };
    let cut = full.floor_char_boundary(PANIC_MESSAGE_MAX);
    full.get(..cut).unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use wirken_audit::{AuditLog, AuditQuery};

    /// Tasks recording into an audit log under a temporary directory.
    /// The directory and the writer's flush task come back so a test
    /// can read the rows once everything holding the writer is gone.
    fn new_tasks() -> (
        ConnectionTasks,
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let (writer, handle) = AuditWriter::new(&tmp.path().join("audit.db")).unwrap();
        (ConnectionTasks::new(Arc::new(writer)), tmp, handle)
    }

    /// The `connection.panic` rows in the log under `tmp`.
    fn panic_rows(tmp: &tempfile::TempDir) -> Vec<AuditEvent> {
        AuditLog::open(&tmp.path().join("audit.db"))
            .unwrap()
            .query(&AuditQuery::default())
            .unwrap()
            .into_iter()
            .map(|e| e.event)
            .filter(|e| e.action == "connection.panic")
            .collect()
    }

    #[tokio::test]
    async fn shutdown_stops_a_task_that_would_never_finish() {
        let (tasks, _tmp, _flush) = new_tasks();
        let ran_past_wait = Arc::new(AtomicBool::new(false));
        let flag = ran_past_wait.clone();
        tasks.spawn("test", async move {
            std::future::pending::<()>().await;
            flag.store(true, Ordering::SeqCst);
        });
        tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
            .await
            .expect("shutdown returns");
        assert!(!ran_past_wait.load(Ordering::SeqCst));
        assert_eq!(tasks.tracked(), 0);
    }

    #[tokio::test]
    async fn shutdown_waits_until_the_task_has_stopped() {
        // A task holding a clone of something shutdown later drops
        // must have released it by the time shutdown returns: that is
        // what lets the audit writer flush.
        let (tasks, _tmp, _flush) = new_tasks();
        let held = Arc::new(());
        let clone = held.clone();
        tasks.spawn("test", async move {
            let _clone = clone;
            std::future::pending::<()>().await;
        });
        tasks.shutdown().await;
        assert_eq!(Arc::strong_count(&held), 1);
    }

    #[tokio::test]
    async fn finished_tasks_are_reaped_on_the_next_spawn() {
        let (tasks, _tmp, _flush) = new_tasks();
        for _ in 0..3 {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            tasks.spawn("test", async move {
                let _ = tx.send(());
            });
            rx.await.unwrap();
            tokio::task::yield_now().await;
        }
        tasks.spawn("test", std::future::pending::<()>());
        assert_eq!(tasks.tracked(), 1, "only the live task is kept");
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn a_panicked_task_is_recorded_when_reaped() {
        let (tasks, tmp, handle) = new_tasks();
        tasks.spawn("adapter", async { panic!("boom at {}", 7) });
        // Let the panicking task run to completion, then reap it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        tasks.spawn("webchat", async {});
        tasks.shutdown().await;
        // The spawn-time row goes through a task of its own.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(tasks);
        handle.await.unwrap();

        let rows = panic_rows(&tmp);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].target, "adapter");
        assert_eq!(rows[0].detail["kind"].as_str(), Some("adapter"));
        assert_eq!(rows[0].detail["panic"].as_str(), Some("boom at 7"));
    }

    #[tokio::test]
    async fn a_panic_before_shutdown_is_recorded_and_an_abort_is_not() {
        let (tasks, tmp, handle) = new_tasks();
        tasks.spawn("hooks", async { panic!("static message") });
        tasks.spawn("webchat", std::future::pending::<()>());
        tokio::time::sleep(Duration::from_millis(50)).await;
        tasks.shutdown().await;
        drop(tasks);
        handle.await.unwrap();

        let rows = panic_rows(&tmp);
        assert_eq!(rows.len(), 1, "the aborted task is not a panic: {rows:?}");
        assert_eq!(rows[0].detail["kind"].as_str(), Some("hooks"));
        assert_eq!(rows[0].detail["panic"].as_str(), Some("static message"));
    }

    #[test]
    fn a_long_panic_message_is_cut_at_a_character_boundary() {
        let long = format!(
            "{}\u{e9}{}",
            "a".repeat(PANIC_MESSAGE_MAX - 1),
            "b".repeat(100)
        );
        let cut = panic_message(Box::new(long));
        assert_eq!(cut, "a".repeat(PANIC_MESSAGE_MAX - 1));
        assert_eq!(
            panic_message(Box::new(42u32)),
            "<panic payload is not a string>"
        );
    }
}
