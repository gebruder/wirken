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
//! A task that panics is recorded as it unwinds: each connection future
//! runs under `catch_unwind` inside its own task, and a panic becomes an
//! error log line and a `connection.panic` row carrying the kind of
//! connection, the adapter id once the connection has authenticated as
//! one, where the panic was raised, and the length and SHA-256 of its
//! message. The message itself is never recorded: a slicing panic quotes
//! the string it was slicing, which can be message text. Reaping a
//! finished task, on the next spawn and at shutdown, records any panic
//! that got past the catch.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex, Once, OnceLock};
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use tokio::task::{Id, JoinError, JoinSet};
use wirken_audit::{ActorKind, AuditEvent, AuditWriter};

/// Where each panic in a tokio task was raised, by task id. The hook
/// [`install_panic_location_hook`] installs fills it; recording a panic
/// takes the entry.
static PANIC_LOCATIONS: LazyLock<Mutex<HashMap<Id, String>>> = LazyLock::new(Mutex::default);

/// Panics in tasks this module never reaps leave their entries behind.
/// Past this many the map is cleared rather than left to grow.
const PANIC_LOCATIONS_MAX: usize = 256;

/// Chain a hook in front of the current panic hook that notes where a
/// panic inside a tokio task was raised. The previous hook still runs,
/// so the panic is reported on stderr as before. Installed once per
/// process.
fn install_panic_location_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let (Some(id), Some(location)) = (tokio::task::try_id(), info.location()) {
                let mut map = PANIC_LOCATIONS.lock().unwrap_or_else(|e| e.into_inner());
                if map.len() >= PANIC_LOCATIONS_MAX {
                    map.clear();
                }
                map.insert(
                    id,
                    format!(
                        "{}:{}",
                        source_path_without_build_prefix(location.file()),
                        location.line()
                    ),
                );
            }
            previous(info);
        }));
    });
}

/// The adapter id an adapter connection authenticates as, set by the
/// connection once its handshake has passed, so a panic after that names
/// the adapter.
pub type AdapterIdSlot = Arc<OnceLock<String>>;

#[derive(Clone)]
pub struct ConnectionTasks {
    set: Arc<Mutex<JoinSet<()>>>,
    /// The kind of connection each live task serves, by task id.
    kinds: Arc<Mutex<HashMap<Id, &'static str>>>,
    audit: Arc<AuditWriter>,
}

impl ConnectionTasks {
    pub fn new(audit: Arc<AuditWriter>) -> Self {
        install_panic_location_hook();
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
        self.spawn_recording(kind, None, task);
    }

    /// [`Self::spawn`] for an adapter connection, which fills `adapter_id`
    /// once it knows who it is talking to.
    pub fn spawn_adapter<F>(&self, adapter_id: AdapterIdSlot, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_recording("adapter", Some(adapter_id), task);
    }

    fn spawn_recording<F>(&self, kind: &'static str, adapter_id: Option<AdapterIdSlot>, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let audit = self.audit.clone();
        let task = async move {
            let Err(payload) = CatchUnwind(Box::pin(task)).await else {
                return;
            };
            let location = take_panic_location(tokio::task::id());
            let adapter_id = adapter_id.and_then(|slot| slot.get().cloned());
            let event = PanicFacts::of(location, payload.as_ref()).event(kind, adapter_id);
            if let Err(e) = audit.log(event).await {
                tracing::error!("connection.panic audit write failed: {e}");
            }
        };
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
        let location = take_panic_location(id);
        let err = result.err()?;
        if !err.is_panic() {
            return None;
        }
        let facts = PanicFacts::of(location, err.into_panic().as_ref());
        Some(facts.event(kind, None))
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.set.lock().unwrap().len()
    }
}

/// Take the location the panic hook noted for a panic in task `id`.
fn take_panic_location(id: Id) -> Option<String> {
    PANIC_LOCATIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
}

/// A future that resolves to `Err` with the payload of a panic raised
/// while polling `F`, instead of unwinding out of the task.
struct CatchUnwind<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, Box<dyn Any + Send>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.as_mut();
        // Unwind-safe in the sense that matters: after a panic the inner
        // future is never polled again, only dropped.
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// What is recorded about a panic: where it was raised and the length
/// and SHA-256 of its message, never the message.
struct PanicFacts {
    location: Option<String>,
    payload_len: Option<usize>,
    payload_sha256: Option<String>,
}

impl PanicFacts {
    /// A payload that is not a string, which `panic_any` can raise, has
    /// no length or digest.
    fn of(location: Option<String>, payload: &(dyn Any + Send)) -> Self {
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        Self {
            location,
            payload_len: message.map(str::len),
            payload_sha256: message.map(|m| {
                Sha256::digest(m.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            }),
        }
    }

    /// Log the panic and build its `connection.panic` row. The row's
    /// target is the adapter id when there is one, else the kind.
    fn event(&self, kind: &'static str, adapter_id: Option<String>) -> AuditEvent {
        tracing::error!(
            kind,
            adapter_id = adapter_id.as_deref().unwrap_or("none"),
            location = self.location.as_deref().unwrap_or("unknown"),
            payload_len = self.payload_len,
            payload_sha256 = self.payload_sha256.as_deref().unwrap_or("none"),
            "connection task panicked"
        );
        let target = adapter_id.clone().unwrap_or_else(|| kind.to_string());
        AuditEvent::new(ActorKind::Service, "gateway", "connection.panic", &target).with_detail(
            serde_json::json!({
                "kind": kind,
                "adapter_id": adapter_id,
                "location": self.location,
                "payload_len": self.payload_len,
                "payload_sha256": self.payload_sha256,
            }),
        )
    }
}

/// A source path as a panic location reports it, without the part that
/// names the machine it was built on. A workspace path is relative
/// already. A dependency's path starts with the builder's Cargo home and
/// is cut to the crate directory; a standard library path is cut to
/// `library/`. Any other absolute path keeps its file name only.
fn source_path_without_build_prefix(file: &str) -> String {
    let path = file.replace('\\', "/");
    let absolute = path.starts_with('/') || path.get(1..3) == Some(":/");
    if !absolute {
        return path;
    }
    for marker in ["/.cargo/registry/src/", "/.cargo/git/checkouts/"] {
        if let Some((_, rest)) = path.split_once(marker) {
            // The first component is the registry index or the checkout
            // name, which is build-machine state; the crate follows it.
            if let Some((_, from_crate)) = rest.split_once('/') {
                return from_crate.to_string();
            }
        }
    }
    if let Some((_, rest)) = path.split_once("/library/") {
        return format!("library/{rest}");
    }
    path.rsplit('/').next().unwrap_or_default().to_string()
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
    async fn a_panicked_task_is_recorded() {
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
        assert_eq!(rows[0].detail["payload_len"].as_u64(), Some(9));
        assert_eq!(
            rows[0].detail["payload_sha256"].as_str(),
            Some(sha256_hex("boom at 7").as_str())
        );
        let location = rows[0].detail["location"].as_str().unwrap();
        assert!(
            location.starts_with("crates/cli/src/commands/connection_tasks.rs:"),
            "{location}"
        );
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
        assert_eq!(rows[0].detail["payload_len"].as_u64(), Some(14));
    }

    /// The panic row is written as the task unwinds, ahead of anything
    /// that happens on any connection afterwards. A row written only when
    /// the task is reaped would come after the event below, which no
    /// spawn precedes.
    #[tokio::test]
    async fn a_webchat_panic_is_on_the_chain_before_the_next_connection_event() {
        let (tasks, tmp, handle) = new_tasks();
        let audit = tasks.audit.clone();
        tasks.spawn("webchat", async { panic!("request handler panicked") });
        tokio::time::sleep(Duration::from_millis(100)).await;
        audit
            .log(AuditEvent::new(
                ActorKind::Service,
                "gateway",
                "adapter.connect",
                "telegram",
            ))
            .await
            .unwrap();
        drop(audit);
        tasks.shutdown().await;
        drop(tasks);
        handle.await.unwrap();

        let mut rows = AuditLog::open(&tmp.path().join("audit.db"))
            .unwrap()
            .query(&AuditQuery::default())
            .unwrap();
        rows.sort_by_key(|r| r.id);
        let actions: Vec<&str> = rows.iter().map(|r| r.event.action.as_str()).collect();
        assert_eq!(
            actions,
            ["connection.panic", "adapter.connect"],
            "{actions:?}"
        );
        assert_eq!(rows[0].event.detail["kind"].as_str(), Some("webchat"));
    }

    #[tokio::test]
    async fn an_adapter_panic_names_the_adapter_once_it_is_known() {
        let (tasks, tmp, handle) = new_tasks();
        let slot = AdapterIdSlot::default();
        let known = slot.clone();
        tasks.spawn_adapter(slot, async move {
            known.set("telegram".to_string()).unwrap();
            panic!("message loop panicked");
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        tasks.shutdown().await;
        drop(tasks);
        handle.await.unwrap();

        let rows = panic_rows(&tmp);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].target, "telegram");
        assert_eq!(rows[0].detail["kind"].as_str(), Some("adapter"));
        assert_eq!(rows[0].detail["adapter_id"].as_str(), Some("telegram"));
    }

    fn sha256_hex(s: &str) -> String {
        Sha256::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Nothing the panic said reaches the log: not in a row, not in the
    /// database files on disk.
    #[tokio::test]
    async fn a_panic_message_never_reaches_the_audit_log() {
        const MARKER: &str = "MARKER-7f3a9c-panic-text";
        let (tasks, tmp, handle) = new_tasks();
        tasks.spawn("webchat", async {
            panic!("slicing failed inside `{MARKER}` of a message");
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        tasks.shutdown().await;
        drop(tasks);
        handle.await.unwrap();

        let rows = AuditLog::open(&tmp.path().join("audit.db"))
            .unwrap()
            .query(&AuditQuery::default())
            .unwrap();
        assert!(rows.iter().any(|r| r.event.action == "connection.panic"));
        for row in &rows {
            let json = serde_json::to_string(&row.event).unwrap();
            assert!(!json.contains(MARKER), "{json}");
        }
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "the marker is in a file under the audit directory"
            );
        }
    }

    #[test]
    fn a_non_string_payload_has_no_length_or_digest() {
        let facts = PanicFacts::of(None, &42u32);
        assert!(facts.payload_len.is_none());
        assert!(facts.payload_sha256.is_none());
    }

    #[test]
    fn a_location_keeps_no_build_machine_path() {
        assert_eq!(
            source_path_without_build_prefix("crates/agent/src/slash.rs"),
            "crates/agent/src/slash.rs"
        );
        assert_eq!(
            source_path_without_build_prefix(
                "/home/someone/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/teloxide-0.17.0/src/lib.rs"
            ),
            "teloxide-0.17.0/src/lib.rs"
        );
        assert_eq!(
            source_path_without_build_prefix(
                "/home/someone/.cargo/git/checkouts/tinfoil-rs-0a1b2c/abc1234/src/client.rs"
            ),
            "abc1234/src/client.rs"
        );
        assert_eq!(
            source_path_without_build_prefix("/rustc/b940084d7/library/core/src/str/mod.rs"),
            "library/core/src/str/mod.rs"
        );
        assert_eq!(
            source_path_without_build_prefix("C:\\Users\\someone\\build\\x.rs"),
            "x.rs"
        );
        assert_eq!(
            source_path_without_build_prefix("/home/someone/elsewhere/y.rs"),
            "y.rs"
        );
    }
}
