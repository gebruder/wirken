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

use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::task::JoinSet;

#[derive(Clone, Default)]
pub struct ConnectionTasks {
    set: Arc<Mutex<JoinSet<()>>>,
}

impl ConnectionTasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `task` as a tracked connection task. Tasks that have already
    /// finished are reaped first, so the set holds only live ones.
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut set = self.set.lock().unwrap();
        while set.try_join_next().is_some() {}
        set.spawn(task);
    }

    /// Abort every tracked task and wait until each has stopped. A
    /// task stops at its next await, so when this returns none of them
    /// is running.
    pub async fn shutdown(&self) {
        let mut set = std::mem::take(&mut *self.set.lock().unwrap());
        set.abort_all();
        while set.join_next().await.is_some() {}
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.set.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_stops_a_task_that_would_never_finish() {
        let tasks = ConnectionTasks::new();
        let ran_past_wait = Arc::new(AtomicBool::new(false));
        let flag = ran_past_wait.clone();
        tasks.spawn(async move {
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
        let tasks = ConnectionTasks::new();
        let held = Arc::new(());
        let clone = held.clone();
        tasks.spawn(async move {
            let _clone = clone;
            std::future::pending::<()>().await;
        });
        tasks.shutdown().await;
        assert_eq!(Arc::strong_count(&held), 1);
    }

    #[tokio::test]
    async fn finished_tasks_are_reaped_on_the_next_spawn() {
        let tasks = ConnectionTasks::new();
        for _ in 0..3 {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            tasks.spawn(async move {
                let _ = tx.send(());
            });
            rx.await.unwrap();
            tokio::task::yield_now().await;
        }
        tasks.spawn(std::future::pending::<()>());
        assert_eq!(tasks.tracked(), 1, "only the live task is kept");
        tasks.shutdown().await;
    }
}
