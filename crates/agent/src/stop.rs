//! `wirken agents stop`: whether an agent is stopped, asked of the
//! permission store each time.

use std::sync::{Arc, Mutex};

use wirken_gateway::permissions::PermissionStore;

/// Whether `agent_id` is stopped. A store that cannot be read, or a
/// lock a panic poisoned, reads as stopped.
pub fn is_stopped(perms: &Arc<Mutex<PermissionStore>>, agent_id: &str) -> bool {
    match perms.lock() {
        Ok(store) => store.is_stopped(agent_id).unwrap_or(true),
        Err(_) => true,
    }
}

/// What the model reads when a sub-agent it spawned is stopped.
pub fn stopped_child_message(agent_id: &str) -> String {
    format!("Agent stopped: '{agent_id}' was stopped by the operator. This call was not completed.")
}

/// One watch per agent id that has run a turn in this process. A stop
/// bumps it, and every turn of that agent listening ends.
static TURNS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<String, tokio::sync::watch::Sender<u64>>>,
> = std::sync::LazyLock::new(Default::default);

fn turns_of(agent_id: &str) -> tokio::sync::watch::Sender<u64> {
    let mut turns = TURNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    turns
        .entry(agent_id.to_string())
        .or_insert_with(|| tokio::sync::watch::channel(0).0)
        .clone()
}

/// End every turn of `agent_id` running in this process. Returns how
/// many were listening.
pub fn cancel_turns(agent_id: &str) -> usize {
    let turns = turns_of(agent_id);
    let listening = turns.receiver_count();
    turns.send_modify(|generation| *generation += 1);
    listening
}

/// Run `turn` until it ends or [`cancel_turns`] is called for
/// `agent_id`, whichever is first; a cancelled turn is
/// `Err(AgentStopped)`. The turn is polled first, so a decision it was
/// woken with, such as a denial sent just before the cancel, is
/// recorded before it ends.
pub(crate) async fn until_stopped<T>(
    agent_id: Option<String>,
    turn: impl std::future::Future<Output = Result<T, crate::error::AgentError>>,
) -> Result<T, crate::error::AgentError> {
    let Some(agent_id) = agent_id else {
        return turn.await;
    };
    let mut cancelled = turns_of(&agent_id).subscribe();
    tokio::select! {
        biased;
        result = turn => result,
        _ = cancelled.changed() => Err(crate::error::AgentError::AgentStopped { agent_id }),
    }
}

#[cfg(test)]
mod tests {
    use super::{cancel_turns, until_stopped};
    use crate::error::AgentError;

    #[tokio::test]
    async fn a_cancel_ends_only_that_agents_turns() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let stopped = tokio::spawn(until_stopped(Some("stop-a".into()), async move {
            let _ = rx.await;
            Ok::<_, AgentError>("finished")
        }));
        let other = tokio::spawn(until_stopped(Some("stop-b".into()), async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok::<_, AgentError>("finished")
        }));
        tokio::task::yield_now().await;
        while cancel_turns("stop-a") == 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            stopped.await.unwrap(),
            Err(AgentError::AgentStopped { ref agent_id }) if agent_id == "stop-a"
        ));
        assert_eq!(other.await.unwrap().unwrap(), "finished");
        drop(tx);
    }

    #[tokio::test]
    async fn a_turn_woken_with_its_result_finishes_before_the_cancel() {
        let (tx, rx) = tokio::sync::oneshot::channel::<&'static str>();
        let turn = tokio::spawn(until_stopped(Some("stop-c".into()), async move {
            Ok::<_, AgentError>(rx.await.unwrap_or("dropped"))
        }));
        tokio::task::yield_now().await;
        tx.send("denied").unwrap();
        cancel_turns("stop-c");
        assert_eq!(turn.await.unwrap().unwrap(), "denied");
    }
}
