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
