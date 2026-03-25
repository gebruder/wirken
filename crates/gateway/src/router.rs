use std::sync::RwLock;

use crate::error::GatewayError;

/// A routing binding: maps a channel + optional conversation pattern to an agent.
#[derive(Debug, Clone)]
pub struct RouteBinding {
    /// Channel identifier (e.g., "telegram", "discord").
    pub channel: String,
    /// Conversation ID pattern. "*" matches all conversations on this channel.
    pub conversation_pattern: String,
    /// Agent ID to route to.
    pub agent_id: String,
}

/// Routes inbound messages to the correct agent based on channel and conversation.
pub struct Router {
    bindings: RwLock<Vec<RouteBinding>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            bindings: RwLock::new(Vec::new()),
        }
    }

    /// Add a routing binding.
    pub fn bind(&self, binding: RouteBinding) {
        self.bindings.write().unwrap().push(binding);
    }

    /// Remove all bindings for a channel.
    pub fn unbind_channel(&self, channel: &str) {
        self.bindings
            .write()
            .unwrap()
            .retain(|b| b.channel != channel);
    }

    /// Resolve which agent should handle a message from a given channel + conversation.
    /// Checks specific conversation matches first, then wildcard "*" bindings.
    pub fn resolve(&self, channel: &str, conversation_id: &str) -> Result<String, GatewayError> {
        let bindings = self.bindings.read().unwrap();

        // First pass: exact conversation match
        for binding in bindings.iter() {
            if binding.channel == channel && binding.conversation_pattern == conversation_id {
                return Ok(binding.agent_id.clone());
            }
        }

        // Second pass: wildcard match
        for binding in bindings.iter() {
            if binding.channel == channel && binding.conversation_pattern == "*" {
                return Ok(binding.agent_id.clone());
            }
        }

        Err(GatewayError::NoRoute {
            channel: channel.to_string(),
            conversation: conversation_id.to_string(),
        })
    }

    /// List all current bindings.
    pub fn list_bindings(&self) -> Vec<RouteBinding> {
        self.bindings.read().unwrap().clone()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
