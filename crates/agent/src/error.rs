use thiserror::Error;
use wirken_gateway::permissions::{Action, PermissionTier};

/// Structured context for a permission denial, providing all the information
/// an incident responder needs to understand what happened and why.
#[derive(Debug, Clone)]
pub struct PermissionDenialContext {
    /// The tool the agent attempted to invoke.
    pub tool_name: String,
    /// The permission action that was checked.
    pub action: Action,
    /// The tier required for this action.
    pub requested_tier: PermissionTier,
    /// The agent that attempted the action.
    pub agent_id: String,
    /// The inbound user message that triggered the agent's tool call attempt.
    pub trigger_message: Option<String>,
}

impl std::fmt::Display for PermissionDenialContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tool '{}' requires {} approval (action: {:?})",
            self.tool_name,
            self.requested_tier.label(),
            self.action,
        )
    }
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("llm error: {0}")]
    Llm(String),

    #[error("tool error: {0}")]
    Tool(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("skill load error: {0}")]
    SkillLoad(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("permission denied: {0}")]
    PermissionDeniedCtx(PermissionDenialContext),

    #[error("conversation error: {0}")]
    Conversation(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(String),

    #[error("mcp error: {0}")]
    Mcp(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),
}
