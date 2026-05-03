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

    #[error(
        "skill {name} contains an envelope-collision substring in {field} \
         and would forge the BEGIN/END UNTRUSTED SKILL boundary"
    )]
    EnvelopeCollision { name: String, field: &'static str },

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

    #[error("identity error: {0}")]
    Identity(String),

    #[error("session log error: {0}")]
    SessionLog(String),

    #[error(
        "context overflow: conversation requires {current_tokens} tokens but the model budget is {budget_tokens}"
    )]
    ContextOverflow {
        current_tokens: usize,
        budget_tokens: usize,
    },

    /// Item 6 slice 1: a child agent invocation hit its
    /// `max_rounds` budget before producing a final assistant
    /// message. The parent harness catches this and reports
    /// `status: "rounds_exceeded"` in the `SubagentResult` envelope.
    #[error("subagent rounds budget exceeded after {rounds} rounds")]
    RoundsExceeded { rounds: usize },

    /// #76 Phase 2.2: a built-in tool tried to reach a host that the
    /// agent's effective skill permissions egress allow-set rejects.
    /// The agent's dispatcher catches this variant, emits a
    /// `SkillPermissionDenied` audit event, and returns a non-success
    /// `ToolResult` to the LLM rather than propagating the error up.
    #[error(
        "egress denied: host '{host}' is not in the agent's effective skill permissions egress allow-set"
    )]
    EgressDenied { host: String },

    /// #79: user typed `/<name>` as a slash invocation but no loaded
    /// skill has that name. Surfaced to the channel so the user can
    /// retry with a correct skill name.
    #[error("unknown skill '/{name}'; loaded skills: {}", known.join(", "))]
    UnknownSlashSkill { name: String, known: Vec<String> },

    /// agent-runtime-error-recovery: provider returned HTTP 429 on
    /// every retry. The dispatch helper bubbles this up so callers
    /// (lyrik, bench harness, …) can record `lyrik.dispatch.failed`
    /// and emit an empty findings.json so the failure counts.
    #[error("rate limit exhausted after {attempts} attempts")]
    RateLimitExhausted { attempts: u32 },
}
