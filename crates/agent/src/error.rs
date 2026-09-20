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
    /// The arguments the model sent for this call, as it sent them.
    ///
    /// The gate's own [`Action`] is a classification: `shell:ls` for
    /// a whole family of `ls` invocations, and the sentinel
    /// `shell::pipeline:` for anything carrying a shell
    /// metacharacter. An operator approving a call is approving this
    /// string, not that key, so a prompt that shows only the key is
    /// asking them to approve something they have not been shown.
    ///
    /// `None` where the call has no arguments to show, and on the
    /// paths that build a context without a call in hand.
    pub arguments: Option<String>,
    /// What the model said in the same message as the call.
    ///
    /// Often the only statement of intent an operator gets: the
    /// arguments say what would run and this says what the model
    /// thinks it is doing, which is the pair a decision is made on.
    /// `None` where the model sent calls and no text.
    pub assistant_text: Option<String>,
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

    /// A configured registry root (`<data_dir>/registry-root.pub`) is
    /// present but unusable (unreadable or not a valid Ed25519 public
    /// key). Distinct from `SkillLoad` so the loader can surface a
    /// corrupt strict anchor loudly: absent means the intended
    /// self-signed floor, but unparseable means a misconfigured strict
    /// anchor that just refused every skill, and an operator who
    /// fat-fingered `wirken skills trust-root` must see the difference.
    #[error("registry root unusable: {0}")]
    RegistryRootUnusable(String),

    #[error(
        "skill {name} contains an envelope-collision substring in {field} \
         and would forge the BEGIN/END UNTRUSTED SKILL boundary"
    )]
    EnvelopeCollision { name: String, field: &'static str },

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("permission denied: {0}")]
    /// Boxed: this is the largest variant by a wide margin, and an
    /// `AgentError` is returned from most of the crate's fallible
    /// paths. Inline it and every one of those `Result`s carries the
    /// context's width whether it denies anything or not.
    PermissionDeniedCtx(Box<PermissionDenialContext>),

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

    /// A child agent invocation hit its `max_rounds` budget before
    /// producing a final assistant
    /// message. The parent harness catches this and reports
    /// `status: "rounds_exceeded"` in the `SubagentResult` envelope.
    #[error("subagent rounds budget exceeded after {rounds} rounds")]
    RoundsExceeded { rounds: usize },

    /// A built-in tool tried to reach a host that the agent's
    /// effective skill permissions egress allow-set rejects.
    /// The agent's dispatcher catches this variant, emits a
    /// `SkillPermissionDenied` audit event, and returns a non-success
    /// `ToolResult` to the LLM rather than propagating the error up.
    ///
    /// A tuple variant wrapping [`crate::egress::EgressDenied`] so
    /// the `reason` field (Profile vs Phase) carries through to the
    /// audit emit site without a parallel `host` slot drifting from
    /// the underlying egress error.
    #[error("{0}")]
    EgressDenied(crate::egress::EgressDenied),

    /// User typed `/<name>` as a slash invocation but no loaded
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
