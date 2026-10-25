// Slicing a str off a character boundary panics. Each slice that
// stays carries an allow naming why its offsets are boundaries.
#![cfg_attr(not(test), deny(clippy::string_slice))]

pub mod approval_gate;
pub mod attestation;
pub mod bundled_presets;
pub mod bundled_skills;
pub mod cli_approval_gate;
pub mod context;
pub mod conversation;
pub mod discord_approval_gate;
pub mod egress;
pub mod error;
pub mod exec_location;
pub mod factory;
pub mod http_tool;
pub mod identity;
pub mod imported_tool;
pub mod inbound_interceptor;
pub mod keycloak_identity;
pub mod llm;
pub mod llm_responses;
pub mod llm_stream;
pub mod mcp;
pub mod memory_tool;
pub mod persona;
pub mod plan_auth;
pub mod preset;
pub mod rate_limit;
pub mod recovery;
pub mod runtime;
pub mod sandbox;
pub mod sandbox_egress;
pub mod signal_approval_gate;
pub(crate) mod sigv4;
pub mod skill;
pub mod skill_perms;
pub mod slash;
pub mod sse_approval_gate;
pub mod telegram_approval_gate;
pub mod terminal_approval_gate;
pub mod tool;
pub mod yaml;

/// The control-sequence strip, kept at this path for its callers; it
/// lives with the approval card in the adapter core.
pub use wirken_adapter_core::ansi;
/// The environment every host-side child starts from; see
/// `wirken_sandbox::child_env`. Re-exported so the CLI reaches it
/// through the crate it already depends on.
pub use wirken_sandbox::child_env;

pub use context::ContextEngine;
pub use error::{AgentError, PermissionDenialContext};
pub use factory::{AgentFactory, AgentStaticConfig, ChannelOverride, session_id_for};
pub use identity::AgentIdentity;
pub use recovery::{
    MAX_RATE_LIMIT_RETRIES, MAX_TOOL_VALIDATION_RETRIES, RecoveryObserver, RetryDecision,
};
pub use runtime::{
    Agent, DivergenceRecord, ExecLocationFinding, InboundContext, PARTIAL_RESULT_LOST_SENTINEL,
    ProcessResult, ToolGate, VerifyOptions, VerifyReport, ask_inbound_id,
};
pub use skill::SkillLoader;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod http_tool_tests;

#[cfg(test)]
mod example_skill_e2e_tests;
