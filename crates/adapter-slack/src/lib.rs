//! Slack channel adapter: Socket Mode in, `chat.postMessage` out,
//! bridged to the gateway over IPC.
//!
//! The approval-card path in [`adapter`] (an `ApprovalRequest` frame
//! rendered as a section block with Approve and Deny buttons, and a
//! button press forwarded as an `ApprovalDecision`) is reached only by
//! this crate's tests. `wirken run` attaches no Slack approval gate, so
//! a tool call on a Slack session that needs approval prompts on the
//! CLI surface and resolves to deny when nobody decides it.
pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::SlackAdapter;
pub use error::SlackError;

#[cfg(test)]
mod tests;
