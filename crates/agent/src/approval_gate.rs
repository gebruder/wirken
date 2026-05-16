//! Operator-approval surface for `NeedsApproval` tool calls.
//!
//! The runtime hits [`crate::error::PermissionDenialContext`] when a
//! Tier-2 action wants approval. By default the call refuses
//! terminally; when an [`ApprovalGate`] is attached, the runtime
//! consults it once, and on `Approved` retries the call via the
//! one-shot bypass field on `Agent`.
//!
//! `Option<Arc<dyn ApprovalGate>>` on the Agent is the right shape;
//! a `NoopApprovalGate` would change current behavior (today's
//! unmediated denial path emits `denied_via: None`, whereas a noop
//! gate would emit `denied_via: Some(_)` even when no operator
//! interaction occurred). `None` preserves the existing audit row;
//! `Some` opts into the gate flow.
//!
//! The trait surface is shared with every future approval surface
//! (webchat SSE, `wirken permissions approve` CLI, channel adapters).
//! `source()` returns the structured [`wirken_audit::ApprovalSource`]
//! that lands on the audit row so SIEM detections can pivot
//! per-surface.

use async_trait::async_trait;

use wirken_audit::ApprovalSource;

use crate::error::PermissionDenialContext;

/// Outcome of a single approval-gate consult. `Denied` carries the
/// operator's reason verbatim (surfaced to the LLM as the tool
/// call's failure message). `Timeout` is the read-deadline case;
/// the runtime treats it as a deny with a synthetic
/// `"approval timeout"` reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied { reason: Option<String> },
    Timeout,
}

/// One mediated decision per `NeedsApproval` short-circuit. The
/// runtime passes the full [`PermissionDenialContext`] (tool name,
/// action, agent id, trigger message) so a surface that wants to
/// render operator-facing text can include the trigger that drove
/// the call.
///
/// `source()` is queried separately because the runtime audit-emits
/// happen outside the gate call — keeping the surface label fixed
/// for the lifetime of a gate (rather than per-call) matches the
/// real model: a stdin gate is always stdin, a Telegram gate is
/// always Telegram.
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome;

    /// Which surface this gate represents. Recorded on
    /// `SessionEvent::PermissionApproved.approved_via` /
    /// `SessionEvent::PermissionDenied.denied_via` so the audit
    /// chain carries the mediation point.
    fn source(&self) -> ApprovalSource;
}

// Allow `Arc<dyn ApprovalGate>` storage: async_trait already makes
// the trait object-safe by boxing the future, but spelling out the
// requirement is clearer than the inferred bound.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// Test gate that returns scripted outcomes in order. Each
    /// `request_approval` call pops the next outcome. Used by
    /// runtime tests to drive Approved / Denied / Timeout paths
    /// deterministically without spinning up real stdin.
    #[allow(dead_code)]
    pub struct ScriptedGate {
        pub script: Mutex<Vec<ApprovalOutcome>>,
        pub calls: Mutex<Vec<String>>,
    }

    #[allow(dead_code)]
    impl ScriptedGate {
        pub fn new(outcomes: Vec<ApprovalOutcome>) -> Self {
            Self {
                script: Mutex::new(outcomes),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ApprovalGate for ScriptedGate {
        async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
            self.calls.lock().unwrap().push(ctx.tool_name.clone());
            self.script
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(ApprovalOutcome::Denied {
                    reason: Some("scripted gate empty".into()),
                })
        }

        fn source(&self) -> ApprovalSource {
            ApprovalSource::Stdin
        }
    }
}
