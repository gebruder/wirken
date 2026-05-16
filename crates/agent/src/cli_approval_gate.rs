//! CLI approval gate: bridges the agent's `ApprovalGate` trait to
//! the gateway's `PendingApprovalQueue`. Suspends the agent task
//! by registering an entry in the queue and awaiting the
//! `oneshot::Receiver`; the gateway's permissions-IPC handler
//! resolves the entry when `wirken permissions pending approve`
//! arrives over `gateway-permissions.sock`.
//!
//! The gate runs its own timeout (`WIRKEN_CLI_APPROVAL_TIMEOUT_S`,
//! default 300 seconds) so a runaway pending entry doesn't hold
//! the agent forever if no operator decides. On timeout the gate
//! calls `queue.forget` to clear the entry; subsequent operator
//! decisions for the same request_id get `UnknownKey`.
//!
//! Translation between the gateway-local `PendingDecision` (Allow
//! / Deny / Timeout) and the agent's `ApprovalOutcome` (Approved /
//! Denied / Timeout) is one `match` arm. The two enums coexist
//! because the queue lives in `wirken-gateway` (which cannot depend
//! on agent) and the trait lives in `wirken-agent` (which depends
//! on gateway).

use std::sync::Arc;

use async_trait::async_trait;

use wirken_audit::ApprovalSource;
use wirken_gateway::pending_approvals::{
    PendingApprovalQueue, PendingDecision, PendingRequest, resolve_cli_timeout,
};

use crate::approval_gate::{ApprovalGate, ApprovalOutcome};
use crate::error::PermissionDenialContext;

/// `ApprovalGate` impl that suspends on the gateway's pending queue.
/// Shared with the gateway's permissions-IPC accept loop via
/// `Arc<PendingApprovalQueue>`; the loop calls `queue.resolve` from
/// the IPC handler thread, which wakes the agent task awaiting in
/// `request_approval`.
pub struct CliApprovalGate {
    queue: Arc<PendingApprovalQueue>,
}

impl CliApprovalGate {
    pub fn new(queue: Arc<PendingApprovalQueue>) -> Self {
        Self { queue }
    }
}

#[async_trait]
impl ApprovalGate for CliApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        let request = PendingRequest {
            agent_id: ctx.agent_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            trigger_message: ctx.trigger_message.clone(),
        };
        let (request_id, rx) = self.queue.register(request);
        tracing::info!(
            request_id = %request_id,
            tool = %ctx.tool_name,
            agent = %ctx.agent_id,
            "approval pending; awaiting operator decision via `wirken permissions pending approve`",
        );

        let timeout = resolve_cli_timeout();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => match decision {
                PendingDecision::Allow { actor } => ApprovalOutcome::Approved { actor },
                PendingDecision::Deny { reason, actor } => {
                    ApprovalOutcome::Denied { reason, actor }
                }
                PendingDecision::Timeout => ApprovalOutcome::Timeout,
            },
            // Sender dropped (gateway shutdown, queue purge, or a
            // double-resolve race that closed the channel): treat
            // as timeout. The chain still records the denial; an
            // operator inspecting the audit log sees the decline
            // attributed to the cli surface even when the precise
            // shutdown reason is not recoverable from here.
            Ok(Err(_)) => ApprovalOutcome::Timeout,
            Err(_) => {
                // Gate's own deadline fired before any operator
                // decision arrived. Clear the queue entry so a late
                // operator decision sees UnknownKey instead of
                // racing the next `request_approval` for the same
                // tool. `forget` is a no-op if the entry was
                // already resolved between the timeout firing and
                // this lock acquisition.
                self.queue.forget(&request_id);
                ApprovalOutcome::Timeout
            }
        }
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::Cli
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wirken_gateway::permissions::{Action, PermissionTier};

    fn ctx(name: &str) -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: name.into(),
            action: Action::ShellExec {
                pattern: name.into(),
            },
            requested_tier: PermissionTier::Tier2,
            agent_id: "default".into(),
            trigger_message: Some("operator request".into()),
        }
    }

    #[tokio::test]
    async fn approve_via_queue_resolves_to_approved() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let gate = CliApprovalGate::new(queue.clone());

        // Spawn the gate's await first so the entry lands in the
        // queue; then the IPC-handler-equivalent resolves it.
        let gate_task = tokio::spawn({
            let ctx = ctx("exec");
            async move { gate.request_approval(&ctx).await }
        });

        // Poll until the entry is visible. The await races the
        // spawned task; a tight sleep loop is fine because the
        // register call is synchronous.
        let id = loop {
            let entries = queue.list();
            if let Some(e) = entries.first() {
                break e.request_id.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        let result = queue.resolve(
            &id,
            PendingDecision::Allow {
                actor: Some("davi".into()),
            },
        );
        assert_eq!(
            result,
            wirken_gateway::pending_approvals::ResolveResult::Accepted
        );
        let outcome = gate_task.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Approved {
                actor: Some("davi".into())
            }
        );
    }

    #[tokio::test]
    async fn deny_via_queue_propagates_reason() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let gate = CliApprovalGate::new(queue.clone());

        let gate_task = tokio::spawn({
            let ctx = ctx("rm");
            async move { gate.request_approval(&ctx).await }
        });

        let id = loop {
            let entries = queue.list();
            if let Some(e) = entries.first() {
                break e.request_id.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        queue.resolve(
            &id,
            PendingDecision::Deny {
                reason: Some("not safe".into()),
                actor: Some("davi".into()),
            },
        );
        let outcome = gate_task.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("not safe".into()),
                actor: Some("davi".into()),
            }
        );
    }

    #[tokio::test]
    async fn unresolved_entry_times_out_after_env_override() {
        // Set the env var to a sub-second value to make the test
        // tight. The gate reads the var inside request_approval, so
        // setting it BEFORE the call is what matters.
        // SAFETY: cargo test parallelism — this test sets and clears
        // its own env var; no other test reads this var concurrently.
        unsafe {
            std::env::set_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S", "1");
        }
        let queue = Arc::new(PendingApprovalQueue::new());
        let gate = CliApprovalGate::new(queue.clone());

        // Don't resolve. The gate's deadline fires; outcome is
        // Timeout; the entry is cleared from the queue.
        let outcome = gate.request_approval(&ctx("exec")).await;
        unsafe {
            std::env::remove_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "timed-out entry should be forgotten");
    }

    #[tokio::test]
    async fn gate_source_is_cli() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let gate = CliApprovalGate::new(queue);
        assert_eq!(gate.source(), ApprovalSource::Cli);
    }
}
