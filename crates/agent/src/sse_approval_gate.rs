//! SSE approval gate: bridges the agent's `ApprovalGate` trait to
//! the webchat `/api/chat` SSE stream.
//!
//! Mirrors `TelegramApprovalGate` in structure. The signal source
//! differs from Telegram and CLI: the webchat surface has no
//! out-of-band primitive — NeedsApproval on webchat can only fire
//! during an in-flight /api/chat request, and the SSE stream
//! that's already streaming the agent's response carries the
//! approval request as a new event type. The gate's await target
//! is the same `oneshot::Receiver` the queue mints; the
//! /api/approvals/{request_id} POST handler resolves the entry
//! exactly the way the Telegram callback path does.
//!
//! Operator identity collapses to the literal label `"webchat"`
//! today because webchat has no login layer (verify-first finding
//! Q3). When login lands as a separate slice the actor field
//! flows through to per-user identity without touching this gate's
//! contract.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use wirken_audit::ApprovalSource;
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingDecision, PendingRequest};
use wirken_gateway::sse_approval_registry::{SseApprovalRegistry, SseEvent};

use crate::approval_gate::{ApprovalGate, ApprovalOutcome};
use crate::error::PermissionDenialContext;

/// Default wall-clock cap on an SSE approval await. Same 300s
/// default as CLI and Telegram; the operational shape — an
/// operator decides via a UI surface bounded by a single chat
/// turn — is comparable.
pub const DEFAULT_WEBCHAT_TIMEOUT_SECS: u64 = 300;

pub fn resolve_webchat_timeout() -> Duration {
    match std::env::var("WIRKEN_WEBCHAT_APPROVAL_TIMEOUT_S") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_WEBCHAT_TIMEOUT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_WEBCHAT_TIMEOUT_SECS),
    }
}

pub struct SseApprovalGate {
    queue: Arc<PendingApprovalQueue>,
    registry: Arc<SseApprovalRegistry>,
}

impl SseApprovalGate {
    pub fn new(queue: Arc<PendingApprovalQueue>, registry: Arc<SseApprovalRegistry>) -> Self {
        Self { queue, registry }
    }
}

#[async_trait]
impl ApprovalGate for SseApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        // Preflight: is there a live SSE stream for this session?
        // Structurally there should always be one (NeedsApproval
        // fires inside /api/chat which registers on entry), but
        // the absence path is checked so a future webchat
        // architecture change doesn't silently lose decisions.
        let session_id =
            wirken_audit::SessionId::new(format!("{}/webchat/webchat-default", ctx.agent_id));
        let Some(sender) = self.registry.sender_for(&session_id) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "sse approval gate: no live SSE stream for session; failing closed. \
                 (NeedsApproval should only fire mid-/api/chat which registers a sender.)"
            );
            return ApprovalOutcome::Timeout;
        };

        let request = PendingRequest {
            agent_id: ctx.agent_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            trigger_message: ctx.trigger_message.clone(),
        };
        let (request_id, rx) = self.queue.register(request);

        let event = SseEvent::ApprovalRequest {
            request_id: request_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            triggering_agent: ctx.agent_id.clone(),
            trigger_message: ctx.trigger_message.clone().unwrap_or_default(),
        };

        if let Err(e) = sender.send(event).await {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                "sse approval gate: failed to push ApprovalRequest event; \
                 forgetting queue entry and returning Timeout"
            );
            self.queue.forget(&request_id);
            return ApprovalOutcome::Timeout;
        }

        tracing::info!(
            request_id = %request_id,
            tool = %ctx.tool_name,
            agent = %ctx.agent_id,
            "webchat approval pending; awaiting operator decision via /api/approvals POST"
        );

        let timeout = resolve_webchat_timeout();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => match decision {
                PendingDecision::Allow { actor } => ApprovalOutcome::Approved {
                    // Default to the literal `"webchat"` label when
                    // the resolver did not supply an actor. The
                    // /api/approvals handler always supplies
                    // `Some("webchat")`; the fallback covers a
                    // theoretical resolver that doesn't.
                    actor: actor.or_else(|| Some("webchat".to_string())),
                },
                PendingDecision::Deny { reason, actor } => ApprovalOutcome::Denied {
                    reason,
                    actor: actor.or_else(|| Some("webchat".to_string())),
                },
                PendingDecision::Timeout => ApprovalOutcome::Timeout,
            },
            Ok(Err(_)) => ApprovalOutcome::Timeout,
            Err(_) => {
                self.queue.forget(&request_id);
                ApprovalOutcome::Timeout
            }
        }
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::Sse
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use wirken_gateway::permissions::{Action, PermissionTier};

    fn ctx(name: &str) -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: name.into(),
            action: Action::ShellExec {
                pattern: name.into(),
            },
            requested_tier: PermissionTier::Tier2,
            agent_id: "default".into(),
            trigger_message: Some("clean logs".into()),
        }
    }

    #[tokio::test]
    async fn missing_sse_sender_fails_closed_without_queue_entry() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let registry = Arc::new(SseApprovalRegistry::new());
        let gate = SseApprovalGate::new(queue.clone(), registry);
        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "no queue entry on preflight failure");
    }

    #[tokio::test]
    async fn happy_path_sends_approval_request_event_and_resolves_on_allow() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let registry = Arc::new(SseApprovalRegistry::new());
        let (tx, mut rx) = mpsc::channel::<SseEvent>(8);
        let session_id =
            wirken_audit::SessionId::new("default/webchat/webchat-default".to_string());
        registry.register(session_id, tx);

        let gate = SseApprovalGate::new(queue.clone(), registry);
        let queue_for_resolver = queue.clone();
        let gate_task = tokio::spawn(async move { gate.request_approval(&ctx("exec")).await });

        // Pull the SSE event off the mpsc to discover the request_id.
        let event = rx.recv().await.expect("sender push");
        let request_id = match event {
            SseEvent::ApprovalRequest {
                ref request_id,
                tool_name,
                triggering_agent,
                ..
            } => {
                assert_eq!(tool_name, "exec");
                assert_eq!(triggering_agent, "default");
                request_id.clone()
            }
            other => panic!("expected ApprovalRequest, got {other:?}"),
        };

        queue_for_resolver.resolve(
            &request_id,
            PendingDecision::Allow {
                actor: Some("webchat".into()),
            },
        );
        let outcome = gate_task.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Approved {
                actor: Some("webchat".into())
            }
        );
    }

    #[tokio::test]
    async fn deny_propagates_reason_through_outcome() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let registry = Arc::new(SseApprovalRegistry::new());
        let (tx, mut rx) = mpsc::channel::<SseEvent>(8);
        registry.register(
            wirken_audit::SessionId::new("default/webchat/webchat-default".to_string()),
            tx,
        );

        let gate = SseApprovalGate::new(queue.clone(), registry);
        let queue_for_resolver = queue.clone();
        let gate_task = tokio::spawn(async move { gate.request_approval(&ctx("rm")).await });

        let event = rx.recv().await.unwrap();
        let request_id = match event {
            SseEvent::ApprovalRequest { request_id, .. } => request_id,
            _ => panic!("expected ApprovalRequest"),
        };
        queue_for_resolver.resolve(
            &request_id,
            PendingDecision::Deny {
                reason: Some("rm is too dangerous".into()),
                actor: Some("webchat".into()),
            },
        );
        let outcome = gate_task.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("rm is too dangerous".into()),
                actor: Some("webchat".into()),
            }
        );
    }

    #[tokio::test]
    async fn timeout_forgets_queue_entry() {
        // SAFETY: this test sets and removes its own env var; no
        // other test reads WIRKEN_WEBCHAT_APPROVAL_TIMEOUT_S
        // concurrently.
        unsafe {
            std::env::set_var("WIRKEN_WEBCHAT_APPROVAL_TIMEOUT_S", "1");
        }
        let queue = Arc::new(PendingApprovalQueue::new());
        let registry = Arc::new(SseApprovalRegistry::new());
        let (tx, _rx) = mpsc::channel::<SseEvent>(8);
        registry.register(
            wirken_audit::SessionId::new("default/webchat/webchat-default".to_string()),
            tx,
        );
        let gate = SseApprovalGate::new(queue.clone(), registry);

        let outcome = gate.request_approval(&ctx("exec")).await;
        unsafe {
            std::env::remove_var("WIRKEN_WEBCHAT_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "timed-out entry must be forgotten");
    }

    #[tokio::test]
    async fn source_reports_sse() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let registry = Arc::new(SseApprovalRegistry::new());
        let gate = SseApprovalGate::new(queue, registry);
        assert_eq!(gate.source(), ApprovalSource::Sse);
    }
}
