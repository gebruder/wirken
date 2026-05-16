//! Signal approval gate: bridges the agent's `ApprovalGate` trait
//! to the Signal channel adapter. Mirrors `TelegramApprovalGate`
//! structurally; the differences live entirely in the wire-side
//! UX (text command rather than inline keyboard) which is the
//! adapter's concern, not the gate's.
//!
//! `request_approval` preflights `approver_registry::approval_conversation`
//! and fails-closed at request time when no approval conversation
//! is configured. The same fail-closed reasoning as Telegram
//! applies: the alternative is to ship the frame, have the
//! adapter bounce back as `ApprovalRequestFailed`, and burn the
//! queue entry for the round-trip. Preflight is cheaper and the
//! warn-level log gives operators a clear signal that the
//! adapter is misconfigured.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use wirken_audit::ApprovalSource;
use wirken_gateway::approver_registry::ApproverRegistry;
use wirken_gateway::outbound_dispatcher::OutboundDispatcher;
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingDecision, PendingRequest};
use wirken_ipc::wirken_capnp::frame;

use crate::approval_gate::{ApprovalGate, ApprovalOutcome};
use crate::error::PermissionDenialContext;

/// Default wall-clock cap on a Signal approval await. 300s
/// default matches Telegram, CLI, and SSE; the operational shape
/// (an operator finding the approval message in chat) is the
/// same across out-of-band surfaces.
pub const DEFAULT_SIGNAL_TIMEOUT_SECS: u64 = 300;

pub fn resolve_signal_timeout() -> Duration {
    match std::env::var("WIRKEN_SIGNAL_APPROVAL_TIMEOUT_S") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_SIGNAL_TIMEOUT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_SIGNAL_TIMEOUT_SECS),
    }
}

const SIGNAL_CHANNEL: &str = "signal";

pub struct SignalApprovalGate {
    queue: Arc<PendingApprovalQueue>,
    approvers: Arc<ApproverRegistry>,
    outbound: Arc<OutboundDispatcher>,
}

impl SignalApprovalGate {
    pub fn new(
        queue: Arc<PendingApprovalQueue>,
        approvers: Arc<ApproverRegistry>,
        outbound: Arc<OutboundDispatcher>,
    ) -> Self {
        Self {
            queue,
            approvers,
            outbound,
        }
    }
}

#[async_trait]
impl ApprovalGate for SignalApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        let Some(target_conversation) = self.approvers.approval_conversation(SIGNAL_CHANNEL) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "signal approval gate: no approval conversation configured for adapter \
                 '{SIGNAL_CHANNEL}'; failing closed. Run \
                 `wirken approvers set-chat {SIGNAL_CHANNEL} <group_id>` to enable."
            );
            return ApprovalOutcome::Timeout;
        };

        let Some(writer) = self.outbound.writer_for(SIGNAL_CHANNEL) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "signal approval gate: adapter '{SIGNAL_CHANNEL}' not currently \
                 connected; failing closed"
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

        let mut message = capnp::message::Builder::new_default();
        {
            let frame_builder = message.init_root::<frame::Builder<'_>>();
            let mut req = frame_builder.init_approval_request();
            req.set_request_id(&request_id);
            req.set_tool_name(&ctx.tool_name);
            req.set_action_key(ctx.action.approval_key());
            req.set_requested_tier(ctx.requested_tier.label());
            req.set_triggering_agent(&ctx.agent_id);
            req.set_trigger_message(ctx.trigger_message.as_deref().unwrap_or(""));
            req.set_target_conversation_id(&target_conversation);
        }

        {
            let mut w = writer.lock().await;
            if let Err(e) = w.write_message(&message).await {
                tracing::warn!(
                    request_id = %request_id,
                    error = %e,
                    "signal approval gate: failed to send ApprovalRequest frame; \
                     forgetting queue entry and returning Timeout"
                );
                self.queue.forget(&request_id);
                return ApprovalOutcome::Timeout;
            }
        }

        tracing::info!(
            request_id = %request_id,
            tool = %ctx.tool_name,
            agent = %ctx.agent_id,
            "signal approval pending; awaiting operator decision via text command"
        );

        let timeout = resolve_signal_timeout();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => match decision {
                PendingDecision::Allow { actor } => ApprovalOutcome::Approved { actor },
                PendingDecision::Deny { reason, actor } => {
                    ApprovalOutcome::Denied { reason, actor }
                }
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
        ApprovalSource::ChannelAdapter {
            channel: SIGNAL_CHANNEL.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::sync::Mutex as AsyncMutex;
    use wirken_gateway::permissions::{Action, PermissionTier};
    use wirken_ipc::{IpcFrameWriter, split_stream, test_pair};

    fn ctx(name: &str) -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: name.into(),
            action: Action::ShellExec {
                pattern: name.into(),
            },
            requested_tier: PermissionTier::Tier2,
            agent_id: "default".into(),
            trigger_message: Some("clean old logs".into()),
        }
    }

    async fn writer_pair() -> (Arc<AsyncMutex<IpcFrameWriter>>, wirken_ipc::IpcFrameReader) {
        let (a, b) = test_pair().unwrap();
        let (_unused_a_reader, a_writer) = split_stream(a);
        let (b_reader, _unused_b_writer) = split_stream(b);
        (Arc::new(AsyncMutex::new(a_writer)), b_reader)
    }

    fn setup_approvers(
        adapter: &str,
        conversation: Option<&str>,
    ) -> (TempDir, Arc<ApproverRegistry>) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("approvers.db");
        let reg = ApproverRegistry::open(&path).unwrap();
        if let Some(c) = conversation {
            reg.set_approval_conversation(adapter, c).unwrap();
        }
        (tmp, Arc::new(reg))
    }

    #[tokio::test]
    async fn missing_approval_conversation_fails_closed_without_writing_frame() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", None);
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = SignalApprovalGate::new(queue.clone(), approvers, outbound);

        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "no queue entry on preflight failure");
    }

    #[tokio::test]
    async fn adapter_not_connected_fails_closed_with_no_queue_entry() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", Some("9LJqVbY9wKD2c3vH/abc=="));
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = SignalApprovalGate::new(queue.clone(), approvers, outbound);

        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn happy_path_writes_approval_request_with_signal_group_id() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", Some("9LJqVbY9wKD2c3vH/abc=="));
        let outbound = Arc::new(OutboundDispatcher::new());
        let (writer, mut reader) = writer_pair().await;
        outbound.register("signal", writer);
        let gate = SignalApprovalGate::new(queue.clone(), approvers.clone(), outbound.clone());

        let queue_for_resolver = queue.clone();
        let gate_task = tokio::spawn(async move { gate.request_approval(&ctx("exec")).await });

        let msg = reader.read_message().await.unwrap();
        let request_id = {
            let f = msg.get_root::<frame::Reader<'_>>().unwrap();
            match f.which().unwrap() {
                frame::ApprovalRequest(req) => {
                    let req = req.unwrap();
                    assert_eq!(req.get_tool_name().unwrap().to_string().unwrap(), "exec");
                    assert_eq!(
                        req.get_target_conversation_id()
                            .unwrap()
                            .to_string()
                            .unwrap(),
                        "9LJqVbY9wKD2c3vH/abc=="
                    );
                    assert_eq!(
                        req.get_triggering_agent().unwrap().to_string().unwrap(),
                        "default"
                    );
                    req.get_request_id().unwrap().to_string().unwrap()
                }
                _ => panic!("expected ApprovalRequest"),
            }
        };

        queue_for_resolver.resolve(
            &request_id,
            PendingDecision::Allow {
                actor: Some("davi".into()),
            },
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
    async fn deny_with_reason_propagates_through_outcome() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", Some("group-abc=="));
        let outbound = Arc::new(OutboundDispatcher::new());
        let (writer, mut reader) = writer_pair().await;
        outbound.register("signal", writer);
        let gate = SignalApprovalGate::new(queue.clone(), approvers, outbound);

        let queue_for_resolver = queue.clone();
        let gate_task = tokio::spawn(async move { gate.request_approval(&ctx("rm")).await });

        let msg = reader.read_message().await.unwrap();
        let request_id = {
            let f = msg.get_root::<frame::Reader<'_>>().unwrap();
            match f.which().unwrap() {
                frame::ApprovalRequest(req) => {
                    req.unwrap().get_request_id().unwrap().to_string().unwrap()
                }
                _ => panic!("expected ApprovalRequest"),
            }
        };

        queue_for_resolver.resolve(
            &request_id,
            PendingDecision::Deny {
                reason: Some("rm is too dangerous".into()),
                actor: Some("davi".into()),
            },
        );
        let outcome = gate_task.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("rm is too dangerous".into()),
                actor: Some("davi".into()),
            }
        );
    }

    #[tokio::test]
    async fn timeout_path_forgets_queue_entry() {
        // SAFETY: parallel tests; this env var is set/read/removed
        // within this test's scope only.
        unsafe {
            std::env::set_var("WIRKEN_SIGNAL_APPROVAL_TIMEOUT_S", "1");
        }
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", Some("group-abc=="));
        let outbound = Arc::new(OutboundDispatcher::new());
        let (writer, _reader) = writer_pair().await;
        outbound.register("signal", writer);
        let gate = SignalApprovalGate::new(queue.clone(), approvers, outbound);

        let outcome = gate.request_approval(&ctx("exec")).await;
        unsafe {
            std::env::remove_var("WIRKEN_SIGNAL_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "timed-out entry must be forgotten");
    }

    #[tokio::test]
    async fn source_reports_channel_adapter_signal() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("signal", None);
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = SignalApprovalGate::new(queue, approvers, outbound);
        match gate.source() {
            ApprovalSource::ChannelAdapter { channel } => assert_eq!(channel, "signal"),
            other => panic!("expected ChannelAdapter, got {other:?}"),
        }
    }
}
