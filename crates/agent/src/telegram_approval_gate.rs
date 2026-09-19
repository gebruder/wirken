//! Telegram approval gate: bridges the agent's `ApprovalGate`
//! trait to the channel-adapter wire plane.
//!
//! Mirrors `CliApprovalGate` in structure: holds
//! `Arc<PendingApprovalQueue>` and awaits the same `oneshot::Receiver`
//! the queue mints on `register`. The difference is the resolve
//! signal source: the CLI surface signals via a JSON-line socket;
//! the Telegram surface signals via the existing capnp adapter
//! wire (gateway-side IPC handler routes `ApprovalDecision` frames
//! and calls `queue.resolve`). From this gate's perspective, the
//! await target is identical.
//!
//! `request_approval` preflights `approver_registry::approval_chat`
//! and fails-closed at request time (with a `tracing::warn`) when
//! no approval chat is configured. The alternative — pushing an
//! `ApprovalRequest` frame that the adapter would bounce back as
//! `ApprovalRequestFailed` — works but burns the queue entry and
//! the gate's await for the round-trip. Preflight is cheaper and
//! the warn-level log line gives operators a clear signal that
//! the adapter is misconfigured.
//!
//! The outbound send handle is `Arc<OutboundDispatcher>`. The
//! dispatcher tracks live capnp writers per channel name; the
//! gate looks up the "telegram" channel's writer to send the
//! frame. When no writer is registered (adapter not currently
//! connected), the gate fails closed via the same warn-and-
//! return-Timeout path.

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

/// Default wall-clock cap on a Telegram approval await. Same
/// default as `CliApprovalGate` (300s) because the operational
/// shape is the same: out-of-band, expected to involve an
/// operator finding the approval message.
pub const DEFAULT_TELEGRAM_TIMEOUT_SECS: u64 = 300;

pub fn resolve_telegram_timeout() -> Duration {
    telegram_timeout_from(
        std::env::var("WIRKEN_TELEGRAM_APPROVAL_TIMEOUT_S")
            .ok()
            .as_deref(),
    )
}

/// The rule on its own, with the environment read lifted out.
///
/// Split out so the tests cover the value without writing a
/// process-global variable. `std::env::set_var` is `unsafe` in the
/// 2024 edition because it is undefined behaviour while another
/// thread reads or writes the environment, and cargo runs a crate's
/// tests on parallel threads that do exactly that. A serializing
/// mutex orders the writers and leaves every reader alone.
fn telegram_timeout_from(raw: Option<&str>) -> Duration {
    match raw.map(|s| s.trim().parse::<u64>()) {
        Some(Ok(secs)) if secs > 0 => Duration::from_secs(secs),
        _ => Duration::from_secs(DEFAULT_TELEGRAM_TIMEOUT_SECS),
    }
}

/// Channel constant for the Telegram surface. Used to resolve the
/// live writer in `OutboundDispatcher` and as the adapter_id when
/// looking up the approval chat. The single-Telegram-bot model
/// today maps `channel == adapter_id == "telegram"`; multi-bot
/// deployments are a follow-up slice that introduces per-adapter
/// channel naming.
const TELEGRAM_CHANNEL: &str = "telegram";

pub struct TelegramApprovalGate {
    queue: Arc<PendingApprovalQueue>,
    approvers: Arc<ApproverRegistry>,
    outbound: Arc<OutboundDispatcher>,
    /// Captured once at construction. The gate is built at
    /// startup and lives for the process, so reading the override
    /// here rather than on every request is the same value and one
    /// fewer environment read on the approval path.
    timeout: Duration,
}

impl TelegramApprovalGate {
    pub fn new(
        queue: Arc<PendingApprovalQueue>,
        approvers: Arc<ApproverRegistry>,
        outbound: Arc<OutboundDispatcher>,
    ) -> Self {
        Self::with_timeout(queue, approvers, outbound, resolve_telegram_timeout())
    }

    /// Construct with an explicit timeout instead of the value
    /// [`resolve_telegram_timeout`] reads from the environment. Lets a test drive
    /// the deadline directly rather than writing a process-global
    /// variable other threads are reading.
    pub fn with_timeout(
        queue: Arc<PendingApprovalQueue>,
        approvers: Arc<ApproverRegistry>,
        outbound: Arc<OutboundDispatcher>,
        timeout: Duration,
    ) -> Self {
        Self {
            queue,
            approvers,
            outbound,
            timeout,
        }
    }
}

#[async_trait]
impl ApprovalGate for TelegramApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        // Preflight 1: approval conversation configured?
        let Some(target_conversation) = self.approvers.approval_conversation(TELEGRAM_CHANNEL)
        else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "telegram approval gate: no approval conversation configured for adapter \
                 '{TELEGRAM_CHANNEL}'; failing closed. Run \
                 `wirken approvers set-chat {TELEGRAM_CHANNEL} <chat_id>` to enable."
            );
            return ApprovalOutcome::Timeout;
        };

        // Preflight 2: adapter connected?
        let Some(writer) = self.outbound.writer_for(TELEGRAM_CHANNEL) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "telegram approval gate: adapter '{TELEGRAM_CHANNEL}' not currently \
                 connected; failing closed"
            );
            return ApprovalOutcome::Timeout;
        };

        // Register the queue entry. The oneshot receiver is what
        // we await; the IPC handler at the gateway resolves the
        // entry when an authorized `ApprovalDecision` arrives.
        let request = PendingRequest {
            agent_id: ctx.agent_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            trigger_message: ctx.trigger_message.clone(),
        };
        let (request_id, rx) = self.queue.register(request);

        // Build and send the ApprovalRequest frame. The adapter
        // reads it, renders the inline-keyboard message, and waits
        // for a callback press.
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
                    "telegram approval gate: failed to send ApprovalRequest frame; \
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
            "telegram approval pending; awaiting operator decision via inline keyboard"
        );

        let timeout = self.timeout;
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
                // Gate's own deadline fired. Clear the queue entry
                // so a late ApprovalDecision frame sees UnknownKey
                // instead of racing the next request.
                self.queue.forget(&request_id);
                ApprovalOutcome::Timeout
            }
        }
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::ChannelAdapter {
            channel: TELEGRAM_CHANNEL.to_string(),
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

    fn setup_approvers(adapter: &str, chat_id: Option<i64>) -> (TempDir, Arc<ApproverRegistry>) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("approvers.db");
        let reg = ApproverRegistry::open(&path).unwrap();
        if let Some(c) = chat_id {
            reg.set_approval_conversation(adapter, &c.to_string())
                .unwrap();
        }
        (tmp, Arc::new(reg))
    }

    #[tokio::test]
    async fn missing_approval_chat_fails_closed_without_writing_frame() {
        // No approval_chat_id configured for the telegram adapter.
        // The gate must NOT consult the outbound dispatcher (no
        // writer registered in this test anyway) and must return
        // Timeout immediately.
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("telegram", None);
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = TelegramApprovalGate::new(queue.clone(), approvers, outbound);

        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "no queue entry on preflight failure");
    }

    #[tokio::test]
    async fn adapter_not_connected_fails_closed_with_no_queue_entry() {
        // Chat is configured but no adapter writer is registered
        // in the OutboundDispatcher (adapter offline). Gate fails
        // closed without registering a queue entry that would just
        // time out.
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("telegram", Some(-100123));
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = TelegramApprovalGate::new(queue.clone(), approvers, outbound);

        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn happy_path_writes_approval_request_and_resolves_on_allow() {
        // Wire up a mock adapter writer; the gate writes the
        // frame, we read it back to assert the fields, then resolve
        // the queue and confirm the gate returns Approved.
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("telegram", Some(-100123));
        let outbound = Arc::new(OutboundDispatcher::new());
        let (writer, mut reader) = writer_pair().await;
        outbound.register("telegram", writer);
        let gate = TelegramApprovalGate::new(queue.clone(), approvers.clone(), outbound.clone());

        let queue_for_resolver = queue.clone();
        let gate_task = tokio::spawn(async move { gate.request_approval(&ctx("exec")).await });

        // Read the ApprovalRequest frame off the adapter side and
        // pull out the request_id so we can resolve.
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
                        "-100123"
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
    async fn timeout_path_forgets_queue_entry() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("telegram", Some(-100123));
        let outbound = Arc::new(OutboundDispatcher::new());
        let (writer, _reader) = writer_pair().await;
        outbound.register("telegram", writer);
        let gate = TelegramApprovalGate::with_timeout(
            queue.clone(),
            approvers,
            outbound,
            Duration::from_millis(50),
        );

        let outcome = gate.request_approval(&ctx("exec")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty(), "timed-out entry must be forgotten");
    }

    #[tokio::test]
    async fn source_reports_channel_adapter_telegram() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let (_tmp, approvers) = setup_approvers("telegram", None);
        let outbound = Arc::new(OutboundDispatcher::new());
        let gate = TelegramApprovalGate::new(queue, approvers, outbound);
        match gate.source() {
            ApprovalSource::ChannelAdapter { channel } => assert_eq!(channel, "telegram"),
            other => panic!("expected ChannelAdapter, got {other:?}"),
        }
    }
}
