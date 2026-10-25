//! Discord approval gate. Posts an `ApprovalRequest` frame to the
//! Discord adapter, which renders it as a card with Approve and Deny
//! buttons in the configured approval channel, and waits on the
//! pending-approval queue for the decision the gateway resolves.
//!
//! Who may decide is checked by the gateway against the approver
//! allowlist, not here and not in the adapter.

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
use crate::exec_location::runtime_name;

/// Adapter id and channel name of the Discord adapter.
const DISCORD: &str = "discord";

/// Seconds an undecided request waits before it is refused.
pub const DEFAULT_DISCORD_TIMEOUT_SECS: u64 = 300;

/// `WIRKEN_DISCORD_APPROVAL_TIMEOUT_S`, else the default.
pub fn resolve_discord_timeout() -> Duration {
    discord_timeout_from(
        std::env::var("WIRKEN_DISCORD_APPROVAL_TIMEOUT_S")
            .ok()
            .as_deref(),
    )
}

fn discord_timeout_from(raw: Option<&str>) -> Duration {
    match raw.and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => Duration::from_secs(DEFAULT_DISCORD_TIMEOUT_SECS),
    }
}

pub struct DiscordApprovalGate {
    queue: Arc<PendingApprovalQueue>,
    approvers: Arc<ApproverRegistry>,
    outbound: Arc<OutboundDispatcher>,
    timeout: Duration,
}

impl DiscordApprovalGate {
    pub fn new(
        queue: Arc<PendingApprovalQueue>,
        approvers: Arc<ApproverRegistry>,
        outbound: Arc<OutboundDispatcher>,
    ) -> Self {
        Self::with_timeout(queue, approvers, outbound, resolve_discord_timeout())
    }

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
impl ApprovalGate for DiscordApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        // Both checks run before a queue entry exists.
        let Some(channel_id) = self.approvers.approval_conversation(DISCORD) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "discord approval: no approval channel set; refused. Set one with \
                 `wirken approvers set-chat discord <channel_id>`."
            );
            return ApprovalOutcome::Timeout;
        };
        let Some(writer) = self.outbound.writer_for(DISCORD) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                tool = %ctx.tool_name,
                "discord approval: adapter not connected; refused"
            );
            return ApprovalOutcome::Timeout;
        };

        let runtime = ctx.exec_location.as_ref().map(|l| runtime_name(l.mode));
        let (request_id, decided) = self.queue.register(PendingRequest {
            agent_id: ctx.agent_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            trigger_message: ctx.trigger_message.clone(),
            arguments: ctx.arguments.clone(),
            assistant_text: ctx.assistant_text.clone(),
            exec_location: ctx.exec_location.as_ref().map(|l| l.text.clone()),
            exec_runtime: runtime.map(str::to_string),
            prompt_conversation: Some(channel_id.clone()),
        });

        let mut message = capnp::message::Builder::new_default();
        {
            let mut card = message
                .init_root::<frame::Builder<'_>>()
                .init_approval_request();
            card.set_request_id(&request_id);
            card.set_tool_name(&ctx.tool_name);
            card.set_action_key(ctx.action.approval_key());
            card.set_requested_tier(ctx.requested_tier.label());
            card.set_triggering_agent(&ctx.agent_id);
            card.set_trigger_message(ctx.trigger_message.as_deref().unwrap_or(""));
            card.set_target_conversation_id(&channel_id);
            card.set_exec_location(ctx.exec_location.as_ref().map_or("", |l| l.text.as_str()));
            card.set_exec_runtime(runtime.unwrap_or(""));
            card.set_arguments(ctx.arguments.as_deref().unwrap_or(""));
            card.set_assistant_text(ctx.assistant_text.as_deref().unwrap_or(""));
            card.set_timeout_secs(u32::try_from(self.timeout.as_secs()).unwrap_or(u32::MAX));
        }
        if let Err(e) = writer.lock().await.write_message(&message).await {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                "discord approval: could not send the card; refused"
            );
            self.queue.forget(&request_id);
            return ApprovalOutcome::Timeout;
        }
        tracing::info!(
            request_id = %request_id,
            tool = %ctx.tool_name,
            agent = %ctx.agent_id,
            "discord approval: card sent, waiting for a decision"
        );

        match tokio::time::timeout(self.timeout, decided).await {
            Ok(Ok(PendingDecision::Allow { actor })) => ApprovalOutcome::Approved { actor },
            Ok(Ok(PendingDecision::Deny { reason, actor })) => {
                ApprovalOutcome::Denied { reason, actor }
            }
            Ok(Ok(PendingDecision::Timeout)) | Ok(Err(_)) => ApprovalOutcome::Timeout,
            Err(_) => {
                // A press after this finds no entry.
                self.queue.forget(&request_id);
                ApprovalOutcome::Timeout
            }
        }
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::ChannelAdapter {
            channel: DISCORD.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex as AsyncMutex;
    use wirken_gateway::pending_approvals::DecisionActor;
    use wirken_gateway::permissions::{Action, PermissionTier};
    use wirken_ipc::{IpcFrameReader, split_stream, test_pair};

    const CHANNEL_ID: &str = "11223344556677889";

    fn asked() -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: "exec".into(),
            action: Action::ShellExec {
                pattern: "pwd".into(),
            },
            requested_tier: PermissionTier::Tier2,
            agent_id: "default".into(),
            session_id: format!("default/discord/{CHANNEL_ID}"),
            trigger_message: Some("where are you?".into()),
            arguments: Some(r#"{"command":"pwd"}"#.into()),
            assistant_text: None,
            exec_location: None,
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        queue: Arc<PendingApprovalQueue>,
        approvers: Arc<ApproverRegistry>,
        outbound: Arc<OutboundDispatcher>,
    }

    fn rig(channel: Option<&str>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let approvers = ApproverRegistry::open(&dir.path().join("approvers.db")).unwrap();
        if let Some(c) = channel {
            approvers.set_approval_conversation(DISCORD, c).unwrap();
        }
        Rig {
            _dir: dir,
            queue: Arc::new(PendingApprovalQueue::new()),
            approvers: Arc::new(approvers),
            outbound: Arc::new(OutboundDispatcher::new()),
        }
    }

    /// Registers a connected adapter and returns the side it reads.
    fn connect(rig: &Rig) -> IpcFrameReader {
        let (gateway_end, adapter_end) = test_pair().unwrap();
        let (_, writer) = split_stream(gateway_end);
        let (reader, _) = split_stream(adapter_end);
        rig.outbound
            .register(DISCORD, Arc::new(AsyncMutex::new(writer)));
        reader
    }

    fn gate(rig: &Rig, timeout: Duration) -> DiscordApprovalGate {
        DiscordApprovalGate::with_timeout(
            rig.queue.clone(),
            rig.approvers.clone(),
            rig.outbound.clone(),
            timeout,
        )
    }

    /// The card's request id and target channel.
    async fn read_card(reader: &mut IpcFrameReader) -> (String, String) {
        let msg = reader.read_message().await.unwrap();
        let frame::ApprovalRequest(card) = msg
            .get_root::<frame::Reader<'_>>()
            .unwrap()
            .which()
            .unwrap()
        else {
            panic!("expected an ApprovalRequest");
        };
        let card = card.unwrap();
        (
            card.get_request_id().unwrap().to_string().unwrap(),
            card.get_target_conversation_id()
                .unwrap()
                .to_string()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn with_no_approval_channel_it_refuses_before_queueing() {
        let rig = rig(None);
        let _reader = connect(&rig);
        let outcome = gate(&rig, Duration::from_secs(5))
            .request_approval(&asked())
            .await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(rig.queue.is_empty());
    }

    #[tokio::test]
    async fn with_the_adapter_down_it_refuses_before_queueing() {
        let rig = rig(Some(CHANNEL_ID));
        let outcome = gate(&rig, Duration::from_secs(5))
            .request_approval(&asked())
            .await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(rig.queue.is_empty());
    }

    #[tokio::test]
    async fn another_adapters_approval_chat_does_not_count() {
        let rig = rig(None);
        rig.approvers
            .set_approval_conversation("telegram", "-100123")
            .unwrap();
        let _reader = connect(&rig);
        let outcome = gate(&rig, Duration::from_secs(5))
            .request_approval(&asked())
            .await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(rig.queue.is_empty());
    }

    #[tokio::test]
    async fn the_card_goes_to_the_approval_channel_and_an_approval_carries_its_actor() {
        let rig = rig(Some(CHANNEL_ID));
        let mut reader = connect(&rig);
        let g = gate(&rig, Duration::from_secs(5));
        let waiting = tokio::spawn(async move { g.request_approval(&asked()).await });

        let (request_id, target) = read_card(&mut reader).await;
        assert_eq!(target, CHANNEL_ID);
        let entry = rig.queue.show(&request_id).unwrap();
        assert_eq!(entry.prompt_conversation.as_deref(), Some(CHANNEL_ID));
        assert_eq!(entry.session_id, format!("default/discord/{CHANNEL_ID}"));

        let actor = DecisionActor::new("424242").with_display("Ada");
        rig.queue.resolve(
            &request_id,
            PendingDecision::Allow {
                actor: Some(actor.clone()),
            },
        );
        assert_eq!(
            waiting.await.unwrap(),
            ApprovalOutcome::Approved { actor: Some(actor) }
        );
    }

    #[tokio::test]
    async fn a_deny_carries_its_reason_and_actor() {
        let rig = rig(Some(CHANNEL_ID));
        let mut reader = connect(&rig);
        let g = gate(&rig, Duration::from_secs(5));
        let waiting = tokio::spawn(async move { g.request_approval(&asked()).await });

        let (request_id, _) = read_card(&mut reader).await;
        let actor = DecisionActor::new("424242").with_display("Ada");
        rig.queue.resolve(
            &request_id,
            PendingDecision::Deny {
                reason: Some("not now".into()),
                actor: Some(actor.clone()),
            },
        );
        assert_eq!(
            waiting.await.unwrap(),
            ApprovalOutcome::Denied {
                reason: Some("not now".into()),
                actor: Some(actor),
            }
        );
    }

    #[tokio::test]
    async fn an_undecided_request_is_refused_and_forgotten() {
        let rig = rig(Some(CHANNEL_ID));
        let mut reader = connect(&rig);
        let outcome = gate(&rig, Duration::from_millis(50))
            .request_approval(&asked())
            .await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        let (request_id, _) = read_card(&mut reader).await;
        assert!(rig.queue.show(&request_id).is_none());
    }

    #[test]
    fn the_timeout_is_300_seconds_unless_set() {
        assert_eq!(discord_timeout_from(None), Duration::from_secs(300));
        assert_eq!(discord_timeout_from(Some("0")), Duration::from_secs(300));
        assert_eq!(discord_timeout_from(Some("ten")), Duration::from_secs(300));
        assert_eq!(discord_timeout_from(Some(" 45 ")), Duration::from_secs(45));
    }

    #[test]
    fn a_request_id_fits_a_discord_button() {
        use wirken_adapter_core::approval::{ApprovalPayload, DISCORD_CUSTOM_ID_MAX, Decision};
        let queue = PendingApprovalQueue::new();
        let (request_id, _) = queue.register(PendingRequest {
            agent_id: "default".into(),
            session_id: format!("default/discord/{CHANNEL_ID}"),
            tool_name: "exec".into(),
            action_key: "shell:pwd".into(),
            requested_tier: "tier2".into(),
            trigger_message: None,
            arguments: None,
            assistant_text: None,
            exec_location: None,
            exec_runtime: None,
            prompt_conversation: Some(CHANNEL_ID.into()),
        });
        for decision in [Decision::Allow, Decision::Deny] {
            let custom_id = wirken_adapter_core::approval::encode(&ApprovalPayload {
                request_id: request_id.clone(),
                decision,
            })
            .unwrap();
            assert!(custom_id.len() <= DISCORD_CUSTOM_ID_MAX, "{custom_id}");
        }
    }

    #[test]
    fn the_source_is_the_discord_channel() {
        let rig = rig(None);
        assert_eq!(
            gate(&rig, Duration::from_secs(1)).source(),
            ApprovalSource::ChannelAdapter {
                channel: "discord".into()
            }
        );
    }
}
