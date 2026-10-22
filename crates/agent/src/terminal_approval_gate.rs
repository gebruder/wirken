//! Terminal approval gate: bridges the agent's `ApprovalGate` trait to
//! the `wirken chat` client on the gateway's `terminal` channel.
//!
//! Shaped like `TelegramApprovalGate` and `SignalApprovalGate`: it
//! registers the request in the shared `PendingApprovalQueue`, writes
//! an `ApprovalRequest` frame, and waits for the queue to resolve. The
//! difference is where the frame goes. A Telegram request goes to the
//! one Telegram adapter's configured approval chat; a terminal request
//! goes to the connection whose message started the turn, found in
//! `TerminalSessions` by the turn's session, because the person who
//! typed the message is the operator at that terminal and several
//! terminals can be connected at once. A request from a sub-agent the
//! turn spawned is found by the session it was spawned from.
//!
//! The decision comes back on the same connection as an
//! `ApprovalDecision` frame, which the gateway's message loop accepts
//! only for a request this connection's own turn raised.
//!
//! Fails closed throughout: no connection for the session, a frame
//! that cannot be written, or a client that disconnects while the
//! request is open each refuse the call, and the runtime records the
//! refusal with this gate's source.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use wirken_audit::ApprovalSource;
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingDecision, PendingRequest};
use wirken_gateway::terminal_sessions::{TERMINAL_CHANNEL, TerminalSessions};
use wirken_ipc::wirken_capnp::frame;

use crate::approval_gate::{ApprovalGate, ApprovalOutcome};
use crate::error::PermissionDenialContext;
use crate::exec_location::runtime_name;

/// Default wall-clock cap on a terminal approval await. Same 300s as
/// the other out-of-band surfaces.
pub const DEFAULT_TERMINAL_TIMEOUT_SECS: u64 = 300;

/// The denial reason recorded when the terminal is gone before it
/// decided: closed, or not reachable to ask.
pub const CLIENT_GONE_REASON: &str = "terminal client disconnected";

pub fn resolve_terminal_timeout() -> Duration {
    terminal_timeout_from(
        std::env::var("WIRKEN_TERMINAL_APPROVAL_TIMEOUT_S")
            .ok()
            .as_deref(),
    )
}

/// The rule on its own, with the environment read lifted out, so the
/// tests cover it without writing a process-global variable.
fn terminal_timeout_from(raw: Option<&str>) -> Duration {
    match raw.map(|s| s.trim().parse::<u64>()) {
        Some(Ok(secs)) if secs > 0 => Duration::from_secs(secs),
        _ => Duration::from_secs(DEFAULT_TERMINAL_TIMEOUT_SECS),
    }
}

pub struct TerminalApprovalGate {
    queue: Arc<PendingApprovalQueue>,
    terminals: Arc<TerminalSessions>,
    /// Captured once at construction, as the other gates do.
    timeout: Duration,
}

impl TerminalApprovalGate {
    pub fn new(queue: Arc<PendingApprovalQueue>, terminals: Arc<TerminalSessions>) -> Self {
        Self::with_timeout(queue, terminals, resolve_terminal_timeout())
    }

    /// Construct with an explicit timeout instead of the value
    /// [`resolve_terminal_timeout`] reads from the environment.
    pub fn with_timeout(
        queue: Arc<PendingApprovalQueue>,
        terminals: Arc<TerminalSessions>,
        timeout: Duration,
    ) -> Self {
        Self {
            queue,
            terminals,
            timeout,
        }
    }
}

fn client_gone() -> ApprovalOutcome {
    ApprovalOutcome::Denied {
        reason: Some(CLIENT_GONE_REASON.into()),
        actor: None,
    }
}

#[async_trait]
impl ApprovalGate for TerminalApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        let root = crate::factory::root_session_id(&ctx.session_id);
        let Some(link) = self.terminals.link_for(root) else {
            tracing::warn!(
                agent = %ctx.agent_id,
                session = %ctx.session_id,
                tool = %ctx.tool_name,
                "terminal approval gate: no terminal connection is running this session's \
                 turn; failing closed"
            );
            return ApprovalOutcome::Timeout;
        };
        if link.is_gone() {
            return client_gone();
        }

        let request = PendingRequest {
            agent_id: ctx.agent_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            action_key: ctx.action.approval_key(),
            requested_tier: ctx.requested_tier.label().to_string(),
            trigger_message: ctx.trigger_message.clone(),
            arguments: ctx.arguments.clone(),
            assistant_text: ctx.assistant_text.clone(),
            exec_location: ctx.exec_location.as_ref().map(|l| l.text.clone()),
            exec_runtime: ctx
                .exec_location
                .as_ref()
                .map(|l| runtime_name(l.mode).to_string()),
        };
        let (request_id, rx) = self.queue.register(request);

        let mut message = capnp::message::Builder::new_default();
        {
            let mut req = message
                .init_root::<frame::Builder<'_>>()
                .init_approval_request();
            req.set_request_id(&request_id);
            req.set_tool_name(&ctx.tool_name);
            req.set_action_key(ctx.action.approval_key());
            req.set_requested_tier(ctx.requested_tier.label());
            req.set_triggering_agent(&ctx.agent_id);
            req.set_trigger_message(ctx.trigger_message.as_deref().unwrap_or(""));
            req.set_target_conversation_id(root.splitn(3, '/').nth(2).unwrap_or(""));
            req.set_exec_location(
                ctx.exec_location
                    .as_ref()
                    .map(|l| l.text.as_str())
                    .unwrap_or(""),
            );
            req.set_arguments(ctx.arguments.as_deref().unwrap_or(""));
            req.set_assistant_text(ctx.assistant_text.as_deref().unwrap_or(""));
            req.set_timeout_secs(u32::try_from(self.timeout.as_secs()).unwrap_or(u32::MAX));
            req.set_exec_runtime(
                ctx.exec_location
                    .as_ref()
                    .map(|l| runtime_name(l.mode))
                    .unwrap_or(""),
            );
        }

        if let Err(e) = link.writer().lock().await.write_message(&message).await {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                "terminal approval gate: could not send the ApprovalRequest frame; \
                 forgetting the queue entry and refusing"
            );
            self.queue.forget(&request_id);
            return client_gone();
        }

        tracing::info!(
            request_id = %request_id,
            tool = %ctx.tool_name,
            agent = %ctx.agent_id,
            "terminal approval pending; awaiting the operator's decision at the terminal"
        );

        tokio::select! {
            biased;
            decision = rx => match decision {
                Ok(PendingDecision::Allow { actor }) => ApprovalOutcome::Approved { actor },
                Ok(PendingDecision::Deny { reason, actor }) => {
                    ApprovalOutcome::Denied { reason, actor }
                }
                Ok(PendingDecision::Timeout) | Err(_) => ApprovalOutcome::Timeout,
            },
            () = link.gone() => {
                self.queue.forget(&request_id);
                tracing::info!(
                    request_id = %request_id,
                    "terminal approval withdrawn: the terminal disconnected before deciding"
                );
                client_gone()
            }
            () = tokio::time::sleep(self.timeout) => {
                self.queue.forget(&request_id);
                ApprovalOutcome::Timeout
            }
        }
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::ChannelAdapter {
            channel: TERMINAL_CHANNEL.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex as AsyncMutex;
    use wirken_gateway::permissions::{Action, PermissionTier};
    use wirken_gateway::terminal_sessions::TerminalConnection;
    use wirken_ipc::{IpcFrameReader, split_stream, test_pair};

    fn ctx(session_id: &str) -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: "exec".into(),
            action: Action::ShellExec {
                pattern: "ls".into(),
            },
            requested_tier: PermissionTier::Tier2,
            agent_id: "default".into(),
            trigger_message: Some("list the files".into()),
            arguments: Some(r#"{"command":"ls"}"#.into()),
            assistant_text: Some("I'll list them.".into()),
            exec_location: None,
            session_id: session_id.into(),
        }
    }

    fn connection() -> (TerminalConnection, IpcFrameReader) {
        let (a, b) = test_pair().unwrap();
        let (_unused_reader, writer) = split_stream(a);
        let (reader, _unused_writer) = split_stream(b);
        (
            TerminalConnection::new(Arc::new(AsyncMutex::new(writer))),
            reader,
        )
    }

    async fn request_id_of(reader: &mut IpcFrameReader) -> (String, String, String) {
        let msg = reader.read_message().await.unwrap();
        let frame::ApprovalRequest(req) = msg
            .get_root::<frame::Reader<'_>>()
            .unwrap()
            .which()
            .unwrap()
        else {
            panic!("expected ApprovalRequest");
        };
        let req = req.unwrap();
        (
            req.get_request_id().unwrap().to_string().unwrap(),
            req.get_arguments().unwrap().to_string().unwrap(),
            req.get_target_conversation_id()
                .unwrap()
                .to_string()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn no_connection_for_the_session_fails_closed_without_a_queue_entry() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let gate = TerminalApprovalGate::new(queue.clone(), Arc::new(TerminalSessions::new()));
        let outcome = gate.request_approval(&ctx("default/terminal/c1")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn the_request_reaches_the_turns_connection_and_its_decision_returns() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let sessions = Arc::new(TerminalSessions::new());
        let (conn, mut reader) = connection();
        let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
        let gate = TerminalApprovalGate::new(queue.clone(), sessions);

        let task =
            tokio::spawn(async move { gate.request_approval(&ctx("default/terminal/c1")).await });
        let (request_id, arguments, conversation) = request_id_of(&mut reader).await;
        assert_eq!(arguments, r#"{"command":"ls"}"#);
        assert_eq!(conversation, "c1");
        queue.resolve(
            &request_id,
            PendingDecision::Allow {
                actor: Some("op".into()),
            },
        );
        assert_eq!(
            task.await.unwrap(),
            ApprovalOutcome::Approved {
                actor: Some("op".into())
            }
        );
    }

    #[tokio::test]
    async fn a_sub_agents_request_reaches_the_connection_that_spawned_it() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let sessions = Arc::new(TerminalSessions::new());
        let (conn, mut reader) = connection();
        let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
        let gate = TerminalApprovalGate::new(queue.clone(), sessions);

        let task = tokio::spawn(async move {
            gate.request_approval(&ctx("default/terminal/c1#sub-0#sub-1"))
                .await
        });
        let (request_id, _, conversation) = request_id_of(&mut reader).await;
        assert_eq!(conversation, "c1");
        queue.resolve(
            &request_id,
            PendingDecision::Deny {
                reason: None,
                actor: None,
            },
        );
        assert_eq!(
            task.await.unwrap(),
            ApprovalOutcome::Denied {
                reason: None,
                actor: None
            }
        );
    }

    #[tokio::test]
    async fn a_client_that_disconnects_while_asked_is_refused_and_the_entry_withdrawn() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let sessions = Arc::new(TerminalSessions::new());
        let (conn, mut reader) = connection();
        let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
        let gate = TerminalApprovalGate::new(queue.clone(), sessions);

        let task =
            tokio::spawn(async move { gate.request_approval(&ctx("default/terminal/c1")).await });
        let (request_id, _, _) = request_id_of(&mut reader).await;
        conn.mark_gone();
        assert_eq!(task.await.unwrap(), client_gone());
        assert!(queue.show(&request_id).is_none(), "the entry is withdrawn");
    }

    #[tokio::test]
    async fn the_timeout_forgets_the_entry() {
        let queue = Arc::new(PendingApprovalQueue::new());
        let sessions = Arc::new(TerminalSessions::new());
        let (conn, _reader) = connection();
        let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
        let gate =
            TerminalApprovalGate::with_timeout(queue.clone(), sessions, Duration::from_millis(50));
        let outcome = gate.request_approval(&ctx("default/terminal/c1")).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
        assert!(queue.is_empty());
    }

    /// The card names the runtime from the exec location the runtime
    /// computed from the agent's sandbox settings; the client is told,
    /// it does not guess.
    #[tokio::test]
    async fn the_request_names_the_runtime_the_exec_would_run_under() {
        for (mode, expected) in [
            (wirken_audit::SandboxModeLabel::Gvisor, "gvisor"),
            (wirken_audit::SandboxModeLabel::ExecOnly, "docker"),
            (wirken_audit::SandboxModeLabel::Off, "host"),
        ] {
            let queue = Arc::new(PendingApprovalQueue::new());
            let sessions = Arc::new(TerminalSessions::new());
            let (conn, mut reader) = connection();
            let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
            let gate = TerminalApprovalGate::new(queue.clone(), sessions);
            let mut asked = ctx("default/terminal/c1");
            asked.exec_location = Some(wirken_audit::ExecLocation {
                mode,
                text: "runs somewhere".into(),
            });
            let task = tokio::spawn(async move { gate.request_approval(&asked).await });
            let msg = reader.read_message().await.unwrap();
            let frame::ApprovalRequest(req) = msg
                .get_root::<frame::Reader<'_>>()
                .unwrap()
                .which()
                .unwrap()
            else {
                panic!("expected ApprovalRequest");
            };
            let req = req.unwrap();
            assert_eq!(req.get_exec_runtime().unwrap().to_str().unwrap(), expected);
            let id = req.get_request_id().unwrap().to_string().unwrap();
            queue.resolve(
                &id,
                PendingDecision::Deny {
                    reason: None,
                    actor: None,
                },
            );
            task.await.unwrap();
        }
    }

    #[test]
    fn the_source_is_the_terminal_channel() {
        let gate = TerminalApprovalGate::new(
            Arc::new(PendingApprovalQueue::new()),
            Arc::new(TerminalSessions::new()),
        );
        assert_eq!(
            gate.source(),
            ApprovalSource::ChannelAdapter {
                channel: "terminal".into()
            }
        );
    }

    #[test]
    fn the_timeout_override_needs_a_positive_number() {
        assert_eq!(terminal_timeout_from(Some("30")), Duration::from_secs(30));
        for raw in [None, Some("0"), Some("soon")] {
            assert_eq!(
                terminal_timeout_from(raw),
                Duration::from_secs(DEFAULT_TERMINAL_TIMEOUT_SECS)
            );
        }
    }
}
