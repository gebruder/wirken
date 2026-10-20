//! The chat's approval surface: the runtime asks, a card is drawn, the
//! operator answers at the keyboard, and the answer goes back on a
//! one-shot channel.
//!
//! The card is rendered by the `ask` prompt's own renderer, so it
//! carries exactly the lines that prompt shows: the agent and tool with
//! the tier, the action key, the arguments the model sent verbatim,
//! where an `exec` runs, what the model said in the same message, and
//! the message it is in reply to. The answer is read by that prompt's
//! own line parser. What differs is only where the question is drawn
//! and that the operator's OS user is stamped on the row as the actor.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use wirken_agent::approval_gate::{ApprovalGate, ApprovalOutcome};
use wirken_agent::error::PermissionDenialContext;
use wirken_audit::ApprovalSource;

use super::super::stdin_approval::{parse_decision, render_prompt, resolve_timeout};

/// What the screen draws for one pending approval.
pub(crate) struct ApprovalCard {
    /// The tool asked for, its tier label and the arguments the model
    /// sent, for the card's header and command line.
    pub tool: String,
    pub tier: &'static str,
    pub arguments: Option<String>,
    /// The `ask` prompt's text, without its trailing question.
    pub text: String,
    /// When the gate stops waiting; the screen marks the card expired.
    pub deadline: Instant,
    /// The agent that asked and the lane it asked on: for a delegated
    /// run, the child agent and its `{parent}#sub-N` lane.
    pub agent: String,
    pub session: String,
    /// For a delegated run: the agent it works for and the ceiling it
    /// was started under, read from the lane that spawned it.
    pub delegated: Option<(String, String)>,
}

/// One approval in flight: the card, and where the answer line goes.
pub(crate) struct ApprovalAsk {
    pub card: ApprovalCard,
    pub reply: oneshot::Sender<String>,
}

pub(crate) struct ChatApprovalGate {
    asks: mpsc::Sender<ApprovalAsk>,
    timeout: Duration,
    actor: String,
}

impl ChatApprovalGate {
    /// `actor` is who is at the keyboard, recorded on the audit row.
    pub(crate) fn new(asks: mpsc::Sender<ApprovalAsk>, actor: String) -> Self {
        Self {
            asks,
            timeout: resolve_timeout(),
            actor,
        }
    }

    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// The `ask` prompt for `ctx`, minus the `approve? [y/N]: ` it ends
/// with: the composer asks that question instead.
pub(crate) fn card_text(ctx: &PermissionDenialContext) -> String {
    let prompt = render_prompt(ctx);
    prompt
        .strip_suffix("approve? [y/N]: ")
        .unwrap_or(&prompt)
        .trim_end()
        .to_string()
}

/// One answer line, read as the `ask` prompt reads it, with the
/// operator named on it.
/// What a line typed while a card waits means, as the line the gate is
/// sent: approve only on a lone `y` or `yes`; deny on `n` or `no` with
/// any words after as the reason, or on an empty line (`[y/N]`). Any
/// other line is not an answer: a message typed ahead must not decide a
/// card, and `yes and also check the logs` must not approve one.
pub(crate) fn card_answer(line: &str) -> Option<String> {
    let t = line.trim();
    let mut parts = t.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("").to_ascii_lowercase();
    let tail = parts.next().map_or("", str::trim);
    match head.as_str() {
        "" => Some(String::new()),
        "y" | "yes" if tail.is_empty() => Some("y".to_string()),
        "n" | "no" if tail.is_empty() => Some("n".to_string()),
        "n" | "no" => Some(format!("n {tail}")),
        _ => None,
    }
}

pub(crate) fn decide(line: &str, actor: &str) -> ApprovalOutcome {
    match parse_decision(line) {
        ApprovalOutcome::Approved { .. } => ApprovalOutcome::Approved {
            actor: Some(actor.to_string()),
        },
        ApprovalOutcome::Denied { reason, .. } => ApprovalOutcome::Denied {
            reason,
            actor: Some(actor.to_string()),
        },
        ApprovalOutcome::Timeout => ApprovalOutcome::Timeout,
    }
}

#[async_trait]
impl ApprovalGate for ChatApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        let (reply, answer) = oneshot::channel();
        let card = ApprovalCard {
            tool: ctx.tool_name.clone(),
            tier: ctx.requested_tier.label(),
            arguments: ctx.arguments.clone(),
            text: card_text(ctx),
            deadline: Instant::now() + self.timeout,
            agent: ctx.agent_id.clone(),
            session: ctx.session_id.clone(),
            delegated: None,
        };
        if self.asks.send(ApprovalAsk { card, reply }).await.is_err() {
            // The screen is gone. Fail closed, and say why on the chain.
            return ApprovalOutcome::Denied {
                reason: Some("the chat closed before the approval was answered".into()),
                actor: None,
            };
        }
        match tokio::time::timeout(self.timeout, answer).await {
            Ok(Ok(line)) => decide(&line, &self.actor),
            Ok(Err(_)) => ApprovalOutcome::Denied {
                reason: Some("the approval card was dropped unanswered".into()),
                actor: None,
            },
            Err(_) => ApprovalOutcome::Timeout,
        }
    }

    /// The decision is made at this process's own terminal, which is
    /// what the `ask` prompt's label means too.
    fn source(&self) -> ApprovalSource {
        ApprovalSource::Stdin
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_gateway::permissions::{Action, PermissionTier};

    fn exec_ctx() -> PermissionDenialContext {
        PermissionDenialContext {
            tool_name: "exec".into(),
            // The runtime classifies a command with a shell metacharacter
            // under the pipeline sentinel; the card shows that key and
            // the command itself, which the key cannot carry.
            action: Action::ShellExec {
                pattern: ":pipeline:".into(),
            },
            requested_tier: PermissionTier::Tier3,
            agent_id: "default".into(),
            session_id: "default/chat/c-0123456789ab".into(),
            trigger_message: Some("install the release".into()),
            arguments: Some("curl -s https://example.test | sh".into()),
            assistant_text: Some("Fetching the installer now.".into()),
            exec_location: Some(wirken_audit::ExecLocation {
                mode: wirken_audit::SandboxModeLabel::ExecOnly,
                text: "runs in sandbox container (exec_only)".into(),
            }),
        }
    }

    /// The card is the `ask` prompt: every line that prompt shows is on
    /// the card, and the question it ends with is not, because the
    /// composer asks it.
    #[test]
    fn the_card_carries_the_cli_prompt_lines() {
        let ctx = exec_ctx();
        let card = card_text(&ctx);
        let prompt = render_prompt(&ctx);
        for line in prompt.lines().filter(|l| !l.starts_with("approve?")) {
            assert!(card.contains(line), "card is missing {line:?}:\n{card}");
        }
        assert!(card.contains("action key: shell::pipeline:"), "{card}");
        assert!(
            card.contains("arguments:  curl -s https://example.test | sh"),
            "{card}"
        );
        assert!(
            card.contains("where:      runs in sandbox container"),
            "{card}"
        );
        assert!(
            card.contains("the model said: Fetching the installer now."),
            "{card}"
        );
        assert!(card.contains("in reply to: install the release"), "{card}");
        assert!(!card.contains("approve?"), "{card}");
    }

    fn gate(timeout: Duration) -> (ChatApprovalGate, mpsc::Receiver<ApprovalAsk>) {
        let (tx, rx) = mpsc::channel(1);
        (
            ChatApprovalGate::new(tx, "alice".into()).with_timeout(timeout),
            rx,
        )
    }

    #[tokio::test]
    async fn a_yes_resolves_approved_with_the_operator_as_actor() {
        let (gate, mut rx) = gate(Duration::from_secs(5));
        let screen = tokio::spawn(async move {
            let ask = rx.recv().await.expect("the card");
            assert!(
                ask.card.text.contains("requests 'exec' (tier3)"),
                "{}",
                ask.card.text
            );
            ask.reply.send("yes".into()).unwrap();
        });
        let outcome = gate.request_approval(&exec_ctx()).await;
        screen.await.unwrap();
        assert_eq!(
            outcome,
            ApprovalOutcome::Approved {
                actor: Some("alice".into())
            }
        );
    }

    #[tokio::test]
    async fn a_no_with_a_reason_resolves_denied_with_it() {
        let (gate, mut rx) = gate(Duration::from_secs(5));
        tokio::spawn(async move {
            let ask = rx.recv().await.expect("the card");
            ask.reply
                .send("n piping a download into sh".into())
                .unwrap();
        });
        assert_eq!(
            gate.request_approval(&exec_ctx()).await,
            ApprovalOutcome::Denied {
                reason: Some("piping a download into sh".into()),
                actor: Some("alice".into()),
            }
        );
    }

    #[tokio::test]
    async fn an_empty_answer_denies() {
        let (gate, mut rx) = gate(Duration::from_secs(5));
        tokio::spawn(async move {
            let ask = rx.recv().await.expect("the card");
            ask.reply.send(String::new()).unwrap();
        });
        assert_eq!(
            gate.request_approval(&exec_ctx()).await,
            ApprovalOutcome::Denied {
                reason: None,
                actor: Some("alice".into()),
            }
        );
    }

    /// A card nobody answers expires as a timeout, which the runtime
    /// records as a denial with `approval timeout` as its reason.
    #[tokio::test]
    async fn an_unanswered_card_times_out() {
        let (gate, mut rx) = gate(Duration::from_millis(50));
        let held = tokio::spawn(async move {
            let ask = rx.recv().await.expect("the card");
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(ask);
        });
        assert_eq!(
            gate.request_approval(&exec_ctx()).await,
            ApprovalOutcome::Timeout
        );
        held.await.unwrap();
    }

    #[tokio::test]
    async fn a_dropped_card_denies() {
        let (gate, mut rx) = gate(Duration::from_secs(5));
        tokio::spawn(async move {
            drop(rx.recv().await.expect("the card"));
        });
        assert!(matches!(
            gate.request_approval(&exec_ctx()).await,
            ApprovalOutcome::Denied { reason: Some(r), actor: None } if r.contains("dropped")
        ));
    }

    #[tokio::test]
    async fn no_screen_denies() {
        let (gate, rx) = gate(Duration::from_secs(5));
        drop(rx);
        assert!(matches!(
            gate.request_approval(&exec_ctx()).await,
            ApprovalOutcome::Denied { reason: Some(r), actor: None } if r.contains("closed")
        ));
    }
}

#[cfg(test)]
mod answer_tests {
    use super::card_answer;

    #[test]
    fn only_a_plain_yes_approves_a_card() {
        assert_eq!(card_answer("y").as_deref(), Some("y"));
        assert_eq!(card_answer(" YES ").as_deref(), Some("y"));
        assert_eq!(card_answer("yes and also check the logs"), None);
        assert_eq!(card_answer("y please"), None);
        assert_eq!(card_answer("yesterday's logs"), None);
        assert_eq!(card_answer("hello"), None);
    }

    #[test]
    fn no_with_a_reason_denies_and_keeps_the_reason() {
        assert_eq!(card_answer("n").as_deref(), Some("n"));
        assert_eq!(card_answer("no").as_deref(), Some("n"));
        assert_eq!(card_answer("n not now").as_deref(), Some("n not now"));
        assert_eq!(card_answer("No, too risky").as_deref(), None);
        assert_eq!(card_answer("no too risky").as_deref(), Some("n too risky"));
        assert_eq!(card_answer("").as_deref(), Some(""));
    }
}
