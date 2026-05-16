//! Live-stream registry for the webchat approval surface.
//!
//! Keyed by `SessionId`, holds the `mpsc::Sender<SseEvent>` for the
//! /api/chat handler's currently-running SSE response stream. The
//! `SseApprovalGate` (in `wirken-agent`) looks the sender up at
//! `request_approval` time and pushes an `ApprovalRequest` event;
//! the /api/approvals/{request_id} POST handler looks up the same
//! sender to push an `ApprovalDecisionAck` once the queue resolves.
//!
//! ## Lifetime contract
//!
//! Entries live only for the duration of one /api/chat request.
//! The handler registers on entry and unregisters on exit. The
//! `register_guard` returns a `RegistryGuard` whose `Drop` impl
//! removes the entry; this survives panics, early returns from
//! the SSE-forwarder task, and the cancel-safety quirks of async
//! code. Bare `register` is available for tests but production
//! callers should use the guard.
//!
//! ## Why this lives in `wirken-gateway`
//!
//! Mirrors `OutboundDispatcher` (channel-adapter live-writer
//! registry) and `PendingApprovalQueue` (operator-decide queue):
//! shared state that both the agent's gate (via `Arc<...>`) and
//! the per-request handler manipulate, owned by gateway because
//! gateway is the dependency root that agent imports from. The
//! gate in agent holds `Arc<SseApprovalRegistry>` exactly the way
//! `TelegramApprovalGate` holds `Arc<OutboundDispatcher>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use wirken_audit::SessionId;

/// Result the gateway communicates back to the operator's browser
/// when their `/api/approvals/{request_id}` POST has been
/// processed. `Accepted` means the queue resolved the entry and
/// the awaiting agent task was signaled. `UnknownKey` collapses
/// "never existed" and "already resolved" (the operator's UI shows
/// the same "your decision arrived too late" message in either
/// case; the audit chain has the actual outcome).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AckResult {
    Accepted,
    UnknownKey,
    /// Reserved for a future "tombstone seen, decision arrived
    /// later than a timeout" distinction. Not used today —
    /// `UnknownKey` covers both cases — but parsing-side support
    /// exists so a future audit-chain extension that tracks
    /// timed-out entries explicitly does not need a wire change.
    Expired,
}

/// One server-sent event pushed from the gateway's mpsc forwarder
/// into the browser's `/api/chat` SSE stream. Serialized as JSON
/// with a `type` discriminator matching the existing event format
/// (`{"type":"delta","text":...}`). The slice adds two new types
/// alongside the existing delta/error events the agent loop emits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SseEvent {
    /// Gateway → browser. Fires when an agent hits `NeedsApproval`
    /// during a tool dispatch inside the in-flight /api/chat
    /// request. The browser renders an approval card and waits for
    /// the operator's click.
    ApprovalRequest {
        request_id: String,
        tool_name: String,
        action_key: String,
        requested_tier: String,
        triggering_agent: String,
        trigger_message: String,
    },
    /// Gateway → browser. Fires after the operator POSTs to
    /// /api/approvals/{request_id}. Distinct from
    /// fire-and-forget acknowledgments (Telegram's
    /// answer_callback_query): carries `result` so the browser
    /// learns whether its decision actually landed or was rejected
    /// because the queue had already moved on. The
    /// channel-adapter slices that follow should adopt this shape
    /// where their platform's UX supports it.
    ApprovalDecisionAck {
        request_id: String,
        result: AckResult,
    },
}

impl SseEvent {
    /// Serialize as a single SSE `data:` line plus the required
    /// `\n\n` terminator. The forwarder task writes the bytes
    /// straight to the TCP stream.
    pub fn to_sse_line(&self) -> String {
        // Construction-time `to_string` cannot fail on a serde-
        // derived enum with String/owned fields; if a future
        // extension introduces a non-serializable variant the
        // panic surfaces in tests.
        let payload = serde_json::to_string(self).expect("SseEvent must serialize; check derive");
        format!("data: {payload}\n\n")
    }
}

#[derive(Default)]
pub struct SseApprovalRegistry {
    senders: Mutex<HashMap<SessionId, mpsc::Sender<SseEvent>>>,
}

impl SseApprovalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bare register/unregister pair for tests and call sites that
    /// manage lifetime explicitly. Production callers should use
    /// [`Self::register_guard`] so cleanup runs on every exit path.
    pub fn register(&self, session_id: SessionId, sender: mpsc::Sender<SseEvent>) {
        self.senders
            .lock()
            .expect("sse approval registry mutex")
            .insert(session_id, sender);
    }

    /// Idempotent removal. A `register_guard` Drop calls this; a
    /// double-unregister from a buggy call site is a no-op.
    pub fn unregister(&self, session_id: &SessionId) {
        self.senders
            .lock()
            .expect("sse approval registry mutex")
            .remove(session_id);
    }

    /// Lookup the live sender for `session_id`. `None` when no
    /// /api/chat request is currently in flight for that session;
    /// the gate's preflight reads this as "no SSE stream to push
    /// to" and fails closed.
    pub fn sender_for(&self, session_id: &SessionId) -> Option<mpsc::Sender<SseEvent>> {
        self.senders
            .lock()
            .expect("sse approval registry mutex")
            .get(session_id)
            .cloned()
    }

    /// Register with an RAII guard. The returned `RegistryGuard`
    /// unregisters on Drop. Use this in async handlers so panics,
    /// early returns via `?`, and `.await` cancellations all
    /// clean up. The guard owns an `Arc<Self>` so the registry
    /// outlives the guard's clone even when the original `Arc` is
    /// moved.
    pub fn register_guard(
        self: &Arc<Self>,
        session_id: SessionId,
        sender: mpsc::Sender<SseEvent>,
    ) -> RegistryGuard {
        self.register(session_id.clone(), sender);
        RegistryGuard {
            registry: Some(self.clone()),
            session_id,
        }
    }
}

/// RAII guard that unregisters its session id when dropped. The
/// pattern is borrowed from existing Rust idioms for per-request
/// state; this is the first instance in the wirken codebase and
/// is worth becoming the default shape for any future per-request
/// live-writer registry that follows.
pub struct RegistryGuard {
    registry: Option<Arc<SseApprovalRegistry>>,
    session_id: SessionId,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Some(reg) = self.registry.take() {
            reg.unregister(&self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(s: &str) -> SessionId {
        SessionId::new(s.to_string())
    }

    #[tokio::test]
    async fn register_then_sender_for_returns_sender() {
        let reg = SseApprovalRegistry::new();
        let (tx, _rx) = mpsc::channel::<SseEvent>(8);
        reg.register(sess("a"), tx);
        assert!(reg.sender_for(&sess("a")).is_some());
    }

    #[tokio::test]
    async fn sender_for_absent_session_is_none() {
        let reg = SseApprovalRegistry::new();
        assert!(reg.sender_for(&sess("nope")).is_none());
    }

    #[tokio::test]
    async fn unregister_removes_entry() {
        let reg = SseApprovalRegistry::new();
        let (tx, _rx) = mpsc::channel::<SseEvent>(8);
        reg.register(sess("a"), tx);
        reg.unregister(&sess("a"));
        assert!(reg.sender_for(&sess("a")).is_none());
    }

    #[tokio::test]
    async fn unregister_unknown_session_is_noop() {
        let reg = SseApprovalRegistry::new();
        reg.unregister(&sess("nope")); // does not panic
    }

    #[tokio::test]
    async fn raii_guard_unregisters_on_drop() {
        let reg = Arc::new(SseApprovalRegistry::new());
        let (tx, _rx) = mpsc::channel::<SseEvent>(8);
        {
            let _guard = reg.register_guard(sess("a"), tx);
            assert!(reg.sender_for(&sess("a")).is_some());
        }
        // Guard dropped at end of scope.
        assert!(reg.sender_for(&sess("a")).is_none());
    }

    #[tokio::test]
    async fn raii_guard_survives_panic_in_owning_task() {
        // The Drop on RegistryGuard runs during unwind, so a
        // panicking caller still cleans up. The slice's
        // load-bearing property; pin it.
        let reg = Arc::new(SseApprovalRegistry::new());
        let (tx, _rx) = mpsc::channel::<SseEvent>(8);
        let reg_for_task = reg.clone();
        let handle = tokio::spawn(async move {
            let _guard = reg_for_task.register_guard(sess("a"), tx);
            panic!("simulated handler panic");
        });
        let _ = handle.await; // task panicked; guard ran during unwind
        assert!(
            reg.sender_for(&sess("a")).is_none(),
            "panicking owner must still trigger guard unregister"
        );
    }

    #[test]
    fn approval_request_event_serializes_with_type_discriminator() {
        let ev = SseEvent::ApprovalRequest {
            request_id: "r".into(),
            tool_name: "shell".into(),
            action_key: "shell:rm".into(),
            requested_tier: "tier3".into(),
            triggering_agent: "default".into(),
            trigger_message: "clean logs".into(),
        };
        let line = ev.to_sse_line();
        assert!(line.starts_with("data: "));
        assert!(line.ends_with("\n\n"));
        let body = line
            .strip_prefix("data: ")
            .unwrap()
            .strip_suffix("\n\n")
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["type"], "approval_request");
        assert_eq!(v["request_id"], "r");
        assert_eq!(v["tool_name"], "shell");
    }

    #[test]
    fn approval_decision_ack_round_trips_each_result_kind() {
        for result in [
            AckResult::Accepted,
            AckResult::UnknownKey,
            AckResult::Expired,
        ] {
            let ev = SseEvent::ApprovalDecisionAck {
                request_id: "r".into(),
                result: result.clone(),
            };
            let line = ev.to_sse_line();
            let body = line
                .strip_prefix("data: ")
                .unwrap()
                .strip_suffix("\n\n")
                .unwrap();
            let back: SseEvent = serde_json::from_str(body).unwrap();
            match back {
                SseEvent::ApprovalDecisionAck {
                    request_id,
                    result: got,
                } => {
                    assert_eq!(request_id, "r");
                    assert_eq!(got, result);
                }
                _ => panic!("expected ApprovalDecisionAck"),
            }
        }
    }
}
