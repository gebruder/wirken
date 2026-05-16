//! Pending-approval queue for the out-of-band CLI approval path.
//!
//! `NeedsApproval` short-circuits today (post the stdin-gate slice)
//! either fail terminally (no gate attached) or block on the
//! attached gate's `request_approval`. For the daemon-mode case
//! where stdin is unavailable, `CliApprovalGate` (in `wirken-agent`)
//! suspends the agent task by inserting an entry into this queue
//! and awaiting a `oneshot::Receiver`. `wirken permissions pending
//! approve` (in `wirken-cli`) sends a JSON-line decision over
//! `gateway-permissions.sock`; the gateway's IPC handler calls
//! `resolve` on this queue, which sends the decision over the
//! oneshot and unblocks the agent.
//!
//! ## Decision type
//!
//! The queue is owned by `wirken-gateway` but the consuming gate
//! lives in `wirken-agent` (where the `ApprovalGate` trait lives).
//! Gateway cannot depend on agent (the dependency direction is
//! `agent → gateway`); the gate cannot move into gateway because it
//! impls a trait whose definition is in agent. The queue therefore
//! uses a gateway-local `PendingDecision` enum identical in shape
//! to `agent::approval_gate::ApprovalOutcome`; the gate translates
//! between the two at the await boundary. Two enums, three values
//! each — the layering cost is one `From` impl in agent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::oneshot;
use uuid::Uuid;

/// Decision communicated from the queue back to the awaiting gate.
/// Same three-valued shape as `agent::approval_gate::ApprovalOutcome`;
/// the gate maps `Allow ↔ Approved`, `Deny ↔ Denied`, `Timeout`
/// passes through. `actor` is the operator-identity label the IPC
/// handler reads from the JSON request (e.g. `$USER`); the gate
/// threads it into `ApprovalOutcome.actor` so the audit row's
/// `approved_by` carries the operator's identity rather than the
/// surface-derived default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingDecision {
    Allow {
        actor: Option<String>,
    },
    Deny {
        reason: Option<String>,
        actor: Option<String>,
    },
    Timeout,
}

/// Request fields the gate hands to the queue on registration.
/// Lossless mirror of the operator-visible portion of
/// `PermissionDenialContext` plus a minted timestamp.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub agent_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub trigger_message: Option<String>,
}

/// Per-entry shape kept in the queue. The receiver half of the
/// oneshot lives in the gate's await; the sender half is consumed
/// here when `resolve` is called.
struct Entry {
    request: PendingRequest,
    requested_at: DateTime<Utc>,
    requested_instant: Instant,
    tx: oneshot::Sender<PendingDecision>,
}

/// Outcome of a `resolve` call from the IPC handler. `Accepted` and
/// `UnknownKey` map directly to the wire shape in
/// `wirken_ipc::permissions::DecisionResult`. `UnknownKey` collapses
/// "never existed" and "already resolved" because the queue does
/// not retain a tombstone for resolved request_ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveResult {
    Accepted,
    UnknownKey,
}

/// Full per-entry detail for the show path. Includes the trigger
/// message; the list path omits it.
#[derive(Debug, Clone)]
pub struct PendingDetail {
    pub request_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub trigger_message: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub age_seconds: u64,
}

/// Compact per-entry shape for the list path.
#[derive(Debug, Clone)]
pub struct PendingSummary {
    pub request_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub requested_at: DateTime<Utc>,
    pub age_seconds: u64,
}

/// Default wall-clock cap on an awaiting `request_approval`.
/// Overridable via `WIRKEN_CLI_APPROVAL_TIMEOUT_S`. 300 seconds is
/// longer than the stdin gate's 60s because out-of-band approval
/// is expected to involve an operator finding another terminal.
pub const DEFAULT_CLI_TIMEOUT_SECS: u64 = 300;

pub fn resolve_cli_timeout() -> Duration {
    match std::env::var("WIRKEN_CLI_APPROVAL_TIMEOUT_S") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_CLI_TIMEOUT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_CLI_TIMEOUT_SECS),
    }
}

/// Gateway-side state for the operator-decide flow. Shared between
/// the agent's `CliApprovalGate` (which `register`s entries and
/// receives outcomes) and the gateway's permissions-IPC accept
/// loop (which `list`s entries and calls `resolve` on operator
/// decisions).
#[derive(Default, Clone)]
pub struct PendingApprovalQueue {
    inner: Arc<Mutex<HashMap<String, Entry>>>,
}

impl PendingApprovalQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh entry, return the minted request_id and the
    /// oneshot receiver the gate will await. The receiver yields
    /// the operator's decision when the IPC handler calls
    /// `resolve`, or the sender is dropped (gateway shutdown / queue
    /// purge) which the gate observes as a closed channel.
    pub fn register(
        &self,
        request: PendingRequest,
    ) -> (String, oneshot::Receiver<PendingDecision>) {
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let entry = Entry {
            request,
            requested_at: Utc::now(),
            requested_instant: Instant::now(),
            tx,
        };
        self.inner.lock().unwrap().insert(request_id.clone(), entry);
        (request_id, rx)
    }

    /// Remove an entry without resolving it. Used by the gate when
    /// its own timeout fires before the operator decides — drop the
    /// sender so subsequent `resolve` calls see `UnknownKey`. If
    /// the entry was already consumed (another resolve raced),
    /// `forget` is a no-op.
    pub fn forget(&self, request_id: &str) {
        self.inner.lock().unwrap().remove(request_id);
    }

    /// Apply an operator decision. Returns `Accepted` when the
    /// entry was present (and the gate's receiver is now signaled),
    /// `UnknownKey` otherwise. The two-state response collapses
    /// "never existed" and "already resolved" because the queue
    /// does not retain a tombstone for resolved ids; SIEM consumers
    /// see the actual decision on the audit chain in either case.
    pub fn resolve(&self, request_id: &str, decision: PendingDecision) -> ResolveResult {
        // Race: if the gate's tokio::time::timeout fires while
        // resolve() is mid-call, the entry is removed and tx.send
        // may succeed into an already-dropping receiver. The gate
        // returns Timeout, the audit chain records timeout-denial,
        // but the HTTP response to the operator returned Accepted.
        // Sub-millisecond window. Audit chain is authoritative; the
        // operator-UI mismatch is the cost.
        let entry = self.inner.lock().unwrap().remove(request_id);
        match entry {
            Some(e) => match e.tx.send(decision) {
                Ok(()) => ResolveResult::Accepted,
                // The receiver was dropped: the gate's own timeout
                // fired and the gate already returned `Timeout`.
                // Treat the same as UnknownKey at the wire level.
                Err(_) => ResolveResult::UnknownKey,
            },
            None => ResolveResult::UnknownKey,
        }
    }

    /// Snapshot of the queue for `wirken permissions pending list`.
    /// Order is unspecified; the CLI sorts by request_id for
    /// stable display.
    pub fn list(&self) -> Vec<PendingSummary> {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|(id, e)| PendingSummary {
                request_id: id.clone(),
                agent_id: e.request.agent_id.clone(),
                tool_name: e.request.tool_name.clone(),
                action_key: e.request.action_key.clone(),
                requested_tier: e.request.requested_tier.clone(),
                requested_at: e.requested_at,
                age_seconds: now.saturating_duration_since(e.requested_instant).as_secs(),
            })
            .collect()
    }

    /// Per-entry detail for `wirken permissions pending show`.
    /// Returns `None` if the entry has already been resolved or
    /// never existed.
    pub fn show(&self, request_id: &str) -> Option<PendingDetail> {
        let guard = self.inner.lock().unwrap();
        let e = guard.get(request_id)?;
        let now = Instant::now();
        Some(PendingDetail {
            request_id: request_id.to_string(),
            agent_id: e.request.agent_id.clone(),
            tool_name: e.request.tool_name.clone(),
            action_key: e.request.action_key.clone(),
            requested_tier: e.request.requested_tier.clone(),
            trigger_message: e.request.trigger_message.clone(),
            requested_at: e.requested_at,
            age_seconds: now.saturating_duration_since(e.requested_instant).as_secs(),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str) -> PendingRequest {
        PendingRequest {
            agent_id: "default".into(),
            tool_name: name.into(),
            action_key: format!("shell:{name}"),
            requested_tier: "tier2".into(),
            trigger_message: Some("user said something".into()),
        }
    }

    #[tokio::test]
    async fn register_then_resolve_allow_routes_decision_to_receiver() {
        let q = PendingApprovalQueue::new();
        let (id, rx) = q.register(req("exec"));
        let result = q.resolve(&id, PendingDecision::Allow { actor: None });
        assert_eq!(result, ResolveResult::Accepted);
        let decision = rx.await.unwrap();
        assert_eq!(decision, PendingDecision::Allow { actor: None });
    }

    #[tokio::test]
    async fn register_then_resolve_deny_routes_reason() {
        let q = PendingApprovalQueue::new();
        let (id, rx) = q.register(req("rm"));
        q.resolve(
            &id,
            PendingDecision::Deny {
                reason: Some("looks dangerous".into()),
                actor: Some("davi".into()),
            },
        );
        let decision = rx.await.unwrap();
        match decision {
            PendingDecision::Deny { reason, actor } => {
                assert_eq!(reason.as_deref(), Some("looks dangerous"));
                assert_eq!(actor.as_deref(), Some("davi"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_unknown_key_returns_unknown() {
        let q = PendingApprovalQueue::new();
        let result = q.resolve("not-a-real-id", PendingDecision::Allow { actor: None });
        assert_eq!(result, ResolveResult::UnknownKey);
    }

    #[tokio::test]
    async fn resolve_after_first_resolve_returns_unknown() {
        // Race semantics: two operators send decisions for the same
        // pending entry. First wins, second sees UnknownKey because
        // the entry was already removed.
        let q = PendingApprovalQueue::new();
        let (id, _rx) = q.register(req("exec"));
        let first = q.resolve(&id, PendingDecision::Allow { actor: None });
        let second = q.resolve(
            &id,
            PendingDecision::Deny {
                reason: Some("racing".into()),
                actor: None,
            },
        );
        assert_eq!(first, ResolveResult::Accepted);
        assert_eq!(second, ResolveResult::UnknownKey);
    }

    #[tokio::test]
    async fn forget_makes_subsequent_resolve_unknown() {
        // Gate-side timeout path: gate fires its own deadline,
        // calls `forget` to clear the entry, then later an
        // operator decision arrives. The queue treats it as
        // UnknownKey because the entry is gone.
        let q = PendingApprovalQueue::new();
        let (id, _rx) = q.register(req("exec"));
        q.forget(&id);
        let result = q.resolve(&id, PendingDecision::Allow { actor: None });
        assert_eq!(result, ResolveResult::UnknownKey);
    }

    #[tokio::test]
    async fn resolve_after_receiver_dropped_returns_unknown() {
        // Gate suspended on the receiver, then the gate's task got
        // cancelled (rare but possible). The oneshot's send returns
        // Err; the queue reports UnknownKey to the operator. The
        // operator's audit-event emit on the IPC-handler side does
        // not need to fire because no agent task heard the decision.
        let q = PendingApprovalQueue::new();
        let (id, rx) = q.register(req("exec"));
        drop(rx);
        let result = q.resolve(&id, PendingDecision::Allow { actor: None });
        assert_eq!(result, ResolveResult::UnknownKey);
    }

    #[tokio::test]
    async fn list_returns_all_pending_entries() {
        let q = PendingApprovalQueue::new();
        let (_id_a, _rx_a) = q.register(req("exec_a"));
        let (_id_b, _rx_b) = q.register(req("exec_b"));
        let mut entries = q.list();
        entries.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tool_name, "exec_a");
        assert_eq!(entries[1].tool_name, "exec_b");
    }

    #[tokio::test]
    async fn list_excludes_resolved_entries() {
        let q = PendingApprovalQueue::new();
        let (id_a, _rx_a) = q.register(req("exec_a"));
        let (_id_b, _rx_b) = q.register(req("exec_b"));
        q.resolve(&id_a, PendingDecision::Allow { actor: None });
        let entries = q.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "exec_b");
    }

    #[tokio::test]
    async fn show_returns_full_detail_including_trigger() {
        let q = PendingApprovalQueue::new();
        let (id, _rx) = q.register(req("exec"));
        let detail = q.show(&id).expect("entry present");
        assert_eq!(detail.tool_name, "exec");
        assert_eq!(
            detail.trigger_message.as_deref(),
            Some("user said something")
        );
    }

    #[tokio::test]
    async fn show_returns_none_for_unknown_id() {
        let q = PendingApprovalQueue::new();
        assert!(q.show("not-a-real-id").is_none());
    }

    #[test]
    fn resolve_cli_timeout_uses_env_when_set() {
        // SAFETY: cargo test parallelizes; this test sets a unique
        // env var, reads it via the helper once, and removes. No
        // other test reads this variable.
        unsafe {
            std::env::set_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S", "42");
        }
        let d = resolve_cli_timeout();
        unsafe {
            std::env::remove_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(d, Duration::from_secs(42));
    }

    #[test]
    fn resolve_cli_timeout_falls_back_on_malformed() {
        unsafe {
            std::env::set_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S", "not-a-number");
        }
        let d = resolve_cli_timeout();
        unsafe {
            std::env::remove_var("WIRKEN_CLI_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(d, Duration::from_secs(DEFAULT_CLI_TIMEOUT_SECS));
    }
}
