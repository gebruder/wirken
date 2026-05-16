//! Veto-hook synchronous dispatcher.
//!
//! Sits between the agent runtime (which calls `dispatch` after the
//! built-in `NeedsApproval` gate) and the live veto-hook
//! connections (registered on the hooks accept loop after a clean
//! handshake). Implements **serial cumulative-budget** dispatch:
//!
//! - Hooks invoked in registration order (insertion order of the
//!   active set).
//! - Each hook gets `min(budget_remaining, PER_HOOK_CAP)` as its
//!   timeout.
//! - First `Deny` short-circuits the iteration; remaining hooks emit
//!   `Skipped` outcomes that the runtime drops from the audit chain
//!   (absent-row-means-skipped is the operator-visible convention).
//! - When `budget_remaining` reaches zero before a hook is reached,
//!   that hook and every hook after it emits `Timeout` without
//!   actually being dispatched; those rows DO land on the chain so
//!   the operator can tell "budget was exhausted" from "hook was
//!   skipped because an earlier deny short-circuited".
//!
//! Trade-offs documented at `crates/gateway/src/hook_dispatcher.rs`
//! (slice rationale): bounded worst-case latency, preserved
//! fast-fail, deterministic audit ordering, audit chain
//! structurally distinguishes the three possible end states.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use uuid::Uuid;

use wirken_ipc::IpcFrameWriter;
use wirken_ipc::wirken_capnp::frame;

use wirken_audit::HookDecision;

/// Wall-clock ceiling for one full veto-hook iteration. Defaults to
/// 1000ms; overridable via `WIRKEN_VETO_BUDGET_MS`. Bounds the
/// agent's tool-call latency floor at a single configurable number
/// regardless of how many veto hooks the operator has registered.
pub const DEFAULT_VETO_BUDGET_MS: u64 = 1000;

/// Per-hook hard ceiling. Even when the cumulative budget has more
/// time available, no single hook is allowed to consume more than
/// this. Protects against one slow hook monopolizing the budget and
/// starving subsequent fast hooks.
pub const PER_HOOK_CAP: Duration = Duration::from_millis(500);

/// Internal-trait outcome shape. Carries `Skipped` so the dispatcher
/// can report the full per-hook accounting to the runtime; the
/// runtime drops `Skipped` rows before emitting to the audit chain
/// per the absent-row-means-fast-fail-skip convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalDecision {
    Allow,
    Deny {
        reason: String,
    },
    Timeout,
    /// An earlier `Deny` short-circuited the iteration. The runtime
    /// translates this to "no audit row" so the chain reads
    /// honestly: only invoked-or-timed-out hooks leave a trace.
    Skipped,
}

impl InternalDecision {
    /// Project the internal three-way down to the audit-chain
    /// `HookDecision`. `Skipped` returns `None` because skipped
    /// hooks do not land on the chain.
    pub fn for_audit(&self) -> Option<HookDecision> {
        match self {
            Self::Allow => Some(HookDecision::Allow),
            Self::Deny { reason } => Some(HookDecision::Deny {
                reason: reason.clone(),
            }),
            Self::Timeout => Some(HookDecision::Timeout),
            Self::Skipped => None,
        }
    }
}

/// One per-hook outcome from a single `dispatch` call. Returned in
/// registration order. The runtime emits `HookDispatched` rows for
/// every entry except those with `decision == Skipped`.
#[derive(Debug, Clone)]
pub struct DispatchedVeto {
    pub hook_id: String,
    pub decision: InternalDecision,
}

/// What the dispatcher returns to the agent runtime. Carries the
/// per-hook outcomes plus a top-level summary the runtime uses to
/// decide whether to proceed with the tool call.
#[derive(Debug, Clone)]
pub struct VetoOutcome {
    pub per_hook: Vec<DispatchedVeto>,
    /// True iff every non-Skipped outcome is `Allow`. False on any
    /// `Deny` or `Timeout`. The runtime uses this with the
    /// `WIRKEN_ALLOW_UNREGISTERED_HOOKS` env var to decide
    /// fail-closed (production) vs fail-open (dev) on `Timeout`.
    pub all_allow: bool,
    /// The first `Deny` reason if any, otherwise `None`. The runtime
    /// surfaces this string to the LLM as the tool call's failure
    /// message.
    pub first_deny_reason: Option<String>,
    /// True iff at least one `Timeout` was recorded. Lets the
    /// runtime distinguish "budget exhausted or hook slow" from
    /// "hook denied" for the dev-mode fail-open path.
    pub any_timeout: bool,
}

/// Trait the agent runtime calls. Default impl is the in-process
/// `HookDispatcher`; the `NoopDispatcher` is the no-veto-hooks-
/// configured stub so agents with no veto hooks pay no cost.
#[async_trait]
pub trait VetoDispatcher: Send + Sync {
    async fn dispatch(&self, tool_name: &str, arguments: &str, session_id: &str) -> VetoOutcome;
}

/// No-veto-hooks-configured stub. `dispatch` returns an empty
/// `per_hook` with `all_allow: true`. The runtime treats it as
/// "fall through to the dispatch table".
pub struct NoopDispatcher;

#[async_trait]
impl VetoDispatcher for NoopDispatcher {
    async fn dispatch(&self, _tool_name: &str, _arguments: &str, _session_id: &str) -> VetoOutcome {
        VetoOutcome {
            per_hook: Vec::new(),
            all_allow: true,
            first_deny_reason: None,
            any_timeout: false,
        }
    }
}

/// In-process veto dispatcher. Owns the active set of connected
/// veto hooks. The hooks accept loop calls `register` on handshake
/// success and `unregister` on disconnect.
pub struct HookDispatcher {
    inner: Arc<AsyncMutex<DispatcherInner>>,
    budget: Duration,
}

struct DispatcherInner {
    /// Registration-order list of active veto hooks. `Vec`, not
    /// `HashMap`, because the slice locks serial-cumulative-budget
    /// dispatch in registration order; the audit chain reads in the
    /// same order so an operator can reason about hook precedence.
    active: Vec<VetoHook>,
}

struct VetoHook {
    hook_id: String,
    writer: Arc<AsyncMutex<IpcFrameWriter>>,
    /// Map of in-flight request_id to the oneshot that owns the
    /// dispatcher's await. The per-hook reader task (owned by the
    /// hooks accept loop) routes incoming `VetoResponse` frames by
    /// looking up the request_id here. On connection drop, the
    /// reader task drains every sender with `Err` so all pending
    /// dispatchers see `Timeout`.
    pending: Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<VetoResult>>>>,
}

/// Internal channel payload between the per-hook reader task and
/// the dispatcher. Equivalent to the wire-level `VetoResponse`
/// variants plus an explicit connection-drop signal so the
/// dispatcher's await sees a typed error rather than a generic
/// channel close.
#[derive(Debug, Clone)]
pub enum VetoResult {
    Allow,
    Deny { reason: String },
}

impl Default for HookDispatcher {
    fn default() -> Self {
        Self::new(Self::resolve_budget())
    }
}

impl HookDispatcher {
    /// Create a dispatcher with an explicit cumulative budget. Tests
    /// pass tight budgets to exercise the budget-exhaustion path.
    pub fn new(budget: Duration) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(DispatcherInner { active: Vec::new() })),
            budget,
        }
    }

    /// Read `WIRKEN_VETO_BUDGET_MS` from the environment, or fall
    /// back to `DEFAULT_VETO_BUDGET_MS`. Malformed values fall back
    /// silently; the env var is operator-tuning, not an
    /// integrity-critical surface.
    fn resolve_budget() -> Duration {
        match std::env::var("WIRKEN_VETO_BUDGET_MS") {
            Ok(s) => match s.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => Duration::from_millis(ms),
                _ => Duration::from_millis(DEFAULT_VETO_BUDGET_MS),
            },
            Err(_) => Duration::from_millis(DEFAULT_VETO_BUDGET_MS),
        }
    }

    /// Register a freshly-connected veto hook. Append to the active
    /// set in handshake-acceptance order so the dispatcher's serial
    /// iteration matches operator-configured precedence.
    pub async fn register(
        &self,
        hook_id: &str,
        writer: Arc<AsyncMutex<IpcFrameWriter>>,
        pending: Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<VetoResult>>>>,
    ) {
        let mut inner = self.inner.lock().await;
        // Defensive: if a hook with this id is somehow already in
        // the active set (a registry race or a misbehaving operator
        // running two hook processes with the same hook_id), drop
        // the prior entry so dispatch never double-invokes.
        inner.active.retain(|h| h.hook_id != hook_id);
        inner.active.push(VetoHook {
            hook_id: hook_id.to_string(),
            writer,
            pending,
        });
    }

    /// Remove a hook from the active set. Idempotent. Called by the
    /// per-connection task on disconnect.
    pub async fn unregister(&self, hook_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.active.retain(|h| h.hook_id != hook_id);
    }

    /// Number of currently active veto hooks. Test seam.
    pub async fn active_count(&self) -> usize {
        self.inner.lock().await.active.len()
    }
}

#[async_trait]
impl VetoDispatcher for HookDispatcher {
    async fn dispatch(&self, tool_name: &str, arguments: &str, session_id: &str) -> VetoOutcome {
        // Snapshot the active set so we don't hold the dispatcher's
        // async mutex across hook awaits (a slow hook would otherwise
        // block every other dispatcher and the accept loop).
        let snapshot: Vec<(
            String,
            Arc<AsyncMutex<IpcFrameWriter>>,
            Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<VetoResult>>>>,
        )> = {
            let inner = self.inner.lock().await;
            inner
                .active
                .iter()
                .map(|h| (h.hook_id.clone(), h.writer.clone(), h.pending.clone()))
                .collect()
        };

        let start = Instant::now();
        let mut per_hook = Vec::with_capacity(snapshot.len());
        let mut short_circuited = false;
        let mut first_deny_reason: Option<String> = None;
        let mut any_timeout = false;

        for (idx, (hook_id, writer, pending)) in snapshot.iter().enumerate() {
            if short_circuited {
                per_hook.push(DispatchedVeto {
                    hook_id: hook_id.clone(),
                    decision: InternalDecision::Skipped,
                });
                continue;
            }

            let elapsed = start.elapsed();
            let remaining = self.budget.saturating_sub(elapsed);
            if remaining.is_zero() {
                // Budget exhausted. The remaining hooks emit
                // Timeout-without-dispatch so the audit chain shows
                // which hooks were reached but couldn't be called.
                for (skip_id, _, _) in &snapshot[idx..] {
                    per_hook.push(DispatchedVeto {
                        hook_id: skip_id.clone(),
                        decision: InternalDecision::Timeout,
                    });
                    any_timeout = true;
                }
                break;
            }

            let per_hook_timeout = remaining.min(PER_HOOK_CAP);
            let result = invoke_one(
                writer,
                pending,
                tool_name,
                arguments,
                session_id,
                per_hook_timeout,
            )
            .await;

            match result {
                Ok(VetoResult::Allow) => {
                    per_hook.push(DispatchedVeto {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Allow,
                    });
                }
                Ok(VetoResult::Deny { reason }) => {
                    if first_deny_reason.is_none() {
                        first_deny_reason = Some(reason.clone());
                    }
                    per_hook.push(DispatchedVeto {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Deny { reason },
                    });
                    short_circuited = true;
                }
                Err(InvokeError::Timeout) | Err(InvokeError::ConnectionDropped) => {
                    per_hook.push(DispatchedVeto {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Timeout,
                    });
                    any_timeout = true;
                }
            }
        }

        let all_allow = per_hook.iter().all(|d| {
            matches!(
                d.decision,
                InternalDecision::Allow | InternalDecision::Skipped
            )
        });

        VetoOutcome {
            per_hook,
            all_allow,
            first_deny_reason,
            any_timeout,
        }
    }
}

enum InvokeError {
    Timeout,
    ConnectionDropped,
}

/// Invoke one veto hook synchronously. Mints a request_id, parks an
/// oneshot in the hook's pending map, sends the `VetoRequest`
/// frame, awaits the response under `per_hook_timeout`.
async fn invoke_one(
    writer: &Arc<AsyncMutex<IpcFrameWriter>>,
    pending: &Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<VetoResult>>>>,
    tool_name: &str,
    arguments: &str,
    session_id: &str,
    per_hook_timeout: Duration,
) -> Result<VetoResult, InvokeError> {
    let request_id = Uuid::new_v4().to_string();

    let (tx, rx) = oneshot::channel::<VetoResult>();
    pending.lock().unwrap().insert(request_id.clone(), tx);

    let mut message = capnp::message::Builder::new_default();
    {
        let frame_builder = message.init_root::<frame::Builder<'_>>();
        let mut req = frame_builder.init_veto_request();
        req.set_request_id(&request_id);
        req.set_tool_name(tool_name);
        req.set_arguments(arguments);
        req.set_session_id(session_id);
    }

    // Write the request. On write failure (connection dropped), the
    // reader task will eventually drain the pending map; drop the
    // sender here to surface the error promptly to the awaiter.
    {
        let mut w = writer.lock().await;
        if w.write_message(&message).await.is_err() {
            pending.lock().unwrap().remove(&request_id);
            return Err(InvokeError::ConnectionDropped);
        }
    }

    match tokio::time::timeout(per_hook_timeout, rx).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => {
            // Sender dropped: the reader task drained pending on a
            // connection-drop event. Surface as connection-dropped.
            Err(InvokeError::ConnectionDropped)
        }
        Err(_) => {
            // Timeout fired. Remove our pending entry so a late
            // response doesn't land in a stale oneshot.
            pending.lock().unwrap().remove(&request_id);
            Err(InvokeError::Timeout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use wirken_ipc::{split_stream, test_pair};

    /// Test rig that drives one end of an IpcFrameWriter while
    /// installing a programmable "responder" on the other end. The
    /// responder reads `VetoRequest` frames and emits scripted
    /// `VetoResult`s back via the pending map (simulating what the
    /// real per-hook reader task does).
    struct TestHook {
        writer: Arc<AsyncMutex<IpcFrameWriter>>,
        pending: Arc<StdMutex<HashMap<String, oneshot::Sender<VetoResult>>>>,
    }

    impl TestHook {
        async fn new() -> (Self, tokio::sync::mpsc::Sender<TestResponse>) {
            // Local-loopback pair: the dispatcher writes one end; we
            // read the other to discover request_ids.
            let (a, b) = test_pair().unwrap();
            let (_unused_reader, w) = split_stream(a);
            let writer = Arc::new(AsyncMutex::new(w));
            let pending: Arc<StdMutex<HashMap<String, oneshot::Sender<VetoResult>>>> =
                Arc::new(StdMutex::new(HashMap::new()));

            // The script channel lets each test queue responses
            // ahead of time. The responder pulls one response per
            // VetoRequest it reads, in arrival order.
            let (script_tx, mut script_rx) = tokio::sync::mpsc::channel::<TestResponse>(16);

            let pending_for_task = pending.clone();
            let (mut reader, _peer_writer) = split_stream(b);
            tokio::spawn(async move {
                loop {
                    match reader.read_message().await {
                        Ok(msg) => {
                            let frame_reader = match msg.get_root::<frame::Reader<'_>>() {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            let request_id = match frame_reader.which() {
                                Ok(frame::VetoRequest(r)) => {
                                    let r = match r {
                                        Ok(r) => r,
                                        Err(_) => return,
                                    };
                                    match r.get_request_id() {
                                        Ok(id) => match id.to_string() {
                                            Ok(s) => s,
                                            Err(_) => return,
                                        },
                                        Err(_) => return,
                                    }
                                }
                                _ => return,
                            };

                            // Wait for the test to script a response.
                            let scripted = match script_rx.recv().await {
                                Some(s) => s,
                                None => return,
                            };

                            // Sleep models hook latency.
                            if !scripted.delay.is_zero() {
                                tokio::time::sleep(scripted.delay).await;
                            }

                            // Connection-drop variant: bail out
                            // without replying so the
                            // dispatcher's per-hook timeout
                            // catches it OR the cleanup path
                            // drains the pending map.
                            if scripted.drop_connection {
                                // Drain pending now to simulate the
                                // reader task seeing EOF and notifying
                                // every waiter.
                                let mut p = pending_for_task.lock().unwrap();
                                for (_, sender) in p.drain() {
                                    drop(sender);
                                }
                                return;
                            }

                            // Deliver the response by completing the
                            // oneshot for this request_id.
                            let sender = {
                                let mut p = pending_for_task.lock().unwrap();
                                p.remove(&request_id)
                            };
                            if let Some(sender) = sender {
                                let _ = sender.send(scripted.result);
                            }
                        }
                        Err(_) => return,
                    }
                }
            });

            (Self { writer, pending }, script_tx)
        }
    }

    struct TestResponse {
        result: VetoResult,
        delay: Duration,
        drop_connection: bool,
    }

    impl TestResponse {
        fn allow() -> Self {
            Self {
                result: VetoResult::Allow,
                delay: Duration::ZERO,
                drop_connection: false,
            }
        }
        fn deny(reason: &str) -> Self {
            Self {
                result: VetoResult::Deny {
                    reason: reason.into(),
                },
                delay: Duration::ZERO,
                drop_connection: false,
            }
        }
        fn delay(self, d: Duration) -> Self {
            Self { delay: d, ..self }
        }
        fn drop_conn() -> Self {
            Self {
                result: VetoResult::Allow, // unused
                delay: Duration::ZERO,
                drop_connection: true,
            }
        }
    }

    async fn dispatcher_with(budget_ms: u64, hooks: Vec<(String, &TestHook)>) -> HookDispatcher {
        let d = HookDispatcher::new(Duration::from_millis(budget_ms));
        for (hid, hook) in hooks {
            d.register(&hid, hook.writer.clone(), hook.pending.clone())
                .await;
        }
        d
    }

    #[tokio::test]
    async fn allow_path_returns_all_allow() {
        let (hook, script) = TestHook::new().await;
        script.send(TestResponse::allow()).await.unwrap();
        let d = dispatcher_with(1000, vec![("h1".into(), &hook)]).await;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert!(outcome.all_allow);
        assert!(outcome.first_deny_reason.is_none());
        assert!(!outcome.any_timeout);
        assert_eq!(outcome.per_hook.len(), 1);
        assert_eq!(outcome.per_hook[0].decision, InternalDecision::Allow);
    }

    #[tokio::test]
    async fn deny_short_circuits_and_marks_remaining_skipped() {
        let (h1, s1) = TestHook::new().await;
        let (h2, _s2) = TestHook::new().await;
        s1.send(TestResponse::deny("policy/no-shell"))
            .await
            .unwrap();
        // h2 is never scripted: a non-skipped invocation would block.
        let d = dispatcher_with(1000, vec![("h1".into(), &h1), ("h2".into(), &h2)]).await;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert!(!outcome.all_allow);
        assert_eq!(
            outcome.first_deny_reason.as_deref(),
            Some("policy/no-shell")
        );
        assert!(!outcome.any_timeout);
        assert_eq!(outcome.per_hook.len(), 2);
        assert!(matches!(
            outcome.per_hook[0].decision,
            InternalDecision::Deny { ref reason } if reason == "policy/no-shell"
        ));
        assert_eq!(outcome.per_hook[1].decision, InternalDecision::Skipped);
    }

    #[tokio::test]
    async fn skipped_outcomes_do_not_emit_audit_rows() {
        // Lock the absent-row-means-fast-fail-skip convention at the
        // decision-to-audit projection layer.
        assert_eq!(InternalDecision::Skipped.for_audit(), None);
        assert_eq!(
            InternalDecision::Allow.for_audit(),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            InternalDecision::Deny { reason: "x".into() }.for_audit(),
            Some(HookDecision::Deny { reason: "x".into() })
        );
        assert_eq!(
            InternalDecision::Timeout.for_audit(),
            Some(HookDecision::Timeout)
        );
    }

    #[tokio::test]
    async fn cumulative_budget_exhaustion_marks_remaining_timeout() {
        // Two hooks. Budget = 200ms. First hook sleeps 150ms then
        // allows. The second hook should be reached but find
        // remaining < the per-hook minimum granularity; it lands as
        // Timeout-without-dispatch. The audit row is present (not
        // skipped) so an operator can see "budget exhausted before
        // this hook ran" distinct from "earlier deny short-
        // circuited this hook".
        let (h1, s1) = TestHook::new().await;
        let (h2, _s2) = TestHook::new().await;
        s1.send(TestResponse::allow().delay(Duration::from_millis(220)))
            .await
            .unwrap();
        let d = dispatcher_with(200, vec![("h1".into(), &h1), ("h2".into(), &h2)]).await;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        // h1 ran past its share of the budget -> Timeout.
        assert_eq!(outcome.per_hook[0].decision, InternalDecision::Timeout);
        // h2 should be Timeout (budget exhausted), not Skipped.
        assert_eq!(outcome.per_hook[1].decision, InternalDecision::Timeout);
        assert!(!outcome.all_allow);
        assert!(outcome.any_timeout);
    }

    #[tokio::test]
    async fn per_hook_cap_bounds_a_slow_hook_alone() {
        // One slow hook, generous budget. PER_HOOK_CAP (500ms)
        // bounds the await regardless of the cumulative budget.
        let (hook, script) = TestHook::new().await;
        script
            .send(TestResponse::allow().delay(Duration::from_millis(2_000)))
            .await
            .unwrap();
        let d = dispatcher_with(10_000, vec![("h1".into(), &hook)]).await;
        let start = Instant::now();
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(700),
            "PER_HOOK_CAP must bound a single slow hook; elapsed={elapsed:?}"
        );
        assert_eq!(outcome.per_hook[0].decision, InternalDecision::Timeout);
        assert!(outcome.any_timeout);
    }

    #[tokio::test]
    async fn connection_drop_drains_pending_to_timeout() {
        // Simulates the per-hook reader task seeing EOF and draining
        // every pending oneshot. The dispatcher's await sees the
        // sender dropped and surfaces ConnectionDropped, which maps
        // to Timeout in the per-hook outcome.
        let (hook, script) = TestHook::new().await;
        script.send(TestResponse::drop_conn()).await.unwrap();
        let d = dispatcher_with(1000, vec![("h1".into(), &hook)]).await;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert_eq!(outcome.per_hook[0].decision, InternalDecision::Timeout);
        assert!(outcome.any_timeout);
    }

    #[tokio::test]
    async fn no_active_hooks_returns_empty_all_allow() {
        let d = HookDispatcher::new(Duration::from_millis(1000));
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert!(outcome.per_hook.is_empty());
        assert!(outcome.all_allow);
        assert!(!outcome.any_timeout);
        assert!(outcome.first_deny_reason.is_none());
    }

    #[tokio::test]
    async fn noop_dispatcher_always_allows() {
        let d = NoopDispatcher;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert!(outcome.per_hook.is_empty());
        assert!(outcome.all_allow);
    }

    #[tokio::test]
    async fn registration_order_preserved_in_outcome() {
        // Three hooks; all allow. The outcome vec must list hooks
        // in registration order so the audit chain reads
        // deterministically.
        let (h1, s1) = TestHook::new().await;
        let (h2, s2) = TestHook::new().await;
        let (h3, s3) = TestHook::new().await;
        s1.send(TestResponse::allow()).await.unwrap();
        s2.send(TestResponse::allow()).await.unwrap();
        s3.send(TestResponse::allow()).await.unwrap();
        let d = dispatcher_with(
            2000,
            vec![
                ("alpha".into(), &h1),
                ("beta".into(), &h2),
                ("gamma".into(), &h3),
            ],
        )
        .await;
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        let ids: Vec<&str> = outcome
            .per_hook
            .iter()
            .map(|d| d.hook_id.as_str())
            .collect();
        assert_eq!(ids, vec!["alpha", "beta", "gamma"]);
    }

    #[tokio::test]
    async fn register_replaces_existing_entry_for_same_id() {
        // If a hook reconnects without unregister-first (e.g. fast
        // restart), the dispatcher should not double-invoke it on
        // the next dispatch. The newer entry wins.
        let (hook_a, _s_a) = TestHook::new().await;
        let (hook_b, s_b) = TestHook::new().await;
        s_b.send(TestResponse::allow()).await.unwrap();
        let d = HookDispatcher::new(Duration::from_millis(1000));
        d.register("h1", hook_a.writer.clone(), hook_a.pending.clone())
            .await;
        d.register("h1", hook_b.writer.clone(), hook_b.pending.clone())
            .await;
        assert_eq!(d.active_count().await, 1);
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        // Only one outcome row even though we registered twice.
        assert_eq!(outcome.per_hook.len(), 1);
        assert_eq!(outcome.per_hook[0].decision, InternalDecision::Allow);
    }

    #[tokio::test]
    async fn unregister_removes_from_active_set() {
        let (hook, _) = TestHook::new().await;
        let d = HookDispatcher::new(Duration::from_millis(1000));
        d.register("h1", hook.writer.clone(), hook.pending.clone())
            .await;
        d.unregister("h1").await;
        assert_eq!(d.active_count().await, 0);
        let outcome = d.dispatch("shell", "{}", "sess-1").await;
        assert!(outcome.per_hook.is_empty());
    }
}
