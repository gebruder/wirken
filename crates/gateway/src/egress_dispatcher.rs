//! Egress-hook synchronous dispatcher.
//!
//! Twin of [`crate::hook_dispatcher`] on the post-execution path.
//! Whereas the veto dispatcher runs before a tool dispatches (and
//! gates the call by `Allow` / `Deny`), the egress dispatcher runs
//! after the tool has produced output (and mediates the output
//! bytes by `Allow` / `Replace { bytes }` / `Refuse { reason }`).
//!
//! ## Pipeline semantics
//!
//! Hooks run in registration order. Each hook sees the current
//! working output bytes. A `Replace` mutates the working copy that
//! the next hook sees; the final working copy is what the runtime
//! feeds into `add_tool_result` and onto the `ToolResult` row. A
//! `Refuse` short-circuits the iteration; remaining hooks emit
//! `Skipped` outcomes (no audit row, matching the
//! absent-row-means-fast-fail-skip convention from the veto
//! dispatcher).
//!
//! ## Budget
//!
//! Cumulative wall-clock budget across the iteration: defaults to
//! 1000ms, overridable via `WIRKEN_EGRESS_BUDGET_MS`. Per-hook
//! ceiling is the same `PER_HOOK_CAP` as veto (500ms). When the
//! cumulative budget is exhausted before a hook is reached, that
//! hook and every hook after it emit `Timeout` outcomes that DO
//! land on the chain so an operator can tell "budget exhausted
//! before this hook ran" apart from "earlier refuse short-
//! circuited this hook".
//!
//! ## Chain integrity
//!
//! The dispatcher writes no audit rows itself; the runtime emits
//! one `EgressHookDispatched` per non-skipped per-hook outcome and
//! one `ToolOutputRedacted` when the final working copy differs
//! from the original. The chain's per-session leaf hash is over
//! the raw stored payload bytes, so adding the new event variants
//! does not affect verify on rows that did not carry them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use uuid::Uuid;

use wirken_ipc::IpcFrameWriter;
use wirken_ipc::wirken_capnp::frame;

use crate::hook_dispatcher::PER_HOOK_CAP;

/// Wall-clock ceiling for one full egress-hook iteration. Defaults
/// to 1000ms; overridable via `WIRKEN_EGRESS_BUDGET_MS`. Symmetric
/// with [`crate::hook_dispatcher::DEFAULT_VETO_BUDGET_MS`].
pub const DEFAULT_EGRESS_BUDGET_MS: u64 = 1000;

/// Internal-trait outcome shape. `Skipped` is for hooks the runtime
/// projects to "no audit row" (an earlier refuse short-circuited
/// the iteration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalDecision {
    Allow,
    Replace {
        /// The replacement bytes from this hook. The runtime
        /// chains these through subsequent hooks.
        bytes: Vec<u8>,
    },
    Refuse {
        reason: String,
    },
    Timeout,
    Skipped,
}

/// One per-hook outcome from a single `dispatch` call. Returned in
/// registration order. The runtime emits `EgressHookDispatched`
/// rows for every entry except those with `decision == Skipped`.
#[derive(Debug, Clone)]
pub struct DispatchedEgress {
    pub hook_id: String,
    pub decision: InternalDecision,
}

/// What the dispatcher returns to the agent runtime. Carries the
/// per-hook outcomes plus the final working bytes.
#[derive(Debug, Clone)]
pub struct EgressOutcome {
    pub per_hook: Vec<DispatchedEgress>,
    /// The final working bytes after every hook in the pipeline has
    /// had its say. Equal to the input bytes when no hook replaced
    /// them. The runtime feeds these into `add_tool_result`.
    pub final_bytes: Vec<u8>,
    /// `Some(reason)` if any hook refused. Short-circuits the
    /// pipeline; remaining hooks are `Skipped`.
    pub first_refuse_reason: Option<String>,
    /// `true` if any hook timed out (per-hook or cumulative budget).
    /// The runtime branches on `WIRKEN_ALLOW_UNREGISTERED_HOOKS` to
    /// decide fail-closed vs fail-open, same as veto.
    pub any_timeout: bool,
    /// `true` if the final bytes differ from the input bytes (any
    /// hook returned `Replace`). The runtime uses this to decide
    /// whether to emit a `ToolOutputRedacted` row.
    pub replaced: bool,
}

/// Trait the agent runtime calls. Default impl is the in-process
/// [`EgressDispatcher`]; the [`NoopEgressDispatcher`] is the
/// no-egress-hooks-configured stub so agents with no egress hooks
/// pay no cost.
#[async_trait]
pub trait EgressHookDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        tool_name: &str,
        output_bytes: &[u8],
        session_id: &str,
    ) -> EgressOutcome;
}

/// No-egress-hooks-configured stub. `dispatch` returns an empty
/// `per_hook` and the input bytes unchanged.
pub struct NoopEgressDispatcher;

#[async_trait]
impl EgressHookDispatcher for NoopEgressDispatcher {
    async fn dispatch(
        &self,
        _tool_name: &str,
        output_bytes: &[u8],
        _session_id: &str,
    ) -> EgressOutcome {
        EgressOutcome {
            per_hook: Vec::new(),
            final_bytes: output_bytes.to_vec(),
            first_refuse_reason: None,
            any_timeout: false,
            replaced: false,
        }
    }
}

/// In-process egress dispatcher. Owns the active set of connected
/// egress hooks. The hooks accept loop calls `register` on
/// handshake success and `unregister` on disconnect.
pub struct EgressDispatcher {
    inner: Arc<AsyncMutex<DispatcherInner>>,
    budget: Duration,
}

struct DispatcherInner {
    active: Vec<EgressHook>,
}

struct EgressHook {
    hook_id: String,
    writer: Arc<AsyncMutex<IpcFrameWriter>>,
    pending: Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<EgressResult>>>>,
}

/// Internal channel payload between the per-hook reader task and
/// the dispatcher.
#[derive(Debug, Clone)]
pub enum EgressResult {
    Allow,
    Replace { bytes: Vec<u8> },
    Refuse { reason: String },
}

impl Default for EgressDispatcher {
    fn default() -> Self {
        Self::new(Self::resolve_budget())
    }
}

impl EgressDispatcher {
    pub fn new(budget: Duration) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(DispatcherInner { active: Vec::new() })),
            budget,
        }
    }

    fn resolve_budget() -> Duration {
        match std::env::var("WIRKEN_EGRESS_BUDGET_MS") {
            Ok(s) => match s.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => Duration::from_millis(ms),
                _ => Duration::from_millis(DEFAULT_EGRESS_BUDGET_MS),
            },
            Err(_) => Duration::from_millis(DEFAULT_EGRESS_BUDGET_MS),
        }
    }

    pub async fn register(
        &self,
        hook_id: &str,
        writer: Arc<AsyncMutex<IpcFrameWriter>>,
        pending: Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<EgressResult>>>>,
    ) {
        let mut inner = self.inner.lock().await;
        inner.active.retain(|h| h.hook_id != hook_id);
        inner.active.push(EgressHook {
            hook_id: hook_id.to_string(),
            writer,
            pending,
        });
    }

    pub async fn unregister(&self, hook_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.active.retain(|h| h.hook_id != hook_id);
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().await.active.len()
    }
}

#[async_trait]
impl EgressHookDispatcher for EgressDispatcher {
    async fn dispatch(
        &self,
        tool_name: &str,
        output_bytes: &[u8],
        session_id: &str,
    ) -> EgressOutcome {
        // Snapshot the active set so we don't hold the dispatcher's
        // async mutex across hook awaits.
        let snapshot: Vec<(
            String,
            Arc<AsyncMutex<IpcFrameWriter>>,
            Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<EgressResult>>>>,
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
        let mut first_refuse_reason: Option<String> = None;
        let mut any_timeout = false;
        let mut working = output_bytes.to_vec();
        let mut replaced = false;

        for (idx, (hook_id, writer, pending)) in snapshot.iter().enumerate() {
            if short_circuited {
                per_hook.push(DispatchedEgress {
                    hook_id: hook_id.clone(),
                    decision: InternalDecision::Skipped,
                });
                continue;
            }

            let elapsed = start.elapsed();
            let remaining = self.budget.saturating_sub(elapsed);
            if remaining.is_zero() {
                for (skip_id, _, _) in &snapshot[idx..] {
                    per_hook.push(DispatchedEgress {
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
                &working,
                session_id,
                per_hook_timeout,
            )
            .await;

            match result {
                Ok(EgressResult::Allow) => {
                    per_hook.push(DispatchedEgress {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Allow,
                    });
                }
                Ok(EgressResult::Replace { bytes }) => {
                    working = bytes.clone();
                    replaced = true;
                    per_hook.push(DispatchedEgress {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Replace { bytes },
                    });
                }
                Ok(EgressResult::Refuse { reason }) => {
                    if first_refuse_reason.is_none() {
                        first_refuse_reason = Some(reason.clone());
                    }
                    per_hook.push(DispatchedEgress {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Refuse { reason },
                    });
                    short_circuited = true;
                }
                Err(InvokeError::Timeout) | Err(InvokeError::ConnectionDropped) => {
                    per_hook.push(DispatchedEgress {
                        hook_id: hook_id.clone(),
                        decision: InternalDecision::Timeout,
                    });
                    any_timeout = true;
                }
            }
        }

        EgressOutcome {
            per_hook,
            final_bytes: working,
            first_refuse_reason,
            any_timeout,
            replaced,
        }
    }
}

enum InvokeError {
    Timeout,
    ConnectionDropped,
}

async fn invoke_one(
    writer: &Arc<AsyncMutex<IpcFrameWriter>>,
    pending: &Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<EgressResult>>>>,
    tool_name: &str,
    output: &[u8],
    session_id: &str,
    per_hook_timeout: Duration,
) -> Result<EgressResult, InvokeError> {
    let request_id = Uuid::new_v4().to_string();

    let (tx, rx) = oneshot::channel::<EgressResult>();
    pending.lock().unwrap().insert(request_id.clone(), tx);

    let mut message = capnp::message::Builder::new_default();
    {
        let frame_builder = message.init_root::<frame::Builder<'_>>();
        let mut req = frame_builder.init_egress_request();
        req.set_request_id(&request_id);
        req.set_tool_name(tool_name);
        req.set_output(output);
        req.set_session_id(session_id);
    }

    {
        let mut w = writer.lock().await;
        if w.write_message(&message).await.is_err() {
            pending.lock().unwrap().remove(&request_id);
            return Err(InvokeError::ConnectionDropped);
        }
    }

    match tokio::time::timeout(per_hook_timeout, rx).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(InvokeError::ConnectionDropped),
        Err(_) => {
            pending.lock().unwrap().remove(&request_id);
            Err(InvokeError::Timeout)
        }
    }
}
