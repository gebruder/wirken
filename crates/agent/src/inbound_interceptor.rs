//! Pre-LLM inbound message interceptors.
//!
//! When a user message arrives at [`crate::runtime::Agent::process_message`],
//! the agent runs it through a chain of registered interceptors before
//! the LLM ever sees it. Each interceptor can:
//!
//! - **Pass** — the message isn't relevant to this interceptor; the chain
//!   continues to the next one.
//! - **Rewrite** — transform the message and pass it down the chain (the
//!   rewritten form is what later interceptors and the LLM see).
//! - **Handle** — fully handle the message, returning a reply text and
//!   audit events. The LLM is not invoked for this turn; the agent's
//!   outbound is the interceptor's reply.
//!
//! ## Why this exists
//!
//! The slash-command surface from #79 was the first consumer
//! (`Agent::preprocess_slash_invocation` → `crate::slash::parse`).
//! Zirkel's keep/skip reply parser is the second. The refactor from
//! a hardcoded slash-only call to a registered chain happens **because
//! Zirkel needs it** — not as speculative cleanup. A second real
//! consumer earns the abstraction; one consumer doesn't.
//!
//! ## First-match-wins semantics
//!
//! The chain stops at the first non-`Pass` result. Interceptors
//! should be designed to be orthogonal: slash invocations look
//! nothing like keep/skip replies. Order doesn't matter for
//! correctness, but registration order is the tiebreaker if two
//! interceptors ever match the same shape.

use crate::error::AgentError;
use crate::skill::Skill;
use wirken_audit::SessionEvent;

/// Result of running one interceptor over a message.
#[derive(Debug)]
pub enum InterceptResult {
    /// Not for me; pass through unchanged. Chain continues.
    Pass,
    /// Rewrote the message; chain continues with the rewritten form,
    /// and the rewritten form is what the LLM ultimately sees.
    Rewrite(String),
    /// Fully handled. The agent emits `reply` to the channel and
    /// records `audit_events` to the session log; the LLM is **not**
    /// invoked for this turn.
    Handle {
        reply: String,
        audit_events: Vec<SessionEvent>,
    },
    /// Refuse the message — surface to the channel as an error.
    /// Used by slash for unknown skill names; could be used by
    /// keep/skip for out-of-range numbers.
    Reject(AgentError),
}

/// Context passed to every interceptor. Contains the data interceptors
/// commonly need without coupling them to the full agent state.
pub struct InterceptorContext<'a> {
    pub agent_id: &'a str,
    pub skills: &'a [Skill],
}

/// One pre-LLM interceptor. Implementors live in their own crates
/// (slash in `wirken-agent`, keep/skip in `wirken-zirkel`) and
/// register with the agent at startup.
///
/// Synchronous by design — the trait stays light. Implementors that
/// need I/O (Zirkel's keep/skip touches SQLite) do it inside the
/// call without holding `.await` across operations.
pub trait InboundInterceptor: Send + Sync {
    /// A short identifier for tracing / debugging. Not load-bearing
    /// for routing.
    fn name(&self) -> &'static str;

    fn intercept(&self, message: &str, ctx: &InterceptorContext<'_>) -> InterceptResult;
}

/// Run an inbound message through every interceptor in order, stopping
/// at the first non-`Pass` result. Helper for [`Agent::process_message_inner`]
/// and [`Agent::process_message_stream`] — the two callsites that need
/// to apply the chain identically.
pub fn run_chain(
    interceptors: &[Box<dyn InboundInterceptor>],
    message: &str,
    ctx: &InterceptorContext<'_>,
) -> InterceptResult {
    let mut current = message.to_string();
    for interceptor in interceptors {
        match interceptor.intercept(&current, ctx) {
            InterceptResult::Pass => continue,
            InterceptResult::Rewrite(s) => current = s,
            InterceptResult::Handle {
                reply,
                audit_events,
            } => {
                return InterceptResult::Handle {
                    reply,
                    audit_events,
                };
            }
            InterceptResult::Reject(e) => return InterceptResult::Reject(e),
        }
    }
    if current == message {
        InterceptResult::Pass
    } else {
        InterceptResult::Rewrite(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PassThrough;
    impl InboundInterceptor for PassThrough {
        fn name(&self) -> &'static str {
            "pass"
        }
        fn intercept(&self, _: &str, _: &InterceptorContext<'_>) -> InterceptResult {
            InterceptResult::Pass
        }
    }

    struct AlwaysRewrite(&'static str);
    impl InboundInterceptor for AlwaysRewrite {
        fn name(&self) -> &'static str {
            "rewrite"
        }
        fn intercept(&self, msg: &str, _: &InterceptorContext<'_>) -> InterceptResult {
            InterceptResult::Rewrite(format!("{msg} {}", self.0))
        }
    }

    struct AlwaysHandle(&'static str);
    impl InboundInterceptor for AlwaysHandle {
        fn name(&self) -> &'static str {
            "handle"
        }
        fn intercept(&self, _: &str, _: &InterceptorContext<'_>) -> InterceptResult {
            InterceptResult::Handle {
                reply: self.0.to_string(),
                audit_events: vec![],
            }
        }
    }

    fn ctx<'a>() -> InterceptorContext<'a> {
        InterceptorContext {
            agent_id: "test",
            skills: &[],
        }
    }

    #[test]
    fn empty_chain_returns_pass() {
        let r = run_chain(&[], "hello", &ctx());
        assert!(matches!(r, InterceptResult::Pass));
    }

    #[test]
    fn all_pass_returns_pass() {
        let chain: Vec<Box<dyn InboundInterceptor>> =
            vec![Box::new(PassThrough), Box::new(PassThrough)];
        let r = run_chain(&chain, "hello", &ctx());
        assert!(matches!(r, InterceptResult::Pass));
    }

    #[test]
    fn rewrites_compose_in_order() {
        let chain: Vec<Box<dyn InboundInterceptor>> = vec![
            Box::new(AlwaysRewrite("alpha")),
            Box::new(AlwaysRewrite("beta")),
        ];
        match run_chain(&chain, "start", &ctx()) {
            InterceptResult::Rewrite(s) => assert_eq!(s, "start alpha beta"),
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }

    #[test]
    fn handle_short_circuits_chain() {
        let chain: Vec<Box<dyn InboundInterceptor>> = vec![
            Box::new(AlwaysHandle("done")),
            Box::new(AlwaysRewrite("never-runs")),
        ];
        match run_chain(&chain, "hello", &ctx()) {
            InterceptResult::Handle { reply, .. } => assert_eq!(reply, "done"),
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn pass_then_rewrite_yields_rewrite() {
        let chain: Vec<Box<dyn InboundInterceptor>> =
            vec![Box::new(PassThrough), Box::new(AlwaysRewrite("end"))];
        match run_chain(&chain, "hi", &ctx()) {
            InterceptResult::Rewrite(s) => assert_eq!(s, "hi end"),
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }
}
