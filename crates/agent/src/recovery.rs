//! Error-recovery primitives shared by the LLM client and the agent
//! tool dispatcher.
//!
//! Two failure classes are handled here:
//!
//! 1. HTTP 429 from any provider — wrapped in [`classify_429`] and the
//!    [`crate::llm::LlmClient`]'s `send_with_retry` helper. Exponential
//!    backoff with jitter, max [`MAX_RATE_LIMIT_RETRIES`], honors a
//!    provider's `Retry-After` header where present.
//! 2. Tool-call schema/argument validation errors — the agent runtime
//!    converts an `AgentError::Tool` from the registry into a
//!    [`crate::tool::ToolResult`] with `success: false` and feeds it
//!    back into the conversation so the model can retry. Per-turn
//!    counter, capped at [`MAX_TOOL_VALIDATION_RETRIES`] before the
//!    tool is reported unavailable for the rest of the turn.
//!
//! Both paths surface their decisions through the [`RecoveryObserver`]
//! trait. Lyrik's runner registers an observer that emits
//! `lyrik.dispatch.rate_limited`, `lyrik.dispatch.failed`,
//! `lyrik.tool.validation_failed`, and `lyrik.tool.failed` audit
//! records. Other consumers may register their own observer or none at
//! all; the recovery behavior is independent of the observer.

use rand::RngExt;

/// Maximum number of HTTP-429 retries in [`crate::llm::LlmClient::send_with_retry`]
/// before [`crate::error::AgentError::RateLimitExhausted`] is returned.
pub const MAX_RATE_LIMIT_RETRIES: u32 = 5;

/// Maximum number of validation-failure retries the agent allows for
/// the same tool name within a single `process_message_inner` turn
/// before reporting the tool unavailable.
pub const MAX_TOOL_VALIDATION_RETRIES: u32 = 3;

/// Upper bound on a `Retry-After` header value before it gets clamped.
/// Providers occasionally return very long retry windows for
/// maintenance; the bench harness cares more about producing data than
/// about waiting an hour.
pub const RETRY_AFTER_CAP_MS: u64 = 60_000;

/// Base delay for exponential backoff when no `Retry-After` is present.
const BACKOFF_BASE_MS: u64 = 1_000;

/// Cap on the exponential portion of the backoff. The backoff grows as
/// `min(BACKOFF_BASE_MS << (attempt - 1), BACKOFF_CAP_MS)`.
const BACKOFF_CAP_MS: u64 = 32_000;

/// Maximum random jitter added on top of the exponential base. Keeps
/// concurrent retries from hammering the provider in lockstep.
const BACKOFF_JITTER_MS: u64 = 1_000;

/// Observer surface for recovery events. Implementations are registered
/// via [`crate::llm::LlmClient::set_recovery_observer`] and
/// [`crate::runtime::Agent::set_recovery_observer`]. All four hooks are
/// called from inside the request/dispatch path and must not block.
pub trait RecoveryObserver: Send + Sync {
    /// A 429 was received and a retry is scheduled.
    fn on_rate_limited(&self, attempt: u32, retry_after_ms: u64, status: u16);
    /// All retries exhausted; the dispatch is about to fail with
    /// [`crate::error::AgentError::RateLimitExhausted`].
    fn on_rate_limit_exhausted(&self, attempts: u32);
    /// A tool call failed argument validation. The runtime is about to
    /// surface a synthetic non-success [`crate::tool::ToolResult`] to
    /// the LLM. `attempt` is 1-indexed.
    fn on_tool_validation_failed(&self, tool: &str, attempt: u32, message: &str);
    /// Validation failures for `tool` reached
    /// [`MAX_TOOL_VALIDATION_RETRIES`]. The runtime is about to emit a
    /// "tool unavailable" `ToolResult` for the remainder of this turn.
    fn on_tool_validation_exhausted(&self, tool: &str, attempts: u32);
}

/// Decision returned by [`classify_429`].
#[derive(Debug, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry after the given delay.
    Retry { delay_ms: u64 },
    /// Do not retry.
    NoRetry,
}

/// Decide whether and how to retry given a status code, an optional
/// `Retry-After` header value, and the current 1-indexed attempt
/// number. Pure function — testable without HTTP.
///
/// Behavior:
/// - status != 429 → `NoRetry`.
/// - 429 with parseable `Retry-After` (delta-seconds, integer) →
///   `Retry { delay_ms: clamp(seconds * 1000, RETRY_AFTER_CAP_MS) }`.
/// - 429 with absent or unparseable `Retry-After` → exponential
///   backoff: `min(BACKOFF_BASE_MS << (attempt - 1), BACKOFF_CAP_MS)`
///   plus uniform jitter in `[0, BACKOFF_JITTER_MS)`.
pub fn classify_429(status: u16, retry_after_header: Option<&str>, attempt: u32) -> RetryDecision {
    if status != 429 {
        return RetryDecision::NoRetry;
    }
    if let Some(raw) = retry_after_header
        && let Ok(seconds) = raw.trim().parse::<u64>()
    {
        let ms = seconds.saturating_mul(1_000).min(RETRY_AFTER_CAP_MS);
        return RetryDecision::Retry { delay_ms: ms };
    }
    let exp_shift = attempt.saturating_sub(1).min(20);
    let exp = BACKOFF_BASE_MS
        .checked_shl(exp_shift)
        .unwrap_or(BACKOFF_CAP_MS)
        .min(BACKOFF_CAP_MS);
    let jitter = rand::rng().random_range(0..BACKOFF_JITTER_MS);
    RetryDecision::Retry {
        delay_ms: exp + jitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_returns_no_retry_for_non_429() {
        assert_eq!(classify_429(200, None, 1), RetryDecision::NoRetry);
        assert_eq!(classify_429(500, Some("10"), 1), RetryDecision::NoRetry);
        assert_eq!(classify_429(503, None, 4), RetryDecision::NoRetry);
    }

    #[test]
    fn classify_uses_retry_after_seconds() {
        assert_eq!(
            classify_429(429, Some("30"), 1),
            RetryDecision::Retry { delay_ms: 30_000 }
        );
        assert_eq!(
            classify_429(429, Some("  5  "), 4),
            RetryDecision::Retry { delay_ms: 5_000 }
        );
    }

    #[test]
    fn classify_clamps_retry_after_to_cap() {
        // Retry-After 600 seconds → clamped to RETRY_AFTER_CAP_MS.
        assert_eq!(
            classify_429(429, Some("600"), 1),
            RetryDecision::Retry {
                delay_ms: RETRY_AFTER_CAP_MS
            }
        );
    }

    #[test]
    fn classify_falls_back_to_exp_backoff_when_no_header() {
        for attempt in 1..=5 {
            let d = classify_429(429, None, attempt);
            match d {
                RetryDecision::Retry { delay_ms } => {
                    let exp_shift = (attempt - 1).min(20);
                    let exp = BACKOFF_BASE_MS
                        .checked_shl(exp_shift)
                        .unwrap_or(BACKOFF_CAP_MS)
                        .min(BACKOFF_CAP_MS);
                    assert!(
                        delay_ms >= exp && delay_ms < exp + BACKOFF_JITTER_MS,
                        "attempt {attempt}: delay_ms {delay_ms} outside [{exp}, {})",
                        exp + BACKOFF_JITTER_MS
                    );
                }
                RetryDecision::NoRetry => panic!("429 without header must retry"),
            }
        }
    }

    #[test]
    fn classify_exp_backoff_caps_at_backoff_cap() {
        let d = classify_429(429, None, 12);
        match d {
            RetryDecision::Retry { delay_ms } => {
                assert!(delay_ms >= BACKOFF_CAP_MS);
                assert!(delay_ms < BACKOFF_CAP_MS + BACKOFF_JITTER_MS);
            }
            RetryDecision::NoRetry => panic!("expected retry"),
        }
    }

    #[test]
    fn classify_ignores_unparseable_retry_after() {
        // "tomorrow" is not delta-seconds; falls back to exp-backoff.
        let d = classify_429(429, Some("tomorrow"), 1);
        match d {
            RetryDecision::Retry { delay_ms } => {
                assert!(delay_ms >= BACKOFF_BASE_MS);
                assert!(delay_ms < BACKOFF_BASE_MS + BACKOFF_JITTER_MS);
            }
            RetryDecision::NoRetry => panic!("expected retry"),
        }
    }
}
