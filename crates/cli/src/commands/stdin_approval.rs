//! `StdinApprovalGate`: prompt-and-retry approval surface for
//! interactive `wirken ask`.
//!
//! The agent runtime calls `request_approval` when a `NeedsApproval`
//! short-circuit fires. This gate prints a one-line prompt to stderr
//! and reads one line from stdin with a hard timeout. The parser:
//!
//! - trimmed `y` or `yes` (case-insensitive) → `Approved`
//! - anything else, with optional space-delimited reason → `Denied { reason }`
//! - EOF on stdin → `Denied { reason: Some("eof on stdin") }`
//! - read times out → `Timeout`
//!
//! The reader is generic over `AsyncBufRead` so tests can drive it
//! with `Cursor<&[u8]>` without spinning up real stdin.

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use wirken_agent::approval_gate::{ApprovalGate, ApprovalOutcome};
use wirken_agent::error::PermissionDenialContext;
use wirken_audit::ApprovalSource;

/// Default wall-clock cap on the prompt read. Overridable via
/// `WIRKEN_ASK_APPROVAL_TIMEOUT_S`. 60 seconds is long enough that
/// an operator who paused to think doesn't get cut off, short
/// enough that a redirected-from-`/dev/null` stdin doesn't hang the
/// agent for a meaningful fraction of the session.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Read the configured timeout, falling back to the default on
/// missing env or malformed value. Malformed silently falls back —
/// the env var is operator-tuning, not an integrity-critical
/// surface.
pub fn resolve_timeout() -> Duration {
    match std::env::var("WIRKEN_ASK_APPROVAL_TIMEOUT_S") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
    }
}

/// Stdin gate that prompts on stderr (so stdout pipes stay clean
/// for the agent's response) and reads one line from real stdin.
pub struct StdinApprovalGate {
    timeout: Duration,
}

impl StdinApprovalGate {
    pub fn new() -> Self {
        Self {
            timeout: resolve_timeout(),
        }
    }
}

impl Default for StdinApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalGate for StdinApprovalGate {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        // Print prompt to stderr. Stdout is reserved for the agent's
        // final response so a pipeline consumer (`wirken ask | jq`)
        // sees only the response, not interleaved approval prompts.
        let mut stderr = tokio::io::stderr();
        let prompt = format!(
            "wirken: agent '{}' requests '{}' ({}). approve? [y/N]: ",
            ctx.agent_id,
            ctx.tool_name,
            ctx.requested_tier.label(),
        );
        if let Err(e) = stderr.write_all(prompt.as_bytes()).await {
            tracing::warn!("approval-prompt stderr write failed: {e}");
        }
        let _ = stderr.flush().await;

        let reader = tokio::io::BufReader::new(tokio::io::stdin());
        read_one_decision(reader, self.timeout).await
    }

    fn source(&self) -> ApprovalSource {
        ApprovalSource::Stdin
    }
}

/// Read one line from the reader within `timeout`, classify it.
/// Generic over [`AsyncBufRead`] so tests pass a `Cursor` or a
/// duplex half without real stdin.
pub async fn read_one_decision<R>(mut reader: R, timeout: Duration) -> ApprovalOutcome
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    let read_result = tokio::time::timeout(timeout, reader.read_line(&mut line)).await;
    match read_result {
        Err(_) => ApprovalOutcome::Timeout,
        Ok(Err(_)) | Ok(Ok(0)) => ApprovalOutcome::Denied {
            reason: Some("eof on stdin".into()),
        },
        Ok(Ok(_)) => parse_decision(&line),
    }
}

fn parse_decision(line: &str) -> ApprovalOutcome {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ApprovalOutcome::Denied { reason: None };
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("").to_ascii_lowercase();
    let tail = parts.next().map(|s| s.trim().to_string());
    match head.as_str() {
        "y" | "yes" => ApprovalOutcome::Approved,
        _ => ApprovalOutcome::Denied {
            reason: tail.filter(|s| !s.is_empty()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn y_approves() {
        let r = Cursor::new(b"y\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn yes_approves_case_insensitive() {
        let r = Cursor::new(b"YES\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn approve_with_trailing_text_treated_as_yes() {
        // `y trust me` -> Approved. Tail is operator-noise; the
        // decision is the first token.
        let r = Cursor::new(b"y trust me\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn n_denies_with_no_reason() {
        let r = Cursor::new(b"n\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Denied { reason: None });
    }

    #[tokio::test]
    async fn deny_with_reason_after_space() {
        let r = Cursor::new(b"n unsafe path\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("unsafe path".into())
            }
        );
    }

    #[tokio::test]
    async fn deny_with_word_other_than_y_records_word_as_reason_prefix() {
        // First token is `cancel`, not `y`. Tail is empty.
        let r = Cursor::new(b"cancel\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Denied { reason: None });
    }

    #[tokio::test]
    async fn empty_line_denies_with_no_reason() {
        let r = Cursor::new(b"\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Denied { reason: None });
    }

    #[tokio::test]
    async fn eof_without_newline_denies() {
        // Empty reader, immediate EOF. The parser returns the
        // dedicated "eof on stdin" reason so a SIEM consumer can
        // distinguish "operator typed empty line" from "stdin
        // closed".
        let r = Cursor::new(b"");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("eof on stdin".into())
            }
        );
    }

    #[tokio::test]
    async fn timeout_fires_on_unresponsive_reader() {
        use tokio::io::duplex;
        // duplex pair with no writer side activity: the reader
        // will block forever. A tight timeout proves the deadline
        // path returns `Timeout`.
        let (_writer, reader) = duplex(64);
        let r = tokio::io::BufReader::new(reader);
        let outcome = read_one_decision(r, Duration::from_millis(50)).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
    }

    #[test]
    fn resolve_timeout_uses_env_when_set() {
        // SAFETY: cargo test runs this binary's tests in parallel
        // by default. Use a unique env value and read it back
        // through the helper before any other test could touch it;
        // the helper reads once and returns. We do not assert
        // global cleanup because every test that touches this var
        // sets it explicitly before reading.
        unsafe {
            std::env::set_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S", "5");
        }
        let d = resolve_timeout();
        unsafe {
            std::env::remove_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(d, Duration::from_secs(5));
    }

    #[test]
    fn resolve_timeout_falls_back_on_malformed() {
        unsafe {
            std::env::set_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S", "not-a-number");
        }
        let d = resolve_timeout();
        unsafe {
            std::env::remove_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(d, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn resolve_timeout_falls_back_on_zero() {
        // Zero would mean "never wait"; not what an operator means
        // when they configure a timeout. Fall back to the default
        // so a misconfiguration doesn't auto-deny every prompt.
        unsafe {
            std::env::set_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S", "0");
        }
        let d = resolve_timeout();
        unsafe {
            std::env::remove_var("WIRKEN_ASK_APPROVAL_TIMEOUT_S");
        }
        assert_eq!(d, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }
}
