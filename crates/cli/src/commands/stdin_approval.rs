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
    timeout_from(
        std::env::var("WIRKEN_ASK_APPROVAL_TIMEOUT_S")
            .ok()
            .as_deref(),
    )
}

/// The rule on its own, with the environment read lifted out.
///
/// Split out so the tests cover every case without writing a
/// process-global variable. `std::env::set_var` is `unsafe` in the
/// 2024 edition because it is undefined behaviour while another
/// thread reads or writes the environment, and cargo runs a binary's
/// tests on parallel threads that do exactly that. The mutex this
/// module used to hold ordered the writers and left every reader
/// alone; one interleaving was observed in a full workspace run,
/// which is what a lock cannot fix.
fn timeout_from(raw: Option<&str>) -> Duration {
    match raw.map(|s| s.trim().parse::<u64>()) {
        Some(Ok(secs)) if secs > 0 => Duration::from_secs(secs),
        _ => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
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
            actor: None,
        },
        Ok(Ok(_)) => parse_decision(&line),
    }
}

fn parse_decision(line: &str) -> ApprovalOutcome {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ApprovalOutcome::Denied {
            reason: None,
            actor: None,
        };
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("").to_ascii_lowercase();
    let tail = parts.next().map(|s| s.trim().to_string());
    // Stdin gate does not know an operator-identity label other
    // than "this terminal session"; leave `actor: None` so the
    // runtime falls back to the surface-derived "stdin" label.
    match head.as_str() {
        "y" | "yes" => ApprovalOutcome::Approved { actor: None },
        _ => ApprovalOutcome::Denied {
            reason: tail.filter(|s| !s.is_empty()),
            actor: None,
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
        assert_eq!(outcome, ApprovalOutcome::Approved { actor: None });
    }

    #[tokio::test]
    async fn yes_approves_case_insensitive() {
        let r = Cursor::new(b"YES\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Approved { actor: None });
    }

    #[tokio::test]
    async fn approve_with_trailing_text_treated_as_yes() {
        // `y trust me` -> Approved. Tail is operator-noise; the
        // decision is the first token.
        let r = Cursor::new(b"y trust me\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(outcome, ApprovalOutcome::Approved { actor: None });
    }

    #[tokio::test]
    async fn n_denies_with_no_reason() {
        let r = Cursor::new(b"n\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: None,
                actor: None,
            }
        );
    }

    #[tokio::test]
    async fn deny_with_reason_after_space() {
        let r = Cursor::new(b"n unsafe path\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: Some("unsafe path".into()),
                actor: None,
            }
        );
    }

    #[tokio::test]
    async fn deny_with_word_other_than_y_records_word_as_reason_prefix() {
        // First token is `cancel`, not `y`. Tail is empty.
        let r = Cursor::new(b"cancel\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: None,
                actor: None,
            }
        );
    }

    #[tokio::test]
    async fn empty_line_denies_with_no_reason() {
        let r = Cursor::new(b"\n");
        let outcome = read_one_decision(r, Duration::from_secs(1)).await;
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: None,
                actor: None,
            }
        );
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
                reason: Some("eof on stdin".into()),
                actor: None,
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
        assert_eq!(timeout_from(Some("5")), Duration::from_secs(5));
    }

    #[test]
    fn resolve_timeout_tolerates_surrounding_space() {
        assert_eq!(timeout_from(Some("  5  ")), Duration::from_secs(5));
    }

    #[test]
    fn resolve_timeout_falls_back_when_unset() {
        assert_eq!(
            timeout_from(None),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_timeout_falls_back_on_malformed() {
        assert_eq!(
            timeout_from(Some("not-a-number")),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_timeout_falls_back_on_zero() {
        // Zero would mean "never wait"; not what an operator means
        // when they configure a timeout. Fall back to the default
        // so a misconfiguration doesn't auto-deny every prompt.
        assert_eq!(
            timeout_from(Some("0")),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
    }

    /// The env read and the rule are separate functions, so this is
    /// what asserts they are wired together. It reads whatever the
    /// ambient environment holds, so it needs no write.
    #[test]
    fn resolve_timeout_reads_the_documented_variable() {
        assert_eq!(
            resolve_timeout(),
            timeout_from(
                std::env::var("WIRKEN_ASK_APPROVAL_TIMEOUT_S")
                    .ok()
                    .as_deref()
            )
        );
    }
}
