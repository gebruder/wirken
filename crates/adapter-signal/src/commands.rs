//! Text-command parser for the Signal approval surface. Signal
//! has no native button or interaction primitive, so the approval
//! UX is a text exchange in the configured approval conversation:
//!
//! ```text
//! !approve <prefix>
//! !deny <prefix> [reason text]
//! ```
//!
//! `<prefix>` is the first 8 hex characters of the
//! `request_id` UUID embedded in the bot's approval message. The
//! prefix is short enough to type on a phone keyboard, long
//! enough that collisions are rare with the small set of
//! in-flight approvals typical for this surface. A collision is
//! handled by the approval-command handler in `adapter.rs`
//! (zero/multi-match -> clarification message, no resolve); this
//! module only parses.
//!
//! This is the text-command channel adapter in Wirken. The
//! prediction in this comment's original form (that Matrix and
//! iMessage would follow the same shape) did not survive: Matrix
//! adopted m.reaction with a correlation table on E2EE-posture
//! grounds (reactions are unencrypted by spec, message bodies
//! are not; the Matrix adapter is plaintext-only today and
//! reaction approval inherits that posture without making it
//! worse). iMessage is TBD. The parser pattern here factors to a
//! shared crate only if a second text-command consumer arrives,
//! which is now contingent on iMessage's shape decision rather
//! than presumed for Matrix.

/// Parsed Signal approval command. Returned by [`parse_command`]
/// when the message body matches the wire format above. Anything
/// else (regular agent-bound messages, malformed approvals,
/// commands missing the prefix) returns `None` from
/// [`parse_command`] and continues down the normal inbound
/// pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind {
    /// `!approve <prefix>`. The prefix is the verbatim hex string
    /// the operator typed; the handler resolves prefix to
    /// `request_id` via its local map. No reason capture on
    /// approve; the audit row's `approved_by` is the actor.
    Approve { prefix: String },
    /// `!deny <prefix> [reason text]`. `reason` is everything
    /// after the prefix and following whitespace; trimmed; empty
    /// string becomes `None` so the audit row's `denial_reason`
    /// distinguishes "no reason supplied" from "supplied empty".
    Deny {
        prefix: String,
        reason: Option<String>,
    },
}

/// Parse a Signal message body. Returns `Some(CommandKind)` on a
/// well-formed approval command, `None` otherwise. Strict shape:
///
/// - leading `!approve` or `!deny` (case-sensitive; lowercase
///   only, matching the standard Signal-bot convention),
/// - exactly one whitespace between the command and the prefix,
/// - prefix is a non-empty hex-only run (case-insensitive on the
///   hex digits themselves; `aBcD12Ef` and `abcd12ef` both work),
/// - on deny: optional trailing reason after one or more
///   whitespace characters.
///
/// Multi-line bodies are rejected: an approval command is a
/// single line, and a body whose first line is a valid command
/// but whose subsequent lines carry agent-bound content would be
/// ambiguous. The slice's contract is "an approval is just an
/// approval"; the handler does not split a multi-line body into
/// command-plus-agent-content.
pub fn parse_command(body: &str) -> Option<CommandKind> {
    let trimmed = body.trim();
    if trimmed.contains('\n') {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("!approve") {
        let prefix = parse_prefix(rest)?;
        if !rest_after_prefix(rest, &prefix).is_empty() {
            // `!approve abc 123` -> reject. The approve form
            // takes only the prefix; trailing tokens indicate the
            // operator was trying to add a reason on an approve,
            // which is not a supported shape.
            return None;
        }
        Some(CommandKind::Approve { prefix })
    } else if let Some(rest) = trimmed.strip_prefix("!deny") {
        let prefix = parse_prefix(rest)?;
        let tail = rest_after_prefix(rest, &prefix);
        let reason = if tail.is_empty() {
            None
        } else {
            Some(tail.to_string())
        };
        Some(CommandKind::Deny { prefix, reason })
    } else {
        None
    }
}

/// Pull the prefix token out of the remainder after `!approve` /
/// `!deny`. Returns `None` if the remainder does not start with
/// whitespace + hex token. The prefix is lower-cased on the way
/// out so the handler's prefix-map lookup is canonical.
fn parse_prefix(rest: &str) -> Option<String> {
    let after_cmd = rest.strip_prefix(|c: char| c.is_ascii_whitespace())?;
    let prefix_end = after_cmd
        .char_indices()
        .find_map(|(i, c)| (!c.is_ascii_hexdigit()).then_some(i))
        .unwrap_or(after_cmd.len());
    if prefix_end == 0 {
        return None;
    }
    Some(after_cmd[..prefix_end].to_ascii_lowercase())
}

/// Return the substring after the matched prefix, with leading
/// whitespace trimmed. The caller passes the same `rest` it gave
/// to [`parse_prefix`]; this re-walks to find the prefix end
/// rather than reusing an offset because the prefix may have
/// been lower-cased and offsets would have to be recomputed
/// anyway.
fn rest_after_prefix<'a>(rest: &'a str, prefix: &str) -> &'a str {
    let after_cmd = rest.trim_start();
    let after_prefix = &after_cmd[prefix.len()..];
    after_prefix.trim_start()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_with_lowercase_prefix() {
        let r = parse_command("!approve abc12345").unwrap();
        assert_eq!(
            r,
            CommandKind::Approve {
                prefix: "abc12345".into()
            }
        );
    }

    #[test]
    fn approve_with_mixed_case_prefix_is_lowered() {
        let r = parse_command("!approve AbCd12Ef").unwrap();
        assert_eq!(
            r,
            CommandKind::Approve {
                prefix: "abcd12ef".into()
            }
        );
    }

    #[test]
    fn approve_with_short_prefix() {
        // Length is the handler's concern (unique-or-reject); the
        // parser accepts any non-empty hex prefix.
        let r = parse_command("!approve ab").unwrap();
        assert_eq!(
            r,
            CommandKind::Approve {
                prefix: "ab".into()
            }
        );
    }

    #[test]
    fn approve_with_trailing_text_rejects() {
        // Approve takes only the prefix. A trailing token indicates
        // either an operator confusion (typing a reason on approve)
        // or a different command shape; either way the parser
        // returns None and the handler does not route.
        assert!(parse_command("!approve abc12345 because").is_none());
    }

    #[test]
    fn deny_without_reason_returns_none_reason() {
        let r = parse_command("!deny abc12345").unwrap();
        assert_eq!(
            r,
            CommandKind::Deny {
                prefix: "abc12345".into(),
                reason: None
            }
        );
    }

    #[test]
    fn deny_with_reason_captures_trailing_text() {
        let r = parse_command("!deny abc12345 looks risky").unwrap();
        assert_eq!(
            r,
            CommandKind::Deny {
                prefix: "abc12345".into(),
                reason: Some("looks risky".into())
            }
        );
    }

    #[test]
    fn deny_reason_with_multiple_words_preserved() {
        let r = parse_command("!deny abc12345 this command would delete files I need").unwrap();
        match r {
            CommandKind::Deny { reason, .. } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("this command would delete files I need")
                );
            }
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn leading_whitespace_tolerated() {
        // Some Signal clients add a stray space on autocorrect.
        let r = parse_command("   !approve abc12345   ").unwrap();
        assert_eq!(
            r,
            CommandKind::Approve {
                prefix: "abc12345".into()
            }
        );
    }

    #[test]
    fn missing_bang_prefix_not_a_command() {
        // The leading `!` is required to disambiguate from a
        // normal agent-bound message that happens to start with
        // the word "approve" (e.g. "approve the spec doc").
        assert!(parse_command("approve abc12345").is_none());
    }

    #[test]
    fn uppercase_command_not_a_command() {
        // Case-sensitive on the command; only lowercase
        // `!approve` / `!deny` route. Keeps the parse simple and
        // matches the convention.
        assert!(parse_command("!Approve abc12345").is_none());
    }

    #[test]
    fn nonhex_prefix_not_a_command() {
        // The prefix must be hex (the leading slice of a UUID).
        // Non-hex tokens come back as None and continue down the
        // inbound pipeline; this prevents typo'd commands like
        // `!approve allofit` from routing to the handler at all.
        assert!(parse_command("!approve nothex!").is_none());
    }

    #[test]
    fn empty_prefix_not_a_command() {
        assert!(parse_command("!approve ").is_none());
        assert!(parse_command("!deny ").is_none());
    }

    #[test]
    fn unknown_command_word_not_a_command() {
        assert!(parse_command("!hello abc12345").is_none());
        assert!(parse_command("!allow abc12345").is_none());
    }

    #[test]
    fn multiline_body_rejected() {
        // An approval is a single line. A body that mixes a
        // command-shaped first line with subsequent lines is
        // ambiguous; the slice's contract says we don't route
        // it as approval.
        assert!(parse_command("!approve abc12345\nand more").is_none());
    }

    #[test]
    fn plain_message_is_not_a_command() {
        // The most important negative case: a normal agent-bound
        // message returns None, which lets the existing inbound
        // pipeline carry on unchanged.
        assert!(parse_command("hey, please summarize the day").is_none());
    }
}
