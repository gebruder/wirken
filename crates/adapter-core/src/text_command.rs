//! Text-command approval parser for channels with no button or
//! interaction primitive. Two adapters consume this: Signal and
//! iMessage, both in the umbrella's
//! "text-command-with-no-toast-by-shape" group. The approval UX is
//! a text exchange in the configured approval conversation:
//!
//! ```text
//! !approve <prefix>
//! !deny <prefix> [reason text]
//! ```
//!
//! `<prefix>` is the start of the `request_id` the gateway minted
//! for the ask and the approval card shows: its first
//! [`CODE_LEN`] hex characters, which the card's instruction names,
//! or more of them. The code is short enough to type on a phone; the
//! full id decides, so a typed prefix answers only the pending ask
//! whose id it begins, and a prefix two pending asks share answers
//! neither until more of the id is typed. A model never sees the id,
//! so a card it writes into a reply cannot name the code a real ask
//! takes. [`parse_command`] parses; [`take`] resolves.
//!
//! ## Factoring history
//!
//! This module originated as duplicated parsers in
//! `adapter-signal/src/commands.rs` and
//! `adapter-imessage/src/commands.rs`. Both copies were byte-
//! identical by construction: the iMessage slice landed with a
//! verbatim-clone discipline pinned at the top of its file, on the
//! reasoning that shared crates shaped by an uncommitted boundary
//! become debt, and a one-consumer abstraction is shaped by
//! conjecture rather than by observation. Once both consumers
//! existed with stable shapes, the boundary was visible and the
//! factoring became mechanical (#121).
//!
//! The richer comments below are from the Signal version; the
//! iMessage clone trimmed them when cloning. The full prose is
//! the original intent.

use std::collections::HashMap;

/// Hex characters of a request id the operator types to answer it.
pub const CODE_LEN: usize = 4;

/// A request id as hex: its dashes out, lower case.
pub fn id_hex(request_id: &str) -> String {
    request_id
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The code an answer to `request_id` carries: its first
/// [`CODE_LEN`] hex characters.
pub fn answer_code(request_id: &str) -> String {
    id_hex(request_id).chars().take(CODE_LEN).collect()
}

/// Whether `typed` answers `request_id`: at least [`CODE_LEN`] hex
/// characters, in any case, that the id begins with.
pub fn answers(typed: &str, request_id: &str) -> bool {
    let typed = typed.to_ascii_lowercase();
    typed.len() >= CODE_LEN
        && typed.chars().all(|c| c.is_ascii_hexdigit())
        && id_hex(request_id).starts_with(&typed)
}

/// What a typed prefix finds among the pending asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// No pending ask's id begins with it.
    None,
    /// One does, and it is taken off the list.
    One(String),
    /// This many do; none is taken.
    Many(usize),
}

/// Find the pending ask `typed` answers in `pending`, a map from each
/// ask's [`answer_code`] to the ids that share it, and take it off the
/// map when it is the only one. Every other ask stays pending.
pub fn take(pending: &mut HashMap<String, Vec<String>>, typed: &str) -> Lookup {
    let code: String = typed.to_ascii_lowercase().chars().take(CODE_LEN).collect();
    let Some(ids) = pending.get_mut(&code) else {
        return Lookup::None;
    };
    let found: Vec<usize> = (0..ids.len())
        .filter(|&i| answers(typed, &ids[i]))
        .collect();
    match found.as_slice() {
        [] => Lookup::None,
        [one] => {
            let id = ids.remove(*one);
            if ids.is_empty() {
                pending.remove(&code);
            }
            Lookup::One(id)
        }
        many => Lookup::Many(many.len()),
    }
}

/// Parsed approval command. Returned by [`parse_command`] when the
/// message body matches the wire format above. Anything else
/// (regular agent-bound messages, malformed approvals, commands
/// missing the prefix) returns `None` from [`parse_command`] and
/// continues down the normal inbound pipeline.
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

/// Parse a message body. Returns `Some(CommandKind)` on a
/// well-formed approval command, `None` otherwise. Strict shape:
///
/// - leading `!approve` or `!deny` (case-sensitive; lowercase
///   only, matching the standard text-command convention),
/// - exactly one whitespace between the command and the prefix,
/// - prefix is a non-empty hex-only run (case-insensitive on the
///   hex digits themselves; `aBcD12Ef` and `abcd12ef` both work),
/// - on deny: optional trailing reason after one or more
///   whitespace characters.
///
/// Multi-line bodies are rejected: an approval command is a
/// single line, and a body whose first line is a valid command
/// but whose subsequent lines carry agent-bound content would be
/// ambiguous. The contract is "an approval is just an approval";
/// the handler does not split a multi-line body into
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
#[allow(
    clippy::string_slice,
    reason = "prefix_end is from char_indices, a char boundary"
)]
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
    #[allow(
        clippy::string_slice,
        reason = "parse_prefix accepted rest as one ASCII space then this ASCII prefix"
    )]
    let after_prefix = &after_cmd[prefix.len()..];
    after_prefix.trim_start()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "3f9a52c1-0b7e-4c2d-9a10-5e6f7a8b9c0d";
    const B: &str = "3f9a77d0-1111-4222-8333-444455556666";

    #[test]
    fn the_code_is_the_ids_first_four_hex_characters() {
        assert_eq!(answer_code(A), "3f9a");
        assert_eq!(answer_code("3F9A52C1-0000"), "3f9a");
        assert!(answers("3f9a", A) && answers("3F9A52", A) && answers(&id_hex(A), A));
        for no in ["3f9", "3f9b", "3f9a53", "", "zz9a"] {
            assert!(!answers(no, A), "{no}");
        }
    }

    #[test]
    fn a_code_answers_only_the_ask_it_begins_and_a_shared_one_answers_neither() {
        let mut pending: HashMap<String, Vec<String>> = HashMap::new();
        for id in [A, B] {
            pending
                .entry(answer_code(id))
                .or_default()
                .push(id.to_string());
        }
        assert_eq!(take(&mut pending, "3f9a"), Lookup::Many(2));
        assert_eq!(take(&mut pending, "0000"), Lookup::None);
        assert_eq!(take(&mut pending, "3f9a5"), Lookup::One(A.to_string()));
        // The other ask is still pending, and now its code alone
        // answers it.
        assert_eq!(take(&mut pending, "3f9a"), Lookup::One(B.to_string()));
        assert!(pending.is_empty());
        assert_eq!(take(&mut pending, "3f9a"), Lookup::None);
    }

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
        // Some clients (Signal autocorrect, iMessage paste) add a
        // stray leading space.
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
        // ambiguous; the contract says we don't route it as
        // approval.
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
