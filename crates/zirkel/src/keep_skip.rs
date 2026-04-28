//! Reply-parser for the daily-digest keep/skip surface.
//!
//! The lawyer's reply on Signal is one short message that resolves
//! the digest in a single shot. Recognised forms:
//!
//! - `keep all`      — every item in the digest is kept
//! - `skip all`      — every item is skipped
//! - `keep N`        — that one item is kept, every other is skipped
//! - `skip N`        — that one item is skipped, every other is kept
//! - `keep N,M,P`    — listed items kept, rest skipped
//! - `skip N,M,P`    — listed items skipped, rest kept
//! - `keep N M P`    — whitespace-separated form, equivalent
//! - `keep 3, 5, 7`  — whitespace inside lists is tolerated
//!
//! Numbers are 1-indexed, scoped to the most recently sent digest
//! for the receiving agent. Anything that isn't a clean keep/skip
//! command — including a number out of range — yields `None` from
//! [`parse`]; the orchestrator decides whether to surface "out of
//! range" as a Reject or to ignore. `parse` is shape-only.
//!
//! ## Strict, not fuzzy
//!
//! Like the slash parser, the surface is the contract. We don't
//! match `"please keep item 3"` or `"keep #3"`. The Signal user
//! sees the exact syntax in the digest footer; anything outside
//! that shape is a free-text reply and falls through.

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeepSkipCmd {
    Keep(KeepSkipTargets),
    Skip(KeepSkipTargets),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeepSkipTargets {
    All,
    /// 1-indexed positions, in caller-provided order. May contain
    /// duplicates — the resolver dedupes.
    Indices(Vec<u32>),
}

/// Parse a user reply for a keep/skip command. `None` for anything
/// that isn't a clean command shape.
pub fn parse(message: &str) -> Option<KeepSkipCmd> {
    let trimmed = message.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (verb, rest) = if let Some(r) = lower.strip_prefix("keep") {
        (Verb::Keep, r)
    } else if let Some(r) = lower.strip_prefix("skip") {
        (Verb::Skip, r)
    } else {
        return None;
    };
    // Verb must be followed by whitespace (or end of message — bare
    // `keep` is not a command).
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let arg = rest.trim();
    if arg.is_empty() {
        return None;
    }
    if arg == "all" {
        return Some(verb.with(KeepSkipTargets::All));
    }
    let indices = parse_indices(arg)?;
    if indices.is_empty() {
        return None;
    }
    Some(verb.with(KeepSkipTargets::Indices(indices)))
}

#[derive(Copy, Clone)]
enum Verb {
    Keep,
    Skip,
}

impl Verb {
    fn with(self, t: KeepSkipTargets) -> KeepSkipCmd {
        match self {
            Verb::Keep => KeepSkipCmd::Keep(t),
            Verb::Skip => KeepSkipCmd::Skip(t),
        }
    }
}

/// Parse a numeric list — comma- or whitespace-separated 1-indexed
/// positive integers. Returns `None` on any non-numeric token or
/// zero / overflow / negative.
fn parse_indices(s: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for tok in s.split(|c: char| c == ',' || c.is_whitespace()) {
        if tok.is_empty() {
            continue;
        }
        let n: u32 = tok.parse().ok()?;
        if n == 0 {
            return None;
        }
        out.push(n);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keep_indices(v: &[u32]) -> KeepSkipCmd {
        KeepSkipCmd::Keep(KeepSkipTargets::Indices(v.to_vec()))
    }
    fn skip_indices(v: &[u32]) -> KeepSkipCmd {
        KeepSkipCmd::Skip(KeepSkipTargets::Indices(v.to_vec()))
    }

    #[test]
    fn keep_all_parses() {
        assert_eq!(
            parse("keep all"),
            Some(KeepSkipCmd::Keep(KeepSkipTargets::All))
        );
    }

    #[test]
    fn skip_all_parses() {
        assert_eq!(
            parse("skip all"),
            Some(KeepSkipCmd::Skip(KeepSkipTargets::All))
        );
    }

    #[test]
    fn keep_single_index() {
        assert_eq!(parse("keep 3"), Some(keep_indices(&[3])));
    }

    #[test]
    fn skip_single_index() {
        assert_eq!(parse("skip 4"), Some(skip_indices(&[4])));
    }

    #[test]
    fn comma_separated_list() {
        assert_eq!(parse("keep 3,5,7"), Some(keep_indices(&[3, 5, 7])));
    }

    #[test]
    fn whitespace_separated_list() {
        assert_eq!(parse("keep 3 5 7"), Some(keep_indices(&[3, 5, 7])));
    }

    #[test]
    fn mixed_separators() {
        assert_eq!(parse("keep 3, 5,7  9"), Some(keep_indices(&[3, 5, 7, 9])));
    }

    #[test]
    fn case_insensitive_verb() {
        assert_eq!(parse("KEEP 1"), Some(keep_indices(&[1])));
        assert_eq!(
            parse("Skip All"),
            Some(KeepSkipCmd::Skip(KeepSkipTargets::All))
        );
    }

    #[test]
    fn leading_and_trailing_whitespace_tolerated() {
        assert_eq!(parse("  keep 3  "), Some(keep_indices(&[3])));
    }

    #[test]
    fn bare_verb_is_not_a_command() {
        assert_eq!(parse("keep"), None);
        assert_eq!(parse("skip"), None);
        assert_eq!(parse("keep "), None);
    }

    #[test]
    fn zero_index_rejected() {
        assert_eq!(parse("keep 0"), None);
        assert_eq!(parse("keep 0,1,2"), None);
    }

    #[test]
    fn non_numeric_token_rejected() {
        assert_eq!(parse("keep 3,a,5"), None);
        assert_eq!(parse("keep three"), None);
    }

    #[test]
    fn negative_rejected() {
        assert_eq!(parse("keep -3"), None);
    }

    #[test]
    fn unrelated_message_returns_none() {
        assert_eq!(parse("thanks for the digest"), None);
        assert_eq!(parse("/help"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn verb_only_at_start_no_substring_match() {
        // "keepsake" must not be parsed as "keep sake".
        assert_eq!(parse("keepsake"), None);
        // "keep1" likewise — needs whitespace after the verb.
        assert_eq!(parse("keep1"), None);
    }

    #[test]
    fn embedded_keep_in_freeform_reply_is_not_a_command() {
        // Strictness: only commands at message start. The user's
        // reply "I'd like to keep 3 of these" must not resolve
        // the digest.
        assert_eq!(parse("I'd like to keep 3 of these"), None);
    }
}
