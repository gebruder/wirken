//! Exact-match leak detection: the stored secrets a process knows, and a
//! search for them in content.
//!
//! A process that runs agents seeds one [`LeakMatcher`] from the vault at
//! start, every secret entry split into the parts it can appear as
//! ([`wirken_vault::matchable_secret`]), and adds each value it decrypts
//! later, so a value rotated since the start is known once the process
//! has read it. The checks that refuse model-authored content ask
//! [`LeakMatcher::find`] for the name of the first stored secret in a
//! piece of text; the audit row carries that name, never the value.
//!
//! The values are held in [`Zeroizing`] buffers. The search automaton
//! (Aho-Corasick) keeps its own copies of their bytes in its tables,
//! which are not zeroed when it is dropped; it lives in the process
//! that already holds the decrypted values.
//!
//! What is matched: the exact bytes of each part, at least
//! [`wirken_vault::MIN_MATCH_BYTES`] long. Not matched: encoded forms
//! (base64, URL or JSON escaping), and a secret split across two
//! pieces of content.

use std::sync::RwLock;

use aho_corasick::AhoCorasick;
use zeroize::Zeroizing;

pub use wirken_vault::{CredentialKind, MatchableSecret};

/// One part of one stored secret.
struct Pattern {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct State {
    patterns: Vec<Pattern>,
    automaton: Option<AhoCorasick>,
    longest: usize,
}

/// The stored secrets a process knows, searchable in content.
#[derive(Default)]
pub struct LeakMatcher {
    state: RwLock<State>,
}

impl LeakMatcher {
    /// A matcher that knows no secret and finds nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// A matcher that knows `secrets`.
    pub fn seeded(secrets: impl IntoIterator<Item = MatchableSecret>) -> Self {
        let matcher = Self::new();
        matcher.learn_all(secrets);
        matcher
    }

    /// Learn the secret parts in `secrets`. A part already known under
    /// the same name is not added again.
    pub fn learn_all(&self, secrets: impl IntoIterator<Item = MatchableSecret>) {
        let Ok(mut state) = self.state.write() else {
            tracing::error!("leak matcher lock poisoned; a new secret is not learned");
            return;
        };
        let mut changed = false;
        for secret in secrets {
            for part in secret.parts {
                let known = state
                    .patterns
                    .iter()
                    .any(|p| p.name == secret.name && p.value.as_slice() == part.as_bytes());
                if !known {
                    state.patterns.push(Pattern {
                        name: secret.name.clone(),
                        value: Zeroizing::new(part.as_bytes().to_vec()),
                    });
                    changed = true;
                }
            }
        }
        if changed {
            state.rebuild();
        }
    }

    /// Learn `value`, just decrypted under `name` as `kind`. Identifiers
    /// and values too short to match are left out
    /// ([`wirken_vault::matchable_secret`]).
    pub fn learn(&self, name: &str, value: &str, kind: CredentialKind) {
        if let Some(secret) = wirken_vault::matchable_secret(name, value, kind) {
            self.learn_all([secret]);
        }
    }

    /// The name of the first stored secret `text` contains.
    pub fn find(&self, text: &str) -> Option<String> {
        let state = self.state.read().ok()?;
        let automaton = state.automaton.as_ref()?;
        let found = automaton.find(text)?;
        Some(state.patterns[found.pattern().as_usize()].name.clone())
    }

    /// The length in bytes of the longest part known, zero when none
    /// is. A stream that holds back this many bytes less one cannot have
    /// sent part of a secret it has not yet checked.
    pub fn longest(&self) -> usize {
        self.state.read().map(|s| s.longest).unwrap_or(0)
    }

    /// Whether no secret is known.
    pub fn is_empty(&self) -> bool {
        self.state
            .read()
            .map(|s| s.patterns.is_empty())
            .unwrap_or(true)
    }
}

/// A reply streamed in pieces, sent on only once no stored secret can
/// be in what is sent. It holds back the last `longest − 1` bytes of the
/// text so far: the start of a secret that has not finished arriving is
/// never sent, and a secret that has finished arriving is found before
/// any of it goes. Once one is found, nothing more is sent.
pub struct HeldStream {
    matcher: std::sync::Arc<LeakMatcher>,
    text: String,
    sent: usize,
    refused: bool,
}

impl HeldStream {
    pub fn new(matcher: std::sync::Arc<LeakMatcher>) -> Self {
        Self {
            matcher,
            text: String::new(),
            sent: 0,
            refused: false,
        }
    }

    /// Add `piece`; returns what may be sent now, if anything.
    pub fn push(&mut self, piece: &str) -> Option<String> {
        if self.refused {
            return None;
        }
        self.text.push_str(piece);
        let longest = self.matcher.longest();
        // A secret not seen before ends in the new piece, so it starts
        // no earlier than `longest` bytes before what was sent.
        let from = self
            .text
            .floor_char_boundary(self.sent.saturating_sub(longest));
        if self
            .text
            .get(from..)
            .and_then(|t| self.matcher.find(t))
            .is_some()
        {
            self.refused = true;
            return None;
        }
        let safe = self
            .text
            .floor_char_boundary(self.text.len().saturating_sub(longest.saturating_sub(1)));
        self.release(safe)
    }

    /// The stream ended: the rest, if no secret is in the whole text.
    pub fn finish(&mut self) -> Option<String> {
        if self.refused || self.matcher.find(&self.text).is_some() {
            self.refused = true;
            return None;
        }
        self.release(self.text.len())
    }

    /// Whether a stored secret was found and the stream stopped.
    pub fn refused(&self) -> bool {
        self.refused
    }

    fn release(&mut self, upto: usize) -> Option<String> {
        if upto <= self.sent {
            return None;
        }
        let out = self.text.get(self.sent..upto)?.to_string();
        self.sent = upto;
        Some(out)
    }
}

impl State {
    fn rebuild(&mut self) {
        self.longest = self
            .patterns
            .iter()
            .map(|p| p.value.len())
            .max()
            .unwrap_or(0);
        self.automaton = if self.patterns.is_empty() {
            None
        } else {
            match AhoCorasick::new(self.patterns.iter().map(|p| p.value.as_slice())) {
                Ok(automaton) => Some(automaton),
                Err(e) => {
                    tracing::error!(error = %e, "leak matcher not rebuilt; it keeps the secrets it had");
                    return;
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str, parts: &[&str]) -> MatchableSecret {
        MatchableSecret {
            name: name.to_string(),
            parts: parts
                .iter()
                .map(|p| Zeroizing::new(p.to_string()))
                .collect(),
        }
    }

    #[test]
    fn an_empty_matcher_finds_nothing() {
        let m = LeakMatcher::new();
        assert!(m.is_empty());
        assert_eq!(m.find("anything at all"), None);
        assert_eq!(m.longest(), 0);
    }

    #[test]
    fn a_seeded_secret_is_found_by_name_anywhere_in_text() {
        let m = LeakMatcher::seeded([
            secret("telegram-token", &["123456:telegram-bot-token"]),
            secret("linear-oauth", &["lin-access-0001", "lin-refresh-0001"]),
        ]);
        assert_eq!(
            m.find("the token is 123456:telegram-bot-token, see?")
                .as_deref(),
            Some("telegram-token")
        );
        assert_eq!(
            m.find("refresh with lin-refresh-0001").as_deref(),
            Some("linear-oauth")
        );
        assert_eq!(m.find("nothing stored here"), None);
        // Exact bytes only: a changed case, or a part of a part, is not
        // a match.
        assert_eq!(m.find("123456:TELEGRAM-BOT-TOKEN"), None);
        assert_eq!(m.find("telegram-bot"), None);
        assert_eq!(m.longest(), "123456:telegram-bot-token".len());
    }

    #[test]
    fn a_value_learned_after_the_seed_is_found_and_identifiers_and_short_values_are_not() {
        let m = LeakMatcher::seeded([secret("slack-token", &["xoxb-original-1"])]);
        m.learn("slack-token", "xoxb-rotated-22", CredentialKind::Secret);
        m.learn(
            "matrix-username",
            "@wirken:example.org",
            CredentialKind::Identifier,
        );
        m.learn("short-pin", "1234", CredentialKind::Secret);
        assert_eq!(
            m.find("old xoxb-original-1").as_deref(),
            Some("slack-token")
        );
        assert_eq!(
            m.find("new xoxb-rotated-22").as_deref(),
            Some("slack-token")
        );
        assert_eq!(m.find("hello @wirken:example.org"), None);
        assert_eq!(m.find("pin 1234"), None);
    }

    #[test]
    fn learning_a_known_value_again_does_not_add_it_twice() {
        let m = LeakMatcher::seeded([secret("a-key", &["value-aaaa-1111"])]);
        m.learn("a-key", "value-aaaa-1111", CredentialKind::Secret);
        assert_eq!(m.state.read().unwrap().patterns.len(), 1);
    }

    fn held(m: LeakMatcher, pieces: &[&str]) -> (String, bool) {
        let mut h = HeldStream::new(std::sync::Arc::new(m));
        let mut sent = String::new();
        for p in pieces {
            sent.extend(h.push(p));
        }
        sent.extend(h.finish());
        (sent, h.refused())
    }

    #[test]
    fn a_clean_stream_is_sent_whole() {
        let m = LeakMatcher::seeded([secret("k", &["sk-0123456789"])]);
        let (sent, refused) = held(m, &["Hello ", "there, ", "this is fine."]);
        assert_eq!(sent, "Hello there, this is fine.");
        assert!(!refused);
    }

    #[test]
    fn no_part_of_a_secret_split_across_pieces_is_sent() {
        let m = LeakMatcher::seeded([secret("k", &["sk-0123456789"])]);
        let (sent, refused) = held(m, &["Here: s", "k-0123", "4567", "89 done"]);
        assert!(refused);
        assert!(sent.starts_with("Here"), "{sent}");
        // Not even the first character of the secret went out.
        assert!(!sent.contains('s'), "{sent}");
    }

    #[test]
    fn a_secret_at_the_very_end_is_held_and_never_sent() {
        let m = LeakMatcher::seeded([secret("k", &["sk-0123456789"])]);
        let (sent, refused) = held(m, &["ok ", "sk-0123456789"]);
        assert!(refused);
        assert_eq!(sent, "");
    }

    #[test]
    fn with_no_secret_known_every_piece_goes_at_once() {
        let mut h = HeldStream::new(std::sync::Arc::new(LeakMatcher::new()));
        assert_eq!(h.push("abc").as_deref(), Some("abc"));
        assert_eq!(h.push("déf").as_deref(), Some("déf"));
        assert_eq!(h.finish(), None);
    }

    #[test]
    fn a_multibyte_text_is_cut_on_character_boundaries() {
        let m = LeakMatcher::seeded([secret("k", &["sk-0123456789"])]);
        let (sent, refused) = held(m, &["café ", "naïve ", "résumé"]);
        assert_eq!(sent, "café naïve résumé");
        assert!(!refused);
    }
}
