//! Keyword and exclusion screening.
//!
//! Both axes are case-insensitive substring matches against the
//! candidate's `title + " " + abstract_text`. This is the user's
//! actual interface — what she'd write on paper if she were doing
//! this manually. The C-LLM slice adds an LLM-relevance scorer in a
//! separate axis (`llm_relevance_score REAL`) that runs on top.
//!
//! Scoring semantics in this slice:
//! - `keyword_match_score = number of distinct keywords matched`.
//! - Threshold for inclusion in the candidates table: `score >= 1`.
//! - Items with no keyword match land in `skipped_log` with reason
//!   `score_zero`, not in `candidates`.
//! - Exclusion takes precedence over keyword match: if any exclusion
//!   matches, the item lands in `skipped_log` with reason
//!   `exclusion_match`, regardless of keyword matches.

/// What [`Item::haystack`] is matched against.
pub trait Item {
    /// Concatenated text the matchers operate over. Caller composes
    /// from title + abstract; the trait keeps the matcher independent
    /// of the underlying record shape.
    fn haystack(&self) -> String;
}

/// Outcome of running an item through both screens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screened {
    /// Drop: an exclusion phrase matched. Caller writes a
    /// `skipped_log` row with `reason = "exclusion_match"` and the
    /// matched phrase in `detail`.
    Excluded { matched_exclusion: String },
    /// Drop: no keyword matched (score 0). Caller writes a
    /// `skipped_log` row with `reason = "score_zero"`.
    Zero,
    /// Keep: at least one keyword matched. Caller writes a
    /// `candidates` row with `matched_keywords` (JSON-encoded) and
    /// `keyword_match_score`.
    Kept {
        matched_keywords: Vec<String>,
        keyword_match_score: u32,
    },
}

/// Run an item through exclusion-first then keyword screening.
/// Exclusions are checked in declaration order; the first match
/// wins and short-circuits the rest.
pub fn screen<I: Item>(item: &I, keywords: &[String], exclusions: &[String]) -> Screened {
    let haystack = item.haystack().to_lowercase();
    for ex in exclusions {
        if ex.is_empty() {
            continue;
        }
        if haystack.contains(&ex.to_lowercase()) {
            return Screened::Excluded {
                matched_exclusion: ex.clone(),
            };
        }
    }
    let mut matched: Vec<String> = Vec::new();
    for kw in keywords {
        if kw.is_empty() {
            continue;
        }
        if haystack.contains(&kw.to_lowercase()) && !matched.iter().any(|m| m == kw) {
            matched.push(kw.clone());
        }
    }
    if matched.is_empty() {
        Screened::Zero
    } else {
        let score = matched.len() as u32;
        Screened::Kept {
            matched_keywords: matched,
            keyword_match_score: score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestItem(String);
    impl Item for TestItem {
        fn haystack(&self) -> String {
            self.0.clone()
        }
    }
    fn item(text: &str) -> TestItem {
        TestItem(text.to_string())
    }

    #[test]
    fn no_match_returns_zero() {
        let result = screen(
            &item("Some random article about cats"),
            &["BIPA".to_string()],
            &[],
        );
        assert_eq!(result, Screened::Zero);
    }

    #[test]
    fn one_match_returns_kept_with_score_1() {
        let result = screen(&item("BIPA enforcement update"), &["BIPA".to_string()], &[]);
        assert_eq!(
            result,
            Screened::Kept {
                matched_keywords: vec!["BIPA".to_string()],
                keyword_match_score: 1,
            }
        );
    }

    #[test]
    fn multiple_distinct_matches_score_each_once() {
        let result = screen(
            &item("BIPA, Section 5, and data broker registry"),
            &[
                "BIPA".to_string(),
                "Section 5".to_string(),
                "data broker".to_string(),
            ],
            &[],
        );
        match result {
            Screened::Kept {
                matched_keywords,
                keyword_match_score,
            } => {
                assert_eq!(keyword_match_score, 3);
                assert!(matched_keywords.contains(&"BIPA".to_string()));
                assert!(matched_keywords.contains(&"Section 5".to_string()));
                assert!(matched_keywords.contains(&"data broker".to_string()));
            }
            other => panic!("expected Kept, got {other:?}"),
        }
    }

    #[test]
    fn case_insensitive() {
        let result = screen(&item("bipa enforcement"), &["BIPA".to_string()], &[]);
        assert!(matches!(result, Screened::Kept { .. }));
    }

    #[test]
    fn repeated_match_counts_once() {
        let result = screen(&item("BIPA BIPA BIPA"), &["BIPA".to_string()], &[]);
        match result {
            Screened::Kept {
                matched_keywords,
                keyword_match_score,
            } => {
                assert_eq!(keyword_match_score, 1);
                assert_eq!(matched_keywords, vec!["BIPA".to_string()]);
            }
            other => panic!("expected Kept score 1, got {other:?}"),
        }
    }

    #[test]
    fn exclusion_takes_precedence_over_keyword_match() {
        let result = screen(
            &item("BIPA cookie banner enforcement"),
            &["BIPA".to_string()],
            &["cookie banner".to_string()],
        );
        assert_eq!(
            result,
            Screened::Excluded {
                matched_exclusion: "cookie banner".to_string(),
            }
        );
    }

    #[test]
    fn first_exclusion_match_wins_over_later_exclusions() {
        let result = screen(
            &item("alpha beta gamma"),
            &[],
            &["alpha".to_string(), "beta".to_string()],
        );
        assert_eq!(
            result,
            Screened::Excluded {
                matched_exclusion: "alpha".to_string(),
            }
        );
    }

    #[test]
    fn empty_keyword_or_exclusion_strings_skipped() {
        // An empty string in `contains` matches everything; ensure
        // our screen doesn't misfire on empties.
        let result = screen(
            &item("anything"),
            &["".to_string(), "needle".to_string()],
            &["".to_string()],
        );
        // The empty exclusion should NOT trigger Excluded.
        // The empty keyword should NOT contribute a match.
        assert_eq!(result, Screened::Zero);
    }
}
