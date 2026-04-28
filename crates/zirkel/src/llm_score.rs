//! LLM relevance scoring for Zirkel candidates.
//!
//! One LLM call per candidate using the
//! [`crate::synthetic_tool::score_candidate_tool`] structured-output
//! channel. Returns a 0–100 relevance rating plus a one-line
//! `why_surfaced` rationale and the matched user keyword.
//!
//! The keyword pre-filter (Scope C-foundation) already guaranteed
//! every input here matched at least one user keyword; this pass
//! adds the LLM's nuance — e.g. "matched 'biometric' but the paper
//! is about consumer authentication, score lower" — that a literal
//! substring match can't make.

use thiserror::Error;
use wirken_agent::llm::LlmClient;

use crate::fetcher::FetchedItem;
use crate::interests::Interests;
use crate::synthetic_tool::{
    ScoreCandidateArgs, SyntheticToolError, call_structured, score_candidate_tool,
};

/// Per-call error. `Synthetic` wraps the structured-output failure
/// modes (LLM didn't call the tool, parse failure, etc.); `Llm`
/// wraps lower-level transport / provider failures.
#[derive(Debug, Error)]
pub enum LlmScoreError {
    #[error("synthetic-tool call failed: {0}")]
    Synthetic(#[from] SyntheticToolError),
}

/// Score one candidate against the user's interests.
pub async fn score_candidate(
    llm: &LlmClient,
    api_key: Option<&str>,
    item: &FetchedItem,
    interests: &Interests,
) -> Result<ScoreCandidateArgs, LlmScoreError> {
    let system = system_prompt();
    let user = build_user_prompt(item, interests);
    let args: ScoreCandidateArgs =
        call_structured(llm, api_key, &system, &user, score_candidate_tool()).await?;
    Ok(args)
}

fn system_prompt() -> String {
    r#"You are Zirkel's relevance scorer. The user is a privacy lawyer who has hand-curated a list of interest keywords and exclusion phrases. The orchestrator has already filtered out items that don't match any keyword, so every item you see has at least one literal keyword match.

Your job is to add nuance the literal match cannot:
- A high score (80–100) means the candidate substantively addresses the matched keyword.
- A medium score (40–79) means the keyword appears but the candidate's main subject is adjacent.
- A low score (1–39) means the keyword appears incidentally (a casual mention, an unrelated pun on the term).
- Score 0 is for cases where the candidate is, on closer reading, a false positive — the keyword matched but the content has no real bearing on the user's interest.

You MUST call the zirkel_score_candidate tool. Do not respond with text."#
        .to_string()
}

fn build_user_prompt(item: &FetchedItem, interests: &Interests) -> String {
    let keywords = interests.keywords.join(", ");
    let exclusions = if interests.exclusions.is_empty() {
        "(none)".to_string()
    } else {
        interests.exclusions.join(", ")
    };
    format!(
        "User keywords:\n  {keywords}\n\
         User exclusions (already pre-filtered against — for context):\n  {exclusions}\n\n\
         Candidate:\n\
         Source: {source}\n\
         Title:  {title}\n\
         Abstract: {abstract_text}\n",
        keywords = keywords,
        exclusions = exclusions,
        source = item.source_name,
        title = item.title,
        abstract_text = item.abstract_text,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_item() -> FetchedItem {
        FetchedItem {
            source_name: "ftc".to_string(),
            url: "https://www.ftc.gov/x".to_string(),
            title: "FTC sues data broker".to_string(),
            abstract_text: "Section 5 unfairness against ExampleCorp.".to_string(),
            published_at: "2026-04-28T00:00:00Z".to_string(),
        }
    }

    fn fixture_interests() -> Interests {
        Interests {
            keywords: vec!["data broker".to_string(), "Section 5".to_string()],
            exclusions: vec!["cookie banner".to_string()],
            file_hash: "fixture".to_string(),
            raw_contents: String::new(),
        }
    }

    #[test]
    fn user_prompt_includes_candidate_and_interests() {
        let p = build_user_prompt(&fixture_item(), &fixture_interests());
        assert!(p.contains("data broker"));
        assert!(p.contains("Section 5"));
        assert!(p.contains("cookie banner"));
        assert!(p.contains("FTC sues data broker"));
        assert!(p.contains("Section 5 unfairness against ExampleCorp"));
    }

    #[test]
    fn user_prompt_handles_empty_exclusions_cleanly() {
        let mut interests = fixture_interests();
        interests.exclusions.clear();
        let p = build_user_prompt(&fixture_item(), &interests);
        assert!(p.contains("(none)"));
    }

    // End-to-end with a mocked LLM is exercised in
    // `crate::orchestrator::tests` — running `score_candidate` here
    // would require either a local OpenAI-compatible HTTP server or
    // a refactor of LlmClient to accept an injected transport. The
    // orchestrator integration test gives better coverage for less
    // duplicated setup.
}
