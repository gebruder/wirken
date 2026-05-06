//! Perspective-guided query expansion (front-half of Stanford STORM,
//! stripped of synthesis).
//!
//! Given a topic, gather Wikipedia section headings from a small
//! number of related articles, ask the LLM for short noun-phrase
//! perspective labels, return the labels. Labels are ephemeral: the
//! orchestrator threads them through one fetch loop per perspective
//! and discards them at the end of the turn. They are not persisted
//! outside the audit chain.
//!
//! Two HTTP calls plus one LLM call per turn: an opensearch lookup
//! to discover related Wikipedia titles, then one section-list
//! fetch per discovered title, then a single structured-output LLM
//! call that produces the labels. STORM's `persona_generator`
//! mechanism, with the article-generation back half intentionally
//! absent.

use thiserror::Error;
use wirken_agent::egress::EgressClient;
use wirken_agent::llm::LlmClient;

use crate::fetcher::{FetchError, Fetcher, SourceConfig, WikipediaTocFetcher, fetch_body};
use crate::synthetic_tool::{
    EmitPerspectivesArgs, SyntheticToolError, call_structured, emit_perspectives_tool,
};

/// Production-default Wikipedia Action API endpoint. Tests redirect
/// to a localhost mock by passing an alternative `api_base` to
/// [`expand`].
pub const DEFAULT_WIKIPEDIA_API_BASE: &str = "https://en.wikipedia.org/w/api.php";

#[derive(Debug, Error)]
pub enum PerspectiveError {
    #[error("opensearch failed: {0}")]
    Opensearch(String),
    #[error("toc fetch failed: {0}")]
    TocFetch(#[from] FetchError),
    #[error("perspective-emit LLM call failed: {0}")]
    Llm(#[from] SyntheticToolError),
    #[error("no related Wikipedia titles produced for topic")]
    NoRelated,
}

/// Run a perspective-expansion turn for `topic`. Returns up to
/// `max_perspectives` short noun-phrase labels.
///
/// `max_related` caps how many Wikipedia articles get their TOC
/// fetched. The orchestrator's per-topic fan-out budget gates the
/// downstream retriever loop separately; this function only knows
/// about its own metadata fetches.
pub async fn expand(
    llm: &LlmClient,
    api_key: Option<&str>,
    http: &EgressClient,
    api_base: &str,
    topic: &str,
    max_related: usize,
    max_perspectives: usize,
) -> Result<Vec<String>, PerspectiveError> {
    let related = wikipedia_opensearch(http, api_base, topic, max_related).await?;
    if related.is_empty() {
        return Err(PerspectiveError::NoRelated);
    }

    let toc_fetcher = WikipediaTocFetcher;
    let mut headings: Vec<String> = Vec::new();
    for title in &related {
        let endpoint = wikipedia_parse_sections_url(api_base, title);
        let cfg = SourceConfig {
            name: format!("wiki:{title}"),
            endpoint,
        };
        match toc_fetcher.fetch(http, &cfg).await {
            Ok(items) => {
                for item in items {
                    if !item.title.is_empty() {
                        headings.push(format!("{title}: {}", item.title));
                    }
                }
            }
            Err(e) => {
                // One related title's TOC failing must not abort the
                // whole expansion. The retriever loop only needs the
                // labels in aggregate; a thinner heading set just
                // means slightly less grounding for the LLM.
                tracing::warn!(
                    "wikipedia toc fetch for related title '{title}' failed: {e}; skipping"
                );
            }
        }
    }

    let user_prompt = build_user_prompt(topic, &related, &headings);
    let args: EmitPerspectivesArgs = call_structured(
        llm,
        api_key,
        SYSTEM_PROMPT,
        &user_prompt,
        emit_perspectives_tool(max_perspectives),
    )
    .await?;

    let mut labels: Vec<String> = args
        .perspectives
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    labels.truncate(max_perspectives);
    Ok(labels)
}

/// MediaWiki opensearch returns `[term, [titles...], [descriptions...], [urls...]]`.
/// The titles array is the only field this function uses; the
/// descriptions and url arrays are discarded.
async fn wikipedia_opensearch(
    http: &EgressClient,
    api_base: &str,
    term: &str,
    limit: usize,
) -> Result<Vec<String>, PerspectiveError> {
    let url = url::Url::parse_with_params(
        api_base,
        &[
            ("action", "opensearch"),
            ("format", "json"),
            ("search", term),
            ("limit", &limit.max(1).to_string()),
        ],
    )
    .map_err(|e| PerspectiveError::Opensearch(format!("build url: {e}")))?;
    let body = fetch_body(http, url.as_str())
        .await
        .map_err(|e| PerspectiveError::Opensearch(format!("http: {e}")))?;
    parse_opensearch_titles(&body)
}

fn parse_opensearch_titles(body: &str) -> Result<Vec<String>, PerspectiveError> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| PerspectiveError::Opensearch(format!("parse: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| PerspectiveError::Opensearch("expected array root".into()))?;
    let titles = arr
        .get(1)
        .and_then(|v| v.as_array())
        .ok_or_else(|| PerspectiveError::Opensearch("missing titles array at index 1".into()))?;
    Ok(titles
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

fn wikipedia_parse_sections_url(api_base: &str, title: &str) -> String {
    url::Url::parse_with_params(
        api_base,
        &[
            ("action", "parse"),
            ("format", "json"),
            ("prop", "sections"),
            ("page", title),
        ],
    )
    .map(|u| u.to_string())
    .unwrap_or_else(|_| api_base.to_string())
}

fn build_user_prompt(topic: &str, related: &[String], headings: &[String]) -> String {
    let related_list = related.join(", ");
    let headings_block = if headings.is_empty() {
        "(none -- the related-article TOC fetch returned no usable headings)".to_string()
    } else {
        headings.join("\n")
    };
    format!(
        "Topic: {topic}\n\n\
         Related Wikipedia articles surveyed: {related_list}\n\n\
         Section headings from those articles:\n{headings_block}\n"
    )
}

const SYSTEM_PROMPT: &str = "You are Zirkel's perspective expander. Given a topic and a list of section headings drawn from related Wikipedia articles, produce a short list of noun-phrase labels naming distinct angles on the topic. \
Each label must be 2 to 5 words. No verbs, no full sentences, no quotes. Labels must be distinct: do not return synonyms of the same angle. Prefer concrete framings over abstract ones. \
You MUST call the zirkel_emit_perspectives tool. Do not respond with text.";

/// Drop labels whose slug collides with an earlier label's slug.
///
/// Returned tuple is `(kept, dropped)`. Both vectors preserve the
/// LLM's emission order; first occurrence of any given slug wins.
/// The slug helper folds case, whitespace, and Unicode into ASCII
/// alphanumerics, so two surface-distinct labels can collapse to
/// the same `SourceConfig.name`. Two synthetic configs with
/// identical names dispatch the same fetch twice (the seen-table
/// dedup then drops the second batch as duplicate URLs), but the
/// audit chain loses the "two perspectives meant the same fetch"
/// fact and the `RunSummary.perspectives_used` list overstates the
/// turn's coverage. The system prompt asks the LLM for distinct
/// labels but does not constrain slug-collision specifically, so
/// this filter runs unconditionally and the orchestrator records
/// the dropped labels alongside the kept ones in the
/// `PerspectiveExpansion` event.
pub fn dedupe_by_slug(labels: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(labels.len());
    let mut kept: Vec<String> = Vec::with_capacity(labels.len());
    let mut dropped: Vec<String> = Vec::new();
    for label in labels {
        let s = slug(&label);
        if seen.insert(s) {
            kept.push(label);
        } else {
            dropped.push(label);
        }
    }
    (kept, dropped)
}

/// Slugify a perspective label for use in a synthetic
/// `SourceConfig.name` field. Lowercase, ASCII alphanumerics kept,
/// runs of other characters collapsed to a single `-`, leading and
/// trailing `-` stripped. Empty input returns the literal
/// `"perspective"` so an audit row never has an empty source name.
pub fn slug(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut prev_dash = true;
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "perspective".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opensearch_titles_parse_from_array_shape() {
        let body = r#"["climate", ["Climate change", "Climate policy", "Climate justice"], ["a","b","c"], ["u1","u2","u3"]]"#;
        let titles = parse_opensearch_titles(body).unwrap();
        assert_eq!(
            titles,
            vec!["Climate change", "Climate policy", "Climate justice"]
        );
    }

    #[test]
    fn opensearch_with_no_titles_yields_empty_vec() {
        let body = r#"["climate", [], [], []]"#;
        let titles = parse_opensearch_titles(body).unwrap();
        assert!(titles.is_empty());
    }

    #[test]
    fn opensearch_non_array_root_is_an_error() {
        let body = r#"{"unexpected":"object"}"#;
        let err = parse_opensearch_titles(body).unwrap_err();
        assert!(matches!(err, PerspectiveError::Opensearch(_)));
    }

    #[test]
    fn dedupe_by_slug_preserves_first_and_records_dropped() {
        let (kept, dropped) = dedupe_by_slug(vec![
            "Climate policy".to_string(),
            "climate-policy".to_string(),
            "Section 5 enforcement".to_string(),
            "section, 5, enforcement".to_string(),
            "Distinct angle".to_string(),
        ]);
        assert_eq!(
            kept,
            vec![
                "Climate policy".to_string(),
                "Section 5 enforcement".to_string(),
                "Distinct angle".to_string(),
            ]
        );
        assert_eq!(
            dropped,
            vec![
                "climate-policy".to_string(),
                "section, 5, enforcement".to_string(),
            ]
        );
    }

    #[test]
    fn dedupe_by_slug_with_empty_input_returns_empty() {
        let (kept, dropped) = dedupe_by_slug(vec![]);
        assert!(kept.is_empty());
        assert!(dropped.is_empty());
    }

    #[test]
    fn dedupe_by_slug_treats_empty_label_slugs_as_one() {
        // Both slug to "perspective" because the helper substitutes
        // a literal for empty inputs. Pinning so a future slug-helper
        // change does not silently produce two identical
        // `SourceConfig.name` values.
        let (kept, dropped) = dedupe_by_slug(vec!["".to_string(), "!!!".to_string()]);
        assert_eq!(kept, vec!["".to_string()]);
        assert_eq!(dropped, vec!["!!!".to_string()]);
    }

    #[test]
    fn slug_keeps_ascii_alphanumerics_and_collapses_other_runs() {
        assert_eq!(slug("Section 5 enforcement"), "section-5-enforcement");
        assert_eq!(slug("EU AI Act"), "eu-ai-act");
        assert_eq!(
            slug("  --leading--and--trailing--  "),
            "leading-and-trailing"
        );
        assert_eq!(slug(""), "perspective");
        assert_eq!(slug("!!!"), "perspective");
    }

    #[test]
    fn parse_sections_url_round_trips_title() {
        let u = wikipedia_parse_sections_url(
            DEFAULT_WIKIPEDIA_API_BASE,
            "Biometric Information Privacy Act",
        );
        assert!(u.contains("action=parse"));
        assert!(u.contains("prop=sections"));
        // Url's encoder uses + for spaces in query strings.
        assert!(u.contains("Biometric") && u.contains("Privacy") && u.contains("Act"));
    }

    #[test]
    fn parse_sections_url_honours_alternative_base() {
        let u = wikipedia_parse_sections_url("http://127.0.0.1:9999/w/api.php", "Topic");
        assert!(u.starts_with("http://127.0.0.1:9999/w/api.php"));
        assert!(u.contains("page=Topic"));
    }

    #[test]
    fn build_user_prompt_lists_topic_related_and_headings() {
        let p = build_user_prompt(
            "biometric privacy",
            &["BIPA".to_string(), "GDPR".to_string()],
            &[
                "BIPA: Background".to_string(),
                "GDPR: Article 9".to_string(),
            ],
        );
        assert!(p.contains("biometric privacy"));
        assert!(p.contains("BIPA"));
        assert!(p.contains("GDPR"));
        assert!(p.contains("Background"));
        assert!(p.contains("Article 9"));
    }

    #[test]
    fn build_user_prompt_handles_empty_headings_block() {
        let p = build_user_prompt("x", &["X".to_string()], &[]);
        assert!(p.contains("(none"));
    }
}
