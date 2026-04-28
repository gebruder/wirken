//! Theme naming for Zirkel clusters.
//!
//! One LLM call per cluster using the
//! [`crate::synthetic_tool::name_theme_tool`] structured-output
//! channel. Input: the cluster's member titles plus the union of
//! `matched_keywords` across members. Output: a 2–5 word theme
//! name like "FTC enforcement" or "biometric privacy in employment".
//!
//! Per `docs/zirkel/DESIGN.md`: names should read like prose, not
//! cluster ids or jargon. The synthetic tool's parameter description
//! and the system prompt both reinforce that constraint.

use thiserror::Error;
use wirken_agent::llm::LlmClient;

use crate::synthetic_tool::{NameThemeArgs, SyntheticToolError, call_structured, name_theme_tool};

/// One cluster member, as the orchestrator hands it to
/// [`name_theme`]. `matched_keywords` is the JSON array stored on
/// the candidate row (parsed by the orchestrator before calling).
#[derive(Debug, Clone)]
pub struct ClusterMember {
    pub title: String,
    pub matched_keywords: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ThemeNameError {
    #[error("synthetic-tool call failed: {0}")]
    Synthetic(#[from] SyntheticToolError),
    #[error("cluster has no members; cannot name an empty cluster")]
    EmptyCluster,
}

pub async fn name_theme(
    llm: &LlmClient,
    api_key: Option<&str>,
    members: &[ClusterMember],
) -> Result<NameThemeArgs, ThemeNameError> {
    if members.is_empty() {
        return Err(ThemeNameError::EmptyCluster);
    }
    let system = system_prompt();
    let user = build_user_prompt(members);
    let args: NameThemeArgs =
        call_structured(llm, api_key, &system, &user, name_theme_tool()).await?;
    Ok(args)
}

fn system_prompt() -> String {
    r#"You are Zirkel's theme namer. You will be given a small cluster of related candidates (titles + the user keywords each one matched). Return a 2–5 word theme name that captures what the cluster is about, written in prose-style (e.g. "FTC enforcement", "biometric privacy in employment", "data broker registry"). Never return a cluster id, the literal user keywords as a list, or jargon-only labels.

You MUST call the zirkel_name_theme tool. Do not respond with text."#
        .to_string()
}

fn build_user_prompt(members: &[ClusterMember]) -> String {
    let mut all_keywords: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for m in members {
        for k in &m.matched_keywords {
            all_keywords.insert(k.clone());
        }
    }
    let keywords_csv = all_keywords.into_iter().collect::<Vec<_>>().join(", ");

    let mut s = String::new();
    s.push_str("Cluster members:\n");
    for (i, m) in members.iter().enumerate() {
        s.push_str(&format!("  {}. {}\n", i + 1, m.title));
    }
    s.push_str("\nUnion of user keywords matched across members: ");
    s.push_str(&keywords_csv);
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<ClusterMember> {
        vec![
            ClusterMember {
                title: "FTC sues data broker over Section 5 unfairness".to_string(),
                matched_keywords: vec!["data broker".to_string(), "Section 5".to_string()],
            },
            ClusterMember {
                title: "FTC announces new data broker registration rule".to_string(),
                matched_keywords: vec!["data broker".to_string()],
            },
        ]
    }

    #[test]
    fn user_prompt_includes_titles_and_union_keywords() {
        let p = build_user_prompt(&members());
        assert!(p.contains("FTC sues data broker"));
        assert!(p.contains("FTC announces new data broker"));
        // Union of keywords across members.
        assert!(p.contains("data broker"));
        assert!(p.contains("Section 5"));
    }

    #[tokio::test]
    async fn empty_cluster_is_a_typed_error() {
        // We can't reach a real LlmClient in a unit test; building a
        // dummy one with a localhost base_url is cheap and we never
        // make a request because the empty-cluster check short-circuits.
        let cfg = wirken_agent::llm::LlmConfig {
            provider: "ollama".into(),
            model: "llama3.1:8b".into(),
            base_url: "http://127.0.0.1:11434/v1".into(),
            max_tokens: 1024,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            context_window: 32_000,
        };
        let llm = LlmClient::new(cfg).unwrap();
        let err = name_theme(&llm, None, &[]).await.unwrap_err();
        assert!(matches!(err, ThemeNameError::EmptyCluster));
    }
}
