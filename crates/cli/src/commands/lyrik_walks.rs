//! Per-walk Lyrik dispatch: parse + validate `walks: [...]` and
//! `max_concurrent_walks` from `.lyrik/config.json`, stage selected
//! walk skills under the run directory with synthesized
//! wirken-shaped frontmatter, and run one agent turn per walk.
//!
//! Concurrency lands in commit 2; this module ships the serial
//! baseline. The one-call slice (no `walks` field) keeps the
//! existing `/lyrik` dispatch path; this module is reached only
//! when the operator opts in via the config field.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Maximum concurrent walks when not specified in config. Tuned to
/// the conservative end of common provider rate limits; operators
/// running on higher tiers can raise it. Higher than the total walk
/// count is a no-op.
pub const DEFAULT_MAX_CONCURRENT_WALKS: u32 = 4;

/// Canonical list of walk skill names. Adding a walk: extend the
/// list and ship a SKILL.md in the operator's `~/.claude/skills/`
/// tree (or any directory the validator points at). Names are the
/// directory name under that tree.
pub const KNOWN_WALKS: &[&str] = &[
    "chain-walk",
    "crypto-walk",
    "differential-walk",
    "doc-walk",
    "fuzz-walk",
    "graph-walk",
    "invariant-walk",
    "sink-walk",
];

/// Parsed `walks:` block from `.lyrik/config.json`. `walks: None`
/// is the one-call slice; callers route to the existing `/lyrik`
/// dispatch. `walks: Some([...])` opts into per-walk dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalksConfig {
    /// Selected walks for this run, in operator-supplied order.
    pub walks: Vec<String>,
    /// Maximum concurrent walks. Always populated; the parser
    /// substitutes [`DEFAULT_MAX_CONCURRENT_WALKS`] when the field
    /// is absent.
    pub max_concurrent_walks: u32,
}

/// Source directory that holds operator-installed walk skills.
/// `~/.claude/skills/<walk-name>/SKILL.md`. Resolved at runtime so
/// tests can substitute a fixture tree.
pub fn default_walks_source_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".claude").join("skills")
}

/// Parse and validate the `walks:` block.
///
/// Returns `Ok(None)` when the field is absent (one-call slice).
/// Returns `Err` for any of:
///
/// - empty `walks: []` array (likely-typo guard; the way to skip
///   Lyrik is don't run it),
/// - unknown walk name,
/// - missing `<walks_source_dir>/<walk-name>/SKILL.md`.
///
/// `max_concurrent_walks` defaults to
/// [`DEFAULT_MAX_CONCURRENT_WALKS`] when absent. Values of 0 are
/// rejected; values above the selected walk count are clamped (a
/// cap above the list is a no-op).
pub fn parse_walks_config(
    config: &serde_json::Value,
    walks_source_dir: &Path,
) -> Result<Option<WalksConfig>> {
    let walks_value = match config.get("walks") {
        Some(v) => v,
        None => return Ok(None),
    };

    let arr = walks_value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("config.walks must be an array of walk names"))?;

    if arr.is_empty() {
        anyhow::bail!(
            "config.walks is an empty array; remove the field to keep the one-call slice or list \
             walks like [\"sink-walk\", \"chain-walk\"]"
        );
    }

    let mut walks = Vec::with_capacity(arr.len());
    for v in arr {
        let name = v
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("config.walks entries must be strings"))?;
        if !KNOWN_WALKS.contains(&name) {
            anyhow::bail!(
                "config.walks contains unknown walk `{name}`; known walks: {known}",
                known = KNOWN_WALKS.join(", ")
            );
        }
        let skill_md = walks_source_dir.join(name).join("SKILL.md");
        if !skill_md.is_file() {
            anyhow::bail!(
                "walk `{name}` is not installed at {} \
                 (install via the operator's skill tree, then rerun)",
                skill_md.display()
            );
        }
        walks.push(name.to_string());
    }

    let max_concurrent_walks = match config.get("max_concurrent_walks") {
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("config.max_concurrent_walks must be an integer"))?;
            if n == 0 {
                anyhow::bail!(
                    "config.max_concurrent_walks must be >= 1; omit the field to use the default \
                     ({DEFAULT_MAX_CONCURRENT_WALKS})"
                );
            }
            u32::try_from(n).unwrap_or(DEFAULT_MAX_CONCURRENT_WALKS)
        }
        None => DEFAULT_MAX_CONCURRENT_WALKS,
    };

    Ok(Some(WalksConfig {
        walks,
        max_concurrent_walks,
    }))
}

/// Stage each selected walk's `SKILL.md` into the per-run staging
/// directory under a wirken-shaped frontmatter. Operators install
/// walk skills as Claude-style SKILL.md files (no permissions
/// block); the wirken Agent's SkillLoader requires a permissions
/// block, so we wrap each walk at run time rather than asking
/// operators to maintain two copies.
///
/// Returns the staged directory path. Pass it to
/// [`wirken_agent::Agent::extend_skills`] alongside the existing
/// `<data_dir>/skills/` load so the slash interceptor finds
/// `/<walk-name>` as a first-class skill.
pub fn stage_walk_skills(
    walks: &[String],
    walks_source_dir: &Path,
    run_dir: &Path,
) -> Result<PathBuf> {
    let staged = run_dir.join("walks-skills");
    std::fs::create_dir_all(&staged).with_context(|| format!("create {}", staged.display()))?;
    for name in walks {
        let src = walks_source_dir.join(name).join("SKILL.md");
        let body =
            std::fs::read_to_string(&src).with_context(|| format!("read {}", src.display()))?;
        let dest_dir = staged.join(name);
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("create {}", dest_dir.display()))?;
        let dest = dest_dir.join("SKILL.md");
        let wrapped = wrap_with_wirken_frontmatter(name, &body);
        std::fs::write(&dest, wrapped).with_context(|| format!("write {}", dest.display()))?;
        wirken_agent::bundled_skills::self_sign_skill_dir(&dest_dir)
            .with_context(|| format!("sign staged walk skill at {}", dest_dir.display()))?;
    }
    Ok(staged)
}

/// Wrap an operator-installed walk SKILL.md body with a
/// wirken-compatible frontmatter so the Agent's SkillLoader
/// accepts it. The wrapped permissions match the Lyrik skill's
/// posture: read the workspace, write only under
/// `<workspace>/.lyrik`, deny network, allow any inference
/// provider. Walks do not need anything broader.
///
/// Strips an existing leading `---` frontmatter block from the
/// source (Claude-style `name:` / `description:`) and writes a
/// fresh one. The original description is preserved when present
/// so the slash interceptor still surfaces a useful one-liner.
pub fn wrap_with_wirken_frontmatter(walk_name: &str, source: &str) -> String {
    let (orig_description, body) = strip_leading_frontmatter(source);
    let description =
        orig_description.unwrap_or_else(|| format!("Per-walk Lyrik dispatch: {walk_name}"));
    format!(
        "---\nname: {walk_name}\ndescription: {description}\ndisable-model-invocation: true\npermissions:\n  tools:\n    allow: [exec, read_file, write_file, list_files]\n  egress:\n    mode: deny\n  filesystem:\n    read_paths: [\"<workspace>\"]\n    write_paths: [\"<workspace>/.lyrik\"]\n  inference:\n    allow: [\"*\"]\n---\n\n{body}"
    )
}

/// Pull the `description:` line out of a leading `---` frontmatter
/// block (if any) and return the remainder as the body. Used to
/// preserve a meaningful description on the staged skill so
/// `/<walk-name>` keeps the operator-facing context that the
/// upstream walk SKILL.md carried.
fn strip_leading_frontmatter(source: &str) -> (Option<String>, &str) {
    let trimmed = source.trim_start_matches('\u{feff}');
    if !trimmed.starts_with("---") {
        return (None, trimmed);
    }
    let after_open = &trimmed[3..];
    // The frontmatter terminator is `\n---` followed by newline or end.
    let close_idx = match after_open.find("\n---") {
        Some(i) => i,
        None => return (None, trimmed),
    };
    let block = &after_open[..close_idx];
    let after_close = &after_open[close_idx + 4..];
    let body_start = after_close.trim_start_matches('\n');

    let mut description = None;
    for line in block.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("description:") {
            description = Some(rest.trim().to_string());
            break;
        }
    }
    (description, body_start)
}

/// Build the per-walk staging subtree under
/// `<run-dir>/staging/<walk-name>/{context,rubric,findings}/`.
/// Idempotent. The Lyrik runner aggregates walk-emitted artifacts
/// from these directories after the agent turns return.
pub fn ensure_walk_staging(run_dir: &Path, walks: &[String]) -> Result<()> {
    for w in walks {
        let walk_dir = run_dir.join("staging").join(w);
        for sub in &["context", "rubric", "findings"] {
            let p = walk_dir.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("create {}", p.display()))?;
        }
    }
    Ok(())
}

/// Synthesize the per-walk dispatch prompt. The slash interceptor
/// rewrites `/<walk-name> ...` to prepend the staged walk body, so
/// the runner only needs to supply the run-id, the staging path,
/// and the workspace pointer. Walks read the rest from the staged
/// SKILL.md body.
pub fn build_walk_prompt(walk_name: &str, run_id: &str, seed_protocol_suffix: &str) -> String {
    format!(
        "/{walk_name} Run {walk_name} on this workspace. Run-id: `{run_id}`. \
         Emission is staged. Findings: write each finding to \
         `.lyrik/state/runs/{run_id}/staging/{walk_name}/findings/finding-NNN.json` \
         (zero-padded ordinal; one finding per file). Context (if produced): \
         `.lyrik/state/runs/{run_id}/staging/{walk_name}/context/<NN>-<section>.md`. \
         Rubric (if produced): `.lyrik/state/runs/{run_id}/staging/{walk_name}/rubric/<NN>-<tier>.md`. \
         Do not write `findings.json` directly; the Lyrik runner aggregates \
         per-walk staging into the canonical findings.json after every walk \
         turn returns.{seed_protocol_suffix}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn install_walk_fixture(dir: &Path, name: &str, body: &str) {
        let walk_dir = dir.join(name);
        std::fs::create_dir_all(&walk_dir).unwrap();
        std::fs::write(walk_dir.join("SKILL.md"), body).unwrap();
    }

    fn minimal_walk_body(name: &str) -> String {
        format!("---\nname: {name}\ndescription: stub for tests\n---\n\n# {name}\n\nbody.\n")
    }

    #[test]
    fn parse_walks_config_returns_none_when_field_absent() {
        let cfg = serde_json::json!({"phases": {}});
        let tmp = tempdir().unwrap();
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_walks_config_rejects_empty_array() {
        let cfg = serde_json::json!({"walks": []});
        let tmp = tempdir().unwrap();
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("empty array"));
    }

    #[test]
    fn parse_walks_config_rejects_unknown_walk() {
        let cfg = serde_json::json!({"walks": ["typo-walk"]});
        let tmp = tempdir().unwrap();
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unknown walk"));
    }

    #[test]
    fn parse_walks_config_rejects_missing_skill_file() {
        let cfg = serde_json::json!({"walks": ["sink-walk"]});
        let tmp = tempdir().unwrap();
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("not installed"),
            "expected 'not installed' in: {err}"
        );
    }

    #[test]
    fn parse_walks_config_accepts_known_installed_walk() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({"walks": ["sink-walk"]});
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap().unwrap();
        assert_eq!(parsed.walks, vec!["sink-walk"]);
        assert_eq!(parsed.max_concurrent_walks, DEFAULT_MAX_CONCURRENT_WALKS);
    }

    #[test]
    fn parse_walks_config_honors_max_concurrent_override() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({
            "walks": ["sink-walk"],
            "max_concurrent_walks": 8
        });
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap().unwrap();
        assert_eq!(parsed.max_concurrent_walks, 8);
    }

    #[test]
    fn parse_walks_config_rejects_zero_concurrency() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({
            "walks": ["sink-walk"],
            "max_concurrent_walks": 0
        });
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(">= 1"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_strips_existing_block_and_preserves_description() {
        let src = "---\nname: sink-walk\ndescription: existing one\n---\n\n# Sink-Walk\n\nbody.";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", src);
        assert!(wrapped.starts_with("---\nname: sink-walk\n"));
        assert!(wrapped.contains("description: existing one"));
        assert!(wrapped.contains("# Sink-Walk"));
        assert!(wrapped.contains("permissions:"));
        assert!(wrapped.contains("write_paths: [\"<workspace>/.lyrik\"]"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_supplies_default_description_when_missing() {
        let src = "---\nname: sink-walk\n---\n\n# Sink-Walk\n";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", src);
        assert!(wrapped.contains("Per-walk Lyrik dispatch: sink-walk"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_handles_no_existing_frontmatter() {
        let src = "# Just a body\n";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", src);
        assert!(wrapped.starts_with("---\nname: sink-walk"));
        assert!(wrapped.contains("# Just a body"));
    }

    #[test]
    fn stage_walk_skills_writes_one_file_per_walk() {
        let src = tempdir().unwrap();
        install_walk_fixture(src.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        install_walk_fixture(src.path(), "chain-walk", &minimal_walk_body("chain-walk"));
        let run = tempdir().unwrap();
        let staged = stage_walk_skills(
            &["sink-walk".to_string(), "chain-walk".to_string()],
            src.path(),
            run.path(),
        )
        .unwrap();
        assert!(staged.join("sink-walk/SKILL.md").is_file());
        assert!(staged.join("chain-walk/SKILL.md").is_file());
        let body = std::fs::read_to_string(staged.join("sink-walk/SKILL.md")).unwrap();
        assert!(body.contains("permissions:"));
    }

    /// Each staged walk dir carries a SKILL.sig + SKILL.pub pair that
    /// verifies under the same loader gate the agent runtime applies.
    /// Catches the silent regression where stage_walk_skills stops
    /// calling self_sign_skill_dir and walks load empty again.
    #[test]
    fn stage_walk_skills_self_signs_each_staged_dir() {
        use wirken_gateway::skill_registry::{
            VerifyResult as SkillVerifyResult, verify_skill_self_signed,
        };

        let src = tempdir().unwrap();
        install_walk_fixture(src.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        install_walk_fixture(src.path(), "chain-walk", &minimal_walk_body("chain-walk"));
        let run = tempdir().unwrap();
        let staged = stage_walk_skills(
            &["sink-walk".to_string(), "chain-walk".to_string()],
            src.path(),
            run.path(),
        )
        .unwrap();
        for walk in ["sink-walk", "chain-walk"] {
            let walk_dir = staged.join(walk);
            assert!(
                walk_dir.join("SKILL.sig").exists(),
                "{walk}: SKILL.sig missing"
            );
            assert!(
                walk_dir.join("SKILL.pub").exists(),
                "{walk}: SKILL.pub missing"
            );
            let result = verify_skill_self_signed(&walk_dir).unwrap();
            assert!(
                matches!(result, SkillVerifyResult::Valid { .. }),
                "{walk}: signature did not verify: {result:?}"
            );
        }
    }

    #[test]
    fn ensure_walk_staging_creates_three_subdirs_per_walk() {
        let run = tempdir().unwrap();
        ensure_walk_staging(
            run.path(),
            &["sink-walk".to_string(), "graph-walk".to_string()],
        )
        .unwrap();
        for w in ["sink-walk", "graph-walk"] {
            for sub in ["context", "rubric", "findings"] {
                assert!(
                    run.path().join("staging").join(w).join(sub).is_dir(),
                    "missing {w}/{sub}"
                );
            }
        }
    }

    #[test]
    fn build_walk_prompt_includes_walk_name_run_id_and_staging_path() {
        let p = build_walk_prompt("sink-walk", "sample/run-001", "");
        assert!(p.starts_with("/sink-walk "));
        assert!(p.contains("Run-id: `sample/run-001`"));
        assert!(p.contains("staging/sink-walk/findings/finding-NNN.json"));
    }

    #[test]
    fn build_walk_prompt_appends_seed_protocol_suffix_when_supplied() {
        let suffix = " SEEDS-MARKER";
        let p = build_walk_prompt("sink-walk", "sample/run-001", suffix);
        assert!(p.ends_with(suffix));
    }
}
