//! `wirken zirkel` subcommands.
//!
//! Entry point for the Zirkel orchestrator. Both the cron-fired and
//! the manual run path call into here. The C-foundation slice loops
//! every source in `sources.toml`, dispatches RSS/Atom through the
//! policed transport, dedups against the seen table, screens with
//! the user's interests file, and writes kept items to the per-skill
//! SQLite. LLM relevance scoring, clustering, theme naming, and
//! digest push are subsequent Scope C slices.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use wirken_agent::rate_limit::RateLimitConfig;
use wirken_audit::{SessionLog, SqliteSessionLog};
use wirken_zirkel::orchestrator::{OrchestratorConfig, run as orchestrator_run};

/// `wirken zirkel run` — load the installed Zirkel preset, run the
/// daily fetch + screen pipeline, exit.
pub async fn run() -> Result<()> {
    let data_dir = super::data_dir()?;
    let preset_dir = data_dir.join("presets").join("zirkel");
    if !preset_dir.join("preset.toml").exists() {
        return Err(anyhow!(
            "Zirkel preset is not installed at {}; run `wirken preset install zirkel` first",
            preset_dir.display(),
        ));
    }

    // Storage lives at <data_dir>/zirkel/. Must be inside the
    // aggregator skill's filesystem.write_paths allow-set.
    let storage_dir = data_dir.join("zirkel");
    std::fs::create_dir_all(&storage_dir)?;
    let interests_path = storage_dir.join("interests.toml");
    if !interests_path.exists() {
        return Err(anyhow!(
            "interests file not found at {}. Create it with `keywords = [...]` and \
             optional `exclusions = [...]` before running.",
            interests_path.display()
        ));
    }

    // Wirken's session-log SQLite is the audit chain. Open it as a
    // thread-safe trait object so the orchestrator's HttpFetch /
    // CandidateScored / CandidateSkipped events join the same chain
    // the agent runtime writes to.
    let audit_path = data_dir.join("audit.db");
    let session_log: Arc<dyn SessionLog> = Arc::new(
        SqliteSessionLog::open(&audit_path)
            .map_err(|e| anyhow!("open audit log at {}: {e}", audit_path.display()))?,
    );

    let summary = orchestrator_run(OrchestratorConfig {
        preset_dir,
        storage_dir,
        interests_path,
        rate_limit: RateLimitConfig::default(),
        session_log: Some(session_log),
    })
    .await
    .map_err(|e| anyhow!("zirkel orchestrator: {e}"))?;

    println!("Zirkel run complete (run_id: {}):", summary.run_id);
    println!("  sources attempted:   {}", summary.sources_attempted);
    println!("  sources succeeded:   {}", summary.sources_succeeded);
    if !summary.sources_unsupported.is_empty() {
        println!(
            "  sources unsupported: {}",
            summary.sources_unsupported.join(", ")
        );
    }
    if !summary.sources_failed.is_empty() {
        println!("  sources failed:      {}", summary.sources_failed.len());
        for failure in &summary.sources_failed {
            println!("    - {}: {}", failure.source, failure.reason);
        }
    }
    println!("  items seen:          {}", summary.items_seen);
    println!("  items new:           {}", summary.items_new);
    println!("  items excluded:      {}", summary.items_excluded);
    println!("  items score 0:       {}", summary.items_score_zero);
    println!("  items kept:          {}", summary.items_kept);
    if summary.interests_changed {
        println!("  interests changed:   yes (audit event emitted)");
    }
    println!("(C-foundation: keyword screen only. LLM relevance scoring is the next slice.)");
    Ok(())
}
