//! `wirken zirkel` subcommands.
//!
//! Entry point for the Zirkel orchestrator. Both the cron-fired and the
//! manual run path call into here. Scope B fetches one source through
//! the policed transport and writes one candidate to the per-skill
//! SQLite. Scoring, clustering, theme naming, and digest push are
//! Scope C.

use anyhow::{Result, anyhow};
use wirken_agent::rate_limit::RateLimitConfig;
use wirken_zirkel::orchestrator::{OrchestratorConfig, run as orchestrator_run};

/// `wirken zirkel run` — load the installed Zirkel preset, fetch the
/// first source, write a candidate row, exit. Cron and manual entry
/// share this code path.
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
    // aggregator skill's filesystem.write_paths allow-set; the
    // bundled aggregator declares `~/.wirken/zirkel` which resolves
    // to that directory. `SkillStore::open` fails loud if the path
    // is outside the policy.
    let storage_dir = data_dir.join("zirkel");

    let summary = orchestrator_run(OrchestratorConfig {
        preset_dir,
        storage_dir,
        rate_limit: RateLimitConfig::default(),
    })
    .await
    .map_err(|e| anyhow!("zirkel orchestrator: {e}"))?;

    println!("Zirkel run complete:");
    println!(
        "  source:        {} ({})",
        summary.source_name, summary.source_url
    );
    println!("  bytes fetched: {}", summary.bytes_fetched);
    println!("  candidate id:  {}", summary.candidate_id);
    println!("(Scope B: one source per run, no scoring or digest yet — Scope C wires those.)");
    Ok(())
}
