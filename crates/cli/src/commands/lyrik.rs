//! `wirken lyrik report` subcommand.
//!
//! Slice 4 ships the CLI surface and a minimal-valid empty SARIF
//! skeleton. Slice 5 swaps the inline `serde_json::json!` stub for
//! typed structs that read `findings.json` and emit per-finding
//! results, rules, and properties bags.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json";
const SARIF_VERSION: &str = "2.1.0";
const LYRIK_INFO_URI: &str = "https://lyrik.wirken.ai";

/// Emit a Lyrik report in the requested format.
///
/// `run` is the run-id under `.lyrik/state/runs/<run-id>/` in the
/// current working directory. The findings input is read from that
/// directory's `findings.json` (slice 5).
pub async fn report(format: &str, run: &str, output: &Path) -> Result<()> {
    if format != "sarif" {
        anyhow::bail!("only --format sarif is supported (got {format:?})");
    }
    let run_dir = resolve_run_dir(run)?;
    if !run_dir.exists() {
        anyhow::bail!(
            "run directory does not exist: {}",
            run_dir.display()
        );
    }

    let driver_version = env!("CARGO_PKG_VERSION");
    let skeleton = serde_json::json!({
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "lyrik",
                    "version": driver_version,
                    "informationUri": LYRIK_INFO_URI,
                    "rules": []
                }
            },
            "automationDetails": { "id": format!("lyrik/run/{run}") },
            "invocations": [{ "executionSuccessful": true }],
            "results": []
        }]
    });
    let body = serde_json::to_string_pretty(&skeleton)?;

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(output, body)
        .with_context(|| format!("write {}", output.display()))?;
    println!("wrote {} (skeleton; slice 5 fills in findings)", output.display());
    Ok(())
}

fn resolve_run_dir(run: &str) -> Result<PathBuf> {
    Ok(std::env::current_dir()?
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run))
}
