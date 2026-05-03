//! `wirken lyrik report` subcommand.
//!
//! Reads `.lyrik/state/runs/<run-id>/findings.json` and emits SARIF
//! 2.1.0 via [`super::lyrik_sarif::build_sarif`].

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Emit a Lyrik report in the requested format.
///
/// `run` is the run-id under `.lyrik/state/runs/<run-id>/` in the
/// current working directory. The findings input is read from that
/// directory's `findings.json`.
pub async fn report(format: &str, run: &str, output: &Path) -> Result<()> {
    if format != "sarif" {
        anyhow::bail!("only --format sarif is supported (got {format:?})");
    }
    let run_dir = resolve_run_dir(run)?;
    if !run_dir.exists() {
        anyhow::bail!("run directory does not exist: {}", run_dir.display());
    }
    let findings_path = run_dir.join("findings.json");
    if !findings_path.exists() {
        anyhow::bail!(
            "findings.json missing under {} (the run did not reach the report stage)",
            run_dir.display()
        );
    }

    let driver_version = env!("CARGO_PKG_VERSION");
    let sarif = super::lyrik_sarif::build_sarif(&findings_path, driver_version)?;
    let body = serde_json::to_string_pretty(&sarif)?;

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(output, body).with_context(|| format!("write {}", output.display()))?;
    println!("wrote {}", output.display());
    Ok(())
}

fn resolve_run_dir(run: &str) -> Result<PathBuf> {
    Ok(std::env::current_dir()?
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run))
}
