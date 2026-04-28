//! `wirken preset` subcommands.
//!
//! Scope A — installation only. List prints bundled preset names;
//! install copies a bundled preset to `~/.wirken/presets/<name>/` and
//! verifies it loads cleanly via `PresetLoader`.

use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;

/// `wirken preset list` — print the names of bundled presets.
pub async fn list() -> Result<()> {
    let names = wirken_agent::bundled_presets::bundled_preset_names();
    if names.is_empty() {
        println!("(no bundled presets)");
        return Ok(());
    }
    println!("Bundled presets:");
    for name in names {
        println!("  {name}");
    }
    Ok(())
}

/// `wirken preset install <name>` — write the bundled preset to
/// `<data_dir>/presets/<name>/` and verify it loads.
pub async fn install(name: &str) -> Result<()> {
    let data_dir = super::data_dir()?;
    let presets_root = data_dir.join("presets");
    std::fs::create_dir_all(&presets_root)
        .with_context(|| format!("create presets root at {}", presets_root.display()))?;
    let dest: PathBuf = presets_root.join(name);

    let count = wirken_agent::bundled_presets::install_bundled_preset(name, &dest)
        .map_err(|e| anyhow!("install preset '{name}': {e}"))?;

    let loaded = wirken_agent::preset::PresetLoader::load_dir(&dest)
        .map_err(|e| anyhow!("preset '{name}' wrote {count} files but failed to load: {e}"))?;

    println!("Installed preset '{name}' to {}", dest.display());
    println!("  files written: {count}");
    println!("  description:   {}", loaded.metadata.description);
    println!(
        "  skills:        {}",
        loaded
            .skills
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}
