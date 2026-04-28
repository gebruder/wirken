//! `wirken preset` subcommands.
//!
//! Scope A: list / install. Scope B: schedule / unschedule, which wire
//! a cron entry that calls `wirken zirkel run` (or the per-preset
//! orchestrator entry) on a daily tick.
//!
//! Cron manipulation goes through the OS's `crontab` binary. Wirken-
//! managed entries are bracketed with marker comments so unschedule
//! can remove exactly the entry it added without disturbing user-
//! authored cron lines:
//!
//! ```text
//! # >>> wirken preset:zirkel
//! 0 6 * * * /path/to/wirken zirkel run
//! # <<< wirken preset:zirkel
//! ```

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

/// `wirken preset schedule <name>` — add a cron entry that runs the
/// preset's orchestrator daily at 06:00 in the user's local timezone.
pub async fn schedule(name: &str) -> Result<()> {
    // Verify the preset is installed before scheduling so we don't
    // wire a cron entry pointing at a missing preset.
    let data_dir = super::data_dir()?;
    let preset_dir = data_dir.join("presets").join(name);
    if !preset_dir.join("preset.toml").exists() {
        return Err(anyhow!(
            "preset '{name}' is not installed at {}; run `wirken preset install {name}` first",
            preset_dir.display(),
        ));
    }

    let wirken_path =
        std::env::current_exe().with_context(|| "resolve current wirken binary path")?;
    let wirken_path = wirken_path
        .to_str()
        .ok_or_else(|| anyhow!("wirken binary path is not valid UTF-8"))?
        .to_string();

    let entry_command = match name {
        "zirkel" => format!("{wirken_path} zirkel run"),
        other => {
            return Err(anyhow!(
                "preset '{other}' has no orchestrator entry yet — only 'zirkel' is supported in Scope B"
            ));
        }
    };

    let current = read_crontab()?;
    let updated = with_managed_entry(&current, name, "0 6 * * *", &entry_command);
    write_crontab(&updated)?;

    println!("Scheduled preset '{name}': daily at 06:00 local time.");
    println!("  command: {entry_command}");
    Ok(())
}

/// `wirken preset unschedule <name>` — remove the wirken-managed cron
/// entry for `<name>`. Leaves user-authored cron lines untouched.
pub async fn unschedule(name: &str) -> Result<()> {
    let current = read_crontab()?;
    let (updated, removed) = without_managed_entry(&current, name);
    if !removed {
        println!("No wirken-managed cron entry found for preset '{name}'.");
        return Ok(());
    }
    write_crontab(&updated)?;
    println!("Removed wirken-managed cron entry for preset '{name}'.");
    Ok(())
}

// --- crontab helpers -------------------------------------------------------

fn marker_open(preset: &str) -> String {
    format!("# >>> wirken preset:{preset}")
}

fn marker_close(preset: &str) -> String {
    format!("# <<< wirken preset:{preset}")
}

/// Insert (or replace) the wirken-managed cron block for `preset`.
/// The block is bracketed with marker comments so `unschedule` can
/// drop exactly the lines it added.
pub(crate) fn with_managed_entry(
    current: &str,
    preset: &str,
    schedule: &str,
    command: &str,
) -> String {
    let (without_existing, _) = without_managed_entry(current, preset);
    let mut out = without_existing.trim_end().to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&marker_open(preset));
    out.push('\n');
    out.push_str(schedule);
    out.push(' ');
    out.push_str(command);
    out.push('\n');
    out.push_str(&marker_close(preset));
    out.push('\n');
    out
}

/// Remove the wirken-managed cron block for `preset` if present.
/// Returns the new crontab and a flag indicating whether anything was
/// removed. Lines outside the marker block are preserved verbatim.
pub(crate) fn without_managed_entry(current: &str, preset: &str) -> (String, bool) {
    let open = marker_open(preset);
    let close = marker_close(preset);
    let mut out_lines: Vec<&str> = Vec::new();
    let mut inside = false;
    let mut removed = false;
    for line in current.lines() {
        if line.trim() == open {
            inside = true;
            removed = true;
            continue;
        }
        if inside && line.trim() == close {
            inside = false;
            continue;
        }
        if !inside {
            out_lines.push(line);
        }
    }
    let mut joined = out_lines.join("\n");
    if !joined.is_empty() && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, removed)
}

fn read_crontab() -> Result<String> {
    let output = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .with_context(|| "invoke `crontab -l` (is the crontab binary on PATH?)")?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    // `crontab -l` exits non-zero when no crontab is set for the user.
    // The stderr typically reads "no crontab for <user>"; treat as empty.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("no crontab") {
        return Ok(String::new());
    }
    Err(anyhow!(
        "crontab -l failed (status {:?}): {}",
        output.status,
        stderr
    ))
}

fn write_crontab(contents: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| "spawn `crontab -`")?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("crontab stdin not available"))?
        .write_all(contents.as_bytes())
        .with_context(|| "write to crontab stdin")?;
    let status = child.wait().with_context(|| "wait for crontab process")?;
    if !status.success() {
        return Err(anyhow!("crontab - exited with status {status:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_managed_entry_appends_to_empty() {
        let result = with_managed_entry("", "zirkel", "0 6 * * *", "/bin/wirken zirkel run");
        assert!(result.contains("# >>> wirken preset:zirkel"));
        assert!(result.contains("0 6 * * * /bin/wirken zirkel run"));
        assert!(result.contains("# <<< wirken preset:zirkel"));
    }

    #[test]
    fn with_managed_entry_replaces_existing_block() {
        let initial = "# >>> wirken preset:zirkel\n0 5 * * * /old/path zirkel run\n# <<< wirken preset:zirkel\n";
        let updated = with_managed_entry(initial, "zirkel", "0 6 * * *", "/new/path zirkel run");
        assert!(!updated.contains("/old/path"));
        assert!(updated.contains("/new/path"));
        // Block should appear exactly once.
        assert_eq!(updated.matches("# >>> wirken preset:zirkel").count(), 1);
    }

    #[test]
    fn with_managed_entry_preserves_user_lines() {
        let initial = "0 0 * * * /usr/bin/some-other-job\n";
        let updated = with_managed_entry(initial, "zirkel", "0 6 * * *", "/bin/wirken zirkel run");
        assert!(updated.contains("/usr/bin/some-other-job"));
        assert!(updated.contains("# >>> wirken preset:zirkel"));
    }

    #[test]
    fn without_managed_entry_drops_block() {
        let initial = "# >>> wirken preset:zirkel\n0 6 * * * /bin/wirken zirkel run\n# <<< wirken preset:zirkel\n";
        let (out, removed) = without_managed_entry(initial, "zirkel");
        assert!(removed);
        assert!(!out.contains("zirkel"));
    }

    #[test]
    fn without_managed_entry_preserves_user_lines() {
        let initial = concat!(
            "0 0 * * * /usr/bin/backup\n",
            "# >>> wirken preset:zirkel\n",
            "0 6 * * * /bin/wirken zirkel run\n",
            "# <<< wirken preset:zirkel\n",
            "30 1 * * * /usr/bin/cleanup\n",
        );
        let (out, removed) = without_managed_entry(initial, "zirkel");
        assert!(removed);
        assert!(out.contains("/usr/bin/backup"));
        assert!(out.contains("/usr/bin/cleanup"));
        assert!(!out.contains("wirken preset:zirkel"));
    }

    #[test]
    fn without_managed_entry_returns_false_when_no_block_present() {
        let initial = "0 0 * * * /usr/bin/backup\n";
        let (out, removed) = without_managed_entry(initial, "zirkel");
        assert!(!removed);
        assert_eq!(out.trim_end(), "0 0 * * * /usr/bin/backup");
    }

    #[test]
    fn without_managed_entry_only_drops_block_for_named_preset() {
        let initial = concat!(
            "# >>> wirken preset:zirkel\n",
            "0 6 * * * /bin/wirken zirkel run\n",
            "# <<< wirken preset:zirkel\n",
            "# >>> wirken preset:other\n",
            "0 7 * * * /bin/wirken other run\n",
            "# <<< wirken preset:other\n",
        );
        let (out, removed) = without_managed_entry(initial, "zirkel");
        assert!(removed);
        assert!(!out.contains("preset:zirkel"));
        assert!(out.contains("preset:other"));
        assert!(out.contains("/bin/wirken other run"));
    }
}
