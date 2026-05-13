//! `wirken persona` subcommands.
//!
//! A persona bundles an `AgentConfig` row with an optional `Preset`
//! reference. The bundle is materialised on demand via
//! `wirken_agent::persona::Persona::materialize`. This module is the
//! operator-facing CLI surface; the lower-level operations on
//! AgentConfig and Preset stay reachable through `wirken agents` and
//! `wirken preset`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use wirken_agent::persona::{Persona, PersonaError};
use wirken_gateway::agent_config::{AgentConfig, AgentConfigStore, SubagentCeiling};
use wirken_gateway::permissions::PermissionTier;

use super::config;

/// `wirken persona create <name>`: register a new persona row.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    name: &str,
    preset: Option<&str>,
    provider: &str,
    model: &str,
    base_url: &str,
    credential: &str,
    channels: Vec<String>,
    allow_subagent: Vec<String>,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("persona name must not be empty"));
    }

    let cfg = config();
    cfg.ensure_dirs()?;

    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    if store.get(name).is_ok() {
        return Err(anyhow!(
            "persona '{name}' already exists; use `wirken persona edit {name}` to modify it"
        ));
    }

    // Warn but allow when the named preset is not installed yet. The
    // persona view surfaces the dangling reference at lookup; the
    // operator may install the preset later.
    if let Some(preset_name) = preset {
        let preset_path = cfg.data_dir.join("presets").join(preset_name);
        if !preset_path.exists() {
            eprintln!(
                "Warning: preset '{preset_name}' is not installed at {}; persona will hold a dangling reference until the preset is installed.",
                preset_path.display()
            );
        }
    }

    let mut allowed_subagents = BTreeMap::new();
    for child in &allow_subagent {
        allowed_subagents.insert(
            child.clone(),
            SubagentCeiling {
                tool_allowlist: Vec::new(),
                max_permission_tier: PermissionTier::Tier1,
                max_rounds: 5,
                max_runtime_secs: 30,
            },
        );
    }

    let agent_config = AgentConfig {
        id: name.to_string(),
        name: name.to_string(),
        provider: provider.to_string(),
        model: model.to_string(),
        base_url: base_url.to_string(),
        api_key_credential: credential.to_string(),
        channels: channels.clone(),
        allowed_subagents,
        tools_enabled: None,
        preset: preset.map(String::from),
    };

    store
        .register(&agent_config)
        .with_context(|| format!("register persona '{name}'"))?;

    std::fs::create_dir_all(cfg.agent_workspace(name))?;
    std::fs::create_dir_all(cfg.agent_skills_dir(name))?;

    println!("  Persona '{name}' created.");
    if let Some(p) = preset {
        println!("    preset:    {p}");
    }
    println!("    provider:  {provider}/{model}");
    if channels.is_empty() {
        println!("    channels:  (none)");
    } else {
        println!("    channels:  {}", channels.join(", "));
    }
    if !allow_subagent.is_empty() {
        println!("    subagents: {}", allow_subagent.join(", "));
    }
    Ok(())
}

/// `wirken persona list`: table of registered personas.
pub async fn list() -> Result<()> {
    let cfg = config();
    let path = cfg.agent_config_db_path();
    if !path.exists() {
        println!("  No personas configured. Run `wirken persona create <name>`.");
        return Ok(());
    }

    let store = AgentConfigStore::open(&path).context("Failed to open agent config store")?;
    let agents = store.list().context("Failed to list personas")?;

    if agents.is_empty() {
        println!("  No personas configured.");
        return Ok(());
    }

    println!(
        "  {:16}  {:16}  {:24}  CHANNELS",
        "NAME", "PRESET", "PROVIDER"
    );
    println!(
        "  {}  {}  {}  {}",
        "-".repeat(16),
        "-".repeat(16),
        "-".repeat(24),
        "-".repeat(30)
    );

    for agent in &agents {
        let preset_display = agent.preset.as_deref().unwrap_or("<no preset>");
        let channels = if agent.channels.is_empty() {
            "(none)".to_string()
        } else if agent.channels.len() > 4 {
            format!("{} channels", agent.channels.len())
        } else {
            agent.channels.join(", ")
        };
        println!(
            "  {:16}  {:16}  {:24}  {}",
            agent.id,
            preset_display,
            format!("{}/{}", agent.provider, agent.model),
            channels,
        );
    }
    Ok(())
}

/// `wirken persona show <name>`: pretty-print the resolved view.
pub async fn show(name: &str) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let agent_config = store
        .get(name)
        .with_context(|| format!("persona '{name}' not found"))?;

    let presets_root = cfg.data_dir.join("presets");

    let preset_state = match Persona::materialize(agent_config.clone(), &presets_root) {
        Ok(persona) => match persona.preset {
            Some(loaded) => PresetState::Resolved {
                name: loaded.metadata.name,
                skills: loaded.skills.into_iter().map(|s| s.name).collect(),
            },
            None => PresetState::None,
        },
        Err(PersonaError::DanglingPresetReference {
            preset_name,
            preset_path,
            ..
        }) => PresetState::Dangling {
            name: preset_name,
            path: preset_path,
        },
        Err(PersonaError::PresetLoadFailed {
            preset_name,
            source,
            ..
        }) => PresetState::LoadFailed {
            name: preset_name,
            reason: source.to_string(),
        },
    };

    let (stdout, stderr) = render_persona_show(name, &agent_config, &preset_state);
    print!("{stdout}");
    if let Some(warning) = stderr {
        eprintln!("{warning}");
    }
    Ok(())
}

/// `wirken persona edit <name>`: read-modify-write a single row.
#[allow(clippy::too_many_arguments)]
pub async fn edit(
    name: &str,
    preset: Option<&str>,
    clear_preset: bool,
    provider: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
    credential: Option<&str>,
    channels: Vec<String>,
    display_name: Option<&str>,
) -> Result<()> {
    if preset.is_none()
        && !clear_preset
        && provider.is_none()
        && model.is_none()
        && base_url.is_none()
        && credential.is_none()
        && channels.is_empty()
        && display_name.is_none()
    {
        return Err(anyhow!(
            "`wirken persona edit` requires at least one field flag (--preset, --clear-preset, --provider, --model, --base-url, --credential, --channel, --display-name)"
        ));
    }

    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let mut agent_config = store
        .get(name)
        .with_context(|| format!("persona '{name}' not found"))?;

    if clear_preset {
        agent_config.preset = None;
    } else if let Some(p) = preset {
        let preset_path = cfg.data_dir.join("presets").join(p);
        if !preset_path.exists() {
            eprintln!(
                "Warning: preset '{p}' is not installed at {}; persona will hold a dangling reference.",
                preset_path.display()
            );
        }
        agent_config.preset = Some(p.to_string());
    }

    if let Some(v) = provider {
        agent_config.provider = v.to_string();
    }
    if let Some(v) = model {
        agent_config.model = v.to_string();
    }
    if let Some(v) = base_url {
        agent_config.base_url = v.to_string();
    }
    if let Some(v) = credential {
        agent_config.api_key_credential = v.to_string();
    }
    if !channels.is_empty() {
        agent_config.channels = channels;
    }
    if let Some(v) = display_name {
        agent_config.name = v.to_string();
    }

    store
        .update(&agent_config)
        .with_context(|| format!("update persona '{name}'"))?;

    println!("  Persona '{name}' updated.");
    Ok(())
}

/// `wirken persona delete <name>`: drop the row from the store.
pub async fn delete(name: &str) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    store
        .remove(name)
        .with_context(|| format!("persona '{name}' not found"))?;

    println!("  Persona '{name}' deleted.");
    Ok(())
}

/// Resolved-or-not state for the preset half of the persona view.
/// Constructed once in `show()` and consumed by the formatter so the
/// formatter stays pure and snapshot-friendly.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PresetState {
    /// The persona's AgentConfig.preset was `None`.
    None,
    /// The named preset resolved cleanly. `name` is the manifest name
    /// (not the AgentConfig.preset string, which is a directory name;
    /// they typically match but we use the manifest name for display).
    Resolved { name: String, skills: Vec<String> },
    /// The AgentConfig.preset pointed at a directory that does not
    /// exist. `path` is what we tried so the warning is actionable.
    Dangling { name: String, path: PathBuf },
    /// The preset directory exists but PresetLoader rejected it
    /// (malformed manifest, signature failure, missing skill body,
    /// etc.). `reason` is the underlying error's display form.
    LoadFailed { name: String, reason: String },
}

/// Pure formatter for `wirken persona show`. Returns the stdout body
/// and an optional stderr warning. Separated from `show()` so the
/// output format is exercised by unit tests without touching the
/// global config or filesystem.
pub(crate) fn render_persona_show(
    name: &str,
    agent_config: &AgentConfig,
    preset_state: &PresetState,
) -> (String, Option<String>) {
    use std::fmt::Write;

    let mut out = String::new();
    let mut warning: Option<String> = None;

    let _ = writeln!(out, "Persona: {name}");
    let _ = writeln!(out, "  Identity:");
    let _ = writeln!(out, "    id:           {}", agent_config.id);
    let _ = writeln!(out, "    name:         {}", agent_config.name);
    let _ = writeln!(out, "  Provider:");
    let _ = writeln!(out, "    provider:     {}", agent_config.provider);
    let _ = writeln!(out, "    model:        {}", agent_config.model);
    let _ = writeln!(out, "    base_url:     {}", agent_config.base_url);
    let credential = if agent_config.api_key_credential.is_empty() {
        "(none)"
    } else {
        agent_config.api_key_credential.as_str()
    };
    let _ = writeln!(out, "    credential:   {credential}");

    let channels_display = if agent_config.channels.is_empty() {
        "(none)".to_string()
    } else {
        agent_config.channels.join(", ")
    };
    let _ = writeln!(out, "  Channels:       {channels_display}");

    match preset_state {
        PresetState::None => {
            let _ = writeln!(out, "  Preset:         <no preset>");
            let _ = writeln!(out, "  Skills:         <no preset>");
        }
        PresetState::Resolved {
            name: preset_name,
            skills,
        } => {
            let _ = writeln!(out, "  Preset:         {preset_name}");
            let skills_display = if skills.is_empty() {
                "(none)".to_string()
            } else {
                skills.join(", ")
            };
            let _ = writeln!(out, "  Skills:         {skills_display}");
        }
        PresetState::Dangling {
            name: preset_name,
            path,
        } => {
            let _ = writeln!(out, "  Preset:         {preset_name} (not installed)");
            let _ = writeln!(out, "  Skills:         <preset '{preset_name}' not found>");
            warning = Some(format!(
                "Warning: persona '{name}' references preset '{preset_name}' which is not installed at {}",
                path.display()
            ));
        }
        PresetState::LoadFailed {
            name: preset_name,
            reason,
        } => {
            let _ = writeln!(out, "  Preset:         {preset_name} (load failed)");
            let _ = writeln!(
                out,
                "  Skills:         <preset '{preset_name}' failed to load>"
            );
            warning = Some(format!(
                "Warning: persona '{name}' preset '{preset_name}' failed to load: {reason}"
            ));
        }
    }

    if agent_config.allowed_subagents.is_empty() {
        let _ = writeln!(out, "  Subagents:      (none)");
    } else {
        let names: Vec<&str> = agent_config
            .allowed_subagents
            .keys()
            .map(String::as_str)
            .collect();
        let _ = writeln!(out, "  Subagents:      {}", names.join(", "));
    }

    (out, warning)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> AgentConfig {
        AgentConfig {
            id: "alice".into(),
            name: "Alice".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com/v1".into(),
            api_key_credential: "alice-key".into(),
            channels: vec!["slack".into(), "teams".into()],
            allowed_subagents: Default::default(),
            tools_enabled: None,
            preset: None,
        }
    }

    #[test]
    fn render_show_with_no_preset() {
        let cfg = sample_config();
        let (out, warning) = render_persona_show("alice", &cfg, &PresetState::None);
        assert!(out.contains("Persona: alice"));
        assert!(out.contains("    id:           alice"));
        assert!(out.contains("Preset:         <no preset>"));
        assert!(out.contains("Skills:         <no preset>"));
        assert!(warning.is_none());
    }

    #[test]
    fn render_show_with_resolved_preset_lists_skills() {
        let mut cfg = sample_config();
        cfg.preset = Some("researcher".into());
        let state = PresetState::Resolved {
            name: "researcher".into(),
            skills: vec!["read_file".into(), "web_search".into()],
        };
        let (out, warning) = render_persona_show("alice", &cfg, &state);
        assert!(out.contains("Preset:         researcher"));
        assert!(out.contains("Skills:         read_file, web_search"));
        assert!(warning.is_none());
    }

    #[test]
    fn render_show_surfaces_dangling_reference_explicitly() {
        let mut cfg = sample_config();
        cfg.preset = Some("ghost".into());
        let state = PresetState::Dangling {
            name: "ghost".into(),
            path: PathBuf::from("/data/presets/ghost"),
        };
        let (out, warning) = render_persona_show("alice", &cfg, &state);
        assert!(out.contains("Preset:         ghost (not installed)"));
        assert!(out.contains("Skills:         <preset 'ghost' not found>"));
        let w = warning.expect("expected stderr warning on dangling preset");
        assert!(w.contains("ghost"));
        assert!(w.contains("not installed at /data/presets/ghost"));
        assert!(w.contains("persona 'alice'"));
    }

    #[test]
    fn render_show_surfaces_load_failure_distinctly_from_dangling() {
        let mut cfg = sample_config();
        cfg.preset = Some("broken".into());
        let state = PresetState::LoadFailed {
            name: "broken".into(),
            reason: "expected `[preset]` table".into(),
        };
        let (out, warning) = render_persona_show("alice", &cfg, &state);
        assert!(out.contains("Preset:         broken (load failed)"));
        assert!(out.contains("Skills:         <preset 'broken' failed to load>"));
        let w = warning.expect("expected stderr warning on load failure");
        assert!(w.contains("failed to load"));
        assert!(w.contains("expected `[preset]` table"));
    }

    #[test]
    fn render_show_lists_subagents_when_present() {
        let mut cfg = sample_config();
        cfg.allowed_subagents.insert(
            "researcher".into(),
            SubagentCeiling {
                tool_allowlist: vec![],
                max_permission_tier: PermissionTier::Tier1,
                max_rounds: 5,
                max_runtime_secs: 30,
            },
        );
        cfg.allowed_subagents.insert(
            "writer".into(),
            SubagentCeiling {
                tool_allowlist: vec![],
                max_permission_tier: PermissionTier::Tier1,
                max_rounds: 5,
                max_runtime_secs: 30,
            },
        );
        let (out, _) = render_persona_show("alice", &cfg, &PresetState::None);
        assert!(out.contains("Subagents:      researcher, writer"));
    }

    #[test]
    fn render_show_handles_empty_credential_as_none() {
        let mut cfg = sample_config();
        cfg.api_key_credential = String::new();
        let (out, _) = render_persona_show("alice", &cfg, &PresetState::None);
        assert!(out.contains("credential:   (none)"));
    }
}
