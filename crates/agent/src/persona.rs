//! Named persona bundling.
//!
//! A persona is the operator-facing handle that ties an
//! [`AgentConfig`] (provider + channels + identity record, stored in
//! `agents.db` via [`wirken_gateway::agent_config::AgentConfigStore`])
//! to an optional [`crate::preset::LoadedPreset`] (skill bundle,
//! stored as a directory tree under
//! `~/.wirken/presets/<name>/`).
//!
//! ## Why both
//!
//! Wirken already has the two underlying concepts as separate
//! operator surfaces:
//!
//! - `wirken agents <subcommand>` manages [`AgentConfig`] rows (the
//!   provider, model, channel allowlist, subagent ceilings).
//! - `wirken preset <subcommand>` manages preset directories (the
//!   skill bundle).
//!
//! An operator who wants both at once has to issue two commands and
//! remember the join. The persona view bundles them at lookup time:
//! one [`AgentConfig`] row may name a preset, the persona materialises
//! the pair, and the CLI / agent construction code consume the
//! resolved bundle.
//!
//! ## Single-write-path discipline
//!
//! Operators write to [`AgentConfig`] and presets via their existing
//! stores. The persona view is read-only and resolved at lookup time:
//! a renamed or deleted preset surfaces as
//! [`PersonaError::DanglingPresetReference`] when the agent
//! constructor (or `wirken persona show`) tries to materialise the
//! view. The view never mutates anything; the writable stores stay
//! authoritative.

use std::path::{Path, PathBuf};

use thiserror::Error;
use wirken_gateway::agent_config::AgentConfig;

use crate::preset::{LoadedPreset, PresetError, PresetLoader};

/// Read-only materialised bundle of an [`AgentConfig`] with its
/// optionally resolved preset. Constructed by [`Self::materialize`];
/// never written to directly by the CLI or runtime. The wrapped
/// values are owned (not borrowed) so callers can keep the view past
/// the stores' lifetimes.
#[derive(Debug)]
pub struct Persona {
    /// The underlying agent configuration row. Source of truth for
    /// provider, model, channels, subagent ceilings, etc.
    pub agent_config: AgentConfig,
    /// The resolved preset, when [`AgentConfig::preset`] names one
    /// that exists on disk. `None` when the config did not name a
    /// preset; the dangling-reference case surfaces as a typed error
    /// from [`Self::materialize`], not as `Some(empty)` and not as
    /// silent `None`.
    pub preset: Option<LoadedPreset>,
}

/// Failure modes for [`Persona::materialize`]. Each variant maps to
/// a distinct operator-side remediation: re-install the preset,
/// pick a different preset, or fix the preset directory contents.
#[derive(Debug, Error)]
pub enum PersonaError {
    /// [`AgentConfig::preset`] named a preset that is not installed
    /// at the expected path. The CLI surfaces this on `wirken
    /// persona show <name>`; agent construction errors here so a
    /// misconfigured persona does not silently degrade to "no
    /// skills". Operator fix: either install the named preset or
    /// edit the persona to point at a different one (or to clear
    /// the field).
    #[error(
        "persona '{persona_name}' references preset '{preset_name}' which is not installed at {preset_path:?}"
    )]
    DanglingPresetReference {
        persona_name: String,
        preset_name: String,
        preset_path: PathBuf,
    },
    /// The preset directory exists but loading it failed (malformed
    /// `preset.toml`, missing skill subdirectories, signature
    /// problems propagated by `SkillLoader`, etc.). Distinct from
    /// [`Self::DanglingPresetReference`] because the operator-side
    /// remediation is different: reinstall or repair the preset
    /// rather than redirect the persona to a new one.
    #[error("persona '{persona_name}' preset '{preset_name}' failed to load: {source}")]
    PresetLoadFailed {
        persona_name: String,
        preset_name: String,
        #[source]
        source: PresetError,
    },
}

impl Persona {
    /// Materialise a [`Persona`] from an [`AgentConfig`] plus the
    /// presets-directory root the operator's installation uses
    /// (typically `~/.wirken/presets/`). The lookup is by directory
    /// name: `presets_dir.join(&agent_config.preset)`.
    ///
    /// `None` preset on the underlying config short-circuits to a
    /// `Persona` with `preset: None` and no IO. A `Some(name)` that
    /// does not exist on disk surfaces as
    /// [`PersonaError::DanglingPresetReference`]; a `Some(name)` that
    /// exists but fails to load surfaces as
    /// [`PersonaError::PresetLoadFailed`]. The two cases drive
    /// different operator-side fixes; collapsing them into a single
    /// error would lose that signal.
    pub fn materialize(
        agent_config: AgentConfig,
        presets_dir: &Path,
    ) -> Result<Self, PersonaError> {
        let Some(preset_name) = agent_config.preset.clone() else {
            return Ok(Self {
                agent_config,
                preset: None,
            });
        };
        let preset_path = presets_dir.join(&preset_name);
        if !preset_path.exists() {
            return Err(PersonaError::DanglingPresetReference {
                persona_name: agent_config.id.clone(),
                preset_name,
                preset_path,
            });
        }
        let loaded = PresetLoader::load_dir(&preset_path).map_err(|source| {
            PersonaError::PresetLoadFailed {
                persona_name: agent_config.id.clone(),
                preset_name: preset_name.clone(),
                source,
            }
        })?;
        Ok(Self {
            agent_config,
            preset: Some(loaded),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Minimal AgentConfig with `preset = None`. Mirrors the
    /// pre-slice-1 shape every existing test in
    /// `wirken_gateway::agent_config` constructs.
    fn agent_config_without_preset(id: &str) -> AgentConfig {
        AgentConfig {
            id: id.to_string(),
            name: format!("{id} agent"),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            api_key_credential: "key".to_string(),
            channels: vec![],
            allowed_subagents: Default::default(),
            tools_enabled: None,
            preset: None,
            channel_egress: Default::default(),
        }
    }

    fn agent_config_with_preset(id: &str, preset_name: &str) -> AgentConfig {
        AgentConfig {
            preset: Some(preset_name.to_string()),
            ..agent_config_without_preset(id)
        }
    }

    /// Self-sign a skill bundle so `SkillLoader::load_dir` accepts
    /// it. Mirrors the `sign_for_test` helper in `preset.rs` tests:
    /// generate an ephemeral keypair, sign the bundle, discard the
    /// key. Without this the loader's signature gate rejects every
    /// unsigned skill and the test would have to set
    /// `WIRKEN_ALLOW_UNSIGNED_SKILLS` (a cross-test env var that
    /// races under parallel test execution).
    fn sign_skill_for_test(skill_dir: &Path) {
        let (secret_hex, _) = wirken_gateway::skill_registry::generate_signing_keypair();
        let bytes =
            wirken_gateway::skill_registry::hex_decode_public(&secret_hex).expect("hex decode");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let key = ed25519_dalek::SigningKey::from_bytes(&arr);
        wirken_gateway::skill_registry::sign_skill(skill_dir, &key).expect("sign test skill");
    }

    fn write_minimal_preset(presets_dir: &Path, name: &str, skill_dir_name: &str) {
        let preset_dir = presets_dir.join(name);
        let skills_dir = preset_dir.join("skills").join(skill_dir_name);
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            preset_dir.join("preset.toml"),
            format!(
                r#"[preset]
name = "{name}"
description = "test preset"
version = "0.1.0"
skills = ["{skill_dir_name}"]
"#
            ),
        )
        .unwrap();
        // Minimal SKILL.md. The frontmatter shape mirrors the one
        // SkillLoader accepts; an explicit-only skill keeps the
        // surface tight.
        fs::write(
            skills_dir.join("SKILL.md"),
            format!(
                "---\nname: {skill_dir_name}\ndescription: test skill\ndisable-model-invocation: true\npermissions: {{}}\n---\n"
            ),
        )
        .unwrap();
        sign_skill_for_test(&skills_dir);
    }

    #[test]
    fn materialize_with_no_preset_returns_view_with_preset_none() {
        let tmp = TempDir::new().unwrap();
        let persona =
            Persona::materialize(agent_config_without_preset("alice"), tmp.path()).unwrap();
        assert_eq!(persona.agent_config.id, "alice");
        assert!(persona.preset.is_none());
    }

    #[test]
    fn materialize_resolves_existing_preset() {
        let tmp = TempDir::new().unwrap();
        let presets_dir = tmp.path();
        write_minimal_preset(presets_dir, "researcher", "test-skill");

        let persona =
            Persona::materialize(agent_config_with_preset("alice", "researcher"), presets_dir)
                .unwrap();
        let preset = persona.preset.expect("preset resolved");
        assert_eq!(preset.metadata.name, "researcher");
        assert_eq!(preset.skills.len(), 1);
    }

    #[test]
    fn dangling_preset_reference_surfaces_as_typed_error() {
        let tmp = TempDir::new().unwrap();
        // No preset directory written. The AgentConfig names one
        // anyway, simulating a deleted preset directory after the
        // row was written.
        let err = Persona::materialize(agent_config_with_preset("alice", "ghost"), tmp.path())
            .unwrap_err();
        match err {
            PersonaError::DanglingPresetReference {
                persona_name,
                preset_name,
                ..
            } => {
                assert_eq!(persona_name, "alice");
                assert_eq!(preset_name, "ghost");
            }
            other => panic!("expected DanglingPresetReference, got {other:?}"),
        }
    }

    #[test]
    fn malformed_preset_surfaces_as_load_failed_not_dangling() {
        // The preset directory exists but the manifest is invalid:
        // missing `[preset]` table. Materialize must distinguish
        // this from the dangling case because the operator fix
        // differs (repair the manifest vs reinstall vs pick another
        // preset).
        let tmp = TempDir::new().unwrap();
        let preset_dir = tmp.path().join("broken");
        fs::create_dir_all(&preset_dir).unwrap();
        fs::write(preset_dir.join("preset.toml"), "not-valid-toml-at-all").unwrap();

        let err = Persona::materialize(agent_config_with_preset("alice", "broken"), tmp.path())
            .unwrap_err();
        assert!(
            matches!(err, PersonaError::PresetLoadFailed { .. }),
            "expected PresetLoadFailed, got {err:?}",
        );
    }

    #[test]
    fn agent_config_round_trips_preset_field_through_store() {
        // Regression on the schema-delta half of slice 1:
        // AgentConfigStore must round-trip the new column. Without
        // this test the agent_config_db_path migration could
        // silently swallow `preset` on get / list and the persona
        // view would always materialize with `preset: None`.
        let tmp = TempDir::new().unwrap();
        let store =
            wirken_gateway::agent_config::AgentConfigStore::open(&tmp.path().join("agents.db"))
                .unwrap();
        store
            .register(&agent_config_with_preset("alice", "researcher"))
            .unwrap();
        let got = store.get("alice").unwrap();
        assert_eq!(got.preset.as_deref(), Some("researcher"));

        store.register(&agent_config_without_preset("bob")).unwrap();
        let bob = store.get("bob").unwrap();
        assert!(bob.preset.is_none());
    }
}
