//! Preset bundles — curated multi-skill packages with a coherent posture.
//!
//! A preset is a directory containing a `preset.toml` declaration plus a
//! `skills/<name>/SKILL.md` per included skill. Optional siblings:
//! `sources.toml`, `prompts/`, and (in later scopes) per-preset config
//! that the runtime consumes.
//!
//! ```text
//! preset/<name>/
//!   preset.toml                    # name, description, version, skills[]
//!   skills/
//!     <skill_a>/SKILL.md
//!     <skill_b>/SKILL.md
//!   sources.toml                   # optional, preset-specific
//!   prompts/                       # optional, preset-specific
//! ```
//!
//! [`PresetLoader::load_dir`] reads the declaration, verifies the
//! referenced skill subdirectories exist, loads each through
//! [`crate::skill::SkillLoader`], and returns a [`LoadedPreset`]. The
//! caller (typically [`crate::Agent::attach_skills`]) merges the
//! profiles via #76's union semantics; coherence checks fire there.
//!
//! Loading the preset does *not* configure the runtime — fetcher,
//! scheduler, and channel-push wiring are the next scope. This module
//! is the keystone gap-G fix from `docs/zirkel/DESIGN.md` (Scope A):
//! the directory layout, the `preset.toml` schema, and the smoke test
//! that the bundle is internally coherent. Later scopes wire the
//! runtime pieces.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::error::AgentError;
use crate::skill::{Skill, SkillLoader};

/// On-disk shape of `preset.toml`. Only the `[preset]` table is
/// required at this scope; later scopes may add `[channel]`,
/// `[scheduler]`, `[storage]` etc. as the runtime pieces land.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetManifest {
    pub preset: PresetMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetMetadata {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    /// Names of skill subdirectories under `skills/`. Each must exist
    /// with a `SKILL.md`. Order is irrelevant — the agent computes the
    /// effective profile as a union and skill-name uniqueness is
    /// enforced at attach time.
    pub skills: Vec<String>,
}

/// What [`PresetLoader::load_dir`] returns: the manifest plus the
/// loaded skills. The caller decides what to do with them — typically
/// `agent.attach_skills(loaded.skills, vec![])`.
#[derive(Debug)]
pub struct LoadedPreset {
    pub metadata: PresetMetadata,
    pub skills: Vec<Skill>,
}

#[derive(Debug, Error)]
pub enum PresetError {
    #[error("preset.toml not found at {0}")]
    ManifestMissing(PathBuf),
    #[error("preset.toml at {0} could not be read: {1}")]
    ManifestUnreadable(PathBuf, std::io::Error),
    #[error("preset.toml at {0} failed to parse: {1}")]
    ManifestParse(PathBuf, String),
    #[error("preset declares skill '{skill}' but no SKILL.md exists at {expected}")]
    SkillMissing { skill: String, expected: PathBuf },
    #[error("preset declares no skills — at least one required")]
    EmptySkillList,
    #[error("preset name in manifest is empty")]
    EmptyName,
    #[error("preset declares duplicate skill name '{0}'")]
    DuplicateSkill(String),
}

pub struct PresetLoader;

impl PresetLoader {
    /// Read a preset directory: parse the manifest, verify the
    /// declared skill subdirectories exist and load each. Returns
    /// `LoadedPreset` whose `skills` are ready to hand to
    /// `Agent::attach_skills`.
    ///
    /// This loader does not enforce any cross-skill coherence
    /// (permissions merge, name uniqueness, reachability of explicit-
    /// only skills) — those checks fire in `attach_skills` per #76 and
    /// #79, and are the same regardless of whether the skills came
    /// from a preset or were attached individually.
    pub fn load_dir(preset_dir: &Path) -> Result<LoadedPreset, PresetError> {
        let manifest_path = preset_dir.join("preset.toml");
        if !manifest_path.exists() {
            return Err(PresetError::ManifestMissing(manifest_path));
        }
        let raw = std::fs::read_to_string(&manifest_path)
            .map_err(|e| PresetError::ManifestUnreadable(manifest_path.clone(), e))?;
        let manifest: PresetManifest = toml::from_str(&raw)
            .map_err(|e| PresetError::ManifestParse(manifest_path.clone(), e.to_string()))?;

        if manifest.preset.name.trim().is_empty() {
            return Err(PresetError::EmptyName);
        }
        if manifest.preset.skills.is_empty() {
            return Err(PresetError::EmptySkillList);
        }
        // Catch in-manifest duplicates early — `attach_skills` will
        // also reject them, but a preset-author bug deserves a clearer
        // pointer at the manifest line.
        let mut seen = std::collections::BTreeSet::new();
        for s in &manifest.preset.skills {
            if !seen.insert(s.clone()) {
                return Err(PresetError::DuplicateSkill(s.clone()));
            }
        }

        let skills_root = preset_dir.join("skills");
        let mut skills = Vec::with_capacity(manifest.preset.skills.len());
        for declared in &manifest.preset.skills {
            let skill_dir = skills_root.join(declared);
            let skill_md = skill_dir.join("SKILL.md");
            if !skill_md.exists() {
                return Err(PresetError::SkillMissing {
                    skill: declared.clone(),
                    expected: skill_md,
                });
            }
            let skill = SkillLoader::load_file(&skill_md).map_err(|e| {
                // Surface the load error with preset context but keep
                // the original variant family.
                match e {
                    AgentError::SkillLoad(msg) => PresetError::ManifestParse(
                        skill_md.clone(),
                        format!("skill '{declared}' failed to load: {msg}"),
                    ),
                    other => PresetError::ManifestParse(
                        skill_md.clone(),
                        format!("skill '{declared}' failed to load: {other}"),
                    ),
                }
            })?;
            skills.push(skill);
        }

        Ok(LoadedPreset {
            metadata: manifest.preset,
            skills,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_skill_md(dir: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let frontmatter = format!(
            "---\n\
             name: {name}\n\
             description: test skill {name}\n\
             disable-model-invocation: false\n\
             permissions: {{}}\n\
             ---\n\n{body}\n",
        );
        std::fs::write(dir.join("SKILL.md"), frontmatter).unwrap();
    }

    #[test]
    fn loads_a_minimal_preset() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = "test"
description = "test preset"
version = "0.0.1"
skills = ["alpha", "beta"]
"#,
        )
        .unwrap();
        write_skill_md(&root.join("skills/alpha"), "alpha", "alpha body");
        write_skill_md(&root.join("skills/beta"), "beta", "beta body");

        let loaded = PresetLoader::load_dir(root).unwrap();
        assert_eq!(loaded.metadata.name, "test");
        assert_eq!(loaded.metadata.skills, vec!["alpha", "beta"]);
        assert_eq!(loaded.skills.len(), 2);
        assert_eq!(loaded.skills[0].name, "alpha");
        assert_eq!(loaded.skills[1].name, "beta");
    }

    #[test]
    fn missing_manifest_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = PresetLoader::load_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, PresetError::ManifestMissing(_)));
    }

    #[test]
    fn missing_skill_subdir_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = "test"
skills = ["only_declared"]
"#,
        )
        .unwrap();
        // No skills/only_declared/SKILL.md — should error.
        let err = PresetLoader::load_dir(root).unwrap_err();
        assert!(matches!(err, PresetError::SkillMissing { .. }));
    }

    #[test]
    fn empty_skill_list_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = "test"
skills = []
"#,
        )
        .unwrap();
        let err = PresetLoader::load_dir(root).unwrap_err();
        assert!(matches!(err, PresetError::EmptySkillList));
    }

    #[test]
    fn duplicate_skill_in_manifest_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = "test"
skills = ["alpha", "alpha"]
"#,
        )
        .unwrap();
        write_skill_md(&root.join("skills/alpha"), "alpha", "alpha");
        let err = PresetLoader::load_dir(root).unwrap_err();
        assert!(matches!(err, PresetError::DuplicateSkill(_)));
    }

    #[test]
    fn empty_name_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = ""
skills = ["alpha"]
"#,
        )
        .unwrap();
        write_skill_md(&root.join("skills/alpha"), "alpha", "alpha");
        let err = PresetLoader::load_dir(root).unwrap_err();
        assert!(matches!(err, PresetError::EmptyName));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("preset.toml"),
            r#"
[preset]
name = "test"
skills = ["alpha"]

[unknown]
foo = "bar"
"#,
        )
        .unwrap();
        write_skill_md(&root.join("skills/alpha"), "alpha", "alpha");
        let err = PresetLoader::load_dir(root).unwrap_err();
        assert!(matches!(err, PresetError::ManifestParse(_, _)));
    }
}
