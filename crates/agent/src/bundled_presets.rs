//! Bundled presets shipped with Wirken.
//!
//! Same shape as [`crate::bundled_skills`] but for multi-file preset
//! bundles. The CLI's `wirken preset install <name>` writes these to
//! `~/.wirken/presets/<name>/`; from there the user (or a follow-up
//! scope's runtime) loads them via [`crate::preset::PresetLoader`].
//!
//! Adding a new bundled preset means: (1) commit the preset directory
//! under `preset/<name>/`, (2) add a `BundledPreset` entry below with
//! one `(relative_path, include_str!)` pair per file in the bundle.

use std::io;
use std::path::Path;

struct BundledPreset {
    name: &'static str,
    files: &'static [(&'static str, &'static str)],
}

const PRESETS: &[BundledPreset] = &[BundledPreset {
    name: "zirkel",
    files: &[
        (
            "preset.toml",
            include_str!("../../../preset/zirkel/preset.toml"),
        ),
        (
            "sources.toml",
            include_str!("../../../preset/zirkel/sources.toml"),
        ),
        (
            "skills/aggregator/SKILL.md",
            include_str!("../../../preset/zirkel/skills/aggregator/SKILL.md"),
        ),
        (
            "skills/librarian/SKILL.md",
            include_str!("../../../preset/zirkel/skills/librarian/SKILL.md"),
        ),
    ],
}];

/// Write a bundled preset's files to `dest_dir`. The directory is
/// created if missing; existing files are overwritten so an update of
/// the wirken binary refreshes the on-disk preset on next install.
/// Returns the count of files written.
///
/// Each skill directory the preset ships (any `SKILL.md` path under
/// `skills/<name>/`) is self-signed with a one-shot keypair after
/// the SKILL.md is written. The signing key is discarded after the
/// signature file is on disk. Matches the bundled-skill install
/// behaviour: the loader's signature gate accepts the bundle on
/// first load without operator setup, and any post-install edit to
/// a SKILL.md without re-signing is rejected.
pub fn install_bundled_preset(name: &str, dest_dir: &Path) -> io::Result<usize> {
    let preset = PRESETS.iter().find(|p| p.name == name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no bundled preset named '{name}'"),
        )
    })?;
    let mut count = 0;
    let mut skill_dirs: Vec<std::path::PathBuf> = Vec::new();
    for (rel_path, content) in preset.files {
        let path = dest_dir.join(rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        if path.file_name().and_then(|n| n.to_str()) == Some("SKILL.md")
            && let Some(parent) = path.parent()
        {
            skill_dirs.push(parent.to_path_buf());
        }
        count += 1;
    }
    for dir in skill_dirs {
        let (secret_hex, _) = wirken_gateway::skill_registry::generate_signing_keypair();
        let bytes = wirken_gateway::skill_registry::hex_decode_public(&secret_hex)
            .map_err(io::Error::other)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let key = ed25519_dalek::SigningKey::from_bytes(&arr);
        wirken_gateway::skill_registry::sign_skill(&dir, &key).map_err(io::Error::other)?;
    }
    Ok(count)
}

/// Names of every bundled preset.
pub fn bundled_preset_names() -> Vec<&'static str> {
    PRESETS.iter().map(|p| p.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zirkel_is_bundled() {
        let names = bundled_preset_names();
        assert!(names.contains(&"zirkel"), "zirkel preset should be bundled");
    }

    #[test]
    fn install_zirkel_writes_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("zirkel");
        let count = install_bundled_preset("zirkel", &dest).unwrap();
        assert_eq!(count, 4, "zirkel bundle should write 4 files");
        assert!(dest.join("preset.toml").exists());
        assert!(dest.join("sources.toml").exists());
        assert!(dest.join("skills/aggregator/SKILL.md").exists());
        assert!(dest.join("skills/librarian/SKILL.md").exists());
    }

    #[test]
    fn install_unknown_preset_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let err = install_bundled_preset("does-not-exist", tmp.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// The keystone integration test: install the bundled Zirkel preset
    /// to a temp dir, load it via `PresetLoader::load_dir`, and verify
    /// the bundle is internally coherent (both skills load with parsed
    /// permissions blocks; effective profile resolves cleanly via the
    /// per-skill permissions union from #76).
    #[test]
    fn zirkel_preset_loads_and_merges_into_a_resolved_effective_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("zirkel");
        install_bundled_preset("zirkel", &dest).unwrap();

        let loaded = crate::preset::PresetLoader::load_dir(&dest).unwrap();
        assert_eq!(loaded.metadata.name, "zirkel");
        assert_eq!(loaded.skills.len(), 2);

        let names: Vec<&str> = loaded.skills.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"aggregator"));
        assert!(names.contains(&"librarian"));

        // Both Zirkel skills are explicit-only.
        for s in &loaded.skills {
            assert!(
                s.disable_model_invocation,
                "{} should be disable-model-invocation: true",
                s.name
            );
        }

        // The merged effective profile must be Resolved (not Legacy)
        // and must not produce a default-conflict — both skills declare
        // `inference.default = "ollama"` so the union is unanimous.
        let profiles: Vec<_> = loaded
            .skills
            .iter()
            .map(|s| s.permissions.clone())
            .collect();
        let eff = crate::skill_perms::effective_for_skills(&profiles).unwrap();
        match eff {
            crate::skill_perms::EffectiveProfile::Resolved(p) => {
                assert_eq!(p.inference.default.as_deref(), Some("ollama"));
            }
            crate::skill_perms::EffectiveProfile::Legacy => {
                panic!("zirkel preset merged to Legacy — at least one skill missed migration")
            }
        }
    }
}
