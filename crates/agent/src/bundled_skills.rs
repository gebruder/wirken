//! Bundled skills shipped with wirken.
//! These are installed to ~/.wirken/skills/ on first setup.

use std::path::Path;

struct BundledSkill {
    name: &'static str,
    content: &'static str,
}

const SKILLS: &[BundledSkill] = &[
    BundledSkill {
        name: "weather",
        content: include_str!("../../../skills/weather/SKILL.md"),
    },
    BundledSkill {
        name: "github",
        content: include_str!("../../../skills/github/SKILL.md"),
    },
    BundledSkill {
        name: "git",
        content: include_str!("../../../skills/git/SKILL.md"),
    },
    BundledSkill {
        name: "tmux",
        content: include_str!("../../../skills/tmux/SKILL.md"),
    },
    BundledSkill {
        name: "system-info",
        content: include_str!("../../../skills/system-info/SKILL.md"),
    },
    BundledSkill {
        name: "web-fetch",
        content: include_str!("../../../skills/web-fetch/SKILL.md"),
    },
    BundledSkill {
        name: "docker",
        content: include_str!("../../../skills/docker/SKILL.md"),
    },
    BundledSkill {
        name: "notes",
        content: include_str!("../../../skills/notes/SKILL.md"),
    },
    BundledSkill {
        name: "calculator",
        content: include_str!("../../../skills/calculator/SKILL.md"),
    },
    BundledSkill {
        name: "file-search",
        content: include_str!("../../../skills/file-search/SKILL.md"),
    },
    BundledSkill {
        name: "disk-usage",
        content: include_str!("../../../skills/disk-usage/SKILL.md"),
    },
    BundledSkill {
        name: "process-manager",
        content: include_str!("../../../skills/process-manager/SKILL.md"),
    },
    BundledSkill {
        name: "ssh",
        content: include_str!("../../../skills/ssh/SKILL.md"),
    },
    BundledSkill {
        name: "json-tools",
        content: include_str!("../../../skills/json-tools/SKILL.md"),
    },
    BundledSkill {
        name: "csv-tools",
        content: include_str!("../../../skills/csv-tools/SKILL.md"),
    },
    BundledSkill {
        name: "lyrik",
        content: include_str!("../../../skills/lyrik/SKILL.md"),
    },
];

/// Install bundled skills to a directory. Skips skills that already exist.
/// Returns the number of skills installed.
///
/// Each freshly installed skill is self-signed with a one-shot keypair
/// so the loader's signature gate (see
/// `crates/agent/src/skill.rs::verify_skill_signature`) accepts the
/// bundle without operator setup. The signing key is discarded after
/// the signature is written. The pair gives tamper-detection for the
/// bundled set after install: if any file in the bundle changes
/// without re-signing, the loader rejects it. Skills that already
/// exist on disk are left untouched (re-signing them would mask any
/// operator edits to the SKILL.md content).
pub fn install_bundled_skills(skills_dir: &Path) -> std::io::Result<usize> {
    let mut installed = 0;

    for skill in SKILLS {
        let dir = skills_dir.join(skill.name);
        let path = dir.join("SKILL.md");

        if path.exists() {
            continue;
        }

        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, skill.content)?;

        let (secret_hex, _public_hex) = wirken_gateway::skill_registry::generate_signing_keypair();
        let secret_bytes = wirken_gateway::skill_registry::hex_decode_public(&secret_hex)
            .map_err(std::io::Error::other)?;
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
        wirken_gateway::skill_registry::sign_skill(&dir, &signing_key)
            .map_err(std::io::Error::other)?;

        installed += 1;
    }

    Ok(installed)
}

/// Number of bundled skills.
pub fn bundled_count() -> usize {
    SKILLS.len()
}
