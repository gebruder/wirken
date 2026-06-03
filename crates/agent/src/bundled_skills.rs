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

/// Self-sign a skill directory (containing `SKILL.md`) with a freshly
/// generated one-shot ed25519 keypair, writing `SKILL.sig` and
/// `SKILL.pub` alongside. Used at install or staging time so the
/// loader's signature gate (`wirken_agent::skill::verify_skill_signature`)
/// accepts the bundle without operator action. The signing key is
/// discarded after use; the pair only proves the bundle is internally
/// consistent (catches post-install tampering, not provenance).
pub fn self_sign_skill_dir(dir: &Path) -> std::io::Result<()> {
    let (secret_hex, _public_hex) = wirken_gateway::skill_registry::generate_signing_keypair();
    let secret_bytes = wirken_gateway::skill_registry::hex_decode_public(&secret_hex)
        .map_err(std::io::Error::other)?;
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
    wirken_gateway::skill_registry::sign_skill(dir, &signing_key).map_err(std::io::Error::other)?;
    Ok(())
}

/// Install bundled skills to a directory. Skips skills that already exist.
/// Returns the number of skills installed.
///
/// Each freshly installed skill is self-signed via [`self_sign_skill_dir`]
/// so the loader's signature gate accepts the bundle without operator
/// setup. Skills that already exist on disk are left untouched
/// (re-signing them would mask any operator edits to the SKILL.md
/// content).
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
        self_sign_skill_dir(&dir)?;

        installed += 1;
    }

    Ok(installed)
}

/// Install bundled skills to a directory, delegate-signing each under
/// an operator registry root instead of self-signing. Used only when
/// an operator has opted into identity anchoring and supplies the root
/// private key in their offline signing environment; with no root the
/// plain [`install_bundled_skills`] self-signed floor applies and is
/// unchanged.
///
/// Each freshly written skill gets a fresh, immediately-discarded
/// signer keypair whose public key is delegated by `root_key` (see
/// [`wirken_gateway::skill_registry::delegate_sign_skill`]), so the
/// bundle verifies under the configured root at load. Skills that
/// already exist on disk are left untouched, the same as the
/// self-signed installer, so an operator's edits are never masked.
pub fn install_bundled_skills_delegated(
    skills_dir: &Path,
    root_key: &ed25519_dalek::SigningKey,
) -> std::io::Result<usize> {
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
        let signer = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
        wirken_gateway::skill_registry::delegate_sign_skill(&dir, &signer, root_key)
            .map_err(std::io::Error::other)?;

        installed += 1;
    }

    Ok(installed)
}

/// Number of bundled skills.
pub fn bundled_count() -> usize {
    SKILLS.len()
}

/// Look up the canonical SKILL.md content for a bundled skill by name.
/// Used by the Lyrik runner to stage the skill into a per-run dir at
/// dispatch time, so the agent's loaded set includes `/lyrik`
/// regardless of operator state under `~/.wirken/skills/`.
pub fn bundled_skill_content(name: &str) -> Option<&'static str> {
    SKILLS.iter().find(|s| s.name == name).map(|s| s.content)
}
