//! Bundled skills shipped with wirken.
//! These are installed to ~/.wirken/skills/ on first setup.

use std::path::Path;

/// One bundled skill and the signing artifacts shipped with it.
///
/// The signature is produced offline by the project skill-signing key
/// and delegated under the project registry root, so a fresh install
/// lands a bundle that verifies at the self-signed floor and under
/// that root in strict mode, without any key ever reaching the
/// gateway host. Editing a `SKILL.md` in this repo therefore invalidates
/// its committed signature until it is re-signed offline;
/// `every_bundled_skill_ships_a_valid_delegated_signature` fails loudly
/// when that happens.
struct BundledSkill {
    name: &'static str,
    content: &'static str,
    signature: &'static str,
    signer_pubkey: &'static str,
    delegation: &'static str,
}

const SKILLS: &[BundledSkill] = &[
    BundledSkill {
        name: "weather",
        content: include_str!("../../../skills/weather/SKILL.md"),
        signature: include_str!("../../../skills/weather/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/weather/SKILL.pub"),
        delegation: include_str!("../../../skills/weather/SKILL.deleg"),
    },
    BundledSkill {
        name: "github",
        content: include_str!("../../../skills/github/SKILL.md"),
        signature: include_str!("../../../skills/github/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/github/SKILL.pub"),
        delegation: include_str!("../../../skills/github/SKILL.deleg"),
    },
    BundledSkill {
        name: "git",
        content: include_str!("../../../skills/git/SKILL.md"),
        signature: include_str!("../../../skills/git/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/git/SKILL.pub"),
        delegation: include_str!("../../../skills/git/SKILL.deleg"),
    },
    BundledSkill {
        name: "tmux",
        content: include_str!("../../../skills/tmux/SKILL.md"),
        signature: include_str!("../../../skills/tmux/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/tmux/SKILL.pub"),
        delegation: include_str!("../../../skills/tmux/SKILL.deleg"),
    },
    BundledSkill {
        name: "system-info",
        content: include_str!("../../../skills/system-info/SKILL.md"),
        signature: include_str!("../../../skills/system-info/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/system-info/SKILL.pub"),
        delegation: include_str!("../../../skills/system-info/SKILL.deleg"),
    },
    BundledSkill {
        name: "web-fetch",
        content: include_str!("../../../skills/web-fetch/SKILL.md"),
        signature: include_str!("../../../skills/web-fetch/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/web-fetch/SKILL.pub"),
        delegation: include_str!("../../../skills/web-fetch/SKILL.deleg"),
    },
    BundledSkill {
        name: "docker",
        content: include_str!("../../../skills/docker/SKILL.md"),
        signature: include_str!("../../../skills/docker/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/docker/SKILL.pub"),
        delegation: include_str!("../../../skills/docker/SKILL.deleg"),
    },
    BundledSkill {
        name: "notes",
        content: include_str!("../../../skills/notes/SKILL.md"),
        signature: include_str!("../../../skills/notes/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/notes/SKILL.pub"),
        delegation: include_str!("../../../skills/notes/SKILL.deleg"),
    },
    BundledSkill {
        name: "calculator",
        content: include_str!("../../../skills/calculator/SKILL.md"),
        signature: include_str!("../../../skills/calculator/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/calculator/SKILL.pub"),
        delegation: include_str!("../../../skills/calculator/SKILL.deleg"),
    },
    BundledSkill {
        name: "file-search",
        content: include_str!("../../../skills/file-search/SKILL.md"),
        signature: include_str!("../../../skills/file-search/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/file-search/SKILL.pub"),
        delegation: include_str!("../../../skills/file-search/SKILL.deleg"),
    },
    BundledSkill {
        name: "disk-usage",
        content: include_str!("../../../skills/disk-usage/SKILL.md"),
        signature: include_str!("../../../skills/disk-usage/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/disk-usage/SKILL.pub"),
        delegation: include_str!("../../../skills/disk-usage/SKILL.deleg"),
    },
    BundledSkill {
        name: "process-manager",
        content: include_str!("../../../skills/process-manager/SKILL.md"),
        signature: include_str!("../../../skills/process-manager/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/process-manager/SKILL.pub"),
        delegation: include_str!("../../../skills/process-manager/SKILL.deleg"),
    },
    BundledSkill {
        name: "ssh",
        content: include_str!("../../../skills/ssh/SKILL.md"),
        signature: include_str!("../../../skills/ssh/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/ssh/SKILL.pub"),
        delegation: include_str!("../../../skills/ssh/SKILL.deleg"),
    },
    BundledSkill {
        name: "json-tools",
        content: include_str!("../../../skills/json-tools/SKILL.md"),
        signature: include_str!("../../../skills/json-tools/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/json-tools/SKILL.pub"),
        delegation: include_str!("../../../skills/json-tools/SKILL.deleg"),
    },
    BundledSkill {
        name: "csv-tools",
        content: include_str!("../../../skills/csv-tools/SKILL.md"),
        signature: include_str!("../../../skills/csv-tools/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/csv-tools/SKILL.pub"),
        delegation: include_str!("../../../skills/csv-tools/SKILL.deleg"),
    },
    BundledSkill {
        name: "lyrik",
        content: include_str!("../../../skills/lyrik/SKILL.md"),
        signature: include_str!("../../../skills/lyrik/SKILL.sig"),
        signer_pubkey: include_str!("../../../skills/lyrik/SKILL.pub"),
        delegation: include_str!("../../../skills/lyrik/SKILL.deleg"),
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
/// Each freshly installed skill lands with the `SKILL.sig`,
/// `SKILL.pub` and `SKILL.deleg` shipped in this binary, produced
/// offline by the project skill-signing key and delegated under the
/// project registry root. Nothing is signed at install time, so no
/// signing key is needed on the gateway host. Skills that already
/// exist on disk are left untouched, so an operator's edits are never
/// masked by a fresh signature that would make an edited bundle look
/// authentic.
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
        // Ship the signature that was produced offline rather than
        // minting a fresh one here. A self-signature proves only that
        // the bundle is internally consistent on this machine; the
        // shipped one carries the project signer's identity and its
        // delegation, so the same bundle verifies at the floor and
        // under the project registry root in strict mode.
        std::fs::write(dir.join("SKILL.sig"), skill.signature)?;
        std::fs::write(dir.join("SKILL.pub"), skill.signer_pubkey)?;
        std::fs::write(dir.join("SKILL.deleg"), skill.delegation)?;

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
