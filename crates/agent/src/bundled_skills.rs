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

/// What [`install_bundled_skills`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BundledInstall {
    /// Skills newly written, with their shipped signature files.
    pub installed: usize,
    /// Skills already on disk whose `SKILL.md` is the bundled one byte
    /// for byte, which had other signature files and now carry the
    /// shipped ones.
    pub restored: Vec<&'static str>,
}

/// Install bundled skills to a directory, and give each unmodified
/// bundled copy already there the signature shipped with it.
///
/// Each freshly installed skill lands with the `SKILL.sig`,
/// `SKILL.pub` and `SKILL.deleg` shipped in this binary, produced
/// offline by the project skill-signing key and delegated under the
/// project registry root. Nothing is signed at install time, so no
/// signing key is needed on the gateway host.
///
/// A skill already on disk keeps its files unless its `SKILL.md` is
/// the bundled one byte for byte. Then the shipped signature files
/// replace whatever is beside it, which for a copy installed before the
/// bundle shipped signed is a self-signature minted on this host with
/// no `SKILL.deleg`, so it would not load under the project root. They
/// are replaced only when the shipped signature verifies for that
/// directory. An edited `SKILL.md` is left alone for the operator to
/// re-sign, so an edit is never covered by a signature that would make
/// it look authentic.
pub fn install_bundled_skills(skills_dir: &Path) -> std::io::Result<BundledInstall> {
    let mut out = BundledInstall::default();

    for skill in SKILLS {
        let dir = skills_dir.join(skill.name);
        let path = dir.join("SKILL.md");

        if path.exists() {
            if restore_shipped_signature(&dir, skill)? {
                out.restored.push(skill.name);
            }
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
        write_shipped_signature(&dir, skill)?;

        out.installed += 1;
    }

    Ok(out)
}

fn write_shipped_signature(dir: &Path, skill: &BundledSkill) -> std::io::Result<()> {
    std::fs::write(dir.join("SKILL.sig"), skill.signature)?;
    std::fs::write(dir.join("SKILL.pub"), skill.signer_pubkey)?;
    std::fs::write(dir.join("SKILL.deleg"), skill.delegation)
}

/// Give an installed copy the shipped signature when its `SKILL.md` is
/// the bundled one and its signature files are not already the shipped
/// ones. Returns whether it wrote them.
fn restore_shipped_signature(dir: &Path, skill: &BundledSkill) -> std::io::Result<bool> {
    let Ok(skill_md) = wirken_gateway::skill_registry::read_skill_md(&dir.join("SKILL.md")) else {
        return Ok(false);
    };
    if skill_md != skill.content.as_bytes() {
        return Ok(false);
    }
    let same = |file: &str, shipped: &str| {
        std::fs::read(dir.join(file)).is_ok_and(|b| b == shipped.as_bytes())
    };
    if same("SKILL.sig", skill.signature)
        && same("SKILL.pub", skill.signer_pubkey)
        && same("SKILL.deleg", skill.delegation)
    {
        return Ok(false);
    }
    // The shipped signature covers SKILL.md alone. A skill.wasm beside
    // it changes what the bundle hashes to, and writing a signature
    // that does not verify would stop a loading skill from loading.
    let verifies = matches!(
        wirken_gateway::skill_registry::verify_skill_with_expected_key_and_delegation(
            dir,
            &skill_md,
            skill.signature,
            skill.signer_pubkey,
            None,
            None,
        ),
        Ok(wirken_gateway::skill_registry::VerifyResult::Valid { .. })
    );
    if !verifies {
        return Ok(false);
    }
    write_shipped_signature(dir, skill)?;
    Ok(true)
}

/// Whether the copy of bundled skill `name` in `dir` would load under
/// `root` once [`install_bundled_skills`] has run: its `SKILL.md`
/// (`skill_md`) is the bundled one byte for byte, and the signature
/// shipped with it verifies for `dir` with its delegation under `root`.
pub fn shipped_signature_verifies(
    dir: &Path,
    name: &str,
    skill_md: &[u8],
    root: &ed25519_dalek::VerifyingKey,
) -> bool {
    let Some(skill) = SKILLS.iter().find(|s| s.name == name) else {
        return false;
    };
    skill_md == skill.content.as_bytes()
        && matches!(
            wirken_gateway::skill_registry::verify_skill_with_expected_key_and_delegation(
                dir,
                skill_md,
                skill.signature,
                skill.signer_pubkey,
                Some(skill.delegation),
                Some(root),
            ),
            Ok(wirken_gateway::skill_registry::VerifyResult::Valid { .. })
        )
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

#[cfg(test)]
mod tests {
    use super::{SKILLS, install_bundled_skills, self_sign_skill_dir, shipped_signature_verifies};
    use std::path::Path;

    fn project_root() -> ed25519_dalek::VerifyingKey {
        wirken_gateway::skill_registry::parse_registry_root(include_str!(
            "../../../skills/REGISTRY-ROOT.pub"
        ))
        .unwrap()
    }

    fn files(dir: &Path) -> [Option<Vec<u8>>; 3] {
        ["SKILL.sig", "SKILL.pub", "SKILL.deleg"].map(|f| std::fs::read(dir.join(f)).ok())
    }

    fn shipped(name: &str) -> [Option<Vec<u8>>; 3] {
        let s = SKILLS.iter().find(|s| s.name == name).unwrap();
        [s.signature, s.signer_pubkey, s.delegation].map(|v| Some(v.as_bytes().to_vec()))
    }

    /// A bundled copy installed before the bundle shipped signed: the
    /// bundled SKILL.md under a signature minted on the host, no
    /// SKILL.deleg.
    fn host_signed_copy(skills_dir: &Path, name: &str) -> std::path::PathBuf {
        let dir = skills_dir.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let content = SKILLS.iter().find(|s| s.name == name).unwrap().content;
        std::fs::write(dir.join("SKILL.md"), content).unwrap();
        self_sign_skill_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn an_unmodified_host_signed_copy_gets_the_shipped_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = host_signed_copy(tmp.path(), "weather");
        let md = std::fs::read(dir.join("SKILL.md")).unwrap();
        assert_ne!(files(&dir), shipped("weather"), "host-minted to start");

        let done = install_bundled_skills(tmp.path()).unwrap();
        assert_eq!(done.installed, SKILLS.len() - 1);
        assert_eq!(done.restored, vec!["weather"]);
        assert_eq!(files(&dir), shipped("weather"));
        assert_eq!(std::fs::read(dir.join("SKILL.md")).unwrap(), md);

        let again = install_bundled_skills(tmp.path()).unwrap();
        assert_eq!(again.installed, 0);
        assert!(again.restored.is_empty(), "already shipped: {again:?}");
    }

    #[test]
    fn an_edited_copy_keeps_its_own_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = host_signed_copy(tmp.path(), "weather");
        let mut md = std::fs::read(dir.join("SKILL.md")).unwrap();
        md.extend_from_slice(b"\nlocal note\n");
        std::fs::write(dir.join("SKILL.md"), &md).unwrap();
        self_sign_skill_dir(&dir).unwrap();
        let before = files(&dir);

        let done = install_bundled_skills(tmp.path()).unwrap();
        assert!(done.restored.is_empty(), "{done:?}");
        assert_eq!(files(&dir), before);
        assert_eq!(std::fs::read(dir.join("SKILL.md")).unwrap(), md);
    }

    /// The shipped signature covers SKILL.md alone. With a skill.wasm
    /// beside it, writing it would leave a bundle that does not verify,
    /// so the host signature stays.
    #[test]
    fn a_copy_with_a_skill_wasm_keeps_its_own_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("weather");
        std::fs::create_dir_all(&dir).unwrap();
        let content = SKILLS.iter().find(|s| s.name == "weather").unwrap().content;
        std::fs::write(dir.join("SKILL.md"), content).unwrap();
        std::fs::write(dir.join("skill.wasm"), b"\0asm").unwrap();
        self_sign_skill_dir(&dir).unwrap();
        let before = files(&dir);

        let done = install_bundled_skills(tmp.path()).unwrap();
        assert!(done.restored.is_empty(), "{done:?}");
        assert_eq!(files(&dir), before);
        let md = std::fs::read(dir.join("SKILL.md")).unwrap();
        assert!(!shipped_signature_verifies(
            &dir,
            "weather",
            &md,
            &project_root()
        ));
    }

    #[test]
    fn the_shipped_signature_verifies_under_the_project_root_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = host_signed_copy(tmp.path(), "git");
        let md = std::fs::read(dir.join("SKILL.md")).unwrap();
        assert!(shipped_signature_verifies(
            &dir,
            "git",
            &md,
            &project_root()
        ));

        let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(!shipped_signature_verifies(&dir, "git", &md, &other));
        assert!(!shipped_signature_verifies(
            &dir,
            "git",
            b"edited",
            &project_root()
        ));
        assert!(!shipped_signature_verifies(
            &dir,
            "not-bundled",
            &md,
            &project_root()
        ));
    }
}
