//! A skill installed from the registry index loads under a configured
//! registry root (strict mode) when its index entry carries a valid
//! delegation, and is refused when it does not.
//!
//! The index and the skills are served from a loopback server through
//! `WIRKEN_SKILLS_INDEX`. This build bundles no registry root, so
//! `install` accepts both entries on their signatures. The operator root
//! set with `skills trust-root` then decides at load, and `skills list`
//! shows only what the load gate accepted.
#![cfg(unix)]

mod common;

use std::path::Path;

use ed25519_dalek::SigningKey;
use wirken_gateway::skill_registry::{self, SkillEntry, SkillIndex, generate_signing_keypair};

use common::{serve_dir, wirken, write_skill};

/// A published skill under `registry/<name>`, author-signed, and its
/// index entry without a delegation.
fn publish(registry: &Path, base_url: &str, name: &str) -> SkillEntry {
    let dir = registry.join(name);
    write_skill(&dir, name, &["read_file"], "marker");
    let read = |file: &str| std::fs::read_to_string(dir.join(file)).unwrap();
    SkillEntry {
        name: name.into(),
        description: format!("test skill {name}"),
        version: "1.0.0".into(),
        author: "test".into(),
        url: format!("{base_url}/{name}/SKILL.md"),
        signature: Some(read("SKILL.sig")),
        signer_key: Some(read("SKILL.pub")),
        signer_key_delegation: None,
        sha256: None,
    }
}

#[test]
fn an_installed_skill_loads_under_the_root_only_with_its_delegation() {
    let registry = tempfile::tempdir().unwrap();
    let base_url = serve_dir(registry.path().to_path_buf());

    let (root_secret, root_pub) = generate_signing_keypair();
    let root_bytes = skill_registry::hex_decode_public(&root_secret).unwrap();
    let root = SigningKey::from_bytes(&root_bytes.try_into().unwrap());

    let mut delegated = SkillIndex {
        skills: vec![publish(registry.path(), &base_url, "delegated-skill")],
    };
    skill_registry::sign_index(&mut delegated, &root, |entry| {
        std::fs::read(registry.path().join(&entry.name).join("SKILL.md"))
            .map_err(|e| wirken_gateway::error::GatewayError::Config(e.to_string()))
    })
    .unwrap();
    let mut index = delegated;
    index
        .skills
        .push(publish(registry.path(), &base_url, "plain-skill"));
    std::fs::write(
        registry.path().join("index.json"),
        serde_json::to_string(&index).unwrap(),
    )
    .unwrap();

    let data = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let out = wirken(data.path())
            .env("WIRKEN_SKILLS_INDEX", format!("{base_url}/index.json"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };

    run(&["skills", "trust-root", &root_pub]);
    run(&["skills", "install", "delegated-skill"]);
    run(&["skills", "install", "plain-skill"]);

    let skills = data.path().join("skills");
    assert!(skills.join("delegated-skill/SKILL.deleg").is_file());
    assert!(!skills.join("plain-skill/SKILL.deleg").exists());

    // `skills list` prints one row per skill the load gate accepted; the
    // refused one appears only in the warning naming what failed to load.
    let listed = run(&["skills", "list"]);
    let row = |name: &str| {
        listed
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{name} ")))
    };
    assert!(row("delegated-skill"), "{listed}");
    assert!(!row("plain-skill"), "{listed}");
}
