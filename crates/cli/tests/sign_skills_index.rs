//! `scripts/sign-skills-index.sh` signs a registry index that
//! `wirken skills install`'s check accepts under the signing root, and
//! only under it.
//!
//! The root and the author key are throwaway keys generated here. The
//! root's public half goes through the same parser the build applies to
//! `wirken-registry-pubkey.pub`, so the test also covers the step of
//! writing a generated key into that file.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use wirken_gateway::skill_registry::{
    self, SkillIndex, VerifyResult, generate_signing_keypair, parse_bundled_registry_pubkey,
    verify_skill_with_expected_key_and_delegation,
};

const URL_PREFIX: &str = "https://raw.githubusercontent.com/gebruder/wirken-skills/main/";

fn signing_key(secret_hex: &str) -> SigningKey {
    let bytes = skill_registry::hex_decode_public(secret_hex).unwrap();
    SigningKey::from_bytes(&bytes.try_into().unwrap())
}

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sign-skills-index.sh")
}

struct Registry {
    dir: tempfile::TempDir,
    root_pub: String,
    signature: String,
    signer_pub: String,
}

impl Registry {
    fn checkout(&self) -> PathBuf {
        self.dir.path().join("wirken-skills")
    }

    fn skill_md(&self) -> PathBuf {
        self.checkout().join("connectors/demo/SKILL.md")
    }

    fn index(&self) -> PathBuf {
        self.dir.path().join("index.json")
    }

    fn signed_index(&self) -> PathBuf {
        self.dir.path().join("index.signed.json")
    }

    fn sign(&self) -> Output {
        Command::new("sh")
            .arg(script())
            .arg("--root-key")
            .arg(self.dir.path().join("registry-root.seed"))
            .arg(self.index())
            .arg(self.checkout())
            .env("WIRKEN_BIN", env!("CARGO_BIN_EXE_wirken"))
            .env("WIRKEN_DATA_DIR", self.dir.path().join("data"))
            .output()
            .unwrap()
    }
}

/// A registry checkout with one author-signed skill and its index
/// entry, and a root seed file, all as the operator would hold them.
fn registry() -> Registry {
    let dir = tempfile::tempdir().unwrap();
    let (root_secret, root_pub) = generate_signing_keypair();
    std::fs::write(dir.path().join("registry-root.seed"), &root_secret).unwrap();

    let (author_secret, signer_pub) = generate_signing_keypair();
    let skill_dir = dir.path().join("wirken-skills/connectors/demo");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(skill_dir.join("SKILL.md"), "---\nname: demo\n---\nbody\n").unwrap();
    let signature = skill_registry::sign_skill(&skill_dir, &signing_key(&author_secret)).unwrap();

    let index = serde_json::json!({"skills": [{
        "name": "demo",
        "description": "demo skill",
        "version": "1.0.0",
        "author": "someone",
        "url": format!("{URL_PREFIX}connectors/demo/SKILL.md"),
        "signature": signature,
        "signer_key": signer_pub,
    }]});
    std::fs::write(dir.path().join("index.json"), index.to_string()).unwrap();

    Registry {
        dir,
        root_pub,
        signature,
        signer_pub,
    }
}

#[test]
fn the_script_signs_an_index_that_install_accepts_under_its_root_only() {
    let reg = registry();
    let out = reg.sign();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let signed: SkillIndex =
        serde_json::from_str(&std::fs::read_to_string(reg.signed_index()).unwrap()).unwrap();
    let entry = &signed.skills[0];
    assert_eq!(entry.signature.as_deref(), Some(reg.signature.as_str()));
    assert_eq!(entry.signer_key.as_deref(), Some(reg.signer_pub.as_str()));
    let skill_md = std::fs::read(reg.skill_md()).unwrap();
    let digest: String = Sha256::digest(&skill_md)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(entry.sha256.as_deref(), Some(digest.as_str()));

    // `wirken skills install` writes the downloaded SKILL.md alone into
    // the skill directory and checks it against the entry, with the
    // bundled root read from wirken-registry-pubkey.pub.
    let install_dir = reg.dir.path().join("installed/demo");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join("SKILL.md"), &skill_md).unwrap();
    let install_check = |bundled_pub_file: &str| {
        let bundled = parse_bundled_registry_pubkey(bundled_pub_file).unwrap();
        verify_skill_with_expected_key_and_delegation(
            &install_dir,
            entry.signature.as_deref().unwrap(),
            entry.signer_key.as_deref().unwrap(),
            entry.signer_key_delegation.as_deref(),
            Some(&bundled),
        )
        .unwrap()
    };
    assert!(matches!(
        install_check(&format!("{}\n", reg.root_pub)),
        VerifyResult::Valid { .. }
    ));
    let (_, other_root) = generate_signing_keypair();
    assert!(matches!(
        install_check(&format!("{other_root}\n")),
        VerifyResult::Invalid
    ));
}

#[test]
fn the_script_refuses_an_index_whose_skill_md_changed() {
    let reg = registry();
    std::fs::write(reg.skill_md(), "changed after the author signed").unwrap();
    let out = reg.sign();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not verify"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!reg.signed_index().exists());
    assert!(!reg.dir.path().join("index.signed.json.tmp").exists());
}
