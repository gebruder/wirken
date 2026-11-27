//! `wirken skills verify --strict` passes a bundle whose signer the
//! registry root in effect delegated, and fails one it did not.
//!
//! Driven through the binary on copies of the bundled skills, with a
//! fresh data directory, so the compiled project root is the one in
//! effect, and with an operator root installed in its place.
mod common;

use std::path::{Path, PathBuf};

use common::wirken;

fn copy_skill(name: &str, to: &Path) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills")
        .join(name);
    let dir = to.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["SKILL.md", "SKILL.sig", "SKILL.pub", "SKILL.deleg"] {
        std::fs::copy(from.join(file), dir.join(file)).unwrap();
    }
    dir
}

fn verify(data: &Path, dir: &Path) -> (bool, String) {
    let out = wirken(data)
        .args(["skills", "verify", "--strict"])
        .arg(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn every_bundled_skill_passes_strict_under_the_compiled_root() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let root = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills/REGISTRY-ROOT.pub"),
    )
    .unwrap();
    let skills = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills");
    let mut checked = 0;
    for entry in std::fs::read_dir(&skills).unwrap() {
        let path = entry.unwrap().path();
        if !path.join("SKILL.deleg").exists() {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let dir = copy_skill(&name, tmp.path());
        let (ok, text) = verify(&data, &dir);
        assert!(ok, "{name}: {text}");
        assert!(text.contains("Signature: DELEGATED"), "{name}: {text}");
        assert!(text.contains(root.trim()), "{name}: {text}");
        checked += 1;
    }
    assert_eq!(checked, 16, "every signed bundled skill was checked");
}

#[test]
fn strict_fails_a_bundle_the_root_in_effect_did_not_delegate() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();

    // No delegation: self-signed only.
    let bare = copy_skill("git", &tmp.path().join("bare"));
    std::fs::remove_file(bare.join("SKILL.deleg")).unwrap();
    let (ok, text) = verify(&data, &bare);
    assert!(!ok, "{text}");
    assert!(text.contains("Signature: SELF-SIGNED"), "{text}");

    // An edited body: the signature no longer matches.
    let edited = copy_skill("git", &tmp.path().join("edited"));
    let mut md = std::fs::read_to_string(edited.join("SKILL.md")).unwrap();
    md.push('\n');
    std::fs::write(edited.join("SKILL.md"), md).unwrap();
    let (ok, text) = verify(&data, &edited);
    assert!(!ok, "{text}");
    assert!(text.contains("Signature: INVALID"), "{text}");

    // An operator root in place of the compiled one: the project's
    // delegation no longer anchors the bundle.
    let other: String = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let installed = wirken(&data)
        .args(["skills", "trust-root", "--yes", &other])
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    let dir = copy_skill("git", &tmp.path().join("pinned"));
    let (ok, text) = verify(&data, &dir);
    assert!(!ok, "{text}");
    assert!(text.contains("Signature: SELF-SIGNED"), "{text}");
}
