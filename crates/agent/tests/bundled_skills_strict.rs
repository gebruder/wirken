//! The bundled set under a configured registry root.
//!
//! `SkillLoader::load_file` resolves the operator's registry root from
//! the process-wide data directory, so this lives in its own test
//! binary: setting `WIRKEN_DATA_DIR` inside the unit-test process would
//! put every other test that loads a skill into strict mode. One test
//! function, one process, no interference.

use std::path::Path;

use wirken_agent::skill::{Refusal, SkillLoader};

/// Fresh data dir with the project registry root installed: all sixteen
/// bundled skills load, because each ships a signature by the project
/// skill-signing key delegated under that root. Change one byte of one
/// `SKILL.md` and that skill is refused, while the other fifteen still
/// load.
///
/// This is the end-to-end form of the claim signing.md makes. The
/// narrower check that each committed signature is currently valid
/// lives in the unit tests as
/// `every_bundled_skill_ships_a_valid_delegated_signature`, which is
/// the one that fails when someone edits a bundled `SKILL.md` without
/// re-signing it offline.
#[test]
fn bundled_skills_load_under_the_project_root_and_refuse_when_edited() {
    let data_dir = tempfile::tempdir().unwrap();

    // The published root, exactly as an operator would install it with
    // `wirken skills trust-root $(cat skills/REGISTRY-ROOT.pub)`.
    let root_hex = include_str!("../../../skills/REGISTRY-ROOT.pub").trim();
    std::fs::write(data_dir.path().join("registry-root.pub"), root_hex).unwrap();

    // SAFETY: this test binary runs in its own process and sets the
    // variable once, before anything reads it.
    unsafe {
        std::env::set_var("WIRKEN_DATA_DIR", data_dir.path());
    }

    let skills_dir = data_dir.path().join("skills");
    let installed = wirken_agent::bundled_skills::install_bundled_skills(&skills_dir)
        .unwrap()
        .installed;
    assert_eq!(
        installed,
        wirken_agent::bundled_skills::bundled_count(),
        "install must land every bundled skill"
    );
    assert_eq!(installed, 16, "the bundled set is sixteen skills");

    let dirs = |d: &Path| {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                p.join("SKILL.md").exists().then_some(p)
            })
            .collect();
        v.sort();
        v
    };

    let all = dirs(&skills_dir);
    assert_eq!(all.len(), 16);
    for dir in &all {
        SkillLoader::load_file(&dir.join("SKILL.md")).unwrap_or_else(|e| {
            panic!(
                "bundled skill at {} must load under the project root: {e}",
                dir.display()
            )
        });
    }

    // One byte, in the body rather than the frontmatter, so the refusal
    // is attributable to the signature and not to a parse failure.
    let edited = skills_dir.join("weather").join("SKILL.md");
    let original = std::fs::read_to_string(&edited).unwrap();
    std::fs::write(&edited, format!("{original} ")).unwrap();

    let err =
        SkillLoader::load_file(&edited).expect_err("an edited bundle must be refused, not loaded");
    let msg = format!("{err}");
    assert!(
        msg.contains("signature") || msg.contains("delegated"),
        "refusal should name the signature check, got: {msg}"
    );

    // The other fifteen are unaffected: the gate is per-bundle.
    for dir in all.iter().filter(|d| !d.ends_with("weather")) {
        SkillLoader::load_file(&dir.join("SKILL.md")).unwrap_or_else(|e| {
            panic!("editing one bundle must not affect {}: {e}", dir.display())
        });
    }

    // A bundled copy from before the bundle shipped signed: the bundled
    // SKILL.md under a signature minted on the host, no SKILL.deleg.
    // The listing reports both refusals from the read that refused
    // them, and only the unedited copy points at the restore.
    let git = skills_dir.join("git");
    for f in ["SKILL.sig", "SKILL.pub", "SKILL.deleg"] {
        std::fs::remove_file(git.join(f)).unwrap();
    }
    wirken_agent::bundled_skills::self_sign_skill_dir(&git).unwrap();

    let found = SkillLoader::load_dir(&skills_dir).unwrap();
    assert_eq!(found.loaded.len(), 14);
    let refused: Vec<_> = found
        .refused
        .iter()
        .map(|r| (r.name.as_str(), r.refusal.clone(), r.restorable))
        .collect();
    assert_eq!(
        refused,
        [
            ("git", Refusal::NotDelegated, true),
            ("weather", Refusal::NotDelegated, false),
        ]
    );

    let restored = wirken_agent::bundled_skills::restore_bundled_signatures(&skills_dir).unwrap();
    assert_eq!(restored.restored, ["git"]);
    let found = SkillLoader::load_dir(&skills_dir).unwrap();
    assert_eq!(found.loaded.len(), 15);
    assert_eq!(found.refused.len(), 1);
    assert_eq!(found.refused[0].name, "weather");
}
