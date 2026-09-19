//! `WIRKEN_ALLOW_UNSIGNED_SKILLS`, both directions, in one test in its
//! own binary.
//!
//! The bypass is read inside `SkillLoader::load_file`, so exercising it
//! means the variable has to be set in this process. `std::env::set_var`
//! is `unsafe` in the 2024 edition because it is undefined behaviour
//! while any other thread reads or writes the environment, and cargo
//! runs a test binary's tests on parallel threads that do exactly that.
//! A mutex between the writers does not help: the readers are the
//! problem.
//!
//! So this is one test function, alone in its own binary. Both
//! directions run in sequence on the one thread the harness gives it,
//! which is what makes the SAFETY claim below a fact rather than a
//! hope. The rest of the gate's cases need no environment and live in
//! the crate's unit tests.
#![cfg(unix)]

use tempfile::TempDir;
use wirken_agent::skill::SkillLoader;

fn write_unsigned_skill(skill_dir: &std::path::Path, contents: &str) {
    std::fs::create_dir_all(skill_dir).unwrap();
    std::fs::write(skill_dir.join("SKILL.md"), contents).unwrap();
}

#[test]
fn the_unsigned_bypass_is_off_by_default_and_on_when_set() {
    let tmp = TempDir::new().unwrap();

    // SAFETY: this binary holds one test, so the harness runs it on a
    // single thread and no other thread in the process reads or writes
    // the environment while these calls run. Both writes and every
    // read between them happen here, in order.
    unsafe { std::env::remove_var("WIRKEN_ALLOW_UNSIGNED_SKILLS") };

    let refused_dir = tmp.path().join("unsigned");
    write_unsigned_skill(
        &refused_dir,
        "---\nname: unsigned\ndescription: x\n---\nbody\n",
    );
    let err = SkillLoader::load_file(&refused_dir.join("SKILL.md"))
        .expect_err("an unsigned bundle must be refused with the bypass unset");
    let msg = format!("{err}");
    assert!(
        msg.contains("unsigned") && msg.contains("WIRKEN_ALLOW_UNSIGNED_SKILLS"),
        "the refusal must name the opt-in, got: {msg}"
    );

    // SAFETY: as above. Nothing has been spawned in between.
    unsafe { std::env::set_var("WIRKEN_ALLOW_UNSIGNED_SKILLS", "1") };

    let allowed_dir = tmp.path().join("bypass-test");
    write_unsigned_skill(
        &allowed_dir,
        "---\nname: bypass-test\ndescription: loaded via bypass\n---\nbody\n",
    );
    let skill = SkillLoader::load_file(&allowed_dir.join("SKILL.md"))
        .expect("WIRKEN_ALLOW_UNSIGNED_SKILLS=1 must allow the load");
    assert_eq!(skill.name, "bypass-test");

    // A bad signature is still refused with the bypass on: the opt-in
    // admits an absent signature, never a wrong one.
    let forged_dir = tmp.path().join("forged");
    write_unsigned_skill(
        &forged_dir,
        "---\nname: forged\ndescription: x\n---\nbody\n",
    );
    std::fs::write(forged_dir.join("SKILL.sig"), "00".repeat(64)).unwrap();
    std::fs::write(forged_dir.join("SKILL.pub"), "11".repeat(32)).unwrap();
    let err = SkillLoader::load_file(&forged_dir.join("SKILL.md"))
        .expect_err("a present-but-bad signature must be refused even with the bypass set");
    let msg = format!("{err}");
    assert!(
        !msg.contains("is unsigned"),
        "the refusal should be about the signature, not absence: {msg}"
    );

    // SAFETY: as above.
    unsafe { std::env::remove_var("WIRKEN_ALLOW_UNSIGNED_SKILLS") };
}
