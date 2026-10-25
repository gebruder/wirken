//! `WIRKEN_ALLOW_UNSIGNED_SKILLS` under the compiled registry root, in
//! one test in its own binary.
//!
//! The bypass is read inside `SkillLoader::load_file`, so exercising it
//! means the variable has to be set in this process. `std::env::set_var`
//! is `unsafe` in the 2024 edition because it is undefined behaviour
//! while any other thread reads or writes the environment, and cargo
//! runs a test binary's tests on parallel threads that do exactly that.
//! A mutex between the writers does not help: the readers are the
//! problem.
//!
//! So this is one test function, alone in its own binary, which is what
//! makes the SAFETY claim below a fact rather than a hope.
#![cfg(unix)]

use tempfile::TempDir;
use wirken_agent::skill::SkillLoader;

fn write_unsigned_skill(skill_dir: &std::path::Path, contents: &str) {
    std::fs::create_dir_all(skill_dir).unwrap();
    std::fs::write(skill_dir.join("SKILL.md"), contents).unwrap();
}

#[test]
fn the_unsigned_bypass_does_not_apply_under_the_compiled_root() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("unsigned");
    write_unsigned_skill(&dir, "---\nname: unsigned\ndescription: x\n---\nbody\n");

    for value in [None, Some("1")] {
        // SAFETY: this binary holds one test, so the harness runs it on
        // a single thread and no other thread in the process reads or
        // writes the environment while these calls run.
        unsafe {
            match value {
                Some(v) => std::env::set_var("WIRKEN_ALLOW_UNSIGNED_SKILLS", v),
                None => std::env::remove_var("WIRKEN_ALLOW_UNSIGNED_SKILLS"),
            }
        }
        let err = SkillLoader::load_file(&dir.join("SKILL.md"))
            .expect_err("an unsigned bundle is refused under the compiled root");
        let msg = format!("{err}");
        assert!(
            msg.contains("unsigned") && msg.contains("registry root"),
            "{value:?}: {msg}"
        );
    }

    // SAFETY: as above.
    unsafe { std::env::remove_var("WIRKEN_ALLOW_UNSIGNED_SKILLS") };
}
