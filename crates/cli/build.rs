//! Build identity for the wirken binary: which commit it came from and
//! whether the tree was clean when it was built. Issue 231.
//!
//! No timestamp, on purpose. The same commit built twice must produce
//! the same binary, and a clock inside the binary would make that false
//! for no gain the three incidents behind this needed: every one of
//! them was a question about which commit, never about when.
//!
//! No dependency, on purpose either: this shells out to `git` and treats
//! any failure as "unknown" rather than failing the build, so a tarball
//! build with no repository still compiles and says so.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn main() {
    // Re-run when HEAD moves, when the ref it points at moves, or when
    // the index changes. Without these the embedded hash goes stale
    // across commits, which is a lie about identity and worse than no
    // hash at all. Paths are relative to this package's directory.
    let git_dir = "../../.git";
    println!("cargo:rerun-if-changed={git_dir}/HEAD");
    println!("cargo:rerun-if-changed={git_dir}/index");
    println!("cargo:rerun-if-changed={git_dir}/packed-refs");
    if let Ok(head) = std::fs::read_to_string(format!("{git_dir}/HEAD"))
        && let Some(r) = head.strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed={git_dir}/{}", r.trim());
    }
    // An explicit override for builds that have the commit but not the
    // repository, such as a tarball whose packager knows what it holds.
    println!("cargo:rerun-if-env-changed=WIRKEN_BUILD_COMMIT");
    // GIT_DIR changes what git answers, so it changes the identity.
    println!("cargo:rerun-if-env-changed=GIT_DIR");

    let commit = std::env::var("WIRKEN_BUILD_COMMIT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| git(&["rev-parse", "--short", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());

    // Tracked files only. An untracked scratch file beside the tree is
    // not a change to what was built.
    let dirty = match Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
    {
        Ok(o) if o.status.success() => {
            if o.stdout.iter().any(|b| !b.is_ascii_whitespace()) {
                "dirty"
            } else {
                "clean"
            }
        }
        _ => "unknown",
    };

    println!("cargo:rustc-env=WIRKEN_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=WIRKEN_BUILD_DIRTY={dirty}");
}
