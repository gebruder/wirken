//! What this binary is, for `--version` and the startup banner.
//!
//! The values come from `build.rs` at compile time. `identity` is the
//! line an observation should be pasted with, so that the paste names
//! the commit it is evidence about; `binary_path` is the running
//! executable's absolute path, so a procedure can be written by copying
//! a path out of a prior run rather than assuming a layout.

/// The crate version, as `--version` always printed.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short commit hash the binary was built from, or `unknown`.
pub const COMMIT: &str = env!("WIRKEN_BUILD_COMMIT");
/// `clean`, `dirty`, or `unknown` (no repository at build time).
pub const DIRTY: &str = env!("WIRKEN_BUILD_DIRTY");

/// `1.19.0 (26e00f5)`, or `1.19.0 (26e00f5, dirty)` when tracked files
/// had uncommitted changes at build time, or `1.19.0 (unknown)` when
/// there was no repository to ask.
pub fn identity() -> String {
    format_identity(VERSION, COMMIT, DIRTY)
}

/// The formatting rule, separated so it can be tested for each state
/// without controlling the state of the tree the tests build from.
pub fn format_identity(version: &str, commit: &str, dirty: &str) -> String {
    if dirty == "dirty" {
        format!("{version} ({commit}, dirty)")
    } else {
        format!("{version} ({commit})")
    }
}

/// Absolute path of the running executable, or the reason it could not
/// be resolved. Never the bare name: the whole point is to say which
/// file on disk produced the output.
pub fn binary_path() -> String {
    match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(e) => format!("unresolved ({e})"),
    }
}

/// The two lines `--version` prints after the program name.
pub fn version_text() -> String {
    format!("{}\nbinary: {}", identity(), binary_path())
}

/// `version_text` as the `&'static str` clap's `version` takes without
/// the `string` feature. Leaked once, at startup, for a string a few
/// dozen bytes long; that is the documented clap idiom for a version
/// only known at runtime, and it keeps the manifest unchanged.
pub fn version_static() -> &'static str {
    Box::leak(version_text().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_build_names_the_commit_only() {
        assert_eq!(
            format_identity("1.19.0", "26e00f5", "clean"),
            "1.19.0 (26e00f5)"
        );
    }

    #[test]
    fn a_dirty_build_says_so_beside_the_commit() {
        assert_eq!(
            format_identity("1.19.0", "26e00f5", "dirty"),
            "1.19.0 (26e00f5, dirty)"
        );
    }

    #[test]
    fn no_repository_is_named_rather_than_hidden() {
        // The tarball case: the build script had no git to ask. The
        // word is printed so the reader knows the identity is absent
        // rather than mistaking a blank for a clean build.
        assert_eq!(
            format_identity("1.19.0", "unknown", "unknown"),
            "1.19.0 (unknown)"
        );
    }

    #[test]
    fn the_compiled_in_values_have_the_shape_build_rs_promises() {
        // Whatever tree this test was built from, the constants must be
        // one of the shapes build.rs can emit. A hash is hex; the only
        // non-hex value allowed is the literal fallback.
        assert!(
            COMMIT == "unknown" || COMMIT.chars().all(|c| c.is_ascii_hexdigit()),
            "commit must be hex or the fallback: {COMMIT:?}"
        );
        assert!(matches!(DIRTY, "clean" | "dirty" | "unknown"), "{DIRTY:?}");
        assert!(identity().starts_with(VERSION));
    }

    #[test]
    fn the_binary_path_is_absolute() {
        let p = binary_path();
        assert!(
            std::path::Path::new(&p).is_absolute() || p.starts_with("unresolved ("),
            "{p:?}"
        );
    }
}
