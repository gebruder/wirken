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
/// The target triple the binary was built for, which names its release
/// artifact, `wirken-<target>`.
pub const TARGET: &str = env!("WIRKEN_BUILD_TARGET");
/// The commit's timestamp in seconds since the epoch, or `unknown`.
pub const COMMIT_TIME: &str = env!("WIRKEN_BUILD_COMMIT_TIME");

/// When the commit this binary was built from was made.
pub fn commit_time() -> Option<chrono::DateTime<chrono::Utc>> {
    parse_commit_time(COMMIT_TIME)
}

fn parse_commit_time(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(raw.parse().ok()?, 0)
}

/// What `wirken status` prints: the build, and its age at `now` from
/// the commit's timestamp. No network.
pub fn status_text(now: chrono::DateTime<chrono::Utc>) -> String {
    status_lines(
        VERSION,
        COMMIT,
        DIRTY,
        TARGET,
        commit_time(),
        now,
        &binary_path(),
    )
}

fn status_lines(
    version: &str,
    commit: &str,
    dirty: &str,
    target: &str,
    commit_time: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    binary: &str,
) -> String {
    let age = match commit_time {
        Some(t) => {
            let days = (now - t).num_days();
            let age = match days {
                d if d < 0 => "in the future; check this host's clock".to_string(),
                0 => "less than a day old".to_string(),
                1 => "1 day old".to_string(),
                d => format!("{d} days old"),
            };
            format!("{}, {age}", t.format("%Y-%m-%d"))
        }
        None => "unknown (built without the commit's timestamp)".to_string(),
    };
    format!(
        "  wirken {version}\n  commit   {commit} ({dirty})\n  built    from a commit of {age}\n  target   {target}\n  binary   {binary}\n"
    )
}

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

/// This build as the audit chain records it.
pub fn audit_identity() -> wirken_audit::BuildIdentity {
    wirken_audit::BuildIdentity {
        version: VERSION.to_string(),
        commit: COMMIT.to_string(),
        dirty: DIRTY.to_string(),
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
    fn status_reports_age_from_the_commit_timestamp() {
        let t = chrono::DateTime::from_timestamp(1_760_000_000, 0).unwrap();
        let now = t + chrono::Duration::days(12) + chrono::Duration::hours(3);
        let text = status_lines(
            "2.3.0",
            "abc1234",
            "clean",
            "x86_64-unknown-linux-musl",
            Some(t),
            now,
            "/b/wirken",
        );
        assert!(text.contains("wirken 2.3.0"), "{text}");
        assert!(text.contains("commit   abc1234 (clean)"), "{text}");
        assert!(
            text.contains(&format!("{}, 12 days old", t.format("%Y-%m-%d"))),
            "{text}"
        );
        assert!(
            text.contains("target   x86_64-unknown-linux-musl"),
            "{text}"
        );
        let fresh = status_lines("2.3.0", "abc1234", "dirty", "t", Some(t), t, "/b");
        assert!(fresh.contains("less than a day old"), "{fresh}");
        let unknown = status_lines("2.3.0", "unknown", "unknown", "t", None, now, "/b");
        assert!(
            unknown.contains("built    from a commit of unknown"),
            "{unknown}"
        );
        let skew = status_lines("2.3.0", "a", "clean", "t", Some(now), t, "/b");
        assert!(skew.contains("in the future"), "{skew}");
    }

    #[test]
    fn the_commit_time_is_a_timestamp_or_the_fallback() {
        assert!(
            COMMIT_TIME == "unknown" || parse_commit_time(COMMIT_TIME).is_some(),
            "{COMMIT_TIME:?}"
        );
        assert_eq!(parse_commit_time("unknown"), None);
        assert_eq!(parse_commit_time("12a"), None);
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
