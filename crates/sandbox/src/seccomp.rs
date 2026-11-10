//! The seccomp profile an `exec` container runs under.
//!
//! The container runtime applies a default profile when none is named.
//! That default refuses `unshare`, `mount`, `setns` and a `clone` that
//! makes a namespace only because the container holds no
//! `CAP_SYS_ADMIN`: the rule is conditional on the capability set. This
//! profile is the same allowlist with every capability-conditional
//! allowance removed, so those refusals are stated here and hold
//! whatever capabilities a container is given and whatever the
//! daemon's default is.
//!
//! [`PROFILE`] is `seccomp.json`; `seccomp.NOTICE` records where it
//! comes from and how it differs.
//!
//! Docker's API takes the profile as JSON in the security option.
//! Podman's takes a path, and reads the file itself, so there the
//! profile is written to a private file and its path is sent
//! ([`for_runtime`]). Both run the container under the same profile.

use std::path::{Path, PathBuf};

use bollard::models::HostConfig;

/// The profile, as the JSON the runtime's API takes.
pub const PROFILE: &str = include_str!("seccomp.json");

/// Prefix of the security option that names a seccomp profile.
const OPTION_PREFIX: &str = "seccomp=";

/// File name of the profile inside its directory.
const FILE_NAME: &str = "seccomp.json";

/// Which seccomp profile a container gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seccomp {
    /// [`PROFILE`], passed to the runtime as JSON with the container.
    Profile,
    /// [`PROFILE`], in the file at this path, which the runtime reads.
    ProfileAt(PathBuf),
    /// No profile is named, so the runtime applies its own default.
    RuntimeDefault,
}

impl Seccomp {
    /// The security option for this choice, if it adds one.
    pub(crate) fn security_opt(&self) -> Option<String> {
        match self {
            Self::Profile => Some(format!("{OPTION_PREFIX}{PROFILE}")),
            Self::ProfileAt(path) => Some(format!("{OPTION_PREFIX}{}", path.display())),
            Self::RuntimeDefault => None,
        }
    }
}

/// How [`PROFILE`] is handed to this runtime: as JSON to Docker, as the
/// path of a file holding it to Podman. An `Err` means the file could
/// not be put in place; the caller refuses the container, since a
/// fallback to the runtime's default would be a different profile.
pub fn for_runtime(podman: bool) -> Result<Seccomp, String> {
    if !podman {
        return Ok(Seccomp::Profile);
    }
    install(&std::env::temp_dir())
        .map(Seccomp::ProfileAt)
        .map_err(|e| format!("could not write the seccomp profile for the runtime to read: {e}"))
}

/// Write [`PROFILE`] under `base` and return its path.
///
/// The file lives in a directory named for this user, mode 0700. A
/// directory already there is used only if it is a real directory this
/// user owns with no access for anyone else: a path another user made
/// first is refused, never written into or read from. The file is
/// replaced by rename, so a runtime reading it sees the whole profile
/// or the previous whole profile.
#[cfg(unix)]
pub fn install(base: &Path) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    // SAFETY: `geteuid` is always-safe FFI; documented as never failing.
    let uid = unsafe { libc::geteuid() };
    let dir = base.join(format!("wirken-seccomp-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(&dir)?;
    if !meta.file_type().is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is not a directory private to this user", dir.display()),
        ));
    }
    let path = dir.join(FILE_NAME);
    // Staged under a name no other call uses, in this process or
    // another, so two installs at once each rename a whole file.
    static STAGED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let staged = dir.join(format!(
        "{FILE_NAME}.{}.{}",
        std::process::id(),
        STAGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    file.write_all(PROFILE.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&staged, &path)?;
    Ok(path)
}

/// No runtime that takes a profile by path runs on this platform.
#[cfg(not(unix))]
pub fn install(_base: &Path) -> std::io::Result<PathBuf> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a seccomp profile file is written on unix only",
    ))
}

/// Whether `host` names a seccomp profile.
pub fn is_set(host: &HostConfig) -> bool {
    host.security_opt
        .iter()
        .flatten()
        .any(|o| o.starts_with(OPTION_PREFIX))
}

/// Name `choice` on `host` in place of whatever profile it named.
pub fn apply(host: &mut HostConfig, choice: &Seccomp) {
    let opts = host.security_opt.get_or_insert_with(Vec::new);
    opts.retain(|o| !o.starts_with(OPTION_PREFIX));
    opts.extend(choice.security_opt());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<serde_json::Value> {
        let profile: serde_json::Value = serde_json::from_str(PROFILE).expect("the profile parses");
        assert_eq!(profile["defaultAction"], "SCMP_ACT_ERRNO");
        profile["syscalls"].as_array().expect("rules").clone()
    }

    fn names(rule: &serde_json::Value) -> Vec<&str> {
        rule["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect()
    }

    /// Nothing is refused by default and then allowed back for a
    /// container that holds a capability.
    #[test]
    fn no_rule_depends_on_a_capability() {
        for rule in rules() {
            for side in ["includes", "excludes"] {
                assert!(
                    rule[side].get("caps").is_none(),
                    "a rule is conditional on capabilities: {rule}"
                );
            }
        }
    }

    /// The syscalls that make a namespace or change the mount table
    /// are on no allow rule, so the default action refuses them.
    #[test]
    fn namespace_and_mount_syscalls_are_refused() {
        let refused = [
            "unshare",
            "setns",
            "mount",
            "umount",
            "umount2",
            "pivot_root",
            "chroot",
            "move_mount",
            "open_tree",
            "fsopen",
            "fsmount",
            "fsconfig",
            "fspick",
            "mount_setattr",
            "bpf",
        ];
        for rule in rules() {
            if rule["action"] != "SCMP_ACT_ALLOW" {
                continue;
            }
            for name in names(&rule) {
                assert!(!refused.contains(&name), "{name} is allowed by {rule}");
            }
        }
    }

    /// `clone` is allowed only with no namespace flag set, and `clone3`,
    /// whose flags a filter cannot read, answers ENOSYS so a libc falls
    /// back to `clone`.
    #[test]
    fn a_clone_that_makes_a_namespace_is_refused() {
        // CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
        const NAMESPACE_FLAGS: u64 = 0x7E02_0000;
        let mut clone_rules = 0;
        let mut clone3_rules = 0;
        for rule in rules() {
            let names = names(&rule);
            if names.contains(&"clone") {
                clone_rules += 1;
                assert_eq!(names, ["clone"], "clone shares no rule: {rule}");
                assert_eq!(rule["action"], "SCMP_ACT_ALLOW");
                let args = rule["args"].as_array().expect("clone is allowed on a mask");
                assert_eq!(args.len(), 1);
                assert_eq!(args[0]["op"], "SCMP_CMP_MASKED_EQ");
                assert_eq!(args[0]["value"], NAMESPACE_FLAGS);
                assert!(
                    args[0].get("valueTwo").is_none_or(|v| v == 0),
                    "allowed only when every namespace flag is clear: {rule}"
                );
            }
            if names.contains(&"clone3") {
                clone3_rules += 1;
                assert_eq!(names, ["clone3"]);
                assert_eq!(rule["action"], "SCMP_ACT_ERRNO");
                assert_eq!(rule["errnoRet"], 38, "ENOSYS");
            }
        }
        assert_eq!(clone_rules, 2, "one rule per argument order");
        assert_eq!(clone3_rules, 1);
    }

    /// `socket` is allowed per address family, as the release this
    /// profile is derived from allows it, and never by a rule that
    /// admits every family but one.
    #[test]
    fn a_socket_is_allowed_by_address_family() {
        let mut families = Vec::new();
        for rule in rules() {
            if !names(&rule).contains(&"socket") {
                continue;
            }
            assert_eq!(names(&rule), ["socket"], "socket shares no rule: {rule}");
            let args = rule["args"]
                .as_array()
                .expect("socket is allowed on its family");
            assert_eq!(args.len(), 1);
            assert_eq!(args[0]["index"], 0, "the family is the first argument");
            let op = args[0]["op"].as_str().unwrap();
            assert!(
                matches!(op, "SCMP_CMP_EQ" | "SCMP_CMP_LT"),
                "a family is named or bounded from above, never excluded: {rule}"
            );
            families.push((op.to_string(), args[0]["value"].as_u64().unwrap()));
        }
        // AF_UNSPEC, AF_UNIX and AF_INET by the bound, AF_INET6 and
        // AF_NETLINK by name.
        assert!(families.contains(&("SCMP_CMP_LT".to_string(), 3)));
        for family in [10, 16] {
            assert!(
                families.contains(&("SCMP_CMP_EQ".to_string(), family)),
                "{family}"
            );
        }
        // AF_VSOCK reaches the hypervisor and is on no rule.
        assert!(!families.iter().any(|(_, f)| *f == 40));
    }

    #[test]
    fn the_profile_is_one_security_option_and_can_be_taken_back_out() {
        let mut host = HostConfig {
            security_opt: Some(vec![
                "no-new-privileges:true".into(),
                Seccomp::Profile.security_opt().unwrap(),
            ]),
            ..Default::default()
        };
        assert!(is_set(&host));
        apply(&mut host, &Seccomp::RuntimeDefault);
        assert!(!is_set(&host));
        assert_eq!(
            host.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(Seccomp::RuntimeDefault.security_opt(), None);
    }

    /// The file a path-reading runtime is pointed at holds the profile,
    /// in a directory and a file no other user can read or replace, and
    /// the option names that path.
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[test]
    fn the_profile_is_installed_privately_and_named_by_path() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("wirken-seccomp-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let path = install(&base).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), PROFILE);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        // A second install replaces the file in place and leaves
        // nothing else in the directory.
        assert_eq!(install(&base).unwrap(), path);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );

        let mut host = HostConfig {
            security_opt: Some(vec![
                "no-new-privileges:true".into(),
                Seccomp::Profile.security_opt().unwrap(),
            ]),
            ..Default::default()
        };
        apply(&mut host, &Seccomp::ProfileAt(path.clone()));
        assert_eq!(
            host.security_opt,
            Some(vec![
                "no-new-privileges:true".to_string(),
                format!("seccomp={}", path.display()),
            ])
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A directory at the profile's place that others can enter is not
    /// used: what is in it could have been put there by someone else.
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[test]
    fn a_directory_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("wirken-seccomp-open-{}", std::process::id()));
        // SAFETY: as in `install`.
        let uid = unsafe { libc::geteuid() };
        let dir = base.join(format!("wirken-seccomp-{uid}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = install(&base).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!dir.join(FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn docker_is_sent_the_profile_as_json() {
        assert_eq!(for_runtime(false), Ok(Seccomp::Profile));
    }
}
