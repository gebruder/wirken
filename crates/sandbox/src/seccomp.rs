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

use bollard::models::HostConfig;

/// The profile, as the JSON the runtime's API takes.
pub const PROFILE: &str = include_str!("seccomp.json");

/// Prefix of the security option that names a seccomp profile.
const OPTION_PREFIX: &str = "seccomp=";

/// Which seccomp profile a container gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seccomp {
    /// [`PROFILE`], passed to the runtime with the container.
    Profile,
    /// No profile is named, so the runtime applies its own default.
    RuntimeDefault,
}

impl Seccomp {
    /// The security option for this choice, if it adds one.
    pub(crate) fn security_opt(self) -> Option<String> {
        match self {
            Self::Profile => Some(format!("{OPTION_PREFIX}{PROFILE}")),
            Self::RuntimeDefault => None,
        }
    }
}

/// Whether `host` names a seccomp profile.
pub fn is_set(host: &HostConfig) -> bool {
    host.security_opt
        .iter()
        .flatten()
        .any(|o| o.starts_with(OPTION_PREFIX))
}

/// Remove the named profile from `host`, leaving the runtime's default.
/// For a runtime whose API does not take a profile as JSON.
pub fn use_runtime_default(host: &mut HostConfig) {
    if let Some(opts) = host.security_opt.as_mut() {
        opts.retain(|o| !o.starts_with(OPTION_PREFIX));
    }
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
        use_runtime_default(&mut host);
        assert!(!is_set(&host));
        assert_eq!(
            host.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(Seccomp::RuntimeDefault.security_opt(), None);
    }
}
