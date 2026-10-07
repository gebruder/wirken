//! The line an approval prompt shows for an `exec`: where the command
//! will run if the operator approves it.
//!
//! Built from the settings the `exec` itself will use: the agent's
//! loaded [`SandboxConfig`] and the channel's egress policy for the
//! turn. Not from `sandbox.json` on disk, which can have been edited
//! since the agent loaded it and would then describe a place the
//! command does not run.
//!
//! The network part follows the decision the sandbox makes at run
//! time (`sandbox::egress_decision`): a channel policy, when there is
//! one, decides; without one the legacy `network` flag does.

use wirken_audit::ExecLocation;

use crate::sandbox::{SandboxConfig, SandboxMode};
use crate::sandbox_egress::{SandboxEgressMode, SandboxEgressPolicy};
use crate::skill_perms::AllowSet;

/// Hosts named before the list is cut, so a long allowlist does not
/// push the rest of the prompt off the screen.
const MAX_HOSTS_SHOWN: usize = 5;

/// Where an `exec` approved now would run.
///
/// `egress` is the channel's policy for this turn, `None` when no
/// channel policy applies. `host_user` is who a host `exec` runs as,
/// which is whoever runs the gateway.
pub fn describe(
    config: &SandboxConfig,
    egress: Option<&SandboxEgressPolicy>,
    host_user: &str,
) -> ExecLocation {
    let mode = config.mode.label();
    let text = match config.mode {
        SandboxMode::Off => format!("runs on this host as {host_user}"),
        SandboxMode::ExecOnly | SandboxMode::GVisor => {
            let label = match config.mode {
                SandboxMode::GVisor => "gvisor",
                _ => "exec_only",
            };
            format!(
                "runs in sandbox container ({label}, read-only root, workspace at /workspace, {})",
                network(config, egress)
            )
        }
    };
    ExecLocation { mode, text }
}

fn network(config: &SandboxConfig, egress: Option<&SandboxEgressPolicy>) -> String {
    let Some(policy) = egress else {
        return if config.network {
            "unrestricted network".to_string()
        } else {
            "no network".to_string()
        };
    };
    match (policy.mode, &policy.domains) {
        (SandboxEgressMode::None, _) => "no network".to_string(),
        (SandboxEgressMode::Open, _) | (SandboxEgressMode::Allowlist, AllowSet::Wildcard) => {
            "network to any public host through the egress proxy".to_string()
        }
        (SandboxEgressMode::Allowlist, AllowSet::Set(hosts)) if hosts.is_empty() => {
            "no network".to_string()
        }
        (SandboxEgressMode::Allowlist, AllowSet::Set(hosts)) => {
            let shown: Vec<&str> = hosts
                .iter()
                .take(MAX_HOSTS_SHOWN)
                .map(String::as_str)
                .collect();
            let more = hosts.len().saturating_sub(MAX_HOSTS_SHOWN);
            let tail = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            format!(
                "network only to {}{tail} through the egress proxy",
                shown.join(", ")
            )
        }
    }
}

/// Who a host `exec` runs as: the user running this process.
pub fn host_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "the gateway's user".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wirken_audit::SandboxModeLabel;

    fn config(mode: SandboxMode, network: bool) -> SandboxConfig {
        SandboxConfig {
            mode,
            network,
            ..SandboxConfig::default()
        }
    }

    fn allowlist(hosts: &[&str]) -> SandboxEgressPolicy {
        SandboxEgressPolicy::allowlist(AllowSet::Set(
            hosts.iter().map(|h| h.to_string()).collect::<BTreeSet<_>>(),
        ))
    }

    #[test]
    fn exec_only_with_no_network() {
        let loc = describe(&config(SandboxMode::ExecOnly, false), None, "davi");
        assert_eq!(loc.mode, SandboxModeLabel::ExecOnly);
        assert_eq!(
            loc.text,
            "runs in sandbox container (exec_only, read-only root, workspace at /workspace, no network)"
        );
    }

    #[test]
    fn gvisor_names_its_mode() {
        let loc = describe(&config(SandboxMode::GVisor, false), None, "davi");
        assert_eq!(loc.mode, SandboxModeLabel::Gvisor);
        assert_eq!(
            loc.text,
            "runs in sandbox container (gvisor, read-only root, workspace at /workspace, no network)"
        );
    }

    #[test]
    fn off_runs_on_the_host_as_the_gateway_user() {
        let loc = describe(&config(SandboxMode::Off, false), None, "davi");
        assert_eq!(loc.mode, SandboxModeLabel::Off);
        assert_eq!(loc.text, "runs on this host as davi");
    }

    #[test]
    fn the_legacy_network_flag_without_a_channel_policy_is_unrestricted() {
        let loc = describe(&config(SandboxMode::ExecOnly, true), None, "davi");
        assert!(
            loc.text.ends_with(", unrestricted network)"),
            "{}",
            loc.text
        );
    }

    #[test]
    fn a_denying_channel_policy_wins_over_the_legacy_flag() {
        let loc = describe(
            &config(SandboxMode::ExecOnly, true),
            Some(&SandboxEgressPolicy::denied()),
            "davi",
        );
        assert!(loc.text.ends_with(", no network)"), "{}", loc.text);
    }

    #[test]
    fn an_allowlist_names_its_hosts() {
        let loc = describe(
            &config(SandboxMode::ExecOnly, false),
            Some(&allowlist(&["pypi.org", "files.pythonhosted.org"])),
            "davi",
        );
        assert!(
            loc.text.ends_with(
                ", network only to files.pythonhosted.org, pypi.org through the egress proxy)"
            ),
            "{}",
            loc.text
        );
    }

    #[test]
    fn a_long_allowlist_is_cut_with_a_count() {
        let loc = describe(
            &config(SandboxMode::ExecOnly, false),
            Some(&allowlist(&[
                "a.org", "b.org", "c.org", "d.org", "e.org", "f.org", "g.org",
            ])),
            "davi",
        );
        assert!(
            loc.text
                .contains("network only to a.org, b.org, c.org, d.org, e.org and 2 more through"),
            "{}",
            loc.text
        );
    }

    #[test]
    fn an_empty_allowlist_reaches_nothing() {
        let loc = describe(
            &config(SandboxMode::ExecOnly, false),
            Some(&allowlist(&[])),
            "davi",
        );
        assert!(loc.text.ends_with(", no network)"), "{}", loc.text);
    }

    #[test]
    fn open_and_wildcard_reach_any_public_host() {
        let open = SandboxEgressPolicy {
            mode: SandboxEgressMode::Open,
            domains: AllowSet::Set(BTreeSet::new()),
        };
        let wildcard = SandboxEgressPolicy::allowlist(AllowSet::Wildcard);
        for policy in [open, wildcard] {
            let loc = describe(&config(SandboxMode::ExecOnly, false), Some(&policy), "davi");
            assert!(
                loc.text
                    .ends_with(", network to any public host through the egress proxy)"),
                "{}",
                loc.text
            );
        }
    }
}
