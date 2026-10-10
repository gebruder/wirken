//! Default-deny egress proxy for sandboxed `exec`.
//!
//! This module holds exec's policy: the per-channel mode and
//! allowlist, and the confidentiality stage that conditions a verdict
//! on what the session has read. The sidecar, the decision broker and
//! the structural rules are shared with contained MCP servers and live
//! in `wirken_sandbox::egress`; the networks in
//! `wirken_sandbox::egress_net`.
//!
//! The container-level floor is `--network none`: with egress mode
//! `none` (the default) a sandboxed `exec` has no network namespace
//! connectivity at all and this module is never instantiated. This
//! proxy exists for the two modes that grant some reach, and it is
//! the only route out of the sandbox in those modes.
//!
//! # Topology
//!
//! The sandbox container is attached to a per-exec Docker network
//! created with `Internal: true` and inter-container communication
//! disabled, so it has no default route and no reach to any sibling
//! container. The single reachable endpoint is this proxy, listening
//! on the network's gateway address. A process in the container that
//! ignores `HTTP_PROXY` and opens a raw socket does not bypass the
//! allowlist; it fails to route anywhere.
//!
//! # Properties
//!
//! * **HTTP(S) or nothing.** CONNECT on 443 and plain HTTP on 80 are
//!   the only shapes proxied. There is no generic TCP forward, so
//!   SSH, raw sockets, and every non-HTTP protocol are unreachable
//!   from a sandbox regardless of allowlist contents.
//! * **Domain match only.** IP-literal targets are refused before
//!   the allowlist is consulted. An allowlist entry is a domain
//!   pattern and can never authorize a bare address.
//! * **The proxy resolves.** The container has no working resolver.
//!   Hostname resolution happens here, after the allowlist decision,
//!   and resolved addresses outside the global unicast range are
//!   dropped so an allowlisted name cannot be rebound onto loopback,
//!   link-local (including the cloud metadata address), or private
//!   space.
//! * **Attribution is structural.** Each `exec` call gets its own
//!   listener carrying the agent, channel, and sender it was bound
//!   to. Nothing on an audit row is parsed out of request content,
//!   so a sandboxed process cannot forge its own attribution.
//!
//! # Known limit
//!
//! CONNECT allowlisting is decided on the CONNECT target, and the
//! tunnel is not inspected after that. A client that CONNECTs to an
//! allowlisted host and then presents a different SNI reaches
//! whatever the allowlisted host's address serves for that name.
//! Where a shared-IP CDN fronts both an allowed and a denied origin,
//! the allowlist is only as tight as that address. Closing this
//! would require terminating TLS in the proxy, which this design
//! deliberately does not do.

use std::collections::BTreeMap;
use std::sync::Arc;

use wirken_audit::{
    OwnSession, SandboxEgressDenyReason, SandboxEgressModeLabel, SessionEvent, SessionHandle,
    SessionLog, TrustLevel,
};
use wirken_gateway::agent_config::ChannelEgress;

use crate::skill_perms::{AllowSet, host_in_set};
use crate::tool::ReadSensitivity;

// The proxy itself, and the rules every request is held to whatever
// the policy, are shared with contained MCP servers.
#[cfg(unix)]
pub use wirken_sandbox::egress::run_sidecar;
pub use wirken_sandbox::egress::{
    DecisionReply, DecisionRequest, RequestKind, SIDECAR_HELLO, Verdict, check_shape,
    is_global_unicast, is_ip_literal,
};

/// Operator-selected egress posture for one channel's sandboxed
/// `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxEgressMode {
    /// No egress. The container runs with `--network none` and no
    /// proxy is started. The default, and the posture any
    /// unrecognized or missing configuration resolves to.
    #[default]
    None,
    /// Egress limited to an operator-configured domain allowlist.
    Allowlist,
    /// Any host reachable, subject to the port, IP-literal, and
    /// address-range rules. Explicit operator configuration only;
    /// never a fallback.
    Open,
}

impl SandboxEgressMode {
    /// Parse a mode from config. Unknown, empty, and malformed
    /// values resolve to [`SandboxEgressMode::None`]: egress is the
    /// axis where a config typo must not widen reach, so this does
    /// not mirror `SandboxMode::from_str_config`'s fall-back-to-
    /// default behaviour.
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "allowlist" => Self::Allowlist,
            "open" => Self::Open,
            "none" | "" => Self::None,
            _ => {
                tracing::warn!("Unknown sandbox egress mode '{s}', denying all sandbox egress");
                Self::None
            }
        }
    }

    /// Stable label for config round-trips and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Allowlist => "allowlist",
            Self::Open => "open",
        }
    }

    /// Audit-crate mirror of this mode.
    pub fn label(self) -> SandboxEgressModeLabel {
        match self {
            Self::None => SandboxEgressModeLabel::None,
            Self::Allowlist => SandboxEgressModeLabel::Allowlist,
            Self::Open => SandboxEgressModeLabel::Open,
        }
    }

    /// Whether this mode needs a proxy and an internal network.
    /// `None` runs the container on `--network none` instead.
    pub fn needs_proxy(self) -> bool {
        matches!(self, Self::Allowlist | Self::Open)
    }
}

/// One channel's resolved egress policy.
#[derive(Debug, Clone, Default)]
pub struct SandboxEgressPolicy {
    pub mode: SandboxEgressMode,
    pub domains: AllowSet,
}

impl SandboxEgressPolicy {
    /// The deny-everything policy. What an absent, unreadable, or
    /// malformed configuration resolves to.
    pub fn denied() -> Self {
        Self {
            mode: SandboxEgressMode::None,
            domains: AllowSet::Set(Default::default()),
        }
    }

    /// Build an allowlist policy over `domains`.
    pub fn allowlist(domains: AllowSet) -> Self {
        Self {
            mode: SandboxEgressMode::Allowlist,
            domains,
        }
    }

    /// Resolve a stored `ChannelEgress` entry into an enforced
    /// policy. The gateway crate holds the stored shape as plain
    /// strings because the dependency runs agent → gateway, so the
    /// interpretation lives here.
    ///
    /// A `*` entry becomes a wildcard allowset, matching skill-side
    /// `egress.domains`. An unrecognized mode resolves to `none`.
    pub fn from_config(mode: &str, domains: &[String]) -> Self {
        let mode = SandboxEgressMode::from_str_config(mode);
        let domains = if domains.iter().any(|d| d == "*") {
            AllowSet::Wildcard
        } else {
            AllowSet::Set(domains.iter().cloned().collect())
        };
        Self { mode, domains }
    }

    /// Resolve the policy for `channel` from an agent's per-channel
    /// config map. A turn with no channel, or a channel with no
    /// entry, gets the deny posture: adding a channel without
    /// configuring egress never grants reach.
    pub fn for_channel(
        channel: Option<&str>,
        configured: &BTreeMap<String, ChannelEgress>,
    ) -> Self {
        let Some(channel) = channel else {
            return Self::denied();
        };
        match configured.get(channel) {
            Some(entry) => Self::from_config(&entry.mode, &entry.domains),
            None => Self::denied(),
        }
    }
}

/// Decide whether one request may proceed. Pure, so the policy can
/// be asserted without sockets.
///
/// Order is deliberate. Mode comes first so a `none` sandbox reports
/// one unambiguous reason rather than whichever structural rule
/// happened to trip. The structural rules follow, and the allowlist
/// is consulted last: a refusal that never reached the allowlist is
/// a different operator problem from a host that simply is not on
/// it.
pub fn check_target(
    policy: &SandboxEgressPolicy,
    host: &str,
    port: u16,
    kind: RequestKind,
) -> Result<(), SandboxEgressDenyReason> {
    if policy.mode == SandboxEgressMode::None {
        return Err(SandboxEgressDenyReason::ModeNone);
    }
    check_shape(host, port, kind)?;
    match policy.mode {
        SandboxEgressMode::Open => Ok(()),
        SandboxEgressMode::Allowlist => {
            if host_in_set(host, &policy.domains) {
                Ok(())
            } else {
                Err(SandboxEgressDenyReason::NotAllowed)
            }
        }
        // Handled above; repeated so a future mode addition is a
        // compile error rather than a silent allow.
        SandboxEgressMode::None => Err(SandboxEgressDenyReason::ModeNone),
    }
}

/// Where an audit row's identity fields come from. Populated when
/// the listener is bound, never from request content.
#[derive(Debug, Clone, Default)]
pub struct SandboxEgressAttribution {
    pub agent_id: String,
    pub channel: Option<String>,
    pub adapter_id: Option<String>,
    pub sender_id: Option<String>,
}

/// Audit sink for proxy denials, mirroring
/// [`crate::http_tool::HttpAuditCtx`].
#[derive(Clone)]
pub struct SandboxEgressAudit {
    pub log: Arc<dyn SessionLog>,
    pub handle: SessionHandle<OwnSession>,
}

/// Everything one listener needs to serve and account for a single
/// `exec` call.
/// The session's observed confidentiality labels, shared live with
/// the runtime rather than snapshotted.
///
/// Snapshotting would be wrong: labels accrue as tools run during a
/// turn, while the egress context is installed once per turn, so a
/// copy taken at turn start would answer for reads that had not
/// happened yet.
pub type ObservedSensitivity = Arc<std::sync::RwLock<std::collections::HashSet<ReadSensitivity>>>;

#[derive(Clone)]
pub struct SandboxEgressContext {
    pub policy: SandboxEgressPolicy,
    pub attribution: SandboxEgressAttribution,
    pub audit: Option<SandboxEgressAudit>,
    /// Confidentiality labels this session has observed.
    pub observed: ObservedSensitivity,
    /// Operator approval surface. `None` means no operator is
    /// reachable, which is the cron and headless-subagent case; a
    /// restricting label then refuses rather than waiting for an
    /// answer that cannot come.
    pub approval: Option<Arc<dyn crate::approval_gate::ApprovalGate>>,
}

impl SandboxEgressContext {
    /// Labels this session has observed that restrict egress, sorted
    /// for stable audit rows. Sorting is presentation only; the set
    /// carries no order.
    #[cfg(unix)]
    fn restricting_basis(&self) -> Vec<String> {
        let Ok(seen) = self.observed.read() else {
            // A poisoned lock means an unknown observation history.
            // Report the most restricting basis rather than an empty
            // one, so failure to read the set cannot read as "nothing
            // sensitive was seen".
            return vec![ReadSensitivity::Workspace.as_str().to_string()];
        };
        let mut basis: Vec<String> = seen
            .iter()
            .filter(|s| s.restricts_egress())
            .map(|s| s.as_str().to_string())
            .collect();
        basis.sort();
        basis
    }

    /// Record one request verdict, allow or deny, with the basis it
    /// was decided on.
    #[cfg(unix)]
    pub(crate) fn record_verdict(
        &self,
        host: &str,
        port: u16,
        allowed: bool,
        reason: Option<SandboxEgressDenyReason>,
        escalated: bool,
        basis: Vec<String>,
    ) {
        if !allowed {
            tracing::warn!(
                "sandbox egress denied: host={host} port={port} reason={reason:?} \
                 agent={} mode={} basis={basis:?}",
                self.attribution.agent_id,
                self.policy.mode.as_str(),
            );
        }
        let Some(audit) = &self.audit else {
            return;
        };
        let event = SessionEvent::SandboxEgressVerdict {
            host: host.to_string(),
            port,
            allowed,
            reason,
            mode: self.policy.mode.label(),
            sensitivity_basis: basis,
            escalated,
            agent_id: self.attribution.agent_id.clone(),
            channel: self.attribution.channel.clone(),
            adapter_id: self.attribution.adapter_id.clone(),
            sender_id: self.attribution.sender_id.clone(),
            mcp_server: None,
        };
        if let Err(e) = audit.log.append(&audit.handle, TrustLevel::System, event) {
            tracing::warn!("could not record sandbox egress verdict: {e}");
        }
    }

    /// Record that egress was configured on a platform with no broker
    /// transport, so the `exec` was refused. Not a request verdict.
    #[cfg(not(unix))]
    pub(crate) fn record_unsupported(&self) {
        tracing::warn!(
            "sandbox egress unsupported on this platform: agent={} mode={}",
            self.attribution.agent_id,
            self.policy.mode.as_str(),
        );
        let Some(audit) = &self.audit else {
            return;
        };
        let event = SessionEvent::SandboxEgressUnsupported {
            mode: self.policy.mode.label(),
            agent_id: self.attribution.agent_id.clone(),
            channel: self.attribution.channel.clone(),
            adapter_id: self.attribution.adapter_id.clone(),
            sender_id: self.attribution.sender_id.clone(),
        };
        if let Err(e) = audit.log.append(&audit.handle, TrustLevel::System, event) {
            tracing::warn!("could not record sandbox egress platform refusal: {e}");
        }
    }

    /// Decide a request that has already cleared [`check_target`],
    /// conditioning on what the session has read.
    ///
    /// No restricting label observed: allowed unchanged. Otherwise the
    /// verdict escalates, and what escalation means depends on the
    /// mode. `allowlist` has a set the operator authored, so the
    /// question "may this session still use it" is one an operator can
    /// answer, and it goes to them. `open` has no authored set to fall
    /// back to, so there is no non-arbitrary automatic answer and the
    /// request is refused.
    ///
    /// With no approval surface reachable, which is the cron and
    /// headless-subagent case, escalation refuses. Fail-closed is the
    /// right default for a tainted session asking for a destination
    /// with no operator present.
    #[cfg(unix)]
    async fn decide_with_sensitivity(&self, host: &str, port: u16) -> Verdict {
        let basis = self.restricting_basis();
        if basis.is_empty() {
            return Verdict {
                allowed: true,
                reason: None,
                escalated: false,
                basis,
            };
        }

        if self.policy.mode == SandboxEgressMode::Open {
            return Verdict {
                allowed: false,
                reason: Some(SandboxEgressDenyReason::SensitivityRefused),
                escalated: true,
                basis,
            };
        }

        let Some(gate) = &self.approval else {
            return Verdict {
                allowed: false,
                reason: Some(SandboxEgressDenyReason::SensitivityRefused),
                escalated: true,
                basis,
            };
        };

        // The operator is asked about the destination, at the tier a
        // network request already carries.
        let ctx = crate::error::PermissionDenialContext {
            tool_name: "sandbox_egress".to_string(),
            action: wirken_gateway::permissions::Action::NetworkRequest {
                domain: host.to_string(),
            },
            requested_tier: wirken_gateway::permissions::PermissionTier::Tier3,
            agent_id: self.attribution.agent_id.clone(),
            session_id: self
                .audit
                .as_ref()
                .map(|a| a.handle.id().to_string())
                .unwrap_or_default(),
            trigger_message: Some(format!(
                "sandbox egress to {host}:{port} after reading {}",
                basis.join(", ")
            )),
            // No tool call: what is being approved is the
            // destination, which the action already names.
            arguments: None,
            assistant_text: None,
            exec_location: None,
        };
        let approved = matches!(
            gate.request_approval(&ctx).await,
            crate::approval_gate::ApprovalOutcome::Approved { .. }
        );
        Verdict {
            allowed: approved,
            reason: (!approved).then_some(SandboxEgressDenyReason::SensitivityRefused),
            escalated: true,
            basis,
        }
    }
}

/// The channel policy first, then what the session has read. A
/// structural refusal is decided before confidentiality is consulted,
/// so its row carries the basis but did not escalate.
#[cfg(unix)]
#[async_trait::async_trait]
impl wirken_sandbox::egress::EgressDecider for SandboxEgressContext {
    async fn decide(&self, host: &str, port: u16, kind: RequestKind) -> Verdict {
        if let Err(reason) = check_target(&self.policy, host, port, kind) {
            return Verdict {
                basis: self.restricting_basis(),
                ..Verdict::deny(reason)
            };
        }
        self.decide_with_sensitivity(host, port).await
    }

    fn record(&self, host: &str, port: u16, verdict: &Verdict) {
        self.record_verdict(
            host,
            port,
            verdict.allowed,
            verdict.reason,
            verdict.escalated,
            verdict.basis.clone(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn allowlist(hosts: &[&str]) -> SandboxEgressPolicy {
        SandboxEgressPolicy::allowlist(AllowSet::Set(
            hosts.iter().map(|h| h.to_string()).collect::<BTreeSet<_>>(),
        ))
    }

    #[test]
    fn default_mode_is_none() {
        assert_eq!(SandboxEgressMode::default(), SandboxEgressMode::None);
        assert_eq!(SandboxEgressPolicy::default().mode, SandboxEgressMode::None);
    }

    #[test]
    fn unknown_mode_denies_rather_than_defaulting_open() {
        assert_eq!(
            SandboxEgressMode::from_str_config("allow-all"),
            SandboxEgressMode::None
        );
        assert_eq!(
            SandboxEgressMode::from_str_config(""),
            SandboxEgressMode::None
        );
    }

    #[test]
    fn mode_none_denies_even_an_allowlisted_host() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::None,
            domains: AllowSet::Wildcard,
        };
        assert_eq!(
            check_target(&policy, "example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::ModeNone)
        );
    }

    #[test]
    fn allowlisted_host_on_443_passes() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Ok(())
        );
    }

    #[test]
    fn unlisted_host_denied() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "evil.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn wildcard_suffix_matches_like_skill_egress() {
        let policy = allowlist(&["*.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn ip_literal_denied_even_when_allowlisted_verbatim() {
        let policy = allowlist(&["93.184.216.34"]);
        assert_eq!(
            check_target(&policy, "93.184.216.34", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
    }

    #[test]
    fn ip_literal_denied_under_open_mode() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::Open,
            domains: AllowSet::Wildcard,
        };
        assert_eq!(
            check_target(&policy, "169.254.169.254", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
        assert_eq!(
            check_target(&policy, "[::1]", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
    }

    #[test]
    fn connect_restricted_to_443() {
        let policy = allowlist(&["api.example.com"]);
        for port in [22u16, 80, 8080, 3306] {
            assert_eq!(
                check_target(&policy, "api.example.com", port, RequestKind::Connect),
                Err(SandboxEgressDenyReason::PortNotAllowed),
                "port {port} must not tunnel"
            );
        }
    }

    #[test]
    fn plain_http_restricted_to_80() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 80, RequestKind::Plain),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "api.example.com", 8080, RequestKind::Plain),
            Err(SandboxEgressDenyReason::PortNotAllowed)
        );
    }

    #[test]
    fn open_mode_allows_any_name_but_still_bounds_port() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::Open,
            domains: AllowSet::Set(BTreeSet::new()),
        };
        assert_eq!(
            check_target(&policy, "anything.example.com", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "anything.example.com", 22, RequestKind::Connect),
            Err(SandboxEgressDenyReason::PortNotAllowed)
        );
    }

    #[test]
    fn unconfigured_channel_resolves_to_deny() {
        let configured = BTreeMap::new();
        let policy = SandboxEgressPolicy::for_channel(Some("slack"), &configured);
        assert_eq!(policy.mode, SandboxEgressMode::None);
        assert!(!policy.mode.needs_proxy());
    }

    #[test]
    fn turn_with_no_channel_resolves_to_deny() {
        let mut configured = BTreeMap::new();
        configured.insert(
            "slack".to_string(),
            ChannelEgress {
                mode: "open".to_string(),
                domains: vec![],
            },
        );
        // A cron or CLI turn carries no channel and must not inherit
        // another channel's reach.
        let policy = SandboxEgressPolicy::for_channel(None, &configured);
        assert_eq!(policy.mode, SandboxEgressMode::None);
    }

    #[test]
    fn each_channel_gets_only_its_own_allowlist() {
        let mut configured = BTreeMap::new();
        configured.insert(
            "slack".to_string(),
            ChannelEgress {
                mode: "allowlist".to_string(),
                domains: vec!["slack-ok.example".to_string()],
            },
        );
        configured.insert(
            "signal".to_string(),
            ChannelEgress {
                mode: "allowlist".to_string(),
                domains: vec!["signal-ok.example".to_string()],
            },
        );

        let slack = SandboxEgressPolicy::for_channel(Some("slack"), &configured);
        assert_eq!(
            check_target(&slack, "slack-ok.example", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&slack, "signal-ok.example", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed),
            "one channel's allowlist must not leak into another's"
        );
    }

    #[test]
    fn wildcard_entry_becomes_a_wildcard_allowset() {
        let policy = SandboxEgressPolicy::from_config("allowlist", &["*".to_string()]);
        assert!(matches!(policy.domains, AllowSet::Wildcard));
        assert_eq!(
            check_target(&policy, "anything.example", 443, RequestKind::Connect),
            Ok(())
        );
    }

    #[test]
    fn allowlist_mode_with_no_domains_denies_everything() {
        let policy = SandboxEgressPolicy::from_config("allowlist", &[]);
        assert_eq!(policy.mode, SandboxEgressMode::Allowlist);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn unknown_stored_mode_resolves_to_deny_not_to_its_domains() {
        // A mode string a newer build wrote must not be honoured as
        // an allowlist by an older one.
        let policy = SandboxEgressPolicy::from_config("permissive", &["api.example.com".into()]);
        assert_eq!(policy.mode, SandboxEgressMode::None);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::ModeNone)
        );
    }

    #[test]
    fn only_allowlist_and_open_provision_a_proxy() {
        assert!(!SandboxEgressMode::None.needs_proxy());
        assert!(SandboxEgressMode::Allowlist.needs_proxy());
        assert!(SandboxEgressMode::Open.needs_proxy());
    }
}
