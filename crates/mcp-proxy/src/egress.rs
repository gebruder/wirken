//! Egress for contained stdio MCP servers.
//!
//! A server whose `sandbox` block lists `egress.hosts` gets the route
//! `exec` gets: an internal network shared only with its own sidecar,
//! the sidecar as its HTTP(S) proxy, and a broker in this process that
//! decides each request against the listed hosts, resolves the name,
//! and records the verdict. A server that lists none has no network.
//!
//! The hosts are part of the signed entry, so widening them breaks the
//! signature. Every verdict is a `SandboxEgressVerdict` row on the
//! `gateway-mcp` session naming the agent and the server.

use std::sync::Arc;

use wirken_audit::{
    SandboxEgressDenyReason, SandboxEgressModeLabel, SessionEvent, SessionId, SessionLog,
    TrustLevel,
};
use wirken_sandbox::egress::{
    EgressDecider, RequestKind, Verdict, check_shape, host_matches, is_ip_literal,
};

use crate::mcp_registry::MCP_SENTINEL_SESSION;

/// The bare wildcard: any domain name, still held to the port,
/// address-literal and global-unicast rules.
const ANY_HOST: &str = "*";

/// Check one `egress.hosts` entry: a domain name, `*.` and a domain
/// name, or `*`. Addresses are refused, since the proxy never connects
/// to one by literal.
pub fn check_host_pattern(pattern: &str) -> Result<(), String> {
    if pattern == ANY_HOST {
        return Ok(());
    }
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    if is_ip_literal(name) {
        return Err(format!(
            "egress.hosts entry {pattern:?} is an address; only domain names are allowed"
        ));
    }
    let labels_ok = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if labels_ok {
        Ok(())
    } else {
        Err(format!(
            "egress.hosts entry {pattern:?} is not a domain name, *.<domain>, or *"
        ))
    }
}

/// One contained server's egress policy and audit sink.
pub struct McpEgressPolicy {
    pub agent_id: String,
    pub server: String,
    /// The entry's `egress.hosts`, already checked.
    pub hosts: Vec<String>,
    pub audit: Option<Arc<dyn SessionLog>>,
}

impl McpEgressPolicy {
    /// `open` when `*` is listed, `allowlist` otherwise.
    fn mode(&self) -> SandboxEgressModeLabel {
        if self.hosts.iter().any(|h| h == ANY_HOST) {
            SandboxEgressModeLabel::Open
        } else {
            SandboxEgressModeLabel::Allowlist
        }
    }

    /// The verdict on one request, without resolution.
    pub fn check(&self, host: &str, port: u16, kind: RequestKind) -> Verdict {
        if let Err(reason) = check_shape(host, port, kind) {
            return Verdict::deny(reason);
        }
        let listed = self
            .hosts
            .iter()
            .any(|p| p == ANY_HOST || host_matches(host, p));
        if listed {
            Verdict::allow()
        } else {
            Verdict::deny(SandboxEgressDenyReason::NotAllowed)
        }
    }
}

#[async_trait::async_trait]
impl EgressDecider for McpEgressPolicy {
    async fn decide(&self, host: &str, port: u16, kind: RequestKind) -> Verdict {
        self.check(host, port, kind)
    }

    fn record(&self, host: &str, port: u16, verdict: &Verdict) {
        if !verdict.allowed {
            tracing::warn!(
                agent_id = %self.agent_id,
                server = %self.server,
                "MCP server egress denied: host={host} port={port} reason={:?}",
                verdict.reason,
            );
        }
        let Some(log) = &self.audit else {
            return;
        };
        let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
        let event = SessionEvent::SandboxEgressVerdict {
            host: host.to_string(),
            port,
            allowed: verdict.allowed,
            reason: verdict.reason,
            mode: self.mode(),
            sensitivity_basis: verdict.basis.clone(),
            escalated: verdict.escalated,
            agent_id: self.agent_id.clone(),
            channel: None,
            adapter_id: None,
            sender_id: None,
            mcp_server: Some(self.server.clone()),
        };
        if let Err(e) = log.append(&handle, TrustLevel::System, event) {
            tracing::warn!("could not record MCP server egress verdict: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hosts: &[&str]) -> McpEgressPolicy {
        McpEgressPolicy {
            agent_id: "agent-1".into(),
            server: "github".into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            audit: None,
        }
    }

    #[test]
    fn host_patterns_are_names_suffixes_or_the_wildcard() {
        for ok in [
            "api.github.com",
            "*.github.com",
            "*",
            "localhost",
            "a-b.example",
        ] {
            assert!(check_host_pattern(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "1.2.3.4",
            "[::1]",
            "*.1.2.3.4",
            "api.github.com:443",
            "https://api.github.com",
            "a..b",
            "*github.com",
            "api.*.com",
            " api.github.com",
        ] {
            assert!(check_host_pattern(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_listed_hosts_pass() {
        let p = policy(&["api.github.com", "*.githubusercontent.com"]);
        assert_eq!(
            p.check("api.github.com", 443, RequestKind::Connect),
            Verdict::allow()
        );
        assert_eq!(
            p.check("raw.githubusercontent.com", 443, RequestKind::Connect),
            Verdict::allow()
        );
        assert_eq!(
            p.check("evil.example.com", 443, RequestKind::Connect),
            Verdict::deny(SandboxEgressDenyReason::NotAllowed)
        );
        assert_eq!(
            p.check("github.com", 443, RequestKind::Connect),
            Verdict::deny(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn the_wildcard_still_holds_the_shape_rules() {
        let p = policy(&["*"]);
        assert_eq!(p.mode(), SandboxEgressModeLabel::Open);
        assert_eq!(
            p.check("anything.example", 443, RequestKind::Connect),
            Verdict::allow()
        );
        assert_eq!(
            p.check("169.254.169.254", 443, RequestKind::Connect),
            Verdict::deny(SandboxEgressDenyReason::IpLiteral)
        );
        assert_eq!(
            p.check("anything.example", 22, RequestKind::Connect),
            Verdict::deny(SandboxEgressDenyReason::PortNotAllowed)
        );
        assert_eq!(
            policy(&["a.example"]).mode(),
            SandboxEgressModeLabel::Allowlist
        );
    }

    #[test]
    fn a_verdict_row_names_the_agent_and_server_on_the_mcp_session() {
        let log: Arc<dyn SessionLog> =
            Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap());
        let p = McpEgressPolicy {
            audit: Some(log.clone()),
            ..policy(&["api.github.com"])
        };
        p.record(
            "evil.example.com",
            443,
            &Verdict::deny(SandboxEgressDenyReason::NotAllowed),
        );
        let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
        let events: Vec<_> = log
            .get_since(&handle, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.event)
            .collect();
        assert_eq!(
            events,
            [SessionEvent::SandboxEgressVerdict {
                host: "evil.example.com".into(),
                port: 443,
                allowed: false,
                reason: Some(SandboxEgressDenyReason::NotAllowed),
                mode: SandboxEgressModeLabel::Allowlist,
                sensitivity_basis: Vec::new(),
                escalated: false,
                agent_id: "agent-1".into(),
                channel: None,
                adapter_id: None,
                sender_id: None,
                mcp_server: Some("github".into()),
            }]
        );
    }
}
