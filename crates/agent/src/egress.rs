//! Egress allowlist enforcement at the HTTP transport layer.
//!
//! [`EgressClient`] wraps `reqwest::Client` and refuses requests whose host
//! is not in the agent's effective `permissions.egress.domains` allow-set.
//! The check is host-based, pre-flight, and runs before any TCP connection
//! is opened — denied hosts cost zero bytes on the wire.
//!
//! ## Layering with future rate limiting
//!
//! Per the design discussion under #76 (the rescoped permissions block),
//! a future per-host rate limiter ("Zirkel's `RateLimitedClient`") sits
//! *between* this client and `reqwest::Client`, NOT outside it:
//!
//! ```text
//! caller → EgressClient → RateLimitedClient → reqwest::Client
//! ```
//!
//! This ordering matters: a request to a denied host short-circuits at
//! the egress check and never enters the rate-limit budget. Reversing
//! the layers would have rate-limit accounting paying for requests
//! that egress was always going to deny.
//!
//! When `RateLimitedClient` lands, this module's `inner` field becomes
//! the rate-limited transport; the public surface (the `get`/`post`
//! methods) is unchanged.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use reqwest::RequestBuilder;
use thiserror::Error;

use crate::skill_perms::{AllowSet, EffectiveProfile, EgressMode};

/// What the wrapper enforces. Computed by [`Agent::attach_skills`] from
/// the effective permission profile and pushed into the client via
/// [`EgressClient::set_enforcement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressEnforcement {
    /// Bypass — no checking. Used in `EffectiveProfile::Legacy` and as
    /// the initial state before any skills are attached.
    Unrestricted,
    /// Reject everything. Used when the resolved profile is
    /// `egress.mode = deny`.
    DenyAll,
    /// Allow exactly these hosts. Each entry is matched literally
    /// (`api.example.com`) or as a leading-wildcard label
    /// (`*.example.com`). The literal `"*"` global wildcard
    /// short-circuits to allow-all.
    Allowlist(BTreeSet<String>),
    /// Global wildcard — allow any host. Used when an attached skill
    /// declares `egress.domains: ["*"]` (and merge yields wildcard).
    AllowAll,
}

impl EgressEnforcement {
    pub fn from_profile(p: &EffectiveProfile) -> Self {
        match p {
            EffectiveProfile::Legacy => EgressEnforcement::Unrestricted,
            EffectiveProfile::Resolved(prof) => match prof.egress.mode {
                EgressMode::Deny => EgressEnforcement::DenyAll,
                EgressMode::Allowlist => match &prof.egress.domains {
                    AllowSet::Wildcard => EgressEnforcement::AllowAll,
                    AllowSet::Set(s) => EgressEnforcement::Allowlist(s.clone()),
                },
            },
        }
    }

    fn allows(&self, host: &str) -> bool {
        match self {
            EgressEnforcement::Unrestricted | EgressEnforcement::AllowAll => true,
            EgressEnforcement::DenyAll => false,
            EgressEnforcement::Allowlist(set) => set.iter().any(|pat| host_matches(host, pat)),
        }
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.")
        && let Some(idx) = host.find('.')
    {
        return &host[idx + 1..] == suffix;
    }
    false
}

/// Pre-flight host check around `reqwest::Client`. The wrapper holds
/// the enforcement policy in shared state so the agent can update it
/// after attaching skills without rebuilding the client.
#[derive(Clone)]
pub struct EgressClient {
    inner: reqwest::Client,
    enforcement: Arc<RwLock<EgressEnforcement>>,
}

impl EgressClient {
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::new(),
            enforcement: Arc::new(RwLock::new(EgressEnforcement::Unrestricted)),
        }
    }

    /// Replace the enforcement policy. Called by the agent at
    /// `attach_skills` time after computing the effective profile.
    pub fn set_enforcement(&self, e: EgressEnforcement) {
        if let Ok(mut guard) = self.enforcement.write() {
            *guard = e;
        }
    }

    /// Pre-flight check: extract host from `url`, return `Err` if not
    /// allowed. Caller must use the returned `RequestBuilder` rather
    /// than constructing one against the inner client.
    pub fn get(&self, url: &str) -> Result<RequestBuilder, EgressDenied> {
        self.check(url)?;
        Ok(self.inner.get(url))
    }

    pub fn post(&self, url: &str) -> Result<RequestBuilder, EgressDenied> {
        self.check(url)?;
        Ok(self.inner.post(url))
    }

    fn check(&self, url: &str) -> Result<(), EgressDenied> {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .ok_or_else(|| EgressDenied {
                host: format!("<unparseable url: {url}>"),
            })?;
        let guard = self
            .enforcement
            .read()
            .map_err(|_| EgressDenied { host: host.clone() })?;
        if guard.allows(&host) {
            Ok(())
        } else {
            Err(EgressDenied { host })
        }
    }
}

impl Default for EgressClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error(
    "egress denied: host '{host}' is not in the agent's effective skill permissions egress allow-set"
)]
pub struct EgressDenied {
    pub host: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill_perms::{AllowSet, EgressMode, EgressPolicy, PermissionProfile};

    fn profile_with_egress(mode: EgressMode, domains: AllowSet) -> PermissionProfile {
        PermissionProfile {
            egress: EgressPolicy { mode, domains },
            ..Default::default()
        }
    }

    #[test]
    fn legacy_profile_is_unrestricted() {
        let e = EgressEnforcement::from_profile(&EffectiveProfile::Legacy);
        assert_eq!(e, EgressEnforcement::Unrestricted);
        assert!(e.allows("anything.example.com"));
    }

    #[test]
    fn resolved_deny_mode_blocks_all() {
        let p = profile_with_egress(EgressMode::Deny, AllowSet::default());
        let e = EgressEnforcement::from_profile(&EffectiveProfile::Resolved(p));
        assert_eq!(e, EgressEnforcement::DenyAll);
        assert!(!e.allows("foo.com"));
    }

    #[test]
    fn resolved_wildcard_allows_anything() {
        let p = profile_with_egress(EgressMode::Allowlist, AllowSet::Wildcard);
        let e = EgressEnforcement::from_profile(&EffectiveProfile::Resolved(p));
        assert_eq!(e, EgressEnforcement::AllowAll);
        assert!(e.allows("anything.example.com"));
    }

    #[test]
    fn resolved_specific_allowlist_matches_literal() {
        let mut domains = BTreeSet::new();
        domains.insert("api.example.com".to_string());
        let p = profile_with_egress(EgressMode::Allowlist, AllowSet::Set(domains));
        let e = EgressEnforcement::from_profile(&EffectiveProfile::Resolved(p));
        assert!(e.allows("api.example.com"));
        assert!(!e.allows("other.example.com"));
    }

    #[test]
    fn resolved_specific_allowlist_matches_wildcard_label() {
        let mut domains = BTreeSet::new();
        domains.insert("*.example.com".to_string());
        let p = profile_with_egress(EgressMode::Allowlist, AllowSet::Set(domains));
        let e = EgressEnforcement::from_profile(&EffectiveProfile::Resolved(p));
        assert!(e.allows("api.example.com"));
        assert!(e.allows("foo.example.com"));
        assert!(!e.allows("example.com"));
        assert!(!e.allows("api.other.com"));
    }

    #[test]
    fn client_get_denies_when_host_not_allowed() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        let err = c.get("https://denied.example.com/foo").unwrap_err();
        assert_eq!(err.host, "denied.example.com");
    }

    #[test]
    fn client_get_allows_when_host_is_in_allowlist() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        assert!(c.get("https://allowed.example.com/foo").is_ok());
    }

    #[test]
    fn client_default_state_is_unrestricted() {
        let c = EgressClient::new();
        assert!(c.get("https://anywhere.example.com/foo").is_ok());
    }

    #[test]
    fn unparseable_url_is_denied() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "ok.example.com".to_string(),
        ])));
        let err = c.get("not a url").unwrap_err();
        assert!(err.host.starts_with("<unparseable"));
    }
}
