//! Egress allowlist enforcement at the HTTP transport layer.
//!
//! [`EgressClient`] is the outer transport wrapper:
//!
//! ```text
//! caller → EgressClient → RateLimitedClient → reqwest::Client
//! ```
//!
//! The egress check runs first — host-based, pre-flight, before any
//! TCP connection. Denied hosts cost zero bytes on the wire AND zero
//! against the rate-limit budget. Only after the egress check passes
//! does the request enter [`crate::rate_limit::RateLimitedClient`],
//! where per-host daily caps and inter-request jitter are enforced
//! before the underlying `reqwest::Client` actually issues bytes.
//!
//! Reversing the layers would have rate-limit accounting paying for
//! requests egress was always going to deny.
//!
//! ## Two construction shapes
//!
//! - [`EgressClient::new`] — unrestricted rate limit (cap = u32::MAX,
//!   no jitter). Used by the agent's tool registry where the LLM
//!   drives `web_search` / `generate_image` ad hoc; there is no
//!   daily-budget concept for chat-time tools.
//! - [`EgressClient::with_rate_limit`] — caller supplies a
//!   [`crate::rate_limit::RateLimitConfig`]. Used by the daily-fetch
//!   orchestrator (Zirkel's `wirken zirkel run`) where the budget is
//!   real and per-source.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use reqwest::RequestBuilder;
use thiserror::Error;

use crate::rate_limit::{RateLimitConfig, RateLimitDenied, RateLimitedClient};
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

/// Pre-flight host check around the inner [`RateLimitedClient`]. The
/// wrapper holds the enforcement policy in shared state so the agent
/// can update it after attaching skills without rebuilding the client.
#[derive(Clone)]
pub struct EgressClient {
    inner: RateLimitedClient,
    enforcement: Arc<RwLock<EgressEnforcement>>,
}

impl EgressClient {
    /// Construct with an unrestricted rate limit (no daily cap, no
    /// jitter). Used by the agent's tool registry where chat-time
    /// LLM-driven HTTP calls have no daily-budget concept.
    pub fn new() -> Self {
        Self::with_rate_limit(RateLimitConfig::unrestricted_for_tests())
    }

    /// Construct with a caller-supplied rate-limit config. Used by the
    /// daily-fetch orchestrator (Zirkel's `wirken zirkel run`) so each
    /// source's per-day cap is honored at the transport layer.
    pub fn with_rate_limit(config: RateLimitConfig) -> Self {
        Self {
            inner: RateLimitedClient::new(reqwest::Client::new(), config),
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
    /// allowed (egress) or if the rate-limit budget is exhausted.
    /// Caller must use the returned `RequestBuilder` rather than
    /// constructing one against the inner client.
    ///
    /// Async because the inner [`RateLimitedClient`] sleeps on
    /// inter-request jitter when configured. With the unrestricted
    /// rate-limit config (the agent default) jitter is zero and the
    /// call returns synchronously without yielding.
    pub async fn get(&self, url: &str) -> Result<RequestBuilder, HttpAccessDenied> {
        self.check_egress(url).map_err(HttpAccessDenied::Egress)?;
        self.inner
            .get(url)
            .await
            .map_err(HttpAccessDenied::RateLimit)
    }

    pub async fn post(&self, url: &str) -> Result<RequestBuilder, HttpAccessDenied> {
        self.check_egress(url).map_err(HttpAccessDenied::Egress)?;
        self.inner
            .post(url)
            .await
            .map_err(HttpAccessDenied::RateLimit)
    }

    fn check_egress(&self, url: &str) -> Result<(), EgressDenied> {
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

/// Unified result for [`EgressClient`] gating. The two variants
/// distinguish which layer rejected the request — egress allowlist
/// (outer, runs first) or rate-limit budget (inner, only consulted
/// after egress passes).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpAccessDenied {
    #[error(transparent)]
    Egress(#[from] EgressDenied),
    #[error(transparent)]
    RateLimit(#[from] RateLimitDenied),
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

    #[tokio::test]
    async fn client_get_denies_when_host_not_allowed() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        let err = c.get("https://denied.example.com/foo").await.unwrap_err();
        assert!(matches!(
            err,
            HttpAccessDenied::Egress(EgressDenied { ref host }) if host == "denied.example.com"
        ));
    }

    #[tokio::test]
    async fn client_get_allows_when_host_is_in_allowlist() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        assert!(c.get("https://allowed.example.com/foo").await.is_ok());
    }

    #[tokio::test]
    async fn client_default_state_is_unrestricted() {
        let c = EgressClient::new();
        assert!(c.get("https://anywhere.example.com/foo").await.is_ok());
    }

    #[tokio::test]
    async fn unparseable_url_is_denied() {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "ok.example.com".to_string(),
        ])));
        let err = c.get("not a url").await.unwrap_err();
        assert!(matches!(
            err,
            HttpAccessDenied::Egress(EgressDenied { ref host }) if host.starts_with("<unparseable")
        ));
    }

    /// Layering correctness: a request to a denied host must fail at
    /// the egress check WITHOUT consuming rate-limit budget. Named
    /// to match `EgressDenied` so future readers grep this when
    /// investigating layering questions.
    #[tokio::test]
    async fn egress_denied_does_not_consume_rate_budget() {
        // Cap of 2 on the inner rate limiter so we can detect any
        // accounting that escaped the egress short-circuit.
        let c = EgressClient::with_rate_limit(RateLimitConfig {
            default_daily_cap: 2,
            jitter_min: std::time::Duration::ZERO,
            jitter_max: std::time::Duration::ZERO,
            ..Default::default()
        });
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));

        // Three rejected requests to a non-allowlisted host. None
        // should consume budget — otherwise the cap would be hit
        // before the legitimate request below.
        for _ in 0..3 {
            let err = c.get("https://denied.example.com/x").await.unwrap_err();
            assert!(matches!(err, HttpAccessDenied::Egress(_)));
        }

        // Allowed host: should succeed twice, then hit the cap.
        assert!(c.get("https://allowed.example.com/a").await.is_ok());
        assert!(c.get("https://allowed.example.com/b").await.is_ok());
        let err = c.get("https://allowed.example.com/c").await.unwrap_err();
        assert!(matches!(err, HttpAccessDenied::RateLimit(_)));
    }
}
