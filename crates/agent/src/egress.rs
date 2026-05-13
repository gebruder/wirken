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
//! ## What `EgressClient` covers — and what it does not
//!
//! `EgressClient` mediates only the agent built-in tools that go
//! through it: `web_search` and `generate_image`. The following
//! outbound paths bypass `EgressClient` and do **not** consult the
//! skill-set egress allowlist:
//!
//! - **`exec` shell sink.** When `sandbox.json` is `mode: off`, the
//!   host shell runs `curl`, `wget`, `nc`, etc. directly. Egress is
//!   determined by the OS, not by wirken.
//! - **MCP children.** MCP servers spawned by the proxy open their
//!   own outbound network connections.
//! - **LLM HTTP.** The LLM client constructs its own `reqwest::Client`
//!   so the agent can keep talking to the configured provider even
//!   when the operator's egress rules are tight; provider host is
//!   gated by name (`provider.json::base_url`) but not by the egress
//!   allowlist.
//!
//! Operators wanting hard egress control should run wirken inside a
//! network namespace, container with restricted egress, or with
//! iptables/firewall rules at the OS level. The skill-side
//! `egress.domains` list is a defense-in-depth control on the
//! built-in tools, not a network boundary.
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
use std::fmt;
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

/// A phase-deny overlay pushed onto the [`EgressClient`] by the
/// per-pass deny mechanism. The check path consults this BEFORE the
/// base [`EgressEnforcement`], so a phase that denies a host
/// short-circuits even when the base profile would have allowed it.
/// Closes the egress-axis coverage gap that the original slice-2
/// commit message flagged: `PhaseAxis::EgressHost` was type-prepared
/// but the runtime gate didn't consult the overlay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseEgressDeny {
    /// Operator-readable label from the active phase; surfaced on
    /// the [`EgressDenyReason::Phase`] reason that bubbles up to the
    /// audit chain.
    pub phase_name: String,
    /// Hosts the overlay refuses. Matched with the same exact /
    /// wildcard-label semantics as [`EgressEnforcement::Allowlist`].
    pub hosts: BTreeSet<String>,
}

/// Which layer of the egress gate refused a request. Carried on
/// [`EgressDenied`] so the runtime can emit the matching typed
/// `SkillDeniedReason` (`Profile` vs `Phase { phase_name }`) on the
/// `SkillPermissionDenied` audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDenyReason {
    /// Base permission profile refused the host (the pre-slice-6
    /// shape). Pre-slice-6 audit rows that did not carry a reason
    /// field deserialize as this via the audit-side default.
    Profile,
    /// Active phase deny overlay refused the host. `phase_name`
    /// flows into the audit event for SIEM correlation with the
    /// triggering `PhaseEntered` row.
    Phase { phase_name: String },
}

/// Pre-flight host check around the inner [`RateLimitedClient`]. The
/// wrapper holds the enforcement policy in shared state so the agent
/// can update it after attaching skills without rebuilding the client.
///
/// Slice 6 of the per-pass deny overlay adds a second `Arc<RwLock<_>>`
/// holding the optional phase overlay deny. The check path consults
/// the overlay first, then the base enforcement; transitions
/// (`enter_phase`, `exit_phase`, turn-end auto-clear, wake-replay)
/// push the overlay state via [`Self::set_phase_overlay_deny`] /
/// [`Self::clear_phase_overlay_deny`].
#[derive(Clone)]
pub struct EgressClient {
    inner: RateLimitedClient,
    enforcement: Arc<RwLock<EgressEnforcement>>,
    overlay_deny: Arc<RwLock<Option<PhaseEgressDeny>>>,
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
            overlay_deny: Arc::new(RwLock::new(None)),
        }
    }

    /// Replace the enforcement policy. Called by the agent at
    /// `attach_skills` time after computing the effective profile.
    pub fn set_enforcement(&self, e: EgressEnforcement) {
        if let Ok(mut guard) = self.enforcement.write() {
            *guard = e;
        }
    }

    /// Slice-6 phase-overlay setter. Called by the runtime's phase
    /// intercepts (`wirken_enter_phase`) and the wake-replay path
    /// after `Agent::enter_phase` or `Agent::restore_phase_overlay`
    /// successfully installs an overlay. The overlay is consulted
    /// BEFORE the base enforcement in [`Self::check_egress`], so a
    /// phase that denies a host short-circuits even when the base
    /// profile would have allowed it.
    pub fn set_phase_overlay_deny(&self, deny: PhaseEgressDeny) {
        if let Ok(mut guard) = self.overlay_deny.write() {
            *guard = Some(deny);
        }
    }

    /// Slice-6 phase-overlay clear. Called by the runtime's
    /// `wirken_exit_phase` intercept, the turn-end auto-clear, and
    /// any wake-replay that ends with no active phase. A no-op when
    /// no overlay is currently installed.
    pub fn clear_phase_overlay_deny(&self) {
        if let Ok(mut guard) = self.overlay_deny.write() {
            *guard = None;
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
                reason: EgressDenyReason::Profile,
            })?;
        // Slice 6: overlay deny first. A phase-installed deny entry
        // short-circuits even when the base enforcement would have
        // allowed the host, and surfaces a `Phase` reason so the
        // runtime emits `SkillDeniedReason::Phase { phase_name }` on
        // the audit row instead of `Profile`.
        if let Ok(overlay) = self.overlay_deny.read()
            && let Some(deny) = overlay.as_ref()
            && deny.hosts.iter().any(|pat| host_matches(&host, pat))
        {
            return Err(EgressDenied {
                host,
                reason: EgressDenyReason::Phase {
                    phase_name: deny.phase_name.clone(),
                },
            });
        }
        let guard = self.enforcement.read().map_err(|_| EgressDenied {
            host: host.clone(),
            reason: EgressDenyReason::Profile,
        })?;
        if guard.allows(&host) {
            Ok(())
        } else {
            Err(EgressDenied {
                host,
                reason: EgressDenyReason::Profile,
            })
        }
    }
}

impl Default for EgressClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Egress refused by [`EgressClient::check_egress`]. `reason`
/// distinguishes the base profile path from the phase-overlay path
/// so the runtime audit emit can stamp the correct
/// `SkillDeniedReason` on the `SkillPermissionDenied` row. Manual
/// `Display` impl because the message text differs by reason and
/// the `#[error(...)]` shorthand does not branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenied {
    pub host: String,
    pub reason: EgressDenyReason,
}

impl std::error::Error for EgressDenied {}

impl fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            EgressDenyReason::Profile => write!(
                f,
                "egress denied: host '{}' is not in the agent's effective skill permissions egress allow-set",
                self.host,
            ),
            EgressDenyReason::Phase { phase_name } => write!(
                f,
                "egress denied: host '{}' is denied by active phase '{}'",
                self.host, phase_name,
            ),
        }
    }
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
            HttpAccessDenied::Egress(EgressDenied { ref host, .. }) if host == "denied.example.com"
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
            HttpAccessDenied::Egress(EgressDenied { ref host, .. }) if host.starts_with("<unparseable")
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

    // ---------------------------------------------------------------
    // Phase overlay deny (slice 6 of per-pass deny overlay)
    // ---------------------------------------------------------------

    fn overlay_denying(phase: &str, host: &str) -> PhaseEgressDeny {
        let mut hosts = BTreeSet::new();
        hosts.insert(host.to_string());
        PhaseEgressDeny {
            phase_name: phase.to_string(),
            hosts,
        }
    }

    #[tokio::test]
    async fn overlay_denies_host_with_phase_reason() {
        // Base is Unrestricted; overlay denies one host. The host
        // should refuse with reason=Phase even though the base
        // would have allowed.
        let c = EgressClient::new();
        c.set_phase_overlay_deny(overlay_denying("scoring", "api.openai.com"));

        let err = c.get("https://api.openai.com/v1/x").await.unwrap_err();
        match err {
            HttpAccessDenied::Egress(d) => {
                assert_eq!(d.host, "api.openai.com");
                assert_eq!(
                    d.reason,
                    EgressDenyReason::Phase {
                        phase_name: "scoring".to_string(),
                    },
                );
            }
            other => panic!("expected Egress denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlay_does_not_match_falls_through_to_base_with_profile_reason() {
        // Overlay denies `denied.example.com`; base also denies
        // anything not on its allowlist. A call to a different
        // refused host (`other.example.com`) should surface a
        // `Profile` reason because the overlay did not match.
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        c.set_phase_overlay_deny(overlay_denying("scoring", "denied.example.com"));

        let err = c.get("https://other.example.com/x").await.unwrap_err();
        match err {
            HttpAccessDenied::Egress(d) => {
                assert_eq!(d.host, "other.example.com");
                assert_eq!(d.reason, EgressDenyReason::Profile);
            }
            other => panic!("expected Egress denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlay_does_not_widen_base_allowlist() {
        // Overlay-denied entries narrow only. A host not on the
        // base allowlist still gets denied (Profile reason); the
        // presence of an overlay does not implicitly admit hosts.
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        c.set_phase_overlay_deny(overlay_denying("scoring", "nothing-to-do-with-this.com"));

        let err = c.get("https://forbidden.example.com/x").await.unwrap_err();
        match err {
            HttpAccessDenied::Egress(d) => {
                assert_eq!(d.reason, EgressDenyReason::Profile);
            }
            other => panic!("expected Egress denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlay_allows_when_neither_layer_denies() {
        // Base allows the host AND overlay does not list it: ok.
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "allowed.example.com".to_string(),
        ])));
        c.set_phase_overlay_deny(overlay_denying("scoring", "other.example.com"));

        assert!(c.get("https://allowed.example.com/x").await.is_ok());
    }

    #[tokio::test]
    async fn clear_phase_overlay_deny_falls_back_to_base() {
        // Overlay denies a host; clearing the overlay restores the
        // base-alone behaviour. Mirrors the phase-end auto-clear
        // and the wirken_exit_phase intercept's side effect.
        let c = EgressClient::new();
        c.set_phase_overlay_deny(overlay_denying("scoring", "api.openai.com"));
        assert!(c.get("https://api.openai.com/v1/x").await.is_err());

        c.clear_phase_overlay_deny();
        assert!(c.get("https://api.openai.com/v1/x").await.is_ok());
    }

    #[tokio::test]
    async fn overlay_message_distinguishes_phase_from_profile() {
        // EgressDenied's Display impl branches on `reason` so a
        // human reading a log line can tell which layer fired.
        let phase = EgressDenied {
            host: "api.openai.com".to_string(),
            reason: EgressDenyReason::Phase {
                phase_name: "scoring".to_string(),
            },
        };
        assert!(format!("{phase}").contains("denied by active phase 'scoring'"));

        let profile = EgressDenied {
            host: "api.openai.com".to_string(),
            reason: EgressDenyReason::Profile,
        };
        assert!(format!("{profile}").contains("not in the agent's effective skill permissions"));
    }
}
