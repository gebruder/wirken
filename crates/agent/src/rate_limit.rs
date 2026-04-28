//! Per-host daily-cap rate limiter for outbound HTTP.
//!
//! [`RateLimitedClient`] sits between [`crate::egress::EgressClient`] and
//! the underlying `reqwest::Client`. Per the layering note in
//! `crates/agent/src/egress.rs`:
//!
//! ```text
//! caller → EgressClient → RateLimitedClient → reqwest::Client
//! ```
//!
//! Egress-allowlist denials short-circuit at the outer layer and never
//! consume rate budget. Rate-budget rejections happen here, after the
//! egress check has already passed — so a denied host never costs against
//! the budget, and a budget-exhausted host fails after the egress check
//! confirmed it was an *allowed* host that hit its cap.
//!
//! ## What's enforced
//!
//! - Per-host daily count, default cap 2. Overrides supported.
//! - Inter-request jitter delay. Default 3–12s, applied between
//!   consecutive requests to the same host. Disabled by passing zero
//!   for both bounds (test-only).
//!
//! ## What isn't enforced (yet)
//!
//! - Persistence across process restarts. State is in-memory; a
//!   restart resets counters. Persistence to a SkillStore-shared
//!   SQLite is the right shape and lands when the orchestrator gains
//!   crash-recovery semantics. For Scope B the daily-run model
//!   (`wirken zirkel run` once per cron tick, then exit) means the
//!   process-lifetime state is the run-lifetime state — adequate.
//! - Cross-process coordination. If two `wirken zirkel run` processes
//!   race, they'll each have their own counter. Cron is one-shot per
//!   tick so this isn't a real risk for Zirkel; documented as a
//!   constraint for any future caller that wants concurrent fetches.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rand::RngExt;
use reqwest::RequestBuilder;
use thiserror::Error;
use url::Url;

/// Configuration for [`RateLimitedClient`].
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default cap for hosts without an entry in `per_host_overrides`.
    pub default_daily_cap: u32,
    /// Per-host caps that override the default. Useful for sources
    /// whose published rate limits permit a higher count
    /// (e.g. `api.congress.gov` at 30/day).
    pub per_host_overrides: HashMap<String, u32>,
    /// Inter-request jitter range (inclusive lower bound, exclusive
    /// upper). Each request to a host that has already been hit waits
    /// for a uniformly-sampled delay in `[min, max)` since its last
    /// request. `Duration::ZERO` for both disables jitter (tests).
    pub jitter_min: Duration,
    pub jitter_max: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_daily_cap: 2,
            per_host_overrides: HashMap::new(),
            jitter_min: Duration::from_secs(3),
            jitter_max: Duration::from_secs(12),
        }
    }
}

impl RateLimitConfig {
    /// Test-only config: no caps, no delay. Use this in tests of
    /// composing layers (e.g. an `EgressClient` test) when the rate
    /// limiter should be a transparent passthrough.
    pub fn unrestricted_for_tests() -> Self {
        Self {
            default_daily_cap: u32::MAX,
            per_host_overrides: HashMap::new(),
            jitter_min: Duration::ZERO,
            jitter_max: Duration::ZERO,
        }
    }
}

/// Per-host counter state.
#[derive(Debug)]
struct HostState {
    /// Number of requests consumed in the current 24h window.
    count: u32,
    /// Wall-clock start of the current window. When `now` crosses
    /// `window_start + 24h` the counter resets.
    window_start: SystemTime,
    /// Monotonic timestamp of the last successful request, used for
    /// inter-request jitter.
    last_request: Option<Instant>,
}

#[derive(Debug)]
struct RateState {
    counters: HashMap<String, HostState>,
}

impl RateState {
    fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }
}

/// HTTP client with per-host daily caps and inter-request jitter.
#[derive(Clone)]
pub struct RateLimitedClient {
    inner: reqwest::Client,
    config: RateLimitConfig,
    state: Arc<Mutex<RateState>>,
}

impl RateLimitedClient {
    pub fn new(inner: reqwest::Client, config: RateLimitConfig) -> Self {
        Self {
            inner,
            config,
            state: Arc::new(Mutex::new(RateState::new())),
        }
    }

    /// Pre-flight: extract host from `url`, reserve a slot in the
    /// budget. On accept, returns `Ok(())` and the caller proceeds
    /// with a normal `reqwest` request. On reject, returns
    /// `Err(RateLimitDenied)` with the reason.
    ///
    /// This method is `async` because jitter sleeps are observed here
    /// (when configured non-zero). Callers that don't want to wait
    /// should disable jitter.
    pub async fn check_and_reserve(&self, url: &str) -> Result<(), RateLimitDenied> {
        let host = host_from_url(url)?;
        let cap = self
            .config
            .per_host_overrides
            .get(&host)
            .copied()
            .unwrap_or(self.config.default_daily_cap);

        // Hold the lock only across counter mutation; release before
        // the (potentially long) jitter sleep.
        let sleep_for = {
            let mut state = self.state.lock().map_err(|_| RateLimitDenied::Poisoned)?;
            let now_wall = SystemTime::now();
            let now_mono = Instant::now();
            let entry = state
                .counters
                .entry(host.clone())
                .or_insert_with(|| HostState {
                    count: 0,
                    window_start: now_wall,
                    last_request: None,
                });

            // Window roll-over.
            if let Ok(elapsed) = now_wall.duration_since(entry.window_start) {
                if elapsed >= Duration::from_secs(24 * 60 * 60) {
                    entry.count = 0;
                    entry.window_start = now_wall;
                    entry.last_request = None;
                }
            }

            if entry.count >= cap {
                return Err(RateLimitDenied::DailyCapExceeded {
                    host,
                    cap,
                    consumed: entry.count,
                });
            }

            // Compute jitter sleep before incrementing — if jitter is
            // disabled (both bounds zero) skip the sleep entirely.
            let sleep_for = if let Some(prev) = entry.last_request {
                jitter_sleep(prev, now_mono, &self.config)
            } else {
                Duration::ZERO
            };

            entry.count += 1;
            entry.last_request = Some(now_mono);
            sleep_for
        };

        if sleep_for > Duration::ZERO {
            tokio::time::sleep(sleep_for).await;
        }
        Ok(())
    }

    /// Compose with the inner client: `get(url)` after a successful
    /// `check_and_reserve`. Returns the unbuilt `RequestBuilder`.
    pub async fn get(&self, url: &str) -> Result<RequestBuilder, RateLimitDenied> {
        self.check_and_reserve(url).await?;
        Ok(self.inner.get(url))
    }

    pub async fn post(&self, url: &str) -> Result<RequestBuilder, RateLimitDenied> {
        self.check_and_reserve(url).await?;
        Ok(self.inner.post(url))
    }

    /// Snapshot the current count for a host. Test-only.
    #[cfg(test)]
    pub(crate) fn count_for_test(&self, host: &str) -> u32 {
        self.state
            .lock()
            .map(|s| s.counters.get(host).map(|h| h.count).unwrap_or(0))
            .unwrap_or(0)
    }
}

fn jitter_sleep(prev: Instant, now: Instant, config: &RateLimitConfig) -> Duration {
    if config.jitter_max == Duration::ZERO && config.jitter_min == Duration::ZERO {
        return Duration::ZERO;
    }
    let elapsed = now.saturating_duration_since(prev);
    let target = if config.jitter_max <= config.jitter_min {
        config.jitter_min
    } else {
        let mut rng = rand::rng();
        let span = config.jitter_max - config.jitter_min;
        let extra = Duration::from_nanos(rng.random_range(0..span.as_nanos() as u64));
        config.jitter_min + extra
    };
    if elapsed >= target {
        Duration::ZERO
    } else {
        target - elapsed
    }
}

fn host_from_url(url: &str) -> Result<String, RateLimitDenied> {
    let parsed = Url::parse(url).map_err(|_| RateLimitDenied::UnparseableUrl(url.to_string()))?;
    parsed
        .host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| RateLimitDenied::UnparseableUrl(url.to_string()))
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RateLimitDenied {
    #[error("daily cap exceeded for host '{host}' ({consumed}/{cap})")]
    DailyCapExceeded {
        host: String,
        cap: u32,
        consumed: u32,
    },
    #[error("unparseable URL '{0}'")]
    UnparseableUrl(String),
    #[error("rate limiter state lock poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unrestricted_client() -> RateLimitedClient {
        RateLimitedClient::new(
            reqwest::Client::new(),
            RateLimitConfig::unrestricted_for_tests(),
        )
    }

    fn capped_client(cap: u32) -> RateLimitedClient {
        RateLimitedClient::new(
            reqwest::Client::new(),
            RateLimitConfig {
                default_daily_cap: cap,
                jitter_min: Duration::ZERO,
                jitter_max: Duration::ZERO,
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn unrestricted_passes_through() {
        let c = unrestricted_client();
        for _ in 0..5 {
            assert!(c.check_and_reserve("https://example.com/foo").await.is_ok());
        }
        assert_eq!(c.count_for_test("example.com"), 5);
    }

    #[tokio::test]
    async fn cap_exceeded_returns_denied() {
        let c = capped_client(2);
        assert!(c.check_and_reserve("https://x.com/a").await.is_ok());
        assert!(c.check_and_reserve("https://x.com/b").await.is_ok());
        let err = c.check_and_reserve("https://x.com/c").await.unwrap_err();
        assert!(matches!(
            err,
            RateLimitDenied::DailyCapExceeded {
                consumed: 2,
                cap: 2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn cap_is_per_host() {
        let c = capped_client(2);
        assert!(c.check_and_reserve("https://a.com/x").await.is_ok());
        assert!(c.check_and_reserve("https://a.com/y").await.is_ok());
        // a.com is at cap, b.com is fresh.
        assert!(c.check_and_reserve("https://a.com/z").await.is_err());
        assert!(c.check_and_reserve("https://b.com/x").await.is_ok());
    }

    #[tokio::test]
    async fn per_host_override_raises_cap() {
        let mut overrides = HashMap::new();
        overrides.insert("api.example.com".to_string(), 5);
        let c = RateLimitedClient::new(
            reqwest::Client::new(),
            RateLimitConfig {
                default_daily_cap: 2,
                per_host_overrides: overrides,
                jitter_min: Duration::ZERO,
                jitter_max: Duration::ZERO,
            },
        );
        for _ in 0..5 {
            assert!(
                c.check_and_reserve("https://api.example.com/foo")
                    .await
                    .is_ok()
            );
        }
        assert!(
            c.check_and_reserve("https://api.example.com/foo")
                .await
                .is_err()
        );
        // Default cap still applies to other hosts.
        assert!(c.check_and_reserve("https://other.com/x").await.is_ok());
        assert!(c.check_and_reserve("https://other.com/y").await.is_ok());
        assert!(c.check_and_reserve("https://other.com/z").await.is_err());
    }

    #[tokio::test]
    async fn unparseable_url_is_denied() {
        let c = unrestricted_client();
        let err = c.check_and_reserve("not a url").await.unwrap_err();
        assert!(matches!(err, RateLimitDenied::UnparseableUrl(_)));
        // No counter is created for an unparseable URL.
        assert_eq!(c.count_for_test("not a url"), 0);
    }

    #[tokio::test]
    async fn rejected_request_does_not_consume_budget() {
        // Cap is 2; consume both, third returns Err. The Err must NOT
        // increment the count beyond 2 — otherwise budget accounting
        // is off.
        let c = capped_client(2);
        c.check_and_reserve("https://x.com/a").await.unwrap();
        c.check_and_reserve("https://x.com/b").await.unwrap();
        let _ = c.check_and_reserve("https://x.com/c").await;
        assert_eq!(c.count_for_test("x.com"), 2);
    }

    #[tokio::test]
    async fn jitter_disabled_runs_without_delay() {
        // unrestricted_for_tests sets both bounds to zero.
        let c = unrestricted_client();
        let start = Instant::now();
        for _ in 0..3 {
            c.check_and_reserve("https://x.com/foo").await.unwrap();
        }
        let elapsed = start.elapsed();
        // With zero jitter, three requests should be near-instant.
        assert!(
            elapsed < Duration::from_millis(50),
            "expected <50ms for zero-jitter; got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn jitter_enforces_inter_request_delay() {
        let c = RateLimitedClient::new(
            reqwest::Client::new(),
            RateLimitConfig {
                default_daily_cap: 100,
                per_host_overrides: HashMap::new(),
                jitter_min: Duration::from_millis(20),
                jitter_max: Duration::from_millis(40),
            },
        );
        let start = Instant::now();
        c.check_and_reserve("https://y.com/a").await.unwrap();
        c.check_and_reserve("https://y.com/b").await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(20),
            "expected >=20ms for second request; got {elapsed:?}"
        );
    }
}
