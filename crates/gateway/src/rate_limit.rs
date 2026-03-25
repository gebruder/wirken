use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Per-source rate limiter for authentication attempts.
/// No loopback exemption — all sources are treated equally.
pub struct AuthRateLimiter {
    sources: RwLock<HashMap<String, SourceState>>,
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
}

struct SourceState {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

impl AuthRateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            sources: RwLock::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
            lockout: Duration::from_secs(lockout_secs),
        }
    }

    /// Record a failed auth attempt from a source.
    /// Returns Err if the source is now locked out.
    pub fn record_failure(&self, source: &str) -> Result<(), RateLimitExceeded> {
        let mut sources = self.sources.write().unwrap();
        let state = sources.entry(source.to_string()).or_insert_with(|| SourceState {
            attempts: Vec::new(),
            locked_until: None,
        });

        let now = Instant::now();

        // Check if locked out
        if let Some(until) = state.locked_until {
            if now < until {
                return Err(RateLimitExceeded {
                    source: source.to_string(),
                    retry_after: until.duration_since(now),
                });
            }
            // Lockout expired — reset
            state.locked_until = None;
            state.attempts.clear();
        }

        // Prune old attempts outside the window
        state.attempts.retain(|t| now.duration_since(*t) < self.window);

        // Record this attempt
        state.attempts.push(now);

        // Check if we've exceeded the limit
        if state.attempts.len() as u32 >= self.max_attempts {
            state.locked_until = Some(now + self.lockout);
            return Err(RateLimitExceeded {
                source: source.to_string(),
                retry_after: self.lockout,
            });
        }

        Ok(())
    }

    /// Record a successful auth — clears the failure counter.
    pub fn record_success(&self, source: &str) {
        let mut sources = self.sources.write().unwrap();
        sources.remove(source);
    }

    /// Check if a source is currently locked out.
    pub fn is_locked(&self, source: &str) -> bool {
        let sources = self.sources.read().unwrap();
        match sources.get(source) {
            Some(state) => {
                state.locked_until.map(|until| Instant::now() < until).unwrap_or(false)
            }
            None => false,
        }
    }

    /// Prune stale entries (sources with no recent activity).
    pub fn prune(&self) {
        let mut sources = self.sources.write().unwrap();
        let now = Instant::now();
        sources.retain(|_, state| {
            // Keep if locked or has recent attempts
            if let Some(until) = state.locked_until {
                if now < until {
                    return true;
                }
            }
            !state.attempts.is_empty()
                && now.duration_since(*state.attempts.last().unwrap()) < Duration::from_secs(300)
        });
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    pub source: String,
    pub retry_after: Duration,
}

impl std::fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rate limited: {} (retry after {:?})", self.source, self.retry_after)
    }
}

/// Generic rate limiter for control plane operations.
/// Uses governor's GCRA algorithm — lock-free, zero-alloc on hot path.
pub struct ControlPlaneRateLimiter {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl ControlPlaneRateLimiter {
    /// Create a new rate limiter allowing `max_per_minute` operations per minute.
    pub fn new(max_per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(max_per_minute).unwrap_or(NonZeroU32::MIN));
        Self {
            limiter: RateLimiter::direct(quota),
        }
    }

    /// Check if an operation is allowed. Returns Ok(()) or Err with wait time.
    pub fn check(&self) -> Result<(), Duration> {
        self.limiter.check().map_err(|e| e.wait_time_from(governor::clock::Clock::now(&DefaultClock::default())))
    }
}
