//! What a Lyrik run costs while it runs: a check that the prompt cache
//! is being used, and the operator's ceiling on a run's spend.
//!
//! Both read the run's own `llm_response` rows from the session log,
//! so they see what the audit chain sees: the tokens the provider
//! reported and the cost the price table gave each call.

use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog};

/// One model call of a run, as its `llm_response` row has it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CallUsage {
    /// Input sent uncached: neither read from nor written to the cache.
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    /// `None` when the model has no price entry.
    pub cost_micros: Option<u64>,
}

/// The run's model calls since `mark`, in order.
pub fn calls_since(
    log: &dyn SessionLog,
    handle: &SessionHandle<OwnSession>,
    mark: Option<u64>,
) -> Vec<CallUsage> {
    let Ok(rows) = log.get_since(handle, mark.map_or(0, |m| m + 1)) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter_map(|row| match row.event {
            SessionEvent::LlmResponse {
                input_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                total_cost_usd_micros,
                ..
            } => Some(CallUsage {
                input_tokens: u64::from(input_tokens),
                cache_read_tokens: u64::from(cache_read_input_tokens),
                cache_write_tokens: u64::from(cache_creation_input_tokens),
                cost_micros: total_cost_usd_micros,
            }),
            _ => None,
        })
        .collect()
}

/// Whether a provider reports prompt-cache token counts, so their
/// absence means the cache is not in use rather than not reported.
pub fn reports_cache_tokens(provider: &str) -> bool {
    provider == "anthropic"
}

/// The cache check looks from this many calls on.
pub const CACHE_CHECK_AFTER_CALLS: usize = 3;
/// Below this many prompt tokens in all, a conversation is too short
/// for the provider to cache, and the check says nothing.
pub const CACHE_CHECK_MIN_PROMPT_TOKENS: u64 = 10_000;
/// The check warns when more than this share of the prompt tokens was
/// sent uncached.
pub const CACHE_CHECK_UNCACHED_SHARE: f64 = 0.5;

/// What the cache check found.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CacheWarning {
    pub calls: usize,
    pub uncached_input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    /// What the uncached input cost more than a cache read would have,
    /// in USD micros. An estimate: it assumes all of it could have been
    /// read from the cache. `None` when the model has no price entry.
    pub estimated_extra_usd_micros: Option<u64>,
}

impl CacheWarning {
    /// One line for the run output and the summary.
    pub fn line(&self) -> String {
        let extra = match self.estimated_extra_usd_micros {
            Some(micros) => format!("about ${:.2} more so far", micros as f64 / 1e6),
            None => "extra cost unknown: the model has no price entry".to_string(),
        };
        format!(
            "warning: the conversation is being sent uncached: after {} model calls, {} input \
             tokens were sent uncached against {} read from the prompt cache and {} written to \
             it ({extra}, an estimate)",
            self.calls, self.uncached_input_tokens, self.cache_read_tokens, self.cache_write_tokens
        )
    }
}

/// After the third model call, whether the conversation is being
/// resent uncached: more than half of all the prompt tokens so far
/// were sent as plain input, neither read from the cache nor written
/// to it. A healthy cached conversation sends almost nothing that way.
/// Says nothing for a provider that reports no cache counters, before
/// the third call, or under [`CACHE_CHECK_MIN_PROMPT_TOKENS`].
pub fn cache_check(provider: &str, model: &str, calls: &[CallUsage]) -> Option<CacheWarning> {
    if !reports_cache_tokens(provider) || calls.len() < CACHE_CHECK_AFTER_CALLS {
        return None;
    }
    let uncached: u64 = calls.iter().map(|c| c.input_tokens).sum();
    let read: u64 = calls.iter().map(|c| c.cache_read_tokens).sum();
    let written: u64 = calls.iter().map(|c| c.cache_write_tokens).sum();
    let prompt = uncached + read + written;
    if prompt < CACHE_CHECK_MIN_PROMPT_TOKENS
        || (uncached as f64) <= CACHE_CHECK_UNCACHED_SHARE * prompt as f64
    {
        return None;
    }
    let premium = wirken_audit::pricing::uncached_premium_per_million_usd(provider, model);
    Some(CacheWarning {
        calls: calls.len(),
        uncached_input_tokens: uncached,
        cache_read_tokens: read,
        cache_write_tokens: written,
        estimated_extra_usd_micros: premium.map(|p| (uncached as f64 * p) as u64),
    })
}

/// A run's spend so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Spend {
    pub usd_micros: u64,
    pub calls: usize,
    /// Calls that recorded no cost because the model has no price
    /// entry. They are not in `usd_micros`.
    pub unpriced_calls: usize,
}

pub fn spend(calls: &[CallUsage]) -> Spend {
    Spend {
        usd_micros: calls.iter().filter_map(|c| c.cost_micros).sum(),
        calls: calls.len(),
        unpriced_calls: calls.iter().filter(|c| c.cost_micros.is_none()).count(),
    }
}

/// Whether `spend` has reached the operator's ceiling for a run. No
/// ceiling is never reached; a ceiling of zero or less is no ceiling.
pub fn ceiling_reached(spend: &Spend, ceiling_usd: Option<f64>) -> bool {
    match ceiling_usd {
        Some(ceiling) if ceiling > 0.0 => spend.usd_micros as f64 >= ceiling * 1e6,
        _ => false,
    }
}

/// The sign-off banner's cost lines: the ceiling or that none is set,
/// and, when the run's model has no price entry, that cost is not
/// recorded and a ceiling cannot hold.
pub fn banner_lines(
    provider: &str,
    model: &str,
    ceiling_usd: Option<f64>,
) -> Vec<(String, String)> {
    let priced = wirken_audit::pricing::is_priced(provider, model);
    let ceiling = match ceiling_usd {
        Some(c) if c > 0.0 && priced => {
            format!("the run stops at ${c:.2} of recorded cost (`run_ceiling_usd` in lyrik.json)")
        }
        Some(c) if c > 0.0 => {
            format!("${c:.2} is set but cannot be enforced: {provider} {model} has no price entry")
        }
        _ => "none set: this run has no cost limit (`run_ceiling_usd` in lyrik.json sets one)"
            .to_string(),
    };
    let mut lines = vec![("ceiling".to_string(), ceiling)];
    if !priced {
        lines.push((
            "pricing".to_string(),
            format!("{provider} {model} has no price entry: this run's cost is not recorded"),
        ));
    }
    lines
}

/// The run summary's cost lines.
pub fn summary_lines(
    spend: &Spend,
    ceiling_usd: Option<f64>,
    stopped_at_ceiling: bool,
    warning: Option<&CacheWarning>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let unpriced = if spend.unpriced_calls > 0 {
        format!(
            ", {} of them with no price entry and not counted",
            spend.unpriced_calls
        )
    } else {
        String::new()
    };
    lines.push(format!(
        "cost: ${:.2} recorded over {} model call(s){unpriced}",
        spend.usd_micros as f64 / 1e6,
        spend.calls
    ));
    match (ceiling_usd.filter(|c| *c > 0.0), stopped_at_ceiling) {
        (Some(c), true) => lines.push(format!(
            "stopped at the cost ceiling of ${c:.2}: walks were ended, staged findings were kept, \
             and no replay or fix step ran after it"
        )),
        (Some(c), false) => lines.push(format!("cost ceiling ${c:.2}: not reached")),
        (None, _) => {}
    }
    if let Some(w) = warning {
        lines.push(w.line());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(input: u64, read: u64, write: u64, cost: Option<u64>) -> CallUsage {
        CallUsage {
            input_tokens: input,
            cache_read_tokens: read,
            cache_write_tokens: write,
            cost_micros: cost,
        }
    }

    /// A session with caching off: every call resends the whole
    /// conversation as plain input and reports no cache tokens. The
    /// check says nothing for two calls and warns at the third, with
    /// the tokens and what they cost more than cache reads would have.
    #[test]
    fn a_session_with_caching_disabled_triggers_the_warning() {
        let uncached = [
            call(6_000, 0, 0, Some(48_000)),
            call(9_000, 0, 0, Some(72_000)),
            call(12_000, 0, 0, Some(96_000)),
        ];
        assert_eq!(
            cache_check("anthropic", "claude-mythos-5-2", &uncached[..2]),
            None
        );
        let w = cache_check("anthropic", "claude-mythos-5-2", &uncached).expect("warns");
        assert_eq!(w.calls, 3);
        assert_eq!(w.uncached_input_tokens, 27_000);
        assert_eq!(w.cache_read_tokens, 0);
        assert_eq!(w.cache_write_tokens, 0);
        // 27,000 tokens at $8.00 less $0.20 a million.
        assert_eq!(w.estimated_extra_usd_micros, Some(210_600));
        let line = w.line();
        assert!(line.contains("after 3 model calls"), "{line}");
        assert!(
            line.contains("27000 input tokens were sent uncached"),
            "{line}"
        );
        assert!(line.contains("about $0.21 more so far"), "{line}");
    }

    /// A cached conversation, one too short to cache, a provider that
    /// reports no cache counters and a model with no price entry.
    #[test]
    fn the_cache_check_is_quiet_when_the_cache_is_in_use_or_cannot_be_judged() {
        // Healthy: the first call writes, later calls read.
        let cached = [
            call(120, 0, 9_000, None),
            call(130, 9_000, 2_000, None),
            call(140, 11_000, 2_500, None),
        ];
        assert_eq!(cache_check("anthropic", "claude-mythos-5-2", &cached), None);
        // Exactly half uncached is not "more than half".
        let half = [
            call(5_000, 0, 0, None),
            call(0, 5_000, 0, None),
            call(0, 0, 0, None),
        ];
        assert_eq!(cache_check("anthropic", "claude-mythos-5-2", &half), None);
        // Too short to be cached at all.
        let short = [call(900, 0, 0, None); 3];
        assert_eq!(cache_check("anthropic", "claude-mythos-5-2", &short), None);
        // A provider that reports no cache tokens is not judged.
        let big = [call(20_000, 0, 0, None); 3];
        assert_eq!(cache_check("openai", "gpt-x", &big), None);
        assert!(reports_cache_tokens("anthropic"));
        // No price entry: it still warns, without a figure.
        let w = cache_check("anthropic", "no-such-model", &big).unwrap();
        assert_eq!(w.estimated_extra_usd_micros, None);
        assert!(w.line().contains("extra cost unknown"));
        assert_eq!(CACHE_CHECK_AFTER_CALLS, 3);
    }

    /// The ceiling is reached on recorded cost; unpriced calls are
    /// counted apart and add nothing; no ceiling is never reached.
    #[test]
    fn the_run_ceiling_is_reached_on_recorded_cost() {
        let calls = [
            call(1, 0, 0, Some(600_000)),
            call(1, 0, 0, None),
            call(1, 0, 0, Some(450_000)),
        ];
        let s = spend(&calls);
        assert_eq!(
            s,
            Spend {
                usd_micros: 1_050_000,
                calls: 3,
                unpriced_calls: 1
            }
        );
        assert!(ceiling_reached(&s, Some(1.0)));
        assert!(ceiling_reached(&s, Some(1.05)));
        assert!(!ceiling_reached(&s, Some(1.06)));
        assert!(!ceiling_reached(&s, None));
        assert!(!ceiling_reached(&s, Some(0.0)));
        assert!(!ceiling_reached(&spend(&calls[..1]), Some(1.0)));

        let lines = summary_lines(&s, Some(1.0), true, None);
        assert_eq!(
            lines[0],
            "cost: $1.05 recorded over 3 model call(s), 1 of them with no price entry and not counted"
        );
        assert!(
            lines[1].starts_with("stopped at the cost ceiling of $1.00"),
            "{}",
            lines[1]
        );
        assert!(lines[1].contains("staged findings were kept"));
        assert_eq!(
            summary_lines(&s, Some(5.0), false, None)[1],
            "cost ceiling $5.00: not reached"
        );
        assert_eq!(summary_lines(&s, None, false, None).len(), 1);
    }

    /// The banner says what the ceiling is or that there is none, and
    /// says so before the run when the model has no price entry.
    #[test]
    fn the_banner_shows_the_ceiling_and_a_missing_price_entry() {
        let set = banner_lines("anthropic", "claude-mythos-5-2", Some(25.0));
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].0, "ceiling");
        assert!(
            set[0]
                .1
                .starts_with("the run stops at $25.00 of recorded cost"),
            "{}",
            set[0].1
        );

        let none = banner_lines("anthropic", "claude-mythos-5-2", None);
        assert!(
            none[0]
                .1
                .starts_with("none set: this run has no cost limit"),
            "{}",
            none[0].1
        );

        let unpriced = banner_lines("anthropic", "no-such-model", Some(25.0));
        assert_eq!(unpriced.len(), 2);
        assert!(
            unpriced[0].1.contains("cannot be enforced"),
            "{}",
            unpriced[0].1
        );
        assert_eq!(unpriced[1].0, "pricing");
        assert_eq!(
            unpriced[1].1,
            "anthropic no-such-model has no price entry: this run's cost is not recorded"
        );
        assert_eq!(banner_lines("anthropic", "no-such-model", None).len(), 2);
    }
}
