//! What a Lyrik run costs while it runs: a check that the prompt cache
//! is being used, and the operator's ceilings on a run.
//!
//! Both read the run's own `llm_response` rows from the session log,
//! so they see what the audit chain sees: the tokens the provider
//! reported, the cost the price table gave each call, and how long the
//! call took.
//!
//! A run has three ceilings, each the operator's and each optional:
//! recorded cost, model time and model calls. Recorded cost holds only
//! where calls are priced. A run on a plan sign-in records no cost, so
//! it does not start without one of the other two
//! ([`refuse_unbounded_plan_run`]).

use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog};

/// One model call of a run, as its `llm_response` row has it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CallUsage {
    /// Input sent uncached: neither read from nor written to the cache.
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    /// `None` when the model has no price entry, or the call ran on a
    /// plan sign-in.
    pub cost_micros: Option<u64>,
    /// How long the call took, as its row has it.
    pub latency_ms: u64,
    /// What a plan call would have cost at API rates: an estimate,
    /// not a charge. `None` on a billed call and where the model has
    /// no price entry.
    pub estimated_micros: Option<u64>,
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
                estimated_cost_usd_micros,
                latency_ms,
                ..
            } => Some(CallUsage {
                input_tokens: u64::from(input_tokens),
                cache_read_tokens: u64::from(cache_read_input_tokens),
                cache_write_tokens: u64::from(cache_creation_input_tokens),
                cost_micros: total_cost_usd_micros,
                latency_ms,
                estimated_micros: estimated_cost_usd_micros,
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
    /// Cost recorded for billed calls.
    pub usd_micros: u64,
    pub calls: usize,
    /// Calls with neither a cost nor an estimate: the model has no
    /// price entry. They are in neither sum.
    pub unpriced_calls: usize,
    /// The calls' durations, summed. Calls that overlap each count in
    /// full, so this is model time and not the run's wall-clock time.
    pub model_millis: u64,
    /// What the run's plan calls would have cost at API rates. An
    /// estimate: nothing was billed for them.
    pub estimated_usd_micros: u64,
}

impl Spend {
    /// What the cost ceiling is held against: recorded cost and, for
    /// plan calls, the estimate.
    pub fn counted_usd_micros(&self) -> u64 {
        self.usd_micros + self.estimated_usd_micros
    }
}

pub fn spend(calls: &[CallUsage]) -> Spend {
    Spend {
        usd_micros: calls.iter().filter_map(|c| c.cost_micros).sum(),
        calls: calls.len(),
        unpriced_calls: calls
            .iter()
            .filter(|c| c.cost_micros.is_none() && c.estimated_micros.is_none())
            .count(),
        model_millis: calls.iter().map(|c| c.latency_ms).sum(),
        estimated_usd_micros: calls.iter().filter_map(|c| c.estimated_micros).sum(),
    }
}

/// Whether `spend` has reached the operator's cost ceiling for a run:
/// recorded cost and, for plan calls, the estimate. No ceiling is
/// never reached; a ceiling of zero or less is no ceiling.
pub fn ceiling_reached(spend: &Spend, ceiling_usd: Option<f64>) -> bool {
    match ceiling_usd {
        Some(ceiling) if ceiling > 0.0 => spend.counted_usd_micros() as f64 >= ceiling * 1e6,
        _ => false,
    }
}

/// One line of a plan run's estimate: a step's calls on one model.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EstimateLine {
    /// The step the calls were made for: a walk's name, `replay`,
    /// `probe`, or `null` where a call named none.
    pub step: Option<String>,
    pub model: String,
    pub calls: usize,
    pub estimated_usd_micros: u64,
    /// Calls with no estimate: the model has no price entry.
    pub unpriced_calls: usize,
}

/// The run's plan calls since `mark` by step and model, in the order
/// each pair first appears. A call's model is the one its request row
/// names, or the one a child process reported for it.
pub fn estimate_lines(
    log: &dyn SessionLog,
    handle: &SessionHandle<OwnSession>,
    mark: Option<u64>,
) -> Vec<EstimateLine> {
    let Ok(rows) = log.get_since(handle, mark.map_or(0, |m| m + 1)) else {
        return Vec::new();
    };
    let mut asked: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut lines: Vec<EstimateLine> = Vec::new();
    for row in rows {
        match row.event {
            SessionEvent::LlmRequest {
                request_id, model, ..
            } => {
                asked.insert(request_id, model);
            }
            SessionEvent::LlmResponse {
                request_id,
                total_cost_usd_micros: None,
                estimated_cost_usd_micros,
                step,
                reported,
                ..
            } => {
                let model = match reported {
                    Some(r) => r.model,
                    None => asked.remove(&request_id).unwrap_or_default(),
                };
                let at = match lines
                    .iter()
                    .position(|l| l.step == step && l.model == model)
                {
                    Some(at) => at,
                    None => {
                        lines.push(EstimateLine {
                            step,
                            model,
                            calls: 0,
                            estimated_usd_micros: 0,
                            unpriced_calls: 0,
                        });
                        lines.len() - 1
                    }
                };
                lines[at].calls += 1;
                match estimated_cost_usd_micros {
                    Some(e) => lines[at].estimated_usd_micros += e,
                    None => lines[at].unpriced_calls += 1,
                }
            }
            _ => {}
        }
    }
    lines
}

/// The run summary's lines for [`estimate_lines`].
pub fn estimate_summary_lines(lines: &[EstimateLine]) -> Vec<String> {
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out =
        vec!["estimated cost at API rates, by step and model (nothing billed):".to_string()];
    for l in lines {
        let unpriced = if l.unpriced_calls > 0 {
            format!(
                ", {} with no price entry and not estimated",
                l.unpriced_calls
            )
        } else {
            String::new()
        };
        out.push(format!(
            "  {} on {}: ${:.4} over {} model call(s){unpriced}",
            l.step.as_deref().unwrap_or("(no step)"),
            l.model,
            l.estimated_usd_micros as f64 / 1e6,
            l.calls
        ));
    }
    out
}

/// The operator's ceilings for a run. An unset one is never reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Bounds {
    /// USD of recorded cost.
    pub usd: Option<f64>,
    /// Seconds of model time: the calls' durations, summed.
    pub model_seconds: Option<u64>,
    /// Model calls answered.
    pub model_calls: Option<u64>,
}

impl Bounds {
    /// Whether a ceiling is set that holds for calls with no recorded
    /// cost and no estimate.
    pub fn holds_without_cost(&self) -> bool {
        self.model_seconds.is_some() || self.model_calls.is_some()
    }

    /// Whether a ceiling is set that holds for a plan run. Any of the
    /// three does where every call can be estimated; where a model has
    /// no price entry, the cost ceiling has nothing to count.
    pub fn holds_on_plan(&self, every_model_priced: bool) -> bool {
        self.holds_without_cost() || (every_model_priced && self.usd.is_some_and(|c| c > 0.0))
    }
}

/// The ceiling a run reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reached {
    Usd,
    ModelSeconds,
    ModelCalls,
}

/// The first of the operator's ceilings `spend` has reached, if any.
/// The check runs between calls, so the calls in flight when a ceiling
/// is crossed complete.
pub fn reached(spend: &Spend, bounds: &Bounds) -> Option<Reached> {
    if ceiling_reached(spend, bounds.usd) {
        return Some(Reached::Usd);
    }
    if bounds
        .model_seconds
        .is_some_and(|s| spend.model_millis >= s.saturating_mul(1000))
    {
        return Some(Reached::ModelSeconds);
    }
    if bounds.model_calls.is_some_and(|n| spend.calls as u64 >= n) {
        return Some(Reached::ModelCalls);
    }
    None
}

/// The line the run prints when it reaches a ceiling.
pub fn reached_line(reached: Reached, spend: &Spend, bounds: &Bounds) -> String {
    let what = match reached {
        Reached::Usd => format!(
            "cost ceiling of ${:.2} (${:.2} {} over {} model calls)",
            bounds.usd.unwrap_or_default(),
            spend.counted_usd_micros() as f64 / 1e6,
            // A plan run's figure is an estimate; nothing was billed.
            if spend.estimated_usd_micros > 0 {
                "estimated at API rates, nothing billed,"
            } else {
                "recorded"
            },
            spend.calls
        ),
        Reached::ModelSeconds => format!(
            "model-time ceiling of {} second(s) ({} recorded over {} model calls)",
            bounds.model_seconds.unwrap_or_default(),
            spend.model_millis / 1000,
            spend.calls
        ),
        Reached::ModelCalls => format!(
            "model-call ceiling of {} ({} model calls recorded)",
            bounds.model_calls.unwrap_or_default(),
            spend.calls
        ),
    };
    format!("the run reached its {what}; stopping, staged findings are kept")
}

/// Why a run on a plan may not start, when it may not. A plan call is
/// not billed, so a ceiling has to count something else: model time,
/// model calls, or the cost estimated at API rates. The last needs
/// every model of the run to have a price entry; `unpriced` names the
/// first that has none.
pub fn refuse_unbounded_plan_run(
    bounds: &Bounds,
    unpriced: Option<&str>,
    settings: &std::path::Path,
) -> Option<String> {
    if bounds.holds_on_plan(unpriced.is_none()) {
        return None;
    }
    Some(match (bounds.usd.filter(|c| *c > 0.0), unpriced) {
        (Some(c), Some(model)) => format!(
            "this run is on a plan, whose calls are not billed, and `run_ceiling_usd` (${c:.2}) \
             cannot stop it: {model} has no price entry, so its calls cannot be estimated. Set \
             `run_ceiling_model_seconds` or `run_ceiling_model_calls` in {} and run it again",
            settings.display()
        ),
        _ => format!(
            "this run is on a plan, whose calls are not billed, and no ceiling is set that \
             would stop it. Set `run_ceiling_usd` (held against the cost estimated at API \
             rates), `run_ceiling_model_seconds` or `run_ceiling_model_calls` in {} and run it \
             again",
            settings.display()
        ),
    })
}

/// The sign-off banner's cost lines: each ceiling that is set, or that
/// none is, and what the run's cost figures are: recorded cost, an
/// estimate at API rates on `plan` (the plan the run is on, as a
/// phrase), or nothing where the model has no price entry.
pub fn banner_lines(
    provider: &str,
    model: &str,
    plan: Option<&str>,
    bounds: &Bounds,
) -> Vec<(String, String)> {
    let in_table = wirken_audit::pricing::is_priced(provider, model);
    let no_entry = format!("{provider} {model} has no price entry");
    let usd = bounds.usd.filter(|c| *c > 0.0);
    let ceiling = match (usd, plan.is_some(), in_table) {
        (Some(c), false, true) => {
            format!("the run stops at ${c:.2} of recorded cost (`run_ceiling_usd` in lyrik.json)")
        }
        (Some(c), true, true) => format!(
            "the run stops at ${c:.2} of estimated cost at API rates; nothing is billed \
             (`run_ceiling_usd` in lyrik.json)"
        ),
        (Some(c), _, false) => format!("${c:.2} is set but cannot be enforced: {no_entry}"),
        (None, true, _) => "no cost ceiling set: the run is held by the ceilings below".to_string(),
        (None, false, _) => {
            "none set: this run has no cost limit (`run_ceiling_usd` in lyrik.json sets one)"
                .to_string()
        }
    };
    let mut lines = vec![("ceiling".to_string(), ceiling)];
    if let Some(s) = bounds.model_seconds {
        lines.push((
            "time".to_string(),
            format!(
                "the run stops at {s} second(s) of model time (`run_ceiling_model_seconds` in \
                 lyrik.json)"
            ),
        ));
    }
    if let Some(n) = bounds.model_calls {
        lines.push((
            "calls".to_string(),
            format!("the run stops at {n} model call(s) (`run_ceiling_model_calls` in lyrik.json)"),
        ));
    }
    match (plan, in_table) {
        (Some(plan), true) => lines.push((
            "pricing".to_string(),
            format!(
                "the run is on {plan}: nothing is billed, and every cost figure is an estimate \
                 at API rates"
            ),
        )),
        (Some(plan), false) => lines.push((
            "pricing".to_string(),
            format!(
                "the run is on {plan}: nothing is billed, and {no_entry}, so no cost estimate \
                 is recorded"
            ),
        )),
        (None, false) => lines.push((
            "pricing".to_string(),
            format!("{no_entry}: this run's cost is not recorded"),
        )),
        (None, true) => {}
    }
    lines
}

/// The run summary's cost lines. `plan` is the plan the run was on,
/// as a phrase, when it was on one.
pub fn summary_lines(
    spend: &Spend,
    bounds: &Bounds,
    stopped_at: Option<Reached>,
    plan: Option<&str>,
    warning: Option<&CacheWarning>,
) -> Vec<String> {
    const STOPPED: &str =
        "walks were ended, staged findings were kept, and no replay or fix step ran after it";
    let mut lines = Vec::new();
    match plan {
        Some(plan) => {
            let unpriced = if spend.unpriced_calls > 0 {
                format!(
                    ", {} of them with no price entry and not estimated",
                    spend.unpriced_calls
                )
            } else {
                String::new()
            };
            lines.push(format!(
                "cost: nothing billed, the run was on {plan}; an estimated ${:.2} at API rates \
                 over {} model call(s){unpriced}, {} second(s) of model time",
                spend.estimated_usd_micros as f64 / 1e6,
                spend.calls,
                spend.model_millis / 1000
            ));
        }
        None => {
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
        }
    }
    if let Some(c) = bounds.usd.filter(|c| *c > 0.0) {
        let on = if plan.is_some() {
            " on estimated cost"
        } else {
            ""
        };
        lines.push(if stopped_at == Some(Reached::Usd) {
            format!("stopped at the cost ceiling of ${c:.2}{on}: {STOPPED}")
        } else {
            format!("cost ceiling ${c:.2}{on}: not reached")
        });
    }
    if let Some(s) = bounds.model_seconds {
        lines.push(if stopped_at == Some(Reached::ModelSeconds) {
            format!("stopped at the model-time ceiling of {s} second(s): {STOPPED}")
        } else {
            format!(
                "model-time ceiling {s} second(s): not reached ({} recorded)",
                spend.model_millis / 1000
            )
        });
    }
    if let Some(n) = bounds.model_calls {
        lines.push(if stopped_at == Some(Reached::ModelCalls) {
            format!("stopped at the model-call ceiling of {n}: {STOPPED}")
        } else {
            format!("model-call ceiling {n}: not reached ({} made)", spend.calls)
        });
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
            latency_ms: 0,
            estimated_micros: None,
        }
    }

    fn usd(ceiling: Option<f64>) -> Bounds {
        Bounds {
            usd: ceiling,
            ..Bounds::default()
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
                unpriced_calls: 1,
                model_millis: 0,
                estimated_usd_micros: 0,
            }
        );
        assert!(ceiling_reached(&s, Some(1.0)));
        assert!(ceiling_reached(&s, Some(1.05)));
        assert!(!ceiling_reached(&s, Some(1.06)));
        assert!(!ceiling_reached(&s, None));
        assert!(!ceiling_reached(&s, Some(0.0)));
        assert!(!ceiling_reached(&spend(&calls[..1]), Some(1.0)));

        let lines = summary_lines(&s, &usd(Some(1.0)), Some(Reached::Usd), None, None);
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
            summary_lines(&s, &usd(Some(5.0)), None, None, None)[1],
            "cost ceiling $5.00: not reached"
        );
        assert_eq!(summary_lines(&s, &usd(None), None, None, None).len(), 1);
    }

    /// The banner says what the ceiling is or that there is none, and
    /// says so before the run when the model has no price entry.
    #[test]
    fn the_banner_shows_the_ceiling_and_a_missing_price_entry() {
        let set = banner_lines("anthropic", "claude-mythos-5-2", None, &usd(Some(25.0)));
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].0, "ceiling");
        assert!(
            set[0]
                .1
                .starts_with("the run stops at $25.00 of recorded cost"),
            "{}",
            set[0].1
        );

        let none = banner_lines("anthropic", "claude-mythos-5-2", None, &usd(None));
        assert!(
            none[0]
                .1
                .starts_with("none set: this run has no cost limit"),
            "{}",
            none[0].1
        );

        let unpriced = banner_lines("anthropic", "no-such-model", None, &usd(Some(25.0)));
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
        assert_eq!(
            banner_lines("anthropic", "no-such-model", None, &usd(None)).len(),
            2
        );
    }

    fn timed(latency_ms: u64) -> CallUsage {
        CallUsage {
            latency_ms,
            ..CallUsage::default()
        }
    }

    /// The two ceilings that need no price: model time is the calls'
    /// durations summed, model calls their count. Calls with no cost,
    /// as a plan sign-in's are, reach both and never the cost ceiling.
    #[test]
    fn model_time_and_model_calls_are_reached_without_a_recorded_cost() {
        let calls = [timed(40_000), timed(15_000), timed(5_500)];
        let s = spend(&calls);
        assert_eq!((s.usd_micros, s.unpriced_calls, s.calls), (0, 3, 3));
        assert_eq!(s.model_millis, 60_500);

        let only_usd = usd(Some(0.01));
        assert!(!only_usd.holds_without_cost());
        assert_eq!(reached(&s, &only_usd), None);

        let seconds = |n| Bounds {
            model_seconds: Some(n),
            ..Bounds::default()
        };
        assert!(seconds(60).holds_without_cost());
        assert_eq!(reached(&s, &seconds(60)), Some(Reached::ModelSeconds));
        assert_eq!(reached(&s, &seconds(61)), None);
        assert_eq!(reached(&spend(&calls[..2]), &seconds(60)), None);

        let count = |n| Bounds {
            model_calls: Some(n),
            ..Bounds::default()
        };
        assert!(count(3).holds_without_cost());
        assert_eq!(reached(&s, &count(3)), Some(Reached::ModelCalls));
        assert_eq!(reached(&s, &count(4)), None);

        assert_eq!(
            reached_line(Reached::ModelSeconds, &s, &seconds(60)),
            "the run reached its model-time ceiling of 60 second(s) (60 recorded over 3 model \
             calls); stopping, staged findings are kept"
        );
        assert_eq!(
            reached_line(Reached::ModelCalls, &s, &count(3)),
            "the run reached its model-call ceiling of 3 (3 model calls recorded); stopping, \
             staged findings are kept"
        );
    }

    fn estimated(micros: Option<u64>, latency_ms: u64) -> CallUsage {
        CallUsage {
            estimated_micros: micros,
            latency_ms,
            ..CallUsage::default()
        }
    }

    const PLAN: &str = "the plan sign-in 'openai-plan'";

    /// A plan run starts on any one ceiling that can count its calls:
    /// model time, model calls, or cost where every model can be
    /// estimated. A cost ceiling alone does not hold for a model with
    /// no price entry.
    #[test]
    fn a_plan_run_starts_on_any_ceiling_that_can_count_its_calls() {
        let path = std::path::Path::new("/d/lyrik.json");
        let none = refuse_unbounded_plan_run(&Bounds::default(), None, path).expect("refused");
        for setting in [
            "`run_ceiling_usd`",
            "`run_ceiling_model_seconds`",
            "`run_ceiling_model_calls`",
            "/d/lyrik.json",
        ] {
            assert!(none.contains(setting), "{none}");
        }
        // A cost ceiling holds where every model has a price.
        assert_eq!(
            refuse_unbounded_plan_run(&usd(Some(20.0)), None, path),
            None
        );
        // It does not where one has none, and the refusal names it.
        let unpriced = refuse_unbounded_plan_run(&usd(Some(20.0)), Some("openai gpt-plan"), path)
            .expect("refused");
        assert!(
            unpriced.contains("openai gpt-plan has no price entry"),
            "{unpriced}"
        );
        for bounded in [
            Bounds {
                model_seconds: Some(1),
                ..Bounds::default()
            },
            Bounds {
                model_calls: Some(1),
                ..usd(Some(20.0))
            },
        ] {
            assert_eq!(
                refuse_unbounded_plan_run(&bounded, Some("openai gpt-plan"), path),
                None
            );
        }
    }

    /// On a plan the cost ceiling is held against the estimate. The
    /// estimate is kept apart from recorded cost, which stays zero,
    /// and the stop says the figure is an estimate.
    #[test]
    fn a_plan_runs_cost_ceiling_is_held_against_the_estimate() {
        let calls = [
            estimated(Some(600_000), 1000),
            estimated(None, 1000),
            estimated(Some(450_000), 1000),
        ];
        let s = spend(&calls);
        assert_eq!(
            (s.usd_micros, s.estimated_usd_micros, s.unpriced_calls),
            (0, 1_050_000, 1)
        );
        assert_eq!(s.counted_usd_micros(), 1_050_000);
        assert_eq!(reached(&s, &usd(Some(1.0))), Some(Reached::Usd));
        assert_eq!(reached(&s, &usd(Some(1.06))), None);
        assert_eq!(
            reached_line(Reached::Usd, &s, &usd(Some(1.0))),
            "the run reached its cost ceiling of $1.00 ($1.05 estimated at API rates, nothing \
             billed, over 3 model calls); stopping, staged findings are kept"
        );
        // A billed run's line is as it was.
        let billed = spend(&[call(1, 0, 0, Some(1_500_000))]);
        assert_eq!(
            reached_line(Reached::Usd, &billed, &usd(Some(1.0))),
            "the run reached its cost ceiling of $1.00 ($1.50 recorded over 1 model calls); \
             stopping, staged findings are kept"
        );
    }

    /// The banner and the summary of a plan run say that nothing is
    /// billed and that the figure is an estimate at API rates; where
    /// the model has no price entry they say no estimate is made.
    #[test]
    fn a_plan_run_says_its_cost_is_an_estimate_and_nothing_is_billed() {
        let bounds = Bounds {
            usd: Some(20.0),
            model_seconds: Some(3600),
            model_calls: Some(400),
        };
        let banner = banner_lines("openai", "gpt-6.2-astra", Some(PLAN), &bounds);
        assert_eq!(
            banner,
            [
                (
                    "ceiling".to_string(),
                    "the run stops at $20.00 of estimated cost at API rates; nothing is billed \
                     (`run_ceiling_usd` in lyrik.json)"
                        .to_string()
                ),
                (
                    "time".to_string(),
                    "the run stops at 3600 second(s) of model time (`run_ceiling_model_seconds` \
                     in lyrik.json)"
                        .to_string()
                ),
                (
                    "calls".to_string(),
                    "the run stops at 400 model call(s) (`run_ceiling_model_calls` in lyrik.json)"
                        .to_string()
                ),
                (
                    "pricing".to_string(),
                    "the run is on the plan sign-in 'openai-plan': nothing is billed, and every \
                     cost figure is an estimate at API rates"
                        .to_string()
                ),
            ]
        );
        let unpriced = banner_lines("openai", "no-such-model", Some(PLAN), &bounds);
        assert_eq!(
            unpriced[0].1,
            "$20.00 is set but cannot be enforced: openai no-such-model has no price entry"
        );
        assert_eq!(
            unpriced[3].1,
            "the run is on the plan sign-in 'openai-plan': nothing is billed, and openai \
             no-such-model has no price entry, so no cost estimate is recorded"
        );
        let no_usd = Bounds {
            usd: None,
            ..bounds
        };
        assert_eq!(
            banner_lines("openai", "gpt-6.2-astra", Some(PLAN), &no_usd)[0].1,
            "no cost ceiling set: the run is held by the ceilings below"
        );

        let s = spend(&[
            estimated(Some(1_200_000), 30_000),
            estimated(Some(340_000), 45_000),
            estimated(None, 0),
        ]);
        assert_eq!(
            summary_lines(&s, &bounds, None, Some(PLAN), None),
            [
                "cost: nothing billed, the run was on the plan sign-in 'openai-plan'; an \
                 estimated $1.54 at API rates over 3 model call(s), 1 of them with no price \
                 entry and not estimated, 75 second(s) of model time",
                "cost ceiling $20.00 on estimated cost: not reached",
                "model-time ceiling 3600 second(s): not reached (75 recorded)",
                "model-call ceiling 400: not reached (3 made)",
            ]
        );
        let stopped = summary_lines(&s, &bounds, Some(Reached::Usd), Some(PLAN), None);
        assert!(
            stopped[1]
                .starts_with("stopped at the cost ceiling of $20.00 on estimated cost: walks"),
            "{stopped:?}"
        );
    }

    /// The estimate is shown by step and model, with the calls that
    /// could not be estimated counted apart.
    #[test]
    fn the_estimate_is_listed_by_step_and_model() {
        let lines = [
            EstimateLine {
                step: Some("sink-walk".to_string()),
                model: "small".to_string(),
                calls: 12,
                estimated_usd_micros: 41_200,
                unpriced_calls: 0,
            },
            EstimateLine {
                step: None,
                model: "large".to_string(),
                calls: 3,
                estimated_usd_micros: 0,
                unpriced_calls: 3,
            },
        ];
        assert_eq!(
            estimate_summary_lines(&lines),
            [
                "estimated cost at API rates, by step and model (nothing billed):",
                "  sink-walk on small: $0.0412 over 12 model call(s)",
                "  (no step) on large: $0.0000 over 3 model call(s), 3 with no price entry and \
                 not estimated",
            ]
        );
        assert!(estimate_summary_lines(&[]).is_empty());
    }
}
