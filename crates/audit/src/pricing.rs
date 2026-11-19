//! Baked per-model token pricing for the `LlmResponse` cost fields.
//!
//! The table is `include_str!`'d from `pricing.toml` at compile time
//! and parsed once into a `OnceLock<HashMap<(String, String), Pricing>>`
//! on first call. This matches Wirken's single-static-binary
//! architecture: no runtime file resolution, no "is the file there?"
//! failure mode, version-bump-controlled.
//!
//! `cost_micros` is the public entry point. It returns
//! `(input_cost_micros, output_cost_micros, total_cost_micros)`,
//! each `None` when the `(provider, model)` pair is absent from the
//! baked table. Callers emit the result onto
//! `SessionEvent::LlmResponse` and log a `tracing::warn` so a stale
//! binary against a new model is visible in the audit stream.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// Per-million-token USD prices for one (provider, model) pair.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Pricing {
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
    /// What a cache read costs against the input price.
    /// [`CACHE_READ_MULTIPLIER`] when the row does not set it. Used
    /// when the row has no `cache_read_per_million_usd`.
    #[serde(default = "default_cache_read_multiplier")]
    pub cache_read_multiplier: f64,
    /// The vendor's own price for a cache read. `None` for a row that
    /// lists none; the multiplier above is then the estimate.
    #[serde(default)]
    pub cache_read_per_million_usd: Option<f64>,
    /// The vendor's own price for a cache write kept five minutes.
    /// `None` for a row that lists none; [`CACHE_WRITE_MULTIPLIER`]
    /// times input is then the estimate.
    #[serde(default)]
    pub cache_write_5m_per_million_usd: Option<f64>,
    /// The vendor's own price for a cache write kept one hour. `None`
    /// for a row that lists none; [`CACHE_WRITE_1H_MULTIPLIER`] times
    /// input is then the estimate.
    #[serde(default)]
    pub cache_write_1h_per_million_usd: Option<f64>,
    /// The prices a call pays when its prompt is longer than
    /// `over_prompt_tokens`. `None` for a model with one price at
    /// every prompt length.
    #[serde(default)]
    pub long_prompt: Option<LongPrompt>,
    /// The prices that replace the row's own from a date on. `None`
    /// for a model with no announced price change.
    #[serde(default)]
    pub scheduled: Option<Scheduled>,
}

/// A price change the vendor has announced for a date.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scheduled {
    /// The instant from which a call pays the prices below.
    #[serde(deserialize_with = "wirken_time::serde_z::deserialize")]
    pub from: wirken_time::Timestamp,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

/// The second price tier of a model priced by prompt length.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LongPrompt {
    /// A prompt of more tokens than this pays the prices below. The
    /// prompt is the call's whole input: uncached input, cache writes
    /// and cache reads.
    pub over_prompt_tokens: u32,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

fn default_cache_read_multiplier() -> f64 {
    CACHE_READ_MULTIPLIER
}

#[derive(Debug, Deserialize)]
struct PricingFile {
    #[serde(default)]
    entries: Vec<PricingEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PricingEntry {
    provider: String,
    model: String,
    input_per_million_usd: f64,
    output_per_million_usd: f64,
    #[serde(default = "default_cache_read_multiplier")]
    cache_read_multiplier: f64,
    #[serde(default)]
    cache_read_per_million_usd: Option<f64>,
    #[serde(default)]
    cache_write_5m_per_million_usd: Option<f64>,
    #[serde(default)]
    cache_write_1h_per_million_usd: Option<f64>,
    #[serde(default)]
    long_prompt: Option<LongPrompt>,
    #[serde(default)]
    scheduled: Option<Scheduled>,
}

const BAKED_PRICING_TOML: &str = include_str!("pricing.toml");

fn table() -> &'static HashMap<(String, String), Pricing> {
    static TABLE: OnceLock<HashMap<(String, String), Pricing>> = OnceLock::new();
    TABLE.get_or_init(|| parse_table(BAKED_PRICING_TOML))
}

fn parse_table(raw: &str) -> HashMap<(String, String), Pricing> {
    // Parse failure on the baked file is a build-time bug — the file
    // is shipped in-tree and the compile_time_pricing_parses test
    // pins it. Panic so a malformed edit fails loudly rather than
    // silently emitting cost=None for every call.
    let parsed: PricingFile = toml::from_str(raw).expect("baked pricing.toml must parse");
    let mut map = HashMap::with_capacity(parsed.entries.len());
    for e in parsed.entries {
        map.insert(
            (e.provider, e.model),
            Pricing {
                input_per_million_usd: e.input_per_million_usd,
                output_per_million_usd: e.output_per_million_usd,
                cache_read_multiplier: e.cache_read_multiplier,
                cache_read_per_million_usd: e.cache_read_per_million_usd,
                cache_write_5m_per_million_usd: e.cache_write_5m_per_million_usd,
                cache_write_1h_per_million_usd: e.cache_write_1h_per_million_usd,
                long_prompt: e.long_prompt,
                scheduled: e.scheduled,
            },
        );
    }
    map
}

/// Compute per-call cost in USD micros for one `(provider, model)`
/// pair against the baked pricing table.
///
/// Returns `(input_cost_micros, output_cost_micros, total_cost_micros)`.
/// All three are `None` when the pair is absent from the table; the
/// caller is expected to emit a `tracing::warn` so a stale binary
/// against a new model is visible.
///
/// A 1 USD = 1_000_000 micros convention. Cost is floor-rounded
/// (truncation toward zero, which equals floor for non-negative
/// values) so re-summing recorded micros against a separate
/// f64-priced calculation cannot drift upward.
pub fn cost_micros(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    cost_micros_cached(provider, model, input_tokens, output_tokens, 0, 0)
}

/// The estimates used for a row that lists no cache price of its own:
/// what a prompt-cache write costs against the input price at the
/// five-minute and at the one-hour lifetime, and what a cache read
/// costs on a model whose row sets no `cache_read_multiplier`. A row
/// with the vendor's own cache prices does not use them.
pub const CACHE_WRITE_MULTIPLIER: f64 = 1.25;
pub const CACHE_WRITE_1H_MULTIPLIER: f64 = 2.0;
pub const CACHE_READ_MULTIPLIER: f64 = 0.1;

/// How long a prompt-cache write is kept. A vendor prices the two
/// lifetimes differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheWrite {
    FiveMinutes,
    OneHour,
}

/// The lifetime Wirken asks for on every cache breakpoint it sets: it
/// sends `cache_control: {"type": "ephemeral"}` with no `ttl`, which
/// is the five-minute lifetime. Cache writes are priced at this tier.
/// A change to the request that sets a `ttl` changes this with it.
pub const REQUESTED_CACHE_WRITE: CacheWrite = CacheWrite::FiveMinutes;

/// The `cache_control` value for [`REQUESTED_CACHE_WRITE`], so the
/// request and the price are read from one place.
pub fn requested_cache_control() -> serde_json::Value {
    match REQUESTED_CACHE_WRITE {
        CacheWrite::FiveMinutes => serde_json::json!({ "type": "ephemeral" }),
        CacheWrite::OneHour => serde_json::json!({ "type": "ephemeral", "ttl": "1h" }),
    }
}

/// [`cost_micros`] for a call that wrote to or read from a prompt
/// cache. A provider that reports cache counters reports `input_tokens`
/// without them, so the input cost is the three together: uncached
/// input at the input price, cache writes at the row's price for the
/// lifetime Wirken requests ([`REQUESTED_CACHE_WRITE`]) and cache
/// reads at the row's cache-read price. A row that lists no cache
/// price of its own is estimated: writes at
/// [`CACHE_WRITE_MULTIPLIER`] times input and reads at the row's
/// `cache_read_multiplier` times it. Left out, a cached conversation
/// would be recorded at a fraction of what it cost.
///
/// A model priced by prompt length pays its `long_prompt` prices, for
/// input and output both, on a call whose three input counts add up to
/// more than the row's `over_prompt_tokens`. A row with a `scheduled`
/// price pays it from that date on.
pub fn cost_micros_cached(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: u32,
    cache_read_input_tokens: u32,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    let key = (provider.to_string(), model.to_string());
    let Some(p) = table().get(&key) else {
        return (None, None, None);
    };
    let (input, output) = cost_at(
        p,
        wirken_time::now(),
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
    );
    (
        Some(input),
        Some(output),
        Some(input.saturating_add(output)),
    )
}

/// The cache-write tokens of one call, by the lifetime they were
/// written at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheWrites {
    pub five_minutes: u32,
    pub one_hour: u32,
}

/// The total cost in micros of a call whose cache writes are known by
/// lifetime, as a call some other client made reports them. Wirken's
/// own calls write at one lifetime and use [`cost_micros_cached`].
/// `None` when the table has no row for the pair.
pub fn cost_micros_by_write_lifetime(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    writes: CacheWrites,
    cache_read_input_tokens: u32,
) -> Option<u64> {
    let p = table().get(&(provider.to_string(), model.to_string()))?;
    let (input, output) = cost_at_writes(
        p,
        wirken_time::now(),
        input_tokens,
        output_tokens,
        writes,
        cache_read_input_tokens,
    );
    Some(input.saturating_add(output))
}

/// Whether the table has a row for `(provider, model)`: whether a call
/// to it records a cost.
pub fn is_priced(provider: &str, model: &str) -> bool {
    table().contains_key(&(provider.to_string(), model.to_string()))
}

/// What a million input tokens cost more when sent uncached than when
/// read from the prompt cache, at the row's base prices. `None` when
/// the model has no row.
pub fn uncached_premium_per_million_usd(provider: &str, model: &str) -> Option<f64> {
    let p = table().get(&(provider.to_string(), model.to_string()))?;
    let read = p
        .cache_read_per_million_usd
        .unwrap_or(p.input_per_million_usd * p.cache_read_multiplier);
    Some((p.input_per_million_usd - read).max(0.0))
}

/// Input and output cost in micros of one call made at `now` at the
/// prices of `p`.
fn cost_at(
    p: &Pricing,
    now: wirken_time::Timestamp,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: u32,
    cache_read_input_tokens: u32,
) -> (u64, u64) {
    // A call Wirken made wrote at the lifetime Wirken asked for.
    let writes = match REQUESTED_CACHE_WRITE {
        CacheWrite::FiveMinutes => CacheWrites {
            five_minutes: cache_creation_input_tokens,
            one_hour: 0,
        },
        CacheWrite::OneHour => CacheWrites {
            five_minutes: 0,
            one_hour: cache_creation_input_tokens,
        },
    };
    cost_at_writes(
        p,
        now,
        input_tokens,
        output_tokens,
        writes,
        cache_read_input_tokens,
    )
}

/// [`cost_at`] with the cache writes given by lifetime.
fn cost_at_writes(
    p: &Pricing,
    now: wirken_time::Timestamp,
    input_tokens: u32,
    output_tokens: u32,
    writes: CacheWrites,
    cache_read_input_tokens: u32,
) -> (u64, u64) {
    let prompt_tokens = u64::from(input_tokens)
        + u64::from(writes.five_minutes)
        + u64::from(writes.one_hour)
        + u64::from(cache_read_input_tokens);
    // `base` is false when a second tier or a scheduled price is in
    // effect. The row's own cache prices belong to its base input
    // price, so off the base the cache is estimated from the input
    // price that applies.
    let (input_price, output_price, base) = match p.long_prompt {
        Some(long) if prompt_tokens > u64::from(long.over_prompt_tokens) => (
            long.input_per_million_usd,
            long.output_per_million_usd,
            false,
        ),
        _ => match p.scheduled {
            Some(s) if now >= s.from => (s.input_per_million_usd, s.output_per_million_usd, false),
            _ => (p.input_per_million_usd, p.output_per_million_usd, true),
        },
    };
    let write_price = |lifetime: CacheWrite| {
        let (listed, multiplier) = match lifetime {
            CacheWrite::FiveMinutes => (p.cache_write_5m_per_million_usd, CACHE_WRITE_MULTIPLIER),
            CacheWrite::OneHour => (p.cache_write_1h_per_million_usd, CACHE_WRITE_1H_MULTIPLIER),
        };
        listed.filter(|_| base).unwrap_or(input_price * multiplier)
    };
    let read_price = p
        .cache_read_per_million_usd
        .filter(|_| base)
        .unwrap_or(input_price * p.cache_read_multiplier);
    let input = compute_one(input_tokens, input_price)
        .saturating_add(compute_one(
            writes.five_minutes,
            write_price(CacheWrite::FiveMinutes),
        ))
        .saturating_add(compute_one(
            writes.one_hour,
            write_price(CacheWrite::OneHour),
        ))
        .saturating_add(compute_one(cache_read_input_tokens, read_price));
    (input, compute_one(output_tokens, output_price))
}

/// `tokens * (usd_per_million / 1_000_000)` in micros simplifies to
/// `tokens * usd_per_million` (the per-million and the micros
/// multiplier are reciprocal). Floor via `as u64` on the non-negative
/// product.
fn compute_one(tokens: u32, usd_per_million: f64) -> u64 {
    // Guard against negative or non-finite pricing entries in case a
    // future edit lands one; treat as zero rather than panicking in
    // the hot path.
    if !usd_per_million.is_finite() || usd_per_million <= 0.0 {
        return 0;
    }
    let raw = f64::from(tokens) * usd_per_million;
    // `as u64` floors toward zero. f64 has 53 bits of mantissa, so for
    // realistic token counts (≤ ~10^7) and prices (≤ ~10^3) the
    // product fits exactly and the floor is the integer micros.
    raw as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_pricing_parses() {
        // Force the OnceLock to initialize. If pricing.toml is
        // malformed this panics in parse_table; the test catches it
        // before runtime.
        let t = table();
        assert!(!t.is_empty(), "baked pricing table is empty");
    }

    #[test]
    fn cache_writes_and_reads_are_priced_into_the_input_cost() {
        // $5 / 1M input. 1000 uncached, 1000 written, 10000 read:
        // 5_000 + 6_250 + 5_000 micros.
        let (inp, out, total) =
            cost_micros_cached("anthropic", "claude-opus-4-7", 1_000, 0, 1_000, 10_000);
        assert_eq!(inp, Some(16_250));
        assert_eq!(out, Some(0));
        assert_eq!(total, Some(16_250));
        // With no cache counters it is the plain price.
        assert_eq!(
            cost_micros_cached("anthropic", "claude-opus-4-7", 1_000, 0, 0, 0),
            cost_micros("anthropic", "claude-opus-4-7", 1_000, 0)
        );
        assert_eq!(
            cost_micros_cached("nonexistent", "model", 1, 1, 1, 1),
            (None, None, None)
        );
    }

    fn row(fields: &str) -> Pricing {
        let raw = format!("[[entries]]\nprovider = \"p\"\nmodel = \"m\"\n{fields}");
        parse_table(&raw)[&("p".to_string(), "m".to_string())]
    }

    fn at(text: &str) -> wirken_time::Timestamp {
        wirken_time::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn a_scheduled_price_starts_at_its_instant() {
        let p = row(
            "input_per_million_usd = 2.0\noutput_per_million_usd = 10.0\n\
             [entries.scheduled]\nfrom = \"2026-12-01T00:00:00Z\"\n\
             input_per_million_usd = 4.0\noutput_per_million_usd = 20.0",
        );
        assert_eq!(
            cost_at(&p, at("2026-11-30T23:59:59Z"), 1_000, 1_000, 0, 0),
            (2_000, 10_000)
        );
        assert_eq!(
            cost_at(&p, at("2026-12-01T00:00:00Z"), 1_000, 1_000, 0, 0),
            (4_000, 20_000)
        );
    }

    #[test]
    fn a_row_sets_its_own_cache_read_multiplier() {
        // $4 / 1M input, read at 0.05 times it: 10_000 read is 2_000.
        let p = row(
            "input_per_million_usd = 4.0\noutput_per_million_usd = 20.0\n\
             cache_read_multiplier = 0.05",
        );
        assert_eq!(
            cost_at(&p, at("2026-01-01T00:00:00Z"), 0, 0, 0, 10_000),
            (2_000, 0)
        );
        // A row that sets none reads at 0.1 times input.
        let p = row("input_per_million_usd = 4.0\noutput_per_million_usd = 20.0");
        assert_eq!(
            cost_at(&p, at("2026-01-01T00:00:00Z"), 0, 0, 0, 10_000),
            (4_000, 0)
        );
    }

    #[test]
    fn a_long_prompt_pays_the_second_tier() {
        let p = row(
            "input_per_million_usd = 0.1\noutput_per_million_usd = 0.5\n\
             [entries.long_prompt]\nover_prompt_tokens = 100000\n\
             input_per_million_usd = 0.5\noutput_per_million_usd = 2.5",
        );
        // At the threshold the first tier still applies.
        assert_eq!(
            cost_at(&p, at("2026-01-01T00:00:00Z"), 100_000, 1_000, 0, 0),
            (10_000, 500)
        );
        // One token over, input and output both move.
        assert_eq!(
            cost_at(&p, at("2026-01-01T00:00:00Z"), 100_001, 1_000, 0, 0),
            (50_000, 2_500)
        );
        // Cache writes and reads count toward the prompt length, and
        // are priced off the second tier's input price:
        // 10_000 * 0.5 + 40_000 * 0.625 + 60_000 * 0.05.
        assert_eq!(
            cost_at(&p, at("2026-01-01T00:00:00Z"), 10_000, 0, 40_000, 60_000),
            (33_000, 0)
        );
    }

    #[test]
    #[should_panic(expected = "baked pricing.toml must parse")]
    fn an_unknown_row_key_fails_the_parse() {
        row("input_per_million_usd = 1.0\noutput_per_million_usd = 1.0\ncache_read = 0.1");
    }

    #[test]
    fn cost_arithmetic_exact_micros() {
        // $5 / 1M input tokens, 1000 tokens.
        // 1000 * 5.0 = 5_000 micros = $0.005. Exact.
        let (inp, out, total) = cost_micros("anthropic", "claude-opus-4-7", 1_000, 0);
        assert_eq!(inp, Some(5_000));
        assert_eq!(out, Some(0));
        assert_eq!(total, Some(5_000));
    }

    #[test]
    fn cost_arithmetic_floors_fractional_micros() {
        // gpt-4o-mini input: $0.15 / 1M tokens.
        // 7 tokens * 0.15 = 1.05 micros. Floor to 1.
        // Output: $0.60 / 1M. 3 tokens * 0.60 = 1.80 micros. Floor to 1.
        let (inp, out, total) = cost_micros("openai", "gpt-4o-mini", 7, 3);
        assert_eq!(inp, Some(1));
        assert_eq!(out, Some(1));
        assert_eq!(total, Some(2));
    }

    #[test]
    fn cost_arithmetic_large_token_counts() {
        // 200_000 tokens * $3.0/M = 600_000 micros = $0.60. Exact.
        let (inp, _, _) = cost_micros("anthropic", "claude-sonnet-4-6", 200_000, 0);
        assert_eq!(inp, Some(600_000));
    }

    #[test]
    fn cost_total_is_sum_of_input_and_output() {
        // claude-sonnet-4-6: $3 in, $15 out.
        // 10_000 in -> 30_000 micros. 5_000 out -> 75_000 micros.
        // Total: 105_000 micros.
        let (inp, out, total) = cost_micros("anthropic", "claude-sonnet-4-6", 10_000, 5_000);
        assert_eq!(inp, Some(30_000));
        assert_eq!(out, Some(75_000));
        assert_eq!(total, Some(105_000));
    }

    /// The rates Anthropic lists for Mythos 5.2 and Fable 5.2: $8
    /// input, $40 output, $10 for a five-minute cache write, $16 for a
    /// one-hour one, $0.20 for a cache read.
    #[test]
    fn mythos_and_fable_5_2_pay_their_listed_cache_prices() {
        for model in ["claude-mythos-5-2", "claude-fable-5-2"] {
            let p = table()
                .get(&("anthropic".to_string(), model.to_string()))
                .unwrap_or_else(|| panic!("{model} has no row"));
            assert_eq!(p.input_per_million_usd, 8.0, "{model}");
            assert_eq!(p.output_per_million_usd, 40.0, "{model}");
            assert_eq!(p.cache_write_5m_per_million_usd, Some(10.0), "{model}");
            assert_eq!(p.cache_write_1h_per_million_usd, Some(16.0), "{model}");
            assert_eq!(p.cache_read_per_million_usd, Some(0.2), "{model}");
            // 2,168 input, 1,281,647 output, 11,947,033 cache read and
            // 1,749,117 cache write:
            //   17,344 + 17,491,170 + 2,389,406 input-side micros,
            //   51,265,880 output micros.
            let (inp, out, total) =
                cost_micros_cached("anthropic", model, 2_168, 1_281_647, 1_749_117, 11_947_033);
            assert_eq!(inp, Some(19_897_920), "{model}");
            assert_eq!(out, Some(51_265_880), "{model}");
            assert_eq!(total, Some(71_163_800), "{model}");
        }
        // The fallback would have charged the reads at 0.1 times input,
        // four times the listed price.
        assert_eq!(
            compute_one(11_947_033, 8.0 * CACHE_READ_MULTIPLIER),
            9_557_626
        );
        assert_eq!(compute_one(11_947_033, 0.2), 2_389_406);
    }

    #[test]
    fn the_premium_for_sending_input_uncached_is_input_less_cache_read() {
        assert!(is_priced("anthropic", "claude-mythos-5-2"));
        assert!(!is_priced("anthropic", "no-such-model"));
        // $8 input, $0.20 cache read.
        let premium = uncached_premium_per_million_usd("anthropic", "claude-mythos-5-2").unwrap();
        assert!((premium - 7.8).abs() < 1e-9, "{premium}");
        // $5 input, read at the 0.1 estimate.
        let premium = uncached_premium_per_million_usd("anthropic", "claude-opus-4-7").unwrap();
        assert!((premium - 4.5).abs() < 1e-9, "{premium}");
        assert_eq!(
            uncached_premium_per_million_usd("nonexistent", "model"),
            None
        );
    }

    /// Wirken asks for the five-minute lifetime, so a write is priced
    /// at the five-minute rate and not the one-hour one.
    #[test]
    fn a_cache_write_is_priced_at_the_lifetime_wirken_requests() {
        assert_eq!(REQUESTED_CACHE_WRITE, CacheWrite::FiveMinutes);
        assert_eq!(
            requested_cache_control(),
            serde_json::json!({ "type": "ephemeral" })
        );
        let p = row(
            "input_per_million_usd = 8.0\noutput_per_million_usd = 40.0\n\
             cache_write_5m_per_million_usd = 10.0\ncache_write_1h_per_million_usd = 16.0\n\
             cache_read_per_million_usd = 0.2",
        );
        let now = at("2026-01-01T00:00:00Z");
        assert_eq!(cost_at(&p, now, 0, 0, 1_000_000, 0), (10_000_000, 0));
        assert_eq!(cost_at(&p, now, 0, 0, 0, 1_000_000), (200_000, 0));
        // A row with no cache price of its own is estimated.
        let q = row("input_per_million_usd = 8.0\noutput_per_million_usd = 40.0");
        assert_eq!(cost_at(&q, now, 0, 0, 1_000_000, 0), (10_000_000, 0));
        assert_eq!(cost_at(&q, now, 0, 0, 0, 1_000_000), (800_000, 0));
    }

    #[test]
    fn every_row_is_a_usable_price() {
        for ((provider, model), p) in table() {
            let id = format!("{provider}/{model}");
            for price in [p.input_per_million_usd, p.output_per_million_usd] {
                assert!(price.is_finite() && price > 0.0, "{id}");
            }
            let listed = [
                p.cache_read_per_million_usd,
                p.cache_write_5m_per_million_usd,
                p.cache_write_1h_per_million_usd,
            ];
            for price in listed.into_iter().flatten() {
                assert!(price.is_finite() && price > 0.0, "{id}");
            }
            if let Some(read) = p.cache_read_per_million_usd {
                assert!(read < p.input_per_million_usd, "{id}");
            }
            if let Some(write) = p.cache_write_5m_per_million_usd {
                assert!(write >= p.input_per_million_usd, "{id}");
            }
            assert!(
                p.cache_read_multiplier > 0.0 && p.cache_read_multiplier <= 1.0,
                "{id}"
            );
            if let Some(s) = p.scheduled {
                // One second tier per row: a scheduled price does not
                // reach a long-prompt tier.
                assert!(p.long_prompt.is_none(), "{id}");
                for price in [s.input_per_million_usd, s.output_per_million_usd] {
                    assert!(price.is_finite() && price > 0.0, "{id}");
                }
            }
            if let Some(long) = p.long_prompt {
                assert!(long.over_prompt_tokens > 0, "{id}");
                assert!(long.input_per_million_usd > p.input_per_million_usd, "{id}");
                assert!(
                    long.output_per_million_usd > p.output_per_million_usd,
                    "{id}"
                );
            }
        }
    }

    #[test]
    fn the_table_carries_each_model_s_own_rates() {
        // Opus 5.5: $4 in, $20 out, cache read at 0.05 times input.
        assert_eq!(
            cost_micros_cached("anthropic", "claude-opus-5-5", 1_000, 1_000, 0, 10_000),
            (Some(6_000), Some(20_000), Some(26_000))
        );
        // Haiku 5.5 moves to $0.50 / $2.50 over a 100,000 token prompt.
        assert_eq!(
            cost_micros("anthropic", "claude-haiku-5-5", 100_000, 1_000),
            (Some(10_000), Some(500), Some(10_500))
        );
        assert_eq!(
            cost_micros("anthropic", "claude-haiku-5-5", 200_000, 1_000),
            (Some(100_000), Some(2_500), Some(102_500))
        );
        // gpt-5.5: $5 / $30, and $10 / $45 over 272,000.
        assert_eq!(
            cost_micros("openai", "gpt-5.5", 300_000, 1_000),
            (Some(3_000_000), Some(45_000), Some(3_045_000))
        );
        // Bedrock: the global profile at the list price, the regional
        // id ten percent over it.
        assert_eq!(
            cost_micros("bedrock", "global.anthropic.claude-opus-4-7", 1_000, 0).0,
            Some(5_000)
        );
        assert_eq!(
            cost_micros("bedrock", "anthropic.claude-opus-4-7", 1_000, 0).0,
            Some(5_500)
        );
        // gemini-2.5-pro: $1.25 / $10, and $2.50 / $15 over 200,000.
        assert_eq!(
            cost_micros("gemini", "gemini-2.5-pro", 200_001, 0).0,
            Some(500_002)
        );
    }

    #[test]
    fn cost_missing_provider_returns_none() {
        let (inp, out, total) = cost_micros("nonexistent", "model", 1000, 1000);
        assert_eq!(inp, None);
        assert_eq!(out, None);
        assert_eq!(total, None);
    }

    #[test]
    fn cost_missing_model_returns_none() {
        // Known provider, unknown model.
        let (inp, out, total) = cost_micros("anthropic", "model-never-shipped", 1000, 1000);
        assert_eq!(inp, None);
        assert_eq!(out, None);
        assert_eq!(total, None);
    }

    #[test]
    fn cost_local_provider_returns_none() {
        // Ollama and tinfoil are intentionally absent from the table —
        // operator-run hardware has no per-token vendor cost. Confirm
        // the lookup returns None rather than treating absence as
        // zero (which would silently understate cost if a future edit
        // mis-categorizes a vendor-priced model as local).
        let (inp, out, total) = cost_micros("ollama", "llama3", 1000, 1000);
        assert_eq!(inp, None);
        assert_eq!(out, None);
        assert_eq!(total, None);
    }

    #[test]
    fn cost_zero_tokens_zero_micros() {
        let (inp, out, total) = cost_micros("anthropic", "claude-opus-4-7", 0, 0);
        assert_eq!(inp, Some(0));
        assert_eq!(out, Some(0));
        assert_eq!(total, Some(0));
    }

    /// A cache write is priced at the lifetime it was written at: an
    /// hour costs twice the input price where the row lists none,
    /// five minutes one and a quarter.
    #[test]
    fn a_cache_write_is_priced_at_its_own_lifetime() {
        let at = |five_minutes, one_hour| {
            cost_micros_by_write_lifetime(
                "anthropic",
                "claude-sonnet-4-6",
                0,
                0,
                CacheWrites {
                    five_minutes,
                    one_hour,
                },
                0,
            )
        };
        assert_eq!(at(1_000_000, 0), Some(3_750_000));
        assert_eq!(at(0, 1_000_000), Some(6_000_000));
        assert_eq!(at(1_000_000, 1_000_000), Some(9_750_000));
        // The five-minute price is the one a call of Wirken's own pays.
        assert_eq!(
            at(1_000_000, 0),
            cost_micros_cached("anthropic", "claude-sonnet-4-6", 0, 0, 1_000_000, 0).2
        );
        assert_eq!(
            cost_micros_by_write_lifetime(
                "anthropic",
                "no-such-model",
                1,
                1,
                CacheWrites::default(),
                0
            ),
            None
        );
    }
}
