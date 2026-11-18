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
    /// [`CACHE_READ_MULTIPLIER`] when the row does not set it.
    #[serde(default = "default_cache_read_multiplier")]
    pub cache_read_multiplier: f64,
    /// The prices a call pays when its prompt is longer than
    /// `over_prompt_tokens`. `None` for a model with one price at
    /// every prompt length.
    #[serde(default)]
    pub long_prompt: Option<LongPrompt>,
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
    long_prompt: Option<LongPrompt>,
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
                long_prompt: e.long_prompt,
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

/// What a prompt-cache write costs against the input price, at the
/// default five-minute lifetime, and what a cache read costs on a
/// model whose row sets no `cache_read_multiplier`.
pub const CACHE_WRITE_MULTIPLIER: f64 = 1.25;
pub const CACHE_READ_MULTIPLIER: f64 = 0.1;

/// [`cost_micros`] for a call that wrote to or read from a prompt
/// cache. A provider that reports cache counters reports `input_tokens`
/// without them, so the input cost is the three together: uncached
/// input at the input price, cache writes at
/// [`CACHE_WRITE_MULTIPLIER`] times it and cache reads at the row's
/// `cache_read_multiplier` times it. Left out, a cached conversation
/// would be recorded at a fraction of what it cost.
///
/// A model priced by prompt length pays its `long_prompt` prices, for
/// input and output both, on a call whose three input counts add up to
/// more than the row's `over_prompt_tokens`.
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

/// Input and output cost in micros of one call at the prices of `p`.
fn cost_at(
    p: &Pricing,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: u32,
    cache_read_input_tokens: u32,
) -> (u64, u64) {
    let prompt_tokens = u64::from(input_tokens)
        + u64::from(cache_creation_input_tokens)
        + u64::from(cache_read_input_tokens);
    let (input_price, output_price) = match p.long_prompt {
        Some(long) if prompt_tokens > u64::from(long.over_prompt_tokens) => {
            (long.input_per_million_usd, long.output_per_million_usd)
        }
        _ => (p.input_per_million_usd, p.output_per_million_usd),
    };
    let input = compute_one(input_tokens, input_price)
        .saturating_add(compute_one(
            cache_creation_input_tokens,
            input_price * CACHE_WRITE_MULTIPLIER,
        ))
        .saturating_add(compute_one(
            cache_read_input_tokens,
            input_price * p.cache_read_multiplier,
        ));
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
        // $15 / 1M input. 1000 uncached, 1000 written, 10000 read:
        // 15_000 + 18_750 + 15_000 micros.
        let (inp, out, total) =
            cost_micros_cached("anthropic", "claude-opus-4-7", 1_000, 0, 1_000, 10_000);
        assert_eq!(inp, Some(48_750));
        assert_eq!(out, Some(0));
        assert_eq!(total, Some(48_750));
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

    #[test]
    fn a_row_sets_its_own_cache_read_multiplier() {
        // $4 / 1M input, read at 0.05 times it: 10_000 read is 2_000.
        let p = row(
            "input_per_million_usd = 4.0\noutput_per_million_usd = 20.0\n\
             cache_read_multiplier = 0.05",
        );
        assert_eq!(cost_at(&p, 0, 0, 0, 10_000), (2_000, 0));
        // A row that sets none reads at 0.1 times input.
        let p = row("input_per_million_usd = 4.0\noutput_per_million_usd = 20.0");
        assert_eq!(cost_at(&p, 0, 0, 0, 10_000), (4_000, 0));
    }

    #[test]
    fn a_long_prompt_pays_the_second_tier() {
        let p = row(
            "input_per_million_usd = 0.1\noutput_per_million_usd = 0.5\n\
             [entries.long_prompt]\nover_prompt_tokens = 100000\n\
             input_per_million_usd = 0.5\noutput_per_million_usd = 2.5",
        );
        // At the threshold the first tier still applies.
        assert_eq!(cost_at(&p, 100_000, 1_000, 0, 0), (10_000, 500));
        // One token over, input and output both move.
        assert_eq!(cost_at(&p, 100_001, 1_000, 0, 0), (50_000, 2_500));
        // Cache writes and reads count toward the prompt length, and
        // are priced off the second tier's input price:
        // 10_000 * 0.5 + 40_000 * 0.625 + 60_000 * 0.05.
        assert_eq!(cost_at(&p, 10_000, 0, 40_000, 60_000), (33_000, 0));
    }

    #[test]
    #[should_panic(expected = "baked pricing.toml must parse")]
    fn an_unknown_row_key_fails_the_parse() {
        row("input_per_million_usd = 1.0\noutput_per_million_usd = 1.0\ncache_read = 0.1");
    }

    #[test]
    fn cost_arithmetic_exact_micros() {
        // $15 / 1M input tokens, 1000 tokens.
        // 1000 * 15.0 = 15_000 micros = $0.015. Exact.
        let (inp, out, total) = cost_micros("anthropic", "claude-opus-4-7", 1_000, 0);
        assert_eq!(inp, Some(15_000));
        assert_eq!(out, Some(0));
        assert_eq!(total, Some(15_000));
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
}
