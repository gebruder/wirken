//! Zirkel preset orchestrator.
//!
//! Implements the daily-fetch pipeline that runs from `wirken zirkel run`
//! (cron or manual). Reads the installed Zirkel preset's permissions
//! block and `sources.toml`, constructs an [`wirken_agent::egress::EgressClient`]
//! wrapping a [`wirken_agent::rate_limit::RateLimitedClient`] from the
//! aggregator skill's policy, fetches sources, dedups against the seen
//! set in [`wirken_skill_store::SkillStore`], and writes candidate rows.
//!
//! ## What ships in Scope B
//!
//! Pure Rust pipeline through policed transport: fetch → write → exit.
//! No LLM call (relevance scoring is Scope C). No clustering, no theme
//! naming, no digest push.

pub mod orchestrator;
