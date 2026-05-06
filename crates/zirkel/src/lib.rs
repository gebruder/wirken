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

pub mod binding;
pub mod cluster;
pub mod digest;
pub mod digest_log;
pub mod embedding;
pub mod fetcher;
pub mod fetcher_congress;
pub mod fetcher_federal_register;
pub mod fetcher_govinfo;
pub mod fetcher_keyed;
pub mod fetcher_registry;
pub mod interests;
pub mod keep_skip;
pub mod keep_skip_interceptor;
pub mod llm_score;
pub mod orchestrator;
pub mod perspectives;
#[cfg(unix)]
pub mod push_client;
pub mod schema;
pub mod score;
pub mod synthetic_tool;
pub mod themes;
