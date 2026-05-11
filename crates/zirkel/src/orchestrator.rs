//! Zirkel orchestrator pipeline.
//!
//! Pure Rust pipeline through the policed HTTP transport. The LLM is
//! NOT in the fetch loop — that path was rejected during Scope B
//! design because subprocess HTTP (curl-via-exec) routes around
//! [`wirken_agent::egress::EgressClient`] and
//! [`wirken_agent::rate_limit::RateLimitedClient`] entirely. This
//! pipeline calls the policed client directly so egress allowlist
//! and rate-limit budget enforcement are structural.
//!
//! ## What ships in the C-foundation slice
//!
//! - Load preset; read aggregator skill's permission profile.
//! - Load interests file from [`OrchestratorConfig::interests_path`]
//!   and snapshot it into `interests_snapshots` for the run.
//! - For every source in `sources.toml`: dispatch by `method` (RSS
//!   and Atom go through [`crate::fetcher`]; API and scrape methods
//!   are unsupported in this slice and logged as skipped).
//! - Dedup parsed items against the `seen` table by URL.
//! - Screen each new item with [`crate::score::screen`] — exclusions
//!   take precedence over keyword matches; items with score 0 land in
//!   `skipped_log`, not `candidates`.
//! - Write kept items to `candidates` with `run_id`, `matched_keywords`,
//!   and `keyword_match_score`.
//! - Emit `HttpFetch`, `CandidateScored`, `CandidateSkipped`, and
//!   `InterestsEdited` audit events into the supplied
//!   [`wirken_audit::SessionLog`].
//!
//! Scoring's `keyword_match_score` field is the count of distinct
//! keyword matches against title + abstract, not a 0–100 relevance
//! rating. The C-LLM slice adds a separate `llm_relevance_score
//! REAL` column for the LLM-driven relevance pass; the keyword score
//! stays as a transparent first filter the user can verify.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use wirken_agent::egress::{EgressClient, EgressEnforcement, HttpAccessDenied};
use wirken_agent::preset::PresetLoader;
use wirken_agent::rate_limit::RateLimitConfig;
use wirken_agent::skill_perms::PermissionProfile;
use wirken_audit::{
    HashHex, HttpFetchOutcome, OwnSession, SessionEvent, SessionHandle, SessionId, SessionLog,
    TrustLevel,
};
use wirken_skill_store::{SkillStore, SkillStoreError};

use wirken_agent::llm::LlmClient;

use crate::cluster::{ClusterLabel, cluster as cluster_embeddings, group_by_cluster};
use crate::embedding::embed_batch;
use crate::fetcher::{
    FetchError, FetchedItem, RssFetcher, SourceConfig, WIKIPEDIA_TOC_METHOD, WikipediaTocFetcher,
};
use crate::fetcher_congress::CongressBillFetcher;
use crate::fetcher_federal_register::FederalRegisterFetcher;
use crate::fetcher_govinfo::GovInfoBillsFetcher;
use crate::fetcher_registry::FetcherRegistry;
use crate::interests::{InterestsError, last_snapshot_hash, load as load_interests, snapshot};
use crate::llm_score::score_candidate;
use crate::schema::AGGREGATOR_MIGRATIONS;
use crate::score::{Item, Screened, screen};
use crate::themes::{ClusterMember, name_theme};

const AGGREGATOR_SKILL_NAME: &str = "aggregator";

/// Caller-supplied configuration for [`run`].
pub struct OrchestratorConfig {
    /// Directory of the installed preset (e.g. `~/.wirken/presets/zirkel/`).
    pub preset_dir: PathBuf,
    /// Directory where the aggregator's SQLite store lives. Must be
    /// inside the aggregator skill's
    /// `permissions.filesystem.write_paths` allow-set.
    pub storage_dir: PathBuf,
    /// Path to the interests file. Conventionally `<storage_dir>/interests.toml`
    /// but kept explicit so tests can drop a fixture anywhere.
    pub interests_path: PathBuf,
    /// Rate-limit config for per-source HTTP. Production uses
    /// [`RateLimitConfig::default`]; tests can pass
    /// [`RateLimitConfig::unrestricted_for_tests`] to skip jitter.
    pub rate_limit: RateLimitConfig,
    /// Audit log to emit fetch / score / skip events into. `None`
    /// disables audit emission — useful for tests that don't care
    /// about audit chain semantics. Production threads in the same
    /// `Arc<dyn SessionLog>` the rest of Wirken uses so the chain is
    /// continuous across orchestrator runs and agent sessions.
    pub session_log: Option<Arc<dyn SessionLog>>,
    /// LLM client for the relevance-scoring + theme-naming passes.
    /// `None` disables both passes — kept items still land in the
    /// database with `llm_relevance_score` NULL and no `themes` rows.
    /// Production threads an `LlmClient` configured for the agent's
    /// `inference.default` provider; tests pass `None` (skip) or a
    /// client pointing at a local mock server.
    pub llm: Option<Arc<LlmClient>>,
    /// API key for the LLM provider. `None` is correct for Ollama
    /// (no auth) and for tests with a mock server.
    pub llm_api_key: Option<String>,
    /// Base URL for Ollama's `/api/embed` endpoint (the embedding
    /// pass for clustering). The orchestrator hits this through the
    /// policed [`EgressClient`] — `127.0.0.1` must be in the
    /// aggregator's `egress.domains` allow-set. Empty string disables
    /// embedding + clustering even when `llm` is set; useful for
    /// tests of the LLM-scoring path in isolation.
    pub ollama_embed_base: String,
    /// Embedding model name for the `/api/embed` request. Defaults to
    /// [`crate::embedding::DEFAULT_EMBEDDING_MODEL`] in the CLI; tests
    /// can pass any string the mock server will echo.
    pub embed_model: String,
    /// API keys for the api.data.gov-keyed sources, keyed by source
    /// name (matches `sources.toml`'s `name` field — e.g.
    /// `"congress-gov"`, `"govinfo-gov"`). The CLI populates this at
    /// startup from the wirken vault; the orchestrator registers the
    /// matching fetcher only when the key is present, otherwise the
    /// source records as unsupported.
    ///
    /// Keys are passed pre-resolved (operator's UID has already
    /// opened the vault). They never reach the agent / LLM layer:
    /// the keyed fetchers inject them into the X-Api-Key header at
    /// fetch time and the resulting [`FetchedItem`] flows downstream
    /// without the secret material.
    pub source_api_keys: std::collections::HashMap<String, String>,
    /// Perspective-guided query expansion (front-half of Stanford
    /// STORM, retrieval-only). When `false` the run is bit-identical
    /// to a pre-perspective build: no LLM expansion call, no
    /// PerspectiveExpansion audit event, no expansion_id field on
    /// HttpFetch / CandidateScored. When `true` and `topic` is set,
    /// the orchestrator runs one expansion turn before the fetcher
    /// loop and dispatches retrievers once per emitted label via
    /// synthetic `SourceConfig`s.
    pub perspectives_enabled: bool,
    /// Topic the expansion turn surveys. `None` (or empty) skips
    /// expansion even when `perspectives_enabled` is true. Only the
    /// labels produced from this topic land in the audit chain;
    /// the topic itself is not persisted in the candidates table.
    pub topic: Option<String>,
    /// Upper bound on perspective labels returned by the LLM. The
    /// expansion's structured-output tool caps at this value;
    /// callers further trim if the model returns more.
    pub max_perspectives: usize,
    /// Upper bound on related Wikipedia articles surveyed for
    /// section headings. Each surveyed title costs one Action API
    /// metadata fetch.
    pub max_related_topics: usize,
    /// Hard cap on retriever calls a single perspective-expansion
    /// turn may dispatch (perspectives x manifest sources). The
    /// orchestrator checks `max_perspectives * sources <= cap`
    /// before any expansion fetch goes out and skips the expansion
    /// entirely when over budget. The cap covers retriever calls,
    /// not the upstream Wikipedia metadata calls.
    pub per_topic_fanout_cap: usize,
    /// Override for the Wikipedia Action API endpoint. `None`
    /// resolves to [`crate::perspectives::DEFAULT_WIKIPEDIA_API_BASE`];
    /// tests redirect this at a localhost mock so the egress
    /// allowlist stays scoped to `127.0.0.1`.
    pub wikipedia_api_base: Option<String>,
    /// Agent that drove this orchestrator run. Threaded into
    /// [`SessionEvent::HttpFetch::agent_id`] so a SIEM consumer can
    /// correlate fetches back to the agent (and from there to the
    /// inbound that triggered the run). `None` when the run is
    /// agent-anonymous (cron + the rare ad-hoc CLI invocation).
    pub agent_id: Option<String>,
    /// Skill that owns the fetcher (`"zirkel"` for the standard
    /// orchestrator). `None` when the caller is not skill-attributable.
    pub skill_name: Option<String>,
}

/// Outcome of one orchestrator run, by category.
#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    pub run_id: String,
    pub sources_attempted: usize,
    pub sources_succeeded: usize,
    /// Sources whose method this slice does not yet support
    /// (api / scrape). Logged as skipped in the audit, not failed.
    pub sources_unsupported: Vec<String>,
    /// Sources whose fetch or parse failed. The run continues — one
    /// flaky source does not block the others.
    pub sources_failed: Vec<SourceFailure>,
    pub items_seen: usize,
    pub items_new: usize,
    pub items_excluded: usize,
    pub items_score_zero: usize,
    pub items_kept: usize,
    pub kept_candidate_ids: Vec<i64>,
    pub interests_changed: bool,
    /// Count of candidates the LLM relevance pass scored. Equals
    /// `items_kept` on a clean run; less if the LLM failed for some
    /// candidates (which is logged but doesn't abort the run).
    pub items_llm_scored: usize,
    /// `themes` rows written by the theme-naming pass. Zero when LLM
    /// is disabled, embedding fails, all items land in noise, or
    /// fewer than 2 items survived the filter (clustering is skipped).
    pub themes_named: usize,
    /// Per-candidate LLM-call failures during the relevance pass.
    /// Audit chain has the kept-item event but no LLM event for these.
    pub llm_score_failures: Vec<LlmStageFailure>,
    /// Embedding / clustering / theme-naming failures. Logged here
    /// for the CLI summary; the run completes regardless.
    pub theme_stage_failures: Vec<LlmStageFailure>,
    /// Ephemeral perspective labels emitted by the expansion turn,
    /// or empty when expansion was disabled or skipped. Mirrors what
    /// the `PerspectiveExpansion` audit event records; surfaced on
    /// `RunSummary` for the CLI summary line. Not persisted past
    /// this run.
    pub perspectives_used: Vec<String>,
    /// `Some` when this run dispatched retrievers under a
    /// perspective-expansion turn; the embedded UUID matches the
    /// `expansion_id` field on the corresponding audit events.
    pub expansion_id: Option<String>,
    /// True when expansion was enabled and a topic was supplied but
    /// the planned fan-out (max_perspectives x sources) exceeded the
    /// configured cap; surfaces the rejection on the summary so the
    /// CLI can warn the operator without re-deriving the check.
    pub perspective_skipped_over_budget: bool,
}

#[derive(Debug, Clone)]
pub struct LlmStageFailure {
    pub candidate_id: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SourceFailure {
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("load preset: {0}")]
    LoadPreset(String),
    #[error("aggregator skill missing from preset")]
    AggregatorSkillMissing,
    #[error("read sources.toml at {path}: {source}")]
    ReadSources {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse sources.toml at {path}: {message}")]
    ParseSources { path: PathBuf, message: String },
    #[error("load interests: {0}")]
    LoadInterests(#[from] InterestsError),
    #[error("skill store: {0}")]
    Store(#[from] SkillStoreError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// On-disk shape of `sources.toml`.
#[derive(Debug, Deserialize)]
struct SourcesManifest {
    #[serde(default, rename = "source")]
    sources: Vec<SourceEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct SourceEntry {
    name: String,
    endpoint: String,
    method: String,
}

/// Adapter so [`FetchedItem`] can be passed to [`screen`].
impl Item for FetchedItem {
    fn haystack(&self) -> String {
        format!("{} {}", self.title, self.abstract_text)
    }
}

/// Run the orchestrator once.
pub async fn run(config: OrchestratorConfig) -> Result<RunSummary, OrchestratorError> {
    let run_id = uuid::Uuid::new_v4().to_string();

    // Preset + aggregator profile.
    let loaded = PresetLoader::load_dir(&config.preset_dir)
        .map_err(|e| OrchestratorError::LoadPreset(e.to_string()))?;
    let aggregator = loaded
        .skills
        .iter()
        .find(|s| s.name == AGGREGATOR_SKILL_NAME)
        .ok_or(OrchestratorError::AggregatorSkillMissing)?;
    let profile: PermissionProfile = aggregator.permissions.clone();

    // Interests file is required — running without one would produce
    // an unscored fetch with no honest threshold for digest inclusion.
    let interests = load_interests(&config.interests_path)?;

    // Sources manifest.
    let sources_path = config.preset_dir.join("sources.toml");
    let raw =
        std::fs::read_to_string(&sources_path).map_err(|e| OrchestratorError::ReadSources {
            path: sources_path.clone(),
            source: e,
        })?;
    let manifest: SourcesManifest =
        toml::from_str(&raw).map_err(|e| OrchestratorError::ParseSources {
            path: sources_path.clone(),
            message: e.to_string(),
        })?;

    // Fetcher registry: built once per run. RSS handles both
    // `"rss"` and `"atom-api"` (feed-rs discriminates internally).
    // Federal Register lands on `"json-federal-register"`. The
    // api.data.gov-keyed fetchers (Congress, GovInfo) register here
    // only when their api key is present in
    // [`OrchestratorConfig::source_api_keys`] — otherwise the source
    // records as unsupported with a clear message rather than
    // failing the run.
    let mut fetchers = FetcherRegistry::new();
    {
        let rss: Arc<dyn crate::fetcher::Fetcher> = Arc::new(RssFetcher);
        fetchers.register("rss", rss.clone());
        fetchers.register("atom-api", rss);
        fetchers.register(
            crate::fetcher_federal_register::METHOD,
            Arc::new(FederalRegisterFetcher),
        );
        // Wikipedia TOC fetcher is registered unconditionally. It is
        // not reachable from `sources.toml` (operators would not
        // declare a wiki-section TOC as a research source); the
        // perspective-expansion module reaches it directly via the
        // registry by method name.
        fetchers.register(WIKIPEDIA_TOC_METHOD, Arc::new(WikipediaTocFetcher));
        if let Some(key) = config.source_api_keys.get("congress-gov") {
            fetchers.register(
                crate::fetcher_congress::METHOD,
                Arc::new(CongressBillFetcher::new(secrecy::SecretString::from(
                    key.clone(),
                ))),
            );
        }
        if let Some(key) = config.source_api_keys.get("govinfo-gov") {
            fetchers.register(
                crate::fetcher_govinfo::METHOD,
                Arc::new(GovInfoBillsFetcher::new(secrecy::SecretString::from(
                    key.clone(),
                ))),
            );
        }
    }

    // Build the rate-limit config: start from the caller-supplied
    // base (which carries jitter + global default cap), then for
    // each manifest source whose registered fetcher declares an
    // opinion, set the per-host override. This keeps the polite
    // 2/day default for unauthenticated scraping and lets the
    // documented-quota APIs run within their published budgets
    // without per-source TOML fields. Host is derived from the
    // endpoint URL so the override key matches what
    // [`wirken_agent::rate_limit::RateLimitedClient`] extracts at
    // request time.
    let mut rate_limit = config.rate_limit.clone();
    for source in &manifest.sources {
        let Some(fetcher) = fetchers.get(&source.method) else {
            continue;
        };
        let Some(cap) = fetcher.default_rate_limit_per_day() else {
            continue;
        };
        let Some(host) = url::Url::parse(&source.endpoint)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
        else {
            tracing::warn!(
                "source '{}' endpoint is not a parseable URL; rate-limit override skipped",
                source.name
            );
            continue;
        };
        rate_limit.per_host_overrides.entry(host).or_insert(cap);
    }
    let http = EgressClient::with_rate_limit(rate_limit);
    http.set_enforcement(EgressEnforcement::from_profile(
        &wirken_agent::skill_perms::EffectiveProfile::Resolved(profile.clone()),
    ));

    // Per-skill SQLite store.
    let mut store = SkillStore::open(AGGREGATOR_SKILL_NAME, &config.storage_dir, &profile)?;
    store.migrate(AGGREGATOR_MIGRATIONS)?;

    // Audit handle for this run.
    let audit_handle = config
        .session_log
        .as_ref()
        .map(|log| log.handle_for(SessionId::new(run_id.clone())));

    // Snapshot interests and detect change against the prior run.
    let prior_hash = last_snapshot_hash(store.conn())?;
    snapshot(store.conn(), &run_id, &interests)?;
    let interests_changed = match prior_hash.as_deref() {
        Some(h) if h != interests.file_hash => {
            emit(
                config.session_log.as_ref(),
                audit_handle.as_ref(),
                SessionEvent::InterestsEdited {
                    before_hash: HashHex(h.to_string()),
                    after_hash: HashHex(interests.file_hash.clone()),
                },
            );
            true
        }
        _ => false,
    };

    let mut summary = RunSummary {
        run_id: run_id.clone(),
        interests_changed,
        ..Default::default()
    };

    // Build the perspective passes for this run. The default
    // (perspectives disabled) is one pass with no label and no
    // expansion id, which iterates over the manifest sources
    // unchanged: bit-identical to the pre-perspective build.
    let perspective_passes: Vec<PerspectivePass> = build_perspective_passes(
        &config,
        &http,
        &manifest,
        &run_id,
        config.session_log.as_ref(),
        audit_handle.as_ref(),
        &mut summary,
    )
    .await;

    for pass in &perspective_passes {
        for source in &manifest.sources {
            summary.sources_attempted += 1;

            // Dispatch by method via the fetcher registry. Methods with
            // no registered fetcher (today: scrape; tomorrow: anything
            // not yet wired) record as unsupported and the run continues.
            let Some(fetcher) = fetchers.get(&source.method) else {
                summary.sources_unsupported.push(source.name.clone());
                tracing::info!(
                    "source '{}' uses method '{}' which is not registered (registered: {})",
                    source.name,
                    source.method,
                    fetchers.registered_methods().join(", "),
                );
                continue;
            };
            let source_cfg = pass.synthesize_source_config(source);
            let items = match fetcher.fetch(&http, &source_cfg).await {
                Ok(items) => {
                    emit_http_fetch(
                        config.session_log.as_ref(),
                        audit_handle.as_ref(),
                        &source_cfg.name,
                        &source_cfg.endpoint,
                        HttpFetchOutcome::Success,
                        None,
                        bytes_total(&items),
                        &run_id,
                        pass.expansion_id.as_deref(),
                        config.agent_id.as_deref(),
                        config.skill_name.as_deref(),
                    );
                    items
                }
                Err(e) => {
                    let (outcome, status) = fetch_outcome_label(&e);
                    emit_http_fetch(
                        config.session_log.as_ref(),
                        audit_handle.as_ref(),
                        &source_cfg.name,
                        &source_cfg.endpoint,
                        outcome,
                        status,
                        0,
                        &run_id,
                        pass.expansion_id.as_deref(),
                        config.agent_id.as_deref(),
                        config.skill_name.as_deref(),
                    );
                    summary.sources_failed.push(SourceFailure {
                        source: source_cfg.name.clone(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };

            summary.sources_succeeded += 1;
            summary.items_seen += items.len();

            for item in items {
                // Dedup against the seen table.
                let url_hash = sha256_hex(&item.url);
                let already_seen: i64 = store.conn().query_row(
                    "SELECT COUNT(*) FROM seen WHERE url_hash = ?1",
                    rusqlite::params![url_hash],
                    |row| row.get(0),
                )?;
                if already_seen > 0 {
                    emit_skip(
                        config.session_log.as_ref(),
                        audit_handle.as_ref(),
                        &run_id,
                        &item,
                        &url_hash,
                        "duplicate_url",
                    );
                    store.conn().execute(
                        "INSERT INTO skipped_log (run_id, url_hash, url, source_name, reason) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            &run_id,
                            &url_hash,
                            &item.url,
                            &item.source_name,
                            "duplicate_url"
                        ],
                    )?;
                    continue;
                }
                // Mark seen before screening so a later orchestrator run
                // doesn't re-discover the same URL even if screening
                // changed (e.g., updated interests file would make a
                // previously-excluded item now match a keyword).
                store.conn().execute(
                    "INSERT INTO seen (url, url_hash) VALUES (?1, ?2)",
                    rusqlite::params![&item.url, &url_hash],
                )?;
                summary.items_new += 1;

                match screen(&item, &interests.keywords, &interests.exclusions) {
                    Screened::Excluded { matched_exclusion } => {
                        summary.items_excluded += 1;
                        store.conn().execute(
                        "INSERT INTO skipped_log (run_id, url_hash, url, source_name, reason, detail) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            &run_id,
                            &url_hash,
                            &item.url,
                            &item.source_name,
                            "exclusion_match",
                            matched_exclusion
                        ],
                    )?;
                        emit_skip(
                            config.session_log.as_ref(),
                            audit_handle.as_ref(),
                            &run_id,
                            &item,
                            &url_hash,
                            "exclusion_match",
                        );
                    }
                    Screened::Zero => {
                        summary.items_score_zero += 1;
                        store.conn().execute(
                            "INSERT INTO skipped_log (run_id, url_hash, url, source_name, reason) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params![
                                &run_id,
                                &url_hash,
                                &item.url,
                                &item.source_name,
                                "score_zero"
                            ],
                        )?;
                        emit_skip(
                            config.session_log.as_ref(),
                            audit_handle.as_ref(),
                            &run_id,
                            &item,
                            &url_hash,
                            "score_zero",
                        );
                    }
                    Screened::Kept {
                        matched_keywords,
                        keyword_match_score,
                    } => {
                        let matched_json = serde_json::to_string(&matched_keywords)
                            .unwrap_or_else(|_| "[]".to_string());
                        let published_at: Option<String> = if item.published_at.is_empty() {
                            None
                        } else {
                            Some(item.published_at.clone())
                        };
                        // Default empty source_metadata to '{}' so the
                        // column's NOT NULL DEFAULT semantics match the
                        // value the fetcher passed (or didn't).
                        let source_metadata: &str = if item.source_metadata.is_empty() {
                            "{}"
                        } else {
                            &item.source_metadata
                        };
                        store.conn().execute(
                            "INSERT INTO candidates ( \
                            source_name, url, body, run_id, title, published_at, \
                            matched_keywords, keyword_match_score, source_metadata \
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                            rusqlite::params![
                                &item.source_name,
                                &item.url,
                                &item.abstract_text,
                                &run_id,
                                &item.title,
                                &published_at,
                                &matched_json,
                                keyword_match_score as i64,
                                source_metadata,
                            ],
                        )?;
                        let candidate_id = store.conn().last_insert_rowid();
                        summary.items_kept += 1;
                        summary.kept_candidate_ids.push(candidate_id);
                        emit_candidate_scored(
                            config.session_log.as_ref(),
                            audit_handle.as_ref(),
                            &run_id,
                            candidate_id,
                            keyword_match_score,
                            matched_keywords.clone(),
                            pass.expansion_id.as_deref(),
                        );
                    }
                }
            }
        }
    }

    // ----- LLM relevance scoring pass --------------------------------
    // One LLM call per kept candidate. Failures are logged in the run
    // summary but don't abort the run — the keyword pass already
    // recorded the candidate; the LLM pass adds nuance, not gating.
    if let Some(llm) = config.llm.as_ref() {
        run_llm_score_pass(
            &store,
            llm,
            config.llm_api_key.as_deref(),
            &interests,
            &run_id,
            config.session_log.as_ref(),
            audit_handle.as_ref(),
            &mut summary,
        )
        .await;

        // ----- Embedding + clustering + theme naming -----------------
        // Skipped when fewer than 2 candidates landed in this run
        // (HDBSCAN can't cluster a single point) or when the operator
        // explicitly disabled embedding by passing an empty
        // `ollama_embed_base`.
        if summary.items_kept >= 2 && !config.ollama_embed_base.is_empty() {
            run_theme_pass(
                &store,
                &http,
                llm,
                config.llm_api_key.as_deref(),
                &config.ollama_embed_base,
                &config.embed_model,
                &run_id,
                config.session_log.as_ref(),
                audit_handle.as_ref(),
                &mut summary,
            )
            .await;
        }
    }

    Ok(summary)
}

/// Iterate this run's kept candidates, call the LLM relevance scorer
/// for each, write the result back, emit the audit event. Per-candidate
/// failures land in `summary.llm_score_failures` and the run continues.
#[allow(clippy::too_many_arguments)]
async fn run_llm_score_pass(
    store: &SkillStore,
    llm: &LlmClient,
    api_key: Option<&str>,
    interests: &crate::interests::Interests,
    run_id: &str,
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    summary: &mut RunSummary,
) {
    let candidates: Vec<(i64, FetchedItem)> = match collect_run_candidates(store, run_id) {
        Ok(c) => c,
        Err(e) => {
            summary.theme_stage_failures.push(LlmStageFailure {
                candidate_id: None,
                reason: format!("read run candidates: {e}"),
            });
            return;
        }
    };

    for (cid, item) in candidates {
        match score_candidate(llm, api_key, &item, interests).await {
            Ok(score) => {
                let res = store.conn().execute(
                    "UPDATE candidates SET llm_relevance_score = ?1, llm_why_surfaced = ?2 \
                     WHERE id = ?3",
                    rusqlite::params![score.score as i64, score.why_surfaced, cid],
                );
                if let Err(e) = res {
                    summary.llm_score_failures.push(LlmStageFailure {
                        candidate_id: Some(cid),
                        reason: format!("update candidate row: {e}"),
                    });
                    continue;
                }
                summary.items_llm_scored += 1;
                emit(
                    session_log,
                    handle,
                    SessionEvent::CandidateLlmScored {
                        run_id: run_id.to_string(),
                        candidate_id: cid,
                        llm_relevance_score: score.score,
                        matched_keyword: score.matched_keyword,
                        why_surfaced: score.why_surfaced,
                    },
                );
            }
            Err(e) => {
                tracing::warn!("LLM scoring failed for candidate {cid}: {e}");
                summary.llm_score_failures.push(LlmStageFailure {
                    candidate_id: Some(cid),
                    reason: e.to_string(),
                });
            }
        }
    }
}

/// Embed every kept candidate, cluster, name each cluster, write the
/// `themes` rows and update each candidate's `cluster_id`. Stage-level
/// failures (embedding HTTP errors, clustering failure, individual
/// theme-naming failures) land in `summary.theme_stage_failures` and
/// the run completes regardless.
#[allow(clippy::too_many_arguments)]
async fn run_theme_pass(
    store: &SkillStore,
    http: &EgressClient,
    llm: &LlmClient,
    api_key: Option<&str>,
    ollama_embed_base: &str,
    embed_model: &str,
    run_id: &str,
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    summary: &mut RunSummary,
) {
    // Pull (id, title, abstract, matched_keywords_json) for clustering.
    let rows: Vec<(i64, String, String, String)> = match collect_cluster_rows(store, run_id) {
        Ok(r) => r,
        Err(e) => {
            summary.theme_stage_failures.push(LlmStageFailure {
                candidate_id: None,
                reason: format!("query cluster rows: {e}"),
            });
            return;
        }
    };

    if rows.len() < 2 {
        return;
    }

    let texts: Vec<String> = rows
        .iter()
        .map(|(_, title, abs_, _)| format!("{title}\n\n{abs_}"))
        .collect();
    let text_refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    let embeddings = match embed_batch(http, ollama_embed_base, embed_model, &text_refs).await {
        Ok(e) => e,
        Err(e) => {
            summary.theme_stage_failures.push(LlmStageFailure {
                candidate_id: None,
                reason: format!("embed batch: {e}"),
            });
            return;
        }
    };

    let labels = match cluster_embeddings(&embeddings, 2, 1) {
        Ok(l) => l,
        Err(e) => {
            summary.theme_stage_failures.push(LlmStageFailure {
                candidate_id: None,
                reason: format!("hdbscan: {e}"),
            });
            return;
        }
    };

    // Build `(label, candidate_id, ClusterMember)` triples for grouping.
    let mut by_cluster: std::collections::BTreeMap<u32, Vec<(i64, ClusterMember)>> =
        Default::default();
    for ((row, label), _) in rows.iter().zip(labels.iter()).zip(0..) {
        if let ClusterLabel::Cluster(n) = label {
            let kws: Vec<String> = serde_json::from_str(&row.3).unwrap_or_default();
            by_cluster.entry(*n).or_default().push((
                row.0,
                ClusterMember {
                    title: row.1.clone(),
                    matched_keywords: kws,
                },
            ));
        }
    }

    // Use group_by_cluster to confirm parity with the expected shape.
    // (Functionally redundant with the loop above; kept as the public
    // API entry the cluster module exposes.)
    let _check = group_by_cluster(&labels, &rows);

    for (_cluster_label, members) in by_cluster.iter() {
        let cluster_members: Vec<ClusterMember> = members.iter().map(|(_, m)| m.clone()).collect();
        match name_theme(llm, api_key, &cluster_members).await {
            Ok(theme) => {
                let member_count = cluster_members.len() as i64;
                let res = store.conn().execute(
                    "INSERT INTO themes (run_id, name, member_count) VALUES (?1, ?2, ?3)",
                    rusqlite::params![run_id, &theme.name, member_count],
                );
                let theme_id = match res {
                    Ok(_) => store.conn().last_insert_rowid(),
                    Err(e) => {
                        summary.theme_stage_failures.push(LlmStageFailure {
                            candidate_id: None,
                            reason: format!("insert theme: {e}"),
                        });
                        continue;
                    }
                };
                for (cid, _) in members {
                    let _ = store.conn().execute(
                        "UPDATE candidates SET cluster_id = ?1 WHERE id = ?2",
                        rusqlite::params![theme_id, cid],
                    );
                }
                summary.themes_named += 1;
                emit(
                    session_log,
                    handle,
                    SessionEvent::ThemeNamed {
                        run_id: run_id.to_string(),
                        theme_id,
                        name: theme.name,
                        member_count: member_count as u32,
                    },
                );
            }
            Err(e) => {
                tracing::warn!("theme naming failed for cluster: {e}");
                summary.theme_stage_failures.push(LlmStageFailure {
                    candidate_id: None,
                    reason: format!("name_theme: {e}"),
                });
            }
        }
    }
}

fn collect_cluster_rows(
    store: &SkillStore,
    run_id: &str,
) -> Result<Vec<(i64, String, String, String)>, rusqlite::Error> {
    let conn = store.conn();
    let mut stmt =
        conn.prepare("SELECT id, title, body, matched_keywords FROM candidates WHERE run_id = ?1")?;
    stmt.query_map(rusqlite::params![run_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?
    .collect()
}

fn collect_run_candidates(
    store: &SkillStore,
    run_id: &str,
) -> Result<Vec<(i64, FetchedItem)>, rusqlite::Error> {
    let conn = store.conn();
    let mut stmt = conn.prepare(
        "SELECT id, source_name, url, title, body, COALESCE(published_at, '') \
         FROM candidates WHERE run_id = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![run_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            FetchedItem {
                source_name: row.get::<_, String>(1)?,
                url: row.get::<_, String>(2)?,
                title: row.get::<_, String>(3)?,
                abstract_text: row.get::<_, String>(4)?,
                published_at: row.get::<_, String>(5)?,
                // Not loaded — the LLM-scoring rebuild path
                // doesn't read source_metadata yet. Adding the
                // column to the SELECT is a future change when a
                // scoring prompt actually consumes it.
                source_metadata: String::new(),
            },
        ))
    })?;
    rows.collect()
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn bytes_total(items: &[FetchedItem]) -> u64 {
    items
        .iter()
        .map(|i| (i.title.len() + i.abstract_text.len()) as u64)
        .sum()
}

fn fetch_outcome_label(e: &FetchError) -> (HttpFetchOutcome, Option<u16>) {
    match e {
        FetchError::Denied {
            source: HttpAccessDenied::Egress(_),
            ..
        } => (HttpFetchOutcome::EgressDenied, None),
        FetchError::Denied {
            source: HttpAccessDenied::RateLimit(_),
            ..
        } => (HttpFetchOutcome::RateLimited, None),
        FetchError::HttpStatus { status, .. } => (HttpFetchOutcome::HttpError, Some(*status)),
        FetchError::Network { .. } => (HttpFetchOutcome::NetworkError, None),
        FetchError::Parse { .. } => (HttpFetchOutcome::NetworkError, None),
        FetchError::TooLarge { .. } => (HttpFetchOutcome::NetworkError, None),
    }
}

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn emit(
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    event: SessionEvent,
) {
    if let (Some(log), Some(handle)) = (session_log, handle) {
        if let Err(e) = log.append(handle, TrustLevel::System, event) {
            tracing::warn!("zirkel audit append failed: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_http_fetch(
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    source_name: &str,
    endpoint: &str,
    outcome: HttpFetchOutcome,
    http_status_code: Option<u16>,
    bytes: u64,
    run_id: &str,
    expansion_id: Option<&str>,
    agent_id: Option<&str>,
    skill_name: Option<&str>,
) {
    emit(
        session_log,
        handle,
        SessionEvent::HttpFetch {
            source: source_name.to_string(),
            host: host_of(endpoint),
            url: endpoint.to_string(),
            outcome,
            http_status_code,
            bytes,
            run_id: Some(run_id.to_string()),
            expansion_id: expansion_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            skill_name: skill_name.map(str::to_string),
        },
    );
}

fn emit_candidate_scored(
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    run_id: &str,
    candidate_id: i64,
    keyword_match_score: u32,
    matched_keywords: Vec<String>,
    expansion_id: Option<&str>,
) {
    emit(
        session_log,
        handle,
        SessionEvent::CandidateScored {
            run_id: run_id.to_string(),
            candidate_id,
            keyword_match_score,
            matched_keywords,
            expansion_id: expansion_id.map(str::to_string),
        },
    );
}

fn emit_skip(
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    run_id: &str,
    item: &FetchedItem,
    url_hash: &str,
    reason: &str,
) {
    emit(
        session_log,
        handle,
        SessionEvent::CandidateSkipped {
            run_id: run_id.to_string(),
            url_hash: HashHex(url_hash.to_string()),
            source: item.source_name.clone(),
            reason: reason.to_string(),
        },
    );
}

/// One iteration of the orchestrator's outer loop. The default
/// (perspectives disabled, or expansion skipped for any reason) is
/// a single pass with `label` and `expansion_id` both `None`, which
/// makes the inner fetcher loop bit-identical to the
/// pre-perspective build: no synthetic source-name rewriting, no
/// expansion_id field on emitted audit events.
struct PerspectivePass {
    label: Option<String>,
    expansion_id: Option<String>,
}

impl PerspectivePass {
    fn synthesize_source_config(&self, source: &SourceEntry) -> SourceConfig {
        match self.label.as_deref() {
            Some(label) => SourceConfig {
                name: format!("{}::p={}", source.name, crate::perspectives::slug(label)),
                endpoint: source.endpoint.clone(),
            },
            None => SourceConfig {
                name: source.name.clone(),
                endpoint: source.endpoint.clone(),
            },
        }
    }
}

/// Decide which passes the orchestrator runs this turn. Returns
/// `[PerspectivePass{None, None}]` for a default run; returns one
/// pass per emitted label (each carrying the same `expansion_id`)
/// when perspective expansion is enabled and successful.
///
/// Pre-check: `max_perspectives * manifest.sources.len() <=
/// per_topic_fanout_cap`. Over-budget configurations skip expansion
/// entirely without making any HTTP call (Wikipedia metadata
/// included), which is what "rejects over-budget expansions before
/// any fetch" requires.
async fn build_perspective_passes(
    config: &OrchestratorConfig,
    http: &EgressClient,
    manifest: &SourcesManifest,
    run_id: &str,
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    summary: &mut RunSummary,
) -> Vec<PerspectivePass> {
    let default_pass = || {
        vec![PerspectivePass {
            label: None,
            expansion_id: None,
        }]
    };

    if !config.perspectives_enabled {
        return default_pass();
    }
    let topic = match config.topic.as_deref() {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            tracing::info!("perspectives_enabled but no topic supplied; skipping expansion");
            return default_pass();
        }
    };
    let Some(llm) = config.llm.as_ref() else {
        tracing::info!("perspectives_enabled but no LLM client; skipping expansion");
        return default_pass();
    };
    let planned = config
        .max_perspectives
        .saturating_mul(manifest.sources.len());
    if planned == 0 || planned > config.per_topic_fanout_cap {
        tracing::info!(
            "perspective fan-out {planned} outside cap {} (max_perspectives={}, sources={}); skipping expansion",
            config.per_topic_fanout_cap,
            config.max_perspectives,
            manifest.sources.len()
        );
        summary.perspective_skipped_over_budget = true;
        emit(
            session_log,
            handle,
            SessionEvent::PerspectiveSkipped {
                run_id: run_id.to_string(),
                topic: topic.to_string(),
                reason: "over_budget".to_string(),
            },
        );
        return default_pass();
    }

    let api_base = config
        .wikipedia_api_base
        .as_deref()
        .unwrap_or(crate::perspectives::DEFAULT_WIKIPEDIA_API_BASE);
    let raw_labels = match crate::perspectives::expand(
        llm,
        config.llm_api_key.as_deref(),
        http,
        api_base,
        topic,
        config.max_related_topics,
        config.max_perspectives,
    )
    .await
    {
        Ok(labels) if !labels.is_empty() => labels,
        Ok(_) => {
            tracing::info!("perspective expansion produced no labels; skipping fan-out");
            return default_pass();
        }
        Err(e) => {
            tracing::warn!("perspective expansion failed: {e}; falling back to default fetch");
            return default_pass();
        }
    };

    let (labels, dropped_for_collision) = crate::perspectives::dedupe_by_slug(raw_labels);
    if !dropped_for_collision.is_empty() {
        tracing::info!(
            "perspective expansion dropped {} slug-colliding label(s): {:?}",
            dropped_for_collision.len(),
            dropped_for_collision
        );
    }
    if labels.is_empty() {
        tracing::info!("perspective expansion produced no kept labels after dedup; skipping");
        return default_pass();
    }

    let expansion_id = uuid::Uuid::new_v4().to_string();
    emit(
        session_log,
        handle,
        SessionEvent::PerspectiveExpansion {
            run_id: run_id.to_string(),
            topic: topic.to_string(),
            perspectives: labels.clone(),
            expansion_id: expansion_id.clone(),
            dropped_for_collision,
        },
    );
    summary.perspectives_used = labels.clone();
    summary.expansion_id = Some(expansion_id.clone());

    labels
        .into_iter()
        .map(|label| PerspectivePass {
            label: Some(label),
            expansion_id: Some(expansion_id.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wirken_audit::SqliteSessionLog;

    /// One-shot HTTP server that responds with a fixed body.
    async fn one_shot_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/xml\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    /// Multi-shot server that serves the same body N times.
    async fn multi_shot_server(body: &'static str, count: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/", addr);
        tokio::spawn(async move {
            for _ in 0..count {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/xml\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            }
        });
        url
    }

    fn write_fixture_preset(
        dest: &Path,
        storage_dir: &Path,
        egress_allowlist: &[&str],
        sources_toml: &str,
    ) {
        std::fs::create_dir_all(dest.join("skills/aggregator")).unwrap();
        std::fs::write(
            dest.join("preset.toml"),
            r#"
[preset]
name = "test-preset"
description = "fixture for orchestrator tests"
version = "0.0.1"
skills = ["aggregator"]
"#,
        )
        .unwrap();
        let domains_yaml = egress_allowlist
            .iter()
            .map(|d| format!("      - {d}"))
            .collect::<Vec<_>>()
            .join("\n");
        let storage_yaml = storage_dir.display().to_string();
        let aggregator_md = format!(
            "---\n\
             name: aggregator\n\
             description: fixture aggregator\n\
             disable-model-invocation: true\n\
             permissions:\n\
             \x20\x20tools:\n\
             \x20\x20\x20\x20allow: [exec]\n\
             \x20\x20egress:\n\
             \x20\x20\x20\x20mode: allowlist\n\
             \x20\x20\x20\x20domains:\n{domains_yaml}\n\
             \x20\x20filesystem:\n\
             \x20\x20\x20\x20write_paths: [\"{storage_yaml}\"]\n\
             \x20\x20\x20\x20read_paths: [\"{storage_yaml}\"]\n\
             \x20\x20inference:\n\
             \x20\x20\x20\x20allow: [\"*\"]\n\
             ---\n\nbody\n",
        );
        let aggregator_dir = dest.join("skills/aggregator");
        std::fs::write(aggregator_dir.join("SKILL.md"), aggregator_md).unwrap();
        sign_test_skill(&aggregator_dir);
        std::fs::write(dest.join("sources.toml"), sources_toml).unwrap();
    }

    /// Self-sign a test skill directory with a fresh one-shot
    /// keypair. Mirrors what bundled-skill / bundled-preset install
    /// does on the production paths so the loader's signature gate
    /// accepts the fixture without test-only env-var games.
    fn sign_test_skill(skill_dir: &Path) {
        let (secret_hex, _) = wirken_gateway::skill_registry::generate_signing_keypair();
        let bytes =
            wirken_gateway::skill_registry::hex_decode_public(&secret_hex).expect("hex decode");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let key = ed25519_dalek::SigningKey::from_bytes(&arr);
        wirken_gateway::skill_registry::sign_skill(skill_dir, &key).expect("sign test skill");
    }

    fn write_interests(path: &Path, raw: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, raw).unwrap();
    }

    const FTC_FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>FTC</title><link>https://www.ftc.gov</link><description>x</description>
<item>
  <title>FTC sues data broker over Section 5 unfairness</title>
  <link>https://www.ftc.gov/news/2026/04/data-broker</link>
  <pubDate>Tue, 28 Apr 2026 14:00:00 GMT</pubDate>
  <description>The Federal Trade Commission today filed suit against ExampleCorp under Section 5 of the FTC Act for unfair data broker practices.</description>
</item>
<item>
  <title>Cookie banner enforcement update</title>
  <link>https://www.ftc.gov/news/2026/04/cookie-banner</link>
  <pubDate>Mon, 27 Apr 2026 09:30:00 GMT</pubDate>
  <description>The FTC announces updates to cookie banner standards.</description>
</item>
<item>
  <title>Generic news about birds</title>
  <link>https://www.ftc.gov/news/2026/04/birds</link>
  <pubDate>Sun, 26 Apr 2026 09:30:00 GMT</pubDate>
  <description>Birds are an underexplored area of FTC interest.</description>
</item>
</channel></rss>"#;

    fn config_with_log(
        preset_dir: PathBuf,
        storage_dir: PathBuf,
        interests_path: PathBuf,
        log: Option<Arc<dyn SessionLog>>,
    ) -> OrchestratorConfig {
        OrchestratorConfig {
            preset_dir,
            storage_dir,
            interests_path,
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
            session_log: log,
            // C-LLM fields default to "off" for the C-foundation tests:
            // none of them exercise the LLM-scoring or theme-naming
            // passes. The C-LLM tests construct their own config with
            // the LLM client and embed base populated.
            llm: None,
            llm_api_key: None,
            ollama_embed_base: String::new(),
            embed_model: String::new(),
            source_api_keys: std::collections::HashMap::new(),
            perspectives_enabled: false,
            topic: None,
            max_perspectives: 0,
            max_related_topics: 0,
            per_topic_fanout_cap: 0,
            wikipedia_api_base: None,
            agent_id: None,
            skill_name: None,
        }
    }

    /// Keystone test for the C-foundation slice: orchestrator fetches an
    /// RSS feed, parses three items, drops the cookie-banner one for
    /// exclusion match, drops the bird one for score zero, keeps the
    /// data-broker item, writes its candidate row with matched_keywords
    /// and keyword_match_score.
    #[tokio::test]
    async fn fetches_rss_screens_and_writes_kept_candidates() {
        let url = one_shot_server(FTC_FIXTURE).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml = format!(
            "[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n",
            url = url
        );
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker", "Section 5"]
exclusions = ["cookie banner"]"#,
        );

        let summary = run(config_with_log(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            None,
        ))
        .await
        .unwrap();

        assert_eq!(summary.sources_attempted, 1);
        assert_eq!(summary.sources_succeeded, 1);
        assert_eq!(summary.items_seen, 3);
        assert_eq!(summary.items_new, 3);
        assert_eq!(summary.items_excluded, 1);
        assert_eq!(summary.items_score_zero, 1);
        assert_eq!(summary.items_kept, 1);
        assert_eq!(summary.kept_candidate_ids.len(), 1);

        let conn = rusqlite::Connection::open(storage_dir.join("aggregator.db")).unwrap();
        let (title, score, matched, run_id_col): (String, i64, String, String) = conn
            .query_row(
                "SELECT title, keyword_match_score, matched_keywords, run_id \
                 FROM candidates WHERE id = ?1",
                rusqlite::params![summary.kept_candidate_ids[0]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert!(title.contains("data broker"));
        assert_eq!(score, 2);
        assert!(matched.contains("data broker"));
        assert!(matched.contains("Section 5"));
        assert_eq!(run_id_col, summary.run_id);
    }

    /// A second run against the same fixture sees zero new items —
    /// dedup-against-seen takes effect.
    #[tokio::test]
    async fn second_run_dedups_against_seen() {
        let url = multi_shot_server(FTC_FIXTURE, 2).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n");
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker"]
exclusions = []"#,
        );

        let first = run(config_with_log(
            preset_dir.clone(),
            storage_dir.clone(),
            interests_path.clone(),
            None,
        ))
        .await
        .unwrap();
        let second = run(config_with_log(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            None,
        ))
        .await
        .unwrap();

        assert_eq!(first.items_new, 3);
        assert_eq!(second.items_seen, 3, "second run sees the same 3 items");
        assert_eq!(second.items_new, 0, "but dedup drops them all");
        assert_eq!(second.items_kept, 0);
    }

    /// Source method `json-api` is recorded as unsupported; the run
    /// continues for the other sources rather than aborting.
    #[tokio::test]
    async fn unsupported_method_is_recorded_as_skipped() {
        let url = one_shot_server(FTC_FIXTURE).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml = format!(
            "[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n\
             [[source]]\nname=\"congress\"\nendpoint=\"https://api.congress.gov/v3/\"\nmethod=\"json-api\"\n"
        );
        write_fixture_preset(
            &preset_dir,
            &storage_dir,
            &["127.0.0.1", "api.congress.gov"],
            &sources_toml,
        );
        let interests_path = storage_dir.join("interests.toml");
        write_interests(&interests_path, r#"keywords = ["data broker"]"#);

        let summary = run(config_with_log(
            preset_dir,
            storage_dir,
            interests_path,
            None,
        ))
        .await
        .unwrap();

        assert_eq!(summary.sources_attempted, 2);
        assert_eq!(summary.sources_succeeded, 1);
        assert_eq!(summary.sources_unsupported, vec!["congress".to_string()]);
        assert_eq!(summary.items_kept, 1);
    }

    /// Egress denial fails fast WITHOUT consuming budget. The
    /// orchestrator logs the failure and moves on; one source's
    /// allowlist mismatch doesn't abort the run.
    #[tokio::test]
    async fn egress_denied_source_is_recorded_as_failed_run_continues() {
        // Server bound on 127.0.0.1, but egress allowlist names a
        // different host. The fetch fails at egress.
        let url = one_shot_server(FTC_FIXTURE).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n");
        write_fixture_preset(
            &preset_dir,
            &storage_dir,
            &["allowed.example.com"],
            &sources_toml,
        );
        let interests_path = storage_dir.join("interests.toml");
        write_interests(&interests_path, r#"keywords = ["data broker"]"#);

        let summary = run(config_with_log(
            preset_dir,
            storage_dir,
            interests_path,
            None,
        ))
        .await
        .unwrap();

        assert_eq!(summary.sources_attempted, 1);
        assert_eq!(summary.sources_succeeded, 0);
        assert_eq!(summary.sources_failed.len(), 1);
        assert_eq!(summary.items_kept, 0);
    }

    /// Audit emission integration: HttpFetch and CandidateScored
    /// events land in the supplied SessionLog with the expected
    /// `kind` discriminators. The chain stays whole.
    #[tokio::test]
    async fn audit_events_are_emitted_for_fetch_and_score() {
        let url = one_shot_server(FTC_FIXTURE).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n");
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker", "Section 5"]
exclusions = ["cookie banner"]"#,
        );

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));
        let summary = run(config_with_log(
            preset_dir,
            storage_dir,
            interests_path,
            Some(log.clone()),
        ))
        .await
        .unwrap();

        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        let kinds: Vec<&str> = events
            .iter()
            .filter_map(|e| extract_kind(&e.event))
            .collect();
        assert!(kinds.contains(&"HttpFetch"));
        assert!(kinds.contains(&"CandidateScored"));
        assert!(kinds.contains(&"CandidateSkipped"));
    }

    fn extract_kind(event: &SessionEvent) -> Option<&'static str> {
        // Names match the enum variant; serde serializes them via
        // `#[serde(tag = "kind")]` at the wire layer, but in tests we
        // can match the Rust variants directly.
        Some(match event {
            SessionEvent::HttpFetch { .. } => "HttpFetch",
            SessionEvent::CandidateScored { .. } => "CandidateScored",
            SessionEvent::CandidateSkipped { .. } => "CandidateSkipped",
            SessionEvent::CandidateKept { .. } => "CandidateKept",
            SessionEvent::InterestsEdited { .. } => "InterestsEdited",
            _ => return None,
        })
    }

    #[tokio::test]
    async fn missing_aggregator_skill_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        std::fs::create_dir_all(preset_dir.join("skills/other")).unwrap();
        std::fs::write(
            preset_dir.join("preset.toml"),
            r#"
[preset]
name = "no-aggregator"
description = "missing aggregator"
version = "0.0.1"
skills = ["other"]
"#,
        )
        .unwrap();
        std::fs::write(
            preset_dir.join("skills/other/SKILL.md"),
            "---\nname: other\ndescription: x\ndisable-model-invocation: false\npermissions: {}\n---\nbody\n",
        )
        .unwrap();
        sign_test_skill(&preset_dir.join("skills/other"));
        std::fs::write(
            preset_dir.join("sources.toml"),
            "[[source]]\nname=\"x\"\nendpoint=\"http://x\"\nmethod=\"rss\"\n",
        )
        .unwrap();
        let storage = tmp.path().join("storage");
        std::fs::create_dir_all(&storage).unwrap();
        let interests_path = storage.join("interests.toml");
        write_interests(&interests_path, r#"keywords = ["X"]"#);

        let err = run(config_with_log(preset_dir, storage, interests_path, None))
            .await
            .unwrap_err();
        assert!(matches!(err, OrchestratorError::AggregatorSkillMissing));
    }

    #[tokio::test]
    async fn missing_interests_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        write_fixture_preset(
            &preset_dir,
            &storage_dir,
            &["127.0.0.1"],
            "[[source]]\nname=\"x\"\nendpoint=\"http://x\"\nmethod=\"rss\"\n",
        );
        let interests_path = storage_dir.join("interests.toml");
        // Deliberately not writing the file.
        let err = run(config_with_log(
            preset_dir,
            storage_dir,
            interests_path,
            None,
        ))
        .await
        .unwrap_err();
        assert!(matches!(err, OrchestratorError::LoadInterests(_)));
    }

    // ----- C-LLM tests -----------------------------------------------

    /// Multi-request mock server. Dispatches by URL path:
    /// - `/feed` → returns the RSS fixture body
    /// - `/v1/chat/completions` → returns an OpenAI-shaped tool_call
    ///   response. Tool name is detected from the request body so
    ///   the same server can stand in for both score and theme calls.
    /// - `/api/chat` → ollama-native chat endpoint; returns an
    ///   ollama-shaped tool_call response. The wirken-agent ollama
    ///   dispatch (4b3ab48) routes `provider: "ollama"` here instead
    ///   of through the OpenAI-compat bridge.
    /// - `/api/embed` → returns canned vectors.
    ///
    /// Stays alive serving up to `max_requests` connections, then
    /// stops. Returns the bound base URL like `http://127.0.0.1:<port>`.
    async fn mock_llm_and_feed_server(
        feed_body: &'static str,
        embed_vectors: Vec<Vec<f32>>,
        max_requests: usize,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            for _ in 0..max_requests {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 65536];
                let n = match sock.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = match req.find("\r\n\r\n") {
                    Some(idx) => &req[idx + 4..],
                    None => "",
                };

                let response_body: String = if req.contains("POST /feed") {
                    feed_body.to_string()
                } else if req.contains("POST /v1/chat/completions")
                    || req.contains("POST /chat/completions")
                {
                    if body.contains("zirkel_score_candidate") {
                        canned_score_response()
                    } else if body.contains("zirkel_name_theme") {
                        canned_theme_response()
                    } else {
                        // Unrecognized — fail loudly so the test
                        // shows what shape the request actually had.
                        panic!("mock LLM saw no known synthetic-tool name in request body: {body}")
                    }
                } else if req.contains("POST /api/chat") {
                    if body.contains("zirkel_score_candidate") {
                        canned_score_response_ollama()
                    } else if body.contains("zirkel_name_theme") {
                        canned_theme_response_ollama()
                    } else {
                        panic!(
                            "mock LLM saw no known synthetic-tool name in /api/chat body: {body}"
                        )
                    }
                } else if req.contains("POST /api/embed") {
                    canned_embed_response(&embed_vectors)
                } else {
                    // Any GET request (e.g. RSS feed served via GET).
                    if req.contains("GET /feed") {
                        feed_body.to_string()
                    } else {
                        format!("not found: {}", req.lines().next().unwrap_or(""))
                    }
                };

                let content_type = if req.contains("/feed") {
                    "application/xml"
                } else {
                    "application/json"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\n\r\n{}",
                    response_body.len(),
                    content_type,
                    response_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    fn canned_score_response() -> String {
        // OpenAI chat-completions shape with one tool_call to
        // zirkel_score_candidate. Same fixed score for every request
        // — the test asserts whatever lands in the DB matches.
        r#"{
  "id": "test-1",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_score_1",
        "type": "function",
        "function": {
          "name": "zirkel_score_candidate",
          "arguments": "{\"score\":80,\"why_surfaced\":\"matched 'data broker' — substantively about FTC enforcement against a broker\",\"matched_keyword\":\"data broker\"}"
        }
      }]
    },
    "finish_reason": "tool_calls"
  }]
}"#
        .to_string()
    }

    fn canned_theme_response() -> String {
        r#"{
  "id": "test-2",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_theme_1",
        "type": "function",
        "function": {
          "name": "zirkel_name_theme",
          "arguments": "{\"name\":\"FTC enforcement\"}"
        }
      }]
    },
    "finish_reason": "tool_calls"
  }]
}"#
        .to_string()
    }

    /// Ollama-native shape for the same score response. Differences
    /// from OpenAI: single `message` block (no `choices` array);
    /// `tool_calls[].function.arguments` is a JSON object, not a
    /// JSON-encoded string; no `id` field on tool_calls (the wirken
    /// ollama parser synthesizes `call_0`, `call_1`); `done: true`
    /// instead of `finish_reason`.
    fn canned_score_response_ollama() -> String {
        r#"{
  "model": "llama3.1:8b",
  "created_at": "2026-01-01T00:00:00Z",
  "message": {
    "role": "assistant",
    "content": "",
    "tool_calls": [{
      "function": {
        "name": "zirkel_score_candidate",
        "arguments": {
          "score": 80,
          "why_surfaced": "matched 'data broker' — substantively about FTC enforcement against a broker",
          "matched_keyword": "data broker"
        }
      }
    }]
  },
  "done": true,
  "prompt_eval_count": 50,
  "eval_count": 30
}"#
        .to_string()
    }

    fn canned_theme_response_ollama() -> String {
        r#"{
  "model": "llama3.1:8b",
  "created_at": "2026-01-01T00:00:00Z",
  "message": {
    "role": "assistant",
    "content": "",
    "tool_calls": [{
      "function": {
        "name": "zirkel_name_theme",
        "arguments": {
          "name": "FTC enforcement"
        }
      }
    }]
  },
  "done": true,
  "prompt_eval_count": 50,
  "eval_count": 10
}"#
        .to_string()
    }

    fn canned_embed_response(vectors: &[Vec<f32>]) -> String {
        let v_str = vectors
            .iter()
            .map(|v| {
                let inner = v
                    .iter()
                    .map(|f| format!("{}", f))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("[{inner}]")
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"model\":\"nomic-embed-text:v1.5\",\"embeddings\":[{}]}}",
            v_str
        )
    }

    fn config_for_llm_e2e(
        preset_dir: PathBuf,
        storage_dir: PathBuf,
        interests_path: PathBuf,
        log: Option<Arc<dyn SessionLog>>,
        llm_base: &str,
        embed_base: &str,
    ) -> OrchestratorConfig {
        let llm_cfg = wirken_agent::llm::LlmConfig {
            provider: "ollama".to_string(),
            model: "llama3.1:8b".to_string(),
            base_url: format!("{llm_base}/v1"),
            max_tokens: 1024,
            temperature: 0.0,
            region: None,
            tools_enabled: true,
            context_window: 8192,
        };
        let llm = Arc::new(LlmClient::new(llm_cfg).unwrap());
        OrchestratorConfig {
            preset_dir,
            storage_dir,
            interests_path,
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
            session_log: log,
            llm: Some(llm),
            llm_api_key: None,
            ollama_embed_base: embed_base.to_string(),
            embed_model: "nomic-embed-text:v1.5".to_string(),
            source_api_keys: std::collections::HashMap::new(),
            perspectives_enabled: false,
            topic: None,
            max_perspectives: 0,
            max_related_topics: 0,
            per_topic_fanout_cap: 0,
            wikipedia_api_base: None,
            agent_id: None,
            skill_name: None,
        }
    }

    /// LLM relevance-scoring pass writes `llm_relevance_score` and
    /// `llm_why_surfaced` to the candidate row and emits the
    /// `CandidateLlmScored` audit event. Single-source single-item
    /// fixture: clustering is skipped (need ≥2 items), so this test
    /// isolates the LLM-scoring path.
    #[tokio::test]
    async fn llm_scoring_pass_writes_relevance_and_emits_event() {
        let single_item_feed = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>FTC</title><link>https://x</link><description>x</description>
<item>
  <title>FTC sues data broker over Section 5 unfairness</title>
  <link>https://www.ftc.gov/x/data-broker</link>
  <description>The FTC sued ExampleCorp under Section 5.</description>
</item>
</channel></rss>"#;
        // Connections expected: 1 feed GET + 1 score chat-completion.
        let server = mock_llm_and_feed_server(single_item_feed, vec![], 4).await;

        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{server}/feed\"\nmethod=\"rss\"\n");
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(&interests_path, r#"keywords = ["data broker"]"#);

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));

        let summary = run(config_for_llm_e2e(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            Some(log.clone()),
            &server,
            "", // empty embed base disables clustering for this test
        ))
        .await
        .unwrap();

        assert_eq!(summary.items_kept, 1);
        assert_eq!(summary.items_llm_scored, 1);
        assert_eq!(summary.themes_named, 0);

        // Candidate row carries the LLM fields.
        let conn = rusqlite::Connection::open(storage_dir.join("aggregator.db")).unwrap();
        let (relevance, why): (f64, String) = conn
            .query_row(
                "SELECT llm_relevance_score, llm_why_surfaced FROM candidates LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(relevance as i64, 80);
        assert!(why.contains("data broker"));

        // Audit chain has the CandidateLlmScored event.
        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.event, SessionEvent::CandidateLlmScored { .. })),
            "expected CandidateLlmScored event in chain"
        );
    }

    /// Full C-LLM pipeline end-to-end. HDBSCAN's density-based
    /// algorithm needs *contrast* between clusters to identify any
    /// of them as non-noise — a single tightly-packed group of N
    /// points yields all-noise regardless of N. The fixture provides
    /// 6 items that the mock embed returns as two distinct clusters
    /// of 3, which HDBSCAN reliably partitions. Both clusters get
    /// named by the (single) canned theme response.
    /// Assert: `themes_named = 2`, all 6 candidates have a non-NULL
    /// `cluster_id`, audit chain has `ThemeNamed`.
    #[tokio::test]
    async fn clustering_and_theme_naming_e2e() {
        let six_kept_feed = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>FTC</title><link>https://x</link><description>x</description>
<item>
  <title>FTC sues data broker A</title>
  <link>https://www.ftc.gov/a</link>
  <description>Section 5 data broker enforcement.</description>
</item>
<item>
  <title>FTC announces data broker rule B</title>
  <link>https://www.ftc.gov/b</link>
  <description>Data broker registry rule.</description>
</item>
<item>
  <title>FTC investigates data broker C</title>
  <link>https://www.ftc.gov/c</link>
  <description>Data broker investigation.</description>
</item>
<item>
  <title>FTC settles data broker case D</title>
  <link>https://www.ftc.gov/d</link>
  <description>Data broker settlement reached.</description>
</item>
<item>
  <title>FTC issues data broker order E</title>
  <link>https://www.ftc.gov/e</link>
  <description>Data broker compliance order.</description>
</item>
<item>
  <title>FTC closes data broker probe F</title>
  <link>https://www.ftc.gov/f</link>
  <description>Data broker probe concluded.</description>
</item>
</channel></rss>"#;
        // Two well-separated clusters of 3 in 2D feature space.
        let embed_vectors = vec![
            vec![1.0, 0.0],
            vec![1.05, 0.05],
            vec![0.95, -0.05],
            vec![10.0, 10.0],
            vec![10.05, 10.05],
            vec![9.95, 9.95],
        ];
        // 1 feed + 6 score requests + 1 embed + 2 theme = 10 minimum.
        let server = mock_llm_and_feed_server(six_kept_feed, embed_vectors, 20).await;

        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{server}/feed\"\nmethod=\"rss\"\n");
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(&interests_path, r#"keywords = ["data broker"]"#);

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));

        let summary = run(config_for_llm_e2e(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            Some(log.clone()),
            &server,
            &server, // same mock answers /api/embed too
        ))
        .await
        .unwrap();

        assert_eq!(summary.items_kept, 6);
        assert_eq!(summary.items_llm_scored, 6);
        assert_eq!(
            summary.themes_named, 2,
            "two well-separated 3-point clusters should produce two themes; failures: {:?}",
            summary.theme_stage_failures
        );

        let conn = rusqlite::Connection::open(storage_dir.join("aggregator.db")).unwrap();

        // Both themes carry the LLM-supplied name (mock returns the
        // same canned name for every theme call).
        let names: Vec<String> = conn
            .prepare("SELECT name FROM themes ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(names.len(), 2);
        for n in &names {
            assert_eq!(n, "FTC enforcement");
        }

        // All 6 candidates have a non-NULL cluster_id pointing at one
        // of the themes.
        let with_cluster: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE cluster_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(with_cluster, 6);

        // Audit chain has ThemeNamed.
        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.event, SessionEvent::ThemeNamed { .. })),
            "expected ThemeNamed event in chain"
        );
    }

    // ----- Perspective expansion -----------------------------------------

    /// Multi-shot mock that handles Wikipedia opensearch + parse,
    /// the perspective-emit synthetic-tool LLM call, the
    /// candidate-score synthetic-tool LLM call, and an RSS feed body.
    /// Path-keyed dispatch; same wire shape as
    /// [`mock_llm_and_feed_server`].
    async fn mock_perspective_server(feed_body: &'static str, max_requests: usize) -> String {
        mock_perspective_server_with_labels(
            feed_body,
            max_requests,
            canned_perspectives_response(),
            canned_perspectives_response_ollama(),
        )
        .await
    }

    /// Variant of [`mock_perspective_server`] that lets the caller
    /// substitute the perspective-emit canned response. Used to pin
    /// the slug-collision dedup path against an LLM that emitted
    /// two surface-distinct labels with identical slugs.
    async fn mock_perspective_server_with_labels(
        feed_body: &'static str,
        max_requests: usize,
        openai_perspectives_body: String,
        ollama_perspectives_body: String,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            for _ in 0..max_requests {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 65536];
                let n = match sock.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = match req.find("\r\n\r\n") {
                    Some(idx) => &req[idx + 4..],
                    None => "",
                };

                let (response_body, content_type): (String, &str) = if req
                    .starts_with("GET /w/api.php")
                {
                    if req.contains("action=opensearch") {
                        (
                            r#"["topic", ["BIPA", "GDPR"], ["d1","d2"], ["u1","u2"]]"#.to_string(),
                            "application/json",
                        )
                    } else if req.contains("action=parse") {
                        (
                            r#"{"parse":{"title":"Article","sections":[
                                    {"line":"Background","anchor":"Background"},
                                    {"line":"Enforcement","anchor":"Enforcement"}
                                ]}}"#
                                .to_string(),
                            "application/json",
                        )
                    } else {
                        ("{}".to_string(), "application/json")
                    }
                } else if req.contains("POST /v1/chat/completions")
                    || req.contains("POST /chat/completions")
                {
                    if body.contains("zirkel_emit_perspectives") {
                        (openai_perspectives_body.clone(), "application/json")
                    } else if body.contains("zirkel_score_candidate") {
                        (canned_score_response(), "application/json")
                    } else {
                        panic!(
                            "perspective mock saw unknown synthetic-tool name in chat body: {body}"
                        )
                    }
                } else if req.contains("POST /api/chat") {
                    if body.contains("zirkel_emit_perspectives") {
                        (ollama_perspectives_body.clone(), "application/json")
                    } else if body.contains("zirkel_score_candidate") {
                        (canned_score_response_ollama(), "application/json")
                    } else {
                        panic!(
                            "perspective mock saw unknown synthetic-tool name in /api/chat body: {body}"
                        )
                    }
                } else if req.starts_with("GET /feed") {
                    (feed_body.to_string(), "application/xml")
                } else {
                    (
                        format!("not found: {}", req.lines().next().unwrap_or("")),
                        "text/plain",
                    )
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\n\r\n{}",
                    response_body.len(),
                    content_type,
                    response_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    fn canned_perspectives_response() -> String {
        r#"{
  "id": "test-persp-1",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_persp_1",
        "type": "function",
        "function": {
          "name": "zirkel_emit_perspectives",
          "arguments": "{\"perspectives\":[\"Section 5 enforcement\",\"data broker oversight\"]}"
        }
      }]
    },
    "finish_reason": "tool_calls"
  }]
}"#
        .to_string()
    }

    fn canned_perspectives_response_ollama() -> String {
        r#"{
  "model": "llama3.1:8b",
  "created_at": "2026-01-01T00:00:00Z",
  "message": {
    "role": "assistant",
    "content": "",
    "tool_calls": [{
      "function": {
        "name": "zirkel_emit_perspectives",
        "arguments": {
          "perspectives": ["Section 5 enforcement", "data broker oversight"]
        }
      }
    }]
  },
  "done": true,
  "prompt_eval_count": 50,
  "eval_count": 10
}"#
        .to_string()
    }

    /// Build a config configured for perspective expansion against
    /// the supplied mock URL.
    #[allow(clippy::too_many_arguments)]
    fn config_for_perspectives(
        preset_dir: PathBuf,
        storage_dir: PathBuf,
        interests_path: PathBuf,
        log: Option<Arc<dyn SessionLog>>,
        llm_base: &str,
        wikipedia_base: &str,
        max_perspectives: usize,
        max_related_topics: usize,
        per_topic_fanout_cap: usize,
    ) -> OrchestratorConfig {
        let llm_cfg = wirken_agent::llm::LlmConfig {
            provider: "ollama".to_string(),
            model: "llama3.1:8b".to_string(),
            base_url: format!("{llm_base}/v1"),
            max_tokens: 1024,
            temperature: 0.0,
            region: None,
            tools_enabled: true,
            context_window: 8192,
        };
        let llm = Arc::new(LlmClient::new(llm_cfg).unwrap());
        OrchestratorConfig {
            preset_dir,
            storage_dir,
            interests_path,
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
            session_log: log,
            llm: Some(llm),
            llm_api_key: None,
            ollama_embed_base: String::new(),
            embed_model: String::new(),
            source_api_keys: std::collections::HashMap::new(),
            perspectives_enabled: true,
            topic: Some("biometric privacy".to_string()),
            max_perspectives,
            max_related_topics,
            per_topic_fanout_cap,
            wikipedia_api_base: Some(format!("{wikipedia_base}/w/api.php")),
            agent_id: None,
            skill_name: None,
        }
    }

    /// End-to-end perspective-expansion run. The single mocked LLM
    /// call returns two perspective labels; the orchestrator runs
    /// the source loop once per label, the seen-table dedup gives
    /// the first-perspective ownership of the URL. The audit chain
    /// records exactly one PerspectiveExpansion event, every fetch
    /// and candidate event under the expansion shares one
    /// expansion_id, and the kept candidate's source_name carries
    /// the synthetic `::p=<slug>` suffix.
    #[tokio::test]
    async fn perspective_expansion_groups_citations_and_correlates_audit() {
        let mock = mock_perspective_server(FTC_FIXTURE, 64).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml = format!(
            "[[source]]\nname=\"ftc\"\nendpoint=\"{mock}/feed\"\nmethod=\"rss\"\n",
            mock = mock
        );
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker", "Section 5"]
exclusions = ["cookie banner"]"#,
        );

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));
        let summary = run(config_for_perspectives(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            Some(log.clone()),
            &mock,
            &mock,
            2,
            2,
            10,
        ))
        .await
        .unwrap();

        // Pin (a): the structured-output channel actually round-trips
        // the LLM tool-call arguments through perspectives::expand
        // into both summary.perspectives_used and the audit event.
        // Tightening from a length check to a content check pins the
        // shape across the whole call path: the mock returns
        // ["Section 5 enforcement", "data broker oversight"] and
        // those exact strings must surface unchanged.
        let expected_labels = vec![
            "Section 5 enforcement".to_string(),
            "data broker oversight".to_string(),
        ];
        assert_eq!(summary.perspectives_used, expected_labels);
        let expansion_id = summary
            .expansion_id
            .as_ref()
            .expect("expansion_id should be set when expansion ran");
        assert!(!summary.perspective_skipped_over_budget);

        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();

        let perspective_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event, SessionEvent::PerspectiveExpansion { .. }))
            .collect();
        assert_eq!(
            perspective_events.len(),
            1,
            "expected exactly one PerspectiveExpansion event"
        );
        match &perspective_events[0].event {
            SessionEvent::PerspectiveExpansion {
                topic,
                perspectives,
                expansion_id: id,
                dropped_for_collision,
                ..
            } => {
                assert_eq!(topic, "biometric privacy");
                assert_eq!(perspectives, &expected_labels);
                assert!(
                    dropped_for_collision.is_empty(),
                    "non-colliding labels should record no drops"
                );
                assert_eq!(id, expansion_id);
            }
            _ => unreachable!(),
        }

        let mut http_with_id = 0;
        let mut scored_with_id = 0;
        for ev in &events {
            match &ev.event {
                SessionEvent::HttpFetch {
                    expansion_id: Some(id),
                    ..
                } => {
                    assert_eq!(id, expansion_id, "HttpFetch expansion_id mismatch");
                    http_with_id += 1;
                }
                SessionEvent::CandidateScored {
                    expansion_id: Some(id),
                    ..
                } => {
                    assert_eq!(id, expansion_id, "CandidateScored expansion_id mismatch");
                    scored_with_id += 1;
                }
                _ => {}
            }
        }
        assert!(
            http_with_id >= 2,
            "expected at least one HttpFetch per perspective fan-out (got {http_with_id})"
        );
        assert!(
            scored_with_id >= 1,
            "expected at least one CandidateScored under expansion_id (got {scored_with_id})"
        );

        // Persisted candidate's source_name carries the synthetic
        // perspective suffix.
        let conn = rusqlite::Connection::open(storage_dir.join("aggregator.db")).unwrap();
        let kept_source: String = conn
            .query_row(
                "SELECT source_name FROM candidates WHERE id = ?1",
                rusqlite::params![summary.kept_candidate_ids[0]],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            kept_source.starts_with("ftc::p="),
            "expected synthetic source_name prefix, got '{kept_source}'"
        );
    }

    /// Pre-flight cap rejection: when `max_perspectives * sources >
    /// per_topic_fanout_cap`, the orchestrator skips expansion
    /// entirely. No PerspectiveExpansion event is emitted, no audit
    /// row carries an expansion_id, and Wikipedia metadata fetches
    /// never go out (the mock LLM/Wikipedia URL is never hit).
    #[tokio::test]
    async fn fan_out_cap_rejects_over_budget_expansion_before_any_fetch() {
        // The mock here serves the RSS feed and panics on any
        // Wikipedia or LLM request. Setting max_requests=2 caps
        // total accepts at the RSS GET only.
        let mock = mock_perspective_server(FTC_FIXTURE, 2).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml = format!(
            "[[source]]\nname=\"ftc\"\nendpoint=\"{mock}/feed\"\nmethod=\"rss\"\n",
            mock = mock
        );
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker"]
exclusions = []"#,
        );

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));

        // Cap at 2, but planned = max_perspectives(5) * sources(1) = 5 > 2.
        let summary = run(config_for_perspectives(
            preset_dir,
            storage_dir,
            interests_path,
            Some(log.clone()),
            &mock,
            &mock,
            5,
            2,
            2,
        ))
        .await
        .unwrap();

        assert!(
            summary.perspective_skipped_over_budget,
            "expected over-budget rejection"
        );
        assert!(summary.expansion_id.is_none());
        assert!(summary.perspectives_used.is_empty());
        // Default fetch happened: the RSS source was hit and a
        // candidate landed.
        assert_eq!(summary.sources_succeeded, 1);
        assert_eq!(summary.items_kept, 1);

        // Audit chain records PerspectiveSkipped exactly once with
        // the `over_budget` reason and no PerspectiveExpansion. The
        // default fetch's HttpFetch event is present but with
        // `expansion_id: None`.
        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        let mut skipped_seen = 0;
        for ev in &events {
            assert!(
                !matches!(ev.event, SessionEvent::PerspectiveExpansion { .. }),
                "no PerspectiveExpansion expected when cap rejects"
            );
            match &ev.event {
                SessionEvent::PerspectiveSkipped {
                    topic: t, reason, ..
                } => {
                    assert_eq!(t, "biometric privacy");
                    assert_eq!(reason, "over_budget");
                    skipped_seen += 1;
                }
                SessionEvent::HttpFetch { expansion_id, .. } => {
                    assert!(
                        expansion_id.is_none(),
                        "HttpFetch must not carry expansion_id when expansion was skipped"
                    );
                }
                SessionEvent::CandidateScored { expansion_id, .. } => {
                    assert!(
                        expansion_id.is_none(),
                        "CandidateScored must not carry expansion_id when expansion was skipped"
                    );
                }
                _ => {}
            }
        }
        assert_eq!(
            skipped_seen, 1,
            "expected exactly one PerspectiveSkipped event"
        );
    }

    /// LLM emits two surface-distinct labels whose slugs collide.
    /// The orchestrator drops the second label before dispatch,
    /// records both kept and dropped on the `PerspectiveExpansion`
    /// audit event, and dispatches exactly one perspective pass.
    #[tokio::test]
    async fn slug_colliding_labels_drop_to_one_pass_and_record_dropped() {
        // Two labels that fold to the same slug "climate-policy".
        // First wins, second is recorded as dropped.
        let openai_collision = r#"{
  "id": "test-persp-collide",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_persp_collide",
        "type": "function",
        "function": {
          "name": "zirkel_emit_perspectives",
          "arguments": "{\"perspectives\":[\"Climate policy\",\"climate-policy\"]}"
        }
      }]
    },
    "finish_reason": "tool_calls"
  }]
}"#
        .to_string();
        let ollama_collision = r#"{
  "model": "llama3.1:8b",
  "created_at": "2026-01-01T00:00:00Z",
  "message": {
    "role": "assistant",
    "content": "",
    "tool_calls": [{
      "function": {
        "name": "zirkel_emit_perspectives",
        "arguments": {
          "perspectives": ["Climate policy", "climate-policy"]
        }
      }
    }]
  },
  "done": true,
  "prompt_eval_count": 50,
  "eval_count": 10
}"#
        .to_string();
        let mock = mock_perspective_server_with_labels(
            FTC_FIXTURE,
            64,
            openai_collision,
            ollama_collision,
        )
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml = format!(
            "[[source]]\nname=\"ftc\"\nendpoint=\"{mock}/feed\"\nmethod=\"rss\"\n",
            mock = mock
        );
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker"]
exclusions = []"#,
        );

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));
        let summary = run(config_for_perspectives(
            preset_dir,
            storage_dir.clone(),
            interests_path,
            Some(log.clone()),
            &mock,
            &mock,
            2,
            2,
            10,
        ))
        .await
        .unwrap();

        assert_eq!(
            summary.perspectives_used,
            vec!["Climate policy".to_string()],
            "only the first slug-winning label dispatches"
        );
        let expansion_id = summary.expansion_id.as_ref().unwrap();

        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        let perspective_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event, SessionEvent::PerspectiveExpansion { .. }))
            .collect();
        assert_eq!(perspective_events.len(), 1);
        match &perspective_events[0].event {
            SessionEvent::PerspectiveExpansion {
                perspectives,
                dropped_for_collision,
                expansion_id: id,
                ..
            } => {
                assert_eq!(perspectives, &vec!["Climate policy".to_string()]);
                assert_eq!(
                    dropped_for_collision,
                    &vec!["climate-policy".to_string()],
                    "dropped label preserved on the audit event"
                );
                assert_eq!(id, expansion_id);
            }
            _ => unreachable!(),
        }

        // Synthetic source name on the persisted candidate carries
        // the surviving slug, not the dropped label's slug.
        let conn = rusqlite::Connection::open(storage_dir.join("aggregator.db")).unwrap();
        let kept_source: String = conn
            .query_row(
                "SELECT source_name FROM candidates WHERE id = ?1",
                rusqlite::params![summary.kept_candidate_ids[0]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept_source, "ftc::p=climate-policy");

        // Exactly one HttpFetch carries the expansion_id (the single
        // surviving perspective pass over the single source).
        let http_under_id = events
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    SessionEvent::HttpFetch {
                        expansion_id: Some(id),
                        ..
                    } if id == expansion_id
                )
            })
            .count();
        assert_eq!(
            http_under_id, 1,
            "one perspective survived dedup, so one fan-out fetch"
        );
    }

    /// `perspectives_enabled = false` leaves the audit chain
    /// bit-identical to a pre-perspective build: no
    /// PerspectiveExpansion variant, no `expansion_id` field
    /// surfaces on any event (the `Option<String>` skip-serializing
    /// rule means default-built events serialize the same bytes as
    /// before).
    #[tokio::test]
    async fn perspectives_disabled_audit_chain_carries_no_expansion_id() {
        let url = one_shot_server(FTC_FIXTURE).await;
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let sources_toml =
            format!("[[source]]\nname=\"ftc\"\nendpoint=\"{url}\"\nmethod=\"rss\"\n");
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &sources_toml);
        let interests_path = storage_dir.join("interests.toml");
        write_interests(
            &interests_path,
            r#"keywords = ["data broker", "Section 5"]
exclusions = ["cookie banner"]"#,
        );

        let log: Arc<dyn SessionLog> =
            Arc::new(SqliteSessionLog::open_in_memory().expect("in-memory session log"));
        let summary = run(config_with_log(
            preset_dir,
            storage_dir,
            interests_path,
            Some(log.clone()),
        ))
        .await
        .unwrap();

        assert!(summary.expansion_id.is_none());
        assert!(summary.perspectives_used.is_empty());
        assert!(!summary.perspective_skipped_over_budget);

        let handle = log.handle_for(SessionId::new(summary.run_id.clone()));
        let events = log.get_since(&handle, 0).unwrap();
        for ev in &events {
            assert!(
                !matches!(ev.event, SessionEvent::PerspectiveExpansion { .. }),
                "no PerspectiveExpansion expected when feature disabled"
            );
            assert!(
                !matches!(ev.event, SessionEvent::PerspectiveSkipped { .. }),
                "no PerspectiveSkipped expected when feature disabled"
            );
            match &ev.event {
                SessionEvent::HttpFetch { expansion_id, .. } => {
                    assert!(expansion_id.is_none());
                }
                SessionEvent::CandidateScored { expansion_id, .. } => {
                    assert!(expansion_id.is_none());
                }
                _ => {}
            }
        }

        // Pin (e), wire-level: skip_serializing_if drops the
        // expansion_id field when None and the perspective variants
        // are absent entirely, so a downstream reader sees JSON
        // payloads byte-identical to a pre-perspective build.
        // Stronger than the Rust-level Option::is_none check above:
        // a future serde-attribute mistake (forgetting
        // skip_serializing_if) would still pass that check but
        // would leak a `"expansion_id":null` field on the wire.
        for ev in &events {
            let json = serde_json::to_string(&ev.event)
                .expect("session event serializes to JSON for the wire format");
            assert!(
                !json.contains("expansion_id"),
                "no event must serialize an expansion_id field when perspectives are disabled, got: {json}"
            );
            assert!(
                !json.contains("perspective_expansion"),
                "no PerspectiveExpansion variant must appear on the wire when disabled, got: {json}"
            );
            assert!(
                !json.contains("perspective_skipped"),
                "no PerspectiveSkipped variant must appear on the wire when disabled, got: {json}"
            );
        }
    }
}
