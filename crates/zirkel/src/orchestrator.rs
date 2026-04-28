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
    HashHex, OwnSession, SessionEvent, SessionHandle, SessionId, SessionLog, TrustLevel,
};
use wirken_skill_store::{SkillStore, SkillStoreError};

use wirken_agent::llm::LlmClient;

use crate::cluster::{ClusterLabel, cluster as cluster_embeddings, group_by_cluster};
use crate::embedding::embed_batch;
use crate::fetcher::{FetchError, FetchedItem, fetch_rss};
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

    // Policed HTTP transport with the aggregator's egress allow-set.
    let http = EgressClient::with_rate_limit(config.rate_limit.clone());
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

    for source in &manifest.sources {
        summary.sources_attempted += 1;

        // Dispatch by method. Foundation slice supports RSS and Atom
        // (both via feed-rs); api / scrape are recorded as skipped.
        let items = match source.method.as_str() {
            "rss" | "atom-api" => match fetch_rss(&http, &source.name, &source.endpoint).await {
                Ok(items) => {
                    emit_http_fetch(
                        config.session_log.as_ref(),
                        audit_handle.as_ref(),
                        source,
                        "ok",
                        bytes_total(&items),
                        &run_id,
                    );
                    items
                }
                Err(e) => {
                    let outcome = fetch_outcome_label(&e);
                    emit_http_fetch(
                        config.session_log.as_ref(),
                        audit_handle.as_ref(),
                        source,
                        &outcome,
                        0,
                        &run_id,
                    );
                    summary.sources_failed.push(SourceFailure {
                        source: source.name.clone(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            },
            other => {
                summary.sources_unsupported.push(source.name.clone());
                tracing::info!(
                    "source '{}' uses method '{}' which is unsupported in the C-foundation slice",
                    source.name,
                    other
                );
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
                    store.conn().execute(
                        "INSERT INTO candidates ( \
                            source_name, url, body, run_id, title, published_at, \
                            matched_keywords, keyword_match_score \
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![
                            &item.source_name,
                            &item.url,
                            &item.abstract_text,
                            &run_id,
                            &item.title,
                            &published_at,
                            &matched_json,
                            keyword_match_score as i64,
                        ],
                    )?;
                    let candidate_id = store.conn().last_insert_rowid();
                    summary.items_kept += 1;
                    summary.kept_candidate_ids.push(candidate_id);
                    if let (Some(log), Some(handle)) =
                        (config.session_log.as_ref(), audit_handle.as_ref())
                    {
                        let _ = log.append(
                            handle,
                            TrustLevel::System,
                            SessionEvent::CandidateScored {
                                run_id: run_id.clone(),
                                candidate_id,
                                keyword_match_score,
                                matched_keywords: matched_json,
                            },
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

fn fetch_outcome_label(e: &FetchError) -> String {
    match e {
        FetchError::Denied {
            source: HttpAccessDenied::Egress(_),
            ..
        } => "egress_denied".to_string(),
        FetchError::Denied {
            source: HttpAccessDenied::RateLimit(_),
            ..
        } => "rate_limited".to_string(),
        FetchError::HttpStatus { status, .. } => format!("http_error_{}", status),
        FetchError::Network { .. } => "network_error".to_string(),
        FetchError::Parse { .. } => "parse_error".to_string(),
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

fn emit_http_fetch(
    session_log: Option<&Arc<dyn SessionLog>>,
    handle: Option<&SessionHandle<OwnSession>>,
    source: &SourceEntry,
    outcome: &str,
    bytes: u64,
    run_id: &str,
) {
    emit(
        session_log,
        handle,
        SessionEvent::HttpFetch {
            source: source.name.clone(),
            host: host_of(&source.endpoint),
            url: source.endpoint.clone(),
            outcome: outcome.to_string(),
            bytes,
            run_id: Some(run_id.to_string()),
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
        std::fs::write(dest.join("skills/aggregator/SKILL.md"), aggregator_md).unwrap();
        std::fs::write(dest.join("sources.toml"), sources_toml).unwrap();
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
}
