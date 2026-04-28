//! Per-skill SQLite schema for the Zirkel aggregator.
//!
//! Migrations are versioned by index in the slice. The runner records
//! applied indexes in `_migrations` and is idempotent. **Append-only**
//! — never reorder or replace existing entries; the recorded indexes
//! would point at different SQL.
//!
//! ## Score column naming
//!
//! `keyword_match_score INTEGER` is named explicitly to make its
//! semantics legible at SQL-query time: it is the count of distinct
//! keyword matches against title + abstract, not a 0–100 relevance
//! rating. C-LLM adds a separate `llm_relevance_score REAL` column;
//! both will coexist so downstream queries can filter on either.

/// Append-only migration list. Index 0 was Scope B (one-source
/// smoke-test schema); indexes 1+ are the foundation slice's
/// expansion to per-item rows, dedup, screening, snapshots.
pub const AGGREGATOR_MIGRATIONS: &[&str] = &[
    // 0 — Scope B: original `candidates` table. Per-fetch row whose
    // `body` was the entire HTTP response. Kept as-is so the
    // migration runner doesn't need to re-create.
    "CREATE TABLE candidates ( \
        id           INTEGER PRIMARY KEY AUTOINCREMENT, \
        source_name  TEXT NOT NULL, \
        url          TEXT NOT NULL, \
        fetched_at   TEXT NOT NULL DEFAULT (datetime('now')), \
        body         TEXT NOT NULL \
    )",
    // 1 — repurpose `candidates` for per-item rows. Existing rows
    // from Scope B smoke testing have `run_id = ''`; the orchestrator
    // queries by `run_id != ''` so they don't pollute results.
    "ALTER TABLE candidates ADD COLUMN run_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE candidates ADD COLUMN title TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE candidates ADD COLUMN published_at TEXT",
    "ALTER TABLE candidates ADD COLUMN matched_keywords TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE candidates ADD COLUMN keyword_match_score INTEGER NOT NULL DEFAULT 0",
    // 2 — dedup state. URL hash (SHA-256 hex) is what the orchestrator
    // checks before scoring; `url` is kept verbatim for human
    // inspection.
    "CREATE TABLE seen ( \
        url          TEXT PRIMARY KEY, \
        url_hash     TEXT NOT NULL, \
        first_seen   TEXT NOT NULL DEFAULT (datetime('now')) \
    )",
    "CREATE INDEX idx_seen_hash ON seen(url_hash)",
    // 3 — interests file snapshots, one per run. The file's bytes
    // are stored verbatim so a future replay can reconstruct the
    // exact screening / scoring decisions.
    "CREATE TABLE interests_snapshots ( \
        id           INTEGER PRIMARY KEY AUTOINCREMENT, \
        run_id       TEXT NOT NULL, \
        file_hash    TEXT NOT NULL, \
        contents     TEXT NOT NULL, \
        created_at   TEXT NOT NULL DEFAULT (datetime('now')) \
    )",
    "CREATE INDEX idx_interests_snapshots_run ON interests_snapshots(run_id)",
    // 4 — items dropped before scoring (exclusion match, dedup hit,
    // unsupported source method). Kept compact — no body, just the
    // metadata needed to verify the funnel reconciles.
    "CREATE TABLE skipped_log ( \
        id           INTEGER PRIMARY KEY AUTOINCREMENT, \
        run_id       TEXT NOT NULL, \
        url_hash     TEXT NOT NULL, \
        url          TEXT NOT NULL, \
        source_name  TEXT NOT NULL, \
        fetched_at   TEXT NOT NULL DEFAULT (datetime('now')), \
        reason       TEXT NOT NULL, \
        detail       TEXT \
    )",
    "CREATE INDEX idx_skipped_log_run ON skipped_log(run_id)",
];
