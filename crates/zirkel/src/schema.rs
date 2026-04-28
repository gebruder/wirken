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
    // 5 — C-LLM additions. The keyword and LLM scores live in
    // separate columns so a query can filter on either axis. The
    // keyword column stays a count (`keyword_match_score INTEGER`);
    // `llm_relevance_score REAL` is the LLM-driven 0–100 rating.
    // Both nullable on legacy rows; the C-LLM orchestrator pass fills
    // the LLM column on every keep.
    "ALTER TABLE candidates ADD COLUMN llm_relevance_score REAL",
    "ALTER TABLE candidates ADD COLUMN llm_why_surfaced TEXT",
    // Cluster assignment: NULL for noise / ungrouped items. Real
    // cluster ids reference `themes.id`. The digest renderer's
    // "ungrouped" section is the union of NULL-cluster_id rows.
    "ALTER TABLE candidates ADD COLUMN cluster_id INTEGER",
    // 6 — themes table. Per-run; cross-run theme stability is
    // explicitly out of scope (see DESIGN.md). One row per
    // HDBSCAN cluster, populated after theme naming.
    "CREATE TABLE themes ( \
        id           INTEGER PRIMARY KEY AUTOINCREMENT, \
        run_id       TEXT NOT NULL, \
        name         TEXT NOT NULL, \
        member_count INTEGER NOT NULL, \
        created_at   TEXT NOT NULL DEFAULT (datetime('now')) \
    )",
    "CREATE INDEX idx_themes_run ON themes(run_id)",
    "CREATE INDEX idx_candidates_cluster ON candidates(cluster_id)",
    // 7 — C-Signal: per-digest record + per-item position. The
    // digest renderer (piece 4) writes one `digests` row when it
    // pushes to the operator's channel, plus one `digest_items` row
    // per included candidate at the same 1-indexed position the
    // operator sees in the rendered text. The keep/skip interceptor
    // (piece 3) resolves a digest by looking up the most recent
    // unresolved row for the agent and updating each item's
    // `decision`.
    //
    // `agent_id` rather than `(channel, conversation_id)` because
    // the agent_id is what the InboundInterceptor context already
    // carries; today's bind keeps a single zirkel-bound conversation
    // per agent, so the agent scope is sufficient discrimination.
    "CREATE TABLE digests ( \
        id            INTEGER PRIMARY KEY AUTOINCREMENT, \
        run_id        TEXT NOT NULL, \
        agent_id      TEXT NOT NULL, \
        sent_at       TEXT NOT NULL DEFAULT (datetime('now')), \
        resolved_at   TEXT \
    )",
    "CREATE INDEX idx_digests_lookup ON digests(agent_id, resolved_at, sent_at)",
    "CREATE TABLE digest_items ( \
        digest_id     INTEGER NOT NULL, \
        idx           INTEGER NOT NULL, \
        candidate_id  INTEGER NOT NULL, \
        decision      TEXT, \
        PRIMARY KEY (digest_id, idx), \
        FOREIGN KEY (digest_id) REFERENCES digests(id) \
    )",
    "CREATE INDEX idx_digest_items_candidate ON digest_items(candidate_id)",
    // 8 — C-Signal bindings. `wirken zirkel bind` writes one row;
    // `wirken zirkel run`'s push step reads it. Keyed by `agent_id`
    // because multi-zirkel is not in scope today (one bound
    // conversation per agent is the contract); the CLI enforces
    // idempotency / --force semantics on top.
    "CREATE TABLE bindings ( \
        agent_id         TEXT PRIMARY KEY, \
        channel          TEXT NOT NULL, \
        conversation_id  TEXT NOT NULL, \
        bound_at         TEXT NOT NULL DEFAULT (datetime('now')) \
    )",
];
