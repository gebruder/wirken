//! `wirken zirkel calibrate` — read the operator's local Zirkel
//! SQLite at `~/.wirken/zirkel/aggregator.db`, join
//! `candidates.llm_relevance_score` against the user label set from
//! `digest_items.decision`, and report discrimination (AUC),
//! reliability (equal-frequency buckets), and optional
//! stratification by source or matched keyword.
//!
//! Data-source rationale (see issue #138): SQLite, not the audit
//! chain. `CandidateSkipped` audit events carry `url_hash` not
//! `candidate_id`, which would force a url-hash join for negatives.
//! `digest_items.decision` ∈ `{"kept","skipped",NULL}` is set by
//! `keep_skip_interceptor.rs::expand_decisions` so every digest item
//! the user replied to gets either label; orchestrator-driven skips
//! live in a separate `skipped_log` table and never reach
//! `digest_items`. So the JOIN below excludes orchestrator skips
//! structurally rather than via a remembered filter. `NULL` decisions
//! mean the user never engaged with the digest at all and are
//! excluded from the labeled set so absence-of-engagement does not
//! masquerade as rejection.
//!
//! Computation only. The binary names no candidates, keywords,
//! sources, or kept items; the corpus stays in `~/.wirken/`. Same
//! posture as `wirken zirkel status`.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// How to stratify the report. `Overall` is one report over the
/// labeled corpus; `Source` groups by `candidates.source_name`;
/// `Keyword` explodes `candidates.matched_keywords` (JSON array) so
/// a multi-keyword candidate contributes to every keyword's bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StratBy {
    Overall,
    Source,
    Keyword,
}

impl std::str::FromStr for StratBy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "overall" => Ok(StratBy::Overall),
            "source" => Ok(StratBy::Source),
            "keyword" => Ok(StratBy::Keyword),
            other => Err(format!(
                "unknown stratification {other:?}: expected one of overall, source, keyword"
            )),
        }
    }
}

/// Config for one calibration invocation.
#[derive(Debug, Clone)]
pub struct CalibrationConfig {
    /// Optional `candidates.run_id` filter. `None` is "all runs."
    pub run_id: Option<String>,
    /// Number of equal-frequency reliability buckets. Capped at
    /// labeled-set size at compute time so a 5-row corpus does not
    /// emit a 10-row diagram.
    pub buckets: u32,
    pub by: StratBy,
}

/// One labeled candidate row joined out of SQLite.
#[derive(Debug, Clone)]
struct LabeledRow {
    score: f64,
    /// `true` = kept (positive), `false` = user-skipped (negative).
    kept: bool,
    source: String,
    /// Parsed from `candidates.matched_keywords` (JSON array).
    matched_keywords: Vec<String>,
}

/// A reliability diagram bucket. `n` is row count for the bucket
/// before any smoothing; `kept_rate` is `n_kept / n`. Low-n buckets
/// are reported as-is so the operator does not read `kept_rate = 1.0
/// over n = 3` as a calibrated signal.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    pub score_mean: f64,
    pub kept_rate: f64,
    pub n: u32,
}

/// One stratification group's report. `Overall` produces one entry
/// with `label = "overall"`; `Source` produces one per distinct
/// source_name; `Keyword` produces one per distinct matched keyword.
#[derive(Debug, Clone)]
pub struct GroupReport {
    pub label: String,
    pub n_total: u32,
    pub n_kept: u32,
    pub n_skipped: u32,
    /// `None` when either label set is empty (Mann-Whitney U
    /// undefined). Reported as "undefined" by the renderer.
    pub auc: Option<f64>,
    pub buckets: Vec<Bucket>,
}

/// Whole-report aggregate, written to stdout by [`render_report`].
#[derive(Debug, Clone)]
pub struct CalibrationReport {
    pub source_path: String,
    pub run_filter: Option<String>,
    pub strat: StratBy,
    /// Buckets the user asked for. The per-group `buckets.len()` may
    /// be lower when the group is smaller than the requested count.
    pub requested_buckets: u32,
    pub groups: Vec<GroupReport>,
}

/// Read every labeled row out of SQLite, stratify per
/// [`CalibrationConfig::by`], and produce a [`CalibrationReport`].
///
/// The single underlying query is
/// `SELECT c.llm_relevance_score, d.decision, c.source_name,
///  c.matched_keywords FROM candidates c JOIN digest_items d ON
///  d.candidate_id = c.id WHERE d.decision IN ('kept','skipped')
///  [AND c.run_id = ?]`. The JOIN excludes orchestrator skips
/// structurally; the `IN` clause excludes `NULL` decisions
/// structurally.
pub fn compute_calibration(
    conn: &Connection,
    cfg: &CalibrationConfig,
    source_path: &str,
) -> Result<CalibrationReport> {
    let rows = load_labeled_rows(conn, cfg.run_id.as_deref())?;
    let groups = match cfg.by {
        StratBy::Overall => {
            vec![build_group_report("overall", &rows, cfg.buckets)]
        }
        StratBy::Source => {
            let mut by_source: std::collections::BTreeMap<String, Vec<LabeledRow>> =
                std::collections::BTreeMap::new();
            for r in &rows {
                by_source
                    .entry(r.source.clone())
                    .or_default()
                    .push(r.clone());
            }
            by_source
                .into_iter()
                .map(|(label, subset)| build_group_report(&label, &subset, cfg.buckets))
                .collect()
        }
        StratBy::Keyword => {
            let mut by_kw: std::collections::BTreeMap<String, Vec<LabeledRow>> =
                std::collections::BTreeMap::new();
            for r in &rows {
                for kw in &r.matched_keywords {
                    by_kw.entry(kw.clone()).or_default().push(r.clone());
                }
            }
            by_kw
                .into_iter()
                .map(|(label, subset)| build_group_report(&label, &subset, cfg.buckets))
                .collect()
        }
    };

    Ok(CalibrationReport {
        source_path: source_path.to_string(),
        run_filter: cfg.run_id.clone(),
        strat: cfg.by,
        requested_buckets: cfg.buckets,
        groups,
    })
}

fn load_labeled_rows(conn: &Connection, run_id: Option<&str>) -> Result<Vec<LabeledRow>> {
    let (sql, with_filter) = match run_id {
        Some(_) => (
            "SELECT c.llm_relevance_score, d.decision, c.source_name, c.matched_keywords \
             FROM candidates c \
             JOIN digest_items d ON d.candidate_id = c.id \
             WHERE d.decision IN ('kept','skipped') \
               AND c.run_id = ?1 \
               AND c.llm_relevance_score IS NOT NULL",
            true,
        ),
        None => (
            "SELECT c.llm_relevance_score, d.decision, c.source_name, c.matched_keywords \
             FROM candidates c \
             JOIN digest_items d ON d.candidate_id = c.id \
             WHERE d.decision IN ('kept','skipped') \
               AND c.llm_relevance_score IS NOT NULL",
            false,
        ),
    };
    let mut stmt = conn.prepare(sql).context("prepare labeled-rows query")?;
    let mut rows_iter = if with_filter {
        stmt.query(rusqlite::params![run_id.unwrap()])
            .context("query labeled rows (filtered)")?
    } else {
        stmt.query([]).context("query labeled rows")?
    };
    let mut out = Vec::new();
    while let Some(row) = rows_iter.next().context("iterate labeled rows")? {
        let score: f64 = row.get(0).context("read llm_relevance_score")?;
        let decision: String = row.get(1).context("read decision")?;
        let source: String = row.get(2).context("read source_name")?;
        let kw_json: String = row.get(3).context("read matched_keywords")?;
        let matched_keywords: Vec<String> = serde_json::from_str(&kw_json).unwrap_or_default();
        let kept = match decision.as_str() {
            "kept" => true,
            "skipped" => false,
            // The IN clause above keeps this unreachable, but
            // defaulting to skip would silently invert a label on
            // any schema drift. Fail loud instead.
            other => anyhow::bail!("unexpected digest_items.decision {other:?}"),
        };
        out.push(LabeledRow {
            score,
            kept,
            source,
            matched_keywords,
        });
    }
    Ok(out)
}

fn build_group_report(label: &str, rows: &[LabeledRow], requested_buckets: u32) -> GroupReport {
    let n_total = rows.len() as u32;
    let n_kept = rows.iter().filter(|r| r.kept).count() as u32;
    let n_skipped = n_total - n_kept;
    let auc = mann_whitney_auc(rows);
    let bucket_count = std::cmp::min(requested_buckets, n_total).max(1);
    let buckets = if n_total == 0 {
        Vec::new()
    } else {
        equal_frequency_buckets(rows, bucket_count)
    };
    GroupReport {
        label: label.to_string(),
        n_total,
        n_kept,
        n_skipped,
        auc,
        buckets,
    }
}

/// Mann-Whitney U → AUC with mid-rank tie handling. `None` when
/// either label set is empty (AUC undefined).
///
/// Rank all scores together (1-indexed, average rank for ties),
/// `R_pos = sum of ranks of positive labels`,
/// `U = R_pos - n_pos(n_pos + 1) / 2`,
/// `AUC = U / (n_pos * n_neg)`.
fn mann_whitney_auc(rows: &[LabeledRow]) -> Option<f64> {
    let n_pos = rows.iter().filter(|r| r.kept).count();
    let n_neg = rows.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }
    // Index, score, kept. Sort by score ascending; assign mid-ranks
    // over equal-score runs.
    let mut indexed: Vec<(usize, f64, bool)> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (i, r.score, r.kept))
        .collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut ranks = vec![0.0_f64; rows.len()];
    let mut i = 0;
    while i < indexed.len() {
        let mut j = i + 1;
        while j < indexed.len() && (indexed[j].1 - indexed[i].1).abs() < f64::EPSILON {
            j += 1;
        }
        // Ranks i+1..=j (1-indexed). Average is the mean of the run.
        let avg_rank = ((i + 1 + j) as f64) / 2.0;
        for k in i..j {
            ranks[indexed[k].0] = avg_rank;
        }
        i = j;
    }
    let r_pos: f64 = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kept)
        .map(|(i, _)| ranks[i])
        .sum();
    let u = r_pos - (n_pos as f64) * ((n_pos as f64) + 1.0) / 2.0;
    Some(u / ((n_pos as f64) * (n_neg as f64)))
}

/// Equal-frequency buckets. Sort by score ascending, partition into
/// `bucket_count` near-equal chunks (`n/bucket_count` per bucket with
/// the remainder distributed to the leading buckets), report
/// `(score_mean, kept_rate, n)` per bucket. Low-n buckets are not
/// smoothed; the caller's renderer must surface `n` honestly.
fn equal_frequency_buckets(rows: &[LabeledRow], bucket_count: u32) -> Vec<Bucket> {
    if rows.is_empty() || bucket_count == 0 {
        return Vec::new();
    }
    let mut sorted: Vec<&LabeledRow> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let n = sorted.len();
    let bc = std::cmp::min(bucket_count as usize, n);
    let base = n / bc;
    let extra = n % bc;

    let mut out = Vec::with_capacity(bc);
    let mut idx = 0;
    for b in 0..bc {
        let size = base + usize::from(b < extra);
        let slice = &sorted[idx..idx + size];
        let n_kept = slice.iter().filter(|r| r.kept).count();
        let mean = slice.iter().map(|r| r.score).sum::<f64>() / (slice.len() as f64);
        out.push(Bucket {
            score_mean: mean,
            kept_rate: (n_kept as f64) / (slice.len() as f64),
            n: slice.len() as u32,
        });
        idx += size;
    }
    out
}

/// Write the report to stdout in the same terse style as
/// `wirken zirkel status` (`crates/cli/src/commands/zirkel.rs:265`):
/// plain ASCII, no color, no emoji, paths quoted in headers.
pub fn render_report(r: &CalibrationReport) {
    println!("Zirkel calibration report");
    println!("Source: {}", r.source_path);
    match &r.run_filter {
        Some(id) => println!("Filter: run_id = {id}"),
        None => println!("Filter: all runs"),
    }
    let by_label = match r.strat {
        StratBy::Overall => "overall",
        StratBy::Source => "by source (candidates.source_name)",
        StratBy::Keyword => {
            "by matched keyword (candidates.matched_keywords; a \
             multi-keyword candidate contributes to every keyword \
             so per-keyword n's sum to more than the candidate count)"
        }
    };
    println!("Stratification: {by_label}");
    println!("Requested reliability buckets: {}", r.requested_buckets);
    println!();

    if r.groups.iter().all(|g| g.n_total == 0) {
        println!("No labeled candidates in the corpus.");
        println!(
            "(`digest_items.decision IN ('kept','skipped')` is empty; either no digest \
             has been replied to, or the run_id filter matched nothing.)"
        );
        return;
    }

    for g in &r.groups {
        if matches!(r.strat, StratBy::Overall) {
            println!("== overall ==");
        } else {
            println!("== {}: {} ==", strat_label(r.strat), g.label);
        }
        println!(
            "  Labeled: n = {}  (kept = {}, skipped = {})",
            g.n_total, g.n_kept, g.n_skipped
        );
        match g.auc {
            Some(a) => println!("  AUC: {a:.3}  (Mann-Whitney U, mid-rank tie handling)"),
            None => println!("  AUC: undefined (need at least one of each label)"),
        }
        if g.buckets.is_empty() {
            println!("  Reliability diagram: empty");
        } else {
            println!(
                "  Reliability diagram (equal-frequency, {} bucket(s)):",
                g.buckets.len()
            );
            println!("    bucket  score_mean  kept_rate    n");
            for (i, b) in g.buckets.iter().enumerate() {
                println!(
                    "    {:>6}  {:>10.2}  {:>9.3}  {:>4}",
                    i + 1,
                    b.score_mean,
                    b.kept_rate,
                    b.n
                );
            }
        }
        println!();
    }
}

fn strat_label(s: StratBy) -> &'static str {
    match s {
        StratBy::Overall => "overall",
        StratBy::Source => "source",
        StratBy::Keyword => "keyword",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(score: f64, kept: bool, source: &str, kws: &[&str]) -> LabeledRow {
        LabeledRow {
            score,
            kept,
            source: source.to_string(),
            matched_keywords: kws.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn auc_perfectly_separable_is_one() {
        // All kept scores strictly above all skipped scores.
        let rows = vec![
            row(10.0, false, "s", &[]),
            row(20.0, false, "s", &[]),
            row(30.0, false, "s", &[]),
            row(80.0, true, "s", &[]),
            row(90.0, true, "s", &[]),
        ];
        let auc = mann_whitney_auc(&rows).unwrap();
        assert!((auc - 1.0).abs() < 1e-9, "expected 1.0, got {auc}");
    }

    #[test]
    fn auc_inverse_relationship_is_zero() {
        // Kept scores strictly BELOW skipped — calibration is
        // anti-correlated; AUC should be 0.0, not silently flipped.
        let rows = vec![
            row(90.0, false, "s", &[]),
            row(80.0, false, "s", &[]),
            row(20.0, true, "s", &[]),
            row(10.0, true, "s", &[]),
        ];
        let auc = mann_whitney_auc(&rows).unwrap();
        assert!(auc < 1e-9, "expected 0.0, got {auc}");
    }

    #[test]
    fn auc_fully_overlapping_is_one_half() {
        // Every score appears once kept and once skipped → ties
        // fold to 0.5 under mid-rank handling.
        let rows = vec![
            row(10.0, true, "s", &[]),
            row(10.0, false, "s", &[]),
            row(20.0, true, "s", &[]),
            row(20.0, false, "s", &[]),
            row(30.0, true, "s", &[]),
            row(30.0, false, "s", &[]),
        ];
        let auc = mann_whitney_auc(&rows).unwrap();
        assert!((auc - 0.5).abs() < 1e-9, "expected 0.5, got {auc}");
    }

    #[test]
    fn auc_one_label_set_empty_is_none() {
        let all_kept = vec![row(10.0, true, "s", &[]), row(20.0, true, "s", &[])];
        assert!(mann_whitney_auc(&all_kept).is_none());
        let all_skipped = vec![row(10.0, false, "s", &[]), row(20.0, false, "s", &[])];
        assert!(mann_whitney_auc(&all_skipped).is_none());
    }

    #[test]
    fn equal_frequency_buckets_distribute_remainder_to_leading() {
        // 5 rows, 3 buckets → sizes 2, 2, 1 (extra distributed
        // to the leading buckets, not split evenly).
        let rows = vec![
            row(1.0, false, "s", &[]),
            row(2.0, false, "s", &[]),
            row(3.0, false, "s", &[]),
            row(4.0, true, "s", &[]),
            row(5.0, true, "s", &[]),
        ];
        let b = equal_frequency_buckets(&rows, 3);
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].n, 2);
        assert_eq!(b[1].n, 2);
        assert_eq!(b[2].n, 1);
        // Bucket order is by ascending score; kept items concentrate
        // in the top bucket.
        assert!(b[0].kept_rate < 0.001);
        assert!((b[2].kept_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn equal_frequency_buckets_caps_at_corpus_size() {
        // 3 rows, 10 buckets → 3 buckets (one row each).
        let rows = vec![
            row(1.0, true, "s", &[]),
            row(2.0, false, "s", &[]),
            row(3.0, true, "s", &[]),
        ];
        let b = equal_frequency_buckets(&rows, 10);
        assert_eq!(b.len(), 3);
        assert!(b.iter().all(|bk| bk.n == 1));
    }

    #[test]
    fn equal_frequency_buckets_does_not_smooth_low_n() {
        // n=3 rows in one bucket: kept_rate must be exact 2/3,
        // not smoothed or suppressed.
        let rows = vec![
            row(1.0, true, "s", &[]),
            row(2.0, true, "s", &[]),
            row(3.0, false, "s", &[]),
        ];
        let b = equal_frequency_buckets(&rows, 1);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].n, 3);
        assert!((b[0].kept_rate - 2.0 / 3.0).abs() < 1e-9);
    }

    /// End-to-end against an in-memory SQLite that mirrors the
    /// `candidates` / `digest_items` / `skipped_log` schema. Asserts:
    /// (a) orchestrator skips never reach the labeled set, (b) NULL
    /// decisions are excluded, (c) the JOIN produces what the
    /// compute path expects.
    #[test]
    fn end_to_end_join_excludes_orchestrator_skips_and_null_decisions() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE candidates (
                id                    INTEGER PRIMARY KEY,
                run_id                TEXT NOT NULL,
                source_name           TEXT NOT NULL,
                url                   TEXT NOT NULL,
                title                 TEXT NOT NULL DEFAULT '',
                matched_keywords      TEXT NOT NULL DEFAULT '[]',
                keyword_match_score   INTEGER NOT NULL DEFAULT 0,
                llm_relevance_score   REAL,
                llm_why_surfaced      TEXT
             );
             CREATE TABLE digests (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL);
             CREATE TABLE digest_items (
                digest_id     INTEGER NOT NULL,
                idx           INTEGER NOT NULL,
                candidate_id  INTEGER NOT NULL,
                decision      TEXT,
                PRIMARY KEY (digest_id, idx)
             );
             CREATE TABLE skipped_log (
                id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                url TEXT NOT NULL,
                source_name TEXT NOT NULL,
                reason TEXT NOT NULL,
                detail TEXT
             );",
        )
        .unwrap();

        // c1: in a digest, user kept. c2: in a digest, user skipped.
        // c3: in a digest, user never replied (decision NULL).
        // c4: orchestrator-skipped (reason='score_zero'), in
        // skipped_log only, not in digest_items.
        conn.execute(
            "INSERT INTO candidates (id, run_id, source_name, url, matched_keywords, llm_relevance_score) \
             VALUES (1, 'r1', 'arxiv',   'u1', '[\"k1\",\"k2\"]', 92.0), \
                    (2, 'r1', 'arxiv',   'u2', '[\"k1\"]',        15.0), \
                    (3, 'r1', 'arxiv',   'u3', '[\"k2\"]',        50.0), \
                    (4, 'r1', 'ftc',     'u4', '[\"k1\"]',         0.0)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO digests (id, run_id) VALUES (10, 'r1')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO digest_items (digest_id, idx, candidate_id, decision) \
             VALUES (10, 1, 1, 'kept'), \
                    (10, 2, 2, 'skipped'), \
                    (10, 3, 3, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skipped_log (run_id, url_hash, url, source_name, reason) \
             VALUES ('r1', 'h4', 'u4', 'ftc', 'score_zero')",
            [],
        )
        .unwrap();

        let cfg = CalibrationConfig {
            run_id: None,
            buckets: 10,
            by: StratBy::Overall,
        };
        let report = compute_calibration(&conn, &cfg, "in-memory").unwrap();
        assert_eq!(report.groups.len(), 1);
        let g = &report.groups[0];
        assert_eq!(
            g.n_total, 2,
            "only c1 (kept) and c2 (skipped) should be labeled"
        );
        assert_eq!(g.n_kept, 1);
        assert_eq!(g.n_skipped, 1);
        // c1 score (92) > c2 score (15), so kept ranks above
        // skipped → AUC = 1.0.
        assert!((g.auc.unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn keyword_stratification_explodes_per_candidate() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE candidates (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,
                source_name TEXT NOT NULL, url TEXT NOT NULL,
                matched_keywords TEXT NOT NULL DEFAULT '[]',
                llm_relevance_score REAL
             );
             CREATE TABLE digests (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL);
             CREATE TABLE digest_items (
                digest_id INTEGER NOT NULL, idx INTEGER NOT NULL,
                candidate_id INTEGER NOT NULL, decision TEXT,
                PRIMARY KEY (digest_id, idx)
             );",
        )
        .unwrap();
        // One candidate with two matched keywords kept.
        conn.execute(
            "INSERT INTO candidates VALUES \
              (1,'r','s','u','[\"k1\",\"k2\"]', 80.0), \
              (2,'r','s','v','[\"k1\"]',       20.0)",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO digests VALUES (1, 'r'); \
             INSERT INTO digest_items VALUES (1,1,1,'kept'),(1,2,2,'skipped');",
        )
        .unwrap();
        let cfg = CalibrationConfig {
            run_id: None,
            buckets: 5,
            by: StratBy::Keyword,
        };
        let report = compute_calibration(&conn, &cfg, "in-memory").unwrap();
        // Two groups: k1 (both candidates) and k2 (just c1).
        let by_label: std::collections::BTreeMap<String, &GroupReport> =
            report.groups.iter().map(|g| (g.label.clone(), g)).collect();
        assert_eq!(by_label.len(), 2);
        assert_eq!(by_label["k1"].n_total, 2, "k1 sees both candidates");
        assert_eq!(by_label["k2"].n_total, 1, "k2 sees only c1");
        // Per-keyword n's sum to 3, the candidate count is 2 — the
        // header note is the disclosure that this is intentional.
    }

    #[test]
    fn run_id_filter_isolates_rows_from_one_run() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE candidates (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,
                source_name TEXT NOT NULL, url TEXT NOT NULL,
                matched_keywords TEXT NOT NULL DEFAULT '[]',
                llm_relevance_score REAL
             );
             CREATE TABLE digests (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL);
             CREATE TABLE digest_items (
                digest_id INTEGER NOT NULL, idx INTEGER NOT NULL,
                candidate_id INTEGER NOT NULL, decision TEXT,
                PRIMARY KEY (digest_id, idx)
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO candidates VALUES \
              (1,'r1','s','u1','[]', 90.0), \
              (2,'r2','s','u2','[]', 10.0)",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO digests VALUES (1, 'r1'),(2,'r2'); \
             INSERT INTO digest_items VALUES (1,1,1,'kept'),(2,1,2,'skipped');",
        )
        .unwrap();
        let cfg = CalibrationConfig {
            run_id: Some("r1".into()),
            buckets: 5,
            by: StratBy::Overall,
        };
        let report = compute_calibration(&conn, &cfg, "in-memory").unwrap();
        assert_eq!(report.groups[0].n_total, 1);
        assert_eq!(report.groups[0].n_kept, 1);
        assert!(
            report.groups[0].auc.is_none(),
            "only one label class present"
        );
    }

    #[test]
    fn auc_mid_rank_tie_handling_uses_average_rank() {
        // Two kept at score 5, two skipped at score 5, one kept at
        // score 10. Without mid-rank handling AUC would depend on
        // sort order; with mid-rank it's a defined value.
        // Ranks (1-indexed, ascending): all four 5's tie at ranks
        // 1..=4 → mid-rank 2.5 each. The 10 gets rank 5.
        // R_pos = 2.5 + 2.5 + 5 = 10. n_pos=3, n_neg=2.
        // U = 10 - 3*4/2 = 10 - 6 = 4. AUC = 4 / 6 = 0.6667.
        let rows = vec![
            row(5.0, true, "s", &[]),
            row(5.0, true, "s", &[]),
            row(5.0, false, "s", &[]),
            row(5.0, false, "s", &[]),
            row(10.0, true, "s", &[]),
        ];
        let auc = mann_whitney_auc(&rows).unwrap();
        assert!((auc - (2.0 / 3.0)).abs() < 1e-9, "expected 2/3, got {auc}");
    }
}
