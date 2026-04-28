//! Digest renderer for the daily push.
//!
//! Reads candidate + theme rows for a run, groups them, and produces
//! a numbered text body and the matching ordered candidate-id list.
//! The renderer does not touch the database for writes — `digest_log`
//! is the persistence side, called by the wiring after the renderer
//! produces its output.
//!
//! ## Single-section rule
//!
//! HDBSCAN's noise / low-density behaviour means a run can land
//! entirely in one bucket — every item ungrouped, or every item in a
//! single named theme. Rendering a lonely `— Ungrouped (8) —` header
//! over the only section is sad and misleading; the body reads
//! cleaner as a flat numbered list with no header at all. The rule:
//! when the digest collapses to one section, drop the section
//! header. ≥2 sections always render headers, including the
//! ungrouped section if it coexists with named themes.

use rusqlite::{Connection, params};

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("run {run_id} has no candidates to render")]
    EmptyRun { run_id: String },
}

#[derive(Debug, Clone)]
pub struct DigestRow {
    pub candidate_id: i64,
    pub title: String,
    pub url: String,
    pub source_name: String,
    pub llm_relevance_score: Option<u32>,
    pub llm_why_surfaced: Option<String>,
    pub cluster_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ThemeRow {
    pub id: i64,
    pub name: String,
    pub member_count: u32,
}

#[derive(Debug, Clone)]
pub struct RenderOptions {
    /// Cap on rendered items. Items past this cap are dropped from
    /// the output text and from `ordered_candidate_ids`. The
    /// operator can re-query the database for the full run.
    pub max_items: usize,
    /// One-line title for the digest (e.g. `"Daily digest"`).
    pub title: String,
    /// Optional date string appended after the title with `" — "`.
    pub date: Option<String>,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            max_items: 20,
            title: "Daily digest".into(),
            date: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenderedDigest {
    pub text: String,
    /// Candidate ids in the 1-indexed order they appear in `text`.
    /// Goes to `digest_log::record_sent` so the keep/skip
    /// interceptor maps the operator's reply back to candidates.
    pub ordered_candidate_ids: Vec<i64>,
}

/// Read every candidate in the run and the run's theme rows.
pub fn load_run(
    conn: &Connection,
    run_id: &str,
) -> Result<(Vec<DigestRow>, Vec<ThemeRow>), DigestError> {
    let mut stmt = conn.prepare(
        "SELECT id, title, url, source_name, llm_relevance_score, llm_why_surfaced, cluster_id \
         FROM candidates \
         WHERE run_id = ?1 \
         ORDER BY \
            llm_relevance_score IS NULL ASC, \
            llm_relevance_score DESC, \
            id ASC",
    )?;
    let rows: Vec<DigestRow> = stmt
        .query_map(params![run_id], |r| {
            Ok(DigestRow {
                candidate_id: r.get(0)?,
                title: r.get(1)?,
                url: r.get(2)?,
                source_name: r.get(3)?,
                llm_relevance_score: r
                    .get::<_, Option<f64>>(4)?
                    .map(|f| f.round().clamp(0.0, 1000.0) as u32),
                llm_why_surfaced: r.get(5)?,
                cluster_id: r.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut tstmt = conn.prepare(
        "SELECT id, name, member_count FROM themes WHERE run_id = ?1 ORDER BY member_count DESC, id ASC",
    )?;
    let themes: Vec<ThemeRow> = tstmt
        .query_map(params![run_id], |r| {
            Ok(ThemeRow {
                id: r.get(0)?,
                name: r.get(1)?,
                member_count: r.get::<_, i64>(2)? as u32,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok((rows, themes))
}

/// Render a digest from the loaded rows.
pub fn render(
    rows: &[DigestRow],
    themes: &[ThemeRow],
    opts: &RenderOptions,
) -> Result<RenderedDigest, DigestError> {
    if rows.is_empty() {
        return Err(DigestError::EmptyRun {
            run_id: String::new(),
        });
    }

    // Cap before grouping so the rendered text and the recorded
    // ordered ids match exactly.
    let capped: Vec<&DigestRow> = rows.iter().take(opts.max_items).collect();

    // Theme metadata by id.
    let theme_by_id: std::collections::HashMap<i64, &ThemeRow> =
        themes.iter().map(|t| (t.id, t)).collect();

    // Group rows by cluster_id (None = ungrouped). Stable order
    // within a group is the row order we received (already
    // relevance-sorted by load_run).
    let mut groups: std::collections::HashMap<Option<i64>, Vec<&DigestRow>> =
        std::collections::HashMap::new();
    for r in &capped {
        groups.entry(r.cluster_id).or_default().push(r);
    }

    // Order groups: named themes first (by member_count DESC, then id),
    // ungrouped at the end.
    let mut named: Vec<i64> = groups.keys().filter_map(|k| *k).collect();
    named.sort_by_key(|id| {
        let t = theme_by_id.get(id);
        // Sort key: -member_count then id; clusters with no theme
        // row land below named themes but above the ungrouped bucket.
        (
            t.map(|t| -(t.member_count as i64)).unwrap_or(0),
            t.is_none(),
            *id,
        )
    });

    // Total ordered list of (header_label_or_none, rows).
    let mut sections: Vec<(Option<String>, Vec<&DigestRow>)> = Vec::new();
    for cid in &named {
        let label = theme_by_id
            .get(cid)
            .map(|t| t.name.clone())
            .unwrap_or_else(|| format!("Cluster {cid}"));
        if let Some(rs) = groups.remove(&Some(*cid)) {
            sections.push((Some(label), rs));
        }
    }
    if let Some(ungrouped) = groups.remove(&None) {
        sections.push((Some("Ungrouped".into()), ungrouped));
    }

    // Single-section rule: drop the lone header.
    let drop_headers = sections.len() == 1;

    // Build text + ordered_candidate_ids in lockstep.
    let mut text = String::new();
    text.push_str(&opts.title);
    if let Some(date) = opts.date.as_ref() {
        text.push_str(" — ");
        text.push_str(date);
    }
    text.push('\n');

    let mut ordered: Vec<i64> = Vec::with_capacity(capped.len());
    let mut idx: u32 = 1;
    for (header, rs) in &sections {
        if !drop_headers {
            if let Some(h) = header {
                text.push('\n');
                text.push_str("— ");
                text.push_str(h);
                text.push_str(&format!(" ({}) —\n", rs.len()));
            }
        } else {
            text.push('\n');
        }
        for r in rs {
            text.push_str(&format!("{idx}. {}\n", r.title));
            text.push_str(&format!("   {}", r.source_name));
            if let Some(why) = &r.llm_why_surfaced {
                if !why.is_empty() {
                    text.push_str(" — ");
                    text.push_str(why);
                }
            }
            text.push('\n');
            text.push_str(&format!("   {}\n", r.url));
            ordered.push(r.candidate_id);
            idx += 1;
        }
    }

    text.push('\n');
    text.push_str("Reply: keep 1,3,5 / skip 2 / keep all / skip all\n");

    Ok(RenderedDigest {
        text,
        ordered_candidate_ids: ordered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::AGGREGATOR_MIGRATIONS;

    fn open_migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE _migrations (idx INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        for (idx, sql) in AGGREGATOR_MIGRATIONS.iter().enumerate() {
            tx.execute_batch(sql).unwrap();
            tx.execute(
                "INSERT INTO _migrations (idx) VALUES (?1)",
                params![idx as i64],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        conn
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_candidate(
        conn: &Connection,
        run_id: &str,
        title: &str,
        url: &str,
        source: &str,
        llm_score: Option<f64>,
        why: Option<&str>,
        cluster_id: Option<i64>,
    ) -> i64 {
        conn.execute(
            "INSERT INTO candidates (source_name, url, body, run_id, title, llm_relevance_score, \
             llm_why_surfaced, cluster_id) \
             VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, ?7)",
            params![source, url, run_id, title, llm_score, why, cluster_id],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn insert_theme(conn: &Connection, run_id: &str, name: &str, member_count: i64) -> i64 {
        conn.execute(
            "INSERT INTO themes (run_id, name, member_count) VALUES (?1, ?2, ?3)",
            params![run_id, name, member_count],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn empty_run_errors() {
        let r = render(&[], &[], &RenderOptions::default());
        assert!(matches!(r, Err(DigestError::EmptyRun { .. })));
    }

    #[test]
    fn single_section_drops_header_when_all_ungrouped() {
        let conn = open_migrated();
        insert_candidate(
            &conn,
            "run-1",
            "Item A",
            "https://example.com/a",
            "src-a",
            Some(80.0),
            Some("matches your interest in privacy"),
            None,
        );
        insert_candidate(
            &conn,
            "run-1",
            "Item B",
            "https://example.com/b",
            "src-b",
            Some(60.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        // Single-section rule: no "— Ungrouped (2) —" header.
        assert!(
            !out.text.contains("Ungrouped"),
            "should not render section header for the only section: {}",
            out.text
        );
        assert!(out.text.contains("1. Item A"));
        assert!(out.text.contains("2. Item B"));
        assert!(out.text.contains("matches your interest in privacy"));
        assert_eq!(out.ordered_candidate_ids.len(), 2);
    }

    #[test]
    fn single_section_drops_header_when_all_in_one_named_theme() {
        let conn = open_migrated();
        let theme_id = insert_theme(&conn, "run-1", "Adtech consent", 3);
        for n in 0..3 {
            insert_candidate(
                &conn,
                "run-1",
                &format!("Item {n}"),
                &format!("https://example.com/{n}"),
                "src",
                Some(80.0 - n as f64),
                None,
                Some(theme_id),
            );
        }
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        assert!(
            !out.text.contains("Adtech consent ("),
            "should not render lone theme header: {}",
            out.text
        );
        assert!(out.text.contains("1. Item 0"));
        assert!(out.text.contains("3. Item 2"));
    }

    #[test]
    fn multi_section_renders_headers_with_member_counts() {
        let conn = open_migrated();
        let big = insert_theme(&conn, "run-1", "Privacy enforcement", 3);
        let small = insert_theme(&conn, "run-1", "Cross-border transfers", 2);
        for n in 0..3 {
            insert_candidate(
                &conn,
                "run-1",
                &format!("PE {n}"),
                &format!("https://pe/{n}"),
                "src",
                Some(80.0),
                None,
                Some(big),
            );
        }
        for n in 0..2 {
            insert_candidate(
                &conn,
                "run-1",
                &format!("CB {n}"),
                &format!("https://cb/{n}"),
                "src",
                Some(70.0),
                None,
                Some(small),
            );
        }
        // Ungrouped tail.
        insert_candidate(
            &conn,
            "run-1",
            "Loose",
            "https://x/y",
            "src",
            Some(50.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        assert!(out.text.contains("— Privacy enforcement (3) —"));
        assert!(out.text.contains("— Cross-border transfers (2) —"));
        assert!(out.text.contains("— Ungrouped (1) —"));
        // Big theme appears before small theme (by member_count).
        let big_pos = out.text.find("Privacy enforcement").unwrap();
        let small_pos = out.text.find("Cross-border").unwrap();
        let un_pos = out.text.find("Ungrouped").unwrap();
        assert!(big_pos < small_pos);
        assert!(small_pos < un_pos);
        // 6 items total, 1-indexed across the whole digest.
        assert!(out.text.contains("1. PE 0"));
        assert!(out.text.contains("6. Loose"));
        assert_eq!(out.ordered_candidate_ids.len(), 6);
    }

    #[test]
    fn cap_drops_low_relevance_items() {
        let conn = open_migrated();
        for n in 0..5 {
            insert_candidate(
                &conn,
                "run-1",
                &format!("Item {n}"),
                &format!("https://x/{n}"),
                "src",
                // 90, 80, 70, 60, 50
                Some(90.0 - 10.0 * n as f64),
                None,
                None,
            );
        }
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let opts = RenderOptions {
            max_items: 3,
            ..RenderOptions::default()
        };
        let out = render(&rows, &themes, &opts).unwrap();
        assert!(out.text.contains("1. Item 0"));
        assert!(out.text.contains("3. Item 2"));
        assert!(!out.text.contains("Item 3"));
        assert_eq!(out.ordered_candidate_ids.len(), 3);
    }

    #[test]
    fn ordered_candidate_ids_match_rendered_indices() {
        let conn = open_migrated();
        let id_a = insert_candidate(
            &conn,
            "run-1",
            "A",
            "https://a",
            "s",
            Some(90.0),
            None,
            None,
        );
        let id_b = insert_candidate(
            &conn,
            "run-1",
            "B",
            "https://b",
            "s",
            Some(80.0),
            None,
            None,
        );
        let id_c = insert_candidate(
            &conn,
            "run-1",
            "C",
            "https://c",
            "s",
            Some(70.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        assert_eq!(out.ordered_candidate_ids, vec![id_a, id_b, id_c]);
    }

    #[test]
    fn nulls_sort_after_scored_items() {
        let conn = open_migrated();
        let unscored = insert_candidate(
            &conn,
            "run-1",
            "Unscored",
            "https://u",
            "s",
            None,
            None,
            None,
        );
        let scored = insert_candidate(
            &conn,
            "run-1",
            "Scored",
            "https://s",
            "s",
            Some(70.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        assert_eq!(out.ordered_candidate_ids, vec![scored, unscored]);
    }

    #[test]
    fn footer_includes_reply_help() {
        let conn = open_migrated();
        insert_candidate(
            &conn,
            "run-1",
            "X",
            "https://x",
            "s",
            Some(70.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let out = render(&rows, &themes, &RenderOptions::default()).unwrap();
        assert!(out.text.contains("keep 1,3,5"));
        assert!(out.text.contains("skip all"));
    }

    #[test]
    fn date_appears_in_title_when_provided() {
        let conn = open_migrated();
        insert_candidate(
            &conn,
            "run-1",
            "X",
            "https://x",
            "s",
            Some(70.0),
            None,
            None,
        );
        let (rows, themes) = load_run(&conn, "run-1").unwrap();
        let opts = RenderOptions {
            date: Some("2026-04-29".into()),
            ..RenderOptions::default()
        };
        let out = render(&rows, &themes, &opts).unwrap();
        assert!(out.text.starts_with("Daily digest — 2026-04-29"));
    }
}
