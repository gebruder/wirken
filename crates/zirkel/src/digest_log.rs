//! Digest persistence — what was sent, in what order, with what
//! resolution.
//!
//! The digest renderer (piece 4) calls [`record_sent`] when it pushes
//! a digest to the operator's channel; the keep/skip interceptor
//! (piece 3) calls [`most_recent_unresolved`] and [`resolve`] when
//! processing the operator's reply.
//!
//! All operations are scoped by `agent_id`. Today's bind keeps a
//! single zirkel-bound conversation per agent so the agent scope is
//! sufficient discrimination; widening to (agent_id, channel,
//! conversation_id) is a future migration if multi-conversation
//! becomes a real case.

use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug, thiserror::Error)]
pub enum DigestLogError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("digest_id {0} has no items")]
    EmptyDigest(i64),
}

/// One persisted digest with the items the operator was shown.
#[derive(Debug, Clone)]
pub struct DigestRecord {
    pub id: i64,
    pub run_id: String,
    pub agent_id: String,
    pub items: Vec<DigestItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestItem {
    /// 1-indexed position the operator sees in the rendered digest.
    pub idx: u32,
    pub candidate_id: i64,
    /// `None` until the digest is resolved. After resolution one of
    /// `"kept"` or `"skipped"`.
    pub decision: Option<String>,
}

/// Decision applied by the keep/skip resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Kept,
    Skipped,
}

impl Decision {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Decision::Kept => "kept",
            Decision::Skipped => "skipped",
        }
    }
}

/// Insert a new digest with the given 1-indexed candidate list. The
/// caller is responsible for the candidate-ordering decision; the
/// 1-indexed positions in `candidate_ids` (vec position + 1) are
/// what the operator will see and refer to in their reply.
pub fn record_sent(
    conn: &mut Connection,
    run_id: &str,
    agent_id: &str,
    candidate_ids: &[i64],
) -> Result<i64, DigestLogError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO digests (run_id, agent_id) VALUES (?1, ?2)",
        params![run_id, agent_id],
    )?;
    let digest_id = tx.last_insert_rowid();
    {
        let mut stmt = tx.prepare(
            "INSERT INTO digest_items (digest_id, idx, candidate_id) VALUES (?1, ?2, ?3)",
        )?;
        for (i, candidate_id) in candidate_ids.iter().enumerate() {
            let idx = (i as i64) + 1;
            stmt.execute(params![digest_id, idx, candidate_id])?;
        }
    }
    tx.commit()?;
    Ok(digest_id)
}

/// The most recent digest for `agent_id` whose `resolved_at` is
/// still NULL. `None` if every previous digest has been resolved
/// or no digest has been sent.
pub fn most_recent_unresolved(
    conn: &Connection,
    agent_id: &str,
) -> Result<Option<DigestRecord>, DigestLogError> {
    let row = conn
        .query_row(
            "SELECT id, run_id FROM digests \
             WHERE agent_id = ?1 AND resolved_at IS NULL \
             ORDER BY sent_at DESC, id DESC LIMIT 1",
            params![agent_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((id, run_id)) = row else {
        return Ok(None);
    };

    let mut stmt = conn.prepare(
        "SELECT idx, candidate_id, decision FROM digest_items \
         WHERE digest_id = ?1 ORDER BY idx ASC",
    )?;
    let items: Vec<DigestItem> = stmt
        .query_map(params![id], |row| {
            Ok(DigestItem {
                idx: row.get::<_, i64>(0)? as u32,
                candidate_id: row.get(1)?,
                decision: row.get::<_, Option<String>>(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if items.is_empty() {
        return Err(DigestLogError::EmptyDigest(id));
    }

    Ok(Some(DigestRecord {
        id,
        run_id,
        agent_id: agent_id.to_string(),
        items,
    }))
}

/// Apply a decision per-item and mark the digest resolved. Items not
/// listed in `decisions` keep their existing decision (typically
/// `NULL` — the resolver should pass a decision for every item to
/// avoid leaving a partially-resolved digest).
pub fn resolve(
    conn: &mut Connection,
    digest_id: i64,
    decisions: &[(u32, Decision)],
) -> Result<(), DigestLogError> {
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare("UPDATE digest_items SET decision = ?1 WHERE digest_id = ?2 AND idx = ?3")?;
        for (idx, decision) in decisions {
            stmt.execute(params![decision.as_db_str(), digest_id, *idx as i64])?;
        }
    }
    tx.execute(
        "UPDATE digests SET resolved_at = datetime('now') WHERE id = ?1",
        params![digest_id],
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::AGGREGATOR_MIGRATIONS;

    fn open_migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE _migrations (idx INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))",
        ).unwrap();
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

    #[test]
    fn record_sent_returns_id_and_writes_items() {
        let mut conn = open_migrated();
        let id = record_sent(&mut conn, "run-1", "default", &[10, 11, 12]).unwrap();
        assert!(id > 0);
        let rec = most_recent_unresolved(&conn, "default").unwrap().unwrap();
        assert_eq!(rec.id, id);
        assert_eq!(rec.run_id, "run-1");
        assert_eq!(rec.items.len(), 3);
        assert_eq!(rec.items[0].idx, 1);
        assert_eq!(rec.items[0].candidate_id, 10);
        assert_eq!(rec.items[2].idx, 3);
        assert_eq!(rec.items[2].candidate_id, 12);
        for it in rec.items {
            assert!(it.decision.is_none());
        }
    }

    #[test]
    fn most_recent_unresolved_returns_none_when_no_digest() {
        let conn = open_migrated();
        assert!(most_recent_unresolved(&conn, "default").unwrap().is_none());
    }

    #[test]
    fn most_recent_unresolved_skips_resolved_rows() {
        let mut conn = open_migrated();
        let first = record_sent(&mut conn, "run-1", "default", &[10]).unwrap();
        resolve(&mut conn, first, &[(1, Decision::Kept)]).unwrap();
        let second = record_sent(&mut conn, "run-2", "default", &[20, 21]).unwrap();
        let rec = most_recent_unresolved(&conn, "default").unwrap().unwrap();
        assert_eq!(rec.id, second);
        assert_eq!(rec.run_id, "run-2");
    }

    #[test]
    fn most_recent_unresolved_filters_by_agent() {
        let mut conn = open_migrated();
        record_sent(&mut conn, "run-1", "agent-a", &[10]).unwrap();
        let rec = most_recent_unresolved(&conn, "agent-b").unwrap();
        assert!(rec.is_none());
    }

    #[test]
    fn resolve_writes_decisions_and_marks_resolved() {
        let mut conn = open_migrated();
        let id = record_sent(&mut conn, "run-1", "default", &[10, 11, 12]).unwrap();
        resolve(
            &mut conn,
            id,
            &[
                (1, Decision::Kept),
                (2, Decision::Skipped),
                (3, Decision::Kept),
            ],
        )
        .unwrap();
        // Now the digest is resolved → most_recent_unresolved is None.
        assert!(most_recent_unresolved(&conn, "default").unwrap().is_none());
        // Verify the per-item decisions were stored.
        let mut stmt = conn
            .prepare("SELECT idx, decision FROM digest_items WHERE digest_id = ?1 ORDER BY idx")
            .unwrap();
        let rows: Vec<(i64, Option<String>)> = stmt
            .query_map(params![id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows[0], (1, Some("kept".to_string())));
        assert_eq!(rows[1], (2, Some("skipped".to_string())));
        assert_eq!(rows[2], (3, Some("kept".to_string())));
    }
}
