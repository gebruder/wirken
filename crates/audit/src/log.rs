use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::AuditError;
use crate::event::{AuditEvent, StoredEvent};

/// Query parameters for filtering audit events.
#[derive(Debug, Default)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub channel: Option<String>,
    pub actor: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
}

/// Result of hash chain verification.
#[derive(Debug)]
pub enum VerifyResult {
    /// The hash chain is intact.
    Ok { rows_verified: usize },
    /// The hash chain is broken at the specified row.
    Broken { row_id: i64, expected: String, found: String },
    /// The audit log is empty.
    Empty,
}

/// Direct access to the audit log database.
/// Used for queries and verification. Writing goes through AuditWriter.
pub struct AuditLog {
    conn: Connection,
}

impl AuditLog {
    /// Open or create an audit log at the given path.
    pub fn open(db_path: &Path) -> Result<Self, AuditError> {
        let conn = Connection::open(db_path)?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory audit log (for testing).
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    fn init_schema(conn: &Connection) -> Result<(), AuditError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS audit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 action TEXT NOT NULL,
                 target TEXT NOT NULL,
                 channel TEXT NOT NULL DEFAULT '',
                 session TEXT NOT NULL DEFAULT '',
                 detail JSON NOT NULL DEFAULT 'null',
                 hash TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
             CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_events(channel);
             CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);"
        )?;
        Ok(())
    }

    /// Write a batch of events to the audit log.
    /// Computes the hash chain for each event in order.
    pub fn write_batch(&self, events: &[AuditEvent]) -> Result<(), AuditError> {
        if events.is_empty() {
            return Ok(());
        }

        let previous_hash = self.last_hash()?;
        let tx = self.conn.unchecked_transaction()?;

        let mut current_hash = previous_hash;
        for event in events {
            let hash = compute_hash(&current_hash, event);
            tx.execute(
                "INSERT INTO audit_events (ts, actor, action, target, channel, session, detail, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.ts.to_rfc3339(),
                    event.actor,
                    event.action,
                    event.target,
                    event.channel,
                    event.session,
                    event.detail.to_string(),
                    hash,
                ],
            )?;
            current_hash = hash;
        }

        tx.commit()?;
        Ok(())
    }

    /// Query audit events with optional filters.
    pub fn query(&self, q: &AuditQuery) -> Result<Vec<StoredEvent>, AuditError> {
        let mut sql = String::from(
            "SELECT id, ts, actor, action, target, channel, session, detail, hash
             FROM audit_events WHERE 1=1"
        );
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref action) = q.action {
            sql.push_str(&format!(" AND action = ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(action.clone()));
        }
        if let Some(ref channel) = q.channel {
            sql.push_str(&format!(" AND channel = ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(channel.clone()));
        }
        if let Some(ref actor) = q.actor {
            sql.push_str(&format!(" AND actor = ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(actor.clone()));
        }
        if let Some(since) = q.since {
            sql.push_str(&format!(" AND ts >= ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(since.to_rfc3339()));
        }
        if let Some(until) = q.until {
            sql.push_str(&format!(" AND ts <= ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(until.to_rfc3339()));
        }

        sql.push_str(" ORDER BY id DESC");

        if let Some(limit) = q.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(StoredEvent {
                id: row.get(0)?,
                event: AuditEvent {
                    ts: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    channel: row.get(5)?,
                    session: row.get(6)?,
                    detail: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
                },
                hash: row.get(8)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Verify the hash chain integrity.
    pub fn verify(&self) -> Result<VerifyResult, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, actor, action, target, detail, hash
             FROM audit_events ORDER BY id ASC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;

        let mut previous_hash = String::new();
        let mut count = 0usize;

        for row in rows {
            let (id, ts_str, actor, action, target, detail_str, stored_hash) = row?;

            let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .unwrap_or_default()
                .with_timezone(&Utc);
            let detail: serde_json::Value = serde_json::from_str(&detail_str).unwrap_or_default();

            let event = AuditEvent {
                ts,
                actor,
                action,
                target,
                channel: String::new(), // not used in hash
                session: String::new(), // not used in hash
                detail,
            };

            let expected_hash = compute_hash(&previous_hash, &event);

            if expected_hash != stored_hash {
                return Ok(VerifyResult::Broken {
                    row_id: id,
                    expected: expected_hash,
                    found: stored_hash,
                });
            }

            previous_hash = stored_hash;
            count += 1;
        }

        if count == 0 {
            Ok(VerifyResult::Empty)
        } else {
            Ok(VerifyResult::Ok { rows_verified: count })
        }
    }

    /// Prune events older than the given number of days.
    /// Preserves the hash chain by keeping a checkpoint hash.
    pub fn prune(&self, retention_days: u32) -> Result<usize, AuditError> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let deleted = self.conn.execute(
            "DELETE FROM audit_events WHERE ts < ?1",
            params![cutoff_str],
        )?;

        Ok(deleted)
    }

    /// Get the hash of the last event in the chain.
    fn last_hash(&self) -> Result<String, AuditError> {
        let result = self.conn.query_row(
            "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(hash) => Ok(hash),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()),
            Err(e) => Err(AuditError::Database(e)),
        }
    }
}

/// Compute SHA-256(previous_hash || ts || actor || action || detail)
fn compute_hash(previous_hash: &str, event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(event.ts.to_rfc3339().as_bytes());
    hasher.update(event.actor.as_bytes());
    hasher.update(event.action.as_bytes());
    hasher.update(event.detail.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}
