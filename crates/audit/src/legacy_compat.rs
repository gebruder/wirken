//! Backward-compatibility layer between the legacy [`AuditLog`] API
//! and the new [`SqliteSessionLog`] storage.
//!
//! Slice 2 of item 1 in `docs/managed-agents-parity.md` makes
//! `session_events` the single source of truth. The legacy
//! `audit_events` table no longer exists as a real table — it
//! becomes a SQL view that COALESCEs JSON fields out of the
//! [`SessionEvent`] payload so existing SIEM consumers see both
//! legacy events and typed events without changing their queries.
//!
//! This module owns:
//!
//! - [`migrate_legacy_audit_events`] — one-shot migration that
//!   copies any existing `audit_events` rows into `session_events`
//!   under a sentinel session id, then drops the table and creates
//!   the view in its place. Idempotent: safe to call on every open.
//! - [`write_legacy`] — converts an [`AuditEvent`] into a
//!   [`SessionEvent::AuditLegacy`] and appends it to the session
//!   log.
//! - [`query_legacy`] — runs the existing [`AuditQuery`] filter
//!   against the new view.
//! - [`verify_legacy`] — walks every session in the log and verifies
//!   each chain independently. Returns the same [`VerifyResult`]
//!   shape so the existing `wirken audit verify` CLI keeps working.
//! - [`prune_legacy`] — applies the legacy retention policy by
//!   deleting old `session_events` rows, preserving each per-session
//!   chain by keeping a checkpoint row.
//!
//! [`AuditLog`]: crate::AuditLog
//! [`SessionEvent`]: crate::SessionEvent

use chrono::Utc;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::event::{AuditEvent, StoredEvent};
use crate::log::{AuditQuery, VerifyResult};
use crate::session_log::{
    SessionEvent, SessionId, SessionLog, SessionVerifyResult, SqliteSessionLog, TrustLevel,
};

/// Sentinel session id for legacy audit events that have no session
/// (empty `session` field on the original [`AuditEvent`] — typically
/// gateway-level events like `gateway.start`, `adapter.connect`).
pub(crate) const SYSTEM_SESSION: &str = "__system__";

/// Sentinel session id used by [`migrate_legacy_audit_events`] for
/// rows copied out of the legacy `audit_events` table.
pub(crate) const PRE_MIGRATION_SESSION: &str = "__pre_migration__";

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// One-shot migration: if `audit_events` exists as a real table,
/// copy every row into `session_events` under
/// [`PRE_MIGRATION_SESSION`], drop the table, and create the view in
/// its place. If `audit_events` is already a view (i.e. migration
/// already ran), or if it doesn't exist at all, just create the view
/// idempotently.
///
/// Always safe to call on every open.
pub(crate) fn migrate_legacy_audit_events(log: &SqliteSessionLog) -> Result<usize, AuditError> {
    log.with_conn(|conn| {
        let kind: Option<String> = conn
            .query_row(
                "SELECT type FROM sqlite_master WHERE name = 'audit_events'",
                [],
                |row| row.get(0),
            )
            .ok();

        match kind.as_deref() {
            Some("view") => {
                // Migration already ran. Nothing to do.
                Ok(0)
            }
            Some("table") => {
                let migrated = copy_legacy_table_into_session_events(conn)?;
                conn.execute("DROP TABLE audit_events", [])?;
                create_legacy_view(conn)?;
                Ok(migrated)
            }
            Some(other) => Err(AuditError::SiemConfig(format!(
                "audit_events exists as unexpected kind: {other}"
            ))),
            None => {
                // Fresh install. Just create the view.
                create_legacy_view(conn)?;
                Ok(0)
            }
        }
    })
}

fn create_legacy_view(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(
        "CREATE VIEW IF NOT EXISTS audit_events AS
         SELECT
             id,
             ts,
             COALESCE(json_extract(payload, '$.actor'), '') AS actor,
             COALESCE(
                 json_extract(payload, '$.action'),
                 json_extract(payload, '$.kind'),
                 ''
             ) AS action,
             COALESCE(json_extract(payload, '$.target'), '') AS target,
             COALESCE(json_extract(payload, '$.channel'), '') AS channel,
             session_id AS session,
             COALESCE(json_extract(payload, '$.detail'), 'null') AS detail,
             hash
         FROM session_events;",
    )?;
    Ok(())
}

fn copy_legacy_table_into_session_events(conn: &Connection) -> Result<usize, AuditError> {
    let mut stmt = conn.prepare(
        "SELECT ts, actor, action, target, channel, session, detail
         FROM audit_events
         ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;

    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;

    // All migrated rows go into a single chain under the
    // pre-migration sentinel so the original ordering is preserved.
    let session_id = PRE_MIGRATION_SESSION;
    let initial_seq: u64 = tx
        .query_row(
            "SELECT MAX(seq) FROM session_events WHERE session_id = ?1",
            params![session_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .ok()
        .flatten()
        .map(|n| (n as u64) + 1)
        .unwrap_or(0);
    let mut prev_hash: String = tx
        .query_row(
            "SELECT hash FROM session_events
             WHERE session_id = ?1
             ORDER BY seq DESC LIMIT 1",
            params![session_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_default();

    for (idx, row) in rows.enumerate() {
        let (ts, actor, action, target, channel, _session, detail_json) = row?;
        let detail: serde_json::Value = serde_json::from_str(&detail_json)?;

        let event = SessionEvent::AuditLegacy {
            actor,
            action,
            target,
            channel,
            detail,
        };

        let payload_bytes = serde_json::to_vec(&event)?;
        let leaf_hash = sha256_hex(&payload_bytes);
        let row_hash = chain_hex(&prev_hash, &leaf_hash);
        let payload_str =
            String::from_utf8(payload_bytes).expect("serde_json output is always valid utf-8");

        let next_seq = initial_seq + idx as u64;
        tx.execute(
            "INSERT INTO session_events
                 (session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash)
             VALUES (?1, ?2, ?3, 'system', ?4, ?5, ?6, ?7)",
            params![
                session_id,
                next_seq as i64,
                ts,
                payload_str,
                leaf_hash,
                prev_hash,
                row_hash,
            ],
        )?;

        prev_hash = row_hash;
        count = idx + 1;
    }

    tx.commit()?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Convert an [`AuditEvent`] into a [`SessionEvent::AuditLegacy`]
/// and append it to the session log under either the event's
/// `session` field or [`SYSTEM_SESSION`] if empty. The original
/// timestamp is preserved.
pub(crate) fn write_legacy(log: &SqliteSessionLog, event: &AuditEvent) -> Result<(), AuditError> {
    let session_id = if event.session.is_empty() {
        SYSTEM_SESSION
    } else {
        event.session.as_str()
    };
    let handle = log.handle_for(SessionId::new(session_id));
    let session_event = SessionEvent::AuditLegacy {
        actor: event.actor.clone(),
        action: event.action.clone(),
        target: event.target.clone(),
        channel: event.channel.clone(),
        detail: event.detail.clone(),
    };
    log.append_with_ts(&handle, TrustLevel::System, session_event, event.ts)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// Run the legacy [`AuditQuery`] against the `audit_events` view.
/// Returns rows in `id DESC` order to match the pre-slice-2
/// behaviour. Per-row `hash` is the chain hash of the underlying
/// `session_events` row, which is per-session — callers that
/// compared global hashes will not get meaningful equality across
/// sessions, but row-level tamper detection still works.
pub(crate) fn query_legacy(
    log: &SqliteSessionLog,
    q: &AuditQuery,
) -> Result<Vec<StoredEvent>, AuditError> {
    log.with_conn(|conn| {
        let mut sql = String::from(
            "SELECT id, ts, actor, action, target, channel, session, detail, hash
             FROM audit_events WHERE 1=1",
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
        if let Some(ref session) = q.session {
            sql.push_str(&format!(" AND session = ?{}", bind_values.len() + 1));
            bind_values.push(Box::new(session.clone()));
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
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let ts_str: String = row.get(1)?;
            let detail_str: String = row.get(7)?;
            Ok(StoredEvent {
                id: row.get(0)?,
                event: AuditEvent {
                    ts: chrono::DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    channel: row.get(5)?,
                    session: row.get(6)?,
                    detail: serde_json::from_str(&detail_str).unwrap_or_default(),
                },
                hash: row.get(8)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Walk every session in `session_events` and run
/// [`SessionLog::verify`] on each. Returns the legacy
/// [`VerifyResult`] shape:
///
/// - `Ok { rows_verified }` — total events across all sessions
/// - `Empty` — no rows in any session
/// - `Broken { session_id, seq, expected_hash, actual_hash,
///   verified_count }` — first session that fails. `verified_count`
///   sums events from sessions that completed verification plus the
///   per-session count up to (but not including) the breaking event.
pub(crate) fn verify_legacy(log: &SqliteSessionLog) -> Result<VerifyResult, AuditError> {
    let session_ids = list_session_ids(log)?;
    if session_ids.is_empty() {
        return Ok(VerifyResult::Empty);
    }

    let mut total = 0usize;
    for sid in &session_ids {
        let handle = log.handle_for(SessionId::new(sid.clone()));
        match log.verify(&handle)? {
            SessionVerifyResult::Ok { rows_verified } => {
                total += rows_verified;
            }
            SessionVerifyResult::Empty => {
                // Session has no rows — distinct sessions table
                // entries with zero events shouldn't exist, but
                // skip rather than fail.
            }
            SessionVerifyResult::Broken {
                seq,
                expected_hash,
                actual_hash,
                verified_count,
            } => {
                return Ok(VerifyResult::Broken {
                    session_id: SessionId::new(sid.clone()),
                    seq,
                    expected_hash,
                    actual_hash,
                    verified_count: total as u64 + verified_count,
                });
            }
        }
    }

    if total == 0 {
        Ok(VerifyResult::Empty)
    } else {
        Ok(VerifyResult::Ok {
            rows_verified: total,
        })
    }
}

fn list_session_ids(log: &SqliteSessionLog) -> Result<Vec<String>, AuditError> {
    log.with_conn(|conn| {
        let mut stmt =
            conn.prepare("SELECT DISTINCT session_id FROM session_events ORDER BY session_id ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

// ---------------------------------------------------------------------------
// Prune
// ---------------------------------------------------------------------------

/// Delete session events older than `retention_days`. Per-session
/// chains are preserved by keeping the most recent event before the
/// cutoff in each session as a checkpoint, so [`verify_legacy`]
/// continues to validate the surviving rows.
pub(crate) fn prune_legacy(
    log: &SqliteSessionLog,
    retention_days: u32,
) -> Result<usize, AuditError> {
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    let cutoff_str = cutoff.to_rfc3339();

    log.with_conn(|conn| {
        let session_ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT DISTINCT session_id FROM session_events")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };

        let mut total_deleted = 0usize;
        for sid in &session_ids {
            // Find the most recent event in this session before the
            // cutoff. We keep it as a checkpoint so the chain stays
            // valid.
            let checkpoint_seq: Option<i64> = conn
                .query_row(
                    "SELECT seq FROM session_events
                     WHERE session_id = ?1 AND ts < ?2
                     ORDER BY seq DESC LIMIT 1",
                    params![sid, cutoff_str],
                    |row| row.get(0),
                )
                .ok();

            if let Some(keep_seq) = checkpoint_seq {
                let deleted = conn.execute(
                    "DELETE FROM session_events
                     WHERE session_id = ?1 AND ts < ?2 AND seq < ?3",
                    params![sid, cutoff_str, keep_seq],
                )?;
                total_deleted += deleted;
            }
            // If no event exists before the cutoff, the entire
            // session is recent — nothing to prune.
        }

        Ok(total_deleted)
    })
}

// ---------------------------------------------------------------------------
// Hash helpers (duplicated from session_log to avoid exposing them)
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut s = String::with_capacity(64);
    use std::fmt::Write;
    for b in hasher.finalize().iter() {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn chain_hex(prev_hash: &str, leaf_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(leaf_hash.as_bytes());
    let mut s = String::with_capacity(64);
    use std::fmt::Write;
    for b in hasher.finalize().iter() {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}
