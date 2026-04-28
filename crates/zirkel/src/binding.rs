//! Persisted target for the daily-digest push.
//!
//! `wirken zirkel bind` writes one row; `wirken zirkel run`'s push
//! step reads it. The keep/skip interceptor is registered on the
//! agent named by [`Binding::agent_id`] so the operator's reply flows
//! through it.
//!
//! ## Single-binding contract today
//!
//! The schema permits multiple rows (one per agent), but the C-Signal
//! slice runs with a single bound conversation per zirkel install.
//! The CLI's idempotency / `--force` semantics enforce that on the
//! write side — see piece 5. Read side helpers expose both `load`
//! (by agent_id) and [`load_first`] (the single-binding shortcut).

use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub agent_id: String,
    pub channel: String,
    pub conversation_id: String,
}

/// Insert or replace a binding for `agent_id`. Replacement is
/// blanket — call from a CLI that has already done its idempotency
/// check.
pub fn record(conn: &Connection, binding: &Binding) -> Result<(), BindingError> {
    conn.execute(
        "INSERT OR REPLACE INTO bindings (agent_id, channel, conversation_id, bound_at) \
         VALUES (?1, ?2, ?3, datetime('now'))",
        params![
            &binding.agent_id,
            &binding.channel,
            &binding.conversation_id
        ],
    )?;
    Ok(())
}

/// Read the binding for a specific agent. `None` if no row exists.
pub fn load(conn: &Connection, agent_id: &str) -> Result<Option<Binding>, BindingError> {
    let row = conn
        .query_row(
            "SELECT agent_id, channel, conversation_id FROM bindings WHERE agent_id = ?1",
            params![agent_id],
            |r| {
                Ok(Binding {
                    agent_id: r.get(0)?,
                    channel: r.get(1)?,
                    conversation_id: r.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Read the only binding row, ordered deterministically by `agent_id`.
/// `None` if no row exists. Convenience for the run path which
/// today expects exactly one binding.
pub fn load_first(conn: &Connection) -> Result<Option<Binding>, BindingError> {
    let row = conn
        .query_row(
            "SELECT agent_id, channel, conversation_id FROM bindings \
             ORDER BY agent_id ASC LIMIT 1",
            [],
            |r| {
                Ok(Binding {
                    agent_id: r.get(0)?,
                    channel: r.get(1)?,
                    conversation_id: r.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// List every binding row, ordered by `agent_id`.
pub fn list_all(conn: &Connection) -> Result<Vec<Binding>, BindingError> {
    let mut stmt = conn
        .prepare("SELECT agent_id, channel, conversation_id FROM bindings ORDER BY agent_id ASC")?;
    let rows: Vec<Binding> = stmt
        .query_map([], |r| {
            Ok(Binding {
                agent_id: r.get(0)?,
                channel: r.get(1)?,
                conversation_id: r.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Remove a binding. Idempotent.
pub fn remove(conn: &Connection, agent_id: &str) -> Result<(), BindingError> {
    conn.execute(
        "DELETE FROM bindings WHERE agent_id = ?1",
        params![agent_id],
    )?;
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

    fn b(agent: &str, ch: &str, cid: &str) -> Binding {
        Binding {
            agent_id: agent.into(),
            channel: ch.into(),
            conversation_id: cid.into(),
        }
    }

    #[test]
    fn record_and_load_roundtrip() {
        let conn = open_migrated();
        record(&conn, &b("default", "signal", "+15551234567")).unwrap();
        let got = load(&conn, "default").unwrap().unwrap();
        assert_eq!(got, b("default", "signal", "+15551234567"));
    }

    #[test]
    fn record_replaces_on_duplicate_agent() {
        let conn = open_migrated();
        record(&conn, &b("default", "signal", "+15551111111")).unwrap();
        record(&conn, &b("default", "telegram", "12345")).unwrap();
        let got = load(&conn, "default").unwrap().unwrap();
        assert_eq!(got, b("default", "telegram", "12345"));
    }

    #[test]
    fn load_first_returns_none_when_empty() {
        let conn = open_migrated();
        assert!(load_first(&conn).unwrap().is_none());
    }

    #[test]
    fn load_first_returns_lowest_agent_id() {
        let conn = open_migrated();
        record(&conn, &b("zeta", "signal", "+1")).unwrap();
        record(&conn, &b("alpha", "slack", "C0")).unwrap();
        let got = load_first(&conn).unwrap().unwrap();
        assert_eq!(got.agent_id, "alpha");
    }

    #[test]
    fn remove_deletes_binding() {
        let conn = open_migrated();
        record(&conn, &b("default", "signal", "+15551234567")).unwrap();
        remove(&conn, "default").unwrap();
        assert!(load(&conn, "default").unwrap().is_none());
    }

    #[test]
    fn list_all_orders_by_agent_id() {
        let conn = open_migrated();
        record(&conn, &b("zeta", "signal", "+1")).unwrap();
        record(&conn, &b("alpha", "slack", "C0")).unwrap();
        record(&conn, &b("mid", "telegram", "999")).unwrap();
        let rows = list_all(&conn).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].agent_id, "alpha");
        assert_eq!(rows[1].agent_id, "mid");
        assert_eq!(rows[2].agent_id, "zeta");
    }
}
