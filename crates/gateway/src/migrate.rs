//! Append-only SQLite migration runner for gateway-owned stores.
//!
//! The other stores in this crate create their schema with
//! `CREATE TABLE IF NOT EXISTS` on every open. That is idempotent for
//! the shape it first created and silent about anything after: adding
//! a column to the DDL leaves every database that already exists
//! without it, because the `IF NOT EXISTS` guard skips the whole
//! statement. A store expected to gain columns needs a runner instead.
//!
//! # Addressing
//!
//! A migration is addressed by its index in the slice handed to
//! [`apply`], and the applied indexes are recorded in a `_migrations`
//! table. Two consequences the caller has to hold to:
//!
//! * **Append only.** A new migration goes on the end.
//! * **Never reorder or replace.** A recorded index would then point
//!   at different SQL than the one that ran, and no error would say so.
//!
//! # Return value
//!
//! [`apply`] returns how many migrations it ran on this call, not how
//! many exist. A caller can tell a fresh database from an up-to-date
//! one by that number, which is the observation the import command
//! reports.
//!
//! # Transaction
//!
//! Every pending migration and its bookkeeping row run inside one
//! transaction, so a call is all or nothing. A failure part way rolls
//! back the whole call, including migrations that had already
//! succeeded within it, and the database is left where the previous
//! successful call left it. It is never left half way through a
//! migration, and never with a recorded index whose SQL did not run.

use rusqlite::Connection;

use crate::error::GatewayError;

/// Apply every migration not yet recorded, in slice order.
///
/// Returns the number applied on this call. Repeat calls with an
/// unchanged slice return zero and touch nothing.
pub fn apply(conn: &mut Connection, migrations: &[&str]) -> Result<usize, GatewayError> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
             idx INTEGER PRIMARY KEY,
             applied_at TEXT NOT NULL DEFAULT (datetime('now'))
         )",
    )?;

    let applied: std::collections::BTreeSet<i64> = {
        let mut stmt = tx.prepare("SELECT idx FROM _migrations")?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        let mut set = std::collections::BTreeSet::new();
        for row in rows {
            set.insert(row?);
        }
        set
    };

    let mut ran = 0usize;
    for (idx, sql) in migrations.iter().enumerate() {
        let idx = idx as i64;
        if applied.contains(&idx) {
            continue;
        }
        tx.execute_batch(sql)?;
        tx.execute("INSERT INTO _migrations (idx) VALUES (?1)", [idx])?;
        ran += 1;
    }

    tx.commit()?;
    Ok(ran)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn first_call_applies_every_migration_and_second_applies_none() {
        let mut c = conn();
        let m = &["CREATE TABLE a (x INTEGER);", "CREATE TABLE b (y INTEGER);"];
        assert_eq!(apply(&mut c, m).unwrap(), m.len());
        assert_eq!(apply(&mut c, m).unwrap(), 0);
    }

    #[test]
    fn appending_a_migration_runs_only_the_new_one() {
        let mut c = conn();
        assert_eq!(apply(&mut c, &["CREATE TABLE a (x INTEGER);"]).unwrap(), 1);
        let grown = &[
            "CREATE TABLE a (x INTEGER);",
            "ALTER TABLE a ADD COLUMN z TEXT;",
        ];
        assert_eq!(apply(&mut c, grown).unwrap(), 1);
        // The appended migration ran: the column it adds exists.
        let present: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('a') WHERE name = 'z'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(present, 1);
    }

    #[test]
    fn an_empty_slice_is_not_an_error() {
        let mut c = conn();
        assert_eq!(apply(&mut c, &[]).unwrap(), 0);
    }

    #[test]
    fn a_failure_rolls_back_the_whole_call() {
        // Migrations that succeeded earlier in the same call go back
        // with the one that failed: the call is the unit, not the
        // migration.
        let mut c = conn();
        let m = &["CREATE TABLE a (x INTEGER);", "THIS IS NOT SQL;"];
        assert!(apply(&mut c, m).is_err());
        let tables: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

    #[test]
    fn a_failing_migration_leaves_the_earlier_ones_applied_and_itself_unrecorded() {
        let mut c = conn();
        assert_eq!(apply(&mut c, &["CREATE TABLE a (x INTEGER);"]).unwrap(), 1);
        let broken = &["CREATE TABLE a (x INTEGER);", "THIS IS NOT SQL;"];
        assert!(apply(&mut c, broken).is_err());
        // The good migration stays recorded, so a corrected slice
        // re-runs only the fixed entry rather than everything.
        let recorded: i64 = c
            .query_row("SELECT COUNT(*) FROM _migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(recorded, 1);
        let fixed = &["CREATE TABLE a (x INTEGER);", "CREATE TABLE b (y INTEGER);"];
        assert_eq!(apply(&mut c, fixed).unwrap(), 1);
    }
}
