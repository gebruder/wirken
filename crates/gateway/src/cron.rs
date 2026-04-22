use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;

use crate::error::GatewayError;

/// A scheduled cron job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub id: String,
    pub agent_id: String,
    /// Cron expression (5-field standard: "min hour dom month dow")
    pub schedule: String,
    /// Message to send to the agent when the job fires.
    pub message: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: DateTime<Utc>,
    pub run_count: i64,
    pub paused: bool,
}

/// SQLite-backed cron job store.
pub struct CronStore {
    conn: Connection,
}

impl CronStore {
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS cron_jobs (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 schedule TEXT NOT NULL,
                 message TEXT NOT NULL,
                 description TEXT NOT NULL DEFAULT '',
                 created_at TEXT NOT NULL,
                 created_by TEXT NOT NULL,
                 last_run_at TEXT,
                 next_run_at TEXT NOT NULL,
                 run_count INTEGER NOT NULL DEFAULT 0,
                 paused INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_cron_next_run
                 ON cron_jobs(next_run_at) WHERE paused = 0;",
        )?;
        Ok(Self { conn })
    }

    /// Create a new cron job. Validates the cron expression and computes next_run_at.
    pub fn create(
        &self,
        agent_id: &str,
        schedule: &str,
        message: &str,
        description: &str,
        created_by: &str,
    ) -> Result<CronJob, GatewayError> {
        // Validate cron expression
        let cron_schedule = cron::Schedule::from_str(schedule)
            .map_err(|e| GatewayError::Config(format!("invalid cron expression: {e}")))?;

        let now = Utc::now();
        let next = cron_schedule
            .upcoming(Utc)
            .next()
            .ok_or_else(|| GatewayError::Config("cron expression has no upcoming times".into()))?;

        let id = format!("cron_{}", uuid_short());

        let job = CronJob {
            id: id.clone(),
            agent_id: agent_id.to_string(),
            schedule: schedule.to_string(),
            message: message.to_string(),
            description: description.to_string(),
            created_at: now,
            created_by: created_by.to_string(),
            last_run_at: None,
            next_run_at: next,
            run_count: 0,
            paused: false,
        };

        self.conn.execute(
            "INSERT INTO cron_jobs
             (id, agent_id, schedule, message, description, created_at, created_by, next_run_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                job.id,
                job.agent_id,
                job.schedule,
                job.message,
                job.description,
                job.created_at.to_rfc3339(),
                job.created_by,
                job.next_run_at.to_rfc3339(),
            ],
        )?;

        Ok(job)
    }

    /// List all cron jobs, optionally filtered by agent.
    pub fn list(&self, agent_id: Option<&str>) -> Result<Vec<CronJob>, GatewayError> {
        let mut jobs = Vec::new();

        if let Some(aid) = agent_id {
            let mut stmt = self.conn.prepare(
                "SELECT id, agent_id, schedule, message, description, created_at, created_by,
                        last_run_at, next_run_at, run_count, paused
                 FROM cron_jobs WHERE agent_id = ?1 ORDER BY next_run_at",
            )?;
            let rows = stmt.query_map(params![aid], row_to_job)?;
            for row in rows {
                jobs.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, agent_id, schedule, message, description, created_at, created_by,
                        last_run_at, next_run_at, run_count, paused
                 FROM cron_jobs ORDER BY next_run_at",
            )?;
            let rows = stmt.query_map([], row_to_job)?;
            for row in rows {
                jobs.push(row?);
            }
        }

        Ok(jobs)
    }

    /// Get jobs that are due (next_run_at <= now and not paused).
    pub fn due_jobs(&self) -> Result<Vec<CronJob>, GatewayError> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, schedule, message, description, created_at, created_by,
                    last_run_at, next_run_at, run_count, paused
             FROM cron_jobs WHERE next_run_at <= ?1 AND paused = 0",
        )?;
        let rows = stmt.query_map(params![now], row_to_job)?;
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    /// Mark a job as run and compute the next run time.
    pub fn mark_run(&self, id: &str) -> Result<(), GatewayError> {
        let now = Utc::now();

        // Get the schedule to compute next run
        let schedule_str: String = self
            .conn
            .query_row(
                "SELECT schedule FROM cron_jobs WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| GatewayError::Config(format!("cron job not found: {id}")))?;

        let cron_schedule = cron::Schedule::from_str(&schedule_str)
            .map_err(|e| GatewayError::Config(format!("invalid cron: {e}")))?;

        let next = cron_schedule
            .upcoming(Utc)
            .next()
            .ok_or_else(|| GatewayError::Config("no upcoming times".into()))?;

        self.conn.execute(
            "UPDATE cron_jobs SET last_run_at = ?1, next_run_at = ?2, run_count = run_count + 1
             WHERE id = ?3",
            params![now.to_rfc3339(), next.to_rfc3339(), id],
        )?;

        Ok(())
    }

    /// Delete a cron job.
    pub fn delete(&self, id: &str) -> Result<(), GatewayError> {
        let changes = self
            .conn
            .execute("DELETE FROM cron_jobs WHERE id = ?1", params![id])?;
        if changes == 0 {
            return Err(GatewayError::Config(format!("cron job not found: {id}")));
        }
        Ok(())
    }

    /// Pause a cron job.
    pub fn pause(&self, id: &str) -> Result<(), GatewayError> {
        let changes = self
            .conn
            .execute("UPDATE cron_jobs SET paused = 1 WHERE id = ?1", params![id])?;
        if changes == 0 {
            return Err(GatewayError::Config(format!("cron job not found: {id}")));
        }
        Ok(())
    }

    /// Resume a paused cron job.
    pub fn resume(&self, id: &str) -> Result<(), GatewayError> {
        // Recompute next_run_at from now
        let schedule_str: String = self
            .conn
            .query_row(
                "SELECT schedule FROM cron_jobs WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| GatewayError::Config(format!("cron job not found: {id}")))?;

        let cron_schedule = cron::Schedule::from_str(&schedule_str)
            .map_err(|e| GatewayError::Config(format!("invalid cron: {e}")))?;

        let next = cron_schedule
            .upcoming(Utc)
            .next()
            .ok_or_else(|| GatewayError::Config("no upcoming times".into()))?;

        self.conn.execute(
            "UPDATE cron_jobs SET paused = 0, next_run_at = ?1 WHERE id = ?2",
            params![next.to_rfc3339(), id],
        )?;

        Ok(())
    }
}

fn row_to_job(row: &rusqlite::Row) -> Result<CronJob, rusqlite::Error> {
    let created_at_str: String = row.get(5)?;
    let last_run_str: Option<String> = row.get(7)?;
    let next_run_str: String = row.get(8)?;

    Ok(CronJob {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        schedule: row.get(2)?,
        message: row.get(3)?,
        description: row.get(4)?,
        created_at: DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        created_by: row.get(6)?,
        last_run_at: last_run_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        }),
        next_run_at: DateTime::parse_from_rfc3339(&next_run_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        run_count: row.get(9)?,
        paused: row.get::<_, i32>(10)? != 0,
    })
}

fn uuid_short() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_and_list_cron_job() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        let job = store
            .create(
                "default",
                "0 0 9 * * *",
                "check email",
                "morning check",
                "user",
            )
            .unwrap();

        assert!(job.id.starts_with("cron_"));
        assert_eq!(job.agent_id, "default");
        assert_eq!(job.run_count, 0);
        assert!(!job.paused);

        let jobs = store.list(None).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job.id);
    }

    #[test]
    fn delete_cron_job() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        let job = store
            .create("default", "0 0 9 * * *", "task", "", "user")
            .unwrap();
        store.delete(&job.id).unwrap();

        let jobs = store.list(None).unwrap();
        assert!(jobs.is_empty());
    }

    #[test]
    fn pause_and_resume() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        let job = store
            .create("default", "0 0 9 * * *", "task", "", "user")
            .unwrap();

        store.pause(&job.id).unwrap();
        let jobs = store.due_jobs().unwrap();
        assert!(jobs.is_empty()); // paused jobs not returned

        store.resume(&job.id).unwrap();
        let jobs = store.list(None).unwrap();
        assert!(!jobs[0].paused);
    }

    #[test]
    fn mark_run_increments_count() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        let job = store
            .create("default", "0 * * * * *", "task", "", "user")
            .unwrap();

        store.mark_run(&job.id).unwrap();
        let jobs = store.list(None).unwrap();
        assert_eq!(jobs[0].run_count, 1);
        assert!(jobs[0].last_run_at.is_some());
    }

    #[test]
    fn invalid_cron_expression_rejected() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        let result = store.create("default", "not a cron", "task", "", "user");
        assert!(result.is_err());
    }

    #[test]
    fn filter_by_agent() {
        let tmp = TempDir::new().unwrap();
        let store = CronStore::open(&tmp.path().join("cron.db")).unwrap();

        store
            .create("agent-a", "0 0 9 * * *", "task a", "", "user")
            .unwrap();
        store
            .create("agent-b", "0 0 10 * * *", "task b", "", "user")
            .unwrap();

        let a_jobs = store.list(Some("agent-a")).unwrap();
        assert_eq!(a_jobs.len(), 1);
        assert_eq!(a_jobs[0].agent_id, "agent-a");
    }
}
