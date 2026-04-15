use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::GatewayError;

/// A session between a user and the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub channel: String,
    pub conversation_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub message_count: i64,
    pub expired: bool,
}

/// Session store backed by SQLite.
pub struct SessionStore {
    conn: Connection,
    expiry_secs: u64,
}

impl SessionStore {
    /// Open or create the session store.
    pub fn open(db_path: &Path, expiry_secs: u64) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS sessions (
                 id TEXT PRIMARY KEY,
                 channel TEXT NOT NULL,
                 conversation_id TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 last_activity TEXT NOT NULL,
                 message_count INTEGER NOT NULL DEFAULT 0,
                 expired INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_sessions_channel
                 ON sessions(channel);
             CREATE INDEX IF NOT EXISTS idx_sessions_conversation
                 ON sessions(channel, conversation_id);",
        )?;

        Ok(Self { conn, expiry_secs })
    }

    /// Get or create a session for a channel + conversation.
    /// If a non-expired session exists, returns it (updating last_activity).
    /// If no session exists or the existing one expired, creates a new one.
    pub fn get_or_create(
        &self,
        channel: &str,
        conversation_id: &str,
    ) -> Result<Session, GatewayError> {
        // Try to find an existing active session
        let existing = self.conn.query_row(
            "SELECT id, created_at, last_activity, message_count, expired
             FROM sessions
             WHERE channel = ?1 AND conversation_id = ?2 AND expired = 0
             ORDER BY created_at DESC LIMIT 1",
            params![channel, conversation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        );

        match existing {
            Ok((id, created_at_str, last_activity_str, message_count, _expired)) => {
                let last_activity = parse_dt(&last_activity_str);
                let now = Utc::now();

                // Check if session has expired by inactivity
                if now.signed_duration_since(last_activity).num_seconds() as u64 >= self.expiry_secs
                {
                    // Mark as expired and create new
                    self.conn
                        .execute("UPDATE sessions SET expired = 1 WHERE id = ?1", params![id])?;
                    return self.create_session(channel, conversation_id);
                }

                // Update last_activity
                self.conn.execute(
                    "UPDATE sessions SET last_activity = ?1 WHERE id = ?2",
                    params![now.to_rfc3339(), id],
                )?;

                Ok(Session {
                    id,
                    channel: channel.to_string(),
                    conversation_id: conversation_id.to_string(),
                    created_at: parse_dt(&created_at_str),
                    last_activity: now,
                    message_count,
                    expired: false,
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.create_session(channel, conversation_id)
            }
            Err(e) => Err(GatewayError::Database(e)),
        }
    }

    fn create_session(
        &self,
        channel: &str,
        conversation_id: &str,
    ) -> Result<Session, GatewayError> {
        let id = generate_session_id();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        self.conn.execute(
            "INSERT INTO sessions (id, channel, conversation_id, created_at, last_activity, message_count, expired)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)",
            params![id, channel, conversation_id, now_str, now_str],
        )?;

        Ok(Session {
            id,
            channel: channel.to_string(),
            conversation_id: conversation_id.to_string(),
            created_at: now,
            last_activity: now,
            message_count: 0,
            expired: false,
        })
    }

    /// Increment the message count for a session.
    pub fn record_message(&self, session_id: &str) -> Result<(), GatewayError> {
        let now = Utc::now().to_rfc3339();
        let changes = self.conn.execute(
            "UPDATE sessions SET message_count = message_count + 1, last_activity = ?1
             WHERE id = ?2 AND expired = 0",
            params![now, session_id],
        )?;

        if changes == 0 {
            return Err(GatewayError::SessionNotFound(session_id.to_string()));
        }
        Ok(())
    }

    /// Get a session by ID.
    pub fn get(&self, session_id: &str) -> Result<Session, GatewayError> {
        self.conn.query_row(
            "SELECT id, channel, conversation_id, created_at, last_activity, message_count, expired
             FROM sessions WHERE id = ?1",
            params![session_id],
            |row| {
                Ok(Session {
                    id: row.get(0)?,
                    channel: row.get(1)?,
                    conversation_id: row.get(2)?,
                    created_at: parse_dt(&row.get::<_, String>(3)?),
                    last_activity: parse_dt(&row.get::<_, String>(4)?),
                    message_count: row.get(5)?,
                    expired: row.get(6)?,
                })
            },
        ).map_err(|_| GatewayError::SessionNotFound(session_id.to_string()))
    }

    /// Close (expire) a session.
    pub fn close(&self, session_id: &str) -> Result<(), GatewayError> {
        let changes = self.conn.execute(
            "UPDATE sessions SET expired = 1 WHERE id = ?1",
            params![session_id],
        )?;

        if changes == 0 {
            return Err(GatewayError::SessionNotFound(session_id.to_string()));
        }
        Ok(())
    }

    /// List active sessions, optionally filtered by channel.
    pub fn list_active(&self, channel: Option<&str>) -> Result<Vec<Session>, GatewayError> {
        let (sql, param): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match channel {
            Some(ch) => (
                "SELECT id, channel, conversation_id, created_at, last_activity, message_count, expired
                 FROM sessions WHERE expired = 0 AND channel = ?1 ORDER BY last_activity DESC".to_string(),
                vec![Box::new(ch.to_string())],
            ),
            None => (
                "SELECT id, channel, conversation_id, created_at, last_activity, message_count, expired
                 FROM sessions WHERE expired = 0 ORDER BY last_activity DESC".to_string(),
                vec![],
            ),
        };

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(Session {
                id: row.get(0)?,
                channel: row.get(1)?,
                conversation_id: row.get(2)?,
                created_at: parse_dt(&row.get::<_, String>(3)?),
                last_activity: parse_dt(&row.get::<_, String>(4)?),
                message_count: row.get(5)?,
                expired: row.get(6)?,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Expire all sessions that have been inactive longer than the expiry window.
    pub fn expire_inactive(&self) -> Result<usize, GatewayError> {
        let cutoff = Utc::now() - Duration::seconds(self.expiry_secs as i64);
        let changes = self.conn.execute(
            "UPDATE sessions SET expired = 1
             WHERE expired = 0 AND last_activity <= ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(changes)
    }
}

fn generate_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
