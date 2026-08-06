//! Cross-channel memory entries (#64).
//!
//! Continuity between channels is carried by labelled entries rather
//! than by replaying other channels' session logs. Replay was the
//! original sketch and is deliberately not what this does: those logs
//! were written without origin labels, so replaying them would import
//! unlabelled history, and the provenance property below would be
//! false from the first read.
//!
//! # Provenance
//!
//! Every entry carries its origin labels, stamped at insert:
//!
//! * `channel` — routing channel the entry originated on
//! * `adapter_id` — adapter identity that delivered the turn
//! * `sender_id` — platform-scoped principal
//! * `agent_id` — the writing agent
//! * `origin_session_id` — the session the entry was written under
//!
//! [`MemoryStore::write`] refuses an entry with any label empty, and
//! there is no other insert path. Nothing here backfills, and nothing
//! constructs an entry from data that predates the labels, so an
//! unlabelled entry cannot exist to be read.
//!
//! `origin_session_id` is carried because the other labels reconstruct
//! `{agent_id}/{channel}/…` but not the conversation segment. Without
//! it an auditor can narrow an entry to "some conversation on this
//! channel with this agent" and no further; with it the entry pins to
//! the hash chain that recorded its creation.
//!
//! # Scope
//!
//! Reads are scoped to one agent. Cross-channel here means "another
//! channel of the same agent", never another agent and never another
//! person: `(adapter_id, sender_id)` is a platform-scoped principal,
//! not a human. A Slack uid and a Signal number are different values
//! for the same person, and there is no identity linking to join them.

use rusqlite::{Connection, params};
use std::path::Path;

use crate::error::GatewayError;

/// One labelled memory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntry {
    pub id: String,
    pub agent_id: String,
    pub channel: String,
    pub adapter_id: String,
    pub sender_id: String,
    pub origin_session_id: String,
    pub content: String,
    pub created_at: String,
}

/// The origin labels an entry must carry. Separate from
/// [`MemoryEntry`] so a caller cannot construct a write without them:
/// there is no `Default`, and every field is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginLabels {
    pub agent_id: String,
    pub channel: String,
    pub adapter_id: String,
    pub sender_id: String,
    pub origin_session_id: String,
}

impl OriginLabels {
    /// Which label is missing, if any. Empty is treated as missing:
    /// a blank adapter id is not provenance.
    fn missing(&self) -> Option<&'static str> {
        if self.agent_id.trim().is_empty() {
            return Some("agent_id");
        }
        if self.channel.trim().is_empty() {
            return Some("channel");
        }
        if self.adapter_id.trim().is_empty() {
            return Some("adapter_id");
        }
        if self.sender_id.trim().is_empty() {
            return Some("sender_id");
        }
        if self.origin_session_id.trim().is_empty() {
            return Some("origin_session_id");
        }
        None
    }
}

/// Persistent store for labelled memory entries.
pub struct MemoryStore {
    conn: Connection,
}

impl MemoryStore {
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        // NOT NULL on every label so a row without provenance cannot
        // exist even if a future insert path bypasses `write`.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS memory_entries (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 channel TEXT NOT NULL,
                 adapter_id TEXT NOT NULL,
                 sender_id TEXT NOT NULL,
                 origin_session_id TEXT NOT NULL,
                 content TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS memory_by_agent_channel
                 ON memory_entries (agent_id, channel, created_at);",
        )?;
        Ok(Self { conn })
    }

    /// Write one entry. Refuses if any origin label is empty; there is
    /// no path that stores an entry without complete provenance.
    ///
    /// Returns the entry id.
    pub fn write(
        &self,
        labels: &OriginLabels,
        content: &str,
        created_at: &str,
    ) -> Result<String, GatewayError> {
        if let Some(missing) = labels.missing() {
            return Err(GatewayError::Config(format!(
                "refusing to write a memory entry without an origin label: {missing} is empty. \
                 Every entry carries complete provenance by construction"
            )));
        }
        if content.trim().is_empty() {
            return Err(GatewayError::Config(
                "refusing to write an empty memory entry".into(),
            ));
        }
        let id = format!("mem-{}", uuid::Uuid::new_v4());
        self.conn.execute(
            "INSERT INTO memory_entries
             (id, agent_id, channel, adapter_id, sender_id, origin_session_id, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                labels.agent_id,
                labels.channel,
                labels.adapter_id,
                labels.sender_id,
                labels.origin_session_id,
                content,
                created_at,
            ],
        )?;
        Ok(id)
    }

    /// Read an agent's entries from one channel, newest first.
    ///
    /// Takes the channel explicitly rather than inferring it, so the
    /// same-channel and cross-channel callers go through one query and
    /// the caller decides which crossing it is making.
    pub fn read_channel(
        &self,
        agent_id: &str,
        channel: &str,
        limit: usize,
    ) -> Result<Vec<MemoryEntry>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, channel, adapter_id, sender_id, origin_session_id,
                    content, created_at
             FROM memory_entries
             WHERE agent_id = ?1 AND channel = ?2
             ORDER BY created_at DESC, id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![agent_id, channel, limit as i64], |row| {
            Ok(MemoryEntry {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                channel: row.get(2)?,
                adapter_id: row.get(3)?,
                sender_id: row.get(4)?,
                origin_session_id: row.get(5)?,
                content: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Channels this agent has entries on, excluding `current`. What
    /// a cross-channel read can name.
    pub fn other_channels(
        &self,
        agent_id: &str,
        current: &str,
    ) -> Result<Vec<String>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT channel FROM memory_entries
             WHERE agent_id = ?1 AND channel != ?2 ORDER BY channel",
        )?;
        let rows = stmt.query_map(params![agent_id, current], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn labels(agent: &str, channel: &str) -> OriginLabels {
        OriginLabels {
            agent_id: agent.into(),
            channel: channel.into(),
            adapter_id: channel.into(),
            sender_id: "U123".into(),
            origin_session_id: format!("{agent}/{channel}/conv-1"),
        }
    }

    fn store() -> (MemoryStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let s = MemoryStore::open(&tmp.path().join("memory.db")).unwrap();
        (s, tmp)
    }

    #[test]
    fn write_then_read_round_trips_every_label() {
        let (s, _t) = store();
        let l = labels("work", "slack");
        s.write(&l, "the thing we discussed", "2026-08-06T00:00:00Z")
            .unwrap();

        let got = s.read_channel("work", "slack", 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].agent_id, "work");
        assert_eq!(got[0].channel, "slack");
        assert_eq!(got[0].adapter_id, "slack");
        assert_eq!(got[0].sender_id, "U123");
        assert_eq!(got[0].origin_session_id, "work/slack/conv-1");
        assert_eq!(got[0].content, "the thing we discussed");
    }

    #[test]
    fn every_missing_label_is_refused() {
        let (s, _t) = store();
        for field in [
            "agent_id",
            "channel",
            "adapter_id",
            "sender_id",
            "origin_session_id",
        ] {
            let mut l = labels("work", "slack");
            match field {
                "agent_id" => l.agent_id = String::new(),
                "channel" => l.channel = String::new(),
                "adapter_id" => l.adapter_id = String::new(),
                "sender_id" => l.sender_id = String::new(),
                _ => l.origin_session_id = String::new(),
            }
            let err = s
                .write(&l, "x", "2026-08-06T00:00:00Z")
                .expect_err("missing {field} must be refused");
            assert!(
                err.to_string().contains(field),
                "refusal should name {field}, got: {err}"
            );
        }
        assert!(s.read_channel("work", "slack", 10).unwrap().is_empty());
    }

    #[test]
    fn whitespace_only_label_counts_as_missing() {
        // A blank adapter id is not provenance.
        let (s, _t) = store();
        let mut l = labels("work", "slack");
        l.adapter_id = "   ".into();
        assert!(s.write(&l, "x", "2026-08-06T00:00:00Z").is_err());
    }

    #[test]
    fn reads_are_scoped_to_one_agent_and_one_channel() {
        let (s, _t) = store();
        s.write(
            &labels("work", "slack"),
            "slack one",
            "2026-08-06T00:00:01Z",
        )
        .unwrap();
        s.write(
            &labels("work", "signal"),
            "signal one",
            "2026-08-06T00:00:02Z",
        )
        .unwrap();
        s.write(
            &labels("other", "slack"),
            "other agent",
            "2026-08-06T00:00:03Z",
        )
        .unwrap();

        let slack = s.read_channel("work", "slack", 10).unwrap();
        assert_eq!(slack.len(), 1);
        assert_eq!(slack[0].content, "slack one");

        let signal = s.read_channel("work", "signal", 10).unwrap();
        assert_eq!(signal.len(), 1);
        assert_eq!(signal[0].content, "signal one");
    }

    #[test]
    fn other_channels_excludes_the_current_one() {
        let (s, _t) = store();
        s.write(&labels("work", "slack"), "a", "2026-08-06T00:00:01Z")
            .unwrap();
        s.write(&labels("work", "signal"), "b", "2026-08-06T00:00:02Z")
            .unwrap();
        assert_eq!(
            s.other_channels("work", "slack").unwrap(),
            vec!["signal".to_string()]
        );
    }

    #[test]
    fn empty_content_is_refused() {
        let (s, _t) = store();
        assert!(
            s.write(&labels("work", "slack"), "  ", "2026-08-06T00:00:00Z")
                .is_err()
        );
    }
}
