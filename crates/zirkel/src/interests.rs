//! User-owned interests file.
//!
//! Path: `~/.wirken/zirkel/interests.toml`. The lawyer hand-edits
//! this; the orchestrator reads it on every run, snapshots a copy
//! into `interests_snapshots` for reproducibility, and uses it to
//! screen + score fetched items.
//!
//! ## Schema (deliberately small)
//!
//! ```toml
//! keywords   = ["BIPA", "Section 5 unfairness", "data broker"]
//! exclusions = ["cookie banner", "GDPR fines under €1M"]
//! ```
//!
//! Two axes — keywords and exclusions — both case-insensitive
//! substring matches against the candidate's title + abstract.
//! No `concepts` axis, no embeddings, no learned weights. The user's
//! actual interface is the file. If the keyword version produces
//! noise complaints, an embedded-concept axis lands later (Scope D).

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Parsed interests file in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interests {
    pub keywords: Vec<String>,
    pub exclusions: Vec<String>,
    /// SHA-256 hex of the file contents at parse time. Recorded in
    /// `interests_snapshots.file_hash`; an `InterestsEdited` audit
    /// event fires when the hash differs from the previous run.
    pub file_hash: String,
    /// The verbatim bytes parsed. Snapshotted into the run row.
    pub raw_contents: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct InterestsRaw {
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    exclusions: Vec<String>,
}

#[derive(Debug, Error)]
pub enum InterestsError {
    #[error("read interests file at {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse interests file at {path}: {message}")]
    Parse {
        path: std::path::PathBuf,
        message: String,
    },
}

/// Parse an interests file from disk.
pub fn load(path: &Path) -> Result<Interests, InterestsError> {
    let raw = std::fs::read_to_string(path).map_err(|e| InterestsError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse(&raw).map_err(|message| InterestsError::Parse {
        path: path.to_path_buf(),
        message,
    })
}

/// Parse interests from a string. Used by the loader and by tests.
pub fn parse(raw: &str) -> Result<Interests, String> {
    let parsed: InterestsRaw =
        toml::from_str(raw).map_err(|e| format!("invalid interests TOML: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let file_hash = hex::encode(hasher.finalize());
    Ok(Interests {
        keywords: parsed.keywords,
        exclusions: parsed.exclusions,
        file_hash,
        raw_contents: raw.to_string(),
    })
}

/// Snapshot the interests file into `interests_snapshots` for the
/// given run. Idempotent against `(run_id, file_hash)` — calling
/// twice for the same run is a no-op.
pub fn snapshot(
    conn: &rusqlite::Connection,
    run_id: &str,
    interests: &Interests,
) -> Result<(), rusqlite::Error> {
    let already: i64 = conn.query_row(
        "SELECT COUNT(*) FROM interests_snapshots WHERE run_id = ?1 AND file_hash = ?2",
        rusqlite::params![run_id, interests.file_hash],
        |row| row.get(0),
    )?;
    if already > 0 {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO interests_snapshots (run_id, file_hash, contents) VALUES (?1, ?2, ?3)",
        rusqlite::params![run_id, interests.file_hash, interests.raw_contents],
    )?;
    Ok(())
}

/// The most recent (largest `id`) snapshot's `file_hash`, or `None`
/// if no snapshots exist. Used by the orchestrator to decide whether
/// to emit an `InterestsEdited` audit event at the start of a run.
pub fn last_snapshot_hash(conn: &rusqlite::Connection) -> Result<Option<String>, rusqlite::Error> {
    let row: Option<String> = conn
        .query_row(
            "SELECT file_hash FROM interests_snapshots ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(row)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_block() {
        let raw = r#"
keywords   = ["BIPA", "Section 5"]
exclusions = ["cookie banner"]
"#;
        let i = parse(raw).unwrap();
        assert_eq!(i.keywords, vec!["BIPA", "Section 5"]);
        assert_eq!(i.exclusions, vec!["cookie banner"]);
        assert_eq!(i.file_hash.len(), 64);
        assert_eq!(i.raw_contents, raw);
    }

    #[test]
    fn parses_only_keywords() {
        let i = parse(r#"keywords = ["X"]"#).unwrap();
        assert_eq!(i.keywords, vec!["X"]);
        assert!(i.exclusions.is_empty());
    }

    #[test]
    fn parses_only_exclusions() {
        let i = parse(r#"exclusions = ["X"]"#).unwrap();
        assert!(i.keywords.is_empty());
        assert_eq!(i.exclusions, vec!["X"]);
    }

    #[test]
    fn parses_both_empty() {
        let i = parse("").unwrap();
        assert!(i.keywords.is_empty());
        assert!(i.exclusions.is_empty());
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse(r#"concepts = ["foo"]"#).unwrap_err();
        assert!(err.contains("invalid interests TOML"));
    }

    #[test]
    fn rejects_malformed_toml() {
        let err = parse("keywords = [unclosed").unwrap_err();
        assert!(err.contains("invalid interests TOML"));
    }

    #[test]
    fn file_hash_is_deterministic_and_content_sensitive() {
        let a = parse("keywords = [\"X\"]").unwrap();
        let b = parse("keywords = [\"X\"]").unwrap();
        let c = parse("keywords = [\"Y\"]").unwrap();
        assert_eq!(a.file_hash, b.file_hash);
        assert_ne!(a.file_hash, c.file_hash);
    }

    #[test]
    fn snapshot_is_idempotent_for_same_hash() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE interests_snapshots ( \
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                run_id TEXT NOT NULL, \
                file_hash TEXT NOT NULL, \
                contents TEXT NOT NULL, \
                created_at TEXT NOT NULL DEFAULT (datetime('now')) \
            )",
        )
        .unwrap();
        let i = parse(r#"keywords = ["X"]"#).unwrap();
        snapshot(&conn, "run-1", &i).unwrap();
        snapshot(&conn, "run-1", &i).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM interests_snapshots WHERE run_id = 'run-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn last_snapshot_hash_returns_most_recent() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE interests_snapshots ( \
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                run_id TEXT NOT NULL, \
                file_hash TEXT NOT NULL, \
                contents TEXT NOT NULL, \
                created_at TEXT NOT NULL DEFAULT (datetime('now')) \
            )",
        )
        .unwrap();
        assert!(last_snapshot_hash(&conn).unwrap().is_none());
        let a = parse(r#"keywords = ["A"]"#).unwrap();
        snapshot(&conn, "run-1", &a).unwrap();
        let b = parse(r#"keywords = ["B"]"#).unwrap();
        snapshot(&conn, "run-2", &b).unwrap();
        assert_eq!(last_snapshot_hash(&conn).unwrap(), Some(b.file_hash));
    }
}
