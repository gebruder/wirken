//! Imported assistant data-export archives.
//!
//! An archive is a provenance-scoped dataset, not an identity. The
//! account named inside one is a label on rows; it does not enter the
//! federated-identity machinery, which answers a different question.
//!
//! # Provenance
//!
//! Every conversation, message, attachment, and file row carries its
//! origin labels, stamped at insert and `NOT NULL` in the schema:
//!
//! * `source_id` - the import source the row arrived through
//! * `provider` - which assistant's export format it came from
//! * `source_account` - the account identifier inside the archive
//!
//! A message additionally carries `conversation_uuid`, so a message
//! row names the conversation it belongs to without a join.
//!
//! [`SourceLabels`] carries the three. It has no `Default` and every
//! field is required, so a caller cannot construct a write without
//! them, and [`SourceLabels::missing`] names the empty one rather than
//! writing a blank label. A blank label is not provenance.
//!
//! # Records are read-only after import
//!
//! Nothing here mutates stored content. The import path writes rows and
//! the read path returns them. An archive may legitimately contain a
//! script tag or an injection string as the subject of a conversation,
//! so rewriting stored content to compensate for a rendering bug would
//! corrupt the record instead of fixing the renderer. Output encoding at
//! render is the control; there is no sanitizing at import.
//!
//! # Natural keys
//!
//! `(source_account, conversation_uuid)` and
//! `(source_account, message_uuid)`. Both uuids are present on every
//! record in the archives this schema was derived from. The keys are
//! scoped by account rather than global, because two source accounts
//! are two datasets and nothing joins across them.
//!
//! # Closed sets are observed, not contractual
//!
//! Message sender and content block type look like closed sets in the
//! archives examined. They are stored as TEXT with no `CHECK` and no
//! Rust enum at this boundary. A value outside the observed set is
//! stored rather than rejected: the format is not a published
//! interface, and turning an unremarkable upstream addition into a
//! failed import would trade a cosmetic problem for a total one.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::GatewayError;

/// Which assistant's export format a source came from.
///
/// One variant, and the single reserved seam in this schema. It
/// reserves a name rather than a structure: another assistant's export
/// format is an uncommitted boundary, and an abstraction shaped by an
/// uncommitted boundary is shaped by a guess. When a second format is
/// actually implemented, the shape of the seam will be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
}

impl Provider {
    /// Stable label written to rows and audit events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
        }
    }
}

/// The origin labels every imported row carries.
///
/// Separate from the record types so a caller cannot construct a write
/// without them: there is no `Default`, and every field is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLabels {
    pub source_id: String,
    pub provider: Provider,
    pub source_account: String,
}

impl SourceLabels {
    /// Which label is missing, if any. Empty is treated as missing: a
    /// blank source account is not provenance.
    pub fn missing(&self) -> Option<&'static str> {
        if self.source_id.trim().is_empty() {
            return Some("source_id");
        }
        if self.source_account.trim().is_empty() {
            return Some("source_account");
        }
        None
    }
}

/// One import source: an archive, and the account it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSource {
    pub id: String,
    pub provider: String,
    pub source_account: String,
    pub archive_sha256: String,
    pub imported_at: String,
    /// A closed-account source imports once. A second import against
    /// it refuses rather than replacing what is there.
    pub immutable: bool,
}

/// Append-only. A new migration goes on the end; an existing entry is
/// never reordered or replaced, because the recorded index would then
/// point at different SQL than the one that ran.
///
/// Timestamps are stored twice throughout: the original string
/// verbatim, and a normalized integer for ordering and for the
/// re-import comparison. Storing only the normalized value would
/// discard bytes the record carried, and comparing raw strings across
/// two differently shaped forms would be wrong.
const MIGRATIONS: &[&str] = &["CREATE TABLE import_source (
         id              TEXT PRIMARY KEY,
         provider        TEXT NOT NULL,
         source_account  TEXT NOT NULL,
         archive_sha256  TEXT NOT NULL,
         imported_at     TEXT NOT NULL,
         immutable       INTEGER NOT NULL,
         UNIQUE (provider, source_account)
     );

     CREATE TABLE imported_conversation (
         source_id          TEXT NOT NULL,
         provider           TEXT NOT NULL,
         source_account     TEXT NOT NULL,
         conversation_uuid  TEXT NOT NULL,
         title              TEXT NOT NULL,
         summary            TEXT NOT NULL,
         created_at_raw     TEXT NOT NULL,
         created_at_epoch   INTEGER NOT NULL,
         updated_at_raw     TEXT NOT NULL,
         updated_at_epoch   INTEGER NOT NULL,
         PRIMARY KEY (source_account, conversation_uuid)
     );

     CREATE INDEX imported_conversation_by_source
         ON imported_conversation (source_id, updated_at_epoch DESC);

     CREATE TABLE imported_message (
         source_id          TEXT NOT NULL,
         provider           TEXT NOT NULL,
         source_account     TEXT NOT NULL,
         conversation_uuid  TEXT NOT NULL,
         message_uuid       TEXT NOT NULL,
         ordinal            INTEGER NOT NULL,
         sender             TEXT NOT NULL,
         text               TEXT NOT NULL,
         content_json       TEXT NOT NULL,
         created_at_raw     TEXT NOT NULL,
         created_at_epoch   INTEGER NOT NULL,
         updated_at_raw     TEXT NOT NULL,
         updated_at_epoch   INTEGER NOT NULL,
         PRIMARY KEY (source_account, message_uuid)
     );

     CREATE INDEX imported_message_by_conversation
         ON imported_message (source_account, conversation_uuid, ordinal);

     CREATE TABLE imported_attachment (
         source_id          TEXT NOT NULL,
         provider           TEXT NOT NULL,
         source_account     TEXT NOT NULL,
         message_uuid       TEXT NOT NULL,
         ordinal            INTEGER NOT NULL,
         file_name          TEXT NOT NULL,
         file_size          INTEGER,
         file_type          TEXT NOT NULL,
         extracted_content  TEXT NOT NULL,
         PRIMARY KEY (source_account, message_uuid, ordinal)
     );

     CREATE TABLE imported_message_file (
         source_id       TEXT NOT NULL,
         provider        TEXT NOT NULL,
         source_account  TEXT NOT NULL,
         message_uuid    TEXT NOT NULL,
         ordinal         INTEGER NOT NULL,
         file_name       TEXT NOT NULL,
         PRIMARY KEY (source_account, message_uuid, ordinal)
     );"];

/// Store for imported archives.
pub struct ImportStore {
    conn: Connection,
}

impl ImportStore {
    /// Open the store, applying any migrations not yet recorded.
    ///
    /// Returns the store and how many migrations ran on this call. A
    /// fresh database reports the whole slice; an up-to-date one
    /// reports none, which is the difference the import command shows
    /// the operator.
    pub fn open(db_path: &Path) -> Result<(Self, usize), GatewayError> {
        let mut conn = Connection::open(db_path)?;
        // Outside the runner's transaction: journal_mode cannot be set
        // from inside one.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let applied = crate::migrate::apply(&mut conn, MIGRATIONS)?;
        Ok((Self { conn }, applied))
    }

    /// The source for this provider and account, if one was imported.
    pub fn source(
        &self,
        provider: Provider,
        source_account: &str,
    ) -> Result<Option<ImportSource>, GatewayError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, provider, source_account, archive_sha256, imported_at, immutable
                 FROM import_source WHERE provider = ?1 AND source_account = ?2",
                params![provider.as_str(), source_account],
                |row| {
                    Ok(ImportSource {
                        id: row.get(0)?,
                        provider: row.get(1)?,
                        source_account: row.get(2)?,
                        archive_sha256: row.get(3)?,
                        imported_at: row.get(4)?,
                        immutable: row.get::<_, i64>(5)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Every source, oldest import first.
    pub fn sources(&self) -> Result<Vec<ImportSource>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider, source_account, archive_sha256, imported_at, immutable
             FROM import_source ORDER BY imported_at, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ImportSource {
                id: row.get(0)?,
                provider: row.get(1)?,
                source_account: row.get(2)?,
                archive_sha256: row.get(3)?,
                imported_at: row.get(4)?,
                immutable: row.get::<_, i64>(5)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Stored conversation and message counts for one source. Counts
    /// only: no title and no message text leaves this method.
    pub fn counts(&self, source_id: &str) -> Result<StoredCounts, GatewayError> {
        let conversations: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_conversation WHERE source_id = ?1",
            params![source_id],
            |r| r.get(0),
        )?;
        let messages: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_message WHERE source_id = ?1",
            params![source_id],
            |r| r.get(0),
        )?;
        Ok(StoredCounts {
            conversations: conversations as u64,
            messages: messages as u64,
        })
    }
}

/// What a source holds. Counts and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredCounts {
    pub conversations: u64,
    pub messages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (ImportStore, usize, TempDir) {
        let tmp = TempDir::new().unwrap();
        let (s, applied) = ImportStore::open(&tmp.path().join("imported.db")).unwrap();
        (s, applied, tmp)
    }

    #[test]
    fn a_fresh_database_applies_the_migrations_and_reopening_applies_none() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("imported.db");
        let (_s, first) = ImportStore::open(&path).unwrap();
        assert_eq!(first, MIGRATIONS.len());
        let (_s, second) = ImportStore::open(&path).unwrap();
        assert_eq!(second, 0);
    }

    #[test]
    fn every_provenance_column_is_not_null() {
        let (s, _, _t) = store();
        for table in [
            "imported_conversation",
            "imported_message",
            "imported_attachment",
            "imported_message_file",
        ] {
            for column in ["source_id", "provider", "source_account"] {
                let notnull: i64 = s
                    .conn
                    .query_row(
                        "SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = ?2",
                        params![table, column],
                        |r| r.get(0),
                    )
                    .unwrap_or_else(|e| panic!("{table}.{column}: {e}"));
                assert_eq!(notnull, 1, "{table}.{column} must be NOT NULL");
            }
        }
        // A message names its conversation without a join.
        let notnull: i64 = s
            .conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('imported_message') \
                 WHERE name = 'conversation_uuid'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(notnull, 1);
    }

    #[test]
    fn labels_name_the_missing_label() {
        let complete = SourceLabels {
            source_id: "src-1".into(),
            provider: Provider::Anthropic,
            source_account: "acct-1".into(),
        };
        assert_eq!(complete.missing(), None);

        let blank_account = SourceLabels {
            source_account: "   ".into(),
            ..complete.clone()
        };
        assert_eq!(blank_account.missing(), Some("source_account"));

        let blank_id = SourceLabels {
            source_id: String::new(),
            ..complete
        };
        assert_eq!(blank_id.missing(), Some("source_id"));
    }

    #[test]
    fn a_source_is_unique_per_provider_and_account() {
        let (s, _, _t) = store();
        let insert = "INSERT INTO import_source
             (id, provider, source_account, archive_sha256, imported_at, immutable)
             VALUES (?1, 'anthropic', 'acct-1', 'abc', '2026-01-01T00:00:00Z', 1)";
        s.conn.execute(insert, params!["src-1"]).unwrap();
        // The same account through the same provider is the same
        // source, however many archives it produces.
        assert!(s.conn.execute(insert, params!["src-2"]).is_err());
    }

    #[test]
    fn counts_are_zero_on_a_fresh_source() {
        let (s, _, _t) = store();
        let counts = s.counts("src-1").unwrap();
        assert_eq!(counts.conversations, 0);
        assert_eq!(counts.messages, 0);
    }

    #[test]
    fn a_missing_source_reads_as_absent_rather_than_erroring() {
        let (s, _, _t) = store();
        assert!(s.source(Provider::Anthropic, "nobody").unwrap().is_none());
        assert!(s.sources().unwrap().is_empty());
    }
}
