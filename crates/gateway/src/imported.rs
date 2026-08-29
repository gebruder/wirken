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
    /// Refuse a write whose provenance is incomplete, naming the label.
    /// Called by every insert path; there is no other way in.
    pub(crate) fn require_complete(&self) -> Result<(), GatewayError> {
        if let Some(missing) = self.missing() {
            return Err(GatewayError::Config(format!(
                "refusing to write an imported row without an origin label: {missing} is empty. \
                 Every row carries complete provenance by construction"
            )));
        }
        Ok(())
    }

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
    /// Declared by the operator at import time. A sealed source is a
    /// closed account: it imports once, and a second import against it
    /// refuses rather than replacing what is there. There is no
    /// unseal.
    pub sealed: bool,
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
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE import_source (
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
     );",
    // Immutability is an operator declaration at import time, spelled
    // --sealed. The column said immutable, so a reader met two words
    // for one idea. Appended rather than edited into the entry above:
    // that entry has already run against databases that exist, and
    // rewriting it would leave them with the old name and no record
    // that anything was meant to change.
    "ALTER TABLE import_source RENAME COLUMN immutable TO sealed;",
];

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
        restrict_to_owner(db_path)?;
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
                "SELECT id, provider, source_account, archive_sha256, imported_at, sealed
                 FROM import_source WHERE provider = ?1 AND source_account = ?2",
                params![provider.as_str(), source_account],
                |row| {
                    Ok(ImportSource {
                        id: row.get(0)?,
                        provider: row.get(1)?,
                        source_account: row.get(2)?,
                        archive_sha256: row.get(3)?,
                        imported_at: row.get(4)?,
                        sealed: row.get::<_, i64>(5)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Every source, oldest import first.
    pub fn sources(&self) -> Result<Vec<ImportSource>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider, source_account, archive_sha256, imported_at, sealed
             FROM import_source ORDER BY imported_at, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ImportSource {
                id: row.get(0)?,
                provider: row.get(1)?,
                source_account: row.get(2)?,
                archive_sha256: row.get(3)?,
                imported_at: row.get(4)?,
                sealed: row.get::<_, i64>(5)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Decide what an import against this declaration will be, and
    /// create the source when it is new.
    ///
    /// Sealed dominates. A sealed source refuses whatever archive is
    /// presented, matching hash or not: the seal is a statement that
    /// the account is closed and its records final, and an archive
    /// that happens to hash the same does not make re-importing it
    /// meaningful. The all-unchanged no-op below exists only for live
    /// sources.
    pub fn begin_import(
        &mut self,
        decl: &SourceDeclaration,
    ) -> Result<ImportDecision, GatewayError> {
        if decl.source_account.trim().is_empty() {
            return Err(GatewayError::Config(
                "refusing to import without a source account: it is half of every natural key"
                    .into(),
            ));
        }
        match self.source(decl.provider, &decl.source_account)? {
            None => {
                let source_id = format!("src-{}", uuid::Uuid::new_v4());
                self.conn.execute(
                    "INSERT INTO import_source
                     (id, provider, source_account, archive_sha256, imported_at, sealed)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        source_id,
                        decl.provider.as_str(),
                        decl.source_account,
                        decl.archive_sha256,
                        decl.imported_at,
                        i64::from(decl.sealed),
                    ],
                )?;
                Ok(ImportDecision::Fresh { source_id })
            }
            Some(existing) if existing.sealed => Err(GatewayError::SourceSealed {
                source_account: existing.source_account,
            }),
            Some(existing) if existing.archive_sha256 == decl.archive_sha256 => {
                let counts = self.counts(&existing.id)?;
                Ok(ImportDecision::AlreadyCurrent {
                    source_id: existing.id,
                    conversations: counts.conversations,
                })
            }
            Some(existing) => Ok(ImportDecision::Reimport {
                source_id: existing.id,
            }),
        }
    }

    /// Record the archive a source now holds. The source carries the
    /// most recent hash; the hash of any individual run is on the
    /// audit event for that run.
    pub fn finish_import(
        &mut self,
        source_id: &str,
        archive_sha256: &str,
        imported_at: &str,
    ) -> Result<(), GatewayError> {
        self.conn.execute(
            "UPDATE import_source SET archive_sha256 = ?2, imported_at = ?3 WHERE id = ?1",
            params![source_id, archive_sha256, imported_at],
        )?;
        Ok(())
    }

    /// Write one conversation and everything hanging off it.
    ///
    /// Replacement is wholesale. When the incoming conversation is
    /// newer, its stored messages, attachments, and file entries are
    /// deleted and rewritten as a unit rather than merged
    /// message by message. An export is a snapshot, so a message
    /// missing from the newer archive is absent from the account's
    /// history, not merely unmentioned; merging would resurrect it and
    /// leave the store holding a conversation that never existed in
    /// either archive.
    ///
    /// One transaction per conversation, so a run that fails part way
    /// leaves the conversations it finished durable and the counts it
    /// reported true.
    pub fn upsert_conversation(
        &mut self,
        labels: &SourceLabels,
        conversation: &crate::imported_format::ExportConversation,
    ) -> Result<UpsertOutcome, GatewayError> {
        labels.require_complete()?;
        if conversation.uuid.trim().is_empty() {
            return Err(GatewayError::Config(
                "refusing to write a conversation with no uuid: it is half the natural key".into(),
            ));
        }

        let incoming_updated = normalize_timestamp(&conversation.updated_at);
        let tx = self.conn.transaction()?;

        let stored: Option<i64> = tx
            .query_row(
                "SELECT updated_at_epoch FROM imported_conversation
                 WHERE source_account = ?1 AND conversation_uuid = ?2",
                params![labels.source_account, conversation.uuid],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = match stored {
            Some(stored_updated) if incoming_updated <= stored_updated => {
                tx.commit()?;
                return Ok(UpsertOutcome::Unchanged);
            }
            Some(_) => UpsertOutcome::Updated,
            None => UpsertOutcome::Added,
        };

        if outcome == UpsertOutcome::Updated {
            // Wholesale: the children go before the parent is rewritten.
            tx.execute(
                "DELETE FROM imported_attachment
                 WHERE source_account = ?1 AND message_uuid IN
                     (SELECT message_uuid FROM imported_message
                      WHERE source_account = ?1 AND conversation_uuid = ?2)",
                params![labels.source_account, conversation.uuid],
            )?;
            tx.execute(
                "DELETE FROM imported_message_file
                 WHERE source_account = ?1 AND message_uuid IN
                     (SELECT message_uuid FROM imported_message
                      WHERE source_account = ?1 AND conversation_uuid = ?2)",
                params![labels.source_account, conversation.uuid],
            )?;
            tx.execute(
                "DELETE FROM imported_message
                 WHERE source_account = ?1 AND conversation_uuid = ?2",
                params![labels.source_account, conversation.uuid],
            )?;
            tx.execute(
                "DELETE FROM imported_conversation
                 WHERE source_account = ?1 AND conversation_uuid = ?2",
                params![labels.source_account, conversation.uuid],
            )?;
        }

        tx.execute(
            "INSERT INTO imported_conversation
             (source_id, provider, source_account, conversation_uuid, title, summary,
              created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                labels.source_id,
                labels.provider.as_str(),
                labels.source_account,
                conversation.uuid,
                conversation.name,
                conversation.summary,
                conversation.created_at,
                normalize_timestamp(&conversation.created_at),
                conversation.updated_at,
                incoming_updated,
            ],
        )?;

        for (ordinal, message) in conversation.chat_messages.iter().enumerate() {
            if message.uuid.trim().is_empty() {
                // A message with no uuid has no natural key. Skipping
                // it costs one message; refusing would cost the
                // conversation.
                continue;
            }
            tx.execute(
                "INSERT INTO imported_message
                 (source_id, provider, source_account, conversation_uuid, message_uuid,
                  ordinal, sender, text, content_json,
                  created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    labels.source_id,
                    labels.provider.as_str(),
                    labels.source_account,
                    conversation.uuid,
                    message.uuid,
                    ordinal as i64,
                    message.sender,
                    message.text,
                    message.content_json(),
                    message.created_at,
                    normalize_timestamp(&message.created_at),
                    message.updated_at,
                    normalize_timestamp(&message.updated_at),
                ],
            )?;

            for (att_ordinal, attachment) in message.attachments.iter().enumerate() {
                tx.execute(
                    "INSERT INTO imported_attachment
                     (source_id, provider, source_account, message_uuid, ordinal,
                      file_name, file_size, file_type, extracted_content)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        labels.source_id,
                        labels.provider.as_str(),
                        labels.source_account,
                        message.uuid,
                        att_ordinal as i64,
                        attachment.file_name,
                        attachment.file_size,
                        attachment.file_type,
                        attachment.extracted_content,
                    ],
                )?;
            }

            for (file_ordinal, file) in message.files.iter().enumerate() {
                tx.execute(
                    "INSERT INTO imported_message_file
                     (source_id, provider, source_account, message_uuid, ordinal, file_name)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        labels.source_id,
                        labels.provider.as_str(),
                        labels.source_account,
                        message.uuid,
                        file_ordinal as i64,
                        file.file_name,
                    ],
                )?;
            }
        }

        tx.commit()?;
        Ok(outcome)
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

/// What the operator declared about a source at import time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDeclaration {
    pub provider: Provider,
    pub source_account: String,
    pub archive_sha256: String,
    pub imported_at: String,
    /// The operator's statement that this account is closed. Sealing
    /// is a declaration, not something inferred from the archive: only
    /// the operator knows whether an account still exists.
    pub sealed: bool,
}

/// What an import against a source is going to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDecision {
    /// No source for this account yet. Everything is added.
    Fresh { source_id: String },
    /// A live source presented with an archive it has not seen.
    Reimport { source_id: String },
    /// A live source presented with the archive it already holds.
    /// Nothing is read and nothing is written.
    AlreadyCurrent {
        source_id: String,
        conversations: u64,
    },
}

impl ImportDecision {
    pub fn source_id(&self) -> &str {
        match self {
            Self::Fresh { source_id }
            | Self::Reimport { source_id }
            | Self::AlreadyCurrent { source_id, .. } => source_id,
        }
    }
}

/// What upserting one conversation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    Added,
    Updated,
    Unchanged,
}

/// Normalize an ISO 8601 timestamp to microseconds for ordering.
///
/// Unparseable yields zero, which orders oldest. That is deliberate
/// and has a consequence worth stating: a conversation whose
/// `updated_at` cannot be parsed is never newer than what is stored,
/// so a re-import leaves it alone. The alternative, treating
/// unorderable as newer, would let a record be replaced on no evidence
/// that it changed. Not mutating a stored record is the safer of the
/// two wrong answers.
fn normalize_timestamp(raw: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.timestamp_micros())
        .unwrap_or(0)
}

/// Pin the database to owner-only, converging a file that already
/// exists under a looser mode.
///
/// The data directory is already 0o700, so this is defense in depth
/// rather than the only barrier. It is worth having because this store
/// holds an entire imported conversation corpus, including attachment
/// text, which is the most confidential thing in the directory after
/// the vault. The vault takes the same posture for the same reason;
/// the stores that stay at the default hold registrations and
/// schedules, not content.
fn restrict_to_owner(db_path: &Path) -> Result<(), GatewayError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = db_path;
    Ok(())
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
    use crate::imported_format::ExportConversation;
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
             (id, provider, source_account, archive_sha256, imported_at, sealed)
             VALUES (?1, 'anthropic', 'acct-1', 'abc', '2026-01-01T00:00:00Z', 1)";
        s.conn.execute(insert, params!["src-1"]).unwrap();
        // The same account through the same provider is the same
        // source, however many archives it produces.
        assert!(s.conn.execute(insert, params!["src-2"]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_database_is_owner_only_and_converges_a_loose_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("imported.db");
        let _ = ImportStore::open(&path).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // A database left loose by an earlier run converges on reopen
        // rather than staying loose forever.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = ImportStore::open(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn counts_are_zero_on_a_fresh_source() {
        let (s, _, _t) = store();
        let counts = s.counts("src-1").unwrap();
        assert_eq!(counts.conversations, 0);
        assert_eq!(counts.messages, 0);
    }

    fn decl(account: &str, hash: &str, sealed: bool) -> SourceDeclaration {
        SourceDeclaration {
            provider: Provider::Anthropic,
            source_account: account.into(),
            archive_sha256: hash.into(),
            imported_at: "2026-01-01T00:00:00Z".into(),
            sealed,
        }
    }

    fn labels_for(decision: &ImportDecision, account: &str) -> SourceLabels {
        SourceLabels {
            source_id: decision.source_id().to_string(),
            provider: Provider::Anthropic,
            source_account: account.into(),
        }
    }

    fn conversation(uuid: &str, updated_at: &str, messages: &[&str]) -> ExportConversation {
        let body = messages
            .iter()
            .map(|m| format!(r#"{{"uuid":"{m}","sender":"human","text":"{m} body"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{"uuid":"{uuid}","name":"t","updated_at":"{updated_at}","chat_messages":[{body}]}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn a_fresh_source_is_created_and_its_conversations_are_added() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        assert!(matches!(d, ImportDecision::Fresh { .. }));
        let labels = labels_for(&d, "acct-1");
        let outcome = s
            .upsert_conversation(
                &labels,
                &conversation("c1", "2026-01-02T00:00:00Z", &["m1"]),
            )
            .unwrap();
        assert_eq!(outcome, UpsertOutcome::Added);
        assert_eq!(s.counts(d.source_id()).unwrap().conversations, 1);
        assert_eq!(s.counts(d.source_id()).unwrap().messages, 1);
    }

    #[test]
    fn a_sealed_source_refuses_a_second_import_whatever_the_hash() {
        // Sealed dominates. The same-hash no-op path must not rescue a
        // sealed source, or sealing would mean "refuses a different
        // archive" rather than "is final".
        let (mut s, _, _t) = store();
        s.begin_import(&decl("acct-1", "hash-a", true)).unwrap();

        for hash in ["hash-a", "hash-b"] {
            let err = s.begin_import(&decl("acct-1", hash, false)).unwrap_err();
            assert!(
                matches!(&err, GatewayError::SourceSealed { source_account } if source_account == "acct-1"),
                "{err:?}"
            );
            let text = err.to_string();
            assert!(text.contains("sealed"), "names the sealed state: {text}");
            assert!(text.contains("acct-1"), "names the source: {text}");
        }
    }

    #[test]
    fn a_live_source_presented_with_the_same_archive_does_nothing() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &conversation("c1", "2026-01-02T00:00:00Z", &["m1"]),
        )
        .unwrap();
        s.finish_import(d.source_id(), "hash-a", "2026-01-01T00:00:00Z")
            .unwrap();

        match s.begin_import(&decl("acct-1", "hash-a", false)).unwrap() {
            ImportDecision::AlreadyCurrent { conversations, .. } => {
                assert_eq!(conversations, 1);
            }
            other => panic!("expected AlreadyCurrent, got {other:?}"),
        }
    }

    #[test]
    fn a_live_source_presented_with_a_new_archive_reimports() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        s.finish_import(d.source_id(), "hash-a", "2026-01-01T00:00:00Z")
            .unwrap();
        assert!(matches!(
            s.begin_import(&decl("acct-1", "hash-b", false)).unwrap(),
            ImportDecision::Reimport { .. }
        ));
    }

    #[test]
    fn a_newer_conversation_replaces_its_rows_wholesale() {
        // A message absent from the newer snapshot is absent from the
        // account's history. Merging would resurrect it and leave a
        // conversation that existed in neither archive.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");

        s.upsert_conversation(
            &labels,
            &conversation("c1", "2026-01-02T00:00:00Z", &["m1", "m2", "m3"]),
        )
        .unwrap();
        assert_eq!(s.counts(d.source_id()).unwrap().messages, 3);

        // The newer snapshot carries one of the three.
        let outcome = s
            .upsert_conversation(
                &labels,
                &conversation("c1", "2026-01-03T00:00:00Z", &["m2"]),
            )
            .unwrap();
        assert_eq!(outcome, UpsertOutcome::Updated);
        assert_eq!(
            s.counts(d.source_id()).unwrap().messages,
            1,
            "the dropped messages are gone, not merged"
        );

        let surviving: String = s
            .conn
            .query_row(
                "SELECT message_uuid FROM imported_message WHERE conversation_uuid = 'c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(surviving, "m2");
    }

    #[test]
    fn a_conversation_that_is_not_newer_is_left_alone() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &conversation("c1", "2026-01-05T00:00:00Z", &["m1"]),
        )
        .unwrap();

        for stamp in ["2026-01-05T00:00:00Z", "2026-01-01T00:00:00Z"] {
            let outcome = s
                .upsert_conversation(&labels, &conversation("c1", stamp, &["replacement"]))
                .unwrap();
            assert_eq!(outcome, UpsertOutcome::Unchanged, "for {stamp}");
        }
        let surviving: String = s
            .conn
            .query_row(
                "SELECT message_uuid FROM imported_message WHERE conversation_uuid = 'c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(surviving, "m1", "an equal or older snapshot writes nothing");
    }

    #[test]
    fn attachments_and_files_are_written_and_replaced_with_their_conversation() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        let with_children: ExportConversation = serde_json::from_str(
            r#"{"uuid":"c1","updated_at":"2026-01-02T00:00:00Z","chat_messages":[
                 {"uuid":"m1","attachments":[
                    {"file_name":"a.txt","file_size":3,"file_type":"text/plain",
                     "extracted_content":"abc"}],
                  "files":[{"file_name":"a.txt"}]}]}"#,
        )
        .unwrap();
        s.upsert_conversation(&labels, &with_children).unwrap();

        fn count(store: &ImportStore, table: &str) -> i64 {
            store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        }
        assert_eq!(count(&s, "imported_attachment"), 1);
        assert_eq!(count(&s, "imported_message_file"), 1);

        s.upsert_conversation(
            &labels,
            &conversation("c1", "2026-01-03T00:00:00Z", &["m9"]),
        )
        .unwrap();
        assert_eq!(
            count(&s, "imported_attachment"),
            0,
            "children go with the parent"
        );
        assert_eq!(count(&s, "imported_message_file"), 0);
    }

    #[test]
    fn an_incomplete_label_refuses_the_write_and_names_the_label() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        for (labels, expected) in [
            (
                SourceLabels {
                    source_id: String::new(),
                    provider: Provider::Anthropic,
                    source_account: "acct-1".into(),
                },
                "source_id",
            ),
            (
                SourceLabels {
                    source_id: d.source_id().into(),
                    provider: Provider::Anthropic,
                    source_account: "   ".into(),
                },
                "source_account",
            ),
        ] {
            let err = s
                .upsert_conversation(
                    &labels,
                    &conversation("c1", "2026-01-02T00:00:00Z", &["m1"]),
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains(expected), "{err}");
        }
        assert_eq!(s.counts(d.source_id()).unwrap().conversations, 0);
    }

    #[test]
    fn an_unparseable_updated_at_never_counts_as_newer() {
        // Stated so the consequence is pinned rather than discovered:
        // a record whose timestamp cannot be ordered is never replaced.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(&labels, &conversation("c1", "not a timestamp", &["m1"]))
            .unwrap();
        let outcome = s
            .upsert_conversation(&labels, &conversation("c1", "also not one", &["m2"]))
            .unwrap();
        assert_eq!(outcome, UpsertOutcome::Unchanged);
        assert_eq!(normalize_timestamp("not a timestamp"), 0);
    }

    #[test]
    fn the_rename_migration_reaches_a_database_created_before_it() {
        // The runner's whole reason for existing: a database that
        // stopped at the first migration picks up the second on open.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("imported.db");
        let mut conn = Connection::open(&path).unwrap();
        let applied = crate::migrate::apply(&mut conn, &MIGRATIONS[..1]).unwrap();
        assert_eq!(applied, 1);
        let old_name: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('import_source') WHERE name = 'immutable'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_name, 1, "the shipped schema had the old name");
        drop(conn);

        let (s, applied) = ImportStore::open(&path).unwrap();
        assert_eq!(applied, MIGRATIONS.len() - 1, "only the new entry ran");
        let new_name: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('import_source') WHERE name = 'sealed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(new_name, 1);
    }

    #[test]
    fn a_missing_source_reads_as_absent_rather_than_erroring() {
        let (s, _, _t) = store();
        assert!(s.source(Provider::Anthropic, "nobody").unwrap().is_none());
        assert!(s.sources().unwrap().is_empty());
    }
}
