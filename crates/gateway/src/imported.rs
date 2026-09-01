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

/// An existing import source, as much of it as the decision needs.
///
/// The row carries a provider and an import timestamp too. Neither is
/// read when deciding what an import will be, so neither is selected:
/// a field nothing reads is a field that can drift from the row
/// without anything noticing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportSource {
    id: String,
    source_account: String,
    archive_sha256: String,
    /// Declared by the operator at import time. A sealed source is a
    /// closed account: it imports once, and a second import against it
    /// refuses rather than replacing what is there. There is no
    /// unseal.
    sealed: bool,
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
    "CREATE TABLE imported_project (
         source_id           TEXT NOT NULL,
         provider            TEXT NOT NULL,
         source_account      TEXT NOT NULL,
         project_uuid        TEXT NOT NULL,
         name                TEXT NOT NULL,
         description         TEXT NOT NULL,
         prompt_template     TEXT NOT NULL,
         is_private          INTEGER NOT NULL,
         is_starter_project  INTEGER NOT NULL,
         creator_uuid        TEXT NOT NULL,
         created_at_raw      TEXT NOT NULL,
         created_at_epoch    INTEGER NOT NULL,
         updated_at_raw      TEXT NOT NULL,
         updated_at_epoch    INTEGER NOT NULL,
         PRIMARY KEY (source_account, project_uuid)
     );

     CREATE INDEX imported_project_by_source
         ON imported_project (source_id, updated_at_epoch DESC);

     CREATE TABLE imported_project_doc (
         source_id         TEXT NOT NULL,
         provider          TEXT NOT NULL,
         source_account    TEXT NOT NULL,
         project_uuid      TEXT NOT NULL,
         doc_uuid          TEXT NOT NULL,
         ordinal           INTEGER NOT NULL,
         filename          TEXT NOT NULL,
         content           TEXT NOT NULL,
         created_at_raw    TEXT NOT NULL,
         created_at_epoch  INTEGER NOT NULL,
         PRIMARY KEY (source_account, doc_uuid)
     );

     CREATE INDEX imported_project_doc_by_project
         ON imported_project_doc (source_account, project_uuid, ordinal);",
    // Full-text search. Three external-content indexes rather than one
    // table holding a second copy of the text: the substantive row
    // stays in its base table and the index carries only the terms.
    //
    // Triggers rather than write-path calls. The write path already
    // deletes and reinserts a record's rows wholesale, and an index
    // maintained beside that by hand would drift the first time a new
    // delete path forgot it. A trigger cannot be forgotten, and delete
    // is by rowid rather than a scan.
    //
    // What is indexed is exactly what the views render and what the
    // gate covers: flattened message text, attachment text, and
    // project-document text. Content blocks are not indexed; they are
    // stored verbatim and never parsed for meaning.
    "CREATE VIRTUAL TABLE imported_message_fts USING fts5(
         text,
         content='imported_message',
         content_rowid='rowid'
     );

     CREATE TRIGGER imported_message_fts_insert AFTER INSERT ON imported_message BEGIN
         INSERT INTO imported_message_fts(rowid, text) VALUES (new.rowid, new.text);
     END;

     CREATE TRIGGER imported_message_fts_delete AFTER DELETE ON imported_message BEGIN
         INSERT INTO imported_message_fts(imported_message_fts, rowid, text)
             VALUES ('delete', old.rowid, old.text);
     END;

     CREATE VIRTUAL TABLE imported_attachment_fts USING fts5(
         extracted_content,
         content='imported_attachment',
         content_rowid='rowid'
     );

     CREATE TRIGGER imported_attachment_fts_insert AFTER INSERT ON imported_attachment BEGIN
         INSERT INTO imported_attachment_fts(rowid, extracted_content)
             VALUES (new.rowid, new.extracted_content);
     END;

     CREATE TRIGGER imported_attachment_fts_delete AFTER DELETE ON imported_attachment BEGIN
         INSERT INTO imported_attachment_fts(imported_attachment_fts, rowid, extracted_content)
             VALUES ('delete', old.rowid, old.extracted_content);
     END;

     CREATE VIRTUAL TABLE imported_project_doc_fts USING fts5(
         content,
         content='imported_project_doc',
         content_rowid='rowid'
     );

     CREATE TRIGGER imported_project_doc_fts_insert AFTER INSERT ON imported_project_doc BEGIN
         INSERT INTO imported_project_doc_fts(rowid, content) VALUES (new.rowid, new.content);
     END;

     CREATE TRIGGER imported_project_doc_fts_delete AFTER DELETE ON imported_project_doc BEGIN
         INSERT INTO imported_project_doc_fts(imported_project_doc_fts, rowid, content)
             VALUES ('delete', old.rowid, old.content);
     END;",
    // The migration above creates the indexes and the triggers that
    // keep them current. Triggers fire on writes that happen after
    // they exist, so a store that already held rows when it ran came
    // out of it with three empty indexes and no error: every search
    // against that corpus returned nothing, which reads exactly like
    // a corpus that does not contain the term.
    //
    // `rebuild` reads the content tables and reconstructs each index
    // from them. Appended rather than folded into the migration above,
    // per the append-only rule: a store that already recorded that
    // migration would never re-run an edited copy of it.
    //
    // Idempotent and safe on a store that needs nothing: rebuilding an
    // index that is already correct produces the same index. It reads
    // the content tables and writes only index rows, so the archive's
    // own bytes are untouched and a sealed source stays sealed.
    "INSERT INTO imported_message_fts(imported_message_fts) VALUES('rebuild');
     INSERT INTO imported_attachment_fts(imported_attachment_fts) VALUES('rebuild');
     INSERT INTO imported_project_doc_fts(imported_project_doc_fts) VALUES('rebuild');",
];

/// Index of the migration that creates the FTS tables and triggers.
/// Tests build a store with rows written before it to reproduce the
/// state a real store reached: content present, index empty.
#[cfg(test)]
const FTS_MIGRATION_INDEX: usize = 3;

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
    fn source(
        &self,
        provider: Provider,
        source_account: &str,
    ) -> Result<Option<ImportSource>, GatewayError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, source_account, archive_sha256, sealed
                 FROM import_source WHERE provider = ?1 AND source_account = ?2",
                params![provider.as_str(), source_account],
                |row| {
                    Ok(ImportSource {
                        id: row.get(0)?,
                        source_account: row.get(1)?,
                        archive_sha256: row.get(2)?,
                        sealed: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row)
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

        let tx = self.conn.transaction()?;

        // The stored raw string, not its epoch: whether a stored record
        // can be ordered is a question about the string it arrived as.
        let stored_raw: Option<String> = tx
            .query_row(
                "SELECT updated_at_raw FROM imported_conversation
                 WHERE source_account = ?1 AND conversation_uuid = ?2",
                params![labels.source_account, conversation.uuid],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = decide_outcome(stored_raw.as_deref(), &conversation.updated_at);
        if outcome != UpsertOutcome::Added && outcome != UpsertOutcome::Updated {
            tx.commit()?;
            return Ok(outcome);
        }

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
                normalize_timestamp(&conversation.created_at).unwrap_or_default(),
                conversation.updated_at,
                normalize_timestamp(&conversation.updated_at).unwrap_or_default(),
            ],
        )?;

        for (ordinal, message) in conversation.chat_messages.iter().enumerate() {
            if message.uuid.trim().is_empty() {
                // A message with no uuid has no natural key. Skipping
                // it costs one message; refusing would cost the
                // conversation.
                continue;
            }
            let inserted = tx.execute(
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
                    normalize_timestamp(&message.created_at).unwrap_or_default(),
                    message.updated_at,
                    normalize_timestamp(&message.updated_at).unwrap_or_default(),
                ],
            );
            if let Err(err) = inserted {
                // The collision is recoverable from inside the still
                // open transaction: a constraint violation rolls back
                // the statement, not the transaction, so the row that
                // is already there can still be named before this
                // conversation unwinds.
                if is_primary_key_violation(&err) {
                    let stored_conversation: Option<String> = tx
                        .query_row(
                            "SELECT conversation_uuid FROM imported_message
                             WHERE source_account = ?1 AND message_uuid = ?2",
                            params![labels.source_account, message.uuid],
                            |row| row.get(0),
                        )
                        .optional()?;
                    return Err(GatewayError::DuplicateMessageUuid {
                        source_account: labels.source_account.clone(),
                        message_uuid: message.uuid.clone(),
                        stored_conversation: stored_conversation
                            .unwrap_or_else(|| "unknown".to_string()),
                        incoming_conversation: conversation.uuid.clone(),
                    });
                }
                return Err(err.into());
            }

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

    /// Write one project and its documents.
    ///
    /// Every semantic is the conversation's: the natural key is scoped
    /// by source account, the ordering decision is the shared one, and
    /// replacement is wholesale, with a project's documents deleted and
    /// rewritten alongside it. A document absent from the newer
    /// snapshot is absent from the project, and merging would leave a
    /// project that existed in neither archive.
    ///
    /// A project's creator is stored as its uuid. The archive carries
    /// the creator's name too; it is not in the parsed struct, so it
    /// cannot arrive here.
    pub fn upsert_project(
        &mut self,
        labels: &SourceLabels,
        project: &crate::imported_format::ExportProject,
    ) -> Result<UpsertOutcome, GatewayError> {
        labels.require_complete()?;
        if project.uuid.trim().is_empty() {
            return Err(GatewayError::Config(
                "refusing to write a project with no uuid: it is half the natural key".into(),
            ));
        }

        let tx = self.conn.transaction()?;
        let stored_raw: Option<String> = tx
            .query_row(
                "SELECT updated_at_raw FROM imported_project
                 WHERE source_account = ?1 AND project_uuid = ?2",
                params![labels.source_account, project.uuid],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = decide_outcome(stored_raw.as_deref(), &project.updated_at);
        if outcome != UpsertOutcome::Added && outcome != UpsertOutcome::Updated {
            tx.commit()?;
            return Ok(outcome);
        }

        if outcome == UpsertOutcome::Updated {
            tx.execute(
                "DELETE FROM imported_project_doc
                 WHERE source_account = ?1 AND project_uuid = ?2",
                params![labels.source_account, project.uuid],
            )?;
            tx.execute(
                "DELETE FROM imported_project
                 WHERE source_account = ?1 AND project_uuid = ?2",
                params![labels.source_account, project.uuid],
            )?;
        }

        tx.execute(
            "INSERT INTO imported_project
             (source_id, provider, source_account, project_uuid, name, description,
              prompt_template, is_private, is_starter_project, creator_uuid,
              created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                labels.source_id,
                labels.provider.as_str(),
                labels.source_account,
                project.uuid,
                project.name,
                project.description,
                project.prompt_template,
                i64::from(project.is_private),
                i64::from(project.is_starter_project),
                project.creator.uuid,
                project.created_at,
                normalize_timestamp(&project.created_at).unwrap_or_default(),
                project.updated_at,
                normalize_timestamp(&project.updated_at).unwrap_or_default(),
            ],
        )?;

        for (ordinal, doc) in project.docs.iter().enumerate() {
            if doc.uuid.trim().is_empty() {
                // No natural key. Skipping costs one document; refusing
                // would cost the project.
                continue;
            }
            tx.execute(
                "INSERT INTO imported_project_doc
                 (source_id, provider, source_account, project_uuid, doc_uuid, ordinal,
                  filename, content, created_at_raw, created_at_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    labels.source_id,
                    labels.provider.as_str(),
                    labels.source_account,
                    project.uuid,
                    doc.uuid,
                    ordinal as i64,
                    doc.filename,
                    doc.content,
                    doc.created_at,
                    normalize_timestamp(&doc.created_at).unwrap_or_default(),
                ],
            )?;
        }

        tx.commit()?;
        Ok(outcome)
    }

    /// Search one source's imported content.
    ///
    /// Covers flattened message text, attachment text, and
    /// project-document text, which is what the index covers and what
    /// the gate covers. Content blocks are not searched: they are
    /// stored verbatim and never parsed for meaning, so there is
    /// nothing to match against that a reader would recognise.
    ///
    /// `query` is FTS5 match syntax. A query the matcher cannot parse
    /// is a refusal naming that, not a crash and not an empty result:
    /// an empty result would tell a caller their term is absent when
    /// in fact their query was never run.
    pub fn search(
        &self,
        source_id: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SearchHit>, GatewayError> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();
        self.search_messages(source_id, query, limit, &mut hits)?;
        self.search_attachments(source_id, query, limit, &mut hits)?;
        self.search_project_docs(source_id, query, limit, &mut hits)?;
        hits.truncate(limit);
        Ok(hits)
    }

    fn search_messages(
        &self,
        source_id: &str,
        query: &str,
        limit: usize,
        out: &mut Vec<SearchHit>,
    ) -> Result<(), GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.conversation_uuid, m.message_uuid,
                    snippet(imported_message_fts, 0, '', '', '…', 16)
             FROM imported_message_fts f
             JOIN imported_message m ON m.rowid = f.rowid
             WHERE imported_message_fts MATCH ?1 AND m.source_id = ?2
             ORDER BY rank
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![query, source_id, limit as i64], |row| {
                Ok(SearchHit {
                    kind: SearchKind::Message,
                    source_id: source_id.to_string(),
                    conversation_uuid: Some(row.get(0)?),
                    project_uuid: None,
                    owner_uuid: row.get(1)?,
                    snippet: row.get(2)?,
                })
            })
            .map_err(malformed_query)?;
        // The parse failure surfaces when the statement is stepped,
        // not when it is prepared, so the step error is mapped too.
        // Everything else in these statements is fixed SQL over tables
        // that exist, so a failure here is the caller's query.
        for row in rows {
            out.push(row.map_err(malformed_query)?);
        }
        Ok(())
    }

    fn search_attachments(
        &self,
        source_id: &str,
        query: &str,
        limit: usize,
        out: &mut Vec<SearchHit>,
    ) -> Result<(), GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.conversation_uuid, a.message_uuid,
                    snippet(imported_attachment_fts, 0, '', '', '…', 16)
             FROM imported_attachment_fts f
             JOIN imported_attachment a ON a.rowid = f.rowid
             LEFT JOIN imported_message m
                 ON m.source_account = a.source_account AND m.message_uuid = a.message_uuid
             WHERE imported_attachment_fts MATCH ?1 AND a.source_id = ?2
             ORDER BY rank
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![query, source_id, limit as i64], |row| {
                Ok(SearchHit {
                    kind: SearchKind::Attachment,
                    source_id: source_id.to_string(),
                    conversation_uuid: row.get(0)?,
                    project_uuid: None,
                    owner_uuid: row.get(1)?,
                    snippet: row.get(2)?,
                })
            })
            .map_err(malformed_query)?;
        // The parse failure surfaces when the statement is stepped,
        // not when it is prepared, so the step error is mapped too.
        // Everything else in these statements is fixed SQL over tables
        // that exist, so a failure here is the caller's query.
        for row in rows {
            out.push(row.map_err(malformed_query)?);
        }
        Ok(())
    }

    fn search_project_docs(
        &self,
        source_id: &str,
        query: &str,
        limit: usize,
        out: &mut Vec<SearchHit>,
    ) -> Result<(), GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT d.project_uuid, d.doc_uuid,
                    snippet(imported_project_doc_fts, 0, '', '', '…', 16)
             FROM imported_project_doc_fts f
             JOIN imported_project_doc d ON d.rowid = f.rowid
             WHERE imported_project_doc_fts MATCH ?1 AND d.source_id = ?2
             ORDER BY rank
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![query, source_id, limit as i64], |row| {
                Ok(SearchHit {
                    kind: SearchKind::ProjectDocument,
                    source_id: source_id.to_string(),
                    conversation_uuid: None,
                    project_uuid: Some(row.get(0)?),
                    owner_uuid: row.get(1)?,
                    snippet: row.get(2)?,
                })
            })
            .map_err(malformed_query)?;
        // The parse failure surfaces when the statement is stepped,
        // not when it is prepared, so the step error is mapped too.
        // Everything else in these statements is fixed SQL over tables
        // that exist, so a failure here is the caller's query.
        for row in rows {
            out.push(row.map_err(malformed_query)?);
        }
        Ok(())
    }

    /// Every source with what it holds, oldest import first.
    ///
    /// This was removed in a subtraction pass while nothing needed it.
    /// The archive list needs it now, which is the pass working rather
    /// than churn: the surface exists because a caller does.
    pub fn source_views(&self) -> Result<Vec<SourceView>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider, source_account, archive_sha256, imported_at, sealed
             FROM import_source ORDER BY imported_at, id",
        )?;
        let rows: Vec<(String, String, String, String, String, bool)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get::<_, i64>(5)? != 0,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut out = Vec::with_capacity(rows.len());
        for (id, provider, source_account, archive_sha256, imported_at, sealed) in rows {
            let counts = self.counts(&id)?;
            out.push(SourceView {
                id,
                provider,
                source_account,
                archive_sha256,
                imported_at,
                sealed,
                counts,
            });
        }
        Ok(out)
    }

    /// A source's conversations, most recently updated first.
    ///
    /// Ordered on the normalized epoch, which is what that column and
    /// its index are for. A conversation whose timestamp would not
    /// parse sorts oldest; it is still listed, and its raw timestamp
    /// is what the view shows.
    pub fn conversation_rows(
        &self,
        source_id: &str,
        limit: usize,
    ) -> Result<Vec<ConversationRow>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.conversation_uuid, c.title, c.updated_at_raw,
                    (SELECT COUNT(*) FROM imported_message m
                     WHERE m.source_account = c.source_account
                       AND m.conversation_uuid = c.conversation_uuid)
             FROM imported_conversation c
             WHERE c.source_id = ?1
             ORDER BY c.updated_at_epoch DESC, c.conversation_uuid
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![source_id, limit as i64], |row| {
            Ok(ConversationRow {
                conversation_uuid: row.get(0)?,
                title: row.get(1)?,
                updated_at_raw: row.get(2)?,
                message_count: row.get::<_, i64>(3)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// One conversation, projected for the detail view.
    /// The account a source belongs to, or `None` when no source
    /// carries that id.
    ///
    /// Its own lookup rather than a field on `ConversationDetail`:
    /// the read audit row is written whether or not the conversation
    /// was found, and a source that exists with a conversation that
    /// does not still has an account to name.
    pub fn source_account(&self, source_id: &str) -> Result<Option<String>, GatewayError> {
        Ok(self
            .conn
            .query_row(
                "SELECT source_account FROM import_source WHERE id = ?1",
                params![source_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn conversation_detail(
        &self,
        source_id: &str,
        conversation_uuid: &str,
    ) -> Result<Option<ConversationDetail>, GatewayError> {
        let account: Option<String> = self
            .conn
            .query_row(
                "SELECT source_account FROM import_source WHERE id = ?1",
                params![source_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(source_account) = account else {
            return Ok(None);
        };

        let head: Option<(String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT title, summary, created_at_raw, updated_at_raw
                 FROM imported_conversation
                 WHERE source_account = ?1 AND conversation_uuid = ?2",
                params![source_account, conversation_uuid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((title, summary, created_at_raw, updated_at_raw)) = head else {
            return Ok(None);
        };

        let mut stmt = self.conn.prepare(
            "SELECT message_uuid, sender, text, created_at_raw, content_json
             FROM imported_message
             WHERE source_account = ?1 AND conversation_uuid = ?2
             ORDER BY ordinal",
        )?;
        let raw: Vec<(String, String, String, String, String)> = stmt
            .query_map(params![source_account, conversation_uuid], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut messages = Vec::with_capacity(raw.len());
        for (message_uuid, sender, text, created_at_raw, content_json) in raw {
            let mut att = self.conn.prepare(
                "SELECT file_name, extracted_content FROM imported_attachment
                 WHERE source_account = ?1 AND message_uuid = ?2
                 ORDER BY ordinal",
            )?;
            let attachments: Vec<AttachmentView> = att
                .query_map(params![source_account, message_uuid], |row| {
                    Ok(AttachmentView {
                        file_name: row.get(0)?,
                        extracted_content: row.get(1)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            messages.push(MessageView {
                message_uuid,
                sender,
                text,
                created_at_raw,
                attachments,
                unrendered_blocks: unrendered_block_count(&content_json),
            });
        }

        Ok(Some(ConversationDetail {
            conversation_uuid: conversation_uuid.to_string(),
            title,
            summary,
            created_at_raw,
            updated_at_raw,
            messages,
        }))
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
        let projects: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_project WHERE source_id = ?1",
            params![source_id],
            |r| r.get(0),
        )?;
        let project_docs: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_project_doc WHERE source_id = ?1",
            params![source_id],
            |r| r.get(0),
        )?;
        Ok(StoredCounts {
            conversations: conversations as u64,
            messages: messages as u64,
            projects: projects as u64,
            project_docs: project_docs as u64,
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

/// What upserting one record did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// Not previously stored.
    Added,
    /// Stored, and the incoming snapshot is demonstrably newer.
    Updated,
    /// Stored, and the incoming snapshot is demonstrably not newer.
    Unchanged,
    /// Stored, and there is no ordering evidence either way, because a
    /// timestamp on one side or the other could not be parsed. Nothing
    /// is written.
    ///
    /// Distinct from `Unchanged` on purpose. Both write nothing, but
    /// they mean opposite things: unchanged is a comparison that
    /// happened and came out equal or older, unorderable is a
    /// comparison that could not happen at all. Folding them together
    /// would let an upstream timestamp format change land as a quiet
    /// archive of unchanged records while the store went stale. Kept
    /// apart, the same break reports a whole archive unorderable,
    /// which is a signal.
    Unorderable,
}

/// Normalize an ISO 8601 timestamp to microseconds for ordering.
///
/// `None` means the string could not be parsed, which is the absence
/// of ordering evidence rather than a very old time. A sentinel would
/// not do: a timestamp of the unix epoch parses legitimately and
/// yields zero, so zero cannot also mean "unparseable" without making
/// one real timestamp indistinguishable from a broken one.
///
/// Orderability is derived from the stored raw string rather than
/// carried in its own column. The raw string is already stored
/// verbatim, so it is the source of truth for whether a stored record
/// could be ordered, and no schema change is needed to ask.
fn normalize_timestamp(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.timestamp_micros())
}

/// Turn a match-syntax failure into a refusal that says so.
///
/// An unparseable query returning an empty result would tell a caller
/// their term is absent from the corpus when in fact nothing was ever
/// searched, which is the worst answer of the three available.
fn malformed_query(err: rusqlite::Error) -> GatewayError {
    GatewayError::Config(format!(
        "the search query is not valid match syntax and was not run: {err}"
    ))
}

/// Whether this is the natural key refusing a duplicate, as opposed
/// to any other database failure.
fn is_primary_key_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// How many stored content blocks the flattened body does not
/// represent.
///
/// Blocks of type `text` are what the flattened body is made of;
/// everything else, a tool call, a tool result, a thinking block, is
/// stored and not shown. Counting them is a read, not a parse of the
/// union: only each block's `type` is inspected, and an unreadable or
/// unexpected shape counts as nothing rather than failing a view.
fn unrendered_block_count(content_json: &str) -> u64 {
    let Ok(blocks) = serde_json::from_str::<Vec<serde_json::Value>>(content_json) else {
        return 0;
    };
    blocks
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) != Some("text"))
        .count() as u64
}

/// Decide what writing this record would be, from the stored raw
/// timestamp and the incoming one.
///
/// One function for every record type. Conversations and projects do
/// not each carry their own copy of this reasoning, so they cannot
/// drift apart and a change to the rule reaches both.
fn decide_outcome(stored_raw: Option<&str>, incoming_raw: &str) -> UpsertOutcome {
    match stored_raw {
        None => UpsertOutcome::Added,
        Some(stored_raw) => match (
            normalize_timestamp(incoming_raw),
            normalize_timestamp(stored_raw),
        ) {
            (Some(incoming), Some(stored)) if incoming > stored => UpsertOutcome::Updated,
            (Some(_), Some(_)) => UpsertOutcome::Unchanged,
            // No ordering evidence on one side or the other. Nothing is
            // written, and the caller is told which it was.
            _ => UpsertOutcome::Unorderable,
        },
    }
}

/// The tally an import reports. Counts and nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportCounts {
    pub added: u64,
    pub updated: u64,
    pub unchanged: u64,
    /// Records left alone because no ordering evidence was available.
    /// A whole archive landing here is a format break, not a quiet
    /// no-op.
    pub unorderable: u64,
    /// Records that did not fit the structs and were skipped.
    pub skipped: u64,
}

impl ImportCounts {
    /// Fold one outcome into the tally.
    pub fn record(&mut self, outcome: UpsertOutcome) {
        match outcome {
            UpsertOutcome::Added => self.added += 1,
            UpsertOutcome::Updated => self.updated += 1,
            UpsertOutcome::Unchanged => self.unchanged += 1,
            UpsertOutcome::Unorderable => self.unorderable += 1,
        }
    }
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

/// Where a search hit came from.
///
/// The three kinds the index covers, which are the three the gate
/// covers: attachment text and project-document text are conversation
/// content that arrived as a file, so they are searched and gated
/// exactly like a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKind {
    Message,
    Attachment,
    ProjectDocument,
}

impl SearchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Attachment => "attachment",
            Self::ProjectDocument => "project_document",
        }
    }
}

/// One search hit. Carries content, which is why the tool that returns
/// it is gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub kind: SearchKind,
    pub source_id: String,
    /// The conversation a message or attachment belongs to. Absent for
    /// a project document, which belongs to a project instead.
    pub conversation_uuid: Option<String>,
    pub project_uuid: Option<String>,
    /// The message, attachment, or document the hit is in.
    pub owner_uuid: String,
    /// The matching text with its surroundings.
    pub snippet: String,
}

/// One source as the archive list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceView {
    pub id: String,
    pub provider: String,
    pub source_account: String,
    pub archive_sha256: String,
    pub imported_at: String,
    pub sealed: bool,
    pub counts: StoredCounts,
}

/// One row of the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRow {
    pub conversation_uuid: String,
    /// Empty is a real value: archives carry untitled conversations,
    /// so a view falls back to the uuid rather than treating this as
    /// missing.
    pub title: String,
    pub updated_at_raw: String,
    pub message_count: u64,
}

/// One conversation as the detail view shows it.
///
/// A projection, not the record. The stored content blocks are not
/// here: the view renders the flattened body and attachment text, and
/// says how many blocks it is not showing. Walking the block union
/// would mean teaching the view a shape the store deliberately never
/// parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationDetail {
    pub conversation_uuid: String,
    pub title: String,
    pub summary: String,
    pub created_at_raw: String,
    pub updated_at_raw: String,
    pub messages: Vec<MessageView>,
}

/// One message as the detail view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub message_uuid: String,
    pub sender: String,
    /// The flattened body. What the view renders and what search
    /// covers.
    pub text: String,
    pub created_at_raw: String,
    pub attachments: Vec<AttachmentView>,
    /// Stored content blocks the flattened body does not represent:
    /// everything whose type is not `text`. The view states this count
    /// rather than rendering the blocks, which is how a projection
    /// admits to being one.
    pub unrendered_blocks: u64,
}

/// One attachment as the detail view shows it. Its extracted text is
/// message content that arrived as a file, so the view renders it like
/// any other message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentView {
    pub file_name: String,
    pub extracted_content: String,
}

/// What a source holds. Counts and nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoredCounts {
    pub conversations: u64,
    pub messages: u64,
    pub projects: u64,
    pub project_docs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imported_format::{ExportConversation, ExportProject};
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
    fn an_unorderable_timestamp_reports_unorderable_rather_than_unchanged() {
        // The distinction that makes a format break visible. Both
        // outcomes write nothing; only one of them says a comparison
        // happened.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(&labels, &conversation("c1", "not a timestamp", &["m1"]))
            .unwrap();

        // Unparseable on both sides.
        assert_eq!(
            s.upsert_conversation(&labels, &conversation("c1", "also not one", &["m2"]))
                .unwrap(),
            UpsertOutcome::Unorderable
        );
        // Unparseable on the stored side only: still no evidence.
        assert_eq!(
            s.upsert_conversation(
                &labels,
                &conversation("c1", "2026-09-09T00:00:00Z", &["m3"])
            )
            .unwrap(),
            UpsertOutcome::Unorderable
        );
        // Nothing was written by either.
        let surviving: String = s
            .conn
            .query_row(
                "SELECT message_uuid FROM imported_message WHERE conversation_uuid = 'c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(surviving, "m1");
    }

    #[test]
    fn the_unix_epoch_is_a_real_timestamp_not_an_unparseable_one() {
        // Why orderability is not a sentinel value: this parses, and
        // yields the same number a sentinel would have claimed for a
        // broken string.
        assert_eq!(normalize_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(normalize_timestamp("not a timestamp"), None);
    }

    #[test]
    fn counts_keep_unorderable_apart_from_unchanged() {
        let mut counts = ImportCounts::default();
        counts.record(UpsertOutcome::Added);
        counts.record(UpsertOutcome::Unchanged);
        counts.record(UpsertOutcome::Unorderable);
        counts.record(UpsertOutcome::Unorderable);
        counts.skipped += 1;
        assert_eq!(counts.added, 1);
        assert_eq!(counts.unchanged, 1);
        assert_eq!(counts.unorderable, 2);
        assert_eq!(counts.skipped, 1);
    }

    fn project(uuid: &str, updated_at: &str, docs: &[&str]) -> ExportProject {
        let body = docs
            .iter()
            .map(|d| format!(r#"{{"uuid":"{d}","filename":"{d}.md","content":"{d} body"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{"uuid":"{uuid}","name":"p","updated_at":"{updated_at}",
                 "creator":{{"uuid":"creator-1","full_name":"A Person"}},
                 "docs":[{body}]}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn a_project_is_added_with_its_documents() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        let outcome = s
            .upsert_project(
                &labels,
                &project("p1", "2026-01-02T00:00:00Z", &["d1", "d2"]),
            )
            .unwrap();
        assert_eq!(outcome, UpsertOutcome::Added);
        let counts = s.counts(d.source_id()).unwrap();
        assert_eq!(counts.projects, 1);
        assert_eq!(counts.project_docs, 2);
    }

    #[test]
    fn a_creator_name_never_reaches_the_store() {
        // The archive carries it; the parsed struct has no field for
        // it, so the exclusion holds by construction rather than by
        // the insert site remembering.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_project(&labels, &project("p1", "2026-01-02T00:00:00Z", &["d1"]))
            .unwrap();

        let stored_uuid: String = s
            .conn
            .query_row("SELECT creator_uuid FROM imported_project", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored_uuid, "creator-1");

        // The strong form: the name is absent from the stored bytes,
        // not merely from a column someone remembered to leave out.
        let stored: String = s
            .conn
            .query_row(
                "SELECT group_concat(
                     project_uuid || '|' || name || '|' || description || '|' ||
                     prompt_template || '|' || creator_uuid, char(10))
                 FROM imported_project",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !stored.contains("A Person"),
            "the creator name reached the store: {stored}"
        );
    }

    #[test]
    fn a_newer_project_replaces_its_documents_wholesale() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_project(
            &labels,
            &project("p1", "2026-01-02T00:00:00Z", &["d1", "d2", "d3"]),
        )
        .unwrap();
        assert_eq!(s.counts(d.source_id()).unwrap().project_docs, 3);

        let outcome = s
            .upsert_project(&labels, &project("p1", "2026-01-03T00:00:00Z", &["d2"]))
            .unwrap();
        assert_eq!(outcome, UpsertOutcome::Updated);
        assert_eq!(
            s.counts(d.source_id()).unwrap().project_docs,
            1,
            "documents dropped from the newer snapshot are gone, not merged"
        );
        let surviving: String = s
            .conn
            .query_row("SELECT doc_uuid FROM imported_project_doc", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(surviving, "d2");
    }

    #[test]
    fn projects_inherit_the_ordering_decision() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_project(&labels, &project("p1", "2026-01-05T00:00:00Z", &["d1"]))
            .unwrap();
        assert_eq!(
            s.upsert_project(&labels, &project("p1", "2026-01-01T00:00:00Z", &["x"]))
                .unwrap(),
            UpsertOutcome::Unchanged
        );
        assert_eq!(
            s.upsert_project(&labels, &project("p1", "not a timestamp", &["x"]))
                .unwrap(),
            UpsertOutcome::Unorderable
        );
    }

    #[test]
    fn projects_inherit_the_provenance_refusal() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let blank = SourceLabels {
            source_id: d.source_id().into(),
            provider: Provider::Anthropic,
            source_account: "  ".into(),
        };
        let err = s
            .upsert_project(&blank, &project("p1", "2026-01-02T00:00:00Z", &["d1"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("source_account"), "{err}");
    }

    /// A conversation whose messages carry blocks beyond plain text,
    /// so the projection has something to declare it is not showing.
    fn conversation_with_blocks(uuid: &str, updated_at: &str) -> ExportConversation {
        let json = format!(
            r#"{{"uuid":"{uuid}","name":"titled","summary":"a summary",
                 "created_at":"2026-01-01T00:00:00Z","updated_at":"{updated_at}",
                 "chat_messages":[
                   {{"uuid":"m1","sender":"human","text":"plain",
                     "created_at":"2026-01-01T00:00:00Z",
                     "content":[{{"type":"text","text":"plain"}}]}},
                   {{"uuid":"m2","sender":"assistant","text":"answer",
                     "created_at":"2026-01-01T00:00:01Z",
                     "attachments":[{{"file_name":"a.txt","file_size":3,
                                      "file_type":"text/plain",
                                      "extracted_content":"attached body"}}],
                     "content":[{{"type":"thinking","thinking":"..."}},
                                {{"type":"tool_use","name":"x"}},
                                {{"type":"text","text":"answer"}}]}}]}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    /// A conversation whose message, attachment, and a sibling
    /// project document each carry a findable phrase.
    fn searchable(uuid: &str, updated_at: &str, phrase: &str) -> ExportConversation {
        let json = format!(
            r#"{{"uuid":"{uuid}","name":"t","updated_at":"{updated_at}",
                 "chat_messages":[{{"uuid":"m-{uuid}","sender":"human",
                   "text":"a message about {phrase} and other things",
                   "attachments":[{{"file_name":"a.txt","file_size":9,
                     "file_type":"text/plain",
                     "extracted_content":"an attachment about {phrase} too"}}]}}]}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn search_covers_message_attachment_and_document_text() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &searchable("c1", "2026-01-02T00:00:00Z", "borogove"),
        )
        .unwrap();
        let project: ExportProject = serde_json::from_str(
            r#"{"uuid":"p1","name":"p","updated_at":"2026-01-02T00:00:00Z",
                "docs":[{"uuid":"d1","filename":"n.md","content":"a document about borogove"}]}"#,
        )
        .unwrap();
        s.upsert_project(&labels, &project).unwrap();

        let hits = s.search(d.source_id(), "borogove", 20).unwrap();
        let kinds: std::collections::BTreeSet<&str> =
            hits.iter().map(|h| h.kind.as_str()).collect();
        assert!(kinds.contains("message"), "{kinds:?}");
        assert!(kinds.contains("attachment"), "{kinds:?}");
        assert!(kinds.contains("project_document"), "{kinds:?}");
        assert!(hits.iter().all(|h| h.snippet.contains("borogove")));
    }

    #[test]
    fn search_indexes_nothing_beyond_those_three() {
        // Content blocks are stored verbatim and never parsed for
        // meaning, so a term that appears only inside a block must not
        // be findable. Indexing them would make the search surface
        // wider than the gate that covers it.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        let with_block: ExportConversation = serde_json::from_str(
            r#"{"uuid":"c1","name":"t","updated_at":"2026-01-02T00:00:00Z",
                "chat_messages":[{"uuid":"m1","sender":"assistant","text":"plain body",
                  "content":[{"type":"tool_use","name":"x",
                              "input":{"query":"slithytoves"}}]}]}"#,
        )
        .unwrap();
        s.upsert_conversation(&labels, &with_block).unwrap();

        // The block text is stored...
        let detail = s.conversation_detail(d.source_id(), "c1").unwrap().unwrap();
        assert_eq!(detail.messages[0].unrendered_blocks, 1);
        // ...and is not findable.
        assert!(
            s.search(d.source_id(), "slithytoves", 20)
                .unwrap()
                .is_empty()
        );
        // The flattened body is.
        assert!(!s.search(d.source_id(), "plain", 20).unwrap().is_empty());
    }

    #[test]
    fn replaced_text_becomes_unfindable() {
        // The index has to follow wholesale replacement. A snapshot
        // that drops a message leaves the store without it, and an
        // index still carrying its terms would answer for a record
        // that no longer exists in any archive.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &searchable("c1", "2026-01-02T00:00:00Z", "jabberwock"),
        )
        .unwrap();
        assert!(
            !s.search(d.source_id(), "jabberwock", 20)
                .unwrap()
                .is_empty()
        );

        // A newer snapshot of the same conversation, without the term.
        s.upsert_conversation(
            &labels,
            &searchable("c1", "2026-01-03T00:00:00Z", "bandersnatch"),
        )
        .unwrap();
        assert!(
            s.search(d.source_id(), "jabberwock", 20)
                .unwrap()
                .is_empty(),
            "the replaced message text is still findable"
        );
        assert!(
            !s.search(d.source_id(), "bandersnatch", 20)
                .unwrap()
                .is_empty(),
            "the replacing text is not findable"
        );
    }

    #[test]
    fn a_search_is_scoped_to_one_source() {
        let (mut s, _, _t) = store();
        let a = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        s.upsert_conversation(
            &labels_for(&a, "acct-1"),
            &searchable("c1", "2026-01-02T00:00:00Z", "mimsy"),
        )
        .unwrap();
        let b = s.begin_import(&decl("acct-2", "hash-b", false)).unwrap();
        s.upsert_conversation(
            &labels_for(&b, "acct-2"),
            &searchable("c2", "2026-01-02T00:00:00Z", "mimsy"),
        )
        .unwrap();

        // Two datasets, and nothing joins across them.
        let hits = s.search(a.source_id(), "mimsy", 20).unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.source_id == a.source_id()));
    }

    #[test]
    fn an_unparseable_query_refuses_rather_than_answering_empty() {
        // An empty result would say the term is absent. It is not: the
        // query never ran.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let err = s
            .search(d.source_id(), "\"unclosed", 20)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid match syntax"), "{err}");
        assert!(err.contains("was not run"), "{err}");
        // An empty query is not an error, just nothing to ask.
        assert!(s.search(d.source_id(), "   ", 20).unwrap().is_empty());
    }

    #[test]
    fn the_archive_list_shows_each_source_with_what_it_holds() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", true)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &conversation_with_blocks("c1", "2026-01-02T00:00:00Z"),
        )
        .unwrap();

        let views = s.source_views().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].source_account, "acct-1");
        assert!(views[0].sealed);
        assert_eq!(views[0].counts.conversations, 1);
        assert_eq!(views[0].counts.messages, 2);
    }

    #[test]
    fn the_conversation_list_orders_by_the_normalized_timestamp() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        // Distinct message uuids across conversations, as a real
        // archive has: the message key is (source_account,
        // message_uuid), account-wide rather than per conversation.
        for (uuid, stamp) in [
            ("older", "2026-01-01T00:00:00Z"),
            ("newest", "2026-03-01T00:00:00Z"),
            ("middle", "2026-02-01T00:00:00Z"),
        ] {
            let message = format!("m-{uuid}");
            s.upsert_conversation(&labels, &conversation(uuid, stamp, &[&message]))
                .unwrap();
        }
        let rows = s.conversation_rows(d.source_id(), 10).unwrap();
        let order: Vec<&str> = rows.iter().map(|r| r.conversation_uuid.as_str()).collect();
        assert_eq!(order, ["newest", "middle", "older"]);
        assert!(rows.iter().all(|r| r.message_count == 1));
    }

    #[test]
    fn the_detail_view_projects_text_and_attachments_and_counts_the_rest() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &conversation_with_blocks("c1", "2026-01-02T00:00:00Z"),
        )
        .unwrap();

        let detail = s
            .conversation_detail(d.source_id(), "c1")
            .unwrap()
            .expect("the conversation is stored");
        assert_eq!(detail.title, "titled");
        assert_eq!(detail.messages.len(), 2);

        // A message of plain text alone has nothing unrendered.
        assert_eq!(detail.messages[0].text, "plain");
        assert_eq!(detail.messages[0].unrendered_blocks, 0);
        assert!(detail.messages[0].attachments.is_empty());

        // The second carries a thinking block and a tool call the
        // flattened body does not represent.
        assert_eq!(detail.messages[1].text, "answer");
        assert_eq!(detail.messages[1].unrendered_blocks, 2);
        assert_eq!(detail.messages[1].attachments.len(), 1);
        assert_eq!(
            detail.messages[1].attachments[0].extracted_content,
            "attached body"
        );
    }

    #[test]
    fn the_detail_view_carries_no_content_blocks() {
        // The projection must not smuggle the union through. If a
        // block's text appeared here, the view would be rendering a
        // shape the store deliberately never parses.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");
        s.upsert_conversation(
            &labels,
            &conversation_with_blocks("c1", "2026-01-02T00:00:00Z"),
        )
        .unwrap();
        let detail = s.conversation_detail(d.source_id(), "c1").unwrap().unwrap();
        let rendered = format!("{detail:?}");
        assert!(!rendered.contains("thinking"), "{rendered}");
        assert!(!rendered.contains("tool_use"), "{rendered}");
    }

    #[test]
    fn a_duplicate_message_uuid_aborts_and_names_both_conversations() {
        // The natural key is account-wide. A message in two
        // conversations has no correct silent resolution, so the
        // import stops and says exactly what collided.
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        let labels = labels_for(&d, "acct-1");

        s.upsert_conversation(
            &labels,
            &conversation("first", "2026-01-01T00:00:00Z", &["shared"]),
        )
        .unwrap();
        let err = s
            .upsert_conversation(
                &labels,
                &conversation("second", "2026-01-02T00:00:00Z", &["shared"]),
            )
            .unwrap_err();

        match &err {
            GatewayError::DuplicateMessageUuid {
                source_account,
                message_uuid,
                stored_conversation,
                incoming_conversation,
            } => {
                assert_eq!(source_account, "acct-1");
                assert_eq!(message_uuid, "shared");
                assert_eq!(stored_conversation, "first");
                assert_eq!(incoming_conversation, "second");
            }
            other => panic!("expected DuplicateMessageUuid, got {other:?}"),
        }

        let text = err.to_string();
        assert!(text.contains("shared"), "names the message: {text}");
        assert!(
            text.contains("first") && text.contains("second"),
            "names both: {text}"
        );
        assert!(text.contains("remain"), "says what survives: {text}");

        // The conversation that imported before the collision stands.
        assert_eq!(s.counts(d.source_id()).unwrap().conversations, 1);
        assert_eq!(s.counts(d.source_id()).unwrap().messages, 1);
        // The colliding one wrote nothing.
        assert!(
            s.conversation_detail(d.source_id(), "second")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_absent_source_or_conversation_reads_as_none() {
        let (mut s, _, _t) = store();
        let d = s.begin_import(&decl("acct-1", "hash-a", false)).unwrap();
        assert!(
            s.conversation_detail("no-such-source", "c1")
                .unwrap()
                .is_none()
        );
        assert!(
            s.conversation_detail(d.source_id(), "no-such-conversation")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unreadable_content_counts_as_nothing_rather_than_failing_a_view() {
        assert_eq!(unrendered_block_count("not json"), 0);
        assert_eq!(unrendered_block_count("[]"), 0);
        assert_eq!(unrendered_block_count(r#"[{"no_type":1}]"#), 1);
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
    fn the_fts_migration_reaches_rows_that_were_written_before_it() {
        // The exact gap the trigger tests could not see. Those write a
        // row and find it, which exercises the insert trigger; the
        // trigger fires on writes that happen after it exists. A store
        // that already held rows when the FTS migration ran came out of
        // it with empty indexes and no error, and every search over
        // that corpus returned nothing -- indistinguishable, to the
        // operator and to the agent, from a corpus not containing the
        // term.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("imported.db");
        let mut conn = Connection::open(&path).unwrap();

        // Everything up to but not including the FTS migration: the
        // state a store reached by importing before that shipped.
        let applied = crate::migrate::apply(&mut conn, &MIGRATIONS[..FTS_MIGRATION_INDEX]).unwrap();
        assert_eq!(applied, FTS_MIGRATION_INDEX);
        let fts_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'imported_message_fts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            fts_tables, 0,
            "the index must not exist yet, or this proves nothing",
        );

        conn.execute_batch(
            "INSERT INTO import_source
                 (id, provider, source_account, archive_sha256, imported_at, sealed)
             VALUES ('src-1', 'anthropic', 'acct-1', 'hash', '2026-01-01T00:00:00Z', 0);

             INSERT INTO imported_conversation
                 (source_id, provider, source_account, conversation_uuid, title, summary,
                  created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
             VALUES ('src-1','anthropic','acct-1','c1','t','',
                     '2026-01-01T00:00:00Z', 0, '2026-01-01T00:00:00Z', 0);

             INSERT INTO imported_message
                 (source_id, provider, source_account, conversation_uuid, message_uuid,
                  ordinal, sender, text, content_json,
                  created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
             VALUES ('src-1','anthropic','acct-1','c1','m1',0,'human',
                     'a message about frumious things','[]',
                     '2026-01-01T00:00:00Z', 0, '2026-01-01T00:00:00Z', 0);

             INSERT INTO imported_attachment
                 (source_id, provider, source_account, message_uuid, ordinal,
                  file_name, file_size, file_type, extracted_content)
             VALUES ('src-1','anthropic','acct-1','m1',0,'notes.txt',10,'text/plain',
                     'an attachment mentioning brillig');

             INSERT INTO imported_project
                 (source_id, provider, source_account, project_uuid, name, description,
                  prompt_template, is_private, is_starter_project, creator_uuid,
                  created_at_raw, created_at_epoch, updated_at_raw, updated_at_epoch)
             VALUES ('src-1','anthropic','acct-1','p1','proj','','',1,0,'creator-1',
                     '2026-01-01T00:00:00Z', 0, '2026-01-01T00:00:00Z', 0);

             INSERT INTO imported_project_doc
                 (source_id, provider, source_account, project_uuid, doc_uuid, ordinal,
                  filename, content, created_at_raw, created_at_epoch)
             VALUES ('src-1','anthropic','acct-1','p1','d1',0,'doc.md',
                     'a document about slithy toves','2026-01-01T00:00:00Z', 0);",
        )
        .unwrap();
        drop(conn);

        // Opening applies the FTS migration and the backfill after it.
        let (store, applied) = ImportStore::open(&path).unwrap();
        assert_eq!(
            applied,
            MIGRATIONS.len() - FTS_MIGRATION_INDEX,
            "the FTS migration and its backfill both ran",
        );

        for term in ["frumious", "brillig", "slithy"] {
            let hits = store.search("src-1", term, 10).unwrap();
            assert!(
                !hits.is_empty(),
                "'{term}' was written before the index existed and must still be findable; \
                 an index built only by triggers never sees it",
            );
        }
    }

    #[test]
    fn a_missing_source_reads_as_absent_rather_than_erroring() {
        let (s, _, _t) = store();
        assert!(s.source(Provider::Anthropic, "nobody").unwrap().is_none());
    }
}
