//! `wirken import` - bring an assistant data-export archive into the
//! local store.
//!
//! # What this prints
//!
//! Counts and stable identifiers, and nothing else. No conversation
//! title, no message text, and no excerpt of either reaches stdout or
//! the tracing log. The identifiers that do appear are the archive
//! hash, the source account, the source id, and the uuid of a record
//! that had to be skipped.
//!
//! That is not a formatting preference. The whole point of importing an
//! archive into a gated store is that its contents stay behind the
//! gate; a command that echoed titles while importing would leak past
//! the control on the way in.
//!
//! # Why the conversations member is read twice
//!
//! The source account lives inside the archive, on every conversation.
//! A sealed source has to refuse before anything is written, and a
//! decision that arrives half way through a stream has already let
//! writes happen. So the account is established in a pass of its own,
//! the source decision is taken, and only then does the importing pass
//! run. The cost is one extra decompression; the alternative is a
//! refusal that comes too late to mean anything.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, TrustLevel};
use wirken_gateway::imported::{
    ImportCounts, ImportDecision, ImportStore, Provider, SourceDeclaration, SourceLabels,
};
use wirken_gateway::imported_archive::Archive;
use wirken_gateway::imported_format::{
    ParsedConversation, ParsedProject, stream_conversations, stream_projects,
};

use super::config;
use super::webchat::ImportedRoute;

/// The archive members this reads. `users.json` is deliberately absent:
/// it carries names, addresses, and numbers for people beyond the
/// account holder, nothing here needs it, and the account label the
/// natural key wants is already on every conversation.
const CONVERSATIONS_MEMBER: &str = "conversations.json";
const PROJECTS_MEMBER: &str = "projects.json";

/// Session id the import chain is written under. An import is not an
/// agent turn and has no conversation, so it takes a stable name of
/// its own and every import lands on one ordered chain.
const IMPORT_SESSION: &str = "import";

/// Import an archive.
///
/// `sealed` is the operator declaring that this account is closed.
/// Only they know that, so it is a declaration rather than something
/// inferred. A sealed source imports once and refuses afterwards, and
/// there is no unseal.
pub async fn run(archive: &Path, sealed: bool) -> Result<()> {
    if !archive.exists() {
        bail!("archive not found: {}", archive.display());
    }
    if !archive.is_file() {
        bail!("archive is not a file: {}", archive.display());
    }

    let cfg = config();
    // The store lives in the data directory, which may not exist on a
    // machine that has not run the gateway yet. ensure_dirs also lands
    // the 0o700 mode the other stores rely on, so the import store is
    // not the one file created under a looser umask.
    cfg.ensure_dirs()
        .context("Failed to create the data directory")?;
    let db_path = cfg.imported_db_path();
    let (mut store, migrations_applied) =
        ImportStore::open(&db_path).context("Failed to open the imported-archive store")?;

    let archive_sha256 = hash_file(archive).context("Failed to hash the archive")?;
    let mut reader = Archive::open(archive)?;

    if !reader.has_member(CONVERSATIONS_MEMBER) {
        bail!("archive has no {CONVERSATIONS_MEMBER}; it does not look like an export");
    }

    // Pass one: establish the account, so the source decision is taken
    // before any write.
    let source_account = first_account(&mut reader)?;

    let imported_at = chrono::Utc::now().to_rfc3339();
    let decl = SourceDeclaration {
        provider: Provider::Anthropic,
        source_account: source_account.clone(),
        archive_sha256: archive_sha256.clone(),
        imported_at: imported_at.clone(),
        sealed,
    };
    let decision = store.begin_import(&decl)?;

    println!("Import store: {}", db_path.display());
    println!("Migrations applied this run: {migrations_applied}");
    println!("Source: {} account={source_account}", decision.source_id());
    println!("Archive: {archive_sha256}");

    if let ImportDecision::AlreadyCurrent { conversations, .. } = &decision {
        println!("This archive is already imported. Nothing to do.");
        println!("  conversations={conversations}");
        return Ok(());
    }

    let log =
        SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open the session log")?;
    let handle = log.handle_for(SessionId::new(IMPORT_SESSION.to_string()));
    let actor = operator_actor();

    if let Err(e) = log.append(
        &handle,
        TrustLevel::System,
        SessionEvent::ImportStarted {
            source_id: decision.source_id().to_string(),
            provider: Provider::Anthropic.as_str().to_string(),
            source_account: source_account.clone(),
            archive_sha256: archive_sha256.clone(),
            actor: actor.clone(),
        },
    ) {
        tracing::warn!("could not record the import start: {e}");
    }

    let labels = SourceLabels {
        source_id: decision.source_id().to_string(),
        provider: Provider::Anthropic,
        source_account: source_account.clone(),
    };

    // Pass two: the import itself.
    let counts = import_conversations(&mut reader, &mut store, &labels)?;
    let has_projects = reader.has_member(PROJECTS_MEMBER);
    let project_counts = if has_projects {
        import_projects(&mut reader, &mut store, &labels)?
    } else {
        ImportCounts::default()
    };

    store.finish_import(decision.source_id(), &archive_sha256, &imported_at)?;

    let total = combine(counts, project_counts);
    if let Err(e) = log.append(
        &handle,
        TrustLevel::System,
        SessionEvent::ImportCompleted {
            source_id: decision.source_id().to_string(),
            provider: Provider::Anthropic.as_str().to_string(),
            source_account: source_account.clone(),
            archive_sha256: archive_sha256.clone(),
            actor,
            added: total.added,
            updated: total.updated,
            unchanged: total.unchanged,
            unorderable: total.unorderable,
            skipped: total.skipped,
        },
    ) {
        tracing::warn!("could not record the import completion: {e}");
    }

    report("Conversations", counts);
    if has_projects {
        report("Projects", project_counts);
    }
    let stored = store.counts(decision.source_id())?;
    println!(
        "Stored: conversations={} messages={} projects={} project_docs={}",
        stored.conversations, stored.messages, stored.projects, stored.project_docs
    );
    if sealed {
        println!("This source is sealed and will refuse further imports.");
    }
    if total.unorderable > 0 {
        println!(
            "{} records could not be ordered against what is stored and were left alone. \
             A whole archive here means the export's timestamp format has changed.",
            total.unorderable
        );
    }
    Ok(())
}

fn import_conversations(
    reader: &mut Archive,
    store: &mut ImportStore,
    labels: &SourceLabels,
) -> Result<ImportCounts> {
    let mut counts = ImportCounts::default();
    let mut failure: Option<anyhow::Error> = None;
    let member = reader.read_member(CONVERSATIONS_MEMBER)?;
    stream_conversations(member, |parsed| {
        if failure.is_some() {
            return;
        }
        match parsed {
            ParsedConversation::Skipped {
                index,
                uuid,
                reason,
            } => {
                counts.skipped += 1;
                tracing::warn!(
                    "skipping conversation {}: {reason}",
                    uuid.unwrap_or_else(|| format!("at position {index}"))
                );
            }
            ParsedConversation::Ok(conversation) => {
                match store.upsert_conversation(labels, &conversation) {
                    Ok(outcome) => counts.record(outcome),
                    Err(e) => failure = Some(e.into()),
                }
            }
        }
    })
    .context("Failed to read the conversations member")?;
    match failure {
        Some(e) => Err(e),
        None => Ok(counts),
    }
}

fn import_projects(
    reader: &mut Archive,
    store: &mut ImportStore,
    labels: &SourceLabels,
) -> Result<ImportCounts> {
    let mut counts = ImportCounts::default();
    let mut failure: Option<anyhow::Error> = None;
    let member = reader.read_member(PROJECTS_MEMBER)?;
    stream_projects(member, |parsed| {
        if failure.is_some() {
            return;
        }
        match parsed {
            ParsedProject::Skipped {
                index,
                uuid,
                reason,
            } => {
                counts.skipped += 1;
                tracing::warn!(
                    "skipping project {}: {reason}",
                    uuid.unwrap_or_else(|| format!("at position {index}"))
                );
            }
            ParsedProject::Ok(project) => match store.upsert_project(labels, &project) {
                Ok(outcome) => counts.record(outcome),
                Err(e) => failure = Some(e.into()),
            },
        }
    })
    .context("Failed to read the projects member")?;
    match failure {
        Some(e) => Err(e),
        None => Ok(counts),
    }
}

/// Serve one imported-archive read route as JSON.
///
/// Read-only by construction: there is no write route, and this
/// function has no path that mutates. A store failure returns an empty
/// result rather than an error body, matching the session routes,
/// which is what keeps a browser from rendering a database message.
pub(crate) fn read_route_json(
    cfg: &wirken_gateway::config::GatewayConfig,
    route: &ImportedRoute,
) -> String {
    let Ok((store, _)) = ImportStore::open(&cfg.imported_db_path()) else {
        return "[]".to_string();
    };
    match route {
        ImportedRoute::Sources => store
            .source_views()
            .ok()
            .and_then(|views| {
                let rows: Vec<_> = views.iter().map(SourceRow::from).collect();
                serde_json::to_string(&rows).ok()
            })
            .unwrap_or_else(|| "[]".to_string()),
        ImportedRoute::Conversations { source_id } => store
            .conversation_rows(source_id, CONVERSATION_LIST_LIMIT)
            .ok()
            .and_then(|rows| {
                let rows: Vec<_> = rows.iter().map(ConversationListRow::from).collect();
                serde_json::to_string(&rows).ok()
            })
            .unwrap_or_else(|| "[]".to_string()),
        ImportedRoute::Detail {
            source_id,
            conversation_uuid,
        } => store
            .conversation_detail(source_id, conversation_uuid)
            .ok()
            .flatten()
            .and_then(|detail| serde_json::to_string(&DetailBody::from(&detail)).ok())
            .unwrap_or_else(|| "null".to_string()),
    }
}

/// How many conversations one list response carries. A real archive
/// holds thousands, and a browser rendering all of them at once helps
/// nobody; the view pages by source instead.
const CONVERSATION_LIST_LIMIT: usize = 500;

#[derive(serde::Serialize)]
struct SourceRow<'a> {
    id: &'a str,
    provider: &'a str,
    source_account: &'a str,
    archive_sha256: &'a str,
    imported_at: &'a str,
    sealed: bool,
    conversations: u64,
    messages: u64,
    projects: u64,
    project_docs: u64,
}

impl<'a> From<&'a wirken_gateway::imported::SourceView> for SourceRow<'a> {
    fn from(v: &'a wirken_gateway::imported::SourceView) -> Self {
        Self {
            id: &v.id,
            provider: &v.provider,
            source_account: &v.source_account,
            archive_sha256: &v.archive_sha256,
            imported_at: &v.imported_at,
            sealed: v.sealed,
            conversations: v.counts.conversations,
            messages: v.counts.messages,
            projects: v.counts.projects,
            project_docs: v.counts.project_docs,
        }
    }
}

#[derive(serde::Serialize)]
struct ConversationListRow<'a> {
    uuid: &'a str,
    title: &'a str,
    updated_at: &'a str,
    message_count: u64,
}

impl<'a> From<&'a wirken_gateway::imported::ConversationRow> for ConversationListRow<'a> {
    fn from(r: &'a wirken_gateway::imported::ConversationRow) -> Self {
        Self {
            uuid: &r.conversation_uuid,
            title: &r.title,
            updated_at: &r.updated_at_raw,
            message_count: r.message_count,
        }
    }
}

#[derive(serde::Serialize)]
struct DetailBody<'a> {
    uuid: &'a str,
    title: &'a str,
    summary: &'a str,
    created_at: &'a str,
    updated_at: &'a str,
    messages: Vec<DetailMessage<'a>>,
}

#[derive(serde::Serialize)]
struct DetailMessage<'a> {
    uuid: &'a str,
    sender: &'a str,
    text: &'a str,
    created_at: &'a str,
    attachments: Vec<DetailAttachment<'a>>,
    /// Stored blocks this projection does not show. The view states
    /// the number rather than pretending the record is all here.
    unrendered_blocks: u64,
}

#[derive(serde::Serialize)]
struct DetailAttachment<'a> {
    file_name: &'a str,
    text: &'a str,
}

impl<'a> From<&'a wirken_gateway::imported::ConversationDetail> for DetailBody<'a> {
    fn from(d: &'a wirken_gateway::imported::ConversationDetail) -> Self {
        Self {
            uuid: &d.conversation_uuid,
            title: &d.title,
            summary: &d.summary,
            created_at: &d.created_at_raw,
            updated_at: &d.updated_at_raw,
            messages: d
                .messages
                .iter()
                .map(|m| DetailMessage {
                    uuid: &m.message_uuid,
                    sender: &m.sender,
                    text: &m.text,
                    created_at: &m.created_at_raw,
                    attachments: m
                        .attachments
                        .iter()
                        .map(|a| DetailAttachment {
                            file_name: &a.file_name,
                            text: &a.extracted_content,
                        })
                        .collect(),
                    unrendered_blocks: m.unrendered_blocks,
                })
                .collect(),
        }
    }
}

fn report(label: &str, counts: ImportCounts) {
    println!(
        "{label}: added={} updated={} unchanged={} unorderable={} skipped={}",
        counts.added, counts.updated, counts.unchanged, counts.unorderable, counts.skipped
    );
}

fn combine(a: ImportCounts, b: ImportCounts) -> ImportCounts {
    ImportCounts {
        added: a.added + b.added,
        updated: a.updated + b.updated,
        unchanged: a.unchanged + b.unchanged,
        unorderable: a.unorderable + b.unorderable,
        skipped: a.skipped + b.skipped,
    }
}

/// The account every conversation in this archive belongs to.
///
/// Taken from the first record that fits. An archive is one account's
/// export, so the first is representative; a record that does not fit
/// cannot name an account and is passed over here, then counted as
/// skipped by the importing pass.
fn first_account(reader: &mut Archive) -> Result<String> {
    let member = reader.read_member(CONVERSATIONS_MEMBER)?;
    let mut account: Option<String> = None;
    stream_conversations(member, |parsed| {
        if account.is_some() {
            return;
        }
        if let ParsedConversation::Ok(conversation) = parsed
            && !conversation.account.uuid.trim().is_empty()
        {
            account = Some(conversation.account.uuid.clone());
        }
    })
    .context("Failed to read the conversations member")?;
    account.ok_or_else(|| {
        anyhow::anyhow!(
            "no conversation in the archive names an account; \
             the account label is half of every natural key"
        )
    })
}

/// The operator label for the audit rows.
///
/// The convention the CLI approval path already uses: the operator's
/// `$USER`, falling back to the literal `cli` so the value is never
/// empty. The surface is carried separately by the event's own name.
fn operator_actor() -> String {
    std::env::var("USER").unwrap_or_else(|_| "cli".to_string())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
