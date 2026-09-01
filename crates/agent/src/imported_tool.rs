//! Imported-archive tools.
//!
//! # The gate is not here
//!
//! `tool_to_action` classifies `read_imported_chat` as
//! [`wirken_gateway::permissions::Action::ImportedChatRead`], which is
//! Tier 3, keyed by the source read from. The runtime's tier gate runs
//! that classification before dispatch reaches this module, and
//! `tool_to_read_sensitivity` marks the same call at the same site, so
//! the read enters the session's observed-sensitivity set through the
//! path every other read uses.
//!
//! Nothing here re-checks either. A tool body that also checked would
//! be a second copy of the rule, and two copies of a rule are one rule
//! and one bug waiting: the copy that is not the one the runtime
//! consults can be wrong for a long time without anything failing.
//! What this module owns is reading the store and putting the read on
//! the hash chain.
//!
//! # What reaches the chain
//!
//! Identifiers and a count. The row says which conversation was read
//! and how many messages came back, never a title and never message
//! text. A reader who needs the content goes through the gate the
//! agent went through.

use std::sync::{Arc, Mutex};

use wirken_audit::{
    ImportedSearchOutcome, OwnSession, SessionEvent, SessionHandle, SessionLog, TrustLevel,
};
use wirken_gateway::imported::ImportStore;

use crate::error::AgentError;
use crate::tool::ToolResult;

/// The store plus this turn's attribution and audit sink.
#[derive(Clone)]
pub struct ImportedContext {
    /// `rusqlite::Connection` is `Send` but not `Sync`, so the store is
    /// shared behind a mutex exactly like the memory store.
    pub store: Arc<Mutex<ImportStore>>,
    /// Attribution built by the runtime from the inbound context,
    /// never from tool arguments, so a model cannot author its own.
    pub agent_id: String,
    pub adapter_id: Option<String>,
    pub sender_id: Option<String>,
    pub log: Arc<dyn SessionLog>,
    pub handle: SessionHandle<OwnSession>,
    /// Key for the search-query digest. `None` when the keychain
    /// could not supply one, in which case the digest is omitted
    /// rather than replaced with an unkeyed one, which would put a
    /// recoverable form of the query on the row.
    pub search_digest_key: Option<Vec<u8>>,
}

impl ImportedContext {
    /// Put one search attempt on the chain.
    ///
    /// Called on every path out of the search tool, including the ones
    /// that return nothing and the ones that refuse, so the trail
    /// records attempts rather than survivors.
    fn record_search(
        &self,
        scope: &Option<String>,
        query: &str,
        outcome: ImportedSearchOutcome,
        match_count: u64,
    ) {
        self.record(SessionEvent::ImportedChatSearched {
            source_id: scope.clone(),
            outcome,
            match_count,
            query_digest: self
                .search_digest_key
                .as_ref()
                .map(|key| wirken_audit::imported_search_digest(key, query)),
            agent_id: self.agent_id.clone(),
            adapter_id: self.adapter_id.clone(),
            sender_id: self.sender_id.clone(),
        });
    }

    fn record(&self, event: SessionEvent) {
        if let Err(e) = self.log.append(&self.handle, TrustLevel::System, event) {
            tracing::warn!("could not record imported-archive event: {e}");
        }
    }
}

/// Dispatch one imported-archive tool call.
pub async fn execute(
    ctx: &ImportedContext,
    tool: &str,
    args: &serde_json::Value,
) -> Result<ToolResult, AgentError> {
    match tool {
        "read_imported_chat" => read_chat(ctx, args),
        "search_imported_chats" => search(ctx, args),
        other => Err(AgentError::ToolNotFound(other.to_string())),
    }
}

fn fail(message: &str) -> ToolResult {
    ToolResult {
        output: message.to_string(),
        success: false,
    }
}

fn read_chat(ctx: &ImportedContext, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
    let Some(source) = args.get("source").and_then(|v| v.as_str()) else {
        return Ok(fail("read_imported_chat needs a 'source' string"));
    };
    let Some(conversation) = args.get("conversation").and_then(|v| v.as_str()) else {
        return Ok(fail("read_imported_chat needs a 'conversation' string"));
    };

    let (source_account, detail) = {
        let store = ctx
            .store
            .lock()
            .map_err(|e| AgentError::Tool(format!("import store lock: {e}")))?;
        let account = store
            .source_account(source)
            .map_err(|e| AgentError::Tool(format!("read_imported_chat: {e}")))?;
        let detail = store
            .conversation_detail(source, conversation)
            .map_err(|e| AgentError::Tool(format!("read_imported_chat: {e}")))?;
        (account, detail)
    };
    let messages = detail.as_ref().map_or(0, |d| d.messages.len() as u64);

    // Emitted whether or not the conversation was found. A read that
    // found nothing still records that the corpus was reached into,
    // and an operator answered a prompt for it either way.
    ctx.record(SessionEvent::ImportedChatRead {
        source_id: source.to_string(),
        source_account,
        conversation_uuid: conversation.to_string(),
        message_count: messages,
        agent_id: ctx.agent_id.clone(),
        adapter_id: ctx.adapter_id.clone(),
        sender_id: ctx.sender_id.clone(),
    });

    let Some(detail) = detail else {
        return Ok(fail(&format!(
            "no conversation '{conversation}' in source '{source}'"
        )));
    };

    Ok(ToolResult {
        output: render(&detail),
        success: true,
    })
}

/// How many hits a search returns when the caller does not say.
const SEARCH_LIMIT: usize = 20;

/// Search imported archives.
///
/// Every attempt that reaches here emits an event, whether it found
/// matches, found none, or was refused. A trail of only the searches
/// that returned something would answer "what was looked for" with a
/// filtered version of the truth, and the thing an auditor most wants
/// to know about a compromised agent is what it went looking for.
///
/// The outcome is on the row alongside the count because the count
/// cannot carry it: a refusal and an empty result both have no
/// matches, and telling them apart is the difference between "the term
/// is not in the corpus" and "nothing was searched".
fn search(ctx: &ImportedContext, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
    // An absent scope is a search of every archive. That is a wider
    // question than a scoped one, and the classifier already asked the
    // operator about it under a key of its own.
    let scope = args
        .get("source")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if query.trim().is_empty() {
        ctx.record_search(&scope, &query, ImportedSearchOutcome::Refused, 0);
        return Ok(fail("search_imported_chats needs a 'query' string"));
    }

    let sources: Vec<String> = {
        let store = ctx
            .store
            .lock()
            .map_err(|e| AgentError::Tool(format!("import store lock: {e}")))?;
        match &scope {
            Some(id) => vec![id.clone()],
            None => store
                .source_views()
                .map_err(|e| AgentError::Tool(format!("search_imported_chats: {e}")))?
                .into_iter()
                .map(|v| v.id)
                .collect(),
        }
    };

    let mut hits = Vec::new();
    for source in &sources {
        let found = {
            let store = ctx
                .store
                .lock()
                .map_err(|e| AgentError::Tool(format!("import store lock: {e}")))?;
            store.search(source, &query, SEARCH_LIMIT)
        };
        match found {
            Ok(found) => hits.extend(found),
            Err(e) => {
                // The query did not run. Recorded as refused, never as
                // empty: empty would report an absence nothing checked.
                ctx.record_search(&scope, &query, ImportedSearchOutcome::Refused, 0);
                return Ok(fail(&format!("search_imported_chats: {e}")));
            }
        }
    }
    hits.truncate(SEARCH_LIMIT);

    let outcome = if hits.is_empty() {
        ImportedSearchOutcome::Empty
    } else {
        ImportedSearchOutcome::Hits
    };
    ctx.record_search(&scope, &query, outcome, hits.len() as u64);

    Ok(ToolResult {
        output: render_hits(&hits, &query),
        success: true,
    })
}

fn render_hits(hits: &[wirken_gateway::imported::SearchHit], query: &str) -> String {
    if hits.is_empty() {
        return format!("No imported content matches {query:?}.");
    }
    let mut out = format!("Imported content matching {query:?}:\n");
    for hit in hits {
        let owner = match (&hit.conversation_uuid, &hit.project_uuid) {
            (Some(c), _) => format!("conversation {c}"),
            (_, Some(p)) => format!("project {p}"),
            _ => "unknown".to_string(),
        };
        out.push_str(&format!(
            "  [{}] source {} {} ({}): {}\n",
            hit.kind.as_str(),
            hit.source_id,
            owner,
            hit.owner_uuid,
            hit.snippet
        ));
    }
    out
}

/// Render a conversation for the model.
///
/// The same projection the web view shows: flattened message text and
/// attachment text, with a count of the stored blocks not rendered.
/// The model is told what it is not being shown, for the same reason a
/// reader is: a short message and a truncated one look alike otherwise.
fn render(detail: &wirken_gateway::imported::ConversationDetail) -> String {
    let mut out = String::new();
    let title = if detail.title.trim().is_empty() {
        detail.conversation_uuid.as_str()
    } else {
        detail.title.as_str()
    };
    out.push_str(&format!("Imported conversation: {title}\n"));
    if !detail.summary.trim().is_empty() {
        out.push_str(&format!("Summary: {}\n", detail.summary));
    }
    out.push('\n');
    for message in &detail.messages {
        // A message the store holds no text for is labelled rather
        // than rendered as a bare sender line. Real archives carry
        // these in quantity, and an empty line reads as a message that
        // said nothing rather than as one whose text was not imported.
        // The label says what the store holds, not what the archive
        // held: those are different claims and only one is checkable
        // from here.
        if message.text.trim().is_empty() {
            out.push_str(&format!(
                "[{}] (no text stored for this message)\n",
                message.sender
            ));
        } else {
            out.push_str(&format!("[{}] {}\n", message.sender, message.text));
        }
        for attachment in &message.attachments {
            let name = if attachment.file_name.trim().is_empty() {
                "unnamed"
            } else {
                attachment.file_name.as_str()
            };
            out.push_str(&format!(
                "  attachment {name}: {}\n",
                attachment.extracted_content
            ));
        }
        if message.unrendered_blocks > 0 {
            out.push_str(&format!(
                "  ({} stored content blocks are not shown)\n",
                message.unrendered_blocks
            ));
        }
    }
    out
}
