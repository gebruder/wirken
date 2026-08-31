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

use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog, TrustLevel};
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
}

impl ImportedContext {
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

    let detail = ctx
        .store
        .lock()
        .map_err(|e| AgentError::Tool(format!("import store lock: {e}")))?
        .conversation_detail(source, conversation)
        .map_err(|e| AgentError::Tool(format!("read_imported_chat: {e}")))?;

    let (source_account, messages) = match &detail {
        Some(d) => (source.to_string(), d.messages.len() as u64),
        None => (source.to_string(), 0),
    };

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
        out.push_str(&format!("[{}] {}\n", message.sender, message.text));
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
