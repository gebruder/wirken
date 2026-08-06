//! Cross-channel memory tools (#64).
//!
//! Three tools over [`wirken_gateway::memory::MemoryStore`]:
//!
//! * `memory_write` — record an entry, stamped with this turn's origin
//!   labels. Same channel by construction; there is no way to write an
//!   entry labelled as another channel.
//! * `memory_read` — read this channel's own entries. No crossing.
//! * `memory_read_channel` — read another channel's entries. A
//!   trust-zone crossing, gated at Tier 3 by `tool_to_action` before
//!   dispatch reaches here.
//!
//! The gate runs in the runtime, not here. What this module owns is
//! that the labels written are the turn's real ones and that both the
//! write and the crossing land on the hash chain.

use std::sync::{Arc, Mutex};

use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog, TrustLevel};
use wirken_gateway::memory::{MemoryStore, OriginLabels};

use crate::error::AgentError;
use crate::tool::ToolResult;

/// How many entries a read returns when the caller does not say.
const DEFAULT_LIMIT: usize = 20;

/// Upper bound on a caller-supplied limit.
const MAX_LIMIT: usize = 200;

/// The store plus this turn's origin labels and audit sink.
#[derive(Clone)]
pub struct MemoryContext {
    /// `rusqlite::Connection` is `Send` but not `Sync`, so the store
    /// is shared behind a mutex exactly like `PermissionStore`.
    pub store: Arc<Mutex<MemoryStore>>,
    /// Labels stamped onto anything written this turn. Built by the
    /// runtime from the inbound context, never from tool arguments,
    /// so a model cannot author its own provenance.
    pub labels: OriginLabels,
    pub log: Arc<dyn SessionLog>,
    pub handle: SessionHandle<OwnSession>,
}

impl MemoryContext {
    fn record(&self, event: SessionEvent) {
        if let Err(e) = self.log.append(&self.handle, TrustLevel::System, event) {
            tracing::warn!("could not record memory event: {e}");
        }
    }
}

/// Dispatch one memory tool call.
pub async fn execute(
    ctx: &MemoryContext,
    tool: &str,
    args: &serde_json::Value,
) -> Result<ToolResult, AgentError> {
    match tool {
        "memory_write" => write(ctx, args),
        "memory_read" => read_same_channel(ctx, args),
        "memory_read_channel" => read_other_channel(ctx, args),
        other => Err(AgentError::ToolNotFound(other.to_string())),
    }
}

fn limit_from(args: &serde_json::Value) -> usize {
    args.get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT)
}

fn write(ctx: &MemoryContext, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
    let Some(content) = args.get("content").and_then(|v| v.as_str()) else {
        return Ok(fail("memory_write needs a 'content' string"));
    };
    // Labels come from the turn, never from `args`. A model that
    // passes a `channel` or `sender_id` argument is ignored.
    let created_at = chrono::Utc::now().to_rfc3339();
    let written = ctx
        .store
        .lock()
        .map_err(|e| AgentError::Tool(format!("memory store lock: {e}")))?
        .write(&ctx.labels, content, &created_at);
    match written {
        Ok(entry_id) => {
            ctx.record(SessionEvent::MemoryEntryWritten {
                entry_id: entry_id.clone(),
                channel: ctx.labels.channel.clone(),
                adapter_id: ctx.labels.adapter_id.clone(),
                sender_id: ctx.labels.sender_id.clone(),
                agent_id: ctx.labels.agent_id.clone(),
                origin_session_id: ctx.labels.origin_session_id.clone(),
            });
            Ok(ToolResult {
                output: format!("recorded on {} as {entry_id}", ctx.labels.channel),
                success: true,
            })
        }
        Err(e) => Ok(fail(&format!("memory_write refused: {e}"))),
    }
}

fn read_same_channel(
    ctx: &MemoryContext,
    args: &serde_json::Value,
) -> Result<ToolResult, AgentError> {
    let entries = ctx
        .store
        .lock()
        .map_err(|e| AgentError::Tool(format!("memory store lock: {e}")))?
        .read_channel(&ctx.labels.agent_id, &ctx.labels.channel, limit_from(args))
        .map_err(|e| AgentError::Tool(format!("memory_read: {e}")))?;
    // No crossing, so no crossing event. The read is already visible
    // as a tool call on the chain.
    Ok(ToolResult {
        output: render(&entries, &ctx.labels.channel),
        success: true,
    })
}

fn read_other_channel(
    ctx: &MemoryContext,
    args: &serde_json::Value,
) -> Result<ToolResult, AgentError> {
    let Some(from) = args.get("channel").and_then(|v| v.as_str()) else {
        return Ok(fail("memory_read_channel needs a 'channel' string"));
    };
    // Reading your own channel through the crossing tool is a
    // mistake, not a crossing. Refuse rather than silently serving it,
    // so the Tier 3 prompt an operator just answered always means what
    // it said.
    if from == ctx.labels.channel {
        return Ok(fail(&format!(
            "'{from}' is this turn's own channel; use memory_read for it"
        )));
    }

    let entries = ctx
        .store
        .lock()
        .map_err(|e| AgentError::Tool(format!("memory store lock: {e}")))?
        .read_channel(&ctx.labels.agent_id, from, limit_from(args))
        .map_err(|e| AgentError::Tool(format!("memory_read_channel: {e}")))?;

    // Emitted whether or not anything came back: zero entries still
    // records that the crossing was made.
    ctx.record(SessionEvent::CrossChannelMemoryRead {
        from_channel: from.to_string(),
        to_channel: ctx.labels.channel.clone(),
        entry_count: entries.len() as u64,
        agent_id: ctx.labels.agent_id.clone(),
        adapter_id: Some(ctx.labels.adapter_id.clone()),
        sender_id: Some(ctx.labels.sender_id.clone()),
    });

    Ok(ToolResult {
        output: render(&entries, from),
        success: true,
    })
}

fn render(entries: &[wirken_gateway::memory::MemoryEntry], channel: &str) -> String {
    if entries.is_empty() {
        return format!("no memory entries on {channel}");
    }
    let mut out = format!("{} entries from {channel}:\n", entries.len());
    for e in entries {
        out.push_str(&format!("- [{}] {}\n", e.created_at, e.content));
    }
    out
}

fn fail(message: &str) -> ToolResult {
    ToolResult {
        output: message.to_string(),
        success: false,
    }
}
