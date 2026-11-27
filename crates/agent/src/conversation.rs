use serde::{Deserialize, Serialize};
use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog, ToolCallRecord};

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    /// Tool call ID (for tool results)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool name (for tool results — needed by Gemini's functionResponse)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Tool calls requested by the assistant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallRequest>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
    /// A harness-controlled summary of content the context engine
    /// trimmed from the conversation
    /// history. Provider adapters in `crate::llm` map this to the
    /// provider's `system` role with content wrapped in
    /// [`COMPACTION_FENCE_OPEN`] / [`COMPACTION_FENCE_CLOSE`]. The
    /// default system prompt instructs the model to treat the
    /// fenced block as facts the harness recorded, not as new
    /// instructions from any user.
    Compaction,
}

/// Opening tag for the compaction fence wrapped around
/// [`Role::Compaction`] content when sent to a provider.
pub const COMPACTION_FENCE_OPEN: &str = "<|compaction|>";

/// Closing tag for the compaction fence.
pub const COMPACTION_FENCE_CLOSE: &str = "<|/compaction|>";

/// `content` with every compaction fence tag in it broken, so text
/// that did not come from the harness cannot open or close a fence.
///
/// The default system prompt tells the model that a fenced block is
/// the harness's record of earlier turns. A tool result, an inbound
/// message, a model reply or a summary that carried the tag itself
/// would be read as that record, so every message that enters the
/// conversation passes through here first, and the only fence the
/// model sees is the one a provider adapter wraps around a
/// [`Role::Compaction`] message. The tag is matched without regard
/// to ASCII case and a space is written after its `<`. No tag can
/// come out that did not go in: the characters after a `<|` that is
/// left alone are unchanged, since neither tag's remainder holds a
/// `<`.
///
/// The system message is not passed through: it is the operator's
/// prompt, which names the tags, and the skill bodies spliced into
/// it, which [`crate::skill::envelope_collision_check`] refuses when
/// they carry a tag.
#[allow(
    clippy::string_slice,
    reason = "every offset is at a `<` or just after one, an ASCII byte, so on a char boundary"
)]
pub fn without_compaction_fence(content: &str) -> std::borrow::Cow<'_, str> {
    if !content.contains("<|") {
        return std::borrow::Cow::Borrowed(content);
    }
    // Lowercasing ASCII keeps every byte offset.
    let folded = content.to_ascii_lowercase();
    let mut out = String::new();
    let mut from = 0;
    for (at, _) in folded.match_indices("<|") {
        let rest = &folded[at + 2..];
        if rest.starts_with("compaction|>") || rest.starts_with("/compaction|>") {
            out.push_str(&content[from..=at]);
            out.push(' ');
            from = at + 1;
        }
    }
    if from == 0 {
        return std::borrow::Cow::Borrowed(content);
    }
    out.push_str(&content[from..]);
    std::borrow::Cow::Owned(out)
}

/// Whether `text` carries a compaction fence tag, in any ASCII case.
pub fn carries_compaction_fence(text: &str) -> bool {
    matches!(without_compaction_fence(text), std::borrow::Cow::Owned(_))
}

/// A tool call request from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Manages conversation history for an agent session.
///
/// `Clone` is used by [`crate::runtime::Agent::verify`] to take a
/// snapshot of the conversation at a particular point in the
/// session-log replay so the verifier can run a dry-run fit() over
/// the snapshot without mutating the live conversation.
#[derive(Clone)]
pub struct Conversation {
    messages: Vec<Message>,
    /// Approximate token budget. When exceeded, older messages are compacted.
    token_budget: usize,
}

impl Conversation {
    pub fn new(token_budget: usize) -> Self {
        Self {
            messages: Vec::new(),
            token_budget,
        }
    }

    /// Set the system prompt. Replaces any existing system message.
    pub fn set_system_prompt(&mut self, prompt: &str) {
        // Remove existing system message if any
        self.messages.retain(|m| m.role != Role::System);
        // Insert at the front
        self.messages.insert(
            0,
            Message {
                role: Role::System,
                content: prompt.to_string(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
        );
    }

    /// Add a user message.
    pub fn add_user_message(&mut self, content: &str) {
        self.messages.push(Message {
            role: Role::User,
            content: without_compaction_fence(content).into_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        });
    }

    /// Add an assistant message (text response).
    pub fn add_assistant_message(&mut self, content: &str) {
        self.messages.push(Message {
            role: Role::Assistant,
            content: without_compaction_fence(content).into_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        });
    }

    /// Add an assistant message with tool calls.
    pub fn add_assistant_tool_calls(&mut self, tool_calls: Vec<ToolCallRequest>) {
        self.messages.push(Message {
            role: Role::Assistant,
            content: String::new(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Some(tool_calls),
        });
    }

    /// Add a tool result.
    pub fn add_tool_result(&mut self, tool_call_id: &str, tool_name: &str, result: &str) {
        self.messages.push(Message {
            role: Role::Tool,
            content: without_compaction_fence(result).into_owned(),
            tool_call_id: Some(tool_call_id.to_string()),
            tool_name: Some(tool_name.to_string()),
            tool_calls: None,
        });
    }

    /// Get all messages for sending to the LLM.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Approximate token count (4 chars ≈ 1 token).
    pub fn approx_tokens(&self) -> usize {
        self.messages.iter().map(|m| m.content.len() / 4 + 1).sum()
    }

    /// Whether the conversation exceeds the token budget.
    pub fn over_budget(&self) -> bool {
        self.approx_tokens() > self.token_budget
    }

    /// Compact the conversation by removing older non-system messages.
    /// Keeps the system prompt and the most recent messages.
    pub fn compact(&mut self) {
        if !self.over_budget() {
            return;
        }

        let system: Vec<Message> = self
            .messages
            .iter()
            .filter(|m| m.role == Role::System)
            .cloned()
            .collect();

        let non_system: Vec<Message> = self
            .messages
            .iter()
            .filter(|m| m.role != Role::System)
            .cloned()
            .collect();

        // Keep the most recent half of non-system messages
        let keep = non_system.len() / 2;
        let recent: Vec<Message> = non_system
            .into_iter()
            .rev()
            .take(keep.max(2))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        self.messages = system;
        self.messages.extend(recent);
    }

    /// Total message count.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the conversation is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Insert a message at the given index, shifting later
    /// messages right. Out-of-range indices are clamped to the
    /// end. Used by [`crate::context::ContextEngine::fit`] to
    /// inject a [`Role::Compaction`] summary at position 1,
    /// immediately after the system prompt.
    pub fn insert_at(&mut self, idx: usize, mut message: Message) {
        if message.role != Role::System {
            message.content = without_compaction_fence(&message.content).into_owned();
        }
        let pos = idx.min(self.messages.len());
        self.messages.insert(pos, message);
    }

    /// Remove every message of the given role. Used by
    /// [`crate::context::ContextEngine::fit`] to clear stale
    /// [`Role::Compaction`] messages before injecting a fresh one.
    pub fn remove_role(&mut self, role: Role) {
        self.messages.retain(|m| m.role != role);
    }

    /// Replace the `content` of one message in place. Used by
    /// [`crate::context::ContextEngine::fit`] to swap a trimmed-out
    /// message body for a `[trimmed: N bytes]` placeholder while
    /// preserving the message's role, tool_call_id, tool_name, and
    /// tool_calls fields. Out-of-range indices are silently ignored.
    pub fn replace_content(&mut self, idx: usize, new_content: String) {
        if let Some(msg) = self.messages.get_mut(idx) {
            msg.content = if msg.role == Role::System {
                new_content
            } else {
                without_compaction_fence(&new_content).into_owned()
            };
        }
    }

    /// Replay session events into the conversation. Used at wake to
    /// reconstruct an in-memory conversation from a durable session
    /// log.
    ///
    /// Variants that participate in the LLM-visible conversation
    /// projection are replayed:
    ///
    /// - [`SessionEvent::SystemPromptSet`] → replaces [`Role::System`] in place
    /// - [`SessionEvent::UserMessage`] → [`Role::User`]
    /// - [`SessionEvent::AssistantMessage`] → [`Role::Assistant`]
    /// - [`SessionEvent::AssistantToolCalls`] → [`Role::Assistant`] with `tool_calls`
    /// - [`SessionEvent::ToolResult`] → [`Role::Tool`]
    ///
    /// Other variants (LlmRequest, LlmResponse, PermissionDenied,
    /// Compaction, Attestation, SubagentSpawned, SubagentResult,
    /// AuditLegacy) are skipped; they're not part of the LLM context,
    /// just the audit trail.
    ///
    /// Callers may set an initial system prompt via
    /// [`Self::set_system_prompt`] before calling this; any
    /// `SystemPromptSet` event encountered during replay will
    /// overwrite it. The most recent recorded prompt wins.
    pub fn replay_from_log(
        &mut self,
        log: &dyn SessionLog,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<(), wirken_audit::AuditError> {
        let rows = log.get_since(handle, 0)?;
        for row in rows {
            match row.event {
                SessionEvent::SystemPromptSet { content, .. } => {
                    self.set_system_prompt(&content);
                }
                SessionEvent::UserMessage { content, .. } => {
                    self.add_user_message(&content);
                }
                SessionEvent::AssistantMessage { content, .. } => {
                    self.add_assistant_message(&content);
                }
                SessionEvent::AssistantToolCalls { calls, .. } => {
                    self.add_assistant_tool_calls(records_to_calls(calls));
                }
                SessionEvent::ToolResult {
                    call_id,
                    tool_name,
                    output,
                    ..
                } => {
                    self.add_tool_result(&call_id, &tool_name, &output);
                }
                _ => {
                    // Other variants are not part of the LLM-visible
                    // conversation projection.
                }
            }
        }
        Ok(())
    }
}

/// Convert wire-format tool call records back into in-process
/// requests. Inverse of `Agent::calls_to_records`.
fn records_to_calls(records: Vec<ToolCallRecord>) -> Vec<ToolCallRequest> {
    records
        .into_iter()
        .map(|r| ToolCallRequest {
            id: r.id,
            name: r.name,
            arguments: r.arguments,
        })
        .collect()
}
