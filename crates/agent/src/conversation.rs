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
    /// Item 4 slice 2 (alpha): a harness-controlled summary of
    /// content the context engine trimmed from the conversation
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
            content: content.to_string(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        });
    }

    /// Add an assistant message (text response).
    pub fn add_assistant_message(&mut self, content: &str) {
        self.messages.push(Message {
            role: Role::Assistant,
            content: content.to_string(),
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
            content: result.to_string(),
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
    /// end. Used by [`crate::context::ContextEngine::fit`] (item 4
    /// slice 2) to inject a [`Role::Compaction`] summary at
    /// position 1, immediately after the system prompt.
    pub fn insert_at(&mut self, idx: usize, message: Message) {
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
            msg.content = new_content;
        }
    }

    /// Replay session events into the conversation. Used by
    /// `Agent::wake` (item 2 slice 2) to reconstruct an in-memory
    /// conversation from a durable session log.
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
    /// AuditLegacy) are skipped — they're not part of the LLM context,
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
                SessionEvent::SystemPromptSet { content } => {
                    self.set_system_prompt(&content);
                }
                SessionEvent::UserMessage { content, .. } => {
                    self.add_user_message(&content);
                }
                SessionEvent::AssistantMessage { content } => {
                    self.add_assistant_message(&content);
                }
                SessionEvent::AssistantToolCalls { calls } => {
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
