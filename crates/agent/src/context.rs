//! Context engine — fits a [`Conversation`] under the model's
//! token budget before each LLM call.
//!
//! Item 4 of the Managed Agents parity work
//! (`docs/managed-agents-parity.md`). The user-visible problem this
//! solves: context blowups killing sessions. The pre-slice-1
//! [`Conversation::compact`] method dropped the oldest half of
//! non-system messages indiscriminately when over a hardcoded 100k
//! token budget — naive, not configurable, and unaware of tool
//! call/result pairing.
//!
//! ## What slice 1 ships
//!
//! - A [`ContextEngine`] derived from the agent's [`LlmConfig`] that
//!   knows the per-model budget.
//! - A [`ContextEngine::fit`] method that trims the conversation in
//!   place, preferring to drop oldest tool result *content* (not the
//!   message itself — pairing stays intact) before touching user or
//!   assistant text.
//! - A guarantee that the system prompt and the most recent
//!   `min_recent_turns` (default 3) user messages plus everything
//!   after them are never trimmed.
//! - A structured [`SessionEvent::Compaction`] event written to the
//!   session log every time something is trimmed, recording which
//!   conversation positions were touched and how many bytes were
//!   reclaimed. `via_model: false` — slice 1 never invokes an LLM
//!   for compaction.
//! - An [`AgentError::ContextOverflow`] when trimming reaches the
//!   floor and the conversation still does not fit.
//!
//! ## What slice 1 does NOT do
//!
//! - No LLM-based free-text summarization (slice 2)
//! - No `Role::Compaction` projection (slice 2 — needs the
//!   conversation enum to gain a new variant)
//! - No [`InjectionDetector`] integration on replay (slice 2 — only
//!   meaningful when compaction events round-trip back into the
//!   prompt)
//! - No provider-specific prompt cache markers (slice 3)
//! - No `ContextStrategy` trait (premature; one strategy in slice 1)
//! - No real tokenizer (sticking with `len/4 + 1` for now)
//!
//! [`InjectionDetector`]: wirken_gateway::injection_detect::InjectionDetector
//! [`SessionEvent::Compaction`]: wirken_audit::SessionEvent::Compaction

use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog, TrustLevel};

use crate::conversation::{Conversation, Message, Role};
use crate::error::AgentError;
use crate::llm::LlmConfig;
use crate::tool::ToolDef;

/// Apply compaction at this fraction of the configured budget. The
/// 4-chars-per-token estimator is rough, so leave headroom for the
/// LLM's max response and for the difference between estimated and
/// actual tokens.
const SAFETY_FACTOR: f64 = 0.80;

/// Minimum number of recent turns (user messages and everything after
/// them) that fit() will refuse to trim. A "turn" is bounded by user
/// messages — the messages between two consecutive `Role::User`
/// messages all belong to the earlier turn.
const DEFAULT_MIN_RECENT_TURNS: usize = 3;

/// Placeholder content written into a tool result message after its
/// real output has been trimmed. The message itself stays so the
/// `tool_call_id` binding to the matching assistant tool_calls
/// message remains intact.
const TRIMMED_TOOL_RESULT_PREFIX: &str = "[trimmed: ";

/// Placeholder content written into a user/assistant text message
/// after trimming.
const TRIMMED_TEXT_PREFIX: &str = "[trimmed earlier turn: ";

/// Per-message token overhead beyond the content length / 4
/// estimate. Covers role markers, JSON wrapping, function-call
/// boilerplate. Empirically derived; not load-bearing.
const PER_MESSAGE_OVERHEAD_TOKENS: usize = 4;

/// Per-tool-def token overhead. Tool defs are JSON schemas the model
/// sees as part of the system context. Conservatively estimate at
/// 80 tokens of overhead beyond the JSON length / 4.
const PER_TOOL_OVERHEAD_TOKENS: usize = 80;

/// Context engine. One per agent, derived from the agent's
/// [`LlmConfig`]. Stateless beyond the budget config — the engine
/// reads the conversation, computes a plan, applies it, writes one
/// session event.
pub struct ContextEngine {
    budget_tokens: usize,
    min_recent_turns: usize,
}

impl ContextEngine {
    /// Construct an engine sized to a model's context window. The
    /// effective budget is [`SAFETY_FACTOR`] of the configured
    /// `context_window` to leave headroom for the LLM's response
    /// and tokenizer-vs-estimator drift.
    pub fn for_model(llm: &LlmConfig) -> Self {
        let budget_tokens = ((llm.context_window as f64) * SAFETY_FACTOR) as usize;
        Self {
            budget_tokens,
            min_recent_turns: DEFAULT_MIN_RECENT_TURNS,
        }
    }

    /// Test-only constructor with explicit budget and minimum-turns
    /// settings. Production code goes through [`Self::for_model`].
    #[cfg(test)]
    pub(crate) fn for_test(budget_tokens: usize, min_recent_turns: usize) -> Self {
        Self {
            budget_tokens,
            min_recent_turns,
        }
    }

    /// The effective token budget after the safety factor.
    pub fn budget_tokens(&self) -> usize {
        self.budget_tokens
    }

    /// Trim `conversation` in place until it fits the budget. Calls
    /// the trimming algorithm in [crate-private docs above]. Writes
    /// a single [`SessionEvent::Compaction`] event to the session
    /// log if anything was actually trimmed.
    ///
    /// Returns [`AgentError::ContextOverflow`] when the conversation
    /// is still over budget after trimming everything that may be
    /// trimmed.
    ///
    /// Item 4 slice 2 (alpha): at the start, removes any existing
    /// `Role::Compaction` message from the conversation so the
    /// summary block is recomputed fresh on every fit() call. At
    /// the end, if the session log has any prior Compaction events,
    /// inserts a fresh `Role::Compaction` message at position 1
    /// containing a deterministic aggregate summary the LLM sees
    /// inside the `<|compaction|>` fence.
    pub fn fit(
        &self,
        conversation: &mut Conversation,
        tools: &[ToolDef],
        session_log: &dyn SessionLog,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<(), AgentError> {
        // Item 4 slice 2: drop any prior compaction summary so we
        // can recompute it fresh below. This must happen before the
        // budget check so identical fit() calls converge to the
        // same conversation shape.
        conversation.remove_role(Role::Compaction);

        let tools_tokens = estimate_tool_tokens(tools);
        let initial_tokens = estimate_conversation_tokens(conversation) + tools_tokens;

        if initial_tokens <= self.budget_tokens {
            // Even though no new trim is needed, we still want a
            // compaction summary block from any prior trims so the
            // model sees the running summary on every turn.
            self.maybe_inject_compaction_summary(conversation, session_log, handle)?;
            return Ok(());
        }

        let floor = self.compute_floor(conversation);
        let mut plan = TrimPlan::new(conversation.len());
        let mut current = initial_tokens;

        // Pass 1: drop oldest tool result content first.
        for (idx, msg) in conversation.messages().iter().enumerate() {
            if current <= self.budget_tokens {
                break;
            }
            if floor.contains(&idx) {
                continue;
            }
            if msg.role == Role::Tool {
                let saved = plan.trim_tool_result(idx, msg);
                current = current.saturating_sub(saved);
            }
        }

        // Pass 2: oldest assistant text.
        if current > self.budget_tokens {
            for (idx, msg) in conversation.messages().iter().enumerate() {
                if current <= self.budget_tokens {
                    break;
                }
                if floor.contains(&idx) || plan.contains(&idx) {
                    continue;
                }
                if msg.role == Role::Assistant && msg.tool_calls.is_none() {
                    let saved = plan.trim_text(idx, msg, "assistant");
                    current = current.saturating_sub(saved);
                }
            }
        }

        // Pass 3: oldest user messages.
        if current > self.budget_tokens {
            for (idx, msg) in conversation.messages().iter().enumerate() {
                if current <= self.budget_tokens {
                    break;
                }
                if floor.contains(&idx) || plan.contains(&idx) {
                    continue;
                }
                if msg.role == Role::User {
                    let saved = plan.trim_text(idx, msg, "user");
                    current = current.saturating_sub(saved);
                }
            }
        }

        if current > self.budget_tokens {
            return Err(AgentError::ContextOverflow {
                current_tokens: current,
                budget_tokens: self.budget_tokens,
            });
        }

        if plan.is_empty() {
            // Nothing to do. Should not happen given the early-return
            // above, but defensive.
            return Ok(());
        }

        // Snapshot the spans BEFORE consuming `plan` in apply().
        let touched_count = plan.touched_indices.len();
        let spans: Vec<u64> = plan.touched_indices.iter().map(|&i| i as u64).collect();

        let trimmed_bytes = plan.apply(conversation);

        // Persist a structured Compaction event so wake() and the
        // operator can see what was dropped. Slice 1 doesn't render
        // these back into the LLM prompt — that's slice 2.
        let event = SessionEvent::Compaction {
            spans,
            extracts: serde_json::json!({
                "trimmed_bytes": trimmed_bytes,
                "kept_messages": conversation.len(),
                "dropped_messages": touched_count,
                "via_model": false,
            }),
            via_model: false,
        };
        session_log
            .append(handle, TrustLevel::Compaction, event)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;

        // Item 4 slice 2: now that the new Compaction event is in
        // the session log, inject the freshly aggregated summary as
        // a Role::Compaction message at position 1.
        self.maybe_inject_compaction_summary(conversation, session_log, handle)?;

        Ok(())
    }

    /// Walk the session log for any [`SessionEvent::Compaction`]
    /// events recorded for this session and, if any exist, insert a
    /// single [`Role::Compaction`] message at position 1 of the
    /// conversation containing a deterministic aggregate summary.
    /// No-op if there are no compaction events.
    pub(crate) fn maybe_inject_compaction_summary(
        &self,
        conversation: &mut Conversation,
        session_log: &dyn SessionLog,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<(), AgentError> {
        let Some(message) = self.compaction_summary_message(session_log, handle)? else {
            return Ok(());
        };
        // Insert right after any system prompt(s).
        let pos = conversation
            .messages()
            .iter()
            .position(|m| m.role != Role::System)
            .unwrap_or_else(|| conversation.len());
        conversation.insert_at(pos, message);
        Ok(())
    }

    /// Build the compaction summary message from the session log.
    /// Walks every [`SessionEvent::Compaction`] event for this
    /// session and aggregates them into a deterministic text
    /// summary. Returns `None` if the session has no compaction
    /// events. The output content is what gets wrapped in
    /// `<|compaction|>...<|/compaction|>` by the provider adapter.
    pub(crate) fn compaction_summary_message(
        &self,
        session_log: &dyn SessionLog,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<Option<Message>, AgentError> {
        let rows = session_log
            .get_since(handle, 0)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;

        let mut compaction_count = 0usize;
        let mut total_trimmed_bytes: u64 = 0;
        let mut total_dropped: u64 = 0;
        let mut seqs: Vec<u64> = Vec::new();
        let mut via_model_seen = false;

        for row in &rows {
            if let SessionEvent::Compaction {
                extracts,
                via_model,
                ..
            } = &row.event
            {
                compaction_count += 1;
                seqs.push(row.seq);
                if *via_model {
                    via_model_seen = true;
                }
                if let Some(b) = extracts.get("trimmed_bytes").and_then(|v| v.as_u64()) {
                    total_trimmed_bytes += b;
                }
                if let Some(d) = extracts.get("dropped_messages").and_then(|v| v.as_u64()) {
                    total_dropped += d;
                }
            }
        }

        if compaction_count == 0 {
            return Ok(None);
        }

        let model_note = if via_model_seen {
            " (at least one summary used a model call; treat with caution)"
        } else {
            ""
        };

        let content = format!(
            "Earlier in this session, the wirken context engine trimmed older \
             messages to fit the model's context window:\n\
             - {compaction_count} trim round(s){model_note}\n\
             - {total_dropped} message(s) dropped\n\
             - {total_trimmed_bytes} byte(s) reclaimed\n\
             - See session log compaction events at seqs {seqs:?}\n\
             The trimmed content is preserved in the session log; the \
             above is a deterministic aggregate, not a model summary."
        );

        Ok(Some(Message {
            role: Role::Compaction,
            content,
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }))
    }

    /// Indices that fit() must never trim:
    /// - The system prompt(s) (always at the front)
    /// - Everything from the start of the most recent
    ///   `min_recent_turns` user messages onward
    fn compute_floor(&self, conversation: &Conversation) -> Floor {
        let messages = conversation.messages();

        // System prompts at the front
        let mut system_end = 0usize;
        for (i, m) in messages.iter().enumerate() {
            if m.role == Role::System {
                system_end = i + 1;
            } else {
                break;
            }
        }

        // Walk backward to find the start of the Nth most recent user
        // message. Everything from that index forward is protected.
        let mut user_starts: Vec<usize> = Vec::new();
        for (i, m) in messages.iter().enumerate() {
            if m.role == Role::User {
                user_starts.push(i);
            }
        }
        let recent_floor_start = if user_starts.len() <= self.min_recent_turns {
            user_starts.first().copied().unwrap_or(messages.len())
        } else {
            user_starts[user_starts.len() - self.min_recent_turns]
        };

        Floor {
            system_end,
            recent_start: recent_floor_start,
        }
    }
}

/// Set of message indices that fit() will not touch.
struct Floor {
    /// Indices `[0, system_end)` are system messages.
    system_end: usize,
    /// Indices `[recent_start, conversation.len())` are the
    /// protected recent turns.
    recent_start: usize,
}

impl Floor {
    fn contains(&self, idx: &usize) -> bool {
        *idx < self.system_end || *idx >= self.recent_start
    }
}

/// Mutable plan describing which messages will get their content
/// trimmed and to what placeholder. Applied to the conversation in
/// one pass at the end of [`ContextEngine::fit`].
struct TrimPlan {
    /// New content for trimmed messages, keyed by index.
    replacements: std::collections::HashMap<usize, String>,
    /// Original byte size of the trimmed content for each touched
    /// index. Used to compute total `trimmed_bytes`.
    trimmed_bytes: std::collections::HashMap<usize, usize>,
    /// Indices that were touched in any pass, in order of touching.
    /// Used as the `spans` field on the Compaction event.
    touched_indices: Vec<usize>,
    /// Total message count, used by `new` only.
    _total_len: usize,
}

impl TrimPlan {
    fn new(total_len: usize) -> Self {
        Self {
            replacements: std::collections::HashMap::new(),
            trimmed_bytes: std::collections::HashMap::new(),
            touched_indices: Vec::new(),
            _total_len: total_len,
        }
    }

    fn contains(&self, idx: &usize) -> bool {
        self.replacements.contains_key(idx)
    }

    fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }

    /// Replace a tool result's content with a `[trimmed: N bytes]`
    /// marker. Returns the estimated tokens reclaimed.
    fn trim_tool_result(&mut self, idx: usize, msg: &Message) -> usize {
        let original_len = msg.content.len();
        let placeholder = format!("{TRIMMED_TOOL_RESULT_PREFIX}{original_len} bytes]");
        self.touched_indices.push(idx);
        self.trimmed_bytes.insert(idx, original_len);
        let saved = estimate_message_tokens(msg).saturating_sub(estimate_tokens(&placeholder));
        self.replacements.insert(idx, placeholder);
        saved
    }

    /// Replace a user/assistant text message's content with a
    /// `[trimmed earlier turn: N bytes]` marker.
    fn trim_text(&mut self, idx: usize, msg: &Message, _role_label: &str) -> usize {
        let original_len = msg.content.len();
        let placeholder = format!("{TRIMMED_TEXT_PREFIX}{original_len} bytes]");
        self.touched_indices.push(idx);
        self.trimmed_bytes.insert(idx, original_len);
        let saved = estimate_message_tokens(msg).saturating_sub(estimate_tokens(&placeholder));
        self.replacements.insert(idx, placeholder);
        saved
    }

    /// Walk the conversation and apply every replacement. Returns
    /// the total bytes reclaimed.
    fn apply(self, conversation: &mut Conversation) -> usize {
        let total_bytes: usize = self.trimmed_bytes.values().sum();
        for (idx, new_content) in self.replacements {
            conversation.replace_content(idx, new_content);
        }
        total_bytes
    }
}

/// Sum the estimated tokens of every message in the conversation.
pub(crate) fn estimate_conversation_tokens(conversation: &Conversation) -> usize {
    conversation
        .messages()
        .iter()
        .map(estimate_message_tokens)
        .sum()
}

/// Estimate the tokens for one message. Uses the existing
/// `len/4 + 1` heuristic per the slice 1 design (decision 1) plus
/// [`PER_MESSAGE_OVERHEAD_TOKENS`].
pub(crate) fn estimate_message_tokens(msg: &Message) -> usize {
    let content_tokens = estimate_tokens(&msg.content);
    // Tool calls add a JSON-ish payload not in `content`. Add a
    // rough estimate per call.
    let tool_call_tokens = msg
        .tool_calls
        .as_ref()
        .map(|calls| {
            calls
                .iter()
                .map(|c| estimate_tokens(&c.name) + estimate_tokens(&c.arguments) + 8)
                .sum::<usize>()
        })
        .unwrap_or(0);
    content_tokens + tool_call_tokens + PER_MESSAGE_OVERHEAD_TOKENS
}

/// Estimate the tokens consumed by tool definitions. Each tool's
/// JSON schema length / 4 plus a per-tool overhead.
pub(crate) fn estimate_tool_tokens(tools: &[ToolDef]) -> usize {
    tools
        .iter()
        .map(|t| {
            let params_str = t.parameters.to_string();
            estimate_tokens(&t.name)
                + estimate_tokens(&t.description)
                + estimate_tokens(&params_str)
                + PER_TOOL_OVERHEAD_TOKENS
        })
        .sum()
}

/// Token estimator: 4 characters ≈ 1 token, plus 1 to round up.
pub(crate) fn estimate_tokens(s: &str) -> usize {
    s.len() / 4 + 1
}
