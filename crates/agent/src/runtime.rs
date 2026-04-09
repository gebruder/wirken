use std::path::PathBuf;
use std::sync::Arc;

use wirken_audit::{
    OwnSession, SessionEvent, SessionHandle, SessionId, SessionLog, ToolCallRecord, TrustLevel,
};

use crate::context::ContextEngine;
use crate::conversation::{Conversation, ToolCallRequest};
use crate::error::{AgentError, PermissionDenialContext};
use crate::llm::{LlmClient, LlmConfig, LlmResponse};
use crate::llm_stream::StreamEvent;
use crate::mcp::McpProxyClient;
use crate::skill::{Skill, SkillLoader};
use crate::tool::{ToolConfig, ToolRegistry, tool_to_action};
use crate::wasm_sandbox::WasmSkill;
use wirken_gateway::permissions::{PermissionCheck, PermissionStore};

/// Maximum tool call rounds per turn to prevent infinite loops.
const MAX_TOOL_ROUNDS: usize = 20;

/// Prefix on the synthetic `ToolResult` output that
/// [`Agent::from_session_log`] writes for tool calls whose results
/// were lost to a crash. The LLM sees a failed tool call with this
/// recognizable string and can decide what to do (retry, give up,
/// surface the failure to the user). Item 4's context engine will
/// strip the sentinel before showing the LLM, but slice 2 just
/// passes it through verbatim.
pub const PARTIAL_RESULT_LOST_SENTINEL: &str = "PARTIAL_RESULT_LOST:";

/// Result of processing a message, containing the response and any
/// permission denials that occurred during tool execution.
pub struct ProcessResult {
    /// The agent's final text response.
    pub response: String,
    /// Permission denials collected during this processing round.
    /// Each denial corresponds to a tool call the LLM attempted that
    /// was blocked by the permission model. The caller should log these
    /// to the audit trail.
    pub denials: Vec<PermissionDenialContext>,
}

/// The agent runtime. Processes inbound messages, calls the LLM,
/// executes tools, and produces responses.
pub struct Agent {
    pub id: String,
    conversation: Conversation,
    llm: LlmClient,
    tools: ToolRegistry,
    mcp: Option<Arc<tokio::sync::Mutex<McpProxyClient>>>,
    skills: Vec<Skill>,
    wasm_skills: Vec<WasmSkill>,
    system_prompt: String,
    /// API key passed per-request — agent never stores it long-term.
    /// In production, the gateway's LLM proxy handles this.
    api_key: Option<String>,
    /// Optional permission store for checking tool execution permissions.
    /// When None, all tools execute without permission checks (standalone mode).
    permissions: Option<Arc<std::sync::Mutex<PermissionStore>>>,
    /// The current user message that triggered this processing round.
    /// Captured in process_message() for inclusion in denial audit events.
    current_trigger: Option<String>,
    /// Session log this agent writes durability events to. Slice 1
    /// of item 2 in `docs/managed-agents-parity.md` makes every
    /// interaction in process_message a typed session event written
    /// before the next LLM call. Item 2 slice 2 will add wake() and
    /// make the agent stateless.
    session_log: Arc<dyn SessionLog>,
    /// Capability handle for this agent's session. Slice 1 uses
    /// `agent_id` as the session id (one big chain per agent across
    /// all channels). Slice 2 introduces per-conversation session
    /// ids.
    session_handle: SessionHandle<OwnSession>,
    /// Per-model context-window engine. Item 4 slice 1: trims the
    /// conversation in place before each LLM call so context
    /// blowups stop killing sessions. Sized from the agent's
    /// [`LlmConfig::context_window`] at construction time.
    context_engine: ContextEngine,
}

impl Agent {
    /// Create a new agent.
    pub fn new(
        id: String,
        workspace: PathBuf,
        llm_config: LlmConfig,
        api_key: Option<String>,
        session_log: Arc<dyn SessionLog>,
    ) -> Result<Self, AgentError> {
        let tool_config = ToolConfig {
            api_key: api_key.clone(),
            provider: Some(llm_config.provider.clone()),
            base_url: Some(llm_config.base_url.clone()),
            sandbox: Default::default(),
        };
        let tools = ToolRegistry::new(workspace, tool_config);

        let system_prompt = default_system_prompt();
        let mut conversation = Conversation::new(100_000); // legacy compaction is now a no-op; ContextEngine handles trimming
        conversation.set_system_prompt(&system_prompt);

        let session_handle = session_log.handle_for(SessionId::new(id.clone()));
        let context_engine = ContextEngine::for_model(&llm_config);

        Ok(Self {
            id,
            conversation,
            llm: LlmClient::new(llm_config)?,
            tools,
            mcp: None,
            skills: Vec::new(),
            wasm_skills: Vec::new(),
            system_prompt,
            api_key,
            permissions: None,
            current_trigger: None,
            session_log,
            session_handle,
            context_engine,
        })
    }

    /// Reconstruct an `Agent` from a session log. Used by
    /// [`crate::factory::AgentFactory::wake`] to bring an existing
    /// session back to its last good state. The conversation is
    /// rebuilt by replaying every relevant session event for
    /// `session_id`. Half-completed tool rounds (an
    /// `AssistantToolCalls` event with one or more missing
    /// `ToolResult` events) are surfaced by writing synthetic
    /// failure `ToolResult` events to the session log BEFORE the
    /// conversation projection is built — the session log is
    /// self-healing as soon as wake runs.
    ///
    /// Skills, MCP, and permissions are NOT replayed — they're
    /// external state that the caller (the AgentFactory) injects
    /// after construction.
    pub(crate) fn from_session_log(
        id: String,
        workspace: PathBuf,
        llm_config: LlmConfig,
        api_key: Option<String>,
        session_log: Arc<dyn SessionLog>,
    ) -> Result<Self, AgentError> {
        let session_id = SessionId::new(id.clone());
        let session_handle = session_log.handle_for(session_id);

        // Refuse-and-surface for partial tool rounds. Walk the
        // session, find every AssistantToolCalls event, check that
        // each call_id has a matching ToolResult somewhere later in
        // the session. For any call_id that doesn't, write a
        // synthetic ToolResult with the PARTIAL_RESULT_LOST sentinel.
        Self::heal_partial_tool_rounds(&*session_log, &session_handle)?;

        // Build the conversation by replaying the (now-complete)
        // session log.
        let tool_config = ToolConfig {
            api_key: api_key.clone(),
            provider: Some(llm_config.provider.clone()),
            base_url: Some(llm_config.base_url.clone()),
            sandbox: Default::default(),
        };
        let tools = ToolRegistry::new(workspace, tool_config);

        let system_prompt = default_system_prompt();
        let mut conversation = Conversation::new(100_000);
        conversation.set_system_prompt(&system_prompt);
        conversation
            .replay_from_log(&*session_log, &session_handle)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;

        let context_engine = ContextEngine::for_model(&llm_config);

        Ok(Self {
            id,
            conversation,
            llm: LlmClient::new(llm_config)?,
            tools,
            mcp: None,
            skills: Vec::new(),
            wasm_skills: Vec::new(),
            system_prompt,
            api_key,
            permissions: None,
            current_trigger: None,
            session_log,
            session_handle,
            context_engine,
        })
    }

    /// Walk the session log for half-completed tool rounds and write
    /// a synthetic ToolResult for every missing call. Self-heals the
    /// log so subsequent reads see a consistent state. The synthetic
    /// result is recognizable by the [`PARTIAL_RESULT_LOST_SENTINEL`]
    /// prefix in its output.
    fn heal_partial_tool_rounds(
        log: &dyn SessionLog,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<(), AgentError> {
        use std::collections::HashSet;

        let rows = log
            .get_since(handle, 0)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;

        // Collect all completed call_ids and all expected call_ids.
        let mut completed: HashSet<String> = HashSet::new();
        let mut expected: Vec<(String, String)> = Vec::new(); // (call_id, tool_name)
        for row in &rows {
            match &row.event {
                SessionEvent::AssistantToolCalls { calls } => {
                    for c in calls {
                        expected.push((c.id.clone(), c.name.clone()));
                    }
                }
                SessionEvent::ToolResult { call_id, .. } => {
                    completed.insert(call_id.clone());
                }
                _ => {}
            }
        }

        // Write a synthetic failure for every expected call without a
        // matching result. Order preserves the original tool-call
        // order so the conversation projection sees them in sequence.
        for (call_id, tool_name) in expected {
            if completed.contains(&call_id) {
                continue;
            }
            tracing::warn!(
                "wake: synthesizing PARTIAL_RESULT_LOST for tool call {} ({})",
                call_id,
                tool_name,
            );
            let event = SessionEvent::ToolResult {
                call_id: call_id.clone(),
                tool_name,
                output: format!(
                    "{PARTIAL_RESULT_LOST_SENTINEL} previous invocation did not complete; \
                     the tool was not retried"
                ),
                success: false,
            };
            log.append(handle, TrustLevel::Tool, event)
                .map_err(|e| AgentError::SessionLog(e.to_string()))?;
            // Mark as completed so a later AssistantToolCalls with
            // the same call_id (shouldn't happen, but be safe)
            // doesn't get a second synthetic result.
            completed.insert(call_id);
        }

        Ok(())
    }

    /// Set the permission store for tool execution permission checks.
    /// When set, tool calls are checked against the three-tier permission model
    /// before execution. Denials are collected in the `ProcessResult`.
    pub fn set_permissions(&mut self, store: Arc<std::sync::Mutex<PermissionStore>>) {
        self.permissions = Some(store);
    }

    /// Connect to the out-of-process MCP proxy and load this agent's
    /// tool definitions. Replaces the previous in-process MCP loader.
    /// Returns the number of MCP tools available to this agent.
    pub async fn load_mcp(&mut self, proxy_socket: &std::path::Path) -> Result<usize, AgentError> {
        let mut client = McpProxyClient::connect(proxy_socket, &self.id).await?;
        if !client.has_servers() {
            // The proxy is reachable but has no servers configured for this
            // agent. Drop the connection to avoid holding an idle FD.
            client.shutdown().await;
            return Ok(0);
        }
        let count = client.load_tools().await?;
        self.mcp = Some(Arc::new(tokio::sync::Mutex::new(client)));
        Ok(count)
    }

    /// Attach a shared MCP client. Used by [`crate::factory::AgentFactory`]
    /// to inject the per-agent long-lived proxy connection into a
    /// freshly waked Agent. Concurrent waked Agents for the same
    /// agent_id share the same Arc and serialize through its Mutex.
    pub fn attach_mcp(&mut self, client: Arc<tokio::sync::Mutex<McpProxyClient>>) {
        self.mcp = Some(client);
    }

    /// Attach skill collections. Used by
    /// [`crate::factory::AgentFactory`] to inject per-agent skills
    /// loaded once at startup, then rebuild the system prompt to
    /// include them.
    pub fn attach_skills(&mut self, skills: Vec<Skill>, wasm_skills: Vec<WasmSkill>) {
        self.skills = skills;
        self.wasm_skills = wasm_skills;
        self.rebuild_system_prompt();
    }

    /// Load skills from a directory and rebuild the system prompt.
    pub fn load_skills(&mut self, dir: &std::path::Path) -> Result<usize, AgentError> {
        self.skills = SkillLoader::load_dir(dir)?;
        self.rebuild_system_prompt();
        Ok(self.skills.len())
    }

    /// Append a typed event to this agent's session log. Errors
    /// from the underlying log are wrapped as `SessionLog` so the
    /// agent loop fails closed if durability writes break — partial
    /// state is worse than no state.
    ///
    /// Crate-private so tests can drive the session writes without
    /// needing an LLM mock.
    pub(crate) fn log_event(
        &self,
        trust: TrustLevel,
        event: SessionEvent,
    ) -> Result<(), AgentError> {
        self.session_log
            .append(&self.session_handle, trust, event)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;
        Ok(())
    }

    /// Borrow this agent's session log. Crate-private; used by tests
    /// to read back what `log_event` wrote.
    #[cfg(test)]
    pub(crate) fn session_log_for_test(&self) -> &Arc<dyn SessionLog> {
        &self.session_log
    }

    /// Crash-recovery dedup. If the most recent `UserMessage` in
    /// this agent's session has an `inbound_id` matching the
    /// incoming one, this is a re-delivery — return the prior
    /// `AssistantMessage` (the one that followed the matched
    /// UserMessage) without re-running the LLM. If no assistant
    /// message follows the matched UserMessage, the previous turn
    /// was interrupted; return a stable error response so the user
    /// gets a clear "previous turn did not complete, please retry"
    /// rather than re-running the side effects.
    fn dedup_inbound(&self, inbound_id: &str) -> Result<Option<ProcessResult>, AgentError> {
        let last_idx = self
            .session_log
            .last_index(&self.session_handle)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;
        let Some(last_idx) = last_idx else {
            return Ok(None);
        };

        let rows = self
            .session_log
            .get_since(&self.session_handle, 0)
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;

        // Find the most recent UserMessage and its position.
        let mut last_user_pos: Option<usize> = None;
        for (i, row) in rows.iter().enumerate().rev() {
            if matches!(row.event, SessionEvent::UserMessage { .. }) {
                last_user_pos = Some(i);
                break;
            }
        }
        let Some(pos) = last_user_pos else {
            return Ok(None);
        };

        // Check the inbound_id matches.
        let matches = match &rows[pos].event {
            SessionEvent::UserMessage { inbound_id: id, .. } => id.as_deref() == Some(inbound_id),
            _ => false,
        };
        if !matches {
            return Ok(None);
        }

        // Look for an AssistantMessage that follows the matched
        // UserMessage. If we find one, this is a clean re-delivery
        // and we replay the prior response.
        for row in rows.iter().skip(pos + 1) {
            if let SessionEvent::AssistantMessage { content } = &row.event {
                tracing::info!(
                    "agent {} dedup: replaying response for inbound_id {} (idx {})",
                    self.id,
                    inbound_id,
                    last_idx,
                );
                return Ok(Some(ProcessResult {
                    response: content.clone(),
                    denials: Vec::new(),
                }));
            }
        }

        // The matched UserMessage has no following AssistantMessage —
        // the previous turn was interrupted (crash, timeout, etc.).
        // Return a stable error so the user knows to retry rather than
        // re-running the partially-executed turn.
        tracing::warn!(
            "agent {} dedup: matched inbound_id {} but no assistant response — \
             previous turn was interrupted",
            self.id,
            inbound_id,
        );
        Ok(Some(ProcessResult {
            response: "(previous turn did not complete; please retry)".to_string(),
            denials: Vec::new(),
        }))
    }

    /// Convert in-process tool call requests into the wire format
    /// the session log uses.
    pub(crate) fn calls_to_records(calls: &[ToolCallRequest]) -> Vec<ToolCallRecord> {
        calls
            .iter()
            .map(|c| ToolCallRecord {
                id: c.id.clone(),
                name: c.name.clone(),
                arguments: c.arguments.clone(),
            })
            .collect()
    }

    /// Process an inbound message and produce a response.
    /// This is the core agent loop:
    /// 1. Dedup against the most recent UserMessage in the session log
    /// 2. Add user message to conversation
    /// 3. Call LLM
    /// 4. If LLM requests tool calls, execute them and loop
    /// 5. Return the final text response and any permission denials
    ///
    /// `inbound_id` is the platform-supplied message id (Telegram
    /// `message_id`, Slack `ts`, Discord `id`, …) when the source
    /// has one, or a UUID synthesized at the gateway boundary for
    /// `webchat`, `cron`, and `wirken ask`. The harness uses it to
    /// detect re-deliveries after a crash and return the prior
    /// assistant response without re-running the LLM.
    pub async fn process_message(
        &mut self,
        user_message: &str,
        inbound_id: String,
    ) -> Result<ProcessResult, AgentError> {
        if let Some(replay) = self.dedup_inbound(&inbound_id)? {
            return Ok(replay);
        }

        self.current_trigger = Some(user_message.to_string());
        self.conversation.add_user_message(user_message);
        self.log_event(
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: user_message.to_string(),
                inbound_id: Some(inbound_id),
            },
        )?;

        // MCP definitions are cached on the proxy client; lock briefly
        // to read them. The shared Mutex is held only across the
        // synchronous .definitions() copy, never across an LLM call.
        let mcp_defs = match &self.mcp {
            Some(mcp) => mcp.lock().await.definitions(),
            None => Vec::new(),
        };

        let mut tool_defs = if self.llm.config().tools_enabled {
            let mut defs = self.tools.definitions();
            defs.extend(mcp_defs);
            defs.extend(self.wasm_skills.iter().map(|s| s.tool_def()));
            defs
        } else {
            Vec::new()
        };
        // Stable tool def ordering — prompt-cache friendly even
        // before slice 3 adds provider-specific cache markers.
        tool_defs.sort_by(|a, b| a.name.cmp(&b.name));

        // Initial fit before the first LLM call.
        self.context_engine.fit(
            &mut self.conversation,
            &tool_defs,
            &*self.session_log,
            &self.session_handle,
        )?;

        let mut rounds = 0;
        let mut denials = Vec::new();

        loop {
            rounds += 1;
            if rounds > MAX_TOOL_ROUNDS {
                return Err(AgentError::Tool(format!(
                    "exceeded {MAX_TOOL_ROUNDS} tool call rounds — possible loop"
                )));
            }

            // Refit before every LLM call inside the tool loop. A
            // single large tool result can push us over budget after
            // a successful initial fit; this catches it.
            self.context_engine.fit(
                &mut self.conversation,
                &tool_defs,
                &*self.session_log,
                &self.session_handle,
            )?;

            let response = self
                .llm
                .complete(
                    self.conversation.messages(),
                    &tool_defs,
                    self.api_key.as_deref(),
                )
                .await?;

            match response {
                LlmResponse::Text(text) => {
                    self.conversation.add_assistant_message(&text);
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantMessage {
                            content: text.clone(),
                        },
                    )?;
                    return Ok(ProcessResult {
                        response: text,
                        denials,
                    });
                }
                LlmResponse::ToolCalls(calls) => {
                    // Record the tool call request in the conversation AND
                    // in the session log BEFORE executing any tools. The
                    // ordering is load-bearing for item 2 slice 2's wake():
                    // an interruption between "LLM emitted tool calls" and
                    // "tools executed" must be detectable as
                    // AssistantToolCalls with no matching ToolResult events.
                    self.conversation.add_assistant_tool_calls(calls.clone());
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantToolCalls {
                            calls: Self::calls_to_records(&calls),
                        },
                    )?;

                    // Execute each tool call
                    for call in &calls {
                        tracing::info!(
                            "Agent {} executing tool: {}({})",
                            self.id,
                            call.name,
                            truncate(&call.arguments, 100)
                        );

                        let result = match self.execute_tool(&call.name, &call.arguments).await {
                            Ok(result) => result,
                            Err(AgentError::PermissionDeniedCtx(ctx)) => {
                                tracing::warn!(
                                    "Permission denied: agent '{}' tool '{}' requires {}",
                                    ctx.agent_id,
                                    ctx.tool_name,
                                    ctx.requested_tier.label(),
                                );
                                self.log_event(
                                    TrustLevel::System,
                                    SessionEvent::PermissionDenied {
                                        tool: ctx.tool_name.clone(),
                                        tier: ctx.requested_tier.label().to_string(),
                                        agent_id: ctx.agent_id.clone(),
                                        trigger: ctx.trigger_message.clone(),
                                    },
                                )?;
                                let output = format!(
                                    "Permission denied: '{}' requires {} approval. \
                                     This action was not executed.",
                                    ctx.tool_name,
                                    ctx.requested_tier.label(),
                                );
                                denials.push(ctx);
                                crate::tool::ToolResult {
                                    output,
                                    success: false,
                                }
                            }
                            Err(e) => return Err(e),
                        };

                        tracing::debug!(
                            "Tool {} result (success={}): {}",
                            call.name,
                            result.success,
                            truncate(&result.output, 200)
                        );

                        self.conversation
                            .add_tool_result(&call.id, &call.name, &result.output);
                        self.log_event(
                            TrustLevel::Tool,
                            SessionEvent::ToolResult {
                                call_id: call.id.clone(),
                                tool_name: call.name.clone(),
                                output: result.output.clone(),
                                success: result.success,
                            },
                        )?;
                    }

                    // Continue loop — LLM will see tool results and respond
                }
                LlmResponse::Empty => {
                    let fallback = "(no response)".to_string();
                    self.conversation.add_assistant_message(&fallback);
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantMessage {
                            content: fallback.clone(),
                        },
                    )?;
                    return Ok(ProcessResult {
                        response: fallback,
                        denials,
                    });
                }
            }
        }
    }

    /// Process a message with streaming. Text deltas are sent via `tx` as they arrive.
    /// Tool call rounds still execute synchronously within the loop.
    /// Returns the final response text and any permission denials.
    pub async fn process_message_stream(
        &mut self,
        user_message: &str,
        inbound_id: String,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<ProcessResult, AgentError> {
        if let Some(replay) = self.dedup_inbound(&inbound_id)? {
            let _ = tx
                .send(StreamEvent::Done(LlmResponse::Text(
                    replay.response.clone(),
                )))
                .await;
            return Ok(replay);
        }

        self.current_trigger = Some(user_message.to_string());
        self.conversation.add_user_message(user_message);
        self.log_event(
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: user_message.to_string(),
                inbound_id: Some(inbound_id),
            },
        )?;

        let mcp_defs = match &self.mcp {
            Some(mcp) => mcp.lock().await.definitions(),
            None => Vec::new(),
        };

        let mut tool_defs = if self.llm.config().tools_enabled {
            let mut defs = self.tools.definitions();
            defs.extend(mcp_defs);
            defs
        } else {
            Vec::new()
        };
        // Stable tool def ordering — see process_message for the
        // reasoning. Slice 3 of item 4 layers provider-specific
        // cache_control on top of this stable prefix.
        tool_defs.sort_by(|a, b| a.name.cmp(&b.name));

        // Initial fit before the first LLM call.
        self.context_engine.fit(
            &mut self.conversation,
            &tool_defs,
            &*self.session_log,
            &self.session_handle,
        )?;

        let mut rounds = 0;
        let mut denials = Vec::new();

        loop {
            rounds += 1;
            if rounds > MAX_TOOL_ROUNDS {
                return Err(AgentError::Tool(format!(
                    "exceeded {MAX_TOOL_ROUNDS} tool call rounds — possible loop"
                )));
            }

            // Refit before every LLM call inside the tool loop.
            self.context_engine.fit(
                &mut self.conversation,
                &tool_defs,
                &*self.session_log,
                &self.session_handle,
            )?;

            // Create a per-round channel for streaming events
            let (round_tx, mut round_rx) = tokio::sync::mpsc::channel(64);

            // Spawn streaming in background, forward text deltas to caller
            let response = {
                let stream_future = self.llm.complete_stream(
                    self.conversation.messages(),
                    &tool_defs,
                    self.api_key.as_deref(),
                    round_tx,
                );

                let forward_tx = tx.clone();
                let forward_handle = tokio::spawn(async move {
                    while let Some(event) = round_rx.recv().await {
                        if let StreamEvent::TextDelta(_) = &event {
                            let _ = forward_tx.send(event).await;
                        }
                    }
                });

                let result = stream_future.await;
                let _ = forward_handle.await;
                result?
            };

            match response {
                LlmResponse::Text(text) => {
                    self.conversation.add_assistant_message(&text);
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantMessage {
                            content: text.clone(),
                        },
                    )?;
                    let _ = tx
                        .send(StreamEvent::Done(LlmResponse::Text(text.clone())))
                        .await;
                    return Ok(ProcessResult {
                        response: text,
                        denials,
                    });
                }
                LlmResponse::ToolCalls(calls) => {
                    self.conversation.add_assistant_tool_calls(calls.clone());
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantToolCalls {
                            calls: Self::calls_to_records(&calls),
                        },
                    )?;

                    for call in &calls {
                        tracing::info!("Agent {} executing tool: {}", self.id, call.name);

                        let result = match self.execute_tool(&call.name, &call.arguments).await {
                            Ok(result) => result,
                            Err(AgentError::PermissionDeniedCtx(ctx)) => {
                                self.log_event(
                                    TrustLevel::System,
                                    SessionEvent::PermissionDenied {
                                        tool: ctx.tool_name.clone(),
                                        tier: ctx.requested_tier.label().to_string(),
                                        agent_id: ctx.agent_id.clone(),
                                        trigger: ctx.trigger_message.clone(),
                                    },
                                )?;
                                let output = format!(
                                    "Permission denied: '{}' requires {} approval. \
                                     This action was not executed.",
                                    ctx.tool_name,
                                    ctx.requested_tier.label(),
                                );
                                denials.push(ctx);
                                crate::tool::ToolResult {
                                    output,
                                    success: false,
                                }
                            }
                            Err(e) => return Err(e),
                        };

                        self.conversation
                            .add_tool_result(&call.id, &call.name, &result.output);
                        self.log_event(
                            TrustLevel::Tool,
                            SessionEvent::ToolResult {
                                call_id: call.id.clone(),
                                tool_name: call.name.clone(),
                                output: result.output.clone(),
                                success: result.success,
                            },
                        )?;
                    }
                }
                LlmResponse::Empty => {
                    let fallback = "(no response)".to_string();
                    self.conversation.add_assistant_message(&fallback);
                    self.log_event(
                        TrustLevel::System,
                        SessionEvent::AssistantMessage {
                            content: fallback.clone(),
                        },
                    )?;
                    let _ = tx.send(StreamEvent::Done(LlmResponse::Empty)).await;
                    return Ok(ProcessResult {
                        response: fallback,
                        denials,
                    });
                }
            }
        }
    }

    /// Get the current conversation length.
    pub fn conversation_len(&self) -> usize {
        self.conversation.len()
    }

    /// Get the loaded skills.
    pub fn skills(&self) -> &[Skill] {
        &self.skills
    }

    /// Clear the conversation history (keeps system prompt).
    pub fn reset_conversation(&mut self) {
        self.conversation.clear();
        self.rebuild_system_prompt();
    }

    /// Load Wasm skills from a directory.
    pub fn load_wasm_skills(&mut self, dir: &std::path::Path) -> usize {
        let skills = crate::wasm_sandbox::load_wasm_skills(dir);
        let count = skills.len();
        self.wasm_skills.extend(skills);
        count
    }

    /// Execute a tool call, trying built-in tools, then MCP, then Wasm skills.
    /// Permission checks are applied when a PermissionStore is configured.
    async fn execute_tool(
        &mut self,
        name: &str,
        arguments: &str,
    ) -> Result<crate::tool::ToolResult, AgentError> {
        // Permission check before execution
        if let Some(ref perms) = self.permissions {
            let args: serde_json::Value =
                serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);
            if let Some(action) = tool_to_action(name, &args) {
                let check = {
                    let store = perms.lock().map_err(|e| {
                        AgentError::PermissionDenied(format!("permission store lock: {e}"))
                    })?;
                    store.check(&action, &self.id).map_err(|e| {
                        AgentError::PermissionDenied(format!("permission check failed: {e}"))
                    })?
                };
                if let PermissionCheck::NeedsApproval { tier } = check {
                    return Err(AgentError::PermissionDeniedCtx(PermissionDenialContext {
                        tool_name: name.to_string(),
                        action,
                        requested_tier: tier,
                        agent_id: self.id.clone(),
                        trigger_message: self.current_trigger.clone(),
                    }));
                }
            }
        }

        // MCP tool names are prefixed `mcp_{server}_{tool}` by the proxy.
        // Route them straight to the proxy client. Unlike the legacy
        // in-process registry, the proxy's "tool not found" is a typed
        // error message rather than `ToolNotFound`, so prefix routing is
        // the cheap unambiguous way to dispatch.
        if name.starts_with("mcp_") {
            return match &self.mcp {
                Some(mcp) => mcp.lock().await.execute(name, arguments).await,
                None => Err(AgentError::ToolNotFound(name.to_string())),
            };
        }

        // Wasm skills carry an explicit `wasm_` prefix.
        if let Some(wasm_name) = name.strip_prefix("wasm_") {
            for skill in &self.wasm_skills {
                if skill.name == wasm_name {
                    return skill.execute(arguments);
                }
            }
        }
        for skill in &self.wasm_skills {
            if skill.name == name {
                return skill.execute(arguments);
            }
        }

        // Otherwise, built-in tools.
        self.tools.execute(name, arguments).await
    }

    fn rebuild_system_prompt(&mut self) {
        let mut prompt = self.system_prompt.clone();

        let skill_prompt = SkillLoader::build_prompt(&self.skills);
        if !skill_prompt.is_empty() {
            prompt.push_str(&skill_prompt);
        }

        self.conversation.set_system_prompt(&prompt);
    }
}

fn default_system_prompt() -> String {
    "You are a helpful personal AI assistant. \
     You can execute shell commands, read and write files, \
     search the web, generate images, \
     and use available skills to help the user. \
     Be concise and direct in your responses."
        .to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Find a char boundary at or before `max` to avoid panicking on multi-byte UTF-8.
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
