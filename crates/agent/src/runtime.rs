use std::path::PathBuf;
use std::sync::Arc;

use crate::conversation::Conversation;
use crate::error::{AgentError, PermissionDenialContext};
use crate::llm::{LlmClient, LlmConfig, LlmResponse};
use crate::llm_stream::StreamEvent;
use crate::mcp::{McpConfig, McpRegistry};
use crate::skill::{Skill, SkillLoader};
use crate::tool::{ToolConfig, ToolRegistry, tool_to_action};
use crate::wasm_sandbox::WasmSkill;
use wirken_gateway::permissions::{PermissionCheck, PermissionStore};

/// Maximum tool call rounds per turn to prevent infinite loops.
const MAX_TOOL_ROUNDS: usize = 20;

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
    mcp: Option<McpRegistry>,
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
}

impl Agent {
    /// Create a new agent.
    pub fn new(
        id: String,
        workspace: PathBuf,
        llm_config: LlmConfig,
        api_key: Option<String>,
    ) -> Result<Self, AgentError> {
        let tool_config = ToolConfig {
            api_key: api_key.clone(),
            provider: Some(llm_config.provider.clone()),
            base_url: Some(llm_config.base_url.clone()),
            sandbox: Default::default(),
        };
        let tools = ToolRegistry::new(workspace, tool_config);

        let system_prompt = default_system_prompt();
        let mut conversation = Conversation::new(100_000); // ~100k token budget
        conversation.set_system_prompt(&system_prompt);

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
        })
    }

    /// Set the permission store for tool execution permission checks.
    /// When set, tool calls are checked against the three-tier permission model
    /// before execution. Denials are collected in the `ProcessResult`.
    pub fn set_permissions(&mut self, store: Arc<std::sync::Mutex<PermissionStore>>) {
        self.permissions = Some(store);
    }

    /// Load MCP servers from a config file.
    /// The `resolve_secret` function resolves `vault:` prefixed values.
    pub async fn load_mcp<F>(
        &mut self,
        config_path: &std::path::Path,
        resolve_secret: F,
    ) -> Result<usize, AgentError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let config = McpConfig::load(config_path)?;
        if config.servers.is_empty() {
            return Ok(0);
        }

        let registry = McpRegistry::load(&config, resolve_secret).await?;
        let count = registry.server_count();
        self.mcp = Some(registry);
        Ok(count)
    }

    /// Load skills from a directory and rebuild the system prompt.
    pub fn load_skills(&mut self, dir: &std::path::Path) -> Result<usize, AgentError> {
        self.skills = SkillLoader::load_dir(dir)?;
        self.rebuild_system_prompt();
        Ok(self.skills.len())
    }

    /// Process an inbound message and produce a response.
    /// This is the core agent loop:
    /// 1. Add user message to conversation
    /// 2. Call LLM
    /// 3. If LLM requests tool calls, execute them and loop
    /// 4. Return the final text response and any permission denials
    pub async fn process_message(
        &mut self,
        user_message: &str,
    ) -> Result<ProcessResult, AgentError> {
        self.current_trigger = Some(user_message.to_string());
        self.conversation.add_user_message(user_message);

        // Compact if over budget
        if self.conversation.over_budget() {
            self.conversation.compact();
        }

        let tool_defs = if self.llm.config().tools_enabled {
            let mut defs = self.tools.definitions();
            if let Some(ref mcp) = self.mcp {
                defs.extend(mcp.definitions());
            }
            defs.extend(self.wasm_skills.iter().map(|s| s.tool_def()));
            defs
        } else {
            Vec::new()
        };
        let mut rounds = 0;
        let mut denials = Vec::new();

        loop {
            rounds += 1;
            if rounds > MAX_TOOL_ROUNDS {
                return Err(AgentError::Tool(format!(
                    "exceeded {MAX_TOOL_ROUNDS} tool call rounds — possible loop"
                )));
            }

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
                    return Ok(ProcessResult {
                        response: text,
                        denials,
                    });
                }
                LlmResponse::ToolCalls(calls) => {
                    // Record the tool call request in conversation
                    self.conversation.add_assistant_tool_calls(calls.clone());

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
                    }

                    // Continue loop — LLM will see tool results and respond
                }
                LlmResponse::Empty => {
                    let fallback = "(no response)".to_string();
                    self.conversation.add_assistant_message(&fallback);
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
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<ProcessResult, AgentError> {
        self.current_trigger = Some(user_message.to_string());
        self.conversation.add_user_message(user_message);

        if self.conversation.over_budget() {
            self.conversation.compact();
        }

        let tool_defs = if self.llm.config().tools_enabled {
            let mut defs = self.tools.definitions();
            if let Some(ref mcp) = self.mcp {
                defs.extend(mcp.definitions());
            }
            defs
        } else {
            Vec::new()
        };

        let mut rounds = 0;
        let mut denials = Vec::new();

        loop {
            rounds += 1;
            if rounds > MAX_TOOL_ROUNDS {
                return Err(AgentError::Tool(format!(
                    "exceeded {MAX_TOOL_ROUNDS} tool call rounds — possible loop"
                )));
            }

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

                    for call in &calls {
                        tracing::info!("Agent {} executing tool: {}", self.id, call.name);

                        let result = match self.execute_tool(&call.name, &call.arguments).await {
                            Ok(result) => result,
                            Err(AgentError::PermissionDeniedCtx(ctx)) => {
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
                    }
                }
                LlmResponse::Empty => {
                    let fallback = "(no response)".to_string();
                    self.conversation.add_assistant_message(&fallback);
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

        // Try built-in tools first
        match self.tools.execute(name, arguments).await {
            Err(AgentError::ToolNotFound(_)) => {}
            other => return other,
        }

        // Try MCP
        if let Some(ref mut mcp) = self.mcp {
            match mcp.execute(name, arguments).await {
                Err(AgentError::ToolNotFound(_)) => {}
                other => return other,
            }
        }

        // Try Wasm skills
        let wasm_name = name.strip_prefix("wasm_").unwrap_or(name);
        for skill in &self.wasm_skills {
            if skill.name == wasm_name || format!("wasm_{}", skill.name) == name {
                return skill.execute(arguments);
            }
        }

        Err(AgentError::ToolNotFound(name.to_string()))
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
