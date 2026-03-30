use std::path::PathBuf;

use crate::conversation::Conversation;
use crate::error::AgentError;
use crate::llm::{LlmClient, LlmConfig, LlmResponse};
use crate::skill::{Skill, SkillLoader};
use crate::tool::{ToolConfig, ToolRegistry};

/// Maximum tool call rounds per turn to prevent infinite loops.
const MAX_TOOL_ROUNDS: usize = 20;

/// The agent runtime. Processes inbound messages, calls the LLM,
/// executes tools, and produces responses.
pub struct Agent {
    pub id: String,
    conversation: Conversation,
    llm: LlmClient,
    tools: ToolRegistry,
    skills: Vec<Skill>,
    system_prompt: String,
    /// API key passed per-request — agent never stores it long-term.
    /// In production, the gateway's LLM proxy handles this.
    api_key: Option<String>,
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
            skills: Vec::new(),
            system_prompt,
            api_key,
        })
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
    /// 4. Return the final text response
    pub async fn process_message(&mut self, user_message: &str) -> Result<String, AgentError> {
        self.conversation.add_user_message(user_message);

        // Compact if over budget
        if self.conversation.over_budget() {
            self.conversation.compact();
        }

        let tool_defs = self.tools.definitions();
        let mut rounds = 0;

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
                    return Ok(text);
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

                        let result = self.tools.execute(&call.name, &call.arguments).await?;

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
                    return Ok(fallback);
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
        format!("{}...", &s[..max])
    }
}
