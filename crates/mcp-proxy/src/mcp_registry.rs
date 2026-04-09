//! Per-agent registry of MCP server clients held by the proxy.
//!
//! Differences from the previous in-process `wirken_agent::mcp::registry`:
//!
//! 1. The registry is partitioned by `agent_id`. Tools from agent A's
//!    `mcp.json` are never visible to agent B, even when both connect to
//!    the same proxy process.
//! 2. Vault `vault:`-prefixed env values are resolved here using the
//!    real credential store. Previously the agent crate accepted a
//!    closure that callers wired to a no-op (`|_| None`) — meaning
//!    `vault:` was effectively unsupported. This is the bug fix that
//!    falls out of the proxy split.
//! 3. The vault handle never leaves this process.

use std::collections::HashMap;

use wirken_vault::CredentialStore;

use crate::error::ProxyError;
use crate::mcp_client::{McpClient, McpToolResult};
use crate::mcp_config::{McpConfig, McpServerConfig};
use crate::mcp_transport::StdioTransport;
use crate::wire::ToolDefWire;

/// All MCP clients owned by the proxy, keyed by agent id.
pub struct ProxyRegistry {
    /// agent_id → server_name → client
    by_agent: HashMap<String, HashMap<String, McpClient>>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            by_agent: HashMap::new(),
        }
    }

    /// Load all MCP servers for one agent. The vault store is used to
    /// resolve `vault:`-prefixed env values. The vault handle is borrowed
    /// only for the duration of this call.
    pub async fn load_agent(
        &mut self,
        agent_id: &str,
        config: &McpConfig,
        vault: Option<&CredentialStore>,
    ) -> Result<usize, ProxyError> {
        let mut clients = HashMap::new();

        for (name, server_config) in &config.servers {
            match server_config {
                McpServerConfig::Stdio { command, args, env } => {
                    let resolved_env = resolve_env(env, vault);

                    match StdioTransport::spawn(command, args, &resolved_env).await {
                        Ok(transport) => {
                            let mut client = McpClient::new(name.clone(), transport);

                            if let Err(e) = client.initialize().await {
                                tracing::warn!(
                                    "MCP server '{name}' (agent '{agent_id}') initialize failed: {e}"
                                );
                                client.shutdown().await;
                                continue;
                            }

                            match client.list_tools().await {
                                Ok(tools) => {
                                    tracing::info!(
                                        "MCP server '{name}' (agent '{agent_id}'): {} tools available",
                                        tools.len()
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "MCP server '{name}' (agent '{agent_id}') tools/list failed: {e}"
                                    );
                                    client.shutdown().await;
                                    continue;
                                }
                            }

                            clients.insert(name.clone(), client);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "MCP server '{name}' (agent '{agent_id}') spawn failed: {e}"
                            );
                        }
                    }
                }
            }
        }

        let count = clients.len();
        if !clients.is_empty() {
            self.by_agent.insert(agent_id.to_string(), clients);
        }
        Ok(count)
    }

    /// Whether an agent has any MCP servers loaded.
    pub fn has_agent(&self, agent_id: &str) -> bool {
        self.by_agent.contains_key(agent_id)
    }

    /// Tool definitions for one agent. Empty if the agent has no servers.
    pub fn definitions(&self, agent_id: &str) -> Vec<ToolDefWire> {
        match self.by_agent.get(agent_id) {
            Some(servers) => servers
                .values()
                .flat_map(|c| c.tools().iter().cloned())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Execute a tool call from one agent. Routes to the correct MCP
    /// server by name prefix and rejects calls that target a tool the
    /// agent does not own.
    pub async fn execute(
        &mut self,
        agent_id: &str,
        prefixed_name: &str,
        arguments: &str,
    ) -> Result<McpToolResult, ProxyError> {
        let rest = prefixed_name
            .strip_prefix("mcp_")
            .ok_or_else(|| ProxyError::Mcp(format!("not an MCP tool: {prefixed_name}")))?;

        let servers = self
            .by_agent
            .get_mut(agent_id)
            .ok_or_else(|| ProxyError::Mcp(format!("no MCP servers for agent '{agent_id}'")))?;

        for (server_name, client) in servers.iter_mut() {
            let prefix = format!("{server_name}_");
            if let Some(tool_name) = rest.strip_prefix(&prefix) {
                return client.call_tool(tool_name, arguments).await;
            }
        }

        Err(ProxyError::Mcp(format!(
            "tool '{prefixed_name}' not found for agent '{agent_id}'"
        )))
    }

    /// Shut down every MCP server for every agent.
    pub async fn shutdown(&mut self) {
        for (agent_id, servers) in self.by_agent.iter_mut() {
            for (name, client) in servers.iter_mut() {
                tracing::info!("Shutting down MCP server '{name}' (agent '{agent_id}')");
                client.shutdown().await;
            }
        }
        self.by_agent.clear();
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve `vault:`-prefixed env values from the credential store.
/// Values without the prefix are passed through unchanged. If the
/// vault is None or a credential is missing, the value is left as
/// the literal string `vault:NAME` and a warning is logged — the MCP
/// server will most likely fail to authenticate, which is the right
/// failure mode (loud, traceable).
fn resolve_env(
    env: &HashMap<String, String>,
    vault: Option<&CredentialStore>,
) -> HashMap<String, String> {
    env.iter()
        .map(|(k, v)| {
            let resolved = if let Some(vault_key) = v.strip_prefix("vault:") {
                match vault {
                    Some(store) => match store.retrieve(vault_key) {
                        Ok((secret, _)) => secret.expose().to_string(),
                        Err(e) => {
                            tracing::warn!(
                                "vault credential '{vault_key}' not found for env '{k}': {e}"
                            );
                            v.clone()
                        }
                    },
                    None => {
                        tracing::warn!(
                            "vault not available; cannot resolve '{vault_key}' for env '{k}'"
                        );
                        v.clone()
                    }
                }
            } else {
                v.clone()
            };
            (k.clone(), resolved)
        })
        .collect()
}
