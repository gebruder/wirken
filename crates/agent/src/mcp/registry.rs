use std::collections::HashMap;

use crate::error::AgentError;
use crate::tool::{ToolDef, ToolResult};

use super::client::McpClient;
use super::config::{McpConfig, McpServerConfig};
use super::transport::StdioTransport;

/// Manages multiple MCP server connections.
pub struct McpRegistry {
    clients: HashMap<String, McpClient>,
}

impl McpRegistry {
    /// Connect to all configured MCP servers, initialize, and discover tools.
    /// The `resolve_secret` function resolves `vault:` prefixed values to actual secrets.
    pub async fn load<F>(config: &McpConfig, resolve_secret: F) -> Result<Self, AgentError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut clients = HashMap::new();

        for (name, server_config) in &config.servers {
            match server_config {
                McpServerConfig::Stdio { command, args, env } => {
                    // Resolve vault: prefixed env values
                    let resolved_env: HashMap<String, String> = env
                        .iter()
                        .map(|(k, v)| {
                            let resolved = if let Some(vault_key) = v.strip_prefix("vault:") {
                                resolve_secret(vault_key).unwrap_or_else(|| v.clone())
                            } else {
                                v.clone()
                            };
                            (k.clone(), resolved)
                        })
                        .collect();

                    match StdioTransport::spawn(command, args, &resolved_env).await {
                        Ok(transport) => {
                            let mut client = McpClient::new(name.clone(), transport);

                            if let Err(e) = client.initialize().await {
                                tracing::warn!("MCP server '{name}' initialize failed: {e}");
                                client.shutdown().await;
                                continue;
                            }

                            match client.list_tools().await {
                                Ok(tools) => {
                                    tracing::info!(
                                        "MCP server '{name}': {} tools available",
                                        tools.len()
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!("MCP server '{name}' tools/list failed: {e}");
                                    client.shutdown().await;
                                    continue;
                                }
                            }

                            clients.insert(name.clone(), client);
                        }
                        Err(e) => {
                            tracing::warn!("MCP server '{name}' spawn failed: {e}");
                        }
                    }
                }
            }
        }

        Ok(Self { clients })
    }

    /// Get all tool definitions from all connected MCP servers.
    pub fn definitions(&self) -> Vec<ToolDef> {
        self.clients
            .values()
            .flat_map(|c| c.tools().iter().cloned())
            .collect()
    }

    /// Execute a tool call, routing to the correct MCP server by name prefix.
    /// Tool names are formatted as `mcp_{server}_{tool}`.
    pub async fn execute(
        &mut self,
        prefixed_name: &str,
        arguments: &str,
    ) -> Result<ToolResult, AgentError> {
        // Parse prefix: mcp_{server}_{tool}
        let rest = prefixed_name
            .strip_prefix("mcp_")
            .ok_or_else(|| AgentError::ToolNotFound(prefixed_name.to_string()))?;

        // Find which server owns this tool by checking all clients
        for (server_name, client) in &mut self.clients {
            let prefix = format!("{server_name}_");
            if let Some(tool_name) = rest.strip_prefix(&prefix) {
                return client.call_tool(tool_name, arguments).await;
            }
        }

        Err(AgentError::ToolNotFound(prefixed_name.to_string()))
    }

    /// Number of connected servers.
    pub fn server_count(&self) -> usize {
        self.clients.len()
    }

    /// Shut down all MCP servers.
    pub async fn shutdown(&mut self) {
        for (name, client) in &mut self.clients {
            tracing::info!("Shutting down MCP server '{name}'");
            client.shutdown().await;
        }
        self.clients.clear();
    }
}
