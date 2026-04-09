//! MCP client wrapping a single stdio transport.
//!
//! Moved here from `crates/agent/src/mcp/client.rs` as part of the
//! out-of-process MCP proxy split. Edits: error type and ToolDef
//! type are now local to this crate so the proxy does not depend on
//! `wirken-agent`.

use crate::error::ProxyError;
use crate::mcp_transport::Transport;
use crate::wire::ToolDefWire;

/// Result of executing an MCP tool. Mirrors `wirken_agent::tool::ToolResult`
/// but is defined locally so the proxy does not depend on `wirken-agent`.
#[derive(Debug, Clone)]
pub struct McpToolResult {
    pub output: String,
    pub success: bool,
}

/// A connected MCP server client. Holds a [`Transport`] enum so the
/// same client logic works over stdio (item 7 slice 1) and HTTP
/// (item 7 slice 2). The MCP protocol itself is identical at the
/// JSON-RPC layer; the transport is just a byte mover.
pub struct McpClient {
    pub name: String,
    transport: Transport,
    tools: Vec<ToolDefWire>,
}

impl McpClient {
    pub fn new(name: String, transport: Transport) -> Self {
        Self {
            name,
            transport,
            tools: Vec::new(),
        }
    }

    /// Perform the MCP initialize handshake.
    pub async fn initialize(&mut self) -> Result<(), ProxyError> {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "wirken-mcp-proxy",
                "version": env!("CARGO_PKG_VERSION"),
            }
        });

        let resp = self.transport.request("initialize", Some(params)).await?;

        if let Some(ref err) = resp.error {
            return Err(ProxyError::Mcp(format!(
                "MCP initialize failed: {} ({})",
                err.message, err.code
            )));
        }

        self.transport
            .notify("notifications/initialized", None)
            .await?;

        Ok(())
    }

    /// Discover tools from the MCP server.
    /// Tool names are prefixed with `mcp_{server_name}_` to avoid collisions.
    pub async fn list_tools(&mut self) -> Result<Vec<ToolDefWire>, ProxyError> {
        let resp = self.transport.request("tools/list", None).await?;

        if let Some(ref err) = resp.error {
            return Err(ProxyError::Mcp(format!(
                "MCP tools/list failed: {} ({})",
                err.message, err.code
            )));
        }

        let result = resp.result.unwrap_or_default();
        let tools_array = result
            .get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        self.tools.clear();

        for tool_json in &tools_array {
            let name = tool_json
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let description = tool_json
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();

            let parameters = tool_json
                .get("inputSchema")
                .cloned()
                .unwrap_or(serde_json::json!({"type": "object", "properties": {}}));

            let prefixed_name = format!("mcp_{}_{}", self.name, name);

            self.tools.push(ToolDefWire {
                name: prefixed_name,
                description: format!("[{}] {}", self.name, description),
                parameters,
            });
        }

        Ok(self.tools.clone())
    }

    /// Call a tool on this MCP server.
    /// The `name` should be the unprefixed original tool name.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: &str,
    ) -> Result<McpToolResult, ProxyError> {
        let args: serde_json::Value = serde_json::from_str(arguments).unwrap_or_default();

        let params = serde_json::json!({
            "name": name,
            "arguments": args,
        });

        let resp = self.transport.request("tools/call", Some(params)).await?;

        if let Some(ref err) = resp.error {
            return Ok(McpToolResult {
                output: format!("MCP tool error: {} ({})", err.message, err.code),
                success: false,
            });
        }

        let result = resp.result.unwrap_or_default();

        let content = result
            .get("content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        let mut output = String::new();
        for block in &content {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push_str(text);
            }
        }

        let is_error = result
            .get("isError")
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        Ok(McpToolResult {
            output: if output.is_empty() {
                "(no output)".into()
            } else {
                output
            },
            success: !is_error,
        })
    }

    /// Get the discovered tool definitions.
    pub fn tools(&self) -> &[ToolDefWire] {
        &self.tools
    }

    /// Shut down the MCP server.
    pub async fn shutdown(&mut self) {
        let _ = self.transport.request("shutdown", None).await;
        let _ = self.transport.notify("exit", None).await;
        self.transport.shutdown().await;
    }
}
