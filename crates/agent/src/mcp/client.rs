use crate::error::AgentError;
use crate::tool::{ToolDef, ToolResult};

use super::transport::StdioTransport;

/// A connected MCP server client.
pub struct McpClient {
    pub name: String,
    transport: StdioTransport,
    tools: Vec<ToolDef>,
}

impl McpClient {
    /// Create a new MCP client wrapping a transport.
    pub fn new(name: String, transport: StdioTransport) -> Self {
        Self {
            name,
            transport,
            tools: Vec::new(),
        }
    }

    /// Perform the MCP initialize handshake.
    pub async fn initialize(&mut self) -> Result<(), AgentError> {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "wirken",
                "version": env!("CARGO_PKG_VERSION"),
            }
        });

        let resp = self.transport.request("initialize", Some(params)).await?;

        if let Some(ref err) = resp.error {
            return Err(AgentError::Mcp(format!(
                "MCP initialize failed: {} ({})",
                err.message, err.code
            )));
        }

        // Send initialized notification
        self.transport.notify("notifications/initialized", None).await?;

        Ok(())
    }

    /// Discover tools from the MCP server.
    /// Tool names are prefixed with `mcp_{server_name}__` to avoid collisions.
    pub async fn list_tools(&mut self) -> Result<Vec<ToolDef>, AgentError> {
        let resp = self.transport.request("tools/list", None).await?;

        if let Some(ref err) = resp.error {
            return Err(AgentError::Mcp(format!(
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

            self.tools.push(ToolDef {
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
    ) -> Result<ToolResult, AgentError> {
        let args: serde_json::Value = serde_json::from_str(arguments).unwrap_or_default();

        let params = serde_json::json!({
            "name": name,
            "arguments": args,
        });

        let resp = self.transport.request("tools/call", Some(params)).await?;

        if let Some(ref err) = resp.error {
            return Ok(ToolResult {
                output: format!("MCP tool error: {} ({})", err.message, err.code),
                success: false,
            });
        }

        let result = resp.result.unwrap_or_default();

        // MCP tool results have a "content" array with text/image blocks
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

        Ok(ToolResult {
            output: if output.is_empty() {
                "(no output)".into()
            } else {
                output
            },
            success: !is_error,
        })
    }

    /// Get the discovered tool definitions.
    pub fn tools(&self) -> &[ToolDef] {
        &self.tools
    }

    /// Shut down the MCP server.
    pub async fn shutdown(&mut self) {
        let _ = self.transport.request("shutdown", None).await;
        let _ = self.transport.notify("exit", None).await;
        self.transport.shutdown().await;
    }
}
