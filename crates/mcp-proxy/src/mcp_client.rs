//! MCP client wrapping a single stdio transport.
//!
//! Moved here from `crates/agent/src/mcp/client.rs` as part of the
//! out-of-process MCP proxy split. Edits: error type and ToolDef
//! type are now local to this crate so the proxy does not depend on
//! `wirken-agent`.

use crate::error::ProxyError;
use crate::mcp_transport::Transport;
use crate::tool_error::{McpToolError, detect_scope_not_granted};
use crate::wire::ToolDefWire;

/// Result of executing an MCP tool. Mirrors `wirken_agent::tool::ToolResult`
/// but is defined locally so the proxy does not depend on `wirken-agent`.
///
/// `error_kind` is populated when a per-provider detector
/// (see [`crate::tool_error`]) classifies the failure as a known
/// shape (e.g. scope-not-granted). Existing callers that read only
/// `output` continue to work; the field carries the typed message
/// for the operator already so display-side dispatch is optional.
#[derive(Debug, Clone)]
pub struct McpToolResult {
    pub output: String,
    pub success: bool,
    /// Typed classification of the failure when the detector
    /// matched. `None` on success and on unknown / unclassifiable
    /// errors (the generic error path).
    pub error_kind: Option<McpToolError>,
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

        // Snapshot the auth context once (cheap clone of two
        // strings) so both error-handling branches below can run
        // the per-provider scope detector without re-reading the
        // transport. `None` for non-OAuth transports / auth providers
        // (Stdio, NoAuth, BearerAuth) and bypasses detection entirely
        // since rescope only applies to OAuth-managed credentials.
        let oauth_ctx = self.transport.oauth_context();

        if let Some(ref err) = resp.error {
            let raw_output = format!("MCP tool error: {} ({})", err.message, err.code);
            let error_kind = classify_error(&oauth_ctx, &err.message);
            return Ok(McpToolResult {
                output: error_kind
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or(raw_output),
                success: false,
                error_kind,
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

        let raw_output = if output.is_empty() {
            "(no output)".into()
        } else {
            output
        };
        let error_kind = if is_error {
            classify_error(&oauth_ctx, &raw_output)
        } else {
            None
        };

        Ok(McpToolResult {
            output: error_kind
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or(raw_output),
            success: !is_error,
            error_kind,
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

/// Run the per-provider scope detector when an OAuth context is
/// available. Returns `None` for non-OAuth transports, unknown
/// providers, or response shapes the detector cannot match with
/// confidence. The caller substitutes the typed message into
/// `output` when this is `Some`.
fn classify_error(oauth_ctx: &Option<(String, String)>, error_text: &str) -> Option<McpToolError> {
    let (credential, provider) = oauth_ctx.as_ref()?;
    detect_scope_not_granted(provider, credential, error_text)
}
