//! MCP server configuration parsed from `mcp.json`.
//!
//! Moved here from `crates/agent/src/mcp/config.rs` as part of the
//! out-of-process MCP proxy split. The agent process no longer parses
//! mcp.json — only the proxy does.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::ProxyError;

/// MCP configuration — lists servers to connect to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: HashMap<String, McpServerConfig>,
}

/// Configuration for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpServerConfig {
    /// Stdio transport: spawn a process and communicate over stdin/stdout.
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
}

impl McpConfig {
    /// Load MCP config from a JSON file. Returns empty config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, ProxyError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&content)
            .map_err(|e| ProxyError::Config(format!("parse {}: {e}", path.display())))
    }
}
