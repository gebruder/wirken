use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::error::AgentError;

/// JSON-RPC 2.0 request.
#[derive(Debug, serde::Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: Option<u64>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, serde::Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, serde::Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Stdio transport: spawn a child process and communicate via JSON-RPC over stdin/stdout.
pub struct StdioTransport {
    child: Child,
    stdin: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}

impl StdioTransport {
    /// Spawn a child process with the given command, args, and environment.
    pub async fn spawn(
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> Result<Self, AgentError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        for (k, v) in env {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| AgentError::Mcp(format!("spawn '{command}': {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AgentError::Mcp("no stdin on child".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AgentError::Mcp("no stdout on child".into()))?;

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        })
    }

    /// Send a JSON-RPC request and read the response.
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, AgentError> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: Some(id),
            method: method.to_string(),
            params,
        };

        let payload =
            serde_json::to_string(&request).map_err(|e| AgentError::Mcp(e.to_string()))?;

        // Write newline-delimited JSON
        self.stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| AgentError::Mcp(format!("write to MCP server: {e}")))?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| AgentError::Mcp(format!("write newline: {e}")))?;
        self.stdin
            .flush()
            .await
            .map_err(|e| AgentError::Mcp(format!("flush stdin: {e}")))?;

        // Read response lines until we get one with a matching id
        let timeout = std::time::Duration::from_secs(30);
        let response = tokio::time::timeout(timeout, self.read_response(id)).await;

        match response {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(AgentError::Mcp(format!(
                "MCP server timed out after {}s",
                timeout.as_secs()
            ))),
        }
    }

    /// Send a notification (no id, no response expected).
    pub async fn notify(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), AgentError> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: None,
            method: method.to_string(),
            params,
        };

        let payload =
            serde_json::to_string(&request).map_err(|e| AgentError::Mcp(e.to_string()))?;

        self.stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| AgentError::Mcp(format!("write notification: {e}")))?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| AgentError::Mcp(format!("write newline: {e}")))?;
        self.stdin
            .flush()
            .await
            .map_err(|e| AgentError::Mcp(format!("flush: {e}")))?;

        Ok(())
    }

    async fn read_response(&mut self, expected_id: u64) -> Result<JsonRpcResponse, AgentError> {
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| AgentError::Mcp(format!("read from MCP server: {e}")))?;

            if n == 0 {
                return Err(AgentError::Mcp("MCP server closed stdout".into()));
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let response: JsonRpcResponse = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => continue, // Skip notifications and malformed lines
            };

            // Check if this is the response we're waiting for
            if let Some(ref id) = response.id {
                let matches = match id {
                    serde_json::Value::Number(n) => n.as_u64() == Some(expected_id),
                    _ => false,
                };
                if matches {
                    return Ok(response);
                }
            }

            // Not our response — skip (could be a notification)
        }
    }

    /// Kill the child process.
    pub async fn shutdown(&mut self) {
        let _ = self.child.kill().await;
    }
}
