//! Stdio JSON-RPC transport to a single MCP server subprocess.
//!
//! Moved here from `crates/agent/src/mcp/transport.rs` as part of the
//! out-of-process MCP proxy split. Logic is unchanged — the only edit
//! is the error type (ProxyError instead of AgentError).

use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::error::ProxyError;

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
    ) -> Result<Self, ProxyError> {
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
            .map_err(|e| ProxyError::Mcp(format!("spawn '{command}': {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ProxyError::Mcp("no stdin on child".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProxyError::Mcp("no stdout on child".into()))?;

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
    ) -> Result<JsonRpcResponse, ProxyError> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: Some(id),
            method: method.to_string(),
            params,
        };

        let payload =
            serde_json::to_string(&request).map_err(|e| ProxyError::Mcp(e.to_string()))?;

        self.stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| ProxyError::Mcp(format!("write to MCP server: {e}")))?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| ProxyError::Mcp(format!("write newline: {e}")))?;
        self.stdin
            .flush()
            .await
            .map_err(|e| ProxyError::Mcp(format!("flush stdin: {e}")))?;

        let timeout = std::time::Duration::from_secs(30);
        let response = tokio::time::timeout(timeout, self.read_response(id)).await;

        match response {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ProxyError::Mcp(format!(
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
    ) -> Result<(), ProxyError> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: None,
            method: method.to_string(),
            params,
        };

        let payload =
            serde_json::to_string(&request).map_err(|e| ProxyError::Mcp(e.to_string()))?;

        self.stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| ProxyError::Mcp(format!("write notification: {e}")))?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| ProxyError::Mcp(format!("write newline: {e}")))?;
        self.stdin
            .flush()
            .await
            .map_err(|e| ProxyError::Mcp(format!("flush: {e}")))?;

        Ok(())
    }

    async fn read_response(&mut self, expected_id: u64) -> Result<JsonRpcResponse, ProxyError> {
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| ProxyError::Mcp(format!("read from MCP server: {e}")))?;

            if n == 0 {
                return Err(ProxyError::Mcp("MCP server closed stdout".into()));
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let response: JsonRpcResponse = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if let Some(ref id) = response.id {
                let matches = match id {
                    serde_json::Value::Number(n) => n.as_u64() == Some(expected_id),
                    _ => false,
                };
                if matches {
                    return Ok(response);
                }
            }
        }
    }

    /// Kill the child process.
    pub async fn shutdown(&mut self) {
        let _ = self.child.kill().await;
    }
}

// ---------------------------------------------------------------------------
// HTTP transport (item 7 slice 2)
// ---------------------------------------------------------------------------

/// HTTP JSON-RPC transport. Sends MCP requests as POST bodies to a
/// remote URL and reads JSON-RPC responses from the response body.
/// Auth headers come from a pluggable [`crate::auth::AuthProvider`]
/// so OAuth refresh and bearer-token resolution stay outside the
/// transport itself.
pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
    auth: Box<dyn crate::auth::AuthProvider>,
    next_id: u64,
}

impl HttpTransport {
    /// Construct an HTTP transport for `url` with the given auth
    /// provider. The reqwest client is configured with HTTPS-only
    /// for non-localhost URLs and a 30s request timeout.
    pub fn new(url: String, auth: Box<dyn crate::auth::AuthProvider>) -> Result<Self, ProxyError> {
        let is_localhost = url.starts_with("http://localhost")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://[::1]");
        if !url.starts_with("https://") && !is_localhost {
            return Err(ProxyError::Mcp(format!(
                "MCP HTTP endpoint must use HTTPS (got {url}); only localhost may use http://"
            )));
        }
        let client = reqwest::Client::builder()
            .https_only(!is_localhost)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ProxyError::Mcp(format!("HTTP client: {e}")))?;
        Ok(Self {
            client,
            url,
            auth,
            next_id: 1,
        })
    }

    /// Send a JSON-RPC request and parse the response.
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, ProxyError> {
        let id = self.next_id;
        self.next_id += 1;

        let payload = JsonRpcRequest {
            jsonrpc: "2.0",
            id: Some(id),
            method: method.to_string(),
            params,
        };

        let mut req = self.client.post(&self.url).json(&payload);
        if let Some(header) = self.auth.authorization_header().await? {
            req = req.header(reqwest::header::AUTHORIZATION, header);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ProxyError::Mcp(format!("MCP HTTP {method}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProxyError::Mcp(format!(
                "MCP HTTP {method} returned {status}: {body}"
            )));
        }

        let parsed: JsonRpcResponse = resp
            .json()
            .await
            .map_err(|e| ProxyError::Mcp(format!("MCP HTTP {method} body parse: {e}")))?;
        Ok(parsed)
    }

    /// Send a notification. HTTP MCP servers may or may not honor
    /// notifications; we POST and ignore the response body.
    pub async fn notify(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), ProxyError> {
        let payload = JsonRpcRequest {
            jsonrpc: "2.0",
            id: None,
            method: method.to_string(),
            params,
        };
        let mut req = self.client.post(&self.url).json(&payload);
        if let Some(header) = self.auth.authorization_header().await? {
            req = req.header(reqwest::header::AUTHORIZATION, header);
        }
        let _ = req
            .send()
            .await
            .map_err(|e| ProxyError::Mcp(format!("MCP HTTP notify {method}: {e}")))?;
        Ok(())
    }

    /// HTTP transports have no persistent connection; shutdown is a no-op.
    pub async fn shutdown(&mut self) {}
}

// ---------------------------------------------------------------------------
// Unified Transport enum
// ---------------------------------------------------------------------------

/// Either of the two MCP transport flavors. The proxy holds one of
/// these per server and dispatches `request` / `notify` / `shutdown`
/// to the right variant. An enum (rather than `Box<dyn Transport>`)
/// avoids needing async-trait on the transport itself.
///
/// `StdioTransport` is heap-boxed to keep the enum size balanced
/// between variants — `StdioTransport` carries a `Child` and
/// `BufReader<ChildStdout>` which together are several hundred
/// bytes, while `HttpTransport` is much smaller.
pub enum Transport {
    Stdio(Box<StdioTransport>),
    Http(HttpTransport),
}

impl Transport {
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, ProxyError> {
        match self {
            Transport::Stdio(t) => t.request(method, params).await,
            Transport::Http(t) => t.request(method, params).await,
        }
    }

    pub async fn notify(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), ProxyError> {
        match self {
            Transport::Stdio(t) => t.notify(method, params).await,
            Transport::Http(t) => t.notify(method, params).await,
        }
    }

    pub async fn shutdown(&mut self) {
        match self {
            Transport::Stdio(t) => t.shutdown().await,
            Transport::Http(t) => t.shutdown().await,
        }
    }
}
