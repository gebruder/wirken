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

/// Inherited environment variables a spawned MCP server is allowed to
/// see. Anything outside this list is dropped before the child starts.
///
/// The list is the small set real-world MCP servers (npx-based,
/// python/uvx-based, native binaries) need to find their interpreter
/// and config dirs. Notably **excluded**:
///
/// - `WIRKEN_VAULT_PASSPHRASE` — mcp-proxy reads this on startup
///   (`crates/mcp-proxy/src/runner.rs::open_vault`) and it would
///   otherwise stay in mcp-proxy's environ for the proxy's lifetime.
///   Without env-clearing, every MCP child would inherit it, read it
///   from its own env, open `~/.wirken/vault.db` at the same UID,
///   and decrypt every credential — provider API keys, adapter
///   secrets, channel tokens.
/// - `SSH_*`, `AWS_*`, `GOOGLE_*`, `AZURE_*`, etc. — cloud and SSH
///   credentials the operator may have in their shell.
/// - `DISPLAY`, `XAUTHORITY` — X11 authority handles.
/// - Any other operator-environment leak.
///
/// Per-MCP `env` from `mcp.json` (including `vault:`-resolved
/// secrets) is applied AFTER this allowlist, so the operator can
/// override any of these per-server if they need to.
const SAFE_ENV_PASSTHROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_TIME",
    "LC_NUMERIC",
    "TERM",
    "TZ",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
];

/// Build the env map a spawned MCP child should see. Pure function so
/// the env-isolation property can be tested without spawning a real
/// child.
///
/// `parent_env` is any iterator of `(name, value)` pairs representing
/// the host process's environment (typically `std::env::vars()`).
/// `mcp_env` is the per-server env from `mcp.json` (already
/// `vault:`-resolved by the caller).
///
/// Output: only allowlisted vars from `parent_env`, then `mcp_env`
/// (which can override). Anything in `parent_env` not on the
/// allowlist is dropped — including secrets that have no business
/// reaching an external MCP process.
pub(crate) fn build_spawn_env(
    parent_env: impl IntoIterator<Item = (String, String)>,
    mcp_env: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in parent_env {
        if SAFE_ENV_PASSTHROUGH.iter().any(|allowed| *allowed == k) {
            out.insert(k, v);
        }
    }
    for (k, v) in mcp_env {
        out.insert(k.clone(), v.clone());
    }
    out
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

        // Strip inherited env, then re-add only the allowlisted
        // shell variables and the per-MCP env. See
        // `SAFE_ENV_PASSTHROUGH` for what this drops and why
        // (most importantly, `WIRKEN_VAULT_PASSPHRASE`).
        cmd.env_clear();
        let spawn_env = build_spawn_env(std::env::vars(), env);
        cmd.envs(spawn_env);

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

    /// OAuth context for typed error reporting on the tool-call path.
    /// Stdio transports always return `None` (no auth provider).
    /// HTTP transports delegate to the underlying
    /// [`crate::auth::AuthProvider::oauth_context`]; `OAuth2Auth`
    /// returns `Some((credential, provider))`, other auth providers
    /// return `None`.
    pub fn oauth_context(&self) -> Option<(String, String)> {
        match self {
            Transport::Stdio(_) => None,
            Transport::Http(t) => t.auth.oauth_context(),
        }
    }
}

#[cfg(test)]
mod env_isolation_tests {
    use super::{SAFE_ENV_PASSTHROUGH, build_spawn_env};
    use std::collections::HashMap;

    fn parent(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn vault_passphrase_is_dropped() {
        // The headline property: a compromised MCP child must not be
        // able to read the vault passphrase from its inherited env.
        let p = parent(&[
            ("WIRKEN_VAULT_PASSPHRASE", "supersecret"),
            ("PATH", "/usr/bin:/bin"),
        ]);
        let out = build_spawn_env(p, &HashMap::new());
        assert!(!out.contains_key("WIRKEN_VAULT_PASSPHRASE"));
        assert_eq!(out.get("PATH"), Some(&"/usr/bin:/bin".to_string()));
    }

    #[test]
    fn ssh_aws_cloud_creds_are_dropped() {
        // The operator's shell may carry SSH agent sockets, AWS
        // session tokens, GCP / Azure credentials. None of those
        // belong in an external MCP server's environ.
        let p = parent(&[
            ("SSH_AUTH_SOCK", "/tmp/ssh-XXX/agent.123"),
            ("AWS_SESSION_TOKEN", "AQoDYXdzEJr"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "/home/me/.gcp/key.json"),
            ("AZURE_CLIENT_SECRET", "secret"),
            ("PATH", "/usr/bin"),
        ]);
        let out = build_spawn_env(p, &HashMap::new());
        for k in [
            "SSH_AUTH_SOCK",
            "AWS_SESSION_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_CLIENT_SECRET",
        ] {
            assert!(!out.contains_key(k), "{k} must be dropped");
        }
        assert!(out.contains_key("PATH"));
    }

    #[test]
    fn x11_handles_are_dropped() {
        let p = parent(&[("DISPLAY", ":0"), ("XAUTHORITY", "/home/me/.Xauthority")]);
        let out = build_spawn_env(p, &HashMap::new());
        assert!(!out.contains_key("DISPLAY"));
        assert!(!out.contains_key("XAUTHORITY"));
    }

    #[test]
    fn allowlisted_shell_vars_pass_through() {
        // npx, python, uvx need PATH and HOME to find their
        // interpreter and config dirs; locale + tz keep date /
        // string handling sane. The list is exhaustive.
        let inputs: Vec<(String, String)> = SAFE_ENV_PASSTHROUGH
            .iter()
            .map(|name| ((*name).to_string(), format!("val-{name}")))
            .collect();
        let out = build_spawn_env(inputs, &HashMap::new());
        for name in SAFE_ENV_PASSTHROUGH {
            assert_eq!(
                out.get(*name),
                Some(&format!("val-{name}")),
                "{name} must pass through"
            );
        }
    }

    #[test]
    fn per_mcp_env_overrides_allowlist() {
        // The operator can pin a per-server PATH (e.g., to point
        // at a specific node toolchain) by listing it in mcp.json.
        let p = parent(&[("PATH", "/usr/bin:/bin")]);
        let mut mcp = HashMap::new();
        mcp.insert("PATH".to_string(), "/opt/node/bin".to_string());
        mcp.insert("GITHUB_TOKEN".to_string(), "ghp_xxx".to_string());
        let out = build_spawn_env(p, &mcp);
        assert_eq!(out.get("PATH"), Some(&"/opt/node/bin".to_string()));
        assert_eq!(out.get("GITHUB_TOKEN"), Some(&"ghp_xxx".to_string()));
    }

    #[test]
    fn empty_parent_env_yields_only_mcp_env() {
        // Defence against a future call path that ignores
        // std::env::vars() and synthesises its own input.
        let mut mcp = HashMap::new();
        mcp.insert("MY_VAR".to_string(), "1".to_string());
        let out = build_spawn_env(Vec::<(String, String)>::new(), &mcp);
        assert_eq!(out.len(), 1);
        assert_eq!(out.get("MY_VAR"), Some(&"1".to_string()));
    }

    #[test]
    fn unrelated_wirken_env_vars_are_also_dropped() {
        // Any operator-side `WIRKEN_*` config that happens to be
        // in the parent shell does not belong in an MCP server's
        // environ, even if not directly secret.
        let p = parent(&[
            ("WIRKEN_DATA_DIR", "/home/me/.wirken"),
            ("WIRKEN_LOG", "debug"),
            ("WIRKEN_VAULT_PASSPHRASE", "secret"),
        ]);
        let out = build_spawn_env(p, &HashMap::new());
        assert!(out.is_empty());
    }

    #[test]
    fn allowlist_contents_are_pinned_to_documented_minimum() {
        // Companion to `allowlisted_shell_vars_pass_through`: that
        // test iterates whatever is in `SAFE_ENV_PASSTHROUGH` and
        // verifies pass-through, so it would silently accept a
        // newly-added key. This test pins the exact list so a
        // "just one more key" addition fails review and the change
        // author has to argue why the new key is safe to cross
        // the gateway → MCP child trust boundary.
        let expected: &[&str] = &[
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LC_MESSAGES",
            "LC_TIME",
            "LC_NUMERIC",
            "TERM",
            "TZ",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
        ];
        assert_eq!(
            SAFE_ENV_PASSTHROUGH, expected,
            "SAFE_ENV_PASSTHROUGH drifted. Adding a key here expands \
             the surface that crosses gateway → MCP child; document \
             the reason in the SAFE_ENV_PASSTHROUGH docstring and \
             update this test in the same commit."
        );
    }
}
