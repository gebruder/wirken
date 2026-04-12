//! Client for `wirken-mcp-proxy`.
//!
//! Connects to the proxy's Unix domain socket, performs the Ed25519
//! challenge-response handshake, fetches the agent's tool definitions
//! on `connect_and_load`, and serves `call_tool` requests by sending
//! one-shot RPCs over the same connection.
//!
//! Single-threaded use is assumed: each `McpProxyClient` instance is
//! held by exactly one `Agent` and the `Agent` serializes its tool
//! calls. Concurrent calls on the same client would scramble the
//! NDJSON request/response stream — wrap in a `Mutex` if shared.
//!
//! ## Handshake
//!
//! 1. Server sends [`AuthChallenge`] with a fresh nonce.
//! 2. Client signs the nonce with its [`AgentIdentity`] Ed25519 key.
//! 3. Client sends [`AuthResponse`] with agent_id, public key, signature.
//! 4. Server verifies and sends [`HelloAck`] (or drops the connection).

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use wirken_mcp_proxy::wire::{
    AuthChallenge, AuthChallengeKind, AuthResponse, AuthResponseKind, HelloAck, HelloAckKind,
    MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, Response, ToolDefWire,
};

use crate::error::AgentError;
use crate::identity::AgentIdentity;
use crate::tool::{ToolDef, ToolResult};

/// Maximum time to wait for the proxy socket to become reachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Single connect attempt timeout. We loop until [`CONNECT_TIMEOUT`].
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum time to wait for one RPC reply.
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Connection to the out-of-process MCP proxy, scoped to one agent.
pub struct McpProxyClient {
    agent_id: String,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    cached_tools: Vec<ToolDef>,
    has_servers: bool,
}

impl McpProxyClient {
    /// Connect to the proxy and perform the Ed25519 handshake. The
    /// caller provides an [`AgentIdentity`] whose public key must be
    /// registered with the proxy at startup (via the agent's
    /// `identity.pub` file in the data directory) — otherwise the
    /// proxy drops the connection without a HelloAck.
    ///
    /// Returns a client whose tool definitions are not yet loaded —
    /// call [`Self::load_tools`] to populate them.
    pub async fn connect(
        socket_path: &Path,
        agent_id: &str,
        identity: &AgentIdentity,
    ) -> Result<Self, AgentError> {
        let stream = connect_with_retry(socket_path).await?;
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        // 1. Read the server's AuthChallenge.
        let line = read_line(&mut reader)
            .await?
            .ok_or_else(|| AgentError::Mcp("proxy closed before auth challenge".into()))?;
        let challenge: AuthChallenge = serde_json::from_str(&line)
            .map_err(|e| AgentError::Mcp(format!("auth challenge parse: {e}")))?;
        if challenge.kind != AuthChallengeKind::AuthChallenge {
            return Err(AgentError::Mcp(format!(
                "expected auth_challenge, got {:?}",
                challenge.kind
            )));
        }
        if challenge.protocol_version != PROTOCOL_VERSION {
            return Err(AgentError::Mcp(format!(
                "proxy protocol version mismatch: client {PROTOCOL_VERSION} proxy {}",
                challenge.protocol_version
            )));
        }

        // 2. Sign the nonce with this agent's Ed25519 secret key.
        let nonce = hex_decode(&challenge.nonce)
            .map_err(|e| AgentError::Mcp(format!("challenge nonce decode: {e}")))?;
        let signature = identity.sign(&nonce);

        // 3. Send AuthResponse.
        let response = AuthResponse {
            kind: AuthResponseKind::AuthResponse,
            agent_id: agent_id.to_string(),
            public_key: hex_encode(&identity.public_key_bytes()),
            signature: hex_encode(&signature.to_bytes()),
        };
        write_line(&mut writer, &response).await?;

        // 4. Read HelloAck (or EOF, meaning the proxy rejected us).
        let line = read_line(&mut reader).await?.ok_or_else(|| {
            AgentError::Mcp(
                "proxy rejected the handshake (no HelloAck) — \
                     is this agent's identity.pub registered with the proxy?"
                    .into(),
            )
        })?;
        let ack: HelloAck = serde_json::from_str(&line)
            .map_err(|e| AgentError::Mcp(format!("hello ack parse: {e}")))?;
        if ack.kind != HelloAckKind::HelloAck {
            return Err(AgentError::Mcp("expected hello ack".into()));
        }
        if ack.protocol_version != PROTOCOL_VERSION {
            return Err(AgentError::Mcp(format!(
                "proxy protocol version mismatch: client {PROTOCOL_VERSION} proxy {}",
                ack.protocol_version
            )));
        }

        Ok(Self {
            agent_id: agent_id.to_string(),
            reader,
            writer,
            next_id: 1,
            cached_tools: Vec::new(),
            has_servers: ack.has_servers,
        })
    }

    /// Whether the proxy reported any MCP servers for this agent.
    pub fn has_servers(&self) -> bool {
        self.has_servers
    }

    /// Fetch the tool definitions from the proxy and cache them locally.
    /// `definitions()` returns the cached set thereafter.
    pub async fn load_tools(&mut self) -> Result<usize, AgentError> {
        if !self.has_servers {
            return Ok(0);
        }
        let id = self.next_request_id();
        let req = Request::ListTools { id };
        let resp = self.rpc(req).await?;
        match resp {
            Response::ListToolsResult { tools, .. } => {
                self.cached_tools = tools.into_iter().map(wire_to_tool_def).collect();
                Ok(self.cached_tools.len())
            }
            Response::Error { message, .. } => Err(AgentError::Mcp(message)),
            other => Err(AgentError::Mcp(format!(
                "unexpected response to list_tools: {other:?}"
            ))),
        }
    }

    /// Tool definitions cached from the most recent [`Self::load_tools`] call.
    pub fn definitions(&self) -> Vec<ToolDef> {
        self.cached_tools.clone()
    }

    /// Execute a tool by its prefixed name (`mcp_{server}_{tool}`).
    pub async fn execute(&mut self, name: &str, arguments: &str) -> Result<ToolResult, AgentError> {
        let id = self.next_request_id();
        let req = Request::CallTool {
            id,
            name: name.to_string(),
            arguments: arguments.to_string(),
        };
        let resp = self.rpc(req).await?;
        match resp {
            Response::CallToolResult {
                output, success, ..
            } => Ok(ToolResult { output, success }),
            Response::Error { message, .. } => Ok(ToolResult {
                output: format!("MCP proxy error: {message}"),
                success: false,
            }),
            other => Err(AgentError::Mcp(format!(
                "unexpected response to call_tool: {other:?}"
            ))),
        }
    }

    /// Tell the proxy to disconnect this connection cleanly.
    pub async fn shutdown(&mut self) {
        let id = self.next_request_id();
        let req = Request::Shutdown { id };
        let _ = self.rpc(req).await;
    }

    fn next_request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send a request and read responses until one matches the request id.
    async fn rpc(&mut self, request: Request) -> Result<Response, AgentError> {
        let expected_id = request.id();
        write_line(&mut self.writer, &request).await?;

        let read_fut = async {
            loop {
                let line = read_line(&mut self.reader).await?;
                let line = line.ok_or_else(|| AgentError::Mcp("proxy closed mid-rpc".into()))?;
                let resp: Response = serde_json::from_str(&line)
                    .map_err(|e| AgentError::Mcp(format!("response parse: {e}")))?;
                if resp.id() == expected_id || resp.id() == 0 {
                    return Ok::<_, AgentError>(resp);
                }
                tracing::debug!(
                    "ignoring out-of-order response for agent '{}' (id {})",
                    self.agent_id,
                    resp.id()
                );
            }
        };

        match tokio::time::timeout(RPC_TIMEOUT, read_fut).await {
            Ok(r) => r,
            Err(_) => Err(AgentError::Mcp(format!(
                "proxy RPC timed out after {}s",
                RPC_TIMEOUT.as_secs()
            ))),
        }
    }
}

async fn connect_with_retry(socket_path: &Path) -> Result<UnixStream, AgentError> {
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    let mut last_err = None;
    while std::time::Instant::now() < deadline {
        match UnixStream::connect(socket_path).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(CONNECT_RETRY_INTERVAL).await;
            }
        }
    }
    Err(AgentError::Mcp(format!(
        "could not connect to MCP proxy at {} within {}s: {}",
        socket_path.display(),
        CONNECT_TIMEOUT.as_secs(),
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no attempts".into())
    )))
}

async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> Result<Option<String>, AgentError> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        match tokio::io::AsyncReadExt::read(reader, &mut byte).await {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(AgentError::Mcp("eof in mid-line from proxy".into()));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    let line = String::from_utf8(buf)
                        .map_err(|e| AgentError::Mcp(format!("non-utf8 line from proxy: {e}")))?;
                    return Ok(Some(line));
                }
                if buf.len() >= MAX_FRAME_BYTES {
                    return Err(AgentError::Mcp(format!(
                        "proxy frame exceeds {MAX_FRAME_BYTES} bytes"
                    )));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(AgentError::Mcp(format!("read from proxy: {e}"))),
        }
    }
}

async fn write_line<T: serde::Serialize>(
    writer: &mut OwnedWriteHalf,
    value: &T,
) -> Result<(), AgentError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|e| AgentError::Mcp(format!("serialize for proxy: {e}")))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| AgentError::Mcp(format!("write to proxy: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| AgentError::Mcp(format!("flush to proxy: {e}")))?;
    Ok(())
}

fn wire_to_tool_def(w: ToolDefWire) -> ToolDef {
    ToolDef {
        name: w.name,
        description: w.description,
        parameters: w.parameters,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
