//! Wire protocol between the agent (client) and the MCP proxy (server).
//!
//! Newline-delimited JSON over a Unix domain socket. One JSON object
//! per line, framed by '\n'. Each line is at most [`MAX_FRAME_BYTES`]
//! bytes — readers MUST enforce this before allocating, to defend
//! against a malicious peer sending an unbounded line.
//!
//! ## Handshake
//!
//! Protocol version 2 adds an Ed25519 challenge-response handshake
//! before any other traffic. Ported from `wirken_ipc::auth` — same
//! primitives, different framing.
//!
//! 1. Server → client: [`AuthChallenge`] with a fresh 32-byte nonce.
//! 2. Client → server: [`AuthResponse`] with `agent_id`, the client's
//!    Ed25519 public key, and an Ed25519 signature over the nonce.
//! 3. Server verifies that `agent_id` is registered with a matching
//!    public key and that the signature is valid. On success the
//!    server sends [`HelloAck`] with `has_servers`; on failure the
//!    server closes the connection without sending a frame.
//!
//! The handshake is the only authoritative trust boundary. The prior
//! "filesystem ACL is the trust boundary" model is retired — any
//! sibling process running as the same user could previously claim an
//! agent id verbatim and invoke tools under that agent's stored
//! credentials.

use serde::{Deserialize, Serialize};

/// Maximum bytes the reader will accept for a single line, including
/// the trailing newline. Anything larger is a protocol error and the
/// connection is dropped.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Current protocol version. Bumped to 2 when the Ed25519 handshake
/// replaced the old self-declared-agent_id `Hello` frame. Old clients
/// speaking version 1 will fail to parse the server's first frame and
/// disconnect.
pub const PROTOCOL_VERSION: u32 = 2;

/// Size of the authentication challenge nonce in bytes.
pub const CHALLENGE_NONCE_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Handshake frames
// ---------------------------------------------------------------------------

/// First frame on every connection. Sent by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub kind: AuthChallengeKind,
    pub protocol_version: u32,
    /// 32 bytes hex-encoded (64 ASCII chars).
    pub nonce: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthChallengeKind {
    AuthChallenge,
}

/// Reply to [`AuthChallenge`]. Sent by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub kind: AuthResponseKind,
    pub agent_id: String,
    /// 32-byte Ed25519 public key, hex-encoded (64 chars).
    pub public_key: String,
    /// 64-byte Ed25519 signature over the challenge nonce, hex-encoded
    /// (128 chars).
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthResponseKind {
    AuthResponse,
}

/// Sent by the server after a successful handshake. Carries
/// `has_servers` so the client can short-circuit when no MCP servers
/// are loaded for this agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub kind: HelloAckKind,
    pub protocol_version: u32,
    /// True if the proxy has at least one MCP server scoped to this agent.
    pub has_servers: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelloAckKind {
    HelloAck,
}

// ---------------------------------------------------------------------------
// Post-handshake request/response
// ---------------------------------------------------------------------------

/// A request from the agent to the proxy. Tagged by `kind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// List all tool definitions visible to this agent.
    ListTools { id: u64 },
    /// Call a tool by name (the prefixed `mcp_{server}_{tool}` form).
    CallTool {
        id: u64,
        name: String,
        arguments: String,
    },
    /// Request the proxy shut down its servers and close the connection.
    Shutdown { id: u64 },
}

impl Request {
    pub fn id(&self) -> u64 {
        match self {
            Request::ListTools { id } | Request::CallTool { id, .. } | Request::Shutdown { id } => {
                *id
            }
        }
    }
}

/// A response from the proxy to the agent. Always references the
/// request `id` so callers can match concurrent requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    ListToolsResult {
        id: u64,
        tools: Vec<ToolDefWire>,
    },
    CallToolResult {
        id: u64,
        output: String,
        success: bool,
    },
    ShutdownAck {
        id: u64,
    },
    Error {
        id: u64,
        message: String,
    },
}

impl Response {
    pub fn id(&self) -> u64 {
        match self {
            Response::ListToolsResult { id, .. }
            | Response::CallToolResult { id, .. }
            | Response::ShutdownAck { id }
            | Response::Error { id, .. } => *id,
        }
    }
}

/// Wire form of a tool definition. Mirrors `wirken_agent::tool::ToolDef`
/// but is defined here so the proxy crate does not depend on the agent
/// crate. The agent reconstructs `ToolDef` from this on the way in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefWire {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}
