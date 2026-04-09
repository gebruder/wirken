//! Wire protocol between the agent (client) and the MCP proxy (server).
//!
//! Newline-delimited JSON over a Unix domain socket. One JSON object
//! per line, framed by '\n'. Each line is at most [`MAX_FRAME_BYTES`]
//! bytes — readers MUST enforce this before allocating, to defend
//! against a malicious peer sending an unbounded line.
//!
//! The protocol is stateful: every connection MUST send a [`Hello`]
//! frame as its first message and receive a [`HelloAck`] before any
//! other frame is exchanged. The hello carries the `agent_id` so the
//! proxy knows which subset of MCP servers to expose to this caller.

use serde::{Deserialize, Serialize};

/// Maximum bytes the reader will accept for a single line, including
/// the trailing newline. Anything larger is a protocol error and the
/// connection is dropped.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// First frame on every connection. Sent by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub kind: HelloKind,
    pub protocol_version: u32,
    pub agent_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelloKind {
    Hello,
}

/// Reply to [`Hello`]. Sent by the proxy.
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

/// Current protocol version. Bump on any wire-incompatible change.
pub const PROTOCOL_VERSION: u32 = 1;

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
            Request::ListTools { id }
            | Request::CallTool { id, .. }
            | Request::Shutdown { id } => *id,
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
