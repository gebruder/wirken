//! MCP integration on the agent side.
//!
//! Until commit d36e515, the agent process spawned MCP server
//! subprocesses directly via `StdioTransport` and held all MCP
//! credentials in its own address space. As of the out-of-process
//! split (item 7, slice 1 in `docs/managed-agents-parity.md`), all
//! MCP traffic flows through the `wirken-mcp-proxy` binary over a
//! Unix domain socket. The agent never holds plaintext MCP secrets.
//!
//! This module exposes only the typed client used by `Agent`. The
//! transport, registry, and config code now lives in the
//! `wirken-mcp-proxy` crate.

mod proxy_client;

pub use proxy_client::McpProxyClient;
