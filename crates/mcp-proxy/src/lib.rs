//! Out-of-process MCP proxy.
//!
//! This crate runs as a separate OS process spawned by the gateway. It
//! owns the credential vault handle for any `vault:`-prefixed env values
//! in `mcp.json`, and exposes the resulting MCP tools to the agent over
//! a Unix domain socket.
//!
//! See `docs/managed-agents-parity.md` item 7 for the full design.
//!
//! Wire protocol: NDJSON, see [`wire`].

pub mod auth;
pub mod error;
pub mod mcp_client;
pub mod mcp_config;
pub mod mcp_registry;
pub mod mcp_transport;
pub mod oauth;
pub mod server;
pub mod tool_error;
pub mod wire;

mod runner;

pub use error::ProxyError;
pub use mcp_config::McpConfig;
pub use oauth::{
    OAuthCredential, OAuthProvider, PublicOAuthCredential, ScopeCategory, ScopeChoice,
    default_selected_scopes, load_oauth_public, lookup_provider, parse_public_view,
    run_authorization_code_flow, store_oauth,
};
pub use runner::run;
pub use tool_error::{McpToolError, detect_scope_not_granted};

#[cfg(test)]
mod tests;
