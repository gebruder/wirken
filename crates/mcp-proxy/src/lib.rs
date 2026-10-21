//! Out-of-process MCP proxy.
//!
//! This crate runs as a separate OS process spawned by the gateway. It
//! never opens the credential vault: the gateway hands it the values its
//! `mcp.json` entries reference at spawn and refreshes OAuth tokens for
//! it ([`credentials`], [`refresh_service`]). It exposes the resulting
//! MCP tools to the agent over a Unix domain socket.
//!
//! Wire protocol: NDJSON, see [`wire`].

// Slicing a str off a character boundary panics. Each slice that
// stays carries an allow naming why its offsets are boundaries.
#![cfg_attr(not(test), deny(clippy::string_slice))]

pub mod auth;
pub mod container;
pub mod credentials;
pub mod egress;
pub mod error;
pub mod mcp_client;
pub mod mcp_config;
pub mod mcp_registry;
pub mod mcp_signing;
pub mod mcp_transport;
pub mod oauth;
pub mod refresh_service;
pub mod server;
pub mod supervise;
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
pub use runner::{ConfiguredCredentials, configured_credentials, run};
pub use tool_error::{McpToolError, detect_scope_not_granted};

#[cfg(test)]
mod tests;
