//! Error types local to the proxy crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}
