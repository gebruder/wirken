//! Hidden subcommand `wirken mcp-proxy`. Spawned by `wirken run` as a
//! sibling process; not intended to be invoked directly by users.
//!
//! All wiring lives in `wirken_mcp_proxy::run()`. This handler exists
//! only to bridge the CLI subcommand to the proxy crate's entry point
//! and translate its error type into `anyhow::Result`.

use anyhow::{Context, Result};

pub async fn run() -> Result<()> {
    wirken_mcp_proxy::run()
        .await
        .context("MCP proxy exited with error")
}
