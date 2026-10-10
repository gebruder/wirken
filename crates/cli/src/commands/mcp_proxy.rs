//! Hidden subcommand `wirken mcp-proxy`. Spawned by `wirken run` as a
//! sibling process; not intended to be invoked directly by users.
//!
//! The gateway hands the proxy its credentials on stdin, in the same
//! format adapters get theirs: the values its `mcp.json` entries
//! reference, OAuth credentials without their refresh token, and the
//! token that admits it to the gateway's refresh socket. The proxy never
//! opens the vault. All other wiring lives in `wirken_mcp_proxy::run()`.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use wirken_mcp_proxy::credentials::{
    GATEWAY_SOCKET_ENV, GATEWAY_TOKEN_ENTRY, GatewayLink, ProxyCredentials,
};
use zeroize::Zeroizing;

use super::adapter_handoff::Handoff;

pub async fn run() -> Result<()> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "`wirken mcp-proxy` is started by `wirken run`, which hands it its credentials \
             on stdin; it does not run from a terminal"
        );
    }
    let mut entries = Handoff::read_from(stdin.lock())?.into_entries();
    let token = entries
        .remove(GATEWAY_TOKEN_ENTRY)
        .map(|t| Zeroizing::new(t.expose().to_string()));
    let socket = std::env::var_os(GATEWAY_SOCKET_ENV).map(PathBuf::from);
    let gateway = match (socket, token) {
        (Some(socket), Some(token)) => Some(GatewayLink::new(socket, token)),
        _ => None,
    };
    let credentials = ProxyCredentials::new(entries.into_iter().collect(), gateway);
    wirken_mcp_proxy::run(credentials)
        .await
        .context("MCP proxy exited with error")
}
