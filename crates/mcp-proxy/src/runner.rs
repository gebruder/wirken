//! Top-level runner that wires up the registry, the vault, and the server.
//!
//! Called by the CLI's hidden `wirken mcp-proxy` subcommand.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::config::GatewayConfig;
use wirken_vault::{CredentialStore, probe_keychain};

use crate::error::ProxyError;
use crate::mcp_config::McpConfig;
use crate::mcp_registry::ProxyRegistry;
use crate::server;

/// Run the MCP proxy. Reads configuration from the standard wirken
/// data directory and listens on the standard MCP proxy socket.
///
/// Environment variables:
///
/// - `WIRKEN_DATA_DIR` — base data directory (defaults to ~/.wirken)
/// - `WIRKEN_MCP_SOCKET` — override for the listen socket path
/// - `WIRKEN_VAULT_PASSPHRASE` — passphrase used by the keychain
///   fallback when the OS keychain is unavailable
pub async fn run() -> Result<(), ProxyError> {
    let data_dir = std::env::var("WIRKEN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| GatewayConfig::default().data_dir);

    let socket_path = std::env::var("WIRKEN_MCP_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("sockets").join("mcp-proxy.sock"));

    tracing::info!(
        "wirken-mcp-proxy starting (data_dir={}, socket={})",
        data_dir.display(),
        socket_path.display()
    );

    // Open the credential vault. The vault handle stays in this process
    // for the lifetime of the proxy and is never sent to the agent.
    let vault = open_vault(&data_dir);
    if vault.is_none() {
        tracing::warn!(
            "credential vault unavailable; vault:-prefixed env values will not be resolved"
        );
    }

    let mut registry = ProxyRegistry::new();

    // Load each agent's MCP config (per-agent or shared fallback).
    let agent_ids = list_agent_ids(&data_dir);
    if agent_ids.is_empty() {
        // No multi-agent setup. Load the shared mcp.json under "default".
        load_for_agent(&mut registry, "default", &data_dir, vault.as_ref()).await;
    } else {
        for agent_id in &agent_ids {
            load_for_agent(&mut registry, agent_id, &data_dir, vault.as_ref()).await;
        }
        // Also load the shared config under "default" for unbound channels.
        if !agent_ids.iter().any(|id| id == "default") {
            load_for_agent(&mut registry, "default", &data_dir, vault.as_ref()).await;
        }
    }

    let registry = Arc::new(Mutex::new(registry));

    server::serve(socket_path, registry).await
}

fn open_vault(data_dir: &Path) -> Option<CredentialStore> {
    let keychain = probe_keychain(data_dir, || {
        std::env::var("WIRKEN_VAULT_PASSPHRASE").unwrap_or_default()
    });
    CredentialStore::open(&data_dir.join("vault.db"), keychain.as_ref()).ok()
}

fn list_agent_ids(data_dir: &Path) -> Vec<String> {
    let path = data_dir.join("agent_config.db");
    if !path.exists() {
        return Vec::new();
    }
    let store = match AgentConfigStore::open(&path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.id)
        .collect()
}

async fn load_for_agent(
    registry: &mut ProxyRegistry,
    agent_id: &str,
    data_dir: &Path,
    vault: Option<&CredentialStore>,
) {
    let per_agent = data_dir.join("agents").join(agent_id).join("mcp.json");
    let shared = data_dir.join("mcp.json");

    let path = if per_agent.exists() {
        per_agent
    } else {
        shared
    };

    let config = match McpConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "MCP config load failed for agent '{agent_id}' ({}): {e}",
                path.display()
            );
            return;
        }
    };

    if config.servers.is_empty() {
        return;
    }

    match registry.load_agent(agent_id, &config, vault).await {
        Ok(n) if n > 0 => {
            tracing::info!("loaded {n} MCP server(s) for agent '{agent_id}'");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("MCP load failed for agent '{agent_id}': {e}");
        }
    }
}
