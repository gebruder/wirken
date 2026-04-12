//! Top-level runner that wires up the registry, the vault, and the server.
//!
//! Called by the CLI's hidden `wirken mcp-proxy` subcommand.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;

use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::config::GatewayConfig;
use wirken_vault::{CredentialStore, probe_keychain};

use crate::error::ProxyError;
use crate::mcp_config::McpConfig;
use crate::mcp_registry::{ProxyRegistry, SharedVault};
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
    // Wrapped in `Arc<Mutex<Option<_>>>` so the auth providers (item 7
    // slice 2 — BearerAuth, OAuth2Auth) can hold a long-lived
    // reference and refresh tokens on the request path.
    let vault: SharedVault = Arc::new(StdMutex::new(open_vault(&data_dir)));
    if vault.lock().expect("vault mutex").is_none() {
        tracing::warn!(
            "credential vault unavailable; vault:-prefixed env values and auth credentials will not be resolved"
        );
    }

    let mut registry = ProxyRegistry::new();

    // Load each agent's MCP config (per-agent or shared fallback).
    let agent_ids = list_agent_ids(&data_dir);
    let mut identity_agent_ids: Vec<String> = Vec::new();
    if agent_ids.is_empty() {
        // No multi-agent setup. Load the shared mcp.json under "default".
        load_for_agent(&mut registry, "default", &data_dir, vault.clone()).await;
        identity_agent_ids.push("default".to_string());
    } else {
        for agent_id in &agent_ids {
            load_for_agent(&mut registry, agent_id, &data_dir, vault.clone()).await;
            identity_agent_ids.push(agent_id.clone());
        }
        // Also load the shared config under "default" for unbound channels.
        if !agent_ids.iter().any(|id| id == "default") {
            load_for_agent(&mut registry, "default", &data_dir, vault.clone()).await;
            identity_agent_ids.push("default".to_string());
        }
    }

    // Load each agent's Ed25519 public key from disk and register it
    // with the proxy. Every agent that expects to connect to the
    // proxy must have an identity.pub file at
    // {data_dir}/agents/{agent_id}/identity.pub — the CLI creates
    // these lazily via `AgentIdentity::load_or_create` during
    // `wirken run` setup, so by the time the proxy process starts
    // the files already exist.
    //
    // An agent with MCP servers configured but no identity.pub on
    // disk is logged at WARN and silently omitted from the identity
    // table. Its handshake will fail at connect time with a clear
    // error from the server.
    for agent_id in &identity_agent_ids {
        match load_agent_pubkey(&data_dir, agent_id) {
            Ok(Some(pubkey)) => {
                registry.register_identity(agent_id, pubkey);
                tracing::info!("registered MCP proxy identity for agent '{agent_id}'");
            }
            Ok(None) => {
                tracing::warn!(
                    "agent '{agent_id}' has no identity.pub — MCP proxy connections from \
                     this agent will be refused. Run `wirken run` once to create the key."
                );
            }
            Err(e) => {
                tracing::warn!(
                    "failed to load identity.pub for agent '{agent_id}': {e} — \
                     MCP proxy connections from this agent will be refused."
                );
            }
        }
    }

    let registry = Arc::new(Mutex::new(registry));

    server::serve(socket_path, registry).await
}

/// Read `{data_dir}/agents/{agent_id}/identity.pub` and parse it as a
/// hex-encoded Ed25519 public key. Returns `Ok(None)` if the file
/// does not exist, `Err` on malformed contents, `Ok(Some(_))` on
/// success.
fn load_agent_pubkey(data_dir: &Path, agent_id: &str) -> Result<Option<VerifyingKey>, ProxyError> {
    let path = data_dir.join("agents").join(agent_id).join("identity.pub");
    if !path.exists() {
        return Ok(None);
    }
    let hex = std::fs::read_to_string(&path)
        .map_err(|e| ProxyError::Protocol(format!("read {}: {e}", path.display())))?;
    let bytes = hex_decode_32(hex.trim()).map_err(|e| {
        ProxyError::Protocol(format!(
            "parse {}: expected 64 hex chars for Ed25519 public key: {e}",
            path.display()
        ))
    })?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|e| {
        ProxyError::Protocol(format!(
            "invalid Ed25519 public key in {}: {e}",
            path.display()
        ))
    })?;
    Ok(Some(key))
}

fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex decode: {e}"))?;
    }
    Ok(out)
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
    vault: SharedVault,
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
