//! Top-level runner that wires up the registry, the vault, and the server.
//!
//! Called by the CLI's hidden `wirken mcp-proxy` subcommand.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;

use wirken_audit::{SessionLog, SqliteSessionLog};
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::config::GatewayConfig;
use wirken_vault::{CredentialStore, ScopedCredentialStore, probe_keychain};

use crate::container::{self, SandboxHost};
use crate::error::ProxyError;
use crate::mcp_config::McpConfig;
use crate::mcp_registry::{ProxyRegistry, SharedVault, vault_names};
use crate::server;

/// Run the MCP proxy. Reads configuration from the standard wirken
/// data directory and listens on the standard MCP proxy socket.
///
/// Environment variables:
///
/// - `WIRKEN_DATA_DIR` — base data directory (defaults to ~/.wirken).
///   Read through `GatewayConfig::default`, the same resolver the
///   gateway uses, so parent and child cannot disagree about where
///   the vault and the audit log live.
/// - `WIRKEN_MCP_SOCKET` — override for the listen socket path
/// - `WIRKEN_VAULT_PASSPHRASE` — passphrase used by the keychain
///   fallback when the OS keychain is unavailable
pub async fn run() -> Result<(), ProxyError> {
    let data_dir = GatewayConfig::default().data_dir;

    let socket_path = std::env::var("WIRKEN_MCP_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("sockets").join("mcp-proxy.sock"));

    tracing::info!(
        "wirken-mcp-proxy starting (data_dir={}, socket={})",
        data_dir.display(),
        socket_path.display()
    );

    // Every agent's MCP config (per-agent or shared fallback), read
    // before the vault opens so the vault can be limited to the names
    // they reference. The shared config also loads under "default" for
    // unbound channels. Nothing here spawns or awaits, which
    // `open_vault`'s environment scrub depends on.
    let mut identity_agent_ids = list_agent_ids(&data_dir);
    if !identity_agent_ids.iter().any(|id| id == "default") {
        identity_agent_ids.push("default".to_string());
    }
    let configs: Vec<(String, McpConfig)> = identity_agent_ids
        .iter()
        .filter_map(|id| load_config(id, &data_dir).map(|c| (id.clone(), c)))
        .collect();
    let vault_names: BTreeSet<String> = configs
        .iter()
        .flat_map(|(_, config)| vault_names(config))
        .collect();

    // Open the credential vault limited to those names. The handle
    // stays in this process for the lifetime of the proxy and is never
    // sent to the agent. Wrapped in `Arc<Mutex<Option<_>>>` so the auth
    // providers, BearerAuth and OAuth2Auth, can hold a long-lived
    // reference and refresh tokens on the request path.
    let vault: SharedVault = Arc::new(StdMutex::new(open_vault(&data_dir, vault_names)));
    if vault.lock().expect("vault mutex").is_none() {
        tracing::warn!(
            "credential vault unavailable; vault:-prefixed env values and auth credentials will not be resolved"
        );
    }

    // Stdio servers with a `sandbox` block run in containers. Built
    // after the vault so nothing touches the environment, or awaits,
    // before `open_vault`'s scrub. Containers an earlier proxy for this
    // data directory left behind, for example after the gateway killed
    // it, are removed before any new one starts.
    let sandbox = SandboxHost::new(&data_dir);
    if let Some(docker) = &sandbox.docker {
        let removed = container::sweep(docker, &sandbox).await;
        if removed > 0 {
            tracing::info!(
                "removed {removed} MCP server container(s) an earlier proxy left behind"
            );
        }
    }
    let mut registry = ProxyRegistry::new().with_sandbox(sandbox);

    // Open the audit log so MCP signature-verify outcomes land on the
    // `gateway-mcp` sentinel session. The proxy is the sole writer of
    // that session id; the gateway never appends there.
    //
    // Failure to open does not block proxy startup. The gateway opens
    // the same DB independently, and the proxy's per-entry decisions
    // are computable from the same inputs even without audit. Log and
    // continue.
    let audit_path = data_dir.join("audit.db");
    let audit: Option<Arc<dyn SessionLog>> = match SqliteSessionLog::open(&audit_path) {
        Ok(log) => Some(Arc::new(log) as Arc<dyn SessionLog>),
        Err(e) => {
            tracing::warn!(
                path = %audit_path.display(),
                error = %e,
                "MCP proxy could not open audit log; entry verify outcomes will not be \
                 recorded on the gateway-mcp sentinel session"
            );
            None
        }
    };

    for (agent_id, config) in &configs {
        load_for_agent(
            &mut registry,
            agent_id,
            config,
            vault.clone(),
            audit.as_ref(),
        )
        .await;
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

    // Serve until the socket fails or the proxy is told to stop, then
    // stop every server: host children are killed, containers stopped
    // and removed.
    let served = tokio::select! {
        result = server::serve(socket_path, registry.clone()) => result,
        () = shutdown_signal() => {
            tracing::info!("wirken-mcp-proxy shutting down");
            Ok(())
        }
    };
    registry.lock().await.shutdown().await;
    served
}

/// Resolves on SIGTERM or SIGINT (Ctrl-C elsewhere). If the handlers
/// cannot be installed it never resolves, and the proxy runs until it
/// is killed, as before.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
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
    let bytes = crate::server::hex_decode_fixed::<32>(hex.trim()).map_err(|e| {
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

/// Open the vault limited to `names`, the credentials the loaded MCP
/// configs reference. Any other name is refused and logged.
fn open_vault(data_dir: &Path, names: BTreeSet<String>) -> Option<ScopedCredentialStore> {
    let keychain = probe_keychain(data_dir, || {
        let pp = std::env::var("WIRKEN_VAULT_PASSPHRASE").unwrap_or_default();
        // Wipe the passphrase from this process's environ now that
        // the AgeFileKeychain has copied it onto the heap. Defence
        // in depth against a future code path that spawns a child
        // without env_clear() — `mcp_transport::spawn` already
        // clears, but a `/proc/<mcp-proxy-pid>/environ` read by
        // another process at the same UID would otherwise still
        // turn up the passphrase as a plaintext null-separated
        // string in mcp-proxy's environ for the proxy's lifetime.
        //
        // SAFETY: `remove_var` is undefined behaviour while another
        // thread reads or writes the environment. The `#[tokio::main]`
        // runtime has worker threads by now, but nothing has been
        // spawned onto them: `wirken mcp-proxy` dispatches straight
        // into `run()`, and this closure is called by `probe_keychain`
        // from `open_vault`, which `run()` reaches before its first
        // `.await` and before any `tokio::spawn`. The workers are
        // parked with no task to run, so the main thread is the only
        // one executing. mcp-proxy reads `WIRKEN_VAULT_PASSPHRASE`
        // nowhere else, and this call is the only writer.
        //
        // Anything spawned earlier in `run()` in a later change
        // breaks this, which is why the scrub stays first.
        unsafe {
            std::env::remove_var("WIRKEN_VAULT_PASSPHRASE");
        }
        pp
    });
    CredentialStore::open_scoped(
        &data_dir.join("vault.db"),
        keychain.as_ref(),
        "mcp-proxy",
        names,
    )
    .ok()
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

/// The MCP config `agent_id` runs with: its own `mcp.json`, else the
/// shared one. `None` when the file does not parse or lists no servers.
fn load_config(agent_id: &str, data_dir: &Path) -> Option<McpConfig> {
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
            return None;
        }
    };

    (!config.servers.is_empty()).then_some(config)
}

async fn load_for_agent(
    registry: &mut ProxyRegistry,
    agent_id: &str,
    config: &McpConfig,
    vault: SharedVault,
    audit: Option<&Arc<dyn SessionLog>>,
) {
    match registry.load_agent(agent_id, config, vault, audit).await {
        Ok(n) if n > 0 => {
            tracing::info!("loaded {n} MCP server(s) for agent '{agent_id}'");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("MCP load failed for agent '{agent_id}': {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::load_agent_pubkey;

    #[test]
    fn non_ascii_identity_pub_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("agents").join("a");
        std::fs::create_dir_all(&dir).unwrap();
        // 64 bytes, the expected length, with every two-byte slice
        // splitting a character.
        let hex = format!("a{}a", "\u{e9}".repeat(31));
        assert_eq!(hex.len(), 64);
        std::fs::write(dir.join("identity.pub"), hex).unwrap();
        let err = load_agent_pubkey(tmp.path(), "a").expect_err("non-ASCII identity.pub");
        assert!(format!("{err}").contains("non-ASCII hex string"), "{err}");
    }
}
