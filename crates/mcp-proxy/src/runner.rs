//! Top-level runner that wires up the registry, the credentials the
//! gateway handed over, and the server.
//!
//! Called by the CLI's hidden `wirken mcp-proxy` subcommand.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;

use wirken_audit::{SessionLog, SqliteSessionLog};
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::config::GatewayConfig;

use crate::container::{self, SandboxHost};
use crate::credentials::{ProxyCredentials, SharedCredentials};
use crate::error::ProxyError;
use crate::mcp_config::McpConfig;
use crate::mcp_config::{McpAuth, McpServerConfig};
use crate::mcp_registry::{ProxyRegistry, vault_names};
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
///
/// `credentials` is what the gateway handed over on stdin: the values
/// the MCP configs reference, and the channel to ask it for OAuth
/// refreshes. The proxy never opens the vault and holds neither the
/// vault passphrase nor its device key.
pub async fn run(credentials: ProxyCredentials) -> Result<(), ProxyError> {
    let data_dir = GatewayConfig::default().data_dir;

    let socket_path = std::env::var("WIRKEN_MCP_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("sockets").join("mcp-proxy.sock"));

    tracing::info!(
        "wirken-mcp-proxy starting (data_dir={}, socket={})",
        data_dir.display(),
        socket_path.display()
    );

    // Every agent's MCP config (per-agent or shared fallback). The
    // shared config also loads under "default" for unbound channels.
    let (identity_agent_ids, configs) = agent_configs(&data_dir);
    let credentials: SharedCredentials = Arc::new(credentials);

    // Watched from the start, so a gateway that dies while servers are
    // still starting is noticed as well. The same connection reports
    // each handed credential that changes in the vault.
    let (changed_tx, mut changed_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::credentials::ProxyNotice>();
    let mut gateway_gone = {
        let credentials = credentials.clone();
        tokio::spawn(async move { credentials.gateway_gone(changed_tx).await })
    };

    // Stdio servers with a `sandbox` block run in containers. Containers
    // an earlier proxy for this data directory left behind, for example
    // after the gateway killed it, are removed before any new one starts.
    let mut sandbox = SandboxHost::new(&data_dir);
    sandbox.probe().await;
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

    // A stopped agent's servers are not started; its place is held so a
    // resume starts them. A store that cannot be read stops none: the
    // gateway still refuses every turn and tool call of a stopped agent.
    let stopped = wirken_gateway::permissions::stopped_agents(&data_dir.join("permissions.db"))
        .unwrap_or_else(|e| {
            tracing::warn!("could not read which agents are stopped: {e}");
            Vec::new()
        });
    for (agent_id, config) in &configs {
        if stopped.contains(agent_id) {
            registry.defer_agent(agent_id);
            tracing::info!("agent '{agent_id}' is stopped; its MCP servers are not started");
            continue;
        }
        load_for_agent(
            &mut registry,
            agent_id,
            config,
            credentials.clone(),
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

    // Contained servers are restarted when their containers exit.
    let supervisors = Arc::new(Mutex::new(
        crate::supervise::Supervisors::start(registry.clone(), credentials.clone(), audit.clone())
            .await,
    ));

    // A credential changed in the vault: take its current value, or drop
    // it when the gateway no longer sends it, then start again every
    // stdio server it is passed to. HTTP servers read it per request.
    //
    // A stopped agent's servers are stopped, supervision first, and a
    // resumed one's are loaded and supervised as at start.
    let reloads = {
        let (credentials, registry, supervisors, audit, data_dir) = (
            credentials.clone(),
            registry.clone(),
            supervisors.clone(),
            audit.clone(),
            data_dir.clone(),
        );
        let restarts = supervisors.lock().await.restarts();
        tokio::spawn(async move {
            while let Some(notice) = changed_rx.recv().await {
                match notice {
                    crate::credentials::ProxyNotice::Changed(name) => {
                        if let Err(e) = credentials.refetch(&name).await {
                            tracing::warn!("credential '{name}' is no longer held: {e}");
                        }
                        let mut restarted = restarts.restart_using(&name);
                        restarted.extend(
                            registry
                                .lock()
                                .await
                                .restart_host_using(&name, &credentials)
                                .await,
                        );
                        tracing::info!(
                            credential = name,
                            servers = ?restarted,
                            "credential changed in the vault"
                        );
                    }
                    crate::credentials::ProxyNotice::AgentStopped(agent_id) => {
                        supervisors.lock().await.stop_agent(&agent_id).await;
                        let stopped = registry.lock().await.unload_agent(&agent_id).await;
                        tracing::info!(agent_id, servers = stopped, "agent stopped");
                    }
                    crate::credentials::ProxyNotice::AgentResumed(agent_id) => {
                        if registry.lock().await.is_running(&agent_id) {
                            continue;
                        }
                        let Some(config) = load_config(&agent_id, &data_dir) else {
                            continue;
                        };
                        load_for_agent(
                            &mut *registry.lock().await,
                            &agent_id,
                            &config,
                            credentials.clone(),
                            audit.as_ref(),
                        )
                        .await;
                        supervisors.lock().await.supervise_pending().await;
                        tracing::info!(agent_id, "agent resumed");
                    }
                }
            }
        })
    };

    // Serve until the socket fails, the proxy is told to stop or the
    // gateway that started it is gone, then stop every server: host
    // children are killed, containers stopped and removed. Supervision
    // stops first, so the containers stopping are not taken for exits
    // to restart from.
    let served = tokio::select! {
        result = server::serve(socket_path, registry.clone()) => result,
        () = shutdown_signal() => {
            tracing::info!("wirken-mcp-proxy shutting down");
            Ok(())
        }
        _ = &mut gateway_gone => {
            tracing::warn!("the gateway is gone; wirken-mcp-proxy shutting down");
            Ok(())
        }
    };
    gateway_gone.abort();
    reloads.abort();
    supervisors.lock().await.stop_all().await;
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

/// Every agent id with an identity, plus `default`, and the MCP config
/// each of them runs with.
fn agent_configs(data_dir: &Path) -> (Vec<String>, Vec<(String, McpConfig)>) {
    let mut ids = list_agent_ids(data_dir);
    if !ids.iter().any(|id| id == "default") {
        ids.push("default".to_string());
    }
    let configs = ids
        .iter()
        .filter_map(|id| load_config(id, data_dir).map(|c| (id.clone(), c)))
        .collect();
    (ids, configs)
}

/// Each MCP server name in the configs the proxy will load, with the
/// digest of every entry under that name: `None` for an entry whose
/// signature does not verify.
pub fn server_entries(
    data_dir: &Path,
) -> std::collections::BTreeMap<String, BTreeSet<Option<String>>> {
    let (_, configs) = agent_configs(data_dir);
    let mut out: std::collections::BTreeMap<String, BTreeSet<Option<String>>> =
        std::collections::BTreeMap::new();
    for (_, config) in &configs {
        for (name, server) in &config.servers {
            out.entry(name.clone())
                .or_default()
                .insert(crate::mcp_signing::verified_entry_digest(name, server));
        }
    }
    out
}

/// The vault names the proxy needs handed over, and which of them are
/// OAuth credentials the gateway refreshes for it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfiguredCredentials {
    pub names: BTreeSet<String>,
    pub oauth: BTreeSet<String>,
    /// Each server entry that reads a name: `(name, server, digest)`,
    /// the digest present only for an entry whose signature verifies.
    pub uses: BTreeSet<(String, String, Option<String>)>,
}

/// What the gateway must hand the proxy for `data_dir`: every name the
/// MCP configs the proxy will load reference, read the way the proxy
/// reads them.
pub fn configured_credentials(data_dir: &Path) -> ConfiguredCredentials {
    let (_, configs) = agent_configs(data_dir);
    let mut out = ConfiguredCredentials::default();
    for (_, config) in &configs {
        out.names.extend(vault_names(config));
        for (server_name, server) in &config.servers {
            let digest = crate::mcp_signing::verified_entry_digest(server_name, server);
            for name in crate::mcp_registry::server_vault_names(server) {
                out.uses.insert((name, server_name.clone(), digest.clone()));
            }
        }
        for server in config.servers.values() {
            if let McpServerConfig::Http {
                auth: Some(McpAuth::Oauth2 { credential, .. }),
                ..
            } = server
            {
                out.oauth.insert(
                    credential
                        .strip_prefix("vault:")
                        .unwrap_or(credential)
                        .to_string(),
                );
            }
        }
    }
    out
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
    credentials: SharedCredentials,
    audit: Option<&Arc<dyn SessionLog>>,
) {
    match registry
        .load_agent(agent_id, config, credentials, audit)
        .await
    {
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

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
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
