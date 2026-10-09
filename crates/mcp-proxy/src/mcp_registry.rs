//! Per-agent registry of MCP server clients held by the proxy.
//!
//! Differences from the previous in-process `wirken_agent::mcp::registry`:
//!
//! 1. The registry is partitioned by `agent_id`. Tools from agent A's
//!    `mcp.json` are never visible to agent B, even when both connect to
//!    the same proxy process.
//! 2. Vault `vault:`-prefixed env values are resolved here against
//!    the real credential store. The agent crate took a resolver
//!    closure that every caller wired to a no-op, so `vault:` parsed
//!    and then silently resolved to nothing.
//! 3. The vault handle never leaves this process.
//! 4. HTTP MCP servers with bearer or OAuth2 auth are loaded via
//!    [`HttpTransport`] and a pluggable
//!    [`AuthProvider`]. The auth provider holds an `Arc` to the
//!    shared vault and resolves credentials on every request.
//!
//! [`HttpTransport`]: crate::mcp_transport::HttpTransport
//! [`AuthProvider`]: crate::auth::AuthProvider

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use wirken_audit::{SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_vault::{CredentialAccess, ScopedCredentialStore};

use crate::auth::{AuthProvider, BearerAuth, NoAuth, OAuth2Auth};
use crate::error::ProxyError;
use crate::mcp_client::{McpClient, McpToolResult};
use crate::mcp_config::{McpAuth, McpConfig, McpServerConfig};
use crate::mcp_signing::{McpVerifyResult, bundled_mcp_pubkey, verify_mcp_entry};
use crate::mcp_transport::{HttpTransport, StdioTransport, Transport};
use crate::wire::ToolDefWire;

/// Sentinel session id for cross-cutting MCP load-time events.
/// Parallels `gateway-hooks` used by the hook accept loop.
pub const MCP_SENTINEL_SESSION: &str = "gateway-mcp";

/// Outcome of [`pre_spawn_verify`]: do we spawn, and what audit row
/// do we emit?
enum PreSpawnDecision {
    /// Spawn the entry. `signer` is the attribution label for the
    /// audit row.
    Spawn { signer: String },
    /// Refuse the entry. `reason` is the snake_case label for the
    /// audit row and the operator log.
    Refuse { reason: String },
}

/// Vault handle shared by every auth provider in the proxy. Wrapped
/// in `Arc<Mutex<Option<_>>>` because:
///
/// - `Arc` so each long-lived [`AuthProvider`] can clone a reference
/// - `Mutex` because `rusqlite::Connection` is not `Sync`
/// - `Option` because the vault may be unavailable (no keychain,
///   wrong passphrase) and the proxy still needs to serve `NoAuth`
///   and stdio servers
pub type SharedVault = Arc<Mutex<Option<ScopedCredentialStore>>>;

/// All MCP clients owned by the proxy, keyed by agent id.
pub struct ProxyRegistry {
    /// agent_id → server_name → client
    by_agent: HashMap<String, HashMap<String, McpClient>>,
    /// Declared tool costs per agent, per server, keyed by bare tool
    /// name. Read from the signed `mcp.json` entry at load time and
    /// stamped onto each definition handed to an agent.
    costs_by_agent: HashMap<String, HashMap<String, HashMap<String, u64>>>,
    /// agent_id → Ed25519 public key used to authenticate incoming
    /// proxy connections claiming this agent_id. Populated at proxy
    /// startup from each agent's `identity.pub` file.
    identities: HashMap<String, VerifyingKey>,
    /// Per-credential OAuth refresh mutex. Guarantees that two
    /// concurrent requests that both need to refresh the same
    /// credential serialize through one token endpoint call —
    /// providers that rotate refresh tokens (Google) invalidate the
    /// second refresh otherwise. Keyed by the vault credential name
    /// (after stripping the `vault:` prefix).
    oauth_refresh_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            by_agent: HashMap::new(),
            costs_by_agent: HashMap::new(),
            identities: HashMap::new(),
            oauth_refresh_locks: HashMap::new(),
        }
    }

    /// Register an Ed25519 public key as the authoritative identity
    /// for `agent_id`. Overwrites any existing registration.
    pub fn register_identity(&mut self, agent_id: &str, pubkey: VerifyingKey) {
        self.identities.insert(agent_id.to_string(), pubkey);
    }

    /// Look up the registered Ed25519 public key for `agent_id`.
    /// Used by the server handshake.
    pub fn get_identity(&self, agent_id: &str) -> Option<&VerifyingKey> {
        self.identities.get(agent_id)
    }

    /// Fetch (or lazily create) the per-credential refresh mutex for
    /// `credential_name`. The same `Arc` is handed out across every
    /// [`OAuth2Auth`] instance that references the same credential,
    /// so two concurrent tool calls through two different MCP servers
    /// sharing a vault entry still serialize their refreshes.
    fn oauth_refresh_lock(&mut self, credential_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.oauth_refresh_locks
            .entry(credential_name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Load all MCP servers for one agent. The vault store is shared
    /// by long-lived auth providers; vault `vault:`-prefixed env
    /// values are resolved here at load time and baked into the
    /// MCP server's spawn environment (legacy stdio behavior).
    ///
    /// `audit` is an optional session-log handle. When supplied, each
    /// entry's signature-verification outcome is recorded on the
    /// `gateway-mcp` sentinel session via
    /// [`SessionEvent::McpEntryVerified`] or
    /// [`SessionEvent::McpEntryRefused`]. The proxy passes `None` in
    /// callers that have no audit-log access (tests, dev rigs).
    pub async fn load_agent(
        &mut self,
        agent_id: &str,
        config: &McpConfig,
        vault: SharedVault,
        audit: Option<&Arc<dyn SessionLog>>,
    ) -> Result<usize, ProxyError> {
        let mut clients = HashMap::new();
        let bundled_root = bundled_mcp_pubkey();

        for (name, server_config) in &config.servers {
            let decision = pre_spawn_verify(name, server_config, bundled_root.as_ref());
            let signer = match &decision {
                PreSpawnDecision::Spawn { signer } => signer.clone(),
                PreSpawnDecision::Refuse { reason } => {
                    tracing::warn!(
                        agent_id,
                        server = name,
                        reason,
                        "MCP entry refused by signature gate; not spawning"
                    );
                    if let Some(log) = audit {
                        let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
                        let _ = log.append(
                            &handle,
                            TrustLevel::System,
                            SessionEvent::McpEntryRefused {
                                server_name: name.clone(),
                                reason: reason.clone(),
                            },
                        );
                    }
                    continue;
                }
            };

            if let Some(log) = audit {
                let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
                let _ = log.append(
                    &handle,
                    TrustLevel::System,
                    SessionEvent::McpEntryVerified {
                        server_name: name.clone(),
                        signer: signer.clone(),
                    },
                );
            }

            match server_config {
                McpServerConfig::Stdio {
                    command, args, env, ..
                } => {
                    // Resolve `vault:`-prefixed env values via a
                    // brief read on the shared vault.
                    let resolved_env = {
                        let guard = vault.lock().expect("vault mutex");
                        resolve_env(env, guard.as_ref())
                    };

                    match StdioTransport::spawn(command, args, &resolved_env).await {
                        Ok(stdio) => {
                            let mut client =
                                McpClient::new(name.clone(), Transport::Stdio(Box::new(stdio)));
                            if let Err(e) = init_and_list(&mut client, agent_id).await {
                                tracing::warn!(
                                    "MCP stdio server '{name}' (agent '{agent_id}') skipped: {e}"
                                );
                                continue;
                            }
                            clients.insert(name.clone(), client);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "MCP server '{name}' (agent '{agent_id}') spawn failed: {e}"
                            );
                        }
                    }
                }
                McpServerConfig::Http { url, auth, .. } => {
                    let auth_provider: Box<dyn AuthProvider> = match auth {
                        None => Box::new(NoAuth),
                        Some(McpAuth::Bearer { credential }) => Box::new(BearerAuth::new(
                            strip_vault_prefix(credential).to_string(),
                            vault.clone(),
                        )),
                        Some(McpAuth::Oauth2 {
                            provider,
                            credential,
                        }) => {
                            let cred_name = strip_vault_prefix(credential).to_string();
                            let refresh_lock = self.oauth_refresh_lock(&cred_name);
                            Box::new(OAuth2Auth::new(
                                cred_name,
                                provider.clone(),
                                vault.clone(),
                                refresh_lock,
                            ))
                        }
                    };

                    let http = match HttpTransport::new(url.clone(), auth_provider) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::warn!(
                                "MCP http server '{name}' (agent '{agent_id}') construction failed: {e}"
                            );
                            continue;
                        }
                    };
                    let mut client = McpClient::new(name.clone(), Transport::Http(http));
                    if let Err(e) = init_and_list(&mut client, agent_id).await {
                        tracing::warn!(
                            "MCP http server '{name}' (agent '{agent_id}') skipped: {e}"
                        );
                        continue;
                    }
                    clients.insert(name.clone(), client);
                }
            }
        }

        let count = clients.len();
        if !clients.is_empty() {
            let costs: HashMap<String, HashMap<String, u64>> = clients
                .keys()
                .filter_map(|server| {
                    config
                        .servers
                        .get(server)
                        .map(|c| (server.clone(), c.tool_costs().clone()))
                })
                .filter(|(_, m)| !m.is_empty())
                .collect();
            if !costs.is_empty() {
                self.costs_by_agent.insert(agent_id.to_string(), costs);
            }
            self.by_agent.insert(agent_id.to_string(), clients);
        }
        Ok(count)
    }

    /// Whether an agent has any MCP servers loaded.
    pub fn has_agent(&self, agent_id: &str) -> bool {
        self.by_agent.contains_key(agent_id)
    }

    /// Tool definitions for one agent. Empty if the agent has no servers.
    /// Each definition carries its operator-declared cost, looked up
    /// by bare tool name against the server entry's `tool_costs`. A
    /// tool with no declared cost carries `None` and is not budget
    /// gated.
    pub fn definitions(&self, agent_id: &str) -> Vec<ToolDefWire> {
        let Some(servers) = self.by_agent.get(agent_id) else {
            return Vec::new();
        };
        let costs = self.costs_by_agent.get(agent_id);
        servers
            .iter()
            .flat_map(|(server_name, client)| {
                let prefix = format!("mcp_{server_name}_");
                let server_costs = costs.and_then(|c| c.get(server_name));
                client.tools().iter().map(move |t| {
                    let bare = t.name.strip_prefix(&prefix).unwrap_or(&t.name);
                    let mut def = t.clone();
                    def.cost_usd_micros = server_costs.and_then(|m| m.get(bare)).copied();
                    def
                })
            })
            .collect()
    }

    /// Execute a tool call from one agent. Routes to the correct MCP
    /// server by name prefix and rejects calls that target a tool the
    /// agent does not own.
    pub async fn execute(
        &mut self,
        agent_id: &str,
        prefixed_name: &str,
        arguments: &str,
    ) -> Result<McpToolResult, ProxyError> {
        let rest = prefixed_name
            .strip_prefix("mcp_")
            .ok_or_else(|| ProxyError::Mcp(format!("not an MCP tool: {prefixed_name}")))?;

        let servers = self
            .by_agent
            .get_mut(agent_id)
            .ok_or_else(|| ProxyError::Mcp(format!("no MCP servers for agent '{agent_id}'")))?;

        for (server_name, client) in servers.iter_mut() {
            let prefix = format!("{server_name}_");
            if let Some(tool_name) = rest.strip_prefix(&prefix) {
                return client.call_tool(tool_name, arguments).await;
            }
        }

        Err(ProxyError::Mcp(format!(
            "tool '{prefixed_name}' not found for agent '{agent_id}'"
        )))
    }

    /// Shut down every MCP server for every agent.
    pub async fn shutdown(&mut self) {
        for (agent_id, servers) in self.by_agent.iter_mut() {
            for (name, client) in servers.iter_mut() {
                tracing::info!("Shutting down MCP server '{name}' (agent '{agent_id}')");
                client.shutdown().await;
            }
        }
        self.by_agent.clear();
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

async fn init_and_list(client: &mut McpClient, agent_id: &str) -> Result<(), ProxyError> {
    client.initialize().await?;
    let tools = client.list_tools().await?;
    tracing::info!(
        "MCP server '{}' (agent '{agent_id}'): {} tools available",
        client.name,
        tools.len()
    );
    Ok(())
}

/// Resolve the pre-spawn signature decision for one MCP entry. The
/// extracts on each variant pull the signature triplet uniformly so
/// the verify call has one shape regardless of Stdio vs Http.
fn pre_spawn_verify(
    name: &str,
    config: &McpServerConfig,
    bundled_root: Option<&VerifyingKey>,
) -> PreSpawnDecision {
    let (sig, key, delegation) = match config {
        McpServerConfig::Stdio {
            signature,
            signer_key,
            signer_key_delegation,
            ..
        } => (
            signature.as_deref(),
            signer_key.as_deref(),
            signer_key_delegation.as_deref(),
        ),
        McpServerConfig::Http {
            signature,
            signer_key,
            signer_key_delegation,
            ..
        } => (
            signature.as_deref(),
            signer_key.as_deref(),
            signer_key_delegation.as_deref(),
        ),
    };

    let result = verify_mcp_entry(name, config, sig, key, delegation, bundled_root);
    let allow_unsigned = wirken_gateway::org::parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_MCP");

    match result {
        McpVerifyResult::Valid { signer } => PreSpawnDecision::Spawn { signer },
        McpVerifyResult::Invalid => PreSpawnDecision::Refuse {
            reason: "signature_invalid".to_string(),
        },
        McpVerifyResult::Unsigned => {
            // No signature on the entry. Three sub-cases:
            //  - No anchor configured: pre-anchor parity, allow.
            //  - Anchor configured + bypass set: allow with attribution.
            //  - Anchor configured + bypass unset: refuse.
            //
            // The no-anchor branch exists only while
            // `wirken-mcp-pubkey.pub` ships empty. Once a bundled anchor
            // ships, it has no reason to exist.
            if bundled_root.is_none() {
                PreSpawnDecision::Spawn {
                    signer: "<no-anchor>".to_string(),
                }
            } else if allow_unsigned {
                tracing::warn!(
                    server = name,
                    "WIRKEN_ALLOW_UNSIGNED_MCP=1: loading unsigned MCP entry under anchored build"
                );
                PreSpawnDecision::Spawn {
                    signer: "<unsigned-bypass>".to_string(),
                }
            } else {
                PreSpawnDecision::Refuse {
                    reason: "unsigned".to_string(),
                }
            }
        }
    }
}

/// Resolve `vault:`-prefixed env values from the credential store.
/// Values without the prefix are passed through unchanged. If the
/// vault is None or a credential is missing, the value is left as
/// the literal string `vault:NAME` and a warning is logged — the MCP
/// server will most likely fail to authenticate, which is the right
/// failure mode (loud, traceable).
fn resolve_env(
    env: &HashMap<String, String>,
    vault: Option<&ScopedCredentialStore>,
) -> HashMap<String, String> {
    env.iter()
        .map(|(k, v)| {
            let resolved = if let Some(vault_key) = v.strip_prefix("vault:") {
                match vault {
                    Some(store) => match store.retrieve(vault_key) {
                        Ok((secret, _)) => secret.expose().to_string(),
                        Err(e) => {
                            tracing::warn!(
                                "vault credential '{vault_key}' not found for env '{k}': {e}"
                            );
                            v.clone()
                        }
                    },
                    None => {
                        tracing::warn!(
                            "vault not available; cannot resolve '{vault_key}' for env '{k}'"
                        );
                        v.clone()
                    }
                }
            } else {
                v.clone()
            };
            (k.clone(), resolved)
        })
        .collect()
}

/// Every vault name `config` reads: the `vault:` env values of its
/// stdio servers and the bearer and OAuth credentials of its HTTP
/// servers. The proxy opens the vault limited to the union of these
/// over every agent's config.
pub fn vault_names(config: &McpConfig) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for server in config.servers.values() {
        match server {
            McpServerConfig::Stdio { env, .. } => names.extend(
                env.values()
                    .filter_map(|v| v.strip_prefix("vault:"))
                    .map(str::to_string),
            ),
            McpServerConfig::Http { auth, .. } => match auth {
                Some(McpAuth::Bearer { credential } | McpAuth::Oauth2 { credential, .. }) => {
                    names.insert(strip_vault_prefix(credential).to_string());
                }
                None => {}
            },
        }
    }
    names
}

/// Strip the optional `vault:` prefix from a credential reference.
/// `"vault:linear-token"` → `"linear-token"`. Bare names without
/// the prefix pass through unchanged for forward compatibility.
fn strip_vault_prefix(s: &str) -> &str {
    s.strip_prefix("vault:").unwrap_or(s)
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn config(json: &str) -> McpConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn vault_names_covers_env_bearer_and_oauth_references() {
        let config = config(
            r#"{"servers": {
                "local": {"command": "srv", "args": [], "env": {
                    "API_KEY": "vault:stdio-key", "PLAIN": "not-a-reference"}},
                "linear": {"transport": "http", "url": "https://mcp.linear.app/sse",
                    "auth": {"type": "bearer", "credential": "vault:linear-token"}},
                "notion": {"transport": "http", "url": "https://mcp.notion.com/mcp",
                    "auth": {"type": "oauth2", "provider": "notion", "credential": "notion-oauth"}},
                "open": {"transport": "http", "url": "https://example.com/mcp"}
            }}"#,
        );
        let names: Vec<String> = vault_names(&config).into_iter().collect();
        assert_eq!(names, ["linear-token", "notion-oauth", "stdio-key"]);
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[test]
    fn resolve_env_reads_only_names_in_the_scope() {
        let tmp = tempfile::TempDir::new().unwrap();
        let device_key = wirken_vault::VaultSecret::new("a".repeat(64));
        let store =
            wirken_vault::CredentialStore::open_with_key(&tmp.path().join("vault.db"), device_key)
                .unwrap();
        for name in ["stdio-key", "telegram-token"] {
            store
                .store(
                    name,
                    "",
                    &wirken_vault::VaultSecret::new(format!("{name}-value")),
                    None,
                    None,
                )
                .unwrap();
        }
        let scoped = store.into_scoped("mcp-proxy", ["stdio-key".to_string()]);
        let env: HashMap<String, String> = [
            ("OWN", "vault:stdio-key"),
            ("OTHER", "vault:telegram-token"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let resolved = resolve_env(&env, Some(&scoped));
        assert_eq!(resolved["OWN"], "stdio-key-value");
        assert_eq!(resolved["OTHER"], "vault:telegram-token");
    }
}
