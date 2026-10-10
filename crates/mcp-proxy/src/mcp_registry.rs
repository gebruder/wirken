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
use wirken_audit::{McpServerRestartCause, SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_vault::{CredentialAccess, ScopedCredentialStore};

use crate::auth::{AuthProvider, BearerAuth, NoAuth, OAuth2Auth};
use crate::container::{ContainerPlan, PlanError, SandboxHost};
use crate::error::ProxyError;
use crate::mcp_client::{McpClient, McpToolResult};
use crate::mcp_config::{McpAuth, McpConfig, McpServerConfig, StdioSandbox};
use crate::mcp_signing::{McpVerifyResult, bundled_mcp_pubkey, verify_mcp_entry};
use crate::mcp_transport::{HttpTransport, StdioTransport, Transport};
use crate::supervise::{Failure, Pending};
use crate::wire::ToolDefWire;

/// Sentinel session id for cross-cutting MCP load-time events.
/// Parallels `gateway-hooks` used by the hook accept loop.
pub const MCP_SENTINEL_SESSION: &str = "gateway-mcp";

/// `McpEntryRefused` reason: the stdio entry has no `sandbox` block, or
/// one the proxy cannot start as written.
pub const REFUSED_SANDBOX_CONFIG_INVALID: &str = "sandbox_config_invalid";
/// `McpEntryRefused` reason: no container runtime is reachable, or the
/// host lacks something the block needs.
pub const REFUSED_SANDBOX_UNAVAILABLE: &str = "sandbox_unavailable";
/// `McpEntryRefused` reason: the block's image is not on this host.
pub const REFUSED_IMAGE_UNAVAILABLE: &str = "image_unavailable";
/// `McpEntryRefused` reason: the block lists egress hosts and the
/// runtime cannot proxy them.
pub const REFUSED_EGRESS_UNSUPPORTED_RUNTIME: &str = "egress_unsupported_runtime";

/// The refusals that come from the stdio sandbox rather than the
/// signature check. An entry refused for one of these verified.
pub const SANDBOX_REFUSALS: &[&str] = &[
    REFUSED_SANDBOX_CONFIG_INVALID,
    REFUSED_SANDBOX_UNAVAILABLE,
    REFUSED_IMAGE_UNAVAILABLE,
    REFUSED_EGRESS_UNSUPPORTED_RUNTIME,
];

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
    /// Where stdio servers with a `sandbox` block are contained.
    sandbox: SandboxHost,
    /// Contained servers loaded and not yet handed to a supervisor.
    pending: Vec<Pending>,
    /// Agents with a server under supervision, running or not.
    supervised_agents: std::collections::HashSet<String>,
    /// Where shutdown records the containers it stopped.
    audit: Option<Arc<dyn SessionLog>>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            by_agent: HashMap::new(),
            costs_by_agent: HashMap::new(),
            identities: HashMap::new(),
            oauth_refresh_locks: HashMap::new(),
            sandbox: SandboxHost::unavailable(),
            pending: Vec::new(),
            supervised_agents: Default::default(),
            audit: None,
        }
    }

    /// Use `host` to start contained stdio servers.
    pub fn with_sandbox(mut self, host: SandboxHost) -> Self {
        self.sandbox = host;
        self
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
        if let Some(log) = audit {
            self.audit = Some(log.clone());
        }

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
                    command,
                    args,
                    env,
                    sandbox,
                    ..
                } => {
                    // Resolve `vault:`-prefixed env values via a
                    // brief read on the shared vault.
                    let resolved_env = {
                        let guard = vault.lock().expect("vault mutex");
                        resolve_env(env, guard.as_ref())
                    };

                    let spawned = start_stdio(
                        &self.sandbox,
                        StdioEntry {
                            agent_id,
                            server: name,
                            command,
                            args,
                            env,
                            sandbox: sandbox.as_deref(),
                        },
                        &resolved_env,
                        audit,
                    )
                    .await;
                    // A contained server is supervised from here,
                    // whether this first run started or not, unless it
                    // was refused: that waits on the operator.
                    let contained = match sandbox.as_deref() {
                        Some(StdioSandbox::Container(_)) => sandbox.as_deref().cloned(),
                        _ => None,
                    };
                    let first: Option<Result<String, Failure>> = match spawned {
                        Ok(stdio) => {
                            let container_id = stdio.container_id().map(str::to_string);
                            let mut client =
                                McpClient::new(name.clone(), Transport::Stdio(Box::new(stdio)));
                            match init_and_list(&mut client, agent_id).await {
                                Ok(()) => {
                                    clients.insert(name.clone(), client);
                                    container_id.map(Ok)
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "MCP stdio server '{name}' (agent '{agent_id}') skipped: {e}"
                                    );
                                    // Read before shutdown removes the
                                    // container, and with it the log.
                                    let output = client.stderr_tail().await;
                                    client.shutdown().await;
                                    Some(Err(Failure {
                                        cause: McpServerRestartCause::InitializeFailed,
                                        detail: e.to_string(),
                                        output,
                                    }))
                                }
                            }
                        }
                        Err(StartError::Refused { reason, why }) => {
                            tracing::warn!(
                                agent_id,
                                server = name,
                                reason,
                                "MCP server '{name}' (agent '{agent_id}') not started: {why}"
                            );
                            record(
                                audit,
                                SessionEvent::McpEntryRefused {
                                    server_name: name.clone(),
                                    reason: reason.to_string(),
                                },
                            );
                            None
                        }
                        Err(StartError::Failed(e)) => {
                            tracing::warn!(
                                "MCP server '{name}' (agent '{agent_id}') spawn failed: {e}"
                            );
                            Some(Err(Failure {
                                cause: McpServerRestartCause::StartFailed,
                                detail: e.to_string(),
                                output: None,
                            }))
                        }
                    };
                    if let (Some(sandbox), Some(first)) = (contained, first) {
                        self.supervised_agents.insert(agent_id.to_string());
                        self.pending.push(Pending {
                            agent_id: agent_id.to_string(),
                            server: name.clone(),
                            command: command.clone(),
                            args: args.clone(),
                            env: env.clone(),
                            sandbox,
                            host: self.sandbox.clone(),
                            first,
                        });
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
        // Every configured server's costs, not only the ones that
        // started: a server a supervisor starts later is gated the same.
        let costs: HashMap<String, HashMap<String, u64>> = config
            .servers
            .iter()
            .map(|(server, c)| (server.clone(), c.tool_costs().clone()))
            .filter(|(_, m)| !m.is_empty())
            .collect();
        if !costs.is_empty() {
            self.costs_by_agent.insert(agent_id.to_string(), costs);
        }
        if !clients.is_empty() {
            self.by_agent.insert(agent_id.to_string(), clients);
        }
        Ok(count)
    }

    /// The contained servers loaded so far, for [`Supervisors`] to
    /// take over.
    ///
    /// [`Supervisors`]: crate::supervise::Supervisors
    pub(crate) fn take_pending(&mut self) -> Vec<Pending> {
        std::mem::take(&mut self.pending)
    }

    /// Put a started server's client in place, replacing any before it.
    pub(crate) fn install(&mut self, agent_id: &str, server: &str, client: McpClient) {
        self.by_agent
            .entry(agent_id.to_string())
            .or_default()
            .insert(server.to_string(), client);
    }

    /// Take a server's client out, to stop it.
    pub(crate) fn take(&mut self, agent_id: &str, server: &str) -> Option<McpClient> {
        self.by_agent.get_mut(agent_id)?.remove(server)
    }

    /// Whether an agent has MCP servers: loaded now, or under a
    /// supervisor that may start them later. An agent whose servers all
    /// failed at load keeps its proxy connection on this, so the tools a
    /// restart brings are offered on its next turn.
    pub fn has_agent(&self, agent_id: &str) -> bool {
        self.by_agent.contains_key(agent_id) || self.supervised_agents.contains(agent_id)
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
    ///
    /// All servers stop at once, so the time this takes is one server's
    /// rather than the sum of them. Each container stopped is an
    /// `McpServerExited` row with `stopped_by_proxy` set.
    pub async fn shutdown(&mut self) {
        let stopping = self.by_agent.drain().flat_map(|(agent_id, servers)| {
            servers.into_iter().map(move |(name, mut client)| {
                let agent_id = agent_id.clone();
                async move {
                    tracing::info!("Shutting down MCP server '{name}' (agent '{agent_id}')");
                    let exit = client.shutdown().await;
                    (agent_id, name, exit)
                }
            })
        });
        for (agent_id, server_name, exit) in futures_util::future::join_all(stopping).await {
            if let Some(exit) = exit {
                record(
                    self.audit.as_ref(),
                    SessionEvent::McpServerExited {
                        server_name,
                        agent_id,
                        container_id: exit.container_id,
                        exit_code: exit.exit_code,
                        stopped_by_proxy: true,
                    },
                );
            }
        }
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Append `event` to the `gateway-mcp` session, when there is a log.
pub(crate) fn record(audit: Option<&Arc<dyn SessionLog>>, event: SessionEvent) {
    let Some(log) = audit else {
        return;
    };
    let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
    if let Err(e) = log.append(&handle, TrustLevel::System, event) {
        tracing::warn!("could not record an MCP server event: {e}");
    }
}

/// A stdio entry, as [`start_stdio`] needs it.
pub(crate) struct StdioEntry<'a> {
    pub agent_id: &'a str,
    pub server: &'a str,
    pub command: &'a str,
    pub args: &'a [String],
    /// The config's env: `vault:` values are still references.
    pub env: &'a HashMap<String, String>,
    pub sandbox: Option<&'a StdioSandbox>,
}

/// Why a stdio server did not start.
pub(crate) enum StartError {
    /// The entry, or the host, rules it out until the operator acts.
    /// Recorded as `McpEntryRefused` with `reason`; `why` goes to the
    /// log and says what to change.
    Refused { reason: &'static str, why: String },
    /// Starting failed for a reason nothing in the entry names.
    Failed(ProxyError),
}

impl StartError {
    fn refused(reason: &'static str, why: impl Into<String>) -> Self {
        Self::Refused {
            reason,
            why: why.into(),
        }
    }
}

/// Start one stdio server: in its container, or on the host when its
/// entry says `"sandbox": "off"`. An entry with no `sandbox` block is
/// refused; nothing starts a stdio server on the host by default.
pub(crate) async fn start_stdio(
    host: &SandboxHost,
    entry: StdioEntry<'_>,
    resolved_env: &HashMap<String, String>,
    audit: Option<&Arc<dyn SessionLog>>,
) -> Result<StdioTransport, StartError> {
    let block = match entry.sandbox {
        Some(StdioSandbox::Container(block)) => block,
        None => {
            return Err(StartError::refused(
                REFUSED_SANDBOX_CONFIG_INVALID,
                "a stdio server needs a sandbox block. Either add one naming the image it \
                 runs in and re-sign the entry with `wirken mcp sign`, or set \
                 \"sandbox\": \"off\" and re-sign to run it on the host unsandboxed",
            ));
        }
        Some(StdioSandbox::Invalid(_)) => {
            return Err(StartError::refused(
                REFUSED_SANDBOX_CONFIG_INVALID,
                "sandbox is neither \"off\" nor a sandbox block",
            ));
        }
        Some(StdioSandbox::Off(_)) => {
            tracing::warn!(
                agent_id = entry.agent_id,
                server = entry.server,
                "MCP server '{}' runs on the host without a sandbox (\"sandbox\": \"off\")",
                entry.server
            );
            record(
                audit,
                SessionEvent::McpServerUnsandboxed {
                    server_name: entry.server.to_string(),
                    agent_id: entry.agent_id.to_string(),
                },
            );
            return StdioTransport::spawn(entry.command, entry.args, resolved_env)
                .await
                .map_err(StartError::Failed);
        }
    };

    let plan = ContainerPlan::new(
        host,
        entry.agent_id,
        entry.server,
        entry.command,
        entry.args,
        entry.env,
        block,
    )
    .map_err(|e| match e {
        PlanError::Invalid(why) => StartError::refused(REFUSED_SANDBOX_CONFIG_INVALID, why),
        PlanError::Unavailable(why) => StartError::refused(REFUSED_SANDBOX_UNAVAILABLE, why),
        PlanError::EgressUnsupported(why) => {
            StartError::refused(REFUSED_EGRESS_UNSUPPORTED_RUNTIME, why)
        }
    })?;

    // A client exists even when the daemon does not; `facts` is set
    // only once the daemon answered.
    let docker = match (&host.docker, host.facts) {
        (Some(docker), Some(_)) => docker,
        _ => {
            return Err(StartError::refused(
                REFUSED_SANDBOX_UNAVAILABLE,
                "no container runtime is reachable. Start Docker and restart the gateway, or \
                 set \"sandbox\": \"off\" and re-sign to run it on the host unsandboxed",
            ));
        }
    };
    let image = docker.inspect_image(&plan.image).await.map_err(|_| {
        StartError::refused(
            REFUSED_IMAGE_UNAVAILABLE,
            format!(
                "image {} is not on this host and the proxy does not pull; run `docker pull {}`",
                plan.image, plan.image
            ),
        )
    })?;
    if !plan.egress_hosts.is_empty() {
        host.ready_sidecar_binary()
            .map_err(|why| StartError::refused(REFUSED_SANDBOX_UNAVAILABLE, why))?;
    }

    let route = if plan.egress_hosts.is_empty() {
        None
    } else {
        let route = crate::container::start_route(docker, host, &plan, audit.cloned())
            .await
            .map_err(|e| {
                StartError::Failed(ProxyError::Mcp(format!(
                    "egress route for '{}': {e}",
                    plan.server
                )))
            })?;
        Some(route)
    };
    let transport = StdioTransport::spawn_container(docker, &plan, resolved_env, route)
        .await
        .map_err(StartError::Failed)?;

    record(
        audit,
        SessionEvent::McpServerSandboxed {
            server_name: plan.server.clone(),
            agent_id: plan.agent_id.clone(),
            image: plan.image.clone(),
            image_id: image.id,
            image_digest: image.repo_digests.and_then(|d| d.into_iter().next()),
            runtime: wirken_sandbox::runtime_label(plan.runtime.as_deref()),
            container_id: transport.container_id().unwrap_or_default().to_string(),
            egress_hosts: plan.egress_hosts.clone(),
            mounts: plan.mount_summary(),
            memory_bytes: plan.memory_bytes,
            pids: plan.pids,
            nano_cpus: plan.nano_cpus,
            secrets_as_files: plan.secret_file_names.clone(),
            secrets_in_env: plan.env_secret_names.clone(),
        },
    );
    Ok(transport)
}

pub(crate) async fn init_and_list(
    client: &mut McpClient,
    agent_id: &str,
) -> Result<(), ProxyError> {
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
pub(crate) fn resolve_env(
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

#[cfg(test)]
mod start_tests {
    use super::*;
    use wirken_sandbox::RuntimeFacts;

    fn log() -> Arc<dyn SessionLog> {
        Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap())
    }

    fn events(log: &Arc<dyn SessionLog>) -> Vec<SessionEvent> {
        let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
        log.get_since(&handle, 0)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect()
    }

    fn no_vault() -> SharedVault {
        Arc::new(Mutex::new(None))
    }

    fn host(data_dir: &std::path::Path, docker: Option<bollard::Docker>) -> SandboxHost {
        SandboxHost {
            facts: docker.as_ref().map(|_| RuntimeFacts::default()),
            docker,
            instance: crate::container::instance_id(data_dir),
            data_dir: data_dir.to_path_buf(),
            runtime: None,
            secrets_base: Some(data_dir.join("ram")),
            sidecar_binary: None,
        }
    }

    /// Load one server named `srv` and return the rows written.
    async fn load(host: SandboxHost, entry: serde_json::Value) -> (usize, Vec<SessionEvent>) {
        let config: McpConfig =
            serde_json::from_value(serde_json::json!({ "servers": { "srv": entry } })).unwrap();
        let log = log();
        let mut registry = ProxyRegistry::new().with_sandbox(host);
        let loaded = registry
            .load_agent("agent-1", &config, no_vault(), Some(&log))
            .await
            .unwrap();
        registry.shutdown().await;
        (loaded, events(&log))
    }

    fn refused(events: &[SessionEvent]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::McpEntryRefused { reason, .. } => Some(reason.as_str()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn an_entry_without_a_sandbox_block_is_refused_after_it_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, events) = load(
            host(dir.path(), None),
            serde_json::json!({ "command": "/bin/true" }),
        )
        .await;
        assert_eq!(loaded, 0);
        assert!(
            matches!(events[0], SessionEvent::McpEntryVerified { .. }),
            "{events:?}"
        );
        assert_eq!(refused(&events), [REFUSED_SANDBOX_CONFIG_INVALID]);
    }

    #[tokio::test]
    async fn each_sandbox_refusal_has_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (
                serde_json::json!({ "command": "srv", "sandbox": "on" }),
                None,
                REFUSED_SANDBOX_CONFIG_INVALID,
            ),
            (
                serde_json::json!({ "command": "srv", "sandbox": {} }),
                None,
                REFUSED_SANDBOX_CONFIG_INVALID,
            ),
            (
                serde_json::json!({ "command": "srv", "sandbox": { "image": "img" } }),
                None,
                REFUSED_SANDBOX_UNAVAILABLE,
            ),
            (
                serde_json::json!({ "command": "srv", "sandbox": {
                    "image": "img", "egress": { "hosts": ["api.example.com"] } } }),
                Some(RuntimeFacts {
                    rootless: true,
                    ..Default::default()
                }),
                REFUSED_EGRESS_UNSUPPORTED_RUNTIME,
            ),
        ];
        for (entry, facts, reason) in cases {
            let mut host = host(dir.path(), None);
            host.facts = facts;
            let (loaded, events) = load(host, entry.clone()).await;
            assert_eq!(loaded, 0, "{entry}");
            assert_eq!(refused(&events), [reason], "{entry}");
        }
    }

    #[tokio::test]
    async fn an_agent_whose_servers_were_all_refused_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let config: McpConfig = serde_json::from_value(serde_json::json!({ "servers": { "srv": {
            "command": "/bin/true"
        }}}))
        .unwrap();
        let mut registry = ProxyRegistry::new().with_sandbox(host(dir.path(), None));
        registry
            .load_agent("agent-1", &config, no_vault(), None)
            .await
            .unwrap();
        assert!(registry.take_pending().is_empty());
        assert!(!registry.has_agent("agent-1"));
    }

    #[tokio::test]
    async fn sandbox_off_starts_on_the_host_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let (_, events) = load(
            host(dir.path(), None),
            serde_json::json!({ "command": "/bin/true", "sandbox": "off" }),
        )
        .await;
        assert!(refused(&events).is_empty(), "{events:?}");
        assert!(
            events.contains(&SessionEvent::McpServerUnsandboxed {
                server_name: "srv".into(),
                agent_id: "agent-1".into(),
            }),
            "{events:?}"
        );
    }

    async fn docker_with(image: &str) -> Option<bollard::Docker> {
        let docker = bollard::Docker::connect_with_local_defaults().ok()?;
        docker.ping().await.ok()?;
        docker.inspect_image(image).await.ok()?;
        Some(docker)
    }

    /// Live: an image the host does not have is refused, not pulled.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_image_not_on_the_host_is_refused() {
        let Some(docker) = docker_with("debian:bookworm-slim").await else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let (loaded, events) = load(
            host(dir.path(), Some(docker)),
            serde_json::json!({ "command": "srv", "sandbox": {
                "image": "wirken-test-absent-image:0" } }),
        )
        .await;
        assert_eq!(loaded, 0);
        assert_eq!(refused(&events), [REFUSED_IMAGE_UNAVAILABLE]);
    }

    /// Live: a server that dies before answering `initialize` leaves its
    /// last stderr lines on the failure its supervisor starts from, read
    /// before its container was removed.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_server_that_fails_initialize_leaves_its_stderr() {
        let Some(docker) = docker_with("debian:bookworm-slim").await else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config: McpConfig = serde_json::from_value(serde_json::json!({ "servers": { "srv": {
            "command": "sh",
            "args": ["-c", "echo 'boom: API_URL is not set' >&2; exit 1"],
            "sandbox": { "image": "debian:bookworm-slim" }
        }}}))
        .unwrap();
        let mut registry = ProxyRegistry::new().with_sandbox(host(dir.path(), Some(docker)));
        let loaded = registry
            .load_agent("agent-1", &config, no_vault(), None)
            .await
            .unwrap();
        let pending = registry.take_pending();
        assert_eq!(loaded, 0);
        // Nothing runs, but a supervisor will retry, so the agent keeps
        // its proxy connection for the tools a restart brings.
        assert!(registry.has_agent("agent-1"));
        let failure = pending[0].first.as_ref().unwrap_err();
        assert_eq!(failure.cause, McpServerRestartCause::InitializeFailed);
        assert_eq!(failure.output.as_deref(), Some("boom: API_URL is not set"));
    }

    /// Live: a contained start writes what the server was given, by
    /// secret name only, and the server answers.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_contained_start_records_what_the_server_was_given() {
        let Some(docker) = docker_with("debian:bookworm-slim").await else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        // Answers initialize and tools/list, then waits for end of input.
        let script = r#"read a; printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t","version":"1"}}}\n'; read b; read c; printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n'; cat >/dev/null"#;
        let (loaded, events) = load(
            host(dir.path(), Some(docker)),
            serde_json::json!({
                "command": "sh",
                "args": ["-c", script],
                "env": { "FILE_TOKEN": "vault:a", "ENV_TOKEN": "vault:b" },
                "sandbox": {
                    "image": "debian:bookworm-slim",
                    "install_dir": install.to_string_lossy(),
                    "secrets_in_env": ["ENV_TOKEN"]
                }
            }),
        )
        .await;
        assert_eq!(loaded, 1, "{events:?}");
        let row = events
            .iter()
            .find(|e| matches!(e, SessionEvent::McpServerSandboxed { .. }))
            .expect("a start row");
        let SessionEvent::McpServerSandboxed {
            server_name,
            agent_id,
            image,
            image_id,
            container_id,
            egress_hosts,
            mounts,
            secrets_as_files,
            secrets_in_env,
            ..
        } = row
        else {
            unreachable!()
        };
        assert_eq!(server_name, "srv");
        assert_eq!(agent_id, "agent-1");
        assert_eq!(image, "debian:bookworm-slim");
        assert!(image_id.is_some());
        assert!(!container_id.is_empty());
        assert!(egress_hosts.is_empty());
        assert!(
            mounts.contains(&format!("{}:/opt/mcp:ro", install.display())),
            "{mounts:?}"
        );
        assert_eq!(secrets_as_files, &["FILE_TOKEN"]);
        assert_eq!(secrets_in_env, &["ENV_TOKEN"]);
        // The registry's shutdown stopped it and said so.
        assert!(
            events.iter().any(|e| matches!(
                e,
                SessionEvent::McpServerExited {
                    container_id: id,
                    stopped_by_proxy: true,
                    exit_code: Some(_),
                    ..
                } if id == container_id
            )),
            "{events:?}"
        );
    }
}
