use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;

use wirken_agent::factory::CacheMode;
use wirken_agent::llm::LlmConfig;
use wirken_agent::{AgentFactory, AgentStaticConfig, SkillLoader, session_id_for};
use wirken_audit::{AuditEvent, AuditWriter, SiemConfig, SiemTarget};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::injection_detect::InjectionDetector;
use wirken_gateway::router::{RouteBinding, Router};
use wirken_gateway::session::SessionStore;
use wirken_ipc::perform_gateway_handshake;
use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

/// Run the gateway daemon.
pub async fn run(port: Option<u16>) -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs()?;

    println!();
    println!("  wirken gateway");
    println!("  ──────────────");
    println!();

    // --- Refresh org config if configured ---
    if let Some(org_url) = wirken_gateway::org::load_org_url(&cfg.data_dir) {
        match wirken_gateway::org::fetch_org_config(&org_url).await {
            Ok(org) => match wirken_gateway::org::apply_org_config(&cfg.data_dir, &org, true) {
                Ok(applied) if !applied.is_empty() => {
                    println!("  Org config refreshed: {}", applied.join(", "));
                }
                _ => {}
            },
            Err(e) => {
                tracing::warn!("Org config refresh failed: {e}");
            }
        }
    }

    // --- Load provider config ---
    let provider_path = cfg.data_dir.join("provider.json");
    if !provider_path.exists() {
        anyhow::bail!("No AI provider configured. Run `wirken setup` first.");
    }
    let provider_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&provider_path)?)?;
    let provider = provider_json["provider"].as_str().unwrap_or("ollama");
    let model = provider_json["model"].as_str().unwrap_or("llama3");
    let base_url = provider_json["base_url"]
        .as_str()
        .unwrap_or("http://localhost:11434/v1");

    println!("  Provider: {provider}/{model}");

    if provider == "ollama" {
        match super::probe_ollama_version(base_url).await {
            Some(version) => println!("  Ollama version: {version}"),
            None => {
                tracing::warn!("Could not reach Ollama at {base_url}");
                println!("  Warning: Ollama not reachable at {base_url}. Is it running?");
            }
        }
    }

    // --- Load API key from vault ---
    let mut vault_passphrase = String::new();
    let api_key = if provider != "ollama" {
        let keychain = probe_keychain(&cfg.data_dir, || {
            let pp = dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default();
            vault_passphrase = pp.clone();
            pp
        });
        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;
        let cred_name = format!("{provider}-api-key");
        match store.retrieve(&cred_name) {
            Ok((secret, _)) => Some(secret.expose().to_string()),
            Err(_) => {
                tracing::warn!("No API key found for '{provider}'");
                None
            }
        }
    } else {
        None
    };

    // Prompt for vault passphrase if adapters are registered but we haven't prompted yet
    if vault_passphrase.is_empty() {
        let has_adapters = {
            let reg_path = cfg.adapters_db_path();
            reg_path.exists()
                && AdapterRegistry::open(&reg_path)
                    .map(|r| !r.list().is_empty())
                    .unwrap_or(false)
        };
        if has_adapters {
            let _ = probe_keychain(&cfg.data_dir, || {
                let pp = dialoguer::Password::new()
                    .with_prompt("  Vault passphrase")
                    .interact()
                    .unwrap_or_default();
                vault_passphrase = pp.clone();
                pp
            });
        }
    }

    // --- Start audit writer (with optional SIEM forwarding) ---
    let siem_config = load_siem_config(&cfg);
    let (audit_writer, audit_handle) = AuditWriter::with_siem(&cfg.audit_db_path(), siem_config)
        .context("Failed to start audit writer")?;
    let audit = Arc::new(audit_writer);

    audit
        .log(AuditEvent::new("gateway", "gateway.start", "daemon"))
        .await?;
    println!("  Audit log: {}", cfg.audit_db_path().display());

    // --- Open the session log alongside the audit log ---
    //
    // Item 1 slice 2 made the audit DB the home of session_events.
    // Item 2 slice 1 has the agent write durability events
    // (UserMessage, AssistantMessage, AssistantToolCalls, ToolResult,
    // PermissionDenied) into the same store. Slice 2 will introduce
    // wake() which reads them back. Each agent gets its own session
    // id of `agent_id` for now; per-conversation session ids land
    // with wake().
    let session_log: Arc<dyn wirken_audit::SessionLog> = Arc::new(
        wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    );

    // --- Open stores ---
    let registry = Arc::new(Mutex::new(
        AdapterRegistry::open(&cfg.adapters_db_path())
            .context("Failed to open adapter registry")?,
    ));
    let sessions = Arc::new(Mutex::new(
        SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
            .context("Failed to open session store")?,
    ));

    // --- Open permission store ---
    let permissions = Arc::new(std::sync::Mutex::new(
        wirken_gateway::permissions::PermissionStore::open(&cfg.permissions_db_path())
            .context("Failed to open permission store")?,
    ));

    // --- Setup router and gather per-agent static configs ---
    //
    // Item 2 slice 2: agents are no longer long-lived `Mutex<Agent>`
    // instances. The gateway holds an `AgentFactory` that wakes a
    // per-conversation Agent on every inbound message, replaying its
    // session log to reconstruct conversation state. Skills, MCP,
    // and permissions are loaded once into the factory and injected
    // into every waked Agent.
    let router = Arc::new(Router::new());
    let mut static_configs: HashMap<String, AgentStaticConfig> = HashMap::new();

    // Load multi-agent configs if available
    let agent_config_path = cfg.agent_config_db_path();
    let has_multi_agent = agent_config_path.exists()
        && AgentConfigStore::open(&agent_config_path)
            .map(|s| !s.list().unwrap_or_default().is_empty())
            .unwrap_or(false);

    if has_multi_agent {
        let agent_store = AgentConfigStore::open(&agent_config_path)
            .context("Failed to open agent config store")?;

        let keychain = probe_keychain(&cfg.data_dir, || {
            let pp = dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default();
            vault_passphrase = pp.clone();
            pp
        });
        let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()).ok();

        for agent_cfg in agent_store.list()? {
            // Resolve API key from vault
            let agent_api_key = if !agent_cfg.api_key_credential.is_empty() {
                vault
                    .as_ref()
                    .and_then(|v| v.retrieve(&agent_cfg.api_key_credential).ok())
                    .map(|(secret, _)| secret.expose().to_string())
            } else {
                None
            };

            let mut llm = LlmConfig::from_provider(
                &agent_cfg.provider,
                &agent_cfg.base_url,
                &agent_cfg.model,
            );
            if agent_cfg.provider == "bedrock" {
                llm.region = agent_cfg
                    .base_url
                    .strip_prefix("https://bedrock-runtime.")
                    .and_then(|s| s.strip_suffix(".amazonaws.com"))
                    .map(String::from);
            }
            let workspace = cfg.agent_workspace(&agent_cfg.id);
            std::fs::create_dir_all(&workspace)?;

            // Load per-agent skills + shared skills.
            let mut skills = Vec::new();
            let agent_skills = cfg.agent_skills_dir(&agent_cfg.id);
            if agent_skills.is_dir()
                && let Ok(s) = SkillLoader::load_dir(&agent_skills)
            {
                skills.extend(s);
            }
            let shared_skills = cfg.data_dir.join("skills");
            if shared_skills.is_dir()
                && let Ok(s) = SkillLoader::load_dir(&shared_skills)
            {
                skills.extend(s);
            }

            // Bind channels to this agent
            for channel in &agent_cfg.channels {
                router.bind(RouteBinding {
                    channel: channel.clone(),
                    conversation_pattern: "*".into(),
                    agent_id: agent_cfg.id.clone(),
                });
                println!(
                    "  Route: {} -> agent:{} ({}/{})",
                    channel, agent_cfg.id, agent_cfg.provider, agent_cfg.model
                );
            }

            // Item 8 slice 2: load (or generate) the agent's
            // Ed25519 signing identity. The first run creates the
            // key files at ~/.wirken/agents/{id}/identity.{key,pub};
            // subsequent runs load them. Failure here is non-fatal —
            // attestation becomes a no-op for that agent and we log
            // a warning.
            let identity_dir = wirken_agent::identity::identity_dir(&cfg.data_dir, &agent_cfg.id);
            let identity = match wirken_agent::AgentIdentity::load_or_create(
                &agent_cfg.id,
                &identity_dir,
            ) {
                Ok(id) => Some(id),
                Err(e) => {
                    tracing::warn!(
                        "agent identity unavailable for '{}': {e} — session attestation disabled",
                        agent_cfg.id,
                    );
                    None
                }
            };

            static_configs.insert(
                agent_cfg.id.clone(),
                AgentStaticConfig {
                    agent_id: agent_cfg.id.clone(),
                    workspace,
                    llm_config: llm,
                    api_key: agent_api_key,
                    skills,
                    wasm_skills: Vec::new(),
                    mcp_client: None, // populated below after the proxy starts
                    identity,
                    allowed_subagents: agent_cfg.allowed_subagents.clone(),
                },
            );
        }
    }

    // Create default agent for any unbound channels (backward compat with wirken setup)
    if !static_configs.contains_key("default") {
        let mut llm_config = LlmConfig::from_provider(provider, base_url, model);
        // Bedrock: extract region from provider.json or base_url
        if provider == "bedrock" {
            llm_config.region = provider_json["region"]
                .as_str()
                .map(String::from)
                .or_else(|| {
                    base_url
                        .strip_prefix("https://bedrock-runtime.")
                        .and_then(|s| s.strip_suffix(".amazonaws.com"))
                        .map(String::from)
                });
        }
        let workspace = cfg.data_dir.join("workspace");
        std::fs::create_dir_all(&workspace)?;

        let mut skills = Vec::new();
        let skills_dir = cfg.data_dir.join("skills");
        if skills_dir.is_dir()
            && let Ok(s) = SkillLoader::load_dir(&skills_dir)
        {
            skills.extend(s);
        }

        // Bind any channels not already routed
        for adapter in registry.lock().await.list() {
            let already_routed = router.resolve(&adapter.channel, "any").is_ok();
            if !already_routed {
                router.bind(RouteBinding {
                    channel: adapter.channel.clone(),
                    conversation_pattern: "*".into(),
                    agent_id: "default".into(),
                });
                println!("  Route: {} -> agent:default", adapter.channel);
            }
        }

        // Item 8 slice 2: identity for the default agent.
        let default_identity_dir = wirken_agent::identity::identity_dir(&cfg.data_dir, "default");
        let default_identity = match wirken_agent::AgentIdentity::load_or_create(
            "default",
            &default_identity_dir,
        ) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    "agent identity unavailable for 'default': {e} — session attestation disabled"
                );
                None
            }
        };

        static_configs.insert(
            "default".into(),
            AgentStaticConfig {
                agent_id: "default".into(),
                workspace,
                llm_config,
                api_key,
                skills,
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: default_identity,
                allowed_subagents: Default::default(),
            },
        );
    }

    println!(
        "  Agents: {}",
        static_configs
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );

    // --- Setup UDS listener ---
    let socket_path = cfg.socket_dir().join("gateway.sock");
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)
        .context(format!("Failed to bind UDS at {}", socket_path.display()))?;
    println!("  Socket: {}", socket_path.display());

    // --- Spawn adapter processes ---
    let exe = std::env::current_exe()?;
    let mut adapter_handles = Vec::new();

    for adapter_entry in registry.lock().await.list() {
        let adapter_id = adapter_entry.adapter_id.clone();
        let sock = socket_path.clone();
        let exe = exe.clone();
        let data_dir = cfg.data_dir.clone();
        let vp = vault_passphrase.clone();

        let handle = tokio::spawn(async move {
            // Small delay to let the listener start
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            tracing::info!("Spawning adapter: {adapter_id}");
            let result = Command::new(&exe)
                .arg("adapter")
                .arg(&adapter_id)
                .env("WIRKEN_DATA_DIR", &data_dir)
                .env("WIRKEN_SOCKET", &sock)
                .env("WIRKEN_VAULT_PASSPHRASE", &vp)
                .kill_on_drop(true)
                .spawn();

            match result {
                Ok(mut child) => {
                    let status = child.wait().await;
                    tracing::info!("Adapter {adapter_id} exited: {status:?}");
                }
                Err(e) => {
                    tracing::error!("Failed to spawn adapter {adapter_id}: {e}");
                }
            }
        });
        adapter_handles.push(handle);
    }

    // --- Spawn MCP proxy ---
    //
    // The proxy runs as a sibling process. The agent process never holds
    // plaintext MCP credentials — the proxy owns the vault handle for any
    // `vault:`-prefixed env values in mcp.json and resolves them inside its
    // own address space. See docs/managed-agents-parity.md item 7.
    let mcp_proxy_socket = cfg.socket_dir().join("mcp-proxy.sock");
    if mcp_proxy_socket.exists() {
        let _ = std::fs::remove_file(&mcp_proxy_socket);
    }
    let mcp_proxy_handle = {
        let exe = exe.clone();
        let data_dir = cfg.data_dir.clone();
        let vp = vault_passphrase.clone();
        let socket = mcp_proxy_socket.clone();
        tokio::spawn(async move {
            tracing::info!("Spawning MCP proxy");
            let result = Command::new(&exe)
                .arg("mcp-proxy")
                .env("WIRKEN_DATA_DIR", &data_dir)
                .env("WIRKEN_MCP_SOCKET", &socket)
                .env("WIRKEN_VAULT_PASSPHRASE", &vp)
                .kill_on_drop(true)
                .spawn();
            match result {
                Ok(mut child) => {
                    let status = child.wait().await;
                    tracing::info!("MCP proxy exited: {status:?}");
                }
                Err(e) => {
                    tracing::error!("Failed to spawn MCP proxy: {e}");
                }
            }
        })
    };

    // Wait briefly for the proxy to start listening before connecting agents.
    // The proxy itself is responsible for creating the socket file with the
    // right permissions; we just poll for its existence. McpProxyClient::connect
    // also has its own retry loop, so this is a soft signal, not a hard wait.
    for _ in 0..50 {
        if mcp_proxy_socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Connect each agent to the MCP proxy. The proxy client is held
    // in the AgentStaticConfig and shared across every waked Agent
    // for that agent_id (slice 2 design — see crates/agent/src/factory.rs).
    for (agent_id, cfg) in static_configs.iter_mut() {
        match wirken_agent::mcp::McpProxyClient::connect(&mcp_proxy_socket, agent_id).await {
            Ok(mut client) => {
                if !client.has_servers() {
                    client.shutdown().await;
                    continue;
                }
                match client.load_tools().await {
                    Ok(n) if n > 0 => {
                        println!("  MCP: {n} tools for agent:{agent_id}");
                        cfg.mcp_client = Some(Arc::new(tokio::sync::Mutex::new(client)));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("MCP load_tools failed for agent '{agent_id}': {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("MCP connect failed for agent '{agent_id}': {e}");
            }
        }
    }

    // Build the AgentFactory now that all per-agent state is loaded.
    let cache_mode = CacheMode::from_env();
    let cache_capacity = std::env::var("WIRKEN_AGENT_CACHE_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(64);
    let factory = AgentFactory::with_options(
        static_configs,
        session_log.clone(),
        Some(permissions.clone()),
        cache_mode,
        cache_capacity,
    );

    // --- Webchat ---
    let webchat_port = port.unwrap_or(18790);
    let webchat_factory = factory.clone();
    let webchat_audit = audit.clone();
    let webchat_sessions = sessions.clone();
    let webchat_handle = tokio::spawn(async move {
        if let Err(e) = super::webchat::serve(
            webchat_port,
            webchat_factory,
            webchat_audit,
            webchat_sessions,
        )
        .await
        {
            tracing::error!("Webchat server error: {e}");
        }
    });

    // --- Cron scheduler ---
    let cron_store = Arc::new(std::sync::Mutex::new(
        wirken_gateway::cron::CronStore::open(&cfg.cron_db_path())
            .context("Failed to open cron store")?,
    ));
    let scheduler_factory = factory.clone();
    let scheduler_cron = cron_store.clone();
    let scheduler_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            let due = match scheduler_cron.lock().unwrap().due_jobs() {
                Ok(jobs) => jobs,
                Err(e) => {
                    tracing::error!("Cron query failed: {e}");
                    continue;
                }
            };

            for job in due {
                tracing::info!("Cron firing: {} -> agent:{}", job.id, job.agent_id);
                let _ = scheduler_cron.lock().unwrap().mark_run(&job.id);

                // Cron has no platform message id; synthesize one per
                // firing so dedup works.
                let inbound_id = format!("cron-{}", uuid::Uuid::new_v4());
                let session_id = session_id_for(&job.agent_id, "cron", &job.id);

                match scheduler_factory.wake(&job.agent_id, &session_id) {
                    Ok(agent_mutex) => {
                        let mut agent = agent_mutex.lock().await;
                        match agent.process_message(&job.message, inbound_id).await {
                            Ok(result) => {
                                tracing::info!(
                                    "Cron response: {}",
                                    truncate(&result.response, 100)
                                );
                                for denial in &result.denials {
                                    tracing::warn!(
                                        "Cron permission denied: agent '{}' tool '{}'",
                                        denial.agent_id,
                                        denial.tool_name,
                                    );
                                }
                            }
                            Err(e) => tracing::error!("Cron job failed: {e}"),
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Cron: factory.wake failed for '{}': {e}", job.agent_id);
                    }
                }
            }
        }
    });

    println!("  WebChat: http://localhost:{webchat_port}");
    println!();
    println!("  Gateway running. Press Ctrl+C to stop.");
    println!();

    // --- Injection detector (shared, stateless) ---
    let detector = Arc::new(InjectionDetector::new());

    // --- Accept adapter connections ---
    let accept_registry = registry.clone();
    let accept_factory = factory.clone();
    let accept_audit = audit.clone();
    let accept_sessions = sessions.clone();
    let accept_router = router.clone();
    let accept_detector = detector.clone();

    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let reg = accept_registry.clone();
                    let fact = accept_factory.clone();
                    let au = accept_audit.clone();
                    let sess = accept_sessions.clone();
                    let rtr = accept_router.clone();
                    let det = accept_detector.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_adapter_connection(stream, reg, fact, au, sess, rtr, det).await
                        {
                            tracing::error!("Adapter connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Accept error: {e}");
                }
            }
        }
    });

    // --- Wait for shutdown ---
    tokio::signal::ctrl_c().await?;
    println!();
    println!("  Shutting down...");

    audit
        .log(AuditEvent::new("gateway", "gateway.stop", "daemon"))
        .await?;

    // Abort adapter processes
    for handle in adapter_handles {
        handle.abort();
    }
    mcp_proxy_handle.abort();
    accept_handle.abort();
    webchat_handle.abort();
    scheduler_handle.abort();

    // Drop audit writer to flush remaining events
    drop(audit);
    let _ = audit_handle.await;

    // Cleanup sockets
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&mcp_proxy_socket);

    println!("  Gateway stopped.");
    Ok(())
}

/// Handle a single adapter connection: handshake, then message loop.
async fn handle_adapter_connection(
    stream: UnixStream,
    registry: Arc<Mutex<AdapterRegistry>>,
    factory: Arc<AgentFactory>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    router: Arc<Router>,
    detector: Arc<InjectionDetector>,
) -> Result<()> {
    let (mut reader, mut writer) = split_stream(stream);

    // Handshake
    // Collect known adapters for handshake verification (avoids holding lock across await)
    let known: std::collections::HashMap<String, [u8; 32]> = {
        let reg = registry.lock().await;
        reg.list()
            .into_iter()
            .map(|a| (a.adapter_id, a.public_key))
            .collect()
    };

    let (adapter_id, _pub_key) =
        perform_gateway_handshake(&mut reader, &mut writer, move |id, pk| {
            match known.get(id) {
                None => Err(wirken_ipc::HandshakeError::UnknownAdapter(id.to_string())),
                Some(expected) if expected == pk => Ok(()),
                Some(_) => Err(wirken_ipc::HandshakeError::InvalidSignature),
            }
        })
        .await
        .context("Adapter handshake failed")?;

    tracing::info!("Adapter '{adapter_id}' authenticated");
    registry.lock().await.set_connected(&adapter_id, true);

    audit
        .log(AuditEvent::new("gateway", "adapter.connect", &adapter_id).with_channel(&adapter_id))
        .await?;

    let writer = Arc::new(Mutex::new(writer));

    // Message loop
    let result = message_loop(
        &adapter_id,
        &mut reader,
        writer.clone(),
        factory,
        audit.clone(),
        sessions,
        router,
        detector,
    )
    .await;

    registry.lock().await.set_connected(&adapter_id, false);
    audit
        .log(
            AuditEvent::new("gateway", "adapter.disconnect", &adapter_id).with_channel(&adapter_id),
        )
        .await?;

    tracing::info!("Adapter '{adapter_id}' disconnected");
    result
}

/// Main message loop: read inbound from adapter, route to agent, send response back.
#[allow(clippy::too_many_arguments)]
async fn message_loop(
    adapter_id: &str,
    reader: &mut FrameReader,
    writer: Arc<Mutex<FrameWriter>>,
    factory: Arc<AgentFactory>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    router: Arc<Router>,
    detector: Arc<InjectionDetector>,
) -> Result<()> {
    loop {
        let msg = match reader.read_message().await {
            Ok(msg) => msg,
            Err(wirken_ipc::IpcError::ConnectionClosed) => {
                tracing::info!("Adapter '{adapter_id}' connection closed");
                return Ok(());
            }
            Err(e) => {
                tracing::error!("IPC read error from '{adapter_id}': {e}");
                return Err(e.into());
            }
        };

        // Extract fields before any .await (Cap'n Proto readers are not Send)
        let action = {
            let frame_reader = msg
                .get_root::<frame::Reader<'_>>()
                .context("Failed to parse frame")?;

            match frame_reader.which()? {
                frame::Inbound(inbound) => {
                    let m = inbound?;
                    let text = m
                        .get_text()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("text not utf8: {e}"))?
                        .to_string();
                    let sender_id = m
                        .get_sender_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("sender_id not utf8: {e}"))?
                        .to_string();
                    let sender_name = m
                        .get_sender_name()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("sender_name not utf8: {e}"))?
                        .to_string();
                    let channel = m
                        .get_channel()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("channel not utf8: {e}"))?
                        .to_string();
                    let conversation_id = m
                        .get_conversation_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("conversation_id not utf8: {e}"))?
                        .to_string();
                    let msg_id = m
                        .get_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("id not utf8: {e}"))?
                        .to_string();

                    InboundAction::Message {
                        id: msg_id,
                        text,
                        sender_id,
                        sender_name,
                        channel,
                        conversation_id,
                    }
                }
                frame::Heartbeat(hb) => {
                    let seq = hb?.get_seq();
                    InboundAction::Heartbeat(seq)
                }
                frame::OutboundResult(r) => {
                    let r = r?;
                    let success = r.get_success();
                    let msg_id = r.get_message_id()?.to_str().unwrap_or_default().to_string();
                    InboundAction::DeliveryResult { success, msg_id }
                }
                _ => InboundAction::Unknown,
            }
        };
        // msg dropped — safe to .await

        match action {
            InboundAction::Message {
                id,
                text,
                sender_id,
                sender_name,
                channel,
                conversation_id,
            } => {
                tracing::info!(
                    "[{}] {} ({}): {}",
                    channel,
                    sender_name,
                    sender_id,
                    truncate(&text, 80),
                );

                // Audit inbound
                let mut inbound_event = AuditEvent::new(&sender_id, "message.inbound", &text)
                    .with_channel(&channel)
                    .with_session(&conversation_id);

                // Scan for prompt injection patterns
                if let Some(threat) = detector.scan(&text) {
                    let detail = threat.to_detail_json();
                    inbound_event = inbound_event.with_detail(detail.clone());

                    // Emit a separate threat event for SIEM visibility
                    let _ = audit
                        .log(
                            AuditEvent::new(&sender_id, "message.threat_flagged", &text)
                                .with_channel(&channel)
                                .with_session(&conversation_id)
                                .with_detail(detail),
                        )
                        .await;
                }

                audit.log(inbound_event).await?;

                // Resolve session
                let session = {
                    let s = sessions.lock().await;
                    s.get_or_create(&channel, &conversation_id)?
                };
                {
                    let s = sessions.lock().await;
                    s.record_message(&session.id)?;
                }

                // Route to agent
                let agent_id = router
                    .resolve(&channel, &conversation_id)
                    .unwrap_or_else(|_| "default".into());

                // Wake the agent for THIS conversation. Per-conversation
                // session ids land in slice 2: each (agent, channel,
                // conversation_id) gets its own session. The platform
                // message id (msg `id` field on the capnp frame) is the
                // inbound_id used for crash-recovery dedup.
                let resolved_agent = if factory.has_agent(&agent_id) {
                    agent_id.clone()
                } else {
                    tracing::error!("No agent '{agent_id}' found, trying default");
                    "default".into()
                };
                let session_id = session_id_for(&resolved_agent, &channel, &conversation_id);

                let (response, denials) = match factory.wake(&resolved_agent, &session_id) {
                    Ok(agent_mutex) => {
                        let mut ag = agent_mutex.lock().await;
                        match ag.process_message(&text, id.clone()).await {
                            Ok(result) => (result.response, result.denials),
                            Err(e) => {
                                tracing::error!("Agent '{resolved_agent}' error: {e}");
                                (format!("Error processing message: {e}"), Vec::new())
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("factory.wake('{resolved_agent}') failed: {e}");
                        (
                            "No agent available to process this message.".into(),
                            Vec::new(),
                        )
                    }
                };
                let agent_id = resolved_agent;

                // Log permission denials to audit
                for denial in &denials {
                    let detail = serde_json::json!({
                        "tool": denial.tool_name,
                        "action": format!("{:?}", denial.action),
                        "requested_tier": denial.requested_tier.label(),
                        "agent_id": denial.agent_id,
                        "trigger_message": denial.trigger_message,
                    });
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                &denial.agent_id,
                                "permission.denied",
                                &denial.tool_name,
                            )
                            .with_channel(&channel)
                            .with_session(&conversation_id)
                            .with_detail(detail),
                        )
                        .await;
                }

                tracing::info!("[{}] -> {}", channel, truncate(&response, 80));

                // Audit outbound
                audit
                    .log(
                        AuditEvent::new(&agent_id, "message.outbound", &response)
                            .with_channel(&channel)
                            .with_session(&conversation_id),
                    )
                    .await?;

                // Send response back to adapter
                let mut reply = capnp::message::Builder::new_default();
                {
                    let fb = reply.init_root::<frame::Builder<'_>>();
                    let mut outbound = fb.init_outbound();
                    outbound.set_conversation_id(&conversation_id);
                    outbound.set_text(&response);
                    outbound.set_reply_to_id(&id);
                    outbound.set_metadata("{}");
                }

                let mut w = writer.lock().await;
                w.write_message(&reply)
                    .await
                    .context("Failed to send outbound to adapter")?;
            }

            InboundAction::Heartbeat(seq) => {
                tracing::trace!("Heartbeat from '{adapter_id}': seq={seq}");
                // Echo heartbeat back
                let mut hb = capnp::message::Builder::new_default();
                {
                    let fb = hb.init_root::<frame::Builder<'_>>();
                    fb.init_heartbeat().set_seq(seq);
                }
                let mut w = writer.lock().await;
                let _ = w.write_message(&hb).await;
            }

            InboundAction::DeliveryResult { success, msg_id } => {
                if success {
                    tracing::debug!("Delivery confirmed: {msg_id}");
                } else {
                    tracing::warn!("Delivery failed for adapter '{adapter_id}'");
                }
            }

            InboundAction::Unknown => {
                tracing::warn!("Unknown frame from '{adapter_id}'");
            }
        }
    }
}

enum InboundAction {
    Message {
        id: String,
        text: String,
        sender_id: String,
        sender_name: String,
        channel: String,
        conversation_id: String,
    },
    Heartbeat(u64),
    DeliveryResult {
        success: bool,
        msg_id: String,
    },
    Unknown,
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

/// Load SIEM forwarding config from ~/.wirken/siem.json.
/// Returns None if the file doesn't exist (SIEM forwarding disabled).
///
/// Example siem.json:
/// ```json
/// {
///     "target": "datadog",
///     "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
///     "api_key": "your-dd-api-key",
///     "service": "wirken",
///     "environment": "production"
/// }
/// ```
fn load_siem_config(cfg: &wirken_gateway::config::GatewayConfig) -> Option<SiemConfig> {
    let path = cfg.siem_config_path();
    if !path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let target_str = json.get("target")?.as_str()?;
    let target = match target_str {
        "datadog" => SiemTarget::Datadog,
        "splunk" => SiemTarget::Splunk,
        _ => SiemTarget::Webhook,
    };

    let endpoint = json.get("endpoint")?.as_str()?.to_string();
    let api_key = json
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let service = json
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("wirken")
        .to_string();
    let environment = json
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("production")
        .to_string();

    println!("  SIEM: forwarding to {target_str} at {endpoint}");

    Some(SiemConfig {
        target,
        endpoint,
        api_key,
        service,
        environment,
    })
}
