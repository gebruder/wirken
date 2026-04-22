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
use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AuthenticatedChannel, perform_gateway_handshake};
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

/// Run the gateway daemon.
pub async fn run(port: Option<u16>) -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs()?;

    println!();
    println!("  wirken gateway v{}", env!("CARGO_PKG_VERSION"));
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
            // Item 6 slice 2: per-agent tools_enabled override.
            if let Some(override_val) = agent_cfg.tools_enabled {
                llm.tools_enabled = override_val;
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
                    channel_overrides: std::collections::HashMap::new(),
                    api_key: agent_api_key,
                    skills,
                    wasm_skills: Vec::new(),
                    mcp_client: None, // populated below after the proxy starts
                    identity,
                    allowed_subagents: agent_cfg.allowed_subagents.clone(),
                    sandbox: super::load_sandbox_config(&cfg.data_dir),
                },
            );
        }
    }

    // Create default agent for any unbound channels (backward compat with wirken setup)
    if !static_configs.contains_key("default") {
        // Channel overrides from provider.json (closes #60). Optional;
        // absent or empty map means "single-provider agent, pre-#60
        // behavior." Each override entry names a vault slot for its
        // api_key rather than carrying the key directly, so configs
        // on disk stay key-free.
        let channel_overrides = resolve_channel_overrides(
            &provider_json,
            &cfg.data_dir,
            &cfg.vault_db_path(),
            &vault_passphrase,
        )?;

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
                channel_overrides,
                api_key,
                skills,
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: default_identity,
                allowed_subagents: Default::default(),
                sandbox: super::load_sandbox_config(&cfg.data_dir),
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

    // --- Pre-flight: validate per-adapter vault entries ---
    //
    // Each adapter binary will fail at startup if its vault keys are
    // missing or malformed, but that failure surfaces as an adapter
    // subprocess crash several hundred milliseconds after `wirken run`
    // prints "Gateway running," which is a confusing failure mode for
    // an operator. Check upfront. WhatsApp is the first channel with
    // multiple required fields; extend this list as other channels
    // grow mandatory secondary credentials.
    {
        let keychain = probe_keychain(&cfg.data_dir, String::new);
        let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()).ok();
        for adapter_entry in registry.lock().await.list() {
            if adapter_entry.channel == "whatsapp"
                && let Some(ref store) = vault
            {
                let required = [
                    ("whatsapp-token", "access token"),
                    ("whatsapp-phone-number-id", "phone number ID"),
                    ("whatsapp-verify-token", "verify token"),
                    ("whatsapp-app-secret", "app secret"),
                ];
                let missing: Vec<&str> = required
                    .iter()
                    .filter(|(key, _)| store.retrieve(key).is_err())
                    .map(|(_, human)| *human)
                    .collect();
                if !missing.is_empty() {
                    anyhow::bail!(
                        "WhatsApp adapter is registered but the vault is missing: {}. \
                         Re-run `wirken channel add whatsapp` or set WIRKEN_WHATSAPP_TOKEN, \
                         WIRKEN_WHATSAPP_PHONE_NUMBER_ID, WIRKEN_WHATSAPP_VERIFY_TOKEN, and \
                         WIRKEN_WHATSAPP_APP_SECRET before starting.",
                        missing.join(", ")
                    );
                }
            }
        }
    }

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
    //
    // The proxy requires Ed25519 authentication. An agent whose
    // identity file failed to load earlier (cfg.identity is None)
    // cannot connect; we skip it with a warning rather than using
    // a throwaway key the proxy would reject anyway.
    for (agent_id, cfg) in static_configs.iter_mut() {
        let identity = match cfg.identity.as_ref() {
            Some(i) => i,
            None => {
                tracing::warn!(
                    "skipping MCP proxy connection for agent '{agent_id}': no signing identity"
                );
                continue;
            }
        };
        match wirken_agent::mcp::McpProxyClient::connect(&mcp_proxy_socket, agent_id, identity)
            .await
        {
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
    let org_tool_policy =
        wirken_gateway::org::load_tool_policy(&cfg.data_dir).map(std::sync::Arc::new);
    if let Some(ref policy) = org_tool_policy {
        let allowed = if policy.allowed_tools.is_empty() {
            "any".to_string()
        } else {
            policy.allowed_tools.join(", ")
        };
        let blocked = if policy.blocked_tools.is_empty() {
            "none".to_string()
        } else {
            policy.blocked_tools.join(", ")
        };
        println!("  Org tool policy: allowed={allowed}; blocked={blocked}");
    }
    let factory = AgentFactory::with_options(
        static_configs,
        session_log.clone(),
        Some(permissions.clone()),
        org_tool_policy,
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

    // Resolve the authenticated channel from the registry. Every
    // inbound frame on this connection must claim the same channel
    // — otherwise a compromised adapter could send a frame with
    // `channel: "slack"` and drive Slack-bound agent routing under
    // session context that has nothing to do with the authenticated
    // connection. The `channel` field in the frame is attacker-
    // influenced; the registry lookup by adapter_id is authenticated
    // by the ed25519 handshake. Pin to the latter. Wrapped in
    // `AuthenticatedChannel` so the type distinguishes it from any
    // claimed-from-the-wire channel string further down.
    let authenticated_channel = match registry.lock().await.get(&adapter_id) {
        Some(entry) => AuthenticatedChannel::new(entry.channel),
        None => {
            return Err(anyhow::anyhow!(
                "Adapter '{adapter_id}' passed handshake but is not in the registry (race?)"
            ));
        }
    };

    tracing::info!("Adapter '{adapter_id}' authenticated on channel '{authenticated_channel}'");
    registry.lock().await.set_connected(&adapter_id, true);

    audit
        .log(
            AuditEvent::new("gateway", "adapter.connect", &adapter_id)
                .with_channel(authenticated_channel.as_str()),
        )
        .await?;

    let writer = Arc::new(Mutex::new(writer));

    // Message loop
    let result = message_loop(
        &adapter_id,
        &authenticated_channel,
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
            AuditEvent::new("gateway", "adapter.disconnect", &adapter_id)
                .with_channel(authenticated_channel.as_str()),
        )
        .await?;

    tracing::info!("Adapter '{adapter_id}' disconnected");
    result
}

/// Main message loop: read inbound from adapter, route to agent, send response back.
///
/// `authenticated_channel` is the channel string the adapter is
/// registered under in the adapter registry, confirmed by the
/// Ed25519 handshake. Every inbound frame's self-declared `channel`
/// field is compared against this value; mismatches are rejected
/// and audited. Without that check, a compromised adapter could
/// claim any other channel in the frame payload and hijack that
/// channel's session state, routing, and permission context.
#[allow(clippy::too_many_arguments)]
async fn message_loop(
    adapter_id: &str,
    authenticated_channel: &AuthenticatedChannel,
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
                // Reject any inbound that claims a channel the
                // authenticated adapter is not responsible for. See
                // `AuthenticatedChannel::require_match`. The frame's
                // `channel` field is attacker-influenced; the
                // adapter's channel was authenticated by the
                // handshake + registry lookup.
                if let Err(mismatch) = authenticated_channel.require_match(&channel) {
                    tracing::warn!(
                        "Adapter '{adapter_id}' rejected cross-channel frame: {mismatch}"
                    );
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                adapter_id,
                                "adapter.channel_mismatch",
                                mismatch.to_string(),
                            )
                            .with_channel(authenticated_channel.as_str())
                            .with_detail(serde_json::json!({
                                "authenticated_channel": mismatch.authenticated,
                                "claimed_channel": mismatch.claimed,
                                "conversation_id": conversation_id,
                                "sender_id": sender_id,
                                "message_id": id,
                            })),
                        )
                        .await;
                    continue;
                }

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

/// Parse the `channel_overrides` map from provider.json and resolve
/// each override's declared vault slot into a raw api_key.
///
/// Expected shape in provider.json:
///
/// ```json
/// {
///   "provider": "anthropic",
///   "model": "claude-sonnet-4-6",
///   "base_url": "...",
///   "channel_overrides": {
///     "signal": {
///       "provider": "privatemode",
///       "model": "kimi-k2.5",
///       "base_url": "http://localhost:8080/v1",
///       "api_key_name": "privatemode-access-key"
///     }
///   }
/// }
/// ```
///
/// An absent / malformed `channel_overrides` key is treated as
/// "no overrides" — the function returns an empty map and
/// `AgentFactory::wake` falls through to the default for every
/// channel. This matches the back-compat contract from #60.
///
/// `api_key_name` is looked up in the vault; the function is
/// fail-closed on a configured-but-missing slot (an operator who
/// named a slot that does not exist in the vault gets an early,
/// clear error instead of a runtime failure on the first inbound
/// message).
fn resolve_channel_overrides(
    provider_json: &serde_json::Value,
    data_dir: &std::path::Path,
    vault_db_path: &std::path::Path,
    vault_passphrase: &str,
) -> anyhow::Result<std::collections::HashMap<String, wirken_agent::ChannelOverride>> {
    let raw = match provider_json.get("channel_overrides") {
        Some(serde_json::Value::Object(m)) if !m.is_empty() => m,
        _ => return Ok(std::collections::HashMap::new()),
    };

    // Open the vault once, not per-override. The passphrase is
    // already collected earlier in run() for the default provider's
    // key; reuse it verbatim.
    let passphrase = vault_passphrase.to_string();
    let keychain = probe_keychain(data_dir, move || passphrase.clone());
    let store = CredentialStore::open(vault_db_path, keychain.as_ref())
        .context("Failed to open credential store for channel_overrides")?;

    let mut out = std::collections::HashMap::new();
    for (channel, cfg) in raw {
        let provider = cfg
            .get("provider")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("channel_overrides['{channel}'] missing 'provider' field")
            })?;
        let model = cfg.get("model").and_then(|v| v.as_str()).ok_or_else(|| {
            anyhow::anyhow!("channel_overrides['{channel}'] missing 'model' field")
        })?;
        let base_url = cfg.get("base_url").and_then(|v| v.as_str()).unwrap_or("");

        let api_key = match cfg.get("api_key_name").and_then(|v| v.as_str()) {
            Some(slot) => {
                let (secret, _) = store.retrieve(slot).with_context(|| {
                    format!(
                        "channel_overrides['{channel}'] names vault slot '{slot}', \
                         but that slot is not present in the vault. \
                         Run `wirken credentials add {slot}` to add it."
                    )
                })?;
                Some(secret.expose().to_string())
            }
            None => None,
        };

        let llm_config = LlmConfig::from_provider(provider, base_url, model);
        out.insert(
            channel.clone(),
            wirken_agent::ChannelOverride {
                llm_config,
                api_key,
            },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod channel_overrides_tests {
    use super::resolve_channel_overrides;
    use tempfile::TempDir;
    use wirken_vault::{AgeFileKeychain, CredentialStore, VaultSecret};

    fn vault_with(slot: &str, value: &str) -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let keychain = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&vault_path, &keychain).unwrap();
        store
            .store(slot, "test", &VaultSecret::new(value.into()), None, None)
            .unwrap();
        (tmp, vault_path)
    }

    #[test]
    fn missing_channel_overrides_returns_empty_map() {
        let (tmp, vault_path) = vault_with("ignored-slot", "ignored");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "base_url": "https://api.anthropic.com/v1",
        });
        let out =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_channel_overrides_object_returns_empty_map() {
        let (tmp, vault_path) = vault_with("ignored-slot", "ignored");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "channel_overrides": {},
        });
        let out =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn resolves_slot_to_key_and_constructs_override() {
        let (tmp, vault_path) = vault_with("privatemode-access-key", "pm-secret");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "channel_overrides": {
                "signal": {
                    "provider": "privatemode",
                    "model": "kimi-k2.5",
                    "base_url": "http://localhost:8080/v1",
                    "api_key_name": "privatemode-access-key"
                }
            }
        });
        let out =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .unwrap();
        let signal = out.get("signal").expect("signal override resolved");
        assert_eq!(signal.llm_config.model, "kimi-k2.5");
        assert_eq!(signal.api_key.as_deref(), Some("pm-secret"));
    }

    #[test]
    fn missing_slot_in_vault_fails_closed_at_startup() {
        // Operator named a vault slot that was never created. Refusing
        // to start here beats a confusing runtime failure on the first
        // message routed to the channel.
        let (tmp, vault_path) = vault_with("some-other-slot", "irrelevant");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "channel_overrides": {
                "signal": {
                    "provider": "privatemode",
                    "model": "kimi-k2.5",
                    "api_key_name": "privatemode-access-key"
                }
            }
        });
        let err =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .expect_err("missing slot must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("privatemode-access-key"),
            "error must name the missing slot, got: {msg}"
        );
    }

    #[test]
    fn override_without_api_key_name_is_allowed() {
        // Some provider configurations do not require a key (local
        // Ollama, Privatemode proxy accepting any bearer). An override
        // that omits api_key_name persists cleanly with api_key = None.
        let (tmp, vault_path) = vault_with("ignored", "ignored");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "channel_overrides": {
                "ollama-channel": {
                    "provider": "ollama",
                    "model": "llama3",
                    "base_url": "http://localhost:11434/v1"
                }
            }
        });
        let out =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .unwrap();
        let ov = out.get("ollama-channel").unwrap();
        assert_eq!(ov.llm_config.model, "llama3");
        assert_eq!(ov.api_key, None);
    }

    #[test]
    fn override_missing_provider_field_errors_with_channel_name() {
        let (tmp, vault_path) = vault_with("ignored", "ignored");
        let provider_json = serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "channel_overrides": {
                "signal": { "model": "kimi-k2.5" }
            }
        });
        let err =
            resolve_channel_overrides(&provider_json, tmp.path(), &vault_path, "test-passphrase")
                .expect_err("missing provider must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("signal"), "error must name the channel: {msg}");
        assert!(
            msg.contains("provider"),
            "error must name the missing field: {msg}"
        );
    }
}
