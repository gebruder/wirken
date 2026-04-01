use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;

use wirken_agent::Agent;
use wirken_agent::llm::LlmConfig;
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
    let api_key = if provider != "ollama" {
        let keychain = probe_keychain(&cfg.data_dir, || {
            dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
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

    // --- Start audit writer (with optional SIEM forwarding) ---
    let siem_config = load_siem_config(&cfg);
    let (audit_writer, audit_handle) = AuditWriter::with_siem(&cfg.audit_db_path(), siem_config)
        .context("Failed to start audit writer")?;
    let audit = Arc::new(audit_writer);

    audit
        .log(AuditEvent::new("gateway", "gateway.start", "daemon"))
        .await?;
    println!("  Audit log: {}", cfg.audit_db_path().display());

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

    // --- Setup router and create agents ---
    let router = Arc::new(Router::new());
    let mut agents_map: HashMap<String, Mutex<Agent>> = HashMap::new();

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
            dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
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

            let mut agent = Agent::new(agent_cfg.id.clone(), workspace, llm, agent_api_key)?;
            agent.set_permissions(permissions.clone());

            // Load per-agent skills + shared skills
            let agent_skills = cfg.agent_skills_dir(&agent_cfg.id);
            if agent_skills.is_dir() {
                let _ = agent.load_skills(&agent_skills);
            }
            let shared_skills = cfg.data_dir.join("skills");
            if shared_skills.is_dir() {
                let _ = agent.load_skills(&shared_skills);
            }

            // Load MCP servers
            let mcp_path = cfg.mcp_config_path(&agent_cfg.id);
            if mcp_path.exists() {
                match agent.load_mcp(&mcp_path, |_| None).await {
                    Ok(n) if n > 0 => println!("  MCP: {n} servers for agent:{}", agent_cfg.id),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("MCP load failed for {}: {e}", agent_cfg.id),
                }
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

            agents_map.insert(agent_cfg.id.clone(), Mutex::new(agent));
        }
    }

    // Create default agent for any unbound channels (backward compat with wirken setup)
    if !agents_map.contains_key("default") {
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

        let mut default_agent = Agent::new("default".into(), workspace, llm_config, api_key)?;
        default_agent.set_permissions(permissions.clone());

        let skills_dir = cfg.data_dir.join("skills");
        if skills_dir.is_dir() {
            let _ = default_agent.load_skills(&skills_dir);
        }

        // Load MCP servers
        let mcp_path = cfg.mcp_config_path("default");
        if mcp_path.exists() {
            match default_agent.load_mcp(&mcp_path, |_| None).await {
                Ok(n) if n > 0 => println!("  MCP: {n} servers for agent:default"),
                Ok(_) => {}
                Err(e) => tracing::warn!("MCP load failed for default: {e}"),
            }
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

        agents_map.insert("default".into(), Mutex::new(default_agent));
    }

    println!(
        "  Agents: {}",
        agents_map.keys().cloned().collect::<Vec<_>>().join(", ")
    );

    let agents: Arc<HashMap<String, Mutex<Agent>>> = Arc::new(agents_map);

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

        let handle = tokio::spawn(async move {
            // Small delay to let the listener start
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            tracing::info!("Spawning adapter: {adapter_id}");
            let result = Command::new(&exe)
                .arg("adapter")
                .arg(&adapter_id)
                .env("WIRKEN_DATA_DIR", &data_dir)
                .env("WIRKEN_SOCKET", &sock)
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

    // --- Webchat ---
    let webchat_port = port.unwrap_or(18790);
    let webchat_agents = agents.clone();
    let webchat_audit = audit.clone();
    let webchat_sessions = sessions.clone();
    let webchat_handle = tokio::spawn(async move {
        if let Err(e) = super::webchat::serve(
            webchat_port,
            webchat_agents,
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
    let scheduler_agents = agents.clone();
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

                if let Some(agent_mutex) = scheduler_agents.get(&job.agent_id) {
                    let mut agent = agent_mutex.lock().await;
                    match agent.process_message(&job.message).await {
                        Ok(result) => {
                            tracing::info!("Cron response: {}", truncate(&result.response, 100));
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
                } else {
                    tracing::warn!("Cron: agent '{}' not found", job.agent_id);
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
    let accept_agents = agents.clone();
    let accept_audit = audit.clone();
    let accept_sessions = sessions.clone();
    let accept_router = router.clone();
    let accept_detector = detector.clone();

    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let reg = accept_registry.clone();
                    let ag = accept_agents.clone();
                    let au = accept_audit.clone();
                    let sess = accept_sessions.clone();
                    let rtr = accept_router.clone();
                    let det = accept_detector.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_adapter_connection(stream, reg, ag, au, sess, rtr, det).await
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
    accept_handle.abort();
    webchat_handle.abort();
    scheduler_handle.abort();

    // Drop audit writer to flush remaining events
    drop(audit);
    let _ = audit_handle.await;

    // Cleanup socket
    let _ = std::fs::remove_file(&socket_path);

    println!("  Gateway stopped.");
    Ok(())
}

/// Handle a single adapter connection: handshake, then message loop.
async fn handle_adapter_connection(
    stream: UnixStream,
    registry: Arc<Mutex<AdapterRegistry>>,
    agents: Arc<HashMap<String, Mutex<Agent>>>,
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
        agents,
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
async fn message_loop(
    adapter_id: &str,
    reader: &mut FrameReader,
    writer: Arc<Mutex<FrameWriter>>,
    agents: Arc<HashMap<String, Mutex<Agent>>>,
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

                // Process with the routed agent
                let (response, denials) = match agents.get(&agent_id) {
                    Some(agent_mutex) => {
                        let mut ag = agent_mutex.lock().await;
                        match ag.process_message(&text).await {
                            Ok(result) => (result.response, result.denials),
                            Err(e) => {
                                tracing::error!("Agent '{agent_id}' error: {e}");
                                (format!("Error processing message: {e}"), Vec::new())
                            }
                        }
                    }
                    None => {
                        tracing::error!("No agent '{agent_id}' found, trying default");
                        match agents.get("default") {
                            Some(default_mutex) => {
                                let mut ag = default_mutex.lock().await;
                                match ag.process_message(&text).await {
                                    Ok(result) => (result.response, result.denials),
                                    Err(e) => (format!("Error: {e}"), Vec::new()),
                                }
                            }
                            None => (
                                "No agent available to process this message.".into(),
                                Vec::new(),
                            ),
                        }
                    }
                };

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
