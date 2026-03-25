use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;

use wirken_agent::llm::LlmConfig;
use wirken_agent::Agent;
use wirken_audit::{AuditEvent, AuditWriter};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::router::{RouteBinding, Router};
use wirken_gateway::session::SessionStore;
use wirken_ipc::transport::{split_stream, FrameReader, FrameWriter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::perform_gateway_handshake;
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

    // --- Load provider config ---
    let provider_path = cfg.data_dir.join("provider.json");
    if !provider_path.exists() {
        anyhow::bail!("No AI provider configured. Run `wirken setup` first.");
    }
    let provider_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&provider_path)?
    )?;
    let provider = provider_json["provider"].as_str().unwrap_or("ollama");
    let model = provider_json["model"].as_str().unwrap_or("llama3");
    let base_url = provider_json["base_url"].as_str().unwrap_or("http://localhost:11434/v1");

    println!("  Provider: {provider}/{model}");

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

    // --- Start audit writer ---
    let (audit_writer, audit_handle) = AuditWriter::new(&cfg.audit_db_path())
        .context("Failed to start audit writer")?;
    let audit = Arc::new(audit_writer);

    audit.log(AuditEvent::new("gateway", "gateway.start", "daemon")).await?;
    println!("  Audit log: {}", cfg.audit_db_path().display());

    // --- Open stores ---
    let registry = Arc::new(Mutex::new(AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?));
    let sessions = Arc::new(Mutex::new(SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?));

    // --- Setup router ---
    let router = Arc::new(Router::new());
    // Bind all registered adapters to the default agent with wildcard routing
    for adapter in registry.lock().await.list() {
        router.bind(RouteBinding {
            channel: adapter.channel.clone(),
            conversation_pattern: "*".into(),
            agent_id: "default".into(),
        });
        println!("  Route: {} -> agent:default", adapter.channel);
    }

    // --- Create agent ---
    let workspace = cfg.data_dir.join("workspace");
    std::fs::create_dir_all(&workspace)?;

    let llm_config = LlmConfig::custom(base_url, model);
    let mut agent = Agent::new("default".into(), workspace.clone(), llm_config, api_key);

    // Load skills
    let skills_dir = cfg.data_dir.join("skills");
    if skills_dir.is_dir() {
        match agent.load_skills(&skills_dir) {
            Ok(count) if count > 0 => println!("  Skills: {count} loaded"),
            _ => {}
        }
    }

    let agent = Arc::new(Mutex::new(agent));

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
    let webchat_agent = agent.clone();
    let webchat_audit = audit.clone();
    let webchat_sessions = sessions.clone();
    let webchat_handle = tokio::spawn(async move {
        if let Err(e) = super::webchat::serve(
            webchat_port,
            webchat_agent,
            webchat_audit,
            webchat_sessions,
        ).await {
            tracing::error!("Webchat server error: {e}");
        }
    });

    println!("  WebChat: http://localhost:{webchat_port}");
    println!();
    println!("  Gateway running. Press Ctrl+C to stop.");
    println!();

    // --- Accept adapter connections ---
    let accept_registry = registry.clone();
    let accept_agent = agent.clone();
    let accept_audit = audit.clone();
    let accept_sessions = sessions.clone();
    let accept_router = router.clone();

    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let reg = accept_registry.clone();
                    let ag = accept_agent.clone();
                    let au = accept_audit.clone();
                    let sess = accept_sessions.clone();
                    let rtr = accept_router.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_adapter_connection(
                            stream, reg, ag, au, sess, rtr,
                        ).await {
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

    audit.log(AuditEvent::new("gateway", "gateway.stop", "daemon")).await?;

    // Abort adapter processes
    for handle in adapter_handles {
        handle.abort();
    }
    accept_handle.abort();
    webchat_handle.abort();

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
    agent: Arc<Mutex<Agent>>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    router: Arc<Router>,
) -> Result<()> {
    let (mut reader, mut writer) = split_stream(stream);

    // Handshake
    // Collect known adapters for handshake verification (avoids holding lock across await)
    let known: std::collections::HashMap<String, [u8; 32]> = {
        let reg = registry.lock().await;
        reg.list().into_iter().map(|a| (a.adapter_id, a.public_key)).collect()
    };

    let (adapter_id, _pub_key) = perform_gateway_handshake(
        &mut reader,
        &mut writer,
        move |id, pk| {
            match known.get(id) {
                None => Err(wirken_ipc::HandshakeError::UnknownAdapter(id.to_string())),
                Some(expected) if expected == pk => Ok(()),
                Some(_) => Err(wirken_ipc::HandshakeError::InvalidSignature),
            }
        },
    ).await.context("Adapter handshake failed")?;

    tracing::info!("Adapter '{adapter_id}' authenticated");
    registry.lock().await.set_connected(&adapter_id, true);

    audit.log(
        AuditEvent::new("gateway", "adapter.connect", &adapter_id)
            .with_channel(&adapter_id)
    ).await?;

    let writer = Arc::new(Mutex::new(writer));

    // Message loop
    let result = message_loop(
        &adapter_id,
        &mut reader,
        writer.clone(),
        agent,
        audit.clone(),
        sessions,
        router,
    ).await;

    registry.lock().await.set_connected(&adapter_id, false);
    audit.log(
        AuditEvent::new("gateway", "adapter.disconnect", &adapter_id)
            .with_channel(&adapter_id)
    ).await?;

    tracing::info!("Adapter '{adapter_id}' disconnected");
    result
}

/// Main message loop: read inbound from adapter, route to agent, send response back.
async fn message_loop(
    adapter_id: &str,
    reader: &mut FrameReader,
    writer: Arc<Mutex<FrameWriter>>,
    agent: Arc<Mutex<Agent>>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    router: Arc<Router>,
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
            let frame_reader = msg.get_root::<frame::Reader<'_>>()
                .context("Failed to parse frame")?;

            match frame_reader.which()? {
                frame::Inbound(inbound) => {
                    let m = inbound?;
                    let text = m.get_text()?.to_str()
                        .map_err(|e| anyhow::anyhow!("text not utf8: {e}"))?
                        .to_string();
                    let sender_id = m.get_sender_id()?.to_str()
                        .map_err(|e| anyhow::anyhow!("sender_id not utf8: {e}"))?
                        .to_string();
                    let sender_name = m.get_sender_name()?.to_str()
                        .map_err(|e| anyhow::anyhow!("sender_name not utf8: {e}"))?
                        .to_string();
                    let channel = m.get_channel()?.to_str()
                        .map_err(|e| anyhow::anyhow!("channel not utf8: {e}"))?
                        .to_string();
                    let conversation_id = m.get_conversation_id()?.to_str()
                        .map_err(|e| anyhow::anyhow!("conversation_id not utf8: {e}"))?
                        .to_string();
                    let msg_id = m.get_id()?.to_str()
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
                    let msg_id = r.get_message_id()?.to_str()
                        .unwrap_or_default().to_string();
                    InboundAction::DeliveryResult { success, msg_id }
                }
                _ => InboundAction::Unknown,
            }
        };
        // msg dropped — safe to .await

        match action {
            InboundAction::Message {
                id, text, sender_id, sender_name, channel, conversation_id,
            } => {
                tracing::info!(
                    "[{}] {} ({}): {}",
                    channel,
                    sender_name,
                    sender_id,
                    truncate(&text, 80),
                );

                // Audit inbound
                audit.log(
                    AuditEvent::new(&sender_id, "message.inbound", &text)
                        .with_channel(&channel)
                        .with_session(&conversation_id)
                ).await?;

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
                let agent_id = router.resolve(&channel, &conversation_id)
                    .unwrap_or_else(|_| "default".into());

                // Process with agent
                let response = {
                    let mut ag = agent.lock().await;
                    match ag.process_message(&text).await {
                        Ok(response) => response,
                        Err(e) => {
                            tracing::error!("Agent error: {e}");
                            format!("Error processing message: {e}")
                        }
                    }
                };

                tracing::info!("[{}] -> {}", channel, truncate(&response, 80));

                // Audit outbound
                audit.log(
                    AuditEvent::new(&agent_id, "message.outbound", &response)
                        .with_channel(&channel)
                        .with_session(&conversation_id)
                ).await?;

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
                w.write_message(&reply).await
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
    DeliveryResult { success: bool, msg_id: String },
    Unknown,
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
