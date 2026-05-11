use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
// UnixListener/UnixStream are still used for the orchestrator-push
// handler which reads JSON-line requests from the unix-only push
// socket. The gateway↔adapter capnp path uses wirken_ipc::BoxStream
// via `bind`/`connect`. Orchestrator-push is documented as Linux/macOS
// only; the whole block is cfg(unix)-gated.
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;

use wirken_agent::factory::CacheMode;
use wirken_agent::llm::LlmConfig;
use wirken_agent::{AgentFactory, AgentStaticConfig, SkillLoader, session_id_for};
use wirken_audit::{ActorKind, AuditEvent, AuditWriter, SiemConfig, SiemTarget};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::injection_detect::InjectionDetector;
use wirken_gateway::outbound_dispatcher::OutboundDispatcher;
use wirken_gateway::router::{RouteBinding, Router};
use wirken_gateway::session::SessionStore;
use wirken_ipc::orchestrator::{OrchestratorPushRequest, OrchestratorPushResponse};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AuthenticatedChannel, Principal, Stream, perform_gateway_handshake};
use wirken_ipc::{IpcFrameReader, IpcFrameWriter, split_stream};
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

    // --- Start audit writer (with optional SIEM forwarding) ---
    //
    // Fail-closed: if the writer cannot start, abort startup before
    // any other side effect runs (org-config apply, vault open, the
    // adapter sockets). The org-config apply path emits applying /
    // applied / apply-failed audit events, so it must not run until
    // the writer exists.
    //
    // The alarm-log HMAC key is loaded from the keychain (or
    // generated and stored on first run). Failure here is non-fatal:
    // the writer falls back to unsigned-mode and emits a prominent
    // warn so an operator can confirm the trust posture. Doctor
    // surfaces unsigned alarm records as `NoKey` instead of
    // `Verified`.
    let alarm_log_key = {
        let kc = probe_keychain(&cfg.data_dir, String::new);
        match wirken_vault::load_or_create_alarm_log_key(kc.as_ref()) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "alarm log running in UNSIGNED mode: could not load or store \
                     the HMAC signing key in the keychain. Tampered alarm records \
                     will not be detected by `wirken doctor`."
                );
                None
            }
        }
    };
    let siem_config = load_siem_config(&cfg);

    // Load the gateway's audit chain-head signing key. Distinct
    // from any per-adapter IPC key and from per-agent attestation
    // keys: this one signs ChainHead records over the audit chain
    // so an offline verifier with the published public key can
    // anchor the recorded hashes to this gateway. Generated on
    // first run, persisted at <data_dir>/audit/audit-signing.key.
    let audit_signer = match wirken_audit::AuditSigningKey::load_or_create(&cfg.data_dir) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "audit chain-head signing disabled: could not load or generate \
                 the gateway audit signing key. Chain heads will not be emitted; \
                 operators relying on offline-verifiable signatures should fix \
                 the underlying file-permission or disk error and restart."
            );
            None
        }
    };

    let (audit_writer, audit_handle) = AuditWriter::with_siem_alarm_and_audit_signer(
        &cfg.audit_db_path(),
        siem_config,
        alarm_log_key,
        audit_signer.clone(),
    )
    .context("Failed to start audit writer")?;
    let audit = Arc::new(audit_writer);

    audit
        .log(AuditEvent::new(
            ActorKind::Service,
            "gateway",
            "gateway.start",
            "daemon",
        ))
        .await?;
    println!("  Audit log: {}", cfg.audit_db_path().display());

    // --- Refresh org config if configured ---
    //
    // Emits org-config.applying before any write, then either
    // org-config.applied with the section list, or
    // org-config.apply-failed with the partial section list and the
    // failed section name. Both events carry the org URL and the
    // WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG state at refresh time so an
    // operator can reconstruct the trust posture from the audit row
    // alone.
    if let Some(org_url) = wirken_gateway::org::load_org_url(&cfg.data_dir) {
        let allow_unsigned =
            wirken_gateway::org::parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG");
        let pubkey_fingerprint = org_pubkey_fingerprint(&cfg.data_dir);
        audit
            .log(
                AuditEvent::new(
                    ActorKind::Service,
                    "gateway",
                    "org-config.applying",
                    cfg.data_dir.display().to_string(),
                )
                .with_detail(serde_json::json!({
                    "org_url": org_url,
                    "pubkey_fingerprint": pubkey_fingerprint,
                    "allow_unsigned": allow_unsigned,
                })),
            )
            .await?;

        match wirken_gateway::org::fetch_org_config(&org_url, &cfg.data_dir).await {
            Ok(org) => match wirken_gateway::org::apply_org_config(&cfg.data_dir, &org, true) {
                Ok(applied) => {
                    if !applied.is_empty() {
                        println!("  Org config refreshed: {}", applied.join(", "));
                        if applied.iter().any(|s| s == "siem") {
                            tracing::warn!(
                                "Org config refresh landed a new siem.json; the in-process \
                                 audit writer was constructed before this update and will \
                                 only pick it up on the next `wirken run`."
                            );
                        }
                    }
                    audit
                        .log(
                            AuditEvent::new(
                                ActorKind::Service,
                                "gateway",
                                "org-config.applied",
                                cfg.data_dir.display().to_string(),
                            )
                            .with_detail(serde_json::json!({
                                "sections": applied,
                            })),
                        )
                        .await?;
                }
                Err(failure) => {
                    tracing::warn!(
                        "Org config apply failed at section {}: {}",
                        failure.section,
                        failure.error
                    );
                    audit
                        .log(
                            AuditEvent::new(
                                ActorKind::Service,
                                "gateway",
                                "org-config.apply-failed",
                                cfg.data_dir.display().to_string(),
                            )
                            .with_detail(serde_json::json!({
                                "applied_before_failure": failure.applied,
                                "failed_section": failure.section,
                                "error": failure.error,
                            })),
                        )
                        .await?;
                }
            },
            Err(e) => {
                tracing::warn!("Org config refresh failed: {e}");
                audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Service,
                            "gateway",
                            "org-config.apply-failed",
                            cfg.data_dir.display().to_string(),
                        )
                        .with_detail(serde_json::json!({
                            "applied_before_failure": Vec::<String>::new(),
                            "failed_section": "fetch",
                            "error": e,
                        })),
                    )
                    .await?;
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
            Err(wirken_vault::VaultError::Decryption(_)) => {
                // AEAD-tag mismatch on a credential that was stored
                // before the AAD-binding change in 26b1f8e. Older
                // vault.db files cannot be decrypted by the current
                // build; the operator has to re-store the credential
                // (or remove the file) for the gateway to make
                // forward progress on a non-Ollama provider.
                tracing::warn!(
                    vault = %cfg.vault_db_path().display(),
                    "vault decryption failed for '{cred_name}': vault.db at the path \
                     above uses a pre-26b1f8e AEAD format. Decryption will fail for \
                     every credential stored before the upgrade. Remove the file and \
                     re-run `wirken setup` (or re-add channels via `wirken channel add`) \
                     to re-store credentials under the new format. The gateway will \
                     continue starting but the {provider} provider has no usable API \
                     key until the vault is reset."
                );
                None
            }
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

    // --- Resolve the host-exec shell once at startup ---
    //
    // Mode-off and sandbox fallback both invoke `exec` against this
    // shell. Resolving once means the operator sees one log line and
    // skill authors writing for cross-platform portability can tell
    // at a glance whether their researcher's machine picked up sh
    // (Git for Windows installed) or fell back to powershell/cmd.
    let host_exec_sandbox = super::load_sandbox_config(&cfg.data_dir);
    match host_exec_sandbox.shell.resolve() {
        Some(resolved) => {
            println!(
                "  Host exec shell: {} ({})",
                resolved.kind,
                resolved.program.display()
            );
        }
        None => {
            println!(
                "  Host exec shell: none found ({:?}); the exec tool will refuse to run on this host",
                host_exec_sandbox.shell
            );
        }
    }

    // --- exec=Off posture warning ---
    //
    // When `sandbox.json` configures `mode: off`, the `exec` tool
    // shells out at the wirken UID without any container or chroot.
    // That shell can read and rewrite every trust file under the data
    // directory: `tool_policy.json`, `sandbox.json`, `org.url`,
    // `org-config-pubkey.pub`, `audit.db`, `vault.db`,
    // `agents/<id>/identity.key`, `audit-alarms.log`. A change to any
    // of those files takes effect at the next gateway start. This is
    // the documented operator-controlled trust boundary, not a bug,
    // but operators running with `exec=Off` should know which files
    // are reachable.
    if host_exec_sandbox.mode == wirken_agent::sandbox::SandboxMode::Off {
        tracing::warn!(
            data_dir = %cfg.data_dir.display(),
            "sandbox mode is Off — `exec` tool shells out at the wirken UID and can \
             read or rewrite trust files under the data dir: tool_policy.json, \
             sandbox.json, org.url, org-config-pubkey.pub, audit.db, vault.db, \
             agents/<id>/identity.key, audit-alarms.log. See README and \
             docs/security-properties.md."
        );
    }

    // --- Open the session log alongside the audit log ---
    //
    // Item 1 slice 2 made the audit DB the home of session_events.
    // Item 2 slice 1 has the agent write durability events
    // (UserMessage, AssistantMessage, AssistantToolCalls, ToolResult,
    // PermissionDenied) into the same store. Slice 2 will introduce
    // wake() which reads them back. Each agent gets its own session
    // id of `agent_id` for now; per-conversation session ids land
    // with wake().
    let session_log_concrete = match audit_signer.clone() {
        Some(s) => wirken_audit::SqliteSessionLog::open_with_signer(&cfg.audit_db_path(), s)
            .context("Failed to open session log")?,
        None => wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    };
    let session_log_for_shutdown = Arc::new(session_log_concrete);
    let session_log: Arc<dyn wirken_audit::SessionLog> = session_log_for_shutdown.clone();

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
                    extra_interceptors: vec![],
                    zirkel_db_path: None,
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
                extra_interceptors: vec![],
                zirkel_db_path: None,
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

    // --- Setup IPC listener ---
    let socket_path = cfg.socket_dir().join("gateway.sock");
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let mut listener = wirken_ipc::bind(&socket_path)
        .context(format!("Failed to bind IPC at {}", socket_path.display()))?;
    // Defense-in-depth file-permission posture: the load-bearing gate
    // is the Ed25519 adapter handshake, but matching the orchestrator
    // and mcp-proxy sockets' 0o600 chmod closes the cross-user same-
    // host attack surface that the parent dir's umask alone might
    // leave open.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to chmod gateway socket to 0600")?;
    }
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

    // --- MCP server inventory warning ---
    //
    // The agent's per-tool gate at runtime checks the MCP tool *name*
    // against the operator's permission tier; the gate does not bound
    // the MCP child process's own behavior. MCP children spawn at the
    // wirken UID with no chroot, no uid drop, no syscall sandbox, and
    // can read or write any file the wirken user can. Operators
    // installing third-party MCP servers should treat them with the
    // same trust as a binary they would run directly. List configured
    // servers at startup so the inventory is operator-visible.
    {
        let mcp_config_path = cfg.data_dir.join("mcp.json");
        if mcp_config_path.exists()
            && let Ok(body) = std::fs::read_to_string(&mcp_config_path)
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(servers) = val.get("servers").and_then(|s| s.as_object())
            && !servers.is_empty()
        {
            // Surface the command path the operator configured next to
            // the server name. The command is the binary that will be
            // spawned at the wirken UID; pairing the name with the path
            // lets the operator spot a tampered or shadowed entry from
            // the startup line alone, without re-reading mcp.json.
            //
            // Long paths get trimmed at 80 chars to keep the warn line
            // legible; the on-disk config remains canonical.
            let inventory: Vec<String> = servers
                .iter()
                .map(|(name, body)| {
                    let cmd = body
                        .get("command")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<no command>");
                    let trimmed = trim_command_for_inventory(cmd);
                    format!("{name}={trimmed}")
                })
                .collect();
            tracing::warn!(
                servers = ?inventory,
                "MCP servers configured: each runs at the wirken UID with no \
                 process sandbox; the agent's per-tool permission gate checks tool \
                 names only, not child process behavior. Install only from trusted \
                 sources. See docs/security-properties.md."
            );
        }
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

    // --- Wire zirkel keep/skip interceptors -------------------------
    //
    // Read zirkel's bindings table once at startup and attach a
    // KeepSkipInterceptor to each bound agent. Live re-bind doesn't
    // reach already-running agents — `wirken zirkel bind` warns
    // when this daemon is up. This loop runs before the factory is
    // built so the interceptors land in the agent's
    // extra_interceptors list.
    let zirkel_db = cfg.data_dir.join("zirkel").join("aggregator.db");
    if zirkel_db.exists() {
        match rusqlite::Connection::open(&zirkel_db) {
            Ok(zconn) => match wirken_zirkel::binding::list_all(&zconn) {
                Ok(bindings) => {
                    for binding in bindings {
                        let Some(static_cfg) = static_configs.get_mut(&binding.agent_id) else {
                            tracing::warn!(
                                "zirkel binding for agent '{}' has no matching agent config; \
                                 keep/skip interceptor not attached. Run `wirken agents add` or \
                                 fix the binding with `wirken zirkel bind --agent ...`.",
                                binding.agent_id,
                            );
                            continue;
                        };
                        match wirken_zirkel::keep_skip_interceptor::KeepSkipInterceptor::open(
                            &zirkel_db,
                        ) {
                            Ok(interceptor) => {
                                static_cfg.extra_interceptors.push(Arc::new(interceptor));
                                println!(
                                    "  Zirkel: keep/skip on agent '{}' (channel '{}')",
                                    binding.agent_id, binding.channel
                                );
                            }
                            Err(e) => tracing::warn!(
                                "open keep/skip interceptor at {}: {e}",
                                zirkel_db.display()
                            ),
                        }
                    }
                }
                Err(e) => tracing::warn!("list zirkel bindings: {e}"),
            },
            Err(e) => tracing::warn!("open zirkel db {}: {e}", zirkel_db.display()),
        }
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
    if wirken_gateway::org::parse_boolean_escape("WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN") {
        tracing::warn!(
            "WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN: webchat /api/chat accepts requests \
             without an Origin header. Same-host non-browser callers (curl, scripts) \
             can drive the agent. Same UID is the only trust boundary."
        );
    }
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

    // --- Outbound dispatcher (orchestrator push rendezvous) ---
    //
    // Holds the live capnp writer for each connected adapter, keyed
    // by channel. Per-adapter handlers register on auth and
    // unregister on disconnect; the orchestrator-push listener below
    // looks up the writer when forwarding a push.
    let dispatcher = Arc::new(OutboundDispatcher::new());

    // --- Accept adapter connections ---
    let accept_registry = registry.clone();
    let accept_factory = factory.clone();
    let accept_audit = audit.clone();
    let accept_sessions = sessions.clone();
    let accept_router = router.clone();
    let accept_detector = detector.clone();
    let accept_dispatcher = dispatcher.clone();

    // SAFETY: `geteuid` is always-safe FFI; documented as never
    // failing and never invoking user-space callbacks.
    #[cfg(unix)]
    let gateway_expected_principal = Principal::Uid(unsafe { libc::geteuid() });
    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    // Defense-in-depth peer-credential check. Gateway
                    // accepts only same-UID adapter processes; the
                    // Ed25519 handshake is still the load-bearing
                    // identity gate but a different-UID peer is a
                    // structural error worth rejecting before paying
                    // the handshake cost.
                    #[cfg(unix)]
                    match stream.peer_principal() {
                        Ok(actual) if actual == gateway_expected_principal => {}
                        Ok(actual) => {
                            tracing::warn!(
                                "gateway: refusing peer {} (expected {})",
                                actual,
                                gateway_expected_principal
                            );
                            let _ = accept_audit
                                .log(
                                    AuditEvent::new(
                                        ActorKind::Service,
                                        "gateway",
                                        "gateway.peer.refused",
                                        "gateway-socket",
                                    )
                                    .with_detail(
                                        serde_json::json!({
                                            "reason": "principal_mismatch",
                                            "expected": gateway_expected_principal.to_string(),
                                            "actual": actual.to_string(),
                                        }),
                                    ),
                                )
                                .await;
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!("gateway: peer_principal unavailable, refusing: {e}");
                            let _ = accept_audit
                                .log(
                                    AuditEvent::new(
                                        ActorKind::Service,
                                        "gateway",
                                        "gateway.peer.refused",
                                        "gateway-socket",
                                    )
                                    .with_detail(
                                        serde_json::json!({
                                            "reason": "peer_principal_unavailable",
                                            "expected": gateway_expected_principal.to_string(),
                                            "error": e.to_string(),
                                        }),
                                    ),
                                )
                                .await;
                            continue;
                        }
                    }
                    let reg = accept_registry.clone();
                    let fact = accept_factory.clone();
                    let au = accept_audit.clone();
                    let sess = accept_sessions.clone();
                    let rtr = accept_router.clone();
                    let det = accept_detector.clone();
                    let disp = accept_dispatcher.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_adapter_connection(stream, reg, fact, au, sess, rtr, det, disp)
                                .await
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

    // --- Orchestrator-push listener (Zirkel C-Signal) ---
    //
    // This is not an adapter — adapters cross a trust boundary, this
    // doesn't. Local-only outbound channel: the zirkel CLI process
    // runs as the same UID that owns this data dir, builds its
    // daily digest, and pushes via this socket. The gateway forwards
    // each push to the live adapter writer for the named channel.
    //
    // Posture: 0600 file perms is the primary gate; SO_PEERCRED on
    // accept is defense-in-depth in case the perms are accidentally
    // permissive. JSON line in, JSON line out — no capnp, no
    // handshake, no signature. See crates/ipc/src/orchestrator.rs.
    //
    // Linux/macOS only — Windows uses named pipes for the gateway
    // capnp path but the orchestrator-push JSON-line socket has no
    // analog and would have to be redesigned. Out of scope for the
    // tier-2 Windows release.
    #[cfg(unix)]
    let orchestrator_socket_path = cfg.socket_dir().join("orchestrator.sock");
    #[cfg(unix)]
    {
        if orchestrator_socket_path.exists() {
            let _ = std::fs::remove_file(&orchestrator_socket_path);
        }
    }
    #[cfg(unix)]
    let orchestrator_listener = UnixListener::bind(&orchestrator_socket_path).context(format!(
        "Failed to bind orchestrator UDS at {}",
        orchestrator_socket_path.display()
    ))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &orchestrator_socket_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .context("Failed to chmod orchestrator socket to 0600")?;
    }
    #[cfg(unix)]
    println!(
        "  Orchestrator socket: {}",
        orchestrator_socket_path.display()
    );

    #[cfg(unix)]
    let orchestrator_dispatcher = dispatcher.clone();
    #[cfg(unix)]
    let orchestrator_audit = audit.clone();
    // SAFETY: `geteuid` is always-safe FFI; documented as never
    // failing and never invoking user-space callbacks.
    #[cfg(unix)]
    let expected_principal = Principal::Uid(unsafe { libc::geteuid() });
    #[cfg(unix)]
    let orchestrator_handle = tokio::spawn(async move {
        loop {
            match orchestrator_listener.accept().await {
                Ok((stream, _)) => {
                    let actual_principal = match stream.peer_principal() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                "orchestrator: peer_principal unavailable, refusing: {e}"
                            );
                            let _ = orchestrator_audit
                                .log(
                                    AuditEvent::new(
                                        ActorKind::Service,
                                        "gateway",
                                        "orchestrator.push.refused",
                                        "orchestrator",
                                    )
                                    .with_detail(
                                        serde_json::json!({
                                            "reason": "peer_principal_unavailable",
                                            "expected": expected_principal.to_string(),
                                            "error": e.to_string(),
                                        }),
                                    ),
                                )
                                .await;
                            continue;
                        }
                    };
                    if actual_principal != expected_principal {
                        tracing::warn!(
                            "orchestrator: refusing peer {} (expected {})",
                            actual_principal,
                            expected_principal
                        );
                        let _ = orchestrator_audit
                            .log(
                                AuditEvent::new(
                                    ActorKind::Service,
                                    "gateway",
                                    "orchestrator.push.refused",
                                    "orchestrator",
                                )
                                .with_detail(serde_json::json!({
                                    "reason": "principal_mismatch",
                                    "expected": expected_principal.to_string(),
                                    "actual": actual_principal.to_string(),
                                })),
                            )
                            .await;
                        continue;
                    }
                    let disp = orchestrator_dispatcher.clone();
                    let au = orchestrator_audit.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_orchestrator_push(stream, disp, au).await {
                            tracing::error!("orchestrator push handler error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("orchestrator accept error: {e}");
                }
            }
        }
    });

    // --- Wait for shutdown ---
    tokio::signal::ctrl_c().await?;
    println!();
    println!("  Shutting down...");

    audit
        .log(AuditEvent::new(
            ActorKind::Service,
            "gateway",
            "gateway.stop",
            "daemon",
        ))
        .await?;

    // Abort adapter processes before emitting SessionEnd ChainHeads
    // so no concurrent appends race the shutdown signature.
    for handle in adapter_handles {
        handle.abort();
    }
    mcp_proxy_handle.abort();
    accept_handle.abort();
    #[cfg(unix)]
    orchestrator_handle.abort();
    webchat_handle.abort();
    scheduler_handle.abort();

    // Emit a SessionEnd ChainHead per active session so a clean
    // shutdown leaves a signed terminal head rather than an
    // unsigned tail. Failure here is loud and non-fatal to the
    // shutdown sequence: the writer still flushes, and the
    // verifier reports the unsigned tail under --require-signed
    // so an operator can correlate the abnormal close.
    if audit_signer.is_some() {
        use wirken_audit::SessionLog as _;
        let session_log_for_close = session_log_for_shutdown.clone();
        let close_result = tokio::task::spawn_blocking(move || {
            let mut emitted = 0usize;
            let mut errors = 0usize;
            let session_ids = match session_log_for_close.list_session_ids() {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "audit shutdown could not enumerate sessions for SessionEnd ChainHead emission; \
                         the audit log will end with an unsigned tail and the verifier will surface it"
                    );
                    return (0usize, 1usize);
                }
            };
            for sid in session_ids {
                let handle = session_log_for_close.handle_for(wirken_audit::SessionId::new(sid.clone()));
                match session_log_for_close
                    .emit_chain_head(&handle, wirken_audit::ChainHeadReason::SessionEnd)
                {
                    Ok(Some(_)) => emitted += 1,
                    Ok(None) => {}
                    Err(e) => {
                        errors += 1;
                        tracing::error!(
                            session = %sid,
                            error = %e,
                            "audit shutdown could not emit SessionEnd ChainHead; \
                             this session will end with an unsigned tail"
                        );
                    }
                }
            }
            (emitted, errors)
        })
        .await
        .unwrap_or((0, 1));
        let (emitted, errors) = close_result;
        tracing::info!(
            emitted,
            errors,
            "audit shutdown SessionEnd emission complete"
        );
        if errors > 0 {
            // Loud non-fatal: do not exit nonzero from a well-formed
            // ctrl_c path, but record the unsigned tail in the audit
            // chain so the verifier surfaces it.
            audit
                .log(
                    AuditEvent::new(
                        ActorKind::Service,
                        "gateway",
                        "gateway.stop_unsigned_tail",
                        "audit",
                    )
                    .with_detail(serde_json::json!({
                        "emitted": emitted,
                        "errors": errors,
                    })),
                )
                .await
                .ok();
        }
    }

    // Drop audit writer to flush remaining events
    drop(audit);
    let _ = audit_handle.await;

    // Cleanup sockets
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&mcp_proxy_socket);
    #[cfg(unix)]
    let _ = std::fs::remove_file(&orchestrator_socket_path);

    println!("  Gateway stopped.");
    Ok(())
}

/// Handle a single adapter connection: handshake, then message loop.
#[allow(clippy::too_many_arguments)]
async fn handle_adapter_connection(
    stream: wirken_ipc::BoxStream,
    registry: Arc<Mutex<AdapterRegistry>>,
    factory: Arc<AgentFactory>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    router: Arc<Router>,
    detector: Arc<InjectionDetector>,
    dispatcher: Arc<OutboundDispatcher>,
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

    let (adapter_id, pub_key) =
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

    let pubkey_fingerprint = adapter_pubkey_fingerprint(&pub_key);

    audit
        .log(
            AuditEvent::new(
                ActorKind::Service,
                "gateway",
                "adapter.connect",
                &adapter_id,
            )
            .with_channel(authenticated_channel.as_str())
            .with_detail(serde_json::json!({
                "adapter_pubkey_fingerprint": pubkey_fingerprint,
            })),
        )
        .await?;

    let writer = Arc::new(Mutex::new(writer));

    // Register the live writer with the orchestrator-push
    // dispatcher so zirkel's daily digest (and any other
    // orchestrator) can find this adapter by channel name.
    dispatcher.register(authenticated_channel.as_str(), writer.clone());

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

    dispatcher.unregister(authenticated_channel.as_str());
    registry.lock().await.set_connected(&adapter_id, false);
    audit
        .log(
            AuditEvent::new(
                ActorKind::Service,
                "gateway",
                "adapter.disconnect",
                &adapter_id,
            )
            .with_channel(authenticated_channel.as_str())
            .with_detail(serde_json::json!({
                "adapter_pubkey_fingerprint": pubkey_fingerprint,
            })),
        )
        .await?;

    tracing::info!("Adapter '{adapter_id}' disconnected");
    result
}

/// Handle one orchestrator-push connection: read one JSON request,
/// look up the live adapter writer for the requested channel,
/// forward as a capnp Outbound frame, write one JSON response.
///
/// This handler runs only after `peer_cred()` has confirmed the
/// peer UID matches the gateway's. No further authentication.
#[cfg(unix)]
async fn handle_orchestrator_push(
    stream: UnixStream,
    dispatcher: Arc<OutboundDispatcher>,
    audit: Arc<AuditWriter>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let (reader, mut writer) = stream.into_split();
    let mut br = BufReader::new(reader);
    let mut line = String::new();
    let n = br
        .read_line(&mut line)
        .await
        .context("orchestrator: read request")?;
    if n == 0 {
        return Ok(());
    }
    let req: OrchestratorPushRequest = match serde_json::from_str(line.trim_end()) {
        Ok(r) => r,
        Err(e) => {
            let resp = OrchestratorPushResponse {
                ok: false,
                error: Some(format!("invalid request JSON: {e}")),
            };
            let _ = write_orchestrator_response(&mut writer, &resp).await;
            return Ok(());
        }
    };

    let resp = match dispatcher.writer_for(&req.channel) {
        Some(w) => {
            let mut reply = capnp::message::Builder::new_default();
            {
                let fb = reply.init_root::<frame::Builder<'_>>();
                let mut outbound = fb.init_outbound();
                outbound.set_conversation_id(&req.conversation_id);
                outbound.set_text(&req.text);
                outbound.set_reply_to_id(&req.reply_to_id);
                outbound.set_metadata("{}");
            }
            let mut w = w.lock().await;
            match w.write_message(&reply).await {
                Ok(()) => {
                    let outbound_target = format!("{}:out:{}", req.channel, uuid::Uuid::new_v4());
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                ActorKind::Service,
                                "orchestrator",
                                "message.outbound",
                                &outbound_target,
                            )
                            .with_channel(&req.channel)
                            .with_session(&req.conversation_id)
                            .with_detail(serde_json::json!({ "content": &req.text })),
                        )
                        .await;
                    OrchestratorPushResponse {
                        ok: true,
                        error: None,
                    }
                }
                Err(e) => OrchestratorPushResponse {
                    ok: false,
                    error: Some(format!("write to adapter failed: {e}")),
                },
            }
        }
        None => OrchestratorPushResponse {
            ok: false,
            error: Some(format!("no adapter connected on channel '{}'", req.channel)),
        },
    };

    write_orchestrator_response(&mut writer, &resp).await?;
    Ok(())
}

#[cfg(unix)]
async fn write_orchestrator_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &OrchestratorPushResponse,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut line = serde_json::to_string(resp).context("serialize push response")?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .context("write push response")?;
    writer.shutdown().await.ok();
    Ok(())
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
    reader: &mut IpcFrameReader,
    writer: Arc<Mutex<IpcFrameWriter>>,
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
                    // Carry the inbound's reply_to_id (Slack's
                    // thread_ts; Telegram's reply_to_message_id; etc.)
                    // through to the outbound construction below so
                    // the bot's reply lands in the same thread as the
                    // inbound when one was specified, and at the
                    // channel root otherwise. Empty string means "no
                    // thread / no reply target" — explicitly NOT the
                    // inbound's own message id, which would auto-
                    // thread every root message.
                    let reply_to_id = m
                        .get_reply_to_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("reply_to_id not utf8: {e}"))?
                        .to_string();

                    InboundAction::Message {
                        id: msg_id,
                        text,
                        sender_id,
                        sender_name,
                        channel,
                        conversation_id,
                        reply_to_id,
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
                reply_to_id,
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
                                ActorKind::Service,
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

                // Audit inbound. `target` carries the stable resource
                // id `<channel>:<platform-msg-id>`; the message body
                // lives under `detail.content` so downstream consumers
                // can correlate without parsing a free-text field.
                let inbound_target = format!("{channel}:{id}");
                let mut inbound_detail = serde_json::json!({ "content": &text });

                // Scan for prompt injection patterns
                let threat_detail = detector.scan(&text).map(|threat| threat.to_detail_json());
                if let Some(ref threat) = threat_detail {
                    if let (Some(obj), Some(threat_obj)) =
                        (inbound_detail.as_object_mut(), threat.as_object())
                    {
                        for (k, v) in threat_obj {
                            obj.insert(k.clone(), v.clone());
                        }
                    }
                }

                let inbound_event = AuditEvent::new(
                    ActorKind::User,
                    &sender_id,
                    "message.inbound",
                    &inbound_target,
                )
                .with_channel(&channel)
                .with_session(&conversation_id)
                .with_detail(inbound_detail.clone());

                if threat_detail.is_some() {
                    // Emit a separate threat event for SIEM visibility
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                ActorKind::User,
                                &sender_id,
                                "message.threat_flagged",
                                &inbound_target,
                            )
                            .with_channel(&channel)
                            .with_session(&conversation_id)
                            .with_detail(inbound_detail),
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

                let inbound_ctx = wirken_agent::InboundContext {
                    adapter_id: Some(adapter_id.to_string()),
                    sender_id: Some(sender_id.clone()),
                };
                let (response, denials) = match factory.wake(&resolved_agent, &session_id) {
                    Ok(agent_mutex) => {
                        let mut ag = agent_mutex.lock().await;
                        match ag.process_inbound(&text, id.clone(), inbound_ctx).await {
                            Ok(result) => (result.response, result.denials),
                            Err(e) => {
                                // The full error stays in operator logs
                                // and the audit trail. The outbound
                                // reply is a generic apology — raw
                                // error strings can leak operator-side
                                // internals (database paths, session
                                // log locks, provider stack traces)
                                // to an allowlisted contact over
                                // whatever channel they reached us on.
                                tracing::error!("Agent '{resolved_agent}' error: {e}");
                                (
                                    "Sorry, I hit an internal error and could not process \
                                     that message. The operator has been notified."
                                        .into(),
                                    Vec::new(),
                                )
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
                        "action": denial.action.to_string(),
                        "action_key": denial.action.approval_key(),
                        "requested_tier": denial.requested_tier.label(),
                        "agent_id": denial.agent_id,
                        "trigger_message": denial.trigger_message,
                    });
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                ActorKind::User,
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

                // Audit outbound. No platform-assigned id at emit time
                // (the adapter assigns one on send and returns it via
                // `OutboundResult`); synthesize a per-event id so the
                // `target` field stays a stable resource handle and the
                // body lives under `detail.content`.
                let outbound_target = format!("{channel}:out:{}", uuid::Uuid::new_v4());
                audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Agent,
                            &agent_id,
                            "message.outbound",
                            &outbound_target,
                        )
                        .with_channel(&channel)
                        .with_session(&conversation_id)
                        .with_detail(serde_json::json!({ "content": &response })),
                    )
                    .await?;

                // Send response back to adapter. `reply_to_id`
                // carries the inbound's thread root (Slack's
                // thread_ts, Telegram's reply_to_message_id, etc.) —
                // not the inbound's own message id. Setting it to
                // the inbound's id would auto-thread every root
                // message; passing the inbound's reply_to_id
                // through preserves the conversation thread when
                // one existed and leaves the reply at the channel
                // root otherwise.
                let mut reply = capnp::message::Builder::new_default();
                {
                    let fb = reply.init_root::<frame::Builder<'_>>();
                    let mut outbound = fb.init_outbound();
                    outbound.set_conversation_id(&conversation_id);
                    outbound.set_text(&response);
                    outbound.set_reply_to_id(&reply_to_id);
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
        /// Thread root carried from the inbound (Slack thread_ts,
        /// Telegram reply_to_message_id, …). Empty string means the
        /// inbound was at the channel root; the bot's reply must
        /// also go to the channel root in that case, not auto-thread
        /// off the inbound's own message id.
        reply_to_id: String,
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
        return s.to_string();
    }
    // `max` is a byte budget. Slicing bytes mid-char panics on any
    // multi-byte scalar (Devanagari, emoji, CJK, etc.), so walk back
    // to the nearest char boundary. `is_char_boundary(0)` is always
    // true so the loop terminates.
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &s[..cut])
}

/// Width budget for the MCP startup-inventory command paths. Long
/// paths get a leading ellipsis so the trailing binary name stays
/// visible; the on-disk `mcp.json` is canonical.
const MCP_INVENTORY_WIDTH: usize = 80;

fn trim_command_for_inventory(cmd: &str) -> String {
    if cmd.chars().count() <= MCP_INVENTORY_WIDTH {
        return cmd.to_string();
    }
    let mut acc = String::with_capacity(MCP_INVENTORY_WIDTH + 3);
    acc.push_str("...");
    let take = MCP_INVENTORY_WIDTH.saturating_sub(3);
    let suffix: String = cmd
        .chars()
        .rev()
        .take(take)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    acc.push_str(&suffix);
    acc
}

#[cfg(test)]
mod inventory_tests {
    use super::{MCP_INVENTORY_WIDTH, trim_command_for_inventory};

    #[test]
    fn short_command_passes_through() {
        let cmd = "/usr/bin/uvx";
        assert_eq!(trim_command_for_inventory(cmd), cmd);
    }

    #[test]
    fn boundary_command_passes_through() {
        let cmd = "x".repeat(MCP_INVENTORY_WIDTH);
        assert_eq!(trim_command_for_inventory(&cmd), cmd);
    }

    #[test]
    fn long_command_keeps_tail() {
        let cmd = format!("/{}", "x".repeat(200));
        let trimmed = trim_command_for_inventory(&cmd);
        assert!(trimmed.starts_with("..."));
        assert!(trimmed.chars().count() <= MCP_INVENTORY_WIDTH);
        assert!(trimmed.ends_with(&"x".repeat(20)));
    }

    #[test]
    fn multibyte_long_command_does_not_panic() {
        let cmd = "ä".repeat(200);
        let trimmed = trim_command_for_inventory(&cmd);
        assert!(trimmed.starts_with("..."));
        assert!(trimmed.chars().count() <= MCP_INVENTORY_WIDTH);
    }
}

/// Load SIEM forwarding config from ~/.wirken/siem.json.
/// Returns None if the file doesn't exist (SIEM forwarding disabled).
///
/// Example siem.json (Datadog):
/// ```json
/// {
///     "target": "datadog",
///     "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
///     "api_key": "your-dd-api-key",
///     "service": "wirken",
///     "environment": "production"
/// }
/// ```
///
/// Example siem.json (Microsoft Sentinel via Logs Ingestion API):
/// ```json
/// {
///     "target": "sentinel",
///     "endpoint": "https://<dce>.<region>.ingest.monitor.azure.com/dataCollectionRules/<dcr-id>/streams/Custom-WirkenAudit?api-version=2023-01-01",
///     "api_key": "<azure-ad-bearer-token>",
///     "service": "wirken",
///     "environment": "production"
/// }
/// ```
/// Sentinel tokens expire (typically 1 hour); refresh by rewriting
/// this file from a sidecar before expiry. Wirken does not manage
/// Azure AD token lifecycle.
/// First 16 hex chars of the org-config trust anchor at
/// `<data_dir>/org-config-pubkey.pub`. Returned as `None` when the
/// file is absent (the operator opted into unsigned mode). Used as a
/// short identifier in the `org-config.applying` audit row so a
/// reviewer can correlate a refresh against which trust anchor was
/// in effect at the time without having to read the whole file.
fn org_pubkey_fingerprint(data_dir: &std::path::Path) -> Option<String> {
    let path = data_dir.join(wirken_gateway::org::ORG_CONFIG_PUBKEY_FILE);
    let body = std::fs::read_to_string(&path).ok()?;
    let trimmed = body.trim();
    let fp: String = trimmed.chars().take(16).collect();
    if fp.is_empty() { None } else { Some(fp) }
}

/// Short hex fingerprint over a 32-byte adapter pubkey for audit
/// correlation. Same first-16-hex-chars convention as
/// `org_pubkey_fingerprint`; long enough to dedupe in practice,
/// short enough to stay legible on the audit line.
fn adapter_pubkey_fingerprint(pubkey: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for b in pubkey.iter().take(8) {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

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
        "sentinel" => SiemTarget::Sentinel,
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
    let hmac_secret = json
        .get("hmac_secret")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    println!("  SIEM: forwarding to {target_str} at {endpoint}");

    Some(SiemConfig {
        target,
        endpoint,
        api_key,
        service,
        environment,
        hmac_secret,
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

#[cfg(test)]
mod truncate_tests {
    use super::truncate;

    #[test]
    fn short_input_returned_verbatim() {
        assert_eq!(truncate("hi", 80), "hi");
    }

    #[test]
    fn ascii_truncation_at_exact_byte_offset() {
        let s = "a".repeat(200);
        let t = truncate(&s, 80);
        assert_eq!(t, format!("{}...", "a".repeat(80)));
    }

    #[test]
    fn devanagari_input_does_not_panic_at_byte_80() {
        // Regression: this input was captured from an LLM reply that
        // crashed the gateway at `&s[..80]` because byte 80 fell
        // inside a multi-byte Devanagari scalar. The fix walks back
        // to the nearest char boundary.
        let s = "**अब की धड़कन, कविता की झलक**\n\nअब का क्षण, हवाओं में बँधा,\nहर लफ़्ज़ में गूंजे अनकहा।";
        let t = truncate(s, 80);
        assert!(t.ends_with("..."));
        // Safe sanity: the cut prefix must be valid UTF-8 (it already
        // is by construction, but the assertion guards against future
        // refactors that reintroduce raw-byte slicing).
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }

    #[test]
    fn emoji_input_does_not_panic() {
        // 4-byte scalars stress the walk-back loop harder than
        // 3-byte Devanagari because the boundary search has to go
        // back up to 3 bytes.
        let s = "🦀".repeat(40);
        let t = truncate(&s, 50);
        assert!(t.ends_with("..."));
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }
}
