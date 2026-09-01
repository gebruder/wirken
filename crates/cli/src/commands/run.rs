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
use wirken_audit::{ActorKind, AlarmLog, AuditEvent, AuditWriter, SiemConfig, SiemTarget};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::injection_detect::InjectionDetector;
use wirken_gateway::outbound_dispatcher::OutboundDispatcher;
use wirken_gateway::router::{RouteBinding, Router};
use wirken_gateway::session::SessionStore;
// Only `handle_orchestrator_push` uses these, and it is unix-only.
#[cfg(unix)]
use wirken_ipc::orchestrator::{OrchestratorPushRequest, OrchestratorPushResponse};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AuthenticatedChannel, perform_gateway_handshake};
// `Principal` wraps `geteuid` and `Stream` is the trait carrying
// `peer_principal`; both are reached only from the unix
// peer-credential accept paths.
use wirken_ipc::{IpcFrameReader, IpcFrameWriter, split_stream};
#[cfg(unix)]
use wirken_ipc::{Principal, Stream};
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

/// Host-side `http_request` credential resolver backed by the vault.
/// The `CredentialStore` (rusqlite, `!Sync`) is wrapped in a `Mutex` so
/// the resolver is `Send + Sync`. `resolve` returns only a
/// `ResolvedSecret`; the plaintext never crosses back into logs, tool
/// results, or model context.
struct VaultCredentialResolver {
    store: std::sync::Mutex<CredentialStore>,
}

impl wirken_agent::http_tool::CredentialResolver for VaultCredentialResolver {
    fn resolve(
        &self,
        name: &str,
        host: &str,
    ) -> Result<wirken_agent::http_tool::ResolvedSecret, wirken_agent::http_tool::CredentialError>
    {
        use wirken_agent::http_tool::{CredentialError, ResolvedSecret};
        let store = self
            .store
            .lock()
            .map_err(|_| CredentialError::Backend("vault mutex poisoned".into()))?;

        // Check the credential's host binding via `peek` first, so a
        // refused attempt does not bump `last_used_at`. The binding is
        // operator-set vault metadata; a skill cannot widen it.
        let meta = match store.peek(name) {
            Ok((_, meta)) => meta,
            Err(wirken_vault::VaultError::NotFound(_)) => {
                return Err(CredentialError::NotFound(name.to_string()));
            }
            Err(e) => return Err(CredentialError::Backend(e.to_string())),
        };
        if !meta.permits_host(host) {
            return Err(CredentialError::HostNotPermitted {
                name: name.to_string(),
                host: host.to_string(),
            });
        }

        match store.retrieve(name) {
            Ok((secret, _)) => Ok(ResolvedSecret::new(secret.expose().to_string())),
            Err(wirken_vault::VaultError::NotFound(_)) => {
                Err(CredentialError::NotFound(name.to_string()))
            }
            // VaultError never carries the secret value, only names/kinds.
            Err(e) => Err(CredentialError::Backend(e.to_string())),
        }
    }
}

/// Prompt once for the vault passphrase, caching it for the rest of
/// this boot.
///
/// Passed as the `probe_keychain` supplier. On OS-keychain backends
/// (macOS Keychain, Linux Secret Service) `probe_keychain` reads the
/// device key directly and never calls this, so no prompt appears and
/// `cache` stays `None`. On the age-file backend the first probe that
/// needs the device key prompts once; later probes reuse the cache.
///
/// Every keychain probe in `run` must go through this. An empty
/// supplier (`String::new`) cannot unwrap a device key wrapped under a
/// real passphrase on the age-file backend, so any subsystem that
/// probed with one silently degraded — the alarm log to unsigned mode,
/// the `http_request` resolver to refusing credentialed calls.
fn prompt_vault_passphrase(cache: &mut Option<String>) -> String {
    if let Some(existing) = cache {
        return existing.clone();
    }
    let pp = dialoguer::Password::new()
        .with_prompt("  Vault passphrase")
        .interact()
        .unwrap_or_default();
    *cache = Some(pp.clone());
    pp
}

/// Run the gateway daemon.
pub async fn run(port: Option<u16>) -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs()?;

    println!();
    println!("  wirken v{}", env!("CARGO_PKG_VERSION"));
    println!("  ──────");
    println!();

    // --- Boot-time refusal on unacknowledged alarm records ---
    //
    // Tamper records from a prior session that halted at
    // MAX_INTEGRITY_FAILURES sit in `audit-alarms.log`. Refuse to
    // start until an operator acknowledges them via
    // `wirken audit acknowledge --all`. The allowlist of
    // proceed-class alarm types is intentionally small (see
    // `wirken_audit::ACKNOWLEDGE_PROCEED_TYPES`); refuse-by-default
    // is the posture for any unrecognised record.
    {
        let alarm_log = AlarmLog::new(&cfg.data_dir);
        if let Some(report) = alarm_log
            .unacknowledged_blocks()
            .context("scan audit-alarms.log for unacknowledged tamper records")?
        {
            eprintln!(
                "  Refusing to start: {} unacknowledged alarm record(s) in {}",
                report.total,
                report.path.display()
            );
            for (alarm_type, count) in &report.blocking_by_type {
                eprintln!("    {alarm_type}: {count}");
            }
            eprintln!();
            eprintln!(
                "  These records describe audit-chain integrity events from a prior session."
            );
            eprintln!("  Review the log, then run `wirken audit acknowledge --all` to archive it");
            eprintln!("  to a timestamped sibling file and unblock the next gateway start.");
            std::process::exit(1);
        }
    }

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
    // Vault passphrase, prompted once and cached across every keychain
    // probe in this boot (alarm-log key, provider key, adapters,
    // http_request resolver). `None` until the first age-file probe
    // needs it; on OS-keychain backends it stays `None` and no prompt
    // appears. See `prompt_vault_passphrase`.
    let mut vault_passphrase: Option<String> = None;

    let alarm_log_key = {
        let kc = probe_keychain(&cfg.data_dir, || {
            prompt_vault_passphrase(&mut vault_passphrase)
        });
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
        siem_config.clone(),
        alarm_log_key,
        audit_signer.clone(),
    )
    .context("Failed to start audit writer")?;
    let audit = Arc::new(audit_writer);

    // Typed-event SIEM forwarder (hybrid path). Reads
    // session_events via `get_since`; never writes, so the audit
    // chain stays intact. Spawned only when typed forwarding is
    // wired (config has either a custom include/exclude list or, for
    // Sentinel, a `sentinel_typed` endpoint). Otherwise no overhead.
    let typed_siem_handle = maybe_spawn_typed_siem(&cfg, siem_config.as_ref()).await;

    audit
        .log(AuditEvent::new(
            ActorKind::Service,
            "gateway",
            "gateway.start",
            "daemon",
        ))
        .await?;
    // Step 6 of `wirken setup` now surfaces the audit DB path with
    // its full trust-claim framing (append-only, SHA-256 hash chain,
    // Ed25519 chain-head signed). Re-printing the bare path on every
    // `wirken run` was noise. Operators who need the path consult
    // `wirken doctor` or know where it lives.

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
    // Slot name the api_key was resolved from. Stamped on every
    // `LlmRequest`/`LlmResponse` for SIEM correlation. `None` for
    // ollama (no vault lookup) and for the failure paths below where
    // the key didn't resolve.
    let mut api_key_credential: Option<String> = None;
    let api_key = if provider != "ollama" {
        let keychain = probe_keychain(&cfg.data_dir, || {
            prompt_vault_passphrase(&mut vault_passphrase)
        });
        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;
        let cred_name = format!("{provider}-api-key");
        match store.retrieve(&cred_name) {
            Ok((secret, _)) => {
                api_key_credential = Some(cred_name.clone());
                Some(secret.expose().to_string())
            }
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
    if vault_passphrase.is_none() {
        let has_adapters = {
            let reg_path = cfg.adapters_db_path();
            reg_path.exists()
                && AdapterRegistry::open(&reg_path)
                    .map(|r| !r.list().is_empty())
                    .unwrap_or(false)
        };
        if has_adapters {
            let _ = probe_keychain(&cfg.data_dir, || {
                prompt_vault_passphrase(&mut vault_passphrase)
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
            // Happy path: shell is detected and exec will work.
            // Useful when debugging skill compatibility, noise on
            // every boot. Hidden by default under wirken=warn;
            // `RUST_LOG=wirken=info` opts back in.
            tracing::info!(
                "Host exec shell: {} ({})",
                resolved.kind,
                resolved.program.display()
            );
        }
        None => {
            // Operator-actionable: shell-exec skills will refuse
            // until a shell is configured. Stays visible.
            tracing::warn!(
                "Host exec shell: none found ({:?}); the exec tool will refuse to run on this host",
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
            prompt_vault_passphrase(&mut vault_passphrase)
        });
        let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()).ok();

        for agent_cfg in agent_store.list()? {
            // Resolve API key from vault. Track the vault slot name so
            // it can land on every `LlmRequest` / `LlmResponse` for
            // SIEM correlation. `None` when the agent config doesn't
            // name a slot (the api_key was supplied some other way or
            // is absent).
            let agent_api_key_credential = if agent_cfg.api_key_credential.is_empty() {
                None
            } else {
                Some(agent_cfg.api_key_credential.clone())
            };
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

            // Persona-bundling slice 3: merge preset skills into the
            // static config. A dangling reference or load failure
            // hard-fails daemon startup so a misconfigured persona
            // cannot silently route channel traffic to an agent with
            // no skills. The operator sees the same message
            // `wirken ask` would print and applies one of the two
            // recovery hints before the daemon will start.
            let presets_dir = cfg.data_dir.join("presets");
            let preset_skills = super::persona::resolve_for_construction(&agent_cfg, &presets_dir)?;
            skills.extend(preset_skills);

            // Bind channels to this agent
            for channel in &agent_cfg.channels {
                router.bind(RouteBinding {
                    channel: channel.clone(),
                    conversation_pattern: "*".into(),
                    agent_id: agent_cfg.id.clone(),
                });
                println!(
                    "  Route: {} -> agent:{} ({}/{})",
                    super::channel::display_name(channel.as_str()),
                    agent_cfg.id,
                    agent_cfg.provider,
                    agent_cfg.model
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
                    api_key_credential: agent_api_key_credential,
                    skills,
                    wasm_skills: Vec::new(),
                    mcp_client: None, // populated below after the proxy starts
                    identity,
                    allowed_subagents: agent_cfg.allowed_subagents.clone(),
                    sandbox: super::load_sandbox_config(&cfg.data_dir),
                    channel_egress: agent_cfg.channel_egress.clone(),
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
            vault_passphrase.as_deref().unwrap_or(""),
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
                println!(
                    "  Route: {} -> agent:default",
                    super::channel::display_name(&adapter.channel)
                );
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
                api_key_credential,
                skills,
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: default_identity,
                allowed_subagents: Default::default(),
                sandbox: super::load_sandbox_config(&cfg.data_dir),
                // The implicit "default" agent has no registered
                // AgentConfig row to carry a policy, so it gets none:
                // sandboxed exec runs with no networking. Granting
                // egress requires registering an agent and
                // configuring the channel.
                channel_egress: Default::default(),
                extra_interceptors: vec![],
                zirkel_db_path: None,
            },
        );
    }

    // Single-agent boot is the modal case ("Agents: default" tells the
    // user nothing). Surface the list on stdout only when more than one
    // agent is configured; log it under tracing::info either way so
    // `RUST_LOG=info wirken run` still shows the inventory.
    let agent_list = static_configs
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!("Agents: {agent_list}");
    if static_configs.len() > 1 {
        println!("  Agents: {agent_list}");
    }

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
    // Implementation detail: the IPC socket path. Useful for debugging
    // adapter handshake or a stuck socket file, not for an operator
    // confirming wirken started. `RUST_LOG=info wirken run` surfaces it.
    tracing::info!("IPC socket: {}", socket_path.display());

    // --- Setup hooks IPC listener (parallel to adapter socket) ---
    //
    // External hook processes (observe + veto) connect inbound on
    // this separate listener so the adapter and hook acceptors do
    // not share a dispatch ambiguity at the wire layer. Same 0o600
    // posture, same peer-credential gate at accept time.
    let hooks_socket_path = cfg.socket_dir().join("gateway-hooks.sock");
    if hooks_socket_path.exists() {
        std::fs::remove_file(&hooks_socket_path)?;
    }
    let mut hooks_listener = wirken_ipc::bind(&hooks_socket_path).context(format!(
        "Failed to bind hooks IPC at {}",
        hooks_socket_path.display()
    ))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hooks_socket_path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to chmod hooks socket to 0600")?;
    }
    tracing::info!("Hooks IPC socket: {}", hooks_socket_path.display());

    // --- Setup permissions IPC listener (operator decisions) ---
    //
    // `wirken permissions pending {list,show,approve,deny}` invocations
    // connect here, exchange one line-delimited JSON request and
    // response (matching the orchestrator-push precedent), and
    // disconnect. Trust model: SO_PEERCRED + 0o600 file perms. Same
    // UID is the only gate; the operator-tool process is not
    // crossing a trust boundary.
    #[cfg(unix)]
    let permissions_socket_path = cfg.socket_dir().join("gateway-permissions.sock");
    #[cfg(unix)]
    {
        if permissions_socket_path.exists() {
            let _ = std::fs::remove_file(&permissions_socket_path);
        }
    }
    #[cfg(unix)]
    let permissions_listener = UnixListener::bind(&permissions_socket_path).context(format!(
        "Failed to bind permissions IPC at {}",
        permissions_socket_path.display()
    ))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &permissions_socket_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .context("Failed to chmod permissions socket to 0600")?;
    }
    #[cfg(unix)]
    tracing::info!(
        "Permissions IPC socket: {}",
        permissions_socket_path.display()
    );

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
        let keychain = probe_keychain(&cfg.data_dir, || {
            prompt_vault_passphrase(&mut vault_passphrase)
        });
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
        let vp = vault_passphrase.clone().unwrap_or_default();

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
        let vp = vault_passphrase.clone().unwrap_or_default();
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
    let org_tool_policy = wirken_gateway::org::load_tool_policy(&cfg.data_dir)
        .map_err(anyhow::Error::msg)?
        .map(std::sync::Arc::new);
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

    // --- Hook registry + dispatcher ---
    //
    // Open the SQLite-backed hook registry the operator populated
    // via `wirken hooks register`. Construct the veto-hook
    // dispatcher and attach it to the factory so every Agent woken
    // hereafter routes its tool-call dispatch through the active
    // veto set. The registry is consulted at handshake time only;
    // the dispatcher owns the in-process active set populated by
    // the hooks accept loop below.
    let hook_registry = Arc::new(Mutex::new(
        wirken_gateway::hook_registry::HookRegistry::open(&cfg.data_dir.join("hooks.db"))
            .context("Failed to open hook registry")?,
    ));
    let hook_dispatcher = Arc::new(wirken_gateway::hook_dispatcher::HookDispatcher::default());
    factory.attach_veto_dispatcher(hook_dispatcher.clone());
    let egress_dispatcher =
        Arc::new(wirken_gateway::egress_dispatcher::EgressDispatcher::default());
    factory.attach_egress_dispatcher(egress_dispatcher.clone());

    // --- cross-channel memory (#64) ---
    // Opening the store is what makes the memory tools available at
    // all. If it cannot be opened the gateway still starts; the tools
    // report themselves unconfigured rather than the process failing
    // over a feature the operator may not use.
    match wirken_gateway::memory::MemoryStore::open(&cfg.memory_db_path()) {
        Ok(store) => factory.attach_memory_store(Arc::new(std::sync::Mutex::new(store))),
        Err(e) => tracing::warn!(
            "cross-channel memory unavailable: could not open {}: {e}",
            cfg.memory_db_path().display()
        ),
    }

    // --- Imported archives ---
    //
    // Opened here rather than lazily in the agent so a store that
    // cannot be opened is one warning at start rather than a failure
    // inside a gated tool call. An unopened store leaves the imported
    // tools reporting themselves unconfigured, which reads nothing.
    match wirken_gateway::imported::ImportStore::open(&cfg.imported_db_path()) {
        Ok((store, _applied)) => {
            factory.attach_imported_store(Arc::new(std::sync::Mutex::new(store)))
        }
        Err(e) => tracing::warn!(
            "imported archives unavailable: could not open {}: {e}",
            cfg.imported_db_path().display()
        ),
    }

    // The key imported-search audit rows digest their query under. Its
    // own key, never the alarm-log one, which exists to be handed to a
    // reviewer. Without it the digest is left off the row rather than
    // written unkeyed, since an unkeyed digest of a short query is
    // recoverable by anyone holding the rows.
    {
        let keychain = probe_keychain(&cfg.data_dir, String::new);
        match wirken_vault::load_or_create_imported_search_key(keychain.as_ref()) {
            Ok(key) => factory.attach_imported_search_key(key),
            Err(e) => {
                // Deliberate degrade, not a refusal. The Tier 3 gate is
                // the enforcement boundary for reaching a corpus and it
                // still runs; the row still records that a search
                // happened, by whom, over which source, and with what
                // outcome. What is lost is the ability to prove which
                // term was searched. Refusing instead would make a
                // locked vault a denial of the operator's own
                // archives, trading a large functional loss for a
                // smaller forensic one.
                //
                // The degrade goes on the chain rather than only into
                // stderr. `query_digest: None` on a search row is
                // otherwise ambiguous -- no key, or a build that never
                // wrote one -- and a reviewer holding only the rows
                // cannot tell which. This event dates the window.
                tracing::warn!("imported-search audit rows will carry no query digest: {e}");
                let _ = audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Service,
                            "gateway",
                            "imported-search.digest-unavailable",
                            cfg.data_dir.display().to_string(),
                        )
                        .with_detail(serde_json::json!({
                            "reason": e.to_string(),
                            "consequence":
                                "search proceeds; ImportedChatSearched rows carry no \
                                 query_digest until the vault is unlocked and the gateway \
                                 restarted",
                        })),
                    )
                    .await;
            }
        }
    }

    // --- http_request credential resolver ---
    //
    // Open the vault as a long-lived resolver so the `http_request`
    // tool can attach an operator-provisioned credential host-side.
    // Non-interactive keychain probe: if the vault is unavailable the
    // tool refuses credentialed calls rather than blocking startup.
    match CredentialStore::open(
        &cfg.vault_db_path(),
        probe_keychain(&cfg.data_dir, || {
            prompt_vault_passphrase(&mut vault_passphrase)
        })
        .as_ref(),
    ) {
        Ok(store) => factory.attach_credential_resolver(Arc::new(VaultCredentialResolver {
            store: std::sync::Mutex::new(store),
        })),
        Err(e) => tracing::warn!(
            vault = %cfg.vault_db_path().display(),
            "http_request credential resolver disabled (vault unavailable): {e}"
        ),
    }

    // --- Budget enforcement ---
    //
    // Load the budget config first so the store-open failure handling
    // knows whether a block-mode budget is configured. A present-but-
    // malformed budget.json is a hard startup error (fail closed): an
    // operator must not be able to typo a block ceiling into silence.
    let budget_config = wirken_gateway::budget::load_budget_config(&cfg.budget_config_path())
        .context("load budget.json")?;
    match wirken_gateway::budget::BudgetStore::open(&cfg.budget_db_path()) {
        Ok(store) => {
            factory.attach_budget(Arc::new(std::sync::Mutex::new(store)), budget_config);
        }
        Err(e) if budget_config.has_block_mode() => {
            // Fail closed: a block-mode budget is configured but its
            // ledger cannot be opened. Refuse to start so a wedged
            // budget.db never silently converts block into off.
            anyhow::bail!(
                "budget.db could not be opened but a block-mode budget is configured in \
                 budget.json; refusing to start so enforcement is never silently disabled: {e}"
            );
        }
        Err(e) => {
            // Alert-only (or inactive) config. Record the control going
            // offline on the audit chain, not just stderr, so a SIEM or
            // dashboard sees that enforcement is down, then continue.
            if budget_config.has_active() {
                let _ = audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Service,
                            "gateway",
                            "budget.control_offline",
                            "budget.db",
                        )
                        .with_detail(serde_json::json!({
                            "reason": "budget_db_open_failed",
                            "error": e.to_string(),
                        })),
                    )
                    .await;
            }
            tracing::warn!(
                budget_db = %cfg.budget_db_path().display(),
                "budget enforcement disabled (spend store unavailable): {e}"
            );
        }
    }

    // --- Pending-approval queue + CLI approval gate ---
    //
    // Out-of-band approval for daemon-mode agents. The queue holds
    // pending `NeedsApproval` requests; `wirken permissions pending
    // {list,show,approve,deny}` invocations connect to
    // `gateway-permissions.sock` and resolve them. The CliApprovalGate
    // becomes the factory's default approval gate so every Agent the
    // factory wakes (channel-driven sessions, cron jobs, webchat)
    // routes its `NeedsApproval` short-circuits through this queue.
    //
    // Behavior change vs the prior slice: pre-this-slice, a
    // daemon-mode agent that hit `NeedsApproval` failed terminally.
    // Now it queues for `WIRKEN_CLI_APPROVAL_TIMEOUT_S` (default 300s)
    // waiting for an operator decision via `wirken permissions
    // pending approve <key>`. Past the timeout the call fails
    // closed. `wirken ask` continues to attach its own
    // `StdinApprovalGate` per-agent which takes precedence over
    // this default.
    let pending_approval_queue =
        Arc::new(wirken_gateway::pending_approvals::PendingApprovalQueue::new());
    factory.attach_default_approval_gate(Arc::new(
        wirken_agent::cli_approval_gate::CliApprovalGate::new(pending_approval_queue.clone()),
    ));
    tracing::info!(
        timeout_s = wirken_gateway::pending_approvals::resolve_cli_timeout().as_secs(),
        "permissions IPC: daemon-mode NeedsApproval requests queue for operator decision \
         via `wirken permissions pending approve <key>`",
    );

    // --- Approver registry ---
    //
    // The registry holds the operator allowlist
    // (`approver_registry` table, keyed by `(adapter_id, user_id)`)
    // plus the approval-chat configuration
    // (`adapter_approval_conversations` table). The CLI
    // subcommand `wirken approvers` writes both directly to
    // SQLite; the registry's in-memory cache is loaded on next
    // gateway start. The channel-adapter approval gates
    // (`TelegramApprovalGate`, `SignalApprovalGate`) are
    // constructed below where the `OutboundDispatcher` is
    // available; the registry is plumbed through.
    let approver_registry = Arc::new(
        wirken_gateway::approver_registry::ApproverRegistry::open(
            &cfg.data_dir.join("approvers.db"),
        )
        .context("Failed to open approver registry")?,
    );

    // Startup warn for any registered channel-approval adapter
    // (Telegram, Signal, …) without an approval conversation
    // configured. The adapter is in a degraded-but-not-failed
    // state: NeedsApproval requests on this adapter's sessions
    // will fail-closed at the gate's preflight. Warn-level is the
    // honest severity.
    {
        let known_adapters = registry.lock().await.list();
        for entry in &known_adapters {
            let needs_conversation = matches!(entry.channel.as_str(), "telegram" | "signal");
            if needs_conversation
                && approver_registry
                    .approval_conversation(&entry.adapter_id)
                    .is_none()
            {
                tracing::warn!(
                    adapter_id = %entry.adapter_id,
                    channel = %entry.channel,
                    "{} adapter has no approval conversation configured; \
                     NeedsApproval requests on this adapter's sessions will fail-closed. \
                     Run `wirken approvers set-chat {} <conversation_id>` to enable.",
                    entry.channel,
                    entry.adapter_id,
                );
            }
        }
    }

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

    // SSE approval gate. The per-process registry tracks live
    // /api/chat senders so the gate can push ApprovalRequest
    // events to the in-flight stream when an agent hits
    // NeedsApproval mid-tool-dispatch. The gate routes
    // webchat-channel sessions (`{agent}/webchat/{conv}`); other
    // sessions fall back to the default CLI gate.
    let sse_approval_registry =
        Arc::new(wirken_gateway::sse_approval_registry::SseApprovalRegistry::new());
    factory.attach_sse_approval_gate(Arc::new(
        wirken_agent::sse_approval_gate::SseApprovalGate::new(
            pending_approval_queue.clone(),
            sse_approval_registry.clone(),
        ),
    ));
    let webchat_pending = pending_approval_queue.clone();
    let webchat_registry = sse_approval_registry.clone();
    let webchat_handle = tokio::spawn(async move {
        if let Err(e) = super::webchat::serve(
            webchat_port,
            webchat_factory,
            webchat_audit,
            webchat_sessions,
            webchat_pending,
            webchat_registry,
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
    println!("  Wirken running. Press Ctrl+C to stop.");
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

    // Channel-adapter approval gate. Sessions whose id parses with
    // channel `"telegram"` route through `TelegramApprovalGate`;
    // other sessions fall back to the default CLI gate. The
    // factory's `approval_gate_for(session_id)` does the routing
    // at wake time.
    factory.attach_telegram_approval_gate(Arc::new(
        wirken_agent::telegram_approval_gate::TelegramApprovalGate::new(
            pending_approval_queue.clone(),
            approver_registry.clone(),
            dispatcher.clone(),
        ),
    ));

    // Signal sessions route through `SignalApprovalGate`, which
    // shares the same `PendingApprovalQueue` and dispatcher and
    // differs only in the channel constant and source variant.
    factory.attach_signal_approval_gate(Arc::new(
        wirken_agent::signal_approval_gate::SignalApprovalGate::new(
            pending_approval_queue.clone(),
            approver_registry.clone(),
            dispatcher.clone(),
        ),
    ));

    // --- Accept adapter connections ---
    let accept_registry = registry.clone();
    let accept_factory = factory.clone();
    let accept_audit = audit.clone();
    let accept_sessions = sessions.clone();
    let accept_router = router.clone();
    let accept_detector = detector.clone();
    let accept_dispatcher = dispatcher.clone();
    let accept_pending = pending_approval_queue.clone();
    let accept_approvers = approver_registry.clone();

    // SAFETY: `geteuid` is always-safe FFI; documented as never
    // failing and never invoking user-space callbacks.
    #[cfg(unix)]
    let gateway_expected_principal = Principal::Uid(unsafe { libc::geteuid() });
    #[cfg(unix)]
    let hooks_expected_principal = gateway_expected_principal.clone();
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
                    let pend = accept_pending.clone();
                    let apprv = accept_approvers.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_adapter_connection(
                            stream, reg, fact, au, sess, rtr, det, disp, pend, apprv,
                        )
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

    // --- Accept hook connections ---
    //
    // Parallel accept loop on `gateway-hooks.sock`. Snapshot-then-
    // verify matches the adapter loop's locking model; same-UID
    // peer-credential gate; routes by hook_type post-handshake.
    let hooks_accept_registry = hook_registry.clone();
    let hooks_accept_dispatcher = hook_dispatcher.clone();
    let hooks_accept_egress_dispatcher = egress_dispatcher.clone();
    // Consumed only by the unix peer-credential branch below. Silenced
    // for other platforms rather than underscored, so a genuinely
    // unused binding still surfaces on unix, where it is used.
    #[cfg_attr(not(unix), allow(unused_variables))]
    let hooks_accept_audit = audit.clone();
    let hooks_accept_session_log = session_log.clone();
    let hooks_accept_handle = tokio::spawn(async move {
        loop {
            match hooks_listener.accept().await {
                Ok(stream) => {
                    #[cfg(unix)]
                    match stream.peer_principal() {
                        Ok(actual) if actual == hooks_expected_principal => {}
                        Ok(actual) => {
                            tracing::warn!(
                                "hooks gateway: refusing peer {} (expected {})",
                                actual,
                                hooks_expected_principal
                            );
                            let _ = hooks_accept_audit
                                .log(
                                    AuditEvent::new(
                                        ActorKind::Service,
                                        "gateway",
                                        "hooks.peer.refused",
                                        "gateway-hooks-socket",
                                    )
                                    .with_detail(
                                        serde_json::json!({
                                            "reason": "principal_mismatch",
                                            "expected": hooks_expected_principal.to_string(),
                                            "actual": actual.to_string(),
                                        }),
                                    ),
                                )
                                .await;
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "hooks gateway: peer_principal unavailable, refusing: {e}"
                            );
                            let _ = hooks_accept_audit
                                .log(
                                    AuditEvent::new(
                                        ActorKind::Service,
                                        "gateway",
                                        "hooks.peer.refused",
                                        "gateway-hooks-socket",
                                    )
                                    .with_detail(
                                        serde_json::json!({
                                            "reason": "peer_principal_unavailable",
                                            "error": e.to_string(),
                                        }),
                                    ),
                                )
                                .await;
                            continue;
                        }
                    }

                    let reg = hooks_accept_registry.clone();
                    let disp = hooks_accept_dispatcher.clone();
                    let edisp = hooks_accept_egress_dispatcher.clone();
                    let slog = hooks_accept_session_log.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_hook_connection(stream, reg, disp, edisp, slog).await
                        {
                            tracing::error!("Hook connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Hooks accept error: {e}");
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
    tracing::info!(
        "Orchestrator socket: {}",
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

    // --- Permissions accept loop (operator decisions) ---
    //
    // Mirror of the orchestrator-push loop above. Same trust model
    // (SO_PEERCRED + 0o600), same JSON-line protocol, different
    // request shape. Per-connection handler in
    // `handle_permissions_request` reads one JSON request, looks up
    // the queue, writes one JSON response, closes.
    #[cfg(unix)]
    let permissions_queue_for_loop = pending_approval_queue.clone();
    #[cfg(unix)]
    let permissions_audit = audit.clone();
    #[cfg(unix)]
    let permissions_session_log = session_log.clone();
    #[cfg(unix)]
    let permissions_expected_principal = Principal::Uid(unsafe { libc::geteuid() });
    #[cfg(unix)]
    let permissions_handle = tokio::spawn(async move {
        loop {
            match permissions_listener.accept().await {
                Ok((stream, _)) => {
                    let actual_principal = match stream.peer_principal() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                "permissions: peer_principal unavailable, refusing: {e}"
                            );
                            continue;
                        }
                    };
                    if actual_principal != permissions_expected_principal {
                        tracing::warn!(
                            "permissions: refusing peer {} (expected {})",
                            actual_principal,
                            permissions_expected_principal
                        );
                        continue;
                    }
                    let q = permissions_queue_for_loop.clone();
                    let au = permissions_audit.clone();
                    let slog = permissions_session_log.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_permissions_request(stream, q, au, slog).await {
                            tracing::error!("permissions handler error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("permissions accept error: {e}");
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
    hooks_accept_handle.abort();
    #[cfg(unix)]
    orchestrator_handle.abort();
    #[cfg(unix)]
    permissions_handle.abort();
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

    // Signal the typed-event SIEM worker (if spawned) to exit and
    // wait for it to drain. Shutdown is best-effort: a forwarder
    // mid-POST sees the shutdown signal at the next tick boundary.
    if let Some(mut typed) = typed_siem_handle {
        typed.shutdown();
        typed.join().await;
    }

    // Cleanup sockets
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&mcp_proxy_socket);
    #[cfg(unix)]
    let _ = std::fs::remove_file(&orchestrator_socket_path);

    println!("  Wirken stopped.");
    Ok(())
}

/// Build the audit event for a rejected adapter handshake. Records the
/// failure reason and the claimed adapter id only; the id is `None`
/// when the handshake failed before any id was read (recorded as
/// absent, never fabricated). No signature, nonce, or key material is
/// referenced because the inputs carry none.
fn handshake_rejection_event(
    err: &wirken_ipc::HandshakeError,
    claimed_id: Option<&str>,
) -> AuditEvent {
    let reason = match err {
        wirken_ipc::HandshakeError::UnknownAdapter(_) => "unknown_adapter",
        wirken_ipc::HandshakeError::InvalidSignature => "invalid_signature",
        wirken_ipc::HandshakeError::Protocol(_) => "protocol_error",
        wirken_ipc::HandshakeError::Timeout => "timeout",
        _ => "rejected",
    };
    AuditEvent::new(
        ActorKind::Service,
        "gateway",
        "adapter.handshake_rejected",
        claimed_id.unwrap_or("<unknown>"),
    )
    .with_detail(serde_json::json!({
        "reason": reason,
        "claimed_adapter_id": claimed_id,
    }))
}

/// Gateway side of the adapter handshake, audited on rejection. The
/// claimed adapter id is captured inside the verifier so a rejection
/// can be attributed for both failure reasons; `InvalidSignature` does
/// not carry the id in the error type, and a malformed frame may fail
/// before any id is read, so the id is recorded as known-or-absent. On
/// failure an `adapter.handshake_rejected` event is emitted before the
/// error is returned, so the caller's teardown is unchanged.
async fn gateway_handshake_audited<R, W>(
    reader: &mut wirken_ipc::FrameReader<R>,
    writer: &mut wirken_ipc::FrameWriter<W>,
    known: std::collections::HashMap<String, [u8; 32]>,
    audit: &AuditWriter,
) -> std::result::Result<(String, [u8; 32]), wirken_ipc::HandshakeError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let claimed_id: std::sync::Arc<std::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let claimed_id_capture = claimed_id.clone();

    let result = perform_gateway_handshake(reader, writer, move |id, pk| {
        *claimed_id_capture.lock().unwrap() = Some(id.to_string());
        match known.get(id) {
            None => Err(wirken_ipc::HandshakeError::UnknownAdapter(id.to_string())),
            Some(expected) if expected == pk => Ok(()),
            Some(_) => Err(wirken_ipc::HandshakeError::InvalidSignature),
        }
    })
    .await;

    if let Err(ref e) = result {
        let claimed = claimed_id.lock().unwrap().clone();
        let _ = audit
            .log(handshake_rejection_event(e, claimed.as_deref()))
            .await;
    }

    result
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
    pending_approvals: Arc<wirken_gateway::pending_approvals::PendingApprovalQueue>,
    approver_registry: Arc<wirken_gateway::approver_registry::ApproverRegistry>,
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

    let (adapter_id, pub_key) = gateway_handshake_audited(&mut reader, &mut writer, known, &audit)
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
        pending_approvals,
        approver_registry,
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

/// Handle one inbound hook connection. Snapshot-then-verify the
/// hook_registry, perform the hook-domain handshake, emit
/// `SessionEvent::HookRegistered` on the gateway-hooks sentinel
/// session, then route by `hook_type`:
///
/// - **Observe**: serve `SessionLogTail` requests in a loop. The
///   hook drives its own cursor. No fanout, no broadcast; the
///   append path stays zero-touch.
/// - **Veto**: register a live writer + a per-connection pending
///   map with the `HookDispatcher`'s active set. Spawn a reader
///   task that routes incoming `VetoResponse` frames to the
///   matching pending oneshot by request_id. On reader EOF or read
///   error, drain pending and emit `HookCrashed`.
///
/// The dev-mode escape hatch `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1`
/// bypasses the registry verify in the handshake; the audit row
/// records the unregistered status.
#[allow(clippy::too_many_arguments)]
async fn handle_hook_connection(
    stream: wirken_ipc::BoxStream,
    registry: Arc<Mutex<wirken_gateway::hook_registry::HookRegistry>>,
    dispatcher: Arc<wirken_gateway::hook_dispatcher::HookDispatcher>,
    egress_dispatcher: Arc<wirken_gateway::egress_dispatcher::EgressDispatcher>,
    session_log: Arc<dyn wirken_audit::SessionLog>,
) -> Result<()> {
    use wirken_audit::{HookKind, HookSignatureStatus, SessionEvent, SessionId, TrustLevel};
    use wirken_ipc::{HookType, perform_gateway_hook_handshake};

    let (mut reader, mut writer) = split_stream(stream);

    let allow_unregistered =
        wirken_gateway::org::parse_boolean_escape("WIRKEN_ALLOW_UNREGISTERED_HOOKS");
    let known: std::collections::HashMap<String, ([u8; 32], HookType)> = {
        let reg = registry.lock().await;
        reg.list()
            .into_iter()
            .map(|e| (e.hook_id, (e.public_key, e.hook_type)))
            .collect()
    };

    // Track whether this connection was accepted via the dev escape
    // hatch so the post-handshake audit row records the right
    // signature status.
    let unregistered_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let unregistered_flag_for_closure = unregistered_flag.clone();

    let verified = perform_gateway_hook_handshake(&mut reader, &mut writer, move |id, pk, ty| {
        match known.get(id) {
            Some((expected_pk, expected_ty)) => {
                if expected_pk != pk {
                    Err(wirken_ipc::HandshakeError::InvalidSignature)
                } else if *expected_ty != ty {
                    Err(wirken_ipc::HandshakeError::HookTypeMismatch {
                        hook_id: id.to_string(),
                        registered: expected_ty.as_wire().to_string(),
                        claimed: ty.as_wire().to_string(),
                    })
                } else {
                    Ok(())
                }
            }
            None if allow_unregistered => {
                unregistered_flag_for_closure.store(true, std::sync::atomic::Ordering::SeqCst);
                tracing::warn!(
                    hook_id = id,
                    "WIRKEN_ALLOW_UNREGISTERED_HOOKS=1: accepting unregistered hook",
                );
                Ok(())
            }
            None => Err(wirken_ipc::HandshakeError::UnknownHook(id.to_string())),
        }
    })
    .await
    .context("hook handshake failed")?;

    let hook_id = verified.hook_id.clone();
    let hook_type = verified.hook_type;
    let signature_status = if unregistered_flag.load(std::sync::atomic::Ordering::SeqCst) {
        HookSignatureStatus::Unregistered
    } else {
        HookSignatureStatus::Registered
    };

    // Emit HookRegistered on a sentinel session id reserved for
    // gateway-wide hook lifecycle events. Verifiable like any other
    // session; not associated with any agent's chain.
    let gateway_session = session_log.handle_for(SessionId::new("gateway-hooks"));
    let audit_kind = match hook_type {
        HookType::Observe => HookKind::Observe,
        HookType::Veto => HookKind::Veto,
        HookType::Egress => HookKind::Egress,
    };
    let _ = session_log.append(
        &gateway_session,
        TrustLevel::System,
        SessionEvent::HookRegistered {
            hook_id: hook_id.clone(),
            hook_type: audit_kind,
            signature_status,
        },
    );
    registry.lock().await.set_connected(&hook_id, true);
    tracing::info!(
        hook_id = %hook_id,
        hook_type = hook_type.as_wire(),
        signature_status = ?signature_status,
        "Hook authenticated and routed",
    );

    let crash_reason = match hook_type {
        HookType::Observe => serve_observe_loop(reader, writer, &hook_id, &session_log).await,
        HookType::Veto => serve_veto_loop(reader, writer, &hook_id, &dispatcher).await,
        HookType::Egress => serve_egress_loop(reader, writer, &hook_id, &egress_dispatcher).await,
    };

    registry.lock().await.set_connected(&hook_id, false);
    let _ = session_log.append(
        &gateway_session,
        TrustLevel::System,
        SessionEvent::HookCrashed {
            hook_id: hook_id.clone(),
            error: crash_reason.clone(),
        },
    );
    tracing::info!(hook_id = %hook_id, reason = %crash_reason, "Hook disconnected");
    Ok(())
}

/// Observe-hook serving loop. Reads `SessionLogTail` requests from
/// the hook and responds with batched `SessionLogTailResponse`
/// frames. Returns the snake_case crash reason when the loop ends
/// (clean EOF or read error).
async fn serve_observe_loop(
    mut reader: wirken_ipc::IpcFrameReader,
    mut writer: wirken_ipc::IpcFrameWriter,
    hook_id: &str,
    session_log: &Arc<dyn wirken_audit::SessionLog>,
) -> String {
    use wirken_audit::SessionId;
    use wirken_ipc::wirken_capnp::frame;

    loop {
        let msg = match reader.read_message().await {
            Ok(m) => m,
            Err(_) => return "connection_dropped".to_string(),
        };
        // Extract all data from the capnp Reader synchronously into
        // owned types; the Reader contains raw pointers and is !Send,
        // so it must be dropped before any subsequent await.
        let extracted: Result<(String, u64, usize), &'static str> = (|| {
            let frame_reader = msg
                .get_root::<frame::Reader<'_>>()
                .map_err(|_| "observe_frame_parse")?;
            let which = frame_reader.which().map_err(|_| "observe_frame_variant")?;
            let frame::SessionLogTail(tail) = which else {
                return Err("observe_unexpected_frame");
            };
            let tail = tail.map_err(|_| "observe_frame_parse")?;
            let session_id_str = tail
                .get_session_id()
                .map_err(|_| "observe_session_id_parse")?
                .to_string()
                .map_err(|_| "observe_session_id_parse")?;
            let since_seq = tail.get_since_seq();
            let max_rows = tail.get_max_rows() as usize;
            Ok((session_id_str, since_seq, max_rows))
        })();
        let (session_id_str, since_seq, max_rows) = match extracted {
            Ok(t) => t,
            Err(label) => {
                tracing::warn!(hook_id, label, "observe extract failed");
                return label.to_string();
            }
        };
        drop(msg);

        let handle = session_log.handle_for(SessionId::new(session_id_str.clone()));
        let rows = match session_log.get_since(&handle, since_seq) {
            Ok(rs) => rs,
            Err(e) => {
                tracing::warn!(hook_id, error = %e, "observe get_since failed");
                return "observe_session_log_read".to_string();
            }
        };

        let capped: Vec<&wirken_audit::StoredSessionEvent> =
            rows.iter().take(max_rows.max(1)).collect();
        let next_seq = capped.last().map(|row| row.seq + 1).unwrap_or(since_seq);

        let mut message = capnp::message::Builder::new_default();
        {
            let frame_builder = message.init_root::<frame::Builder<'_>>();
            let mut resp = frame_builder.init_session_log_tail_response();
            resp.set_next_seq(next_seq);
            let mut events_builder = resp.init_events(capped.len() as u32);
            for (idx, row) in capped.iter().enumerate() {
                let mut ev = events_builder.reborrow().get(idx as u32);
                ev.set_seq(row.seq);
                let json = match serde_json::to_string(&row.event) {
                    Ok(j) => j,
                    Err(_) => return "observe_event_serialize".to_string(),
                };
                ev.set_payload(&json);
            }
        }
        if writer.write_message(&message).await.is_err() {
            return "connection_dropped".to_string();
        }
    }
}

/// Veto-hook serving loop. Registers the writer + a per-connection
/// pending map with the dispatcher so subsequent `dispatch` calls
/// route through this connection. Reads `VetoResponse` frames in a
/// loop and routes them to the matching pending oneshot by
/// request_id. Returns the snake_case crash reason on EOF or error;
/// the caller is responsible for unregistering.
async fn serve_veto_loop(
    mut reader: wirken_ipc::IpcFrameReader,
    writer: wirken_ipc::IpcFrameWriter,
    hook_id: &str,
    dispatcher: &Arc<wirken_gateway::hook_dispatcher::HookDispatcher>,
) -> String {
    use std::collections::HashMap;
    use tokio::sync::Mutex as AsyncMutex;
    use wirken_gateway::hook_dispatcher::VetoResult;
    use wirken_ipc::wirken_capnp::frame;

    let writer = Arc::new(AsyncMutex::new(writer));
    let pending: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<VetoResult>>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    dispatcher
        .register(hook_id, writer.clone(), pending.clone())
        .await;

    let crash_reason = loop {
        let msg = match reader.read_message().await {
            Ok(m) => m,
            Err(_) => break "connection_dropped".to_string(),
        };
        // Extract owned data from the capnp Reader before holding it
        // across any await. Returns `Err(label)` for parse failures
        // that the loop translates into a crash reason.
        let extracted: Result<(String, VetoResult), &'static str> = (|| {
            let frame_reader = msg
                .get_root::<frame::Reader<'_>>()
                .map_err(|_| "veto_frame_parse")?;
            let which = frame_reader.which().map_err(|_| "veto_frame_variant")?;
            let frame::VetoResponse(resp) = which else {
                return Err("veto_unexpected_frame");
            };
            let resp = resp.map_err(|_| "veto_frame_parse")?;
            let request_id = resp
                .get_request_id()
                .map_err(|_| "veto_request_id_parse")?
                .to_string()
                .map_err(|_| "veto_request_id_parse")?;
            let result = match resp.which() {
                Ok(wirken_ipc::wirken_capnp::veto_response::Allow(_)) => VetoResult::Allow,
                Ok(wirken_ipc::wirken_capnp::veto_response::Deny(reason)) => {
                    let reason = reason
                        .ok()
                        .and_then(|r| r.to_string().ok())
                        .unwrap_or_default();
                    VetoResult::Deny { reason }
                }
                Err(_) => return Err("veto_response_decision"),
            };
            Ok((request_id, result))
        })();
        let (request_id, result) = match extracted {
            Ok(t) => t,
            Err(label) => break label.to_string(),
        };
        drop(msg);

        let sender = pending.lock().unwrap().remove(&request_id);
        if let Some(sender) = sender {
            let _ = sender.send(result);
        } else {
            tracing::warn!(
                hook_id,
                request_id = %request_id,
                "veto response for unknown or timed-out request_id; dropping",
            );
        }
    };

    // Drain pending so all in-flight dispatchers see ConnectionDropped.
    {
        let mut guard = pending.lock().unwrap();
        for (_, sender) in guard.drain() {
            drop(sender);
        }
    }
    dispatcher.unregister(hook_id).await;
    crash_reason
}

/// Egress-hook serving loop. Twin of [`serve_veto_loop`] on the
/// post-execution path. Registers the writer + a per-connection
/// pending map with the egress dispatcher so subsequent `dispatch`
/// calls route through this connection. Reads `EgressResponse`
/// frames in a loop and routes them by request_id. Returns the
/// snake_case crash reason on EOF or error.
async fn serve_egress_loop(
    mut reader: wirken_ipc::IpcFrameReader,
    writer: wirken_ipc::IpcFrameWriter,
    hook_id: &str,
    dispatcher: &Arc<wirken_gateway::egress_dispatcher::EgressDispatcher>,
) -> String {
    use std::collections::HashMap;
    use tokio::sync::Mutex as AsyncMutex;
    use wirken_gateway::egress_dispatcher::EgressResult;
    use wirken_ipc::wirken_capnp::frame;

    let writer = Arc::new(AsyncMutex::new(writer));
    let pending: Arc<
        std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<EgressResult>>>,
    > = Arc::new(std::sync::Mutex::new(HashMap::new()));

    dispatcher
        .register(hook_id, writer.clone(), pending.clone())
        .await;

    let crash_reason = loop {
        let msg = match reader.read_message().await {
            Ok(m) => m,
            Err(_) => break "connection_dropped".to_string(),
        };
        let extracted: Result<(String, EgressResult), &'static str> = (|| {
            let frame_reader = msg
                .get_root::<frame::Reader<'_>>()
                .map_err(|_| "egress_frame_parse")?;
            let which = frame_reader.which().map_err(|_| "egress_frame_variant")?;
            let frame::EgressResponse(resp) = which else {
                return Err("egress_unexpected_frame");
            };
            let resp = resp.map_err(|_| "egress_frame_parse")?;
            let request_id = resp
                .get_request_id()
                .map_err(|_| "egress_request_id_parse")?
                .to_string()
                .map_err(|_| "egress_request_id_parse")?;
            let result = match resp.which() {
                Ok(wirken_ipc::wirken_capnp::egress_response::Allow(_)) => EgressResult::Allow,
                Ok(wirken_ipc::wirken_capnp::egress_response::Replace(bytes)) => {
                    let bytes = bytes.map_err(|_| "egress_replace_payload")?.to_vec();
                    EgressResult::Replace { bytes }
                }
                Ok(wirken_ipc::wirken_capnp::egress_response::Refuse(reason)) => {
                    let reason = reason
                        .ok()
                        .and_then(|r| r.to_string().ok())
                        .unwrap_or_default();
                    EgressResult::Refuse { reason }
                }
                Err(_) => return Err("egress_response_decision"),
            };
            Ok((request_id, result))
        })();
        let (request_id, result) = match extracted {
            Ok(t) => t,
            Err(label) => break label.to_string(),
        };
        drop(msg);

        let sender = pending.lock().unwrap().remove(&request_id);
        if let Some(sender) = sender {
            let _ = sender.send(result);
        } else {
            tracing::warn!(
                hook_id,
                request_id = %request_id,
                "egress response for unknown or timed-out request_id; dropping",
            );
        }
    };

    {
        let mut guard = pending.lock().unwrap();
        for (_, sender) in guard.drain() {
            drop(sender);
        }
    }
    dispatcher.unregister(hook_id).await;
    crash_reason
}

/// Handle one inbound permissions-IPC connection. Reads one
/// line-delimited JSON [`PermissionsRequest`] from the stream,
/// routes it to the [`PendingApprovalQueue`], writes one JSON
/// [`PermissionsResponse`] back, and closes.
///
/// The audit chain is NOT touched by this handler — the awaiting
/// agent task emits `PermissionApproved` / `PermissionDenied`
/// rows when its `request_approval` await wakes up. The handler's
/// only responsibility is queue resolution.
#[cfg(unix)]
async fn handle_permissions_request(
    stream: UnixStream,
    queue: Arc<wirken_gateway::pending_approvals::PendingApprovalQueue>,
    _audit: Arc<AuditWriter>,
    _session_log: Arc<dyn wirken_audit::SessionLog>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use wirken_ipc::permissions::{PermissionsRequest, PermissionsResponse};

    let (reader, mut writer) = stream.into_split();
    let mut br = BufReader::new(reader);
    let mut line = String::new();
    let n = br
        .read_line(&mut line)
        .await
        .context("permissions: read request")?;
    if n == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<PermissionsRequest>(line.trim_end()) {
        Ok(req) => process_permissions_request(req, &queue),
        Err(e) => PermissionsResponse::Error {
            message: format!("invalid request JSON: {e}"),
        },
    };

    let body = serde_json::to_string(&response).context("permissions: serialize response")?;
    writer
        .write_all(body.as_bytes())
        .await
        .context("permissions: write response body")?;
    writer
        .write_all(b"\n")
        .await
        .context("permissions: write response newline")?;
    writer
        .shutdown()
        .await
        .context("permissions: shutdown response")?;
    Ok(())
}

#[cfg(unix)]
fn process_permissions_request(
    req: wirken_ipc::permissions::PermissionsRequest,
    queue: &wirken_gateway::pending_approvals::PendingApprovalQueue,
) -> wirken_ipc::permissions::PermissionsResponse {
    use wirken_gateway::pending_approvals::PendingDecision;
    use wirken_ipc::permissions::{
        DecisionResult, PendingDetail, PendingSummary, PermissionsRequest, PermissionsResponse,
    };

    match req {
        PermissionsRequest::PendingList => {
            let mut entries: Vec<PendingSummary> = queue
                .list()
                .into_iter()
                .map(|s| PendingSummary {
                    request_id: s.request_id,
                    agent_id: s.agent_id,
                    tool_name: s.tool_name,
                    action_key: s.action_key,
                    requested_tier: s.requested_tier,
                    requested_at: s.requested_at.to_rfc3339(),
                    age_seconds: s.age_seconds,
                })
                .collect();
            entries.sort_by(|a, b| a.request_id.cmp(&b.request_id));
            PermissionsResponse::PendingList { entries }
        }
        PermissionsRequest::PendingShow { request_id } => {
            let detail = queue.show(&request_id).map(|d| PendingDetail {
                summary: PendingSummary {
                    request_id: d.request_id,
                    agent_id: d.agent_id,
                    tool_name: d.tool_name,
                    action_key: d.action_key,
                    requested_tier: d.requested_tier,
                    requested_at: d.requested_at.to_rfc3339(),
                    age_seconds: d.age_seconds,
                },
                trigger_message: d.trigger_message,
            });
            PermissionsResponse::PendingShow { entry: detail }
        }
        PermissionsRequest::PendingApprove {
            request_id,
            approved_by,
        } => {
            let result = queue.resolve(
                &request_id,
                PendingDecision::Allow {
                    actor: Some(approved_by),
                },
            );
            PermissionsResponse::Decision {
                result: match result {
                    wirken_gateway::pending_approvals::ResolveResult::Accepted => {
                        DecisionResult::Accepted
                    }
                    wirken_gateway::pending_approvals::ResolveResult::UnknownKey => {
                        DecisionResult::UnknownKey
                    }
                },
            }
        }
        PermissionsRequest::PendingDeny {
            request_id,
            denied_by,
            reason,
        } => {
            let result = queue.resolve(
                &request_id,
                PendingDecision::Deny {
                    reason,
                    actor: Some(denied_by),
                },
            );
            PermissionsResponse::Decision {
                result: match result {
                    wirken_gateway::pending_approvals::ResolveResult::Accepted => {
                        DecisionResult::Accepted
                    }
                    wirken_gateway::pending_approvals::ResolveResult::UnknownKey => {
                        DecisionResult::UnknownKey
                    }
                },
            }
        }
    }
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
    pending_approvals: Arc<wirken_gateway::pending_approvals::PendingApprovalQueue>,
    approver_registry: Arc<wirken_gateway::approver_registry::ApproverRegistry>,
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
                frame::ApprovalDecision(d) => {
                    let d = d?;
                    let request_id = d
                        .get_request_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("approval request_id not utf8: {e}"))?
                        .to_string();
                    let user_id = d
                        .get_actor_user_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("actor_user_id not utf8: {e}"))?
                        .to_string();
                    let user_display = d
                        .get_actor_display()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("actor_display not utf8: {e}"))?
                        .to_string();
                    let decision = match d.get_decision()?.which()? {
                        wirken_ipc::wirken_capnp::approval_decision_kind::Allow(_) => {
                            ApprovalDecisionKind::Allow
                        }
                        wirken_ipc::wirken_capnp::approval_decision_kind::Deny(reason) => {
                            let reason_text = reason?
                                .to_str()
                                .map_err(|e| anyhow::anyhow!("deny reason not utf8: {e}"))?
                                .to_string();
                            let reason = if reason_text.is_empty() {
                                None
                            } else {
                                Some(reason_text)
                            };
                            ApprovalDecisionKind::Deny { reason }
                        }
                    };
                    InboundAction::ApprovalDecision {
                        request_id,
                        decision,
                        user_id,
                        user_display,
                    }
                }
                frame::ApprovalRequestFailed(f) => {
                    let f = f?;
                    let request_id = f
                        .get_request_id()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("approval request_id not utf8: {e}"))?
                        .to_string();
                    let reason = f
                        .get_reason()?
                        .to_str()
                        .map_err(|e| anyhow::anyhow!("failure reason not utf8: {e}"))?
                        .to_string();
                    InboundAction::ApprovalRequestFailed { request_id, reason }
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
                if let Some(ref threat) = threat_detail
                    && let (Some(obj), Some(threat_obj)) =
                        (inbound_detail.as_object_mut(), threat.as_object())
                {
                    for (k, v) in threat_obj {
                        obj.insert(k.clone(), v.clone());
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
                    // Routing channel, not the adapter id: this is
                    // the key `AgentConfig::channel_egress` and the
                    // router are both keyed by.
                    channel: Some(channel.clone()),
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

            InboundAction::ApprovalDecision {
                request_id,
                decision,
                user_id,
                user_display,
            } => {
                // Centralized authorization: validate the actor
                // against `approver_registry` BEFORE resolving the
                // queue. Unauthorized actions are silently dropped
                // (queue stays open until timeout or until an
                // authorized action arrives). Per the slice, an
                // explicit "unauthorized attempt" audit variant is
                // a follow-up if SIEM detections need to count
                // attempts; today's signal is the warn-level log.
                if !approver_registry.verify(adapter_id, &user_id) {
                    tracing::warn!(
                        adapter_id = adapter_id,
                        user_id = %user_id,
                        request_id = %request_id,
                        "channel approval: unauthorized actor sent approve/deny; dropping"
                    );
                    continue;
                }
                // Prefer the wire-supplied display name; fall back
                // to the registry's stored display, then to the
                // user id as a last resort. The chosen value lands
                // on the audit row's `approved_by` / actor field.
                let actor = if !user_display.is_empty() {
                    user_display
                } else {
                    approver_registry
                        .display_name(adapter_id, &user_id)
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| user_id.clone())
                };
                let pending = match decision {
                    ApprovalDecisionKind::Allow => {
                        wirken_gateway::pending_approvals::PendingDecision::Allow {
                            actor: Some(actor),
                        }
                    }
                    ApprovalDecisionKind::Deny { reason } => {
                        wirken_gateway::pending_approvals::PendingDecision::Deny {
                            reason,
                            actor: Some(actor),
                        }
                    }
                };
                let result = pending_approvals.resolve(&request_id, pending);
                match result {
                    wirken_gateway::pending_approvals::ResolveResult::Accepted => {
                        tracing::info!(
                            adapter_id = adapter_id,
                            request_id = %request_id,
                            "channel approval resolved"
                        );
                    }
                    wirken_gateway::pending_approvals::ResolveResult::UnknownKey => {
                        tracing::warn!(
                            adapter_id = adapter_id,
                            request_id = %request_id,
                            "channel approval: unknown or already-resolved request id; \
                             agent timeout may have fired or another action won the race"
                        );
                    }
                }
            }

            InboundAction::ApprovalRequestFailed { request_id, reason } => {
                // Adapter could not deliver the outbound approval
                // message. Resolve the queue with Deny carrying the
                // delivery-failure reason so the agent's audit row
                // records the failure rather than a generic timeout.
                let denial_reason = format!("approval delivery failed: {reason}");
                let result = pending_approvals.resolve(
                    &request_id,
                    wirken_gateway::pending_approvals::PendingDecision::Deny {
                        reason: Some(denial_reason),
                        actor: None,
                    },
                );
                tracing::warn!(
                    adapter_id = adapter_id,
                    request_id = %request_id,
                    reason = %reason,
                    result = ?result,
                    "channel approval delivery failed; queue entry resolved with denial"
                );
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
    /// Channel-adapter approval decision. The adapter forwards the
    /// actor's `(user_id, display)` plus the `request_id` and
    /// decision verbatim. The gateway validates the actor against
    /// `approver_registry` here before resolving the queue
    /// (centralized authorization). Unauthorized actions are
    /// silently dropped at the validate step.
    ApprovalDecision {
        request_id: String,
        decision: ApprovalDecisionKind,
        user_id: String,
        user_display: String,
    },
    /// Adapter could not deliver the outbound approval message.
    /// Gateway resolves the queue with `Timeout` and the audit row
    /// records `denial_reason` carrying the supplied label.
    ApprovalRequestFailed {
        request_id: String,
        reason: String,
    },
    Unknown,
}

/// Mirrors `frame::approval_decision_kind::Which` in owned form so
/// the message-loop dispatch can match on it after the capnp
/// Reader is dropped. The deny variant carries the operator-
/// supplied reason when the surface captured one (Signal text
/// command), `None` otherwise (Telegram inline keyboard has no
/// reason-capture UX wired today).
#[derive(Debug, Clone)]
enum ApprovalDecisionKind {
    Allow,
    Deny { reason: Option<String> },
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

#[cfg(all(test, unix))]
mod handshake_audit_tests {
    use super::{gateway_handshake_audited, handshake_rejection_event};
    use std::collections::HashMap;
    use wirken_audit::{AuditEvent, AuditLog, AuditQuery, AuditWriter};
    use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, send_rejection, split_stream};

    /// Drive one rejected handshake end to end (real adapter signer,
    /// real gateway verifier, real audit writer) and return the
    /// recorded `adapter.handshake_rejected` event, if any.
    async fn run_rejected_handshake(
        known: HashMap<String, [u8; 32]>,
        adapter_identity: AdapterIdentity,
    ) -> Option<AuditEvent> {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let (writer, handle) = AuditWriter::new(&db).unwrap();

        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (mut cr, mut cw) = split_stream(client);
        let (mut sr, mut sw) = split_stream(server);

        let adapter = tokio::spawn(async move {
            // Best-effort: the adapter receives a rejection or EOF.
            let _ = perform_adapter_handshake(&mut cr, &mut cw, &adapter_identity).await;
        });

        let result = gateway_handshake_audited(&mut sr, &mut sw, known, &writer).await;
        assert!(result.is_err(), "handshake must be rejected");

        // Unblock the adapter so it does not hang waiting for a result.
        let _ = send_rejection(&mut sw, "rejected").await;
        let _ = adapter.await;

        // Close the writer to flush, then read the chain back.
        drop(writer);
        handle.await.unwrap();
        let log = AuditLog::open(&db).unwrap();
        log.query(&AuditQuery::default())
            .unwrap()
            .into_iter()
            .find(|e| e.event.action == "adapter.handshake_rejected")
            .map(|e| e.event)
    }

    #[tokio::test]
    async fn unknown_adapter_handshake_is_audited() {
        let ev = run_rejected_handshake(HashMap::new(), AdapterIdentity::generate("ghost"))
            .await
            .expect("rejected handshake must emit adapter.handshake_rejected");
        assert_eq!(ev.detail["reason"].as_str(), Some("unknown_adapter"));
        assert_eq!(ev.detail["claimed_adapter_id"].as_str(), Some("ghost"));
    }

    #[tokio::test]
    async fn invalid_signature_handshake_is_audited() {
        // Register `telegram` under one key, then present a different
        // key for the same id: the verifier's pubkey-mismatch branch
        // yields InvalidSignature with the id still in scope.
        let registered = AdapterIdentity::generate("telegram").public_key_bytes();
        let mut known = HashMap::new();
        known.insert("telegram".to_string(), registered);

        let ev = run_rejected_handshake(known, AdapterIdentity::generate("telegram"))
            .await
            .expect("rejected handshake must emit adapter.handshake_rejected");
        assert_eq!(ev.detail["reason"].as_str(), Some("invalid_signature"));
        assert_eq!(ev.detail["claimed_adapter_id"].as_str(), Some("telegram"));
    }

    #[tokio::test]
    async fn rejected_handshake_event_has_no_secret_material() {
        let ev = run_rejected_handshake(HashMap::new(), AdapterIdentity::generate("ghost"))
            .await
            .unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            !json.contains("signature"),
            "event must not carry signature bytes: {json}"
        );
        assert!(
            !json.contains("nonce"),
            "event must not carry nonce bytes: {json}"
        );
        assert!(
            !json.contains("public_key") && !json.contains("pubkey"),
            "event must not carry key material: {json}"
        );
    }

    #[test]
    fn rejection_event_records_absent_id_as_null() {
        // A failure before any id is read records the id as absent,
        // not fabricated.
        let ev = handshake_rejection_event(
            &wirken_ipc::HandshakeError::Protocol("bad frame".into()),
            None,
        );
        assert_eq!(ev.action, "adapter.handshake_rejected");
        assert_eq!(ev.detail["reason"].as_str(), Some("protocol_error"));
        assert!(ev.detail["claimed_adapter_id"].is_null());
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

/// Spawn the typed-event SIEM worker when the operator has opted
/// in. Opt-in is satisfied by any of four `siem.json` fields:
///
/// - `typed_forwarding_enabled: true`: explicit subscription
///   with the default forwardable-variant set.
/// - `typed_include_variants` set: operator-provided allowlist.
/// - `typed_exclude_variants` set: operator-provided denylist
///   over the default set.
/// - `sentinel_typed` set: Sentinel parallel pipe (DCR-stream
///   constraint).
///
/// `typed_forwarding_enabled: Some(false)` is an explicit off
/// switch that overrides the three include/exclude/sentinel
/// fields; the worker is not spawned even when those are set.
/// Use this to test the legacy-only path against a config that
/// already has the typed fields populated.
///
/// All-null (the 1.3.0 default) = no typed pipe. Back-compat with
/// the original spec; the explicit-true form is the new opt-in.
///
/// The worker reads from `session_events` via
/// `SqliteSessionLog::get_since`; it never writes, so the audit
/// hash chain stays intact regardless of forwarder activity.
async fn maybe_spawn_typed_siem(
    cfg: &wirken_gateway::config::GatewayConfig,
    siem_config: Option<&SiemConfig>,
) -> Option<wirken_audit::TypedEventForwarder> {
    let cfg_ref = siem_config?;
    if !cfg_ref.typed_forwarding_opted_in() {
        return None;
    }
    let log = match wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            tracing::warn!("typed-SIEM: open session log failed; not spawning: {e}");
            return None;
        }
    };
    let sink: Arc<dyn wirken_audit::TypedSink> = Arc::new(
        wirken_audit::siem_typed::HttpTypedSink::new(cfg_ref.clone()),
    );
    tracing::info!("SIEM: typed-event forwarder spawned");
    Some(wirken_audit::TypedEventForwarder::spawn(
        log,
        sink,
        cfg_ref.clone(),
    ))
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

    let sentinel_typed = json.get("sentinel_typed").and_then(|s| {
        let endpoint = s.get("endpoint").and_then(|v| v.as_str())?.to_string();
        let api_key = s
            .get("api_key")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        Some(wirken_audit::SentinelTypedEndpoint { endpoint, api_key })
    });

    let typed_include_variants = json
        .get("typed_include_variants")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let typed_exclude_variants = json
        .get("typed_exclude_variants")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let typed_forwarding_enabled = json
        .get("typed_forwarding_enabled")
        .and_then(|v| v.as_bool());
    let typed_poll_interval_ms = json.get("typed_poll_interval_ms").and_then(|v| v.as_u64());

    println!("  SIEM: forwarding to {target_str} at {endpoint}");

    Some(SiemConfig {
        target,
        endpoint,
        api_key,
        service,
        environment,
        hmac_secret,
        sentinel_typed,
        typed_include_variants,
        typed_exclude_variants,
        typed_forwarding_enabled,
        typed_poll_interval_ms,
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

        let (api_key, api_key_credential) = match cfg.get("api_key_name").and_then(|v| v.as_str()) {
            Some(slot) => {
                let (secret, _) = store.retrieve(slot).with_context(|| {
                    format!(
                        "channel '{channel}' needs a key named '{slot}', \
                         but no key with that name exists. \
                         Add it with: wirken credentials add {slot}"
                    )
                })?;
                (Some(secret.expose().to_string()), Some(slot.to_string()))
            }
            None => (None, None),
        };

        let llm_config = LlmConfig::from_provider(provider, base_url, model);
        out.insert(
            channel.clone(),
            wirken_agent::ChannelOverride {
                llm_config,
                api_key,
                api_key_credential,
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
