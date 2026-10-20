use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use wirken_agent::Agent;
use wirken_agent::approval_gate::ApprovalGate;
use wirken_agent::llm::LlmConfig;
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::config::GatewayConfig;
use wirken_vault::{CredentialStore, probe_keychain};

use super::{config, open_permission_store};

/// Open the session log with the gateway's audit signing key when one
/// is available, so an `ask` session carries signed chain heads the
/// way a `wirken run` session does. Falls back to an unsigned log with
/// a warning rather than refusing to answer: losing the signature is
/// worse than losing the turn only if the operator is relying on it,
/// and the warning is what tells them.
///
/// Returns the concrete type because emitting a head needs it; callers
/// clone it into the `dyn SessionLog` the runtime takes. The flag says
/// whether the log carries the signer, which is what a surface shows as
/// the audit state.
fn open_signed_session_log(
    cfg: &wirken_gateway::config::GatewayConfig,
) -> Result<(Arc<wirken_audit::SqliteSessionLog>, bool)> {
    let signer = match wirken_audit::AuditSigningKey::load_or_create(&cfg.data_dir) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "this ask will write to an unsigned audit chain: could not load or \
                 generate the gateway audit signing key"
            );
            None
        }
    };
    let signed = signer.is_some();
    let log = match signer {
        Some(s) => wirken_audit::SqliteSessionLog::open_with_signer(&cfg.audit_db_path(), s)
            .context("Failed to open session log with signer")?,
        None => wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    };
    Ok((Arc::new(log), signed))
}

/// Close the ask's range with a `SessionEnd` head.
///
/// `wirken ask` is a one-shot. The `SessionStart` head fires on the
/// first append inside the runtime, and nothing else ever closes the
/// range, so without this every row the ask wrote stays in the
/// unsigned tail and `wirken audit verify --require-signed` reports
/// the session as having no signed heads. Consecutive asks share one
/// session id, so each terminal head chains onto the last.
///
/// Best-effort by construction: the turn has already happened and its
/// rows are already on the chain, so a failure to seal is logged and
/// not propagated. A missing signer returns `Ok(None)` and is not an
/// error.
pub(crate) fn seal_session(log: &Arc<wirken_audit::SqliteSessionLog>, session_id: &str) {
    use wirken_audit::SessionLog as _;
    let handle = log.handle_for(wirken_audit::SessionId::new(session_id.to_string()));
    if let Err(e) = log.emit_chain_head(&handle, wirken_audit::ChainHeadReason::SessionEnd) {
        tracing::warn!(
            error = %e,
            session_id,
            "could not write the terminal chain head for this ask; the rows it \
             wrote stay in the unsigned tail"
        );
    }
}

/// An agent built for `wirken ask`, with the log it writes to (for
/// sealing) and the id its grants key on.
pub(crate) struct BuiltAgent {
    pub agent: Agent,
    pub log: Arc<wirken_audit::SqliteSessionLog>,
    pub agent_id: String,
}

/// An agent's configuration resolved for a local surface: what a
/// factory wakes it from, and the provider/model pair the surface shows.
pub(crate) struct ResolvedAgent {
    pub config: wirken_agent::AgentStaticConfig,
    pub provider: String,
    pub model: String,
    /// Tokens the model takes, from the provider's table.
    pub context_window: usize,
}

/// Resolve `agent_id` the way every local surface must: the configured
/// `AgentConfig` row when one exists, else the legacy `provider.json`
/// for `default`; the API key from its vault slot; the operator's
/// sandbox config; the agent's own, shared and preset skills; and, for a
/// configured agent, the sub-agents it may spawn and its channels'
/// egress, as `wirken run` reads them.
pub(crate) fn resolve_agent(cfg: &GatewayConfig, agent_id: &str) -> Result<ResolvedAgent> {
    // Try to load agent config from the multi-agent store first
    let agent_config_path = cfg.agent_config_db_path();
    let configured = if agent_config_path.exists() {
        AgentConfigStore::open(&agent_config_path)
            .ok()
            .and_then(|store| store.get(agent_id).ok())
    } else {
        None
    };

    let (id, llm_config, api_key, api_key_credential, workspace) = match &configured {
        Some(agent_cfg) => {
            let llm_config = super::llm_config_for_agent(agent_cfg);

            // Stamp the slot name on `LlmRequest` / `LlmResponse` emits for
            // SIEM correlation. Empty `api_key_credential` on the agent
            // config means no vault lookup, so no slot name to carry.
            let api_key_credential = if agent_cfg.api_key_credential.is_empty() {
                None
            } else {
                Some(agent_cfg.api_key_credential.clone())
            };
            let api_key = if !agent_cfg.api_key_credential.is_empty() {
                let pp = super::cached_vault_passphrase()?;
                let keychain = probe_keychain(&cfg.data_dir, move || pp);
                let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
                    .context("Failed to open credential store")?;
                match store.retrieve(&agent_cfg.api_key_credential) {
                    Ok((secret, _)) => Some(secret.expose().to_string()),
                    Err(_) => None,
                }
            } else {
                None
            };
            (
                agent_cfg.id.clone(),
                llm_config,
                api_key,
                api_key_credential,
                cfg.agent_workspace(&agent_cfg.id),
            )
        }
        None => {
            // Fall back to legacy provider.json for "default" agent
            if agent_id != "default" {
                anyhow::bail!(
                    "Persona / agent '{agent_id}' not found.\n\
                         Run `wirken persona list` to see configured personas,\n\
                         `wirken persona create {agent_id}` to register one,\n\
                         or use --agent default."
                );
            }

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

            let mut llm_config = LlmConfig::from_provider(provider, base_url, model);
            if provider == "bedrock" {
                llm_config.region =
                    provider_json["region"]
                        .as_str()
                        .map(String::from)
                        .or_else(|| {
                            base_url
                                .strip_prefix("https://bedrock-runtime.")
                                .and_then(|s| s.strip_suffix(".amazonaws.com"))
                                .map(String::from)
                        });
            }

            // Vault slot the api_key was resolved from. Stamped on every
            // `LlmRequest` / `LlmResponse` for SIEM correlation. `None` for
            // ollama (no vault lookup) and for the warn-and-continue failure
            // path below.
            let mut api_key_credential: Option<String> = None;
            let api_key = if provider != "ollama" {
                let pp = super::cached_vault_passphrase()?;
                let keychain = probe_keychain(&cfg.data_dir, move || pp);
                let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
                    .context("Failed to open credential store")?;
                let cred_name = format!("{provider}-api-key");
                match store.retrieve(&cred_name) {
                    Ok((secret, _)) => {
                        api_key_credential = Some(cred_name.clone());
                        Some(secret.expose().to_string())
                    }
                    Err(e) => {
                        tracing::warn!("Failed to retrieve API key '{cred_name}': {e}");
                        None
                    }
                }
            } else {
                None
            };

            if api_key.is_none() && provider != "ollama" {
                anyhow::bail!(
                    "No API key available for '{provider}'. Run `wirken setup` to configure."
                );
            }

            (
                "default".to_string(),
                llm_config,
                api_key,
                api_key_credential,
                cfg.data_dir.join("workspace"),
            )
        }
    };

    std::fs::create_dir_all(&workspace)?;
    // A dangling preset reference is an operator-actionable error, not
    // silent skill absence.
    let skills = match &configured {
        Some(agent_cfg) => super::skills_for_agent(cfg, agent_cfg)?,
        None => super::skills_for_default_agent(cfg)?,
    };
    let (allowed_subagents, channel_egress) = match &configured {
        Some(agent_cfg) => (
            agent_cfg.allowed_subagents.clone(),
            agent_cfg.channel_egress.clone(),
        ),
        None => Default::default(),
    };
    Ok(ResolvedAgent {
        provider: llm_config.provider.clone(),
        model: llm_config.model.clone(),
        context_window: llm_config.context_window,
        config: wirken_agent::AgentStaticConfig {
            agent_id: id,
            workspace,
            llm_config,
            channel_overrides: Default::default(),
            api_key,
            api_key_credential,
            skills,
            mcp_client: None,
            identity: None,
            allowed_subagents,
            sandbox: super::load_sandbox_config(&cfg.data_dir),
            channel_egress,
            extra_interceptors: vec![],
            zirkel_db_path: None,
        },
    })
}

/// Every stored secret, which an agent refuses to let model-authored
/// content carry.
fn leak_matcher(cfg: &GatewayConfig) -> wirken_gateway::leak::LeakMatcher {
    super::seed_leak_matcher(&cfg.vault_db_path(), || {
        probe_keychain(&cfg.data_dir, || {
            super::cached_vault_passphrase().unwrap_or_default()
        })
    })
}

/// Build `agent_id` as [`resolve_agent`] resolves it, for one lane: the
/// gateway's permission store, so tier gating applies here as on every
/// other path (an agent cannot be built without one); the leak matcher
/// set before the skills, which are checked against it as they load;
/// and the skills attached so their permission blocks narrow the tool
/// set exactly as `wirken run` builds the same agent.
///
/// `session_id` is the lane the agent writes to; `wirken ask` passes the
/// agent id, so consecutive asks share one chain. `gate` is the approval
/// surface, or `None` for the unmediated path where a `NeedsApproval`
/// short-circuits with a terminal deny.
pub(crate) fn build_agent(
    cfg: &GatewayConfig,
    agent_id: &str,
    session_id: &str,
    gate: Option<Arc<dyn ApprovalGate>>,
) -> Result<BuiltAgent> {
    let config = resolve_agent(cfg, agent_id)?.config;
    let (log, _signed) = open_signed_session_log(cfg)?;
    let session_log: Arc<dyn wirken_audit::SessionLog> = log.clone();
    let perms = Arc::new(Mutex::new(open_permission_store(cfg)?));
    let mut agent = Agent::new_with_sandbox(
        session_id.to_string(),
        config.workspace,
        config.llm_config,
        config.api_key,
        config.api_key_credential,
        session_log,
        config.sandbox,
        perms,
    )?;

    // Named before any call is gated: an agent that has not named
    // itself gets no persisted grants and prompts for every Tier 2
    // action. The configured agent's own id, not the literal
    // "default": checking a named agent against another agent's grants
    // is the failure the id exists to prevent.
    agent.set_agent_id(config.agent_id.clone());
    if let Some(gate) = gate {
        agent.set_approval_gate(gate);
    }
    agent.set_leak_matcher(Arc::new(leak_matcher(cfg)));
    agent
        .attach_skills(config.skills)
        .context("attach skills")?;

    Ok(BuiltAgent {
        agent,
        log,
        agent_id: config.agent_id,
    })
}

/// What the chat shows about one of its agents.
pub(crate) struct AgentInfo {
    pub provider: String,
    pub model: String,
    pub context_window: usize,
    pub workspace: std::path::PathBuf,
}

/// The chat's agents, woken through one [`wirken_agent::AgentFactory`],
/// as `wirken run` wakes them, so an agent can delegate with
/// `spawn_subagent` to the agents `wirken agents allow-subagent` lets
/// it reach, each child under that command's ceiling and on a lane of
/// its own (`{parent}#sub-N`). Every agent resolves as `wirken ask`
/// resolves it. The factory carries the permission store, the leak
/// matcher, `gate` as the approval surface for the chat's sessions and
/// their children alike, and, as `wirken run` attaches them, the org
/// tool policy and budget enforcement, failing closed as it does: a
/// malformed `budget.json`, or a block-mode budget whose ledger cannot
/// be opened, stops the chat. What needs the daemon (hook processes,
/// MCP servers, the memory and imported-archive stores, and the vault
/// resolver `http_request` names a credential through) is not attached;
/// a call needing one refuses.
pub(crate) struct ChatAgents {
    pub factory: Arc<wirken_agent::AgentFactory>,
    pub log: Arc<wirken_audit::SqliteSessionLog>,
    pub signed: bool,
    pub info: std::collections::BTreeMap<String, AgentInfo>,
    /// Agents that could not be resolved, with why: a chat with one of
    /// them says so instead of failing to start.
    pub unavailable: Vec<(String, String)>,
}

pub(crate) fn chat_agents(cfg: &GatewayConfig, gate: Arc<dyn ApprovalGate>) -> Result<ChatAgents> {
    let path = cfg.agent_config_db_path();
    let mut ids: Vec<String> = if path.exists() {
        AgentConfigStore::open(&path)
            .and_then(|store| store.list())
            .map(|agents| agents.into_iter().map(|a| a.id).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if !ids.iter().any(|id| id == "default") && cfg.data_dir.join("provider.json").exists() {
        ids.insert(0, "default".to_string());
    }
    let mut configs = std::collections::HashMap::new();
    let mut info = std::collections::BTreeMap::new();
    let mut unavailable = Vec::new();
    for id in ids {
        match resolve_agent(cfg, &id) {
            Ok(r) => {
                info.insert(
                    id.clone(),
                    AgentInfo {
                        provider: r.provider,
                        model: r.model,
                        context_window: r.context_window,
                        workspace: r.config.workspace.clone(),
                    },
                );
                configs.insert(id, r.config);
            }
            Err(e) => unavailable.push((id, format!("{e:#}"))),
        }
    }
    let (log, signed) = open_signed_session_log(cfg)?;
    let perms = Arc::new(Mutex::new(open_permission_store(cfg)?));
    let org_tool_policy = wirken_gateway::org::load_tool_policy(&cfg.data_dir)
        .map_err(anyhow::Error::msg)?
        .map(Arc::new);
    let factory = wirken_agent::AgentFactory::with_options(
        configs,
        log.clone() as Arc<dyn wirken_audit::SessionLog>,
        perms,
        org_tool_policy,
        wirken_agent::factory::CacheMode::Cached,
        64,
    );
    factory.attach_default_approval_gate(gate);
    factory.attach_leak_matcher(Arc::new(leak_matcher(cfg)));
    let budget = wirken_gateway::budget::load_budget_config(&cfg.budget_config_path())
        .context("load budget.json")?;
    match wirken_gateway::budget::BudgetStore::open(&cfg.budget_db_path()) {
        Ok(store) => factory.attach_budget(Arc::new(Mutex::new(store)), budget),
        Err(e) if budget.has_block_mode() => anyhow::bail!(
            "budget.db could not be opened but a block-mode budget is configured in \
             budget.json; refusing to start so enforcement is never silently disabled: {e}"
        ),
        Err(e) => tracing::warn!("budget.db could not be opened; budget alerts are off: {e}"),
    }
    Ok(ChatAgents {
        factory,
        log,
        signed,
        info,
        unavailable,
    })
}

pub async fn send(message: &str, agent_id: &str) -> Result<()> {
    let cfg = config();

    // Attach the stdin approval gate when (and only when) stdin is
    // a TTY. A piped / redirected `wirken ask` keeps the unmediated
    // behavior — `NeedsApproval` short-circuits with a terminal
    // deny — so a script doesn't hang on a prompt nobody will
    // answer. Interactive sessions get the prompt-and-retry flow.
    let gate: Option<Arc<dyn ApprovalGate>> = if super::oauth_scope::stdin_is_tty() {
        Some(Arc::new(super::stdin_approval::StdinApprovalGate::new()))
    } else {
        None
    };

    // Consecutive asks share one session id, the agent's own, so each
    // terminal head chains onto the last.
    let BuiltAgent {
        mut agent,
        log,
        agent_id,
        ..
    } = build_agent(&cfg, agent_id, agent_id, gate)?;

    println!();
    let inbound_id = format!("ask-{}", uuid::Uuid::new_v4());
    let outcome = agent.process_message(message, inbound_id).await;
    // Seal before reporting, and on the error path too: the rows the
    // turn already wrote are real, and a failed turn is exactly the one
    // an operator will want to verify.
    seal_session(&log, &agent_id);
    match outcome {
        // B2: strip ANSI / C1 control sequences at the print
        // boundary. The model's response is shaped by skill bodies
        // in the system prompt and by tool output the model echoes
        // back; a hostile skill that asks the model to emit
        // `\x1b[2K\rsudo password:` would otherwise render in the
        // operator's terminal as a fake prompt. The raw response
        // stays in the audit chain unchanged (the audit-write
        // boundary is upstream of this print).
        Ok(result) => println!(
            "{}",
            wirken_agent::ansi::strip_control_sequences(&result.response)
        ),
        Err(e) => {
            eprintln!("  Error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_audit::{SessionId, SessionLog as _, TrustLevel};

    fn cfg_in(dir: &std::path::Path) -> wirken_gateway::config::GatewayConfig {
        wirken_gateway::config::GatewayConfig {
            data_dir: dir.to_path_buf(),
            ..Default::default()
        }
    }

    fn user_row(text: &str) -> wirken_audit::SessionEvent {
        wirken_audit::SessionEvent::UserMessage {
            content: text.into(),
            adapter_id: None,
            sender_id: None,
            inbound_id: None,
        }
    }

    /// An ask session must end up with a signed chain head. Before the
    /// log was opened with the signer, `wirken ask` wrote its rows to
    /// an unsigned log, so every ask session reported zero signed heads
    /// and `--require-signed` failed on it.
    #[test]
    fn ask_session_is_sealed_with_a_signed_head() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        let (log, _) = open_signed_session_log(&cfg).expect("open");

        let handle = log.handle_for(SessionId::new("default".to_string()));
        // The first append fires an implicit SessionStart head, which
        // covers that row. Everything the turn writes after it is what
        // would otherwise never be covered.
        log.append(&handle, TrustLevel::User, user_row("hello"))
            .unwrap();
        log.append(&handle, TrustLevel::User, user_row("and again"))
            .unwrap();

        let before = log.verify_signatures(&handle).unwrap();
        assert!(
            before.unsigned_tail_len > 0,
            "rows written after the SessionStart head sit in the unsigned tail \
             until the ask seals them, got {before:?}"
        );

        seal_session(&log, "default");

        let after = log.verify_signatures(&handle).unwrap();
        assert!(
            after.signed_heads_count >= 1,
            "seal must write a signed head, got {after:?}"
        );
        assert_eq!(
            after.unsigned_tail_len, 0,
            "the terminal head must cover every row the ask wrote"
        );
        assert!(
            after.first_invalid.is_none(),
            "the sealed head must verify, got {:?}",
            after.first_invalid
        );
    }

    /// Consecutive asks share one session id, so each seal chains onto
    /// the last rather than restarting the range.
    #[test]
    fn consecutive_asks_chain_their_heads() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        let (log, _) = open_signed_session_log(&cfg).expect("open");
        let handle = log.handle_for(SessionId::new("default".to_string()));

        for turn in 0..3 {
            log.append(&handle, TrustLevel::User, user_row(&format!("turn {turn}")))
                .unwrap();
            seal_session(&log, "default");
        }

        let result = log.verify_signatures(&handle).unwrap();
        // One SessionStart on the very first append, plus one
        // SessionEnd per ask. Each head's range starts where the last
        // one ended, which is what makes them a chain rather than three
        // independent claims.
        assert_eq!(
            result.signed_heads_count, 4,
            "a SessionStart head plus one terminal head per ask, got {result:?}"
        );
        assert_eq!(result.unsigned_tail_len, 0);
        assert!(result.first_invalid.is_none(), "{:?}", result.first_invalid);
    }

    /// Sealing is best-effort and must not panic when the log carries
    /// no signer, which is the degraded path taken when the signing key
    /// cannot be loaded.
    #[test]
    fn seal_without_a_signer_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let log =
            Arc::new(wirken_audit::SqliteSessionLog::open(&dir.path().join("audit.db")).unwrap());
        let handle = log.handle_for(SessionId::new("default".to_string()));
        log.append(&handle, TrustLevel::User, user_row("hi"))
            .unwrap();

        seal_session(&log, "default");

        let result = log.verify_signatures(&handle).unwrap();
        assert_eq!(result.signed_heads_count, 0);
        assert!(result.first_invalid.is_none());
    }
}
