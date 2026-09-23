use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use wirken_agent::Agent;
use wirken_agent::llm::LlmConfig;
use wirken_gateway::agent_config::AgentConfigStore;
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
/// clone it into the `dyn SessionLog` the runtime takes.
fn open_signed_session_log(
    cfg: &wirken_gateway::config::GatewayConfig,
) -> Result<Arc<wirken_audit::SqliteSessionLog>> {
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
    Ok(Arc::new(match signer {
        Some(s) => wirken_audit::SqliteSessionLog::open_with_signer(&cfg.audit_db_path(), s)
            .context("Failed to open session log with signer")?,
        None => wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    }))
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
fn seal_session(log: &Arc<wirken_audit::SqliteSessionLog>, session_id: &str) {
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

pub async fn send(message: &str, agent_id: &str) -> Result<()> {
    let cfg = config();

    // Try to load agent config from the multi-agent store first
    let agent_config_path = cfg.agent_config_db_path();
    if agent_config_path.exists()
        && let Ok(store) = AgentConfigStore::open(&agent_config_path)
        && let Ok(agent_cfg) = store.get(agent_id)
    {
        return send_with_agent_config(message, &agent_cfg, &cfg).await;
    }

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
        anyhow::bail!("No API key available for '{provider}'. Run `wirken setup` to configure.");
    }

    let workspace = cfg.data_dir.join("workspace");
    std::fs::create_dir_all(&workspace)?;

    let session_log_concrete = open_signed_session_log(&cfg)?;
    let session_log: std::sync::Arc<dyn wirken_audit::SessionLog> = session_log_concrete.clone();

    let mut agent = Agent::new_with_sandbox(
        "default".into(),
        workspace.clone(),
        llm_config,
        api_key,
        api_key_credential,
        session_log,
        super::load_sandbox_config(&cfg.data_dir),
    )?;

    // Attach the gateway's permission store so tier gating applies
    // on the ask path too — otherwise Tier 2/3 actions execute
    // unchecked and bypass the three-tier model.
    //
    // The agent id must be set before the store: an agent that has
    // not named itself gets no persisted grants and prompts for
    // every Tier 2 action.
    agent.set_agent_id("default");
    let perms = open_permission_store(&cfg)?;
    agent.set_permissions(Arc::new(Mutex::new(perms)));

    // Attach the stdin approval gate when (and only when) stdin is
    // a TTY. A piped / redirected `wirken ask` keeps the unmediated
    // behavior — `NeedsApproval` short-circuits with a terminal
    // deny — so a script doesn't hang on a prompt nobody will
    // answer. Interactive sessions get the prompt-and-retry flow.
    if super::oauth_scope::stdin_is_tty() {
        agent.set_approval_gate(std::sync::Arc::new(
            super::stdin_approval::StdinApprovalGate::new(),
        ));
    }

    let skills_dir = cfg.data_dir.join("skills");
    if skills_dir.is_dir() {
        let _ = agent.load_skills(&skills_dir);
    }

    println!();
    let inbound_id = format!("ask-{}", uuid::Uuid::new_v4());
    let outcome = agent.process_message(message, inbound_id).await;
    // Seal before reporting, and on the error path too: the rows the
    // turn already wrote are real, and a failed turn is exactly the one
    // an operator will want to verify.
    seal_session(&session_log_concrete, "default");
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

async fn send_with_agent_config(
    message: &str,
    agent_cfg: &wirken_gateway::agent_config::AgentConfig,
    cfg: &wirken_gateway::config::GatewayConfig,
) -> Result<()> {
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

    let workspace = cfg.agent_workspace(&agent_cfg.id);
    std::fs::create_dir_all(&workspace)?;

    let session_log_concrete = open_signed_session_log(cfg)?;
    let session_log: std::sync::Arc<dyn wirken_audit::SessionLog> = session_log_concrete.clone();

    let mut agent = Agent::new_with_sandbox(
        agent_cfg.id.clone(),
        workspace.clone(),
        llm_config,
        api_key,
        api_key_credential,
        session_log,
        super::load_sandbox_config(&cfg.data_dir),
    )?;

    // The configured agent's own id, not the literal "default": this
    // is the multi-agent path, and checking a named agent against
    // another agent's grants is the failure this whole argument split
    // exists to prevent.
    agent.set_agent_id(agent_cfg.id.clone());
    let perms = open_permission_store(cfg)?;
    agent.set_permissions(Arc::new(Mutex::new(perms)));

    if super::oauth_scope::stdin_is_tty() {
        agent.set_approval_gate(std::sync::Arc::new(
            super::stdin_approval::StdinApprovalGate::new(),
        ));
    }

    let skills_dir = cfg.agent_skills_dir(&agent_cfg.id);
    if skills_dir.is_dir() {
        let _ = agent.load_skills(&skills_dir);
    }
    // Also load shared skills
    let shared_skills = cfg.data_dir.join("skills");
    if shared_skills.is_dir() {
        let _ = agent.load_skills(&shared_skills);
    }

    // Resolve the persona's preset
    // reference (if any) and merge its declared skills into the
    // agent. The resolver hard-fails on a dangling reference or
    // load failure so a misconfigured persona surfaces as an
    // operator-actionable error rather than as silent skill
    // absence.
    let presets_dir = cfg.data_dir.join("presets");
    let preset_skills = super::persona::resolve_for_construction(agent_cfg, &presets_dir)?;
    if !preset_skills.is_empty() {
        agent
            .extend_with_skills(preset_skills)
            .context("attach preset skills")?;
    }

    println!();
    let inbound_id = format!("ask-{}", uuid::Uuid::new_v4());
    let outcome = agent.process_message(message, inbound_id).await;
    // Seal before reporting, and on the error path too: the rows the
    // turn already wrote are real, and a failed turn is exactly the one
    // an operator will want to verify.
    seal_session(&session_log_concrete, &agent_cfg.id);
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
        let log = open_signed_session_log(&cfg).expect("open");

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
        let log = open_signed_session_log(&cfg).expect("open");
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
