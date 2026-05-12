use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use wirken_agent::Agent;
use wirken_agent::llm::LlmConfig;
use wirken_gateway::agent_config::AgentConfigStore;
use wirken_gateway::permissions::PermissionStore;
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

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
            "Agent '{agent_id}' not found. Run `wirken agents add` or use --agent default."
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

    let session_log: std::sync::Arc<dyn wirken_audit::SessionLog> = std::sync::Arc::new(
        wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    );

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
    let perms = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;
    agent.set_permissions(Arc::new(Mutex::new(perms)));

    let skills_dir = cfg.data_dir.join("skills");
    if skills_dir.is_dir() {
        let _ = agent.load_skills(&skills_dir);
    }

    println!();
    let inbound_id = format!("ask-{}", uuid::Uuid::new_v4());
    match agent.process_message(message, inbound_id).await {
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
    let mut llm_config =
        LlmConfig::from_provider(&agent_cfg.provider, &agent_cfg.base_url, &agent_cfg.model);
    if agent_cfg.provider == "bedrock" {
        llm_config.region = agent_cfg
            .base_url
            .strip_prefix("https://bedrock-runtime.")
            .and_then(|s| s.strip_suffix(".amazonaws.com"))
            .map(String::from);
    }

    // Stamp the slot name on `LlmRequest` / `LlmResponse` emits for
    // SIEM correlation. Empty `api_key_credential` on the agent
    // config means no vault lookup, so no slot name to carry.
    let api_key_credential = if agent_cfg.api_key_credential.is_empty() {
        None
    } else {
        Some(agent_cfg.api_key_credential.clone())
    };
    let api_key = if !agent_cfg.api_key_credential.is_empty() {
        let keychain = probe_keychain(&cfg.data_dir, || {
            dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
        });
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

    let session_log: std::sync::Arc<dyn wirken_audit::SessionLog> = std::sync::Arc::new(
        wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?,
    );

    let mut agent = Agent::new_with_sandbox(
        agent_cfg.id.clone(),
        workspace.clone(),
        llm_config,
        api_key,
        api_key_credential,
        session_log,
        super::load_sandbox_config(&cfg.data_dir),
    )?;

    let perms = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;
    agent.set_permissions(Arc::new(Mutex::new(perms)));

    let skills_dir = cfg.agent_skills_dir(&agent_cfg.id);
    if skills_dir.is_dir() {
        let _ = agent.load_skills(&skills_dir);
    }
    // Also load shared skills
    let shared_skills = cfg.data_dir.join("skills");
    if shared_skills.is_dir() {
        let _ = agent.load_skills(&shared_skills);
    }

    println!();
    let inbound_id = format!("ask-{}", uuid::Uuid::new_v4());
    match agent.process_message(message, inbound_id).await {
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
