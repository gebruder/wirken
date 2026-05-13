use anyhow::{Context, Result};
use dialoguer::{Input, Password, Select};

use wirken_gateway::agent_config::{AgentConfig, AgentConfigStore, SubagentCeiling};
use wirken_gateway::permissions::PermissionTier;
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::config;

pub async fn add() -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs()?;

    println!();
    println!("  Add a new agent");
    println!();

    let id: String = Input::new()
        .with_prompt("  Agent ID (e.g., work, personal, dev)")
        .interact_text()?;

    let name: String = Input::new()
        .with_prompt("  Display name")
        .default(id.clone())
        .interact_text()?;

    let providers = &["OpenAI", "Anthropic", "Ollama (local)", "Custom endpoint"];
    let provider_idx = Select::new()
        .with_prompt("  LLM provider")
        .items(providers)
        .default(0)
        .interact()?;

    let (provider, model, base_url, needs_key) = match provider_idx {
        0 => {
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("gpt-4o".into())
                .interact_text()?;
            (
                "openai".to_string(),
                model,
                "https://api.openai.com/v1".to_string(),
                true,
            )
        }
        1 => {
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("claude-sonnet-4-20250514".into())
                .interact_text()?;
            (
                "anthropic".to_string(),
                model,
                "https://api.anthropic.com/v1".to_string(),
                true,
            )
        }
        2 => {
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("llama3".into())
                .interact_text()?;
            let url: String = Input::new()
                .with_prompt("  Ollama URL")
                .default("http://localhost:11434/v1".into())
                .interact_text()?;
            ("ollama".to_string(), model, url, false)
        }
        3 => {
            let url: String = Input::new().with_prompt("  API base URL").interact_text()?;
            let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
            ("custom".to_string(), model, url, true)
        }
        _ => unreachable!(),
    };

    // Store API key in vault with agent-specific credential name
    let api_key_credential = if needs_key {
        let api_key = super::read_secret("  API key: ")?;

        let cred_name = format!("{id}-{provider}-key");
        let keychain = probe_keychain(&cfg.data_dir, || {
            Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
        });
        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;

        let secret = VaultSecret::new(api_key);
        let rotation_due = chrono::Utc::now() + chrono::Duration::days(90);
        store
            .store(&cred_name, &provider, &secret, None, Some(rotation_due))
            .context("Failed to store API key")?;

        println!("  API key encrypted as '{cred_name}'.");
        cred_name
    } else {
        String::new()
    };

    // Pick channels to bind
    let adapter_store =
        wirken_gateway::adapter_registry::AdapterRegistry::open(&cfg.adapters_db_path())
            .context("Failed to open adapter registry")?;

    let available_channels: Vec<String> = adapter_store
        .list()
        .into_iter()
        .map(|a| a.channel)
        .collect();

    let channels = if available_channels.is_empty() {
        println!("  No channels configured. Add channels later with `wirken agent bind`.");
        vec![]
    } else {
        let selections = dialoguer::MultiSelect::new()
            .with_prompt("  Bind channels to this agent")
            .items(&available_channels)
            .interact()?;

        selections
            .into_iter()
            .map(|i| available_channels[i].clone())
            .collect()
    };

    // Register the agent
    let agent_store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let agent_config = AgentConfig {
        id: id.clone(),
        name: name.clone(),
        provider,
        model: model.clone(),
        base_url,
        api_key_credential,
        channels: channels.clone(),
        allowed_subagents: Default::default(),
        tools_enabled: None,
        preset: None,
    };

    agent_store
        .register(&agent_config)
        .context(format!("Failed to register agent '{id}'"))?;

    // Create per-agent directories
    std::fs::create_dir_all(cfg.agent_workspace(&id))?;
    std::fs::create_dir_all(cfg.agent_skills_dir(&id))?;

    println!();
    println!("  Agent '{name}' ({id}) registered.");
    println!("  Model: {model}");
    println!("  Workspace: {}", cfg.agent_workspace(&id).display());
    if channels.is_empty() {
        println!("  Channels: none (bind with `wirken agent bind {id} <channel>`)");
    } else {
        println!("  Channels: {}", channels.join(", "));
    }
    println!();

    Ok(())
}

pub async fn list() -> Result<()> {
    let cfg = config();

    let path = cfg.agent_config_db_path();
    if !path.exists() {
        println!("  No agents configured. Run `wirken agent add` or `wirken setup`.");
        return Ok(());
    }

    let store = AgentConfigStore::open(&path).context("Failed to open agent config store")?;

    let agents = store.list().context("Failed to list agents")?;

    if agents.is_empty() {
        println!("  No agents configured.");
        return Ok(());
    }

    println!("  {:12}  {:16}  {:20}  CHANNELS", "ID", "NAME", "MODEL");
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(12),
        "─".repeat(16),
        "─".repeat(20),
        "─".repeat(30)
    );

    for agent in &agents {
        let channels = if agent.channels.is_empty() {
            "(none)".to_string()
        } else {
            agent.channels.join(", ")
        };
        println!(
            "  {:12}  {:16}  {:20}  {}",
            agent.id,
            agent.name,
            format!("{}/{}", agent.provider, agent.model),
            channels,
        );
    }
    println!();

    Ok(())
}

pub async fn remove(id: &str) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    store
        .remove(id)
        .context(format!("Failed to remove agent '{id}'"))?;

    println!("  Agent '{id}' removed.");
    Ok(())
}

pub async fn bind(agent_id: &str, channel: &str) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    // Verify agent exists
    store
        .get(agent_id)
        .context(format!("Agent '{agent_id}' not found"))?;

    store
        .bind_channel(agent_id, channel)
        .context(format!("Failed to bind '{channel}' to '{agent_id}'"))?;

    println!("  Channel '{channel}' bound to agent '{agent_id}'.");
    Ok(())
}

pub async fn allow_subagent(
    parent: &str,
    child: &str,
    tools: &str,
    max_tier: &str,
    max_rounds: usize,
    max_runtime: u64,
) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let parent_cfg = store
        .get(parent)
        .context(format!("Parent agent '{parent}' not found"))?;

    // Verify child agent exists
    store
        .get(child)
        .context(format!("Child agent '{child}' not found"))?;

    let tier = match max_tier {
        "tier1" => PermissionTier::Tier1,
        "tier2" => PermissionTier::Tier2,
        "tier3" => PermissionTier::Tier3,
        other => anyhow::bail!("unknown tier '{other}'; expected tier1, tier2, or tier3"),
    };

    let tool_allowlist: Vec<String> = if tools.is_empty() {
        Vec::new()
    } else {
        tools.split(',').map(|s| s.trim().to_string()).collect()
    };

    let mut ceilings = parent_cfg.allowed_subagents;
    ceilings.insert(
        child.to_string(),
        SubagentCeiling {
            tool_allowlist: tool_allowlist.clone(),
            max_permission_tier: tier,
            max_rounds,
            max_runtime_secs: max_runtime,
        },
    );
    store
        .set_allowed_subagents(parent, &ceilings)
        .context("Failed to update allowed_subagents")?;

    let tools_display = if tool_allowlist.is_empty() {
        "(none)".to_string()
    } else {
        tool_allowlist.join(", ")
    };
    println!("  Agent '{parent}' may now spawn '{child}'.");
    println!("  Tools: {tools_display}");
    println!("  Max tier: {max_tier}");
    println!("  Max rounds: {max_rounds}");
    println!("  Max runtime: {max_runtime}s");
    Ok(())
}

pub async fn deny_subagent(parent: &str, child: &str) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let parent_cfg = store
        .get(parent)
        .context(format!("Parent agent '{parent}' not found"))?;

    let mut ceilings = parent_cfg.allowed_subagents;
    if ceilings.remove(child).is_none() {
        println!("  Agent '{parent}' does not have '{child}' in its allowed subagents.");
        return Ok(());
    }

    store
        .set_allowed_subagents(parent, &ceilings)
        .context("Failed to update allowed_subagents")?;

    println!("  Removed '{child}' from '{parent}' allowed subagents.");
    Ok(())
}

pub async fn set(id: &str, tools_enabled: Option<&str>) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    // Verify agent exists.
    store.get(id).context(format!("Agent '{id}' not found"))?;

    if let Some(val) = tools_enabled {
        let parsed = match val {
            "true" => Some(true),
            "false" => Some(false),
            "auto" => None,
            other => anyhow::bail!(
                "invalid --tools-enabled value '{other}'; expected true, false, or auto"
            ),
        };
        store
            .set_tools_enabled(id, parsed)
            .context("Failed to update tools_enabled")?;
        let display = match parsed {
            Some(true) => "true (tools always on)",
            Some(false) => "false (tools always off)",
            None => "auto (provider default)",
        };
        println!("  Agent '{id}' tools_enabled set to {display}.");
    } else {
        println!("  No settings to change. Use --tools-enabled <true|false|auto>.");
    }

    Ok(())
}
