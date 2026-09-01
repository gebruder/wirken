use anyhow::{Context, Result};
use dialoguer::{Input, Password, Select};

use wirken_gateway::agent_config::{AgentConfig, AgentConfigStore, ChannelEgress, SubagentCeiling};
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

    // The key comes before the model because the model list comes from
    // the provider, and asking for it needs the key. Nothing here
    // carries a model name of its own: a name written into this file
    // is a guess about someone else's catalogue that goes stale
    // silently, and an operator who accepts the offered default gets a
    // model that 404s at the first turn rather than at config time.
    let (provider, base_url, needs_key) = match provider_idx {
        0 => (
            "openai".to_string(),
            "https://api.openai.com/v1".to_string(),
            true,
        ),
        1 => (
            "anthropic".to_string(),
            "https://api.anthropic.com/v1".to_string(),
            true,
        ),
        2 => {
            let url: String = Input::new()
                .with_prompt("  Ollama URL")
                .default("http://localhost:11434/v1".into())
                .interact_text()?;
            ("ollama".to_string(), url, false)
        }
        3 => {
            let url: String = Input::new().with_prompt("  API base URL").interact_text()?;
            ("custom".to_string(), url, true)
        }
        _ => unreachable!(),
    };

    let api_key = if needs_key {
        Some(super::read_secret("  API key: ")?)
    } else {
        None
    };

    let models = match provider.as_str() {
        "openai" => super::list_openai_models(&base_url, api_key.as_deref().unwrap_or("")).await,
        "anthropic" => super::list_anthropic_models(api_key.as_deref().unwrap_or("")).await,
        "ollama" => super::list_ollama_models(&base_url).await,
        _ => super::list_openai_compatible_models(&base_url, api_key.as_deref().unwrap_or(""))
            .await
            .unwrap_or_default(),
    };

    let model = super::pick_model(models)?;

    // Store API key in vault with agent-specific credential name
    let api_key_credential = if let Some(api_key) = api_key {
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
        println!("  No channels configured. Add channels later with `wirken agents bind`.");
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
        // No sandbox egress for any channel. Operators grant it
        // explicitly per channel; a newly registered agent starts
        // with none.
        channel_egress: Default::default(),
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
        println!("  Channels: none (bind with `wirken agents bind {id} <channel>`)");
    } else {
        let display: Vec<&str> = channels
            .iter()
            .map(|id| super::channel::display_name(id))
            .collect();
        println!("  Channels: {}", display.join(", "));
    }
    println!();

    Ok(())
}

pub async fn list() -> Result<()> {
    let cfg = config();

    let path = cfg.agent_config_db_path();
    if !path.exists() {
        println!("  No agents configured. Run `wirken agents add` or `wirken setup`.");
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
        // Only channels with a granted egress policy are listed. A
        // channel with no entry has no sandbox egress, which is the
        // default and not worth a line each.
        for (chan, egress) in &agent.channel_egress {
            if egress.mode == "none" {
                continue;
            }
            let scope = if egress.domains.is_empty() {
                String::new()
            } else {
                format!(" [{}]", egress.domains.join(", "))
            };
            println!("  {:12}  └─ egress {chan}: {}{scope}", "", egress.mode);
        }
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

pub async fn set(
    id: &str,
    tools_enabled: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
    replace_api_key: bool,
) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    // Verify agent exists.
    let existing = store.get(id).context(format!("Agent '{id}' not found"))?;

    let mut changed = false;

    // Model, base url and key live on the agent row and had no route
    // to them: an operator whose provider retired a model, or who
    // rotated a key, had to remove the agent and add it back, losing
    // its channel bindings and subagent ceilings with it.
    if model.is_some() || base_url.is_some() {
        let mut updated = existing.clone();
        if let Some(url) = base_url {
            updated.base_url = url.to_string();
        }
        if let Some(m) = model {
            // `--model list` asks the provider rather than taking the
            // literal word as an id.
            updated.model = if m == "list" {
                let key = resolve_api_key(&cfg, &existing.api_key_credential);
                let models = match updated.provider.as_str() {
                    "openai" => {
                        super::list_openai_models(&updated.base_url, key.as_deref().unwrap_or(""))
                            .await
                    }
                    "anthropic" => super::list_anthropic_models(key.as_deref().unwrap_or("")).await,
                    "ollama" => super::list_ollama_models(&updated.base_url).await,
                    _ => super::list_openai_compatible_models(
                        &updated.base_url,
                        key.as_deref().unwrap_or(""),
                    )
                    .await
                    .unwrap_or_default(),
                };
                super::pick_model(models)?
            } else {
                m.to_string()
            };
        }
        store
            .update(&updated)
            .context("Failed to update agent model or base url")?;
        println!(
            "  Agent '{id}' now runs {}/{} at {}.",
            updated.provider, updated.model, updated.base_url
        );
        changed = true;
    }

    if replace_api_key {
        let api_key = super::read_secret("  New API key: ")?;
        // Reuse the credential name already on the row when there is
        // one, so the vault entry the gateway resolves is the entry
        // that gets replaced. A row with none gets the same name
        // `agents add` would have given it.
        let cred_name = if existing.api_key_credential.is_empty() {
            format!("{id}-{}-key", existing.provider)
        } else {
            existing.api_key_credential.clone()
        };
        let keychain = probe_keychain(&cfg.data_dir, || {
            Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
        });
        let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;
        let secret = VaultSecret::new(api_key);
        let rotation_due = chrono::Utc::now() + chrono::Duration::days(90);
        vault
            .store(
                &cred_name,
                &existing.provider,
                &secret,
                None,
                Some(rotation_due),
            )
            .context("Failed to store API key")?;
        if existing.api_key_credential != cred_name {
            let mut updated = store.get(id).context("Failed to re-read agent")?;
            updated.api_key_credential = cred_name.clone();
            store
                .update(&updated)
                .context("Failed to record the credential name")?;
        }
        println!("  Agent '{id}' API key replaced in '{cred_name}'.");
        changed = true;
    }

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
        changed = true;
    }

    if !changed {
        println!(
            "  No settings to change. Use --model, --base-url, --api-key, \
             or --tools-enabled <true|false|auto>."
        );
    }

    Ok(())
}

/// Read an agent's API key out of the vault for a model listing.
///
/// Best effort: a locked vault, a missing entry or a row with no
/// credential all yield `None`, and the listing then comes back empty
/// and the operator types the id. Not being able to list is not a
/// reason to refuse the command.
fn resolve_api_key(
    cfg: &wirken_gateway::config::GatewayConfig,
    credential: &str,
) -> Option<String> {
    if credential.is_empty() {
        return None;
    }
    let keychain = probe_keychain(&cfg.data_dir, String::new);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()).ok()?;
    let (secret, _) = store.retrieve(credential).ok()?;
    Some(secret.expose().to_string())
}

/// Grant or revoke sandbox egress for one of an agent's channels.
///
/// Validation is strict here on purpose. The runtime resolver fails
/// closed on anything it does not recognize, which is the right
/// behaviour in the hot path but the wrong behaviour at config time:
/// an operator who mistypes a mode should get an error, not a silently
/// denied channel that looks configured.
pub async fn set_egress(id: &str, channel: &str, mode: &str, domains: Option<&str>) -> Result<()> {
    let cfg = config();
    let store = AgentConfigStore::open(&cfg.agent_config_db_path())
        .context("Failed to open agent config store")?;

    let agent = store.get(id).context(format!("Agent '{id}' not found"))?;

    if !agent.channels.iter().any(|c| c == channel) {
        anyhow::bail!(
            "channel '{channel}' is not bound to agent '{id}' (bound: {}). \
             Bind it first with `wirken agents bind {id} {channel}`, or fix the \
             channel name; egress on an unbound channel would never take effect",
            if agent.channels.is_empty() {
                "none".to_string()
            } else {
                agent.channels.join(", ")
            },
        );
    }

    let mode = match mode {
        "none" | "allowlist" | "open" => mode,
        other => anyhow::bail!("invalid --mode '{other}'; expected none, allowlist, or open"),
    };

    let parsed: Vec<String> = domains
        .map(|d| {
            d.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if mode != "allowlist" && !parsed.is_empty() {
        anyhow::bail!(
            "--domains is only meaningful with --mode allowlist; mode '{mode}' ignores it"
        );
    }
    if mode == "allowlist" && parsed.is_empty() {
        anyhow::bail!(
            "--mode allowlist needs --domains; an empty allowlist denies everything, \
             which is what --mode none already says more clearly"
        );
    }
    for d in &parsed {
        validate_egress_domain(d)?;
    }
    if parsed.iter().any(|d| d == "*") && parsed.len() > 1 {
        anyhow::bail!("--domains cannot mix the '*' wildcard with specific hosts");
    }

    let mut channel_egress = agent.channel_egress.clone();
    channel_egress.insert(
        channel.to_string(),
        ChannelEgress {
            mode: mode.to_string(),
            domains: parsed.clone(),
        },
    );
    store
        .set_channel_egress(id, &channel_egress)
        .context("Failed to update channel egress")?;

    match mode {
        "none" => println!("  Agent '{id}' channel '{channel}': no sandbox egress."),
        "open" => println!(
            "  Agent '{id}' channel '{channel}': egress OPEN (any domain, \
             443/80 only, IP literals refused)."
        ),
        _ => println!(
            "  Agent '{id}' channel '{channel}': egress allowlist [{}].",
            parsed.join(", ")
        ),
    }
    if mode != "none" {
        println!(
            "  Requires rootful Docker; under a rootless runtime exec is refused \
             rather than run unproxied."
        );
    }

    Ok(())
}

/// Reject anything that cannot work as a sandbox egress allowlist
/// entry. Mirrors the skill-side host rules (no scheme, path,
/// credentials, port, or whitespace) and adds the sandbox-specific
/// one: an IP literal is refused by the proxy before the allowlist is
/// consulted, so allowlisting one is always a silent no-op.
fn validate_egress_domain(s: &str) -> Result<()> {
    if s.is_empty() {
        anyhow::bail!("invalid domain: empty entry");
    }
    if s.contains("://") || s.contains('/') || s.contains('@') || s.contains(':') || s.contains(' ')
    {
        anyhow::bail!(
            "invalid domain '{s}': expected a bare host like example.com or \
             *.example.com, with no scheme, path, port, or credentials"
        );
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
    {
        anyhow::bail!("invalid domain '{s}': only letters, digits, '-', '.', and '*' are allowed");
    }
    if wirken_agent::sandbox_egress::is_ip_literal(s) {
        anyhow::bail!(
            "invalid domain '{s}': sandbox egress matches on domains only, and the \
             proxy refuses IP-literal targets before consulting the allowlist, so \
             this entry could never match"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_egress_domain;

    #[test]
    fn plain_and_wildcard_hosts_accepted() {
        for d in ["example.com", "api.example.com", "*.example.com", "*"] {
            assert!(validate_egress_domain(d).is_ok(), "{d} should be accepted");
        }
    }

    #[test]
    fn ip_literals_rejected_because_the_proxy_never_matches_them() {
        // The proxy refuses IP-literal targets before consulting the
        // allowlist, so accepting one here would store an entry that
        // can never match.
        for d in ["169.254.169.254", "127.0.0.1", "93.184.216.34"] {
            assert!(validate_egress_domain(d).is_err(), "{d} should be rejected");
        }
    }

    #[test]
    fn schemes_ports_paths_and_credentials_rejected() {
        for d in [
            "https://example.com",
            "example.com:8443",
            "example.com/path",
            "user@example.com",
            "exa mple.com",
        ] {
            assert!(validate_egress_domain(d).is_err(), "{d} should be rejected");
        }
    }

    #[test]
    fn empty_domain_rejected() {
        assert!(validate_egress_domain("").is_err());
    }
}
