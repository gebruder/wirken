use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};
use super::{config, data_dir};
use super::channel::register_channel;

pub async fn run(install_service: bool) -> Result<()> {
    println!();
    println!("  wirken setup");
    println!("  ────────────");
    println!();
    println!("  Secure personal AI agent gateway.");
    println!("  This wizard configures your AI provider and messaging channels.");
    println!("  Credentials are encrypted immediately — never stored in plaintext.");
    println!();

    let cfg = config();
    let data = data_dir()?;

    // --- Step 1: AI Provider ---

    println!("  Step 1: Pick your AI");
    println!();

    let providers = &["OpenAI", "Anthropic", "Ollama (local)", "Custom endpoint"];
    let provider_idx = Select::new()
        .with_prompt("  Provider")
        .items(providers)
        .default(0)
        .interact()?;

    let (provider_name, model, base_url, needs_key) = match provider_idx {
        0 => {
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("gpt-4o".into())
                .interact_text()?;
            ("openai".to_string(), model, "https://api.openai.com/v1".to_string(), true)
        }
        1 => {
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("claude-sonnet-4-20250514".into())
                .interact_text()?;
            ("anthropic".to_string(), model, "https://api.anthropic.com/v1".to_string(), true)
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
            let url: String = Input::new()
                .with_prompt("  API base URL")
                .interact_text()?;
            let model: String = Input::new()
                .with_prompt("  Model ID")
                .interact_text()?;
            let has_key = Confirm::new()
                .with_prompt("  Requires API key?")
                .default(true)
                .interact()?;
            ("custom".to_string(), model, url, has_key)
        }
        _ => unreachable!(),
    };

    // Store API key in vault
    if needs_key {
        let api_key = Password::new()
            .with_prompt("  API key")
            .interact()?;

        println!("  Encrypting API key...");

        let keychain = probe_keychain(&data, || {
            Password::new()
                .with_prompt("  Vault passphrase (for encrypting credentials)")
                .interact()
                .unwrap_or_default()
        });

        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;

        let secret = VaultSecret::new(api_key);
        let rotation_due = chrono::Utc::now() + chrono::Duration::days(90);
        store.store(
            &format!("{provider_name}-api-key"),
            &provider_name,
            &secret,
            None,
            Some(rotation_due),
        ).context("Failed to store API key")?;

        println!("  API key encrypted and stored.");
    }

    // Save provider config
    let provider_config = serde_json::json!({
        "provider": provider_name,
        "model": model,
        "base_url": base_url,
    });
    let config_path = data.join("provider.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&provider_config)?)?;

    println!();

    // --- Step 2: Channels ---

    println!("  Step 2: Pick your channels");
    println!();

    let channels = &["Telegram", "Discord", "Slack", "Skip for now"];
    let mut selected_channels = Vec::new();

    loop {
        let channel_idx = Select::new()
            .with_prompt("  Add a channel")
            .items(channels)
            .default(0)
            .interact()?;

        match channel_idx {
            0 => {
                setup_telegram_channel(&cfg, &data).await?;
                selected_channels.push("telegram");
            }
            1 => {
                setup_discord_channel(&cfg, &data).await?;
                selected_channels.push("discord");
            }
            2 => {
                setup_slack_channel(&cfg, &data).await?;
                selected_channels.push("slack");
            }
            3 => break,
            _ => unreachable!(),
        }

        if !Confirm::new()
            .with_prompt("  Add another channel?")
            .default(false)
            .interact()?
        {
            break;
        }
    }

    println!();

    // --- Step 3: Service installation ---

    let should_install = if install_service {
        true
    } else {
        Confirm::new()
            .with_prompt("  Install as a system service (starts on login)?")
            .default(true)
            .interact()?
    };

    if should_install {
        println!();
        let exe = std::env::current_exe().context("Failed to determine binary path")?;
        if let Err(e) = super::service::install_service(&exe, &data) {
            println!("  Warning: service installation failed: {e}");
            println!("  You can start manually with: wirken run");
        }
    }

    // --- Done ---

    println!();
    println!("  Setup complete!");
    println!();
    println!("  Provider: {} ({})", provider_name, model);
    if selected_channels.is_empty() {
        println!("  Channels: none (add later with `wirken channel add`)");
    } else {
        println!("  Channels: {}", selected_channels.join(", "));
    }
    println!();
    println!("  Your credentials are encrypted in {}", cfg.vault_db_path().display());
    println!("  Audit log at {}", cfg.audit_db_path().display());
    println!();
    if should_install {
        println!("  The gateway is running as a service.");
        println!("  Manage with: wirken setup --uninstall-service");
    } else {
        println!("  Start the gateway: wirken run");
    }
    println!();

    Ok(())
}

async fn setup_telegram_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let bot_token = Password::new()
        .with_prompt("  Telegram bot token")
        .interact()?;

    register_channel("telegram", &bot_token, cfg, data).await
}

async fn setup_discord_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let bot_token = Password::new()
        .with_prompt("  Discord bot token")
        .interact()?;

    register_channel("discord", &bot_token, cfg, data).await
}

async fn setup_slack_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let app_token = Password::new()
        .with_prompt("  Slack app token (xapp-...)")
        .interact()?;

    register_channel("slack", &app_token, cfg, data).await
}
