use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use super::channel::register_channel;
use super::{config, data_dir};
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

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

    let providers = &[
        "OpenAI",
        "Anthropic",
        "Google Gemini",
        "AWS Bedrock",
        "Tinfoil (confidential)",
        "Privatemode (confidential)",
        "Ollama (local)",
        "Custom endpoint",
    ];
    let provider_idx = Select::new()
        .with_prompt("  Provider")
        .items(providers)
        .default(0)
        .interact()?;

    let mut region: Option<String> = None;

    let (provider_name, model, base_url, needs_key) = match provider_idx {
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
                .default("gemini-2.0-flash".into())
                .interact_text()?;
            (
                "gemini".to_string(),
                model,
                "https://generativelanguage.googleapis.com/v1beta".to_string(),
                true,
            )
        }
        3 => {
            let model: String = Input::new()
                .with_prompt("  Model ID")
                .default("anthropic.claude-sonnet-4-20250514-v2:0".into())
                .interact_text()?;
            let r: String = Input::new()
                .with_prompt("  AWS region")
                .default("us-east-1".into())
                .interact_text()?;
            let base = format!("https://bedrock-runtime.{r}.amazonaws.com");
            println!("  Bedrock uses AWS credentials (access key ID : secret access key).");
            region = Some(r);
            ("bedrock".to_string(), model, base, true)
        }
        4 => {
            println!(
                "  Tinfoil runs open-source LLMs inside hardware enclaves (AMD SEV-SNP + NVIDIA H100)."
            );
            println!("  Get an API key at https://dash.tinfoil.sh");
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("llama3-3-70b".into())
                .interact_text()?;
            (
                "openai".to_string(), // OpenAI-compatible API
                model,
                "https://inference.tinfoil.sh/v1".to_string(),
                true,
            )
        }
        5 => {
            println!(
                "  Privatemode runs open-source LLMs inside confidential enclaves (AMD SEV-SNP + Intel TDX)."
            );
            println!("  Get an API key at https://www.privatemode.ai");
            let model: String = Input::new()
                .with_prompt("  Model")
                .default("gpt-oss-120b".into())
                .interact_text()?;
            (
                "openai".to_string(), // OpenAI-compatible API
                model,
                "https://api.privatemode.ai/v1".to_string(),
                true,
            )
        }
        6 => {
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
        7 => {
            let url: String = Input::new().with_prompt("  API base URL").interact_text()?;
            let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
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
        let api_key = if provider_name == "bedrock" {
            let access_key: String = Input::new()
                .with_prompt("  AWS Access Key ID")
                .interact_text()?;
            let secret_key = Password::new()
                .with_prompt("  AWS Secret Access Key")
                .interact()?;
            format!("{access_key}:{secret_key}")
        } else {
            Password::new().with_prompt("  API key").interact()?
        };

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
        store
            .store(
                &format!("{provider_name}-api-key"),
                &provider_name,
                &secret,
                None,
                Some(rotation_due),
            )
            .context("Failed to store API key")?;

        println!("  API key encrypted and stored.");
    }

    // Save provider config
    let mut provider_config = serde_json::json!({
        "provider": provider_name,
        "model": model,
        "base_url": base_url,
    });
    if let Some(ref r) = region {
        provider_config["region"] = serde_json::Value::String(r.clone());
    }
    let config_path = data.join("provider.json");
    std::fs::write(
        &config_path,
        serde_json::to_string_pretty(&provider_config)?,
    )?;

    // Install bundled skills
    let skills_dir = data.join("skills");
    match wirken_agent::bundled_skills::install_bundled_skills(&skills_dir) {
        Ok(n) if n > 0 => println!("  Installed {n} bundled skills."),
        Ok(_) => {}
        Err(e) => println!("  Warning: could not install bundled skills: {e}"),
    }

    println!();

    // --- Step 2: Channels ---

    println!("  Step 2: Pick your channels");
    println!();

    let channels = &[
        "Telegram",
        "Discord",
        "Slack",
        "Microsoft Teams",
        "Matrix",
        "Skip for now",
    ];
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
            3 => {
                setup_teams_channel(&cfg, &data).await?;
                selected_channels.push("teams");
            }
            4 => {
                setup_matrix_channel(&cfg, &data).await?;
                selected_channels.push("matrix");
            }
            5 => break,
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
    println!(
        "  Your credentials are encrypted in {}",
        cfg.vault_db_path().display()
    );
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
    let bot_token = Password::new()
        .with_prompt("  Slack bot token (xoxb-...)")
        .interact()?;

    let app_token = Password::new()
        .with_prompt("  Slack app token (xapp-...)")
        .interact()?;

    // Register with the bot token as the primary
    register_channel("slack", &bot_token, cfg, data).await?;

    // Store the app token separately (Socket Mode needs both)
    let keychain = wirken_vault::probe_keychain(data, String::new);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    let secret = wirken_vault::VaultSecret::new(app_token);
    store
        .store("slack-app-token", "slack", &secret, None, None)
        .context("Failed to store Slack app token")?;

    println!("  slack: both tokens encrypted.");
    Ok(())
}

async fn setup_teams_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let app_id: String = dialoguer::Input::new()
        .with_prompt("  Microsoft App ID")
        .interact_text()?;

    let app_password = Password::new()
        .with_prompt("  Microsoft App Password")
        .interact()?;

    // Register with the app password as the primary token
    register_channel("teams", &app_password, cfg, data).await?;

    // Store the app ID separately
    let keychain = wirken_vault::probe_keychain(data, String::new);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    let secret = wirken_vault::VaultSecret::new(app_id);
    store
        .store("teams-app-id", "teams", &secret, None, None)
        .context("Failed to store Teams app ID")?;

    println!("  teams: app ID and password encrypted.");
    Ok(())
}

async fn setup_matrix_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let homeserver: String = dialoguer::Input::new()
        .with_prompt("  Homeserver URL (e.g., https://matrix.org)")
        .interact_text()?;

    let username: String = dialoguer::Input::new()
        .with_prompt("  Username (e.g., @wirken:matrix.org)")
        .interact_text()?;

    let password = Password::new().with_prompt("  Password").interact()?;

    // Store password as the primary token
    register_channel("matrix", &password, cfg, data).await?;

    // Store homeserver URL and username in vault
    let keychain = wirken_vault::probe_keychain(data, String::new);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let hs_secret = wirken_vault::VaultSecret::new(homeserver);
    store
        .store("matrix-homeserver", "matrix", &hs_secret, None, None)
        .context("Failed to store homeserver URL")?;

    let user_secret = wirken_vault::VaultSecret::new(username);
    store
        .store("matrix-username", "matrix", &user_secret, None, None)
        .context("Failed to store username")?;

    println!("  matrix: credentials encrypted, E2EE enabled.");
    Ok(())
}
