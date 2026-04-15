use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use super::channel::register_channel;
use super::{config, data_dir};
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

pub async fn run(install_service: bool, org_url: Option<String>) -> Result<()> {
    println!();
    println!("  wirken setup");
    println!("  ────────────");
    println!();

    let cfg = config();
    let data = data_dir()?;

    // --- Org config (if provided) ---

    let org_applied = if let Some(ref url) = org_url {
        println!("  Fetching organization config from {url}...");
        match wirken_gateway::org::fetch_org_config(url).await {
            Ok(org) => {
                wirken_gateway::org::save_org_url(&data, url).context("Failed to save org URL")?;
                match wirken_gateway::org::apply_org_config(&data, &org, false) {
                    Ok(applied) => {
                        for item in &applied {
                            println!("  Applied org {item} config.");
                        }
                        if let Some(ref key_name) = org.api_key_name {
                            // Check if the API key credential already exists
                            let keychain = probe_keychain(&data, || {
                                Password::new()
                                    .with_prompt("  Vault passphrase (for encrypting credentials)")
                                    .interact()
                                    .unwrap_or_default()
                            });
                            let store =
                                CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
                                    .context("Failed to open credential store")?;
                            if store.retrieve(key_name).is_err() {
                                let api_key = super::read_secret("  API key: ")?;
                                let secret = VaultSecret::new(api_key);
                                let provider = org
                                    .provider
                                    .as_ref()
                                    .and_then(|p| p.get("provider"))
                                    .and_then(|p| p.as_str())
                                    .unwrap_or("default");
                                store.store(key_name, provider, &secret, None, None)?;
                                println!("  API key encrypted and stored.");
                            }
                        }
                        true
                    }
                    Err(e) => {
                        println!("  Warning: failed to apply org config: {e}");
                        false
                    }
                }
            }
            Err(e) => {
                println!("  Warning: failed to fetch org config: {e}");
                println!("  Continuing with manual setup.");
                false
            }
        }
    } else {
        false
    };

    println!("  Credentials are encrypted immediately. Never stored in plaintext.");
    println!();

    // --- Step 1: AI Provider (skip if org config provided it) ---

    if org_applied && data.join("provider.json").exists() {
        println!("  Step 1: AI provider configured by organization.");
    } else {
        println!("  Step 1: Pick your AI");
        println!();

        let providers = &[
            "Ollama (local)",
            "Anthropic",
            "OpenAI",
            "Google Gemini",
            "AWS Bedrock",
            "Tinfoil (confidential)",
            "Privatemode (confidential)",
            "Custom endpoint",
        ];
        let provider_idx = Select::new()
            .with_prompt("  Provider")
            .items(providers)
            .default(0)
            .interact()?;

        let mut region: Option<String> = None;

        // Helper: ask for key, list models, store key, return (provider, model, url)
        // Used by all cloud providers for a consistent key → model → encrypt flow.
        let store_key_and_pick_model = |api_key: String,
                                        provider_name: &str,
                                        _base_url: &str,
                                        default_model: &str,
                                        models: Vec<String>,
                                        cfg: &wirken_gateway::config::GatewayConfig,
                                        data: &std::path::Path|
         -> Result<String> {
            println!("  Encrypting API key...");
            let keychain = probe_keychain(data, || {
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
                provider_name,
                &secret,
                None,
                Some(rotation_due),
            )?;
            println!("  API key encrypted and stored.");
            let model = if models.is_empty() {
                Input::new()
                    .with_prompt("  Model")
                    .default(default_model.into())
                    .interact_text()?
            } else {
                let idx = Select::new()
                    .with_prompt("  Model")
                    .items(&models)
                    .default(0)
                    .interact()?;
                models[idx].clone()
            };
            Ok(model)
        };

        let (provider_name, model, base_url, needs_key) = match provider_idx {
            0 => {
                // Ollama
                let url = "http://localhost:11434/v1".to_string();
                match super::probe_ollama_version(&url).await {
                    Some(version) => println!("  Ollama {version} detected."),
                    None => {
                        println!("  Warning: could not reach Ollama. Is it running?");
                    }
                }
                let models = super::list_ollama_models(&url).await;
                let model = if models.is_empty() {
                    Input::new()
                        .with_prompt("  Model")
                        .default("llama3".into())
                        .interact_text()?
                } else {
                    let idx = Select::new()
                        .with_prompt("  Model")
                        .items(&models)
                        .default(0)
                        .interact()?;
                    models[idx]
                        .strip_suffix(":latest")
                        .unwrap_or(&models[idx])
                        .to_string()
                };
                ("ollama".to_string(), model, url, false)
            }
            1 => {
                // Anthropic
                let api_key = super::read_secret("  API key: ")?;
                let models = super::list_anthropic_models(&api_key).await;
                let model = store_key_and_pick_model(
                    api_key,
                    "anthropic",
                    "https://api.anthropic.com/v1",
                    "claude-sonnet-4-20250514",
                    models,
                    &cfg,
                    &data,
                )?;
                (
                    "anthropic".to_string(),
                    model,
                    "https://api.anthropic.com/v1".to_string(),
                    false,
                )
            }
            2 => {
                // OpenAI
                let api_key = super::read_secret("  API key: ")?;
                let models = super::list_openai_models("https://api.openai.com/v1", &api_key).await;
                let model = store_key_and_pick_model(
                    api_key,
                    "openai",
                    "https://api.openai.com/v1",
                    "gpt-4.1-mini",
                    models,
                    &cfg,
                    &data,
                )?;
                (
                    "openai".to_string(),
                    model,
                    "https://api.openai.com/v1".to_string(),
                    false,
                )
            }
            3 => {
                // Google Gemini
                let api_key = super::read_secret("  API key: ")?;
                let models = super::list_gemini_models(&api_key).await;
                let model = store_key_and_pick_model(
                    api_key,
                    "gemini",
                    "https://generativelanguage.googleapis.com/v1beta",
                    "gemini-2.0-flash",
                    models,
                    &cfg,
                    &data,
                )?;
                (
                    "gemini".to_string(),
                    model,
                    "https://generativelanguage.googleapis.com/v1beta".to_string(),
                    false,
                )
            }
            4 => {
                // AWS Bedrock
                let r: String = Input::new()
                    .with_prompt("  AWS region")
                    .default("us-east-1".into())
                    .interact_text()?;
                let base = format!("https://bedrock-runtime.{r}.amazonaws.com");
                println!("  Bedrock uses AWS credentials (access key ID : secret access key).");
                let model: String = Input::new()
                    .with_prompt("  Model ID")
                    .default("anthropic.claude-sonnet-4-20250514-v2:0".into())
                    .interact_text()?;
                region = Some(r);
                ("bedrock".to_string(), model, base, true)
            }
            5 => {
                // Tinfoil
                println!(
                    "  Tinfoil runs open-source LLMs inside hardware enclaves (AMD SEV-SNP + NVIDIA H100)."
                );
                println!("  Direct HTTPS mode (no Rust SDK). Attestation is verifiable via");
                println!("  transparency logs but not checked client-side.");
                println!("  Get an API key at https://dash.tinfoil.sh");
                let api_key = super::read_secret("  API key: ")?;
                let models =
                    super::list_openai_models("https://inference.tinfoil.sh/v1", &api_key).await;
                let model = store_key_and_pick_model(
                    api_key,
                    "openai",
                    "https://inference.tinfoil.sh/v1",
                    "llama3-3-70b",
                    models,
                    &cfg,
                    &data,
                )?;
                (
                    "openai".to_string(),
                    model,
                    "https://inference.tinfoil.sh/v1".to_string(),
                    false,
                )
            }
            6 => {
                // Privatemode
                println!(
                    "  Privatemode runs open-source LLMs inside confidential enclaves (AMD SEV-SNP + Intel TDX)."
                );
                println!("  The local proxy handles attestation and end-to-end encryption.");
                println!("  Start it first:");
                println!(
                    "    docker run -p 8080:8080 ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest --apiKey <key>"
                );
                println!("  Get an API key at https://www.privatemode.ai");
                println!();
                let proxy_url: String = Input::new()
                    .with_prompt("  Proxy URL")
                    .default("http://localhost:8080".into())
                    .interact_text()?;
                let base_url = format!("{}/v1", proxy_url.trim_end_matches('/'));
                let models = super::list_openai_models(&base_url, "").await;
                let model = if models.is_empty() {
                    Input::new()
                        .with_prompt("  Model")
                        .default("gpt-oss-120b".into())
                        .interact_text()?
                } else {
                    let idx = Select::new()
                        .with_prompt("  Model")
                        .items(&models)
                        .default(0)
                        .interact()?;
                    models[idx].clone()
                };
                ("openai".to_string(), model, base_url, false)
            }
            7 => {
                // Custom
                let url: String = Input::new().with_prompt("  API base URL").interact_text()?;
                let has_key = Confirm::new()
                    .with_prompt("  Requires API key?")
                    .default(true)
                    .interact()?;
                let model = if has_key {
                    let api_key = super::read_secret("  API key: ")?;
                    let models = super::list_openai_models(&url, &api_key).await;
                    store_key_and_pick_model(
                        api_key, "custom", &url, "default", models, &cfg, &data,
                    )?
                } else {
                    Input::new().with_prompt("  Model ID").interact_text()?
                };
                ("custom".to_string(), model, url, false)
            }
            _ => unreachable!(),
        };

        // Store API key in vault
        if needs_key {
            let api_key = if provider_name == "bedrock" {
                let access_key: String = Input::new()
                    .with_prompt("  AWS Access Key ID")
                    .interact_text()?;
                let secret_key = super::read_secret("  AWS Secret Access Key: ")?;
                format!("{access_key}:{secret_key}")
            } else {
                super::read_secret("  API key: ")?
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
    } // end of else (manual provider setup)

    // Install bundled skills (always, regardless of org config)
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
        "Signal",
        "Google Chat",
        "iMessage (BlueBubbles)",
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
            5 => {
                setup_signal_channel(&cfg, &data).await?;
                selected_channels.push("signal");
            }
            6 => {
                setup_google_chat_channel(&cfg, &data).await?;
                selected_channels.push("google-chat");
            }
            7 => {
                setup_imessage_channel(&cfg, &data).await?;
                selected_channels.push("imessage");
            }
            8 => break,
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
    // Read provider info from the saved config (works for both org and manual setup)
    let provider_summary = std::fs::read_to_string(data.join("provider.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| {
            format!(
                "{} ({})",
                v["provider"].as_str().unwrap_or("unknown"),
                v["model"].as_str().unwrap_or("unknown")
            )
        })
        .unwrap_or_else(|| "not configured".into());
    println!("  Provider: {provider_summary}");
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
    let bot_token = super::read_secret("  Telegram bot token: ")?;

    register_channel("telegram", &bot_token, cfg, data).await
}

async fn setup_discord_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let bot_token = super::read_secret("  Discord bot token: ")?;

    register_channel("discord", &bot_token, cfg, data).await
}

async fn setup_slack_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    let bot_token = super::read_secret("  Slack bot token (xoxb-...): ")?;

    let app_token = super::read_secret("  Slack app token (xapp-...): ")?;

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

    let app_password = super::read_secret("  Microsoft App Password: ")?;

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

    let password = super::read_secret("  Password: ")?;

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

async fn setup_signal_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    println!("  Signal requires signal-cli running as a JSON-RPC daemon.");
    println!("  See docs/channels/signal.md for the full setup and threat model.");

    let phone: String = dialoguer::Input::new()
        .with_prompt("  Registered phone number (e.g., +15551234567)")
        .interact_text()?;

    let endpoint: String = dialoguer::Input::new()
        .with_prompt("  signal-cli JSON-RPC endpoint")
        .default("http://127.0.0.1:8080/api/v1/rpc".into())
        .interact_text()?;

    println!();
    println!("  Sender allowlist (REQUIRED):");
    println!("  Only messages from these senders will reach the agent.");
    println!("  Enter E.164 phone numbers for DMs and/or Signal group IDs,");
    println!("  comma-separated. Leave empty to drop every inbound message.");
    let allowlist_csv: String = dialoguer::Input::new()
        .with_prompt("  Allowed senders (comma-separated)")
        .allow_empty(true)
        .interact_text()?;

    let allowlist_trimmed = allowlist_csv.trim();
    if allowlist_trimmed.is_empty() {
        println!(
            "  Warning: empty allowlist. The Signal adapter will drop every \
             inbound message until you add entries via `wirken vault set \
             signal-allowed-senders`."
        );
    } else {
        let count = allowlist_trimmed
            .split(',')
            .filter(|e| !e.trim().is_empty())
            .count();
        println!("  signal: allowlist configured with {count} entries.");
    }

    // Use endpoint as the primary "token" for registration
    register_channel("signal", &endpoint, cfg, data).await?;

    let keychain = wirken_vault::probe_keychain(data, String::new);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let phone_secret = wirken_vault::VaultSecret::new(phone);
    store
        .store("signal-phone-number", "signal", &phone_secret, None, None)
        .context("Failed to store phone number")?;

    let endpoint_secret = wirken_vault::VaultSecret::new(endpoint);
    store
        .store("signal-endpoint", "signal", &endpoint_secret, None, None)
        .context("Failed to store endpoint")?;

    let allowlist_secret = wirken_vault::VaultSecret::new(allowlist_trimmed.to_string());
    store
        .store(
            "signal-allowed-senders",
            "signal",
            &allowlist_secret,
            None,
            None,
        )
        .context("Failed to store allowlist")?;

    println!("  signal: credentials encrypted.");
    Ok(())
}

async fn setup_google_chat_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    println!("  Google Chat bots use a service account for API access.");
    println!("  Create a bot at https://developers.google.com/workspace/chat");

    let token = super::read_secret("  Service account bearer token: ")?;

    register_channel("google-chat", &token, cfg, data).await?;

    println!("  google-chat: token encrypted.");
    Ok(())
}

async fn setup_imessage_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    println!("  iMessage requires BlueBubbles Server running on a Mac.");
    println!("  See https://bluebubbles.app for setup.");

    let server_password = super::read_secret("  BlueBubbles server password: ")?;

    let bb_url: String = dialoguer::Input::new()
        .with_prompt("  BlueBubbles server URL")
        .default("http://localhost:1234".into())
        .interact_text()?;

    // Use server password as primary token
    register_channel("imessage", &server_password, cfg, data).await?;

    let keychain = wirken_vault::probe_keychain(data, String::new);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let url_secret = wirken_vault::VaultSecret::new(bb_url);
    store
        .store(
            "imessage-bluebubbles-url",
            "imessage",
            &url_secret,
            None,
            None,
        )
        .context("Failed to store BlueBubbles URL")?;

    let pw_secret = wirken_vault::VaultSecret::new(server_password);
    store
        .store(
            "imessage-server-password",
            "imessage",
            &pw_secret,
            None,
            None,
        )
        .context("Failed to store server password")?;

    println!("  imessage: credentials encrypted.");
    Ok(())
}
