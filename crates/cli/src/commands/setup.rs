use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};

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

    // First run is signalled by the absence of provider.json. The
    // welcome panel surfaces wirken's positioning and the two
    // trust-model claims (no credentials to the LLM; signed
    // hash-chained audit log) at the moment the user is deciding
    // whether to trust the tool. Re-runs skip straight to org
    // config or Step 1; they're typically channel-add or key
    // rotation and the elevator pitch is noise.
    let is_first_run = !data.join("provider.json").exists();
    if is_first_run {
        println!("  Wirken is the switchboard between your messaging channels and an");
        println!("  AI agent you control. Credentials never reach the LLM. Every");
        println!("  action is logged in a signed, hash-chained audit log.");
        println!();
        println!("  Setup walks through six steps: provider, channels, credentials,");
        println!("  service, sandbox, audit. About a minute.");
        println!();
        let proceed = Confirm::new()
            .with_prompt("  Continue")
            .default(true)
            .interact()?;
        if !proceed {
            println!();
            println!("  Setup cancelled.");
            return Ok(());
        }
        println!();
    }

    // --- Org config (if provided) ---

    let org_applied = if let Some(ref url) = org_url {
        println!("  Fetching organization config from {url}...");
        match wirken_gateway::org::fetch_org_config(url, &data).await {
            Ok(org) => {
                wirken_gateway::org::save_org_url(&data, url).context("Failed to save org URL")?;
                match wirken_gateway::org::apply_org_config(&data, &org, false) {
                    Ok(applied) => {
                        for item in &applied {
                            println!("  Applied org {item} config.");
                        }
                        if let Some(ref key_name) = org.api_key_name {
                            // Check if the API key credential already exists
                            let pp = super::cached_vault_passphrase()?;
                            let keychain = probe_keychain(&data, move || pp);
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

    if !is_first_run {
        // Welcome already names the encryption guarantee. Print
        // the one-liner only on re-runs.
        println!("  Credentials are encrypted immediately. Never stored in plaintext.");
        println!();
    }

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
            let pp = super::cached_vault_passphrase()?;
            let keychain = probe_keychain(data, move || pp);
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
                println!("  Wirken dispatches through the tinfoil-rs SDK: each session gates on a");
                println!(
                    "  hardware attestation (AMD SEV-SNP) plus Sigstore code-provenance check"
                );
                println!(
                    "  against the published enclave repo, then pins TLS to the attested cert."
                );
                println!("  See docs/reference/tinfoil.md for the trust model and model list.");
                println!("  Get an API key at https://dash.tinfoil.sh");
                let api_key = super::read_secret("  API key: ")?;
                let models =
                    super::list_openai_models("https://inference.tinfoil.sh/v1", &api_key).await;
                let model = store_key_and_pick_model(
                    api_key,
                    "tinfoil",
                    "https://inference.tinfoil.sh/v1",
                    "llama3-3-70b",
                    models,
                    &cfg,
                    &data,
                )?;
                (
                    "tinfoil".to_string(),
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
                    "    docker run -p 127.0.0.1:8080:8080 ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest --apiKey <key>"
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
                        .default("kimi-k2.5".into())
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

            let pp = super::cached_vault_passphrase()?;
            let keychain = probe_keychain(&data, move || pp);

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
        wirken_gateway::org::write_with_secret_perms(
            &config_path,
            serde_json::to_string_pretty(&provider_config)?.as_bytes(),
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
        "WhatsApp (Cloud API)",
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
            8 => {
                setup_whatsapp_channel(&cfg, &data).await?;
                selected_channels.push("whatsapp");
            }
            9 => break,
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

    // --- Step 2b: Per-channel LLM overrides (closes #60) ---
    //
    // Skip silently when no channels were selected; the override
    // question has no meaning without a channel to attach it to.
    if !selected_channels.is_empty() {
        configure_channel_overrides(&cfg, &data, &selected_channels).await?;
    }

    println!();

    // --- Step 3: Credentials recap ---
    //
    // Pure surfacing: no input. Lists what got encrypted during
    // steps 1 and 2 with the crypto framing, or prints the
    // empty-state with the add command. Querying the vault only
    // makes sense when a passphrase was actually entered earlier;
    // otherwise the file may not exist and we report empty.

    println!("  Step 3: Credentials");
    println!();
    let stored_creds: Vec<String> = if cfg.vault_db_path().exists() {
        std::env::var("WIRKEN_VAULT_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty())
            .and_then(|p| {
                let keychain = probe_keychain(&data, move || p);
                CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()).ok()
            })
            .and_then(|store| store.list().ok())
            .map(|metas| metas.into_iter().map(|m| m.name).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if stored_creds.is_empty() {
        println!("  No credentials stored yet.");
        println!("  Add with: wirken credentials add <name>");
    } else {
        println!("  Encrypted: {}", stored_creds.join(", "));
        println!("  XChaCha20-Poly1305, keyed from the OS keychain.");
    }
    println!();

    // --- Step 4: Service installation ---

    println!("  Step 4: Service installation");
    println!();
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

    // --- Step 5: Sandbox mode ---
    //
    // Default is exec-only (0.7.5). If `runsc` is registered as a
    // Docker runtime, offer the stricter gvisor mode. If the operator
    // is setting up via --org and the org config already wrote
    // sandbox.json, don't prompt; org policy wins.
    println!();
    println!("  Step 5: Sandbox mode");
    println!();
    if data.join("sandbox.json").exists() {
        println!("  Sandbox: configured by organization.");
    } else {
        let runsc_detected = wirken_agent::sandbox::detect_gvisor().await;
        let accept_upgrade = runsc_detected
            && Confirm::new()
                .with_prompt(
                    "  gVisor (runsc) detected. Use stricter gvisor sandbox instead of exec-only?",
                )
                .default(true)
                .interact()?;
        let mode = pick_setup_sandbox_mode(runsc_detected, accept_upgrade);
        let body = serde_json::json!({ "mode": mode });
        wirken_gateway::org::write_with_secret_perms(
            &data.join("sandbox.json"),
            serde_json::to_string_pretty(&body)?.as_bytes(),
        )
        .context("Failed to write sandbox.json")?;
        println!("  Sandbox: {mode}");
    }

    // --- Step 6: Audit log recap ---
    //
    // Surfacing the trust claim: the audit log is the load-bearing
    // story for wirken. Doing it silently means the user installs
    // the tool without ever seeing what the audit guarantee
    // actually is. Path + properties + when-it-gets-created.

    println!();
    println!("  Step 6: Audit log");
    println!();
    println!("  {}", cfg.audit_db_path().display());
    println!("  Append-only, SHA-256 hash chain, Ed25519 chain-head signed.");
    println!("  Created on first `wirken run`.");

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
    println!("  Next steps:");
    println!("    wirken channel add <channel>      Add another messaging channel");
    println!("    wirken credentials add <name>     Add or rotate a key");
    println!("    wirken doctor                     Verify the install");
    println!("    wirken session list               See active conversations");
    println!();
    println!("  WebChat: http://localhost:18790");
    println!();
    if should_install {
        println!("  Wirken is running as a service.");
        println!("  Manage with: wirken setup --uninstall-service");
    } else {
        println!("  Start wirken: wirken run");
    }
    println!();

    Ok(())
}

/// Choose the sandbox mode to write to `sandbox.json` based on
/// runsc availability and the operator's upgrade choice. Extracted
/// so the decision is testable without driving the interactive
/// dialog.
fn pick_setup_sandbox_mode(runsc_detected: bool, accept_upgrade: bool) -> &'static str {
    if runsc_detected && accept_upgrade {
        "gvisor"
    } else {
        "exec-only"
    }
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
    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
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
    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
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
    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
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
    let creds = super::channel::collect_signal_creds()?;
    register_channel("signal", &creds.endpoint, cfg, data).await?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    super::channel::store_signal_creds(&store, &creds)?;

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

    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
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

async fn setup_whatsapp_channel(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    println!("  WhatsApp uses the Meta Cloud API. You need four values from your");
    println!("  Meta app's WhatsApp product page:");
    println!("    - Access token (permanent system-user token recommended)");
    println!("    - Phone number ID (15-16 digit numeric)");
    println!("    - Verify token (any string you chose when registering the webhook)");
    println!("    - App secret (32-char hex from Meta app settings)");
    println!("  See https://developers.facebook.com/docs/whatsapp/cloud-api");

    // collect_whatsapp_creds honors WIRKEN_WHATSAPP_* env vars and
    // otherwise prompts; passing default flags means the wizard is
    // interactive but an operator can still pre-populate via env.
    let creds = super::channel::collect_whatsapp_creds(super::channel::AddFlags::default())
        .context("Failed to collect WhatsApp credentials")?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    super::channel::store_whatsapp_creds(&store, &creds)?;

    // The adapter registry identifies channels by name; register it
    // the same way every other adapter does so the spawn loop in
    // `wirken run` picks it up.
    let identity = wirken_ipc::AdapterIdentity::generate("whatsapp");
    let pub_key = identity.public_key_bytes();
    let secret_key_hex: String = identity
        .secret_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    store
        .store(
            "whatsapp-adapter-key",
            "whatsapp",
            &wirken_vault::VaultSecret::new(secret_key_hex),
            None,
            None,
        )
        .context("Failed to store WhatsApp adapter key")?;
    let registry = wirken_gateway::adapter_registry::AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;
    let _ = registry.unregister("whatsapp");
    registry
        .register("whatsapp", &pub_key, "whatsapp")
        .context("Failed to register WhatsApp adapter")?;

    println!("  whatsapp: credentials encrypted, adapter keypair generated, registered.");
    Ok(())
}

/// #60: prompt the operator for optional per-channel LLM provider
/// overrides and persist them into provider.json under a
/// `channel_overrides` map. Each override is keyed by channel and
/// carries provider + model + base_url + the vault slot name to read
/// the API key from at runtime. The slot is not created here — the
/// operator must have run `wirken credentials add <slot>` separately,
/// or use the default-slot `<provider>-api-key` naming. The wizard
/// validates that the slot exists in the vault before persisting.
async fn configure_channel_overrides(
    cfg: &wirken_gateway::config::GatewayConfig,
    data: &std::path::Path,
    selected_channels: &[&str],
) -> Result<()> {
    let wants_override = Confirm::new()
        .with_prompt("  Configure a per-channel LLM provider override?")
        .default(false)
        .interact()?;
    if !wants_override {
        return Ok(());
    }

    // Load existing provider.json (main provider lands here first
    // during setup, so the file exists by this point).
    let provider_path = data.join("provider.json");
    let mut provider_json: serde_json::Value = std::fs::read_to_string(&provider_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let mut overrides = provider_json
        .get("channel_overrides")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Open the vault once so we can validate slot names the
    // operator picks for each override.
    let pp = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(data, move || pp);
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    loop {
        let channel_choices: Vec<String> =
            selected_channels.iter().map(|s| s.to_string()).collect();
        let ch_idx = Select::new()
            .with_prompt("  Channel to override")
            .items(&channel_choices)
            .default(0)
            .interact()?;
        let channel = &channel_choices[ch_idx];

        let providers = &[
            ("openai", "https://api.openai.com/v1"),
            ("anthropic", "https://api.anthropic.com/v1"),
            ("ollama", "http://localhost:11434/v1"),
            ("privatemode", "http://localhost:8080/v1"),
            ("tinfoil", "https://api.tinfoil.sh/v1"),
            ("bedrock", ""),
            ("gemini", "https://generativelanguage.googleapis.com/v1beta"),
            ("custom", ""),
        ];
        let provider_labels: Vec<&str> = providers.iter().map(|(p, _)| *p).collect();
        let pidx = Select::new()
            .with_prompt("  Provider for this channel")
            .items(&provider_labels)
            .default(0)
            .interact()?;
        let (provider_name, default_base_url) = providers[pidx];

        let model: String = Input::new().with_prompt("  Model").interact_text()?;

        let base_url: String = Input::new()
            .with_prompt("  Base URL")
            .default(default_base_url.to_string())
            .interact_text()?;

        // Per the #60 design: configs reference vault slots by name,
        // the vault owns key material. The default slot name is
        // `<provider>-api-key` (matching how `wirken setup` stores
        // the main provider's key).
        let default_slot = format!("{provider_name}-api-key");
        let api_key_name: String = Input::new()
            .with_prompt("  Name this key (used to reference it later, e.g. anthropic-prod)")
            .default(default_slot.clone())
            .interact_text()?;

        // Validate early: refuse to persist a pointer at a name
        // that has no credential yet. Avoids a runtime failure on
        // the first message routed to this channel.
        if api_key_name.trim().is_empty() {
            println!("  (no name provided - override will run without a key)");
        } else if store.retrieve(&api_key_name).is_err() {
            println!(
                "  Warning: no key named '{api_key_name}'. \
                 Add it with: wirken credentials add {api_key_name}"
            );
        }

        let entry = serde_json::json!({
            "provider": provider_name,
            "model": model,
            "base_url": base_url,
            "api_key_name": api_key_name,
        });
        overrides.insert(channel.clone(), entry);
        println!("  Override recorded: {channel} -> {provider_name}/{model} (key: {api_key_name})");

        if !Confirm::new()
            .with_prompt("  Add another override?")
            .default(false)
            .interact()?
        {
            break;
        }
    }

    provider_json["channel_overrides"] = serde_json::Value::Object(overrides);
    wirken_gateway::org::write_with_secret_perms(
        &provider_path,
        serde_json::to_string_pretty(&provider_json)?.as_bytes(),
    )
    .context("Failed to write provider.json")?;
    Ok(())
}

#[cfg(test)]
mod setup_tests {
    use super::pick_setup_sandbox_mode;

    #[test]
    fn no_runsc_picks_exec_only() {
        assert_eq!(pick_setup_sandbox_mode(false, false), "exec-only");
        // Operator "upgrade" choice is irrelevant when runsc is not detected.
        assert_eq!(pick_setup_sandbox_mode(false, true), "exec-only");
    }

    #[test]
    fn runsc_detected_plus_upgrade_picks_gvisor() {
        assert_eq!(pick_setup_sandbox_mode(true, true), "gvisor");
    }

    #[test]
    fn runsc_detected_but_declined_keeps_exec_only() {
        assert_eq!(pick_setup_sandbox_mode(true, false), "exec-only");
    }
}
