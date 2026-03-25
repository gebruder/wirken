use std::path::PathBuf;

use anyhow::{Context, Result};

use wirken_adapter_discord::DiscordAdapter;
use wirken_adapter_slack::SlackAdapter;
use wirken_adapter_telegram::TelegramAdapter;
use wirken_gateway::config::GatewayConfig;
use wirken_ipc::AdapterIdentity;
use wirken_vault::{CredentialStore, probe_keychain};

/// Run an adapter process. Called by the gateway daemon.
pub async fn run(channel: &str) -> Result<()> {
    let data_dir = std::env::var("WIRKEN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| GatewayConfig::default().data_dir);

    let socket_path = std::env::var("WIRKEN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("sockets/gateway.sock"));

    tracing::info!("Adapter '{channel}' starting, connecting to {}", socket_path.display());

    // Load credentials from vault
    let keychain = probe_keychain(&data_dir, || String::new());
    let store = CredentialStore::open(&data_dir.join("vault.db"), keychain.as_ref())
        .context("Failed to open credential store")?;

    // Get bot token
    let token_name = format!("{channel}-token");
    let (token_secret, _) = store.retrieve(&token_name)
        .context(format!("No token found for '{channel}'. Run `wirken channel add {channel}`."))?;
    let bot_token = token_secret.expose().to_string();

    // Get adapter secret key
    let key_name = format!("{channel}-adapter-key");
    let (key_secret, _) = store.retrieve(&key_name)
        .context(format!("No adapter key found for '{channel}'."))?;

    let key_hex = key_secret.expose();
    let key_bytes = hex_decode(key_hex)
        .context("Invalid adapter key")?;

    let mut secret = [0u8; 32];
    if key_bytes.len() != 32 {
        anyhow::bail!("Adapter key must be 32 bytes, got {}", key_bytes.len());
    }
    secret.copy_from_slice(&key_bytes);

    let identity = AdapterIdentity::from_bytes(&secret, channel);
    secret.fill(0); // zero the copy

    // Run the adapter
    match channel {
        "telegram" => {
            let adapter = TelegramAdapter::new(identity, bot_token);
            adapter.run(&socket_path).await
                .map_err(|e| anyhow::anyhow!("Telegram adapter error: {e}"))?;
        }
        "discord" => {
            let adapter = DiscordAdapter::new(identity, bot_token);
            adapter.run(&socket_path).await
                .map_err(|e| anyhow::anyhow!("Discord adapter error: {e}"))?;
        }
        "slack" => {
            // Slack Socket Mode requires an app token in addition to the bot token
            let app_token_name = format!("{channel}-app-token");
            let (app_token_secret, _) = store.retrieve(&app_token_name)
                .context("No app token found for 'slack'. Run `wirken channel add slack`.")?;
            let app_token = app_token_secret.expose().to_string();

            let adapter = SlackAdapter::new(identity, bot_token, app_token);
            adapter.run(&socket_path).await
                .map_err(|e| anyhow::anyhow!("Slack adapter error: {e}"))?;
        }
        other => {
            anyhow::bail!("Unknown adapter: '{other}'. Supported: telegram, discord, slack");
        }
    }

    Ok(())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("hex decode: {e}"))
        })
        .collect()
}
