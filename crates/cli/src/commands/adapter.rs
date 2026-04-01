use std::path::PathBuf;

use anyhow::{Context, Result};

use wirken_adapter_discord::DiscordAdapter;
use wirken_adapter_google_chat::GoogleChatAdapter;
use wirken_adapter_imessage::IMessageAdapter;
use wirken_adapter_matrix::MatrixAdapter;
use wirken_adapter_signal::SignalAdapter;
use wirken_adapter_slack::SlackAdapter;
use wirken_adapter_teams::TeamsAdapter;
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

    tracing::info!(
        "Adapter '{channel}' starting, connecting to {}",
        socket_path.display()
    );

    // Load credentials from vault
    let keychain = probe_keychain(&data_dir, || {
        std::env::var("WIRKEN_VAULT_PASSPHRASE").unwrap_or_default()
    });
    let store = CredentialStore::open(&data_dir.join("vault.db"), keychain.as_ref())
        .context("Failed to open credential store")?;

    // Get bot token
    let token_name = format!("{channel}-token");
    let (token_secret, _) = store.retrieve(&token_name).context(format!(
        "No token found for '{channel}'. Run `wirken channel add {channel}`."
    ))?;
    let bot_token = token_secret.expose().to_string();

    // Get adapter secret key
    let key_name = format!("{channel}-adapter-key");
    let (key_secret, _) = store
        .retrieve(&key_name)
        .context(format!("No adapter key found for '{channel}'."))?;

    let key_hex = key_secret.expose();
    let key_bytes = hex_decode(key_hex).context("Invalid adapter key")?;

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
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Telegram adapter error: {e}"))?;
        }
        "discord" => {
            let adapter = DiscordAdapter::new(identity, bot_token);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Discord adapter error: {e}"))?;
        }
        "slack" => {
            // Slack Socket Mode requires an app token in addition to the bot token
            let app_token_name = format!("{channel}-app-token");
            let (app_token_secret, _) = store
                .retrieve(&app_token_name)
                .context("No app token found for 'slack'. Run `wirken channel add slack`.")?;
            let app_token = app_token_secret.expose().to_string();

            let adapter = SlackAdapter::new(identity, bot_token, app_token);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Slack adapter error: {e}"))?;
        }
        "teams" => {
            // Teams needs App ID in addition to App Password (bot token)
            let app_id_name = format!("{channel}-app-id");
            let (app_id_secret, _) = store
                .retrieve(&app_id_name)
                .context("No app ID found for 'teams'. Run `wirken channel add teams`.")?;
            let app_id = app_id_secret.expose().to_string();

            let listen_port: u16 = std::env::var("WIRKEN_TEAMS_PORT")
                .unwrap_or_else(|_| "3978".into())
                .parse()
                .unwrap_or(3978);

            let adapter = TeamsAdapter::new(identity, app_id, bot_token, listen_port);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Teams adapter error: {e}"))?;
        }
        "matrix" => {
            // Matrix needs homeserver URL and username from vault
            let hs_name = format!("{channel}-homeserver");
            let (hs_secret, _) = store
                .retrieve(&hs_name)
                .context("No homeserver URL for 'matrix'. Run `wirken channel add matrix`.")?;
            let homeserver = hs_secret.expose().to_string();

            let user_name = format!("{channel}-username");
            let (user_secret, _) = store
                .retrieve(&user_name)
                .context("No username for 'matrix'.")?;
            let username = user_secret.expose().to_string();

            let state_dir = data_dir.join("matrix-state");

            let adapter = MatrixAdapter::new(identity, homeserver, username, bot_token, state_dir);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Matrix adapter error: {e}"))?;
        }
        "whatsapp" => {
            let app_secret_name = format!("{channel}-app-secret");
            let (app_secret_val, _) = store
                .retrieve(&app_secret_name)
                .context("No app secret found for 'whatsapp'.")?;
            let app_secret = app_secret_val.expose().to_string();

            let phone_id_name = format!("{channel}-phone-number-id");
            let (phone_id_val, _) = store
                .retrieve(&phone_id_name)
                .context("No phone number ID found for 'whatsapp'.")?;
            let phone_number_id = phone_id_val.expose().to_string();

            let verify_token_name = format!("{channel}-verify-token");
            let (verify_val, _) = store
                .retrieve(&verify_token_name)
                .context("No verify token found for 'whatsapp'.")?;
            let verify_token = verify_val.expose().to_string();

            let listen_port: u16 = std::env::var("WIRKEN_WHATSAPP_PORT")
                .unwrap_or_else(|_| "3979".into())
                .parse()
                .unwrap_or(3979);

            let adapter = wirken_adapter_whatsapp::WhatsAppAdapter::new(
                identity,
                bot_token,
                phone_number_id,
                verify_token,
                app_secret,
                listen_port,
            );
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("WhatsApp adapter error: {e}"))?;
        }
        "signal" => {
            let endpoint_name = format!("{channel}-endpoint");
            let endpoint = store
                .retrieve(&endpoint_name)
                .map(|(s, _)| s.expose().to_string())
                .unwrap_or_else(|_| "http://localhost:8080/api/v1/rpc".into());

            let phone_name = format!("{channel}-phone-number");
            let (phone_val, _) = store
                .retrieve(&phone_name)
                .context("No phone number found for 'signal'.")?;
            let phone_number = phone_val.expose().to_string();

            let adapter = SignalAdapter::new(identity, endpoint, phone_number);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Signal adapter error: {e}"))?;
        }
        "google-chat" => {
            let listen_port: u16 = std::env::var("WIRKEN_GOOGLE_CHAT_PORT")
                .unwrap_or_else(|_| "3980".into())
                .parse()
                .unwrap_or(3980);

            let adapter = GoogleChatAdapter::new(identity, bot_token, listen_port);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Google Chat adapter error: {e}"))?;
        }
        "imessage" => {
            let url_name = format!("{channel}-bluebubbles-url");
            let bb_url = store
                .retrieve(&url_name)
                .map(|(s, _)| s.expose().to_string())
                .unwrap_or_else(|_| "http://localhost:1234".into());

            let pw_name = format!("{channel}-server-password");
            let (pw_val, _) = store
                .retrieve(&pw_name)
                .context("No BlueBubbles server password found for 'imessage'.")?;
            let server_password = pw_val.expose().to_string();

            let listen_port: u16 = std::env::var("WIRKEN_IMESSAGE_PORT")
                .unwrap_or_else(|_| "3981".into())
                .parse()
                .unwrap_or(3981);

            let adapter = IMessageAdapter::new(identity, bb_url, server_password, listen_port);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("iMessage adapter error: {e}"))?;
        }
        other => {
            anyhow::bail!(
                "Unknown adapter: '{other}'. Supported: telegram, discord, slack, teams, matrix, whatsapp, signal, google-chat, imessage"
            );
        }
    }

    Ok(())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow::anyhow!("hex decode: {e}"))
        })
        .collect()
}
