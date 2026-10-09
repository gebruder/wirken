use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};

use wirken_adapter_discord::DiscordAdapter;
use wirken_adapter_google_chat::GoogleChatAdapter;
use wirken_adapter_imessage::IMessageAdapter;
use wirken_adapter_matrix::MatrixAdapter;
#[cfg(unix)]
use wirken_adapter_signal::SignalAdapter;
#[cfg(unix)]
use wirken_adapter_signal::SignalAllowlist;
use wirken_adapter_slack::SlackAdapter;
use wirken_adapter_teams::TeamsAdapter;
use wirken_adapter_telegram::TelegramAdapter;
use wirken_gateway::config::GatewayConfig;
use wirken_ipc::AdapterIdentity;

use super::adapter_handoff::Handoff;

/// Run an adapter process. Called by the gateway daemon.
pub async fn run(channel: &str) -> Result<()> {
    // Same resolver the gateway that spawned this process uses, so
    // `WIRKEN_DATA_DIR` cannot point the adapter at one directory and
    // the gateway at another.
    let data_dir = GatewayConfig::default().data_dir;

    let socket_path = std::env::var("WIRKEN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("sockets/gateway.sock"));

    tracing::info!(
        "Adapter '{channel}' starting, connecting to {}",
        socket_path.display()
    );

    // The gateway writes this adapter's credentials to stdin at spawn
    // and closes the pipe. The adapter never opens the vault, so it
    // holds no passphrase and no other channel's credentials.
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        anyhow::bail!(
            "`wirken adapter` is started by `wirken run`, which hands it its credentials \
             on stdin; it does not read the vault itself"
        );
    }
    let mut creds = Handoff::read_from(stdin.lock())?;

    let bot_token = required(
        &mut creds,
        &format!("{channel}-token"),
        format!("No token found for '{channel}'. Run `wirken channel add {channel}`."),
    )?;

    let key_secret = creds
        .take(&format!("{channel}-adapter-key"))
        .with_context(|| format!("No adapter key found for '{channel}'."))?;

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
            let app_token = required(
                &mut creds,
                &format!("{channel}-app-token"),
                "No app token found for 'slack'. Run `wirken channel add slack`.",
            )?;

            let adapter = SlackAdapter::new(identity, bot_token, app_token);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Slack adapter error: {e}"))?;
        }
        "teams" => {
            // Teams needs App ID in addition to App Password (bot token)
            let app_id = required(
                &mut creds,
                &format!("{channel}-app-id"),
                "No app ID found for 'teams'. Run `wirken channel add teams`.",
            )?;

            let listen_port: u16 = std::env::var("WIRKEN_TEAMS_PORT")
                .unwrap_or_else(|_| "3978".into())
                .parse()
                .unwrap_or(3978);

            let adapter = TeamsAdapter::new(identity, app_id, bot_token, listen_port)
                .map_err(|e| anyhow::anyhow!("Teams adapter error: {e}"))?;
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Teams adapter error: {e}"))?;
        }
        "matrix" => {
            // Matrix needs homeserver URL and username
            let homeserver = required(
                &mut creds,
                &format!("{channel}-homeserver"),
                "No homeserver URL for 'matrix'. Run `wirken channel add matrix`.",
            )?;
            let username = required(
                &mut creds,
                &format!("{channel}-username"),
                "No username for 'matrix'.",
            )?;

            let state_dir = data_dir.join("matrix-state");

            let adapter = MatrixAdapter::new(identity, homeserver, username, bot_token, state_dir);
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Matrix adapter error: {e}"))?;
        }
        "whatsapp" => {
            let app_secret = required(
                &mut creds,
                &format!("{channel}-app-secret"),
                "No app secret found for 'whatsapp'.",
            )?;
            let phone_number_id = required(
                &mut creds,
                &format!("{channel}-phone-number-id"),
                "No phone number ID found for 'whatsapp'.",
            )?;
            let verify_token = required(
                &mut creds,
                &format!("{channel}-verify-token"),
                "No verify token found for 'whatsapp'.",
            )?;

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
            )
            .map_err(|e| anyhow::anyhow!("WhatsApp adapter error: {e}"))?;
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("WhatsApp adapter error: {e}"))?;
        }
        "signal" => {
            #[cfg(unix)]
            {
                let endpoint = optional(&mut creds, &format!("{channel}-endpoint"))
                    .unwrap_or_else(|| "/tmp/signal-cli.sock".into());

                let phone_number = required(
                    &mut creds,
                    &format!("{channel}-phone-number"),
                    "No phone number found for 'signal'.",
                )?;

                // Fail-closed sender allowlist. Missing vault entry = empty list
                // = every inbound message is dropped. See docs/channels/signal.md.
                let allowlist_csv =
                    optional(&mut creds, &format!("{channel}-allowed-senders")).unwrap_or_default();
                let allowlist = SignalAllowlist::from_csv(&allowlist_csv)
                    .map_err(|e| anyhow::anyhow!("Signal adapter: invalid allowlist entry: {e}"))?;

                let adapter = SignalAdapter::new(identity, endpoint, phone_number, allowlist)
                    .map_err(|e| anyhow::anyhow!("Signal adapter error: {e}"))?;
                std::sync::Arc::new(adapter)
                    .run(&socket_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("Signal adapter error: {e}"))?;
            }
            #[cfg(not(unix))]
            {
                let _ = (&creds, &socket_path, &identity);
                anyhow::bail!(
                    "Signal adapter requires a unix-domain socket to signal-cli; not supported on this platform"
                );
            }
        }
        "google-chat" => {
            let listen_port: u16 = std::env::var("WIRKEN_GOOGLE_CHAT_PORT")
                .unwrap_or_else(|_| "3980".into())
                .parse()
                .unwrap_or(3980);

            let app_project_number = required(
                &mut creds,
                &format!("{channel}-project-number"),
                "No project number found for 'google-chat'. Run `wirken channel add google-chat`. \
                 The project number is the inbound JWT audience required by Google Chat webhooks.",
            )?;

            let adapter =
                GoogleChatAdapter::new(identity, bot_token, app_project_number, listen_port)
                    .map_err(|e| anyhow::anyhow!("Google Chat adapter error: {e}"))?;
            adapter
                .run(&socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Google Chat adapter error: {e}"))?;
        }
        "imessage" => {
            let bb_url = optional(&mut creds, &format!("{channel}-bluebubbles-url"))
                .unwrap_or_else(|| "http://localhost:1234".into());

            let server_password = required(
                &mut creds,
                &format!("{channel}-server-password"),
                "No BlueBubbles server password found for 'imessage'.",
            )?;

            let listen_port: u16 = std::env::var("WIRKEN_IMESSAGE_PORT")
                .unwrap_or_else(|_| "3981".into())
                .parse()
                .unwrap_or(3981);

            let adapter = IMessageAdapter::new(identity, bb_url, server_password, listen_port)
                .map_err(|e| anyhow::anyhow!("iMessage adapter error: {e}"))?;
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

/// Take a credential the adapter cannot start without.
fn required(creds: &mut Handoff, name: &str, missing: impl Into<String>) -> Result<String> {
    creds
        .take(name)
        .map(|secret| secret.expose().to_string())
        .with_context(|| missing.into())
}

/// Take a credential the adapter has a default for.
fn optional(creds: &mut Handoff, name: &str) -> Option<String> {
    creds.take(name).map(|secret| secret.expose().to_string())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    wirken_audit::hex::decode(hex).map_err(|e| anyhow::anyhow!("hex decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::hex_decode;

    #[test]
    fn hex_decode_rejects_non_ascii() {
        // Four bytes, with a character spanning offsets 1..3.
        let err = hex_decode("a\u{e9}a").unwrap_err();
        assert!(
            format!("{err:#}").contains("non-ASCII hex string"),
            "{err:#}"
        );
    }
}
