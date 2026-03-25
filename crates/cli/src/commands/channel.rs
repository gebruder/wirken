use anyhow::{Context, Result};
use dialoguer::Password;

use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::config::GatewayConfig;
use wirken_ipc::AdapterIdentity;
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::{config, data_dir};

pub async fn add(channel: &str) -> Result<()> {
    let cfg = config();
    let data = data_dir()?;

    let token = Password::new()
        .with_prompt(format!("  {channel} bot token"))
        .interact()?;

    register_channel(channel, &token, &cfg, &data).await?;

    println!("  Channel '{channel}' added.");
    println!("  Start the adapter with: wirken adapter {channel}");
    Ok(())
}

pub async fn list() -> Result<()> {
    let cfg = config();
    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;

    let adapters = registry.list();
    if adapters.is_empty() {
        println!("  No channels configured.");
        println!("  Run `wirken setup` or `wirken channel add <channel>`.");
        return Ok(());
    }

    println!("  Configured channels:");
    println!();
    for adapter in &adapters {
        let status = if adapter.connected {
            "connected"
        } else {
            "disconnected"
        };
        println!(
            "  {:12} {:12} {}",
            adapter.adapter_id, adapter.channel, status
        );
    }
    println!();
    Ok(())
}

pub async fn remove(channel: &str) -> Result<()> {
    let cfg = config();

    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;

    registry
        .unregister(channel)
        .context(format!("Failed to remove channel '{channel}'"))?;

    // Remove credential
    let keychain = probe_keychain(&cfg.data_dir, String::new);
    if let Ok(store) = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()) {
        let _ = store.delete(&format!("{channel}-token"));
    }

    println!("  Channel '{channel}' removed.");
    Ok(())
}

/// Register a channel: store token in vault, generate adapter keypair, register in adapter registry.
pub async fn register_channel(
    channel: &str,
    token: &str,
    cfg: &GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    // Store token in vault
    let keychain = probe_keychain(data, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let secret = VaultSecret::new(token.to_string());
    store
        .store(&format!("{channel}-token"), channel, &secret, None, None)
        .context("Failed to store channel token")?;

    // Generate adapter Ed25519 keypair
    let identity = AdapterIdentity::generate(channel);
    let pub_key = identity.public_key_bytes();

    // Store secret key in vault
    let secret_key_hex: String = identity
        .secret_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sk_secret = VaultSecret::new(secret_key_hex);
    store
        .store(
            &format!("{channel}-adapter-key"),
            channel,
            &sk_secret,
            None,
            None,
        )
        .context("Failed to store adapter key")?;

    // Register in adapter registry
    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;

    // Unregister first if already exists (re-registration)
    let _ = registry.unregister(channel);

    registry
        .register(channel, &pub_key, channel)
        .context("Failed to register adapter")?;

    println!("  {channel}: token encrypted, adapter keypair generated, registered.");
    Ok(())
}
