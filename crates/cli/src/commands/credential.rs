use anyhow::{Context, Result};
use dialoguer::Password;

use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::config;

pub async fn list() -> Result<()> {
    let cfg = config();

    let keychain = probe_keychain(&cfg.data_dir, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let creds = store.list()
        .context("Failed to list credentials")?;

    if creds.is_empty() {
        println!("  No credentials stored.");
        return Ok(());
    }

    println!("  {:24}  {:12}  {:20}  {:12}", "NAME", "CHANNEL", "CREATED", "STATUS");
    println!("  {}  {}  {}  {}", "─".repeat(24), "─".repeat(12), "─".repeat(20), "─".repeat(12));

    for cred in &creds {
        let status = if cred.is_expired() {
            "EXPIRED"
        } else if cred.is_rotation_due() {
            "ROTATE DUE"
        } else {
            "ok"
        };

        println!(
            "  {:24}  {:12}  {:20}  {:12}",
            cred.name,
            cred.channel,
            cred.created_at.format("%Y-%m-%d %H:%M:%S"),
            status,
        );
    }

    println!();
    println!("  {} credentials. Values are encrypted — never shown.", creds.len());
    Ok(())
}

pub async fn rotate(name: &str) -> Result<()> {
    let cfg = config();

    let new_value = Password::new()
        .with_prompt(format!("  New value for '{name}'"))
        .interact()?;

    let keychain = probe_keychain(&cfg.data_dir, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let secret = VaultSecret::new(new_value);
    let rotation_due = chrono::Utc::now() + chrono::Duration::days(90);

    store.rotate(name, &secret, Some(rotation_due))
        .context(format!("Failed to rotate '{name}'"))?;

    println!("  Credential '{name}' rotated. Next rotation due in 90 days.");
    Ok(())
}
