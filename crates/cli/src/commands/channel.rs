use anyhow::{Context, Result};
use dialoguer::Password;

use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::config::GatewayConfig;
use wirken_ipc::AdapterIdentity;
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::{config, data_dir};

/// Non-interactive flags for `wirken channel add`. Flags that are
/// `None` fall through to the matching `WIRKEN_<CHANNEL>_*` env var
/// (where applicable) and then to an interactive prompt. Validation
/// runs on whichever source provided the value.
#[derive(Debug, Default)]
pub struct AddFlags {
    pub token: Option<String>,
    pub phone_number_id: Option<String>,
    pub verify_token: Option<String>,
    pub app_secret: Option<String>,
}

pub async fn add(channel: &str, flags: AddFlags) -> Result<()> {
    let cfg = config();
    let data = data_dir()?;

    match channel {
        "whatsapp" => add_whatsapp(&cfg, &data, flags).await,
        "slack" => add_slack(&cfg, &data, flags).await,
        _ => add_simple(channel, &cfg, &data, flags).await,
    }
}

async fn add_simple(
    channel: &str,
    cfg: &GatewayConfig,
    data: &std::path::Path,
    flags: AddFlags,
) -> Result<()> {
    let token = resolve_token(channel, flags.token.as_deref(), true)?;
    register_channel(channel, &token, cfg, data).await?;
    println!("  Channel '{channel}' added.");
    println!("  Start the adapter with: wirken adapter {channel}");
    Ok(())
}

async fn add_slack(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let token = resolve_token("slack", flags.token.as_deref(), true)?;
    let app_token = match std::env::var("WIRKEN_SLACK_APP_TOKEN") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => super::read_secret("  Slack app token (xapp-...): ")?,
    };

    let keychain = probe_keychain(data, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store
        .store(
            "slack-token",
            "slack",
            &VaultSecret::new(token.clone()),
            None,
            None,
        )
        .context("Failed to store Slack token")?;
    store
        .store(
            "slack-app-token",
            "slack",
            &VaultSecret::new(app_token),
            None,
            None,
        )
        .context("Failed to store Slack app token")?;

    register_adapter_identity("slack", cfg, &store)?;
    println!("  slack: tokens encrypted, adapter keypair generated, registered.");
    println!("  Channel 'slack' added.");
    println!("  Start the adapter with: wirken adapter slack");
    Ok(())
}

/// Collect and persist WhatsApp Cloud API credentials. The adapter
/// needs four fields — access token, phone number ID, verify token,
/// app secret — all in the vault before `wirken run` will start the
/// listener. Values come from, in order: CLI flag, env var
/// (`WIRKEN_WHATSAPP_*`), interactive prompt. Validation runs on
/// whichever source supplied the value so a bad flag fails as loudly
/// as a bad prompt entry.
async fn add_whatsapp(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let creds = collect_whatsapp_creds(flags).context("Failed to collect WhatsApp credentials")?;

    let keychain = probe_keychain(data, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store_whatsapp_creds(&store, &creds)?;
    register_adapter_identity("whatsapp", cfg, &store)?;
    println!("  whatsapp: credentials encrypted, adapter keypair generated, registered.");
    println!("  Channel 'whatsapp' added.");
    println!("  Start the adapter with: wirken adapter whatsapp");
    Ok(())
}

/// The four vault entries a WhatsApp adapter needs. Named to match
/// the keys `crates/cli/src/commands/adapter.rs` already retrieves.
#[derive(Debug, Clone)]
pub struct WhatsAppCreds {
    pub token: String,
    pub phone_number_id: String,
    pub verify_token: String,
    pub app_secret: String,
}

/// Resolve the WhatsApp credential set from flags, env vars, and
/// prompts. The collection order is the same for every field:
/// CLI flag → `WIRKEN_WHATSAPP_*` env var → interactive prompt.
/// Validation is applied to whichever source provided the value,
/// and in the interactive case the user is re-prompted until a
/// valid value lands or they abort. Pure in the non-interactive
/// sense: if all four fields are supplied via flag or env and all
/// pass validation, no prompt runs.
pub fn collect_whatsapp_creds(flags: AddFlags) -> Result<WhatsAppCreds> {
    let token = resolve_with_validation(
        "WhatsApp access token",
        flags.token,
        "WIRKEN_WHATSAPP_TOKEN",
        true,
        validate_non_empty,
    )?;
    let phone_number_id = resolve_with_validation(
        "WhatsApp phone number ID",
        flags.phone_number_id,
        "WIRKEN_WHATSAPP_PHONE_NUMBER_ID",
        false,
        validate_phone_number_id,
    )?;
    let verify_token = resolve_with_validation(
        "WhatsApp verify token",
        flags.verify_token,
        "WIRKEN_WHATSAPP_VERIFY_TOKEN",
        true,
        validate_non_empty,
    )?;
    let app_secret = resolve_with_validation(
        "WhatsApp app secret",
        flags.app_secret,
        "WIRKEN_WHATSAPP_APP_SECRET",
        true,
        validate_app_secret,
    )?;
    Ok(WhatsAppCreds {
        token,
        phone_number_id,
        verify_token,
        app_secret,
    })
}

/// Write the four WhatsApp credentials to the vault under the keys
/// the adapter reads in `crates/cli/src/commands/adapter.rs`.
pub fn store_whatsapp_creds(store: &CredentialStore, creds: &WhatsAppCreds) -> Result<()> {
    store
        .store(
            "whatsapp-token",
            "whatsapp",
            &VaultSecret::new(creds.token.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp token")?;
    store
        .store(
            "whatsapp-phone-number-id",
            "whatsapp",
            &VaultSecret::new(creds.phone_number_id.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp phone number ID")?;
    store
        .store(
            "whatsapp-verify-token",
            "whatsapp",
            &VaultSecret::new(creds.verify_token.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp verify token")?;
    store
        .store(
            "whatsapp-app-secret",
            "whatsapp",
            &VaultSecret::new(creds.app_secret.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp app secret")?;
    Ok(())
}

fn register_adapter_identity(
    channel: &str,
    cfg: &GatewayConfig,
    store: &CredentialStore,
) -> Result<()> {
    let identity = AdapterIdentity::generate(channel);
    let pub_key = identity.public_key_bytes();

    let secret_key_hex: String = identity
        .secret_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    store
        .store(
            &format!("{channel}-adapter-key"),
            channel,
            &VaultSecret::new(secret_key_hex),
            None,
            None,
        )
        .context("Failed to store adapter key")?;

    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;
    let _ = registry.unregister(channel);
    registry
        .register(channel, &pub_key, channel)
        .context("Failed to register adapter")?;
    Ok(())
}

fn resolve_token(channel: &str, flag: Option<&str>, secret: bool) -> Result<String> {
    let env_var = format!("WIRKEN_{}_TOKEN", channel.to_uppercase().replace('-', "_"));
    if let Some(t) = flag {
        let t = t.trim().to_string();
        validate_non_empty(&t)?;
        return Ok(t);
    }
    if let Ok(v) = std::env::var(&env_var) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let label = format!("  {channel} bot token");
    loop {
        let value = if secret {
            super::read_secret(&format!("{label}: "))?
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(&label)
                .interact_text()?
        };
        match validate_non_empty(&value) {
            Ok(()) => return Ok(value),
            Err(e) => {
                println!("  {e}");
                continue;
            }
        }
    }
}

fn resolve_with_validation(
    label: &str,
    flag: Option<String>,
    env_var: &str,
    secret: bool,
    validate: fn(&str) -> Result<()>,
) -> Result<String> {
    if let Some(v) = flag {
        let v = v.trim().to_string();
        validate(&v).with_context(|| format!("Invalid --{} flag", env_var))?;
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            validate(&v).with_context(|| format!("Invalid {env_var} env var"))?;
            return Ok(v);
        }
    }
    loop {
        let prompt_label = format!("  {label}");
        let value = if secret {
            super::read_secret(&format!("{prompt_label}: "))?
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(&prompt_label)
                .interact_text()?
        };
        match validate(&value) {
            Ok(()) => return Ok(value),
            Err(e) => {
                println!("  {e}");
                continue;
            }
        }
    }
}

// -- Validators ---------------------------------------------------------

/// A token / secret must have at least one non-whitespace character.
/// The prompt helpers trim before calling, so this rejects the
/// empty string and nothing else.
pub fn validate_non_empty(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        anyhow::bail!("value cannot be empty");
    }
    Ok(())
}

/// WhatsApp Cloud API phone-number-id: numeric, 15 or 16 digits.
/// Meta's IDs are 64-bit-ish integers rendered decimal; we range-
/// check length rather than parsing into u64 to keep the rejection
/// message intelligible.
pub fn validate_phone_number_id(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if !(15..=16).contains(&trimmed.len()) {
        anyhow::bail!(
            "phone number ID must be 15-16 digits (got {} chars)",
            trimmed.len()
        );
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("phone number ID must be numeric");
    }
    Ok(())
}

/// Meta app secret as shown in the Meta Developer portal: 32
/// characters, lowercase hex. Anything else is either a copy-paste
/// mistake (leading whitespace, wrong field) or a mis-configured
/// app. Fail at entry rather than at first webhook delivery.
pub fn validate_app_secret(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.len() != 32 {
        anyhow::bail!(
            "app secret must be exactly 32 characters (got {})",
            trimmed.len()
        );
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        anyhow::bail!("app secret must be lowercase hex (0-9, a-f)");
    }
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

    // Remove credential(s). WhatsApp has four keys; everything else
    // uses one `<channel>-token` entry.
    let keychain = probe_keychain(&cfg.data_dir, String::new);
    if let Ok(store) = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()) {
        if channel == "whatsapp" {
            for key in [
                "whatsapp-token",
                "whatsapp-phone-number-id",
                "whatsapp-verify-token",
                "whatsapp-app-secret",
            ] {
                let _ = store.delete(key);
            }
        } else {
            let _ = store.delete(&format!("{channel}-token"));
        }
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

    register_adapter_identity(channel, cfg, &store)?;
    println!("  {channel}: token encrypted, adapter keypair generated, registered.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Validators ---------------------------------------------------

    #[test]
    fn phone_number_id_accepts_15_and_16_digits() {
        assert!(validate_phone_number_id("123456789012345").is_ok());
        assert!(validate_phone_number_id("1234567890123456").is_ok());
    }

    #[test]
    fn phone_number_id_rejects_wrong_length() {
        assert!(validate_phone_number_id("12345678901234").is_err());
        assert!(validate_phone_number_id("12345678901234567").is_err());
        assert!(validate_phone_number_id("").is_err());
    }

    #[test]
    fn phone_number_id_rejects_non_numeric() {
        assert!(validate_phone_number_id("12345678901234a").is_err());
        assert!(validate_phone_number_id("12345-67890123456").is_err());
    }

    #[test]
    fn app_secret_accepts_32_lowercase_hex() {
        // Low-entropy fixtures so gitleaks' generic-api-key rule
        // does not treat them as real secrets. The validator only
        // cares about char class and length, not distribution.
        assert!(validate_app_secret("abababababababababababababababab").is_ok());
        assert!(validate_app_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    }

    #[test]
    fn app_secret_rejects_wrong_length() {
        assert!(validate_app_secret("abababab").is_err());
        assert!(validate_app_secret("abababababababababababababababababab").is_err());
    }

    #[test]
    fn app_secret_rejects_uppercase_and_non_hex() {
        assert!(validate_app_secret("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(validate_app_secret("abababababababababababababababaZ").is_err());
    }

    #[test]
    fn non_empty_rejects_whitespace_only() {
        assert!(validate_non_empty("").is_err());
        assert!(validate_non_empty("   ").is_err());
        assert!(validate_non_empty("\t\n").is_err());
        assert!(validate_non_empty("x").is_ok());
    }

    // -- Non-interactive end-to-end -----------------------------------

    fn good_flags() -> AddFlags {
        // All fixture values are intentionally low-entropy so the
        // gitleaks scanner does not flag them as `generic-api-key`.
        AddFlags {
            token: Some("fake_token_value".into()),
            phone_number_id: Some("123456789012345".into()),
            verify_token: Some("my_verify_token".into()),
            app_secret: Some("00000000000000000000000000000000".into()),
        }
    }

    #[test]
    fn collect_whatsapp_creds_from_flags_succeeds() {
        let creds = collect_whatsapp_creds(good_flags()).expect("flags should validate");
        assert_eq!(creds.token, "fake_token_value");
        assert_eq!(creds.phone_number_id, "123456789012345");
        assert_eq!(creds.verify_token, "my_verify_token");
        assert_eq!(creds.app_secret, "00000000000000000000000000000000");
    }

    #[test]
    fn collect_whatsapp_creds_rejects_bad_phone_number_id_flag() {
        let mut flags = good_flags();
        flags.phone_number_id = Some("short".into());
        let err = collect_whatsapp_creds(flags).expect_err("short id must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("phone number ID"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn collect_whatsapp_creds_rejects_bad_app_secret_flag() {
        let mut flags = good_flags();
        flags.app_secret = Some("not-hex-at-all".into());
        let err = collect_whatsapp_creds(flags).expect_err("non-hex secret must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("app secret") || msg.contains("APP_SECRET"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn non_interactive_end_to_end_persists_all_four_vault_keys() {
        // The full non-interactive path: flags in, validation passes,
        // credentials land in the vault under the exact keys the
        // adapter reads at startup.
        use tempfile::TempDir;
        use wirken_vault::{AgeFileKeychain, CredentialStore};

        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");

        let keychain = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&vault_path, &keychain).expect("open credential store");

        let creds = collect_whatsapp_creds(good_flags()).expect("flags validate");
        store_whatsapp_creds(&store, &creds).expect("store round-trip");

        for key in [
            "whatsapp-token",
            "whatsapp-phone-number-id",
            "whatsapp-verify-token",
            "whatsapp-app-secret",
        ] {
            let (secret, _) = store
                .retrieve(key)
                .unwrap_or_else(|e| panic!("missing {key}: {e}"));
            assert!(!secret.expose().is_empty(), "{key} round-tripped empty");
        }

        let (token, _) = store.retrieve("whatsapp-token").unwrap();
        assert_eq!(token.expose(), "fake_token_value");
        let (phone, _) = store.retrieve("whatsapp-phone-number-id").unwrap();
        assert_eq!(phone.expose(), "123456789012345");
    }
}
