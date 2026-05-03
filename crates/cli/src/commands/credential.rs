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

    let creds = store.list().context("Failed to list credentials")?;

    if creds.is_empty() {
        println!("  No credentials stored.");
        return Ok(());
    }

    println!(
        "  {:24}  {:12}  {:20}  {:12}",
        "NAME", "CHANNEL", "CREATED", "STATUS"
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(24),
        "─".repeat(12),
        "─".repeat(20),
        "─".repeat(12)
    );

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
    println!(
        "  {} credentials. Values are encrypted — never shown.",
        creds.len()
    );
    Ok(())
}

/// Where the credential value comes from. The CLI layer converts
/// `--stdin` / `--value-file` flags into this enum so the command
/// body doesn't need to know about clap.
pub enum ValueSource {
    /// Prompt on stderr. Default when neither flag is given.
    Prompt,
    /// Read the value from stdin, stripping a single trailing
    /// newline. Matches `echo "$SECRET" | wirken credentials add`.
    Stdin,
    /// Read the value from a file, stripping a single trailing
    /// newline. Meant for ops flows that drop a secret file via
    /// configuration management.
    File(std::path::PathBuf),
}

impl ValueSource {
    /// Build from the two mutually exclusive clap flags. Both false
    /// and file=None means interactive prompt; clap's
    /// `conflicts_with` makes the "both true" case a parse error,
    /// so this method does not need to defend against it.
    pub fn from_flags(stdin: bool, file: Option<std::path::PathBuf>) -> Self {
        match (stdin, file) {
            (true, _) => Self::Stdin,
            (_, Some(p)) => Self::File(p),
            _ => Self::Prompt,
        }
    }
}

pub async fn add(name: &str, channel: Option<&str>, source: ValueSource) -> Result<()> {
    let cfg = config();

    let value = read_credential_value(name, source)?;
    if value.is_empty() {
        anyhow::bail!("empty value");
    }

    let keychain = probe_keychain(&cfg.data_dir, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let secret = VaultSecret::new(value);
    store
        .store(name, channel.unwrap_or(""), &secret, None, None)
        .context(format!("Failed to store '{name}'"))?;

    println!("  Credential '{name}' stored.");
    Ok(())
}

/// Obtain the raw credential value from the requested source. Public
/// in-crate so the non-interactive paths can be unit-tested without
/// mocking clap or a TTY.
pub(crate) fn read_credential_value(name: &str, source: ValueSource) -> Result<String> {
    match source {
        ValueSource::Prompt => super::read_secret(&format!("  Value for '{name}': ")),
        ValueSource::Stdin => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read value from stdin")?;
            Ok(strip_one_trailing_newline(buf))
        }
        ValueSource::File(path) => {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read value file {}", path.display()))?;
            Ok(strip_one_trailing_newline(raw))
        }
    }
}

/// Trim exactly one trailing `\n` (and an optional preceding `\r`).
/// `echo` and most text-file writers add a single newline; stripping
/// it matches operator intent while preserving secrets that
/// intentionally contain whitespace or multiline content. `trim_end`
/// would discard too much.
fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

pub async fn remove(name: &str) -> Result<()> {
    let cfg = config();

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store
        .delete(name)
        .context(format!("Failed to remove '{name}'"))?;

    println!("  Credential '{name}' removed.");
    Ok(())
}

pub async fn rotate(name: &str) -> Result<()> {
    let cfg = config();

    let new_value = super::read_secret(&format!("  New value for '{name}': "))?;

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

    store
        .rotate(name, &secret, Some(rotation_due))
        .context(format!("Failed to rotate '{name}'"))?;

    println!("  Credential '{name}' rotated. Next rotation due in 90 days.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wirken_vault::{AgeFileKeychain, CredentialStore};

    #[test]
    fn value_source_from_flags_default_is_prompt() {
        assert!(matches!(
            ValueSource::from_flags(false, None),
            ValueSource::Prompt
        ));
    }

    #[test]
    fn value_source_from_flags_stdin_wins() {
        assert!(matches!(
            ValueSource::from_flags(true, None),
            ValueSource::Stdin
        ));
    }

    #[test]
    fn value_source_from_flags_file() {
        let p = std::path::PathBuf::from("/tmp/example");
        match ValueSource::from_flags(false, Some(p.clone())) {
            ValueSource::File(path) => assert_eq!(path, p),
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn strip_trailing_newline_keeps_internal_whitespace() {
        assert_eq!(strip_one_trailing_newline("secret\n".into()), "secret");
        assert_eq!(strip_one_trailing_newline("secret\r\n".into()), "secret");
        assert_eq!(strip_one_trailing_newline("secret".into()), "secret");
        assert_eq!(strip_one_trailing_newline("a\nb\n".into()), "a\nb");
        // Only one newline stripped.
        assert_eq!(strip_one_trailing_newline("s\n\n".into()), "s\n");
        // Empty stays empty.
        assert_eq!(strip_one_trailing_newline("".into()), "");
    }

    #[test]
    fn read_credential_value_from_file_strips_trailing_newline() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secret");
        std::fs::write(&path, "my-mcp-token\n").unwrap();
        let value =
            read_credential_value("name", ValueSource::File(path.clone())).expect("read file");
        assert_eq!(value, "my-mcp-token");
    }

    #[test]
    fn read_credential_value_from_file_propagates_missing_file() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("nope");
        let err = read_credential_value("name", ValueSource::File(missing.clone()))
            .expect_err("missing file must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&missing.display().to_string()),
            "error should name the path, got: {msg}"
        );
    }

    #[test]
    fn file_backed_credential_persists_to_vault() {
        // The full non-interactive path: --value-file hands us a
        // secret; it lands in the vault under the requested name
        // and retrieves with the same bytes minus the single
        // trailing newline.
        let tmp = TempDir::new().unwrap();
        let secret_path = tmp.path().join("mcp-token");
        std::fs::write(&secret_path, "hunter2\n").unwrap();

        let value = read_credential_value("my-mcp-token", ValueSource::File(secret_path))
            .expect("read value");
        assert!(!value.is_empty());
        assert_eq!(value, "hunter2");

        let vault_path = tmp.path().join("vault.db");
        let keychain = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&vault_path, &keychain).expect("open vault");
        store
            .store("my-mcp-token", "mcp", &VaultSecret::new(value), None, None)
            .expect("store");

        let (retrieved, _) = store.retrieve("my-mcp-token").expect("retrieve");
        assert_eq!(retrieved.expose(), "hunter2");
    }
}
