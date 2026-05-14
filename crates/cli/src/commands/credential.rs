use anyhow::{Context, Result, anyhow};
use dialoguer::Password;

use wirken_mcp_proxy::{
    OAuthCredential, load_oauth_public, lookup_provider, run_authorization_code_flow, store_oauth,
};
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::config;
use super::oauth_scope::{ScopeFlags, resolve_scopes_with_defaults, stdin_is_tty};

/// Vault channel marker for OAuth-managed credentials. Set by
/// `store_oauth` in the mcp-proxy crate; matched here to discriminate
/// OAuth-backed credentials from raw secrets in `show` / `rescope` /
/// `list`.
const OAUTH_CHANNEL: &str = "oauth";

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
        "  {:24}  {:12}  {:20}  {:12}  SCOPES",
        "NAME", "CHANNEL", "CREATED", "STATUS"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "─".repeat(24),
        "─".repeat(12),
        "─".repeat(20),
        "─".repeat(12),
        "─".repeat(10),
    );

    for cred in &creds {
        let status = if cred.is_expired() {
            "EXPIRED"
        } else if cred.is_rotation_due() {
            "ROTATE DUE"
        } else {
            "ok"
        };

        // Scope summary: OAuth rows decrypt via the public-view
        // helper (which uses `peek` and never carries the bearer
        // tokens out of mcp-proxy) and display a count. Non-OAuth
        // rows show "n/a"; a decryption failure on an OAuth row
        // shows "?" rather than blocking the whole list.
        let scope_summary = if cred.channel == OAUTH_CHANNEL {
            match load_oauth_public(&store, &cred.name) {
                Ok(public) => {
                    let n = public.scopes.len();
                    format!("{n} scope{}", if n == 1 { "" } else { "s" })
                }
                Err(_) => "?".to_string(),
            }
        } else {
            "n/a".to_string()
        };

        println!(
            "  {:24}  {:12}  {:20}  {:12}  {}",
            cred.name,
            cred.channel,
            cred.created_at.format("%Y-%m-%d %H:%M:%S"),
            status,
            scope_summary,
        );
    }

    println!();
    println!(
        "  {} credentials. Values are encrypted — never shown.",
        creds.len()
    );
    println!("  Run `wirken credentials show <name>` for scope detail.");
    Ok(())
}

/// `wirken credentials show <name>`: pretty-print one credential's
/// non-secret metadata. The vault secret itself never enters this
/// function's scope: OAuth credentials route through the public-view
/// helper that drops the bearer tokens inside mcp-proxy; non-OAuth
/// credentials display only their metadata. `peek` is used rather
/// than `retrieve` so inspection does not bump `last_used_at`.
pub async fn show(name: &str) -> Result<()> {
    let cfg = config();

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    // `peek` returns metadata even for non-OAuth credentials; we use
    // its `VaultSecret` only when the channel is `oauth` and even
    // then route through the public-view helper for type-enforced
    // redaction.
    let (_secret, meta) = store
        .peek(name)
        .with_context(|| format!("credential '{name}' not found"))?;

    println!();
    println!("  Credential: {name}");
    println!("    channel:        {}", meta.channel);
    println!(
        "    created:        {}",
        meta.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(last) = meta.last_used_at {
        println!("    last used:      {}", last.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(exp) = meta.expires_at {
        println!("    expires:        {}", exp.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(rot) = meta.rotation_due_at {
        println!("    rotation due:   {}", rot.format("%Y-%m-%d %H:%M:%S"));
    }

    if meta.channel == OAUTH_CHANNEL {
        let public = load_oauth_public(&store, name)
            .map_err(|e| anyhow!("read OAuth credential '{name}': {e}"))?;
        println!("    provider:       {}", public.provider);
        if public.scopes.is_empty() {
            println!("    granted scopes: (none)");
        } else {
            println!("    granted scopes:");
            for s in &public.scopes {
                println!("      {s}");
            }
        }
    } else {
        println!("    scope:          n/a (non-OAuth credential)");
    }

    Ok(())
}

/// `wirken credentials rescope <name>`: re-run the OAuth authorization
/// flow for an existing credential with a newly chosen scope set.
/// The current scopes seed the interactive picker so the operator
/// sees what they have today and can add or drop.
///
/// On success the vault row is replaced atomically via
/// `INSERT OR REPLACE` (the same path `store_oauth` already uses for
/// bootstrap and refresh writeback). On cancel or auth failure the
/// existing credential is left unchanged: the failure path returns
/// before any vault mutation.
///
/// Non-OAuth credentials cannot be rescoped; the function errors
/// with a typed message before any picker UI is rendered. The
/// vault's `channel` column (set to `"oauth"` by `store_oauth`) is
/// the discriminator.
pub async fn rescope(
    name: &str,
    scope: Vec<String>,
    no_scopes: bool,
    all_scopes: bool,
) -> Result<()> {
    let cfg = config();

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let (_secret, meta) = store
        .peek(name)
        .with_context(|| format!("credential '{name}' not found"))?;

    if meta.channel != OAUTH_CHANNEL {
        anyhow::bail!(
            "credential '{name}' is not OAuth-backed (channel: '{}'); only OAuth credentials carry scopes.\n\
             Use `wirken credentials rotate {name}` to replace a raw secret.",
            meta.channel
        );
    }

    let public = load_oauth_public(&store, name)
        .map_err(|e| anyhow!("read OAuth credential '{name}': {e}"))?;

    let provider_def = lookup_provider(&public.provider).ok_or_else(|| {
        anyhow!(
            "credential '{name}' references unknown OAuth provider '{}'; cannot rescope.",
            public.provider
        )
    })?;

    println!();
    println!("  wirken credentials rescope");
    println!("  ──────────────────────────");
    println!("  credential:     {name}");
    println!("  provider:       {}", public.provider);
    if public.scopes.is_empty() {
        println!("  current scopes: (none)");
    } else {
        println!("  current scopes:");
        for s in &public.scopes {
            println!("    {s}");
        }
    }
    println!();

    let scope_flags = ScopeFlags {
        scope,
        no_scopes,
        all_scopes,
    };
    let new_extra_scopes =
        resolve_scopes_with_defaults(provider_def, &scope_flags, stdin_is_tty(), &public.scopes)?;

    println!();
    println!("  New scopes:");
    for s in provider_def.default_scopes {
        println!("    {s}  (provider default)");
    }
    for s in &new_extra_scopes {
        let is_required = provider_def.scopes.iter().any(|c| c.id == s && c.required);
        if is_required {
            println!("    {s}  (required)");
        } else {
            println!("    {s}");
        }
    }
    println!();

    // Re-run the OAuth flow. The user's browser opens, the provider
    // re-confirms consent for the new scope set, and the new tokens
    // are returned. If this fails (timeout, user cancels at the
    // provider's consent screen, network error) the existing vault
    // row is untouched: the function returns before any vault write.
    let new_cred: OAuthCredential =
        run_authorization_code_flow(&public.provider, &new_extra_scopes)
            .await
            .map_err(|e| anyhow!("OAuth re-authorization failed: {e}"))?;

    // Atomic vault rewrite via `INSERT OR REPLACE` semantics in
    // `store.store`. The same path bootstraps a fresh credential, so
    // there is no separate update primitive that could partially
    // succeed.
    store_oauth(&store, name, &new_cred)
        .map_err(|e| anyhow!("vault writeback failed after successful OAuth grant: {e}"))?;

    println!();
    println!("  Credential '{name}' rescoped. New scopes stored in vault.");
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
