use anyhow::{Context, Result, anyhow};
use url::Url;

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

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);

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
    if meta.allowed_hosts.is_empty() {
        println!("    http hosts:     (none — not usable by http_request)");
    } else {
        println!("    http hosts:     {}", meta.allowed_hosts.join(", "));
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

/// Normalize an operator-supplied `--host` into the form
/// `CredentialMetadata::permits_host` matches against.
///
/// Injection reaches `permits_host` with `Url::host_str`, which is
/// lowercase ASCII: a binding typed in unicode (`café.example`) has to
/// be stored punycoded (`xn--caf-dma.example`) or it never matches its
/// own request host and the credential is silently unusable. Feeding
/// the operator's input through the same parser the request side uses
/// is what stops the two from drifting apart again.
///
/// Input carrying anything more than a bare host is rejected rather
/// than rewritten. `Url` is happy to read `https://api.example.com` as
/// the host `https`, and `api.example.com:8443` as `api.example.com`
/// with the port discarded; both yield a binding the operator did not
/// type, and the second is wider than the one they did. A credential
/// host binding is not a place to guess at intent, so anything
/// ambiguous is an error the operator can see rather than a silent
/// rewrite they cannot.
fn normalize_host(raw: &str) -> Result<String> {
    if raw.trim().is_empty() {
        return Err(anyhow!("invalid --host: empty"));
    }
    // Rejected here rather than after parsing: `permits_host` matches
    // one host exactly, with no `*.` wildcard by design, so a pattern
    // would store as a literal that can never match anything.
    if raw.contains('*') {
        return Err(anyhow!(
            "invalid --host '{raw}': credential bindings match one host exactly, \
             with no '*.' wildcard; bind each host you want reachable"
        ));
    }

    let url = Url::parse(&format!("https://{raw}/"))
        .map_err(|e| anyhow!("invalid --host '{raw}': {e}"))?;

    // Each of these means the parser took something the operator typed
    // and put it somewhere other than the host.
    if url.port().is_some() {
        return Err(anyhow!(
            "invalid --host '{raw}': a port is not part of the binding; \
             bindings match the host across every port"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!(
            "invalid --host '{raw}': credentials in the host are not accepted; \
             give a bare host"
        ));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "invalid --host '{raw}': give a bare host, not a URL or path"
        ));
    }

    url.host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("invalid --host '{raw}': no host"))
}

pub async fn add(
    name: &str,
    channel: Option<&str>,
    source: ValueSource,
    allowed_hosts: &[String],
) -> Result<()> {
    let cfg = config();

    // Normalized before the value is read, so a rejected binding fails
    // before the operator is prompted for a secret.
    let allowed_hosts = allowed_hosts
        .iter()
        .map(|h| normalize_host(h))
        .collect::<Result<Vec<_>>>()?;

    let value = read_credential_value(name, source)?;
    if value.is_empty() {
        anyhow::bail!("empty value");
    }

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let secret = VaultSecret::new(value);
    store
        .store_with_hosts(
            name,
            channel.unwrap_or(""),
            &secret,
            None,
            None,
            &allowed_hosts,
        )
        .context(format!("Failed to store '{name}'"))?;

    if allowed_hosts.is_empty() {
        println!("  Credential '{name}' stored (no host binding; not usable by http_request).");
    } else {
        println!(
            "  Credential '{name}' stored, bound to: {}",
            allowed_hosts.join(", ")
        );
    }
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

pub async fn rotate(name: &str, source: ValueSource) -> Result<()> {
    let cfg = config();

    let new_value = read_credential_value(name, source)?;
    if new_value.is_empty() {
        anyhow::bail!("empty value");
    }

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);

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

    #[test]
    fn normalize_host_matches_the_request_side_host() {
        // The invariant the whole normalization exists for: whatever
        // `--host` is stored as has to equal what `http_request` hands
        // `permits_host`, which is `Url::host_str` on the request URL.
        for (typed, requested) in [
            ("café.example", "https://café.example/v1/things"),
            ("Example.COM", "https://example.com/"),
            ("XN--CAF-DMA.example", "https://xn--caf-dma.example/"),
            ("api.example.com", "https://api.example.com/x?y=1"),
        ] {
            let request_host = Url::parse(requested)
                .unwrap()
                .host_str()
                .unwrap()
                .to_string();
            assert_eq!(
                normalize_host(typed).unwrap(),
                request_host,
                "stored binding for {typed} must match the request host"
            );
        }
    }

    #[test]
    fn normalize_host_preserves_ip_literals() {
        assert_eq!(normalize_host("192.168.1.1").unwrap(), "192.168.1.1");
        assert_eq!(normalize_host("[::1]").unwrap(), "[::1]");
    }

    #[test]
    fn normalize_host_rejects_anything_but_a_bare_host() {
        // Each of these parses successfully as a URL host, and each
        // would silently store a binding other than the one typed.
        for raw in [
            "https://api.example.com", // parses to the host `https`
            "api.example.com:8443",    // port dropped, binding widened
            "[::1]:8443",
            "example.com/admin",
            "user:pw@example.com",
            "example.com?a=b",
            "example.com#frag",
            "*.example.com", // no wildcard support, would never match
            "",
            "   ",
            "not a host!!",
        ] {
            assert!(
                normalize_host(raw).is_err(),
                "{raw} should be rejected, not rewritten"
            );
        }
    }
}
