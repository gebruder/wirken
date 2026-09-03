//! `wirken mcp` subcommands.
//!
//! Item 7 slice 2 of `docs/managed-agents-parity.md`. Slice 2 ships
//! one subcommand: `authorize <server>` which runs the OAuth2
//! authorization code flow with PKCE for an HTTP MCP server
//! configured with `auth.type = "oauth2"` in `~/.wirken/mcp.json`.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use wirken_gateway::skill_registry::{self, generate_signing_keypair};
use wirken_mcp_proxy::mcp_config::{McpAuth, McpConfig, McpServerConfig};
use wirken_mcp_proxy::mcp_signing::{
    McpVerifyResult, bundled_mcp_pubkey, sign_mcp_entry, verify_mcp_entry,
};
use wirken_mcp_proxy::{
    OAuthCredential, lookup_provider, run_authorization_code_flow, store_oauth,
};
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;
use super::oauth_scope::{ScopeFlags, resolve_scopes, stdin_is_tty};

/// Bootstrap an OAuth credential for one MCP server.
///
/// Reads `~/.wirken/mcp.json` (or per-agent if `--agent` is given),
/// finds the server entry, confirms it has `auth.type = "oauth2"`,
/// runs the authorization code flow against the configured
/// provider, and stores the resulting tokens in the vault under
/// the credential name from the server's auth config.
pub async fn authorize(
    server: &str,
    agent: Option<&str>,
    scope: Vec<String>,
    no_scopes: bool,
    all_scopes: bool,
) -> Result<()> {
    let cfg = config();
    let mcp_path = match agent {
        Some(a) => cfg.mcp_config_path(a),
        None => cfg.data_dir.join("mcp.json"),
    };
    if !mcp_path.exists() {
        anyhow::bail!(
            "MCP config not found at {}. Create it with the new schema first.",
            mcp_path.display()
        );
    }

    let mcp_config = McpConfig::load(&mcp_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let server_cfg = mcp_config
        .servers
        .get(server)
        .ok_or_else(|| anyhow::anyhow!("server '{server}' not found in {}", mcp_path.display()))?;

    let (provider, credential_ref) = match server_cfg {
        McpServerConfig::Http {
            auth:
                Some(McpAuth::Oauth2 {
                    provider,
                    credential,
                }),
            ..
        } => (provider.clone(), credential.clone()),
        McpServerConfig::Http { .. } => {
            anyhow::bail!(
                "server '{server}' is HTTP but its auth is not oauth2. \
                 wirken mcp authorize only works with `auth.type = \"oauth2\"`."
            );
        }
        McpServerConfig::Stdio { .. } => {
            anyhow::bail!(
                "server '{server}' is a stdio MCP server. wirken mcp authorize \
                 only applies to HTTP MCP servers with OAuth2 auth."
            );
        }
    };

    let provider_def = lookup_provider(&provider).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown OAuth provider '{provider}'. Slice 2 supports: linear, notion, github, google."
        )
    })?;

    let credential_name = credential_ref
        .strip_prefix("vault:")
        .unwrap_or(&credential_ref)
        .to_string();

    println!();
    println!("  wirken mcp authorize");
    println!("  ────────────────────");
    println!("  server:     {server}");
    println!("  provider:   {provider}");
    println!("  credential: {credential_name}");
    println!();

    // Bundle A item 3 slice 2: operator-facing scope selection. The
    // resolver returns the operator's chosen scope set with the
    // required floor unconditionally included. Required scopes
    // (per the slice-1 catalog) are non-negotiable; explicit flags
    // augment the floor, the interactive picker is the default at a
    // TTY. The result is passed as `extra_scopes` and unioned with
    // the provider's hardcoded `default_scopes` inside
    // `run_authorization_code_flow`; slice 3 unifies those layers.
    let scope_flags = ScopeFlags {
        scope,
        no_scopes,
        all_scopes,
    };
    let extra_scopes = resolve_scopes(provider_def, &scope_flags, stdin_is_tty())?;

    println!();
    println!("  Requesting scopes:");
    for s in provider_def.default_scopes {
        println!("    {s}  (provider default)");
    }
    for s in &extra_scopes {
        // Mark required entries so the operator can tell which came
        // from the floor and which were their explicit pick.
        let is_required = provider_def.scopes.iter().any(|c| c.id == s && c.required);
        if is_required {
            println!("    {s}  (required)");
        } else {
            println!("    {s}");
        }
    }
    println!();

    // Run the OAuth flow. This opens the user's browser and waits
    // for the redirect.
    let cred: OAuthCredential = run_authorization_code_flow(&provider, &extra_scopes)
        .await
        .map_err(|e| anyhow::anyhow!("OAuth authorization failed: {e}"))?;

    // Store the resulting tokens in the vault.
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store_oauth(&store, &credential_name, &cred)
        .map_err(|e| anyhow::anyhow!("vault write failed: {e}"))?;

    println!();
    println!("  Authorized. Tokens stored in vault under '{credential_name}'.");
    println!("  The MCP proxy will refresh the access token automatically when it expires.");
    Ok(())
}

/// Sign one MCP entry in `mcp.json`. Reuses the operator's
/// `signing-key.hex` (the same file `wirken skills sign` uses);
/// generates one on first use. Writes `signature` + `signer_key`
/// back into the entry and saves the file.
pub fn sign(server: &str, agent: Option<&str>) -> Result<()> {
    let cfg = config();
    let mcp_path = match agent {
        Some(a) => cfg.mcp_config_path(a),
        None => cfg.data_dir.join("mcp.json"),
    };
    if !mcp_path.exists() {
        anyhow::bail!("MCP config not found at {}.", mcp_path.display());
    }

    // Round-trip through the typed schema so the file we write back
    // is a normalized form (sorted maps, dropped Nones), but parse
    // first into a serde_json::Value so unknown keys survive.
    let raw = std::fs::read_to_string(&mcp_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", mcp_path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", mcp_path.display()))?;

    // Build a typed view to verify the entry's shape and to derive
    // the canonical hash. The signature is computed over the typed
    // representation; the raw Value carries the write-back.
    let typed: McpConfig = serde_json::from_value(value.clone())
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", mcp_path.display()))?;
    let entry = typed
        .servers
        .get(server)
        .ok_or_else(|| anyhow::anyhow!("server '{server}' not found in {}", mcp_path.display()))?;

    let key_path = cfg.data_dir.join("signing-key.hex");
    let signing_key = load_or_create_signing_key(&key_path)?;

    let signature = sign_mcp_entry(server, entry, &signing_key);
    let signer_pub = hex_encode(&signing_key.verifying_key().to_bytes());

    // Patch the signature + signer_key fields onto the entry in the
    // raw JSON tree. `signer_key_delegation` is operator-supplied at
    // a higher trust tier and is not minted here; this command signs
    // with the operator's local key only.
    let server_obj = value
        .get_mut("servers")
        .and_then(|s| s.get_mut(server))
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("server '{server}' missing from JSON tree (parse drift)"))?;
    server_obj.insert(
        "signature".into(),
        serde_json::Value::String(signature.clone()),
    );
    server_obj.insert(
        "signer_key".into(),
        serde_json::Value::String(signer_pub.clone()),
    );

    let pretty =
        serde_json::to_string_pretty(&value).map_err(|e| anyhow::anyhow!("serialize: {e}"))?;
    std::fs::write(&mcp_path, pretty)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", mcp_path.display()))?;

    println!("  Signed: {server} in {}", mcp_path.display());
    println!(
        "  Signature: {}...{}",
        &signature[..16],
        &signature[signature.len() - 16..]
    );
    println!("  Public key: {signer_pub}");
    Ok(())
}

/// Verify the signature on one or every entry in `mcp.json`. Prints
/// `valid`, `invalid`, or `unsigned` per entry. Exit status is 0
/// when every entry is valid or unsigned; non-zero when any entry
/// reports `invalid`.
pub fn verify(server: Option<&str>, agent: Option<&str>) -> Result<()> {
    let cfg = config();
    let mcp_path = match agent {
        Some(a) => cfg.mcp_config_path(a),
        None => cfg.data_dir.join("mcp.json"),
    };
    if !mcp_path.exists() {
        anyhow::bail!("MCP config not found at {}.", mcp_path.display());
    }

    let mcp_config = McpConfig::load(&mcp_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let bundled_root = bundled_mcp_pubkey();

    let mut had_invalid = false;
    let names: Vec<&String> = match server {
        Some(s) => mcp_config
            .servers
            .iter()
            .filter(|(n, _)| n.as_str() == s)
            .map(|(n, _)| n)
            .collect(),
        None => mcp_config.servers.keys().collect(),
    };
    if let Some(s) = server
        && names.is_empty()
    {
        anyhow::bail!("server '{}' not found in {}", s, mcp_path.display());
    }
    if names.is_empty() {
        println!("  No MCP servers configured.");
        return Ok(());
    }

    let mut sorted: Vec<&String> = names;
    sorted.sort();
    for name in sorted {
        let entry = mcp_config
            .servers
            .get(name)
            .expect("name came from this map");
        let (sig, key, delegation) = match entry {
            McpServerConfig::Stdio {
                signature,
                signer_key,
                signer_key_delegation,
                ..
            }
            | McpServerConfig::Http {
                signature,
                signer_key,
                signer_key_delegation,
                ..
            } => (
                signature.as_deref(),
                signer_key.as_deref(),
                signer_key_delegation.as_deref(),
            ),
        };
        let result = verify_mcp_entry(name, entry, sig, key, delegation, bundled_root.as_ref());
        let label = match &result {
            McpVerifyResult::Valid { signer } => format!("valid (signer {}...)", &signer[..16]),
            McpVerifyResult::Invalid => {
                had_invalid = true;
                "invalid".to_string()
            }
            McpVerifyResult::Unsigned => "unsigned".to_string(),
        };
        println!("  {name:.<24} {label}");
    }

    if bundled_root.is_none() {
        println!();
        println!(
            "  Note: no compile-time MCP anchor in this build. \
             Unsigned entries load by default; signed entries verify against \
             their inline signer_key."
        );
    } else {
        println!();
        println!(
            "  Anchor configured in this build. Unsigned entries refuse to \
             load unless WIRKEN_ALLOW_UNSIGNED_MCP=1 is set."
        );
    }

    if had_invalid {
        anyhow::bail!("one or more entries failed verification");
    }
    Ok(())
}

fn load_or_create_signing_key(key_path: &std::path::Path) -> Result<SigningKey> {
    if key_path.exists() {
        let hex = std::fs::read_to_string(key_path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", key_path.display()))?;
        let bytes = skill_registry::hex_decode_public(hex.trim())
            .map_err(|e| anyhow::anyhow!("decode signing key: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "signing key at {} has {} bytes, expected 32",
                key_path.display(),
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    } else {
        let (secret_hex, public_hex) = generate_signing_keypair();
        let parent = key_path.parent().ok_or_else(|| {
            anyhow::anyhow!("signing key path has no parent: {}", key_path.display())
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
        std::fs::write(key_path, &secret_hex)
            .map_err(|e| anyhow::anyhow!("write {}: {e}", key_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("chmod {}: {e}", key_path.display()))?;
        }

        println!("  Generated new signing keypair.");
        println!("  Public key: {public_hex}");
        println!("  Secret key saved to {}", key_path.display());
        println!();

        let bytes = skill_registry::hex_decode_public(&secret_hex)
            .map_err(|e| anyhow::anyhow!("decode generated key: {e}"))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
