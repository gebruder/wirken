//! `wirken mcp` subcommands.
//!
//! Item 7 slice 2 of `docs/managed-agents-parity.md`. Slice 2 ships
//! one subcommand: `authorize <server>` which runs the OAuth2
//! authorization code flow with PKCE for an HTTP MCP server
//! configured with `auth.type = "oauth2"` in `~/.wirken/mcp.json`.

use anyhow::{Context, Result};
use dialoguer::Password;

use wirken_mcp_proxy::mcp_config::{McpAuth, McpConfig, McpServerConfig};
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
    let keychain = probe_keychain(&cfg.data_dir, || {
        Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store_oauth(&store, &credential_name, &cred)
        .map_err(|e| anyhow::anyhow!("vault write failed: {e}"))?;

    println!();
    println!("  Authorized. Tokens stored in vault under '{credential_name}'.");
    println!("  The MCP proxy will refresh the access token automatically when it expires.");
    Ok(())
}
