//! OAuth2 support for HTTP MCP servers.
//!
//! Item 7 slice 2 of `docs/managed-agents-parity.md`. Three pieces:
//!
//! 1. **Provider registry.** A hardcoded table of well-known OAuth2
//!    providers (Linear, Notion, GitHub, Google) with their auth
//!    URLs, token URLs, and default scopes. Per decision 5 of the
//!    slice 2 design, slice 2 hardcodes; future work may add
//!    `.well-known/oauth-authorization-server` discovery.
//!
//! 2. **Authorization code flow runner.** [`run_authorization_code_flow`]
//!    runs the OAuth dance with PKCE: generate verifier + challenge,
//!    open the user's browser to the auth URL, spin up a localhost
//!    redirect server on a random port, wait for the redirect,
//!    exchange the code for tokens. Used by the
//!    `wirken mcp authorize <server>` CLI.
//!
//! 3. **Token storage.** [`OAuthCredential`] is the JSON-serialized
//!    payload stored in the vault as an opaque secret.
//!    [`store_oauth`] / [`load_oauth`] wrap the existing
//!    `CredentialStore` API.
//!
//! 4. **Refresh.** [`refresh_oauth_token`] POSTs to the provider's
//!    token endpoint with `grant_type=refresh_token`. Used by
//!    [`crate::auth::OAuth2Auth`] on the request path when the
//!    access token is within 60 seconds of expiry.
//!
//! ## OAuth client_id strategy
//!
//! Per decision 6 (B in the open questions), Wirken does NOT embed
//! its own registered client_id at the providers — it can't claim
//! to be a registered OAuth app at services it isn't. Operators
//! register their own OAuth app at each provider and supply the
//! client_id (and optionally client_secret) via environment
//! variables: `WIRKEN_LINEAR_CLIENT_ID`, `WIRKEN_NOTION_CLIENT_ID`,
//! `WIRKEN_GITHUB_CLIENT_ID`, `WIRKEN_GOOGLE_CLIENT_ID`. Same for
//! `*_CLIENT_SECRET` if the provider requires a confidential
//! client. The `wirken mcp authorize` CLI fails with a clear error
//! if the env var is missing.

use std::time::{SystemTime, UNIX_EPOCH};

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use wirken_vault::CredentialStore;

use crate::error::ProxyError;

/// One entry in the OAuth provider registry.
pub struct OAuthProvider {
    pub name: &'static str,
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub default_scopes: &'static [&'static str],
    pub client_id_env: &'static str,
    /// Some providers (Google) require a client_secret for the
    /// authorization code grant; others (most installed-app
    /// flows) accept PKCE alone. Slice 2 sets this to `Some` for
    /// every provider since none of the four supported providers
    /// is fully public-client; users can leave the env var unset
    /// if they registered a public OAuth app.
    pub client_secret_env: Option<&'static str>,
}

const LINEAR: OAuthProvider = OAuthProvider {
    name: "linear",
    auth_url: "https://linear.app/oauth/authorize",
    token_url: "https://api.linear.app/oauth/token",
    default_scopes: &["read", "write"],
    client_id_env: "WIRKEN_LINEAR_CLIENT_ID",
    client_secret_env: Some("WIRKEN_LINEAR_CLIENT_SECRET"),
};

const NOTION: OAuthProvider = OAuthProvider {
    name: "notion",
    auth_url: "https://api.notion.com/v1/oauth/authorize",
    token_url: "https://api.notion.com/v1/oauth/token",
    default_scopes: &[],
    client_id_env: "WIRKEN_NOTION_CLIENT_ID",
    client_secret_env: Some("WIRKEN_NOTION_CLIENT_SECRET"),
};

const GITHUB: OAuthProvider = OAuthProvider {
    name: "github",
    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    default_scopes: &["repo", "read:user"],
    client_id_env: "WIRKEN_GITHUB_CLIENT_ID",
    client_secret_env: Some("WIRKEN_GITHUB_CLIENT_SECRET"),
};

const GOOGLE: OAuthProvider = OAuthProvider {
    name: "google",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    default_scopes: &["https://www.googleapis.com/auth/drive.readonly"],
    client_id_env: "WIRKEN_GOOGLE_CLIENT_ID",
    client_secret_env: Some("WIRKEN_GOOGLE_CLIENT_SECRET"),
};

/// Look up a provider by name. Returns `None` if the name isn't in
/// the slice 2 registry.
pub fn lookup_provider(name: &str) -> Option<&'static OAuthProvider> {
    match name {
        "linear" => Some(&LINEAR),
        "notion" => Some(&NOTION),
        "github" => Some(&GITHUB),
        "google" => Some(&GOOGLE),
        _ => None,
    }
}

/// All known provider names. Used by the CLI to print a friendly
/// error when the user types an unknown one.
pub fn provider_names() -> &'static [&'static str] {
    &["linear", "notion", "github", "google"]
}

// ---------------------------------------------------------------------------
// OAuthCredential — the JSON payload stored in the vault
// ---------------------------------------------------------------------------

/// Stored OAuth credential. Lives in the vault as a UTF-8 JSON
/// string under a `vault:NAME` reference. The full JSON is the
/// secret — do NOT log or expose any field other than `provider`
/// and `expires_at` for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp seconds.
    pub expires_at: u64,
    pub scope: String,
    pub provider: String,
}

/// Serialize an [`OAuthCredential`] as JSON and store it in the
/// vault under `name`. Uses `INSERT OR REPLACE` semantics so the
/// same call works for both initial bootstrap and refresh write-back.
/// The `channel` field on the vault entry is set to the literal
/// string `"oauth"` so operators can `wirken credentials list` and
/// see at a glance which entries belong to OAuth-managed servers.
pub fn store_oauth(
    store: &CredentialStore,
    name: &str,
    cred: &OAuthCredential,
) -> Result<(), ProxyError> {
    let json = serde_json::to_string(cred)
        .map_err(|e| ProxyError::Vault(format!("serialize oauth credential: {e}")))?;
    let secret = wirken_vault::VaultSecret::new(json);
    store
        .store(name, "oauth", &secret, None, None)
        .map_err(|e| ProxyError::Vault(format!("store oauth credential '{name}': {e}")))?;
    Ok(())
}

/// Read and parse an [`OAuthCredential`] from the vault.
pub fn load_oauth(store: &CredentialStore, name: &str) -> Result<OAuthCredential, ProxyError> {
    let (secret, _meta) = store
        .retrieve(name)
        .map_err(|e| ProxyError::Vault(format!("load oauth credential '{name}': {e}")))?;
    let cred: OAuthCredential = serde_json::from_str(secret.expose())
        .map_err(|e| ProxyError::Vault(format!("parse oauth credential '{name}': {e}")))?;
    Ok(cred)
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

/// Refresh an access token using the stored refresh token. Called
/// by [`crate::auth::OAuth2Auth`] on the request path when the
/// existing token is within 60 seconds of expiry.
///
/// The provider's `client_id` (and optional `client_secret`) come
/// from environment variables — see the module-level docs for the
/// strategy.
pub async fn refresh_oauth_token(
    provider_name: &str,
    cred: &OAuthCredential,
) -> Result<OAuthCredential, ProxyError> {
    let provider = lookup_provider(provider_name).ok_or_else(|| {
        ProxyError::Vault(format!(
            "unknown OAuth provider '{provider_name}'. Known: {:?}",
            provider_names()
        ))
    })?;

    let client = build_oauth_client(provider, /*redirect_uri=*/ None)?;
    let http_client = reqwest_http_client()?;

    let token = client
        .exchange_refresh_token(&RefreshToken::new(cred.refresh_token.clone()))
        .request_async(&http_client)
        .await
        .map_err(|e| ProxyError::Vault(format!("refresh request: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_in = token.expires_in().map(|d| d.as_secs()).unwrap_or(3600);

    Ok(OAuthCredential {
        access_token: token.access_token().secret().clone(),
        // Some providers don't rotate refresh tokens; reuse the
        // existing one if the response didn't include a new one.
        refresh_token: token
            .refresh_token()
            .map(|r| r.secret().clone())
            .unwrap_or_else(|| cred.refresh_token.clone()),
        expires_at: now + expires_in,
        scope: token
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| cred.scope.clone()),
        provider: cred.provider.clone(),
    })
}

// ---------------------------------------------------------------------------
// Authorization code flow with PKCE + localhost redirect
// ---------------------------------------------------------------------------

/// Run the OAuth2 authorization code flow for `provider_name` and
/// return the resulting credential. Spins up a localhost redirect
/// server on a random port, opens the user's browser to the
/// authorization URL (or prints it if the browser cannot be
/// launched), waits up to 5 minutes for the redirect, exchanges
/// the code for tokens, and returns the [`OAuthCredential`].
///
/// The caller is responsible for storing the result in the vault
/// (typically via [`store_oauth`]).
pub async fn run_authorization_code_flow(
    provider_name: &str,
    extra_scopes: &[String],
) -> Result<OAuthCredential, ProxyError> {
    let provider = lookup_provider(provider_name).ok_or_else(|| {
        ProxyError::Vault(format!(
            "unknown OAuth provider '{provider_name}'. Known: {:?}",
            provider_names()
        ))
    })?;

    // Bind localhost on a random port FIRST so we know the redirect URL.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| ProxyError::Vault(format!("bind localhost callback: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| ProxyError::Vault(format!("local addr: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let client = build_oauth_client(provider, Some(redirect_uri.clone()))?;

    // PKCE: verifier + challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Build the authorization URL with the requested scopes.
    let mut auth_request = client.authorize_url(CsrfToken::new_random);
    for s in provider.default_scopes {
        auth_request = auth_request.add_scope(Scope::new((*s).to_string()));
    }
    for s in extra_scopes {
        auth_request = auth_request.add_scope(Scope::new(s.clone()));
    }
    auth_request = auth_request.set_pkce_challenge(pkce_challenge);

    let (auth_url, csrf_token) = auth_request.url();

    eprintln!();
    eprintln!("  Open this URL in your browser to authorize wirken:");
    eprintln!();
    eprintln!("    {auth_url}");
    eprintln!();
    if let Err(e) = open::that(auth_url.as_str()) {
        eprintln!("  (could not auto-open browser: {e})");
    }
    eprintln!("  Waiting for the redirect (5 minute timeout) …");
    eprintln!();

    // Wait for the callback with a 5 minute deadline.
    let deadline = std::time::Duration::from_secs(300);
    let received = tokio::time::timeout(deadline, accept_callback(listener))
        .await
        .map_err(|_| ProxyError::Vault("timed out waiting for OAuth redirect".into()))??;

    // Verify CSRF state.
    if received.state != *csrf_token.secret() {
        return Err(ProxyError::Vault(
            "OAuth redirect state mismatch — possible CSRF or stale request".into(),
        ));
    }

    // Exchange the code for tokens.
    let http_client = reqwest_http_client()?;
    let token = client
        .exchange_code(AuthorizationCode::new(received.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| ProxyError::Vault(format!("token exchange: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_in = token.expires_in().map(|d| d.as_secs()).unwrap_or(3600);

    Ok(OAuthCredential {
        access_token: token.access_token().secret().clone(),
        refresh_token: token
            .refresh_token()
            .map(|r| r.secret().clone())
            .ok_or_else(|| {
                ProxyError::Vault(
                    "OAuth response did not include a refresh_token. Some providers \
                     require an `access_type=offline` parameter or a special scope; \
                     check the provider's developer docs."
                        .into(),
                )
            })?,
        expires_at: now + expires_in,
        scope: token
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| provider.default_scopes.join(" ")),
        provider: provider.name.to_string(),
    })
}

struct CallbackParams {
    code: String,
    state: String,
}

async fn accept_callback(listener: tokio::net::TcpListener) -> Result<CallbackParams, ProxyError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| ProxyError::Vault(format!("accept callback: {e}")))?;
    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| ProxyError::Vault(format!("read callback: {e}")))?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    // Expecting "GET /callback?code=...&state=... HTTP/1.1"
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            let decoded = percent_decode(v);
            match k {
                "code" => code = Some(decoded),
                "state" => state = Some(decoded),
                _ => {}
            }
        }
    }

    let body = "<html><body><h1>wirken: authorization complete</h1>\
                 <p>You can close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    let code =
        code.ok_or_else(|| ProxyError::Vault("OAuth redirect missing `code` parameter".into()))?;
    let state = state
        .ok_or_else(|| ProxyError::Vault("OAuth redirect missing `state` parameter".into()))?;
    Ok(CallbackParams { code, state })
}

fn percent_decode(s: &str) -> String {
    // Tiny URL-decode. The OAuth params are typically URL-safe
    // base64 codes and a CSRF token; full RFC 3986 compliance is
    // overkill for slice 2.
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let h1 = bytes.next();
            let h2 = bytes.next();
            if let (Some(h1), Some(h2)) = (h1, h2)
                && let (Some(d1), Some(d2)) = (hex_digit(h1), hex_digit(h2))
            {
                out.push((d1 * 16 + d2) as char);
                continue;
            }
        } else if b == b'+' {
            out.push(' ');
            continue;
        }
        out.push(b as char);
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// oauth2 client construction
// ---------------------------------------------------------------------------

type OAuthClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

fn build_oauth_client(
    provider: &OAuthProvider,
    redirect_uri: Option<String>,
) -> Result<OAuthClient, ProxyError> {
    let client_id = std::env::var(provider.client_id_env).map_err(|_| {
        ProxyError::Vault(format!(
            "missing OAuth client id env var {}. Register an OAuth app at the {} \
             developer console and export {}=<id> before running this command. \
             Wirken does not embed registered OAuth client ids — see the slice 2 \
             notes in docs/managed-agents-parity.md item 7.",
            provider.client_id_env, provider.name, provider.client_id_env
        ))
    })?;

    let client_secret = provider
        .client_secret_env
        .and_then(|env| std::env::var(env).ok())
        .map(ClientSecret::new);

    let mut client = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(provider.auth_url.to_string())
                .map_err(|e| ProxyError::Vault(format!("invalid auth_url: {e}")))?,
        )
        .set_token_uri(
            TokenUrl::new(provider.token_url.to_string())
                .map_err(|e| ProxyError::Vault(format!("invalid token_url: {e}")))?,
        );

    if let Some(secret) = client_secret {
        client = client.set_client_secret(secret);
    }
    if let Some(uri) = redirect_uri {
        client = client.set_redirect_uri(
            RedirectUrl::new(uri)
                .map_err(|e| ProxyError::Vault(format!("invalid redirect_uri: {e}")))?,
        );
    }

    Ok(client)
}

/// HTTP client for OAuth token requests. The oauth2 crate ships its
/// own reqwest dependency at a different version from the workspace
/// reqwest, so we use the bundled re-export to satisfy oauth2's
/// `AsyncHttpClient` trait bound.
fn reqwest_http_client() -> Result<oauth2::reqwest::Client, ProxyError> {
    oauth2::reqwest::Client::builder()
        // The oauth2 crate forbids redirects (RFC 6749 section 3.1.2).
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ProxyError::Vault(format!("oauth http client: {e}")))
}
