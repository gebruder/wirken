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
    /// Bundle A item 3 slice 1: catalog of OAuth scopes the
    /// interactive picker offers for this provider. The picker
    /// (slice 2) renders a `dialoguer::MultiSelect` from this
    /// catalog with `required: true` entries pre-checked and not
    /// de-selectable. Slice 3 routes the picker's output into the
    /// authorization URL via the existing `extra_scopes` parameter
    /// on [`run_authorization_code_flow`]; `default_scopes` above
    /// stays in place until slice 3 unifies the two.
    pub scopes: &'static [ScopeChoice],
}

/// Coarse grouping for picker display order. The picker renders
/// categories in this order so the most-likely-needed scopes
/// surface first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeCategory {
    /// Identity / user info. Typically the required minimum so the
    /// operator can answer "whose credential is this".
    Profile,
    /// Read-only access to provider resources.
    Read,
    /// Mutations: create, update, send, delete.
    Write,
    /// Administrative or dangerous scopes (org admin, full Drive,
    /// workflow modification).
    Admin,
}

/// One entry in a provider's scope catalog. The picker consumes
/// `&'static [ScopeChoice]` and renders a `MultiSelect` UI;
/// `required` scopes are pre-checked and not de-selectable so the
/// operator cannot submit a scope set the provider would reject or
/// that leaves wirken unable to identify the credential owner.
///
/// Named `ScopeChoice` to distinguish from `oauth2::Scope` (the
/// protocol-level scope string the `oauth2` crate hands to the
/// authorization URL builder); the picker offers choices, each
/// choice maps to one `oauth2::Scope` at flow time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeChoice {
    /// The OAuth scope string the provider accepts on the
    /// authorization URL (e.g. `"read"`, `"repo"`,
    /// `"https://www.googleapis.com/auth/drive.readonly"`).
    pub id: &'static str,
    /// One-line operator-facing description of what the scope
    /// authorizes. Rendered in the picker UI alongside the id.
    pub description: &'static str,
    /// Coarse grouping for picker display order.
    pub category: ScopeCategory,
    /// `true` when the picker must pre-check and lock this entry.
    /// Two reasons to mark required: the provider rejects auth
    /// without this scope (Google rejects empty scope lists, Linear
    /// requires at least one), or wirken cannot identify the
    /// credential owner without it (Linear `read`, GitHub
    /// `read:user`). All other scopes default to `false`; the
    /// operator picks.
    pub required: bool,
}

/// Linear scope catalog. Linear rejects auth requests with no
/// scope; `read` is the minimum that also identifies the
/// credential owner.
const LINEAR_SCOPES: &[ScopeChoice] = &[
    ScopeChoice {
        id: "read",
        description: "Read issues, comments, projects, and basic user identity",
        category: ScopeCategory::Profile,
        required: true,
    },
    ScopeChoice {
        id: "write",
        description: "Create and update issues, comments, projects (broad write)",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "issues:create",
        description: "Create issues only (narrower than `write`)",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "comments:create",
        description: "Create comments only (narrower than `write`)",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "admin",
        description: "Workspace administration (members, settings)",
        category: ScopeCategory::Admin,
        required: false,
    },
];

/// Notion does not use OAuth scopes for permission scoping. Each
/// Notion integration receives access to a per-workspace set of
/// pages selected during the Notion connection UI, not via OAuth
/// scopes. The picker (slice 2) short-circuits for this provider
/// with a "no scope choices needed at OAuth time" message; this
/// empty catalog is the data representation of that fact.
const NOTION_SCOPES: &[ScopeChoice] = &[];

/// GitHub scope catalog. GitHub accepts auth requests with no
/// scopes (the resulting token has public-only read), but
/// `read:user` is the minimum for wirken to identify the
/// credential owner.
const GITHUB_SCOPES: &[ScopeChoice] = &[
    ScopeChoice {
        id: "read:user",
        description: "Read the authenticated user's profile information",
        category: ScopeCategory::Profile,
        required: true,
    },
    ScopeChoice {
        id: "user:email",
        description: "Read the authenticated user's email addresses",
        category: ScopeCategory::Profile,
        required: false,
    },
    ScopeChoice {
        id: "repo",
        description: "Full control of private and public repositories",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "public_repo",
        description: "Public-repository read and write (narrower than `repo`)",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "read:org",
        description: "Read organization membership and team listings",
        category: ScopeCategory::Read,
        required: false,
    },
    ScopeChoice {
        id: "gist",
        description: "Create and modify gists",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "workflow",
        description: "Update GitHub Actions workflow files",
        category: ScopeCategory::Admin,
        required: false,
    },
];

/// Google scope catalog. Google rejects auth requests with empty
/// scope lists; `openid` plus `userinfo.email` is the OIDC
/// identity minimum.
const GOOGLE_SCOPES: &[ScopeChoice] = &[
    ScopeChoice {
        id: "openid",
        description: "OIDC identity (subject identifier)",
        category: ScopeCategory::Profile,
        required: true,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/userinfo.email",
        description: "Email address",
        category: ScopeCategory::Profile,
        required: true,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/userinfo.profile",
        description: "Display name and profile picture",
        category: ScopeCategory::Profile,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/drive.readonly",
        description: "Read-only access to Drive files",
        category: ScopeCategory::Read,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/drive.file",
        description: "Per-file Drive access for files created by this app",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/drive",
        description: "Full Drive access (broad)",
        category: ScopeCategory::Admin,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/gmail.readonly",
        description: "Read-only Gmail access",
        category: ScopeCategory::Read,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/gmail.send",
        description: "Send mail via Gmail",
        category: ScopeCategory::Write,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/calendar.readonly",
        description: "Read-only Calendar access",
        category: ScopeCategory::Read,
        required: false,
    },
    ScopeChoice {
        id: "https://www.googleapis.com/auth/calendar.events",
        description: "Create and modify Calendar events",
        category: ScopeCategory::Write,
        required: false,
    },
];

const LINEAR: OAuthProvider = OAuthProvider {
    name: "linear",
    auth_url: "https://linear.app/oauth/authorize",
    token_url: "https://api.linear.app/oauth/token",
    default_scopes: &["read", "write"],
    client_id_env: "WIRKEN_LINEAR_CLIENT_ID",
    client_secret_env: Some("WIRKEN_LINEAR_CLIENT_SECRET"),
    scopes: LINEAR_SCOPES,
};

const NOTION: OAuthProvider = OAuthProvider {
    name: "notion",
    auth_url: "https://api.notion.com/v1/oauth/authorize",
    token_url: "https://api.notion.com/v1/oauth/token",
    default_scopes: &[],
    client_id_env: "WIRKEN_NOTION_CLIENT_ID",
    client_secret_env: Some("WIRKEN_NOTION_CLIENT_SECRET"),
    scopes: NOTION_SCOPES,
};

const GITHUB: OAuthProvider = OAuthProvider {
    name: "github",
    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    default_scopes: &["repo", "read:user"],
    client_id_env: "WIRKEN_GITHUB_CLIENT_ID",
    client_secret_env: Some("WIRKEN_GITHUB_CLIENT_SECRET"),
    scopes: GITHUB_SCOPES,
};

const GOOGLE: OAuthProvider = OAuthProvider {
    name: "google",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    default_scopes: &["https://www.googleapis.com/auth/drive.readonly"],
    client_id_env: "WIRKEN_GOOGLE_CLIENT_ID",
    client_secret_env: Some("WIRKEN_GOOGLE_CLIENT_SECRET"),
    scopes: GOOGLE_SCOPES,
};

/// Compute the set of scope ids the picker pre-checks. Returns
/// every `required: true` scope in catalog order. Used by slice 2
/// as the initial selection state for `dialoguer::MultiSelect`.
/// The picker also consults `required` per-entry to lock the
/// pre-checked items so the operator cannot deselect them.
pub fn default_selected_scopes(provider: &OAuthProvider) -> Vec<&'static str> {
    provider
        .scopes
        .iter()
        .filter(|s| s.required)
        .map(|s| s.id)
        .collect()
}

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
    // Expecting "GET /callback?code=...&state=... HTTP/1.1" — or, on
    // user denial, "GET /callback?error=access_denied&...".
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            let decoded = percent_decode(v);
            match k {
                "code" => code = Some(decoded),
                "state" => state = Some(decoded),
                "error" => error = Some(decoded),
                "error_description" => error_description = Some(decoded),
                _ => {}
            }
        }
    }

    // If the provider returned an error (typically because the user
    // clicked "deny"), send a friendlier page to the browser and
    // surface the error to the caller. The CLI shows this message
    // instead of the confusing "missing `code` parameter".
    if let Some(err) = error {
        let desc = error_description.unwrap_or_default();
        let body = format!(
            "<html><body><h1>wirken: authorization failed</h1>\
                 <p>The provider returned <code>error={err}</code>.</p>\
                 <p>{desc}</p>\
                 <p>You can close this tab and try again.</p></body></html>"
        );
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;

        let detail = if desc.is_empty() {
            String::new()
        } else {
            format!(": {desc}")
        };
        return Err(ProxyError::Vault(format!(
            "OAuth authorization failed ({err}){detail}"
        )));
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

#[cfg(test)]
mod scope_catalog_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn three_providers_have_a_scope_catalog_and_notion_is_intentionally_empty() {
        // Notion handles per-workspace permissions outside OAuth
        // scopes; its empty catalog is the data representation of
        // the slice-2 short-circuit.
        assert!(!LINEAR.scopes.is_empty());
        assert!(!GITHUB.scopes.is_empty());
        assert!(!GOOGLE.scopes.is_empty());
        assert_eq!(NOTION.scopes.len(), 0);
    }

    #[test]
    fn linear_requires_read_for_identity() {
        let required: Vec<&str> = LINEAR
            .scopes
            .iter()
            .filter(|s| s.required)
            .map(|s| s.id)
            .collect();
        assert_eq!(required, vec!["read"]);
    }

    #[test]
    fn github_requires_read_user_for_credential_owner_identification() {
        let required: Vec<&str> = GITHUB
            .scopes
            .iter()
            .filter(|s| s.required)
            .map(|s| s.id)
            .collect();
        assert!(
            required.contains(&"read:user"),
            "GitHub picker must require read:user; got {required:?}",
        );
    }

    #[test]
    fn google_requires_oidc_identity_minimum() {
        // Google rejects empty scope lists; OIDC identity needs
        // openid plus an email or profile scope. Both are required
        // here so the picker pre-checks both and locks them.
        let required: Vec<&str> = GOOGLE
            .scopes
            .iter()
            .filter(|s| s.required)
            .map(|s| s.id)
            .collect();
        assert!(required.contains(&"openid"));
        assert!(
            required.iter().any(|s| s.ends_with("/userinfo.email")),
            "Google required set must include userinfo.email; got {required:?}",
        );
    }

    #[test]
    fn notion_has_no_required_scopes() {
        // Empty catalog implies empty required set; the picker
        // short-circuits this provider rather than rendering an
        // empty MultiSelect.
        let required = NOTION.scopes.iter().filter(|s| s.required).count();
        assert_eq!(required, 0);
    }

    #[test]
    fn default_selected_scopes_returns_required_in_catalog_order() {
        let google_defaults = default_selected_scopes(&GOOGLE);
        let required_in_catalog: Vec<&str> = GOOGLE
            .scopes
            .iter()
            .filter(|s| s.required)
            .map(|s| s.id)
            .collect();
        assert_eq!(google_defaults, required_in_catalog);
    }

    #[test]
    fn default_selected_scopes_empty_for_notion() {
        assert!(default_selected_scopes(&NOTION).is_empty());
    }

    #[test]
    fn scope_ids_are_unique_within_each_provider() {
        for provider in [&LINEAR, &NOTION, &GITHUB, &GOOGLE] {
            let mut seen = BTreeSet::new();
            for scope in provider.scopes {
                assert!(
                    seen.insert(scope.id),
                    "duplicate scope id '{}' in provider '{}'",
                    scope.id,
                    provider.name
                );
            }
        }
    }

    #[test]
    fn every_required_scope_is_in_profile_category() {
        // Required scopes exist for identity; the picker renders
        // them under Profile. If a future required entry lands in
        // Read / Write / Admin that's a real design decision worth
        // re-examining, not an oversight: this test catches the
        // drift.
        for provider in [&LINEAR, &NOTION, &GITHUB, &GOOGLE] {
            for scope in provider.scopes {
                if scope.required {
                    assert_eq!(
                        scope.category,
                        ScopeCategory::Profile,
                        "required scope '{}' on provider '{}' is not in Profile category",
                        scope.id,
                        provider.name,
                    );
                }
            }
        }
    }

    #[test]
    fn lookup_provider_finds_every_known_name() {
        for name in provider_names() {
            assert!(
                lookup_provider(name).is_some(),
                "lookup_provider failed for '{name}'",
            );
        }
    }
}
