//! OAuth2 support for HTTP MCP servers, and for an LLM provider that
//! grants plan usage over OAuth (ChatGPT, through Sign in with ChatGPT).
//!
//! Three pieces:
//!
//! 1. **Provider registry.** A hardcoded table of well-known OAuth2
//!    providers (Linear, Notion, GitHub, Google) with their auth
//!    URLs, token URLs, and default scopes. Hardcoded rather than
//!    discovered, so a provider's endpoints cannot move under a
//!    running deployment without a release saying so.
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
//!    token endpoint with `grant_type=refresh_token`. Run in the
//!    gateway by [`crate::refresh_service`] when the proxy's
//!    [`crate::auth::OAuth2Auth`] finds its access token within 60
//!    seconds of expiry.
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
//!
//! ChatGPT is the exception, by the provider's own design: an
//! open-source app is a public client with no secret that registers
//! itself on the first sign-in (`client_id=dynamic_agent_client`), and
//! the callback carries the issued id, which is stored with the
//! credential and used for every later exchange, refresh and sign-in
//! from that data directory. See [`ClientIdSource`].

use std::time::{SystemTime, UNIX_EPOCH};

use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use wirken_vault::CredentialStore;

use crate::error::ProxyError;

/// Where a provider's OAuth client id comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIdSource {
    /// The operator registered an OAuth app at the provider and
    /// exports its id in this environment variable.
    Env(&'static str),
    /// The provider registers the app on its first sign-in: the
    /// authorization request carries `bootstrap` as the client id,
    /// the callback carries the issued one, and that issued id is
    /// stored on the credential ([`OAuthCredential::client_id`]) for
    /// every later request. No environment variable is read.
    Dynamic { bootstrap: &'static str },
}

/// One entry in the OAuth provider registry.
pub struct OAuthProvider {
    pub name: &'static str,
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub default_scopes: &'static [&'static str],
    pub client_id_source: ClientIdSource,
    /// Some providers (Google) require a client_secret for the
    /// authorization code grant; others (most installed-app
    /// flows) accept PKCE alone. `Some` for each of the four MCP
    /// providers, because none of them is fully public-client; an
    /// operator who registered a public OAuth app can leave the env
    /// var unset. `None` for ChatGPT, a public client by design.
    pub client_secret_env: Option<&'static str>,
    /// Path of the loopback redirect. A provider may pin it: ChatGPT
    /// allows only the port to vary between sign-ins.
    pub callback_path: &'static str,
    /// Sent as `resource` on the authorization, code-exchange and
    /// refresh requests, for a provider that scopes its tokens to an
    /// API (RFC 8707). `None` sends nothing.
    pub resource: Option<&'static str>,
    /// OpenID discovery document naming the `revocation_endpoint`
    /// that [`revoke_oauth_token`] posts to. `None` means the
    /// provider is not revoked from here.
    pub discovery_url: Option<&'static str>,
    /// Catalog of OAuth scopes the interactive picker offers for
    /// this provider. The picker renders a `dialoguer::MultiSelect`
    /// from it with `required: true` entries pre-checked and locked,
    /// and its output reaches the authorization URL through the
    /// `extra_scopes` parameter on [`run_authorization_code_flow`].
    ///
    /// `default_scopes` above is a separate list and the two are not
    /// unified: a provider's floor is what `default_scopes` holds,
    /// and this catalog is what an operator may add to it.
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
/// scopes. The picker short-circuits for this provider with a "no
/// scope choices needed at OAuth time" message; this empty catalog is
/// the data representation of that fact.
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
    client_id_source: ClientIdSource::Env("WIRKEN_LINEAR_CLIENT_ID"),
    client_secret_env: Some("WIRKEN_LINEAR_CLIENT_SECRET"),
    scopes: LINEAR_SCOPES,
    callback_path: "/callback",
    resource: None,
    discovery_url: None,
};

const NOTION: OAuthProvider = OAuthProvider {
    name: "notion",
    auth_url: "https://api.notion.com/v1/oauth/authorize",
    token_url: "https://api.notion.com/v1/oauth/token",
    default_scopes: &[],
    client_id_source: ClientIdSource::Env("WIRKEN_NOTION_CLIENT_ID"),
    client_secret_env: Some("WIRKEN_NOTION_CLIENT_SECRET"),
    scopes: NOTION_SCOPES,
    callback_path: "/callback",
    resource: None,
    discovery_url: None,
};

const GITHUB: OAuthProvider = OAuthProvider {
    name: "github",
    auth_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    default_scopes: &["repo", "read:user"],
    client_id_source: ClientIdSource::Env("WIRKEN_GITHUB_CLIENT_ID"),
    client_secret_env: Some("WIRKEN_GITHUB_CLIENT_SECRET"),
    scopes: GITHUB_SCOPES,
    callback_path: "/callback",
    resource: None,
    discovery_url: None,
};

const GOOGLE: OAuthProvider = OAuthProvider {
    name: "google",
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    default_scopes: &["https://www.googleapis.com/auth/drive.readonly"],
    client_id_source: ClientIdSource::Env("WIRKEN_GOOGLE_CLIENT_ID"),
    client_secret_env: Some("WIRKEN_GOOGLE_CLIENT_SECRET"),
    scopes: GOOGLE_SCOPES,
    callback_path: "/callback",
    resource: None,
    discovery_url: None,
};

/// The scope under which an app may run inference on the operator's
/// ChatGPT plan. A grant without it signs the operator in and lets
/// the gateway run nothing.
pub const PLAN_USAGE_SCOPE: &str = "chatgpt.tokens.use.direct";

/// The API a ChatGPT plan token is issued for.
pub const CHATGPT_RESOURCE: &str = "https://api.openai.com/v1";

/// Moves the ChatGPT sign-in, token and discovery endpoints to a
/// loopback base, for an integration test's stub. A base that is not
/// loopback is refused, so the variable cannot send a sign-in to
/// another host. The inference endpoint is not moved by it; that is
/// `provider.json`.
pub const CHATGPT_OAUTH_BASE_ENV: &str = "WIRKEN_CHATGPT_OAUTH_BASE";

/// Sign in with ChatGPT: OpenAI's program under which an open-source,
/// locally run app uses the operator's ChatGPT plan for inference
/// (<https://developers.openai.com/siwc/token-sharing-open-source>). A
/// public client with no secret: the app registers itself on the
/// first sign-in and the callback carries the issued id. Tokens are
/// issued for [`CHATGPT_RESOURCE`]; [`PLAN_USAGE_SCOPE`] is what
/// grants plan usage. The scope set is fixed, so the picker has no
/// catalog to offer.
const CHATGPT: OAuthProvider = OAuthProvider {
    name: "chatgpt",
    auth_url: "https://auth.openai.com/api/accounts/authorize",
    token_url: "https://auth.openai.com/api/accounts/oauth/token",
    default_scopes: &[
        "openid",
        "profile",
        "email",
        "offline_access",
        "resource.invoke",
        PLAN_USAGE_SCOPE,
    ],
    client_id_source: ClientIdSource::Dynamic {
        bootstrap: "dynamic_agent_client",
    },
    client_secret_env: None,
    scopes: &[],
    callback_path: "/auth/callback",
    resource: Some(CHATGPT_RESOURCE),
    discovery_url: Some("https://auth.openai.com/.well-known/openid-configuration"),
};

/// Compute the set of scope ids the picker pre-checks. Returns
/// every `required: true` scope in catalog order, which is the
/// initial selection state for `dialoguer::MultiSelect`. The picker
/// also consults `required` per entry to lock the pre-checked items,
/// so an operator cannot deselect a scope the provider needs.
pub fn default_selected_scopes(provider: &OAuthProvider) -> Vec<&'static str> {
    provider
        .scopes
        .iter()
        .filter(|s| s.required)
        .map(|s| s.id)
        .collect()
}

/// Look up a provider by name. `None` when the name is not in the
/// registry, which is what makes an unknown provider a configuration
/// error rather than an unauthenticated request.
pub fn lookup_provider(name: &str) -> Option<&'static OAuthProvider> {
    match name {
        "linear" => Some(&LINEAR),
        "notion" => Some(&NOTION),
        "github" => Some(&GITHUB),
        "google" => Some(&GOOGLE),
        "chatgpt" => Some(&CHATGPT),
        _ => None,
    }
}

/// All known provider names. Used by the CLI to print a friendly
/// error when the user types an unknown one.
pub fn provider_names() -> &'static [&'static str] {
    &["linear", "notion", "github", "google", "chatgpt"]
}

/// What one sign-in is given beyond the provider and its scopes.
/// [`Default`] is what the MCP providers use: a random loopback port,
/// the browser opened, no host id, no saved client id.
#[derive(Debug, Clone)]
pub struct SignInOptions {
    /// Bind the callback listener to this port rather than a random
    /// one, so an SSH port forward can carry the browser's redirect to
    /// a headless host.
    pub port: Option<u16>,
    /// The client id an earlier sign-in was issued, for a provider that
    /// registers dynamically. `None` registers afresh.
    pub client_id: Option<String>,
    /// Sent as `ext_agent_host_id`: a stable identifier for this host,
    /// for a provider that attributes usage per host.
    pub host_id: Option<String>,
    /// Sent as `agent_name_hint`: the name the provider shows the
    /// operator for this app.
    pub app_name: Option<String>,
    /// Open the authorization URL in the operator's browser. Off, the
    /// URL is only printed, which is what a test or a headless host
    /// wants.
    pub open_browser: bool,
}

impl Default for SignInOptions {
    fn default() -> Self {
        Self {
            port: None,
            client_id: None,
            host_id: None,
            app_name: None,
            open_browser: true,
        }
    }
}

/// The endpoints one sign-in or refresh talks to.
struct Endpoints {
    auth_url: String,
    token_url: String,
    discovery_url: Option<String>,
}

/// A provider's endpoints, with [`CHATGPT_OAUTH_BASE_ENV`] applied for
/// ChatGPT. The variable warns at every use.
fn endpoints(provider: &OAuthProvider) -> Result<Endpoints, ProxyError> {
    let base = (provider.name == CHATGPT.name)
        .then(|| std::env::var(CHATGPT_OAUTH_BASE_ENV).ok())
        .flatten()
        .filter(|b| !b.trim().is_empty());
    match base {
        Some(base) => {
            let base = loopback_base(&base)?;
            tracing::warn!(
                "{CHATGPT_OAUTH_BASE_ENV} is set: ChatGPT sign-in and token requests go to {base}"
            );
            Ok(Endpoints {
                auth_url: format!("{base}/api/accounts/authorize"),
                token_url: format!("{base}/api/accounts/oauth/token"),
                discovery_url: Some(format!("{base}/.well-known/openid-configuration")),
            })
        }
        None => Ok(Endpoints {
            auth_url: provider.auth_url.to_string(),
            token_url: provider.token_url.to_string(),
            discovery_url: provider.discovery_url.map(String::from),
        }),
    }
}

/// `base` without a trailing slash, when its host is a loopback
/// address; anything else is refused.
fn loopback_base(base: &str) -> Result<String, ProxyError> {
    let rest = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
        .ok_or_else(|| {
            ProxyError::Vault(format!(
                "{CHATGPT_OAUTH_BASE_ENV} must be an http:// or https:// URL, got '{base}'"
            ))
        })?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    };
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        Ok(base.trim_end_matches('/').to_string())
    } else {
        Err(ProxyError::Vault(format!(
            "{CHATGPT_OAUTH_BASE_ENV} must point at a loopback address, got host '{host}'"
        )))
    }
}

// ---------------------------------------------------------------------------
// OAuthCredential — the JSON payload stored in the vault
// ---------------------------------------------------------------------------

/// Stored OAuth credential. Lives in the vault as a UTF-8 JSON
/// string under a `vault:NAME` reference. The full JSON is the
/// secret. `Debug` is hand-rolled to redact `access_token` and
/// `refresh_token` so accidental tracing or `dbg!` calls do not
/// surface bearer tokens in logs; the public-view variant
/// [`PublicOAuthCredential`] is the right type for any code path
/// that only needs the non-secret fields (provider, scopes,
/// expiry).
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp seconds.
    pub expires_at: u64,
    pub scope: String,
    pub provider: String,
    /// The client id the provider issued at registration, for a
    /// provider whose [`ClientIdSource`] is dynamic. Every refresh,
    /// revocation and later sign-in sends it. `None` for a provider
    /// configured through the environment, and on entries stored
    /// before the field existed, which is why it is defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl OAuthCredential {
    /// Whether `scope` is among the granted scopes.
    pub fn grants(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }
}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredential")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// Non-secret view of an [`OAuthCredential`]. Carries provider,
/// granted scopes, and expiry; does not carry the access or refresh
/// tokens. Consumed by `wirken credentials show` and `wirken
/// credentials list`'s scope summary so the CLI surface for those
/// commands cannot accidentally leak a bearer token, regardless of
/// what a future contributor decides to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOAuthCredential {
    pub provider: String,
    pub scopes: Vec<String>,
    /// Unix timestamp seconds. Same value as [`OAuthCredential::expires_at`].
    pub expires_at: u64,
}

impl PublicOAuthCredential {
    /// Convert the wrapping [`OAuthCredential`] into the public view,
    /// dropping the bearer tokens. The scope string is split on
    /// whitespace per OAuth convention.
    fn from_full(cred: OAuthCredential) -> Self {
        Self {
            scopes: cred.scope.split_whitespace().map(String::from).collect(),
            expires_at: cred.expires_at,
            provider: cred.provider,
        }
    }
}

/// Parse a vault-stored OAuth credential payload directly into the
/// public view. Pure (no IO) so callers that already hold the
/// decrypted bytes (e.g. tests) can build a `PublicOAuthCredential`
/// without touching the vault. Errors when the payload is not the
/// expected JSON shape.
pub fn parse_public_view(json: &str) -> Result<PublicOAuthCredential, ProxyError> {
    let cred: OAuthCredential = serde_json::from_str(json)
        .map_err(|e| ProxyError::Vault(format!("parse oauth credential: {e}")))?;
    Ok(PublicOAuthCredential::from_full(cred))
}

/// Load the public view of an OAuth credential from the vault.
/// Uses [`wirken_vault::CredentialStore::peek`] so inspection does
/// not bump `last_used_at`. The full [`OAuthCredential`] (with
/// bearer tokens) is constructed inside this function and dropped
/// before returning so the caller never sees the secret fields.
pub fn load_oauth_public(
    store: &CredentialStore,
    name: &str,
) -> Result<PublicOAuthCredential, ProxyError> {
    let (secret, _meta) = store
        .peek(name)
        .map_err(|e| ProxyError::Vault(format!("load oauth credential '{name}': {e}")))?;
    parse_public_view(secret.expose())
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

/// Refresh an access token using the stored refresh token. Called by
/// the gateway's [`crate::refresh_service`] when the MCP proxy asks,
/// because its access token is within 60 seconds of expiry.
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
    let endpoints = endpoints(provider)?;
    refresh_with_token_url(provider, cred, &endpoints.token_url).await
}

/// [`refresh_oauth_token`] against an explicit token endpoint. The
/// request carries the credential's own client id when it has one and
/// the provider's `resource`, and no `scope`, which is what keeps a
/// rotating grant intact.
async fn refresh_with_token_url(
    provider: &OAuthProvider,
    cred: &OAuthCredential,
    token_url: &str,
) -> Result<OAuthCredential, ProxyError> {
    let client = build_oauth_client_at(
        provider,
        provider.auth_url,
        token_url,
        /*redirect_uri=*/ None,
        cred.client_id.as_deref(),
    )?;
    let http_client = reqwest_http_client()?;

    let refresh_token = RefreshToken::new(cred.refresh_token.clone());
    let mut request = client.exchange_refresh_token(&refresh_token);
    if let Some(resource) = provider.resource {
        request = request.add_extra_param("resource", resource);
    }
    let token = request
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
        client_id: cred.client_id.clone(),
    })
}

/// Revoke `cred`'s refresh token at the provider, for a provider that
/// publishes a `revocation_endpoint` in its discovery document. The
/// provider answers an empty 200 for a token that is already invalid,
/// so revoking twice is not an error. The caller removes the vault
/// entry whatever this returns; an `Err` means the operator should
/// also disconnect the app at the provider.
pub async fn revoke_oauth_token(
    provider_name: &str,
    cred: &OAuthCredential,
) -> Result<(), ProxyError> {
    let provider = lookup_provider(provider_name).ok_or_else(|| {
        ProxyError::Vault(format!(
            "unknown OAuth provider '{provider_name}'. Known: {:?}",
            provider_names()
        ))
    })?;
    let discovery_url = endpoints(provider)?.discovery_url.ok_or_else(|| {
        ProxyError::Vault(format!(
            "provider '{}' publishes no revocation endpoint",
            provider.name
        ))
    })?;
    let client_id = match (&cred.client_id, provider.client_id_source) {
        (Some(id), _) => id.clone(),
        (None, ClientIdSource::Env(var)) => std::env::var(var)
            .map_err(|_| ProxyError::Vault(format!("missing OAuth client id env var {var}")))?,
        (None, ClientIdSource::Dynamic { .. }) => {
            return Err(ProxyError::Vault(
                "credential carries no client id; nothing to revoke it with".into(),
            ));
        }
    };

    let http_client = reqwest_http_client()?;
    let document = http_client
        .get(&discovery_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| ProxyError::Vault(format!("discovery document: {e}")))?
        .text()
        .await
        .map_err(|e| ProxyError::Vault(format!("discovery document: {e}")))?;
    let endpoint = serde_json::from_str::<serde_json::Value>(&document)
        .ok()
        .and_then(|doc| {
            doc.get("revocation_endpoint")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            ProxyError::Vault("discovery document names no revocation_endpoint".into())
        })?;

    let response = http_client
        .post(&endpoint)
        .form(&[
            ("token", cred.refresh_token.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", client_id.as_str()),
        ])
        .send()
        .await
        .map_err(|e| ProxyError::Vault(format!("revocation request: {e}")))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(ProxyError::Vault(format!(
            "revocation returned HTTP {}",
            response.status()
        )))
    }
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
    run_authorization_code_flow_with(provider_name, extra_scopes, &SignInOptions::default()).await
}

/// [`run_authorization_code_flow`] with [`SignInOptions`]: a fixed
/// port, a saved client id, the host id and app name a dynamically
/// registering provider takes, and whether the browser is opened.
pub async fn run_authorization_code_flow_with(
    provider_name: &str,
    extra_scopes: &[String],
    opts: &SignInOptions,
) -> Result<OAuthCredential, ProxyError> {
    let provider = lookup_provider(provider_name).ok_or_else(|| {
        ProxyError::Vault(format!(
            "unknown OAuth provider '{provider_name}'. Known: {:?}",
            provider_names()
        ))
    })?;
    let endpoints = endpoints(provider)?;

    // Bind localhost FIRST so we know the redirect URL.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", opts.port.unwrap_or(0)))
        .await
        .map_err(|e| ProxyError::Vault(format!("bind localhost callback: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| ProxyError::Vault(format!("local addr: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{}", provider.callback_path);

    let client = build_oauth_client_at(
        provider,
        &endpoints.auth_url,
        &endpoints.token_url,
        Some(redirect_uri.clone()),
        opts.client_id.as_deref(),
    )?;

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
    if let Some(resource) = provider.resource {
        auth_request = auth_request.add_extra_param("resource", resource);
    }
    if let Some(host_id) = &opts.host_id {
        auth_request = auth_request.add_extra_param("ext_agent_host_id", host_id.clone());
    }
    if let Some(app_name) = &opts.app_name {
        auth_request = auth_request.add_extra_param("agent_name_hint", app_name.clone());
    }
    // OpenID Connect wants a fresh nonce on every request that asks
    // for an id token. The id token itself is not read: nothing here
    // needs the identity, only the tokens.
    if provider.default_scopes.contains(&"openid") {
        auth_request = auth_request.add_extra_param("nonce", CsrfToken::new_random().into_secret());
    }

    let (auth_url, csrf_token) = auth_request.url();

    eprintln!();
    eprintln!("  Open this URL in your browser to authorize wirken:");
    eprintln!();
    eprintln!("    {auth_url}");
    eprintln!();
    if opts.open_browser
        && let Err(e) = open::that(auth_url.as_str())
    {
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

    // A dynamically registering provider issues the client id on the
    // callback; the exchange, and everything after it, uses that one.
    let client_id =
        client_id_for_exchange(provider, opts.client_id.as_deref(), received.client_id)?;
    let client = match &client_id {
        Some(issued) => build_oauth_client_at(
            provider,
            &endpoints.auth_url,
            &endpoints.token_url,
            Some(redirect_uri.clone()),
            Some(issued),
        )?,
        None => client,
    };

    // Exchange the code for tokens.
    let http_client = reqwest_http_client()?;
    let mut exchange = client
        .exchange_code(AuthorizationCode::new(received.code))
        .set_pkce_verifier(pkce_verifier);
    if let Some(resource) = provider.resource {
        exchange = exchange.add_extra_param("resource", resource);
    }
    let token = exchange
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
        client_id,
    })
}

/// The client id the code exchange uses, or `None` to keep the client
/// the authorization request was built with. A provider that
/// registers dynamically is issued its id on the callback; a saved id
/// stands in when the callback repeats none; neither means the
/// registration did not complete.
fn client_id_for_exchange(
    provider: &OAuthProvider,
    saved: Option<&str>,
    from_callback: Option<String>,
) -> Result<Option<String>, ProxyError> {
    match provider.client_id_source {
        ClientIdSource::Env(_) => Ok(None),
        ClientIdSource::Dynamic { bootstrap } => match (saved, from_callback) {
            (_, Some(issued)) if !issued.is_empty() && issued != bootstrap => Ok(Some(issued)),
            (Some(saved), _) => Ok(Some(saved.to_string())),
            _ => Err(ProxyError::Vault(format!(
                "{} did not issue a client id on the callback, so the registration did not \
                 complete. Run the command again.",
                provider.name
            ))),
        },
    }
}

struct CallbackParams {
    code: String,
    state: String,
    /// The client id a dynamically registering provider issued.
    client_id: Option<String>,
}

/// The query parameters of a redirect, each present or not.
#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedCallback {
    code: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_callback_query(query: &str) -> ParsedCallback {
    let mut parsed = ParsedCallback::default();
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            let decoded = percent_decode(v);
            match k {
                "code" => parsed.code = Some(decoded),
                "state" => parsed.state = Some(decoded),
                "client_id" => parsed.client_id = Some(decoded),
                "error" => parsed.error = Some(decoded),
                "error_description" => parsed.error_description = Some(decoded),
                _ => {}
            }
        }
    }
    parsed
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

    let ParsedCallback {
        code,
        state,
        client_id,
        error,
        error_description,
    } = parse_callback_query(query);

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
    Ok(CallbackParams {
        code,
        state,
        client_id,
    })
}

fn percent_decode(s: &str) -> String {
    // Tiny URL-decode. The OAuth params are URL-safe base64 codes
    // and a CSRF token, so the cases full RFC 3986 decoding adds do
    // not arise on this path.
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

/// The client for `provider` at the given endpoints. `client_id`, when
/// given, is used as it is: the id a dynamically registering provider
/// issued. Otherwise an env-configured provider reads its variable and
/// a dynamic one sends its bootstrap id, which is what the first
/// authorization request carries.
fn build_oauth_client_at(
    provider: &OAuthProvider,
    auth_url: &str,
    token_url: &str,
    redirect_uri: Option<String>,
    client_id: Option<&str>,
) -> Result<OAuthClient, ProxyError> {
    let client_id = match (client_id, provider.client_id_source) {
        (Some(id), _) => id.to_string(),
        (None, ClientIdSource::Dynamic { bootstrap }) => bootstrap.to_string(),
        (None, ClientIdSource::Env(var)) => std::env::var(var).map_err(|_| {
            ProxyError::Vault(format!(
                "missing OAuth client id env var {var}. Register an OAuth app at the {} \
                 developer console and export {var}=<id> before running this command. \
                 Wirken does not embed registered OAuth client ids — see the slice 2 \
                 notes in docs/managed-agents-parity.md item 7.",
                provider.name
            ))
        })?,
    };

    let client_secret = provider
        .client_secret_env
        .and_then(|env| std::env::var(env).ok())
        .map(ClientSecret::new);

    let mut client = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(auth_url.to_string())
                .map_err(|e| ProxyError::Vault(format!("invalid auth_url: {e}")))?,
        )
        .set_token_uri(
            TokenUrl::new(token_url.to_string())
                .map_err(|e| ProxyError::Vault(format!("invalid token_url: {e}")))?,
        );

    if let Some(secret) = client_secret {
        client = client.set_client_secret(secret);
    }
    // A public client's id travels in the form body, which is what
    // the provider's token endpoint reads it from.
    if matches!(provider.client_id_source, ClientIdSource::Dynamic { .. }) {
        client = client.set_auth_type(AuthType::RequestBody);
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

    #[test]
    fn parse_public_view_splits_scope_string_on_whitespace() {
        let json = r#"{
            "access_token": "secret-token",
            "refresh_token": "secret-refresh",
            "expires_at": 1234567890,
            "scope": "openid read write",
            "provider": "linear"
        }"#;
        let public = parse_public_view(json).unwrap();
        assert_eq!(public.provider, "linear");
        assert_eq!(public.expires_at, 1234567890);
        assert_eq!(public.scopes, vec!["openid", "read", "write"]);
    }

    #[test]
    fn parse_public_view_returns_empty_scope_vec_for_empty_string() {
        let json = r#"{
            "access_token": "secret-token",
            "refresh_token": "secret-refresh",
            "expires_at": 0,
            "scope": "",
            "provider": "notion"
        }"#;
        let public = parse_public_view(json).unwrap();
        assert!(public.scopes.is_empty());
    }

    #[test]
    fn parse_public_view_errors_on_malformed_json() {
        let err = parse_public_view("not-json-at-all").unwrap_err();
        assert!(format!("{err}").contains("parse oauth credential"));
    }

    #[test]
    fn debug_impl_redacts_access_and_refresh_tokens() {
        // Defense-in-depth: a future contributor who Debug-prints an
        // OAuthCredential (via tracing! or dbg!) does not leak the
        // bearer tokens. The token fields are replaced with
        // "<redacted>"; the non-secret fields render normally.
        let cred = OAuthCredential {
            access_token: "ya29.live-token-value".into(),
            refresh_token: "1//refresh-token-secret".into(),
            expires_at: 1234567890,
            scope: "openid email".into(),
            provider: "google".into(),
            client_id: None,
        };
        let debug = format!("{cred:?}");
        assert!(!debug.contains("ya29.live-token-value"));
        assert!(!debug.contains("1//refresh-token-secret"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("1234567890"));
        assert!(debug.contains("openid email"));
        assert!(debug.contains("google"));
    }
}

#[cfg(test)]
mod chatgpt_tests {
    use super::*;

    fn chatgpt_credential(client_id: Option<&str>) -> OAuthCredential {
        OAuthCredential {
            access_token: "at-1".into(),
            refresh_token: "rt-1".into(),
            expires_at: 10,
            scope: CHATGPT.default_scopes.join(" "),
            provider: "chatgpt".into(),
            client_id: client_id.map(String::from),
        }
    }

    #[test]
    fn a_credential_stored_before_client_id_existed_still_parses() {
        let json = r#"{"access_token":"at","refresh_token":"rt","expires_at":1,"scope":"read","provider":"linear"}"#;
        let cred: OAuthCredential = serde_json::from_str(json).unwrap();
        assert_eq!(cred.client_id, None);
        // And it is written back without the key, byte-stable for the
        // four MCP providers.
        assert!(!serde_json::to_string(&cred).unwrap().contains("client_id"));
    }

    #[test]
    fn an_issued_client_id_round_trips_through_the_stored_json() {
        let cred = chatgpt_credential(Some("oaiapp_abc"));
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains(r#""client_id":"oaiapp_abc""#));
        let back: OAuthCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.client_id.as_deref(), Some("oaiapp_abc"));
    }

    #[test]
    fn chatgpt_registers_dynamically_scopes_plan_usage_and_names_its_resource() {
        let p = lookup_provider("chatgpt").expect("chatgpt in registry");
        assert_eq!(
            p.client_id_source,
            ClientIdSource::Dynamic {
                bootstrap: "dynamic_agent_client"
            }
        );
        assert_eq!(p.client_secret_env, None);
        assert_eq!(p.callback_path, "/auth/callback");
        assert_eq!(p.resource, Some("https://api.openai.com/v1"));
        assert!(p.default_scopes.contains(&PLAN_USAGE_SCOPE));
        assert!(p.default_scopes.contains(&"offline_access"));
        assert!(
            p.scopes.is_empty(),
            "the scope set is fixed; no picker catalog"
        );
        assert!(p.discovery_url.is_some());
        assert!(provider_names().contains(&"chatgpt"));
    }

    #[test]
    fn grants_checks_the_exact_scope_token() {
        let cred = chatgpt_credential(Some("oaiapp_abc"));
        assert!(cred.grants(PLAN_USAGE_SCOPE));
        assert!(!cred.grants("chatgpt.tokens"));
        let mut signed_in_only = cred;
        signed_in_only.scope = "openid profile email".into();
        assert!(!signed_in_only.grants(PLAN_USAGE_SCOPE));
    }

    #[test]
    fn the_callback_query_yields_code_state_and_the_issued_client_id() {
        let parsed = parse_callback_query("code=c%2B1&state=s1&client_id=oaiapp_x&other=1");
        assert_eq!(
            parsed,
            ParsedCallback {
                code: Some("c+1".into()),
                state: Some("s1".into()),
                client_id: Some("oaiapp_x".into()),
                error: None,
                error_description: None,
            }
        );
        let denied = parse_callback_query("error=access_denied&error_description=no");
        assert_eq!(denied.error.as_deref(), Some("access_denied"));
        assert_eq!(denied.code, None);
    }

    #[test]
    fn a_dynamic_provider_needs_an_issued_or_saved_client_id() {
        // Issued on the callback: used, whether or not one was saved.
        assert_eq!(
            client_id_for_exchange(&CHATGPT, None, Some("oaiapp_new".into())).unwrap(),
            Some("oaiapp_new".into())
        );
        assert_eq!(
            client_id_for_exchange(&CHATGPT, Some("oaiapp_old"), Some("oaiapp_new".into()))
                .unwrap(),
            Some("oaiapp_new".into())
        );
        // The callback echoing the bootstrap id, or nothing, falls back
        // to the saved one.
        assert_eq!(
            client_id_for_exchange(
                &CHATGPT,
                Some("oaiapp_old"),
                Some("dynamic_agent_client".into())
            )
            .unwrap(),
            Some("oaiapp_old".into())
        );
        assert_eq!(
            client_id_for_exchange(&CHATGPT, Some("oaiapp_old"), None).unwrap(),
            Some("oaiapp_old".into())
        );
        // Neither: the registration did not complete.
        let err = client_id_for_exchange(&CHATGPT, None, None).unwrap_err();
        assert!(
            format!("{err}").contains("did not issue a client id"),
            "{err}"
        );
        // An env-configured provider keeps its client.
        assert_eq!(
            client_id_for_exchange(&LINEAR, None, Some("x".into())).unwrap(),
            None
        );
    }

    #[test]
    fn the_oauth_base_override_must_be_loopback() {
        assert_eq!(
            loopback_base("http://127.0.0.1:8099/").unwrap(),
            "http://127.0.0.1:8099"
        );
        assert!(loopback_base("http://localhost:1/").is_ok());
        assert!(loopback_base("http://[::1]:1").is_ok());
        for bad in [
            "https://auth.example.com",
            "http://10.0.0.1/",
            "ftp://127.0.0.1",
        ] {
            assert!(loopback_base(bad).is_err(), "{bad} should be refused");
        }
    }

    /// Reads one HTTP request off `stream` in full, headers and body.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&raw);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let wanted = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if body.len() >= wanted {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    #[tokio::test]
    async fn a_refresh_sends_the_issued_client_id_and_the_resource_and_no_scope() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            *record.lock().unwrap() = read_request(&mut stream).await;
            let body = r#"{"access_token":"at-2","refresh_token":"rt-2","token_type":"bearer","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let cred = chatgpt_credential(Some("oaiapp_test"));
        let refreshed =
            refresh_with_token_url(&CHATGPT, &cred, &format!("http://127.0.0.1:{port}/token"))
                .await
                .unwrap();

        let request = seen.lock().unwrap().clone();
        let (_, form) = request.split_once("\r\n\r\n").expect("a body");
        assert!(form.contains("grant_type=refresh_token"), "{form}");
        assert!(form.contains("refresh_token=rt-1"), "{form}");
        assert!(form.contains("client_id=oaiapp_test"), "{form}");
        assert!(
            form.contains("resource=https%3A%2F%2Fapi.openai.com%2Fv1"),
            "{form}"
        );
        assert!(
            !form.contains("scope="),
            "a refresh must not narrow the grant: {form}"
        );
        assert!(!form.contains("dynamic_agent_client"), "{form}");
        assert_eq!(refreshed.access_token, "at-2");
        assert_eq!(
            refreshed.refresh_token, "rt-2",
            "the rotated token replaces the old one"
        );
        assert_eq!(refreshed.client_id.as_deref(), Some("oaiapp_test"));
        assert_eq!(refreshed.provider, "chatgpt");
        assert_eq!(
            refreshed.scope, cred.scope,
            "no scope in the reply keeps the stored one"
        );
    }
}
