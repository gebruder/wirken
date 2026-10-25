//! Sign-in, token refresh and revocation for plan mode
//! (`"auth": "plan"` on the [`PROVIDER`] provider).
//!
//! In this mode an agent's requests run on the operator's own plan at
//! the provider rather than on an API key. The provider runs it as an
//! OAuth flow for public clients: the app registers itself on the first
//! sign-in (there is no client secret; the callback carries the client
//! id the provider issued), the operator consents to plan usage in the
//! browser, and the grant comes back as an access token that lives an
//! hour, a refresh token that lives thirty days and rotates on every
//! use, and an OpenID ID token naming the account.
//!
//! What lives here:
//!
//! - [`PendingSignIn`]: one authorization attempt, from the loopback
//!   listener to a validated credential. The ID token is checked against
//!   the provider's published keys before anything is kept, and a
//!   reauthorization has to come back as the account it started from.
//! - [`PlanTokenSource`]: the bearer for each model call. One per vault
//!   entry per process. Across processes, a refresh holds the entry's
//!   lock file ([`entry_lock_path`]) from read to write, so a rotating
//!   token is never spent twice. The vault itself is touched only in
//!   short steps around the request, and the write still checks that the
//!   stored refresh token is the one the refresh started from
//!   ([`wirken_vault::CredentialStore::update_exclusive`]). No network
//!   call is made while the vault's write lock is held.
//! - [`revoke`] and [`sign_out`]: end the renewable session.
//! - [`host_id`]: the per-host identifier every authorization carries.
//!
//! Every endpoint is fixed ([`AUTH_BASE`], [`API_BASE`]). Nothing in a
//! configuration file or the environment moves them: [`Endpoints::pinned`]
//! is the only constructor outside this crate's tests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wirken_gateway::leak::LeakMatcher;
use wirken_mcp_proxy::OAuthCredential;
use wirken_vault::{CredentialKind, CredentialStore, VaultSecret};

use crate::error::AgentError;

/// The provider's authorization server: authorize, token, discovery
/// and the keys and revocation endpoint discovery names.
pub const AUTH_BASE: &str = "https://auth.openai.com";
/// The API the plan's tokens are issued for, and where `/responses`
/// and `/models` are called.
pub const API_BASE: &str = "https://api.openai.com/v1";
/// Sent as `resource` on authorization, code exchange and refresh.
pub const RESOURCE: &str = "https://api.openai.com/v1";
/// The `base_url` a plan-mode `provider.json` and agent row carry. Not
/// an endpoint, and never used as one here: the plan endpoints are
/// fixed. A build that predates plan mode reads `base_url` as the
/// endpoint and refuses this value (it is neither HTTPS nor loopback)
/// when it builds the client, so a downgrade fails before any request
/// rather than sending one to a default endpoint.
pub const PLAN_BASE_URL: &str = "plan-sign-in";
/// `OAuthCredential::provider` on a plan entry: the provider id the
/// agent runs as.
pub const PROVIDER: &str = "openai";
/// The vault entry a sign-in writes when none is named.
pub const DEFAULT_ENTRY: &str = "openai-plan";
/// The scope that permits plan usage. A grant without it signs the
/// account in and runs nothing.
pub const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
/// Every scope a sign-in asks for: identity, the refresh token, and
/// plan usage.
pub const SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "resource.invoke",
    PLAN_SCOPE,
];
/// The loopback callback path. Only the port may differ between
/// sign-ins.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The name the provider shows the operator for this app on its first
/// registration.
pub const APP_NAME: &str = "Wirken";
/// Where the operator reviews usage and sets this app's limit.
pub const USAGE_URL: &str = "https://chatgpt.com/settings/usage";
/// The file under the data directory that holds this host's id.
pub const HOST_ID_FILE: &str = "plan-host-id";

/// The client id a first sign-in sends to ask the provider to register
/// this app. Never stored, and never sent anywhere but the authorize
/// request.
const REGISTRATION_CLIENT_ID: &str = "dynamic_agent_client";
const AUTHORIZE_PATH: &str = "/api/accounts/authorize";
const TOKEN_PATH: &str = "/api/accounts/oauth/token";
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Refresh codes after which the refresh token cannot be used again.
const TERMINAL_REFRESH_CODES: [&str; 6] = [
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

/// Refresh this long before the access token expires.
const REFRESH_LEAD_SECS: u64 = 300;
/// An access token closer than this to expiry is not sent: the request
/// would reach the provider after the token did.
const EXPIRY_MARGIN_SECS: u64 = 60;
/// Clock leeway on the ID token's `exp`.
const ID_TOKEN_LEEWAY_SECS: u64 = 60;
/// Timeout on each request to the authorization server.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a short vault write waits on another connection's write.
/// No network call is ever made while the vault's write lock is held,
/// so this is the store's ordinary wait.
const VAULT_WAIT: Duration = Duration::from_secs(5);
/// How long a refresh or sign-out waits for another process to release
/// the entry's lock file. Longer than a sign-out's revocation retries
/// (three requests at [`HTTP_TIMEOUT`] plus [`REVOKE_BACKOFF`]).
const ENTRY_LOCK_WAIT: Duration = Duration::from_secs(90);
/// How often a waiting process tries the entry's lock file again.
const ENTRY_LOCK_POLL: Duration = Duration::from_millis(50);
/// The waits between revocation attempts after a network error or a
/// 5xx.
pub const REVOKE_BACKOFF: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
/// How long a sign-in waits for the browser to come back.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// The endpoints one sign-in, refresh or revocation talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    auth_base: String,
    api_base: String,
}

impl Endpoints {
    /// The provider's own endpoints. The only constructor outside tests.
    pub fn pinned() -> Self {
        Self {
            auth_base: AUTH_BASE.to_string(),
            api_base: API_BASE.to_string(),
        }
    }

    /// A loopback stub standing in for both servers.
    #[cfg(test)]
    pub(crate) fn stub(base: &str) -> Self {
        Self {
            auth_base: base.to_string(),
            api_base: format!("{base}/v1"),
        }
    }

    /// The base `/responses` and `/models` are called under.
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// The issuer an ID token must name, which is also what discovery
    /// must report.
    pub fn issuer(&self) -> &str {
        &self.auth_base
    }

    fn authorize_url(&self) -> String {
        format!("{}{AUTHORIZE_PATH}", self.auth_base)
    }

    fn token_url(&self) -> String {
        format!("{}{TOKEN_PATH}", self.auth_base)
    }

    fn discovery_url(&self) -> String {
        format!("{}{DISCOVERY_PATH}", self.auth_base)
    }

    /// Whether a URL the discovery document names is on the
    /// authorization server's own origin. Keys and revocation are not
    /// fetched from anywhere else.
    fn on_auth_origin(&self, url: &str) -> bool {
        url.strip_prefix(self.auth_base.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// The HTTP client every request here goes through: no redirects
/// followed, HTTPS only for the provider's endpoints, a bounded
/// timeout.
pub(crate) fn http_client(endpoints: &Endpoints) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(endpoints.auth_base.starts_with("https://"))
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Why a sign-in did not produce a credential. Nothing is stored on
/// any of these.
#[derive(Debug, thiserror::Error)]
pub enum PlanAuthError {
    #[error("{0}")]
    Local(String),
    #[error("consent was declined at the provider (access_denied); nothing was exchanged")]
    Declined,
    #[error(
        "the sign-in callback's state did not match this attempt; nothing was exchanged. \
         Start the sign-in again."
    )]
    StateMismatch,
    #[error("the provider ended the sign-in with error '{0}'; nothing was exchanged")]
    Provider(String),
    #[error(
        "registration did not complete: the callback carried no issued client id. Start the \
         sign-in again."
    )]
    RegistrationIncomplete,
    #[error(
        "the callback carried client id '{returned}', not the one this account registered \
         ('{saved}'); refused, and the saved registration is unchanged"
    )]
    ClientMismatch { saved: String, returned: String },
    #[error("the ID token was refused: {0}")]
    IdToken(String),
    #[error(
        "the provider signed in a different account than the one this entry belongs to; \
         nothing was replaced. Sign in with the same account, or use another entry name."
    )]
    AccountMismatch,
    #[error("code exchange failed: {0}")]
    Exchange(String),
    #[error("timed out waiting for the browser to return to the sign-in callback")]
    Timeout,
}

/// Seconds since the epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Equality that does not stop at the first differing byte, for the
/// state and nonce comparisons.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// `bytes` random bytes, base64url without padding.
fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// The S256 challenge for a PKCE verifier.
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

// ---------------------------------------------------------------------------
// The credential as a plan entry
// ---------------------------------------------------------------------------

/// Whether `cred` is a plan sign-in: this provider, with the client id
/// it was issued and the account its ID token named.
pub fn is_plan_credential(cred: &OAuthCredential) -> bool {
    cred.provider == PROVIDER && cred.client_id.is_some() && cred.subject.is_some()
}

/// Whether the scopes the last token response granted include plan
/// usage. Only what the provider returned counts.
pub fn plan_granted(cred: &OAuthCredential) -> bool {
    cred.scope.split_whitespace().any(|s| s == PLAN_SCOPE)
}

/// `cred` with its tokens removed: what a terminal refresh error, a
/// sign-out or a declined grant leaves behind. The client id, the
/// account, the ID token and the granted scopes stay, so the next
/// sign-in reuses the registration and sends the ID token as its hint.
pub fn without_tokens(cred: &OAuthCredential) -> OAuthCredential {
    OAuthCredential {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_at: 0,
        ..cred.clone()
    }
}

/// Why `cred`, stored under `entry`, cannot be used for a model call,
/// or `None` when it can.
pub fn unusable_reason(cred: &OAuthCredential, entry: &str) -> Option<String> {
    if !is_plan_credential(cred) {
        return Some(format!(
            "credential '{entry}' is not a plan sign-in. Run `wirken credentials authorize \
             {entry}`."
        ));
    }
    if !plan_granted(cred) {
        return Some(format!(
            "plan usage is not granted to '{entry}' ({PLAN_SCOPE} was not in the last token \
             response). Run `wirken credentials authorize {entry}` and allow plan usage."
        ));
    }
    if cred.refresh_token.is_empty() {
        return Some(format!(
            "'{entry}' needs a new sign-in. Run `wirken credentials authorize {entry}`."
        ));
    }
    None
}

/// Store `cred` under `entry` as a plan sign-in (channel `oauth`, kind
/// [`CredentialKind::PlanSignIn`]). The kind is sealed into the row, so
/// a build that predates plan mode cannot decrypt it, and this one
/// never hands it out as a key.
pub fn store_plan(
    store: &CredentialStore,
    entry: &str,
    cred: &OAuthCredential,
) -> Result<(), String> {
    let mut binding = wirken_vault::Binding::default();
    binding.grant(wirken_vault::Destination::Plan);
    store
        .store_bound(
            entry,
            "oauth",
            &secret_of(cred),
            None,
            None,
            &binding,
            CredentialKind::PlanSignIn,
        )
        .map_err(|e| format!("store credential '{entry}': {e}"))
}

/// The plan sign-in stored under `entry`, read without counting as a
/// use. An entry of any other kind is refused.
pub fn load_plan(store: &CredentialStore, entry: &str) -> Result<OAuthCredential, String> {
    let (secret, meta) = store
        .peek(entry)
        .map_err(|e| format!("plan credential '{entry}': {e}"))?;
    if meta.kind != CredentialKind::PlanSignIn {
        return Err(format!(
            "credential '{entry}' is not a plan sign-in. Run `wirken credentials authorize \
             {entry}`."
        ));
    }
    if !meta.binding.permits(&wirken_vault::Destination::Plan) {
        return Err(format!(
            "plan sign-in '{entry}' may not be sent to the plan endpoints. Allow it with \
             `wirken credentials grant {entry} --plan`."
        ));
    }
    parse_credential(&secret, entry)
}

fn parse_credential(secret: &VaultSecret, entry: &str) -> Result<OAuthCredential, String> {
    serde_json::from_str(secret.expose())
        .map_err(|e| format!("credential '{entry}' is not an OAuth entry: {e}"))
}

fn secret_of(cred: &OAuthCredential) -> VaultSecret {
    // Serializing a struct of strings and integers does not fail.
    VaultSecret::new(serde_json::to_string(cred).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Host id
// ---------------------------------------------------------------------------

/// This host's `ext_agent_host_id`: a `urn:uuid:` around a random v4
/// UUID, created the first time it is asked for and kept in
/// [`HOST_ID_FILE`] under `data_dir`, owner-only. It identifies the
/// host, not the operator, and is not a credential, so it lives outside
/// the vault: a credential copied to another host does not carry it.
///
/// A file that holds anything else is an error rather than replaced,
/// since replacing it would make this host a different one to the
/// provider.
pub fn host_id(data_dir: &Path) -> Result<String, PlanAuthError> {
    let path = data_dir.join(HOST_ID_FILE);
    let read = |path: &Path| -> Result<String, PlanAuthError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| PlanAuthError::Local(format!("read {}: {e}", path.display())))?;
        let id = raw.trim();
        let valid = id
            .strip_prefix("urn:uuid:")
            .is_some_and(|u| uuid::Uuid::parse_str(u).is_ok());
        if valid {
            Ok(id.to_string())
        } else {
            Err(PlanAuthError::Local(format!(
                "{} does not hold a urn:uuid host id; restore it or remove it to create a new one",
                path.display()
            )))
        }
    };
    if path.exists() {
        return read(&path);
    }
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(id.as_bytes())
                .map_err(|e| PlanAuthError::Local(format!("write {}: {e}", path.display())))?;
            Ok(id)
        }
        // Another process created it first; its id is this host's.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read(&path),
        Err(e) => Err(PlanAuthError::Local(format!(
            "create {}: {e}",
            path.display()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/// A token endpoint response. Holds tokens, so no `Debug`.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

/// The granted scopes as stored: the response's own space-separated
/// value, or nothing when it sent none. An omitted `scope` grants
/// nothing here; no default is filled in.
fn granted_scopes(scope: Option<&str>) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for s in scope.unwrap_or("").split_whitespace() {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    seen.join(" ")
}

/// The error code in an error body: OAuth's `{"error": "code"}`, the
/// API's `{"error": {"code": ...}}`, or a bare `{"code": ...}`.
pub(crate) fn error_code(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    match v.get("error") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            o.get("code").and_then(|c| c.as_str()).map(String::from)
        }
        _ => v.get("code").and_then(|c| c.as_str()).map(String::from),
    }
}

async fn post_form(
    http: &reqwest::Client,
    url: &str,
    fields: &[(&str, &str)],
) -> Result<(reqwest::StatusCode, String), reqwest::Error> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    let response = http
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    Ok((status, text))
}

/// How a refresh failed.
#[derive(Debug)]
pub(crate) enum RefreshFailure {
    /// The refresh token cannot be used again: clear the tokens.
    Terminal(String),
    /// The client id was refused: a configuration error.
    InvalidClient,
    /// Anything else, a network error or a 5xx among them: the
    /// credential is kept.
    Retained(String),
}

/// One refresh request. Sends the issued client id, the refresh token
/// and `resource`, and no `scope`, so the grant is kept as it was.
pub(crate) async fn request_refresh(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    cred: &OAuthCredential,
) -> Result<OAuthCredential, RefreshFailure> {
    let client_id = cred
        .client_id
        .as_deref()
        .ok_or(RefreshFailure::InvalidClient)?;
    let (status, body) = post_form(
        http,
        &endpoints.token_url(),
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", cred.refresh_token.as_str()),
            ("resource", RESOURCE),
        ],
    )
    .await
    .map_err(|e| RefreshFailure::Retained(format!("refresh request: {e}")))?;
    if !status.is_success() {
        let code = error_code(&body);
        return Err(match code.as_deref() {
            Some(c) if TERMINAL_REFRESH_CODES.contains(&c) => RefreshFailure::Terminal(c.into()),
            Some("invalid_client") => RefreshFailure::InvalidClient,
            other => RefreshFailure::Retained(format!(
                "refresh returned HTTP {}{}",
                status.as_u16(),
                other.map(|c| format!(" {c}")).unwrap_or_default()
            )),
        });
    }
    let tokens: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| RefreshFailure::Retained(format!("refresh response: {e}")))?;
    Ok(OAuthCredential {
        access_token: tokens.access_token,
        // A rotating grant always sends a replacement; one that does
        // not keeps the token it was sent.
        refresh_token: tokens
            .refresh_token
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| cred.refresh_token.clone()),
        expires_at: unix_now() + tokens.expires_in.unwrap_or(3600),
        // The request sent no scope, so the grant is the one already
        // held; an omitted `scope` in the answer means that grant (RFC
        // 6749 section 5.1). One the answer names replaces it. A first
        // sign-in has no grant to keep and stays strict.
        scope: match tokens.scope.as_deref() {
            Some(scope) => granted_scopes(Some(scope)),
            None => cred.scope.clone(),
        },
        ..cred.clone()
    })
}

// ---------------------------------------------------------------------------
// Discovery and the ID token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

/// What the discovery document names, checked: the issuer it reports
/// is the one expected, and the endpoints are on the authorization
/// server's origin.
struct Discovery {
    jwks_uri: String,
    revocation_endpoint: Option<String>,
}

async fn discover(http: &reqwest::Client, endpoints: &Endpoints) -> Result<Discovery, String> {
    let response = http
        .get(endpoints.discovery_url())
        .send()
        .await
        .map_err(|e| format!("discovery document: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("discovery document: HTTP {}", status.as_u16()));
    }
    let doc: DiscoveryDocument = response
        .json()
        .await
        .map_err(|e| format!("discovery document: {e}"))?;
    if doc.issuer != endpoints.issuer() {
        return Err(format!(
            "discovery names issuer '{}', expected '{}'",
            doc.issuer,
            endpoints.issuer()
        ));
    }
    if !endpoints.on_auth_origin(&doc.jwks_uri) {
        return Err(format!(
            "discovery names keys at '{}', off the authorization server",
            doc.jwks_uri
        ));
    }
    let revocation_endpoint = match doc.revocation_endpoint {
        Some(url) if !endpoints.on_auth_origin(&url) => {
            return Err(format!(
                "discovery names revocation at '{url}', off the authorization server"
            ));
        }
        other => other,
    };
    Ok(Discovery {
        jwks_uri: doc.jwks_uri,
        revocation_endpoint,
    })
}

/// One key from the provider's JWKS.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

async fn fetch_keys(http: &reqwest::Client, jwks_uri: &str) -> Result<Vec<Jwk>, String> {
    let response = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("signing keys: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("signing keys: HTTP {}", status.as_u16()));
    }
    let set: JwkSet = response
        .json()
        .await
        .map_err(|e| format!("signing keys: {e}"))?;
    Ok(set.keys)
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// The identity a validated ID token carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdIdentity {
    pub sub: String,
    pub email: Option<String>,
}

fn b64url(segment: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("{what} is not base64url: {e}"))
}

/// Validate an ID token: an RS256 signature by one of `keys`, the
/// expected issuer, the issued client id among its audiences, an
/// expiry in the future, and the nonce saved for this attempt.
pub(crate) fn validate_id_token(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: u64,
) -> Result<IdIdentity, String> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a three-part JWS".into());
    };
    let header: JwtHeader = serde_json::from_slice(&b64url(header_b64, "header")?)
        .map_err(|e| format!("header: {e}"))?;
    if header.alg != "RS256" {
        return Err(format!("algorithm '{}' is not accepted", header.alg));
    }
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| k.kty == "RSA")
        .filter(|k| k.usage.as_deref().is_none_or(|u| u == "sig"))
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == "RS256"))
        .collect();
    let key = match &header.kid {
        Some(kid) => candidates
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid.as_str()))
            .ok_or_else(|| format!("no published key has id '{kid}'"))?,
        None if candidates.len() == 1 => &candidates[0],
        None => return Err("the token names no key id and the key set is not one key".into()),
    };
    let strip = |v: Vec<u8>| -> Vec<u8> {
        let start = v.iter().position(|b| *b != 0).unwrap_or(v.len());
        v.into_iter().skip(start).collect()
    };
    let n = strip(b64url(key.n.as_deref().unwrap_or(""), "key modulus")?);
    let e = strip(b64url(key.e.as_deref().unwrap_or(""), "key exponent")?);
    let signature = b64url(signature_b64, "signature")?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    aws_lc_rs::signature::RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            &signature,
        )
        .map_err(|_| "the signature does not verify".to_string())?;

    let claims: IdTokenClaims = serde_json::from_slice(&b64url(payload_b64, "payload")?)
        .map_err(|e| format!("claims: {e}"))?;
    if claims.iss != issuer {
        return Err(format!("issuer '{}' is not '{issuer}'", claims.iss));
    }
    let audiences: Vec<&str> = match &claims.aud {
        serde_json::Value::String(a) => vec![a.as_str()],
        serde_json::Value::Array(list) => list.iter().filter_map(|a| a.as_str()).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&client_id) {
        return Err(format!(
            "audience does not include the client id '{client_id}'"
        ));
    }
    if audiences.len() > 1 && claims.azp.as_deref() != Some(client_id) {
        return Err("several audiences and the authorized party is not this client".into());
    }
    if claims.exp + ID_TOKEN_LEEWAY_SECS <= now {
        return Err("expired".into());
    }
    match &claims.nonce {
        Some(got) if same(got, nonce) => {}
        Some(_) => return Err("nonce does not match this sign-in attempt".into()),
        None => return Err("no nonce".into()),
    }
    if claims.sub.is_empty() {
        return Err("no subject".into());
    }
    Ok(IdIdentity {
        sub: claims.sub,
        email: claims.email.filter(|e| !e.is_empty()),
    })
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

/// What a sign-in starts from.
pub struct SignInRequest {
    /// This host's id ([`host_id`]), created before the first sign-in.
    pub host_id: String,
    /// The account's saved registration, for a reauthorization. `None`
    /// registers a new client.
    pub saved: Option<OAuthCredential>,
    /// The loopback port to listen on; 0 picks a free one.
    pub port: u16,
}

/// What a sign-in produced. The credential is validated; whether it may
/// be used for model calls is [`Self::plan_granted`].
pub struct SignedIn {
    pub credential: OAuthCredential,
    /// Whether this sign-in registered a new client rather than reusing
    /// a saved one.
    pub registered: bool,
}

impl SignedIn {
    /// Whether the token response granted plan usage.
    pub fn plan_granted(&self) -> bool {
        plan_granted(&self.credential)
    }
}

/// One authorization attempt: listening, with its state, nonce and PKCE
/// verifier fixed, until [`Self::finish`] reads the callback.
pub struct PendingSignIn {
    endpoints: Endpoints,
    http: reqwest::Client,
    listener: tokio::net::TcpListener,
    redirect_uri: String,
    authorize_url: String,
    state: String,
    nonce: String,
    verifier: String,
    /// The saved issued client id on a reauthorization.
    client_id: Option<String>,
    saved: Option<OAuthCredential>,
}

impl PendingSignIn {
    /// Start listening and build the authorization URL.
    pub async fn start(request: SignInRequest) -> Result<Self, PlanAuthError> {
        Self::start_at(Endpoints::pinned(), request).await
    }

    pub(crate) async fn start_at(
        endpoints: Endpoints,
        request: SignInRequest,
    ) -> Result<Self, PlanAuthError> {
        let client_id = match &request.saved {
            Some(saved) if is_plan_credential(saved) => saved.client_id.clone(),
            Some(_) => {
                return Err(PlanAuthError::Local(
                    "the saved entry is not a plan sign-in; choose another entry name".into(),
                ));
            }
            None => None,
        };
        let http = http_client(&endpoints).map_err(PlanAuthError::Local)?;
        // The listener comes first, so the browser cannot return before
        // anything is there to receive it.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", request.port))
            .await
            .map_err(|e| {
                PlanAuthError::Local(format!(
                    "listen on 127.0.0.1:{} for the sign-in callback: {e}",
                    request.port
                ))
            })?;
        let port = listener
            .local_addr()
            .map_err(|e| PlanAuthError::Local(format!("callback listener: {e}")))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        let state = random_token(32);
        let nonce = random_token(32);
        let verifier = random_token(64);

        let mut url = url::Url::parse(&endpoints.authorize_url())
            .map_err(|e| PlanAuthError::Local(format!("authorize url: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair(
                "client_id",
                client_id.as_deref().unwrap_or(REGISTRATION_CLIENT_ID),
            );
            q.append_pair("redirect_uri", &redirect_uri);
            q.append_pair("scope", &SCOPES.join(" "));
            q.append_pair("resource", RESOURCE);
            q.append_pair("state", &state);
            q.append_pair("nonce", &nonce);
            q.append_pair("code_challenge", &pkce_challenge(&verifier));
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("ext_agent_host_id", &request.host_id);
            match &request.saved {
                // A first registration names the app; a reauthorization
                // must not.
                None => {
                    q.append_pair("agent_name_hint", APP_NAME);
                }
                Some(saved) => {
                    if let Some(hint) = &saved.id_token {
                        q.append_pair("id_token_hint", hint);
                    }
                    if let Some(email) = &saved.email {
                        q.append_pair("login_hint", email);
                    }
                    // Plan usage was declined last time: ask for consent
                    // again rather than reusing the earlier answer.
                    if !plan_granted(saved) {
                        q.append_pair("prompt", "consent");
                    }
                }
            }
        }
        Ok(Self {
            endpoints,
            http,
            listener,
            redirect_uri,
            authorize_url: url.to_string(),
            state,
            nonce,
            verifier,
            client_id,
            saved: request.saved,
        })
    }

    /// The URL the operator opens. Carries the ID token hint on a
    /// reauthorization, so it is shown to the operator and never logged.
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The loopback callback this attempt listens on.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait for the callback, then validate and exchange.
    ///
    /// The state is checked before anything else the callback says. A
    /// declined consent or any other provider error stops here, before
    /// any exchange. On a first registration the callback must carry the
    /// issued client id; on a reauthorization it may leave it out, and
    /// may not name a different one. The ID token is validated against
    /// the provider's keys and this attempt's nonce, and a
    /// reauthorization must name the saved account.
    pub async fn finish(self, timeout: Duration) -> Result<SignedIn, PlanAuthError> {
        let params = tokio::time::timeout(timeout, accept_callback(&self.listener))
            .await
            .map_err(|_| PlanAuthError::Timeout)??;

        let state_ok = params
            .get("state")
            .is_some_and(|got| same(got, &self.state));
        if !state_ok {
            return Err(PlanAuthError::StateMismatch);
        }
        if let Some(error) = params.get("error") {
            return Err(if error == "access_denied" {
                PlanAuthError::Declined
            } else {
                PlanAuthError::Provider(error.clone())
            });
        }
        let client_id = resolve_client_id(
            self.client_id.as_deref(),
            params.get("client_id").map(String::as_str),
        )?;
        let code = params
            .get("code")
            .filter(|c| !c.is_empty())
            .ok_or_else(|| PlanAuthError::Provider("no code in the callback".into()))?;

        let (status, body) = post_form(
            &self.http,
            &self.endpoints.token_url(),
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("client_id", client_id.as_str()),
                ("code_verifier", self.verifier.as_str()),
                ("resource", RESOURCE),
            ],
        )
        .await
        .map_err(|e| PlanAuthError::Exchange(e.to_string()))?;
        if !status.is_success() {
            return Err(PlanAuthError::Exchange(
                match error_code(&body).as_deref() {
                    Some("invalid_grant") => {
                        "the code was refused (invalid_grant); start the sign-in again".into()
                    }
                    Some(code) => format!("HTTP {} {code}", status.as_u16()),
                    None => format!("HTTP {}", status.as_u16()),
                },
            ));
        }
        let tokens: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| PlanAuthError::Exchange(format!("token response: {e}")))?;

        let id_token = tokens
            .id_token
            .clone()
            .ok_or_else(|| PlanAuthError::IdToken("the token response carried none".into()))?;
        let discovery = discover(&self.http, &self.endpoints)
            .await
            .map_err(PlanAuthError::IdToken)?;
        let keys = fetch_keys(&self.http, &discovery.jwks_uri)
            .await
            .map_err(PlanAuthError::IdToken)?;
        let identity = validate_id_token(
            &id_token,
            &keys,
            self.endpoints.issuer(),
            &client_id,
            &self.nonce,
            unix_now(),
        )
        .map_err(PlanAuthError::IdToken)?;
        if let Some(saved) = &self.saved
            && saved.subject.as_deref() != Some(identity.sub.as_str())
        {
            return Err(PlanAuthError::AccountMismatch);
        }

        let scope = granted_scopes(tokens.scope.as_deref());
        let refresh_token = tokens.refresh_token.unwrap_or_default();
        if refresh_token.is_empty() && scope.split_whitespace().any(|s| s == PLAN_SCOPE) {
            return Err(PlanAuthError::Exchange(
                "the token response carried no refresh token".into(),
            ));
        }
        Ok(SignedIn {
            credential: OAuthCredential {
                access_token: tokens.access_token,
                refresh_token,
                expires_at: unix_now() + tokens.expires_in.unwrap_or(3600),
                scope,
                provider: PROVIDER.to_string(),
                client_id: Some(client_id),
                issuer: Some(self.endpoints.issuer().to_string()),
                subject: Some(identity.sub),
                email: identity.email,
                id_token: Some(id_token),
            },
            registered: self.client_id.is_none(),
        })
    }
}

/// The client id the exchange uses. A first registration takes the
/// issued id from the callback and has nothing without it. A
/// reauthorization keeps the saved id; the callback may leave it out
/// and may not name another.
fn resolve_client_id(saved: Option<&str>, returned: Option<&str>) -> Result<String, PlanAuthError> {
    match (saved, returned.filter(|r| !r.is_empty())) {
        (None, Some(issued)) if issued != REGISTRATION_CLIENT_ID => Ok(issued.to_string()),
        (None, _) => Err(PlanAuthError::RegistrationIncomplete),
        (Some(saved), None) => Ok(saved.to_string()),
        (Some(saved), Some(returned)) if returned == saved => Ok(saved.to_string()),
        (Some(saved), Some(returned)) => Err(PlanAuthError::ClientMismatch {
            saved: saved.to_string(),
            returned: returned.to_string(),
        }),
    }
}

/// Accept connections until one requests [`CALLBACK_PATH`], answer it,
/// and return its query parameters. Anything else the browser asks for
/// on the port gets a 404.
async fn accept_callback(
    listener: &tokio::net::TcpListener,
) -> Result<HashMap<String, String>, PlanAuthError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| PlanAuthError::Local(format!("accept callback: {e}")))?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        while raw.len() < 16 * 1024 && !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        }
        let request = String::from_utf8_lossy(&raw);
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if path != CALLBACK_PATH {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let mut params = HashMap::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            params
                .entry(k.into_owned())
                .or_insert_with(|| v.into_owned());
        }
        let body = "<html><body><h1>Sign-in returned to wirken</h1>\
                    <p>You can close this tab. The terminal shows the result.</p></body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        return Ok(params);
    }
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Whether the provider confirmed the end of the renewable session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    /// The revocation endpoint answered 200.
    Confirmed,
    /// The entry held no refresh token; there was nothing to revoke.
    NothingToRevoke,
    /// No confirmation, with the last reason.
    Unconfirmed(String),
}

/// Revoke `cred`'s refresh token at the revocation endpoint discovery
/// names. A network error or a 5xx is retried after each wait in
/// [`REVOKE_BACKOFF`]; any other answer is final.
pub async fn revoke(cred: &OAuthCredential) -> Revocation {
    revoke_at(&Endpoints::pinned(), cred, &REVOKE_BACKOFF).await
}

pub(crate) async fn revoke_at(
    endpoints: &Endpoints,
    cred: &OAuthCredential,
    backoff: &[Duration],
) -> Revocation {
    if cred.refresh_token.is_empty() {
        return Revocation::NothingToRevoke;
    }
    let Some(client_id) = cred.client_id.as_deref() else {
        return Revocation::Unconfirmed("the entry carries no client id".into());
    };
    let http = match http_client(endpoints) {
        Ok(h) => h,
        Err(e) => return Revocation::Unconfirmed(e),
    };
    let mut waits = backoff.iter();
    loop {
        let attempt = async {
            let discovery = discover(&http, endpoints).await.map_err(|e| (true, e))?;
            let endpoint = discovery
                .revocation_endpoint
                .ok_or((false, "discovery names no revocation endpoint".to_string()))?;
            let (status, _) = post_form(
                &http,
                &endpoint,
                &[
                    ("token", cred.refresh_token.as_str()),
                    ("token_type_hint", "refresh_token"),
                    ("client_id", client_id),
                ],
            )
            .await
            .map_err(|e| (true, format!("revocation request: {e}")))?;
            if status.is_success() {
                Ok(())
            } else {
                Err((
                    status.is_server_error(),
                    format!("revocation returned HTTP {}", status.as_u16()),
                ))
            }
        };
        match attempt.await {
            Ok(()) => return Revocation::Confirmed,
            Err((true, reason)) => match waits.next() {
                Some(wait) => tokio::time::sleep(*wait).await,
                None => return Revocation::Unconfirmed(reason),
            },
            Err((false, reason)) => return Revocation::Unconfirmed(reason),
        }
    }
}

/// Sign `entry` out: clear its tokens, keeping the client id, the
/// account and the ID token for the next sign-in, then revoke the
/// refresh token it held. The entry's lock file is held throughout, so
/// no refresh in another process rotates the token in between; the
/// vault's write lock is held only for the clear, never across the
/// revocation requests.
pub async fn sign_out(
    store: Arc<Mutex<CredentialStore>>,
    lock_dir: &Path,
    entry: &str,
) -> Result<Revocation, String> {
    sign_out_at(Endpoints::pinned(), store, lock_dir, entry, &REVOKE_BACKOFF).await
}

pub(crate) async fn sign_out_at(
    endpoints: Endpoints,
    store: Arc<Mutex<CredentialStore>>,
    lock_dir: &Path,
    entry: &str,
    backoff: &[Duration],
) -> Result<Revocation, String> {
    let _held = lock_entry(entry_lock_path(lock_dir, entry)).await?;
    let entry_name = entry.to_string();
    let done = locked_update(store, entry_name.clone(), move |secret| {
        let cred = match parse_credential(secret, &entry_name) {
            Ok(c) if is_plan_credential(&c) => c,
            Ok(_) => return (None, Err(format!("'{entry_name}' is not a plan sign-in"))),
            Err(e) => return (None, Err(e)),
        };
        (Some(secret_of(&without_tokens(&cred))), Ok(cred))
    })
    .await?;
    let cred = done.value?;
    done.written
        .map_err(|e| format!("clearing the tokens of '{entry}' failed: {e}"))?;
    Ok(revoke_at(&endpoints, &cred, backoff).await)
}

/// Run `decide` on `entry` under the vault's write lock, on a blocking
/// thread since the lock may wait on another connection. `decide` makes
/// no network call: the lock blocks every other vault writer while it
/// is held.
async fn locked_update<T: Send + 'static>(
    store: Arc<Mutex<CredentialStore>>,
    entry: String,
    decide: impl FnOnce(&VaultSecret) -> (Option<VaultSecret>, T) + Send + 'static,
) -> Result<wirken_vault::ExclusiveUpdate<T>, String> {
    tokio::task::spawn_blocking(move || {
        let store = store
            .lock()
            .map_err(|_| "vault lock poisoned".to_string())?;
        store
            .update_exclusive(&entry, VAULT_WAIT, decide)
            .map_err(|e| format!("vault: {e}"))
    })
    .await
    .map_err(|e| format!("vault task: {e}"))?
}

/// The lock file that serializes refresh and sign-out of `entry` across
/// processes: one per entry, under `lock_dir` (the data directory),
/// named by a hash of the entry name so any name maps to a plain file.
pub fn entry_lock_path(lock_dir: &Path, entry: &str) -> std::path::PathBuf {
    let digest = Sha256::digest(entry.as_bytes());
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    lock_dir.join(format!("plan-{short}.lock"))
}

/// An entry's lock file, held. Closing the file on drop releases it.
struct EntryLock {
    _file: std::fs::File,
}

/// Take `path`'s lock, waiting up to [`ENTRY_LOCK_WAIT`] for another
/// process to release it. The file is created owner-only.
async fn lock_entry(path: std::path::PathBuf) -> Result<EntryLock, String> {
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let deadline = std::time::Instant::now() + ENTRY_LOCK_WAIT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(EntryLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "another process held {} for {}s",
                            path.display(),
                            ENTRY_LOCK_WAIT.as_secs()
                        ));
                    }
                    std::thread::sleep(ENTRY_LOCK_POLL);
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(format!("lock {}: {e}", path.display()));
                }
            }
        }
    })
    .await
    .map_err(|e| format!("lock task: {e}"))?
}

// ---------------------------------------------------------------------------
// The token source
// ---------------------------------------------------------------------------

/// What a refresh did.
enum Step {
    /// The provider issued new tokens and the vault holds them.
    Refreshed(OAuthCredential),
    /// The provider issued new tokens and the vault write failed.
    Unsaved(OAuthCredential, String),
    /// Another process refreshed first, or the entry changed while this
    /// one refreshed; these are the tokens the vault holds.
    Superseded(OAuthCredential),
    /// The refresh token is dead; the stored tokens were cleared.
    Terminal(String),
    InvalidClient,
    /// A failure that keeps the credential.
    Retained(String),
}

/// The bearer for each model call an agent on a plan entry makes.
///
/// Holds no token of its own between calls beyond one it could not yet
/// write back: every call reads the entry, so a refresh another process
/// made is picked up rather than raced. The mutex inside makes it the
/// single refresher for its entry in this process; the gateway builds
/// one per entry and hands it to every agent on that entry. Across
/// processes the entry's lock file does the same.
pub struct PlanTokenSource {
    entry: String,
    store: Arc<Mutex<CredentialStore>>,
    lock_path: std::path::PathBuf,
    endpoints: Endpoints,
    http: reqwest::Client,
    leak: Arc<LeakMatcher>,
    /// Refreshed tokens the vault refused. Used, and written again, on
    /// the next call; the vault still holds the token they replaced.
    unsaved: tokio::sync::Mutex<Option<OAuthCredential>>,
}

impl PlanTokenSource {
    /// A source over `entry` in `store`, serialized with other processes
    /// through the entry's lock file under `lock_dir` (the data
    /// directory). Refuses an entry that is missing, not a plan sign-in,
    /// signed out, or without plan usage, so the process that would run
    /// on it stops before its first turn.
    pub fn open(
        store: CredentialStore,
        lock_dir: &Path,
        entry: &str,
        leak: Arc<LeakMatcher>,
    ) -> Result<Arc<Self>, String> {
        Self::open_at(Endpoints::pinned(), store, lock_dir, entry, leak)
    }

    pub(crate) fn open_at(
        endpoints: Endpoints,
        store: CredentialStore,
        lock_dir: &Path,
        entry: &str,
        leak: Arc<LeakMatcher>,
    ) -> Result<Arc<Self>, String> {
        let cred = load_plan(&store, entry).map_err(|e| {
            if e.contains("credentials authorize") {
                e
            } else {
                format!("{e}. Run `wirken credentials authorize {entry}`.")
            }
        })?;
        if let Some(reason) = unusable_reason(&cred, entry) {
            return Err(reason);
        }
        let http = http_client(&endpoints)?;
        Ok(Arc::new(Self {
            entry: entry.to_string(),
            store: Arc::new(Mutex::new(store)),
            lock_path: entry_lock_path(lock_dir, entry),
            endpoints,
            http,
            leak,
            unsaved: tokio::sync::Mutex::new(None),
        }))
    }

    /// The vault entry this source reads, stamped on the agent's model
    /// call rows as their credential.
    pub fn entry(&self) -> &str {
        &self.entry
    }

    /// The endpoints the source's tokens are for.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    fn read_entry(&self) -> Result<OAuthCredential, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "vault lock poisoned".to_string())?;
        load_plan(&store, &self.entry)
    }

    fn sign_in_again(&self, why: &str) -> AgentError {
        AgentError::Llm(format!(
            "plan credential '{}' {why}. Run `wirken credentials authorize {}` to sign in again.",
            self.entry, self.entry
        ))
    }

    /// The access token for one call, refreshed first when it is within
    /// five minutes of expiry. Never an expired token: when a refresh
    /// fails for a reason that keeps the credential, the current token
    /// is used only while it is still valid, and the call fails after.
    pub async fn bearer(&self) -> Result<String, AgentError> {
        let mut unsaved = self.unsaved.lock().await;
        if let Some(pending) = unsaved.clone() {
            match self.write(&pending, None).await {
                Ok(_) => {
                    tracing::warn!(
                        credential = %self.entry,
                        "refreshed plan tokens written to the vault on retry"
                    );
                    *unsaved = None;
                }
                Err(e) => tracing::error!(
                    credential = %self.entry,
                    error = %e,
                    "refreshed plan tokens are still not in the vault; this process keeps them \
                     in memory, and any other process using this entry holds a spent refresh \
                     token until the write succeeds"
                ),
            }
        }
        let current = match unsaved.clone() {
            Some(pending) => pending,
            None => self.read_entry().map_err(AgentError::Llm)?,
        };
        if let Some(reason) = unusable_reason(&current, &self.entry) {
            return Err(AgentError::Llm(reason));
        }
        let now = unix_now();
        if current.expires_at > now + REFRESH_LEAD_SECS {
            return Ok(current.access_token);
        }

        // Compare against the vault only when the vault holds what this
        // call read. Unsaved tokens are newer than the vault's, which
        // still carries the refresh token they replaced.
        let compare = unsaved.is_none();
        let step = self.refresh(&current, compare).await;
        let still_valid = current.expires_at > now + EXPIRY_MARGIN_SECS;
        match step {
            Ok(Step::Refreshed(fresh)) => {
                self.learn(&fresh);
                *unsaved = None;
                tracing::info!(credential = %self.entry, "plan token refreshed");
                Ok(fresh.access_token)
            }
            Ok(Step::Unsaved(fresh, e)) => {
                self.learn(&fresh);
                tracing::error!(
                    credential = %self.entry,
                    error = %e,
                    "plan token refreshed but the vault write failed; the new tokens are kept in \
                     memory for this process and the write is retried on the next call"
                );
                *unsaved = Some(fresh.clone());
                Ok(fresh.access_token)
            }
            Ok(Step::Superseded(stored)) => {
                self.learn(&stored);
                *unsaved = None;
                if let Some(reason) = unusable_reason(&stored, &self.entry) {
                    return Err(AgentError::Llm(reason));
                }
                if stored.expires_at > now + EXPIRY_MARGIN_SECS {
                    Ok(stored.access_token)
                } else {
                    Err(self
                        .sign_in_again("holds an expired token after another process's refresh"))
                }
            }
            Ok(Step::Terminal(code)) => {
                *unsaved = None;
                Err(self.sign_in_again(&format!("was refused at refresh ({code})")))
            }
            Ok(Step::InvalidClient) => Err(AgentError::Llm(format!(
                "plan credential '{}': the provider refused its client id (invalid_client). The \
                 registration is not usable; sign in again with `wirken credentials authorize {}`.",
                self.entry, self.entry
            ))),
            Ok(Step::Retained(reason)) | Err(reason) => {
                if still_valid {
                    tracing::warn!(
                        credential = %self.entry,
                        "plan token refresh failed ({reason}); using the current token until it expires"
                    );
                    Ok(current.access_token)
                } else {
                    Err(AgentError::Llm(format!(
                        "plan credential '{}': the access token has expired and the refresh \
                         failed ({reason}); the credential is kept and the next call tries again",
                        self.entry
                    )))
                }
            }
        }
    }

    /// One refresh, holding the entry's lock file from the read to the
    /// write. The vault is read and written in short steps; the request
    /// to the provider runs with no vault transaction open.
    ///
    /// With `compare`, a stored refresh token that differs from the one
    /// `current` read means another process refreshed first, and its
    /// tokens are used instead of spending ours. The write compares
    /// again, as a backstop for a writer that does not take the lock
    /// file (a sign-in, an import).
    async fn refresh(&self, current: &OAuthCredential, compare: bool) -> Result<Step, String> {
        let _held = lock_entry(self.lock_path.clone()).await?;
        let basis = if compare {
            let stored = self.read_entry()?;
            if stored.refresh_token != current.refresh_token {
                return Ok(Step::Superseded(stored));
            }
            stored
        } else {
            current.clone()
        };
        let expected = compare.then(|| basis.refresh_token.clone());
        Ok(
            match request_refresh(&self.http, &self.endpoints, &basis).await {
                Ok(fresh) => match self.write(&fresh, expected).await {
                    Ok(None) => Step::Refreshed(fresh),
                    Ok(Some(stored)) => Step::Superseded(stored),
                    Err(e) => Step::Unsaved(fresh, e),
                },
                Err(RefreshFailure::Terminal(code)) => {
                    match self.write(&without_tokens(&basis), expected).await {
                        Ok(None) => {}
                        Ok(Some(_)) => tracing::warn!(
                            credential = %self.entry,
                            "the refresh token was refused ({code}) and the entry had already \
                             changed; it was left as it is"
                        ),
                        Err(e) => tracing::error!(
                            credential = %self.entry,
                            error = %e,
                            "the refresh token was refused ({code}) and clearing the stored \
                             tokens failed"
                        ),
                    }
                    Step::Terminal(code)
                }
                Err(RefreshFailure::InvalidClient) => Step::InvalidClient,
                Err(RefreshFailure::Retained(reason)) => Step::Retained(reason),
            },
        )
    }

    /// Write `cred` over the entry in one short exclusive update. With
    /// `expected`, only while the stored refresh token is still that
    /// one: `Ok(Some(stored))` says it changed, and what it holds now.
    async fn write(
        &self,
        cred: &OAuthCredential,
        expected: Option<String>,
    ) -> Result<Option<OAuthCredential>, String> {
        let secret = secret_of(cred);
        let entry = self.entry.clone();
        let done = locked_update(self.store.clone(), self.entry.clone(), move |current| {
            let Some(expected) = expected else {
                return (Some(secret), Ok(None));
            };
            match parse_credential(current, &entry) {
                Ok(stored) if stored.refresh_token == expected => (Some(secret), Ok(None)),
                Ok(stored) => (None, Ok(Some(stored))),
                Err(e) => (None, Err(e)),
            }
        })
        .await?;
        let changed = done.value?;
        done.written.map_err(|e| e.to_string())?;
        Ok(changed)
    }

    fn learn(&self, cred: &OAuthCredential) {
        if let Ok(json) = serde_json::to_string(cred) {
            self.leak.learn(&self.entry, &json, CredentialKind::Secret);
        }
    }
}

#[cfg(test)]
#[path = "plan_auth_tests.rs"]
pub(crate) mod tests;
