//! Token refresh for plan mode (`"auth": "plan"` on the [`PROVIDER`]
//! provider).
//!
//! In this mode an agent's requests run on the operator's own plan at
//! the provider rather than on an API key. The grant is an OAuth token
//! set: an access token that lives an hour and a refresh token that
//! lives thirty days and rotates on every use.
//!
//! What lives here:
//!
//! - [`PlanTokenSource`]: the bearer for each model call. One per vault
//!   entry per process. Across processes, a refresh holds the entry's
//!   lock file ([`entry_lock_path`]) from read to write, so a rotating
//!   token is never spent twice. The vault itself is touched only in
//!   short steps around the request, and the write still checks that the
//!   stored refresh token is the one the refresh started from
//!   ([`wirken_vault::CredentialStore::update_exclusive`]). No network
//!   call is made while the vault's write lock is held.
//!
//! Every endpoint is fixed ([`AUTH_BASE`], [`API_BASE`]). Nothing in a
//! configuration file or the environment moves them: [`Endpoints::pinned`]
//! is the only constructor outside this crate's tests.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use wirken_gateway::leak::LeakMatcher;
use wirken_mcp_proxy::OAuthCredential;
use wirken_vault::{CredentialKind, CredentialStore, VaultSecret};

use crate::error::AgentError;

/// The provider's authorization server, whose token endpoint refreshes
/// the grant.
pub const AUTH_BASE: &str = "https://auth.openai.com";
/// The API the plan's tokens are issued for, and where `/responses`
/// and `/models` are called.
pub const API_BASE: &str = "https://api.openai.com/v1";
/// Sent as `resource` on refresh.
pub const RESOURCE: &str = "https://api.openai.com/v1";
/// `OAuthCredential::provider` on a plan entry: the provider id the
/// agent runs as.
pub const PROVIDER: &str = "openai";
/// The vault entry a plan sign-in is kept under when none is named.
pub const DEFAULT_ENTRY: &str = "openai-plan";
/// The scope that permits plan usage. A grant without it runs nothing.
pub const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
/// Every scope a plan grant carries: identity, the refresh token, and
/// plan usage.
pub const SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "resource.invoke",
    PLAN_SCOPE,
];
/// Where the operator reviews usage and sets this app's limit.
pub const USAGE_URL: &str = "https://chatgpt.com/settings/usage";

const TOKEN_PATH: &str = "/api/accounts/oauth/token";

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
/// Timeout on each request to the authorization server.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a short vault write waits on another connection's write.
/// No network call is ever made while the vault's write lock is held,
/// so this is the store's ordinary wait.
const VAULT_WAIT: Duration = Duration::from_secs(5);
/// How long a refresh waits for another process to release the entry's
/// lock file. Longer than any one holder keeps it.
const ENTRY_LOCK_WAIT: Duration = Duration::from_secs(90);
/// How often a waiting process tries the entry's lock file again.
const ENTRY_LOCK_POLL: Duration = Duration::from_millis(50);

/// The endpoints a refresh and a plan-mode call talk to.
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

    fn token_url(&self) -> String {
        format!("{}{TOKEN_PATH}", self.auth_base)
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

/// Seconds since the epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    store
        .store_with_kind(
            entry,
            "oauth",
            &secret_of(cred),
            None,
            None,
            &[],
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
// Token endpoint
// ---------------------------------------------------------------------------

/// A token endpoint response. Holds tokens, so no `Debug`.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
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
