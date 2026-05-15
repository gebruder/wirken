//! Auth providers for HTTP MCP transports.
//!
//! The [`HttpTransport`] knows how to send JSON-RPC over HTTP but
//! stays ignorant about credentials. Each request asks its
//! [`AuthProvider`] for an `Authorization` header value (if any) and
//! forwards it.
//!
//! Three concrete impls:
//!
//! - [`NoAuth`] — for internal MCP servers that don't require auth
//! - [`BearerAuth`] — for static personal-access-token style
//!   credentials (Linear, Notion, GitHub, Datadog, Slack, …)
//! - [`OAuth2Auth`] — for OAuth2-protected servers; refreshes the
//!   access token from the vault when it's about to expire and
//!   writes the new tokens back
//!
//! `OAuth2Auth` does the refresh inline on the request path. To
//! prevent concurrent refreshes of the same credential from racing
//! against each other (providers that rotate refresh tokens, like
//! Google, invalidate the loser), every `OAuth2Auth` holds a shared
//! per-credential [`tokio::sync::Mutex`] provided by the proxy
//! registry. Only one refresh is in flight per credential at any
//! time.
//!
//! The trait returns [`reqwest::header::HeaderValue`] directly rather
//! than a `String` so the bearer-token bytes are not duplicated into
//! a throwaway heap string on every request.
//!
//! [`HttpTransport`]: crate::mcp_transport::HttpTransport

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use reqwest::header::HeaderValue;
use wirken_vault::CredentialStore;

use crate::error::ProxyError;
use crate::oauth::{OAuthCredential, refresh_oauth_token};

/// Returns the value of an HTTP `Authorization` header for the next
/// MCP request. Implementations may consult the vault and may
/// refresh tokens; both happen on the request path.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError>;

    /// OAuth-credential context for typed error reporting. Returns
    /// `Some((credential_name, provider_name))` when this auth
    /// provider is backed by an OAuth credential the `wirken
    /// credentials rescope` flow can re-grant. `NoAuth` and
    /// `BearerAuth` return `None`: they are not OAuth-managed and
    /// rescope does not apply to them.
    ///
    /// Used by the MCP-tool-call path to populate
    /// [`crate::tool_error::McpToolError::ScopeNotGranted`] when a
    /// per-provider detector classifies a tool-call failure as a
    /// scope-missing condition. The credential name appears in the
    /// operator-facing rescope hint; the provider name routes
    /// through to the right detector.
    fn oauth_context(&self) -> Option<(String, String)> {
        None
    }
}

/// No-auth provider — produces no `Authorization` header.
pub struct NoAuth;

#[async_trait]
impl AuthProvider for NoAuth {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError> {
        Ok(None)
    }
}

/// Build a `Bearer <token>` header value without leaving an owned
/// copy of `token` sitting on the heap after we return. `format!`
/// allocates, `HeaderValue::from_str` copies into its own buffer, and
/// the `format!` String drops immediately at the end of the statement.
fn bearer_header(token: &str) -> Result<HeaderValue, ProxyError> {
    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| {
        ProxyError::Vault(format!(
            "invalid bearer token for Authorization header: {e}"
        ))
    })
}

/// Bearer-token provider. The vault entry stores the raw token as
/// a UTF-8 string. The provider reads it on every request — there
/// is no in-memory caching, which keeps the secret out of the
/// proxy's address space for as long as possible.
pub struct BearerAuth {
    credential_name: String,
    vault: Arc<Mutex<Option<CredentialStore>>>,
}

impl BearerAuth {
    pub fn new(credential_name: String, vault: Arc<Mutex<Option<CredentialStore>>>) -> Self {
        Self {
            credential_name,
            vault,
        }
    }
}

#[async_trait]
impl AuthProvider for BearerAuth {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError> {
        let guard = self.vault.lock().expect("vault mutex");
        let store = guard.as_ref().ok_or_else(|| {
            ProxyError::Vault(format!(
                "vault unavailable; cannot resolve bearer credential '{}'",
                self.credential_name
            ))
        })?;
        let (secret, _) = store.retrieve(&self.credential_name).map_err(|e| {
            ProxyError::Vault(format!(
                "bearer credential '{}' not found: {e}",
                self.credential_name
            ))
        })?;
        // `secret.expose()` returns a `&str` backed by the zeroized
        // `VaultSecret`. The `format!` temporary inside `bearer_header`
        // lives only for the duration of that expression.
        let header = bearer_header(secret.expose())?;
        Ok(Some(header))
    }
}

/// OAuth2 provider. Reads the JSON-serialized
/// [`OAuthCredential`] from the vault, checks expiry, refreshes via
/// the configured provider's token endpoint if within 60 seconds of
/// expiry, writes the refreshed credential back to the vault, and
/// returns the (possibly new) `access_token` as a Bearer header.
///
/// Refresh is serialized per credential via a shared
/// [`tokio::sync::Mutex`] handed out by the proxy registry. Two
/// concurrent tool calls that both hit the "about to expire" branch
/// will find only one winner inside the critical section; the other
/// will re-read the freshly refreshed credential and skip the
/// refresh HTTP call entirely.
pub struct OAuth2Auth {
    credential_name: String,
    provider: String,
    vault: Arc<Mutex<Option<CredentialStore>>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl OAuth2Auth {
    pub fn new(
        credential_name: String,
        provider: String,
        vault: Arc<Mutex<Option<CredentialStore>>>,
        refresh_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            credential_name,
            provider,
            vault,
            refresh_lock,
        }
    }

    /// Load the current credential from the vault. Held in a
    /// dedicated helper so the vault mutex guard is scoped tightly
    /// and released before any `.await`.
    fn load_current(&self) -> Result<OAuthCredential, ProxyError> {
        let guard = self.vault.lock().expect("vault mutex");
        let store = guard.as_ref().ok_or_else(|| {
            ProxyError::Vault(format!(
                "vault unavailable; cannot resolve oauth credential '{}'. \
                 Run `wirken mcp authorize <server>` first.",
                self.credential_name
            ))
        })?;
        crate::oauth::load_oauth(store, &self.credential_name).map_err(|e| {
            ProxyError::Vault(format!(
                "oauth credential '{}' not found: {e}. \
                 Run `wirken mcp authorize <server>` to bootstrap.",
                self.credential_name
            ))
        })
    }

    /// Store a refreshed credential back to the vault. Same scoping
    /// discipline as [`Self::load_current`].
    fn store_refreshed(&self, cred: &OAuthCredential) -> Result<(), ProxyError> {
        let guard = self.vault.lock().expect("vault mutex");
        let store = guard.as_ref().ok_or_else(|| {
            ProxyError::Vault("vault unavailable for oauth refresh writeback".into())
        })?;
        crate::oauth::store_oauth(store, &self.credential_name, cred)
            .map_err(|e| ProxyError::Vault(format!("oauth refresh writeback failed: {e}")))
    }
}

#[async_trait]
impl AuthProvider for OAuth2Auth {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError> {
        // First fast-path read: is the existing token still good?
        // If so we skip the refresh mutex entirely — the lock is only
        // needed on the near-expiry branch.
        let mut cred = self.load_current()?;
        let now = chrono::Utc::now().timestamp() as u64;

        if cred.expires_at <= now + 60 {
            // Slow path: acquire the per-credential refresh mutex
            // and re-check expiry. Whoever got here first may have
            // already refreshed; the second arrival will see a
            // bumped `expires_at` and exit without its own refresh.
            let _guard = self.refresh_lock.lock().await;

            cred = self.load_current()?;
            let now = chrono::Utc::now().timestamp() as u64;
            if cred.expires_at <= now + 60 {
                tracing::info!(
                    "oauth credential '{}' expires in {}s — refreshing",
                    self.credential_name,
                    cred.expires_at.saturating_sub(now),
                );
                let refreshed = refresh_oauth_token(&self.provider, &cred)
                    .await
                    .map_err(|e| {
                        ProxyError::Vault(format!(
                            "oauth refresh failed for '{}': {e}. \
                         Run `wirken mcp authorize <server>` to re-bootstrap.",
                            self.credential_name
                        ))
                    })?;
                self.store_refreshed(&refreshed)?;
                cred = refreshed;
            }
        }

        let header = bearer_header(&cred.access_token)?;
        Ok(Some(header))
    }

    fn oauth_context(&self) -> Option<(String, String)> {
        Some((self.credential_name.clone(), self.provider.clone()))
    }
}
