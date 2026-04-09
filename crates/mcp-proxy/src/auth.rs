//! Auth providers for HTTP MCP transports.
//!
//! Item 7 slice 2 of `docs/managed-agents-parity.md`. The
//! [`HttpTransport`] knows how to send JSON-RPC over HTTP but stays
//! ignorant about credentials. Each request asks its
//! [`AuthProvider`] for the value of an `Authorization` header (if
//! any) and forwards it.
//!
//! Three concrete impls in slice 2:
//!
//! - [`NoAuth`] — for internal MCP servers that don't require auth
//! - [`BearerAuth`] — for static personal-access-token style
//!   credentials (Linear, Notion, GitHub, Datadog, Slack, …)
//! - [`OAuth2Auth`] — for OAuth2-protected servers; refreshes the
//!   access token from the vault when it's about to expire and
//!   writes the new tokens back
//!
//! `OAuth2Auth` does the refresh inline on the request path. The
//! latency hit is one extra HTTP round trip on the first call after
//! `expires_at - 60s`. Background refresh is a future optimization.
//!
//! [`HttpTransport`]: crate::mcp_transport::HttpTransport

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use wirken_vault::CredentialStore;

use crate::error::ProxyError;
use crate::oauth::{OAuthCredential, refresh_oauth_token};

/// Returns the value of an HTTP `Authorization` header for the next
/// MCP request. Implementations may consult the vault and may
/// refresh tokens; both happen on the request path.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authorization_header(&mut self) -> Result<Option<String>, ProxyError>;
}

/// No-auth provider — produces no `Authorization` header.
pub struct NoAuth;

#[async_trait]
impl AuthProvider for NoAuth {
    async fn authorization_header(&mut self) -> Result<Option<String>, ProxyError> {
        Ok(None)
    }
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
    async fn authorization_header(&mut self) -> Result<Option<String>, ProxyError> {
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
        let token = secret.expose().to_string();
        Ok(Some(format!("Bearer {token}")))
    }
}

/// OAuth2 provider. Reads the JSON-serialized
/// [`OAuthCredential`] from the vault, checks expiry, refreshes via
/// the configured provider's token endpoint if within 60 seconds of
/// expiry, writes the refreshed credential back to the vault, and
/// returns the (possibly new) `access_token` as a Bearer header.
///
/// On refresh failure the provider returns a [`ProxyError::Vault`]
/// with a message that points the user at
/// `wirken mcp authorize <server>`. Per decision C1 of the slice 2
/// design, refresh failure surfaces to the agent's tool call rather
/// than triggering an interactive re-authorize from the proxy.
pub struct OAuth2Auth {
    credential_name: String,
    provider: String,
    vault: Arc<Mutex<Option<CredentialStore>>>,
}

impl OAuth2Auth {
    pub fn new(
        credential_name: String,
        provider: String,
        vault: Arc<Mutex<Option<CredentialStore>>>,
    ) -> Self {
        Self {
            credential_name,
            provider,
            vault,
        }
    }
}

#[async_trait]
impl AuthProvider for OAuth2Auth {
    async fn authorization_header(&mut self) -> Result<Option<String>, ProxyError> {
        // Read the current credential. Hold the vault mutex only
        // for the read, then release before the (possibly slow)
        // refresh HTTP call.
        let mut cred: OAuthCredential = {
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
            })?
        };

        // Refresh if within 60 seconds of expiry.
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
            cred = refreshed;

            // Write back. Hold the vault mutex briefly.
            let guard = self.vault.lock().expect("vault mutex");
            let store = guard.as_ref().ok_or_else(|| {
                ProxyError::Vault("vault unavailable for oauth refresh writeback".into())
            })?;
            crate::oauth::store_oauth(store, &self.credential_name, &cred)
                .map_err(|e| ProxyError::Vault(format!("oauth refresh writeback failed: {e}")))?;
        }

        Ok(Some(format!("Bearer {}", cred.access_token)))
    }
}
