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
//! - [`OAuth2Auth`] — for OAuth2-protected servers; when the access
//!   token is about to expire, asks the gateway to refresh it. The
//!   gateway holds the refresh token, calls the provider and writes the
//!   vault; the proxy gets the new access token.
//!
//! Every credential comes from what the gateway handed the proxy at
//! spawn ([`crate::credentials`]); the proxy never opens the vault.
//! When a server refuses a credential, [`AuthProvider::refused`] asks
//! the gateway for its current value, which the next request carries.
//! `OAuth2Auth` asks for a refresh on the request path. Every
//! `OAuth2Auth` holds a shared per-credential [`tokio::sync::Mutex`]
//! provided by the proxy registry, so one request per credential asks
//! at a time; the gateway serializes refreshes of a credential too.
//!
//! The trait returns [`reqwest::header::HeaderValue`] directly rather
//! than a `String` so the bearer-token bytes are not duplicated into
//! a throwaway heap string on every request.
//!
//! [`HttpTransport`]: crate::mcp_transport::HttpTransport

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::credentials::SharedCredentials;
use crate::error::ProxyError;
use crate::oauth::OAuthCredential;

/// Returns the value of an HTTP `Authorization` header for the next
/// MCP request. Implementations may consult the vault and may
/// refresh tokens; both happen on the request path.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError>;

    /// The server refused the credential the last header carried. Ask
    /// the gateway for the vault's current value, so a credential
    /// rotated there reaches the next request. Returns whether there
    /// was a credential to ask about.
    async fn refused(&mut self) -> Result<bool, ProxyError> {
        Ok(false)
    }

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

/// Build a `Bearer <token>` header value. The string is assembled in
/// an exactly-sized `Zeroizing<String>`, so the intermediate copy is a
/// single allocation that is zeroed when this returns. The header is
/// marked sensitive, which redacts it from `Debug` output and keeps it
/// out of the HTTP/2 HPACK table.
///
/// Not zeroed: the `Bytes` buffer `HeaderValue` copies the value into,
/// and the copies reqwest makes in its send buffers. Both are freed
/// with the token still in them.
fn bearer_header(token: &str) -> Result<HeaderValue, ProxyError> {
    const PREFIX: &str = "Bearer ";
    let mut value = Zeroizing::new(String::with_capacity(PREFIX.len() + token.len()));
    value.push_str(PREFIX);
    value.push_str(token);
    let mut header = HeaderValue::from_str(&value).map_err(|e| {
        ProxyError::Vault(format!(
            "invalid bearer token for Authorization header: {e}"
        ))
    })?;
    header.set_sensitive(true);
    Ok(header)
}

/// Bearer-token provider. The token is the value the gateway handed
/// over under the credential's name.
pub struct BearerAuth {
    credential_name: String,
    credentials: SharedCredentials,
}

impl BearerAuth {
    pub fn new(credential_name: String, credentials: SharedCredentials) -> Self {
        Self {
            credential_name,
            credentials,
        }
    }
}

#[async_trait]
impl AuthProvider for BearerAuth {
    async fn authorization_header(&mut self) -> Result<Option<HeaderValue>, ProxyError> {
        let secret = self.credentials.get(&self.credential_name).ok_or_else(|| {
            ProxyError::Vault(format!(
                "bearer credential '{}' was not handed to the proxy",
                self.credential_name
            ))
        })?;
        // `secret.expose()` returns a `&str` backed by the zeroized
        // `VaultSecret`; `bearer_header` zeroes its own intermediate.
        let header = bearer_header(secret.expose())?;
        Ok(Some(header))
    }

    async fn refused(&mut self) -> Result<bool, ProxyError> {
        self.credentials.refetch(&self.credential_name).await?;
        Ok(true)
    }
}

/// OAuth2 provider. Reads the access token the gateway handed over,
/// and when it is within 60 seconds of expiry asks the gateway to
/// refresh it, then returns the (possibly new) access token as a
/// Bearer header.
///
/// Requests are serialized per credential via a shared
/// [`tokio::sync::Mutex`] handed out by the proxy registry. Two
/// concurrent tool calls that both hit the "about to expire" branch
/// will find only one winner inside the critical section; the other
/// will re-read the refreshed token and not ask again.
pub struct OAuth2Auth {
    credential_name: String,
    provider: String,
    credentials: SharedCredentials,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl OAuth2Auth {
    pub fn new(
        credential_name: String,
        provider: String,
        credentials: SharedCredentials,
        refresh_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            credential_name,
            provider,
            credentials,
            refresh_lock,
        }
    }

    fn load_current(&self) -> Result<OAuthCredential, ProxyError> {
        self.credentials.oauth(&self.credential_name)
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
            // Slow path: acquire the per-credential mutex and re-check
            // expiry. Whoever got here first may have already had it
            // refreshed; the second arrival will see a bumped
            // `expires_at` and exit without asking again.
            let _guard = self.refresh_lock.lock().await;

            cred = self.load_current()?;
            let now = chrono::Utc::now().timestamp() as u64;
            if cred.expires_at <= now + 60 {
                tracing::info!(
                    "oauth credential '{}' expires in {}s — asking the gateway to refresh it",
                    self.credential_name,
                    cred.expires_at.saturating_sub(now),
                );
                cred = self
                    .credentials
                    .refresh_oauth(&self.credential_name)
                    .await
                    .map_err(|e| {
                        ProxyError::Vault(format!(
                            "oauth refresh failed for '{}': {e}. \
                             Run `wirken mcp authorize <server>` to re-bootstrap.",
                            self.credential_name
                        ))
                    })?;
            }
        }

        let header = bearer_header(&cred.access_token)?;
        Ok(Some(header))
    }

    /// A credential the operator authorized again replaces the one held
    /// here. Under the refresh lock, so it does not cross a refresh.
    async fn refused(&mut self) -> Result<bool, ProxyError> {
        let _guard = self.refresh_lock.lock().await;
        self.credentials.refetch(&self.credential_name).await?;
        Ok(true)
    }

    fn oauth_context(&self) -> Option<(String, String)> {
        Some((self.credential_name.clone(), self.provider.clone()))
    }
}

#[cfg(test)]
mod handed_tests {
    use std::collections::HashMap;

    use super::*;
    use crate::credentials::ProxyCredentials;
    use wirken_vault::VaultSecret;

    fn handed(entries: &[(&str, &str)]) -> SharedCredentials {
        Arc::new(ProxyCredentials::new(
            entries
                .iter()
                .map(|(k, v)| (k.to_string(), VaultSecret::new(v.to_string())))
                .collect::<HashMap<_, _>>(),
            None,
        ))
    }

    #[tokio::test]
    async fn a_bearer_token_is_the_handed_value_and_nothing_else() {
        let credentials = handed(&[("linear-token", "lin_abc")]);
        let mut auth = BearerAuth::new("linear-token".into(), credentials.clone());
        let header = auth.authorization_header().await.unwrap().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer lin_abc");

        let mut other = BearerAuth::new("notion-token".into(), credentials);
        let err = other.authorization_header().await.unwrap_err().to_string();
        assert!(err.contains("not handed to the proxy"), "{err}");
    }

    /// A token that is not near expiry is used without asking anyone.
    #[tokio::test]
    async fn a_fresh_oauth_token_needs_no_gateway() {
        let cred = OAuthCredential {
            access_token: "AT-linear".into(),
            refresh_token: String::new(),
            expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
            scope: String::new(),
            provider: "linear".into(),
        };
        let credentials = handed(&[("linear-oauth", &serde_json::to_string(&cred).unwrap())]);
        let mut auth = OAuth2Auth::new(
            "linear-oauth".into(),
            "linear".into(),
            credentials,
            Arc::new(tokio::sync::Mutex::new(())),
        );
        let header = auth.authorization_header().await.unwrap().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer AT-linear");
    }
}
