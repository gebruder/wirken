//! The credentials the MCP proxy holds, and the channel back to the
//! gateway for OAuth refreshes.
//!
//! The proxy never opens the vault. The gateway resolves every name the
//! MCP configs reference and hands the values over on the proxy's stdin
//! at spawn: stdio `vault:` values, bearer tokens, and OAuth credentials
//! with their refresh token removed. When an OAuth access token nears
//! expiry, the proxy asks the gateway to refresh it; the gateway holds
//! the refresh token, calls the provider, writes the vault, and answers
//! with the new access token. When an MCP server refuses a credential,
//! the proxy asks the gateway for its current vault value, so a
//! credential rotated in the vault reaches the proxy without a restart.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wirken_vault::VaultSecret;
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::oauth::OAuthCredential;

/// The hand-off entry that carries the refresh channel's token rather
/// than a credential. The gateway never hands over a vault credential
/// under this name, so the proxy can take it as the token.
pub const GATEWAY_TOKEN_ENTRY: &str = "wirken:mcp-refresh-token";

/// Environment variable naming the gateway's refresh socket.
pub const GATEWAY_SOCKET_ENV: &str = "WIRKEN_MCP_GATEWAY_SOCKET";

/// How long a refresh may take, the provider's token call included.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(60);

/// What the proxy holds: credential values by vault name, and how to
/// reach the gateway for a refresh.
pub struct ProxyCredentials {
    values: Mutex<HashMap<String, VaultSecret>>,
    gateway: Option<GatewayLink>,
}

/// Shared by every auth provider and the stdio start path.
pub type SharedCredentials = Arc<ProxyCredentials>;

impl ProxyCredentials {
    pub fn new(values: HashMap<String, VaultSecret>, gateway: Option<GatewayLink>) -> Self {
        Self {
            values: Mutex::new(values),
            gateway,
        }
    }

    /// No credentials and no gateway, for callers that use none.
    pub fn none() -> Self {
        Self::new(HashMap::new(), None)
    }

    /// A copy of `name`'s value, if the gateway handed one over.
    pub fn get(&self, name: &str) -> Option<VaultSecret> {
        self.values
            .lock()
            .expect("credentials mutex")
            .get(name)
            .map(|v| VaultSecret::new(v.expose().to_string()))
    }

    /// The OAuth credential handed over under `name`. Its refresh token
    /// is empty: the gateway keeps that.
    pub fn oauth(&self, name: &str) -> Result<OAuthCredential, ProxyError> {
        let secret = self.get(name).ok_or_else(|| {
            ProxyError::Vault(format!(
                "oauth credential '{name}' was not handed to the proxy. \
                 Run `wirken mcp authorize <server>` and restart the gateway."
            ))
        })?;
        serde_json::from_str(secret.expose())
            .map_err(|e| ProxyError::Vault(format!("parse oauth credential '{name}': {e}")))
    }

    /// Have the gateway refresh `name`, and keep the answer in place of
    /// the old value.
    pub async fn refresh_oauth(&self, name: &str) -> Result<OAuthCredential, ProxyError> {
        let gateway = self.gateway.as_ref().ok_or_else(|| {
            ProxyError::Vault(format!(
                "no gateway to refresh oauth credential '{name}' through"
            ))
        })?;
        let refreshed = match gateway.ask(name, RequestKind::Refresh).await? {
            RefreshReply::Refreshed(cred) => cred.into_credential(),
            RefreshReply::Current { .. } => {
                return Err(ProxyError::Vault(format!(
                    "the gateway answered the refresh of '{name}' with a current value"
                )));
            }
            RefreshReply::Refused { reason } => {
                return Err(ProxyError::Vault(format!(
                    "the gateway did not refresh '{name}': {reason}"
                )));
            }
        };
        let json = serde_json::to_string(&refreshed)
            .map_err(|e| ProxyError::Vault(format!("serialize oauth credential: {e}")))?;
        self.values
            .lock()
            .expect("credentials mutex")
            .insert(name.to_string(), VaultSecret::new(json));
        Ok(refreshed)
    }

    /// Have the gateway send the vault's current value of `name`, after
    /// a server refused the one held here, and keep it in its place.
    pub async fn refetch(&self, name: &str) -> Result<(), ProxyError> {
        let gateway = self.gateway.as_ref().ok_or_else(|| {
            ProxyError::Vault(format!("no gateway to fetch credential '{name}' from"))
        })?;
        let value = match gateway.ask(name, RequestKind::Current).await? {
            RefreshReply::Current { value } => VaultSecret::new(value),
            RefreshReply::Refreshed(_) => {
                return Err(ProxyError::Vault(format!(
                    "the gateway answered the fetch of '{name}' with a refresh"
                )));
            }
            RefreshReply::Refused { reason } => {
                return Err(ProxyError::Vault(format!(
                    "the gateway did not send '{name}': {reason}"
                )));
            }
        };
        self.values
            .lock()
            .expect("credentials mutex")
            .insert(name.to_string(), value);
        Ok(())
    }
}

/// The gateway's refresh socket and the token that admits this proxy.
pub struct GatewayLink {
    socket: PathBuf,
    token: Zeroizing<String>,
}

impl GatewayLink {
    pub fn new(socket: PathBuf, token: Zeroizing<String>) -> Self {
        Self { socket, token }
    }

    /// One request to the gateway and its answer.
    async fn ask(&self, name: &str, kind: RequestKind) -> Result<RefreshReply, ProxyError> {
        let exchange = async {
            let stream = wirken_ipc::connect(&self.socket).await.map_err(|e| {
                ProxyError::Vault(format!(
                    "reach the gateway at {}: {e}",
                    self.socket.display()
                ))
            })?;
            let (rd, mut wr) = tokio::io::split(stream);
            let request = RefreshRequest {
                token: self.token.as_str(),
                credential: name,
                kind,
            };
            let mut line = Zeroizing::new(
                serde_json::to_vec(&request)
                    .map_err(|e| ProxyError::Vault(format!("refresh request: {e}")))?,
            );
            line.push(b'\n');
            wr.write_all(&line)
                .await
                .map_err(|e| ProxyError::Vault(format!("send request to the gateway: {e}")))?;
            let mut reply = Zeroizing::new(String::new());
            BufReader::new(rd)
                .read_line(&mut reply)
                .await
                .map_err(|e| ProxyError::Vault(format!("read the gateway's reply: {e}")))?;
            serde_json::from_str::<RefreshReply>(&reply)
                .map_err(|e| ProxyError::Vault(format!("parse the gateway's reply: {e}")))
        };
        tokio::time::timeout(REFRESH_TIMEOUT, exchange)
            .await
            .map_err(|_| {
                ProxyError::Vault(format!(
                    "the gateway did not answer about '{name}' within {}s",
                    REFRESH_TIMEOUT.as_secs()
                ))
            })?
    }
}

/// One request: the token that admits the proxy, the credential, and
/// what to do with it. One request per connection.
#[derive(Serialize, Deserialize)]
pub(crate) struct RefreshRequest<'a> {
    pub token: &'a str,
    pub credential: &'a str,
    #[serde(default)]
    pub kind: RequestKind,
}

/// What the proxy asks for.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestKind {
    /// Refresh an OAuth credential near expiry.
    #[default]
    Refresh,
    /// The vault's current value, after a server refused the one the
    /// proxy holds.
    Current,
}

/// The gateway's answer.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefreshReply {
    Refreshed(HandedOAuth),
    /// The vault's current value; an OAuth credential without its
    /// refresh token.
    Current {
        value: String,
    },
    Refused {
        reason: String,
    },
}

/// An OAuth credential as the proxy may hold it: everything but the
/// refresh token.
#[derive(Serialize, Deserialize)]
pub(crate) struct HandedOAuth {
    pub access_token: String,
    pub expires_at: u64,
    pub scope: String,
    pub provider: String,
}

impl HandedOAuth {
    pub(crate) fn from_credential(cred: &OAuthCredential) -> Self {
        Self {
            access_token: cred.access_token.clone(),
            expires_at: cred.expires_at,
            scope: cred.scope.clone(),
            provider: cred.provider.clone(),
        }
    }

    fn into_credential(self) -> OAuthCredential {
        OAuthCredential {
            access_token: self.access_token,
            refresh_token: String::new(),
            expires_at: self.expires_at,
            scope: self.scope,
            provider: self.provider,
        }
    }
}

/// `value`, a stored OAuth credential, as the proxy may hold it: the
/// same JSON with an empty refresh token. Anything that does not parse
/// as one is returned unchanged; the proxy fails on it as before.
pub fn without_refresh_token(value: &str) -> String {
    match serde_json::from_str::<OAuthCredential>(value) {
        Ok(cred) => serde_json::to_string(&HandedOAuth::from_credential(&cred).into_credential())
            .unwrap_or_else(|_| value.to_string()),
        Err(_) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handed_oauth_credential_has_no_refresh_token() {
        let stored = serde_json::to_string(&OAuthCredential {
            access_token: "at".into(),
            refresh_token: "rt-secret".into(),
            expires_at: 10,
            scope: "read".into(),
            provider: "linear".into(),
        })
        .unwrap();
        let handed = without_refresh_token(&stored);
        assert!(!handed.contains("rt-secret"), "{handed}");
        let parsed: OAuthCredential = serde_json::from_str(&handed).unwrap();
        assert_eq!(parsed.access_token, "at");
        assert_eq!(parsed.refresh_token, "");
        assert_eq!(parsed.expires_at, 10);
        assert_eq!(without_refresh_token("not json"), "not json");
    }
}
