//! The gateway's side of the MCP proxy's OAuth refreshes.
//!
//! Runs in the gateway, which holds the vault. The proxy asks over a
//! socket in the gateway's socket directory. A request is served only
//! with the token the gateway handed that proxy at spawn and, on Unix,
//! only from the proxy's own process, checked by the peer's pid on a
//! socket of mode 0600. Windows named pipes report no peer pid, so
//! there the token alone admits.
//! Only the credentials the proxy was handed can be refreshed. The
//! refresh token never leaves the gateway: it calls the provider, writes
//! the refreshed credential to the vault, and answers with the access
//! token and its expiry.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use wirken_vault::CredentialStore;
use zeroize::Zeroizing;

use crate::credentials::{HandedOAuth, RefreshReply, RefreshRequest};
use crate::error::ProxyError;
use crate::oauth::{OAuthCredential, load_oauth, refresh_oauth_token, store_oauth};

/// Cap on a request line.
const MAX_REQUEST_BYTES: u64 = 16 * 1024;

/// Refreshes an OAuth credential against its provider.
#[async_trait::async_trait]
pub trait Refresher: Send + Sync {
    async fn refresh(&self, cred: &OAuthCredential) -> Result<OAuthCredential, ProxyError>;
}

/// The provider's token endpoint, named by the stored credential.
pub struct ProviderRefresher;

#[async_trait::async_trait]
impl Refresher for ProviderRefresher {
    async fn refresh(&self, cred: &OAuthCredential) -> Result<OAuthCredential, ProxyError> {
        refresh_oauth_token(&cred.provider, cred).await
    }
}

/// Where the refresh service listens.
pub struct RefreshListener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(not(unix))]
    inner: Box<dyn wirken_ipc::Listener>,
}

impl RefreshListener {
    /// Bind at `path`; on Unix, a socket only this user can connect to.
    pub fn bind(path: &std::path::Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let inner = tokio::net::UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner })
        }
        #[cfg(not(unix))]
        {
            let inner = wirken_ipc::bind(path).map_err(std::io::Error::other)?;
            Ok(Self { inner })
        }
    }
}

/// Everything the gateway needs to serve one proxy's refreshes.
pub struct RefreshService {
    store: Option<Arc<std::sync::Mutex<CredentialStore>>>,
    /// The OAuth credentials the proxy was handed.
    allowed: BTreeSet<String>,
    token: Zeroizing<String>,
    /// The proxy's pid; zero until it is spawned.
    proxy_pid: Arc<AtomicU32>,
    refresher: Arc<dyn Refresher>,
    /// One refresh per credential at a time.
    locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RefreshService {
    pub fn new(
        store: Option<Arc<std::sync::Mutex<CredentialStore>>>,
        allowed: BTreeSet<String>,
        token: Zeroizing<String>,
        proxy_pid: Arc<AtomicU32>,
    ) -> Self {
        Self {
            store,
            allowed,
            token,
            proxy_pid,
            refresher: Arc::new(ProviderRefresher),
            locks: Default::default(),
        }
    }

    /// Refresh through `refresher` instead of the provider.
    pub fn with_refresher(mut self, refresher: Arc<dyn Refresher>) -> Self {
        self.refresher = refresher;
        self
    }

    /// Serve requests until the task is dropped.
    #[cfg_attr(unix, allow(unused_mut))]
    pub async fn serve(self: Arc<Self>, mut listener: RefreshListener) {
        loop {
            #[cfg(unix)]
            let accepted = listener.inner.accept().await.map(|(stream, _)| {
                let peer = stream.peer_cred().ok().and_then(|c| c.pid());
                (stream, peer)
            });
            #[cfg(not(unix))]
            let accepted = listener.inner.accept().await.map(|stream| (stream, None));
            let Ok((stream, peer)) = accepted else {
                continue;
            };
            let service = self.clone();
            tokio::spawn(async move {
                if let Err(e) = service.handle(stream, peer).await {
                    tracing::debug!("MCP proxy refresh connection ended: {e}");
                }
            });
        }
    }

    async fn handle<S>(&self, stream: S, peer: Option<i32>) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (rd, mut wr) = tokio::io::split(stream);
        let mut line = Zeroizing::new(String::new());
        BufReader::new(rd.take(MAX_REQUEST_BYTES))
            .read_line(&mut line)
            .await?;

        let reply = match self.admit(peer, &line) {
            Err(reason) => {
                tracing::warn!("MCP proxy refresh request refused: {reason}");
                RefreshReply::Refused { reason }
            }
            Ok(name) => match self.refresh(&name).await {
                Ok(cred) => RefreshReply::Refreshed(HandedOAuth::from_credential(&cred)),
                Err(reason) => {
                    tracing::warn!("MCP proxy refresh of '{name}' failed: {reason}");
                    RefreshReply::Refused { reason }
                }
            },
        };
        let mut out = Zeroizing::new(serde_json::to_vec(&reply).unwrap_or_default());
        out.push(b'\n');
        wr.write_all(&out).await
    }

    /// The credential name a request may refresh, or why it may not.
    fn admit(&self, peer: Option<i32>, line: &str) -> Result<String, String> {
        let expected = self.proxy_pid.load(Ordering::Acquire);
        if expected == 0 {
            return Err("the MCP proxy is not running".to_string());
        }
        // Windows named pipes report no peer pid; the token admits.
        if cfg!(unix) && peer.and_then(|p| u32::try_from(p).ok()) != Some(expected) {
            return Err(format!("the peer {peer:?} is not the MCP proxy"));
        }
        let request: RefreshRequest = serde_json::from_str(line.trim_end())
            .map_err(|_| "malformed refresh request".to_string())?;
        if !same_bytes(request.token.as_bytes(), self.token.as_bytes()) {
            return Err("wrong refresh token".to_string());
        }
        if !self.allowed.contains(request.credential) {
            return Err(format!(
                "'{}' is not an OAuth credential the proxy was handed",
                request.credential
            ));
        }
        Ok(request.credential.to_string())
    }

    /// Refresh `name` and write it to the vault, unless the vault already
    /// holds a credential that is not near expiry, which is returned.
    async fn refresh(&self, name: &str) -> Result<OAuthCredential, String> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| "the gateway has no vault open".to_string())?;
        let lock = self
            .locks
            .lock()
            .await
            .entry(name.to_string())
            .or_default()
            .clone();
        let _serial = lock.lock().await;

        let cred = {
            let store = store
                .lock()
                .map_err(|_| "vault mutex poisoned".to_string())?;
            load_oauth(&*store, name).map_err(|e| e.to_string())?
        };
        let now = chrono::Utc::now().timestamp() as u64;
        if cred.expires_at > now + 60 {
            return Ok(cred);
        }
        let refreshed = self
            .refresher
            .refresh(&cred)
            .await
            .map_err(|e| e.to_string())?;
        {
            let store = store
                .lock()
                .map_err(|_| "vault mutex poisoned".to_string())?;
            store_oauth(&*store, name, &refreshed).map_err(|e| e.to_string())?;
        }
        tracing::info!("refreshed oauth credential '{name}' for the MCP proxy");
        Ok(refreshed)
    }
}

/// Byte equality whose time does not depend on where the inputs differ.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::auth::{AuthProvider, OAuth2Auth};
    use crate::credentials::{GatewayLink, ProxyCredentials, without_refresh_token};
    use wirken_vault::VaultSecret;

    /// Stands in for the provider: checks it was handed the vault's
    /// refresh token, and answers with a new pair.
    struct FakeProvider;

    #[async_trait::async_trait]
    impl Refresher for FakeProvider {
        async fn refresh(&self, cred: &OAuthCredential) -> Result<OAuthCredential, ProxyError> {
            assert_eq!(
                cred.refresh_token, "RT-1",
                "the gateway refreshes with the vault's token"
            );
            Ok(OAuthCredential {
                access_token: "AT-2".into(),
                refresh_token: "RT-2".into(),
                expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
                scope: cred.scope.clone(),
                provider: cred.provider.clone(),
            })
        }
    }

    struct Gateway {
        _dir: tempfile::TempDir,
        store: Arc<std::sync::Mutex<CredentialStore>>,
        socket: std::path::PathBuf,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A vault holding an expired OAuth credential, and the refresh
    /// service over it, admitting this process as the proxy.
    fn gateway(token: &str, proxy_pid: u32) -> Gateway {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::open_with_key(
            &dir.path().join("vault.db"),
            VaultSecret::new("a".repeat(64)),
        )
        .unwrap();
        store_oauth(
            &store,
            "linear-oauth",
            &OAuthCredential {
                access_token: "AT-1".into(),
                refresh_token: "RT-1".into(),
                expires_at: 1,
                scope: "read".into(),
                provider: "linear".into(),
            },
        )
        .unwrap();
        let store = Arc::new(std::sync::Mutex::new(store));
        let socket = dir.path().join("refresh.sock");
        let listener = RefreshListener::bind(&socket).unwrap();
        let service = Arc::new(
            RefreshService::new(
                Some(store.clone()),
                BTreeSet::from(["linear-oauth".to_string()]),
                Zeroizing::new(token.to_string()),
                Arc::new(AtomicU32::new(proxy_pid)),
            )
            .with_refresher(Arc::new(FakeProvider)),
        );
        let task = tokio::spawn(service.serve(listener));
        Gateway {
            _dir: dir,
            store,
            socket,
            task,
        }
    }

    /// The proxy's side: the stored credential as the gateway hands it
    /// over, without its refresh token, and the link back.
    fn proxy(gateway: &Gateway, token: &str) -> Arc<ProxyCredentials> {
        let (stored, _) = gateway
            .store
            .lock()
            .unwrap()
            .retrieve("linear-oauth")
            .unwrap();
        let handed = without_refresh_token(stored.expose());
        Arc::new(ProxyCredentials::new(
            HashMap::from([("linear-oauth".to_string(), VaultSecret::new(handed))]),
            Some(GatewayLink::new(
                gateway.socket.clone(),
                Zeroizing::new(token.to_string()),
            )),
        ))
    }

    fn auth(credentials: Arc<ProxyCredentials>) -> OAuth2Auth {
        OAuth2Auth::new(
            "linear-oauth".into(),
            "linear".into(),
            credentials,
            Arc::new(tokio::sync::Mutex::new(())),
        )
    }

    #[tokio::test]
    async fn the_proxy_refreshes_through_the_gateway_and_the_vault_holds_the_new_token() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        assert!(
            !credentials
                .get("linear-oauth")
                .unwrap()
                .expose()
                .contains("RT-1"),
            "the proxy was handed a refresh token"
        );

        let header = auth(credentials.clone())
            .authorization_header()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer AT-2");

        let stored = load_oauth(&*gateway.store.lock().unwrap(), "linear-oauth").unwrap();
        assert_eq!(stored.access_token, "AT-2");
        assert_eq!(stored.refresh_token, "RT-2");
        let held = credentials.get("linear-oauth").unwrap();
        assert!(held.expose().contains("AT-2"));
        assert!(
            !held.expose().contains("RT-"),
            "the proxy holds a refresh token: {}",
            held.expose()
        );
    }

    #[tokio::test]
    async fn a_refresh_with_the_wrong_token_changes_nothing() {
        let gateway = gateway("t0k3n", std::process::id());
        let err = auth(proxy(&gateway, "guess"))
            .authorization_header()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong refresh token"), "{err}");
        let stored = load_oauth(&*gateway.store.lock().unwrap(), "linear-oauth").unwrap();
        assert_eq!(stored.access_token, "AT-1");
    }

    #[tokio::test]
    async fn a_refresh_from_any_process_but_the_proxy_is_refused() {
        let gateway = gateway("t0k3n", std::process::id() + 1);
        let err = auth(proxy(&gateway, "t0k3n"))
            .authorization_header()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not the MCP proxy"), "{err}");
    }

    #[tokio::test]
    async fn only_a_handed_oauth_credential_can_be_refreshed() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = Arc::new(ProxyCredentials::new(
            HashMap::from([(
                "telegram-token".to_string(),
                VaultSecret::new(
                    serde_json::to_string(&OAuthCredential {
                        access_token: "x".into(),
                        refresh_token: String::new(),
                        expires_at: 1,
                        scope: String::new(),
                        provider: "linear".into(),
                    })
                    .unwrap(),
                ),
            )]),
            Some(GatewayLink::new(
                gateway.socket.clone(),
                Zeroizing::new("t0k3n".to_string()),
            )),
        ));
        let err = credentials
            .refresh_oauth("telegram-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not an OAuth credential the proxy was handed"),
            "{err}"
        );
    }
}
