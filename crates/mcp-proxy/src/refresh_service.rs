//! The gateway's side of the MCP proxy's credential requests: OAuth
//! refreshes, and current values after a server refused a credential.
//!
//! Runs in the gateway, which holds the vault. The proxy asks over a
//! socket in the gateway's socket directory. A request is served only
//! with the token the gateway handed that proxy at spawn and, on Unix,
//! only from the proxy's own process, checked by the peer's pid on a
//! socket of mode 0600. Windows named pipes report no peer pid, so
//! there the token alone admits.
//! Only the credentials the proxy was handed can be asked for, and only
//! the OAuth ones refreshed. The refresh token never leaves the gateway:
//! it calls the provider, writes the refreshed credential to the vault,
//! and answers with the access token and its expiry. A current value is
//! sent as the vault holds it, an OAuth credential without its refresh
//! token, and each one sent is an `mcp_credential_refetched` row naming
//! the credential.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use wirken_audit::{MCP_CREDENTIAL_SESSION, SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_vault::CredentialStore;
use zeroize::{Zeroize, Zeroizing};

use crate::credentials::{
    HandedOAuth, RefreshReply, RefreshRequest, RequestKind, ServerPin, WatchNotice,
    without_refresh_token,
};
use crate::error::ProxyError;
use crate::oauth::{OAuthCredential, load_oauth, refresh_oauth_token};

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

/// Everything the gateway needs to serve one proxy's requests.
pub struct RefreshService {
    store: Option<Arc<std::sync::Mutex<CredentialStore>>>,
    /// The credentials the proxy was handed.
    handed: BTreeSet<String>,
    /// Which of them are OAuth credentials.
    oauth: BTreeSet<String>,
    token: Zeroizing<String>,
    /// The proxy's pid; zero until it is spawned.
    proxy_pid: Arc<AtomicU32>,
    refresher: Arc<dyn Refresher>,
    /// Where each current value sent is recorded.
    audit: Option<Arc<dyn SessionLog>>,
    /// Learns each value read from the vault and each refreshed token,
    /// for leak detection in the gateway.
    leak: Option<Arc<wirken_gateway::leak::LeakMatcher>>,
    /// One refresh per credential at a time.
    locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// The entries each handed credential was handed for. A current
    /// value is sent only for entries its binding still allows. Empty
    /// checks nothing.
    pins: HashMap<String, BTreeSet<ServerPin>>,
    /// Credentials changed in the vault, for the proxy's watch.
    changes: tokio::sync::broadcast::Sender<WatchNotice>,
}

impl RefreshService {
    pub fn new(
        store: Option<Arc<std::sync::Mutex<CredentialStore>>>,
        handed: BTreeSet<String>,
        oauth: BTreeSet<String>,
        token: Zeroizing<String>,
        proxy_pid: Arc<AtomicU32>,
        audit: Option<Arc<dyn SessionLog>>,
    ) -> Self {
        Self {
            store,
            handed,
            oauth,
            token,
            proxy_pid,
            refresher: Arc::new(ProviderRefresher),
            audit,
            leak: None,
            locks: Default::default(),
            pins: HashMap::new(),
            changes: tokio::sync::broadcast::channel(64).0,
        }
    }

    /// Send a current value only for the entries in `pins` its binding
    /// still allows.
    pub fn with_pins(mut self, pins: HashMap<String, BTreeSet<ServerPin>>) -> Self {
        self.pins = pins;
        self
    }

    /// Tell the proxy `name` changed in the vault, if it was handed.
    /// Returns whether it was.
    pub fn notify_changed(&self, name: &str) -> bool {
        if !self.handed.contains(name) {
            return false;
        }
        let _ = self.changes.send(WatchNotice::Changed {
            credential: name.to_string(),
        });
        true
    }

    /// Tell the proxy `agent_id` was stopped, so it stops the agent's
    /// servers.
    pub fn notify_agent_stopped(&self, agent_id: &str) {
        let _ = self.changes.send(WatchNotice::AgentStopped {
            agent_id: agent_id.to_string(),
        });
    }

    /// Tell the proxy `agent_id` was resumed, so it starts the agent's
    /// servers again.
    pub fn notify_agent_resumed(&self, agent_id: &str) {
        let _ = self.changes.send(WatchNotice::AgentResumed {
            agent_id: agent_id.to_string(),
        });
    }

    /// Have `leak` learn every value this service reads or refreshes.
    pub fn with_leak_matcher(mut self, leak: Arc<wirken_gateway::leak::LeakMatcher>) -> Self {
        self.leak = Some(leak);
        self
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
        let mut reader = BufReader::new(rd.take(MAX_REQUEST_BYTES));
        reader.read_line(&mut line).await?;

        let mut reply = match self.admit(peer, &line) {
            Err(reason) => {
                tracing::warn!("MCP proxy credential request refused: {reason}");
                RefreshReply::Refused { reason }
            }
            Ok((_, RequestKind::Watch)) => {
                // Held until the proxy closes it, or this process ends
                // and the operating system closes it, which is how the
                // proxy learns the gateway is gone. Each vault change to
                // a handed credential goes down it as a line.
                let mut changes = self.changes.subscribe();
                let mut out = serde_json::to_vec(&RefreshReply::Watching).unwrap_or_default();
                out.push(b'\n');
                wr.write_all(&out).await?;
                let mut rest = [0u8; 64];
                loop {
                    tokio::select! {
                        n = reader.read(&mut rest) => {
                            if n? == 0 {
                                return Ok(());
                            }
                        }
                        changed = changes.recv() => match changed {
                            Ok(notice) => {
                                let mut out = serde_json::to_vec(&notice).unwrap_or_default();
                                out.push(b'\n');
                                wr.write_all(&out).await?;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                return Ok(());
                            }
                        },
                    }
                }
            }
            Ok((name, RequestKind::Refresh)) => match self.refresh(&name).await {
                Ok(cred) => RefreshReply::Refreshed(HandedOAuth::from_credential(&cred)),
                Err(reason) => {
                    tracing::warn!("MCP proxy refresh of '{name}' failed: {reason}");
                    RefreshReply::Refused { reason }
                }
            },
            Ok((name, RequestKind::Current)) => match self.current(&name) {
                Ok((value, servers)) => RefreshReply::Current { value, servers },
                Err(reason) => {
                    tracing::warn!("MCP proxy fetch of '{name}' failed: {reason}");
                    RefreshReply::Refused { reason }
                }
            },
        };
        let mut out = Zeroizing::new(serde_json::to_vec(&reply).unwrap_or_default());
        if let RefreshReply::Current { value, .. } = &mut reply {
            value.zeroize();
        }
        out.push(b'\n');
        wr.write_all(&out).await
    }

    /// The credential a request names and what it asks, or why it may
    /// not be served.
    fn admit(&self, peer: Option<i32>, line: &str) -> Result<(String, RequestKind), String> {
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
        if request.kind == RequestKind::Watch {
            return Ok((String::new(), RequestKind::Watch));
        }
        if !self.handed.contains(request.credential) {
            return Err(format!(
                "'{}' is not a credential the proxy was handed",
                request.credential
            ));
        }
        if request.kind == RequestKind::Refresh && !self.oauth.contains(request.credential) {
            return Err(format!(
                "'{}' is not an OAuth credential the proxy was handed",
                request.credential
            ));
        }
        Ok((request.credential.to_string(), request.kind))
    }

    /// The vault's current value of `name`, as the proxy may hold it,
    /// recorded as sent.
    fn current(&self, name: &str) -> Result<(String, Option<Vec<ServerPin>>), String> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| "the gateway has no vault open".to_string())?;
        let (secret, meta) = store
            .lock()
            .map_err(|_| "vault mutex poisoned".to_string())?
            .retrieve(name)
            .map_err(|e| e.to_string())?;
        // The entries it may still go to, checked against the binding the
        // decryption just authenticated.
        let servers = match self.pins.get(name) {
            Some(pins) => {
                let allowed: Vec<ServerPin> = pins
                    .iter()
                    .filter(|pin| {
                        meta.binding.permits(&wirken_vault::Destination::McpServer(
                            wirken_vault::McpServerGrant {
                                name: pin.server.clone(),
                                entry: pin.entry.clone(),
                            },
                        ))
                    })
                    .cloned()
                    .collect();
                if allowed.is_empty() {
                    return Err(format!(
                        "'{name}' may no longer go to any MCP server it was handed for"
                    ));
                }
                Some(allowed)
            }
            None => None,
        };
        if let Some(leak) = &self.leak {
            leak.learn(name, secret.expose(), meta.kind);
        }
        let value = if self.oauth.contains(name) {
            without_refresh_token(secret.expose())
        } else {
            secret.expose().to_string()
        };
        if let Some(log) = &self.audit {
            let lane = log.handle_for(SessionId::new(MCP_CREDENTIAL_SESSION));
            let event = SessionEvent::McpCredentialRefetched {
                credential: name.to_string(),
            };
            if let Err(e) = log.append(&lane, TrustLevel::System, event) {
                tracing::warn!("could not record the MCP proxy's fetch of '{name}': {e}");
            }
        }
        tracing::info!("sent the MCP proxy the current value of credential '{name}'");
        Ok((value, servers))
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
            load_oauth(&store, name).map_err(|e| e.to_string())?
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
        // Write only if the entry still holds the refresh token this
        // refresh started from, under the vault's write lock. Only the
        // value changes.
        let json = Zeroizing::new(
            serde_json::to_string(&refreshed)
                .map_err(|e| format!("serialize oauth credential: {e}"))?,
        );
        let swapped =
            {
                let store = store
                    .lock()
                    .map_err(|_| "vault mutex poisoned".to_string())?;
                store.update_exclusive(name, REFRESH_WRITE_WAIT, |current| {
                    match serde_json::from_str::<OAuthCredential>(current.expose()) {
                        Ok(now)
                            if same_bytes(
                                now.refresh_token.as_bytes(),
                                cred.refresh_token.as_bytes(),
                            ) =>
                        {
                            (
                                Some(wirken_vault::VaultSecret::new(json.to_string())),
                                Swap::Written,
                            )
                        }
                        Ok(now) => (None, Swap::Reauthorized(Box::new(now))),
                        Err(_) => (None, Swap::Unreadable),
                    }
                })
            };
        match swapped {
            Ok(update) => {
                update
                    .written
                    .map_err(|e| format!("write refreshed oauth credential '{name}': {e}"))?;
                match update.value {
                    Swap::Written => {}
                    Swap::Reauthorized(now) => {
                        self.record_discarded(name, "reauthorized");
                        return Ok(*now);
                    }
                    Swap::Unreadable => {
                        self.record_discarded(name, "unreadable");
                        return Err(format!(
                            "oauth credential '{name}' changed during the refresh and no longer \
                             parses; the refreshed token is discarded"
                        ));
                    }
                }
            }
            Err(wirken_vault::VaultError::NotFound(_)) => {
                self.record_discarded(name, "removed");
                return Err(format!(
                    "oauth credential '{name}' was removed during the refresh; the refreshed \
                     token is discarded"
                ));
            }
            Err(e) => return Err(format!("write refreshed oauth credential '{name}': {e}")),
        }
        if let Some(leak) = &self.leak {
            let json =
                zeroize::Zeroizing::new(serde_json::to_string(&refreshed).unwrap_or_default());
            leak.learn(name, &json, wirken_vault::CredentialKind::Secret);
        }
        tracing::info!("refreshed oauth credential '{name}' for the MCP proxy");
        Ok(refreshed)
    }
}

/// How long the refresh write waits for the vault's write lock.
const REFRESH_WRITE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// What the refresh write found in the entry.
enum Swap {
    /// Held the starting refresh token; replaced.
    Written,
    /// Held another authorization; kept.
    Reauthorized(Box<OAuthCredential>),
    /// No longer an OAuth credential.
    Unreadable,
}

impl RefreshService {
    /// Record that a refresh's result was not written, and why.
    fn record_discarded(&self, name: &str, reason: &str) {
        tracing::warn!(
            "discarded the refresh of oauth credential '{name}': the entry was {reason} \
             during it"
        );
        if let Some(log) = &self.audit {
            let lane = log.handle_for(SessionId::new(MCP_CREDENTIAL_SESSION));
            let event = SessionEvent::McpCredentialRefreshDiscarded {
                credential: name.to_string(),
                reason: reason.to_string(),
            };
            if let Err(e) = log.append(&lane, TrustLevel::System, event) {
                tracing::warn!("could not record the discarded refresh of '{name}': {e}");
            }
        }
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
    use crate::oauth::store_oauth;
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
                ..Default::default()
            })
        }
    }

    struct Gateway {
        _dir: tempfile::TempDir,
        store: Arc<std::sync::Mutex<CredentialStore>>,
        socket: std::path::PathBuf,
        audit: Arc<dyn SessionLog>,
        task: tokio::task::JoinHandle<()>,
        service: Arc<RefreshService>,
    }

    impl Gateway {
        /// The rows on the gateway's MCP credential lane.
        fn rows(&self) -> Vec<SessionEvent> {
            let lane = self
                .audit
                .handle_for(SessionId::new(MCP_CREDENTIAL_SESSION));
            self.audit
                .get_since(&lane, 0)
                .unwrap()
                .into_iter()
                .map(|r| r.event)
                .collect()
        }
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A vault holding an expired OAuth credential and a bearer token,
    /// and the refresh service over it, admitting this process as the
    /// proxy, which was handed both.
    fn gateway(token: &str, proxy_pid: u32) -> Gateway {
        gateway_pinned(token, proxy_pid, HashMap::new())
    }

    /// [`gateway`], sending current values only for the entries in
    /// `pins` the binding allows.
    fn gateway_pinned(
        token: &str,
        proxy_pid: u32,
        pins: HashMap<String, BTreeSet<ServerPin>>,
    ) -> Gateway {
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
                ..Default::default()
            },
        )
        .unwrap();
        store
            .store(
                "linear-token",
                "mcp",
                &VaultSecret::new("tok-1".into()),
                None,
                None,
            )
            .unwrap();
        let store = Arc::new(std::sync::Mutex::new(store));
        let socket = dir.path().join("refresh.sock");
        let listener = RefreshListener::bind(&socket).unwrap();
        let audit: Arc<dyn SessionLog> =
            Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap());
        let service = Arc::new(
            RefreshService::new(
                Some(store.clone()),
                BTreeSet::from(["linear-oauth".to_string(), "linear-token".to_string()]),
                BTreeSet::from(["linear-oauth".to_string()]),
                Zeroizing::new(token.to_string()),
                Arc::new(AtomicU32::new(proxy_pid)),
                Some(audit.clone()),
            )
            .with_refresher(Arc::new(FakeProvider))
            .with_pins(pins),
        );
        let task = tokio::spawn(service.clone().serve(listener));
        Gateway {
            _dir: dir,
            store,
            socket,
            audit,
            task,
            service,
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
            HashMap::from([
                ("linear-oauth".to_string(), VaultSecret::new(handed)),
                ("linear-token".to_string(), VaultSecret::new("tok-1".into())),
            ]),
            Some(GatewayLink::new(
                gateway.socket.clone(),
                Zeroizing::new(token.to_string()),
            )),
        ))
    }

    fn auth(credentials: Arc<ProxyCredentials>) -> OAuth2Auth {
        OAuth2Auth::new(
            crate::credentials::ServerPin {
                server: "test".into(),
                entry: "sha256:test".into(),
            },
            "linear-oauth".into(),
            "linear".into(),
            credentials,
            Arc::new(tokio::sync::Mutex::new(())),
        )
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
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

        let stored = load_oauth(&gateway.store.lock().unwrap(), "linear-oauth").unwrap();
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

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_refresh_with_the_wrong_token_changes_nothing() {
        let gateway = gateway("t0k3n", std::process::id());
        let err = auth(proxy(&gateway, "guess"))
            .authorization_header()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong refresh token"), "{err}");
        let stored = load_oauth(&gateway.store.lock().unwrap(), "linear-oauth").unwrap();
        assert_eq!(stored.access_token, "AT-1");
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
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

    /// The proxy's watch is held while the gateway lives and ends when
    /// the gateway is gone. The gateway here runs in a runtime of its
    /// own, and dropping that runtime closes its end of the connection
    /// the way a killed process's is closed. A watch with the wrong
    /// token is refused, and never ends.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_watch_ends_when_the_gateway_is_gone() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let gateway_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let gateway = runtime.block_on(async { gateway("t0k3n", std::process::id()) });
            ready_tx.send(gateway.socket.clone()).unwrap();
            let _ = stop_rx.recv();
            drop(gateway);
            drop(runtime);
        });
        let socket = ready_rx.recv().unwrap();
        let link = |token: &str| {
            ProxyCredentials::new(
                HashMap::new(),
                Some(GatewayLink::new(
                    socket.clone(),
                    Zeroizing::new(token.to_string()),
                )),
            )
        };

        let credentials = Arc::new(link("t0k3n"));
        let watching = tokio::spawn({
            let credentials = credentials.clone();
            async move {
                credentials
                    .gateway_gone(tokio::sync::mpsc::unbounded_channel().0)
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !watching.is_finished(),
            "the watch ended with the gateway up"
        );

        let refused = link("guess");
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                refused.gateway_gone(tokio::sync::mpsc::unbounded_channel().0)
            )
            .await
            .is_err(),
            "a refused watch ended"
        );

        stop_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), watching)
            .await
            .expect("the watch ends when the gateway is gone")
            .unwrap();
        gateway_thread.join().unwrap();
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn only_a_handed_oauth_credential_can_be_refreshed() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        let err = credentials
            .refresh_oauth("telegram-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a credential the proxy was handed"),
            "{err}"
        );
        let err = credentials
            .refresh_oauth("linear-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not an OAuth credential the proxy was handed"),
            "{err}"
        );
    }

    /// The gateway's leak detection learns each value the service reads
    /// and each token a refresh brings back.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn the_service_teaches_leak_detection_what_it_reads_and_refreshes() {
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
                access_token: "AT-1-expired-token".into(),
                refresh_token: "RT-1".into(),
                expires_at: 1,
                scope: "read".into(),
                provider: "linear".into(),
                ..Default::default()
            },
        )
        .unwrap();
        store
            .store(
                "linear-token",
                "",
                &VaultSecret::new("tok-rotated-0002".into()),
                None,
                None,
            )
            .unwrap();
        let leak = Arc::new(wirken_gateway::leak::LeakMatcher::new());
        let service = RefreshService::new(
            Some(Arc::new(std::sync::Mutex::new(store))),
            BTreeSet::from(["linear-oauth".to_string(), "linear-token".to_string()]),
            BTreeSet::from(["linear-oauth".to_string()]),
            Zeroizing::new("t".to_string()),
            Arc::new(AtomicU32::new(std::process::id())),
            None,
        )
        .with_refresher(Arc::new(LongTokens))
        .with_leak_matcher(leak.clone());

        service.current("linear-token").unwrap();
        assert_eq!(
            leak.find("tok-rotated-0002").as_deref(),
            Some("linear-token")
        );
        service.refresh("linear-oauth").await.unwrap();
        for token in ["AT-refreshed-0003", "RT-refreshed-0003"] {
            assert_eq!(
                leak.find(&format!("x {token} y")).as_deref(),
                Some("linear-oauth"),
                "{token}"
            );
        }
    }

    /// A provider whose refreshed tokens are long enough to match.
    struct LongTokens;

    #[async_trait::async_trait]
    impl Refresher for LongTokens {
        async fn refresh(&self, cred: &OAuthCredential) -> Result<OAuthCredential, ProxyError> {
            Ok(OAuthCredential {
                access_token: "AT-refreshed-0003".into(),
                refresh_token: "RT-refreshed-0003".into(),
                expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
                scope: cred.scope.clone(),
                provider: cred.provider.clone(),
                ..Default::default()
            })
        }
    }

    /// The proxy holds the rotated value after asking, the vault's
    /// value and no other, and the gateway's row names the credential
    /// without its value.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn the_proxy_gets_a_rotated_value_and_the_row_names_only_the_credential() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        gateway
            .store
            .lock()
            .unwrap()
            .rotate("linear-token", &VaultSecret::new("tok-2".into()), None)
            .unwrap();
        assert_eq!(credentials.get("linear-token").unwrap().expose(), "tok-1");

        credentials.refetch("linear-token").await.unwrap();
        assert_eq!(credentials.get("linear-token").unwrap().expose(), "tok-2");

        let rows = gateway.rows();
        assert_eq!(rows.len(), 1, "one row per value sent: {rows:?}");
        assert!(
            matches!(&rows[0], SessionEvent::McpCredentialRefetched { credential } if credential == "linear-token"),
            "{rows:?}"
        );
        let json = serde_json::to_string(&rows).unwrap();
        assert!(!json.contains("tok-"), "the row carries a value: {json}");
    }

    fn pin(server: &str) -> ServerPin {
        ServerPin {
            server: server.into(),
            entry: format!("sha256:{server}"),
        }
    }

    fn grant(pin: &ServerPin) -> wirken_vault::Destination {
        wirken_vault::Destination::McpServer(wirken_vault::McpServerGrant {
            name: pin.server.clone(),
            entry: pin.entry.clone(),
        })
    }

    /// A destination revoked in the vault reaches the proxy with the
    /// value: the server it was revoked for no longer gets it, and once
    /// none is left the proxy drops what it holds.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_revoked_server_stops_getting_the_value_and_the_last_one_withdraws_it() {
        let (linear, notion) = (pin("linear"), pin("notion"));
        let both = BTreeSet::from([linear.clone(), notion.clone()]);
        let gateway = gateway_pinned(
            "t0k3n",
            std::process::id(),
            HashMap::from([("linear-token".to_string(), both.clone())]),
        );
        let mut binding = wirken_vault::Binding::default();
        binding.grant(grant(&linear));
        binding.grant(grant(&notion));
        gateway
            .store
            .lock()
            .unwrap()
            .store_bound(
                "linear-token",
                "mcp",
                &VaultSecret::new("tok-1".into()),
                None,
                None,
                &binding,
                wirken_vault::default_kind("linear-token"),
            )
            .unwrap();
        let credentials = Arc::new(
            Arc::try_unwrap(proxy(&gateway, "t0k3n"))
                .ok()
                .unwrap()
                .with_pins(HashMap::from([("linear-token".to_string(), both)])),
        );
        credentials.refetch("linear-token").await.unwrap();
        assert!(credentials.get_for(&notion, "linear-token").is_some());

        gateway
            .store
            .lock()
            .unwrap()
            .update_binding_exclusive("linear-token", std::time::Duration::from_secs(5), |b| {
                let mut b = b.clone();
                b.revoke(&grant(&notion)).then_some(b)
            })
            .unwrap();
        credentials.refetch("linear-token").await.unwrap();
        assert!(credentials.get_for(&linear, "linear-token").is_some());
        assert!(
            credentials.get_for(&notion, "linear-token").is_none(),
            "the revoked server no longer gets it"
        );

        gateway
            .store
            .lock()
            .unwrap()
            .update_binding_exclusive("linear-token", std::time::Duration::from_secs(5), |b| {
                let mut b = b.clone();
                b.revoke(&grant(&linear)).then_some(b)
            })
            .unwrap();
        assert!(credentials.refetch("linear-token").await.is_err());
        assert!(
            credentials.get("linear-token").is_none(),
            "nothing is held once no server may have it"
        );
    }

    /// A removed bearer is dropped when the gateway refuses it, so the
    /// next request does not carry the old value.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_removed_credential_is_dropped_on_the_refusal() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        gateway
            .store
            .lock()
            .unwrap()
            .delete("linear-token")
            .unwrap();
        assert!(credentials.refetch("linear-token").await.is_err());
        assert!(credentials.get("linear-token").is_none());
        // A stdio server started again now has no variable for it.
        let env = HashMap::from([
            ("TOKEN".to_string(), "vault:linear-token".to_string()),
            ("LOG".to_string(), "info".to_string()),
        ]);
        let started_with = crate::mcp_registry::resolve_env(&env, &credentials, &pin("test"));
        assert_eq!(
            started_with,
            HashMap::from([("LOG".to_string(), "info".to_string())])
        );
    }

    /// A change to a handed credential goes down the proxy's watch; a
    /// credential it was not handed is not mentioned.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_vault_change_reaches_the_proxy_on_its_watch() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let watching = tokio::spawn({
            let credentials = credentials.clone();
            async move { credentials.gateway_gone(tx).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!gateway.service.notify_changed("telegram-token"));
        assert!(gateway.service.notify_changed("linear-token"));
        let name = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("the notice arrives")
            .unwrap();
        assert_eq!(
            name,
            crate::credentials::ProxyNotice::Changed("linear-token".into())
        );
        gateway.service.notify_agent_stopped("work");
        gateway.service.notify_agent_resumed("work");
        for expected in [
            crate::credentials::ProxyNotice::AgentStopped("work".into()),
            crate::credentials::ProxyNotice::AgentResumed("work".into()),
        ] {
            let notice = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("the notice arrives")
                .unwrap();
            assert_eq!(notice, expected);
        }
        assert!(rx.try_recv().is_err(), "nothing else was sent");
        watching.abort();
    }

    /// An OAuth credential's current value comes without its refresh
    /// token.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_current_oauth_value_has_no_refresh_token() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        credentials.refetch("linear-oauth").await.unwrap();
        let held = credentials.get("linear-oauth").unwrap();
        assert!(held.expose().contains("AT-1"), "{}", held.expose());
        assert!(!held.expose().contains("RT-1"), "{}", held.expose());
    }

    /// Asking for a value goes through the same checks as a refresh,
    /// and a refused request sends nothing and writes no row.
    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn a_current_value_is_refused_like_a_refresh() {
        let gateway = gateway("t0k3n", std::process::id());
        let credentials = proxy(&gateway, "t0k3n");
        let err = credentials
            .refetch("telegram-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a credential the proxy was handed"),
            "{err}"
        );

        let err = proxy(&gateway, "guess")
            .refetch("linear-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong refresh token"), "{err}");

        let other = self::gateway("t0k3n", std::process::id() + 1);
        let err = proxy(&other, "t0k3n")
            .refetch("linear-token")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not the MCP proxy"), "{err}");

        assert!(gateway.rows().is_empty());
        assert!(other.rows().is_empty());
    }

    /// Vault change made while the refresh is in flight.
    enum Meanwhile {
        Remove,
        Reauthorize,
    }

    /// Provider stand-in that applies a `Meanwhile` before answering.
    struct Interfering {
        store: Arc<std::sync::Mutex<CredentialStore>>,
        meanwhile: Meanwhile,
    }

    #[async_trait::async_trait]
    impl Refresher for Interfering {
        async fn refresh(&self, cred: &OAuthCredential) -> Result<OAuthCredential, ProxyError> {
            {
                let store = self.store.lock().unwrap();
                match self.meanwhile {
                    Meanwhile::Remove => store.delete("linear-oauth").unwrap(),
                    Meanwhile::Reauthorize => store_oauth(
                        &store,
                        "linear-oauth",
                        &OAuthCredential {
                            access_token: "AT-NEW".into(),
                            refresh_token: "RT-NEW".into(),
                            expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
                            scope: "read".into(),
                            provider: "linear".into(),
                            ..Default::default()
                        },
                    )
                    .unwrap(),
                }
            }
            Ok(OAuthCredential {
                access_token: "AT-OLD-LINE".into(),
                refresh_token: "RT-OLD-LINE".into(),
                expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
                scope: cred.scope.clone(),
                provider: cred.provider.clone(),
                ..Default::default()
            })
        }
    }

    /// Refresh service over an expired credential and that stand-in.
    fn interfered(
        meanwhile: Meanwhile,
    ) -> (
        tempfile::TempDir,
        Arc<std::sync::Mutex<CredentialStore>>,
        Arc<dyn SessionLog>,
        RefreshService,
    ) {
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
                ..Default::default()
            },
        )
        .unwrap();
        let store = Arc::new(std::sync::Mutex::new(store));
        let audit: Arc<dyn SessionLog> =
            Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap());
        let service = RefreshService::new(
            Some(store.clone()),
            BTreeSet::from(["linear-oauth".to_string()]),
            BTreeSet::from(["linear-oauth".to_string()]),
            Zeroizing::new("t".into()),
            Arc::new(AtomicU32::new(0)),
            Some(audit.clone()),
        )
        .with_refresher(Arc::new(Interfering {
            store: store.clone(),
            meanwhile,
        }));
        (dir, store, audit, service)
    }

    fn discarded(audit: &Arc<dyn SessionLog>) -> Vec<String> {
        let lane = audit.handle_for(SessionId::new(MCP_CREDENTIAL_SESSION));
        audit
            .get_since(&lane, 0)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                SessionEvent::McpCredentialRefreshDiscarded { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn an_entry_removed_during_a_refresh_stays_removed() {
        let (_dir, store, audit, service) = interfered(Meanwhile::Remove);
        let err = service.refresh("linear-oauth").await.unwrap_err();
        assert!(err.contains("removed during the refresh"), "{err}");
        assert!(
            load_oauth(&store.lock().unwrap(), "linear-oauth").is_err(),
            "the refreshed token did not bring the entry back"
        );
        assert_eq!(discarded(&audit), ["removed"]);
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn an_entry_reauthorized_during_a_refresh_keeps_the_new_authorization() {
        let (_dir, store, audit, service) = interfered(Meanwhile::Reauthorize);
        let answered = service.refresh("linear-oauth").await.unwrap();
        assert_eq!(
            answered.access_token, "AT-NEW",
            "the proxy gets the new sign-in"
        );
        let stored = load_oauth(&store.lock().unwrap(), "linear-oauth").unwrap();
        assert_eq!(stored.refresh_token, "RT-NEW");
        assert_eq!(stored.access_token, "AT-NEW");
        assert_eq!(discarded(&audit), ["reauthorized"]);
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[tokio::test]
    async fn an_untouched_entry_takes_the_refresh_and_keeps_its_channel() {
        let (_dir, store, audit, service) = interfered(Meanwhile::Reauthorize);
        // The same, without the interference: a plain provider.
        let service = service.with_refresher(Arc::new(FakeProvider));
        let answered = service.refresh("linear-oauth").await.unwrap();
        assert_eq!(answered.refresh_token, "RT-2");
        let store = store.lock().unwrap();
        assert_eq!(
            load_oauth(&store, "linear-oauth").unwrap().refresh_token,
            "RT-2"
        );
        let (_, meta) = store.peek("linear-oauth").unwrap();
        assert_eq!(meta.channel, "oauth");
        assert!(discarded(&audit).is_empty());
    }
}
