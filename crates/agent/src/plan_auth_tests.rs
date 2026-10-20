use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A loopback HTTP server standing in for the provider: one handler,
/// every request recorded.
pub(crate) mod stub {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug, Clone)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Request {
        pub fn form(&self) -> HashMap<String, String> {
            url::form_urlencoded::parse(self.body.as_bytes())
                .into_owned()
                .collect()
        }

        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        pub fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body).expect("json body")
        }
    }

    pub struct Reply {
        pub status: u16,
        pub content_type: &'static str,
        pub headers: Vec<(String, String)>,
        pub body: String,
        pub delay: Duration,
    }

    impl Reply {
        pub fn json(status: u16, body: serde_json::Value) -> Self {
            Self {
                status,
                content_type: "application/json",
                headers: Vec::new(),
                body: body.to_string(),
                delay: Duration::ZERO,
            }
        }

        pub fn empty(status: u16) -> Self {
            Self {
                status,
                content_type: "text/plain",
                headers: Vec::new(),
                body: String::new(),
                delay: Duration::ZERO,
            }
        }

        pub fn sse(body: &str) -> Self {
            Self {
                status: 200,
                content_type: "text/event-stream",
                headers: Vec::new(),
                body: body.to_string(),
                delay: Duration::ZERO,
            }
        }

        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.into(), value.into()));
            self
        }

        pub fn after(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    pub type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

    pub struct Stub {
        pub base: String,
        pub seen: Arc<Mutex<Vec<Request>>>,
    }

    impl Stub {
        pub fn requests_to(&self, path: &str) -> Vec<Request> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.path == path)
                .cloned()
                .collect()
        }
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Request> {
        let mut raw: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        let header_end = loop {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
        let mut lines = head.lines();
        let first = lines.next()?.to_string();
        let mut parts = first.split_whitespace();
        let method = parts.next()?.to_string();
        let target = parts.next()?.to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        let length = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);
        while raw.len() < header_end + length {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        let body = String::from_utf8_lossy(&raw[header_end..]).to_string();
        let path = target.split('?').next().unwrap_or("").to_string();
        Some(Request {
            method,
            path,
            headers,
            body,
        })
    }

    /// Start a stub; `make` gets the stub's base URL and returns the
    /// handler.
    pub async fn serve(make: impl FnOnce(String) -> Handler) -> Stub {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handler = make(base.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let handler = handler.clone();
                let record = record.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut socket).await else {
                        return;
                    };
                    record.lock().unwrap().push(request.clone());
                    let reply = handler(&request);
                    if !reply.delay.is_zero() {
                        tokio::time::sleep(reply.delay).await;
                    }
                    let mut head = format!(
                        "HTTP/1.1 {} STUB\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reply.status,
                        reply.content_type,
                        reply.body.len()
                    );
                    for (k, v) in &reply.headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(reply.body.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Stub { base, seen }
    }
}

use stub::{Handler, Reply, Request};

fn saved_account() -> OAuthCredential {
    OAuthCredential {
        access_token: "at-old".into(),
        refresh_token: "rt-old".into(),
        expires_at: unix_now() + 3600,
        scope: SCOPES.join(" "),
        provider: PROVIDER.into(),
        client_id: Some("oaiapp_saved".into()),
        issuer: Some(AUTH_BASE.into()),
        subject: Some("user-1".into()),
        email: Some("user@example.com".into()),
        id_token: Some("saved.id.token".into()),
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Token source
// ---------------------------------------------------------------------------

const DEVICE_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn vault_at(path: &Path) -> CredentialStore {
    CredentialStore::open_with_key(path, VaultSecret::new(DEVICE_KEY.into())).unwrap()
}

fn stored(expires_at: u64) -> OAuthCredential {
    OAuthCredential {
        access_token: "at-1".into(),
        refresh_token: "rt-1".into(),
        expires_at,
        ..saved_account()
    }
}

fn read_back(path: &Path, entry: &str) -> OAuthCredential {
    load_plan(&vault_at(path), entry).unwrap()
}

/// A token endpoint that answers a refresh with `reply`, counting the
/// refreshes it sees.
async fn token_endpoint(
    count: Arc<AtomicUsize>,
    reply: impl Fn(&HashMap<String, String>) -> Reply + Send + Sync + 'static,
) -> stub::Stub {
    stub::serve(move |_| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            TOKEN_PATH => {
                let form = req.form();
                assert_eq!(form["grant_type"], "refresh_token");
                assert_eq!(form["client_id"], "oaiapp_saved");
                assert_eq!(form["resource"], RESOURCE);
                assert!(!form.contains_key("scope"), "a refresh keeps the grant");
                count.fetch_add(1, Ordering::SeqCst);
                reply(&form)
            }
            _ => Reply::empty(404),
        })
    })
    .await
}

fn rotated() -> Reply {
    Reply::json(
        200,
        serde_json::json!({
            "access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600,
            "scope": SCOPES.join(" "), "token_type": "Bearer",
        }),
    )
}

#[tokio::test]
async fn a_token_with_time_left_is_used_without_a_refresh() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |_| rotated()).await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 3600)).unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&idp.base),
        vault_at(&db),
        dir.path(),
        "plan",
        Arc::new(LeakMatcher::new()),
    )
    .unwrap();
    assert_eq!(source.bearer().await.unwrap(), "at-1");
    assert_eq!(source.entry(), "plan");
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

/// Two sources over one vault file, each on its own connection, stand
/// for the gateway and a `wirken ask` beside it. Both find the token
/// due at once. One refresh reaches the provider; the other source
/// finds the refresh token changed under the lock and uses the winner's
/// tokens. Spending `rt-1` twice would get `refresh_token_reused`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_due_at_once_refresh_once_and_share_the_winners_tokens() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |form| {
        if form["refresh_token"] == "rt-1" {
            rotated().after(Duration::from_millis(300))
        } else {
            Reply::json(400, serde_json::json!({"error": "refresh_token_reused"}))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 30)).unwrap();
    let open = || {
        PlanTokenSource::open_at(
            Endpoints::stub(&idp.base),
            vault_at(&db),
            dir.path(),
            "plan",
            Arc::new(LeakMatcher::new()),
        )
        .unwrap()
    };
    let (gateway, ask) = (open(), open());
    let (a, b) = tokio::join!(gateway.bearer(), ask.bearer());
    assert_eq!(a.unwrap(), "at-2");
    assert_eq!(b.unwrap(), "at-2");
    assert_eq!(count.load(Ordering::SeqCst), 1, "one refresh for both");
    let after = read_back(&db, "plan");
    assert_eq!(after.refresh_token, "rt-2");
    assert_eq!(after.client_id.as_deref(), Some("oaiapp_saved"));
}

#[tokio::test]
async fn a_terminal_refresh_code_clears_the_tokens_and_keeps_the_registration() {
    for code in TERMINAL_REFRESH_CODES {
        let count = Arc::new(AtomicUsize::new(0));
        let idp = token_endpoint(count.clone(), move |_| {
            // Both error shapes the provider may use.
            if code == "refresh_token_reused" {
                Reply::json(
                    401,
                    serde_json::json!({"error": {"code": code, "message": "x"}}),
                )
            } else {
                Reply::json(400, serde_json::json!({"error": code}))
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        store_plan(&vault_at(&db), "plan", &stored(unix_now() + 30)).unwrap();
        let source = PlanTokenSource::open_at(
            Endpoints::stub(&idp.base),
            vault_at(&db),
            dir.path(),
            "plan",
            Arc::new(LeakMatcher::new()),
        )
        .unwrap();
        let err = source.bearer().await.unwrap_err().to_string();
        assert!(
            err.contains("sign in again") && err.contains(code),
            "{code}: {err}"
        );

        let after = read_back(&db, "plan");
        assert!(
            after.access_token.is_empty() && after.refresh_token.is_empty(),
            "{code}"
        );
        assert_eq!(after.client_id.as_deref(), Some("oaiapp_saved"));
        assert_eq!(after.subject.as_deref(), Some("user-1"));
        assert_eq!(after.id_token.as_deref(), Some("saved.id.token"));

        // The next call says to sign in again without asking the
        // provider.
        let err = source.bearer().await.unwrap_err().to_string();
        assert!(err.contains("credentials authorize plan"), "{err}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn a_temporary_failure_keeps_the_credential_and_never_hands_out_an_expired_token() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |_| Reply::empty(503)).await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");

    // Due for refresh but still valid: the current token is used.
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 120)).unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&idp.base),
        vault_at(&db),
        dir.path(),
        "plan",
        Arc::new(LeakMatcher::new()),
    )
    .unwrap();
    assert_eq!(source.bearer().await.unwrap(), "at-1");

    // Expired: the call fails, and the credential is untouched.
    store_plan(
        &vault_at(&db),
        "plan",
        &stored(unix_now().saturating_sub(5)),
    )
    .unwrap();
    let err = source.bearer().await.unwrap_err().to_string();
    assert!(err.contains("expired") && err.contains("kept"), "{err}");
    let after = read_back(&db, "plan");
    assert_eq!(after.refresh_token, "rt-1");
    assert_eq!(after.access_token, "at-1");
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_client_is_a_configuration_error_and_keeps_the_tokens() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |_| {
        Reply::json(401, serde_json::json!({"error": "invalid_client"}))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 30)).unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&idp.base),
        vault_at(&db),
        dir.path(),
        "plan",
        Arc::new(LeakMatcher::new()),
    )
    .unwrap();
    let err = source.bearer().await.unwrap_err().to_string();
    assert!(err.contains("invalid_client"), "{err}");
    assert_eq!(read_back(&db, "plan").refresh_token, "rt-1");
}

#[test]
fn a_source_refuses_an_entry_it_cannot_use() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let open = || {
        PlanTokenSource::open(
            vault_at(&db),
            dir.path(),
            "plan",
            Arc::new(LeakMatcher::new()),
        )
        .err()
        .unwrap()
    };
    assert!(open().contains("credentials authorize plan"));
    let mut no_plan = stored(unix_now() + 3600);
    no_plan.scope = "openid profile email offline_access".into();
    store_plan(&vault_at(&db), "plan", &no_plan).unwrap();
    assert!(open().contains(PLAN_SCOPE));
    store_plan(&vault_at(&db), "plan", &without_tokens(&stored(0))).unwrap();
    assert!(open().contains("new sign-in"));
}

/// A refresh holds the entry's lock file across its request to the
/// provider, but no vault transaction: while the provider stalls, a
/// write from another connection (retrieve bumps `last_used_at`) goes
/// through at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_writer_is_not_held_up_by_a_refresh_waiting_on_the_provider() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |_| rotated().after(Duration::from_secs(3))).await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 30)).unwrap();
    vault_at(&db)
        .store(
            "other",
            "test",
            &VaultSecret::new("other-value".into()),
            None,
            None,
        )
        .unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&idp.base),
        vault_at(&db),
        dir.path(),
        "plan",
        Arc::new(LeakMatcher::new()),
    )
    .unwrap();
    let refresh = tokio::spawn(async move { source.bearer().await });
    while count.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let started = std::time::Instant::now();
    let other = vault_at(&db);
    let (secret, _) = other
        .retrieve("other")
        .expect("another writer is not blocked");
    assert_eq!(secret.expose(), "other-value");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the write waited {:?}",
        started.elapsed()
    );
    assert!(other.peek("other").unwrap().1.last_used_at.is_some());
    assert!(!refresh.is_finished(), "the refresh was still waiting");

    assert_eq!(refresh.await.unwrap().unwrap(), "at-2");
    assert_eq!(read_back(&db, "plan").refresh_token, "rt-2");
}

/// The refresh request sends no scope, so a refresh answer that omits
/// `scope` keeps the grant already held. One that names scopes
/// replaces it.
#[tokio::test]
async fn a_refresh_that_omits_the_scope_keeps_the_granted_scopes() {
    let count = Arc::new(AtomicUsize::new(0));
    let idp = token_endpoint(count.clone(), |form| {
        let mut body = serde_json::json!({
            "access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600,
        });
        if form["refresh_token"] == "rt-2" {
            body["access_token"] = "at-3".into();
            body["refresh_token"] = "rt-3".into();
            body["scope"] = "openid offline_access".into();
        }
        Reply::json(200, body)
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 30)).unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&idp.base),
        vault_at(&db),
        dir.path(),
        "plan",
        Arc::new(LeakMatcher::new()),
    )
    .unwrap();
    assert_eq!(source.bearer().await.unwrap(), "at-2");
    let after = read_back(&db, "plan");
    assert_eq!(after.scope, SCOPES.join(" "));
    assert!(plan_granted(&after));

    // A refresh answer that names scopes without plan usage replaces
    // the grant, and plan usage is off from then on.
    let mut due = after;
    due.expires_at = unix_now() + 30;
    store_plan(&vault_at(&db), "plan", &due).unwrap();
    assert_eq!(source.bearer().await.unwrap(), "at-3");
    assert_eq!(read_back(&db, "plan").scope, "openid offline_access");
    assert!(source.bearer().await.is_err());
}

#[tokio::test]
async fn every_entry_has_its_own_owner_only_lock_file_in_the_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let a = entry_lock_path(dir.path(), "openai-plan");
    let b = entry_lock_path(dir.path(), "work plan/../x");
    assert_ne!(a, b);
    assert_eq!(a.parent(), Some(dir.path()));
    assert_eq!(b.parent(), Some(dir.path()));
    assert_eq!(entry_lock_path(dir.path(), "openai-plan"), a);
    let held = lock_entry(a.clone()).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Another holder waits; a different entry does not.
    let other = std::fs::File::open(&a).unwrap();
    assert!(other.try_lock().is_err());
    let _b = lock_entry(b).await.unwrap();
    drop(held);
    assert!(other.try_lock().is_ok());
}

#[test]
fn granted_scopes_are_only_what_the_response_said() {
    assert_eq!(granted_scopes(None), "");
    assert_eq!(granted_scopes(Some("a b a")), "a b");
    assert_eq!(
        error_code(r#"{"error":"invalid_grant"}"#).as_deref(),
        Some("invalid_grant")
    );
    assert_eq!(
        error_code(r#"{"error":{"code":"refresh_token_reused"}}"#).as_deref(),
        Some("refresh_token_reused")
    );
    assert_eq!(error_code("not json"), None);
}

/// The plan endpoints are fixed outside this crate's tests: whatever a
/// configuration says the base URL is, the client uses the provider's
/// own.
#[test]
fn the_plan_endpoints_cannot_be_redirected_by_configuration() {
    let pinned = Endpoints::pinned();
    assert_eq!(pinned.api_base(), API_BASE);
    assert_eq!(pinned.token_url(), format!("{AUTH_BASE}{TOKEN_PATH}"));

    for base_url in ["http://127.0.0.1:9/v1", "https://evil.example/v1"] {
        let config = crate::llm::LlmConfig {
            base_url: base_url.into(),
            ..crate::llm::LlmConfig::plan("m")
        };
        let client = crate::llm::LlmClient::new(config).unwrap();
        assert_eq!(client.plan_endpoints(), &pinned, "{base_url}");
    }
}
