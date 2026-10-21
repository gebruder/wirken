use super::*;
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

/// An RSA signing key standing in for the provider's, and a second one
/// that signs under the same key id but is not published.
pub(crate) mod keys {
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::OnceLock;

    fn published() -> &'static KeyPair {
        static PAIR: OnceLock<KeyPair> = OnceLock::new();
        PAIR.get_or_init(|| KeyPair::generate(KeySize::Rsa2048).unwrap())
    }

    fn unpublished() -> &'static KeyPair {
        static PAIR: OnceLock<KeyPair> = OnceLock::new();
        PAIR.get_or_init(|| KeyPair::generate(KeySize::Rsa2048).unwrap())
    }

    /// The modulus and exponent of a DER `RSAPublicKey` (RFC 8017):
    /// `SEQUENCE { INTEGER n, INTEGER e }`.
    fn components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn element(der: &[u8], tag: u8) -> (&[u8], &[u8]) {
            assert_eq!(der[0], tag);
            let (len, start) = if der[1] & 0x80 == 0 {
                (der[1] as usize, 2)
            } else {
                let n = (der[1] & 0x7f) as usize;
                let len = der[2..2 + n]
                    .iter()
                    .fold(0usize, |acc, b| (acc << 8) | *b as usize);
                (len, 2 + n)
            };
            (&der[start..start + len], &der[start + len..])
        }
        let (body, _) = element(der, 0x30);
        let (n, rest) = element(body, 0x02);
        let (e, _) = element(rest, 0x02);
        (n.to_vec(), e.to_vec())
    }

    pub fn jwks() -> serde_json::Value {
        let (n, e) = components(published().public_key().as_ref());
        serde_json::json!({"keys": [{
            "kty": "RSA",
            "kid": "k1",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e),
        }]})
    }

    fn sign_with(pair: &KeyPair, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg": "RS256", "kid": "k1", "typ": "JWT"})
                .to_string()
                .as_bytes(),
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let input = format!("{header}.{payload}");
        let mut signature = vec![0u8; pair.public_modulus_len()];
        pair.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    pub fn sign(claims: &serde_json::Value) -> String {
        sign_with(published(), claims)
    }

    pub fn sign_unpublished(claims: &serde_json::Value) -> String {
        sign_with(unpublished(), claims)
    }
}

use stub::{Handler, Reply, Request};

const HOST_ID: &str = "urn:uuid:00000000-0000-4000-8000-000000000001";

fn discovery(base: &str) -> Reply {
    Reply::json(
        200,
        serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}{AUTHORIZE_PATH}"),
            "token_endpoint": format!("{base}{TOKEN_PATH}"),
            "jwks_uri": format!("{base}/jwks"),
            "revocation_endpoint": format!("{base}/revoke"),
        }),
    )
}

/// What the stub provider puts in the ID token and the token response
/// of a code exchange.
#[derive(Clone)]
struct Issue {
    nonce: String,
    sub: String,
    email: Option<String>,
    scope: Option<String>,
    iss: Option<String>,
    aud: Option<String>,
    exp_offset: i64,
    unpublished_key: bool,
}

impl Default for Issue {
    fn default() -> Self {
        Self {
            nonce: String::new(),
            sub: "user-1".into(),
            email: Some("user@example.com".into()),
            scope: Some(SCOPES.join(" ")),
            iss: None,
            aud: None,
            exp_offset: 3600,
            unpublished_key: false,
        }
    }
}

fn id_token(base: &str, client_id: &str, issue: &Issue) -> String {
    let claims = serde_json::json!({
        "iss": issue.iss.clone().unwrap_or_else(|| base.to_string()),
        "sub": issue.sub,
        "aud": issue.aud.clone().unwrap_or_else(|| client_id.to_string()),
        "exp": (unix_now() as i64 + issue.exp_offset),
        "iat": unix_now(),
        "nonce": issue.nonce,
        "email": issue.email,
    });
    if issue.unpublished_key {
        keys::sign_unpublished(&claims)
    } else {
        keys::sign(&claims)
    }
}

/// The stub provider for sign-in: discovery, keys, and a token endpoint
/// that answers a code exchange from `issue`.
async fn provider(issue: Arc<Mutex<Issue>>) -> stub::Stub {
    stub::serve(move |base| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            DISCOVERY_PATH => discovery(&base),
            "/jwks" => Reply::json(200, keys::jwks()),
            TOKEN_PATH => {
                let form = req.form();
                let issue = issue.lock().unwrap().clone();
                let client_id = form.get("client_id").cloned().unwrap_or_default();
                let mut body = serde_json::json!({
                    "access_token": "at-1",
                    "refresh_token": "rt-1",
                    "id_token": id_token(&base, &client_id, &issue),
                    "token_type": "Bearer",
                    "expires_in": 3600,
                });
                if let Some(scope) = &issue.scope {
                    body["scope"] = scope.clone().into();
                }
                Reply::json(200, body)
            }
            _ => Reply::empty(404),
        })
    })
    .await
}

/// Drive one sign-in against `idp`: start it, have the "browser" return
/// to the callback with what `callback` builds from the authorize
/// parameters, and finish.
async fn sign_in_with(
    idp: &stub::Stub,
    issue: &Arc<Mutex<Issue>>,
    saved: Option<OAuthCredential>,
    callback: impl FnOnce(&HashMap<String, String>) -> Vec<(String, String)>,
) -> (HashMap<String, String>, Result<SignedIn, PlanAuthError>) {
    let pending = PendingSignIn::start_at(
        Endpoints::stub(&idp.base),
        SignInRequest {
            host_id: HOST_ID.into(),
            saved,
            port: 0,
        },
    )
    .await
    .unwrap();
    let url = url::Url::parse(pending.authorize_url()).unwrap();
    assert_eq!(url.path(), AUTHORIZE_PATH);
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    issue.lock().unwrap().nonce = params["nonce"].clone();
    let redirect = pending.redirect_uri().to_string();
    let finish = tokio::spawn(pending.finish(Duration::from_secs(10)));

    let mut back = url::Url::parse(&redirect).unwrap();
    back.query_pairs_mut().extend_pairs(callback(&params));
    // The browser asks for something else first; that gets a 404 and
    // the attempt keeps listening.
    let mut other = url::Url::parse(&redirect).unwrap();
    other.set_path("/favicon.ico");
    let _ = reqwest::get(other).await;
    let _ = reqwest::get(back).await;
    (params, finish.await.unwrap())
}

fn returning(params: &HashMap<String, String>, client_id: Option<&str>) -> Vec<(String, String)> {
    let mut q = vec![
        ("code".to_string(), "code-1".to_string()),
        ("state".to_string(), params["state"].clone()),
    ];
    if let Some(id) = client_id {
        q.push(("client_id".into(), id.into()));
    }
    q
}

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
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_first_sign_in_registers_and_keeps_the_issued_client_id() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;
    let (params, result) =
        sign_in_with(&idp, &issue, None, |p| returning(p, Some("oaiapp_issued"))).await;

    assert_eq!(params["client_id"], "dynamic_agent_client");
    assert_eq!(params["agent_name_hint"], APP_NAME);
    assert_eq!(params["ext_agent_host_id"], HOST_ID);
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["resource"], RESOURCE);
    assert_eq!(params["scope"], SCOPES.join(" "));
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(!params.contains_key("id_token_hint"));
    assert!(!params.contains_key("prompt"));
    let redirect = &params["redirect_uri"];
    assert!(
        redirect.starts_with("http://127.0.0.1:") && redirect.ends_with(CALLBACK_PATH),
        "{redirect}"
    );

    let signed = result.expect("sign-in completes");
    assert!(signed.registered);
    assert!(signed.plan_granted());
    let cred = &signed.credential;
    assert_eq!(cred.client_id.as_deref(), Some("oaiapp_issued"));
    assert_eq!(cred.subject.as_deref(), Some("user-1"));
    assert_eq!(cred.email.as_deref(), Some("user@example.com"));
    assert_eq!(cred.issuer.as_deref(), Some(idp.base.as_str()));
    assert_eq!(cred.refresh_token, "rt-1");
    assert!(is_plan_credential(cred));

    // The exchange used the issued id, the same redirect, the PKCE
    // verifier behind the challenge, and the resource.
    let exchanges = idp.requests_to(TOKEN_PATH);
    assert_eq!(exchanges.len(), 1);
    let form = exchanges[0].form();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_id"], "oaiapp_issued");
    assert_eq!(form["code"], "code-1");
    assert_eq!(&form["redirect_uri"], redirect);
    assert_eq!(form["resource"], RESOURCE);
    assert_eq!(
        pkce_challenge(&form["code_verifier"]),
        params["code_challenge"]
    );
    assert!(!form.contains_key("client_secret"));
}

#[tokio::test]
async fn a_reauthorization_sends_the_issued_id_and_hints_and_no_name_hint() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;
    // The callback leaves the client id out: the pending one is kept.
    let (params, result) =
        sign_in_with(&idp, &issue, Some(saved_account()), |p| returning(p, None)).await;

    assert_eq!(params["client_id"], "oaiapp_saved");
    assert_eq!(params["id_token_hint"], "saved.id.token");
    assert_eq!(params["login_hint"], "user@example.com");
    assert_eq!(params["ext_agent_host_id"], HOST_ID);
    assert!(!params.contains_key("agent_name_hint"));

    let signed = result.expect("reauthorization completes");
    assert!(!signed.registered);
    assert_eq!(signed.credential.client_id.as_deref(), Some("oaiapp_saved"));
    assert_eq!(
        idp.requests_to(TOKEN_PATH)[0].form()["client_id"],
        "oaiapp_saved"
    );
}

#[tokio::test]
async fn a_reauthorization_after_a_declined_grant_asks_for_consent_again() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;
    let mut declined = without_tokens(&saved_account());
    declined.scope = "openid profile email".into();
    let (params, _) = sign_in_with(&idp, &issue, Some(declined), |p| returning(p, None)).await;
    assert_eq!(params["prompt"], "consent");
}

#[tokio::test]
async fn a_callback_naming_a_different_client_id_is_refused_before_any_exchange() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;
    let (_, result) = sign_in_with(&idp, &issue, Some(saved_account()), |p| {
        returning(p, Some("oaiapp_someone_else"))
    })
    .await;
    assert!(
        matches!(result, Err(PlanAuthError::ClientMismatch { .. })),
        "{:?}",
        result.err()
    );
    assert!(idp.requests_to(TOKEN_PATH).is_empty());
}

#[tokio::test]
async fn a_registration_callback_without_an_issued_id_is_incomplete() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;
    for client in [None, Some("dynamic_agent_client")] {
        let (_, result) = sign_in_with(&idp, &issue, None, |p| returning(p, client)).await;
        assert!(
            matches!(result, Err(PlanAuthError::RegistrationIncomplete)),
            "{:?}",
            result.err()
        );
    }
    assert!(idp.requests_to(TOKEN_PATH).is_empty());
}

#[tokio::test]
async fn a_state_mismatch_or_a_declined_consent_stops_without_an_exchange() {
    let issue = Arc::new(Mutex::new(Issue::default()));
    let idp = provider(issue.clone()).await;

    let (_, result) = sign_in_with(&idp, &issue, None, |_| {
        vec![
            ("code".into(), "code-1".into()),
            ("state".into(), "forged".into()),
            ("client_id".into(), "oaiapp_issued".into()),
        ]
    })
    .await;
    assert!(matches!(result, Err(PlanAuthError::StateMismatch)));

    let (_, result) = sign_in_with(&idp, &issue, None, |p| {
        vec![
            ("error".into(), "access_denied".into()),
            ("state".into(), p["state"].clone()),
        ]
    })
    .await;
    assert!(matches!(result, Err(PlanAuthError::Declined)));

    // An error with the wrong state is a state mismatch first.
    let (_, result) = sign_in_with(&idp, &issue, None, |_| {
        vec![
            ("error".into(), "access_denied".into()),
            ("state".into(), "forged".into()),
        ]
    })
    .await;
    assert!(matches!(result, Err(PlanAuthError::StateMismatch)));

    assert!(idp.requests_to(TOKEN_PATH).is_empty());
}

#[tokio::test]
async fn an_id_token_that_fails_any_check_is_refused() {
    type Spoil = fn(&mut Issue);
    let cases: [(&str, Spoil); 5] = [
        ("bad signature", |i| i.unpublished_key = true),
        ("wrong issuer", |i| {
            i.iss = Some("https://elsewhere.example".into())
        }),
        ("wrong audience", |i| i.aud = Some("oaiapp_other".into())),
        ("expired", |i| i.exp_offset = -600),
        ("wrong nonce", |_| {}),
    ];
    for (what, spoil) in cases {
        let issue = Arc::new(Mutex::new(Issue::default()));
        let idp = provider(issue.clone()).await;
        let wrong_nonce = what == "wrong nonce";
        let (_, result) = sign_in_with(&idp, &issue, None, |p| {
            let mut i = issue.lock().unwrap();
            spoil(&mut i);
            if wrong_nonce {
                i.nonce = "not-this-attempt".into();
            }
            returning(p, Some("oaiapp_issued"))
        })
        .await;
        assert!(
            matches!(result, Err(PlanAuthError::IdToken(_))),
            "{what}: {:?}",
            result.err()
        );
    }
}

#[tokio::test]
async fn a_reauthorization_that_returns_another_account_replaces_nothing() {
    let issue = Arc::new(Mutex::new(Issue {
        sub: "user-2".into(),
        ..Default::default()
    }));
    let idp = provider(issue.clone()).await;
    let (_, result) =
        sign_in_with(&idp, &issue, Some(saved_account()), |p| returning(p, None)).await;
    assert!(
        matches!(result, Err(PlanAuthError::AccountMismatch)),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn plan_usage_is_off_when_the_scope_is_missing_or_omitted() {
    for scope in [Some("openid profile email offline_access"), None] {
        let issue = Arc::new(Mutex::new(Issue {
            scope: scope.map(String::from),
            ..Default::default()
        }));
        let idp = provider(issue.clone()).await;
        let (_, result) =
            sign_in_with(&idp, &issue, None, |p| returning(p, Some("oaiapp_issued"))).await;
        let signed = result.expect("the sign-in itself is valid");
        assert!(!signed.plan_granted(), "scope {scope:?}");
        assert_eq!(signed.credential.scope, scope.unwrap_or(""));
        assert!(unusable_reason(&signed.credential, "e").is_some());
    }
}

#[test]
fn the_id_token_checks_hold_on_their_own() {
    let jwks: Vec<Jwk> = serde_json::from_value(keys::jwks()["keys"].clone()).unwrap();
    let now = unix_now();
    let claims = |nonce: &str| {
        serde_json::json!({
            "iss": "https://issuer.example", "sub": "s", "aud": ["oaiapp_x", "other"],
            "azp": "oaiapp_x", "exp": now + 60, "nonce": nonce,
        })
    };
    let good = keys::sign(&claims("n1"));
    assert!(
        validate_id_token(
            &good,
            &jwks,
            "https://issuer.example",
            "oaiapp_x",
            "n1",
            now
        )
        .is_ok()
    );
    assert!(
        validate_id_token(
            &good,
            &jwks,
            "https://issuer.example",
            "oaiapp_x",
            "n2",
            now
        )
        .is_err()
    );
    let mut tampered = good.clone();
    tampered.push('A');
    assert!(
        validate_id_token(
            &tampered,
            &jwks,
            "https://issuer.example",
            "oaiapp_x",
            "n1",
            now
        )
        .is_err()
    );
    // An unsigned token is never accepted.
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims("n1").to_string())
    );
    assert!(
        validate_id_token(
            &none,
            &jwks,
            "https://issuer.example",
            "oaiapp_x",
            "n1",
            now
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Host id
// ---------------------------------------------------------------------------

#[test]
fn the_host_id_is_created_once_owner_only_and_reused() {
    let dir = tempfile::tempdir().unwrap();
    let first = host_id(dir.path()).unwrap();
    assert!(first.starts_with("urn:uuid:"), "{first}");
    assert_eq!(host_id(dir.path()).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(HOST_ID_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    std::fs::write(dir.path().join(HOST_ID_FILE), "user@example.com").unwrap();
    assert!(
        host_id(dir.path()).is_err(),
        "a malformed id is not replaced"
    );
}

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
    stub::serve(move |base| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            DISCOVERY_PATH => discovery(&base),
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

/// The plan endpoints are fixed outside this crate's tests: whatever a
/// configuration says the base URL is, the client and the sign-in use
/// the provider's own.
#[test]
fn the_plan_endpoints_cannot_be_redirected_by_configuration() {
    let pinned = Endpoints::pinned();
    assert_eq!(pinned.api_base(), API_BASE);
    assert_eq!(pinned.issuer(), AUTH_BASE);
    assert_eq!(pinned.token_url(), format!("{AUTH_BASE}{TOKEN_PATH}"));
    assert!(pinned.on_auth_origin(&format!("{AUTH_BASE}/.well-known/jwks.json")));
    assert!(!pinned.on_auth_origin("https://auth.openai.com.evil.example/jwks"));

    for base_url in ["http://127.0.0.1:9/v1", "https://evil.example/v1"] {
        let config = crate::llm::LlmConfig {
            base_url: base_url.into(),
            ..crate::llm::LlmConfig::plan("m")
        };
        let client = crate::llm::LlmClient::new(config).unwrap();
        assert_eq!(client.plan_endpoints(), &pinned, "{base_url}");
    }
}

// ---------------------------------------------------------------------------
// Revocation and sign-out
// ---------------------------------------------------------------------------

async fn revocation_endpoint(statuses: Vec<u16>) -> (stub::Stub, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let stub = stub::serve(move |base| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            DISCOVERY_PATH => discovery(&base),
            "/revoke" => {
                let form = req.form();
                assert_eq!(form["token"], "rt-1");
                assert_eq!(form["token_type_hint"], "refresh_token");
                assert_eq!(form["client_id"], "oaiapp_saved");
                let n = seen.fetch_add(1, Ordering::SeqCst);
                Reply::empty(*statuses.get(n).unwrap_or(statuses.last().unwrap()))
            }
            _ => Reply::empty(404),
        })
    })
    .await;
    (stub, count)
}

#[tokio::test]
async fn revocation_retries_a_5xx_and_confirms_on_200() {
    let (idp, count) = revocation_endpoint(vec![503, 502, 200]).await;
    let zero = [Duration::ZERO; 3];
    let got = revoke_at(&Endpoints::stub(&idp.base), &stored(0), &zero).await;
    assert_eq!(got, Revocation::Confirmed);
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn revocation_gives_up_after_the_backoff_and_says_it_was_not_confirmed() {
    let (idp, count) = revocation_endpoint(vec![503]).await;
    let zero = [Duration::ZERO; 2];
    let got = revoke_at(&Endpoints::stub(&idp.base), &stored(0), &zero).await;
    assert!(
        matches!(got, Revocation::Unconfirmed(ref r) if r.contains("503")),
        "{got:?}"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "the first try and one per wait"
    );

    // A 4xx is an answer, not an outage: no retry.
    let (idp, count) = revocation_endpoint(vec![400]).await;
    let got = revoke_at(&Endpoints::stub(&idp.base), &stored(0), &zero).await;
    assert!(matches!(got, Revocation::Unconfirmed(_)));
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // Nothing listening: a network error each time, then unconfirmed.
    let gone = Endpoints::stub("http://127.0.0.1:1");
    assert!(matches!(
        revoke_at(&gone, &stored(0), &zero).await,
        Revocation::Unconfirmed(_)
    ));
    assert_eq!(
        revoke_at(&gone, &without_tokens(&stored(0)), &zero).await,
        Revocation::NothingToRevoke
    );
}

#[tokio::test]
async fn sign_out_clears_the_tokens_keeps_the_registration_and_reports_the_revocation() {
    let (idp, _) = revocation_endpoint(vec![500]).await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 3600)).unwrap();
    let got = sign_out_at(
        Endpoints::stub(&idp.base),
        Arc::new(Mutex::new(vault_at(&db))),
        dir.path(),
        "plan",
        &[],
    )
    .await
    .unwrap();
    assert!(matches!(got, Revocation::Unconfirmed(_)), "{got:?}");
    let after = read_back(&db, "plan");
    assert!(after.access_token.is_empty() && after.refresh_token.is_empty());
    assert_eq!(after.id_token.as_deref(), Some("saved.id.token"));
    assert_eq!(after.client_id.as_deref(), Some("oaiapp_saved"));
    assert_eq!(after.subject.as_deref(), Some("user-1"));
}

/// The tokens are cleared before the revocation goes out, and the
/// revocation runs with no vault transaction open: when the request
/// reaches the provider, the entry is already cleared and another
/// connection can write to the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_out_clears_first_and_revokes_outside_the_vault_lock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    store_plan(&vault_at(&db), "plan", &stored(unix_now() + 3600)).unwrap();
    vault_at(&db)
        .store(
            "other",
            "test",
            &VaultSecret::new("other-value".into()),
            None,
            None,
        )
        .unwrap();
    let observed: Arc<Mutex<Option<(String, bool)>>> = Arc::new(Mutex::new(None));
    let seen = observed.clone();
    let db_in = db.clone();
    let idp = stub::serve(move |base| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            DISCOVERY_PATH => discovery(&base),
            "/revoke" => {
                let other = vault_at(&db_in);
                let cleared = read_back(&db_in, "plan").refresh_token;
                let wrote = other.retrieve("other").is_ok();
                *seen.lock().unwrap() = Some((cleared, wrote));
                Reply::empty(200)
            }
            _ => Reply::empty(404),
        })
    })
    .await;
    let got = sign_out_at(
        Endpoints::stub(&idp.base),
        Arc::new(Mutex::new(vault_at(&db))),
        dir.path(),
        "plan",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(got, Revocation::Confirmed);
    let (refresh_at_revocation, other_writer_ok) = observed.lock().unwrap().clone().unwrap();
    assert!(refresh_at_revocation.is_empty(), "cleared before revoking");
    assert!(
        other_writer_ok,
        "the vault is not locked during the revocation"
    );
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

/// 2.3.0 builds `LlmConfig::from_provider(provider, base_url, model)`
/// from a `provider.json` (`wirken run`, `wirken ask`) and from an agent
/// row (`llm_config_for_agent`), and its `LlmClient::new`, unchanged for
/// key mode, refuses an endpoint that is neither HTTPS nor loopback.
/// The marker a plan file and row carry fails that check, so a
/// downgraded binary stops before any request instead of sending to a
/// default endpoint.
#[test]
fn a_build_that_predates_plan_mode_refuses_the_plan_base_url() {
    let config = crate::llm::LlmConfig::from_provider("openai", PLAN_BASE_URL, "m");
    let err = crate::llm::LlmClient::new(config).err().expect("refused");
    assert!(err.to_string().contains("must use HTTPS"), "{err}");
    // This build never reads it as an endpoint.
    let plan = crate::llm::LlmClient::new(crate::llm::LlmConfig::plan("m")).unwrap();
    assert_eq!(plan.plan_endpoints(), &Endpoints::pinned());
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
