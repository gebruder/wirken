//! A JWT of the organization's identity provider at the proxy
//! listener: where the issuer's keys come from, and what a presented
//! JWT is given.
//!
//! Wirken verifies a JWT another party issued and maps it to a grant
//! set the operator wrote. It issues nothing, holds no account and
//! runs no sign-in: a caller that has no JWT of the issuer has no way
//! here to get one.
//!
//! The issuer's keys are a pinned JWK set, read once from a file, or
//! are fetched from the issuer: its discovery document, then the JWK
//! set that document names. Both fetches go to the issuer's own
//! origin, over HTTPS unless the issuer is on loopback, and follow no
//! redirect. Keys that cannot be had verify nothing: every JWT is
//! refused until they can.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use wirken_audit::{ProxyIdentity, ProxyRefusal};
use wirken_gateway::proxy::{OidcConfig, ProxyToken, ProxyTokenStore, Selection};
use wirken_gateway::proxy_identity::{self, JwtError, KeySet};
use wirken_vault::CredentialStore;
use zeroize::Zeroizing;

/// The most of a discovery document or a JWK set that is read.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// How long a fetch of either may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The least time between two fetches the cache's age did not call
/// for: one after a JWT named a key the set does not hold, or one
/// after a fetch failed. A stranger's JWTs cannot make the gateway ask
/// the issuer more often than this.
const MIN_REFETCH: Duration = Duration::from_secs(60);

/// The key subjects are hashed under: the vault entry `name`, made
/// there on first use. 32 random bytes, in hex.
pub(crate) fn subject_key(
    vault: &CredentialStore,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let unhex = |text: &str| -> Option<Vec<u8>> {
        (text.len() == 64 && text.is_ascii())
            .then(|| {
                (0..32)
                    .map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
                    .collect::<Option<Vec<u8>>>()
            })
            .flatten()
    };
    match vault.retrieve(name) {
        Ok((key, _)) => unhex(key.expose())
            .map(Zeroizing::new)
            .ok_or_else(|| format!("the subject key '{name}' is not 32 bytes of hex")),
        Err(wirken_vault::VaultError::NotFound(_)) => {
            let mut key = [0u8; 32];
            rand::fill(&mut key);
            let text: String = key.iter().map(|b| format!("{b:02x}")).collect();
            vault
                .store(
                    name,
                    "proxy-identity",
                    &wirken_vault::VaultSecret::new(text),
                    None,
                    None,
                )
                .map_err(|e| format!("store the subject key '{name}': {e}"))?;
            tracing::info!(
                "made the subject key '{name}' in the vault. The subject hashes on proxy rows \
                 are under it, and mean nothing once it is removed"
            );
            Ok(Zeroizing::new(key.to_vec()))
        }
        Err(e) => Err(format!("the subject key '{name}': {e}")),
    }
}

/// The issuer's keys as last fetched.
#[derive(Default)]
struct Fetched {
    keys: Option<Arc<KeySet>>,
    /// When `keys` were fetched.
    at: Option<Instant>,
    /// When the issuer was last asked, whether or not it answered.
    asked: Option<Instant>,
    /// Why the last fetch failed, when it did.
    failure: Option<String>,
}

enum KeySource {
    /// A JWK set read from a file at start. The issuer is never asked.
    Pinned(Arc<KeySet>),
    Issuer(Box<IssuerKeys>),
}

/// Keys fetched from the issuer, and kept for a time.
struct IssuerKeys {
    http: reqwest::Client,
    issuer: reqwest::Url,
    cache_for: Duration,
    fetched: tokio::sync::Mutex<Fetched>,
}

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// GET `url` and return its body, read up to [`MAX_DOCUMENT_BYTES`].
async fn fetch(http: &reqwest::Client, url: reqwest::Url) -> Result<String, String> {
    use futures_util::StreamExt as _;
    let response = http
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !response.status().is_success() {
        // A redirect is an answer too, and is not followed.
        return Err(format!("{url}: HTTP {}", response.status().as_u16()));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("{url}: {e}"))?;
        if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(format!("{url}: over {MAX_DOCUMENT_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| format!("{url}: not UTF-8"))
}

/// The issuer's keys, from its discovery document and the JWK set it
/// names.
async fn fetch_keys(http: &reqwest::Client, issuer: &reqwest::Url) -> Result<KeySet, String> {
    // The document is at the issuer with this path appended (OpenID
    // Connect Discovery 1.0, section 4).
    let discovery = reqwest::Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.as_str().trim_end_matches('/')
    ))
    .map_err(|e| format!("the discovery URL: {e}"))?;
    let document: serde_json::Value = serde_json::from_str(&fetch(http, discovery.clone()).await?)
        .map_err(|e| format!("{discovery}: not JSON: {e}"))?;
    // A document that speaks for another issuer is not this one's.
    if document["issuer"].as_str().map(|i| i.trim_end_matches('/'))
        != Some(issuer.as_str().trim_end_matches('/'))
    {
        return Err(format!(
            "{discovery}: the document is for the issuer {}, not {issuer}",
            document["issuer"]
        ));
    }
    let jwks_uri = document["jwks_uri"]
        .as_str()
        .ok_or_else(|| format!("{discovery}: no jwks_uri"))?;
    let jwks_uri = reqwest::Url::parse(jwks_uri)
        .map_err(|e| format!("{discovery}: jwks_uri {jwks_uri:?}: {e}"))?;
    if !same_origin(&jwks_uri, issuer) {
        return Err(format!(
            "{discovery}: jwks_uri {jwks_uri} is not on the issuer's origin. Keys are fetched \
             from the issuer only; for an issuer that keeps them elsewhere, pin them with \
             \"jwks_file\""
        ));
    }
    KeySet::parse(&fetch(http, jwks_uri.clone()).await?).map_err(|e| format!("{jwks_uri}: {e}"))
}

impl KeySource {
    /// The keys to verify with. `rotated` says a JWT named a key the
    /// last set does not hold, which is how a rotation at the issuer
    /// first shows.
    async fn keys(&self, rotated: bool) -> Result<Arc<KeySet>, String> {
        let (http, issuer, cache_for, fetched) = match self {
            Self::Pinned(keys) => return Ok(keys.clone()),
            Self::Issuer(from) => (&from.http, &from.issuer, from.cache_for, &from.fetched),
        };
        let mut fetched = fetched.lock().await;
        let fresh = fetched.at.is_some_and(|at| at.elapsed() < cache_for);
        let asked_lately = fetched.asked.is_some_and(|at| at.elapsed() < MIN_REFETCH);
        if fresh
            && (!rotated || asked_lately)
            && let Some(keys) = &fetched.keys
        {
            return Ok(keys.clone());
        }
        // The issuer was asked a moment ago and had no answer.
        if !fresh
            && asked_lately
            && let Some(failure) = &fetched.failure
        {
            return Err(failure.clone());
        }
        fetched.asked = Some(Instant::now());
        match fetch_keys(http, issuer).await {
            Ok(keys) => {
                let keys = Arc::new(keys);
                fetched.keys = Some(keys.clone());
                fetched.at = Some(Instant::now());
                fetched.failure = None;
                Ok(keys)
            }
            Err(e) => {
                tracing::warn!("proxy: the issuer's keys could not be fetched: {e}");
                fetched.failure = Some(e.clone());
                // Keys still within their time are used; keys past it
                // are not, and nothing is verified until a fetch works.
                match (&fetched.keys, fresh) {
                    (Some(keys), true) => Ok(keys.clone()),
                    _ => Err(e),
                }
            }
        }
    }
}

/// What a presented JWT was given.
pub enum Presented {
    /// The grant set the mapping selected, as the record the call is
    /// made under.
    Caller(Box<ProxyToken>),
    Refused {
        reason: ProxyRefusal,
        status: StatusCode,
        message: String,
        /// Whose JWT it was, where it was verified.
        identity: Option<ProxyIdentity>,
    },
}

/// Verifies JWTs of the one configured issuer.
pub struct IdentityVerifier {
    config: OidcConfig,
    keys: KeySource,
    subject_key: Zeroizing<Vec<u8>>,
}

impl IdentityVerifier {
    /// The verifier `config` describes. A pinned key set is read now,
    /// from `jwks_file`, relative to `data_dir` unless absolute; a file
    /// that cannot be read or holds no usable key stops the start.
    pub fn new(
        config: &OidcConfig,
        data_dir: &std::path::Path,
        subject_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, String> {
        let issuer = reqwest::Url::parse(&config.issuer)
            .map_err(|e| format!("issuer {:?}: {e}", config.issuer))?;
        let keys = match &config.jwks_file {
            Some(file) => {
                let path = data_dir.join(file);
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("jwks_file {}: {e}", path.display()))?;
                let keys = KeySet::parse(&text)
                    .map_err(|e| format!("jwks_file {}: {e}", path.display()))?;
                KeySource::Pinned(Arc::new(keys))
            }
            None => KeySource::Issuer(Box::new(IssuerKeys {
                http: reqwest::Client::builder()
                    .https_only(issuer.scheme() == "https")
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(FETCH_TIMEOUT)
                    .build()
                    .map_err(|e| format!("HTTP client: {e}"))?,
                issuer,
                cache_for: Duration::from_secs(config.jwks_cache_secs),
                fetched: tokio::sync::Mutex::new(Fetched::default()),
            })),
        };
        Ok(Self {
            config: config.clone(),
            keys,
            subject_key,
        })
    }

    /// Whether the keys are a pinned set.
    pub fn pinned(&self) -> bool {
        matches!(self.keys, KeySource::Pinned(_))
    }

    /// The keys, fetched now where they are fetched: what a start
    /// reports of an issuer it cannot reach.
    pub async fn warm(&self) -> Result<usize, String> {
        self.keys.keys(false).await.map(|k| k.len())
    }

    /// How `subject` is put on a row: as issued where the operator set
    /// that, as its keyed hash otherwise.
    fn identity(
        &self,
        subject: &str,
        jti: Option<String>,
        grant_set: Option<String>,
    ) -> (ProxyIdentity, String) {
        let hash = proxy_identity::subject_hash(&self.subject_key, &self.config.issuer, subject);
        let id = proxy_identity::subject_id(&hash);
        let (subject_hash, subject) = if self.config.record_subject {
            (None, Some(subject.to_string()))
        } else {
            (Some(hash), None)
        };
        (
            ProxyIdentity {
                issuer: self.config.issuer.clone(),
                grant_set,
                jti,
                subject_hash,
                subject,
            },
            id,
        )
    }

    /// Verify `jwt` and give it what the operator's mapping in `store`
    /// gives it.
    pub async fn check(&self, jwt: &str, store: &ProxyTokenStore) -> Presented {
        let refused = |reason, status, message: String, identity| Presented::Refused {
            reason,
            status,
            message,
            identity,
        };
        let unavailable = |why: String| {
            refused(
                ProxyRefusal::JwtKeysUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                format!("the issuer's keys could not be had, so no JWT is accepted: {why}"),
                None,
            )
        };
        let now = wirken_time::now().as_second();
        let keys = match self.keys.keys(false).await {
            Ok(keys) => keys,
            Err(why) => return unavailable(why),
        };
        let mut verdict = proxy_identity::verify(jwt, &keys, &self.config, now);
        if matches!(verdict, Err(JwtError::UnknownKey(_))) && !self.pinned() {
            // The issuer may have a key newer than the set held.
            match self.keys.keys(true).await {
                Ok(newer) if !Arc::ptr_eq(&newer, &keys) => {
                    verdict = proxy_identity::verify(jwt, &newer, &self.config, now);
                }
                _ => {}
            }
        }
        let verified = match verdict {
            Ok(verified) => verified,
            Err(e) => {
                return refused(e.refusal(), StatusCode::UNAUTHORIZED, e.to_string(), None);
            }
        };
        let selection = store.select_grant_set(
            &self.config.issuer,
            &verified.claim_values,
            &verified.subject,
        );
        match selection {
            Ok(Selection::One(set)) => {
                let (identity, id) =
                    self.identity(&verified.subject, verified.jti, Some(set.name.clone()));
                Presented::Caller(Box::new(set.caller(id, identity)))
            }
            Ok(Selection::None) => {
                let (identity, _) = self.identity(&verified.subject, verified.jti, None);
                refused(
                    ProxyRefusal::JwtNoGrant,
                    StatusCode::FORBIDDEN,
                    "the JWT is valid and no mapping gives it a grant set".into(),
                    Some(identity),
                )
            }
            Ok(Selection::Several(names)) => {
                let (identity, _) = self.identity(&verified.subject, verified.jti, None);
                refused(
                    ProxyRefusal::JwtAmbiguousGrant,
                    StatusCode::FORBIDDEN,
                    format!(
                        "the JWT is valid and mappings give it more than one grant set ({}), so \
                         it gets none",
                        names.join(", ")
                    ),
                    Some(identity),
                )
            }
            Err(e) => {
                tracing::error!("proxy: token store: {e}");
                unavailable("the mapping could not be read".into())
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What a scripted issuer answers a path with.
    pub(crate) type Routes =
        Arc<dyn Fn(&str) -> (u16, Vec<(String, String)>, String) + Send + Sync>;

    /// A loopback HTTP server that answers each GET with what `routes`
    /// says, and counts the requests it got.
    pub(crate) fn serve(routes: Routes) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                counted.fetch_add(1, Ordering::SeqCst);
                let (status, headers, body) = routes(path);
                let mut reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    reply.push_str(&format!("{name}: {value}\r\n"));
                }
                reply.push_str("\r\n");
                reply.push_str(&body);
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (port, hits)
    }

    pub(crate) const ISSUER: &str = "https://idp.example.com/realms/acme";
    pub(crate) const AUDIENCE: &str = "wirken-proxy";

    /// An identity provider for a test: one Ed25519 key, the JWK set
    /// it would publish, and JWTs signed with it.
    pub(crate) struct TestIssuer(ring::signature::Ed25519KeyPair);

    fn enc(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    impl TestIssuer {
        pub(crate) fn new() -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Self(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        pub(crate) fn jwks(&self) -> String {
            use ring::signature::KeyPair as _;
            serde_json::json!({"keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "k1", "use": "sig",
                "x": enc(self.0.public_key().as_ref()),
            }]})
            .to_string()
        }

        pub(crate) fn jwt(&self, claims: &serde_json::Value) -> String {
            let signed = format!(
                "{}.{}",
                enc(br#"{"alg":"EdDSA","kid":"k1","typ":"JWT"}"#),
                enc(claims.to_string().as_bytes())
            );
            format!("{signed}.{}", enc(self.0.sign(signed.as_bytes()).as_ref()))
        }

        /// A JWT of `subject`, in `groups`, issued a moment ago and
        /// good for five minutes.
        pub(crate) fn jwt_for(&self, subject: &str, groups: &[&str]) -> String {
            self.jwt(&claims(subject, groups))
        }

        /// A verifier of this issuer's JWTs with its keys pinned in
        /// `dir`, the grant claim `groups`, and whatever `change` sets.
        pub(crate) fn verifier(
            &self,
            dir: &std::path::Path,
            change: impl FnOnce(&mut OidcConfig),
        ) -> IdentityVerifier {
            std::fs::write(dir.join("idp.jwks"), self.jwks()).unwrap();
            let mut config: OidcConfig = serde_json::from_value(serde_json::json!({
                "issuer": ISSUER, "audience": AUDIENCE, "max_token_lifetime_secs": 600,
                "jwks_file": "idp.jwks", "grant_claim": "groups",
            }))
            .unwrap();
            change(&mut config);
            IdentityVerifier::new(&config, dir, Zeroizing::new(vec![7; 32])).unwrap()
        }
    }

    pub(crate) fn claims(subject: &str, groups: &[&str]) -> serde_json::Value {
        let now = wirken_time::now().as_second();
        serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": subject, "groups": groups,
            "iat": now - 10, "exp": now + 300, "jti": jti(subject),
        })
    }

    /// The `jti` of a test JWT of `subject`: one per subject, and not
    /// the subject's name, so a test can look for the name on a row.
    pub(crate) fn jti(subject: &str) -> String {
        format!("jti-{}", subject.chars().rev().collect::<String>())
    }

    /// The id a subject's calls are kept under by a test verifier.
    pub(crate) fn subject_id(subject: &str) -> String {
        proxy_identity::subject_id(&proxy_identity::subject_hash(&[7; 32], ISSUER, subject))
    }

    fn config(issuer: &str) -> OidcConfig {
        serde_json::from_value(serde_json::json!({
            "issuer": issuer, "audience": "wirken-proxy", "max_token_lifetime_secs": 600,
        }))
        .unwrap()
    }

    const JWKS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

    fn verifier(issuer: &str) -> IdentityVerifier {
        let tmp = tempfile::tempdir().unwrap();
        IdentityVerifier::new(&config(issuer), tmp.path(), Zeroizing::new(vec![7; 32])).unwrap()
    }

    /// The key subjects are hashed under is made in the vault once
    /// and read from it after.
    #[test]
    fn the_subject_key_is_made_once_and_kept_in_the_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = CredentialStore::open_with_key(
            &tmp.path().join("vault.db"),
            wirken_vault::VaultSecret::new("a".repeat(64)),
        )
        .unwrap();
        let first = subject_key(&vault, "proxy-subject-key").unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(subject_key(&vault, "proxy-subject-key").unwrap(), first);
        assert_ne!(subject_key(&vault, "another-key").unwrap(), first);
        vault
            .store(
                "short",
                "proxy-identity",
                &wirken_vault::VaultSecret::new("abcd".to_string()),
                None,
                None,
            )
            .unwrap();
        assert!(
            subject_key(&vault, "short")
                .unwrap_err()
                .contains("32 bytes")
        );
    }

    /// The keys come from the discovery document of the configured
    /// issuer and from the JWK set on its origin, and from nowhere a
    /// document or a redirect points.
    #[tokio::test]
    async fn keys_are_fetched_from_the_issuers_origin_and_no_redirect_is_followed() {
        let elsewhere = serve(Arc::new(|_| (200, vec![], JWKS.to_string())));

        // The issuer as it should be.
        let port = Arc::new(AtomicUsize::new(0));
        let own = port.clone();
        let good = serve(Arc::new(move |path| {
            let issuer = format!("http://127.0.0.1:{}", own.load(Ordering::SeqCst));
            match path {
                "/.well-known/openid-configuration" => (
                    200,
                    vec![],
                    serde_json::json!({"issuer": issuer, "jwks_uri": format!("{issuer}/keys")})
                        .to_string(),
                ),
                "/keys" => (200, vec![], JWKS.to_string()),
                _ => (404, vec![], String::new()),
            }
        }));
        port.store(good.0 as usize, Ordering::SeqCst);
        let issuer = format!("http://127.0.0.1:{}", good.0);
        assert_eq!(verifier(&issuer).warm().await.unwrap(), 1);

        // A document that names a JWK set on another origin.
        let other_port = elsewhere.0;
        let port = Arc::new(AtomicUsize::new(0));
        let own = port.clone();
        let foreign = serve(Arc::new(move |_| {
            let issuer = format!("http://127.0.0.1:{}", own.load(Ordering::SeqCst));
            (
                200,
                vec![],
                serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": format!("http://127.0.0.1:{other_port}/keys"),
                })
                .to_string(),
            )
        }));
        port.store(foreign.0 as usize, Ordering::SeqCst);
        let err = verifier(&format!("http://127.0.0.1:{}", foreign.0))
            .warm()
            .await
            .unwrap_err();
        assert!(err.contains("not on the issuer's origin"), "{err}");

        // A document that speaks for another issuer.
        let impostor = serve(Arc::new(|_| {
            (
                200,
                vec![],
                r#"{"issuer":"https://idp.example.com","jwks_uri":"https://idp.example.com/k"}"#
                    .to_string(),
            )
        }));
        let err = verifier(&format!("http://127.0.0.1:{}", impostor.0))
            .warm()
            .await
            .unwrap_err();
        assert!(err.contains("is for the issuer"), "{err}");

        // A discovery document that redirects, and a JWK set that does.
        let redirecting = serve(Arc::new(move |_| {
            (
                302,
                vec![(
                    "location".to_string(),
                    format!("http://127.0.0.1:{other_port}/.well-known/openid-configuration"),
                )],
                String::new(),
            )
        }));
        let err = verifier(&format!("http://127.0.0.1:{}", redirecting.0))
            .warm()
            .await
            .unwrap_err();
        assert!(err.contains("HTTP 302"), "{err}");

        let port = Arc::new(AtomicUsize::new(0));
        let own = port.clone();
        let keys_redirect = serve(Arc::new(move |path| {
            let issuer = format!("http://127.0.0.1:{}", own.load(Ordering::SeqCst));
            match path {
                "/.well-known/openid-configuration" => (
                    200,
                    vec![],
                    serde_json::json!({"issuer": issuer, "jwks_uri": format!("{issuer}/keys")})
                        .to_string(),
                ),
                _ => (
                    307,
                    vec![(
                        "location".to_string(),
                        format!("http://127.0.0.1:{other_port}/keys"),
                    )],
                    String::new(),
                ),
            }
        }));
        port.store(keys_redirect.0 as usize, Ordering::SeqCst);
        let err = verifier(&format!("http://127.0.0.1:{}", keys_redirect.0))
            .warm()
            .await
            .unwrap_err();
        assert!(err.contains("HTTP 307"), "{err}");

        // Nothing above reached the other origin.
        assert_eq!(elsewhere.1.load(Ordering::SeqCst), 0);
    }

    /// An issuer that cannot be reached, with no pinned keys: every
    /// JWT is refused, and the issuer is not asked again for each.
    #[tokio::test]
    async fn an_unreachable_issuer_with_no_pinned_keys_refuses_every_jwt() {
        // A port nothing listens on.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let verifier = verifier(&format!("http://127.0.0.1:{port}"));
        let tmp = tempfile::tempdir().unwrap();
        let store = ProxyTokenStore::open(&tmp.path().join("t.db")).unwrap();
        for _ in 0..3 {
            let Presented::Refused {
                reason,
                status,
                identity,
                ..
            } = verifier.check("a.b.c", &store).await
            else {
                panic!("a JWT was accepted with no keys");
            };
            assert_eq!(reason, ProxyRefusal::JwtKeysUnavailable);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(identity.is_none());
        }

        // An issuer that answers once and then is gone is asked once
        // more by a JWT that names an unknown key, and not again.
        let down = serve(Arc::new(|_| (500, vec![], String::new())));
        let verifier = self::verifier(&format!("http://127.0.0.1:{}", down.0));
        for _ in 0..5 {
            assert!(matches!(
                verifier.check("a.b.c", &store).await,
                Presented::Refused {
                    reason: ProxyRefusal::JwtKeysUnavailable,
                    ..
                }
            ));
        }
        assert_eq!(down.1.load(Ordering::SeqCst), 1);
    }

    /// A pinned key set is read from its file and the issuer is never
    /// asked; a file with no usable key stops the start.
    #[tokio::test]
    async fn a_pinned_key_set_is_read_once_and_the_issuer_is_never_asked() {
        let issuer = serve(Arc::new(|_| (200, vec![], JWKS.to_string())));
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("idp.jwks"), JWKS).unwrap();
        let mut config = config(&format!("http://127.0.0.1:{}", issuer.0));
        config.jwks_file = Some("idp.jwks".into());
        let key = || Zeroizing::new(vec![7; 32]);
        let verifier = IdentityVerifier::new(&config, tmp.path(), key()).unwrap();
        assert!(verifier.pinned());
        assert_eq!(verifier.warm().await.unwrap(), 1);
        let store = ProxyTokenStore::open(&tmp.path().join("t.db")).unwrap();
        // A JWT naming a key the set does not hold does not send the
        // gateway to the issuer for a newer one.
        assert!(matches!(
            verifier.check("a.b.c", &store).await,
            Presented::Refused {
                reason: ProxyRefusal::JwtInvalid,
                ..
            }
        ));
        assert_eq!(issuer.1.load(Ordering::SeqCst), 0);

        config.jwks_file = Some("absent.jwks".into());
        assert!(IdentityVerifier::new(&config, tmp.path(), key()).is_err());
        std::fs::write(tmp.path().join("empty.jwks"), r#"{"keys":[]}"#).unwrap();
        config.jwks_file = Some("empty.jwks".into());
        assert!(IdentityVerifier::new(&config, tmp.path(), key()).is_err());
    }
}
