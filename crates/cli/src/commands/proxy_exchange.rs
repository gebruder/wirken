//! Token exchange for the proxy's MCP endpoint (RFC 8693).
//!
//! A call a client makes at the MCP endpoint with a JWT of the
//! configured issuer, to a server whose signed entry names an audience,
//! is made with a token of that audience the gateway got for the JWT at
//! the issuer's token endpoint. The downstream then sees the person
//! behind the client, not the connector.
//!
//! The token endpoint is the one the issuer's discovery document names,
//! on the issuer's origin. The gateway authenticates there as the
//! client `proxy.json` names, with a secret read from the vault under a
//! `--token-exchange` binding to the endpoint's host.
//!
//! The JWT is sent as the subject token and kept no longer than the
//! request. The token got for it is held in memory, per subject and
//! audience, until shortly before it expires; nothing of it is written
//! anywhere. Wirken issues nothing: what the downstream accepts is what
//! the issuer gave.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use wirken_gateway::proxy::{ExchangeClient, OidcConfig};
use wirken_mcp_proxy::wire::ExchangedToken;
use wirken_time::{SignedDuration, Timestamp};
use zeroize::Zeroizing;

/// RFC 8693, section 2.1.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693, section 3: the subject token is the access token the
/// client presented, and an access token is what is asked for.
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// How long before its expiry a held token is no longer used.
const MARGIN: Duration = Duration::from_secs(30);

/// The most tokens held at once. The one nearest its expiry goes first.
const MAX_HELD: usize = 4096;

/// The most of a token endpoint's answer that is read.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// How long one exchange may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The least time between two fetches of the discovery document after
/// one failed.
const MIN_REFETCH: Duration = Duration::from_secs(60);

/// The client secret for the token endpoint at `host`, from the vault.
pub type ClientSecret =
    Box<dyn Fn(&str) -> Result<Zeroizing<String>, String> + Send + Sync + 'static>;

/// A token for one caller and one audience.
pub struct Exchanged {
    pub token: ExchangedToken,
    pub expires_at: Timestamp,
    /// Got by this exchange, rather than held from an earlier one. One
    /// row is written for each.
    pub fresh: bool,
}

struct Held {
    token: ExchangedToken,
    expires_at: Timestamp,
    /// When it stops being used.
    until: Instant,
}

/// The token endpoint, as last read from the discovery document.
#[derive(Default)]
struct Endpoint {
    url: Option<reqwest::Url>,
    at: Option<Instant>,
    asked: Option<Instant>,
    failure: Option<String>,
}

/// Exchanges callers' JWTs at the configured issuer.
pub struct Exchanger {
    http: reqwest::Client,
    issuer: reqwest::Url,
    client_id: String,
    secret: ClientSecret,
    cache_for: Duration,
    endpoint: tokio::sync::Mutex<Endpoint>,
    held: std::sync::Mutex<HashMap<(String, String), Held>>,
}

/// A form body, `application/x-www-form-urlencoded`.
fn form(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        body.append_pair(name, value);
    }
    Zeroizing::new(body.finish())
}

/// The `Basic` header of RFC 6749, section 2.3.1: id and secret each
/// form-encoded, then joined and base64-encoded.
fn basic(client_id: &str, secret: &str) -> Result<reqwest::header::HeaderValue, String> {
    use base64::Engine as _;
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let joined = Zeroizing::new(format!("{}:{}", encode(client_id), encode(secret)));
    let text = Zeroizing::new(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(joined.as_bytes())
    ));
    let mut value = reqwest::header::HeaderValue::from_str(&text)
        .map_err(|_| "the client credential is not a header value".to_string())?;
    value.set_sensitive(true);
    Ok(value)
}

/// What a token endpoint's error answer says, without anything it
/// echoed: the `error` code of RFC 6749, section 5.2, and its
/// description cut short.
fn refusal(status: u16, body: &str) -> String {
    let answer: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let code = answer["error"]
        .as_str()
        .filter(|c| c.len() <= 64 && c.chars().all(|c| c.is_ascii_graphic()))
        .unwrap_or("no error code");
    let description: String = answer["error_description"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    if description.is_empty() {
        format!("the token endpoint refused the exchange: HTTP {status}, {code}")
    } else {
        format!("the token endpoint refused the exchange: HTTP {status}, {code}: {description}")
    }
}

impl Exchanger {
    /// The exchanger `client` describes, for `oidc`'s issuer.
    pub fn new(
        oidc: &OidcConfig,
        client: &ExchangeClient,
        secret: ClientSecret,
    ) -> Result<Self, String> {
        let issuer = reqwest::Url::parse(&oidc.issuer)
            .map_err(|e| format!("issuer {:?}: {e}", oidc.issuer))?;
        Ok(Self {
            http: reqwest::Client::builder()
                .https_only(issuer.scheme() == "https")
                .redirect(reqwest::redirect::Policy::none())
                .timeout(EXCHANGE_TIMEOUT)
                .build()
                .map_err(|e| format!("HTTP client: {e}"))?,
            issuer,
            client_id: client.client_id.clone(),
            secret,
            cache_for: Duration::from_secs(oidc.jwks_cache_secs),
            endpoint: tokio::sync::Mutex::new(Endpoint::default()),
            held: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// The token endpoint the issuer's discovery document names. It
    /// must be on the issuer's origin.
    async fn token_endpoint(&self) -> Result<reqwest::Url, String> {
        let mut endpoint = self.endpoint.lock().await;
        if let (Some(url), Some(at)) = (&endpoint.url, endpoint.at)
            && at.elapsed() < self.cache_for
        {
            return Ok(url.clone());
        }
        if endpoint.asked.is_some_and(|at| at.elapsed() < MIN_REFETCH)
            && let Some(failure) = &endpoint.failure
        {
            return Err(failure.clone());
        }
        endpoint.asked = Some(Instant::now());
        let found = async {
            let document = super::proxy_oidc::discovery(&self.http, &self.issuer).await?;
            let named = document["token_endpoint"]
                .as_str()
                .ok_or("the discovery document names no token_endpoint")?;
            let url =
                reqwest::Url::parse(named).map_err(|e| format!("token_endpoint {named:?}: {e}"))?;
            if !super::proxy_oidc::same_origin(&url, &self.issuer) {
                return Err(format!(
                    "token_endpoint {url} is not on the issuer's origin; the exchange is made at \
                     the issuer only"
                ));
            }
            Ok(url)
        }
        .await;
        match found {
            Ok(url) => {
                *endpoint = Endpoint {
                    url: Some(url.clone()),
                    at: Some(Instant::now()),
                    asked: endpoint.asked,
                    failure: None,
                };
                Ok(url)
            }
            Err(e) => {
                tracing::warn!("proxy: the issuer's token endpoint could not be had: {e}");
                endpoint.failure = Some(e.clone());
                Err(e)
            }
        }
    }

    fn held(&self, key: &(String, String)) -> Option<Exchanged> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.retain(|_, h| Instant::now() < h.until);
        held.get(key).map(|h| Exchanged {
            token: h.token.clone(),
            expires_at: h.expires_at,
            fresh: false,
        })
    }

    fn hold(
        &self,
        key: (String, String),
        token: &ExchangedToken,
        expires_in: Duration,
        expires_at: Timestamp,
    ) {
        let Some(usable) = expires_in.checked_sub(MARGIN) else {
            // Too short-lived to be worth keeping: used for this call.
            return;
        };
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.retain(|_, h| Instant::now() < h.until);
        while held.len() >= MAX_HELD {
            let Some(soonest) = held
                .iter()
                .min_by_key(|(_, h)| h.until)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            held.remove(&soonest);
        }
        held.insert(
            key,
            Held {
                token: token.clone(),
                expires_at,
                until: Instant::now() + usable,
            },
        );
    }

    /// Stop using what is held for `subject_id` and `audience`.
    pub fn forget(&self, subject_id: &str, audience: &str) {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(subject_id.to_string(), audience.to_string()));
    }

    /// A token of `audience` for the caller whose verified JWT is
    /// `subject_token` and whose id is `subject_id`: one held from an
    /// earlier exchange, or one got now.
    pub async fn exchange(
        &self,
        subject_token: &str,
        subject_id: &str,
        audience: &str,
    ) -> Result<Exchanged, String> {
        let key = (subject_id.to_string(), audience.to_string());
        if let Some(held) = self.held(&key) {
            return Ok(held);
        }
        let endpoint = self.token_endpoint().await?;
        let host = wirken_agent::egress::host_name(&endpoint)
            .ok_or_else(|| format!("token_endpoint {endpoint} has no host"))?;
        let secret = (self.secret)(&host)?;
        let body = form(&[
            ("grant_type", GRANT_TYPE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ACCESS_TOKEN),
            ("audience", audience),
        ]);
        let response = self
            .http
            .post(endpoint.clone())
            .header(
                reqwest::header::AUTHORIZATION,
                basic(&self.client_id, &secret)?,
            )
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| format!("{endpoint}: {}", e.without_url()))?;
        let status = response.status();
        let answer = read_limited(response).await?;
        if !status.is_success() {
            // A redirect is an answer too, and is not followed.
            return Err(refusal(status.as_u16(), &answer));
        }
        let answer: serde_json::Value = serde_json::from_str(&answer)
            .map_err(|_| "the token endpoint's answer is not JSON".to_string())?;
        let token = answer["access_token"]
            .as_str()
            .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_graphic()))
            .ok_or("the token endpoint's answer holds no access_token")?;
        if let Some(issued) = answer["issued_token_type"].as_str()
            && issued != ACCESS_TOKEN
        {
            return Err(format!(
                "the token endpoint issued a {issued}, not an access token"
            ));
        }
        if !answer["token_type"]
            .as_str()
            .is_some_and(|t| t.eq_ignore_ascii_case("bearer"))
        {
            return Err(format!(
                "the token endpoint issued a token of type {}, not a bearer token",
                answer["token_type"]
            ));
        }
        let expires_in = answer["expires_in"]
            .as_u64()
            .filter(|s| *s > 0)
            .ok_or("the token endpoint's answer says nothing of when the token expires")?;
        let expires_in = Duration::from_secs(expires_in);
        let expires_at = wirken_time::now()
            .saturating_add(SignedDuration::try_from(expires_in).unwrap_or_default())
            .unwrap_or(wirken_time::FOREVER);
        let token = ExchangedToken::new(token.to_string());
        self.hold(key, &token, expires_in, expires_at);
        Ok(Exchanged {
            token,
            expires_at,
            fresh: true,
        })
    }
}

/// A response body, read up to [`MAX_ANSWER_BYTES`].
async fn read_limited(response: reqwest::Response) -> Result<String, String> {
    use futures_util::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("the token endpoint's answer: {e}"))?;
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(format!(
                "the token endpoint's answer is over {MAX_ANSWER_BYTES} bytes"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "the token endpoint's answer is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::commands::proxy_oidc::tests::{Routes, serve};

    /// A loopback issuer that answers its discovery document with a
    /// `token_endpoint` that `endpoint` makes of its own origin, and
    /// every other path with `token`.
    fn issuer(
        endpoint: impl Fn(&str) -> String + Send + Sync + 'static,
        token: (u16, Vec<(String, String)>, String),
    ) -> (String, Arc<AtomicUsize>) {
        let port = Arc::new(AtomicUsize::new(0));
        let own = port.clone();
        let routes: Routes = Arc::new(move |path| {
            let origin = format!("http://127.0.0.1:{}", own.load(Ordering::SeqCst));
            if path == "/.well-known/openid-configuration" {
                (
                    200,
                    vec![],
                    serde_json::json!({"issuer": origin, "token_endpoint": endpoint(&origin)})
                        .to_string(),
                )
            } else {
                token.clone()
            }
        });
        let (bound, hits) = serve(routes);
        port.store(bound as usize, Ordering::SeqCst);
        (format!("http://127.0.0.1:{bound}"), hits)
    }

    fn exchanger(issuer: &str, asked: Arc<std::sync::Mutex<Vec<String>>>) -> Exchanger {
        let oidc: OidcConfig = serde_json::from_value(serde_json::json!({
            "issuer": issuer, "audience": "wirken-proxy", "max_token_lifetime_secs": 600,
        }))
        .unwrap();
        let client = ExchangeClient {
            client_id: "wirken".into(),
            client_secret: "idp-secret".into(),
        };
        Exchanger::new(
            &oidc,
            &client,
            Box::new(move |host| {
                asked.lock().unwrap().push(host.to_string());
                Ok(Zeroizing::new("s3cret".into()))
            }),
        )
        .unwrap()
    }

    fn token(expires_in: u64) -> (u16, Vec<(String, String)>, String) {
        (
            200,
            vec![],
            serde_json::json!({
                "access_token": "exchanged", "token_type": "Bearer", "expires_in": expires_in,
            })
            .to_string(),
        )
    }

    /// The exchange is made at the issuer's own token endpoint, with
    /// the secret read for that endpoint's host. One on another origin,
    /// or one that redirects, is not used, and nothing reaches the
    /// other origin.
    #[tokio::test]
    async fn the_exchange_is_made_at_the_issuers_own_token_endpoint_only() {
        let elsewhere = serve(Arc::new(|_| token(300)));
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));

        let (own, _) = issuer(|origin| format!("{origin}/token"), token(300));
        let got = exchanger(&own, asked.clone())
            .exchange("a.b.c", "u1", "crm-api")
            .await
            .unwrap();
        assert_eq!(got.token.expose(), "exchanged");
        assert_eq!(
            *asked.lock().unwrap(),
            [own.trim_start_matches("http://").to_string()]
        );

        let other = elsewhere.0;
        let (foreign, _) = issuer(
            move |_| format!("http://127.0.0.1:{other}/token"),
            token(300),
        );
        let err = exchanger(&foreign, asked.clone())
            .exchange("a.b.c", "u1", "crm-api")
            .await
            .err()
            .unwrap();
        assert!(err.contains("not on the issuer's origin"), "{err}");

        let (redirecting, _) = issuer(
            |origin| format!("{origin}/token"),
            (
                307,
                vec![("location".into(), format!("http://127.0.0.1:{other}/token"))],
                String::new(),
            ),
        );
        let err = exchanger(&redirecting, asked)
            .exchange("a.b.c", "u1", "crm-api")
            .await
            .err()
            .unwrap();
        assert!(err.contains("HTTP 307"), "{err}");
        assert_eq!(elsewhere.1.load(Ordering::SeqCst), 0);
    }

    /// A token is held per subject and audience until shortly before it
    /// expires. One too short-lived to hold is used for its call and
    /// asked for again the next time, and one forgotten is too.
    #[tokio::test]
    async fn a_token_is_held_per_subject_and_audience_until_near_its_expiry() {
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (long, hits) = issuer(|origin| format!("{origin}/token"), token(300));
        let exchanger = exchanger(&long, asked.clone());
        let posts = || hits.load(Ordering::SeqCst) - 1;
        assert!(exchanger.exchange("j", "u1", "crm").await.unwrap().fresh);
        assert!(!exchanger.exchange("j", "u1", "crm").await.unwrap().fresh);
        assert_eq!(posts(), 1);
        assert!(exchanger.exchange("j", "u2", "crm").await.unwrap().fresh);
        assert!(exchanger.exchange("j", "u1", "erp").await.unwrap().fresh);
        assert_eq!(posts(), 3);
        exchanger.forget("u1", "crm");
        assert!(exchanger.exchange("j", "u1", "crm").await.unwrap().fresh);
        assert_eq!(posts(), 4);

        let (short, hits) = issuer(|origin| format!("{origin}/token"), token(20));
        let exchanger = super::tests::exchanger(&short, asked);
        for _ in 0..2 {
            assert!(exchanger.exchange("j", "u1", "crm").await.unwrap().fresh);
        }
        assert_eq!(hits.load(Ordering::SeqCst) - 1, 2);
    }

    /// What the provider says on a refusal reaches the operator; what
    /// it echoed of the request does not.
    #[test]
    fn a_refusal_names_the_error_code_and_nothing_else_of_the_request() {
        assert_eq!(
            refusal(
                400,
                r#"{"error":"invalid_target","error_description":"no\nsuch"}"#
            ),
            "the token endpoint refused the exchange: HTTP 400, invalid_target: nosuch"
        );
        assert_eq!(
            refusal(401, "<html>a.b.c</html>"),
            "the token endpoint refused the exchange: HTTP 401, no error code"
        );
    }
}
