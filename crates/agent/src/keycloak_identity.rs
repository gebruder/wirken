//! Keycloak [`FederatedIdentity`] implementation using the OIDC
//! client-credentials flow against a configurable realm token
//! endpoint.
//!
//! ## Vendor-neutral attribute set
//!
//! `span_attributes()` returns exactly two pairs: `gen_ai.agent.id`
//! and `gen_ai.agent.name`. Both come from operator config rather
//! than from JWT decode; for client-credentials the JWT `sub`
//! claim equals `client_id` equals the configured agent id, so
//! round-tripping through token parse buys nothing. No
//! Microsoft-namespaced attributes (`microsoft.tenant.id`,
//! `microsoft.a365.agent.blueprint.id`) are emitted because a
//! non-Microsoft OTLP backend (Datadog, Honeycomb, Jaeger, an
//! in-house OTel Collector) does not consume them; emitting them
//! would be wirken-namespacing noise on a generic pipeline.
//!
//! Per the [`FederatedIdentity`] trait contract, the configured
//! `client_id` is the single source of truth for both the
//! `agent_id()` getter (the URL `{agentId}` slot) and the
//! `gen_ai.agent.id` attribute in `span_attributes()`. The URL
//! slot and the per-span tag cannot disagree because they read
//! from one field.
//!
//! ## Token cache
//!
//! `current_token()` caches the bearer in a `tokio::sync::Mutex<Option<CachedToken>>`
//! and refreshes when `Instant::now()` reaches `refreshable_at`.
//! `refreshable_at = expires_at - lead_time` with a saturating
//! subtraction (`checked_sub(...).unwrap_or(expires_at)`) so a
//! configured lead time longer than the issued token's lifetime
//! does not underflow into a wrap-around; in that case
//! `refreshable_at == expires_at` and the cache window collapses
//! to zero, refreshing on every call.
//!
//! `expires_at` is computed from `Instant::now()` captured
//! **before** issuing the POST, not after parsing the response.
//! The off-by-network-round-trip drift would otherwise hand out a
//! token that expires mid-flight whenever the lead time is short.
//!
//! Single-flight is not provided: concurrent callers hitting an
//! expired cache may issue N redundant token requests, with the
//! last write winning. Acceptable for the single-forwarder-poller
//! deployment shape; impls that need single-flight should add an
//! acquisition lock distinct from the cache-read lock.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::Mutex;
use wirken_audit::otel_exporter::{FederatedIdentity, OtelError};

const DEFAULT_REFRESH_LEAD_TIME_SECS: u64 = 60;

/// OAuth2 token endpoint response shape. Only the two
/// load-bearing fields are deserialized; `token_type`,
/// `refresh_token`, and similar are present on the wire but
/// ignored.
#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
}

/// HTTP transport abstraction for the Keycloak token endpoint.
/// Production wires [`ReqwestKeycloakTokenClient`]; tests wire a
/// mock returning canned [`TokenResponse`] values without
/// touching the network.
#[async_trait]
pub trait KeycloakTokenClient: Send + Sync {
    async fn fetch_token(
        &self,
        endpoint: &str,
        client_id: &str,
        client_secret: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, OtelError>;
}

/// Production [`KeycloakTokenClient`] wrapping a `reqwest::Client`.
/// Posts the client-credentials grant as
/// `application/x-www-form-urlencoded`, the OAuth2-spec form.
pub struct ReqwestKeycloakTokenClient {
    client: reqwest::Client,
}

impl ReqwestKeycloakTokenClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl KeycloakTokenClient for ReqwestKeycloakTokenClient {
    async fn fetch_token(
        &self,
        endpoint: &str,
        client_id: &str,
        client_secret: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, OtelError> {
        let mut body = format!(
            "grant_type=client_credentials&client_id={cid}&client_secret={csec}",
            cid = encode_form_value(client_id),
            csec = encode_form_value(client_secret),
        );
        if let Some(s) = scope {
            body.push_str(&format!("&scope={}", encode_form_value(s)));
        }
        let response = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| OtelError::TokenAcquisition(format!("POST {endpoint}: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(OtelError::TokenAcquisition(format!(
                "token endpoint returned {status}: {body_text}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| OtelError::TokenAcquisition(format!("token body read: {e}")))?;
        serde_json::from_slice::<TokenResponse>(&bytes)
            .map_err(|e| OtelError::TokenAcquisition(format!("token body parse: {e}")))
    }
}

/// Percent-encode a value for `application/x-www-form-urlencoded`.
///
/// RFC 3986 unreserved characters pass through. Space becomes `+`
/// per the form-encoding convention; everything else is `%HH`.
/// Hand-rolled to keep the agent crate's dependency set tight;
/// reqwest 0.13 with `default-features = false` does not expose
/// `RequestBuilder::form()`.
fn encode_form_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Configuration for the Keycloak token acquisition path.
#[derive(Clone, Debug)]
pub struct KeycloakConfig {
    /// Token endpoint URL, typically
    /// `https://<host>/realms/<realm>/protocol/openid-connect/token`.
    pub token_endpoint: String,
    /// OIDC client id. This is the single source of truth for
    /// both the [`FederatedIdentity::agent_id`] URL slot and the
    /// `gen_ai.agent.id` value in
    /// [`FederatedIdentity::span_attributes`].
    pub client_id: String,
    /// OIDC client secret.
    pub client_secret: String,
    /// Display name stamped as `gen_ai.agent.name`. Operator-
    /// supplied; not from the JWT.
    pub agent_name: String,
    /// Optional `scope` query parameter sent with the token
    /// request. `None` omits the parameter; many Keycloak realms
    /// do not require it for client-credentials.
    pub scope: Option<String>,
    /// Tenant identifier the forwarder interpolates into the URL
    /// `{tenantId}` slot. Operator-chosen; the value has no
    /// semantic meaning in non-Microsoft OTLP backends but the
    /// URL template still requires a non-empty string.
    pub tenant_id: String,
    /// How long before declared expiry to start refreshing. The
    /// default 60s absorbs network round-trip drift. Set to 0 to
    /// disable lead time (refresh exactly at expiry).
    pub refresh_lead_time_secs: u64,
}

impl KeycloakConfig {
    pub fn new(
        token_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        agent_name: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            token_endpoint: token_endpoint.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            agent_name: agent_name.into(),
            scope: None,
            tenant_id: tenant_id.into(),
            refresh_lead_time_secs: DEFAULT_REFRESH_LEAD_TIME_SECS,
        }
    }
}

#[derive(Debug)]
struct CachedToken {
    bearer: String,
    refreshable_at: Instant,
}

pub struct KeycloakFederatedIdentity {
    config: KeycloakConfig,
    token_client: Arc<dyn KeycloakTokenClient>,
    cache: Mutex<Option<CachedToken>>,
}

impl KeycloakFederatedIdentity {
    pub fn new(config: KeycloakConfig, token_client: Arc<dyn KeycloakTokenClient>) -> Self {
        Self {
            config,
            token_client,
            cache: Mutex::new(None),
        }
    }

    async fn acquire_and_cache(&self) -> Result<String, OtelError> {
        // Capture the pre-request instant so refresh timing is
        // measured from when we initiated the POST, not from
        // when we parsed the response. Removes the
        // off-by-network-round-trip drift that the 60s default
        // lead time only masks.
        let issued_at = Instant::now();
        let token = self
            .token_client
            .fetch_token(
                &self.config.token_endpoint,
                &self.config.client_id,
                &self.config.client_secret,
                self.config.scope.as_deref(),
            )
            .await?;
        let expires_at = issued_at + Duration::from_secs(token.expires_in);
        let lead_time = Duration::from_secs(self.config.refresh_lead_time_secs);
        // Saturating subtraction: if expires_in is shorter than
        // lead_time, refreshable_at equals expires_at and the
        // cache window collapses to zero. No wrap-around.
        let refreshable_at = expires_at.checked_sub(lead_time).unwrap_or(expires_at);
        let bearer = token.access_token;
        let mut cache = self.cache.lock().await;
        *cache = Some(CachedToken {
            bearer: bearer.clone(),
            refreshable_at,
        });
        Ok(bearer)
    }
}

#[async_trait]
impl FederatedIdentity for KeycloakFederatedIdentity {
    fn tenant_id(&self) -> &str {
        &self.config.tenant_id
    }

    fn agent_id(&self) -> &str {
        &self.config.client_id
    }

    async fn current_token(&self) -> Result<String, OtelError> {
        {
            let cached = self.cache.lock().await;
            if let Some(c) = cached.as_ref()
                && Instant::now() < c.refreshable_at
            {
                return Ok(c.bearer.clone());
            }
        }
        self.acquire_and_cache().await
    }

    fn span_attributes(&self) -> Vec<(String, String)> {
        // Vendor-neutral subset. Both pairs derive from
        // KeycloakConfig fields, with `gen_ai.agent.id` reading
        // the same `client_id` value `agent_id()` returns so the
        // URL slot and the span attribute cannot disagree.
        vec![
            ("gen_ai.agent.id".to_string(), self.config.client_id.clone()),
            (
                "gen_ai.agent.name".to_string(),
                self.config.agent_name.clone(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[test]
    fn encode_form_value_passes_unreserved_through_and_percent_encodes_specials() {
        assert_eq!(encode_form_value("abc-XYZ_123.~"), "abc-XYZ_123.~");
        assert_eq!(encode_form_value("hello world"), "hello+world");
        assert_eq!(encode_form_value("a&b=c"), "a%26b%3Dc");
        assert_eq!(encode_form_value("secret+%"), "secret%2B%25");
    }

    enum MockResponse {
        Ok {
            access_token: String,
            expires_in: u64,
        },
        Err(String),
    }

    /// Captured arguments per `fetch_token` call: `(endpoint,
    /// client_id, client_secret, scope)`.
    type RecordedCall = (String, String, String, Option<String>);

    struct MockTokenClient {
        responses: StdMutex<VecDeque<MockResponse>>,
        calls: StdMutex<Vec<RecordedCall>>,
    }

    impl MockTokenClient {
        fn new(responses: Vec<MockResponse>) -> Self {
            Self {
                responses: StdMutex::new(responses.into()),
                calls: StdMutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl KeycloakTokenClient for MockTokenClient {
        async fn fetch_token(
            &self,
            endpoint: &str,
            client_id: &str,
            client_secret: &str,
            scope: Option<&str>,
        ) -> Result<TokenResponse, OtelError> {
            self.calls.lock().unwrap().push((
                endpoint.to_string(),
                client_id.to_string(),
                client_secret.to_string(),
                scope.map(str::to_string),
            ));
            let next = self.responses.lock().unwrap().pop_front();
            match next {
                Some(MockResponse::Ok {
                    access_token,
                    expires_in,
                }) => Ok(TokenResponse {
                    access_token,
                    expires_in,
                }),
                Some(MockResponse::Err(msg)) => Err(OtelError::TokenAcquisition(msg)),
                None => Err(OtelError::TokenAcquisition(
                    "mock ran out of canned responses".to_string(),
                )),
            }
        }
    }

    fn config() -> KeycloakConfig {
        KeycloakConfig::new(
            "https://keycloak.invalid/realms/wirken/protocol/openid-connect/token",
            "test-client",
            "test-secret",
            "test-agent",
            "test-tenant",
        )
    }

    #[tokio::test]
    async fn acquires_token_on_first_call_and_returns_bearer() {
        let mock = Arc::new(MockTokenClient::new(vec![MockResponse::Ok {
            access_token: "tok-1".to_string(),
            expires_in: 3600,
        }]));
        let id = KeycloakFederatedIdentity::new(config(), mock.clone());
        let token = id.current_token().await.expect("first call must succeed");
        assert_eq!(token, "tok-1");
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn cache_hit_within_window_skips_second_post() {
        let mock = Arc::new(MockTokenClient::new(vec![MockResponse::Ok {
            access_token: "tok-1".to_string(),
            expires_in: 3600,
        }]));
        let id = KeycloakFederatedIdentity::new(config(), mock.clone());
        let _ = id.current_token().await.unwrap();
        let second = id.current_token().await.unwrap();
        assert_eq!(second, "tok-1");
        assert_eq!(
            mock.call_count(),
            1,
            "second call must hit the cache; expected one POST, got {}",
            mock.call_count(),
        );
    }

    #[tokio::test]
    async fn refresh_after_expiry_re_posts_and_returns_new_token() {
        let mock = Arc::new(MockTokenClient::new(vec![
            MockResponse::Ok {
                access_token: "tok-1".to_string(),
                expires_in: 0,
            },
            MockResponse::Ok {
                access_token: "tok-2".to_string(),
                expires_in: 3600,
            },
        ]));
        let mut cfg = config();
        cfg.refresh_lead_time_secs = 0;
        let id = KeycloakFederatedIdentity::new(cfg, mock.clone());
        let first = id.current_token().await.unwrap();
        assert_eq!(first, "tok-1");
        // Refreshable_at equals issued_at (lead_time=0,
        // expires_in=0); Instant::now() advances during the
        // intervening await so the next call refreshes.
        tokio::time::sleep(Duration::from_millis(1)).await;
        let second = id.current_token().await.unwrap();
        assert_eq!(second, "tok-2");
        assert_eq!(mock.call_count(), 2);
    }

    #[tokio::test]
    async fn span_attributes_returns_two_vendor_neutral_pairs_no_microsoft_keys() {
        let id =
            KeycloakFederatedIdentity::new(config(), Arc::new(MockTokenClient::new(Vec::new())));
        let attrs = id.span_attributes();
        assert_eq!(attrs.len(), 2);
        let map: HashMap<String, String> = attrs.into_iter().collect();
        assert_eq!(
            map.get("gen_ai.agent.id").map(String::as_str),
            Some("test-client"),
        );
        assert_eq!(
            map.get("gen_ai.agent.name").map(String::as_str),
            Some("test-agent"),
        );
        // No Microsoft-namespaced keys on a Keycloak-targeted
        // deployment; emitting them would be noise on a generic
        // OTLP pipeline.
        assert!(!map.contains_key("microsoft.tenant.id"));
        assert!(!map.contains_key("microsoft.a365.agent.blueprint.id"));
        assert!(!map.contains_key("microsoft.channel.name"));
    }

    #[tokio::test]
    async fn agent_id_getter_matches_gen_ai_agent_id_in_span_attributes() {
        // The single-source rule the trait doc names: URL slot
        // and span attribute derive from one field and cannot
        // disagree.
        let id =
            KeycloakFederatedIdentity::new(config(), Arc::new(MockTokenClient::new(Vec::new())));
        let getter_value = id.agent_id().to_string();
        let attr_value = id
            .span_attributes()
            .into_iter()
            .find(|(k, _)| k == "gen_ai.agent.id")
            .map(|(_, v)| v)
            .expect("span_attributes must carry gen_ai.agent.id");
        assert_eq!(getter_value, attr_value);
    }

    #[tokio::test]
    async fn token_endpoint_failure_maps_to_token_acquisition_error() {
        let mock = Arc::new(MockTokenClient::new(vec![MockResponse::Err(
            "HTTP 401 invalid_client".to_string(),
        )]));
        let id = KeycloakFederatedIdentity::new(config(), mock);
        let result = id.current_token().await;
        assert!(
            matches!(result, Err(OtelError::TokenAcquisition(_))),
            "expected TokenAcquisition error, got {result:?}",
        );
    }

    #[tokio::test]
    async fn short_expiry_below_lead_time_saturates_and_refreshes_every_call() {
        // expires_in=0 with lead_time=60: refreshable_at would
        // be expires_at-60s, which checked_sub returns None for
        // (underflow), so the saturating fallback leaves
        // refreshable_at = expires_at = issued_at. Instant::now()
        // advances during the await between calls, so every
        // subsequent call goes to the wire. No panic, no
        // wrap-around.
        let mock = Arc::new(MockTokenClient::new(vec![
            MockResponse::Ok {
                access_token: "tok-a".to_string(),
                expires_in: 0,
            },
            MockResponse::Ok {
                access_token: "tok-b".to_string(),
                expires_in: 0,
            },
            MockResponse::Ok {
                access_token: "tok-c".to_string(),
                expires_in: 0,
            },
        ]));
        let mut cfg = config();
        cfg.refresh_lead_time_secs = 60;
        let id = KeycloakFederatedIdentity::new(cfg, mock.clone());
        let _ = id.current_token().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let _ = id.current_token().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let _ = id.current_token().await.unwrap();
        assert_eq!(
            mock.call_count(),
            3,
            "short expiry below lead time must refresh every call without underflow",
        );
    }

    #[tokio::test]
    async fn scope_is_forwarded_when_set_omitted_when_none() {
        // Two separate identities to assert both branches of
        // the scope option without spinning multiple acquire
        // cycles on one cache.
        let mock_with = Arc::new(MockTokenClient::new(vec![MockResponse::Ok {
            access_token: "tok-1".to_string(),
            expires_in: 3600,
        }]));
        let mut cfg_with = config();
        cfg_with.scope = Some("openid".to_string());
        let id_with = KeycloakFederatedIdentity::new(cfg_with, mock_with.clone());
        let _ = id_with.current_token().await.unwrap();
        // Scope the lock so the StdMutex guard is dropped at
        // block exit, before the next await; otherwise the
        // await-holding-lock lint fires.
        {
            let calls_with = mock_with.calls.lock().unwrap();
            assert_eq!(calls_with[0].3.as_deref(), Some("openid"));
        }

        let mock_without = Arc::new(MockTokenClient::new(vec![MockResponse::Ok {
            access_token: "tok-2".to_string(),
            expires_in: 3600,
        }]));
        let id_without = KeycloakFederatedIdentity::new(config(), mock_without.clone());
        let _ = id_without.current_token().await.unwrap();
        {
            let calls_without = mock_without.calls.lock().unwrap();
            assert_eq!(calls_without[0].3, None);
        }
    }
}
