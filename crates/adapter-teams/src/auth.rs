//! Inbound JWT validation for the Bot Framework webhook.
//!
//! Microsoft signs every inbound activity with a JWT in the
//! `Authorization: Bearer` header. The JWT is signed with one of
//! Microsoft's rotating RSA keys, published at a JWKS URI listed in
//! the Bot Framework OpenID metadata. Without verification the
//! webhook accepts any POST matching the Activity shape and any
//! attacker reachable to the listening socket can impersonate any
//! Teams user.
//!
//! This module provides [`JwksCache`], which fetches and caches the
//! JWKS and validates inbound tokens against it. A refresh is
//! triggered when the cache is empty, older than
//! [`REFRESH_INTERVAL`], or when an inbound JWT references a `kid`
//! that isn't in the cache (key rotation). Refreshes are serialized
//! through a mutex so concurrent inbound requests do not stampede.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::AuthError;

/// Bot Framework production issuer. Deployments that also need to
/// accept the emulator or other Microsoft channels can extend the
/// `accepted_issuers` list on the cache; this constant is the
/// default.
pub const BOT_FRAMEWORK_ISSUER: &str = "https://api.botframework.com";

/// OpenID configuration URL for the Bot Framework channel. The JWKS
/// URI is read from the `jwks_uri` field of the returned document.
pub const OPENID_CONFIG_URL: &str =
    "https://login.botframework.com/v1/.well-known/openidconfiguration";

/// Hard refresh interval. A JWKS rotation typically reuses an
/// overlapping window so tokens still validate while keys rotate; if
/// a `kid` miss occurs we force a refresh immediately, but we also
/// refresh on this cadence to pick up new keys ahead of their first
/// use and to drop keys that have been retired.
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Claims surfaced from a validated JWT. Only the fields that affect
/// authorization live here. Additional fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    #[serde(default, rename = "serviceurl")]
    pub service_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: String,
    kty: String,
    #[serde(rename = "n")]
    modulus: Option<String>,
    #[serde(rename = "e")]
    exponent: Option<String>,
}

struct CacheState {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

impl CacheState {
    fn is_stale(&self) -> bool {
        self.fetched_at
            .map(|t| t.elapsed() >= REFRESH_INTERVAL)
            .unwrap_or(true)
    }
}

/// JWKS cache and JWT validator for Bot Framework inbound tokens.
pub struct JwksCache {
    state: Arc<RwLock<CacheState>>,
    http: reqwest::Client,
    openid_config_url: String,
    accepted_issuers: Vec<String>,
}

impl JwksCache {
    /// Production constructor. Uses the public Bot Framework OpenID
    /// config URL and accepts the documented production issuer.
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            state: Arc::new(RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
            })),
            http,
            openid_config_url: OPENID_CONFIG_URL.into(),
            accepted_issuers: vec![BOT_FRAMEWORK_ISSUER.into()],
        }
    }

    /// Validate an inbound `Authorization: Bearer <jwt>` header
    /// value (raw bearer token, not the full header). Returns the
    /// validated claims on success. On failure, returns a specific
    /// reason suitable for logging; callers should surface a generic
    /// 401 on the wire and not echo the reason.
    pub async fn validate_token(
        &self,
        token: &str,
        expected_aud: &str,
    ) -> Result<Claims, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::JwtHeader(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| AuthError::JwtHeader("no kid".into()))?;

        let key = self.get_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[expected_aud]);
        validation.set_issuer(&self.accepted_issuers);
        validation.validate_exp = true;
        validation.leeway = 60;

        let data: TokenData<Claims> = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::JwtValidation(e.to_string()))?;

        if !self.accepted_issuers.iter().any(|i| i == &data.claims.iss) {
            return Err(AuthError::IssuerRejected(data.claims.iss.clone()));
        }

        Ok(data.claims)
    }

    /// Look up a signing key by `kid`. Refreshes the cache on miss
    /// (handles key rotation) and on staleness.
    async fn get_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        {
            let state = self.state.read().await;
            if let Some(k) = state.keys.get(kid) {
                if !state.is_stale() {
                    return Ok(k.clone());
                }
            }
        }

        self.refresh().await?;

        let state = self.state.read().await;
        state
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| AuthError::UnknownKid(kid.to_string()))
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        let config: OpenIdConfig = self
            .http
            .get(&self.openid_config_url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AuthError::JwksFetch(format!("openid config: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::JwksFetch(format!("openid config parse: {e}")))?;

        let jwks: Jwks = self
            .http
            .get(&config.jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AuthError::JwksFetch(format!("jwks: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::JwksFetch(format!("jwks parse: {e}")))?;

        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for key in jwks.keys {
            if key.kty != "RSA" {
                continue;
            }
            let (Some(n), Some(e)) = (key.modulus.as_ref(), key.exponent.as_ref()) else {
                continue;
            };
            let Ok(decoding) = DecodingKey::from_rsa_components(n, e) else {
                continue;
            };
            keys.insert(key.kid, decoding);
        }

        let mut state = self.state.write().await;
        state.keys = keys;
        state.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// Test-only constructor: seed the cache with a fixed set of
    /// keys so validation can run without network access.
    #[cfg(test)]
    pub(crate) fn for_test(keys: Vec<(String, DecodingKey)>, issuer: &str) -> Self {
        let mut map = HashMap::new();
        for (kid, key) in keys {
            map.insert(kid, key);
        }
        Self {
            state: Arc::new(RwLock::new(CacheState {
                keys: map,
                fetched_at: Some(Instant::now()),
            })),
            http: reqwest::Client::new(),
            openid_config_url: String::new(),
            accepted_issuers: vec![issuer.to_string()],
        }
    }
}

/// Extract the bearer token from a raw HTTP request buffer. Returns
/// the token string on success. Returns `AuthError::MissingHeader`
/// when no Authorization line is present and `MalformedHeader` when
/// the line is present but not `Bearer <non-empty-token>`.
pub fn extract_bearer_token(request: &str) -> Result<&str, AuthError> {
    for line in request.lines() {
        // Headers end at the first empty line.
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let value = value.trim();
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .ok_or(AuthError::MalformedHeader)?
            .trim();
        if token.is_empty() {
            return Err(AuthError::MalformedHeader);
        }
        return Ok(token);
    }
    Err(AuthError::MissingHeader)
}
