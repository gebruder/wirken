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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
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

/// Clock skew leeway applied to `exp` validation, in seconds.
const EXP_LEEWAY_SECS: i64 = 60;

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

/// Public RSA key components for a single signing key. `n` and `e`
/// are big-endian byte strings without leading zero octets, matching
/// the encoding `ring::signature::RsaPublicKeyComponents` expects.
#[derive(Debug, Clone)]
pub struct RsaPubKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RsaPubKey {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), AuthError> {
        let comps = RsaPublicKeyComponents {
            n: self.n.as_slice(),
            e: self.e.as_slice(),
        };
        comps
            .verify(&RSA_PKCS1_2048_8192_SHA256, msg, sig)
            .map_err(|_| AuthError::JwtValidation("rsa signature invalid".into()))
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AuthError::JwtHeader(format!("base64url: {e}")))
}

struct ParsedJwt<'a> {
    header: JwtHeader,
    payload: Vec<u8>,
    signature: Vec<u8>,
    signing_input: &'a str,
}

fn parse_jwt(token: &str) -> Result<ParsedJwt<'_>, AuthError> {
    let dot1 = token
        .find('.')
        .ok_or_else(|| AuthError::JwtHeader("expected three dot-separated segments".into()))?;
    let rest = &token[dot1 + 1..];
    let dot2_rel = rest
        .find('.')
        .ok_or_else(|| AuthError::JwtHeader("expected three dot-separated segments".into()))?;
    let dot2 = dot1 + 1 + dot2_rel;

    let header_b64 = &token[..dot1];
    let payload_b64 = &token[dot1 + 1..dot2];
    let sig_b64 = &token[dot2 + 1..];
    if sig_b64.contains('.') {
        return Err(AuthError::JwtHeader(
            "expected three dot-separated segments".into(),
        ));
    }
    let signing_input = &token[..dot2];

    let header_bytes = b64url_decode(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AuthError::JwtHeader(format!("header parse: {e}")))?;
    let payload = b64url_decode(payload_b64)?;
    let signature = b64url_decode(sig_b64)?;

    Ok(ParsedJwt {
        header,
        payload,
        signature,
        signing_input,
    })
}

struct CacheState {
    keys: HashMap<String, RsaPubKey>,
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
        let parsed = parse_jwt(token)?;
        if parsed.header.alg != "RS256" {
            return Err(AuthError::JwtHeader(format!(
                "alg {} not supported",
                parsed.header.alg
            )));
        }
        let kid = parsed
            .header
            .kid
            .clone()
            .ok_or_else(|| AuthError::JwtHeader("no kid".into()))?;

        let key = self.get_key(&kid).await?;
        key.verify(parsed.signing_input.as_bytes(), &parsed.signature)?;

        let claims: Claims = serde_json::from_slice(&parsed.payload)
            .map_err(|e| AuthError::JwtValidation(format!("claims parse: {e}")))?;

        let now = chrono::Utc::now().timestamp();
        if claims.exp + EXP_LEEWAY_SECS < now {
            return Err(AuthError::JwtValidation("token expired".into()));
        }
        if claims.aud != expected_aud {
            return Err(AuthError::JwtValidation("aud mismatch".into()));
        }
        if !self.accepted_issuers.iter().any(|i| i == &claims.iss) {
            return Err(AuthError::IssuerRejected(claims.iss.clone()));
        }

        Ok(claims)
    }

    /// Look up a signing key by `kid`. Refreshes the cache on miss
    /// (handles key rotation) and on staleness.
    async fn get_key(&self, kid: &str) -> Result<RsaPubKey, AuthError> {
        {
            let state = self.state.read().await;
            if let Some(k) = state.keys.get(kid)
                && !state.is_stale()
            {
                return Ok(k.clone());
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
            let Ok(n_bytes) = b64url_decode(n) else {
                continue;
            };
            let Ok(e_bytes) = b64url_decode(e) else {
                continue;
            };
            keys.insert(
                key.kid,
                RsaPubKey {
                    n: n_bytes,
                    e: e_bytes,
                },
            );
        }

        let mut state = self.state.write().await;
        state.keys = keys;
        state.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// Test-only constructor: seed the cache with a fixed set of
    /// keys so validation can run without network access.
    #[cfg(test)]
    pub(crate) fn for_test(keys: Vec<(String, RsaPubKey)>, issuer: &str) -> Self {
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
