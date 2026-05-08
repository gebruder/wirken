//! Inbound JWT validation for the Google Chat webhook.
//!
//! Google signs every inbound Chat event with a JWT in the
//! `Authorization: Bearer` header. The JWT is signed with one of
//! Google's rotating RSA keys, published at the service account's
//! JWKS endpoint. Without verification the webhook accepts any POST
//! matching the Chat event shape and any attacker reachable to the
//! listening socket can impersonate any Google Chat user or space.
//!
//! The issuer is `chat@system.gserviceaccount.com` and the audience
//! must equal the Chat app's project number as configured in Google
//! Cloud. Both are enforced here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::AuthError;

/// The Google Chat service-account issuer. Every inbound event's
/// JWT must have this as its `iss` claim.
pub const CHAT_ISSUER: &str = "chat@system.gserviceaccount.com";

/// JWKS URL for the Chat service account. Keys rotate; we refresh
/// on staleness or on a kid-miss.
pub const JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/chat@system.gserviceaccount.com";

/// Hard refresh interval. Google rotates keys periodically with an
/// overlap window; we refresh once a day to pick up new keys ahead
/// of first use and drop retired ones.
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Clock skew leeway applied to `exp` validation, in seconds.
const EXP_LEEWAY_SECS: i64 = 60;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
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

/// JWKS cache and JWT validator for Google Chat inbound tokens.
pub struct JwksCache {
    state: Arc<RwLock<CacheState>>,
    http: reqwest::Client,
    jwks_url: String,
    accepted_issuers: Vec<String>,
}

impl JwksCache {
    /// Production constructor. Uses the documented Google Chat JWKS
    /// URL and accepts the Chat service account issuer.
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            state: Arc::new(RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
            })),
            http,
            jwks_url: JWKS_URL.into(),
            accepted_issuers: vec![CHAT_ISSUER.into()],
        }
    }

    /// Validate an inbound bearer token. Returns the validated
    /// claims on success. On failure, returns a specific reason for
    /// logs; callers should always return a generic 401 on the wire.
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
        let jwks: Jwks = self
            .http
            .get(&self.jwks_url)
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
            jwks_url: String::new(),
            accepted_issuers: vec![issuer.to_string()],
        }
    }
}

/// Extract the bearer token from a raw HTTP request buffer.
pub fn extract_bearer_token(request: &str) -> Result<&str, AuthError> {
    for line in request.lines() {
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
