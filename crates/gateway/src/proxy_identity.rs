//! Verification of a JWT a client presents at the proxy listener in
//! place of a token issued here.
//!
//! The JWT is one the organization's identity provider issued. Wirken
//! issues none: it checks the signature against the issuer's public
//! keys and the claims against `proxy.json`, and what comes out is who
//! the issuer says the caller is. Which grants that caller gets is the
//! operator's mapping, in [`crate::proxy`].
//!
//! Only public-key signatures are accepted. A JWT signed with a shared
//! secret (`HS256` and its kin) or not signed at all (`none`) is
//! refused before any key is looked at: there is no code path here
//! that verifies either.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature;
use sha2::Sha256;

use wirken_audit::ProxyRefusal;

use crate::proxy::OidcConfig;

/// Every signature algorithm a JWT may be signed with.
pub const ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// The longest JWT that is read.
pub const MAX_JWT_BYTES: usize = 32 * 1024;

/// The longest subject, `jti` or grant-claim value that is used.
pub const MAX_CLAIM_BYTES: usize = 256;

/// A public key of the issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub kid: Option<String>,
    /// The one algorithm the key is for, when its entry names one.
    alg: Option<String>,
    material: Material,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Material {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// An uncompressed point: `0x04 || x || y`.
    P256(Vec<u8>),
    P384(Vec<u8>),
    Ed25519(Vec<u8>),
}

impl Material {
    /// Whether a key of this kind verifies `alg`.
    fn fits(&self, alg: &str) -> bool {
        match self {
            Self::Rsa { .. } => alg.starts_with("RS") || alg.starts_with("PS"),
            Self::P256(_) => alg == "ES256",
            Self::P384(_) => alg == "ES384",
            Self::Ed25519(_) => alg == "EdDSA",
        }
    }
}

/// The issuer's public keys: a JWK set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySet {
    keys: Vec<Key>,
}

fn b64(value: &serde_json::Value) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.as_str()?.trim_end_matches('='))
        .ok()
}

impl KeySet {
    /// Read a JWK set. Entries that are not signing keys of a kind
    /// verified here are left out; a set with none left is refused, and
    /// so is one that holds a private key.
    pub fn parse(json: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("not a JWK set: {e}"))?;
        let entries = value["keys"]
            .as_array()
            .ok_or("not a JWK set: no `keys` list")?;
        let mut keys = Vec::new();
        for entry in entries {
            if entry.get("d").is_some() {
                return Err("the key set holds a private key; it takes public keys only".into());
            }
            if entry["use"].as_str().is_some_and(|u| u != "sig") {
                continue;
            }
            let material = match (entry["kty"].as_str(), entry["crv"].as_str()) {
                (Some("RSA"), _) => match (b64(&entry["n"]), b64(&entry["e"])) {
                    (Some(n), Some(e)) => Material::Rsa { n, e },
                    _ => continue,
                },
                (Some("EC"), Some(crv @ ("P-256" | "P-384"))) => {
                    let size = if crv == "P-256" { 32 } else { 48 };
                    match (b64(&entry["x"]), b64(&entry["y"])) {
                        (Some(x), Some(y)) if x.len() == size && y.len() == size => {
                            let mut point = Vec::with_capacity(1 + 2 * size);
                            point.push(0x04);
                            point.extend_from_slice(&x);
                            point.extend_from_slice(&y);
                            if crv == "P-256" {
                                Material::P256(point)
                            } else {
                                Material::P384(point)
                            }
                        }
                        _ => continue,
                    }
                }
                (Some("OKP"), Some("Ed25519")) => match b64(&entry["x"]) {
                    Some(x) if x.len() == 32 => Material::Ed25519(x),
                    _ => continue,
                },
                _ => continue,
            };
            keys.push(Key {
                kid: entry["kid"].as_str().map(str::to_string),
                alg: entry["alg"].as_str().map(str::to_string),
                material,
            });
        }
        if keys.is_empty() {
            return Err("the key set holds no RSA, P-256, P-384 or Ed25519 signing key".into());
        }
        Ok(Self { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The key a JWT signed with `alg` under `kid` is verified with. A
    /// JWT that names no key is verified with the one key that fits
    /// its algorithm, and with none when more than one does.
    fn find(&self, kid: Option<&str>, alg: &str) -> Option<&Key> {
        let mut fitting = self
            .keys
            .iter()
            .filter(|k| k.material.fits(alg) && k.alg.as_deref().is_none_or(|a| a == alg));
        match kid {
            Some(kid) => fitting.find(|k| k.kid.as_deref() == Some(kid)),
            None => {
                let first = fitting.next()?;
                fitting.next().is_none().then_some(first)
            }
        }
    }
}

/// Why a JWT was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// Not three base64url parts holding a JSON header and claims.
    Malformed(&'static str),
    /// An algorithm that is not accepted, with its name.
    Algorithm(String),
    /// No key of the issuer is the one the JWT names.
    UnknownKey(Option<String>),
    /// The signature is not the key's over this JWT.
    Signature,
    /// A claim that is needed is missing or is not what it must be.
    Claim(&'static str),
    /// `nbf` or `iat` is ahead of this host's clock.
    NotYetValid,
    /// Past `exp`.
    Expired,
    /// Issued longer ago than the configured maximum lifetime.
    TooOld,
    WrongIssuer,
    WrongAudience,
}

impl JwtError {
    /// The reason on the `proxy_refused` row.
    pub fn refusal(&self) -> ProxyRefusal {
        match self {
            Self::Expired | Self::TooOld => ProxyRefusal::JwtExpired,
            Self::WrongIssuer => ProxyRefusal::JwtWrongIssuer,
            Self::WrongAudience => ProxyRefusal::JwtWrongAudience,
            Self::Malformed(_)
            | Self::Algorithm(_)
            | Self::UnknownKey(_)
            | Self::Signature
            | Self::Claim(_)
            | Self::NotYetValid => ProxyRefusal::JwtInvalid,
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "the JWT is malformed: {why}"),
            Self::Algorithm(alg) => {
                write!(f, "the JWT is signed with {alg:?}, which is not accepted")
            }
            Self::UnknownKey(Some(kid)) => write!(f, "the issuer has no key {kid:?}"),
            Self::UnknownKey(None) => write!(
                f,
                "the JWT names no key and the issuer has not exactly one for its algorithm"
            ),
            Self::Signature => write!(f, "the JWT's signature does not verify"),
            Self::Claim(why) => write!(f, "the JWT's claims: {why}"),
            Self::NotYetValid => write!(f, "the JWT is not valid yet"),
            Self::Expired => write!(f, "the JWT has expired"),
            Self::TooOld => write!(
                f,
                "the JWT was issued longer ago than the maximum lifetime allows"
            ),
            Self::WrongIssuer => write!(f, "the JWT is from another issuer"),
            Self::WrongAudience => write!(f, "the JWT is for another audience"),
        }
    }
}

/// What a verified JWT says of its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub subject: String,
    pub jti: Option<String>,
    /// The values of the configured grant claim. Empty when no claim
    /// is configured or the JWT has none.
    pub claim_values: Vec<String>,
}

/// The JWT's three parts, before anything is believed.
struct Parts<'a> {
    alg: String,
    kid: Option<String>,
    claims: serde_json::Value,
    signed: &'a [u8],
    signature: Vec<u8>,
}

fn split(jwt: &str) -> Result<Parts<'_>, JwtError> {
    if jwt.len() > MAX_JWT_BYTES {
        return Err(JwtError::Malformed("it is too long"));
    }
    let mut parts = jwt.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed("it is not three parts"));
    };
    let decode = |part: &str, what: &'static str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| JwtError::Malformed(what))
    };
    let header: serde_json::Value =
        serde_json::from_slice(&decode(header, "the header is not base64url")?)
            .map_err(|_| JwtError::Malformed("the header is not JSON"))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode(payload, "the claims are not base64url")?)
            .map_err(|_| JwtError::Malformed("the claims are not JSON"))?;
    if !header.is_object() || !claims.is_object() {
        return Err(JwtError::Malformed(
            "the header or the claims are not an object",
        ));
    }
    // A header parameter the verifier must understand, and none is.
    if header.get("crit").is_some() {
        return Err(JwtError::Malformed("it carries a `crit` header"));
    }
    let alg = header["alg"]
        .as_str()
        .ok_or(JwtError::Malformed("the header names no algorithm"))?
        .to_string();
    Ok(Parts {
        alg,
        kid: header["kid"].as_str().map(str::to_string),
        claims,
        // The signature is over the first two parts as they were sent.
        signed: &jwt.as_bytes()[..jwt.len() - signature.len() - 1],
        signature: decode(signature, "the signature is not base64url")?,
    })
}

/// Whether `signature` is `key`'s over `signed`, under `alg`.
fn signature_holds(key: &Key, alg: &str, signed: &[u8], signature: &[u8]) -> bool {
    match &key.material {
        Material::Rsa { n, e } => {
            let params: &signature::RsaParameters = match alg {
                "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
                "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
                "PS512" => &signature::RSA_PSS_2048_8192_SHA512,
                _ => return false,
            };
            signature::RsaPublicKeyComponents { n, e }
                .verify(params, signed, signature)
                .is_ok()
        }
        Material::P256(point) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(signed, signature)
                .is_ok()
        }
        Material::P384(point) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point)
                .verify(signed, signature)
                .is_ok()
        }
        Material::Ed25519(key) => signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(signed, signature)
            .is_ok(),
    }
}

/// A NumericDate claim, in whole seconds.
fn seconds(claim: &serde_json::Value) -> Option<i64> {
    claim
        .as_i64()
        .or_else(|| claim.as_f64().map(|f| f.floor() as i64))
}

/// A claim that is a string or a list of strings, as its strings.
fn strings(claim: &serde_json::Value) -> Vec<&str> {
    match claim {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(list) => list.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

/// Verify `jwt` against the issuer's `keys` and `config`, at `now`
/// (seconds since the epoch).
///
/// The issuer is compared first, so a JWT of another issuer is not a
/// reason to look for a key. Then the algorithm, the key and the
/// signature, and only then the claims a signature makes believable.
pub fn verify(
    jwt: &str,
    keys: &KeySet,
    config: &OidcConfig,
    now: i64,
) -> Result<Verified, JwtError> {
    let parts = split(jwt)?;
    if parts.claims["iss"].as_str() != Some(config.issuer.as_str()) {
        return Err(JwtError::WrongIssuer);
    }
    if !config.accepts(&parts.alg) {
        return Err(JwtError::Algorithm(parts.alg));
    }
    let key = keys
        .find(parts.kid.as_deref(), &parts.alg)
        .ok_or_else(|| JwtError::UnknownKey(parts.kid.clone()))?;
    if !signature_holds(key, &parts.alg, parts.signed, &parts.signature) {
        return Err(JwtError::Signature);
    }

    let claims = &parts.claims;
    if !strings(&claims["aud"]).contains(&config.audience.as_str()) {
        return Err(JwtError::WrongAudience);
    }
    let skew = config.clock_skew_secs as i64;
    let exp = seconds(&claims["exp"]).ok_or(JwtError::Claim("no `exp`"))?;
    let iat = seconds(&claims["iat"]).ok_or(JwtError::Claim(
        "no `iat`, so its age cannot be held to the maximum lifetime",
    ))?;
    if iat > now + skew {
        return Err(JwtError::NotYetValid);
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = seconds(nbf).ok_or(JwtError::Claim("`nbf` is not a time"))?;
        if nbf > now + skew {
            return Err(JwtError::NotYetValid);
        }
    }
    if now > exp.saturating_add(skew) {
        return Err(JwtError::Expired);
    }
    let lifetime = i64::try_from(config.max_token_lifetime_secs).unwrap_or(i64::MAX);
    if now > iat.saturating_add(lifetime).saturating_add(skew) {
        return Err(JwtError::TooOld);
    }
    let subject = claims["sub"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= MAX_CLAIM_BYTES)
        .ok_or(JwtError::Claim("no `sub`, or one over 256 bytes"))?
        .to_string();
    let jti = match claims.get("jti") {
        None | Some(serde_json::Value::Null) => None,
        Some(jti) => Some(
            jti.as_str()
                .filter(|s| !s.is_empty() && s.len() <= MAX_CLAIM_BYTES)
                .ok_or(JwtError::Claim("`jti` is not a string of 1 to 256 bytes"))?
                .to_string(),
        ),
    };
    let claim_values = config
        .grant_claim
        .as_deref()
        .map(|name| {
            strings(&claims[name])
                .into_iter()
                .filter(|v| !v.is_empty() && v.len() <= MAX_CLAIM_BYTES)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(Verified {
        subject,
        jti,
        claim_values,
    })
}

/// Whether `presented` has the outline of a JWT: three parts, the
/// first a base64url JSON object. A token issued here never has.
pub fn looks_like_jwt(presented: &str) -> bool {
    let mut parts = presented.split('.');
    let (Some(header), Some(_), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok())
        .is_some_and(|h| h.is_object())
}

/// The keyed hash a subject is recorded as: HMAC-SHA256 under `key` of
/// the issuer and the subject, in hex. The same subject of another
/// issuer hashes differently, and without the key a hash cannot be
/// tried against a list of names.
pub fn subject_hash(key: &[u8], issuer: &str, subject: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(issuer.as_bytes());
    mac.update(&[0]);
    mac.update(subject.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The id a subject's calls are kept under: its lanes, its call count
/// and its spend. `u` and the first sixteen characters of the
/// subject's hash, so it is never the id of a token, which is eight
/// hex characters.
pub fn subject_id(subject_hash: &str) -> String {
    let head: String = subject_hash.chars().take(16).collect();
    format!("u{head}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair};

    const ISSUER: &str = "https://idp.example.com/realms/acme";
    const AUDIENCE: &str = "wirken-proxy";
    const NOW: i64 = 1_800_000_000;

    /// A 2048-bit RSA key made for tests, shared with the Teams
    /// adapter's JWT tests.
    const RSA_PKCS8: &[u8] = include_bytes!("../../adapter-teams/src/test_rsa_legit.pkcs8.der");
    const OTHER_RSA_PKCS8: &[u8] =
        include_bytes!("../../adapter-teams/src/test_rsa_attacker.pkcs8.der");

    fn config() -> OidcConfig {
        serde_json::from_value(serde_json::json!({
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "max_token_lifetime_secs": 3600,
            "grant_claim": "groups",
        }))
        .unwrap()
    }

    fn enc(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "alice",
            "iat": NOW - 60, "exp": NOW + 240, "jti": "j-1",
            "groups": ["engineers", "oncall"],
        })
    }

    /// One signer per algorithm family, with the JWK its issuer would
    /// publish.
    enum Signer {
        Rsa(RsaKeyPair),
        P256(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    impl Signer {
        fn rsa(pkcs8: &[u8]) -> Self {
            Self::Rsa(RsaKeyPair::from_pkcs8(pkcs8).unwrap())
        }

        fn p256() -> Self {
            let rng = SystemRandom::new();
            let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            Self::P256(EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap())
        }

        fn ed() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        fn jwk(&self, kid: &str) -> serde_json::Value {
            match self {
                Self::Rsa(pair) => {
                    let public = signature::RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
                    serde_json::json!({
                        "kty": "RSA", "kid": kid, "use": "sig",
                        "n": enc(&public.n), "e": enc(&public.e),
                    })
                }
                Self::P256(pair) => {
                    let point = pair.public_key().as_ref();
                    serde_json::json!({
                        "kty": "EC", "crv": "P-256", "kid": kid,
                        "x": enc(&point[1..33]), "y": enc(&point[33..]),
                    })
                }
                Self::Ed(pair) => serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "kid": kid,
                    "x": enc(pair.public_key().as_ref()),
                }),
            }
        }

        fn sign(&self, alg: &str, signed: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                Self::Rsa(pair) => {
                    let padding: &dyn signature::RsaEncoding = match alg {
                        "RS256" => &signature::RSA_PKCS1_SHA256,
                        "RS384" => &signature::RSA_PKCS1_SHA384,
                        "RS512" => &signature::RSA_PKCS1_SHA512,
                        "PS256" => &signature::RSA_PSS_SHA256,
                        "PS384" => &signature::RSA_PSS_SHA384,
                        _ => &signature::RSA_PSS_SHA512,
                    };
                    let mut out = vec![0; pair.public().modulus_len()];
                    pair.sign(padding, &rng, signed, &mut out).unwrap();
                    out
                }
                Self::P256(pair) => pair.sign(&rng, signed).unwrap().as_ref().to_vec(),
                Self::Ed(pair) => pair.sign(signed).as_ref().to_vec(),
            }
        }

        /// A JWT with this header and these claims, signed.
        fn jwt(&self, header: serde_json::Value, claims: &serde_json::Value) -> String {
            let signed = format!(
                "{}.{}",
                enc(header.to_string().as_bytes()),
                enc(claims.to_string().as_bytes())
            );
            let alg = header["alg"].as_str().unwrap_or("RS256").to_string();
            let signature = self.sign(&alg, signed.as_bytes());
            format!("{signed}.{}", enc(&signature))
        }
    }

    fn set(keys: &[serde_json::Value]) -> KeySet {
        KeySet::parse(&serde_json::json!({ "keys": keys }).to_string()).unwrap()
    }

    fn header(alg: &str, kid: &str) -> serde_json::Value {
        serde_json::json!({"alg": alg, "kid": kid, "typ": "JWT"})
    }

    #[test]
    fn a_jwt_signed_by_the_issuers_key_is_verified_under_each_algorithm() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let ec = Signer::p256();
        let ed = Signer::ed();
        let keys = set(&[rsa.jwk("r"), ec.jwk("e"), ed.jwk("d")]);
        for (signer, alg, kid) in [
            (&rsa, "RS256", "r"),
            (&rsa, "RS384", "r"),
            (&rsa, "RS512", "r"),
            (&rsa, "PS256", "r"),
            (&rsa, "PS384", "r"),
            (&rsa, "PS512", "r"),
            (&ec, "ES256", "e"),
            (&ed, "EdDSA", "d"),
        ] {
            let jwt = signer.jwt(header(alg, kid), &claims());
            let verified = verify(&jwt, &keys, &config(), NOW).unwrap_or_else(|e| {
                panic!("{alg}: {e}");
            });
            assert_eq!(verified.subject, "alice", "{alg}");
            assert_eq!(verified.jti.as_deref(), Some("j-1"));
            assert_eq!(verified.claim_values, ["engineers", "oncall"]);
        }
    }

    /// `HS256` with the public key as the secret, and `none`: neither
    /// is an algorithm, whatever the configuration lists.
    #[test]
    fn a_shared_secret_or_unsigned_jwt_is_refused_and_cannot_be_configured() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        for alg in ["HS256", "HS384", "HS512", "none", "None", "rs256", ""] {
            let jwt = rsa.jwt(header(alg, "r"), &claims());
            assert_eq!(
                verify(&jwt, &keys, &config(), NOW),
                Err(JwtError::Algorithm(alg.to_string())),
                "{alg}"
            );
        }
        // An unsigned JWT as it is sent: an empty third part.
        let unsigned = format!(
            "{}.{}.",
            enc(br#"{"alg":"none"}"#),
            enc(claims().to_string().as_bytes())
        );
        assert_eq!(
            verify(&unsigned, &keys, &config(), NOW),
            Err(JwtError::Algorithm("none".into()))
        );

        for alg in ["HS256", "none"] {
            let refused = serde_json::from_value::<crate::proxy::ProxyConfig>(serde_json::json!({
                "upstreams": {"local": {"provider": "ollama", "base_url": "http://localhost:1/v1"}},
                "oidc": {
                    "issuer": ISSUER, "audience": AUDIENCE,
                    "max_token_lifetime_secs": 3600, "algorithms": [alg],
                },
            }))
            .unwrap();
            let why = refused.oidc.unwrap().validate_for_test().unwrap_err();
            assert!(why.contains("is not accepted"), "{why}");
        }
    }

    #[test]
    fn the_configured_algorithms_narrow_what_is_accepted() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        let mut only_ps = config();
        only_ps.algorithms = vec!["PS256".into()];
        assert!(
            verify(
                &rsa.jwt(header("PS256", "r"), &claims()),
                &keys,
                &only_ps,
                NOW
            )
            .is_ok()
        );
        assert_eq!(
            verify(
                &rsa.jwt(header("RS256", "r"), &claims()),
                &keys,
                &only_ps,
                NOW
            ),
            Err(JwtError::Algorithm("RS256".into()))
        );
    }

    #[test]
    fn a_signature_by_another_key_or_over_other_claims_is_refused() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let other = Signer::rsa(OTHER_RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        // Another key, claiming the issuer's key id.
        let forged = other.jwt(header("RS256", "r"), &claims());
        assert_eq!(
            verify(&forged, &keys, &config(), NOW),
            Err(JwtError::Signature)
        );
        // The issuer's signature, with the claims changed after it.
        let jwt = rsa.jwt(header("RS256", "r"), &claims());
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let mut changed = claims();
        changed["sub"] = "mallory".into();
        let changed = enc(changed.to_string().as_bytes());
        parts[1] = &changed;
        assert_eq!(
            verify(&parts.join("."), &keys, &config(), NOW),
            Err(JwtError::Signature)
        );
        // A key id the issuer does not have.
        assert_eq!(
            verify(
                &rsa.jwt(header("RS256", "gone"), &claims()),
                &keys,
                &config(),
                NOW
            ),
            Err(JwtError::UnknownKey(Some("gone".into())))
        );
    }

    #[test]
    fn a_jwt_that_names_no_key_is_verified_only_where_one_key_fits() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let other = Signer::rsa(OTHER_RSA_PKCS8);
        let jwt = rsa.jwt(serde_json::json!({"alg": "RS256"}), &claims());
        assert!(verify(&jwt, &set(&[rsa.jwk("r")]), &config(), NOW).is_ok());
        assert_eq!(
            verify(&jwt, &set(&[rsa.jwk("r"), other.jwk("o")]), &config(), NOW),
            Err(JwtError::UnknownKey(None))
        );
    }

    #[test]
    fn issuer_and_audience_are_held_to_the_configuration() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        let with = |name: &str, value: serde_json::Value| {
            let mut c = claims();
            c[name] = value;
            verify(&rsa.jwt(header("RS256", "r"), &c), &keys, &config(), NOW)
        };
        assert_eq!(
            with("iss", "https://idp.example.com/realms/other".into()),
            Err(JwtError::WrongIssuer)
        );
        // A trailing slash is another issuer.
        assert_eq!(
            with("iss", format!("{ISSUER}/").into()),
            Err(JwtError::WrongIssuer)
        );
        assert_eq!(
            with("aud", "another-service".into()),
            Err(JwtError::WrongAudience)
        );
        assert_eq!(
            with("aud", serde_json::json!(["a", "b"])),
            Err(JwtError::WrongAudience)
        );
        assert_eq!(
            with("aud", serde_json::Value::Null),
            Err(JwtError::WrongAudience)
        );
        assert!(with("aud", serde_json::json!(["a", AUDIENCE])).is_ok());
    }

    #[test]
    fn a_jwt_is_good_between_its_issue_and_the_earlier_of_its_expiry_and_the_maximum_lifetime() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        let at = |iat: i64, exp: i64, now: i64| {
            let mut c = claims();
            c["iat"] = iat.into();
            c["exp"] = exp.into();
            verify(&rsa.jwt(header("RS256", "r"), &c), &keys, &config(), now)
        };
        // Skew is sixty seconds; the maximum lifetime an hour.
        assert!(at(NOW, NOW + 300, NOW + 300 + 60).is_ok());
        assert_eq!(at(NOW, NOW + 300, NOW + 300 + 61), Err(JwtError::Expired));
        // A day-long JWT stops at the hour.
        assert!(at(NOW, NOW + 86_400, NOW + 3600 + 60).is_ok());
        assert_eq!(
            at(NOW, NOW + 86_400, NOW + 3600 + 61),
            Err(JwtError::TooOld)
        );
        // Issued ahead of this clock by more than the skew.
        assert!(at(NOW + 60, NOW + 300, NOW).is_ok());
        assert_eq!(at(NOW + 61, NOW + 300, NOW), Err(JwtError::NotYetValid));

        let without = |name: &str| {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(name);
            verify(&rsa.jwt(header("RS256", "r"), &c), &keys, &config(), NOW)
        };
        assert!(matches!(without("exp"), Err(JwtError::Claim(_))));
        assert!(matches!(without("iat"), Err(JwtError::Claim(_))));
        assert!(matches!(without("sub"), Err(JwtError::Claim(_))));
        assert_eq!(without("jti").unwrap().jti, None);

        let mut early = claims();
        early["nbf"] = (NOW + 61).into();
        assert_eq!(
            verify(
                &rsa.jwt(header("RS256", "r"), &early),
                &keys,
                &config(),
                NOW
            ),
            Err(JwtError::NotYetValid)
        );
    }

    #[test]
    fn the_grant_claim_is_a_string_or_a_list_and_absent_without_configuration() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        let values = |groups: serde_json::Value, config: &OidcConfig| {
            let mut c = claims();
            c["groups"] = groups;
            verify(&rsa.jwt(header("RS256", "r"), &c), &keys, config, NOW)
                .unwrap()
                .claim_values
        };
        assert_eq!(values("engineers".into(), &config()), ["engineers"]);
        assert_eq!(
            values(serde_json::json!(["a", 7, "", "b"]), &config()),
            ["a", "b"]
        );
        assert!(values(serde_json::json!({"a": 1}), &config()).is_empty());
        let mut no_claim = config();
        no_claim.grant_claim = None;
        assert!(values("engineers".into(), &no_claim).is_empty());
    }

    #[test]
    fn what_is_not_a_jwt_is_malformed() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let keys = set(&[rsa.jwk("r")]);
        let good = rsa.jwt(header("RS256", "r"), &claims());
        for bad in [
            "wkp_0a0a0a0a_ff".to_string(),
            "a.b".to_string(),
            format!("{good}.more"),
            "!!.!!.!!".to_string(),
            format!("{}.{}.x", enc(b"[]"), enc(b"{}")),
            "x".repeat(MAX_JWT_BYTES + 1),
        ] {
            assert!(
                matches!(
                    verify(&bad, &keys, &config(), NOW),
                    Err(JwtError::Malformed(_))
                ),
                "{}",
                &bad[..bad.len().min(40)]
            );
        }
        let crit = rsa.jwt(
            serde_json::json!({"alg": "RS256", "kid": "r", "crit": ["x"]}),
            &claims(),
        );
        assert!(matches!(
            verify(&crit, &keys, &config(), NOW),
            Err(JwtError::Malformed(_))
        ));
        assert!(looks_like_jwt(&good));
        assert!(!looks_like_jwt("wkp_0a0a0a0a_ff"));
        assert!(!looks_like_jwt("a.b.c"));
    }

    #[test]
    fn a_key_set_takes_public_signing_keys_only() {
        let rsa = Signer::rsa(RSA_PKCS8);
        let mut private = rsa.jwk("r");
        private["d"] = "AAAA".into();
        let refused = KeySet::parse(&serde_json::json!({"keys": [private]}).to_string());
        assert!(refused.unwrap_err().contains("private key"));

        let mut encryption = rsa.jwk("enc");
        encryption["use"] = "enc".into();
        let symmetric = serde_json::json!({"kty": "oct", "kid": "s", "k": "AAAA"});
        let only_unusable =
            KeySet::parse(&serde_json::json!({"keys": [encryption, symmetric]}).to_string());
        assert!(only_unusable.unwrap_err().contains("no RSA"));

        assert_eq!(set(&[rsa.jwk("r"), Signer::ed().jwk("d")]).len(), 2);
        assert!(KeySet::parse("{}").is_err());

        // A key its entry gives to one algorithm verifies no other.
        let mut pinned = rsa.jwk("r");
        pinned["alg"] = "PS256".into();
        let keys = set(&[pinned]);
        assert_eq!(
            verify(
                &rsa.jwt(header("RS256", "r"), &claims()),
                &keys,
                &config(),
                NOW
            ),
            Err(JwtError::UnknownKey(Some("r".into())))
        );
    }

    #[test]
    fn a_subject_hash_is_keyed_and_bound_to_the_issuer() {
        let hash = subject_hash(&[1; 32], ISSUER, "alice");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, subject_hash(&[1; 32], ISSUER, "alice"));
        assert_ne!(hash, subject_hash(&[2; 32], ISSUER, "alice"));
        assert_ne!(
            hash,
            subject_hash(&[1; 32], "https://other.example", "alice")
        );
        assert_ne!(hash, subject_hash(&[1; 32], ISSUER, "bob"));
        let id = subject_id(&hash);
        assert_eq!(id.len(), 17);
        assert!(id.starts_with('u') && hash.starts_with(&id[1..]));
    }

    #[test]
    fn each_error_has_its_refusal_reason() {
        for (error, reason) in [
            (JwtError::Signature, ProxyRefusal::JwtInvalid),
            (JwtError::Algorithm("none".into()), ProxyRefusal::JwtInvalid),
            (JwtError::NotYetValid, ProxyRefusal::JwtInvalid),
            (JwtError::Expired, ProxyRefusal::JwtExpired),
            (JwtError::TooOld, ProxyRefusal::JwtExpired),
            (JwtError::WrongIssuer, ProxyRefusal::JwtWrongIssuer),
            (JwtError::WrongAudience, ProxyRefusal::JwtWrongAudience),
        ] {
            assert_eq!(error.refusal(), reason, "{error}");
        }
    }
}
