//! Signature verification for `mcp.json` entries. Twin of
//! [`wirken_gateway::skill_registry`] for the MCP surface.
//!
//! Skills carry signatures as on-disk `SKILL.sig` / `SKILL.pub` files
//! that the loader checks on every agent wake. MCP entries are inline
//! in `mcp.json`: a signature is an optional field on the entry
//! struct, the public key is either inline on the same entry or
//! delegated by a compile-time-bundled root in
//! `wirken-mcp-pubkey.pub`. The proxy calls
//! [`verify_mcp_entry`] before each [`crate::mcp_transport`] spawn or
//! HTTP transport construction; an entry that fails verification
//! never reaches the spawn path.
//!
//! ## Trust model
//!
//! - **No compile-time anchor (default build, `wirken-mcp-pubkey.pub`
//!   empty).** [`bundled_mcp_pubkey`] returns `None`. An unsigned
//!   entry loads (pre-anchor parity). A signed entry verifies
//!   against its inline `signer_key`. An invalid signature is a hard
//!   fail.
//! - **Compile-time anchor present.** An unsigned entry refuses to
//!   load unless `WIRKEN_ALLOW_UNSIGNED_MCP=1` is set (the bypass is
//!   logged and recorded on the chain as
//!   [`SessionEvent::McpEntryVerified`] with signer
//!   `"<unsigned-bypass>"`; bypass for missing signatures, never for
//!   bad ones). A signed entry must additionally carry a
//!   `signer_key_delegation` Ed25519 signature by the bundled root
//!   over the raw 32-byte `signer_key`.
//!
//! Anchor rotation requires rebuilding the binary against a fresh
//! `wirken-mcp-pubkey.pub`. The bundled root is meaningful only when
//! the binary itself is what an attacker cannot replace without
//! operator action; an anchor file at the same UID as the gateway
//! would not survive a same-UID attacker.
//!
//! ## Signed payload
//!
//! [`hash_mcp_entry`] defines the canonical hash. The hash covers
//! the load-bearing surface of the entry config:
//!
//! - **Stdio:** `sha256("stdio\0" || name_len_le || name ||
//!   command_len_le || command || arg_count_le || (per-arg
//!   arg_len_le || arg) || env_count_le || (per-env key_len_le ||
//!   key))`. Env keys, not env values: values are `vault:NAME`
//!   references the proxy resolves at load time; the signature
//!   must remain stable across vault rotations of the same logical
//!   credential.
//! - **Http:** `sha256("http\0" || name_len_le || name ||
//!   url_len_le || url || auth_kind_le)` where `auth_kind_le` is
//!   `u8`: 0 = none, 1 = bearer, 2 = oauth2. The credential ref is
//!   not in the payload for the same reason as env values.
//!
//! Null separators and length prefixes prevent content-boundary
//! confusion. Env keys are sorted ascending before hashing so the
//! signature is stable across `serde_json` map orderings.
//!
//! ## What the signature attests
//!
//! "This is the entry config the publisher intended." It does not
//! attest to the binary at `command` resolving to a specific
//! artifact on disk: a signed entry whose command is
//! `/usr/local/bin/foo` verifies the same on two operator machines
//! where `foo` is built differently. Per-binary attestation is a
//! separate concern (operator's own package manager, sandboxing
//! posture, etc.).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ProxyError;
use crate::mcp_config::{HttpTransportTag, McpAuth, McpServerConfig, StdioTransportTag};

/// Compile-time-bundled hex-encoded Ed25519 public key of the wirken
/// MCP-anchor root. Empty string means "no root anchor configured
/// in this build" — the verification path then falls back to
/// trusting the entry's inline `signer_key` directly, which is the
/// pre-anchor behavior.
///
/// Rotation requires rebuilding the binary against a fresh key file.
pub const BUNDLED_MCP_PUBKEY_HEX: &str = include_str!("wirken-mcp-pubkey.pub");

/// Parse the bundled root key into a [`VerifyingKey`]. Returns `None`
/// when the file is empty (build without MCP anchor) or when the
/// content does not parse as a 32-byte hex Ed25519 key (corrupt
/// bundle; treated as no-anchor and a runtime warn).
pub fn bundled_mcp_pubkey() -> Option<VerifyingKey> {
    let trimmed = BUNDLED_MCP_PUBKEY_HEX.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() != 64 {
        tracing::warn!(
            len = trimmed.len(),
            "bundled MCP pubkey has unexpected length; ignoring \
             and falling back to per-entry signer_key trust"
        );
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => return None,
        };
        bytes[i] = match u8::from_str_radix(s, 16) {
            Ok(b) => b,
            Err(_) => return None,
        };
    }
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Sentinel for the `auth_kind_le` byte in the HTTP hash payload.
/// Distinct values for None / Bearer / OAuth2 so a config that
/// silently drops the auth block does not produce the same hash as
/// one that explicitly declared no auth.
const AUTH_KIND_NONE: u8 = 0;
const AUTH_KIND_BEARER: u8 = 1;
const AUTH_KIND_OAUTH2: u8 = 2;

/// Compute the canonical signed hash for an MCP entry. Layout is
/// documented at the module level. The hash binds the entry's
/// `name` so an attacker cannot lift a signature off one entry and
/// paste it onto another with the same command but a different
/// public name.
pub fn hash_mcp_entry(name: &str, config: &McpServerConfig) -> Vec<u8> {
    let mut hasher = Sha256::new();
    match config {
        McpServerConfig::Stdio {
            command, args, env, ..
        } => {
            hasher.update(b"stdio\0");
            write_len_prefixed(&mut hasher, name.as_bytes());
            write_len_prefixed(&mut hasher, command.as_bytes());
            hasher.update((args.len() as u32).to_le_bytes());
            for arg in args {
                write_len_prefixed(&mut hasher, arg.as_bytes());
            }
            // Sort env keys before hashing so the signature is stable
            // across HashMap iteration orders. Values are intentionally
            // not part of the payload (vault: indirection rotates them).
            let mut keys: Vec<&String> = env.keys().collect();
            keys.sort();
            hasher.update((keys.len() as u32).to_le_bytes());
            for k in keys {
                write_len_prefixed(&mut hasher, k.as_bytes());
            }
        }
        McpServerConfig::Http { url, auth, .. } => {
            hasher.update(b"http\0");
            write_len_prefixed(&mut hasher, name.as_bytes());
            write_len_prefixed(&mut hasher, url.as_bytes());
            let auth_kind = match auth {
                None => AUTH_KIND_NONE,
                Some(McpAuth::Bearer { .. }) => AUTH_KIND_BEARER,
                Some(McpAuth::Oauth2 { .. }) => AUTH_KIND_OAUTH2,
            };
            hasher.update([auth_kind]);
        }
    }
    hasher.finalize().to_vec()
}

fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

/// Sign an MCP entry with `signing_key`. Returns the hex-encoded
/// 64-byte Ed25519 signature; the caller pairs it with the signer's
/// public key (hex-encoded 32-byte) on the entry's `signer_key` field
/// to produce a verifiable record.
pub fn sign_mcp_entry(name: &str, config: &McpServerConfig, signing_key: &SigningKey) -> String {
    let hash = hash_mcp_entry(name, config);
    let sig = signing_key.sign(&hash);
    hex_encode(&sig.to_bytes())
}

/// Result of verifying one MCP entry's signature. `Valid` carries
/// the hex-encoded signer pubkey for audit attribution. `Invalid` is
/// always a hard fail. `Unsigned` is the operator-bypass surface
/// (covers missing signature, missing signer_key, missing
/// delegation when an anchor is configured — anything that is "no
/// claim" rather than "bad claim").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpVerifyResult {
    Valid { signer: String },
    Invalid,
    Unsigned,
}

/// Verify an MCP entry against the policy:
///
/// - No signature on the entry: returns [`McpVerifyResult::Unsigned`].
/// - Signature present but `signer_key` missing or invalid: returns
///   [`McpVerifyResult::Invalid`] (an attacker could not name a key
///   they did not control).
/// - Signature + `signer_key` present, signature does not verify:
///   [`McpVerifyResult::Invalid`].
/// - Bundled root configured and delegation signature missing or
///   invalid: [`McpVerifyResult::Invalid`].
/// - All checks pass: [`McpVerifyResult::Valid { signer }`].
///
/// Uses [`VerifyingKey::verify_strict`] for every Ed25519 check, so
/// non-canonical signatures and small-order R points are rejected.
pub fn verify_mcp_entry(
    name: &str,
    config: &McpServerConfig,
    signature_hex: Option<&str>,
    signer_key_hex: Option<&str>,
    signer_key_delegation_hex: Option<&str>,
    bundled_root: Option<&VerifyingKey>,
) -> McpVerifyResult {
    let sig_hex = match signature_hex {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return McpVerifyResult::Unsigned,
    };
    let key_hex = match signer_key_hex {
        Some(k) if !k.trim().is_empty() => k.trim(),
        _ => return McpVerifyResult::Invalid,
    };

    let sig_bytes = match hex_decode(sig_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return McpVerifyResult::Invalid,
    };
    let key_bytes = match hex_decode(key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return McpVerifyResult::Invalid,
    };

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
        Ok(k) => k,
        Err(_) => return McpVerifyResult::Invalid,
    };

    // Delegation gate. With a bundled root, the entry's signer_key
    // must be delegated by that root.
    if let Some(root) = bundled_root {
        let delegation_hex = match signer_key_delegation_hex {
            Some(s) if !s.trim().is_empty() => s.trim(),
            _ => return McpVerifyResult::Invalid,
        };
        let delegation_bytes = match hex_decode(delegation_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return McpVerifyResult::Invalid,
        };
        let mut delegation_arr = [0u8; 64];
        delegation_arr.copy_from_slice(&delegation_bytes);
        let delegation_sig = Signature::from_bytes(&delegation_arr);
        if root.verify_strict(&key_bytes, &delegation_sig).is_err() {
            return McpVerifyResult::Invalid;
        }
    }

    let hash = hash_mcp_entry(name, config);
    match verifying_key.verify_strict(&hash, &signature) {
        Ok(()) => McpVerifyResult::Valid {
            signer: key_hex.to_string(),
        },
        Err(_) => McpVerifyResult::Invalid,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ProxyError> {
    if !hex.len().is_multiple_of(2) {
        return Err(ProxyError::Config("odd-length hex string".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| ProxyError::Config(format!("hex decode: {e}")))
        })
        .collect()
}

// Test helpers: keep StdioTransportTag / HttpTransportTag visible so
// tests in this module can build configs without re-deriving the
// untagged-enum machinery.
#[allow(dead_code)]
fn _force_transport_tag_visible() -> (StdioTransportTag, HttpTransportTag) {
    (StdioTransportTag::Stdio, HttpTransportTag::Http)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::collections::HashMap;

    fn random_signing_key() -> SigningKey {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    }

    fn stdio_entry() -> McpServerConfig {
        McpServerConfig::Stdio {
            transport: None,
            command: "npx".into(),
            args: vec!["-y".into(), "@org/server".into()],
            env: HashMap::new(),
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        }
    }

    fn http_entry() -> McpServerConfig {
        McpServerConfig::Http {
            transport: HttpTransportTag::Http,
            url: "https://mcp.example.com/sse".into(),
            auth: None,
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        }
    }

    #[test]
    fn unsigned_returns_unsigned() {
        let cfg = stdio_entry();
        assert_eq!(
            verify_mcp_entry("foo", &cfg, None, None, None, None),
            McpVerifyResult::Unsigned
        );
    }

    #[test]
    fn signed_matching_key_verifies() {
        let cfg = stdio_entry();
        let key = random_signing_key();
        let sig = sign_mcp_entry("foo", &cfg, &key);
        let pk = hex_encode(&key.verifying_key().to_bytes());
        match verify_mcp_entry("foo", &cfg, Some(&sig), Some(&pk), None, None) {
            McpVerifyResult::Valid { signer } => assert_eq!(signer, pk),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn signature_with_wrong_key_invalid() {
        let cfg = stdio_entry();
        let key_a = random_signing_key();
        let key_b = random_signing_key();
        let sig = sign_mcp_entry("foo", &cfg, &key_a);
        let pk_b = hex_encode(&key_b.verifying_key().to_bytes());
        assert_eq!(
            verify_mcp_entry("foo", &cfg, Some(&sig), Some(&pk_b), None, None),
            McpVerifyResult::Invalid
        );
    }

    #[test]
    fn signature_lifted_to_different_name_invalid() {
        // A signature minted against entry "foo" must not verify
        // against an entry named "bar"; the name binding lives in
        // the canonical hash.
        let cfg = stdio_entry();
        let key = random_signing_key();
        let sig = sign_mcp_entry("foo", &cfg, &key);
        let pk = hex_encode(&key.verifying_key().to_bytes());
        assert_eq!(
            verify_mcp_entry("bar", &cfg, Some(&sig), Some(&pk), None, None),
            McpVerifyResult::Invalid
        );
    }

    #[test]
    fn env_value_change_does_not_invalidate_signature() {
        // Vault rotation changes the env value but not the key.
        // Signing covers the key set; the signature stays valid.
        let mut env_a = HashMap::new();
        env_a.insert("TOKEN".to_string(), "vault:old-token".to_string());
        let mut env_b = HashMap::new();
        env_b.insert("TOKEN".to_string(), "vault:rotated-token".to_string());

        let cfg_a = McpServerConfig::Stdio {
            transport: None,
            command: "x".into(),
            args: vec![],
            env: env_a,
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        };
        let cfg_b = McpServerConfig::Stdio {
            transport: None,
            command: "x".into(),
            args: vec![],
            env: env_b,
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        };

        let key = random_signing_key();
        let sig = sign_mcp_entry("s", &cfg_a, &key);
        let pk = hex_encode(&key.verifying_key().to_bytes());
        match verify_mcp_entry("s", &cfg_b, Some(&sig), Some(&pk), None, None) {
            McpVerifyResult::Valid { .. } => {}
            other => panic!("expected Valid across env rotation, got {other:?}"),
        }
    }

    #[test]
    fn env_key_change_invalidates_signature() {
        // Adding or removing an env key changes the load-bearing
        // surface; the signature must reject.
        let mut env_a = HashMap::new();
        env_a.insert("A".to_string(), "vault:x".into());
        let mut env_b = env_a.clone();
        env_b.insert("B".to_string(), "vault:y".into());

        let cfg_a = McpServerConfig::Stdio {
            transport: None,
            command: "c".into(),
            args: vec![],
            env: env_a,
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        };
        let cfg_b = McpServerConfig::Stdio {
            transport: None,
            command: "c".into(),
            args: vec![],
            env: env_b,
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        };

        let key = random_signing_key();
        let sig = sign_mcp_entry("s", &cfg_a, &key);
        let pk = hex_encode(&key.verifying_key().to_bytes());
        assert_eq!(
            verify_mcp_entry("s", &cfg_b, Some(&sig), Some(&pk), None, None),
            McpVerifyResult::Invalid
        );
    }

    #[test]
    fn http_auth_kind_change_invalidates_signature() {
        let cfg_none = http_entry();
        let cfg_bearer = McpServerConfig::Http {
            transport: HttpTransportTag::Http,
            url: "https://mcp.example.com/sse".into(),
            auth: Some(McpAuth::Bearer {
                credential: "vault:t".into(),
            }),
            signature: None,
            signer_key: None,
            signer_key_delegation: None,
        };
        let key = random_signing_key();
        let sig = sign_mcp_entry("s", &cfg_none, &key);
        let pk = hex_encode(&key.verifying_key().to_bytes());
        assert_eq!(
            verify_mcp_entry("s", &cfg_bearer, Some(&sig), Some(&pk), None, None),
            McpVerifyResult::Invalid
        );
    }

    #[test]
    fn delegation_required_when_root_present() {
        let cfg = stdio_entry();
        let root = random_signing_key();
        let signer = random_signing_key();
        let sig = sign_mcp_entry("s", &cfg, &signer);
        let pk = hex_encode(&signer.verifying_key().to_bytes());
        let delegation = root.sign(&signer.verifying_key().to_bytes());
        let delegation_hex = hex_encode(&delegation.to_bytes());
        let root_pub = root.verifying_key();

        // Happy path.
        match verify_mcp_entry(
            "s",
            &cfg,
            Some(&sig),
            Some(&pk),
            Some(&delegation_hex),
            Some(&root_pub),
        ) {
            McpVerifyResult::Valid { .. } => {}
            other => panic!("expected Valid, got {other:?}"),
        }

        // Missing delegation under an anchor: Invalid.
        assert_eq!(
            verify_mcp_entry("s", &cfg, Some(&sig), Some(&pk), None, Some(&root_pub)),
            McpVerifyResult::Invalid
        );

        // Wrong root: Invalid.
        let other_root = random_signing_key().verifying_key();
        assert_eq!(
            verify_mcp_entry(
                "s",
                &cfg,
                Some(&sig),
                Some(&pk),
                Some(&delegation_hex),
                Some(&other_root),
            ),
            McpVerifyResult::Invalid
        );

        // No root configured: delegation is ignored, signature still
        // verifies (legacy path).
        match verify_mcp_entry("s", &cfg, Some(&sig), Some(&pk), None, None) {
            McpVerifyResult::Valid { .. } => {}
            other => panic!("expected Valid in legacy path, got {other:?}"),
        }
    }

    #[test]
    fn signer_key_missing_with_signature_invalid() {
        // A signature without a signer_key is structurally bogus;
        // accept it would allow an attacker to claim a signature
        // they could not check.
        let cfg = stdio_entry();
        let key = random_signing_key();
        let sig = sign_mcp_entry("s", &cfg, &key);
        assert_eq!(
            verify_mcp_entry("s", &cfg, Some(&sig), None, None, None),
            McpVerifyResult::Invalid
        );
    }

    #[test]
    fn empty_bundled_pubkey_returns_none() {
        // The committed wirken-mcp-pubkey.pub is empty by design.
        let trimmed = BUNDLED_MCP_PUBKEY_HEX.trim();
        if trimmed.is_empty() {
            assert!(bundled_mcp_pubkey().is_none());
        }
    }
}
