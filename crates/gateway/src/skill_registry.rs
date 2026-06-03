use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::GatewayError;

/// Compile-time-bundled hex-encoded Ed25519 public key of the wirken
/// skill-registry root. Empty string means "no root anchor configured
/// in this build" — the verification path then falls back to trusting
/// the registry index's per-entry `signer_key` directly, which is the
/// pre-anchor behavior.
///
/// Rotation requires rebuilding the binary against a fresh key file.
/// This is intentional: a registry-anchored trust root that lives on
/// disk under the same UID as the gateway adds no real defense; the
/// anchor is meaningful only when the binary itself is what an
/// attacker cannot replace without operator action.
pub const BUNDLED_REGISTRY_PUBKEY_HEX: &str = include_str!("wirken-registry-pubkey.pub");

/// Parse the bundled root key into a [`VerifyingKey`]. Returns `None`
/// when the file is empty (build without registry anchor) or when the
/// content does not parse as a 32-byte hex Ed25519 key (corrupt
/// bundle; treated as no-anchor and a runtime warn).
pub fn bundled_registry_pubkey() -> Option<VerifyingKey> {
    let trimmed = BUNDLED_REGISTRY_PUBKEY_HEX.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() != 64 {
        tracing::warn!(
            len = trimmed.len(),
            "bundled registry pubkey has unexpected length; ignoring \
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

/// File name, under the operator data dir, of the operator-set
/// registry root public key. This is runtime operator state, distinct
/// from the compile-time [`BUNDLED_REGISTRY_PUBKEY_HEX`] placeholder:
/// an administrator installs it (`wirken skills trust-root`) to opt
/// into identity anchoring. The file holds the hex-encoded 32-byte
/// Ed25519 root public key. The matching root *private* key never
/// ships with wirken and never lands on this machine; it signs
/// signer-key delegations offline (see `docs/signing.md`).
pub const REGISTRY_ROOT_FILE: &str = "registry-root.pub";

/// Path to the operator-set registry root key file under `data_dir`.
pub fn registry_root_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(REGISTRY_ROOT_FILE)
}

/// Parse a hex-encoded 32-byte Ed25519 public key. `None` on any
/// length / hex / point-decode failure.
fn parse_pubkey_hex(hex: &str) -> Option<VerifyingKey> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = hex_decode(trimmed).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Install an operator-set registry root public key under `data_dir`.
/// `pubkey_hex` must be a 64-char hex (32-byte) Ed25519 public key;
/// anything else is rejected so a malformed anchor never lands on
/// disk.
///
/// The file is integrity-sensitive, not secret: it is written
/// owner-write / world-read (0644). The permission intent is that a
/// non-owner process cannot replace the anchor the loader trusts,
/// while any reader may verify against it. This is deliberately *not*
/// the 0600 credential model — the public key is meant to be readable.
pub fn save_registry_root(data_dir: &Path, pubkey_hex: &str) -> Result<(), GatewayError> {
    let trimmed = pubkey_hex.trim();
    if parse_pubkey_hex(trimmed).is_none() {
        return Err(GatewayError::Config(
            "registry root must be a 64-char hex (32-byte) Ed25519 public key".into(),
        ));
    }
    let path = registry_root_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| GatewayError::Config(format!("create {}: {e}", parent.display())))?;
    }
    std::fs::write(&path, format!("{trimmed}\n"))
        .map_err(|e| GatewayError::Config(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| GatewayError::Config(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

/// Resolve the operator-set registry root, if one is installed under
/// `data_dir`.
///
/// - `Ok(None)`: no root file present. The operator has not opted into
///   identity anchoring; the load path keeps its self-signed floor.
/// - `Ok(Some(key))`: a well-formed root key is present.
/// - `Err(..)`: the file is present but unreadable or does not parse
///   as a key. The load gate treats this as fail-closed (a
///   configured-but-unusable anchor refuses skills rather than
///   silently downgrading to the floor), so a corrupted or truncated
///   anchor cannot disable strict mode unnoticed.
pub fn load_registry_root(data_dir: &Path) -> Result<Option<VerifyingKey>, GatewayError> {
    let path = registry_root_path(data_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(GatewayError::Config(format!(
                "registry root {} is present but unreadable: {e}",
                path.display()
            )));
        }
    };
    match parse_pubkey_hex(&raw) {
        Some(key) => Ok(Some(key)),
        None => Err(GatewayError::Config(format!(
            "registry root {} is present but does not parse as a 32-byte Ed25519 \
             public key; refusing to load skills with an unusable anchor",
            path.display()
        ))),
    }
}

/// A skill entry in the registry index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntry {
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    /// URL to download the SKILL.md file.
    pub url: String,
    /// Hex-encoded Ed25519 signature of the SKILL.md content hash.
    pub signature: Option<String>,
    /// Hex-encoded Ed25519 public key of the signer.
    pub signer_key: Option<String>,
    /// Hex-encoded Ed25519 signature over the raw 32-byte
    /// `signer_key`, computed by the bundled registry root key. When
    /// the bundled root key is configured, this delegation must
    /// verify before the entry's `signature` is trusted; otherwise
    /// (legacy bundles, dev installs without the root anchor) the
    /// field is `None` and the verifier falls back to the previous
    /// trust path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_delegation: Option<String>,
}

/// The registry index — a list of published skills.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillIndex {
    pub skills: Vec<SkillEntry>,
}

impl SkillIndex {
    /// Search skills by name or description substring.
    pub fn search(&self, query: &str) -> Vec<&SkillEntry> {
        let q = query.to_lowercase();
        self.skills
            .iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&q) || s.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Find a skill by exact name.
    pub fn find(&self, name: &str) -> Option<&SkillEntry> {
        self.skills.iter().find(|s| s.name == name)
    }
}

/// Compute the SHA-256 hash of a file's contents.
pub fn hash_skill_file(path: &Path) -> Result<Vec<u8>, GatewayError> {
    let content = std::fs::read(path)
        .map_err(|e| GatewayError::Config(format!("read {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(hasher.finalize().to_vec())
}

/// Compute the SHA-256 hash that covers the full signable surface of
/// a skill bundle: the SKILL.md content, and the skill.wasm content
/// when present.
///
/// **Composite layout:** `sha256(SKILL.md_bytes || 0x00 || skill.wasm_bytes)`
/// when skill.wasm exists; plain `sha256(SKILL.md_bytes)` when it does
/// not. The null byte is a separator that prevents a content boundary
/// from being confused with file content (a trailing null inside
/// SKILL.md would otherwise hash identically to a preceding empty
/// wasm). Bundles authored before wasm was in scope continue to
/// hash to the same value as long as no skill.wasm file appears at
/// verify time; this preserves their existing signatures.
///
/// Adding a skill.wasm post-sign or removing one post-sign both
/// shift the composite and produce `VerifyResult::Invalid` on
/// verification, which is the intent of the wider scope.
pub fn hash_skill_bundle(skill_dir: &Path) -> Result<Vec<u8>, GatewayError> {
    let skill_md = skill_dir.join("SKILL.md");
    let md_bytes = std::fs::read(&skill_md)
        .map_err(|e| GatewayError::Config(format!("read {}: {e}", skill_md.display())))?;
    let mut hasher = Sha256::new();
    hasher.update(&md_bytes);

    let wasm_path = skill_dir.join("skill.wasm");
    if wasm_path.exists() {
        let wasm_bytes = std::fs::read(&wasm_path)
            .map_err(|e| GatewayError::Config(format!("read {}: {e}", wasm_path.display())))?;
        hasher.update([0x00]);
        hasher.update(&wasm_bytes);
    }
    Ok(hasher.finalize().to_vec())
}

/// Sign a skill directory. Signs the composite bundle hash with
/// Ed25519: SKILL.md alone when the directory has no skill.wasm,
/// otherwise the composite over both files (see
/// [`hash_skill_bundle`] for the layout). Writes the signature to
/// SKILL.sig as hex.
pub fn sign_skill(skill_dir: &Path, signing_key: &SigningKey) -> Result<String, GatewayError> {
    let skill_md = skill_dir.join("SKILL.md");
    if !skill_md.exists() {
        return Err(GatewayError::Config(format!(
            "no SKILL.md in {}",
            skill_dir.display()
        )));
    }

    let hash = hash_skill_bundle(skill_dir)?;
    let signature = signing_key.sign(&hash);
    let sig_hex = hex_encode(&signature.to_bytes());

    // Write signature file
    let sig_path = skill_dir.join("SKILL.sig");
    std::fs::write(&sig_path, &sig_hex)
        .map_err(|e| GatewayError::Config(format!("write sig: {e}")))?;

    // Write public key file
    let pub_key_hex = hex_encode(&signing_key.verifying_key().to_bytes());
    let key_path = skill_dir.join("SKILL.pub");
    std::fs::write(&key_path, &pub_key_hex)
        .map_err(|e| GatewayError::Config(format!("write pub key: {e}")))?;

    Ok(sig_hex)
}

/// Verify a skill's signature against `SKILL.pub` bundled in the skill
/// directory itself.
///
/// **Trust model:** this is *self-signed* verification — the public key
/// comes from the same directory whose contents it is verifying. Anyone
/// with write access to the skill directory can replace `SKILL.md`,
/// `SKILL.sig`, and `SKILL.pub` together with their own keypair and
/// pass this check. Use [`verify_skill_with_expected_key`] when the
/// expected signer key is anchored out-of-band (registry index entry,
/// operator-pinned key file, etc.).
///
/// Callers presenting the result to operators should label it
/// "self-signed" rather than "valid" — `VerifyResult::Valid` here means
/// "the bundle's signature checks against the bundle's own key", not
/// "the bundle came from a trusted publisher".
pub fn verify_skill_self_signed(skill_dir: &Path) -> Result<VerifyResult, GatewayError> {
    let sig_path = skill_dir.join("SKILL.sig");
    let key_path = skill_dir.join("SKILL.pub");

    if !sig_path.exists() || !key_path.exists() {
        return Ok(VerifyResult::Unsigned);
    }

    let hash = hash_skill_bundle(skill_dir)?;

    let sig_hex = std::fs::read_to_string(&sig_path)
        .map_err(|e| GatewayError::Config(format!("read sig: {e}")))?;
    let sig_bytes =
        hex_decode(sig_hex.trim()).map_err(|e| GatewayError::Config(format!("decode sig: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(GatewayError::Config(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .map_err(|e| GatewayError::Config(format!("read pub key: {e}")))?;
    let key_bytes = hex_decode(key_hex.trim())
        .map_err(|e| GatewayError::Config(format!("decode pub key: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(GatewayError::Config(format!(
            "public key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| GatewayError::Config(format!("invalid pub key: {e}")))?;

    match verifying_key.verify_strict(&hash, &signature) {
        Ok(()) => Ok(VerifyResult::Valid {
            signer: key_hex.trim().to_string(),
        }),
        Err(_) => Ok(VerifyResult::Invalid),
    }
}

/// Sign a skill bundle and delegate its signer key under a registry
/// root, for installs that have opted into identity anchoring.
///
/// Writes the same `SKILL.sig` / `SKILL.pub` as [`sign_skill`] (the
/// signer key signs the composite bundle hash), then writes
/// `SKILL.deleg`: the root's Ed25519 signature over the signer's raw
/// 32-byte public key. The bundle then verifies under
/// [`verify_skill_delegated`] against `root_key.verifying_key()`.
///
/// `root_key` is the operator's offline root private key, supplied at
/// sign time in their signing environment. It never ships with wirken
/// and is not written anywhere by this function.
pub fn delegate_sign_skill(
    skill_dir: &Path,
    signer_key: &SigningKey,
    root_key: &SigningKey,
) -> Result<(), GatewayError> {
    sign_skill(skill_dir, signer_key)?;
    let signer_pub = signer_key.verifying_key();
    let delegation = root_key.sign(&signer_pub.to_bytes());
    let deleg_hex = hex_encode(&delegation.to_bytes());
    std::fs::write(skill_dir.join("SKILL.deleg"), &deleg_hex)
        .map_err(|e| GatewayError::Config(format!("write delegation: {e}")))?;
    Ok(())
}

/// Generate a new Ed25519 keypair for skill signing.
/// Returns (secret_key_hex, public_key_hex).
pub fn generate_signing_keypair() -> (String, String) {
    use rand::Rng;
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let secret_hex = hex_encode(signing_key.as_bytes());
    let public_hex = hex_encode(&signing_key.verifying_key().to_bytes());
    (secret_hex, public_hex)
}

/// Verify a skill's signature against an expected public key from the registry.
/// This prevents an attacker from bundling their own key with a tampered skill.
///
/// When the bundled registry root key is configured (non-empty
/// `wirken-registry-pubkey.pub`), `delegation_sig_hex` must contain a
/// valid Ed25519 signature by the bundled root over the raw 32-byte
/// `expected_key_hex`. Without that signature, the entry is treated
/// as `Invalid` even when the per-skill signature itself verifies —
/// the registry index's `signer_key` field is no longer the
/// trust-anchor on its own. When the bundled root is empty, the
/// delegation field is ignored and the legacy trust path applies.
pub fn verify_skill_with_expected_key(
    skill_dir: &Path,
    expected_sig_hex: &str,
    expected_key_hex: &str,
) -> Result<VerifyResult, GatewayError> {
    verify_skill_with_expected_key_and_delegation(
        skill_dir,
        expected_sig_hex,
        expected_key_hex,
        None,
        bundled_registry_pubkey().as_ref(),
    )
}

/// Same as [`verify_skill_with_expected_key`] but lets a caller pass
/// the delegation signature explicitly and override the bundled root
/// key. Tests use this seam to exercise the rotation matrix without
/// rebuilding the binary.
pub fn verify_skill_with_expected_key_and_delegation(
    skill_dir: &Path,
    expected_sig_hex: &str,
    expected_key_hex: &str,
    delegation_sig_hex: Option<&str>,
    bundled_root: Option<&VerifyingKey>,
) -> Result<VerifyResult, GatewayError> {
    let hash = hash_skill_bundle(skill_dir)?;

    let sig_bytes = hex_decode(expected_sig_hex.trim())
        .map_err(|e| GatewayError::Config(format!("decode sig: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(GatewayError::Config(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let key_bytes = hex_decode(expected_key_hex.trim())
        .map_err(|e| GatewayError::Config(format!("decode pub key: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(GatewayError::Config(format!(
            "public key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| GatewayError::Config(format!("invalid pub key: {e}")))?;

    // Delegation gate. If the binary was built with a registry root
    // key, the entry's signer_key must be delegated by that root.
    if let Some(root) = bundled_root {
        let delegation_hex = delegation_sig_hex.unwrap_or("");
        let delegation_bytes = hex_decode(delegation_hex.trim())
            .map_err(|e| GatewayError::Config(format!("decode signer_key_delegation: {e}")))?;
        if delegation_bytes.len() != 64 {
            return Ok(VerifyResult::Invalid);
        }
        let mut delegation_arr = [0u8; 64];
        delegation_arr.copy_from_slice(&delegation_bytes);
        let delegation_sig = Signature::from_bytes(&delegation_arr);
        // The delegation signs the raw 32-byte signer_key.
        if root.verify_strict(&key_bytes, &delegation_sig).is_err() {
            return Ok(VerifyResult::Invalid);
        }
    }

    match verifying_key.verify_strict(&hash, &signature) {
        Ok(()) => Ok(VerifyResult::Valid {
            signer: expected_key_hex.trim().to_string(),
        }),
        Err(_) => Ok(VerifyResult::Invalid),
    }
}

/// Verify a skill bundle under an operator-configured registry root,
/// requiring a valid signer-key delegation by that root. Reads
/// `SKILL.sig`, `SKILL.pub`, and `SKILL.deleg` from the bundle
/// directory and defers the cryptographic checks to
/// [`verify_skill_with_expected_key_and_delegation`] with the on-disk
/// `SKILL.pub` as the expected signer key.
///
/// - `Unsigned`: `SKILL.sig` / `SKILL.pub` are absent. The strict load
///   path treats this as a refusal; there is no unsigned bypass once a
///   root is configured.
/// - `Invalid`: the signature, the signer key, or the delegation does
///   not verify under `root`. A self-signed-only bundle (no
///   `SKILL.deleg`) lands here, because a configured root requires the
///   signer key to be delegated.
/// - `Valid`: the signer is delegated by `root` and the bundle
///   signature verifies under the signer key.
pub fn verify_skill_delegated(
    skill_dir: &Path,
    root: &VerifyingKey,
) -> Result<VerifyResult, GatewayError> {
    let sig_path = skill_dir.join("SKILL.sig");
    let key_path = skill_dir.join("SKILL.pub");
    if !sig_path.exists() || !key_path.exists() {
        return Ok(VerifyResult::Unsigned);
    }
    let sig_hex = std::fs::read_to_string(&sig_path)
        .map_err(|e| GatewayError::Config(format!("read sig: {e}")))?;
    let key_hex = std::fs::read_to_string(&key_path)
        .map_err(|e| GatewayError::Config(format!("read pub key: {e}")))?;
    let deleg_path = skill_dir.join("SKILL.deleg");
    let deleg_hex = match std::fs::read_to_string(&deleg_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(GatewayError::Config(format!("read delegation: {e}"))),
    };
    verify_skill_with_expected_key_and_delegation(
        skill_dir,
        sig_hex.trim(),
        key_hex.trim(),
        deleg_hex.as_deref().map(str::trim),
        Some(root),
    )
}

/// Result of signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Skill has a valid signature.
    Valid { signer: String },
    /// Skill has a signature but it's invalid.
    Invalid,
    /// Skill has no signature.
    Unsigned,
}

/// Public hex encode (for CLI).
pub fn hex_encode_public(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// Public hex decode (for CLI).
pub fn hex_decode_public(hex: &str) -> Result<Vec<u8>, GatewayError> {
    hex_decode(hex).map_err(|e| GatewayError::Config(format!("hex decode: {e}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use tempfile::TempDir;

    fn random_signing_key() -> SigningKey {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    }

    #[test]
    fn sign_and_verify_skill() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("weather");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: weather\n---\nUse curl wttr.in",
        )
        .unwrap();

        let signing_key = random_signing_key();
        sign_skill(&skill_dir, &signing_key).unwrap();

        assert!(skill_dir.join("SKILL.sig").exists());
        assert!(skill_dir.join("SKILL.pub").exists());

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Valid { .. } => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn unsigned_skill() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("unsigned");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "---\nname: test\n---\nbody").unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Unsigned => {}
            other => panic!("expected Unsigned, got {other:?}"),
        }
    }

    #[test]
    fn tampered_skill_detected() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("tampered");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "original content").unwrap();

        let signing_key = random_signing_key();
        sign_skill(&skill_dir, &signing_key).unwrap();

        // Tamper with the content
        std::fs::write(skill_dir.join("SKILL.md"), "TAMPERED content").unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_detected() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("wrongkey");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "content").unwrap();

        let key1 = random_signing_key();
        sign_skill(&skill_dir, &key1).unwrap();

        // Replace pub key with a different key
        let key2 = random_signing_key();
        let pub_hex = hex_encode(&key2.verifying_key().to_bytes());
        std::fs::write(skill_dir.join("SKILL.pub"), &pub_hex).unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn empty_bundled_pubkey_returns_none() {
        // A build whose `wirken-registry-pubkey.pub` is empty should
        // resolve to None and let the legacy trust path apply.
        let trimmed = BUNDLED_REGISTRY_PUBKEY_HEX.trim();
        // We commit the placeholder file empty; this assert pins the
        // default-build behavior. A real-key build would fail here
        // and the test would need an explicit expected_some variant.
        if trimmed.is_empty() {
            assert!(bundled_registry_pubkey().is_none());
        }
    }

    #[test]
    fn delegation_required_when_root_present() {
        // Build a synthetic registry-rooted trust chain:
        //   root_key -> entry signer key -> SKILL.md signature
        // Verify the happy path, then break each delegation and assert
        // rejection.
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("delegated");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "skill body").unwrap();

        let root = random_signing_key();
        let signer = random_signing_key();
        // Sign SKILL.md hash with the entry signer key.
        let skill_hash = hash_skill_file(&skill_dir.join("SKILL.md")).unwrap();
        let skill_sig = signer.sign(&skill_hash);
        let skill_sig_hex = hex_encode(&skill_sig.to_bytes());
        let signer_pub_hex = hex_encode(&signer.verifying_key().to_bytes());
        // Root delegates the entry signer's pubkey.
        let delegation_sig = root.sign(&signer.verifying_key().to_bytes());
        let delegation_hex = hex_encode(&delegation_sig.to_bytes());
        let root_pubkey = root.verifying_key();

        // Happy path: delegation valid, skill signature valid.
        let result = verify_skill_with_expected_key_and_delegation(
            &skill_dir,
            &skill_sig_hex,
            &signer_pub_hex,
            Some(&delegation_hex),
            Some(&root_pubkey),
        )
        .unwrap();
        assert!(matches!(result, VerifyResult::Valid { .. }));

        // Missing delegation when root is present → Invalid.
        let result = verify_skill_with_expected_key_and_delegation(
            &skill_dir,
            &skill_sig_hex,
            &signer_pub_hex,
            None,
            Some(&root_pubkey),
        )
        .unwrap();
        assert_eq!(result, VerifyResult::Invalid);

        // Wrong root key → Invalid.
        let other_root = random_signing_key().verifying_key();
        let result = verify_skill_with_expected_key_and_delegation(
            &skill_dir,
            &skill_sig_hex,
            &signer_pub_hex,
            Some(&delegation_hex),
            Some(&other_root),
        )
        .unwrap();
        assert_eq!(result, VerifyResult::Invalid);

        // No root configured → legacy path; delegation field ignored.
        let result = verify_skill_with_expected_key_and_delegation(
            &skill_dir,
            &skill_sig_hex,
            &signer_pub_hex,
            None,
            None,
        )
        .unwrap();
        assert!(matches!(result, VerifyResult::Valid { .. }));
    }

    #[test]
    fn non_canonical_s_signature_rejected() {
        // Regression: the verifier path uses `verify_strict`, which
        // rejects signatures whose `s` scalar is outside the canonical
        // range [0, L). The skill verifier must surface this as
        // `Invalid`, not bubble up a panic or accept it. Take a real
        // signature, force the high byte of `s` to 0xff so the scalar
        // is far above L, and assert rejection.
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("malleable");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "body").unwrap();

        let signing_key = random_signing_key();
        sign_skill(&skill_dir, &signing_key).unwrap();

        let sig_path = skill_dir.join("SKILL.sig");
        let sig_hex = std::fs::read_to_string(&sig_path).unwrap();
        let mut sig_bytes = hex_decode(sig_hex.trim()).unwrap();
        // s lives in the upper 32 bytes of the 64-byte signature in
        // little-endian. The top byte at index 63 forced to 0xff
        // pushes s above L unambiguously.
        sig_bytes[63] = 0xff;
        std::fs::write(&sig_path, hex_encode(&sig_bytes)).unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn delegate_sign_round_trips_under_matching_root() {
        // delegate_sign_skill must produce SKILL.sig/SKILL.pub/SKILL.deleg
        // that verify_skill_delegated accepts under the matching root and
        // rejects under any other root. Locks the helper's message bytes
        // against the verifier (the load-gate branch tests build their own
        // delegation and would not catch a wrong-bytes regression here).
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "---\nname: d\n---\nbody").unwrap();

        let signer = random_signing_key();
        let root = random_signing_key();
        delegate_sign_skill(&dir, &signer, &root).unwrap();
        assert!(dir.join("SKILL.deleg").exists());

        match verify_skill_delegated(&dir, &root.verifying_key()).unwrap() {
            VerifyResult::Valid { .. } => {}
            other => panic!("expected Valid under matching root, got {other:?}"),
        }
        let other = random_signing_key();
        assert_eq!(
            verify_skill_delegated(&dir, &other.verifying_key()).unwrap(),
            VerifyResult::Invalid,
            "a delegation by a different root must not verify"
        );
    }

    #[test]
    fn generate_keypair_returns_valid_hex() {
        let (secret, public) = generate_signing_keypair();
        assert_eq!(secret.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(public.len(), 64);

        // Can reconstruct from hex
        let secret_bytes = hex_decode(&secret).unwrap();
        assert_eq!(secret_bytes.len(), 32);
    }

    #[test]
    fn search_index() {
        let index = SkillIndex {
            skills: vec![
                SkillEntry {
                    name: "weather".into(),
                    description: "Get current weather".into(),
                    version: "1.0.0".into(),
                    author: "wirken".into(),
                    url: "https://example.com/weather".into(),
                    signature: None,
                    signer_key: None,
                    signer_key_delegation: None,
                },
                SkillEntry {
                    name: "github".into(),
                    description: "GitHub operations via gh CLI".into(),
                    version: "1.0.0".into(),
                    author: "wirken".into(),
                    url: "https://example.com/github".into(),
                    signature: None,
                    signer_key: None,
                    signer_key_delegation: None,
                },
                SkillEntry {
                    name: "tmux".into(),
                    description: "Control tmux sessions".into(),
                    version: "1.0.0".into(),
                    author: "wirken".into(),
                    url: "https://example.com/tmux".into(),
                    signature: None,
                    signer_key: None,
                    signer_key_delegation: None,
                },
            ],
        };

        let results = index.search("weather");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "weather");

        let results = index.search("git");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "github");

        let results = index.search("CLI");
        assert_eq!(results.len(), 1); // github has "CLI" in description

        let results = index.search("nonexistent");
        assert!(results.is_empty());

        assert!(index.find("tmux").is_some());
        assert!(index.find("nope").is_none());
    }

    #[test]
    fn sign_verify_roundtrip_with_generated_keypair() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("roundtrip");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: test\ndescription: roundtrip test\n---\nBody content here.",
        )
        .unwrap();

        let (secret_hex, _public_hex) = generate_signing_keypair();
        let secret_bytes = hex_decode(&secret_hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        let signing_key = SigningKey::from_bytes(&arr);

        sign_skill(&skill_dir, &signing_key).unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Valid { signer } => {
                assert_eq!(signer.len(), 64);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_expected_key_accepts_matching_anchor() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("anchored");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "---\nname: a\n---\nbody").unwrap();
        let signing = random_signing_key();
        sign_skill(&skill_dir, &signing).unwrap();
        let sig_hex = std::fs::read_to_string(skill_dir.join("SKILL.sig")).unwrap();
        let key_hex = hex_encode(&signing.verifying_key().to_bytes());
        match verify_skill_with_expected_key(&skill_dir, sig_hex.trim(), &key_hex).unwrap() {
            VerifyResult::Valid { .. } => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_expected_key_rejects_mismatched_anchor() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("anchored");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "---\nname: a\n---\nbody").unwrap();
        let signing_a = random_signing_key();
        sign_skill(&skill_dir, &signing_a).unwrap();
        let sig_hex = std::fs::read_to_string(skill_dir.join("SKILL.sig")).unwrap();
        let signing_b = random_signing_key();
        let other_key_hex = hex_encode(&signing_b.verifying_key().to_bytes());
        match verify_skill_with_expected_key(&skill_dir, sig_hex.trim(), &other_key_hex).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // ---- B1: skill.wasm under composite signature scope ---------------

    /// A bundle with no `skill.wasm` hashes to the same value as it
    /// did pre-1.3.0: `sha256(SKILL.md_bytes)` alone. Pre-1.3.0
    /// signatures must continue to verify after the composite
    /// helper landed.
    #[test]
    fn c4_md_only_bundle_hashes_to_pre_wasm_value() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("md-only");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), b"---\nname: x\n---\nbody").unwrap();

        let composite = hash_skill_bundle(&skill_dir).unwrap();
        let md_only = hash_skill_file(&skill_dir.join("SKILL.md")).unwrap();
        assert_eq!(
            composite, md_only,
            "no skill.wasm in dir must preserve pre-1.3.0 hash so old signatures still verify"
        );
    }

    /// Signing with a `skill.wasm` present and verifying with the
    /// same wasm yields `Valid`.
    #[test]
    fn c4_wasm_bundle_sign_then_verify_is_valid() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("wasm-skill");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), b"---\nname: x\n---\nbody").unwrap();
        std::fs::write(skill_dir.join("skill.wasm"), b"\x00asm\x01\x00\x00\x00").unwrap();

        let signing = random_signing_key();
        sign_skill(&skill_dir, &signing).unwrap();
        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Valid { .. } => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// Swap the `skill.wasm` for different bytes after sign and the
    /// composite shifts; verify reports `Invalid`. Locks in the
    /// scope expansion: the wasm is in the signature surface.
    #[test]
    fn c4_swapped_wasm_fails_verification() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("wasm-tamper");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), b"---\nname: x\n---\nbody").unwrap();
        std::fs::write(skill_dir.join("skill.wasm"), b"original-wasm").unwrap();

        let signing = random_signing_key();
        sign_skill(&skill_dir, &signing).unwrap();

        // Tamper: swap the wasm bytes without re-signing.
        std::fs::write(skill_dir.join("skill.wasm"), b"tampered-wasm").unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid after wasm swap, got {other:?}"),
        }
    }

    /// Adding a `skill.wasm` after sign changes the composite and
    /// fails verification. The opposite direction (removing wasm
    /// after sign) is also caught.
    #[test]
    fn c4_adding_wasm_post_sign_fails_verification() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("wasm-injected");
        std::fs::create_dir(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), b"---\nname: x\n---\nbody").unwrap();

        let signing = random_signing_key();
        sign_skill(&skill_dir, &signing).unwrap();

        // Drop a wasm into the directory without re-signing.
        std::fs::write(skill_dir.join("skill.wasm"), b"injected").unwrap();

        match verify_skill_self_signed(&skill_dir).unwrap() {
            VerifyResult::Invalid => {}
            other => panic!("expected Invalid after wasm injection, got {other:?}"),
        }
    }
}
