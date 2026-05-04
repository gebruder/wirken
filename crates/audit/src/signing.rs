//! Per-gateway Ed25519 signing key for audit chain heads.
//!
//! Distinct from the IPC handshake keypair and from per-agent
//! attestation identities. The audit signing key signs `ChainHead`
//! records emitted at session boundaries and on a checkpoint cadence,
//! so an offline verifier with the public key can prove the recorded
//! chain hashes were produced by this gateway.
//!
//! Compromise of this key does not compromise IPC handshake auth, and
//! compromise of an adapter or agent identity does not let the holder
//! forge audit chain heads.
//!
//! ## Storage
//!
//! - `<data_dir>/audit/audit-signing.key` mode 0600 (Unix)
//! - `<data_dir>/audit/audit-signing.pub` default mode
//!
//! The secret key file is hex-encoded; 64 ASCII characters, 32 bytes.
//! [`AuditSigningKey::load_or_create`] generates a fresh keypair on
//! first call and reuses it forever after.
//!
//! ## Signed-message layout
//!
//! See [`build_signed_message`] for the canonical byte layout. The
//! domain separator is fixed at v1; bumping it is a wire-incompatible
//! change.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::AuditError;

/// Domain separator for chain-head signatures. Distinct from
/// `wirken/session-attest/v1` so a per-agent attestation signature
/// cannot be replayed as a chain-head signature on a key reused
/// across both surfaces.
pub const CHAIN_HEAD_DOMAIN: &[u8] = b"wirken/audit-chain-head/v1\0";

/// Schema version covered by the chain-head signature payload.
/// Bump when the signed-message layout changes; the verifier rejects
/// signatures whose embedded version does not match the version it
/// was compiled against.
pub const CHAIN_HEAD_SCHEMA_VERSION: u32 = 2;

/// Subdirectory under the gateway data dir that holds audit-signing
/// material.
const AUDIT_SIGNING_DIR: &str = "audit";
const AUDIT_SECRET_FILE: &str = "audit-signing.key";
const AUDIT_PUBLIC_FILE: &str = "audit-signing.pub";

/// Per-gateway Ed25519 signing identity for audit chain heads.
///
/// `Clone` is cheap (32-byte secret). The runtime is expected to
/// load the key once at gateway start and clone the handle into the
/// session log so signing happens without disk I/O on the hot path.
#[derive(Clone)]
pub struct AuditSigningKey {
    signing_key: SigningKey,
}

impl AuditSigningKey {
    /// Generate a fresh signing key. Does not persist anything.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        Self { signing_key }
    }

    /// Load the audit signing key from `<data_dir>/audit/`, or
    /// generate and persist a new one if the secret file does not
    /// exist. Both `audit/` and the parent data dir are created on
    /// demand. The secret file is mode 0600 on Unix; the public
    /// file uses default permissions.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, AuditError> {
        let dir = data_dir.join(AUDIT_SIGNING_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| {
            AuditError::SiemConfig(format!("create audit signing dir {}: {e}", dir.display()))
        })?;

        let secret_path = dir.join(AUDIT_SECRET_FILE);
        let public_path = dir.join(AUDIT_PUBLIC_FILE);

        if secret_path.exists() {
            return Self::load_from(&secret_path);
        }

        let identity = Self::generate();

        let secret_hex = hex_encode(identity.signing_key.as_bytes());
        write_secret(&secret_path, secret_hex.as_bytes())?;

        let public_hex = hex_encode(&identity.public_key_bytes());
        std::fs::write(&public_path, public_hex.as_bytes()).map_err(|e| {
            AuditError::SiemConfig(format!(
                "write audit public key {}: {e}",
                public_path.display()
            ))
        })?;

        Ok(identity)
    }

    /// Load a signing key from a known secret-file path. The file
    /// must contain exactly 64 hex characters (32 bytes after decode).
    pub fn load_from(secret_path: &Path) -> Result<Self, AuditError> {
        let hex = std::fs::read_to_string(secret_path).map_err(|e| {
            AuditError::SiemConfig(format!(
                "read audit signing key {}: {e}",
                secret_path.display()
            ))
        })?;
        let bytes = hex_decode(hex.trim()).map_err(|e| {
            AuditError::SiemConfig(format!(
                "decode audit signing key {}: {e}",
                secret_path.display()
            ))
        })?;
        if bytes.len() != 32 {
            return Err(AuditError::SiemConfig(format!(
                "audit signing key {} has {} bytes, expected 32",
                secret_path.display(),
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        Ok(Self { signing_key })
    }

    /// 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Verifying key for offline signature checks.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Hex-encoded public key. Stable identifier for this key and
    /// the canonical form embedded in `ChainHead.signing_key_id`.
    pub fn key_id_hex(&self) -> String {
        hex_encode(&self.public_key_bytes())
    }

    /// Sign a domain-separated chain-head payload.
    pub fn sign_chain_head(
        &self,
        sequence_range: (u64, u64),
        prev_chain_hash: &str,
        current_chain_hash: &str,
    ) -> Signature {
        let payload = build_signed_message(
            sequence_range,
            prev_chain_hash,
            current_chain_hash,
            CHAIN_HEAD_SCHEMA_VERSION,
        );
        self.signing_key.sign(&payload)
    }
}

/// Build the canonical message that an audit chain-head signature
/// covers.
///
/// Layout:
///
/// ```text
/// signed_msg =
///     CHAIN_HEAD_DOMAIN
///  || u64_le(sequence_range_start)
///  || u64_le(sequence_range_end)
///  || u32_le(prev_chain_hash.len())
///  || prev_chain_hash.as_bytes()
///  || u32_le(current_chain_hash.len())
///  || current_chain_hash.as_bytes()
///  || u32_le(schema_version)
/// ```
///
/// The hashes are passed as their hex string form (the same form
/// stored in `session_events.hash`). Length-prefixing both keeps the
/// layout unambiguous if a future schema drops to raw bytes.
pub fn build_signed_message(
    sequence_range: (u64, u64),
    prev_chain_hash: &str,
    current_chain_hash: &str,
    schema_version: u32,
) -> Vec<u8> {
    let prev = prev_chain_hash.as_bytes();
    let curr = current_chain_hash.as_bytes();
    let mut out =
        Vec::with_capacity(CHAIN_HEAD_DOMAIN.len() + 8 + 8 + 4 + prev.len() + 4 + curr.len() + 4);
    out.extend_from_slice(CHAIN_HEAD_DOMAIN);
    out.extend_from_slice(&sequence_range.0.to_le_bytes());
    out.extend_from_slice(&sequence_range.1.to_le_bytes());
    out.extend_from_slice(&(prev.len() as u32).to_le_bytes());
    out.extend_from_slice(prev);
    out.extend_from_slice(&(curr.len() as u32).to_le_bytes());
    out.extend_from_slice(curr);
    out.extend_from_slice(&schema_version.to_le_bytes());
    out
}

/// Default location of the audit signing key directory under a
/// gateway data dir. Callers that hold a `data_dir` path use this so
/// they do not depend on `wirken-gateway`.
pub fn audit_signing_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(AUDIT_SIGNING_DIR)
}

#[cfg(unix)]
fn write_secret(path: &Path, contents: &[u8]) -> Result<(), AuditError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            AuditError::SiemConfig(format!("open audit signing key {}: {e}", path.display()))
        })?;
    f.write_all(contents).map_err(|e| {
        AuditError::SiemConfig(format!("write audit signing key {}: {e}", path.display()))
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &[u8]) -> Result<(), AuditError> {
    tracing::warn!(
        "writing audit signing key {} without 0o600-equivalent file permissions; \
         relying on user profile isolation for confidentiality",
        path.display()
    );
    std::fs::write(path, contents).map_err(|e| {
        AuditError::SiemConfig(format!("write audit signing key {}: {e}", path.display()))
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("hex decode: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn generate_yields_distinct_keys() {
        let a = AuditSigningKey::generate();
        let b = AuditSigningKey::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn load_or_create_persists_and_reloads() {
        let tmp = tempfile::tempdir().unwrap();
        let a = AuditSigningKey::load_or_create(tmp.path()).unwrap();
        let b = AuditSigningKey::load_or_create(tmp.path()).unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn load_or_create_writes_pub_file() {
        let tmp = tempfile::tempdir().unwrap();
        let key = AuditSigningKey::load_or_create(tmp.path()).unwrap();
        let pub_path = audit_signing_dir(tmp.path()).join(AUDIT_PUBLIC_FILE);
        assert!(pub_path.exists());
        let pub_hex = std::fs::read_to_string(&pub_path).unwrap();
        let mut want = String::new();
        for b in &key.public_key_bytes() {
            use std::fmt::Write;
            write!(&mut want, "{b:02x}").unwrap();
        }
        assert_eq!(pub_hex, want);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let _ = AuditSigningKey::load_or_create(tmp.path()).unwrap();
        let secret_path = audit_signing_dir(tmp.path()).join(AUDIT_SECRET_FILE);
        let mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = AuditSigningKey::generate();
        let sig = key.sign_chain_head((0, 5), "", "abc123");
        let msg = build_signed_message((0, 5), "", "abc123", CHAIN_HEAD_SCHEMA_VERSION);
        key.verifying_key().verify(&msg, &sig).unwrap();
    }

    #[test]
    fn signature_does_not_verify_after_payload_mutation() {
        let key = AuditSigningKey::generate();
        let sig = key.sign_chain_head((0, 5), "", "abc123");
        let msg = build_signed_message((0, 5), "", "abc999", CHAIN_HEAD_SCHEMA_VERSION);
        assert!(key.verifying_key().verify(&msg, &sig).is_err());
    }

    #[test]
    fn key_id_hex_matches_public_key_bytes() {
        let key = AuditSigningKey::generate();
        let pk = key.public_key_bytes();
        let id = key.key_id_hex();
        let mut want = String::new();
        for b in &pk {
            use std::fmt::Write;
            write!(&mut want, "{b:02x}").unwrap();
        }
        assert_eq!(id, want);
    }
}
