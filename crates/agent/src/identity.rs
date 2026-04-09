//! Per-agent Ed25519 identity used for session attestation (item 8).
//!
//! Modeled on `wirken_ipc::AdapterIdentity` — same primitives, same
//! disk format, different purpose. Adapter identities authenticate
//! adapters to the gateway over IPC. Agent identities sign session
//! chain heads so an external auditor with the public key can prove
//! a transcript is intact and untampered.
//!
//! ## Storage
//!
//! Identities live as a pair of files in the agent's data directory:
//!
//! - `identity.key` — 32-byte Ed25519 secret key, hex-encoded, mode 0600
//! - `identity.pub` — 32-byte Ed25519 public key, hex-encoded, mode 0644
//!
//! The secret never enters the credential vault. Vault storage would
//! add a passphrase prompt to every CLI command that touches an
//! attestation; signing keys are not access tokens and the standard
//! Unix pattern (mode-0600 file in the user's data directory) is the
//! right primitive for this use case.
//!
//! ## Lazy creation
//!
//! [`AgentIdentity::load_or_create`] generates a new keypair on the
//! first call and reuses it forever after. There is no separate
//! "create identity" CLI step. The keypair appears the first time
//! the harness or a CLI command needs to sign something for that
//! agent.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::AgentError;

/// One agent's signing identity. Holds the secret key in memory; the
/// caller is responsible for not exposing it.
///
/// `Clone` is cheap (the underlying `SigningKey` is just 32 bytes).
/// Item 8 slice 2 uses it: [`crate::factory::AgentFactory`] holds a
/// canonical identity per agent_id and clones it into every waked
/// Agent so the harness can sign attestation events without
/// touching disk on every wake.
#[derive(Clone)]
pub struct AgentIdentity {
    signing_key: SigningKey,
    agent_id: String,
}

impl AgentIdentity {
    /// Generate a fresh identity. Does not persist anything.
    pub fn generate(agent_id: impl Into<String>) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            signing_key: SigningKey::generate(&mut rng),
            agent_id: agent_id.into(),
        }
    }

    /// Load an identity from disk, or generate and persist a new one
    /// if the secret key file does not exist. The directory is
    /// created on demand. The secret file is written with mode 0600
    /// on Unix; the public file is written with default permissions.
    pub fn load_or_create(agent_id: &str, dir: &Path) -> Result<Self, AgentError> {
        std::fs::create_dir_all(dir).map_err(|e| {
            AgentError::Identity(format!("create identity dir {}: {e}", dir.display()))
        })?;

        let secret_path = dir.join("identity.key");
        let public_path = dir.join("identity.pub");

        if secret_path.exists() {
            return Self::load_from(agent_id, &secret_path);
        }

        let identity = Self::generate(agent_id);

        let secret_hex = hex_encode(identity.signing_key.as_bytes());
        write_secret(&secret_path, secret_hex.as_bytes())?;

        let public_hex = hex_encode(&identity.public_key_bytes());
        std::fs::write(&public_path, public_hex.as_bytes()).map_err(|e| {
            AgentError::Identity(format!(
                "write identity public key {}: {e}",
                public_path.display()
            ))
        })?;

        Ok(identity)
    }

    /// Load an identity from a known secret key path. The file must
    /// contain exactly 64 hex characters (32 bytes).
    pub fn load_from(agent_id: &str, secret_path: &Path) -> Result<Self, AgentError> {
        let hex = std::fs::read_to_string(secret_path).map_err(|e| {
            AgentError::Identity(format!("read identity key {}: {e}", secret_path.display()))
        })?;
        let bytes = hex_decode(hex.trim()).map_err(|e| {
            AgentError::Identity(format!(
                "decode identity key {}: {e}",
                secret_path.display()
            ))
        })?;
        if bytes.len() != 32 {
            return Err(AgentError::Identity(format!(
                "identity key {} has {} bytes, expected 32",
                secret_path.display(),
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        Ok(Self {
            signing_key,
            agent_id: agent_id.to_string(),
        })
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Public key for verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign an arbitrary message. Callers must domain-separate the
    /// message themselves (see `attestation::sign_message`) so the
    /// same key cannot produce signatures that collide across
    /// protocols.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Default directory for an agent's identity files inside a wirken
/// data directory. Mirrors `GatewayConfig::agent_workspace` etc. so
/// callers can compute the path without depending on `wirken-gateway`.
pub fn identity_dir(data_dir: &Path, agent_id: &str) -> PathBuf {
    data_dir.join("agents").join(agent_id)
}

/// Verify a signature against a public key. Convenience wrapper so
/// callers do not need to import ed25519-dalek directly.
pub fn verify(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), AgentError> {
    public_key
        .verify(message, signature)
        .map_err(|_| AgentError::Identity("ed25519 signature verification failed".into()))
}

#[cfg(unix)]
fn write_secret(path: &Path, contents: &[u8]) -> Result<(), AgentError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AgentError::Identity(format!("open identity key {}: {e}", path.display())))?;
    f.write_all(contents)
        .map_err(|e| AgentError::Identity(format!("write identity key {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &[u8]) -> Result<(), AgentError> {
    std::fs::write(path, contents)
        .map_err(|e| AgentError::Identity(format!("write identity key {}: {e}", path.display())))
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
