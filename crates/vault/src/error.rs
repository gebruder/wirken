use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("keychain error: {0}")]
    Keychain(String),

    /// The keychain has not yet been initialized. Distinct from
    /// `Keychain(...)` so `CredentialStore::open` can narrowly auto-
    /// create a fresh device key on legitimate first run, while every
    /// other keychain error propagates to the caller. See the
    /// vault-no-empty-seal slice rationale.
    #[error("keychain not initialized")]
    KeychainNotInitialized,

    #[error("credential not found: {0}")]
    NotFound(String),

    #[error("credential expired: {0}")]
    Expired(String),

    #[error("passphrase derivation failed: {0}")]
    Derivation(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
