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

    /// The entry is a plan sign-in, which only the plan token source
    /// reads; it is never handed out as a key.
    #[error("credential '{0}' is a plan sign-in, not a key")]
    PlanSignIn(String),

    #[error("passphrase derivation failed: {0}")]
    Derivation(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The vault predates destination binding.
    #[error("this vault predates destination binding; run `wirken vault migrate` at a terminal")]
    NeedsMigration,

    #[error("the vault is already migrated")]
    AlreadyMigrated,

    /// The credential's binding does not allow this destination.
    #[error("credential '{name}' may not be sent to {}; allow it with `wirken credentials grant {name} {}`", .destination.describe(), .destination.grant_flags())]
    NotPermitted {
        name: String,
        destination: crate::binding::Destination,
    },
}
