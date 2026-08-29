use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("vault error: {0}")]
    Vault(#[from] wirken_vault::VaultError),

    #[error("audit error: {0}")]
    Audit(#[from] wirken_audit::AuditError),

    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("adapter not registered: {0}")]
    AdapterNotRegistered(String),

    #[error("adapter already registered: {0}")]
    AdapterAlreadyRegistered(String),

    #[error("hook not registered: {0}")]
    HookNotRegistered(String),

    #[error("hook already registered: {0}")]
    HookAlreadyRegistered(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session expired: {0}")]
    SessionExpired(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("no route for channel {channel} conversation {conversation}")]
    NoRoute {
        channel: String,
        conversation: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    /// An archive was turned away on its structural shape: member
    /// count, declared size, expansion ratio, or not being a readable
    /// zip at all. Distinct from a parse failure, which is about a
    /// member's contents rather than the archive's frame.
    #[error("archive refused: {0}")]
    ArchiveRefused(String),
}
