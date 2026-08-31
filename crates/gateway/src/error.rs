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

    /// One message uuid appeared in two conversations of the same
    /// source account, which the natural key does not allow.
    ///
    /// The import aborts rather than resolving it, because no silent
    /// resolution is correct: keeping the first drops the second's
    /// message, keeping the second rewrites history under the first
    /// conversation, and scoping the key per conversation would let
    /// one message exist twice with different parents. Which is right
    /// depends on why the archive contains the collision, and only the
    /// operator can find that out.
    #[error(
        "message '{message_uuid}' appears in two conversations of source account \
         '{source_account}': already stored under '{stored_conversation}', and again in \
         '{incoming_conversation}'. The import stopped here. Conversations imported before \
         this one are committed and remain; this one and everything after it are not. No \
         silent resolution of the collision is correct, so it is not guessed at."
    )]
    DuplicateMessageUuid {
        source_account: String,
        message_uuid: String,
        stored_conversation: String,
        incoming_conversation: String,
    },

    /// A sealed source refused a further import. Typed rather than a
    /// message so a caller can tell this apart from a parse failure
    /// without reading prose.
    #[error(
        "source '{source_account}' is sealed and refuses further imports. It was declared a \
         closed account when it was first imported, so its records are final. There is no \
         unseal; importing a different archive means a different source account."
    )]
    SourceSealed { source_account: String },

    /// An archive was turned away on its structural shape: member
    /// count, declared size, expansion ratio, or not being a readable
    /// zip at all. Distinct from a parse failure, which is about a
    /// member's contents rather than the archive's frame.
    #[error("archive refused: {0}")]
    ArchiveRefused(String),
}
