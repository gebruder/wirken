use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("capnp error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("capnp not-in-schema: {0}")]
    CapnpSchema(#[from] capnp::NotInSchema),

    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u64, max: u64 },
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("authentication rejected: {0}")]
    Rejected(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unknown adapter: {0}")]
    UnknownAdapter(String),

    #[error("unknown hook: {0}")]
    UnknownHook(String),

    #[error(
        "hook_type mismatch for {hook_id}: registered as {registered}, handshake claimed {claimed}"
    )]
    HookTypeMismatch {
        hook_id: String,
        registered: String,
        claimed: String,
    },

    #[error("timeout")]
    Timeout,

    #[error("protocol error: {0}")]
    Protocol(String),
}
