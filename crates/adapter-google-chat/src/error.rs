use thiserror::Error;

#[derive(Debug, Error)]
pub enum GoogleChatError {
    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake failed: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("google chat api error: {0}")]
    Api(String),

    #[error("webhook error: {0}")]
    Webhook(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
