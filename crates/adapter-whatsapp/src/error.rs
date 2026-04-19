use thiserror::Error;

#[derive(Debug, Error)]
pub enum WhatsAppError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake error: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("whatsapp api error: {0}")]
    Api(String),

    #[error("webhook error: {0}")]
    Webhook(String),

    #[error("configuration error: {0}")]
    Config(String),
}
