use thiserror::Error;

#[derive(Debug, Error)]
pub enum TelegramError {
    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake failed: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("teloxide error: {0}")]
    Teloxide(String),

    #[error("not connected to gateway")]
    NotConnected,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
