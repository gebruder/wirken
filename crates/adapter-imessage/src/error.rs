use thiserror::Error;

#[derive(Debug, Error)]
pub enum IMessageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake error: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("bluebubbles api error: {0}")]
    BlueBubbles(String),
}
