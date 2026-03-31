use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake error: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("signal-cli error: {0}")]
    Signal(String),
}
