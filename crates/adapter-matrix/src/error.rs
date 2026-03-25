use thiserror::Error;

#[derive(Debug, Error)]
pub enum MatrixError {
    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake failed: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("matrix error: {0}")]
    Matrix(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
