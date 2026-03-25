use thiserror::Error;

#[derive(Debug, Error)]
pub enum TeamsError {
    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake failed: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("bot framework error: {0}")]
    BotFramework(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("http error: {0}")]
    Http(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
