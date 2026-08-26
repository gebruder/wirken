use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscordError {
    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake failed: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    // Boxed: `serenity::Error` is by far the largest variant here, and
    // inlining it pushes `DiscordError` past the `result_large_err`
    // threshold for every function returning it. The `From` impl below
    // is written out rather than derived with `#[from]` so that `?` on a
    // `serenity::Error` still converts and no call site has to know the
    // variant is boxed.
    #[error("serenity error: {0}")]
    Serenity(#[source] Box<serenity::Error>),

    #[error("not connected to gateway")]
    NotConnected,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<serenity::Error> for DiscordError {
    fn from(e: serenity::Error) -> Self {
        Self::Serenity(Box::new(e))
    }
}
