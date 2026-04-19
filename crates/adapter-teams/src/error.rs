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

    #[error("configuration error: {0}")]
    Config(String),
}

/// Reason an inbound webhook JWT was rejected. Surfaces as a 401
/// on the wire; the variant is only for logs and tests.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing Authorization header")]
    MissingHeader,
    #[error("malformed Authorization header")]
    MalformedHeader,
    #[error("jwt header parse failed: {0}")]
    JwtHeader(String),
    #[error("jwt signature or claim validation failed: {0}")]
    JwtValidation(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
    #[error("unknown signing key id: {0}")]
    UnknownKid(String),
    #[error("issuer not accepted: {0}")]
    IssuerRejected(String),
}
