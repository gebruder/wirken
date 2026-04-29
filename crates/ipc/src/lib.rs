mod auth;
mod channel;
mod error;
pub mod orchestrator;
pub mod principal;
pub mod stream;

#[cfg(unix)]
pub mod transport;

// Generated Cap'n Proto code
pub mod wirken_capnp {
    include!(concat!(env!("OUT_DIR"), "/schema/wirken_capnp.rs"));
}

pub use auth::AdapterIdentity;
#[cfg(unix)]
pub use auth::{perform_adapter_handshake, perform_gateway_handshake, send_rejection};
pub use channel::{AuthenticatedChannel, Channel, ChannelMismatch, SessionHandle, SessionId};
pub use error::HandshakeError;
pub use error::IpcError;
pub use principal::{ParsePrincipalError, Principal};
pub use stream::{BoxStream, Stream};

#[cfg(unix)]
pub use stream::test_pair;
#[cfg(unix)]
pub use transport::{FrameReader, FrameWriter};

// Re-export channel markers for use by adapter crates
pub mod channels {
    pub use super::channel::{
        Discord, Generic, GoogleChat, IMessage, Matrix, Signal, Slack, Teams, Telegram,
    };
}

#[cfg(test)]
mod tests;
