mod auth;
mod channel;
mod error;
pub mod orchestrator;
pub mod transport;

// Generated Cap'n Proto code
pub mod wirken_capnp {
    include!(concat!(env!("OUT_DIR"), "/schema/wirken_capnp.rs"));
}

pub use auth::{
    AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake, send_rejection,
};
pub use channel::{AuthenticatedChannel, Channel, ChannelMismatch, SessionHandle, SessionId};
pub use error::HandshakeError;
pub use error::IpcError;
pub use transport::{FrameReader, FrameWriter};

// Re-export channel markers for use by adapter crates
pub mod channels {
    pub use super::channel::{
        Discord, Generic, GoogleChat, IMessage, Matrix, Signal, Slack, Teams, Telegram,
    };
}

#[cfg(test)]
mod tests;
