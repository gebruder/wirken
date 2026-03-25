mod auth;
mod channel;
mod error;
mod transport;

// Generated Cap'n Proto code
pub mod wirken_capnp {
    include!(concat!(env!("OUT_DIR"), "/schema/wirken_capnp.rs"));
}

pub use auth::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};
pub use error::HandshakeError;
pub use channel::{Channel, SessionHandle, SessionId};
pub use error::IpcError;
pub use transport::{FrameReader, FrameWriter};

// Re-export channel markers for use by adapter crates
pub mod channels {
    pub use super::channel::{Telegram, Discord, Slack, Matrix, Generic};
}

#[cfg(test)]
mod tests;
