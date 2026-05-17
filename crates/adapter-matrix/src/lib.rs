//! Matrix adapter for Wirken. Bridges the Matrix Client-Server
//! API to the gateway IPC. Approval gating uses m.reaction events
//! with a closed-enum decision set (✅ allow, ❌ deny) and a
//! per-room correlation table mapping the bot's outbound
//! approval-request event id to the gateway's `request_id`. The
//! umbrella convention is documented at #119.
//!
//! ## Cross-adapter ack/feedback taxonomy (closed eight-adapter set)
//!
//! Umbrella #119 closed with the iMessage slice; the eight-
//! adapter set falls into three groups by how a clicker /
//! reactor / commander sees their interaction acknowledged:
//!
//! - **Ephemeral-via-platform-mechanism**: Telegram (callback-
//!   query toast), Discord (ephemeral interaction response),
//!   Slack (`chat.postEphemeral`), Google Chat
//!   (`privateMessageViewer` on inline action response).
//!   Platform supports a clicker-only feedback affordance; the
//!   adapter uses it.
//! - **Silent-ack-because-platform-absent**: Teams (no
//!   in-conversation ephemeral; silent 200 OK), WhatsApp (no
//!   ephemeral primitive; silent 200 OK), Matrix (no inbound-ack
//!   mechanism over CS API; reactor's own client renders the
//!   reaction as visual feedback). Genuine platform absence, not
//!   a posture choice.
//! - **Text-command-with-no-toast-by-shape**: Signal, iMessage.
//!   Operator's reply confirming the command lands as the natural
//!   feedback; no separate toast affordance. Both share a
//!   verbatim parser (factoring to a shared crate is filed as a
//!   follow-up to the umbrella close).
//!
//! Matrix joins the silent-ack group with Teams and WhatsApp.
//! The three groups carry four / three / two adapters
//! respectively; the partition is final.

pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::MatrixAdapter;
pub use error::MatrixError;

#[cfg(test)]
mod tests;
