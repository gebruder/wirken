//! Matrix adapter for Wirken. Bridges the Matrix Client-Server
//! API to the gateway IPC. Approval gating uses m.reaction events
//! with a closed-enum decision set (✅ allow, ❌ deny) and a
//! per-room correlation table mapping the bot's outbound
//! approval-request event id to the gateway's `request_id`. The
//! umbrella convention is documented at #119.
//!
//! ## Cross-adapter ack/feedback taxonomy
//!
//! As of the eighth-adapter close-out of umbrella #119, the
//! button-and-text-and-reaction adapter set falls into three
//! groups by how a clicker / reactor / commander sees their
//! interaction acknowledged:
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
//!   a posture choice; recorded so a future maintainer doesn't
//!   re-litigate the silent-ack decision as if it were a
//!   convention call.
//! - **Text-command-with-no-toast-by-shape**: Signal (text
//!   reply confirming the command lands as the natural feedback;
//!   no separate toast affordance). iMessage's shape is TBD and
//!   will join this or one of the others depending on its
//!   approval encoding decision.
//!
//! Matrix joins the silent-ack group with Teams and WhatsApp.

pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::MatrixAdapter;
pub use error::MatrixError;

#[cfg(test)]
mod tests;
