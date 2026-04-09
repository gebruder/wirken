mod error;
mod event;
mod legacy_compat;
mod log;
mod session_log;
pub mod siem;
mod writer;

pub use error::AuditError;
pub use event::AuditEvent;
pub use log::{AuditLog, AuditQuery, VerifyResult};
pub use session_log::{
    HashHex, HexBytes, OwnSession, SessionEvent, SessionHandle, SessionId, SessionLog,
    SessionScope, SessionVerifyResult, SqliteSessionLog, StoredSessionEvent, ToolCallRecord,
    TrustLevel,
};
pub use siem::{SiemConfig, SiemForwarder, SiemTarget};
pub use writer::AuditWriter;

#[cfg(test)]
mod tests;
