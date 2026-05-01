pub mod alarm_log;
mod error;
mod event;
mod legacy_compat;
mod log;
mod session_log;
pub mod siem;
mod writer;

pub use alarm_log::{AlarmLog, AlarmRecord};
pub use error::AuditError;
pub use event::{AuditEvent, StoredEvent};
pub use log::{AuditLog, AuditQuery, VerifyResult};
pub use session_log::{
    HashHex, HexBytes, OwnSession, PermissionDenialRecord, SessionEvent, SessionHandle, SessionId,
    SessionLog, SessionScope, SessionVerifyResult, SqliteSessionLog, StoredSessionEvent,
    ToolCallRecord, TrustLevel,
};
pub use siem::{SiemConfig, SiemForwarder, SiemTarget};
pub use writer::AuditWriter;

#[cfg(test)]
mod tests;
