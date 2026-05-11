pub mod alarm_log;
mod error;
mod event;
mod legacy_compat;
mod log;
mod session_log;
pub mod siem;
pub mod signing;
mod writer;

pub use alarm_log::{AlarmLog, AlarmRecord, AlarmVerifyStatus, VerifiedAlarmRecord};
pub use error::AuditError;
pub use event::{ActorKind, AuditEvent, StoredEvent};
pub use log::{AuditLog, AuditQuery, VerifyResult};
pub use session_log::{
    ChainHeadReason, DenialSource, HashHex, HexBytes, HttpFetchOutcome, OwnSession,
    PermissionDenialRecord, SessionEvent, SessionHandle, SessionId, SessionLog, SessionScope,
    SessionVerifyResult, SqliteSessionLog, StoredSessionEvent, SubagentStatus, ToolCallRecord,
    TrustLevel,
};
pub use siem::{SiemConfig, SiemForwarder, SiemTarget, compute_webhook_signature};
pub use signing::{
    AuditSigningKey, CHAIN_HEAD_DOMAIN, CHAIN_HEAD_SCHEMA_VERSION, audit_signing_dir,
};
pub use writer::AuditWriter;

#[cfg(test)]
mod tests;
