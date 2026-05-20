pub mod alarm_log;
mod error;
mod event;
mod legacy_compat;
mod log;
pub mod pricing;
mod session_log;
pub mod siem;
pub mod siem_typed;
pub mod signing;
mod writer;

pub use alarm_log::{
    ACKNOWLEDGE_PROCEED_TYPES, AlarmLog, AlarmRecord, AlarmVerifyStatus,
    UnacknowledgedBlocksReport, VerifiedAlarmRecord,
};
pub use error::AuditError;
pub use event::{ActorKind, AuditEvent, StoredEvent};
pub use log::{AuditLog, AuditQuery, VerifyResult};
pub use session_log::{
    ApprovalScopeKind, ApprovalSource, ChainHeadReason, DenialSource, EgressDecision, HashHex,
    HexBytes, HookDecision, HookKind, HookSignatureStatus, HttpFetchOutcome, OwnSession,
    PermissionDenialRecord, PhaseDenyContent, PhaseExitReason, SchemaDriftRecord, SessionEvent,
    SessionHandle, SessionId, SessionLog, SessionScope, SessionVerifyResult, SkillDeniedReason,
    SqliteSessionLog, StoredSessionEvent, SubagentStatus, ToolCallRecord, TrustLevel,
};
pub use siem::{
    SentinelTypedEndpoint, SiemConfig, SiemForwarder, SiemTarget, build_datadog_payload,
    build_datadog_typed_entry, build_datadog_typed_payload, build_sentinel_payload,
    build_sentinel_typed_payload, build_splunk_body, build_splunk_typed_body,
    build_webhook_request, build_webhook_typed_request, compute_webhook_signature,
};
pub use siem_typed::{TYPED_POLL_INTERVAL, TypedEventForwarder, TypedSink, TypedTransport};
pub use signing::{
    AuditSigningKey, CHAIN_HEAD_DOMAIN, CHAIN_HEAD_SCHEMA_VERSION, audit_signing_dir,
};
pub use writer::AuditWriter;

#[cfg(test)]
mod tests;
