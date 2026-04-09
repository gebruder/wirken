//! Legacy [`AuditLog`] API. Slice 2 of item 1 makes this a thin
//! façade over [`SqliteSessionLog`] — see
//! `docs/managed-agents-parity.md` for the full design.
//!
//! The public surface is unchanged for the existing CLI commands
//! (`wirken audit log`, `wirken audit verify`) and for the
//! [`AuditWriter`] flush task. Internally:
//!
//! - `audit_events` is no longer a real table — it is a SQL view
//!   over `session_events` defined in [`crate::legacy_compat`].
//! - `write_batch` converts each [`AuditEvent`] into a
//!   [`SessionEvent::AuditLegacy`] and routes through
//!   [`SqliteSessionLog::append_with_ts`].
//! - `query` reads through the view.
//! - `verify` walks every per-session chain in `session_events` and
//!   reports an aggregate result.
//! - `prune` deletes rows older than the retention window from each
//!   session, preserving each chain by keeping a checkpoint.
//!
//! Migration runs idempotently on every [`AuditLog::open`]: if a
//! pre-slice-2 `audit_events` table exists, its rows are copied into
//! `session_events` under the `__pre_migration__` sentinel session
//! and the table is replaced by the view.
//!
//! [`AuditWriter`]: crate::AuditWriter
//! [`SessionEvent::AuditLegacy`]: crate::SessionEvent::AuditLegacy

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::AuditError;
use crate::event::{AuditEvent, StoredEvent};
use crate::legacy_compat;
use crate::session_log::SqliteSessionLog;

/// Query parameters for filtering audit events.
#[derive(Debug, Default)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub channel: Option<String>,
    pub actor: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
}

/// Result of hash chain verification.
///
/// Slice 2 changes the underlying semantics: the chain is now
/// per-session, not global. `Ok::rows_verified` is the total across
/// every session in `session_events`. `Broken` is reported on the
/// first session whose chain is broken; `expected` carries the
/// session id and seq, `found` carries the underlying break reason.
#[derive(Debug)]
pub enum VerifyResult {
    /// All per-session chains are intact.
    Ok { rows_verified: usize },
    /// At least one per-session chain is broken.
    Broken {
        row_id: i64,
        expected: String,
        found: String,
    },
    /// No session events present.
    Empty,
}

/// Façade over [`SqliteSessionLog`] that preserves the legacy
/// [`AuditLog`] API.
pub struct AuditLog {
    inner: Arc<SqliteSessionLog>,
}

impl AuditLog {
    /// Open or create an audit log at `db_path`. Runs the
    /// idempotent migration from the pre-slice-2 `audit_events`
    /// table layout to the new `session_events` table + view.
    pub fn open(db_path: &Path) -> Result<Self, AuditError> {
        let inner = SqliteSessionLog::open(db_path)?;
        legacy_compat::migrate_legacy_audit_events(&inner)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Open an in-memory audit log (test helper). The view is
    /// created on the fresh in-memory database; no legacy table
    /// exists, so migration is a no-op.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let inner = SqliteSessionLog::open_in_memory()?;
        legacy_compat::migrate_legacy_audit_events(&inner)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Borrow the inner session log. Used by the [`AuditWriter`]
    /// flush task to share a single log instance across the writer
    /// and any future direct callers.
    ///
    /// [`AuditWriter`]: crate::AuditWriter
    pub fn session_log(&self) -> Arc<SqliteSessionLog> {
        self.inner.clone()
    }

    /// Write a batch of [`AuditEvent`]s. Each event is converted
    /// into a [`crate::SessionEvent::AuditLegacy`] and appended to
    /// the session log under the event's `session` field, or under
    /// the system sentinel session if `session` is empty.
    pub fn write_batch(&self, events: &[AuditEvent]) -> Result<(), AuditError> {
        for event in events {
            legacy_compat::write_legacy(&self.inner, event)?;
        }
        Ok(())
    }

    /// Query audit events through the legacy `audit_events` view.
    pub fn query(&self, q: &AuditQuery) -> Result<Vec<StoredEvent>, AuditError> {
        legacy_compat::query_legacy(&self.inner, q)
    }

    /// Verify every per-session chain in `session_events`.
    pub fn verify(&self) -> Result<VerifyResult, AuditError> {
        legacy_compat::verify_legacy(&self.inner)
    }

    /// Prune events older than `retention_days`. Per-session chains
    /// are preserved by keeping the most recent event before the
    /// cutoff in each session as a checkpoint.
    pub fn prune(&self, retention_days: u32) -> Result<usize, AuditError> {
        legacy_compat::prune_legacy(&self.inner, retention_days)
    }
}
