//! Approver allowlist for channel-adapter approval gates.
//!
//! Channel adapters cross a trust boundary that the CLI sidesteps:
//! an authenticated channel user (a Telegram user id verified by
//! the bot's update stream, a Slack user id verified by the
//! workspace's auth) is not automatically an authorized approver.
//! The allowlist lives here, gateway-side, keyed by
//! `(adapter_id, user_id)`.
//!
//! Authorization is centralized at the gateway, not pushed to the
//! adapter. The adapter forwards every callback press to the
//! gateway via the `ApprovalDecision` frame; the gateway calls
//! `verify` against this registry before resolving the
//! `PendingApprovalQueue`. The alternative, caching the allowlist
//! at the adapter and validating before forwarding, would create
//! a synchronization problem (invalidation on `remove`, sync on
//! reconnect, race between `remove` and a button press) for no
//! operational benefit. Single source of truth.
//!
//! The approval-conversation configuration lives alongside in a
//! sibling `adapter_approval_conversations` table keyed by
//! `adapter_id`. Stores the adapter-native conversation id as
//! TEXT (Telegram serializes its `i64` chat_id; Signal carries
//! the base64 group_id or E.164/UUID for DM channels; other
//! adapters whatever their conversation primitive is). Same
//! schema-file and connection as the `approvers` table, and read
//! the same way: on every call, so a change from the CLI's process
//! applies without a restart.

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

use crate::error::GatewayError;

/// A registered approver for one channel adapter.
#[derive(Debug, Clone)]
pub struct ApproverEntry {
    pub adapter_id: String,
    /// Platform-side user id. Telegram is `i64`, Slack and others
    /// vary. The table stores it as `TEXT` so every adapter can
    /// pick its natural encoding without a column-type migration.
    pub user_id: String,
    /// Operator-supplied display label. Surfaces on the audit
    /// chain's `approved_by` field via
    /// `ApprovalOutcome.actor`. Empty when the operator did not
    /// supply one; callers fall back to the user_id itself.
    pub display_name: String,
}

/// SQLite-backed approver allowlist, read on every call.
///
/// There is no cache: `verify`, `display_name` and
/// `approval_conversation` query the database each time, so a change
/// `wirken approvers` makes from its own process applies to the next
/// decision without a restart, and a removed approver cannot answer the
/// next request. A read that fails admits nobody: `verify` answers
/// false and `approval_conversation` none, which the channel gates
/// already treat as fail-closed.
///
/// `Connection` is `!Sync` because rusqlite holds a `RefCell` for
/// statement caching. Wrapping it in a `Mutex` inside the struct
/// makes `Arc<ApproverRegistry>` shareable across tokio tasks
/// without forcing callers to wrap externally.
pub struct ApproverRegistry {
    conn: Mutex<Connection>,
}

/// How long SQLite waits on a lock before an operation fails. The CLI
/// writes while the gateway reads; WAL lets those run together, and
/// this covers the brief write lock a checkpoint takes.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl ApproverRegistry {
    /// Open or create the approver registry at `db_path`.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS approvers (
                 adapter_id TEXT NOT NULL,
                 user_id TEXT NOT NULL,
                 display_name TEXT NOT NULL DEFAULT '',
                 added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY (adapter_id, user_id)
             );
             CREATE TABLE IF NOT EXISTS adapter_approval_conversations (
                 adapter_id TEXT PRIMARY KEY,
                 conversation_id TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add `(adapter_id, user_id)` to the allowlist. Idempotent:
    /// repeated calls with the same key update the display name.
    /// Returns whether the entry is new.
    /// CLI surface: `wirken approvers add <adapter_id> <user_id>`.
    pub fn register(
        &self,
        adapter_id: &str,
        user_id: &str,
        display_name: &str,
    ) -> Result<bool, GatewayError> {
        let conn = self.conn();
        let existed = conn
            .query_row(
                "SELECT 1 FROM approvers WHERE adapter_id = ?1 AND user_id = ?2",
                params![adapter_id, user_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        conn.execute(
            "INSERT INTO approvers (adapter_id, user_id, display_name) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(adapter_id, user_id) DO UPDATE SET display_name = excluded.display_name",
            params![adapter_id, user_id, display_name],
        )?;
        Ok(!existed)
    }

    /// Remove `(adapter_id, user_id)` from the allowlist. Returns
    /// `Ok(false)` when the entry was not present (idempotent for
    /// the operator's perspective; the CLI prints "no such
    /// approver" but doesn't fail).
    pub fn unregister(&self, adapter_id: &str, user_id: &str) -> Result<bool, GatewayError> {
        let changes = self.conn().execute(
            "DELETE FROM approvers WHERE adapter_id = ?1 AND user_id = ?2",
            params![adapter_id, user_id],
        )?;
        Ok(changes > 0)
    }

    /// True iff `(adapter_id, user_id)` is in the allowlist now.
    /// Called by the gateway's `ApprovalDecision` handler before
    /// resolving the queue entry. Unauthorized presses are silently
    /// dropped at the call site; this method just answers yes/no. A
    /// read that fails answers no.
    pub fn verify(&self, adapter_id: &str, user_id: &str) -> bool {
        match self
            .conn()
            .query_row(
                "SELECT 1 FROM approvers WHERE adapter_id = ?1 AND user_id = ?2",
                params![adapter_id, user_id],
                |_| Ok(()),
            )
            .optional()
        {
            Ok(found) => found.is_some(),
            Err(e) => {
                tracing::error!(
                    adapter_id,
                    error = %e,
                    "approver allowlist could not be read; refusing the decision"
                );
                false
            }
        }
    }

    /// Display name for `(adapter_id, user_id)` if registered.
    /// Used as the audit row's actor label fallback when the
    /// adapter's `ApprovalDecision` frame did not carry a display.
    pub fn display_name(&self, adapter_id: &str, user_id: &str) -> Option<String> {
        self.conn()
            .query_row(
                "SELECT display_name FROM approvers WHERE adapter_id = ?1 AND user_id = ?2",
                params![adapter_id, user_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Set the approval conversation for `adapter_id`. Channel
    /// gates read this at `request_approval` time to populate
    /// `ApprovalRequest.targetConversationId`. Adapter-native
    /// encoding (Telegram: stringified `i64`; Signal: base64
    /// group_id or E.164/UUID); the registry stores the value
    /// verbatim and the adapter parses on receipt. Overwrites any
    /// prior value, and returns it.
    pub fn set_approval_conversation(
        &self,
        adapter_id: &str,
        conversation_id: &str,
    ) -> Result<Option<String>, GatewayError> {
        let conn = self.conn();
        let previous: Option<String> = conn
            .query_row(
                "SELECT conversation_id FROM adapter_approval_conversations WHERE adapter_id = ?1",
                params![adapter_id],
                |row| row.get(0),
            )
            .optional()?;
        conn.execute(
            "INSERT INTO adapter_approval_conversations (adapter_id, conversation_id) \
             VALUES (?1, ?2) \
             ON CONFLICT(adapter_id) DO UPDATE SET conversation_id = excluded.conversation_id",
            params![adapter_id, conversation_id],
        )?;
        Ok(previous)
    }

    /// Remove `adapter_id`'s approval conversation, so its gate fails
    /// closed. Used to undo a `set-chat` whose audit row could not be
    /// written when none was set before it.
    pub fn clear_approval_conversation(&self, adapter_id: &str) -> Result<bool, GatewayError> {
        let changes = self.conn().execute(
            "DELETE FROM adapter_approval_conversations WHERE adapter_id = ?1",
            params![adapter_id],
        )?;
        Ok(changes > 0)
    }

    /// Approval conversation id for `adapter_id`, or `None` when
    /// none is configured or it could not be read. `None` triggers a
    /// startup `tracing::warn` at `wirken run` and a fail-closed
    /// preflight in the gate.
    pub fn approval_conversation(&self, adapter_id: &str) -> Option<String> {
        match self
            .conn()
            .query_row(
                "SELECT conversation_id FROM adapter_approval_conversations WHERE adapter_id = ?1",
                params![adapter_id],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(found) => found,
            Err(e) => {
                tracing::error!(
                    adapter_id,
                    error = %e,
                    "approval conversation could not be read; no approval chat"
                );
                None
            }
        }
    }

    /// List approvers, optionally filtered by adapter. CLI
    /// surface: `wirken approvers list [--adapter <id>]`.
    pub fn list(&self, adapter_id: Option<&str>) -> Result<Vec<ApproverEntry>, GatewayError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT adapter_id, user_id, display_name FROM approvers \
             WHERE ?1 IS NULL OR adapter_id = ?1 ORDER BY adapter_id, user_id",
        )?;
        let rows = stmt.query_map(params![adapter_id], |row| {
            Ok(ApproverEntry {
                adapter_id: row.get(0)?,
                user_id: row.get(1)?,
                display_name: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, ApproverRegistry) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("approvers.db");
        let reg = ApproverRegistry::open(&path).unwrap();
        (tmp, reg)
    }

    #[test]
    fn register_then_verify_succeeds() {
        let (_tmp, reg) = fresh();
        reg.register("telegram", "12345", "davi").unwrap();
        assert!(reg.verify("telegram", "12345"));
        assert_eq!(
            reg.display_name("telegram", "12345").as_deref(),
            Some("davi")
        );
    }

    #[test]
    fn verify_rejects_unregistered_user() {
        let (_tmp, reg) = fresh();
        reg.register("telegram", "12345", "davi").unwrap();
        assert!(!reg.verify("telegram", "99999"));
    }

    #[test]
    fn verify_rejects_user_under_different_adapter() {
        // The same telegram_user_id is not automatically allowed
        // across multiple adapters (e.g., test bot vs prod bot).
        // The key is the (adapter_id, user_id) pair.
        let (_tmp, reg) = fresh();
        reg.register("telegram-prod", "12345", "davi").unwrap();
        assert!(!reg.verify("telegram-test", "12345"));
    }

    #[test]
    fn register_is_idempotent_and_updates_display_name() {
        let (_tmp, reg) = fresh();
        reg.register("telegram", "12345", "davi").unwrap();
        reg.register("telegram", "12345", "Davi Ottenheimer")
            .unwrap();
        assert_eq!(
            reg.display_name("telegram", "12345").as_deref(),
            Some("Davi Ottenheimer")
        );
    }

    #[test]
    fn unregister_removes_and_returns_true_on_first_removal() {
        let (_tmp, reg) = fresh();
        reg.register("telegram", "12345", "davi").unwrap();
        assert!(reg.unregister("telegram", "12345").unwrap());
        assert!(!reg.verify("telegram", "12345"));
    }

    #[test]
    fn unregister_returns_false_for_unknown_user() {
        let (_tmp, reg) = fresh();
        assert!(!reg.unregister("telegram", "12345").unwrap());
    }

    #[test]
    fn set_and_get_approval_conversation_round_trips() {
        let (_tmp, reg) = fresh();
        reg.set_approval_conversation("telegram", "-100123456789")
            .unwrap();
        assert_eq!(
            reg.approval_conversation("telegram").as_deref(),
            Some("-100123456789")
        );
    }

    #[test]
    fn approval_conversation_unset_returns_none() {
        let (_tmp, reg) = fresh();
        assert_eq!(reg.approval_conversation("telegram"), None);
    }

    #[test]
    fn set_approval_conversation_overwrites_prior_value() {
        let (_tmp, reg) = fresh();
        reg.set_approval_conversation("telegram", "100").unwrap();
        reg.set_approval_conversation("telegram", "200").unwrap();
        assert_eq!(
            reg.approval_conversation("telegram").as_deref(),
            Some("200")
        );
    }

    #[test]
    fn approval_conversation_carries_non_numeric_signal_group_id() {
        // Signal group ids are base64, not numeric. The TEXT-typed
        // column is the contract that makes this work; this test
        // pins the contract.
        let (_tmp, reg) = fresh();
        reg.set_approval_conversation("signal", "9LJqVbY9wKD2c3vH/abcDEF==")
            .unwrap();
        assert_eq!(
            reg.approval_conversation("signal").as_deref(),
            Some("9LJqVbY9wKD2c3vH/abcDEF==")
        );
    }

    #[test]
    fn list_filters_by_adapter() {
        let (_tmp, reg) = fresh();
        reg.register("telegram", "1", "alice").unwrap();
        reg.register("telegram", "2", "bob").unwrap();
        reg.register("discord", "3", "carol").unwrap();
        let mut tg = reg.list(Some("telegram")).unwrap();
        tg.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        assert_eq!(tg.len(), 2);
        assert_eq!(tg[0].user_id, "1");
        assert_eq!(tg[1].user_id, "2");
        let all = reg.list(None).unwrap();
        assert_eq!(all.len(), 3);
    }

    /// The gateway and `wirken approvers` hold separate connections. A
    /// change from the CLI's is seen on the gateway's next read, with no
    /// reopen.
    #[test]
    fn a_change_from_another_connection_is_seen_on_the_next_read() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("approvers.db");
        let gateway = ApproverRegistry::open(&path).unwrap();
        let cli = ApproverRegistry::open(&path).unwrap();
        assert!(cli.register("signal", "U1", "davi").unwrap());
        assert!(gateway.verify("signal", "U1"));
        assert_eq!(
            gateway.display_name("signal", "U1").as_deref(),
            Some("davi")
        );
        cli.set_approval_conversation("signal", "group-1").unwrap();
        assert_eq!(
            gateway.approval_conversation("signal").as_deref(),
            Some("group-1")
        );
        assert!(cli.unregister("signal", "U1").unwrap());
        assert!(!gateway.verify("signal", "U1"));
        assert!(cli.register("signal", "U2", "").unwrap(), "a new entry");
        assert!(
            !cli.register("signal", "U2", "x").unwrap(),
            "an existing entry"
        );
    }

    #[test]
    fn entries_persist_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("approvers.db");
        {
            let reg = ApproverRegistry::open(&path).unwrap();
            reg.register("telegram", "12345", "davi").unwrap();
            reg.set_approval_conversation("telegram", "-100123456789")
                .unwrap();
        }
        let reg = ApproverRegistry::open(&path).unwrap();
        assert!(reg.verify("telegram", "12345"));
        assert_eq!(
            reg.approval_conversation("telegram").as_deref(),
            Some("-100123456789")
        );
    }
}
