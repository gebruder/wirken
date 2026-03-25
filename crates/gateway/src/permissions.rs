use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::GatewayError;

/// Permission tiers from the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionTier {
    /// Always allowed — no approval needed.
    Tier1,
    /// First-use approval, then remembered.
    Tier2,
    /// Always prompt.
    Tier3,
}

/// An action that requires permission checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    // Tier 1 — always allowed
    WorkspaceFileAccess,
    ChannelConverse,
    WebSearch,

    // Tier 2 — first-use approval
    ShellExec { pattern: String },
    ExternalFileAccess { path: String },
    CrossConversationMessage,

    // Tier 3 — always prompt
    DestructiveFileOp,
    NetworkRequest { domain: String },
    CredentialAccess,
    CronCreate,
    SkillInstall,
}

impl Action {
    /// Determine which tier this action belongs to.
    pub fn tier(&self) -> PermissionTier {
        match self {
            Action::WorkspaceFileAccess
            | Action::ChannelConverse
            | Action::WebSearch => PermissionTier::Tier1,

            Action::ShellExec { .. }
            | Action::ExternalFileAccess { .. }
            | Action::CrossConversationMessage => PermissionTier::Tier2,

            Action::DestructiveFileOp
            | Action::NetworkRequest { .. }
            | Action::CredentialAccess
            | Action::CronCreate
            | Action::SkillInstall => PermissionTier::Tier3,
        }
    }

    /// The canonical key for storing approval (Tier 2 actions).
    pub fn approval_key(&self) -> String {
        match self {
            Action::ShellExec { pattern } => format!("shell:{pattern}"),
            Action::ExternalFileAccess { path } => format!("file:{path}"),
            Action::CrossConversationMessage => "cross-conversation".to_string(),
            other => format!("{other:?}"),
        }
    }
}

/// A stored permission approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub action_key: String,
    pub agent_id: String,
    pub approved_at: DateTime<Utc>,
    pub approved_by: String,
    pub expires_at: DateTime<Utc>,
}

/// Permission store backed by SQLite.
pub struct PermissionStore {
    conn: Connection,
    default_expiry_days: u32,
}

impl PermissionStore {
    /// Open or create the permission store.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS approvals (
                 action_key TEXT NOT NULL,
                 agent_id TEXT NOT NULL,
                 approved_at TEXT NOT NULL,
                 approved_by TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 PRIMARY KEY (action_key, agent_id)
             );"
        )?;

        Ok(Self {
            conn,
            default_expiry_days: 30,
        })
    }

    /// Check if an action is allowed for a given agent.
    /// Returns:
    /// - Ok(true) for Tier 1 (always allowed) or approved Tier 2
    /// - Ok(false) for unapproved Tier 2 or any Tier 3
    /// - Err for database errors
    pub fn check(&self, action: &Action, agent_id: &str) -> Result<PermissionCheck, GatewayError> {
        match action.tier() {
            PermissionTier::Tier1 => Ok(PermissionCheck::Allowed),
            PermissionTier::Tier2 => {
                let key = action.approval_key();
                match self.get_approval(&key, agent_id)? {
                    Some(approval) => {
                        if Utc::now() > approval.expires_at {
                            // Expired — needs re-approval
                            self.revoke(&key, agent_id)?;
                            Ok(PermissionCheck::NeedsApproval { tier: PermissionTier::Tier2 })
                        } else {
                            Ok(PermissionCheck::Allowed)
                        }
                    }
                    None => Ok(PermissionCheck::NeedsApproval { tier: PermissionTier::Tier2 }),
                }
            }
            PermissionTier::Tier3 => {
                Ok(PermissionCheck::NeedsApproval { tier: PermissionTier::Tier3 })
            }
        }
    }

    /// Record an approval for a Tier 2 action.
    pub fn approve(
        &self,
        action: &Action,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        let key = action.approval_key();
        let now = Utc::now();
        let expires = now + Duration::days(self.default_expiry_days as i64);

        self.conn.execute(
            "INSERT OR REPLACE INTO approvals (action_key, agent_id, approved_at, approved_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key, agent_id, now.to_rfc3339(), approved_by, expires.to_rfc3339()],
        )?;

        Ok(Approval {
            action_key: key,
            agent_id: agent_id.to_string(),
            approved_at: now,
            approved_by: approved_by.to_string(),
            expires_at: expires,
        })
    }

    /// Revoke an approval.
    pub fn revoke(&self, action_key: &str, agent_id: &str) -> Result<(), GatewayError> {
        self.conn.execute(
            "DELETE FROM approvals WHERE action_key = ?1 AND agent_id = ?2",
            params![action_key, agent_id],
        )?;
        Ok(())
    }

    /// List all approvals for an agent.
    pub fn list(&self, agent_id: &str) -> Result<Vec<Approval>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT action_key, agent_id, approved_at, approved_by, expires_at
             FROM approvals WHERE agent_id = ?1 ORDER BY approved_at DESC"
        )?;

        let rows = stmt.query_map(params![agent_id], |row| {
            Ok(Approval {
                action_key: row.get(0)?,
                agent_id: row.get(1)?,
                approved_at: parse_dt(&row.get::<_, String>(2)?),
                approved_by: row.get(3)?,
                expires_at: parse_dt(&row.get::<_, String>(4)?),
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    fn get_approval(&self, action_key: &str, agent_id: &str) -> Result<Option<Approval>, GatewayError> {
        let result = self.conn.query_row(
            "SELECT action_key, agent_id, approved_at, approved_by, expires_at
             FROM approvals WHERE action_key = ?1 AND agent_id = ?2",
            params![action_key, agent_id],
            |row| {
                Ok(Approval {
                    action_key: row.get(0)?,
                    agent_id: row.get(1)?,
                    approved_at: parse_dt(&row.get::<_, String>(2)?),
                    approved_by: row.get(3)?,
                    expires_at: parse_dt(&row.get::<_, String>(4)?),
                })
            },
        );

        match result {
            Ok(approval) => Ok(Some(approval)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GatewayError::Database(e)),
        }
    }
}

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionCheck {
    /// Action is allowed (Tier 1 or approved Tier 2).
    Allowed,
    /// Action needs user approval before proceeding.
    NeedsApproval { tier: PermissionTier },
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
