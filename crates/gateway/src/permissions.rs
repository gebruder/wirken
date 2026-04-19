use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
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

impl PermissionTier {
    /// Human-readable label for the tier.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
        }
    }
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

/// Command prefixes that escalate a shell exec from the default
/// Tier 2 ("first-use approval, remembered for 30 days") to Tier 3
/// ("always prompt"). These are commands whose reasonable blast
/// radius is wide enough that a single "shell:curl" approval should
/// not cover every subsequent URL, or whose effects extend beyond
/// the local host (network egress, remote shells, container or
/// cluster mutations, privilege elevation, file transfer to/from
/// arbitrary peers). `git` is included for push/fetch but
/// read-only `git log` / `git status` also trigger Tier 3; the
/// tradeoff favours prompting on every git invocation over
/// silently permitting a `git push` with stored credentials.
pub const HIGH_RISK_PREFIXES: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "sudo", "su", "doas", "kubectl", "helm", "docker",
    "podman", "nc", "ncat", "socat", "git",
];

impl Action {
    /// Determine which tier this action belongs to.
    pub fn tier(&self) -> PermissionTier {
        match self {
            Action::WorkspaceFileAccess | Action::ChannelConverse | Action::WebSearch => {
                PermissionTier::Tier1
            }

            // Shell exec splits on command prefix: high-risk
            // prefixes (network egress, remote shells, cluster
            // mutations, privilege elevation) get Tier 3 and prompt
            // every time. Everything else keeps the Tier 2
            // first-use-approval behaviour. This does not change
            // the permissions.db schema; existing Tier 2 approvals
            // for newly-Tier-3 prefixes are ignored by `check`,
            // which never queries the store for Tier 3.
            Action::ShellExec { pattern } if HIGH_RISK_PREFIXES.contains(&pattern.as_str()) => {
                PermissionTier::Tier3
            }

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

/// Normalize a runtime `agent_id` to the logical agent id used in
/// `permissions.db`. The runtime hands permission checks the full
/// session-scoped id `{agent}/{channel}/{conversation}` (see
/// `session_id_for` in `wirken_agent::factory`); approvals are stored
/// per logical agent so a single approval applies across every
/// conversation on every channel for that agent. Returns the prefix
/// before the first `/`, or the input unchanged if no `/` is present.
fn canonical_agent_id(agent_id: &str) -> &str {
    agent_id.split('/').next().unwrap_or(agent_id)
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
             );",
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
        let agent_id = canonical_agent_id(agent_id);
        match action.tier() {
            PermissionTier::Tier1 => Ok(PermissionCheck::Allowed),
            PermissionTier::Tier2 => {
                let key = action.approval_key();
                match self.get_approval(&key, agent_id)? {
                    Some(approval) => {
                        if Utc::now() > approval.expires_at {
                            // Expired — needs re-approval
                            self.revoke(&key, agent_id)?;
                            Ok(PermissionCheck::NeedsApproval {
                                tier: PermissionTier::Tier2,
                            })
                        } else {
                            Ok(PermissionCheck::Allowed)
                        }
                    }
                    None => Ok(PermissionCheck::NeedsApproval {
                        tier: PermissionTier::Tier2,
                    }),
                }
            }
            PermissionTier::Tier3 => Ok(PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier3,
            }),
        }
    }

    /// Record an approval for a Tier 2 action.
    pub fn approve(
        &self,
        action: &Action,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        self.approve_by_key(&action.approval_key(), agent_id, approved_by)
    }

    /// Record an approval using a pre-computed action key. Callers
    /// that already have the key (e.g., the CLI `permissions approve`
    /// command, reading it off a past `PermissionDenied` audit entry)
    /// use this to avoid reparsing the key back into an [`Action`].
    /// Tier semantics are unchanged: Tier 3 keys can be stored but
    /// `check` ignores approvals for them.
    pub fn approve_by_key(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        let now = Utc::now();
        let expires = now + Duration::days(self.default_expiry_days as i64);

        self.conn.execute(
            "INSERT OR REPLACE INTO approvals (action_key, agent_id, approved_at, approved_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![action_key, agent_id, now.to_rfc3339(), approved_by, expires.to_rfc3339()],
        )?;

        Ok(Approval {
            action_key: action_key.to_string(),
            agent_id: agent_id.to_string(),
            approved_at: now,
            approved_by: approved_by.to_string(),
            expires_at: expires,
        })
    }

    /// Check whether a specific `action_key` has a current (non-expired)
    /// approval for `agent_id`. Used by `list-pending` to exclude
    /// already-approved denials.
    pub fn has_approval(&self, action_key: &str, agent_id: &str) -> Result<bool, GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        let mut stmt = self
            .conn
            .prepare("SELECT expires_at FROM approvals WHERE action_key = ?1 AND agent_id = ?2")?;
        let row = stmt
            .query_row(params![action_key, agent_id], |row| row.get::<_, String>(0))
            .optional()?;
        match row {
            None => Ok(false),
            Some(expires) => {
                let expires_at = parse_dt(&expires);
                Ok(Utc::now() < expires_at)
            }
        }
    }

    /// Revoke an approval.
    pub fn revoke(&self, action_key: &str, agent_id: &str) -> Result<(), GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        self.conn.execute(
            "DELETE FROM approvals WHERE action_key = ?1 AND agent_id = ?2",
            params![action_key, agent_id],
        )?;
        Ok(())
    }

    /// List all approvals for an agent.
    pub fn list(&self, agent_id: &str) -> Result<Vec<Approval>, GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        let mut stmt = self.conn.prepare(
            "SELECT action_key, agent_id, approved_at, approved_by, expires_at
             FROM approvals WHERE agent_id = ?1 ORDER BY approved_at DESC",
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

    fn get_approval(
        &self,
        action_key: &str,
        agent_id: &str,
    ) -> Result<Option<Approval>, GatewayError> {
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

#[cfg(test)]
mod tier_tests {
    use super::*;

    fn shell(pattern: &str) -> Action {
        Action::ShellExec {
            pattern: pattern.into(),
        }
    }

    #[test]
    fn high_risk_prefixes_are_tier3() {
        for p in HIGH_RISK_PREFIXES {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier3,
                "shell prefix `{p}` must be Tier 3"
            );
        }
    }

    #[test]
    fn expected_prefixes_are_listed() {
        // Regression: if this list is trimmed, failures here force
        // the change to be audited in review rather than slipping
        // through.
        let expected = [
            "curl", "wget", "ssh", "scp", "sftp", "sudo", "su", "doas", "kubectl", "helm",
            "docker", "podman", "nc", "ncat", "socat", "git",
        ];
        for p in &expected {
            assert!(
                HIGH_RISK_PREFIXES.contains(p),
                "`{p}` must be in HIGH_RISK_PREFIXES"
            );
        }
    }

    #[test]
    fn non_risky_shell_exec_stays_tier2() {
        // `ls`, `echo`, `cat`, `grep`, `rg`, `jq` etc. should keep
        // the first-use approval behaviour.
        for p in ["ls", "echo", "cat", "grep", "rg", "jq", "make"] {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier2,
                "shell prefix `{p}` must stay Tier 2"
            );
        }
    }

    #[test]
    fn other_action_tiers_unchanged() {
        assert_eq!(Action::WorkspaceFileAccess.tier(), PermissionTier::Tier1);
        assert_eq!(Action::WebSearch.tier(), PermissionTier::Tier1);
        assert_eq!(Action::ChannelConverse.tier(), PermissionTier::Tier1);
        assert_eq!(
            Action::ExternalFileAccess {
                path: "/etc/passwd".into(),
            }
            .tier(),
            PermissionTier::Tier2
        );
        assert_eq!(
            Action::CrossConversationMessage.tier(),
            PermissionTier::Tier2
        );
        assert_eq!(Action::DestructiveFileOp.tier(), PermissionTier::Tier3);
        assert_eq!(
            Action::NetworkRequest {
                domain: "example.com".into(),
            }
            .tier(),
            PermissionTier::Tier3
        );
        assert_eq!(Action::CredentialAccess.tier(), PermissionTier::Tier3);
        assert_eq!(Action::CronCreate.tier(), PermissionTier::Tier3);
        assert_eq!(Action::SkillInstall.tier(), PermissionTier::Tier3);
    }

    #[test]
    fn curl_always_needs_approval_even_after_prior_approve_call() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        // Store a Tier-2-style approval for shell:curl. The check
        // path for Tier 3 must ignore it. We exercise this because
        // existing installs may already hold such rows from before
        // 0.7.5; the new tier lookup must not surface them.
        store
            .approve(&shell("curl"), "default", "test-operator")
            .unwrap();
        let result = store.check(&shell("curl"), "default").unwrap();
        assert_eq!(
            result,
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier3,
            },
        );
    }

    #[test]
    fn ls_is_first_use_then_silent_until_expiry() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        // First call: no record, needs approval at Tier 2.
        let first = store.check(&shell("ls"), "default").unwrap();
        assert_eq!(
            first,
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
            },
        );
        // Operator approves once.
        store
            .approve(&shell("ls"), "default", "test-operator")
            .unwrap();
        // Subsequent calls within the 30-day window: allowed
        // without prompting. We check two calls to mirror the user
        // behavior "prompts once then runs silently".
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::Allowed
        );
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::Allowed
        );
    }

    #[test]
    fn approval_for_logical_agent_covers_session_scoped_check() {
        // The agent runtime passes the full session-scoped id
        // `{agent}/{channel}/{conversation}` into `check`. Approvals
        // are stored per logical agent, so the check must normalize
        // on the prefix before the first `/` or a webchat/Telegram
        // caller would never see a stored Tier 2 approval.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        store
            .approve(&shell("ls"), "default", "test-operator")
            .unwrap();

        assert_eq!(
            store
                .check(&shell("ls"), "default/webchat/webchat-default")
                .unwrap(),
            PermissionCheck::Allowed,
        );
        assert_eq!(
            store
                .check(&shell("ls"), "default/telegram/chat-42")
                .unwrap(),
            PermissionCheck::Allowed,
        );
        // approve_by_key called with a session-scoped id must also
        // normalize, so the stored row matches later checks.
        store
            .approve_by_key("shell:cat", "default/webchat/x", "test-operator")
            .unwrap();
        assert_eq!(
            store.check(&shell("cat"), "default").unwrap(),
            PermissionCheck::Allowed,
        );
    }
}
