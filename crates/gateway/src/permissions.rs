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
}

impl std::fmt::Display for Action {
    /// Stable snake_case label. SIEM consumers group by this string;
    /// the `Debug` form would carry struct payloads (`ShellExec { pattern: "curl" }`)
    /// which is not stable wire shape.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Action::WorkspaceFileAccess => "workspace_file_access",
            Action::ChannelConverse => "channel_converse",
            Action::WebSearch => "web_search",
            Action::ShellExec { .. } => "shell_exec",
            Action::ExternalFileAccess { .. } => "external_file_access",
            Action::CrossConversationMessage => "cross_conversation_message",
            Action::DestructiveFileOp => "destructive_file_op",
            Action::NetworkRequest { .. } => "network_request",
            Action::CredentialAccess => "credential_access",
            Action::CronCreate => "cron_create",
        };
        f.write_str(label)
    }
}

/// Commands whose shell-exec pattern keeps the default Tier 2
/// ("first-use approval, remembered for 30 days") behaviour. Every
/// other exec prefix escalates to Tier 3 ("always prompt"). This is
/// an allowlist, not a denylist: the previous denylist grew without
/// bound because every new shell wrapper (`sh`/`env`/`xargs`/...)
/// and every language interpreter with `-c`/`-e` eval (`python`,
/// `node`, `perl`, `ruby`, `lua`, `awk`, `sed` with GNU `s///e`,
/// ...) can launder an arbitrary inner verb past the gate. The
/// allowlist collapses the wrapper-laundering class in one rule:
/// if a verb is not on this list, it prompts.
///
/// Every verb here is pure inspection / identity / path math with
/// no documented `-exec`, `--*-program`, `!`, `$PAGER`, or
/// `system()`-style escape hatch after man-page review. Notable
/// exclusions even among "read-only looking" tools:
/// - `rg` has `--pre <cmd>` that runs a preprocessor.
/// - `sort` has `--compress-program`.
/// - `find` has `-exec`.
/// - `git` honours hooks, `-c core.pager`, and aliases.
/// - `less` / `more` / `man` shell out via `!` and `$PAGER`.
/// - `sed` (GNU) has `s///e`; `awk` has `system()`.
///
/// Match is against the canonical (basename + lowercase) form of
/// the first whitespace-separated token, so `/usr/bin/ls`,
/// `./ls`, and `LS` all reduce to `ls`.
pub const TIER2_ALLOWLIST: &[&str] = &[
    // inspection (read/stat)
    "ls", "cat", "head", "tail", "grep", "diff", "cmp", "stat", "file", "wc", "tree",
    // pure path math
    "readlink", "realpath", "basename", "dirname", // identity / system info (read-only)
    "pwd", "whoami", "id", "uname", "hostname", "date", "echo", "printf", "which", "type",
];

/// Canonicalize a shell-exec pattern's first token for tier matching
/// and approval-key stability.
///
/// - Strips any leading path components so `/usr/bin/curl` and
///   `./curl` both reduce to `curl`.
/// - Lowercases the basename so `CURL` / `SuDo` match on
///   case-insensitive hosts (macOS default APFS, Windows).
///
/// The return is always an owned `String` so callers can form
/// approval keys and slice comparisons without borrow gymnastics.
pub fn canonical_exec_prefix(pattern: &str) -> String {
    let token = pattern.trim();
    let basename = Path::new(token)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(token);
    basename.to_ascii_lowercase()
}

impl Action {
    /// Determine which tier this action belongs to.
    pub fn tier(&self) -> PermissionTier {
        match self {
            Action::WorkspaceFileAccess | Action::ChannelConverse | Action::WebSearch => {
                PermissionTier::Tier1
            }

            // Shell exec: Tier 2 only for inspection verbs on the
            // curated allowlist (read/identity/path math, no exec
            // escape hatch). Everything else is Tier 3. The prefix
            // is canonicalized (basename + lowercase) before the
            // lookup so `/usr/bin/ls`, `./ls`, and `LS` all reduce
            // to `ls`. Wrappers (`sh`, `env`, `xargs`, ...) and
            // interpreters (`python`, `node`, `awk`, `sed`, ...)
            // fall to Tier 3 naturally by absence from the list.
            Action::ShellExec { pattern } => {
                let canonical = canonical_exec_prefix(pattern);
                if TIER2_ALLOWLIST.contains(&canonical.as_str()) {
                    PermissionTier::Tier2
                } else {
                    PermissionTier::Tier3
                }
            }

            Action::ExternalFileAccess { .. } | Action::CrossConversationMessage => {
                PermissionTier::Tier2
            }

            Action::DestructiveFileOp
            | Action::NetworkRequest { .. }
            | Action::CredentialAccess
            | Action::CronCreate => PermissionTier::Tier3,
        }
    }

    /// The canonical key for storing approval (Tier 2 actions).
    ///
    /// Shell-exec keys canonicalize the pattern (basename + lowercase)
    /// so path-qualified and case-variant invocations share a single
    /// approval row. Without this, `curl`, `/usr/bin/curl`, and `CURL`
    /// would each generate their own key and an operator's "approve
    /// shell:curl" would not cover the other forms.
    pub fn approval_key(&self) -> String {
        match self {
            Action::ShellExec { pattern } => format!("shell:{}", canonical_exec_prefix(pattern)),
            Action::ExternalFileAccess { path } => format!("file:{path}"),
            Action::CrossConversationMessage => "cross-conversation".to_string(),
            other => format!("{other:?}"),
        }
    }
}

/// Scope under which an approval applies. Discriminated so the
/// check path can branch on storage lifetime without re-deriving it
/// from `expires_at` heuristics.
///
/// - `Persisted` writes to `permissions.db` with the
///   default-30-day expiry; this is the historical default and the
///   only form pre-existing callers produce.
/// - `Session { session_id }` is in-memory only, scoped to the named
///   agent session, never written to SQLite. Survives crashes only
///   if the session-log replay re-emits the `PermissionApproved`
///   audit event; otherwise it is gone with the process. See
///   `~/code/wirken-ironcurtain/04-surpass.md` for the rationale
///   (the "actually-useful version" of policy hot-swap framed for
///   wirken's single-process model).
///
/// Wire shape: `serde(tag = "kind", ...)` so a future scope (e.g.
/// per-channel) can be added without breaking the persisted rows
/// that did not carry a `kind` field; back-compat handled by the
/// `Default` impl which returns `Persisted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// SQLite-backed, default expiry, survives process restart.
    #[default]
    Persisted,
    /// In-memory only, cleared on session end.
    Session {
        /// Logical agent session id (the `{agent}/{channel}/{conversation}`
        /// shape produced by `wirken_agent::factory::session_id_for`).
        /// Stored verbatim, never normalized; the in-memory cache keys
        /// on it exactly.
        session_id: String,
    },
}

impl ApprovalScope {
    /// True when this scope is session-bounded (in-memory only).
    pub fn is_session_scoped(&self) -> bool {
        matches!(self, Self::Session { .. })
    }

    /// The session id this scope is bound to, if any.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Persisted => None,
            Self::Session { session_id } => Some(session_id.as_str()),
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
    /// Storage lifetime. Defaulted on deserialize so rows persisted
    /// before this field existed read back as `ApprovalScope::Persisted`,
    /// which is the only form the pre-slice-1 emit path produced.
    #[serde(default)]
    pub scope: ApprovalScope,
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
    ///
    /// Runs a one-shot prune of approvals for shell verbs that are no
    /// longer Tier 2 eligible under the current allowlist. When the
    /// Tier 2 model flipped from a denylist (everything except a
    /// small set of high-risk verbs was Tier 2) to an allowlist (only
    /// a small set of inspection verbs is Tier 2), previously stored
    /// approvals for now-Tier-3 verbs (`shell:git`, `shell:kubectl`,
    /// `shell:make`, language interpreters, ...) became dead rows.
    /// Dropping them on open keeps the store honest: the permission
    /// gate does not consult them, and the operator sees a log line
    /// enumerating what was pruned rather than discovering later that
    /// `wirken permissions list` shows approvals that no longer take
    /// effect.
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

        let mut store = Self {
            conn,
            default_expiry_days: 30,
        };
        store.prune_non_tier2_shell_approvals()?;
        Ok(store)
    }

    /// Delete every `shell:<prefix>` approval row whose prefix is not
    /// on [`TIER2_ALLOWLIST`]. Called once from [`Self::open`]. Logs
    /// a single `info` line listing what was pruned if the set is
    /// non-empty; no-op otherwise. Called publicly as well so
    /// integration tests can exercise the migration directly.
    pub fn prune_non_tier2_shell_approvals(&mut self) -> Result<Vec<String>, GatewayError> {
        let mut select = self
            .conn
            .prepare("SELECT DISTINCT action_key FROM approvals WHERE action_key LIKE 'shell:%'")?;
        let rows = select.query_map([], |row| row.get::<_, String>(0))?;

        let mut stale = Vec::new();
        for row in rows {
            let key = row?;
            let Some(prefix) = key.strip_prefix("shell:") else {
                continue;
            };
            if !TIER2_ALLOWLIST.contains(&prefix) {
                stale.push(key);
            }
        }
        drop(select);

        if stale.is_empty() {
            return Ok(stale);
        }

        let tx = self.conn.transaction()?;
        {
            let mut delete = tx.prepare("DELETE FROM approvals WHERE action_key = ?1")?;
            for key in &stale {
                delete.execute(params![key])?;
            }
        }
        tx.commit()?;

        tracing::info!(
            count = stale.len(),
            keys = ?stale,
            "permissions: pruned approvals for shell verbs that are no longer Tier 2 eligible \
             under the current allowlist. These approvals would have been ignored by the gate; \
             removing them keeps `wirken permissions list` honest."
        );

        Ok(stale)
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
    ///
    /// Refuses to write a `shell:<prefix>` approval whose prefix is
    /// not on [`TIER2_ALLOWLIST`]. Those verbs are Tier 3 under the
    /// current policy — the gate would ignore the stored approval
    /// anyway — and accepting the CLI call silently would let an
    /// operator believe they had pre-approved a verb that still
    /// prompts on every use.
    pub fn approve_by_key(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        if let Some(prefix) = action_key.strip_prefix("shell:")
            && !TIER2_ALLOWLIST.contains(&prefix)
        {
            return Err(GatewayError::Config(format!(
                "refusing to store approval for '{action_key}': '{prefix}' is Tier 3 under the \
                 current allowlist and cannot be pre-approved. Tier 3 actions prompt on every \
                 use by design."
            )));
        }

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
            scope: ApprovalScope::Persisted,
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
                scope: ApprovalScope::Persisted,
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
                    scope: ApprovalScope::Persisted,
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
    fn every_tier2_allowlist_verb_is_tier2() {
        for p in TIER2_ALLOWLIST {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier2,
                "allowlisted verb `{p}` must be Tier 2"
            );
        }
    }

    #[test]
    fn expected_verbs_are_in_allowlist() {
        // Regression: trimming the allowlist requires the change to
        // fail this test in review, since any of these becoming
        // Tier 3 is a user-facing policy change worth flagging.
        let expected = [
            "ls", "cat", "head", "tail", "grep", "stat", "pwd", "whoami", "date", "echo",
        ];
        for p in &expected {
            assert!(
                TIER2_ALLOWLIST.contains(p),
                "`{p}` must be in TIER2_ALLOWLIST"
            );
        }
    }

    #[test]
    fn formerly_tier2_unknown_verbs_are_now_tier3() {
        // Under the old denylist these were Tier 2 (just not on the
        // high-risk list). Under the allowlist they are Tier 3
        // because they are not on the allowlist. Locks in the
        // intentional shape change.
        for p in ["rg", "jq", "make", "cargo", "python", "node"] {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier3,
                "non-allowlisted verb `{p}` must now be Tier 3"
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
    }

    /// Compile-time tripwire: this match must remain exhaustive
    /// without a wildcard. Any new `Action` variant added without
    /// updating this list fails to compile. The check exists
    /// because `Action::SkillInstall` was previously defined here
    /// as a Tier 3 action but was never reachable from the CLI
    /// install path (install gates on signature verification, not
    /// tier classification); a future contributor reintroducing
    /// that variant or any other "added but never wired" variant
    /// will be forced to either wire it through or update this
    /// guard. See `crates/cli/src/commands/skills.rs::install`
    /// for the actual install gate.
    #[test]
    fn action_variant_set_is_pinned() {
        fn variant_label(a: &Action) -> &'static str {
            match a {
                Action::WorkspaceFileAccess => "workspace_file_access",
                Action::ChannelConverse => "channel_converse",
                Action::WebSearch => "web_search",
                Action::ShellExec { .. } => "shell_exec",
                Action::ExternalFileAccess { .. } => "external_file_access",
                Action::CrossConversationMessage => "cross_conversation_message",
                Action::DestructiveFileOp => "destructive_file_op",
                Action::NetworkRequest { .. } => "network_request",
                Action::CredentialAccess => "credential_access",
                Action::CronCreate => "cron_create",
            }
        }
        // Smoke a representative variant so the function isn't
        // dead-code-eliminated and the compile-time match still
        // gets exercised.
        assert_eq!(variant_label(&Action::WebSearch), "web_search");
    }

    #[test]
    fn curl_cannot_be_pre_approved_and_always_prompts() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        // curl is Tier 3 under the allowlist. Two invariants:
        // 1. approve() refuses to store an approval for it (would
        //    otherwise be a dead row).
        // 2. check() returns Tier 3 NeedsApproval on every call.
        let err = store
            .approve(&shell("curl"), "default", "test-operator")
            .expect_err("approve for Tier 3 shell verb must refuse");
        match err {
            GatewayError::Config(msg) => assert!(msg.contains("Tier 3"), "msg: {msg}"),
            other => panic!("expected Config error, got {other:?}"),
        }
        let result = store.check(&shell("curl"), "default").unwrap();
        assert_eq!(
            result,
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier3,
            },
        );
    }

    #[test]
    fn prune_drops_stale_non_allowlist_shell_rows_on_open() {
        let tmp = tempfile::NamedTempFile::new().unwrap();

        // Seed the DB with rows for verbs that WERE Tier 2 under the
        // old denylist and are now Tier 3. We bypass approve() since
        // it now refuses these, and insert directly.
        {
            let conn = rusqlite::Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS approvals (
                     action_key TEXT NOT NULL,
                     agent_id TEXT NOT NULL,
                     approved_at TEXT NOT NULL,
                     approved_by TEXT NOT NULL,
                     expires_at TEXT NOT NULL,
                     PRIMARY KEY (action_key, agent_id)
                 );",
            )
            .unwrap();
            for key in [
                "shell:git",
                "shell:kubectl",
                "shell:make",
                "shell:ls",
                "shell:cat",
            ] {
                conn.execute(
                    "INSERT INTO approvals VALUES (?1, 'default', '2026-01-01T00:00:00Z', 'seed', '2100-01-01T00:00:00Z')",
                    rusqlite::params![key],
                )
                .unwrap();
            }
            // Also seed a non-shell approval that must survive.
            conn.execute(
                "INSERT INTO approvals VALUES ('file:/tmp/*', 'default', '2026-01-01T00:00:00Z', 'seed', '2100-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Open runs the migration.
        let store = PermissionStore::open(tmp.path()).unwrap();

        // Allowlisted shell verbs survive. Non-allowlisted are gone.
        let remaining = store.list("default").unwrap();
        let keys: std::collections::BTreeSet<String> =
            remaining.iter().map(|a| a.action_key.clone()).collect();
        assert!(
            keys.contains("shell:ls"),
            "allowlisted shell:ls must survive"
        );
        assert!(
            keys.contains("shell:cat"),
            "allowlisted shell:cat must survive"
        );
        assert!(
            keys.contains("file:/tmp/*"),
            "non-shell approvals must survive"
        );
        assert!(!keys.contains("shell:git"), "shell:git must be pruned");
        assert!(
            !keys.contains("shell:kubectl"),
            "shell:kubectl must be pruned"
        );
        assert!(!keys.contains("shell:make"), "shell:make must be pruned");
    }

    #[test]
    fn prune_is_idempotent_and_noop_on_clean_store() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut store = PermissionStore::open(tmp.path()).unwrap();
        // Fresh store is already clean.
        let first = store.prune_non_tier2_shell_approvals().unwrap();
        assert!(first.is_empty());
        // Running again is still a no-op.
        let second = store.prune_non_tier2_shell_approvals().unwrap();
        assert!(second.is_empty());
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
