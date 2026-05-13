use anyhow::{Context, Result};
use std::collections::HashSet;

use wirken_audit::{SessionId, SessionLog, SqliteSessionLog};
use wirken_gateway::permissions::{ApprovalScope, PermissionStore, approve_and_log_by_key};

use super::config;

pub async fn list(agent: &str) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    let approvals = store.list(agent).context("Failed to list permissions")?;

    if approvals.is_empty() {
        println!("  No permissions granted for agent '{agent}'.");
        return Ok(());
    }

    println!("  Permissions for agent '{agent}':");
    println!();
    println!(
        "  {:30}  {:12}  {:20}  {:20}",
        "ACTION", "APPROVED BY", "APPROVED AT", "EXPIRES AT"
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(30),
        "─".repeat(12),
        "─".repeat(20),
        "─".repeat(20)
    );

    for approval in &approvals {
        println!(
            "  {:30}  {:12}  {:20}  {:20}",
            approval.action_key,
            approval.approved_by,
            approval.approved_at.format("%Y-%m-%d %H:%M:%S"),
            approval.expires_at.format("%Y-%m-%d %H:%M:%S"),
        );
    }
    println!();
    Ok(())
}

pub async fn revoke(key: &str, agent: &str) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    store
        .revoke(key, agent)
        .context(format!("Failed to revoke permission '{key}'"))?;

    println!("  Permission '{key}' revoked for agent '{agent}'.");
    Ok(())
}

/// Grant an approval for `key`, operator-initiated.
///
/// When `session` is `None`, writes a 30-day persisted approval
/// directly to `permissions.db` (unchanged from the pre-slice-4
/// behaviour). When `session` is `Some(session_id)`, writes a
/// session-scoped approval to the in-memory cache and appends a
/// `PermissionApproved` event to the session's audit chain via
/// `approve_and_log_by_key`; the grant covers only the named
/// session and is cleared on session end.
///
/// The persisted path stays silent on the audit chain by design:
/// an operator-initiated persisted grant is structurally out of
/// band of any agent session log, and a synthetic operator-session
/// would pollute `wirken sessions list`. A non-session operator-
/// action audit channel is the cleaner future home for these.
pub async fn approve(key: &str, agent: &str, session: Option<&str>) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    match session {
        None => {
            let approval = store
                .approve_by_key(key, agent, "operator")
                .context(format!("Failed to approve permission '{key}'"))?;
            println!(
                "  Approved '{}' for agent '{}' until {}.",
                approval.action_key,
                approval.agent_id,
                approval.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
            );
        }
        Some(session_id) => {
            let log = SqliteSessionLog::open(&cfg.audit_db_path())
                .context("Failed to open session log")?;
            let handle = log.handle_for(SessionId::new(session_id.to_string()));
            let scope = ApprovalScope::Session {
                session_id: session_id.to_string(),
            };
            let approval =
                approve_and_log_by_key(&store, key, agent, "operator", scope, &log, &handle)
                    .context(format!(
                        "Failed to approve permission '{key}' for session '{session_id}'"
                    ))?;
            println!(
                "  Approved '{}' for session '{}' (agent '{}'); cleared on session end.",
                approval.action_key, session_id, approval.agent_id,
            );
        }
    }
    Ok(())
}

/// Show `PermissionDenied` audit entries for `agent` whose action
/// key has no current approval. Deduped by action_key so a single
/// denied tool does not spam the list. Most recent occurrence wins.
pub async fn list_pending(agent: &str) -> Result<()> {
    let cfg = config();
    let log = SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?;
    let perms = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    let denials = log.find_permission_denials(agent);

    let mut seen: HashSet<String> = HashSet::new();
    let mut pending: Vec<_> = Vec::new();
    for rec in denials {
        if !seen.insert(rec.action_key.clone()) {
            continue;
        }
        if perms.has_approval(&rec.action_key, agent).unwrap_or(false) {
            continue;
        }
        pending.push(rec);
    }

    if pending.is_empty() {
        println!("  No pending permission approvals for agent '{agent}'.");
        return Ok(());
    }

    println!("  Pending approvals for agent '{agent}':");
    println!();
    println!(
        "  {:30}  {:6}  {:20}  TOOL",
        "ACTION KEY", "TIER", "LAST SEEN",
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(30),
        "─".repeat(6),
        "─".repeat(20),
        "─".repeat(8),
    );
    for rec in &pending {
        let ts_short = rec.ts.get(..19).unwrap_or(rec.ts.as_str());
        let tier_label = rec.tier.as_deref().unwrap_or("-");
        println!(
            "  {:30}  {:6}  {:20}  {}",
            rec.action_key, tier_label, ts_short, rec.tool,
        );
    }
    println!();
    println!("  Approve one with: wirken permissions approve <ACTION KEY> --agent {agent}");
    Ok(())
}
