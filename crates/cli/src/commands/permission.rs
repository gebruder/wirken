use anyhow::{Context, Result};
use std::collections::HashSet;

use wirken_audit::SqliteSessionLog;
use wirken_gateway::permissions::PermissionStore;

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

/// Grant a 30-day approval for `key` to `agent`, operator-initiated.
/// Writes directly to permissions.db; no prompt, no gateway round-trip.
pub async fn approve(key: &str, agent: &str) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    let approval = store
        .approve_by_key(key, agent, "operator")
        .context(format!("Failed to approve permission '{key}'"))?;

    println!(
        "  Approved '{}' for agent '{}' until {}.",
        approval.action_key,
        approval.agent_id,
        approval.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );
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
        println!(
            "  {:30}  {:6}  {:20}  {}",
            rec.action_key, rec.tier, ts_short, rec.tool,
        );
    }
    println!();
    println!("  Approve one with: wirken permissions approve <ACTION KEY> --agent {agent}");
    Ok(())
}
