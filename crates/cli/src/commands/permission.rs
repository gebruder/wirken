use anyhow::{Context, Result};

use wirken_gateway::permissions::PermissionStore;

use super::config;

pub async fn list(agent: &str) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    let approvals = store.list(agent)
        .context("Failed to list permissions")?;

    if approvals.is_empty() {
        println!("  No permissions granted for agent '{agent}'.");
        return Ok(());
    }

    println!("  Permissions for agent '{agent}':");
    println!();
    println!("  {:30}  {:12}  {:20}  {:20}", "ACTION", "APPROVED BY", "APPROVED AT", "EXPIRES AT");
    println!("  {}  {}  {}  {}", "─".repeat(30), "─".repeat(12), "─".repeat(20), "─".repeat(20));

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

    store.revoke(key, agent)
        .context(format!("Failed to revoke permission '{key}'"))?;

    println!("  Permission '{key}' revoked for agent '{agent}'.");
    Ok(())
}
