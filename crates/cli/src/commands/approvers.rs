//! `wirken approvers` subcommand surface for managing the channel-
//! adapter approval allowlist plus per-adapter approval-chat
//! configuration. Direct SQLite writes against
//! `<data_dir>/approvers.db`; the gateway's in-memory cache is
//! loaded on next `wirken run`. Matches the
//! `wirken hooks register|list|unregister` shape.

use anyhow::{Context, Result};

use wirken_gateway::approver_registry::ApproverRegistry;

use super::config;

fn open_registry() -> Result<ApproverRegistry> {
    let cfg = config();
    let path = cfg.data_dir.join("approvers.db");
    ApproverRegistry::open(&path)
        .map_err(|e| anyhow::anyhow!("open approver registry at {}: {e}", path.display()))
}

pub fn add(adapter_id: &str, user_id: &str, display: Option<&str>) -> Result<()> {
    let display = display.unwrap_or("");
    let registry = open_registry()?;
    registry
        .register(adapter_id, user_id, display)
        .map_err(|e| anyhow::anyhow!("register approver: {e}"))?;
    println!(
        "Approver added: adapter='{adapter_id}', user_id='{user_id}', display='{display}'.\n\
         Restart wirken to apply (gateway loads the cache on next start)."
    );
    Ok(())
}

pub fn list(adapter_id: Option<&str>) -> Result<()> {
    let registry = open_registry()?;
    let mut entries = registry.list(adapter_id);
    if entries.is_empty() {
        if let Some(a) = adapter_id {
            println!("No approvers registered for adapter '{a}'.");
        } else {
            println!("No approvers registered.");
        }
        return Ok(());
    }
    entries.sort_by(|a, b| {
        a.adapter_id
            .cmp(&b.adapter_id)
            .then_with(|| a.user_id.cmp(&b.user_id))
    });
    println!("{:<20}  {:<20}  DISPLAY", "ADAPTER", "USER_ID");
    for e in entries {
        println!(
            "{:<20}  {:<20}  {}",
            e.adapter_id, e.user_id, e.display_name
        );
    }
    Ok(())
}

pub fn remove(adapter_id: &str, user_id: &str) -> Result<()> {
    let registry = open_registry()?;
    let removed = registry
        .unregister(adapter_id, user_id)
        .map_err(|e| anyhow::anyhow!("unregister approver: {e}"))?;
    if removed {
        println!(
            "Approver removed: adapter='{adapter_id}', user_id='{user_id}'.\n\
             Restart wirken to apply (the in-memory cache holds the prior \
             entry until next start)."
        );
    } else {
        println!("No approver matching adapter='{adapter_id}', user_id='{user_id}'.");
    }
    Ok(())
}

pub fn set_chat(adapter_id: &str, chat_id: i64) -> Result<()> {
    let registry = open_registry()?;
    registry
        .set_approval_chat(adapter_id, chat_id)
        .context("set approval chat")?;
    println!(
        "Approval chat set: adapter='{adapter_id}', chat_id={chat_id}.\n\
         Restart wirken to apply."
    );
    Ok(())
}

pub fn show_chat(adapter_id: &str) -> Result<()> {
    let registry = open_registry()?;
    match registry.approval_chat(adapter_id) {
        Some(c) => println!("adapter='{adapter_id}' approval_chat_id={c}"),
        None => println!("adapter='{adapter_id}' has no approval_chat_id configured"),
    }
    Ok(())
}
