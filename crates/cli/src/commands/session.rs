use anyhow::{Context, Result};

use wirken_gateway::session::SessionStore;

use super::config;

pub async fn list(channel: Option<String>) -> Result<()> {
    let cfg = config();
    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?;

    let sessions = store
        .list_active(channel.as_deref())
        .context("Failed to list sessions")?;

    if sessions.is_empty() {
        println!("  No active sessions.");
        return Ok(());
    }

    println!(
        "  {:32}  {:12}  {:>6}  {:20}",
        "ID", "CHANNEL", "MSGS", "LAST ACTIVITY"
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(32),
        "─".repeat(12),
        "─".repeat(6),
        "─".repeat(20)
    );

    for session in &sessions {
        println!(
            "  {:32}  {:12}  {:>6}  {:20}",
            session.id,
            session.channel,
            session.message_count,
            session.last_activity.format("%Y-%m-%d %H:%M:%S"),
        );
    }

    println!();
    println!("  {} active sessions.", sessions.len());
    Ok(())
}

pub async fn close(id: &str) -> Result<()> {
    let cfg = config();
    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?;

    store
        .close(id)
        .context(format!("Failed to close session '{id}'"))?;

    println!("  Session '{id}' closed.");
    Ok(())
}
