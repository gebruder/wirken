use anyhow::{Context, Result};

use wirken_audit::{AuditLog, AuditQuery, VerifyResult};

use super::config;

pub async fn log(action: Option<String>, channel: Option<String>, limit: usize) -> Result<()> {
    let cfg = config();
    let audit = AuditLog::open(&cfg.audit_db_path()).context("Failed to open audit log")?;

    let query = AuditQuery {
        action,
        channel,
        limit: Some(limit),
        ..Default::default()
    };

    let events = audit.query(&query).context("Failed to query audit log")?;

    if events.is_empty() {
        println!("  No audit events found.");
        return Ok(());
    }

    println!(
        "  {:>6}  {:20}  {:16}  {:20}  TARGET",
        "ID", "TIMESTAMP", "ACTOR", "ACTION"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "─".repeat(6),
        "─".repeat(20),
        "─".repeat(16),
        "─".repeat(20),
        "─".repeat(30)
    );

    for event in &events {
        println!(
            "  {:>6}  {:20}  {:16}  {:20}  {}",
            event.id,
            event.event.ts.format("%Y-%m-%d %H:%M:%S"),
            truncate(&event.event.actor, 16),
            truncate(&event.event.action, 20),
            truncate(&event.event.target, 40),
        );
    }
    println!();
    println!("  {} events shown.", events.len());
    Ok(())
}

pub async fn verify() -> Result<()> {
    let cfg = config();
    let audit = AuditLog::open(&cfg.audit_db_path()).context("Failed to open audit log")?;

    match audit.verify()? {
        VerifyResult::Ok { rows_verified } => {
            println!("  Audit log integrity: OK");
            println!("  {} rows verified, hash chain intact.", rows_verified);
        }
        VerifyResult::Broken {
            row_id,
            expected,
            found,
        } => {
            println!("  Audit log integrity: BROKEN");
            println!("  Hash chain broken at row {row_id}.");
            println!("  Expected: {expected}");
            println!("  Found:    {found}");
            println!();
            println!("  The audit log has been tampered with.");
            std::process::exit(1);
        }
        VerifyResult::Empty => {
            println!("  Audit log is empty.");
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max.saturating_sub(1);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}
