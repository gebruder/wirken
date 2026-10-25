//! `wirken senders`: the inbound sender allowlist.
//!
//! Read by the gateway on every message. Adds and removes are rows on
//! the signed `gateway-senders` lane. `refused` reads drops from the
//! `gateway-inbound` lane. Refused under the `exec` marker.

use anyhow::{Context, Result, bail};

use wirken_audit::{
    INBOUND_SENDERS_SESSION, OPERATOR_SENDERS_SESSION, SessionEvent, SessionId, SessionLog as _,
    SqliteSessionLog, TrustLevel,
};
use wirken_gateway::sender_registry::{SenderRegistry, validate_channel, validate_id};

use super::{config, local_operator, open_signed_session_log, seal_operator_lane};

/// Refuse under the `exec` marker and record it; the row is best effort.
fn refuse_inside_exec(invocation: &str) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        let recorded = open_signed_session_log(&config()).and_then(|log| {
            record(
                &log,
                SessionEvent::OperatorCommandRefused {
                    command: "senders".to_string(),
                    invocation: invocation.to_string(),
                    reason: "inside_exec".to_string(),
                },
            )
        });
        if let Err(e) = recorded {
            tracing::warn!(
                error = %e,
                "could not record the refusal on the {OPERATOR_SENDERS_SESSION} lane"
            );
        }
        bail!(
            "wirken senders refuses to run inside a Wirken exec ({} is set); run it \
             yourself, from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    Ok(())
}

fn open_registry() -> Result<SenderRegistry> {
    let path = config().senders_db_path();
    SenderRegistry::open(&path)
        .map_err(|e| anyhow::anyhow!("open the sender allowlist at {}: {e}", path.display()))
}

fn kind(group: bool) -> &'static str {
    if group { "group" } else { "sender" }
}

/// Append `event` to the operator senders lane and seal it.
fn record(log: &SqliteSessionLog, event: SessionEvent) -> Result<()> {
    let handle = log.handle_for(SessionId::new(OPERATOR_SENDERS_SESSION.to_string()));
    log.append(&handle, TrustLevel::User, event)
        .context("append the allowlist row")?;
    seal_operator_lane(log, OPERATOR_SENDERS_SESSION);
    Ok(())
}

/// Admit `id` on `channel`. A new entry whose row fails is removed.
pub fn add(channel: &str, id: &str, group: bool, label: Option<&str>) -> Result<()> {
    refuse_inside_exec("add")?;
    validate_channel(channel).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_id(id).map_err(|e| anyhow::anyhow!("{e}"))?;
    let label = label.unwrap_or("");
    let cfg = config();
    let log = open_signed_session_log(&cfg)?;
    let registry = open_registry()?;
    let new = registry
        .add(channel, id, group, label)
        .map_err(|e| anyhow::anyhow!("add the entry: {e}"))?;
    let recorded = record(
        &log,
        SessionEvent::InboundSenderAdded {
            channel: channel.to_string(),
            id: id.to_string(),
            group,
            label: label.to_string(),
            added_by: local_operator(),
        },
    );
    if let Err(e) = recorded {
        if new {
            registry
                .remove(channel, id, group)
                .map_err(|e| anyhow::anyhow!("take the unrecorded entry out again: {e}"))?;
        }
        return Err(e.context(format!(
            "the {} '{id}' on {channel} was not admitted: its {OPERATOR_SENDERS_SESSION} \
             audit row could not be written",
            kind(group)
        )));
    }
    let what = if group {
        format!("group '{id}' (every member of it)")
    } else {
        format!("sender '{id}'")
    };
    if new {
        println!("Admitted {what} on {channel}. It applies to the next message.");
    } else {
        println!("{what} was already admitted on {channel}; label updated.");
    }
    Ok(())
}

/// Remove `id` from `channel`. Stands even if the row fails.
pub fn remove(channel: &str, id: &str, group: bool) -> Result<()> {
    refuse_inside_exec("remove")?;
    validate_channel(channel).map_err(|e| anyhow::anyhow!("{e}"))?;
    let registry = open_registry()?;
    let removed = registry
        .remove(channel, id, group)
        .map_err(|e| anyhow::anyhow!("remove the entry: {e}"))?;
    if !removed {
        println!(
            "No {} entry '{id}' on {channel}.{}",
            kind(group),
            if group {
                ""
            } else {
                " Pass --group to remove a group entry."
            }
        );
        return Ok(());
    }
    let cfg = config();
    let recorded = open_signed_session_log(&cfg).and_then(|log| {
        record(
            &log,
            SessionEvent::InboundSenderRemoved {
                channel: channel.to_string(),
                id: id.to_string(),
                group,
                removed_by: local_operator(),
            },
        )
    });
    if let Err(e) = recorded {
        eprintln!(
            "  The entry is removed, but its {OPERATOR_SENDERS_SESSION} audit row could not \
             be written: {e:#}"
        );
    }
    println!(
        "Removed {} '{id}' from {channel}. It applies to the next message.",
        kind(group)
    );
    Ok(())
}

/// Print the allowlist, or one channel's.
pub fn list(channel: Option<&str>) -> Result<()> {
    refuse_inside_exec("list")?;
    if let Some(c) = channel {
        validate_channel(c).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let entries = open_registry()?
        .list(channel)
        .map_err(|e| anyhow::anyhow!("read the allowlist: {e}"))?;
    if entries.is_empty() {
        match channel {
            Some(c) => println!("No senders admitted on {c}: every message on it is dropped."),
            None => println!("No senders admitted on any channel: every message is dropped."),
        }
        return Ok(());
    }
    println!(
        "{:<12}  {:<6}  {:<36}  {:<20}  ADDED",
        "CHANNEL", "KIND", "ID", "LABEL"
    );
    for e in entries {
        println!(
            "{:<12}  {:<6}  {:<36}  {:<20}  {}",
            e.channel,
            kind(e.group),
            e.id,
            e.label,
            e.added_at
        );
    }
    Ok(())
}

/// Rows read per step when walking the lane back from its end.
const PAGE: u64 = 512;

/// Print recent refusal rows, newest first.
pub fn refused(channel: Option<&str>, limit: usize) -> Result<()> {
    refuse_inside_exec("refused")?;
    if let Some(c) = channel {
        validate_channel(c).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let cfg = config();
    let log = SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?;
    let handle = log.handle_for(SessionId::new(INBOUND_SENDERS_SESSION.to_string()));
    let mut found = Vec::new();
    let mut end = log.last_index(&handle)?.map_or(0, |last| last + 1);
    while end > 0 && found.len() < limit {
        let start = end.saturating_sub(PAGE);
        for row in log.get_range(&handle, start..end)?.into_iter().rev() {
            if let SessionEvent::InboundSenderRefused {
                channel: row_channel,
                sender_id,
                conversation_id,
                reason,
                suppressed,
                ..
            } = row.event
                && channel.is_none_or(|c| c == row_channel)
            {
                found.push((
                    row.ts,
                    row_channel,
                    sender_id,
                    conversation_id,
                    reason,
                    suppressed,
                ));
                if found.len() == limit {
                    break;
                }
            }
        }
        end = start;
    }
    if found.is_empty() {
        println!("No refused inbound messages recorded.");
        return Ok(());
    }
    println!(
        "{:<20}  {:<12}  {:<28}  {:<28}  {:<20}  SUPPRESSED",
        "TIME", "CHANNEL", "SENDER", "CONVERSATION", "REASON"
    );
    for (ts, channel, sender, conversation, reason, suppressed) in found {
        let reason = match reason {
            wirken_audit::InboundRefusalReason::NotAllowed => "not_allowed",
            wirken_audit::InboundRefusalReason::AllowlistUnreadable => "allowlist_unreadable",
        };
        println!(
            "{:<20}  {:<12}  {:<28}  {:<28}  {:<20}  {suppressed}",
            ts.format("%Y-%m-%dT%H:%M:%SZ"),
            channel,
            sender,
            conversation,
            reason
        );
    }
    println!(
        "\nAdmit a sender with `wirken senders add <channel> <sender>`, or the whole \
         conversation with `wirken senders add <channel> <conversation> --group`."
    );
    Ok(())
}
