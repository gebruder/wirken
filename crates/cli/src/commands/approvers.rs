//! `wirken approvers` subcommand surface for managing the channel-
//! adapter approval allowlist plus per-adapter approval-chat
//! configuration. Direct SQLite writes against
//! `<data_dir>/approvers.db`, which the gateway reads on every
//! decision, so a change applies to the next one without a restart.
//! Each add and remove is a row on the signed `gateway-approvers`
//! lane, sealed by a chain head.
//!
//! Every subcommand refuses under the `exec` marker: the allowlist
//! decides who can approve an agent's actions, so an agent's own
//! command cannot be what changes it. The refusal is an
//! `operator_command_refused` row on the same lane.

use anyhow::{Context, Result, bail};

use wirken_audit::{
    OPERATOR_APPROVERS_SESSION, SessionEvent, SessionId, SessionLog as _, SqliteSessionLog,
    TrustLevel,
};
use wirken_gateway::approver_registry::ApproverRegistry;

use super::{config, local_operator, open_signed_session_log, seal_operator_lane};

/// Refuse under the `exec` marker, before the allowlist is opened, and
/// record the refusal on the lane. The row is best effort: a log that
/// cannot be opened is reported and the refusal stands.
fn refuse_inside_exec(invocation: &str) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        let recorded = open_signed_session_log(&config()).and_then(|log| {
            record(
                &log,
                SessionEvent::OperatorCommandRefused {
                    command: "approvers".to_string(),
                    invocation: invocation.to_string(),
                    reason: "inside_exec".to_string(),
                },
            )
        });
        if let Err(e) = recorded {
            tracing::warn!(
                error = %e,
                "could not record the refusal on the {OPERATOR_APPROVERS_SESSION} lane"
            );
        }
        bail!(
            "wirken approvers refuses to run inside a Wirken exec ({} is set); run it \
             yourself, from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    Ok(())
}

fn open_registry() -> Result<ApproverRegistry> {
    let cfg = config();
    let path = cfg.data_dir.join("approvers.db");
    ApproverRegistry::open(&path)
        .map_err(|e| anyhow::anyhow!("open approver registry at {}: {e}", path.display()))
}

/// Append `event` to the operator approvers lane and seal it.
fn record(log: &SqliteSessionLog, event: SessionEvent) -> Result<()> {
    let handle = log.handle_for(SessionId::new(OPERATOR_APPROVERS_SESSION.to_string()));
    log.append(&handle, TrustLevel::User, event)
        .context("append the approver row")?;
    seal_operator_lane(log, OPERATOR_APPROVERS_SESSION);
    Ok(())
}

/// Let `user_id` approve on `adapter_id`. The entry is written first
/// and the row after it, so the row records what is in the allowlist; a
/// new entry whose row cannot be written is taken out again, so nobody
/// can approve without one.
pub fn add(adapter_id: &str, user_id: &str, display: Option<&str>) -> Result<()> {
    refuse_inside_exec("add")?;
    let display = display.unwrap_or("");
    let log = open_signed_session_log(&config())?;
    let registry = open_registry()?;
    let new = registry
        .register(adapter_id, user_id, display)
        .map_err(|e| anyhow::anyhow!("register approver: {e}"))?;
    let recorded = record(
        &log,
        SessionEvent::ApproverAdded {
            adapter_id: adapter_id.to_string(),
            user_id: user_id.to_string(),
            display_name: display.to_string(),
            added_by: local_operator(),
        },
    );
    if let Err(e) = recorded {
        if new {
            registry
                .unregister(adapter_id, user_id)
                .map_err(|e| anyhow::anyhow!("take the unrecorded approver out again: {e}"))?;
        }
        return Err(e.context(format!(
            "'{user_id}' was not made an approver on {adapter_id}: its \
             {OPERATOR_APPROVERS_SESSION} audit row could not be written"
        )));
    }
    println!(
        "Approver added: adapter='{adapter_id}', user_id='{user_id}', display='{display}'.\n\
         It applies to the next decision."
    );
    Ok(())
}

pub fn list(adapter_id: Option<&str>) -> Result<()> {
    refuse_inside_exec("list")?;
    let entries = open_registry()?
        .list(adapter_id)
        .map_err(|e| anyhow::anyhow!("read the approver allowlist: {e}"))?;
    if entries.is_empty() {
        if let Some(a) = adapter_id {
            println!("No approvers registered for adapter '{a}'.");
        } else {
            println!("No approvers registered.");
        }
        return Ok(());
    }
    println!("{:<20}  {:<20}  DISPLAY", "ADAPTER", "USER_ID");
    for e in entries {
        println!(
            "{:<20}  {:<20}  {}",
            e.adapter_id, e.user_id, e.display_name
        );
    }
    Ok(())
}

/// Take `user_id` off `adapter_id`. The removal stands even if its row
/// cannot be written: failing to record it is no reason to keep letting
/// them approve.
pub fn remove(adapter_id: &str, user_id: &str) -> Result<()> {
    refuse_inside_exec("remove")?;
    let removed = open_registry()?
        .unregister(adapter_id, user_id)
        .map_err(|e| anyhow::anyhow!("unregister approver: {e}"))?;
    if !removed {
        println!("No approver matching adapter='{adapter_id}', user_id='{user_id}'.");
        return Ok(());
    }
    let recorded = open_signed_session_log(&config()).and_then(|log| {
        record(
            &log,
            SessionEvent::ApproverRemoved {
                adapter_id: adapter_id.to_string(),
                user_id: user_id.to_string(),
                removed_by: local_operator(),
            },
        )
    });
    if let Err(e) = recorded {
        eprintln!(
            "  The approver is removed, but its {OPERATOR_APPROVERS_SESSION} audit row could \
             not be written: {e:#}"
        );
    }
    println!(
        "Approver removed: adapter='{adapter_id}', user_id='{user_id}'.\n\
         It applies to the next decision."
    );
    Ok(())
}

pub fn set_chat(adapter_id: &str, conversation_id: &str) -> Result<()> {
    refuse_inside_exec("set-chat")?;
    let registry = open_registry()?;
    registry
        .set_approval_conversation(adapter_id, conversation_id)
        .context("set approval conversation")?;
    println!(
        "Approval conversation set: adapter='{adapter_id}', \
         conversation_id='{conversation_id}'.\n\
         It applies to the next approval request."
    );
    Ok(())
}

pub fn show_chat(adapter_id: &str) -> Result<()> {
    refuse_inside_exec("show-chat")?;
    let registry = open_registry()?;
    match registry.approval_conversation(adapter_id) {
        Some(c) => println!("adapter='{adapter_id}' approval_conversation_id='{c}'"),
        None => println!("adapter='{adapter_id}' has no approval conversation configured"),
    }
    Ok(())
}
