use anyhow::{Context, Result};
use std::collections::HashSet;

use wirken_audit::{SessionId, SessionLog, SqliteSessionLog};
use wirken_gateway::permissions::{
    ApprovalScope, PermissionStore, approve_and_log_by_key,
    list_active_session_scoped_grants_for_agent,
};
use wirken_ipc::permissions::{PermissionsRequest, PermissionsResponse};

use super::config;

/// Connect to `gateway-permissions.sock`, send one request, read
/// one response, close. Mirrors the orchestrator-push client
/// shape: blocking single-shot RPC against a same-UID local
/// gateway. The socket has 0o600 perms so cross-user access is
/// already blocked at the filesystem layer.
#[cfg(unix)]
async fn permissions_rpc(req: &PermissionsRequest) -> Result<PermissionsResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let cfg = config();
    let path = cfg.socket_dir().join("gateway-permissions.sock");
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("permissions IPC: connect {}", path.display()))?;
    let (reader, mut writer) = stream.into_split();

    let body = serde_json::to_string(req).context("permissions IPC: serialize request")?;
    writer
        .write_all(body.as_bytes())
        .await
        .context("permissions IPC: write request body")?;
    writer
        .write_all(b"\n")
        .await
        .context("permissions IPC: write request newline")?;
    writer
        .shutdown()
        .await
        .context("permissions IPC: shutdown write side")?;

    let mut br = BufReader::new(reader);
    let mut line = String::new();
    br.read_line(&mut line)
        .await
        .context("permissions IPC: read response")?;
    serde_json::from_str(line.trim_end()).context("permissions IPC: parse response")
}

#[cfg(not(unix))]
async fn permissions_rpc(_req: &PermissionsRequest) -> Result<PermissionsResponse> {
    anyhow::bail!("permissions IPC is unix-only");
}

/// `wirken permissions pending list`: print every in-flight
/// `NeedsApproval` request the gateway is holding. Distinct from
/// `wirken permissions list-pending` (which walks the audit log
/// for historical denials without a matching approval); this
/// command shows the live queue an operator can `approve` or
/// `deny` right now.
pub async fn pending_list() -> Result<()> {
    let resp = permissions_rpc(&PermissionsRequest::PendingList).await?;
    match resp {
        PermissionsResponse::PendingList { entries } => {
            if entries.is_empty() {
                println!("No pending approvals.");
                return Ok(());
            }
            println!(
                "{:<10}  {:<14}  {:<18}  {:<6}  AGE",
                "REQUEST", "AGENT", "TOOL", "TIER"
            );
            for e in entries {
                // First 8 chars of the UUID is the operator's
                // copy-paste handle. The full UUID still has to be
                // supplied to approve / deny; truncation is for
                // visual scan only.
                let short = e.request_id.chars().take(8).collect::<String>();
                println!(
                    "{:<10}  {:<14}  {:<18}  {:<6}  {}s",
                    short, e.agent_id, e.tool_name, e.requested_tier, e.age_seconds,
                );
            }
            println!();
            println!("Use the full request id from `pending show` for approve/deny.");
            Ok(())
        }
        PermissionsResponse::Error { message } => anyhow::bail!("gateway error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// `wirken permissions pending show <request_id>`: render the
/// full context for one pending entry including the trigger
/// message.
pub async fn pending_show(request_id: &str) -> Result<()> {
    let resp = permissions_rpc(&PermissionsRequest::PendingShow {
        request_id: request_id.to_string(),
    })
    .await?;
    match resp {
        PermissionsResponse::PendingShow { entry: Some(d) } => {
            println!("Request ID:    {}", d.summary.request_id);
            println!("Agent ID:      {}", d.summary.agent_id);
            println!("Tool:          {}", d.summary.tool_name);
            println!("Action key:    {}", d.summary.action_key);
            println!("Required tier: {}", d.summary.requested_tier);
            println!("Requested at:  {}", d.summary.requested_at);
            println!("Age:           {}s", d.summary.age_seconds);
            if let Some(msg) = d.trigger_message {
                println!();
                println!("Trigger message:");
                println!("  {msg}");
            }
            Ok(())
        }
        PermissionsResponse::PendingShow { entry: None } => {
            anyhow::bail!("no pending entry with request id '{request_id}'")
        }
        PermissionsResponse::Error { message } => anyhow::bail!("gateway error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// `wirken permissions pending approve <request_id>`: resolve the
/// pending entry as `Allow`. `approved_by` carries the operator's
/// `$USER` (falling back to the literal `"cli"`) so the audit
/// row records who approved on the CLI surface.
pub async fn pending_approve(request_id: &str) -> Result<()> {
    let approved_by = std::env::var("USER").unwrap_or_else(|_| "cli".to_string());
    let resp = permissions_rpc(&PermissionsRequest::PendingApprove {
        request_id: request_id.to_string(),
        approved_by,
    })
    .await?;
    print_decision(resp, request_id, "approve")
}

/// `wirken permissions pending deny <request_id> [reason]`: resolve
/// the pending entry as `Deny`. The reason, if supplied, surfaces
/// to the LLM as the failed tool result's output and lands on the
/// audit row's `denial_reason`.
pub async fn pending_deny(request_id: &str, reason: Option<String>) -> Result<()> {
    let denied_by = std::env::var("USER").unwrap_or_else(|_| "cli".to_string());
    let resp = permissions_rpc(&PermissionsRequest::PendingDeny {
        request_id: request_id.to_string(),
        denied_by,
        reason,
    })
    .await?;
    print_decision(resp, request_id, "deny")
}

fn print_decision(resp: PermissionsResponse, request_id: &str, verb: &str) -> Result<()> {
    use wirken_ipc::permissions::DecisionResult;
    match resp {
        PermissionsResponse::Decision {
            result: DecisionResult::Accepted,
        } => {
            println!("{verb}: accepted (request {request_id})");
            Ok(())
        }
        PermissionsResponse::Decision {
            result: DecisionResult::UnknownKey,
        } => {
            anyhow::bail!(
                "{verb}: unknown or already-resolved request id '{request_id}'. \
                 Another operator may have already decided, the agent's own \
                 timeout may have fired, or the gateway restarted."
            )
        }
        PermissionsResponse::Error { message } => anyhow::bail!("gateway error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// List both persisted approvals (from SQLite) and active
/// session-scoped grants (from the on-disk session log, replayed
/// last-event-wins per session id). Out-of-process safe: the
/// daemon's in-memory cache is not consulted, so session-scoped
/// grants made and not yet replayed to the audit log will not
/// appear. The append-on-every-grant pattern in
/// `approve_and_log_by_key` keeps that gap to a single un-flushed
/// row at worst.
///
/// The two scopes share one table; the SCOPE column distinguishes
/// them. For session-scoped rows the expiry column shows the
/// session id instead of a date (session-scoped has no time-based
/// expiry; it ends with the session).
pub async fn list(agent: &str) -> Result<()> {
    let cfg = config();
    let store = PermissionStore::open(&cfg.permissions_db_path())
        .context("Failed to open permission store")?;

    let persisted = store.list(agent).context("Failed to list permissions")?;

    let log = SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?;
    let session_scoped = list_active_session_scoped_grants_for_agent(&log, agent)
        .context("Failed to scan session-scoped grants")?;

    if persisted.is_empty() && session_scoped.is_empty() {
        println!("  No permissions granted for agent '{agent}'.");
        return Ok(());
    }

    println!("  Permissions for agent '{agent}':");
    println!();
    println!(
        "  {:30}  {:10}  {:12}  {:20}  EXPIRES AT / SESSION",
        "ACTION", "SCOPE", "APPROVED BY", "APPROVED AT"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "─".repeat(30),
        "─".repeat(10),
        "─".repeat(12),
        "─".repeat(20),
        "─".repeat(40)
    );

    for approval in &persisted {
        println!(
            "  {:30}  {:10}  {:12}  {:20}  {}",
            approval.action_key,
            "persisted",
            approval.approved_by,
            approval.approved_at.format("%Y-%m-%d %H:%M:%S"),
            approval.expires_at.format("%Y-%m-%d %H:%M:%S"),
        );
    }
    for grant in &session_scoped {
        println!(
            "  {:30}  {:10}  {:12}  {:20}  {}",
            grant.action_key,
            "session",
            grant.approved_by,
            grant.approved_at.format("%Y-%m-%d %H:%M:%S"),
            grant.session_id,
        );
    }
    println!();
    println!(
        "  {} grant(s): {} persisted, {} session-scoped.",
        persisted.len() + session_scoped.len(),
        persisted.len(),
        session_scoped.len(),
    );
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
            let approval = approve_and_log_by_key(
                &store, key, agent, "operator", scope, &log, &handle, None, None,
            )
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
