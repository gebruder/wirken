use anyhow::{Context, Result};
use std::collections::HashSet;

use wirken_audit::{SessionId, SessionLog, SqliteSessionLog};
use wirken_gateway::permissions::{
    ApprovalScope, OPERATOR_PERMISSIONS_SESSION, approve_and_log_by_key_with_expiry,
    list_active_session_scoped_grants_for_agent,
};
use wirken_ipc::permissions::{PermissionsRequest, PermissionsResponse};

use super::{config, open_permission_store};

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
                "{:<36}  {:<14}  {:<18}  {:<6}  AGE",
                "REQUEST", "AGENT", "TOOL", "TIER"
            );
            for e in entries {
                // The whole id. `show`, `approve` and `deny` match on
                // it, and it appears nowhere else, so printing a
                // truncation left the queue unreachable: the short
                // form was refused and the long form had no surface
                // that would show it.
                println!(
                    "{:<36}  {:<14}  {:<18}  {:<6}  {}s",
                    e.request_id, e.agent_id, e.tool_name, e.requested_tier, e.age_seconds,
                );
            }
            println!();
            println!("approve / deny / show take the id above, or any prefix unique to one row.");
            Ok(())
        }
        PermissionsResponse::Error { message } => anyhow::bail!("gateway error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Outcome of matching an operator-supplied id against the queue.
#[derive(Debug, PartialEq)]
enum IdMatch {
    /// The input is a request id verbatim.
    Exact(String),
    /// The input is a prefix of exactly one request id.
    Unique(String),
    /// The input names nothing in the queue.
    NoMatch,
    /// The input is a prefix of more than one request id.
    Ambiguous(Vec<String>),
}

/// Match an operator-supplied id against the ids the gateway holds.
///
/// An exact match wins outright, so a full id never depends on what
/// else is queued. Otherwise a prefix naming exactly one entry
/// resolves to it. An ambiguous prefix resolves to nothing: picking
/// one of several would approve a tool call the operator has not
/// read.
fn resolve_request_id<'a>(input: &str, ids: impl IntoIterator<Item = &'a str>) -> IdMatch {
    // Every id starts with the empty string, so an empty argument
    // would otherwise resolve whenever exactly one entry is queued.
    if input.is_empty() {
        return IdMatch::NoMatch;
    }
    let mut prefix_hits: Vec<String> = Vec::new();
    for id in ids {
        if id == input {
            return IdMatch::Exact(id.to_string());
        }
        if id.starts_with(input) {
            prefix_hits.push(id.to_string());
        }
    }
    match prefix_hits.len() {
        0 => IdMatch::NoMatch,
        1 => IdMatch::Unique(prefix_hits.remove(0)),
        _ => IdMatch::Ambiguous(prefix_hits),
    }
}

/// Expand an operator-supplied id to the full request id by reading
/// the live queue first.
///
/// An id that names nothing is passed through untouched so the
/// gateway answers for it: its reply separates "already resolved by
/// someone else, or timed out" from "never existed", which this side
/// cannot tell apart.
async fn resolved_request_id(input: &str) -> Result<String> {
    let entries = match permissions_rpc(&PermissionsRequest::PendingList).await? {
        PermissionsResponse::PendingList { entries } => entries,
        PermissionsResponse::Error { message } => anyhow::bail!("gateway error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    let ids: Vec<&str> = entries.iter().map(|e| e.request_id.as_str()).collect();
    match resolve_request_id(input, ids.iter().copied()) {
        IdMatch::Exact(id) | IdMatch::Unique(id) => Ok(id),
        IdMatch::NoMatch => Ok(input.to_string()),
        IdMatch::Ambiguous(hits) => {
            let mut msg = format!("'{input}' matches {} pending requests:", hits.len());
            for id in hits {
                msg.push_str(&format!("\n  {id}"));
            }
            msg.push_str("\nSupply enough characters to name one.");
            anyhow::bail!(msg)
        }
    }
}

/// `wirken permissions pending show <request_id>`: render the
/// full context for one pending entry including the trigger
/// message.
pub async fn pending_show(request_id: &str) -> Result<()> {
    let request_id = &resolved_request_id(request_id).await?;
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
    let request_id = &resolved_request_id(request_id).await?;
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
    let request_id = &resolved_request_id(request_id).await?;
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
    let store = open_permission_store(&cfg)?;

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
    let store = open_permission_store(&cfg)?;

    store
        .revoke(key, agent)
        .context(format!("Failed to revoke permission '{key}'"))?;

    println!("  Permission '{key}' revoked for agent '{agent}'.");
    Ok(())
}

/// Grant an approval for `key`, operator-initiated.
///
/// When `session` is `None`, writes a persisted approval to
/// `permissions.db` for the store's configured default window, or
/// for `expires_in_days` when the operator named one.
///
/// When `session` is `Some(session_id)`, writes a session-scoped
/// approval to the in-memory cache; the grant covers only the named
/// session and is cleared on session end. A day count passed
/// alongside `--session` is refused rather than ignored: session
/// grants end with the session and carry no window, so accepting the
/// flag would tell the operator they had set an expiry that nothing
/// reads.
///
/// Both paths append to the audit chain. The session path writes to
/// the named session; the persisted path writes to the
/// `gateway-permissions` sentinel lane, because an operator grant made
/// out of band of any conversation belongs to no agent session. The
/// persisted path used to write nothing at all, which left the only
/// production writer of persisted grants absent from the chain.
pub async fn approve(
    key: &str,
    agent: &str,
    session: Option<&str>,
    expires_in_days: Option<u32>,
) -> Result<()> {
    let cfg = config();
    let store = open_permission_store(&cfg)?;
    let log = SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?;

    match session {
        None => {
            let handle = log.handle_for(SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()));
            let approval = approve_and_log_by_key_with_expiry(
                &store,
                key,
                agent,
                "operator",
                ApprovalScope::Persisted,
                &log,
                &handle,
                None,
                None,
                expires_in_days,
            )
            .context(format!("Failed to approve permission '{key}'"))?;
            println!(
                "  Approved '{}' for agent '{}' until {}.",
                approval.action_key,
                approval.agent_id,
                approval.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
            );
        }
        Some(session_id) => {
            if expires_in_days.is_some() {
                anyhow::bail!(
                    "--expires-in-days does not apply to a session-scoped grant: it is \
                     cleared on session end, not on a date. Drop --session for a persisted \
                     grant with a window, or drop --expires-in-days."
                );
            }
            let handle = log.handle_for(SessionId::new(session_id.to_string()));
            let scope = ApprovalScope::Session {
                session_id: session_id.to_string(),
            };
            let approval = approve_and_log_by_key_with_expiry(
                &store, key, agent, "operator", scope, &log, &handle, None, None, None,
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
    let perms = open_permission_store(&cfg)?;

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

#[cfg(test)]
mod tests {
    use super::{IdMatch, resolve_request_id};

    const A: &str = "5a6255fd-1111-4000-8000-000000000001";
    const B: &str = "5a6255fd-2222-4000-8000-000000000002";
    const C: &str = "9f0e1d2c-3333-4000-8000-000000000003";

    #[test]
    fn full_id_matches_exactly() {
        assert_eq!(
            resolve_request_id(A, [A, B, C]),
            IdMatch::Exact(A.to_string())
        );
    }

    /// An id that is also a prefix of another resolves to itself
    /// rather than being reported ambiguous.
    #[test]
    fn exact_match_wins_over_prefix_of_another() {
        let short = "5a6255fd-1111";
        let longer = "5a6255fd-1111-4000-8000-000000000001";
        assert_eq!(
            resolve_request_id(short, [short, longer]),
            IdMatch::Exact(short.to_string())
        );
    }

    #[test]
    fn unique_prefix_resolves() {
        assert_eq!(
            resolve_request_id("9f0e", [A, B, C]),
            IdMatch::Unique(C.to_string())
        );
    }

    /// The truncation `pending list` used to print. It names two
    /// rows here, so it has to be refused rather than guessed.
    #[test]
    fn ambiguous_prefix_lists_every_match() {
        let IdMatch::Ambiguous(hits) = resolve_request_id("5a6255fd", [A, B, C]) else {
            panic!("expected an ambiguous match");
        };
        assert_eq!(hits, vec![A.to_string(), B.to_string()]);
    }

    #[test]
    fn unknown_prefix_does_not_match() {
        assert_eq!(resolve_request_id("dead", [A, B, C]), IdMatch::NoMatch);
    }

    /// Every id starts with "", so an empty argument must not
    /// resolve to the only queued entry.
    #[test]
    fn empty_input_never_resolves() {
        assert_eq!(resolve_request_id("", [A]), IdMatch::NoMatch);
        assert_eq!(resolve_request_id("", [A, B, C]), IdMatch::NoMatch);
    }
}
