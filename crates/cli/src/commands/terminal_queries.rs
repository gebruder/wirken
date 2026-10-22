//! What the gateway tells a `wirken chat` client about its own state,
//! on the terminal channel: the panels, the check of a conversation's
//! chain, the agents and their terminal conversations, and a
//! conversation's messages to resume it.
//!
//! The client opens no store. Everything here is read in the gateway,
//! from the factory it runs agents with and the session log it writes,
//! and goes back as JSON in a `TerminalReply`. Only terminal
//! conversations are listed or read; the session ids are built here from
//! the agent the connection is routed to, not taken from the client.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};
use wirken_agent::AgentFactory;
use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, StoredSessionEvent};
use wirken_gateway::terminal_sessions::TERMINAL_CHANNEL;

/// Characters of a first message kept as a conversation's title.
const TITLE_CHARS: usize = 80;

/// How many rows from the start of a conversation are read for its
/// title.
const TITLE_ROWS: u64 = 32;

fn rows(log: &dyn SessionLog, session_id: &str) -> Vec<StoredSessionEvent> {
    log.get_since(&log.handle_for(SessionId::new(session_id)), 0)
        .unwrap_or_default()
}

/// `~` for the home directory, so the panel says `~/.wirken`.
fn home_relative(path: &Path) -> String {
    match std::env::var_os("HOME").map(std::path::PathBuf::from) {
        Some(home) if !home.as_os_str().is_empty() => match path.strip_prefix(&home) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        },
        _ => path.display().to_string(),
    }
}

fn mode_word(mode: wirken_audit::SandboxModeLabel) -> &'static str {
    match mode {
        wirken_audit::SandboxModeLabel::ExecOnly => "exec_only",
        wirken_audit::SandboxModeLabel::Gvisor => "gvisor",
        wirken_audit::SandboxModeLabel::Off => "off",
    }
}

/// The panels for the conversation on `session_id`, run by `agent`.
pub(crate) async fn status(
    factory: &AgentFactory,
    log: &dyn SessionLog,
    data_dir: &Path,
    agent: &str,
    session_id: &str,
) -> Value {
    let rows = rows(log, session_id);
    let settings = factory.agent_settings(agent);

    let environment = match &settings {
        Some((llm, sandbox)) => {
            let mode = sandbox.mode.label();
            json!({
                "data_dir": home_relative(data_dir),
                "agent": agent,
                "provider": llm.provider,
                "model": llm.model,
                "exec": {
                    "mode": mode_word(mode),
                    "runtime": wirken_agent::exec_location::runtime_name(mode),
                },
            })
        }
        None => json!({ "data_dir": home_relative(data_dir), "agent": agent }),
    };

    let mut calls = 0u64;
    let (mut input, mut output, mut costed, mut micros) = (0u64, 0u64, 0u64, 0u64);
    let mut last_used = None;
    let (mut approved, mut denied, mut heads) = (0u64, 0u64, 0u64);
    let mut unsigned_tail = 0u64;
    for row in &rows {
        unsigned_tail += 1;
        match &row.event {
            SessionEvent::LlmResponse {
                input_tokens,
                output_tokens,
                total_cost_usd_micros,
                ..
            } => {
                calls += 1;
                input += u64::from(*input_tokens);
                output += u64::from(*output_tokens);
                if let Some(cost) = total_cost_usd_micros {
                    costed += 1;
                    micros += cost;
                }
                last_used = Some(u64::from(*input_tokens) + u64::from(*output_tokens));
            }
            SessionEvent::PermissionApproved { .. } => approved += 1,
            SessionEvent::PermissionDenied { .. } => denied += 1,
            SessionEvent::ChainHead { .. } => {
                heads += 1;
                unsigned_tail = 0;
            }
            _ => {}
        }
    }

    let budget = match factory.budget_state(agent) {
        None => json!({ "mode": "off" }),
        Some((b, spent)) => json!({
            "mode": serde_json::to_value(b.mode).unwrap_or(Value::Null),
            "window": b.window.label(),
            "ceiling_usd_micros": b.ceiling_usd_micros,
            "spent_usd_micros": spent,
        }),
    };
    let grants = factory.stored_grants(agent).map(|grants| {
        grants
            .iter()
            .map(|g| json!({ "action_key": g.action_key, "expires_at": g.expires_at.to_rfc3339() }))
            .collect::<Vec<_>>()
    });

    json!({
        "agent": agent,
        "environment": environment,
        "context": {
            "used_tokens": last_used,
            "window": settings.as_ref().map(|(llm, _)| llm.context_window),
        },
        "cost": {
            "calls": calls,
            "input_tokens": input,
            "output_tokens": output,
            "costed_calls": costed,
            "cost_usd_micros": (costed > 0).then_some(micros),
            "budget": budget,
        },
        "audit": {
            "rows": rows.len(),
            "heads": heads,
            "unsigned_tail": unsigned_tail,
        },
        "approvals": {
            "approved": approved,
            "denied": denied,
            "grants": grants,
        },
        "tools": tools(factory, agent, session_id).await,
    })
}

/// What the agent is offered and how many of those the gate asks about
/// before they run. A turn in flight holds the agent, so it answers
/// busy rather than waiting.
async fn tools(factory: &AgentFactory, agent: &str, session_id: &str) -> Value {
    let Ok(handle) = factory.wake(agent, session_id) else {
        return json!({ "available": false });
    };
    let Ok(guard) = handle.try_lock() else {
        return json!({ "busy": true });
    };
    let defs = guard
        .snapshot_tool_defs_for(wirken_audit::ToolsHashVersion::V2)
        .await;
    let skills: Vec<String> = guard.skills().iter().map(|s| s.name.clone()).collect();
    drop(guard);
    let mut names = Vec::new();
    let mut ask_first = 0u64;
    for def in &defs {
        let entry = super::webchat::tool_tier_entry(&def.name, &def.description);
        let asks = entry["tier_depends_on_arguments"] == true
            || matches!(entry["tier"].as_str(), Some("tier2" | "tier3"));
        if asks {
            ask_first += 1;
        }
        names.push(def.name.clone());
    }
    names.sort();
    json!({
        "count": names.len(),
        "ask_first": ask_first,
        "names": names,
        "skills": skills,
    })
}

/// Verify the conversation's chain: every row's hash against its
/// payload and its predecessor, and every signed head's signature. Off
/// the async runtime, since a long session is a lot of hashing.
pub(crate) async fn verify(log: Arc<SqliteSessionLog>, session_id: String) -> Value {
    let checked = tokio::task::spawn_blocking(move || {
        let handle = log.handle_for(SessionId::new(session_id));
        let chain = log.verify(&handle);
        let signatures = log.verify_signatures(&handle);
        (chain, signatures)
    })
    .await;
    let Ok((chain, signatures)) = checked else {
        return json!({ "chain": "error", "error": "the check did not complete" });
    };
    let mut out = match chain {
        Ok(wirken_audit::SessionVerifyResult::Ok { rows_verified }) => {
            json!({ "chain": "ok", "rows": rows_verified })
        }
        Ok(wirken_audit::SessionVerifyResult::Empty) => json!({ "chain": "empty", "rows": 0 }),
        Ok(wirken_audit::SessionVerifyResult::Broken {
            seq,
            verified_count,
            ..
        }) => json!({ "chain": "broken", "broken_at": seq, "rows": verified_count }),
        Err(e) => json!({ "chain": "error", "error": e.to_string() }),
    };
    match signatures {
        Ok(s) => {
            out["signed_heads"] = json!(s.signed_heads_count);
            out["unsigned_tail"] = json!(s.unsigned_tail_len);
            out["invalid_signature"] = json!(s.first_invalid.is_some());
        }
        Err(e) => out["signature_error"] = json!(e.to_string()),
    }
    out
}

/// The agents, each with its model, and every terminal conversation on
/// the chain, most recent first.
pub(crate) fn conversations(factory: &AgentFactory, log: &SqliteSessionLog) -> Value {
    let mut ids = factory.known_agent_ids();
    ids.sort();
    let agents: Vec<Value> = ids
        .iter()
        .map(|id| match factory.agent_settings(id) {
            Some((llm, _)) => json!({ "id": id, "provider": llm.provider, "model": llm.model }),
            None => json!({ "id": id }),
        })
        .collect();

    let mut conversations: Vec<(String, Value)> = Vec::new();
    for session_id in log.list_session_ids().unwrap_or_default() {
        let mut parts = session_id.splitn(3, '/');
        let (Some(agent), Some(TERMINAL_CHANNEL), Some(conversation)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        // A sub-agent's lane belongs to the conversation that spawned it.
        if session_id.contains("#sub-") {
            continue;
        }
        let handle = log.handle_for(SessionId::new(session_id.clone()));
        let title = log
            .get_range(&handle, 0..TITLE_ROWS)
            .unwrap_or_default()
            .into_iter()
            .find_map(|r| match r.event {
                SessionEvent::UserMessage { content, .. } => Some(content),
                _ => None,
            })
            .map(|t| t.chars().take(TITLE_CHARS).collect::<String>());
        let updated = log
            .last_index(&handle)
            .ok()
            .flatten()
            .and_then(|last| log.get_range(&handle, last..last + 1).ok())
            .and_then(|r| r.into_iter().next())
            .map(|r| r.ts.to_rfc3339())
            .unwrap_or_default();
        conversations.push((
            updated.clone(),
            json!({
                "agent": agent,
                "conversation": conversation,
                "title": title,
                "updated": updated,
            }),
        ));
    }
    conversations.sort_by(|a, b| b.0.cmp(&a.0));
    json!({
        "agents": agents,
        "conversations": conversations.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
    })
}

/// The conversation's messages and tool calls in order, to show it
/// again when it is resumed.
pub(crate) fn history(log: &dyn SessionLog, session_id: &str) -> Value {
    let mut entries: Vec<Value> = Vec::new();
    for row in rows(log, session_id) {
        match row.event {
            SessionEvent::UserMessage { content, .. } => {
                entries.push(json!({ "kind": "user", "text": content }));
            }
            SessionEvent::AssistantMessage { content, .. } => {
                entries.push(json!({ "kind": "agent", "text": content }));
            }
            SessionEvent::AssistantToolCalls { calls, text, .. } => {
                if let Some(text) = text.filter(|t| !t.is_empty()) {
                    entries.push(json!({ "kind": "agent", "text": text }));
                }
                for call in calls {
                    entries.push(json!({
                        "kind": "tool",
                        "id": call.id,
                        "name": call.name,
                        "arguments": call.arguments,
                        "success": Value::Null,
                        "output": "",
                    }));
                }
            }
            SessionEvent::ToolResult {
                call_id,
                success,
                output,
                ..
            } => {
                if let Some(entry) = entries
                    .iter_mut()
                    .rev()
                    .find(|e| e["kind"] == "tool" && e["id"] == call_id.as_str())
                {
                    entry["success"] = json!(success);
                    entry["output"] = json!(output);
                }
            }
            _ => {}
        }
    }
    json!({ "entries": entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_directory_is_shown_as_a_tilde() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let home = std::path::PathBuf::from(home);
        assert_eq!(home_relative(&home.join(".wirken")), "~/.wirken");
        assert_eq!(home_relative(Path::new("/srv/wirken")), "/srv/wirken");
    }
}
