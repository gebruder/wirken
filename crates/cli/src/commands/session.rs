use anyhow::{Context, Result};
use serde::Serialize;

use wirken_audit::SessionLog;
use wirken_gateway::permissions::{
    SESSION_CLEAR_REASON_ENDED, count_active_session_scoped_approvals,
    emit_session_scoped_approvals_cleared,
};
use wirken_gateway::session::SessionStore;

use super::config;

/// Resolve a CLI session-id argument to the composite log id
/// (`{agent_id}/{channel}/{conversation_id}`) the session log and
/// `factory.evict` key on. Accepts either form so the CLI's "Use
/// STORE ID for `wirken sessions close`, LOG ID for `wirken sessions
/// verify`" message stays operator-friendly:
///
/// - composite (contains `/`): returned unchanged.
/// - hex store id: looked up in `SessionStore`, joined with the
///   agent id resolved from `AgentConfigStore`, defaulting to
///   `"default"` if no agent owns the session's channel.
///
/// Returns `None` when a hex id has no matching `SessionStore` row;
/// the caller surfaces that as a "session not found" error.
fn resolve_to_composite_log_id(
    cfg: &wirken_gateway::config::GatewayConfig,
    raw_id: &str,
) -> Option<String> {
    if raw_id.contains('/') {
        return Some(raw_id.to_string());
    }
    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs).ok()?;
    let sess = store.get(raw_id).ok()?;
    let agent_id =
        wirken_gateway::agent_config::AgentConfigStore::open(&cfg.agent_config_db_path())
            .ok()
            .and_then(|s| s.list().ok())
            .and_then(|agents| {
                agents
                    .into_iter()
                    .find(|a| a.channels.iter().any(|c| c == &sess.channel))
                    .map(|a| a.id)
            })
            .unwrap_or_else(|| "default".into());
    Some(format!(
        "{}/{}/{}",
        agent_id, sess.channel, sess.conversation_id
    ))
}

/// One active session as structured data, shared by the
/// `wirken sessions list` printer and the webchat `GET /api/sessions`
/// endpoint. `log_id` is the composite `{agent}/{channel}/{conversation}`
/// that the session log keys on; `store_id` is the hex primary key in
/// the sessions DB.
#[derive(Serialize)]
pub struct SessionRow {
    pub store_id: String,
    pub log_id: String,
    pub channel: String,
    pub message_count: i64,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

/// Gather active sessions (optionally filtered by channel) as structured
/// rows. The channel-to-agent binding resolution and the composite
/// log-id assembly live here once; both `list` and the webchat sessions
/// endpoint call this rather than duplicating the query.
pub fn active_session_rows(
    cfg: &wirken_gateway::config::GatewayConfig,
    channel: Option<&str>,
) -> Result<Vec<SessionRow>> {
    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?;

    let sessions = store
        .list_active(channel)
        .context("Failed to list sessions")?;

    // Resolve channel -> agent bindings so we can build the composite
    // session-log id (`<agent>/<channel>/<conversation>`) that the
    // session log keys on. The store's hex id is only a primary key
    // inside the sessions DB.
    let binding_map =
        match wirken_gateway::agent_config::AgentConfigStore::open(&cfg.agent_config_db_path()) {
            Ok(agent_store) => {
                let mut map = std::collections::HashMap::new();
                if let Ok(agents) = agent_store.list() {
                    for agent in agents {
                        for ch in agent.channels {
                            map.insert(ch, agent.id.clone());
                        }
                    }
                }
                map
            }
            Err(_) => std::collections::HashMap::new(),
        };

    Ok(sessions
        .into_iter()
        .map(|session| {
            let agent_id = binding_map
                .get(&session.channel)
                .cloned()
                .unwrap_or_else(|| "default".to_string());
            SessionRow {
                log_id: format!(
                    "{}/{}/{}",
                    agent_id, session.channel, session.conversation_id
                ),
                store_id: session.id,
                channel: session.channel,
                message_count: session.message_count,
                last_activity: session.last_activity,
            }
        })
        .collect())
}

/// A single displayable turn from a session transcript: a user or
/// assistant message. Tool calls, tool results, LLM request/response
/// accounting, and every other event kind are not displayable turns and
/// are skipped by [`session_transcript`].
#[derive(Serialize)]
pub struct TranscriptTurn {
    pub role: &'static str,
    pub content: String,
}

/// Read the displayable transcript for a composite session-log id
/// (`{agent}/{channel}/{conversation}`) through the same session-log
/// lookup path `wirken sessions verify` uses. Only user and assistant
/// messages are returned, in sequence order; every other event kind is
/// skipped rather than stringified.
pub fn session_transcript(
    cfg: &wirken_gateway::config::GatewayConfig,
    composite_id: &str,
) -> Result<Vec<TranscriptTurn>> {
    use wirken_audit::{SessionEvent, SessionId, SqliteSessionLog};

    let log = SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?;
    let handle = log.handle_for(SessionId::new(composite_id.to_string()));
    let events = log
        .get_since(&handle, 0)
        .context("Failed to read session events")?;

    Ok(events
        .into_iter()
        .filter_map(|ev| match ev.event {
            SessionEvent::UserMessage { content, .. } => Some(TranscriptTurn {
                role: "user",
                content,
            }),
            SessionEvent::AssistantMessage { content, .. } => Some(TranscriptTurn {
                role: "assistant",
                content,
            }),
            _ => None,
        })
        .collect())
}

pub async fn list(channel: Option<String>, parent: Option<String>) -> Result<()> {
    let cfg = config();

    // Item 6 slice 2: --parent shows child sessions by querying
    // session_events for session_ids that start with the parent's
    // id followed by "#sub-".
    if let Some(ref parent_id) = parent {
        let log = wirken_audit::SqliteSessionLog::open(&cfg.sessions_db_path())
            .or_else(|_| wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()))
            .context("Failed to open session log")?;
        let children = log.list_child_sessions(parent_id);
        if children.is_empty() {
            println!("  No child sessions for '{parent_id}'.");
        } else {
            println!("  Child sessions of {parent_id}:");
            for child_id in &children {
                let h = log.handle_for(wirken_audit::SessionId::new(child_id.clone()));
                let count = log
                    .last_index(&h)
                    .unwrap_or(None)
                    .map(|n| n + 1)
                    .unwrap_or(0);
                println!("    {child_id}  ({count} events)");
            }
            println!();
            println!("  {} child session(s).", children.len());
        }
        return Ok(());
    }

    let rows = active_session_rows(&cfg, channel.as_deref())?;

    if rows.is_empty() {
        println!("  No active sessions.");
        return Ok(());
    }

    // The composite LOG ID (`<agent>/<channel>/<conversation>`) is what
    // `wirken sessions verify` accepts; the STORE ID is the hex primary
    // key `wirken sessions close` takes. Printing both removes the "ID
    // from list does not work with verify" paper cut.
    println!(
        "  {:16}  {:40}  {:12}  {:>6}  {:20}",
        "STORE ID", "LOG ID", "CHANNEL", "MSGS", "LAST ACTIVITY"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "─".repeat(16),
        "─".repeat(40),
        "─".repeat(12),
        "─".repeat(6),
        "─".repeat(20)
    );

    for row in &rows {
        let short_id: String = row.store_id.chars().take(16).collect();
        println!(
            "  {:16}  {:40}  {:12}  {:>6}  {:20}",
            short_id,
            truncate_for_display(&row.log_id, 40),
            row.channel,
            row.message_count,
            row.last_activity.format("%Y-%m-%d %H:%M:%S"),
        );
    }

    println!();
    println!("  {} active sessions.", rows.len());
    println!("  Use STORE ID for `wirken sessions close`, LOG ID for `wirken sessions verify`.");
    Ok(())
}

/// Close (mark expired) a session and tombstone any active
/// session-scoped approval grants in its audit chain. The store-side
/// flip is what `wirken sessions list` reflects; the audit tombstone
/// is what the replay-on-wake path in `AgentFactory::wake` consumes
/// to leave the in-memory cache empty on the next wake.
///
/// Coherence note: the daemon (if running) keeps any session-scoped
/// grants in its own in-process cache until process restart, because
/// the CLI runs out-of-band of the daemon and cannot directly call
/// `factory.evict`. A daemon-side background sweep that routes
/// expired sessions through `factory.evict` is the architecturally
/// clean follow-up; until that lands, in-flight grants on a CLI-
/// closed session remain effective for the lifetime of the daemon
/// process. Replay correctness on the next wake is preserved by the
/// tombstone emitted here.
pub async fn close(id: &str) -> Result<()> {
    let cfg = config();
    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?;

    store
        .close(id)
        .context(format!("Failed to close session '{id}'"))?;

    // Tombstone any session-scoped approvals. The CLI may have
    // received a hex store id or a composite log id; the audit
    // chain keys on the composite, so translate before emitting.
    // Translation failure is non-fatal: a session that has no
    // composite mapping (or no SessionStore row) cannot have had
    // session-scoped grants emitted under it, so the tombstone
    // would be a no-op anyway.
    if let Some(composite) = resolve_to_composite_log_id(&cfg, id) {
        let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log")?;
        let active = count_active_session_scoped_approvals(&log, &composite)
            .context("Failed to count active session-scoped approvals")?;
        if active > 0 {
            emit_session_scoped_approvals_cleared(
                &log,
                &composite,
                active,
                SESSION_CLEAR_REASON_ENDED,
            )
            .context("Failed to emit SessionScopedApprovalsCleared")?;
        }
    }

    println!("  Session '{id}' closed.");
    Ok(())
}

/// `wirken session verify <session_id> [--strict]` — item 10 slice 1.
///
/// Walks the session log for `session_id` and verifies what can be
/// verified: chain integrity, LlmRequest input hashes (against the
/// conversation projection at each point with the same `fit()`
/// applied), and deterministic tool re-execution. Prints a structured
/// report.
///
/// Exit codes:
///   0  fully verified clean
///   1  at least one divergence
///   2  --strict and at least one unverifiable event with no divergences
///   3  underlying chain broken
///   4  command setup failure (agent_id not found, log unreachable, …)
pub async fn verify(session_id: &str, strict: bool) -> Result<()> {
    use std::collections::HashMap;
    use std::sync::Arc;

    use wirken_agent::factory::CacheMode;
    use wirken_agent::llm::LlmConfig;
    use wirken_agent::{AgentFactory, AgentStaticConfig};
    use wirken_audit::SqliteSessionLog;
    use wirken_gateway::agent_config::AgentConfigStore;

    let cfg = config();

    // Accept either the composite session-log id or the hex store id
    // that `wirken sessions list` prints. Translating the store id
    // into the composite via SessionStore lookup lets operators copy
    // from either column of the list output. For composite input
    // (contains `/`) we pass through unchanged.
    let session_id_owned = if session_id.contains('/') {
        session_id.to_string()
    } else {
        match wirken_gateway::session::SessionStore::open(
            &cfg.sessions_db_path(),
            cfg.session_expiry_secs,
        )
        .ok()
        .and_then(|s| s.get(session_id).ok())
        {
            Some(sess) => {
                let agent_id = match AgentConfigStore::open(&cfg.agent_config_db_path()) {
                    Ok(agent_store) => agent_store
                        .list()
                        .ok()
                        .and_then(|agents| {
                            agents
                                .into_iter()
                                .find(|a| a.channels.iter().any(|c| c == &sess.channel))
                                .map(|a| a.id)
                        })
                        .unwrap_or_else(|| "default".into()),
                    Err(_) => "default".into(),
                };
                format!("{}/{}/{}", agent_id, sess.channel, sess.conversation_id)
            }
            None => session_id.to_string(),
        }
    };
    let session_id = session_id_owned.as_str();

    // Parse agent_id from session_id. Slice 2 of item 2 fixed the
    // format as `{agent_id}/{channel}/{conversation_id}`. Older
    // (slice-1-of-item-2) sessions used the bare agent_id; if we
    // can't split, treat the whole thing as the agent_id.
    let agent_id = match session_id.split_once('/') {
        Some((aid, _)) => aid.to_string(),
        None => session_id.to_string(),
    };

    // Look up the agent's static config. Falls back to the default
    // provider config if no per-agent record exists.
    let agent_config_path = cfg.agent_config_db_path();
    let (workspace, llm_config) = if agent_config_path.exists()
        && let Ok(store) = AgentConfigStore::open(&agent_config_path)
        && let Ok(agent_cfg) = store.get(&agent_id)
    {
        let mut llm =
            LlmConfig::from_provider(&agent_cfg.provider, &agent_cfg.base_url, &agent_cfg.model);
        if agent_cfg.provider == "bedrock" {
            llm.region = agent_cfg
                .base_url
                .strip_prefix("https://bedrock-runtime.")
                .and_then(|s| s.strip_suffix(".amazonaws.com"))
                .map(String::from);
        }
        (cfg.agent_workspace(&agent_cfg.id), llm)
    } else {
        // Fall back to provider.json (the default agent's config).
        let provider_path = cfg.data_dir.join("provider.json");
        if !provider_path.exists() {
            eprintln!("  No agent '{agent_id}' configured. Run `wirken setup` first.");
            std::process::exit(4);
        }
        let provider_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&provider_path)?)?;
        let provider = provider_json["provider"].as_str().unwrap_or("ollama");
        let model = provider_json["model"].as_str().unwrap_or("llama3");
        let base_url = provider_json["base_url"]
            .as_str()
            .unwrap_or("http://localhost:11434/v1");
        (
            cfg.data_dir.join("workspace"),
            LlmConfig::from_provider(provider, base_url, model),
        )
    };

    // Open the session log.
    let session_log: Arc<dyn wirken_audit::SessionLog> = Arc::new(
        SqliteSessionLog::open(&cfg.audit_db_path()).context("Failed to open session log")?,
    );

    // Verify the session has events at all.
    let probe_handle = session_log.handle_for(wirken_audit::SessionId::new(session_id.to_string()));
    let event_count = session_log
        .last_index(&probe_handle)
        .context("session log query failed")?;
    if event_count.is_none() {
        eprintln!("  No events for session '{session_id}'.");
        std::process::exit(4);
    }

    // Build a one-shot factory and wake the agent. The factory is
    // the only public path to `Agent::from_session_log` (which
    // replays + heals partial tool rounds).
    let mut configs: HashMap<String, AgentStaticConfig> = HashMap::new();
    configs.insert(
        agent_id.clone(),
        AgentStaticConfig {
            agent_id: agent_id.clone(),
            workspace,
            llm_config,
            channel_overrides: HashMap::new(),
            api_key: None, // verify never calls the LLM
            api_key_credential: None,
            skills: Vec::new(),
            wasm_skills: Vec::new(),
            mcp_client: None,
            identity: None, // verify never signs new attestations
            allowed_subagents: Default::default(),
            // verify re-executes deterministic read-only tools against
            // the current workspace; no shell exec is ever replayed,
            // so the sandbox config is inert here. Use the default
            // rather than loading provider.json to keep verify
            // independent of the runtime sandbox selection.
            sandbox: Default::default(),
            extra_interceptors: vec![],
            zirkel_db_path: None,
        },
    );
    let factory =
        AgentFactory::with_options(configs, session_log.clone(), None, None, CacheMode::Drop, 1);

    let agent_arc = factory
        .wake(&agent_id, session_id)
        .map_err(|e| anyhow::anyhow!("factory.wake('{agent_id}', '{session_id}') failed: {e}"))?;
    let agent = agent_arc.lock().await;

    println!();
    println!("  wirken session verify {session_id}");
    println!("  ──────────────────────");
    println!("  agent: {agent_id}");
    println!("  Note: deterministic tools (read_file, list_files) are re-executed against the");
    println!("        CURRENT workspace, not the workspace state at the time of execution.");
    println!();

    let report = agent.verify().await.context("verify failed")?;

    // Print the report.
    println!("  events_total:        {}", report.events_total);
    println!("  events_verified:     {}", report.events_verified);
    println!("  events_unverifiable: {}", report.events_unverifiable);
    println!("  events_divergent:    {}", report.events_divergent.len());
    match &report.chain_status {
        wirken_audit::SessionVerifyResult::Ok { rows_verified } => {
            println!("  chain:               OK ({rows_verified} rows)");
        }
        wirken_audit::SessionVerifyResult::Empty => {
            println!("  chain:               EMPTY");
        }
        wirken_audit::SessionVerifyResult::Broken {
            seq,
            expected_hash,
            actual_hash,
            ..
        } => {
            println!(
                "  chain:               BROKEN at seq {seq}: expected {expected_hash}, got {actual_hash}"
            );
        }
    }

    if !report.events_divergent.is_empty() {
        println!();
        println!("  Divergences:");
        for d in &report.events_divergent {
            println!(
                "    seq {} [{}]: expected {} found {}",
                d.seq,
                d.kind,
                truncate_for_display(&d.expected, 64),
                truncate_for_display(&d.found, 64),
            );
        }
    }

    println!();

    // Determine exit code.
    if matches!(
        report.chain_status,
        wirken_audit::SessionVerifyResult::Broken { .. }
    ) {
        std::process::exit(3);
    }
    if !report.events_divergent.is_empty() {
        std::process::exit(1);
    }
    if strict && report.events_unverifiable > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn truncate_for_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}
