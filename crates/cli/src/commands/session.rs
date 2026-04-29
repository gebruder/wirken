use anyhow::{Context, Result};

use wirken_audit::SessionLog;
use wirken_gateway::session::SessionStore;

use super::config;

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

    let store = SessionStore::open(&cfg.sessions_db_path(), cfg.session_expiry_secs)
        .context("Failed to open session store")?;

    let sessions = store
        .list_active(channel.as_deref())
        .context("Failed to list sessions")?;

    if sessions.is_empty() {
        println!("  No active sessions.");
        return Ok(());
    }

    // Resolve channel -> agent bindings so we can print the composite
    // session-log id (`<agent>/<channel>/<conversation>`) that
    // `wirken sessions verify` actually accepts. The store's hex id is
    // only a primary key inside the sessions DB; the audit/session-log
    // DB keys rows by composite. Printing both removes the "ID from
    // list does not work with verify" paper cut.
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

    for session in &sessions {
        let agent_id = binding_map
            .get(&session.channel)
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        let log_id = format!(
            "{}/{}/{}",
            agent_id, session.channel, session.conversation_id
        );
        let short_id: String = session.id.chars().take(16).collect();
        println!(
            "  {:16}  {:40}  {:12}  {:>6}  {:20}",
            short_id,
            truncate_for_display(&log_id, 40),
            session.channel,
            session.message_count,
            session.last_activity.format("%Y-%m-%d %H:%M:%S"),
        );
    }

    println!();
    println!("  {} active sessions.", sessions.len());
    println!("  Use STORE ID for `wirken sessions close`, LOG ID for `wirken sessions verify`.");
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
