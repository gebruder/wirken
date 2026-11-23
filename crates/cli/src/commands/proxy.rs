//! `wirken proxy`: the tokens clients of the inference proxy
//! authenticate with.
//!
//! Issuing and revoking a token decide who may spend the operator's
//! provider credentials, so both are done at a terminal, refuse inside
//! a Wirken `exec`, and are a signed row on the operator lane. A token
//! is shown once, when it is issued: only its digest is stored.

use anyhow::{Context, Result, bail};
use wirken_gateway::budget::BudgetWindow;
use wirken_gateway::proxy::{
    PROXY_TOKENS_FILE, ProxyConfig, ProxyToken, ProxyTokenStore, TokenGrant,
};

use super::config;

/// Refuse without a terminal. The exec marker is refused, with a row,
/// before any command here is dispatched.
fn require_terminal(command: &str) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        bail!(
            "wirken proxy {command} refuses to run inside a Wirken exec ({} is set); \
             run it yourself, from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("wirken proxy {command} is run by the operator at a terminal");
    }
    Ok(())
}

pub(crate) fn open_store(data_dir: &std::path::Path) -> Result<ProxyTokenStore> {
    ProxyTokenStore::open(&data_dir.join(PROXY_TOKENS_FILE))
        .context("Failed to open the proxy token store")
}

fn parse_window(window: &str) -> Result<BudgetWindow> {
    Ok(match window {
        "hour" => BudgetWindow::Hour,
        "day" => BudgetWindow::Day,
        "week" => BudgetWindow::Week,
        other => bail!("--window {other:?} is not hour, day or week"),
    })
}

/// The MCP servers `agent` is configured with whose entries are
/// signed, each with its entry digest. Read from the file the MCP
/// proxy loads for that agent: `agents/<agent>/mcp.json` when it
/// exists, the shared `mcp.json` otherwise.
pub(crate) fn signed_mcp_servers(
    data_dir: &std::path::Path,
    agent: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let per_agent = data_dir.join("agents").join(agent).join("mcp.json");
    let path = if per_agent.exists() {
        per_agent
    } else {
        data_dir.join("mcp.json")
    };
    let config = wirken_mcp_proxy::McpConfig::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(config
        .servers
        .iter()
        .filter_map(|(name, server)| {
            wirken_mcp_proxy::mcp_signing::verified_entry_digest(name, server)
                .map(|digest| (name.clone(), digest))
        })
        .collect())
}

/// What a token is allowed, as one line for a row or a listing.
fn describe(token: &ProxyToken) -> String {
    let mut parts = Vec::new();
    if !token.upstreams.is_empty() {
        parts.push(format!("upstreams {}", token.upstreams.join(",")));
        parts.push(if token.models.is_empty() {
            "any model".to_string()
        } else {
            format!("models {}", token.models.join(","))
        });
    }
    if !token.mcp_servers.is_empty() {
        parts.push(format!(
            "MCP servers {} of agent {}",
            token.mcp_servers.join(","),
            token.mcp_agent
        ));
    }
    if let Some(micros) = token.ceiling_usd_micros {
        parts.push(format!(
            "${:.2} a {}",
            micros as f64 / 1e6,
            token.window.label()
        ));
    }
    if let Some(calls) = token.ceiling_calls {
        parts.push(format!("{calls} calls a {}", token.window.label()));
    }
    parts.join("; ")
}

/// Issue a token in `data_dir` and record it. The token is taken back
/// if its row cannot be written. Returns the record and the token.
pub(crate) fn issue_recorded(
    data_dir: &std::path::Path,
    grant: &TokenGrant,
) -> Result<(ProxyToken, String)> {
    if let Some(config) = ProxyConfig::load(data_dir).map_err(|e| anyhow::anyhow!("{e}"))? {
        for upstream in &grant.upstreams {
            if !config.upstreams.contains_key(upstream) {
                bail!(
                    "proxy.json has no upstream named {upstream}; it has {}",
                    config
                        .upstreams
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
    if !grant.mcp_servers.is_empty() {
        let signed = signed_mcp_servers(data_dir, &grant.mcp_agent)?;
        for server in &grant.mcp_servers {
            if !signed.contains_key(server) {
                bail!(
                    "agent {} has no signed MCP server named {server}; sign its entry with \
                     `wirken mcp sign {server}`",
                    grant.mcp_agent
                );
            }
        }
    }
    let store = open_store(data_dir)?;
    let (token, value) = store.issue(grant).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Err(e) = super::record_operator_command(
        "proxy token issue",
        &format!("{} ({})", token.name, token.id),
        &describe(&token),
    ) {
        let _ = store.revoke(&token.id);
        return Err(e.context("the token was not issued: its row could not be written"));
    }
    Ok((token, value))
}

/// Revoke a token in `data_dir` and record it.
pub(crate) fn revoke_recorded(
    data_dir: &std::path::Path,
    id_or_name: &str,
) -> Result<Option<ProxyToken>> {
    let store = open_store(data_dir)?;
    let Some(token) = store
        .revoke(id_or_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(None);
    };
    super::record_operator_command(
        "proxy token revoke",
        &format!("{} ({})", token.name, token.id),
        "",
    )
    .context("the token is revoked, but its row could not be written")?;
    Ok(Some(token))
}

#[allow(clippy::too_many_arguments)]
pub fn token_issue(
    name: &str,
    upstreams: &[String],
    models: &[String],
    ceiling_usd: Option<f64>,
    ceiling_calls: Option<u64>,
    window: &str,
    mcp_servers: &[String],
    mcp_agent: &str,
) -> Result<()> {
    require_terminal("token issue")?;
    if upstreams.is_empty() && mcp_servers.is_empty() {
        bail!("a token needs --upstream, --mcp-server or both");
    }
    let ceiling_usd_micros = match ceiling_usd {
        Some(usd) if !(usd.is_finite() && usd > 0.0) => {
            bail!("--ceiling-usd must be a positive number")
        }
        Some(usd) => Some((usd * 1e6) as u64),
        None => None,
    };
    if ceiling_calls == Some(0) {
        bail!("--ceiling-calls must be above zero");
    }
    let grant = TokenGrant {
        name: name.to_string(),
        upstreams: upstreams.to_vec(),
        models: models.to_vec(),
        ceiling_usd_micros,
        ceiling_calls,
        window: parse_window(window)?,
        mcp_agent: mcp_agent.to_string(),
        mcp_servers: mcp_servers.to_vec(),
    };
    let (token, value) = issue_recorded(&config().data_dir, &grant)?;
    println!(
        "  Issued token {} ({}): {}",
        token.name,
        token.id,
        describe(&token)
    );
    println!();
    println!("  {value}");
    println!();
    println!("  This is the only time it is shown. A client sends it as its API key.");
    Ok(())
}

pub fn token_revoke(id_or_name: &str) -> Result<()> {
    require_terminal("token revoke")?;
    match revoke_recorded(&config().data_dir, id_or_name)? {
        Some(token) => println!("  Revoked token {} ({}).", token.name, token.id),
        None => bail!("no live token has the id or name {id_or_name}"),
    }
    Ok(())
}

/// Destroy the key of each archived body in `hashes` in `data_dir`,
/// then record each. The objects stay in the bucket for their
/// retention period and can no longer be read. `session` is the proxy
/// session the bodies are redacted as, when they are redacted
/// together. Returns how many keys were destroyed.
pub(crate) fn redact_recorded(
    data_dir: &std::path::Path,
    hashes: &[String],
    reason: &str,
    session: Option<&str>,
) -> Result<usize> {
    use wirken_audit::SessionLog as _;
    let keys = super::proxy_archive::KeyStore::open(
        &data_dir.join(super::proxy_archive::ARCHIVE_KEYS_FILE),
    )
    .map_err(|e| anyhow::anyhow!("the archive key store: {e}"))?;
    let log = super::open_signed_session_log(&config())?;
    let handle = log.handle_for(wirken_audit::SessionId::new(
        wirken_audit::PROXY_SESSION.to_string(),
    ));
    let mut destroyed = 0;
    for sha256 in hashes {
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{sha256:?} is not a SHA-256 hash: 64 hex characters, as on the row");
        }
        let sha256 = sha256.to_ascii_lowercase();
        // The key first, the row after: the row says what was done.
        destroyed += keys
            .destroy(&sha256)
            .map_err(|e| anyhow::anyhow!("the key of {sha256} was not destroyed: {e}"))?;
        log.append(
            &handle,
            wirken_audit::TrustLevel::User,
            wirken_audit::SessionEvent::ProxyArchiveRedacted {
                sha256: wirken_audit::HashHex(sha256.clone()),
                operator: super::local_operator(),
                reason: reason.to_string(),
                session: session.map(str::to_string),
            },
        )
        .with_context(|| {
            format!("the key of {sha256} is destroyed, but its row could not be written")
        })?;
    }
    super::seal_operator_lane(&log, wirken_audit::PROXY_SESSION);
    Ok(destroyed)
}

/// The hash of every archived body of the proxy session `lane`.
fn session_hashes(lane: &str) -> Result<Vec<String>> {
    use wirken_audit::SessionLog as _;
    if !super::proxy_archive::is_proxy_session(lane) {
        bail!("{lane:?} is not a proxy session; `wirken proxy sessions` lists them");
    }
    let log = wirken_audit::SqliteSessionLog::open(&config().audit_db_path())
        .context("Failed to open session log")?;
    let handle = log.handle_for(wirken_audit::SessionId::new(lane.to_string()));
    let rows = log
        .get_since(&handle, 0)
        .context("session log query failed")?;
    if rows.is_empty() {
        bail!("no events for session '{lane}'");
    }
    Ok(super::proxy_archive::archived_hashes(&rows))
}

/// What a row holds in place of content a redaction removed.
const REDACTED: &str = "[redacted]";

/// The row that replaces `event` when its session is redacted, for a
/// row that holds what a client's tool call said: the call's arguments,
/// or the tool's output. The call's id, tool and outcome stay. `None`
/// for a row that holds no such content.
fn redacted_row(event: &wirken_audit::SessionEvent) -> Option<wirken_audit::SessionEvent> {
    use wirken_audit::SessionEvent;
    let mut value = serde_json::to_value(event).ok()?;
    match event {
        SessionEvent::AssistantToolCalls { .. } => {
            for call in value["calls"].as_array_mut()? {
                call["arguments"] =
                    serde_json::json!(serde_json::json!({ "redacted": true }).to_string());
            }
            for key in ["text", "reasoning"] {
                if let Some(map) = value.as_object_mut() {
                    map.remove(key);
                }
            }
        }
        SessionEvent::ToolResult { .. } => {
            value["output"] = serde_json::json!(REDACTED);
        }
        _ => return None,
    }
    serde_json::from_value(value).ok()
}

/// Rewrite every row of the proxy session `lane` that holds a tool
/// call's arguments or output, each through the session log's redaction:
/// the row's content is replaced, the chain is resealed over it, and a
/// signed head records the row, the hash it had, the operator and the
/// reason. A row a redaction already rewrote is left as it is. Returns
/// how many rows were rewritten.
pub(crate) fn redact_rows(lane: &str, reason: &str) -> Result<usize> {
    use wirken_audit::SessionLog as _;
    let log = super::open_signed_session_log(&config())?;
    let handle = log.handle_for(wirken_audit::SessionId::new(lane.to_string()));
    let rows = log
        .get_since(&handle, 0)
        .context("session log query failed")?;
    let done = wirken_audit::search::rewritten(&rows);
    let operator = super::local_operator();
    let mut rewritten = 0;
    for row in &rows {
        if done.contains(&row.seq) {
            continue;
        }
        let Some(replacement) = redacted_row(&row.event) else {
            continue;
        };
        log.redact(&handle, row.seq, &replacement, &operator, reason)
            .with_context(|| format!("row {} of {lane} was not rewritten", row.seq))?;
        rewritten += 1;
    }
    Ok(rewritten)
}

pub fn archive_redact(sha256: Option<&str>, session: Option<&str>, reason: &str) -> Result<()> {
    require_terminal("archive redact")?;
    let data_dir = config().data_dir;
    match (sha256, session) {
        (Some(sha256), None) => {
            let destroyed = redact_recorded(&data_dir, &[sha256.to_string()], reason, None)?;
            if destroyed == 0 {
                println!(
                    "  No key was held for {sha256}. It is marked: a body with this hash is \
                     not archived readable from here on."
                );
            } else {
                println!(
                    "  Destroyed {destroyed} key{} for {sha256}. The object stays in the bucket \
                     until its retention ends and can no longer be read.",
                    if destroyed == 1 { "" } else { "s" }
                );
            }
        }
        (None, Some(lane)) => {
            let hashes = session_hashes(lane)?;
            if hashes.is_empty() {
                println!("  Session {lane} has no archived bodies.");
            } else {
                let destroyed = redact_recorded(&data_dir, &hashes, reason, Some(lane))?;
                println!(
                    "  Session {lane}: {} archived bodies, {destroyed} key{} destroyed. The \
                     objects stay in the bucket until their retention ends and can no longer \
                     be read.",
                    hashes.len(),
                    if destroyed == 1 { "" } else { "s" }
                );
            }
            // The rows of a client's tool calls hold what the bodies
            // held. They go with the session.
            let rows = redact_rows(lane, reason)?;
            if rows > 0 {
                println!(
                    "  Session {lane}: {rows} row{} of tool calls rewritten. Each is recorded \
                     on the session's chain with the hash it had.",
                    if rows == 1 { "" } else { "s" }
                );
            }
        }
        _ => bail!("give one body's SHA-256, or --session with a proxy session"),
    }
    Ok(())
}

/// List the proxy sessions: one line for each conversation, with its
/// token, when it started, its calls and its model. `token` is an id
/// or a name to list one token's sessions.
/// What a lane holds, for the session listing: its model calls and the
/// model they asked for, and its tool calls. `None` for a lane that is
/// not a session, such as a token's lane of refusals.
fn session_summary(rows: &[wirken_audit::StoredSessionEvent]) -> Option<String> {
    use wirken_audit::SessionEvent;
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let models: Vec<&str> = rows
        .iter()
        .filter_map(|r| match &r.event {
            SessionEvent::ProxyRequest { model, .. } => Some(model.as_str()),
            _ => None,
        })
        .collect();
    let opened = rows
        .iter()
        .any(|r| matches!(r.event, SessionEvent::ProxyToolsListed { .. }));
    let tools = rows
        .iter()
        .filter(|r| matches!(r.event, SessionEvent::ProxyToolCall { .. }))
        .count();
    let mut parts = Vec::new();
    if let Some(model) = models.first() {
        parts.push(format!(
            "{} call{}  {model}",
            models.len(),
            plural(models.len())
        ));
    }
    if opened {
        parts.push(format!("{tools} tool call{}", plural(tools)));
    }
    (!parts.is_empty()).then(|| parts.join("  "))
}

pub fn sessions(token: Option<&str>) -> Result<()> {
    use wirken_audit::SessionLog as _;
    use wirken_time::TimestampExt as _;
    let cfg = config();
    let tokens = open_store(&cfg.data_dir)?
        .list()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let wanted = match token {
        Some(t) => Some(
            tokens
                .iter()
                .find(|k| k.id == t || k.name == t)
                .map(|k| k.id.clone())
                .ok_or_else(|| anyhow::anyhow!("no token has the id or name {t}"))?,
        ),
        None => None,
    };
    let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
        .context("Failed to open session log")?;
    let mut listed = 0;
    for lane in log.list_session_ids().context("session log query failed")? {
        // `proxy-<token id>-<label>`: a conversation's lane.
        let Some((token_id, _)) = lane
            .strip_prefix("proxy-")
            .and_then(|rest| rest.split_once('-'))
        else {
            continue;
        };
        if wanted.as_deref().is_some_and(|w| w != token_id) {
            continue;
        }
        let handle = log.handle_for(wirken_audit::SessionId::new(lane.clone()));
        let rows = log
            .get_since(&handle, 0)
            .context("session log query failed")?;
        let Some(what) = session_summary(&rows) else {
            continue;
        };
        let name = tokens
            .iter()
            .find(|k| k.id == token_id)
            .map_or("?", |k| k.name.as_str());
        println!("  {lane}  {name}  {}  {what}", rows[0].ts.to_rfc3339_z());
        listed += 1;
    }
    if listed == 0 {
        println!("  No proxy sessions.");
    }
    Ok(())
}

pub fn token_list() -> Result<()> {
    let tokens = open_store(&config().data_dir)?
        .list()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if tokens.is_empty() {
        println!("  No proxy tokens. Issue one with `wirken proxy token issue`.");
        return Ok(());
    }
    for token in tokens {
        let state = match &token.revoked_at {
            Some(at) => format!("revoked {at}"),
            None => format!("issued {}", token.created_at),
        };
        println!(
            "  {}  {}  {}  ({state})",
            token.id,
            token.name,
            describe(&token)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_described_by_what_it_allows() {
        let token = ProxyToken {
            id: "0a1b2c3d".into(),
            name: "laptop".into(),
            upstreams: vec!["local".into(), "cloud".into()],
            models: vec![],
            ceiling_usd_micros: Some(2_500_000),
            ceiling_calls: Some(100),
            window: BudgetWindow::Day,
            created_at: String::new(),
            revoked_at: None,
            mcp_agent: "default".into(),
            mcp_servers: vec!["files".into()],
        };
        assert_eq!(
            describe(&token),
            "upstreams local,cloud; any model; MCP servers files of agent default; \
             $2.50 a day; 100 calls a day"
        );
    }

    #[test]
    fn a_token_is_granted_signed_mcp_servers_only() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("mcp.json"),
            r#"{"servers":{"files":{"command":"files-server","args":[]}}}"#,
        )
        .unwrap();
        let config = wirken_mcp_proxy::McpConfig::load(&tmp.path().join("mcp.json")).unwrap();
        assert!(config.servers.contains_key("files"), "the entry is read");
        assert!(
            signed_mcp_servers(tmp.path(), "default")
                .unwrap()
                .is_empty()
        );
        let grant = TokenGrant {
            name: "tools".into(),
            mcp_agent: "default".into(),
            mcp_servers: vec!["files".into()],
            ..Default::default()
        };
        let err = issue_recorded(tmp.path(), &grant).unwrap_err().to_string();
        assert!(err.contains("no signed MCP server named files"), "{err}");
        assert!(open_store(tmp.path()).unwrap().list().unwrap().is_empty());
    }

    /// A lane of tool calls alone is a session in the listing, and a
    /// lane with both names both.
    #[test]
    fn a_session_is_listed_by_its_model_calls_and_its_tool_calls() {
        use wirken_audit::{HashHex, SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let tmp = tempfile::tempdir().unwrap();
        let log = SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap();
        let hash = || HashHex("0".repeat(64));
        let listed = SessionEvent::ProxyToolsListed {
            token_id: "t".into(),
            agent_id: "default".into(),
            mcp_session: "s".into(),
            servers: vec![],
            tools: vec![],
            tools_sha256: hash(),
            archived: false,
        };
        let tool_call = SessionEvent::ProxyToolCall {
            call_id: "c".into(),
            token_id: "t".into(),
            agent_id: "default".into(),
            mcp_session: "s".into(),
            tool: "mcp_files_read".into(),
            success: true,
            latency_ms: 1,
            request_sha256: hash(),
            request_bytes: 1,
            response_sha256: hash(),
            response_bytes: 1,
            archived: false,
        };
        let request = SessionEvent::ProxyRequest {
            request_id: "r".into(),
            token_id: "t".into(),
            token_name: "laptop".into(),
            upstream: "local".into(),
            provider: "ollama".into(),
            model: "m1".into(),
            shape: wirken_audit::ProxyShape::OpenaiChat,
            stream: false,
            request_sha256: hash(),
            request_bytes: 1,
            credential_id: None,
            archived: false,
        };
        let refused = SessionEvent::ProxyRefused {
            token_id: Some("t".into()),
            shape: None,
            model: None,
            reason: wirken_audit::ProxyRefusal::Malformed,
        };
        let summary = |lane: &str, events: Vec<SessionEvent>| {
            let handle = log.handle_for(SessionId::new(lane.to_string()));
            for event in events {
                log.append(&handle, wirken_audit::TrustLevel::System, event)
                    .unwrap();
            }
            session_summary(&log.get_since(&handle, 0).unwrap())
        };
        assert_eq!(
            summary("proxy-t-m1", vec![listed.clone(), tool_call.clone()]).as_deref(),
            Some("1 tool call")
        );
        assert_eq!(
            summary(
                "proxy-t-work",
                vec![listed, request.clone(), tool_call.clone(), tool_call]
            )
            .as_deref(),
            Some("1 call  m1  2 tool calls")
        );
        assert_eq!(
            summary("proxy-t-c1", vec![request]).as_deref(),
            Some("1 call  m1")
        );
        assert_eq!(summary("proxy-t-x", vec![refused]), None);
    }

    #[test]
    fn a_window_is_hour_day_or_week() {
        assert_eq!(parse_window("hour").unwrap(), BudgetWindow::Hour);
        assert_eq!(parse_window("week").unwrap(), BudgetWindow::Week);
        assert!(parse_window("month").is_err());
    }
}
