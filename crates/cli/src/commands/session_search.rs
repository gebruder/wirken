//! `wirken sessions search`: find text across sessions.
//!
//! Reads the session log, and with an archive configured the proxied
//! bodies the log names. Retrieval only: a row or a body holds the text
//! or it does not, and each hit names the row it came from, so the
//! session can be checked with `wirken sessions verify`.
//!
//! An operator command. It is refused inside a Wirken `exec`, where it
//! would hand an agent every session there is.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use wirken_audit::search::{Filter, Needle, rewritten, row_text};
use wirken_audit::{ProxyShape, SessionEvent, SessionLog as _, StoredSessionEvent};
use wirken_time::TimestampExt as _;

use super::config;
use super::proxy_archive::{Archive, named};
use super::proxy_server::BodyKind;

/// What `sessions search` was asked.
pub struct Args<'a> {
    pub text: &'a str,
    pub agent: Option<&'a str>,
    pub token: Option<&'a str>,
    pub channel: Option<&'a str>,
    pub tool: Option<&'a str>,
    pub session: Option<&'a str>,
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    pub limit: usize,
    pub json: bool,
    pub skip_archive: bool,
}

/// One match, and where on the chain it is.
#[derive(Debug, Serialize)]
pub struct Hit {
    pub session: String,
    /// The row's sequence number in its session.
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    /// The chain hash of the row: its position on the session's chain.
    pub chain_hash: String,
    /// `row` for text the row holds; `request_body` or `response_body`
    /// for text in an archived body the row names.
    pub found_in: &'static str,
    /// The hash of the body, for a match in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    pub snippet: String,
}

/// What a search read, and what it found.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub query: String,
    pub hits: Vec<Hit>,
    /// Whether more matched than `hits` holds.
    pub truncated: bool,
    pub sessions_searched: usize,
    pub rows_searched: usize,
    /// `configured`, `not_configured` or `skipped`.
    pub archive: &'static str,
    pub bodies_searched: usize,
    /// Archived bodies that could not be read: fetched and failed, or
    /// with no key in this data directory. Redacted bodies are not
    /// among them.
    pub bodies_unavailable: usize,
}

fn hit(
    row: &StoredSessionEvent,
    found_in: &'static str,
    body: Option<&str>,
    snippet: String,
) -> Hit {
    Hit {
        session: row.session_id.as_str().to_string(),
        seq: row.seq,
        ts: row.ts.to_rfc3339_z(),
        kind: serde_json::to_value(&row.event)
            .ok()
            .and_then(|v| v["kind"].as_str().map(str::to_string))
            .unwrap_or_default(),
        chain_hash: row.hash.0.clone(),
        found_in,
        body_sha256: body.map(str::to_string),
        snippet,
    }
}

/// The shape of the model call each response row answers, by request
/// id, so a streamed answer is read in its provider's format.
fn shapes(rows: &[StoredSessionEvent]) -> std::collections::HashMap<&str, ProxyShape> {
    rows.iter()
        .filter_map(|row| match &row.event {
            SessionEvent::ProxyRequest {
                request_id, shape, ..
            } => Some((request_id.as_str(), *shape)),
            _ => None,
        })
        .collect()
}

/// Search the rows of one session, and with `archive` the bodies they
/// name. Returns whether the limit was reached.
async fn search_session(
    rows: &[StoredSessionEvent],
    needle: &Needle,
    filter: &Filter,
    archive: Option<&Archive>,
    limit: usize,
    report: &mut Report,
) -> bool {
    let gone = rewritten(rows);
    let shapes = shapes(rows);
    report.sessions_searched += 1;
    for row in rows {
        // A row a redaction rewrote has nothing to find.
        if gone.contains(&row.seq) || !filter.admits(row) {
            continue;
        }
        if let Some(text) = row_text(&row.event) {
            report.rows_searched += 1;
            if let Some(snippet) = needle.find(&text) {
                if report.hits.len() >= limit {
                    report.truncated = true;
                    return true;
                }
                report.hits.push(hit(row, "row", None, snippet));
            }
        }
        let Some(archive) = archive else { continue };
        let shape = match &row.event {
            SessionEvent::ProxyRequest { shape, .. } => Some(*shape),
            SessionEvent::ProxyResponse { request_id, .. } => {
                shapes.get(request_id.as_str()).copied()
            }
            _ => None,
        };
        for body in named(std::slice::from_ref(row)) {
            let text = match archive.search_text(body.kind, &body.sha256, shape).await {
                Ok(Some(text)) => text,
                // Redacted, or never readable here.
                Ok(None) => {
                    if !archive.redacted(body.kind, &body.sha256) {
                        report.bodies_unavailable += 1;
                    }
                    continue;
                }
                Err(e) => {
                    tracing::warn!("search: {} {}: {e}", body.kind.as_str(), body.sha256);
                    report.bodies_unavailable += 1;
                    continue;
                }
            };
            report.bodies_searched += 1;
            if let Some(snippet) = needle.find(&text) {
                if report.hits.len() >= limit {
                    report.truncated = true;
                    return true;
                }
                let found_in = match body.kind {
                    BodyKind::Request => "request_body",
                    BodyKind::Response => "response_body",
                };
                report
                    .hits
                    .push(hit(row, found_in, Some(&body.sha256), snippet));
            }
        }
    }
    false
}

fn print_text(report: &Report) {
    println!();
    for hit in &report.hits {
        println!(
            "  {}  seq {}  {}  {}",
            hit.session, hit.seq, hit.ts, hit.kind
        );
        match &hit.body_sha256 {
            Some(sha) => println!("    in the {} {sha}", hit.found_in.replace('_', " ")),
            None => println!("    in the row"),
        }
        println!("    chain {}", hit.chain_hash);
        println!("    {}", hit.snippet);
        println!();
    }
    let more = if report.truncated {
        " (more matched; raise --limit)"
    } else {
        ""
    };
    println!(
        "  {} hit{}{more} in {} rows of {} sessions",
        report.hits.len(),
        if report.hits.len() == 1 { "" } else { "s" },
        report.rows_searched,
        report.sessions_searched,
    );
    match report.archive {
        "configured" => println!(
            "  archive: {} bodies searched, {} not readable",
            report.bodies_searched, report.bodies_unavailable
        ),
        "skipped" => println!("  archive: skipped (--skip-archive); bodies not searched"),
        _ => println!("  archive: not configured; bodies not searched"),
    }
    if !report.hits.is_empty() {
        println!("  Check a hit's session with `wirken sessions verify <session>`.");
    }
}

pub async fn search(args: Args<'_>) -> Result<()> {
    let cfg = config();
    let Some(needle) = Needle::new(args.text) else {
        bail!("nothing to search for");
    };
    let parse = |flag: &str, value: Option<&str>| -> Result<Option<wirken_time::Timestamp>> {
        value
            .map(|v| {
                wirken_time::parse_rfc3339(v)
                    .with_context(|| format!("{flag} must be an RFC 3339 timestamp: '{v}'"))
            })
            .transpose()
    };
    // A token is named by its id or its name; rows carry the id.
    let token = match args.token {
        Some(given) => {
            let known = super::proxy::open_store(&cfg.data_dir)
                .and_then(|store| store.list().map_err(|e| anyhow::anyhow!("{e}")))
                .unwrap_or_default();
            Some(
                known
                    .iter()
                    .find(|t| t.id == given || t.name == given)
                    .map(|t| t.id.clone())
                    .ok_or_else(|| anyhow::anyhow!("no token has the id or name {given}"))?,
            )
        }
        None => None,
    };
    let filter = Filter {
        agent: args.agent.map(str::to_string),
        token,
        channel: args.channel.map(str::to_string),
        tool: args.tool.map(str::to_string),
        since: parse("--since", args.since)?,
        until: parse("--until", args.until)?,
    };

    let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
        .context("Failed to open session log")?;
    let mut sessions = log.list_session_ids().context("session log query failed")?;
    if let Some(only) = args.session {
        sessions.retain(|id| id == only);
    }
    sessions.sort();

    let archive_config = wirken_gateway::proxy::ProxyConfig::load(&cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .and_then(|c| c.archive);
    let mut report = Report {
        query: args.text.to_string(),
        archive: match (&archive_config, args.skip_archive) {
            (None, _) => "not_configured",
            (Some(_), true) => "skipped",
            (Some(_), false) => "configured",
        },
        ..Default::default()
    };
    let archive = match archive_config.filter(|_| !args.skip_archive) {
        Some(archive_config) => {
            let passphrase = super::cached_vault_passphrase()?;
            let keychain = wirken_vault::probe_keychain(&cfg.data_dir, move || passphrase);
            let vault =
                wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
                    .context("Failed to open credential store")?;
            Some(
                Archive::open(&archive_config, &vault, &cfg.data_dir)
                    .map_err(|e| anyhow::anyhow!("archive: {e}"))?,
            )
        }
        None => None,
    };

    for session in &sessions {
        let handle = log.handle_for(wirken_audit::SessionId::new(session.clone()));
        let rows = log
            .get_since(&handle, 0)
            .context("session log query failed")?;
        if search_session(
            &rows,
            &needle,
            &filter,
            archive.as_ref(),
            args.limit,
            &mut report,
        )
        .await
        {
            break;
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
    }
    Ok(())
}
