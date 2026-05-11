use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;

use wirken_audit::{AuditLog, AuditQuery, VerifyResult};

use super::config;

/// JSON schema version for `wirken audit` output.
///
/// Bump when the output shape changes in a way that breaks
/// existing consumers; the doc page (`docs/audit-cli.md`)
/// describes what's stable per version.
///
/// v2 adds chain-head signature reporting on `verify --format json`:
/// the `signed_heads_count`, `unsigned_heads_count`,
/// `invalid_signatures_count`, `signing_key_ids_seen`,
/// `sessions_with_no_signed_heads`, and `unsigned_tail_max_len`
/// fields, plus two new `result` values: `signature_invalid` and
/// `missing_chain_head`. Existing v1 fields stay where they were.
const SCHEMA_VERSION: u32 = 2;

const WIRKEN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Decomposed view of a session id, structured so consumers can
/// filter on agent/channel without re-parsing the slash-delimited
/// string. `full` is always present and is the round-trippable form;
/// `agent`/`channel`/`id` are convenience fields and may be absent
/// for non-canonical session ids (system sentinel sessions etc.).
#[derive(Debug, Serialize)]
struct SessionView {
    full: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl SessionView {
    fn from_session_string(s: &str) -> Self {
        let mut parts = s.splitn(3, '/');
        let agent = parts.next();
        let channel = parts.next();
        let id = parts.next();
        match (agent, channel, id) {
            (Some(a), Some(c), Some(i)) if !a.is_empty() && !c.is_empty() && !i.is_empty() => {
                Self {
                    full: s.to_string(),
                    agent: Some(a.to_string()),
                    channel: Some(c.to_string()),
                    id: Some(i.to_string()),
                }
            }
            _ => Self {
                full: s.to_string(),
                agent: None,
                channel: None,
                id: None,
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn log(
    action: Option<String>,
    channel: Option<String>,
    actor: Option<String>,
    session: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: usize,
    format: &str,
) -> Result<()> {
    let cfg = config();
    let audit = AuditLog::open(&cfg.audit_db_path()).context("Failed to open audit log")?;

    let since_dt = since
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .context("--since must be an RFC 3339 timestamp")?;
    let until_dt = until
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .context("--until must be an RFC 3339 timestamp")?;

    let query = AuditQuery {
        action,
        channel,
        actor,
        session: session.clone(),
        since: since_dt,
        until: until_dt,
        limit: Some(limit),
    };

    let events = audit.query(&query).context("Failed to query audit log")?;

    match format {
        "json" => print_log_json(&events, session.as_deref()),
        "human" | "" => print_log_human(&events, session.as_deref()),
        other => anyhow::bail!("--format must be 'human' or 'json', got '{other}'"),
    }
}

pub async fn verify_attestations() -> Result<()> {
    let cfg = config();
    let audit = AuditLog::open(&cfg.audit_db_path()).context("Failed to open audit log")?;
    let session_log = audit.session_log();
    let session_ids = audit.list_session_ids()?;
    let result =
        wirken_agent::attestation::verify_recent_attestations(session_log.as_ref(), &session_ids)
            .map_err(|e| anyhow::anyhow!("attestation verification: {e}"))?;
    use wirken_agent::attestation::RecentAttestationResult;
    match result {
        RecentAttestationResult::Ok {
            sessions_checked,
            attestations_verified,
        } => {
            println!("  Attestation verification: OK");
            println!(
                "  {sessions_checked} sessions with attestations checked, \
                 {attestations_verified} signatures verified."
            );
            println!(
                "  Note: this verifies internal consistency only. The signer key \
                 carried on each attestation is the agent's own identity key; an \
                 operator-pinned trust anchor is not yet wired up."
            );
        }
        RecentAttestationResult::ChainBroken {
            session_id,
            seq,
            reason,
        } => {
            println!("  Attestation verification: SESSION CHAIN BROKEN");
            println!("  Session: {session_id}");
            println!("  Seq: {seq}");
            println!("  Reason: {reason}");
            std::process::exit(1);
        }
        RecentAttestationResult::Broken {
            session_id,
            attestation_seq,
            attestations_verified_before,
            reason,
        } => {
            println!("  Attestation verification: BROKEN");
            println!("  Session: {session_id}");
            println!("  Attestation seq: {attestation_seq}");
            println!("  Verified before break: {attestations_verified_before}");
            println!("  Reason: {reason}");
            std::process::exit(1);
        }
    }
    Ok(())
}

pub async fn verify(format: &str, require_signed: bool) -> Result<()> {
    let cfg = config();
    let audit = AuditLog::open(&cfg.audit_db_path()).context("Failed to open audit log")?;
    let result = if require_signed {
        audit.verify_require_signed()?
    } else {
        audit.verify()?
    };

    match format {
        "json" => print_verify_json(&result, require_signed),
        "human" | "" => print_verify_human(&result, require_signed),
        other => anyhow::bail!("--format must be 'human' or 'json', got '{other}'"),
    }
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

fn print_log_human(
    events: &[wirken_audit::StoredEvent],
    session_filter: Option<&str>,
) -> Result<()> {
    if let Some(s) = session_filter {
        let view = SessionView::from_session_string(s);
        println!("  Session: {}", view.full);
        if let (Some(a), Some(c), Some(i)) = (&view.agent, &view.channel, &view.id) {
            println!("    Agent:   {a}");
            println!("    Channel: {c}");
            println!("    ID:      {i}");
        }
        println!();
    }

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

    for event in events {
        println!(
            "  {:>6}  {:20}  {:16}  {:20}  {}",
            event.id,
            event.event.ts.format("%Y-%m-%d %H:%M:%S"),
            truncate(&event.event.actor_id, 16),
            truncate(&event.event.action, 20),
            truncate(&event.event.target, 40),
        );
    }
    println!();
    println!("  {} events shown.", events.len());
    Ok(())
}

fn print_verify_human(result: &VerifyResult, require_signed: bool) -> Result<()> {
    match result {
        VerifyResult::Ok {
            rows_verified,
            sessions_total,
            signed_heads_count,
            unsigned_heads_count: _,
            invalid_signatures_count: _,
            sessions_with_no_signed_heads,
            signing_key_ids_seen,
            unsigned_tail_max_len,
        } => {
            println!("  Audit log integrity: OK");
            println!(
                "  {rows_verified} rows verified across {sessions_total} sessions, hash chain intact."
            );
            println!("  Chain-head signatures: {signed_heads_count} verified.");
            if !signing_key_ids_seen.is_empty() {
                println!(
                    "  Signing key ids seen: {}",
                    signing_key_ids_seen.join(", ")
                );
            }
            if *sessions_with_no_signed_heads > 0 {
                if require_signed {
                    // Cannot reach here under require_signed; that
                    // path returns MissingChainHead. Belt-and-braces.
                    println!(
                        "  WARN: {sessions_with_no_signed_heads} sessions have no signed ChainHead rows."
                    );
                } else {
                    println!(
                        "  Transition-era sessions (no signed heads): {sessions_with_no_signed_heads}. \
                         Pass --require-signed to fail on these."
                    );
                }
            }
            if *unsigned_tail_max_len > 0 {
                println!("  Unsigned tail (max events past last head): {unsigned_tail_max_len}.");
            }
        }
        VerifyResult::Broken {
            session_id,
            seq,
            expected_hash,
            actual_hash,
            verified_count,
        } => {
            println!("  Audit log integrity: BROKEN");
            println!("  Session: {session_id}");
            println!("  Hash chain broken at seq {seq}.");
            println!("  Expected hash: {expected_hash}");
            println!("  Actual hash:   {actual_hash}");
            println!(
                "  {verified_count} events verified before the break; events at and after seq {seq} in this session should not be relied on."
            );
            println!();
            println!("  The audit log has been tampered with.");
            std::process::exit(1);
        }
        VerifyResult::SignatureInvalid {
            session_id,
            seq,
            signing_key_id,
            reason,
            verified_count,
            invalid_signatures_count: _,
        } => {
            println!("  Audit log integrity: SIGNATURE INVALID");
            println!("  Session: {session_id}");
            println!("  Offending ChainHead seq: {seq}");
            println!("  Signing key id: {signing_key_id}");
            println!("  Reason: {reason}");
            println!(
                "  {verified_count} events verified across earlier sessions before the invalid signature."
            );
            println!();
            println!("  The chain head signature does not anchor the recorded chain.");
            std::process::exit(1);
        }
        VerifyResult::MissingChainHead {
            session_id,
            rows,
            verified_count,
        } => {
            println!("  Audit log integrity: MISSING CHAIN HEAD");
            println!("  Session: {session_id}");
            println!("  Rows in session: {rows}");
            println!("  {verified_count} events verified across earlier sessions before this gap.");
            println!();
            println!("  --require-signed is set and this session has no signed ChainHead rows.");
            std::process::exit(1);
        }
        VerifyResult::Empty => {
            println!("  Audit log is empty.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn print_log_json(
    events: &[wirken_audit::StoredEvent],
    _session_filter: Option<&str>,
) -> Result<()> {
    let json_events: Vec<_> = events
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "ts": e.event.ts.to_rfc3339(),
                "actor_kind": match e.event.actor_kind {
                    wirken_audit::ActorKind::User => "user",
                    wirken_audit::ActorKind::Agent => "agent",
                    wirken_audit::ActorKind::Service => "service",
                },
                "actor_id": e.event.actor_id,
                "action": e.event.action,
                "target": e.event.target,
                "channel": e.event.channel,
                "session": SessionView::from_session_string(e.event.session.as_deref().unwrap_or("")),
                "detail": e.event.detail,
                "hash": e.hash,
            })
        })
        .collect();

    let body = json!({
        "schema_version": SCHEMA_VERSION,
        "wirken_version": WIRKEN_VERSION,
        "events": json_events,
    });

    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

fn print_verify_json(result: &VerifyResult, require_signed: bool) -> Result<()> {
    let body = match result {
        VerifyResult::Ok {
            rows_verified,
            sessions_total,
            signed_heads_count,
            unsigned_heads_count,
            invalid_signatures_count,
            sessions_with_no_signed_heads,
            signing_key_ids_seen,
            unsigned_tail_max_len,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "wirken_version": WIRKEN_VERSION,
            "result": "ok",
            "rows_verified": rows_verified,
            "sessions_total": sessions_total,
            "signed_heads_count": signed_heads_count,
            "unsigned_heads_count": unsigned_heads_count,
            "invalid_signatures_count": invalid_signatures_count,
            "sessions_with_no_signed_heads": sessions_with_no_signed_heads,
            "signing_key_ids_seen": signing_key_ids_seen,
            "unsigned_tail_max_len": unsigned_tail_max_len,
            "require_signed": require_signed,
        }),
        VerifyResult::Empty => json!({
            "schema_version": SCHEMA_VERSION,
            "wirken_version": WIRKEN_VERSION,
            "result": "empty",
            "require_signed": require_signed,
        }),
        VerifyResult::Broken {
            session_id,
            seq,
            expected_hash,
            actual_hash,
            verified_count,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "wirken_version": WIRKEN_VERSION,
            "result": "broken",
            "session": SessionView::from_session_string(session_id.as_str()),
            "seq": seq,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "verified_count": verified_count,
            "require_signed": require_signed,
        }),
        VerifyResult::SignatureInvalid {
            session_id,
            seq,
            signing_key_id,
            reason,
            verified_count,
            invalid_signatures_count,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "wirken_version": WIRKEN_VERSION,
            "result": "signature_invalid",
            "session": SessionView::from_session_string(session_id.as_str()),
            "seq": seq,
            "signing_key_id": signing_key_id,
            "reason": reason,
            "verified_count": verified_count,
            "invalid_signatures_count": invalid_signatures_count,
            "require_signed": require_signed,
        }),
        VerifyResult::MissingChainHead {
            session_id,
            rows,
            verified_count,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "wirken_version": WIRKEN_VERSION,
            "result": "missing_chain_head",
            "session": SessionView::from_session_string(session_id.as_str()),
            "rows": rows,
            "verified_count": verified_count,
            "require_signed": require_signed,
        }),
    };
    println!("{}", serde_json::to_string_pretty(&body)?);
    if matches!(
        result,
        VerifyResult::Broken { .. }
            | VerifyResult::SignatureInvalid { .. }
            | VerifyResult::MissingChainHead { .. }
    ) {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("not an RFC 3339 timestamp: '{s}'"))?;
    Ok(dt.with_timezone(&chrono::Utc))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_view_decomposes_canonical_form() {
        let v = SessionView::from_session_string("assistant/webchat/abc123");
        assert_eq!(v.full, "assistant/webchat/abc123");
        assert_eq!(v.agent.as_deref(), Some("assistant"));
        assert_eq!(v.channel.as_deref(), Some("webchat"));
        assert_eq!(v.id.as_deref(), Some("abc123"));
    }

    #[test]
    fn session_view_keeps_full_for_non_canonical() {
        let v = SessionView::from_session_string("dryrun");
        assert_eq!(v.full, "dryrun");
        assert!(v.agent.is_none());
        assert!(v.channel.is_none());
        assert!(v.id.is_none());
    }

    #[test]
    fn session_view_keeps_full_for_two_part_id() {
        let v = SessionView::from_session_string("agent/channel");
        assert_eq!(v.full, "agent/channel");
        assert!(
            v.agent.is_none(),
            "two-part id should not partially decompose"
        );
        assert!(v.channel.is_none());
        assert!(v.id.is_none());
    }

    #[test]
    fn session_view_serializes_decomposed_when_present() {
        let v = SessionView::from_session_string("assistant/webchat/abc");
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["full"], "assistant/webchat/abc");
        assert_eq!(json["agent"], "assistant");
        assert_eq!(json["channel"], "webchat");
        assert_eq!(json["id"], "abc");
    }

    #[test]
    fn session_view_omits_decomposed_when_absent() {
        let v = SessionView::from_session_string("dryrun");
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["full"], "dryrun");
        assert!(json.get("agent").is_none());
        assert!(json.get("channel").is_none());
        assert!(json.get("id").is_none());
    }
}
