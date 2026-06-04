//! Tests for the typed-event SIEM forwarder. Covers:
//!
//! - D1: snapshot shape for each per-target builder against a fixed
//!   AssistantToolCalls / ToolResult / HttpFetch input.
//! - D2: polling worker end-to-end against a stub sink. Asserts
//!   seq-ordered delivery, retry-on-error semantics (cursor not
//!   advanced), and that the default exclude list suppresses
//!   AuditLegacy and PII variants.
//! - D3: legacy SiemConfig (no typed fields) is back-compat; the
//!   worker would not spawn against it under the gateway's
//!   `maybe_spawn_typed_siem` heuristic.
//! - D4: multi-target hybrid scenario where Sentinel uses
//!   parallel-pipe and the other targets use shared endpoints.
//!
//! Tests use a `StubSink` rather than a real HTTP server because
//! per-target wire shape is already covered by D1 snapshots; the
//! sink-level assertions are about *what* the worker hands to the
//! transport, not how the transport phrases an HTTPS POST.

use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use serde_json::Value;
use tempfile::TempDir;

use wirken_audit::{
    SentinelTypedEndpoint, SessionEvent, SessionId, SessionLog, SiemConfig, SiemTarget,
    SqliteSessionLog, ToolCallRecord, TrustLevel, TypedSink, build_datadog_typed_entry,
    build_datadog_typed_payload, build_sentinel_typed_payload, build_splunk_typed_body,
    build_webhook_typed_request, compute_webhook_signature, siem_typed,
};

fn base_config(target: SiemTarget) -> SiemConfig {
    SiemConfig {
        target,
        endpoint: "http://127.0.0.1:0/x".into(),
        api_key: "k".into(),
        service: "wirken".into(),
        environment: "test".into(),
        hmac_secret: None,
        sentinel_typed: None,
        typed_include_variants: None,
        typed_exclude_variants: None,
        typed_forwarding_enabled: None,
    }
}

fn fixture_tool_calls() -> SessionEvent {
    SessionEvent::AssistantToolCalls {
        calls: vec![ToolCallRecord {
            id: "c1".into(),
            name: "exec".into(),
            arguments: r#"{"command":"curl https://example.com"}"#.into(),
        }],
        agent_id: "default".into(),
        adapter_id: Some("slack".into()),
        sender_id: Some("U123".into()),
    }
}

fn fixture_tool_result() -> SessionEvent {
    SessionEvent::ToolResult {
        call_id: "c1".into(),
        tool_name: "exec".into(),
        output: "ok".into(),
        success: true,
        agent_id: "default".into(),
        adapter_id: Some("slack".into()),
        sender_id: Some("U123".into()),
    }
}

fn fixture_http_fetch() -> SessionEvent {
    SessionEvent::HttpFetch {
        source: "feed".into(),
        host: "example.com".into(),
        url: "https://example.com/x".into(),
        outcome: wirken_audit::HttpFetchOutcome::Success,
        http_status_code: None,
        bytes: 1234,
        run_id: Some("run-1".into()),
        expansion_id: None,
        agent_id: Some("default".into()),
        skill_name: Some("zirkel".into()),
    }
}

// ---------------------------------------------------------------------------
// D1: per-target builder snapshots
// ---------------------------------------------------------------------------

fn stored_at_seq(event: SessionEvent, seq: u64) -> wirken_audit::StoredSessionEvent {
    wirken_audit::StoredSessionEvent {
        id: seq as i64,
        session_id: SessionId::new("sess-1"),
        seq,
        ts: Utc.with_ymd_and_hms(2026, 5, 11, 12, 0, 0).unwrap(),
        trust: TrustLevel::System,
        event,
        leaf_hash: wirken_audit::HashHex("aa".repeat(32)),
        prev_hash: wirken_audit::HashHex("bb".repeat(32)),
        hash: wirken_audit::HashHex("cc".repeat(32)),
    }
}

#[test]
fn d1_datadog_typed_assistant_tool_calls_carries_identity() {
    let cfg = base_config(SiemTarget::Datadog);
    let stored = stored_at_seq(fixture_tool_calls(), 7);
    let entry = build_datadog_typed_entry(&stored, &cfg);
    assert_eq!(
        entry.get("ddsource").and_then(|x| x.as_str()),
        Some("wirken")
    );
    let wirken = entry.get("wirken").unwrap();
    assert_eq!(
        wirken.get("kind").and_then(|x| x.as_str()),
        Some("assistant_tool_calls")
    );
    assert_eq!(
        wirken.get("session_id").and_then(|x| x.as_str()),
        Some("sess-1")
    );
    assert_eq!(wirken.get("seq").and_then(|x| x.as_u64()), Some(7));
    // The typed payload nests the variant under `event`; the
    // identity fields are inside that.
    let nested = wirken.get("event").unwrap();
    assert_eq!(
        nested.get("adapter_id").and_then(|x| x.as_str()),
        Some("slack")
    );
    assert_eq!(
        nested.get("sender_id").and_then(|x| x.as_str()),
        Some("U123")
    );
}

#[test]
fn d1_datadog_typed_tool_result_and_http_fetch_carry_identity() {
    let cfg = base_config(SiemTarget::Datadog);
    let stored_tr = stored_at_seq(fixture_tool_result(), 8);
    let stored_hf = stored_at_seq(fixture_http_fetch(), 9);
    let payload = build_datadog_typed_payload(&[&stored_tr, &stored_hf], &cfg);
    assert_eq!(payload.len(), 2);
    let tr_nested = payload[0]
        .get("wirken")
        .and_then(|w| w.get("event"))
        .unwrap();
    assert_eq!(
        tr_nested.get("adapter_id").and_then(|x| x.as_str()),
        Some("slack")
    );
    let hf_nested = payload[1]
        .get("wirken")
        .and_then(|w| w.get("event"))
        .unwrap();
    assert_eq!(
        hf_nested.get("skill_name").and_then(|x| x.as_str()),
        Some("zirkel")
    );
}

#[test]
fn d1_splunk_typed_body_is_ndjson_with_session_sourcetype() {
    let stored_tc = stored_at_seq(fixture_tool_calls(), 1);
    let stored_tr = stored_at_seq(fixture_tool_result(), 2);
    let body = build_splunk_typed_body(&[&stored_tc, &stored_tr]);
    let lines: Vec<&str> = body.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            v.get("sourcetype").and_then(|x| x.as_str()),
            Some("wirken:session"),
            "session sourcetype distinct from legacy 'wirken:audit'"
        );
        let event = v.get("event").unwrap();
        assert!(event.get("kind").is_some());
        assert!(event.get("session_id").is_some());
    }
}

#[test]
fn d1_sentinel_typed_payload_uses_pascalcase_columns() {
    let stored_tc = stored_at_seq(fixture_tool_calls(), 1);
    let payload = build_sentinel_typed_payload(&[&stored_tc]);
    let entry = &payload[0];
    for key in [
        "TimeGenerated",
        "SessionId",
        "Seq",
        "Kind",
        "Trust",
        "AgentId",
        "AdapterId",
        "SenderId",
        "Event",
    ] {
        assert!(
            entry.get(key).is_some(),
            "missing required Sentinel column {key:?}"
        );
    }
    assert_eq!(
        entry.get("Kind").and_then(|x| x.as_str()),
        Some("assistant_tool_calls")
    );
    assert_eq!(
        entry.get("AdapterId").and_then(|x| x.as_str()),
        Some("slack")
    );
}

#[test]
fn d1_webhook_typed_signature_is_over_exact_body_bytes() {
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.hmac_secret = Some("super-secret".into());
    let stored = stored_at_seq(fixture_tool_calls(), 1);
    let (body, sig) = build_webhook_typed_request(&[&stored], &cfg).unwrap();
    let sig = sig.expect("hmac_secret set: signature must be present");
    let recomputed = compute_webhook_signature(b"super-secret", &body);
    assert_eq!(sig, recomputed);
}

#[test]
fn d1_webhook_typed_signature_absent_when_secret_unset() {
    let cfg = base_config(SiemTarget::Webhook);
    let stored = stored_at_seq(fixture_tool_calls(), 1);
    let (_body, sig) = build_webhook_typed_request(&[&stored], &cfg).unwrap();
    assert!(sig.is_none());
}

#[test]
fn d1_webhook_typed_signature_distinct_from_legacy_when_secret_shared() {
    // A shared secret signs the legacy and typed bodies separately
    // because the body bytes differ (the typed wrapper carries
    // `session_id` / `seq` / `kind` / `trust` fields that the
    // legacy AuditEvent wrapper does not have). Receivers must
    // verify per pipe.
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.hmac_secret = Some("shared".into());

    // Legacy body for a synthetic AuditEvent.
    let evt = wirken_audit::AuditEvent::new(
        wirken_audit::ActorKind::Service,
        "gateway",
        "gateway.start",
        "daemon",
    );
    let (legacy_body, legacy_sig) = wirken_audit::build_webhook_request(&[evt], &cfg).unwrap();
    let legacy_sig = legacy_sig.unwrap();

    // Typed body for the same logical operation.
    let stored = stored_at_seq(fixture_tool_calls(), 1);
    let (typed_body, typed_sig) = build_webhook_typed_request(&[&stored], &cfg).unwrap();
    let typed_sig = typed_sig.unwrap();

    assert_ne!(
        legacy_body, typed_body,
        "legacy and typed bodies should differ in shape"
    );
    assert_ne!(
        legacy_sig, typed_sig,
        "shared HMAC over different bodies must yield different signatures"
    );
}

// ---------------------------------------------------------------------------
// D2: polling worker end-to-end
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StubSink {
    received: Mutex<Vec<Vec<u64>>>, // per-call: the seqs the sink saw
    fail_first: Mutex<u32>,
}

#[async_trait::async_trait]
impl TypedSink for StubSink {
    async fn forward(&self, events: &[wirken_audit::StoredSessionEvent]) -> Result<(), String> {
        let mut fail = self.fail_first.lock().unwrap();
        if *fail > 0 {
            *fail -= 1;
            return Err("simulated transport error".into());
        }
        drop(fail);
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        self.received.lock().unwrap().push(seqs);
        Ok(())
    }
}

#[tokio::test]
async fn d2_worker_delivers_in_seq_order_exactly_once() {
    let tmp = TempDir::new().unwrap();
    let log = Arc::new(SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap());
    let handle = log.handle_for(SessionId::new("sess-D2-a"));

    // Seed: AssistantToolCalls (included), AssistantMessage
    // (excluded), ToolResult (included).
    log.append(&handle, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(
        &handle,
        TrustLevel::System,
        SessionEvent::AssistantMessage {
            content: "secret".into(),
            agent_id: "default".into(),
        },
    )
    .unwrap();
    log.append(&handle, TrustLevel::Tool, fixture_tool_result())
        .unwrap();

    let sink = Arc::new(StubSink::default());
    let cfg = base_config(SiemTarget::Webhook);
    let mut cursor: i64 = 0;

    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();

    {
        let received = sink.received.lock().unwrap();
        assert_eq!(received.len(), 1, "exactly one batch this pass");
        assert_eq!(
            received[0],
            vec![0, 2],
            "in seq order, AssistantMessage at seq=1 filtered out"
        );
    }

    // Second pass: no new rows; sink should not be invoked again.
    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();
    let count = sink.received.lock().unwrap().len();
    assert_eq!(count, 1, "no replay");
}

#[tokio::test]
async fn one_pass_sweeps_all_sessions_in_a_single_batch() {
    // #105: the forwarder issues one global query over session_events.id
    // per pass, so events from multiple sessions arrive in a single
    // batch. The previous per-session implementation produced one
    // `forward` call per session (and one `get_since` query per
    // session, the cost that scaled with session count). A single batch
    // here is the observable proof of the O(1)-queries sweep.
    let tmp = TempDir::new().unwrap();
    let log = Arc::new(SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap());

    let a = log.handle_for(SessionId::new("sess-A"));
    let b = log.handle_for(SessionId::new("sess-B"));
    // Interleave forwardable appends across two sessions.
    log.append(&a, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(&b, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(&a, TrustLevel::Tool, fixture_tool_result())
        .unwrap();
    log.append(&b, TrustLevel::Tool, fixture_tool_result())
        .unwrap();

    let sink = Arc::new(StubSink::default());
    let cfg = base_config(SiemTarget::Webhook);
    let mut cursor: i64 = 0;

    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();

    {
        let received = sink.received.lock().unwrap();
        assert_eq!(
            received.len(),
            1,
            "one batch spanning both sessions, not one batch per session"
        );
        let total: usize = received.iter().map(|b| b.len()).sum();
        assert_eq!(total, 4, "all four forwardable rows across both sessions");
    }
    assert!(cursor > 0, "cursor advanced to the highest global id read");

    // Second pass: no new rows across either session.
    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();
    assert_eq!(
        sink.received.lock().unwrap().len(),
        1,
        "no replay once the global cursor has advanced"
    );
}

#[tokio::test]
async fn d2_worker_retries_on_sink_error_without_advancing_cursor() {
    let tmp = TempDir::new().unwrap();
    let log = Arc::new(SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap());
    let handle = log.handle_for(SessionId::new("sess-D2-b"));

    log.append(&handle, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(&handle, TrustLevel::Tool, fixture_tool_result())
        .unwrap();

    let sink = Arc::new(StubSink::default());
    *sink.fail_first.lock().unwrap() = 1;
    let cfg = base_config(SiemTarget::Webhook);
    let mut cursor: i64 = 0;

    // First pass: sink errors. Worker must propagate Err and not
    // advance the cursor.
    let r = siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor).await;
    assert!(r.is_err(), "sink error must propagate");
    assert!(
        cursor == 0,
        "cursor must not advance on error, got {cursor}"
    );

    // Second pass: sink succeeds. Same rows are re-delivered.
    let r = siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor).await;
    assert!(r.is_ok());
    let received = sink.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], vec![0, 1]);
}

#[tokio::test]
async fn d2_worker_respects_exclude_list() {
    let tmp = TempDir::new().unwrap();
    let log = Arc::new(SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap());
    let handle = log.handle_for(SessionId::new("sess-D2-c"));

    log.append(&handle, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(&handle, TrustLevel::Tool, fixture_tool_result())
        .unwrap();

    let sink = Arc::new(StubSink::default());
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.typed_exclude_variants = Some(vec!["tool_result".into()]);
    let mut cursor: i64 = 0;

    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();
    let received = sink.received.lock().unwrap();
    assert_eq!(
        received[0],
        vec![0],
        "tool_result suppressed by exclude list"
    );
}

// ---------------------------------------------------------------------------
// D3: SiemConfig back-compat (legacy fields only)
// ---------------------------------------------------------------------------

#[test]
fn d3_legacy_siem_config_has_no_typed_opt_in() {
    let cfg = base_config(SiemTarget::Datadog);
    // A 1.3.0-shaped config has no typed_include / typed_exclude /
    // sentinel_typed. The gateway's `maybe_spawn_typed_siem` heuristic
    // (CLI) checks exactly these three fields; assert they're all
    // None on the back-compat config so the worker would not spawn.
    assert!(cfg.typed_include_variants.is_none());
    assert!(cfg.typed_exclude_variants.is_none());
    assert!(cfg.sentinel_typed.is_none());
    assert!(
        !cfg.typed_forwarding_opted_in(),
        "all-null SiemConfig must not opt in to the typed pipe"
    );
}

#[test]
fn d3_typed_forwarding_enabled_true_opts_in_with_default_variants() {
    // typed_forwarding_enabled: Some(true) is the explicit
    // subscription form: no include/exclude needed, the default
    // forwardable-variant set is what the worker forwards. This
    // closes the smoke-test Finding A where typed_include_variants:
    // null left the worker un-spawned even though the operator
    // wanted the default set.
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.typed_forwarding_enabled = Some(true);
    assert!(cfg.typed_forwarding_opted_in());
    // And the default set is still in effect: AssistantToolCalls is
    // included, AssistantMessage is excluded.
    let tc = fixture_tool_calls();
    let msg = SessionEvent::AssistantMessage {
        content: "secret".into(),
        agent_id: "default".into(),
    };
    assert!(
        siem_typed::should_forward(&tc, &cfg),
        "default set forwards AssistantToolCalls"
    );
    assert!(
        !siem_typed::should_forward(&msg, &cfg),
        "default set excludes AssistantMessage"
    );
}

#[test]
fn d3_typed_forwarding_enabled_false_overrides_include() {
    // typed_forwarding_enabled: Some(false) is the explicit off
    // switch: even with typed_include_variants populated, the worker
    // must not spawn. Lets an operator test the legacy-only path
    // against a siem.json that already has the typed fields filled
    // in.
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.typed_forwarding_enabled = Some(false);
    cfg.typed_include_variants = Some(vec!["assistant_tool_calls".into()]);
    assert!(
        !cfg.typed_forwarding_opted_in(),
        "Some(false) must override an otherwise-opted-in config"
    );
}

#[test]
fn d3_typed_include_variants_opts_in_without_explicit_flag() {
    // Preserves the original audit-recommended path: setting
    // typed_include_variants is itself an opt-in (no need to also
    // set typed_forwarding_enabled). Older siem.json shapes that
    // pre-date the explicit flag must keep working.
    let mut cfg = base_config(SiemTarget::Webhook);
    cfg.typed_include_variants = Some(vec!["assistant_tool_calls".into()]);
    assert_eq!(cfg.typed_forwarding_enabled, None);
    assert!(cfg.typed_forwarding_opted_in());
}

// ---------------------------------------------------------------------------
// D4: hybrid multi-target (Sentinel parallel, others shared)
// ---------------------------------------------------------------------------

#[test]
fn d4_sentinel_routes_typed_to_separate_endpoint() {
    let mut cfg = base_config(SiemTarget::Sentinel);
    cfg.sentinel_typed = Some(SentinelTypedEndpoint {
        endpoint: "https://example.invalid/typed".into(),
        api_key: Some("typed-bearer".into()),
    });
    match siem_typed::TypedTransport::for_config(&cfg).unwrap() {
        siem_typed::TypedTransport::SentinelSeparate { endpoint, api_key } => {
            assert_eq!(endpoint, "https://example.invalid/typed");
            assert_eq!(api_key, "typed-bearer");
        }
        _ => panic!("expected SentinelSeparate"),
    }
}

#[test]
fn d4_shared_targets_use_one_endpoint_for_mixed_batch() {
    for target in [SiemTarget::Datadog, SiemTarget::Splunk, SiemTarget::Webhook] {
        let cfg = base_config(target);
        match siem_typed::TypedTransport::for_config(&cfg).unwrap() {
            siem_typed::TypedTransport::Shared { .. } => {}
            _ => panic!("expected Shared on non-Sentinel target"),
        }
    }
}

// ---------------------------------------------------------------------------
// C2: chain integrity (the forwarder reads, it does not write)
// ---------------------------------------------------------------------------

/// `run_one_pass` must not mutate the `session_events` table. The
/// audit hash chain is the source-of-truth; a forwarder restart
/// that re-reads from cursor zero must replay over an identical
/// row set. Compare the on-disk row hashes and ts column before
/// and after a polling pass.
#[tokio::test]
async fn c2_polling_pass_does_not_mutate_session_events() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");
    let log = Arc::new(SqliteSessionLog::open(&db_path).unwrap());
    let handle = log.handle_for(SessionId::new("sess-C2"));
    log.append(&handle, TrustLevel::System, fixture_tool_calls())
        .unwrap();
    log.append(&handle, TrustLevel::Tool, fixture_tool_result())
        .unwrap();

    let snapshot_before = read_chain_snapshot(&db_path);

    let sink = Arc::new(StubSink::default());
    let cfg = base_config(SiemTarget::Webhook);
    let mut cursor: i64 = 0;
    siem_typed::run_one_pass(&log, sink.as_ref(), &cfg, &mut cursor)
        .await
        .unwrap();

    let snapshot_after = read_chain_snapshot(&db_path);
    assert_eq!(
        snapshot_before, snapshot_after,
        "polling pass must not write; row hashes must be byte-identical"
    );
}

fn read_chain_snapshot(db_path: &std::path::Path) -> Vec<(i64, String, String, String)> {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT id, leaf_hash, prev_hash, hash FROM session_events ORDER BY id ASC")
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap();
    rows.filter_map(Result::ok).collect()
}
