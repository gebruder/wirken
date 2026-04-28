//! End-to-end test for the C-Signal slice: render → push → record →
//! keep/skip round-trip.
//!
//! What this covers (and why):
//!
//! - The renderer numbers candidates 1..N in a specific order. The
//!   operator's reply against those numbers must map back to the
//!   *same* candidate ids; the contract that holds this together is
//!   `digest::render` → `digest_log::record_sent` (same ordered ids)
//!   → `digest_log::most_recent_unresolved` (preserves order) →
//!   `KeepSkipInterceptor` (1-indexed lookup against that order).
//!
//! - The push request the gateway receives carries the rendered text
//!   for the bound channel + conversation. The push_client unit tests
//!   exercise the wire format against a fake server; this test
//!   exercises that the *digest* output reaches the wire correctly.
//!
//! - A subsequent keep/skip command resolves the most recent
//!   unresolved digest exactly once. Replying again surfaces "no
//!   digest awaiting reply."
//!
//! What this does NOT cover:
//!
//! - The orchestrator pipeline (fetch / screen / LLM / cluster /
//!   theme-name). Those have their own end-to-end tests in
//!   `orchestrator::tests`. We seed candidate rows directly so this
//!   test runs without an HTTP transport, an Ollama instance, or a
//!   network.
//!
//! - The gateway → adapter forwarding inside `wirken run`. Covered by
//!   `OutboundDispatcher` tests + `push_client` loopback tests.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, params};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use wirken_agent::inbound_interceptor::{InboundInterceptor, InterceptResult, InterceptorContext};
use wirken_audit::SessionEvent;
use wirken_ipc::orchestrator::{OrchestratorPushRequest, OrchestratorPushResponse};
use wirken_zirkel::binding::{Binding, record as record_binding};
use wirken_zirkel::digest::{RenderOptions, load_run, render};
use wirken_zirkel::digest_log::{Decision, most_recent_unresolved, record_sent};
use wirken_zirkel::keep_skip_interceptor::KeepSkipInterceptor;
use wirken_zirkel::push_client::push;
use wirken_zirkel::schema::AGGREGATOR_MIGRATIONS;

/// Spin up a fake "gateway" that accepts one push, captures it, and
/// replies with `{ ok: true }`. Returns a join handle that yields the
/// received request.
fn spawn_fake_gateway(
    socket_path: std::path::PathBuf,
    captured: Arc<Mutex<Option<OrchestratorPushRequest>>>,
) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(&socket_path).expect("bind fake gateway socket");
    tokio::spawn(async move {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };
        let (reader, mut writer) = stream.into_split();
        let mut br = BufReader::new(reader);
        let mut line = String::new();
        if br.read_line(&mut line).await.is_err() {
            return;
        }
        if let Ok(req) = serde_json::from_str::<OrchestratorPushRequest>(line.trim_end()) {
            *captured.lock().await = Some(req);
        }
        let resp = OrchestratorPushResponse {
            ok: true,
            error: None,
        };
        let mut out = serde_json::to_string(&resp).unwrap();
        out.push('\n');
        let _ = writer.write_all(out.as_bytes()).await;
        let _ = writer.shutdown().await;
    })
}

fn migrate(conn: &mut Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (idx INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))",
    ).unwrap();
    let tx = conn.transaction().unwrap();
    for (idx, sql) in AGGREGATOR_MIGRATIONS.iter().enumerate() {
        tx.execute_batch(sql).unwrap();
        tx.execute(
            "INSERT OR IGNORE INTO _migrations (idx) VALUES (?1)",
            params![idx as i64],
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

#[allow(clippy::too_many_arguments)]
fn seed_candidate(
    conn: &Connection,
    run_id: &str,
    title: &str,
    url: &str,
    source: &str,
    score: f64,
    why: &str,
    cluster_id: Option<i64>,
) -> i64 {
    conn.execute(
        "INSERT INTO candidates (source_name, url, body, run_id, title, llm_relevance_score, \
         llm_why_surfaced, cluster_id) \
         VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, ?7)",
        params![source, url, run_id, title, score, why, cluster_id],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn seed_theme(conn: &Connection, run_id: &str, name: &str, members: i64) -> i64 {
    conn.execute(
        "INSERT INTO themes (run_id, name, member_count) VALUES (?1, ?2, ?3)",
        params![run_id, name, members],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn ctx_for<'a>(agent_id: &'a str) -> InterceptorContext<'a> {
    InterceptorContext {
        agent_id,
        skills: &[],
    }
}

fn open_zirkel_db(path: &Path) -> Connection {
    let mut conn = Connection::open(path).expect("open db");
    migrate(&mut conn);
    conn
}

#[tokio::test]
async fn render_push_record_keepskip_round_trip() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("aggregator.db");
    let socket_path = tmp.path().join("orchestrator.sock");

    // ---------- Seed: two-theme run with five candidates -------------
    let conn = open_zirkel_db(&db_path);
    let run_id = "run-e2e-1";
    let theme_pe = seed_theme(&conn, run_id, "Privacy enforcement", 3);
    let theme_cb = seed_theme(&conn, run_id, "Cross-border transfers", 2);

    // PE: 3 items, scored 90/85/80
    let pe1 = seed_candidate(
        &conn,
        run_id,
        "EU AG opinion on adtech consent",
        "https://example.com/pe/1",
        "privacy-news",
        90.0,
        "directly responsive to consent-banner interest",
        Some(theme_pe),
    );
    let pe2 = seed_candidate(
        &conn,
        run_id,
        "DPA fines retailer 2M",
        "https://example.com/pe/2",
        "privacy-news",
        85.0,
        "high-profile enforcement against tracking",
        Some(theme_pe),
    );
    let pe3 = seed_candidate(
        &conn,
        run_id,
        "ICO updates cookie guidance",
        "https://example.com/pe/3",
        "ico-blog",
        80.0,
        "regulator guidance pointer",
        Some(theme_pe),
    );
    // CB: 2 items, scored 70/65
    let cb1 = seed_candidate(
        &conn,
        run_id,
        "Adequacy decision review starts",
        "https://example.com/cb/1",
        "eur-lex",
        70.0,
        "covers your transfer-impact assessment topic",
        Some(theme_cb),
    );
    let cb2 = seed_candidate(
        &conn,
        run_id,
        "SCC guidance update Q2",
        "https://example.com/cb/2",
        "edpb-news",
        65.0,
        "follow-up to last quarter's SCC update",
        Some(theme_cb),
    );

    // ---------- Bind for an "operator-default" agent -----------------
    let bound_agent = "default";
    record_binding(
        &conn,
        &Binding {
            agent_id: bound_agent.into(),
            channel: "signal".into(),
            conversation_id: "+15551234567".into(),
        },
    )
    .unwrap();
    drop(conn);

    // ---------- Render -----------------------------------------------
    let conn = Connection::open(&db_path).unwrap();
    let (rows, themes) = load_run(&conn, run_id).unwrap();
    let opts = RenderOptions {
        date: Some("2026-04-29".into()),
        ..RenderOptions::default()
    };
    let rendered = render(&rows, &themes, &opts).unwrap();
    drop(conn);

    // Two themes → both headers present; numbering is 1..5 across
    // the whole digest, biggest theme first.
    assert!(rendered.text.contains("— Privacy enforcement (3) —"));
    assert!(rendered.text.contains("— Cross-border transfers (2) —"));
    assert!(rendered.text.contains("1. EU AG opinion on adtech consent"));
    assert!(rendered.text.contains("4. Adequacy decision review starts"));
    assert!(rendered.text.contains("5. SCC guidance update Q2"));
    assert!(rendered.text.contains("Daily digest — 2026-04-29"));
    assert_eq!(
        rendered.ordered_candidate_ids,
        vec![pe1, pe2, pe3, cb1, cb2]
    );

    // ---------- Push to fake gateway --------------------------------
    let captured = Arc::new(Mutex::new(None));
    let server = spawn_fake_gateway(socket_path.clone(), captured.clone());

    push(&socket_path, "signal", "+15551234567", &rendered.text)
        .await
        .expect("push succeeds");
    server.await.unwrap();

    let req = captured
        .lock()
        .await
        .clone()
        .expect("server captured request");
    assert_eq!(req.channel, "signal");
    assert_eq!(req.conversation_id, "+15551234567");
    assert_eq!(req.text, rendered.text);

    // ---------- Record sent so keep/skip can resolve it -------------
    let mut conn = Connection::open(&db_path).unwrap();
    let digest_id = record_sent(
        &mut conn,
        run_id,
        bound_agent,
        &rendered.ordered_candidate_ids,
    )
    .unwrap();
    drop(conn);

    // ---------- Operator replies "keep 1,3" -------------------------
    // Numbering is operator-visible: 1 = PE first item, 3 = PE third.
    // Items 2, 4, 5 should land as skipped.
    let interceptor = KeepSkipInterceptor::open(&db_path).expect("open interceptor");
    let result = interceptor.intercept("keep 1,3", &ctx_for(bound_agent));

    let (reply, events) = match result {
        InterceptResult::Handle {
            reply,
            audit_events,
        } => (reply, audit_events),
        other => panic!("expected Handle, got {other:?}"),
    };
    assert!(reply.starts_with("✓ kept 1, 3"), "reply was: {reply}");
    assert!(reply.contains("3 skipped"), "reply was: {reply}");
    assert_eq!(events.len(), 5);

    // ---------- Verify per-item decisions in DB ----------------------
    let conn = Connection::open(&db_path).unwrap();
    let decisions: Vec<(i64, Option<String>)> = {
        let mut stmt = conn
            .prepare("SELECT idx, decision FROM digest_items WHERE digest_id = ?1 ORDER BY idx")
            .unwrap();
        stmt.query_map(params![digest_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    };
    assert_eq!(decisions[0], (1, Some(Decision::Kept.as_db_str().into())));
    assert_eq!(
        decisions[1],
        (2, Some(Decision::Skipped.as_db_str().into()))
    );
    assert_eq!(decisions[2], (3, Some(Decision::Kept.as_db_str().into())));
    assert_eq!(
        decisions[3],
        (4, Some(Decision::Skipped.as_db_str().into()))
    );
    assert_eq!(
        decisions[4],
        (5, Some(Decision::Skipped.as_db_str().into()))
    );

    // ---------- Verify session events match decisions ---------------
    let kept_count = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::CandidateKept { .. }))
        .count();
    let skipped_count = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::CandidateSkipped { .. }))
        .count();
    assert_eq!(kept_count, 2);
    assert_eq!(skipped_count, 3);

    // The CandidateKept events should reference pe1 and pe3 by id.
    let kept_ids: Vec<i64> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::CandidateKept { candidate_id, .. } => Some(*candidate_id),
            _ => None,
        })
        .collect();
    assert!(kept_ids.contains(&pe1));
    assert!(kept_ids.contains(&pe3));

    // ---------- Reply again: digest is resolved, no-op ---------------
    let result_again = interceptor.intercept("keep 2", &ctx_for(bound_agent));
    let reply_again = match result_again {
        InterceptResult::Handle { reply, .. } => reply,
        other => panic!("expected Handle, got {other:?}"),
    };
    assert!(
        reply_again.starts_with("No digest awaiting reply"),
        "reply was: {reply_again}"
    );

    // ---------- Out-of-range index doesn't resolve a fresh digest ---
    // Send a new digest and verify "keep 99" leaves it pending.
    let mut conn = Connection::open(&db_path).unwrap();
    record_sent(&mut conn, run_id, bound_agent, &[pe1, pe2]).unwrap();
    drop(conn);
    let result_oor = interceptor.intercept("keep 99", &ctx_for(bound_agent));
    match result_oor {
        InterceptResult::Handle { reply, .. } => {
            assert!(reply.contains("99"), "reply was: {reply}");
            assert!(reply.contains("2 items"), "reply was: {reply}");
        }
        other => panic!("expected Handle, got {other:?}"),
    }
    let conn = Connection::open(&db_path).unwrap();
    assert!(
        most_recent_unresolved(&conn, bound_agent)
            .unwrap()
            .is_some(),
        "out-of-range reply must leave the digest unresolved"
    );
}
