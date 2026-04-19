use chrono::{Duration, Utc};
use tempfile::TempDir;

use crate::event::AuditEvent;
use crate::log::{AuditLog, AuditQuery, VerifyResult};
use crate::writer::AuditWriter;

// ---------------------------------------------------------------------------
// Direct log tests (no async, no batching)
// ---------------------------------------------------------------------------

#[test]
fn write_and_query_single_event() {
    let log = AuditLog::open_in_memory().unwrap();
    let event = AuditEvent::new("user", "exec", "/bin/ls").with_channel("telegram");

    log.write_batch(&[event]).unwrap();

    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event.action, "exec");
    assert_eq!(results[0].event.target, "/bin/ls");
    assert_eq!(results[0].event.channel, "telegram");
}

#[test]
fn hash_chain_integrity_on_sequential_writes() {
    let log = AuditLog::open_in_memory().unwrap();

    for i in 0..100 {
        let event = AuditEvent::new("actor", format!("action-{i}"), "target");
        log.write_batch(&[event]).unwrap();
    }

    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 100),
        other => panic!("Expected Ok, got {other:?}"),
    }
}

#[test]
fn hash_chain_integrity_on_batch_write() {
    let log = AuditLog::open_in_memory().unwrap();

    let events: Vec<AuditEvent> = (0..1000)
        .map(|i| AuditEvent::new("actor", format!("action-{i}"), format!("target-{i}")))
        .collect();

    log.write_batch(&events).unwrap();

    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 1000),
        other => panic!("Expected Ok, got {other:?}"),
    }
}

#[test]
fn tampered_row_detected() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");
    let log = AuditLog::open(&db_path).unwrap();

    let events: Vec<AuditEvent> = (0..10)
        .map(|i| AuditEvent::new("actor", format!("action-{i}"), "target"))
        .collect();
    log.write_batch(&events).unwrap();

    // Tamper with row 5's hash. After slice 2 of item 1, audit_events
    // is a SQL view over session_events — UPDATE the underlying table.
    drop(log);
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE session_events SET hash = 'tampered' WHERE id = 5",
            [],
        )
        .unwrap();
    }

    let log = AuditLog::open(&db_path).unwrap();
    match log.verify().unwrap() {
        VerifyResult::Broken { row_id, .. } => assert_eq!(row_id, 5),
        other => panic!("Expected Broken at row 5, got {other:?}"),
    }
}

#[test]
fn tampered_row_data_detected() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");
    let log = AuditLog::open(&db_path).unwrap();

    let events: Vec<AuditEvent> = (0..10)
        .map(|i| AuditEvent::new("actor", format!("action-{i}"), "target"))
        .collect();
    log.write_batch(&events).unwrap();

    // Tamper with row 3's payload — rewrite the AuditLegacy variant
    // so the leaf_hash no longer matches the stored value. After
    // slice 2, the underlying table is session_events.
    drop(log);
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let new_payload = serde_json::to_string(&serde_json::json!({
            "kind": "audit_legacy",
            "actor": "actor",
            "action": "HACKED",
            "target": "target",
            "channel": "",
            "detail": null
        }))
        .unwrap();
        conn.execute(
            "UPDATE session_events SET payload = ?1 WHERE id = 3",
            rusqlite::params![new_payload],
        )
        .unwrap();
    }

    let log = AuditLog::open(&db_path).unwrap();
    match log.verify().unwrap() {
        VerifyResult::Broken { row_id, .. } => assert_eq!(row_id, 3),
        other => panic!("Expected Broken at row 3, got {other:?}"),
    }
}

#[test]
fn verify_empty_log() {
    let log = AuditLog::open_in_memory().unwrap();
    match log.verify().unwrap() {
        VerifyResult::Empty => {}
        other => panic!("Expected Empty, got {other:?}"),
    }
}

#[test]
fn query_filter_by_action() {
    let log = AuditLog::open_in_memory().unwrap();

    let events = vec![
        AuditEvent::new("user", "exec", "cmd1"),
        AuditEvent::new("user", "message.send", "msg1"),
        AuditEvent::new("user", "exec", "cmd2"),
        AuditEvent::new("user", "credential.access", "key1"),
    ];
    log.write_batch(&events).unwrap();

    let results = log
        .query(&AuditQuery {
            action: Some("exec".into()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.event.action == "exec"));
}

#[test]
fn query_filter_by_channel() {
    let log = AuditLog::open_in_memory().unwrap();

    let events = vec![
        AuditEvent::new("user", "send", "msg").with_channel("telegram"),
        AuditEvent::new("user", "send", "msg").with_channel("discord"),
        AuditEvent::new("user", "send", "msg").with_channel("telegram"),
    ];
    log.write_batch(&events).unwrap();

    let results = log
        .query(&AuditQuery {
            channel: Some("telegram".into()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(results.len(), 2);
}

#[test]
fn query_with_limit() {
    let log = AuditLog::open_in_memory().unwrap();

    let events: Vec<AuditEvent> = (0..50)
        .map(|i| AuditEvent::new("actor", "action", format!("target-{i}")))
        .collect();
    log.write_batch(&events).unwrap();

    let results = log
        .query(&AuditQuery {
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(results.len(), 10);
}

#[test]
fn prune_old_events() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");
    let log = AuditLog::open(&db_path).unwrap();

    // Insert events with backdated timestamps directly into
    // session_events. After slice 2, audit_events is a view and
    // cannot be inserted into. Hash chain values are dummy strings
    // — the prune logic filters by ts only and the test never calls
    // verify() afterwards.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let old_ts = (Utc::now() - Duration::days(100)).to_rfc3339();
    let recent_ts = Utc::now().to_rfc3339();

    for i in 0..5u64 {
        conn.execute(
            "INSERT INTO session_events
                 (session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash)
             VALUES ('__system__', ?1, ?2, 'system', '{}', '', '', ?3)",
            rusqlite::params![i as i64, old_ts, format!("hash-old-{i}")],
        )
        .unwrap();
    }
    for i in 0..3u64 {
        let seq = (i + 5) as i64;
        conn.execute(
            "INSERT INTO session_events
                 (session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash)
             VALUES ('__system__', ?1, ?2, 'system', '{}', '', '', ?3)",
            rusqlite::params![seq, recent_ts, format!("hash-new-{i}")],
        )
        .unwrap();
    }
    drop(conn);

    let log2 = AuditLog::open(&db_path).unwrap();
    let deleted = log2.prune(90).unwrap();
    // 4 deleted: the last old event is kept as a per-session
    // checkpoint so the chain (hypothetically) stays valid.
    assert_eq!(deleted, 4);

    let remaining = log.query(&AuditQuery::default()).unwrap();
    // 3 recent + 1 checkpoint = 4
    assert_eq!(remaining.len(), 4);
}

// ---------------------------------------------------------------------------
// Slice 2 of item 1: migration from legacy audit_events table to
// session_events + view.
// ---------------------------------------------------------------------------

#[test]
fn migration_on_fresh_db_is_a_noop() {
    // Fresh in-memory DB has no audit_events table. Open should
    // create the view directly without complaint.
    let log = AuditLog::open_in_memory().unwrap();
    let results = log.query(&AuditQuery::default()).unwrap();
    assert!(results.is_empty());
}

#[test]
fn migration_of_legacy_table_copies_rows_under_sentinel() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    // Create the pre-slice-2 schema by hand and insert some rows.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 action TEXT NOT NULL,
                 target TEXT NOT NULL,
                 channel TEXT NOT NULL DEFAULT '',
                 session TEXT NOT NULL DEFAULT '',
                 detail JSON NOT NULL DEFAULT 'null',
                 hash TEXT NOT NULL
             );",
        )
        .unwrap();
        let ts = Utc::now().to_rfc3339();
        for i in 0..3 {
            conn.execute(
                "INSERT INTO audit_events
                     (ts, actor, action, target, channel, session, detail, hash)
                 VALUES (?1, 'legacy-actor', ?2, 'legacy-target', '', '', 'null', ?3)",
                rusqlite::params![ts, format!("legacy-action-{i}"), format!("h{i}")],
            )
            .unwrap();
        }
    }

    // First open runs migration: copy → drop table → create view.
    let log = AuditLog::open(&db_path).unwrap();

    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 3);
    // Migrated rows landed under the pre-migration sentinel.
    assert!(
        results
            .iter()
            .all(|r| r.event.session == "__pre_migration__")
    );
    assert!(results.iter().all(|r| r.event.actor == "legacy-actor"));

    // Verify still works on the migrated chain.
    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 3),
        other => panic!("expected Ok(3), got {other:?}"),
    }

    // The audit_events table no longer exists as a table.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let kind: String = conn
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = 'audit_events'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kind, "view");
}

#[test]
fn migration_is_idempotent_across_repeated_opens() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    // Create legacy table with one row.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 action TEXT NOT NULL,
                 target TEXT NOT NULL,
                 channel TEXT NOT NULL DEFAULT '',
                 session TEXT NOT NULL DEFAULT '',
                 detail JSON NOT NULL DEFAULT 'null',
                 hash TEXT NOT NULL
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_events
                 (ts, actor, action, target, channel, session, detail, hash)
             VALUES (?1, 'a', 'x', 't', '', '', 'null', 'h')",
            rusqlite::params![Utc::now().to_rfc3339()],
        )
        .unwrap();
    }

    // First open: migration runs.
    let log1 = AuditLog::open(&db_path).unwrap();
    assert_eq!(log1.query(&AuditQuery::default()).unwrap().len(), 1);
    drop(log1);

    // Second open: migration is a no-op. No rows added, no errors.
    let log2 = AuditLog::open(&db_path).unwrap();
    assert_eq!(log2.query(&AuditQuery::default()).unwrap().len(), 1);

    // Third open through write_batch path: migration still no-op.
    let log3 = AuditLog::open(&db_path).unwrap();
    log3.write_batch(&[AuditEvent::new("new", "post-migration", "t")])
        .unwrap();
    assert_eq!(log3.query(&AuditQuery::default()).unwrap().len(), 2);
}

#[test]
fn audit_event_with_session_routes_to_named_session() {
    let log = AuditLog::open_in_memory().unwrap();

    // Two events: one with a session field, one without.
    log.write_batch(&[
        AuditEvent::new("u", "send", "msg").with_session("conv-42"),
        AuditEvent::new("u", "system.start", "daemon"),
    ])
    .unwrap();

    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 2);

    let by_action: std::collections::HashMap<&str, &str> = results
        .iter()
        .map(|r| (r.event.action.as_str(), r.event.session.as_str()))
        .collect();

    assert_eq!(by_action.get("send"), Some(&"conv-42"));
    assert_eq!(by_action.get("system.start"), Some(&"__system__"));
}

#[test]
fn write_empty_batch_is_noop() {
    let log = AuditLog::open_in_memory().unwrap();
    log.write_batch(&[]).unwrap();

    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 0);
}

#[test]
fn multiple_batches_maintain_chain() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    // Write batch 1
    let log = AuditLog::open(&db_path).unwrap();
    let batch1: Vec<AuditEvent> = (0..50)
        .map(|i| AuditEvent::new("actor", format!("batch1-{i}"), "target"))
        .collect();
    log.write_batch(&batch1).unwrap();
    drop(log);

    // Write batch 2 (reopens DB — simulates restart)
    let log = AuditLog::open(&db_path).unwrap();
    let batch2: Vec<AuditEvent> = (0..50)
        .map(|i| AuditEvent::new("actor", format!("batch2-{i}"), "target"))
        .collect();
    log.write_batch(&batch2).unwrap();

    // Verify chain across both batches
    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 100),
        other => panic!("Expected Ok with 100 rows, got {other:?}"),
    }
}

#[test]
fn events_with_json_detail() {
    let log = AuditLog::open_in_memory().unwrap();

    let detail = serde_json::json!({
        "command": "rm -rf /tmp/test",
        "exit_code": 0,
        "duration_ms": 42
    });

    let event = AuditEvent::new("agent-1", "exec", "/tmp/test").with_detail(detail.clone());
    log.write_batch(&[event]).unwrap();

    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results[0].event.detail, detail);
}

// ---------------------------------------------------------------------------
// Async writer tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn writer_flushes_events() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    let (writer, handle) = AuditWriter::new(&db_path).unwrap();

    // Write 10 events
    for i in 0..10 {
        let event = AuditEvent::new("writer-test", format!("action-{i}"), "target");
        writer.log(event).await.unwrap();
    }

    // Drop writer to close channel, triggering final flush
    drop(writer);
    handle.await.unwrap();

    // Verify events were flushed
    let log = AuditLog::open(&db_path).unwrap();
    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 10);

    // Verify hash chain
    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 10),
        other => panic!("Expected Ok, got {other:?}"),
    }
}

#[tokio::test]
async fn writer_batch_flush_at_capacity() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    let (writer, handle) = AuditWriter::new(&db_path).unwrap();

    // Write more than BATCH_SIZE events quickly
    for i in 0..250 {
        let event = AuditEvent::new("batch-test", format!("action-{i}"), "target");
        writer.log(event).await.unwrap();
    }

    drop(writer);
    handle.await.unwrap();

    let log = AuditLog::open(&db_path).unwrap();
    let results = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(results.len(), 250);

    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 250),
        other => panic!("Expected Ok, got {other:?}"),
    }
}

#[tokio::test]
async fn writer_1000_events_hash_chain_intact() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("audit.db");

    let (writer, handle) = AuditWriter::new(&db_path).unwrap();

    for i in 0..1000 {
        let event = AuditEvent::new("stress", format!("op-{i}"), format!("t-{i}"))
            .with_channel("telegram")
            .with_detail(serde_json::json!({"i": i}));
        writer.log(event).await.unwrap();
    }

    drop(writer);
    handle.await.unwrap();

    let log = AuditLog::open(&db_path).unwrap();
    match log.verify().unwrap() {
        VerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 1000),
        other => panic!("Expected Ok with 1000, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Session log (item 1 slice 1)
// ---------------------------------------------------------------------------

mod session {
    use super::*;
    use crate::session_log::{
        SessionEvent, SessionHandle, SessionId, SessionLog, SessionVerifyResult, SqliteSessionLog,
        ToolCallRecord, TrustLevel,
    };

    fn user_msg(s: &str) -> SessionEvent {
        SessionEvent::UserMessage {
            content: s.into(),
            inbound_id: None,
        }
    }

    fn assistant_msg(s: &str) -> SessionEvent {
        SessionEvent::AssistantMessage { content: s.into() }
    }

    fn tool_result(call_id: &str, name: &str, output: &str) -> SessionEvent {
        SessionEvent::ToolResult {
            call_id: call_id.into(),
            tool_name: name.into(),
            output: output.into(),
            success: true,
        }
    }

    fn fresh() -> (
        SqliteSessionLog,
        SessionHandle<crate::session_log::OwnSession>,
    ) {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("sess-A"));
        (log, h)
    }

    #[test]
    fn empty_session_reports_no_index_no_rows() {
        let (log, h) = fresh();
        assert_eq!(log.last_index(&h).unwrap(), None);
        assert!(log.get_range(&h, 0..100).unwrap().is_empty());
        assert!(log.get_since(&h, 0).unwrap().is_empty());
        assert_eq!(log.verify(&h).unwrap(), SessionVerifyResult::Empty);
    }

    #[test]
    fn append_returns_monotonic_seq_starting_at_zero() {
        let (log, h) = fresh();
        let s0 = log.append(&h, TrustLevel::User, user_msg("hi")).unwrap();
        let s1 = log
            .append(&h, TrustLevel::System, assistant_msg("hello"))
            .unwrap();
        let s2 = log
            .append(&h, TrustLevel::Tool, tool_result("c1", "exec", "ok"))
            .unwrap();
        assert_eq!((s0, s1, s2), (0, 1, 2));
        assert_eq!(log.last_index(&h).unwrap(), Some(2));
    }

    #[test]
    fn get_range_is_half_open_and_ascending() {
        let (log, h) = fresh();
        for i in 0..5 {
            log.append(&h, TrustLevel::User, user_msg(&format!("m{i}")))
                .unwrap();
        }
        let rows = log.get_range(&h, 1..4).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[1].seq, 2);
        assert_eq!(rows[2].seq, 3);
        // start >= end → empty. Construct via variables to keep
        // clippy::reversed_empty_ranges off our backs.
        assert!(log.get_range(&h, 3..3).unwrap().is_empty());
        let (start, end): (u64, u64) = (5, 2);
        assert!(log.get_range(&h, start..end).unwrap().is_empty());
    }

    #[test]
    fn get_since_returns_tail_of_session() {
        let (log, h) = fresh();
        for i in 0..5 {
            log.append(&h, TrustLevel::User, user_msg(&format!("m{i}")))
                .unwrap();
        }
        let rows = log.get_since(&h, 3).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 3);
        assert_eq!(rows[1].seq, 4);
    }

    #[test]
    fn rewind_drops_most_recent_n_events() {
        use crate::{SessionEvent, SessionVerifyResult};

        let (log, h) = fresh();
        for i in 0..5 {
            log.append(&h, TrustLevel::User, user_msg(&format!("m{i}")))
                .unwrap();
        }
        // rewind(0) is a no-op and appends no marker
        assert_eq!(log.rewind(&h, 0, "test").unwrap(), 0);
        assert_eq!(log.last_index(&h).unwrap(), Some(4));

        // rewind(2) drops seqs 3 and 4, leaving max=2, then appends
        // a Rewind marker which `append` slots in at seq=3 (max+1).
        // The returned count is the delete count, not including the
        // appended marker.
        let deleted = log.rewind(&h, 2, "crash_recovery").unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(log.last_index(&h).unwrap(), Some(3));

        // The marker records what happened.
        let rows = log.get_range(&h, 3..4).unwrap();
        match &rows[0].event {
            SessionEvent::Rewind {
                old_last_seq,
                deleted_count,
                reason,
            } => {
                assert_eq!(*old_last_seq, 4);
                assert_eq!(*deleted_count, 2);
                assert_eq!(reason, "crash_recovery");
            }
            other => panic!("expected Rewind, got {other:?}"),
        }

        // The chain is still intact after the delete + marker.
        match log.verify(&h).unwrap() {
            SessionVerifyResult::Ok { rows_verified } => {
                // seqs 0, 1, 2 survive + the Rewind marker at 3 = 4 rows
                assert_eq!(rows_verified, 4);
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        // rewind(big_n) deletes everything still there (seqs 0, 1,
        // 2, 3 = 4 rows), then appends a fresh Rewind marker as the
        // new chain head at seq 0 (since the session is now empty
        // after the DELETE).
        let deleted = log.rewind(&h, 1000, "wipe").unwrap();
        assert_eq!(deleted, 4);
        assert_eq!(log.last_index(&h).unwrap(), Some(0));
    }

    #[test]
    fn rewind_on_empty_session_is_safe() {
        let (log, h) = fresh();
        // No events in the session, so the rewind is a no-op and
        // does NOT append a marker. An empty session stays empty.
        assert_eq!(log.rewind(&h, 5, "nothing").unwrap(), 0);
        assert_eq!(log.last_index(&h).unwrap(), None);
    }

    #[test]
    fn two_sessions_are_isolated() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let a = log.handle_for(SessionId::new("alice"));
        let b = log.handle_for(SessionId::new("bob"));

        log.append(&a, TrustLevel::User, user_msg("a0")).unwrap();
        log.append(&a, TrustLevel::User, user_msg("a1")).unwrap();
        log.append(&b, TrustLevel::User, user_msg("b0")).unwrap();

        assert_eq!(log.last_index(&a).unwrap(), Some(1));
        assert_eq!(log.last_index(&b).unwrap(), Some(0));

        let rows_a = log.get_since(&a, 0).unwrap();
        assert_eq!(rows_a.len(), 2);
        for r in &rows_a {
            assert_eq!(r.session_id.as_str(), "alice");
        }

        let rows_b = log.get_since(&b, 0).unwrap();
        assert_eq!(rows_b.len(), 1);
        assert_eq!(rows_b[0].session_id.as_str(), "bob");
    }

    #[test]
    fn two_sessions_have_independent_chains() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let a = log.handle_for(SessionId::new("alice"));
        let b = log.handle_for(SessionId::new("bob"));

        // Same payload in both sessions. Their leaf hashes should
        // match (deterministic), but their chain hashes must differ
        // because each chain starts from an empty prev_hash.
        log.append(&a, TrustLevel::User, user_msg("hello")).unwrap();
        log.append(&b, TrustLevel::User, user_msg("hello")).unwrap();

        let row_a = &log.get_since(&a, 0).unwrap()[0];
        let row_b = &log.get_since(&b, 0).unwrap()[0];

        // First event in both sessions: prev_hash empty, leaf_hash
        // identical, chain hash identical. (This is fine — it just
        // means a single-event chain isn't unique. The uniqueness
        // kicks in once a session has more than one event.)
        assert_eq!(row_a.leaf_hash, row_b.leaf_hash);
        assert_eq!(row_a.prev_hash.0, "");
        assert_eq!(row_b.prev_hash.0, "");

        // Append a second event to each, with the SAME payload. Now
        // the chains diverge IF and only IF prev_hash is per-session.
        // Since prev_hash is the same in both first events, the
        // second events should also produce the same chain hash for
        // identical payloads. The point of the per-session chain
        // isn't divergence on identical inputs — it's that you can
        // verify a single session in isolation.
        log.append(&a, TrustLevel::User, user_msg("two")).unwrap();
        log.append(&b, TrustLevel::User, user_msg("two")).unwrap();

        // verify both chains independently
        assert_eq!(
            log.verify(&a).unwrap(),
            SessionVerifyResult::Ok { rows_verified: 2 }
        );
        assert_eq!(
            log.verify(&b).unwrap(),
            SessionVerifyResult::Ok { rows_verified: 2 }
        );
    }

    #[test]
    fn verify_intact_chain() {
        let (log, h) = fresh();
        for i in 0..50 {
            log.append(&h, TrustLevel::User, user_msg(&format!("event {i}")))
                .unwrap();
        }
        match log.verify(&h).unwrap() {
            SessionVerifyResult::Ok { rows_verified } => assert_eq!(rows_verified, 50),
            other => panic!("expected Ok(50), got {other:?}"),
        }
    }

    #[test]
    fn verify_detects_payload_tampering() {
        let (log, h) = fresh();
        log.append(&h, TrustLevel::User, user_msg("first")).unwrap();
        log.append(&h, TrustLevel::User, user_msg("second"))
            .unwrap();
        log.append(&h, TrustLevel::User, user_msg("third")).unwrap();

        // Tamper: rewrite the payload of seq=1 directly via the
        // raw connection without recomputing the hashes.
        {
            let conn = log.raw_conn_for_test();
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1
                 WHERE session_id = 'sess-A' AND seq = 1",
                rusqlite::params![serde_json::to_string(&user_msg("EVIL")).unwrap()],
            )
            .unwrap();
        }

        match log.verify(&h).unwrap() {
            SessionVerifyResult::Broken { seq, reason } => {
                assert_eq!(seq, 1);
                assert!(reason.contains("leaf_hash"));
            }
            other => panic!("expected Broken at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn verify_detects_chain_hash_tampering() {
        let (log, h) = fresh();
        log.append(&h, TrustLevel::User, user_msg("first")).unwrap();
        log.append(&h, TrustLevel::User, user_msg("second"))
            .unwrap();

        // Corrupt the chain hash of seq=0 — leaves leaf_hash and
        // payload intact, but breaks the link to seq=1.
        {
            let conn = log.raw_conn_for_test();
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE session_events SET hash = ?1
                 WHERE session_id = 'sess-A' AND seq = 0",
                rusqlite::params![
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ],
            )
            .unwrap();
        }

        match log.verify(&h).unwrap() {
            SessionVerifyResult::Broken { seq, reason } => {
                // The break is detected at seq=0 itself when the
                // recomputed chain hash doesn't match the stored
                // (corrupted) hash.
                assert_eq!(seq, 0);
                assert!(reason.contains("chain hash"));
            }
            other => panic!("expected Broken at seq 0, got {other:?}"),
        }
    }

    #[test]
    fn append_persists_across_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("session.db");
        {
            let log = SqliteSessionLog::open(&path).unwrap();
            let h = log.handle_for(SessionId::new("persist"));
            log.append(&h, TrustLevel::User, user_msg("hello")).unwrap();
            log.append(&h, TrustLevel::User, user_msg("world")).unwrap();
        }
        let log = SqliteSessionLog::open(&path).unwrap();
        let h = log.handle_for(SessionId::new("persist"));
        assert_eq!(log.last_index(&h).unwrap(), Some(1));
        assert_eq!(
            log.verify(&h).unwrap(),
            SessionVerifyResult::Ok { rows_verified: 2 }
        );
    }

    #[test]
    fn handle_stores_session_id() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let h = log.handle_for(SessionId::new("xyz"));
        assert_eq!(h.id().as_str(), "xyz");
    }

    #[test]
    fn round_trip_every_event_variant() {
        let (log, h) = fresh();

        let calls = vec![
            ToolCallRecord {
                id: "c1".into(),
                name: "exec".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            },
            ToolCallRecord {
                id: "c2".into(),
                name: "read_file".into(),
                arguments: r#"{"path":"a.txt"}"#.into(),
            },
        ];

        let events: Vec<(TrustLevel, SessionEvent)> = vec![
            (TrustLevel::User, user_msg("a user message")),
            (TrustLevel::System, assistant_msg("an assistant reply")),
            (
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: calls.clone(),
                },
            ),
            (
                TrustLevel::Tool,
                tool_result("c1", "exec", "command output"),
            ),
            (
                TrustLevel::System,
                SessionEvent::LlmRequest {
                    provider: "anthropic".into(),
                    model: "claude-sonnet-4-20250514".into(),
                    request_id: "req-1".into(),
                    tools_hash: crate::session_log::HashHex("deadbeef".repeat(8)),
                    messages_hash: crate::session_log::HashHex("cafebabe".repeat(8)),
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::LlmResponse {
                    request_id: "req-1".into(),
                    finish_reason: "end_turn".into(),
                    tokens_in: 100,
                    tokens_out: 50,
                    latency_ms: 1234,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::PermissionDenied {
                    tool: "exec".into(),
                    action_key: "shell:curl".into(),
                    tier: "tier3".into(),
                    agent_id: "default".into(),
                    trigger: Some("delete the universe".into()),
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::SandboxProvisioned {
                    name: "default".into(),
                    mode: "gvisor".into(),
                },
            ),
            (
                TrustLevel::Compaction,
                SessionEvent::Compaction {
                    spans: vec![0, 1, 2, 3],
                    extracts: serde_json::json!({
                        "files_read": ["a.txt", "b.txt"],
                        "user_stated_goal": "rename"
                    }),
                    via_model: false,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::Attestation {
                    chain_head_seq: 8,
                    chain_head_hash: crate::session_log::HashHex("1234".repeat(16)),
                    signature: crate::session_log::HexBytes("5678".repeat(32)),
                    signer_pubkey: crate::session_log::HashHex("9abc".repeat(16)),
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::SubagentSpawned {
                    child_session_id: "sess-A/sub-0".into(),
                    child_agent_id: "researcher".into(),
                    tools_granted: vec!["read_file".into(), "web_search".into()],
                },
            ),
            (
                TrustLevel::Tool,
                SessionEvent::SubagentResult {
                    child_session_id: "sess-A/sub-0".into(),
                    output: "found the answer".into(),
                    status: "ok".into(),
                },
            ),
        ];

        let n = events.len();
        for (trust, event) in &events {
            log.append(&h, *trust, event.clone()).unwrap();
        }

        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows.len(), n);
        for (row, (expected_trust, expected_event)) in rows.iter().zip(events.iter()) {
            assert_eq!(row.trust, *expected_trust);
            assert_eq!(row.event, *expected_event);
        }

        // The whole chain must verify intact.
        assert_eq!(
            log.verify(&h).unwrap(),
            SessionVerifyResult::Ok { rows_verified: n }
        );
    }

    #[test]
    fn leaf_hash_is_deterministic_for_same_event() {
        // Byte-stability of the canonical encoding. If serde_json
        // ever produces different bytes for the same struct (key
        // reordering, whitespace, escape changes), this test fails
        // and we know to migrate to a stricter canonical form.
        let (log, h) = fresh();
        let event = SessionEvent::ToolResult {
            call_id: "c".into(),
            tool_name: "exec".into(),
            output: "hello".into(),
            success: true,
        };
        log.append(&h, TrustLevel::Tool, event.clone()).unwrap();
        log.append(&h, TrustLevel::Tool, event).unwrap();
        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows[0].leaf_hash, rows[1].leaf_hash);
    }

    #[test]
    fn merkle_frontier_chain_shape() {
        // row.hash == SHA-256(prev_hash || leaf_hash). Recompute
        // manually for a tiny chain to lock the encoding.
        use sha2::{Digest, Sha256};

        let (log, h) = fresh();
        log.append(&h, TrustLevel::User, user_msg("a")).unwrap();
        log.append(&h, TrustLevel::User, user_msg("b")).unwrap();
        let rows = log.get_since(&h, 0).unwrap();

        // First row: prev_hash is empty.
        assert_eq!(rows[0].prev_hash.0, "");
        let mut hasher = Sha256::new();
        hasher.update("".as_bytes());
        hasher.update(rows[0].leaf_hash.0.as_bytes());
        let expected0 = format!("{:x}", hasher.finalize());
        assert_eq!(rows[0].hash.0, expected0);

        // Second row: prev_hash is the previous chain hash.
        assert_eq!(rows[1].prev_hash.0, rows[0].hash.0);
        let mut hasher = Sha256::new();
        hasher.update(rows[1].prev_hash.0.as_bytes());
        hasher.update(rows[1].leaf_hash.0.as_bytes());
        let expected1 = format!("{:x}", hasher.finalize());
        assert_eq!(rows[1].hash.0, expected1);
    }
}
