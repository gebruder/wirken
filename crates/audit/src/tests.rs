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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 100),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 1000),
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
        // SQL row id 5 corresponds to the 5th event in the sentinel
        // session, which is at seq 4 since per-session seq is 0-indexed.
        VerifyResult::Broken { seq, .. } => assert_eq!(seq, 4),
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
        // SQL row id 3 corresponds to the 3rd event in the sentinel
        // session, which is at seq 2 since per-session seq is 0-indexed.
        VerifyResult::Broken { seq, .. } => assert_eq!(seq, 2),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 3),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 100),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 10),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 250),
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
        VerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 1000),
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
            SessionVerifyResult::Ok { rows_verified, .. } => {
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
            SessionVerifyResult::Ok { rows_verified, .. } => assert_eq!(rows_verified, 50),
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
            SessionVerifyResult::Broken {
                seq,
                expected_hash,
                actual_hash,
                ..
            } => {
                assert_eq!(seq, 1);
                // leaf_hash mismatch: expected = recomputed hash of
                // tampered payload, actual = leaf_hash stored in row
                // (which still matches the original payload).
                assert_ne!(expected_hash, actual_hash);
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
            SessionVerifyResult::Broken {
                seq,
                expected_hash,
                actual_hash,
                ..
            } => {
                // The break is detected at seq=0 itself when the
                // recomputed chain hash doesn't match the stored
                // (corrupted) hash.
                assert_eq!(seq, 0);
                assert_ne!(expected_hash, actual_hash);
                assert_eq!(
                    actual_hash,
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
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
                    cache_creation_input_tokens: 0,
                    cache_read_input_tokens: 0,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_across_distinct_connections_all_succeed() {
        // Regression for "database is locked" errors surfaced in the
        // 0.7.9 signal smoke test. Two separate `SqliteSessionLog`
        // instances on the same file now coexist because the WAL +
        // busy_timeout pragmas are set on every open. Before the
        // fix, the second writer errored immediately with
        // `SQLITE_BUSY` and the error text surfaced to the user via
        // the channel adapter.
        use crate::SessionLog;
        use crate::session_log::{SessionEvent, SessionId, SqliteSessionLog, TrustLevel};
        use std::sync::Arc;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("concurrency.db");

        // Two independent opens on the same file — mirrors the
        // production case where AuditWriter::flush opens a fresh
        // log every 50ms while the agent holds its own handle.
        let log_a = Arc::new(SqliteSessionLog::open(&db_path).unwrap());
        let log_b = Arc::new(SqliteSessionLog::open(&db_path).unwrap());

        let handle_a = log_a.handle_for(SessionId::new("sess-a".to_string()));
        let handle_b = log_b.handle_for(SessionId::new("sess-b".to_string()));

        let a_clone = log_a.clone();
        let b_clone = log_b.clone();

        let task_a = tokio::spawn(async move {
            for i in 0..50 {
                a_clone
                    .append(
                        &handle_a,
                        TrustLevel::User,
                        SessionEvent::AssistantMessage {
                            content: format!("a-{i}"),
                        },
                    )
                    .expect("append via log_a must succeed under contention");
            }
        });
        let task_b = tokio::spawn(async move {
            for i in 0..50 {
                b_clone
                    .append(
                        &handle_b,
                        TrustLevel::User,
                        SessionEvent::AssistantMessage {
                            content: format!("b-{i}"),
                        },
                    )
                    .expect("append via log_b must succeed under contention");
            }
        });

        let (ra, rb) = tokio::join!(task_a, task_b);
        ra.unwrap();
        rb.unwrap();

        // Both sessions' chains are intact and contain exactly the
        // rows each task wrote.
        let probe_a = log_a.handle_for(SessionId::new("sess-a".to_string()));
        let probe_b = log_a.handle_for(SessionId::new("sess-b".to_string()));
        assert_eq!(log_a.last_index(&probe_a).unwrap(), Some(49));
        assert_eq!(log_a.last_index(&probe_b).unwrap(), Some(49));
    }

    #[test]
    fn permission_denied_deserializes_without_action_key() {
        // Legacy rows written before `action_key` was added must
        // still deserialize; the field defaults to an empty string.
        let legacy = r#"{"kind":"permission_denied","tool":"exec","tier":"tier3","agent_id":"default","trigger":"hi"}"#;
        let event: SessionEvent = serde_json::from_str(legacy).unwrap();
        match event {
            SessionEvent::PermissionDenied {
                tool,
                action_key,
                tier,
                agent_id,
                trigger,
            } => {
                assert_eq!(tool, "exec");
                assert_eq!(action_key, "");
                assert_eq!(tier, "tier3");
                assert_eq!(agent_id, "default");
                assert_eq!(trigger.as_deref(), Some("hi"));
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn llm_response_round_trips_with_cache_fields() {
        let (log, h) = fresh();
        log.append(
            &h,
            TrustLevel::System,
            SessionEvent::LlmResponse {
                request_id: "req-cache".into(),
                finish_reason: "end_turn".into(),
                tokens_in: 1234,
                tokens_out: 567,
                cache_creation_input_tokens: 800,
                cache_read_input_tokens: 9000,
                latency_ms: 42,
            },
        )
        .unwrap();
        let events = log.get_range(&h, 0..1).unwrap();
        match &events[0].event {
            SessionEvent::LlmResponse {
                tokens_in,
                tokens_out,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                ..
            } => {
                assert_eq!(*tokens_in, 1234);
                assert_eq!(*tokens_out, 567);
                assert_eq!(*cache_creation_input_tokens, 800);
                assert_eq!(*cache_read_input_tokens, 9000);
            }
            other => panic!("expected LlmResponse, got {other:?}"),
        }
    }

    #[test]
    fn llm_response_deserializes_without_cache_fields() {
        // Legacy rows written before the cache fields were added
        // (and rows from non-anthropic providers, which never carry
        // cache info) must still deserialize; both fields default
        // to zero.
        let legacy = r#"{"kind":"llm_response","request_id":"req-1","finish_reason":"end_turn","tokens_in":100,"tokens_out":50,"latency_ms":1234}"#;
        let event: SessionEvent = serde_json::from_str(legacy).unwrap();
        match event {
            SessionEvent::LlmResponse {
                tokens_in,
                tokens_out,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                ..
            } => {
                assert_eq!(tokens_in, 100);
                assert_eq!(tokens_out, 50);
                assert_eq!(cache_creation_input_tokens, 0);
                assert_eq!(cache_read_input_tokens, 0);
            }
            other => panic!("expected LlmResponse, got {other:?}"),
        }
    }

    #[test]
    fn llm_response_omits_zero_cache_fields_on_serialize() {
        // The skip_serializing_if predicate keeps the wire format
        // tight for non-cached responses (every openai/gemini/bedrock
        // response, plus any anthropic response with no cache hit).
        let event = SessionEvent::LlmResponse {
            request_id: "r".into(),
            finish_reason: "end_turn".into(),
            tokens_in: 10,
            tokens_out: 5,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            latency_ms: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("cache_creation_input_tokens"),
            "zero cache_creation_input_tokens should be skipped: {json}"
        );
        assert!(
            !json.contains("cache_read_input_tokens"),
            "zero cache_read_input_tokens should be skipped: {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// Chain-head signing regressions
// ---------------------------------------------------------------------------

#[cfg(test)]
mod chain_head_signing {
    use std::sync::Arc;

    use rusqlite::params;

    use crate::log::{AuditLog, VerifyResult};
    use crate::session_log::{
        ChainHeadReason, SessionEvent, SessionHandle, SessionId, SessionLog, SqliteSessionLog,
        TrustLevel,
    };
    use crate::signing::{AuditSigningKey, CHAIN_HEAD_SCHEMA_VERSION, build_signed_message};

    fn user_msg(s: &str) -> SessionEvent {
        SessionEvent::UserMessage {
            content: s.into(),
            inbound_id: None,
        }
    }

    fn fresh_signed() -> (
        Arc<SqliteSessionLog>,
        SessionHandle<crate::session_log::OwnSession>,
        Arc<AuditSigningKey>,
    ) {
        let signer = Arc::new(AuditSigningKey::generate());
        let log = SqliteSessionLog::open_in_memory_with_signer(signer.clone()).unwrap();
        let log = Arc::new(log);
        let h = log.handle_for(SessionId::new("sig-sess"));
        (log, h, signer)
    }

    /// Session-start fires a SessionStart head on the first append.
    /// Verifier confirms one signed head and zero invalid signatures.
    #[test]
    fn session_start_emits_signed_chain_head() {
        let (log, h, signer) = fresh_signed();
        log.append(&h, TrustLevel::User, user_msg("hello")).unwrap();

        let rows = log.get_since(&h, 0).unwrap();
        assert_eq!(rows.len(), 2, "regular event then SessionStart head");
        match &rows[1].event {
            SessionEvent::ChainHead {
                reason,
                signing_key_id,
                schema_version,
                ..
            } => {
                assert_eq!(*reason, ChainHeadReason::SessionStart);
                assert_eq!(*schema_version, CHAIN_HEAD_SCHEMA_VERSION);
                assert_eq!(signing_key_id.0, signer.key_id_hex());
            }
            other => panic!("expected ChainHead at seq 1, got {other:?}"),
        }

        let sig = log.verify_signatures(&h).unwrap();
        assert_eq!(sig.signed_heads_count, 1);
        assert!(sig.first_invalid.is_none());
        assert_eq!(sig.signing_key_ids_seen.len(), 1);
    }

    /// Tampering with a ChainHead's claimed current_chain_hash makes
    /// the signature payload mismatch the row's stored chain hash.
    /// The verifier hard-fails on signature check.
    #[test]
    fn tampered_chain_head_current_hash_rejected_by_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("audit.db");
        let signer = Arc::new(AuditSigningKey::generate());
        let log = AuditLog::open_with_signer(&db_path, signer.clone()).unwrap();
        let inner = log.session_log();
        let handle = inner.handle_for(SessionId::new("tampered"));
        inner
            .append(&handle, TrustLevel::User, user_msg("first"))
            .unwrap();

        // Locate the SessionStart head and corrupt its current_chain_hash
        // claim by editing the payload JSON directly. The chain hash and
        // leaf hash on the row are recomputed so the chain check itself
        // still passes; only the signature pass surfaces the break.
        let conn = inner.raw_conn_for_test().lock().unwrap();
        let (id, payload, prev_hash): (i64, String, String) = conn
            .query_row(
                "SELECT id, payload, prev_hash FROM session_events
                 WHERE session_id = 'tampered' AND seq = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        let mut payload_json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        payload_json["current_chain_hash"] = serde_json::Value::String("a".repeat(64));
        let new_payload = serde_json::to_string(&payload_json).unwrap();
        let new_leaf = sha256_hex(new_payload.as_bytes());
        let new_chain = chain_hash(&prev_hash, &new_leaf);
        conn.execute(
            "UPDATE session_events
             SET payload = ?1, leaf_hash = ?2, hash = ?3
             WHERE id = ?4",
            params![new_payload, new_leaf, new_chain, id],
        )
        .unwrap();
        drop(conn);

        match log.verify().unwrap() {
            VerifyResult::SignatureInvalid { reason, .. } => {
                assert!(
                    reason.contains("current_chain_hash") || reason.contains("ed25519"),
                    "reason should cite the failing check, got: {reason}"
                );
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// Removing every ChainHead row from a session is a hard fail
    /// under --require-signed. Without --require-signed the verifier
    /// reports the session as transition-era.
    #[test]
    fn missing_chain_head_hard_fails_under_require_signed() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("audit.db");
        let signer = Arc::new(AuditSigningKey::generate());
        let log = AuditLog::open_with_signer(&db_path, signer.clone()).unwrap();
        let inner = log.session_log();
        let handle = inner.handle_for(SessionId::new("losing-heads"));
        inner
            .append(&handle, TrustLevel::User, user_msg("alpha"))
            .unwrap();
        inner
            .append(&handle, TrustLevel::User, user_msg("beta"))
            .unwrap();

        // Strip every ChainHead row. The chain over the surviving
        // events still needs to recompute correctly, so we rebuild
        // each leaf/prev/chain hash from the surviving payloads.
        let conn = inner.raw_conn_for_test().lock().unwrap();
        conn.execute(
            "DELETE FROM session_events
             WHERE session_id = 'losing-heads'
               AND payload LIKE '%\"chain_head\"%'",
            [],
        )
        .unwrap();
        // Renumber + rehash the survivors as a fresh chain so
        // verify() does not fail on chain integrity before reaching
        // the signature pass.
        let surviving: Vec<(i64, u64, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, seq, payload FROM session_events
                     WHERE session_id = 'losing-heads'
                     ORDER BY seq ASC",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap();
            rows.filter_map(|r| r.ok()).collect()
        };
        let mut prev = String::new();
        for (idx, (id, _old_seq, payload)) in surviving.iter().enumerate() {
            let leaf = sha256_hex(payload.as_bytes());
            let chain = chain_hash(&prev, &leaf);
            conn.execute(
                "UPDATE session_events
                 SET seq = ?1, leaf_hash = ?2, prev_hash = ?3, hash = ?4
                 WHERE id = ?5",
                params![idx as i64, leaf, prev.clone(), chain.clone(), id],
            )
            .unwrap();
            prev = chain;
        }
        drop(conn);

        match log.verify().unwrap() {
            VerifyResult::Ok {
                sessions_with_no_signed_heads,
                signed_heads_count,
                ..
            } => {
                assert_eq!(sessions_with_no_signed_heads, 1);
                assert_eq!(signed_heads_count, 0);
            }
            other => panic!("transition-era verify expected Ok, got {other:?}"),
        }

        match log.verify_require_signed().unwrap() {
            VerifyResult::MissingChainHead { session_id, .. } => {
                assert_eq!(session_id.as_str(), "losing-heads");
            }
            other => panic!("require-signed verify expected MissingChainHead, got {other:?}"),
        }
    }

    /// Signing-key rotation across two sessions: each session is
    /// signed by a different key, the verifier accepts both, and
    /// signing_key_ids_seen contains both ids.
    #[test]
    fn signing_key_rotation_across_two_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("audit.db");
        let signer_a = Arc::new(AuditSigningKey::generate());
        let signer_b = Arc::new(AuditSigningKey::generate());
        assert_ne!(signer_a.key_id_hex(), signer_b.key_id_hex());

        // First session under signer A.
        {
            let log = AuditLog::open_with_signer(&db_path, signer_a.clone()).unwrap();
            let inner = log.session_log();
            let h = inner.handle_for(SessionId::new("rot-A"));
            inner.append(&h, TrustLevel::User, user_msg("a-1")).unwrap();
        }
        // Second session under signer B against the same DB.
        {
            let log = AuditLog::open_with_signer(&db_path, signer_b.clone()).unwrap();
            let inner = log.session_log();
            let h = inner.handle_for(SessionId::new("rot-B"));
            inner.append(&h, TrustLevel::User, user_msg("b-1")).unwrap();
        }

        let log = AuditLog::open_with_signer(&db_path, signer_a.clone()).unwrap();
        match log.verify().unwrap() {
            VerifyResult::Ok {
                signing_key_ids_seen,
                signed_heads_count,
                ..
            } => {
                assert_eq!(signed_heads_count, 2);
                assert_eq!(signing_key_ids_seen.len(), 2);
                assert!(signing_key_ids_seen.contains(&signer_a.key_id_hex()));
                assert!(signing_key_ids_seen.contains(&signer_b.key_id_hex()));
            }
            other => panic!("rotation verify expected Ok, got {other:?}"),
        }
    }

    /// Cadence path 1: append-count trigger fires before any
    /// wall-clock elapsed. The SessionStart head at iter 0 resets
    /// the counter to 0, so iters 1..=1000 are what bump the
    /// counter against the >= 1000 threshold; the loop runs 1001
    /// times so the threshold is reached on the last iteration.
    #[test]
    fn cadence_appends_path_emits_checkpoint() {
        let (log, h, _signer) = fresh_signed();
        for i in 0..=1000 {
            log.append(&h, TrustLevel::User, user_msg(&format!("m{i}")))
                .unwrap();
        }

        let rows = log.get_since(&h, 0).unwrap();
        let chain_heads: Vec<&crate::session_log::SessionEvent> = rows
            .iter()
            .map(|r| &r.event)
            .filter(|e| matches!(e, SessionEvent::ChainHead { .. }))
            .collect();
        assert!(
            chain_heads.len() >= 2,
            "expected SessionStart + at least one Checkpoint head, got {} heads",
            chain_heads.len()
        );
        let has_checkpoint = chain_heads.iter().any(|e| {
            matches!(
                e,
                SessionEvent::ChainHead {
                    reason: ChainHeadReason::Checkpoint,
                    ..
                }
            )
        });
        assert!(has_checkpoint, "expected at least one Checkpoint head");
    }

    /// Cadence path 2: wall-clock trigger fires before the append
    /// counter reaches 1000. Backdate the session's last_head_ts by
    /// 6 minutes (above the 5-minute threshold), then a single
    /// append is enough to trip a Checkpoint head.
    #[test]
    fn cadence_wall_clock_path_emits_checkpoint() {
        let (log, h, _signer) = fresh_signed();
        log.append(&h, TrustLevel::User, user_msg("warm")).unwrap();
        // After SessionStart there are two rows. Backdate so the next
        // append's checkpoint_due check sees > 5 minutes elapsed.
        log.backdate_checkpoint_for_test(h.id().as_str(), 360);
        log.append(&h, TrustLevel::User, user_msg("triggers"))
            .unwrap();

        let rows = log.get_since(&h, 0).unwrap();
        let checkpoint_count = rows
            .iter()
            .filter(|r| {
                matches!(
                    r.event,
                    SessionEvent::ChainHead {
                        reason: ChainHeadReason::Checkpoint,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            checkpoint_count, 1,
            "elapsed-time path should emit exactly one Checkpoint head"
        );
    }

    /// Shutdown emission: emit_chain_head(SessionEnd) writes a
    /// signed terminal head. Mirrors the gateway's SIGTERM path.
    #[test]
    fn session_end_emit_writes_signed_terminal_head() {
        let (log, h, signer) = fresh_signed();
        log.append(&h, TrustLevel::User, user_msg("only-msg"))
            .unwrap();
        let seq = log
            .emit_chain_head(&h, ChainHeadReason::SessionEnd)
            .unwrap()
            .expect("signer present");

        let rows = log.get_since(&h, 0).unwrap();
        let last = rows.last().unwrap();
        assert_eq!(last.seq, seq);
        match &last.event {
            SessionEvent::ChainHead {
                reason,
                signing_key_id,
                ..
            } => {
                assert_eq!(*reason, ChainHeadReason::SessionEnd);
                assert_eq!(signing_key_id.0, signer.key_id_hex());
            }
            other => panic!("expected ChainHead, got {other:?}"),
        }

        let sig = log.verify_signatures(&h).unwrap();
        assert_eq!(sig.unsigned_tail_len, 0);
        assert!(sig.first_invalid.is_none());
    }

    /// Build_signed_message round-trip used by tampering tests:
    /// confirms the verifier's canonical layout matches signing.
    #[test]
    fn signed_message_layout_round_trip() {
        let key = AuditSigningKey::generate();
        let sig = key.sign_chain_head((10, 20), "deadbeef", "feedface");
        let msg = build_signed_message((10, 20), "deadbeef", "feedface", CHAIN_HEAD_SCHEMA_VERSION);
        use ed25519_dalek::Verifier;
        key.verifying_key().verify(&msg, &sig).unwrap();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut s = String::with_capacity(out.len() * 2);
        for b in out.iter() {
            use std::fmt::Write;
            write!(&mut s, "{b:02x}").unwrap();
        }
        s
    }

    fn chain_hash(prev: &str, leaf: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update(leaf.as_bytes());
        let out = h.finalize();
        let mut s = String::with_capacity(out.len() * 2);
        for b in out.iter() {
            use std::fmt::Write;
            write!(&mut s, "{b:02x}").unwrap();
        }
        s
    }
}
