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

    // Tamper with row 5's hash
    drop(log);
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE audit_events SET hash = 'tampered' WHERE id = 5", [])
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

    // Tamper with row 3's action (but leave the hash unchanged)
    drop(log);
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE audit_events SET action = 'HACKED' WHERE id = 3", [])
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

    // Insert events with timestamps in the past
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let old_ts = (Utc::now() - Duration::days(100)).to_rfc3339();
    let recent_ts = Utc::now().to_rfc3339();

    for i in 0..5 {
        conn.execute(
            "INSERT INTO audit_events (ts, actor, action, target, channel, session, detail, hash)
             VALUES (?1, 'actor', ?2, 'target', '', '', 'null', ?3)",
            rusqlite::params![old_ts, format!("old-{i}"), format!("hash-old-{i}")],
        )
        .unwrap();
    }
    for i in 0..3 {
        conn.execute(
            "INSERT INTO audit_events (ts, actor, action, target, channel, session, detail, hash)
             VALUES (?1, 'actor', ?2, 'target', '', '', 'null', ?3)",
            rusqlite::params![recent_ts, format!("new-{i}"), format!("hash-new-{i}")],
        )
        .unwrap();
    }
    drop(conn);

    let log2 = AuditLog::open(&db_path).unwrap();
    let deleted = log2.prune(90).unwrap();
    assert_eq!(deleted, 5);

    let remaining = log.query(&AuditQuery::default()).unwrap();
    assert_eq!(remaining.len(), 3);
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
