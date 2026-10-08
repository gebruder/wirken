//! A chain head whose signature field is not ASCII hex is reported as
//! an invalid signature, with the exit code `audit verify` uses for
//! one, rather than crashing the verifier.

mod common;

use std::sync::Arc;

use common::wirken;
use sha2::{Digest, Sha256};
use wirken_audit::signing::AuditSigningKey;
use wirken_audit::{AuditLog, SessionId, SessionLog, TrustLevel};

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn non_ascii_signature_exits_as_signature_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    let db = data.join("audit.db");

    {
        let log = AuditLog::open_with_signer(&db, Arc::new(AuditSigningKey::generate())).unwrap();
        let inner = log.session_log();
        let handle = inner.handle_for(SessionId::new("malformed-sig"));
        inner
            .append(
                &handle,
                TrustLevel::User,
                wirken_audit::SessionEvent::UserMessage {
                    content: "first".into(),
                    inbound_id: None,
                    adapter_id: None,
                    sender_id: None,
                },
            )
            .unwrap();
    }

    // Rewrite the SessionStart head's signature and recompute the row's
    // hashes, so the chain check passes and the signature pass runs.
    // `"a\u{e9}a"` is four bytes with a character spanning offsets 1..3.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let (id, payload, prev_hash): (i64, String, String) = conn
        .query_row(
            "SELECT id, payload, prev_hash FROM session_events
             WHERE session_id = 'malformed-sig' AND seq = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let mut event: serde_json::Value = serde_json::from_str(&payload).unwrap();
    event["signature"] = serde_json::Value::String("a\u{e9}a".into());
    let payload = event.to_string();
    let leaf = sha256_hex(&[payload.as_bytes()]);
    let hash = sha256_hex(&[prev_hash.as_bytes(), leaf.as_bytes()]);
    conn.execute(
        "UPDATE session_events SET payload = ?1, leaf_hash = ?2, hash = ?3 WHERE id = ?4",
        rusqlite::params![payload, leaf, hash, id],
    )
    .unwrap();
    drop(conn);

    let out = wirken(data).args(["audit", "verify"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.contains("SIGNATURE INVALID"), "{stdout}{stderr}");
    assert!(
        stdout.contains("signature is not 64 bytes of hex"),
        "{stdout}{stderr}"
    );
}
