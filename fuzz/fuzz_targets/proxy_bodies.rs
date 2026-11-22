//! The export of a proxied session, on arbitrary request and response
//! bodies.
//!
//! The proxy listener's HTTP is parsed by a library. What is read by
//! hand is what travels inside it: a request body a client chose and a
//! response body a provider chose, each JSON or a stream of
//! server-sent events in one of two providers' shapes. `sessions
//! export` reads both to rebuild the conversation, and the proxy reads
//! a request's messages to tell one conversation from another. Neither
//! body is vetted by anything before that.
//!
//! The input is a shape byte, then the request body, a NUL, and the
//! response body.
//!
//! Asserted, beyond no panic:
//!
//! - Whatever the bodies hold, the export is a valid trajectory. A
//!   body that makes the exporter write a document its own validator
//!   refuses is a finding: `sessions export` would refuse to write the
//!   session.
//! - The export is deterministic: the same rows and bodies twice are
//!   the same document twice.
//! - A request's conversation chain has one hash for each message.
//!
//! A crash is a finding. Do not relax the validator to make a case
//! pass.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use wirken_audit::atif::{Body, Producer, conversation_chain, export, validate};
use wirken_audit::{
    HashHex, ProxyShape, SessionEvent, SessionId, StoredSessionEvent, TrustLevel,
};

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn row(seq: u64, event: SessionEvent) -> StoredSessionEvent {
    StoredSessionEvent {
        id: seq as i64,
        session_id: SessionId::new("proxy-fuzz"),
        seq,
        ts: "2026-01-01T00:00:00Z".parse().expect("a timestamp"),
        trust: TrustLevel::System,
        event,
        leaf_hash: HashHex(String::new()),
        prev_hash: HashHex(String::new()),
        hash: HashHex(String::new()),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let shape = if shape & 1 == 0 {
        ProxyShape::OpenaiChat
    } else {
        ProxyShape::AnthropicMessages
    };
    let split = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    let (request, response) = (&rest[..split], rest.get(split + 1..).unwrap_or_default());

    if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(request) {
        let messages = parsed["messages"].as_array().map_or(0, Vec::len);
        assert_eq!(conversation_chain(&parsed).len(), messages);
    }

    // Two calls with the same bodies: the second repeats the first's
    // conversation, which is the path that decides what a later
    // request adds.
    let mut rows = Vec::new();
    for (i, id) in ["r1", "r2"].into_iter().enumerate() {
        let seq = i as u64 * 2 + 1;
        rows.push(row(
            seq,
            SessionEvent::ProxyRequest {
                request_id: id.into(),
                token_id: "tok".into(),
                token_name: "fuzz".into(),
                upstream: "u".into(),
                provider: "p".into(),
                model: "m".into(),
                shape,
                stream: false,
                request_sha256: HashHex(sha(request)),
                request_bytes: request.len() as u64,
                credential_id: None,
                archived: true,
            },
        ));
        rows.push(row(
            seq + 1,
            SessionEvent::ProxyResponse {
                request_id: id.into(),
                token_id: "tok".into(),
                status: 200,
                latency_ms: 1,
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                total_cost_usd_micros: None,
                response_sha256: HashHex(sha(response)),
                response_bytes: response.len() as u64,
                complete: true,
                archived: true,
            },
        ));
    }
    let bodies: HashMap<String, Body> = HashMap::from([
        (sha(request), Body::Plain(request.to_vec())),
        (sha(response), Body::Plain(response.to_vec())),
    ]);
    let producer = Producer {
        name: "wirken",
        version: "fuzz",
    };

    let first = export("proxy-fuzz", &rows, &bodies, &producer);
    let errors = validate(&first);
    assert!(
        errors.is_empty(),
        "the export of these bodies is not a valid trajectory: {errors:?}"
    );
    assert_eq!(first, export("proxy-fuzz", &rows, &bodies, &producer));
});
