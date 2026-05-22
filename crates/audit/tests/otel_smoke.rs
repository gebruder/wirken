//! Local OTLP receiver round-trip smoke test for issue #130.
//!
//! Proves what the unit tests cannot: that a span emitted by the
//! projector, serialized by the OTLP module, posted over a real
//! TCP socket, and ingested by a standards-compliant OTLP receiver,
//! comes back out the other side with its operation name, parent
//! chain, and key attributes intact. Catches the class of failure
//! that only breaks across a real serialization boundary, where a
//! JSON shape the wirken serializer emits and the wirken parser
//! would accept might still be rejected or mangled by a conformant
//! receiver.
//!
//! ## Operator-launched container
//!
//! Matches the existing wirken E2E convention (see
//! `WIRKEN_SIGNAL_E2E` in `crates/adapter-signal/src/tests.rs`).
//! The operator runs the container by hand and sets the gate env
//! var; the test does not provision Docker. Three reasons for
//! preferring this shape over `testcontainers-rs`:
//!
//! 1. wirken has one Docker-gated test in the tree today and the
//!    signal-cli E2E test established the operator-launched
//!    pattern; a second test that follows the same shape keeps
//!    the convention consistent rather than fragmented.
//! 2. The `#[ignore]` plus opt-in env-var gate means CI without
//!    Docker stays green by default; the operator opts in
//!    deliberately and is expected to have prerequisites ready,
//!    same posture as the signal E2E.
//! 3. If wirken accumulates several Docker-gated tests, migrating
//!    them together to a testcontainers wrapper becomes a uniform
//!    change rather than an ad-hoc addition for one test.
//!
//! ## To run
//!
//! ```text
//! docker run -d --name jaeger \
//!   -e COLLECTOR_OTLP_ENABLED=true \
//!   -p 4318:4318 \
//!   -p 16686:16686 \
//!   jaegertracing/all-in-one:latest
//!
//! WIRKEN_OTEL_E2E=1 cargo test --test otel_smoke -- --ignored
//!
//! docker stop jaeger && docker rm jaeger
//! ```
//!
//! Override the defaults via env if the operator's container runs
//! on different ports:
//!
//! - `WIRKEN_OTEL_COLLECTOR_ENDPOINT` (default
//!   `http://127.0.0.1:4318/v1/traces`): the OTLP/HTTP+JSON
//!   receiver the forwarder POSTs to.
//! - `WIRKEN_OTEL_QUERY_ENDPOINT` (default
//!   `http://127.0.0.1:16686/api/traces`): the read-back endpoint.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;

use wirken_audit::otel_exporter::{OtelConfig, StaticFederatedIdentity};
use wirken_audit::otel_forwarder::{OtelForwarder, ReqwestPoster};
use wirken_audit::otel_projector::OtelProjector;
use wirken_audit::user_resolver::DeterministicUserResolver;
use wirken_audit::{HashHex, SessionEvent, SessionId, StoredSessionEvent, TrustLevel};

const DEFAULT_COLLECTOR_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
const DEFAULT_QUERY_ENDPOINT: &str = "http://127.0.0.1:16686/api/traces";
const READBACK_POLL_INTERVAL: Duration = Duration::from_millis(500);
const READBACK_TIMEOUT: Duration = Duration::from_secs(15);

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(seconds, 0).unwrap()
}

fn zero_hash() -> HashHex {
    HashHex::from_bytes(&[0u8; 32])
}

fn stored(
    seq: u64,
    session_id: &SessionId,
    event: SessionEvent,
    ts_seconds: i64,
) -> StoredSessionEvent {
    let h = zero_hash();
    StoredSessionEvent {
        id: seq as i64,
        session_id: session_id.clone(),
        seq,
        ts: at(ts_seconds),
        trust: TrustLevel::System,
        event,
        leaf_hash: h.clone(),
        prev_hash: h.clone(),
        hash: h,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn round_trip_against_local_otlp_receiver() {
    if std::env::var("WIRKEN_OTEL_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipping: WIRKEN_OTEL_E2E=1 not set");
        return;
    }
    let collector_endpoint = std::env::var("WIRKEN_OTEL_COLLECTOR_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_COLLECTOR_ENDPOINT.to_string());
    let query_endpoint = std::env::var("WIRKEN_OTEL_QUERY_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_QUERY_ENDPOINT.to_string());

    // Per-test-unique conversation id so the read-back query can
    // isolate this test's spans from anything else the receiver
    // has retained. Nanosecond-resolution timestamp is unique
    // enough for a sequential test run; avoiding the uuid crate
    // keeps the test from adding a dev-dep just for one identifier.
    let conversation_id = format!("smoke-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0),);
    let session_id = SessionId::new(conversation_id.clone());

    // Build a canonical two-span run: UserMessage opens, then
    // AssistantMessage closes. The projector emits an
    // output_messages child and an invoke_agent root. Two spans
    // is the minimum that exercises the parent-chain assertion.
    let rows = vec![
        stored(
            0,
            &session_id,
            SessionEvent::UserMessage {
                content: "smoke test question".to_string(),
                inbound_id: None,
                adapter_id: None,
                sender_id: None,
            },
            0,
        ),
        stored(
            1,
            &session_id,
            SessionEvent::AssistantMessage {
                content: "smoke test answer".to_string(),
                agent_id: "default".to_string(),
            },
            1,
        ),
    ];

    let config = OtelConfig {
        endpoint: collector_endpoint.clone(),
        ..OtelConfig::default()
    };
    let projector = OtelProjector::new(config.clone(), Arc::new(DeterministicUserResolver));
    let identity = Arc::new(StaticFederatedIdentity::new(
        "smoke-tenant",
        "smoke-agent",
        "smoke-token",
        vec![
            ("gen_ai.agent.id".to_string(), "smoke-agent".to_string()),
            ("gen_ai.agent.name".to_string(), "wirken-smoke".to_string()),
            (
                "microsoft.tenant.id".to_string(),
                "smoke-tenant".to_string(),
            ),
            (
                "microsoft.a365.agent.blueprint.id".to_string(),
                "smoke-agent".to_string(),
            ),
        ],
    ));
    let poster = Arc::new(ReqwestPoster::new(reqwest::Client::new()));
    let mut forwarder = OtelForwarder::new(config, projector, identity, poster);

    forwarder
        .process_session_events(&session_id, rows)
        .await
        .expect("forwarder must accept the round; if this is the failure, the receiver rejected the wire shape");
    assert_eq!(
        forwarder.cursor_for(&session_id),
        2,
        "cursor must have advanced past both rows on the 2xx response",
    );

    let spans = read_back_spans(&query_endpoint, &conversation_id)
        .await
        .expect(
            "spans must surface in the receiver within the poll window; if they do not, the receiver accepted the POST but did not retain the spans, which is the silent-drop failure mode this test exists to catch",
        );

    assert_round_trip(&spans, &conversation_id);
}

/// Poll the read-back endpoint until the receiver surfaces a
/// trace matching the per-test conversation id. Returns the
/// parsed spans array as the receiver exposed them.
///
/// Filters are applied client-side rather than via the receiver's
/// tag-filter query parameter. The receiver's filter syntax
/// (Jaeger versus other backends) is the kind of thing that
/// silently changes across versions and would couple the test to
/// a specific receiver release; scanning the response and matching
/// the conversation id on the wirken side is contract-stable.
async fn read_back_spans(
    query_endpoint: &str,
    conversation_id: &str,
) -> Result<Vec<Value>, String> {
    let client = reqwest::Client::new();
    // The serializer puts `service.name=wirken` on the resource,
    // so querying by service narrows the read-back to our spans.
    let url = format!("{query_endpoint}?service=wirken&limit=50");
    let deadline = Instant::now() + READBACK_TIMEOUT;
    loop {
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("query GET failed: {e}"))?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("query body parse failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("query returned {status}: {body}"));
        }
        let traces = body["data"].as_array().cloned().unwrap_or_default();
        for trace in &traces {
            if let Some(spans) = trace["spans"].as_array()
                && spans
                    .iter()
                    .any(|s| span_tag_value(s, "gen_ai.conversation.id") == Some(conversation_id))
            {
                return Ok(spans.clone());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no trace matching conversation_id={conversation_id} surfaced within {READBACK_TIMEOUT:?}; the receiver accepted the POST but did not expose the spans",
            ));
        }
        tokio::time::sleep(READBACK_POLL_INTERVAL).await;
    }
}

fn span_tag_value<'a>(span: &'a Value, key: &str) -> Option<&'a str> {
    span["tags"]
        .as_array()
        .and_then(|arr| arr.iter().find(|t| t["key"].as_str() == Some(key)))
        .and_then(|t| t["value"].as_str())
}

fn assert_round_trip(spans: &[Value], conversation_id: &str) {
    // Two spans expected: output_messages child plus invoke_agent
    // root. The receiver may return them in any order.
    assert_eq!(
        spans.len(),
        2,
        "expected the two-span canonical run (output_messages + invoke_agent root); got {} spans",
        spans.len(),
    );

    let by_op = |name: &str| -> &Value {
        spans
            .iter()
            .find(|s| s["operationName"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing span with operationName={name}"))
    };
    let root = by_op("invoke_agent");
    let output = by_op("output_messages");

    // Root has no parent. Jaeger represents this either by an
    // empty references array or by a zero-spanID; tolerate both.
    let root_parent_refs = root["references"].as_array().cloned().unwrap_or_default();
    let root_parent_id = root_parent_refs
        .iter()
        .find(|r| r["refType"] == "CHILD_OF")
        .and_then(|r| r["spanID"].as_str())
        .map(str::to_string);
    assert!(
        root_parent_id.is_none() || root_parent_id.as_deref() == Some("0"),
        "invoke_agent root must have no parent reference; got {root_parent_id:?}",
    );

    let root_span_id = root["spanID"]
        .as_str()
        .expect("root must have a spanID")
        .to_string();
    let output_parent_refs = output["references"].as_array().cloned().unwrap_or_default();
    let output_parent_id = output_parent_refs
        .iter()
        .find(|r| r["refType"] == "CHILD_OF")
        .and_then(|r| r["spanID"].as_str())
        .map(str::to_string);
    assert_eq!(
        output_parent_id.as_deref(),
        Some(root_span_id.as_str()),
        "output_messages must reference the invoke_agent root as CHILD_OF; got parent {output_parent_id:?}",
    );

    let root_tag = |key: &str| -> String {
        root["tags"]
            .as_array()
            .and_then(|arr| arr.iter().find(|t| t["key"].as_str() == Some(key)))
            .and_then(|t| t["value"].as_str().map(str::to_string))
            .unwrap_or_else(|| {
                panic!(
                    "root span must carry tag {key}; tags on root: {tags}",
                    tags = root["tags"]
                )
            })
    };

    // Conversation id preserved verbatim.
    assert_eq!(root_tag("gen_ai.conversation.id"), conversation_id);
    // Operation name attribute matches the span name.
    assert_eq!(root_tag("gen_ai.operation.name"), "invoke_agent");
    // Identity attributes passed through from FederatedIdentity::span_attributes.
    assert_eq!(root_tag("gen_ai.agent.id"), "smoke-agent");
    assert_eq!(root_tag("microsoft.tenant.id"), "smoke-tenant");
    // Run-wide attrs the projector synthesizes.
    assert_eq!(root_tag("microsoft.channel.name"), "internal");
    // Input and output messages carried verbatim on the root.
    assert_eq!(root_tag("gen_ai.input.messages"), "smoke test question");
    assert_eq!(root_tag("gen_ai.output.messages"), "smoke test answer");
    // The picking-values placeholder for callers without an IP.
    assert_eq!(root_tag("client.address"), "0.0.0.0");
}
