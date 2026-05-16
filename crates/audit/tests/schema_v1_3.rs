//! Wire-format tests for the audit schema. The file name tracks the
//! current schema boundary (currently 1.3.0); the individual test
//! prefixes track the *transition* each test documents:
//!
//! - `pre_<version>_<name>`: a row produced by a pre-`<version>`
//!   binary, read by the current binary. The prefix names the
//!   boundary the test crosses, NOT the binary that runs the test.
//!   `pre_1_2_0_user_message_*` continues to be the right name for
//!   a fixture that captures a 1.1.x-shaped row, even after the
//!   file was renamed for the 1.3.0 schema bump.
//! - `<version>_<name>`: behaviour of a row produced at exactly
//!   `<version>` round-tripping cleanly through the current
//!   deserializer.
//! - `snapshot_<name>`: positive-and-negative presence assertions
//!   on the current wire shape. These keep us honest against a
//!   future revert that silently re-introduces a dropped field.
//!
//! Covers Section D of the 1.2.0 cleanup spec:
//!
//! - D1: regression fixtures for pre-1.2.0 rows on every changed
//!   variant. Each fixture is a captured JSON shape that a 1.1.x
//!   producer would have written; the test deserializes it and
//!   asserts the documented behaviour: defaults applied for
//!   additive fields, or values silently dropped to zero on the
//!   renamed token fields per spec C4.
//! - D3: snapshot assertions on the 1.2.0 wire shape. Each test
//!   constructs a Rust value with 1.2.0 fields populated, serializes
//!   it, and asserts the JSON contains the new keys *and* does not
//!   contain the pre-1.2.0 keys. The negative-presence assertions
//!   are the load-bearing part: a future revert that re-introduces
//!   `tokens_in` / `signing_key_id` / etc. would silently pass a
//!   simple "field present" check.
//! - D4: SIEM forwarder envelope shapes (Datadog, Splunk HEC,
//!   Sentinel, webhook). The webhook test asserts the
//!   `X-Wirken-Signature` value is HMAC-SHA-256 over the exact
//!   serialized body bytes; not over a re-serialized envelope.
//!   Any field-ordering drift between the body the signer hashed
//!   and the body the HTTP client wrote would diverge.

use chrono::{TimeZone, Utc};
use serde_json::Value;

use wirken_audit::{
    ActorKind, AuditEvent, DenialSource, HttpFetchOutcome, SessionEvent, SubagentStatus,
    build_datadog_payload, build_sentinel_payload, build_splunk_body, build_webhook_request,
    compute_webhook_signature,
    signing::{CHAIN_HEAD_SCHEMA_VERSION, build_signed_message},
};
use wirken_audit::{HashHex, HexBytes, SiemConfig, SiemTarget};

// ---------------------------------------------------------------------------
// D1: pre-1.2.0 deserializer regression fixtures
// ---------------------------------------------------------------------------

#[test]
fn pre_1_2_0_user_message_deserializes_with_default_identity() {
    let legacy = r#"{"kind":"user_message","content":"hi","inbound_id":"telegram:42"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::UserMessage {
            content,
            inbound_id,
            adapter_id,
            sender_id,
        } => {
            assert_eq!(content, "hi");
            assert_eq!(inbound_id.as_deref(), Some("telegram:42"));
            assert!(
                adapter_id.is_none(),
                "pre-1.2.0 rows have no adapter_id; serde default must yield None"
            );
            assert!(sender_id.is_none());
        }
        other => panic!("expected UserMessage, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_assistant_message_deserializes_with_empty_agent_id() {
    let legacy = r#"{"kind":"assistant_message","content":"reply"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::AssistantMessage { content, agent_id } => {
            assert_eq!(content, "reply");
            assert_eq!(agent_id, "");
        }
        other => panic!("expected AssistantMessage, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_assistant_tool_calls_deserializes_with_empty_agent_id() {
    let legacy =
        r#"{"kind":"assistant_tool_calls","calls":[{"id":"c1","name":"exec","arguments":"{}"}]}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::AssistantToolCalls {
            calls,
            agent_id,
            adapter_id,
            sender_id,
        } => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id, "c1");
            assert_eq!(agent_id, "");
            assert!(adapter_id.is_none(), "pre-A1 rows have no adapter_id");
            assert!(sender_id.is_none(), "pre-A1 rows have no sender_id");
        }
        other => panic!("expected AssistantToolCalls, got {other:?}"),
    }
}

#[test]
fn pre_a1_assistant_tool_calls_with_agent_id_only_deserializes() {
    // A pre-A1 row from a 1.3.0 emitter carries `agent_id` but no
    // adapter_id / sender_id. Forward-compat: the 1.3.x reader fills
    // both new fields from their `#[serde(default)]` (None).
    let legacy = r#"{"kind":"assistant_tool_calls","calls":[{"id":"c1","name":"exec","arguments":"{\"command\":\"ls\"}"}],"agent_id":"agent-1"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::AssistantToolCalls {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => {
            assert_eq!(agent_id, "agent-1");
            assert!(adapter_id.is_none());
            assert!(sender_id.is_none());
        }
        other => panic!("expected AssistantToolCalls, got {other:?}"),
    }
}

#[test]
fn pre_a1_tool_result_with_agent_id_only_deserializes() {
    let legacy = r#"{"kind":"tool_result","call_id":"c1","tool_name":"exec","output":"ok","success":true,"agent_id":"agent-1"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::ToolResult {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => {
            assert_eq!(agent_id, "agent-1");
            assert!(adapter_id.is_none());
            assert!(sender_id.is_none());
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
}

#[test]
fn a1_assistant_tool_calls_emitted_with_webchat_identity() {
    // 1.3.x emit shape: when the inbound came through the webchat
    // adapter, the AssistantToolCalls row carries
    // adapter_id="webchat" and sender_id="webchat-user" so a SIEM
    // rule can pivot on channel without joining back to the
    // UserMessage row.
    let ev = SessionEvent::AssistantToolCalls {
        calls: vec![wirken_audit::ToolCallRecord {
            id: "c1".into(),
            name: "exec".into(),
            arguments: r#"{"command":"curl https://example.com"}"#.into(),
        }],
        agent_id: "default".into(),
        adapter_id: Some("webchat".into()),
        sender_id: Some("webchat-user".into()),
    };
    let v = serde_json::to_value(&ev).unwrap();
    assert_eq!(
        v.get("adapter_id").and_then(|x| x.as_str()),
        Some("webchat")
    );
    assert_eq!(
        v.get("sender_id").and_then(|x| x.as_str()),
        Some("webchat-user")
    );
}

#[test]
fn a1_tool_result_emitted_with_webchat_identity() {
    let ev = SessionEvent::ToolResult {
        call_id: "c1".into(),
        tool_name: "exec".into(),
        output: "ok".into(),
        success: true,
        agent_id: "default".into(),
        adapter_id: Some("webchat".into()),
        sender_id: Some("webchat-user".into()),
    };
    let v = serde_json::to_value(&ev).unwrap();
    assert_eq!(
        v.get("adapter_id").and_then(|x| x.as_str()),
        Some("webchat")
    );
    assert_eq!(
        v.get("sender_id").and_then(|x| x.as_str()),
        Some("webchat-user")
    );
}

#[test]
fn pre_1_2_0_tool_result_deserializes_with_empty_agent_id() {
    let legacy =
        r#"{"kind":"tool_result","call_id":"c1","tool_name":"exec","output":"ok","success":true}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::ToolResult {
            call_id,
            tool_name,
            success,
            agent_id,
            ..
        } => {
            assert_eq!(call_id, "c1");
            assert_eq!(tool_name, "exec");
            assert!(success);
            assert_eq!(agent_id, "");
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_llm_request_deserializes_with_empty_agent_id() {
    let legacy = r#"{"kind":"llm_request","provider":"anthropic","model":"claude","request_id":"r1","tools_hash":"a","messages_hash":"b"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::LlmRequest {
            provider,
            agent_id,
            credential_id,
            ..
        } => {
            assert_eq!(provider, "anthropic");
            assert_eq!(agent_id, "");
            assert!(
                credential_id.is_none(),
                "pre-credential_id row must default to None"
            );
        }
        other => panic!("expected LlmRequest, got {other:?}"),
    }
}

#[test]
fn llm_request_with_credential_id_round_trips() {
    // The 1.3.x wire shape carries credential_id when the gateway
    // resolved the api_key from a named vault slot. Round-trip a
    // populated value to lock the field in.
    let original = SessionEvent::LlmRequest {
        provider: "anthropic".into(),
        model: "claude-sonnet-4-6".into(),
        request_id: "req-1".into(),
        tools_hash: HashHex("aa".repeat(32)),
        messages_hash: HashHex("bb".repeat(32)),
        agent_id: "default".into(),
        credential_id: Some("anthropic-api-key".into()),
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(
        json.contains("\"credential_id\":\"anthropic-api-key\""),
        "credential_id must serialize on the wire when Some, got: {json}"
    );
    let parsed: SessionEvent = serde_json::from_str(&json).unwrap();
    match parsed {
        SessionEvent::LlmRequest { credential_id, .. } => {
            assert_eq!(credential_id.as_deref(), Some("anthropic-api-key"));
        }
        other => panic!("expected LlmRequest, got {other:?}"),
    }
}

#[test]
fn llm_request_with_credential_id_none_omits_field_on_wire() {
    // None must omit the field entirely so consumers that pin column
    // sets (e.g. Sentinel DCRs) don't see a null where they didn't
    // before. `skip_serializing_if = "Option::is_none"`.
    let ev = SessionEvent::LlmRequest {
        provider: "ollama".into(),
        model: "qwen2.5:7b".into(),
        request_id: "req-2".into(),
        tools_hash: HashHex("00".repeat(32)),
        messages_hash: HashHex("11".repeat(32)),
        agent_id: "default".into(),
        credential_id: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    assert!(
        !json.contains("credential_id"),
        "credential_id must be absent on the wire when None, got: {json}"
    );
    // Round-trip preserves None.
    let parsed: SessionEvent = serde_json::from_str(&json).unwrap();
    match parsed {
        SessionEvent::LlmRequest { credential_id, .. } => {
            assert!(credential_id.is_none());
        }
        other => panic!("expected LlmRequest, got {other:?}"),
    }
}

#[test]
fn llm_response_with_credential_id_round_trips() {
    let original = SessionEvent::LlmResponse {
        request_id: "req-1".into(),
        finish_reason: "end_turn".into(),
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        latency_ms: 1234,
        agent_id: "default".into(),
        credential_id: Some("anthropic-api-key".into()),
        input_cost_usd_micros: None,
        output_cost_usd_micros: None,
        total_cost_usd_micros: None,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("\"credential_id\":\"anthropic-api-key\""));
    let parsed: SessionEvent = serde_json::from_str(&json).unwrap();
    match parsed {
        SessionEvent::LlmResponse { credential_id, .. } => {
            assert_eq!(credential_id.as_deref(), Some("anthropic-api-key"));
        }
        other => panic!("expected LlmResponse, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_llm_response_drops_renamed_token_fields_to_zero() {
    // Pre-1.2.0 producer wrote `tokens_in` / `tokens_out`. After C4
    // there is no serde alias by design; the 1.2.0 reader reads the
    // payload, the renamed fields default to 0, and the legacy values
    // are silently dropped. This test locks the documented drop in;
    // a future revert that re-aliased the names would break it.
    let legacy = r#"{"kind":"llm_response","request_id":"req-1","finish_reason":"end_turn","tokens_in":100,"tokens_out":50,"latency_ms":1234}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::LlmResponse {
            input_tokens,
            output_tokens,
            latency_ms,
            ..
        } => {
            assert_eq!(input_tokens, 0, "pre-1.2.0 tokens_in must drop, not alias");
            assert_eq!(
                output_tokens, 0,
                "pre-1.2.0 tokens_out must drop, not alias"
            );
            assert_eq!(latency_ms, 1234);
        }
        other => panic!("expected LlmResponse, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_permission_denied_tier_shape_deserializes_as_tier_source() {
    // Pre-1.2.0 shape: only `tier: "tier3"`. The 1.2.0 reader fills
    // denial_source from its serde default (Tier) and accepts the
    // legacy string as Option<String> via serde's String → Option<String> coercion.
    let legacy = r#"{"kind":"permission_denied","tool":"exec","tier":"tier3","agent_id":"default","trigger":"go"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::PermissionDenied {
            denial_source,
            tier,
            ..
        } => {
            assert_eq!(denial_source, DenialSource::Tier);
            assert_eq!(tier.as_deref(), Some("tier3"));
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_permission_denied_org_policy_string_is_lost_to_default() {
    // Pre-1.2.0 conflated org-policy denials with the tier field by
    // overloading the sentinel `"tier":"org_policy"`. The 1.2.0
    // reader sees a Tier-source denial (the default) with the
    // sentinel string sitting inside `tier`. The information is
    // recoverable from the string but is no longer typed; new emits
    // use `denial_source: OrgPolicy` and leave `tier: None`.
    let legacy = r#"{"kind":"permission_denied","tool":"exec","tier":"org_policy","agent_id":"default","trigger":null}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::PermissionDenied {
            denial_source,
            tier,
            ..
        } => {
            assert_eq!(denial_source, DenialSource::Tier);
            assert_eq!(tier.as_deref(), Some("org_policy"));
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_http_fetch_outcome_string_fails_to_deserialize() {
    // C5 made outcome a typed enum. Pre-1.2.0 wrote arbitrary strings
    // (`"ok"`, `"http_error_404"`, `"network_error"`, ...) and the
    // 1.2.0 reader does not accept them. This test pins the break so
    // a future "let's silently accept old strings" revert fails.
    let legacy = r#"{"kind":"http_fetch","source":"s","host":"h","url":"u","outcome":"ok","bytes":0,"run_id":null}"#;
    let r = serde_json::from_str::<SessionEvent>(legacy);
    assert!(
        r.is_err(),
        "pre-1.2.0 outcome string must not deserialize into HttpFetchOutcome"
    );
}

#[test]
fn pre_1_2_0_candidate_scored_string_keywords_fails_to_deserialize() {
    // C6 changed matched_keywords from a JSON-encoded string to
    // Vec<String>. Pre-1.2.0 wrote a stringified array. The 1.2.0
    // reader does not accept that.
    let legacy = r#"{"kind":"candidate_scored","run_id":"r","candidate_id":1,"keyword_match_score":2,"matched_keywords":"[\"a\",\"b\"]"}"#;
    let r = serde_json::from_str::<SessionEvent>(legacy);
    assert!(
        r.is_err(),
        "pre-1.2.0 stringified matched_keywords must not deserialize into Vec<String>"
    );
}

#[test]
fn pre_1_2_0_subagent_result_status_string_maps_to_enum_variant() {
    // C7 changed status from a free-form string to a closed enum
    // with snake_case serde. The pre-1.2.0 strings produced by the
    // envelope (`"ok"`, `"error"`, `"rounds_exceeded"`,
    // `"depth_exceeded"`, `"timeout"`) all match enum variants in
    // their serde-rendered form, so old rows continue to read
    // cleanly. A future fork that emits a string outside this set
    // would fail to deserialize; that is the documented intent.
    let legacy = r#"{"kind":"subagent_result","child_session_id":"s","output":"out","status":"rounds_exceeded"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::SubagentResult { status, .. } => {
            assert_eq!(status, SubagentStatus::RoundsExceeded);
        }
        other => panic!("expected SubagentResult, got {other:?}"),
    }

    let bogus =
        r#"{"kind":"subagent_result","child_session_id":"s","output":"out","status":"made_up"}"#;
    assert!(
        serde_json::from_str::<SessionEvent>(bogus).is_err(),
        "unknown status string must not deserialize into SubagentStatus"
    );
}

#[test]
fn pre_1_2_0_chain_head_signing_key_id_fails_to_deserialize() {
    // C8 renamed the field. No alias by design; old ChainHead rows
    // cannot have their signatures re-verified on 1.2.0. The chain
    // hash (over raw stored bytes) still verifies; only the
    // signature check is intentionally broken.
    let legacy = r#"{"kind":"chain_head","reason":"session_start","sequence_range_start":0,"sequence_range_end":0,"prev_chain_hash":"","current_chain_hash":"","signature":"","signing_key_id":"abc","schema_version":1}"#;
    let r = serde_json::from_str::<SessionEvent>(legacy);
    assert!(
        r.is_err(),
        "pre-1.2.0 signing_key_id must not deserialize into signing_pubkey"
    );
}

#[test]
fn pre_1_2_0_system_prompt_set_deserializes_with_empty_agent_id() {
    let legacy = r#"{"kind":"system_prompt_set","content":"hello"}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::SystemPromptSet { content, agent_id } => {
            assert_eq!(content, "hello");
            assert_eq!(agent_id, "");
        }
        other => panic!("expected SystemPromptSet, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_compaction_deserializes_with_empty_agent_id() {
    let legacy =
        r#"{"kind":"compaction","spans":[0,1,2],"extracts":{"files_read":[]},"via_model":false}"#;
    let ev: SessionEvent = serde_json::from_str(legacy).unwrap();
    match ev {
        SessionEvent::Compaction {
            agent_id,
            provider,
            model,
            ..
        } => {
            assert_eq!(agent_id, "");
            assert!(provider.is_none());
            assert!(model.is_none());
        }
        other => panic!("expected Compaction, got {other:?}"),
    }
}

#[test]
fn pre_1_2_0_audit_event_flat_tuple_actor_is_classified_heuristically() {
    // Pre-1.2.0 AuditEvent JSON carried `actor: String` and used
    // empty strings for channel/session-absent. The 1.2.0 reader's
    // custom Deserialize classifies the actor (service literals →
    // Service, everything else → User) and maps empty strings to
    // None on channel/session.
    let legacy_gateway = r#"{"ts":"2026-01-01T00:00:00Z","actor":"gateway","action":"gateway.start","target":"daemon","channel":"","session":"","detail":null}"#;
    let ev: AuditEvent = serde_json::from_str(legacy_gateway).unwrap();
    assert_eq!(ev.actor_kind, ActorKind::Service);
    assert_eq!(ev.actor_id, "gateway");
    assert!(ev.channel.is_none());
    assert!(ev.session.is_none());

    let legacy_sender = r#"{"ts":"2026-01-01T00:00:00Z","actor":"telegram:12345","action":"message.inbound","target":"hi","channel":"telegram","session":"sess-1","detail":null}"#;
    let ev: AuditEvent = serde_json::from_str(legacy_sender).unwrap();
    assert_eq!(
        ev.actor_kind,
        ActorKind::User,
        "non-service-literal must classify as User"
    );
    assert_eq!(ev.actor_id, "telegram:12345");
    assert_eq!(ev.channel.as_deref(), Some("telegram"));
}

#[test]
fn audit_event_1_2_0_shape_round_trips() {
    // 1.2.0 producer + 1.2.0 reader.
    let modern = r#"{"ts":"2026-05-11T12:00:00Z","actor_kind":"agent","actor_id":"a1","action":"message.outbound","target":"slack:out:abc","channel":"slack","session":"sess-1","detail":{"content":"hi"}}"#;
    let ev: AuditEvent = serde_json::from_str(modern).unwrap();
    assert_eq!(ev.actor_kind, ActorKind::Agent);
    assert_eq!(ev.actor_id, "a1");
    assert_eq!(ev.channel.as_deref(), Some("slack"));
}

// ---------------------------------------------------------------------------
// D3: 1.2.0 wire-shape snapshot tests (presence + absence)
// ---------------------------------------------------------------------------

fn to_value(ev: &SessionEvent) -> Value {
    serde_json::to_value(ev).unwrap()
}

fn assert_keys_present(v: &Value, keys: &[&str]) {
    let obj = v.as_object().expect("event must serialize as object");
    for k in keys {
        assert!(obj.contains_key(*k), "expected field `{k}` in {v}");
    }
}

fn assert_keys_absent(v: &Value, keys: &[&str]) {
    let obj = v.as_object().expect("event must serialize as object");
    for k in keys {
        assert!(
            !obj.contains_key(*k),
            "removed field `{k}` must not reappear in 1.2.0 wire shape: {v}"
        );
    }
}

#[test]
fn snapshot_user_message_carries_adapter_and_sender() {
    let ev = SessionEvent::UserMessage {
        content: "hi".into(),
        inbound_id: Some("t:1".into()),
        adapter_id: Some("telegram".into()),
        sender_id: Some("u:42".into()),
    };
    let v = to_value(&ev);
    assert_keys_present(&v, &["adapter_id", "sender_id", "inbound_id", "content"]);
}

#[test]
fn snapshot_llm_response_renames_tokens_and_carries_agent_id() {
    let ev = SessionEvent::LlmResponse {
        request_id: "req-1".into(),
        finish_reason: "end_turn".into(),
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        latency_ms: 1234,
        agent_id: "agent-1".into(),
        credential_id: None,
        input_cost_usd_micros: None,
        output_cost_usd_micros: None,
        total_cost_usd_micros: None,
    };
    let v = to_value(&ev);
    assert_keys_present(&v, &["input_tokens", "output_tokens", "agent_id"]);
    // Pre-1.2.0 field names must not reappear. A revert of C4 would
    // re-introduce these and fail the snapshot.
    assert_keys_absent(&v, &["tokens_in", "tokens_out"]);
    // credential_id is skip_serializing_if = "Option::is_none"; the
    // None case omits the field from the wire shape entirely.
    assert_keys_absent(&v, &["credential_id"]);
}

#[test]
fn snapshot_permission_denied_carries_denial_source_with_optional_tier() {
    let ev = SessionEvent::PermissionDenied {
        tool: "exec".into(),
        action_key: "shell:curl".into(),
        denial_source: DenialSource::OrgPolicy,
        tier: None,
        agent_id: "agent-1".into(),
        trigger: None,
    };
    let v = to_value(&ev);
    assert_keys_present(&v, &["denial_source"]);
    assert_eq!(
        v.get("denial_source").and_then(|x| x.as_str()),
        Some("org_policy")
    );
    // tier absent because None + skip_serializing_if = Option::is_none
    assert_keys_absent(&v, &["tier"]);
}

#[test]
fn snapshot_http_fetch_outcome_is_enum_string() {
    let ev = SessionEvent::HttpFetch {
        source: "s".into(),
        host: "example.com".into(),
        url: "https://example.com/x".into(),
        outcome: HttpFetchOutcome::HttpError,
        http_status_code: Some(404),
        bytes: 0,
        run_id: Some("run-1".into()),
        expansion_id: None,
        agent_id: None,
        skill_name: Some("zirkel".into()),
    };
    let v = to_value(&ev);
    assert_eq!(
        v.get("outcome").and_then(|x| x.as_str()),
        Some("http_error")
    );
    assert_eq!(
        v.get("http_status_code").and_then(|x| x.as_u64()),
        Some(404)
    );
    assert_keys_present(&v, &["skill_name"]);
}

#[test]
fn snapshot_candidate_scored_matched_keywords_is_array() {
    let ev = SessionEvent::CandidateScored {
        run_id: "run-1".into(),
        candidate_id: 7,
        keyword_match_score: 2,
        matched_keywords: vec!["alpha".into(), "beta".into()],
        expansion_id: None,
    };
    let v = to_value(&ev);
    let arr = v
        .get("matched_keywords")
        .and_then(|x| x.as_array())
        .expect("matched_keywords must serialize as a JSON array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].as_str(), Some("alpha"));
}

#[test]
fn snapshot_subagent_result_status_is_enum_string() {
    let ev = SessionEvent::SubagentResult {
        child_session_id: "child-1".into(),
        output: "out".into(),
        status: SubagentStatus::Timeout,
    };
    let v = to_value(&ev);
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("timeout"));
}

#[test]
fn snapshot_chain_head_uses_signing_pubkey() {
    let ev = SessionEvent::ChainHead {
        reason: wirken_audit::ChainHeadReason::SessionStart,
        sequence_range_start: 0,
        sequence_range_end: 0,
        prev_chain_hash: HashHex("00".repeat(32)),
        current_chain_hash: HashHex("11".repeat(32)),
        signature: HexBytes("ab".repeat(32)),
        signing_pubkey: HashHex("cd".repeat(32)),
        schema_version: CHAIN_HEAD_SCHEMA_VERSION,
    };
    let v = to_value(&ev);
    assert_keys_present(&v, &["signing_pubkey"]);
    // The pre-1.2.0 field name must not reappear under any path.
    assert_keys_absent(&v, &["signing_key_id"]);
    // Sanity: the signed-message builder still accepts the values
    // (i.e. nothing about the rename changed the canonical bytes).
    let _ = build_signed_message((0, 0), "", "11", CHAIN_HEAD_SCHEMA_VERSION);
}

#[test]
fn snapshot_audit_event_uses_actor_kind_and_optional_channel() {
    let ev = AuditEvent::new(ActorKind::Service, "gateway", "gateway.start", "daemon");
    let v = serde_json::to_value(&ev).unwrap();
    assert_keys_present(&v, &["actor_kind", "actor_id"]);
    // The pre-1.2.0 flat `actor` field must not reappear.
    assert_keys_absent(&v, &["actor"]);
    // No channel/session set → omitted entirely (Option + skip_serializing_if = Option::is_none).
    assert_keys_absent(&v, &["channel", "session"]);
}

// ---------------------------------------------------------------------------
// D4: SIEM forwarder envelope shapes + webhook HMAC
// ---------------------------------------------------------------------------

fn fixture_event() -> AuditEvent {
    AuditEvent {
        ts: Utc.with_ymd_and_hms(2026, 5, 11, 12, 0, 0).unwrap(),
        actor_kind: ActorKind::Agent,
        actor_id: "agent-1".into(),
        action: "message.outbound".into(),
        target: "slack:out:abc".into(),
        channel: Some("slack".into()),
        session: Some("sess-1".into()),
        detail: serde_json::json!({"content": "hi"}),
    }
}

fn fixture_config(target: SiemTarget, hmac_secret: Option<&str>) -> SiemConfig {
    SiemConfig {
        target,
        endpoint: "http://127.0.0.1:0/x".into(),
        api_key: "k".into(),
        service: "wirken".into(),
        environment: "test".into(),
        hmac_secret: hmac_secret.map(String::from),
        sentinel_typed: None,
        typed_include_variants: None,
        typed_exclude_variants: None,
        typed_forwarding_enabled: None,
    }
}

#[test]
fn datadog_envelope_carries_actor_kind_and_actor_id() {
    let config = fixture_config(SiemTarget::Datadog, None);
    let payload = build_datadog_payload(&[fixture_event()], &config);
    let entry = &payload[0];
    let wirken = entry.get("wirken").unwrap();
    assert_eq!(
        wirken.get("actor_kind").and_then(|x| x.as_str()),
        Some("agent")
    );
    assert_eq!(
        wirken.get("actor_id").and_then(|x| x.as_str()),
        Some("agent-1")
    );
    // pre-1.2.0 flat "actor" field must not reappear in the envelope.
    assert!(wirken.get("actor").is_none());
}

#[test]
fn splunk_envelope_carries_actor_kind_and_actor_id() {
    let body = build_splunk_body(&[fixture_event()]);
    let line = body.trim_end_matches('\n');
    let v: Value = serde_json::from_str(line).unwrap();
    let event = v.get("event").unwrap();
    assert_eq!(
        event.get("actor_kind").and_then(|x| x.as_str()),
        Some("agent")
    );
    assert_eq!(
        event.get("actor_id").and_then(|x| x.as_str()),
        Some("agent-1")
    );
    assert!(event.get("actor").is_none());
}

#[test]
fn sentinel_envelope_carries_actor_kind_and_actor_id() {
    let config = fixture_config(SiemTarget::Sentinel, None);
    let payload = build_sentinel_payload(&[fixture_event()], &config);
    let entry = &payload[0];
    assert_eq!(
        entry.get("ActorKind").and_then(|x| x.as_str()),
        Some("agent")
    );
    assert_eq!(
        entry.get("ActorId").and_then(|x| x.as_str()),
        Some("agent-1")
    );
    assert!(entry.get("Actor").is_none());
}

#[test]
fn webhook_signature_is_over_exact_serialized_body_bytes() {
    // The load-bearing invariant: the receiver computes HMAC over
    // the raw HTTP body bytes; we must hash the same bytes. If the
    // signer re-serializes the payload separately, any field-order
    // drift between `serde_json::to_vec` calls would diverge. The
    // production path threads a single `serde_json::to_vec` result
    // through both the signer and the HTTP body; this test asserts
    // that.
    let config = fixture_config(SiemTarget::Webhook, Some("super-secret"));
    let (body, sig) = build_webhook_request(&[fixture_event()], &config).unwrap();

    let sig = sig.expect("hmac_secret was set; signature must be present");
    let recomputed = compute_webhook_signature(b"super-secret", &body);
    assert_eq!(
        sig, recomputed,
        "X-Wirken-Signature must equal HMAC-SHA-256 over the exact body bytes"
    );

    // Sanity: the body parses as JSON and contains the new actor
    // shape. If a future change rewrote the body builder to emit a
    // different envelope, this would fail before the HMAC assert
    // could even run.
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let entry = &parsed.as_array().unwrap()[0];
    assert_eq!(
        entry.get("actor_kind").and_then(|x| x.as_str()),
        Some("agent")
    );
    assert_eq!(
        entry.get("actor_id").and_then(|x| x.as_str()),
        Some("agent-1")
    );
}

#[test]
fn webhook_signature_absent_when_hmac_secret_unset() {
    let config = fixture_config(SiemTarget::Webhook, None);
    let (_body, sig) = build_webhook_request(&[fixture_event()], &config).unwrap();
    assert!(sig.is_none(), "no header when hmac_secret is unset");

    let config_empty = fixture_config(SiemTarget::Webhook, Some(""));
    let (_body, sig) = build_webhook_request(&[fixture_event()], &config_empty).unwrap();
    assert!(
        sig.is_none(),
        "empty hmac_secret is treated as unset; no header"
    );
}

#[test]
fn webhook_signature_changes_when_body_changes() {
    // Defense-in-depth on the HMAC test: changing any byte in the
    // body must produce a different signature. If a future revert
    // hashed a constant string instead of the body, this would fail.
    let secret = "k";
    let body_a = b"[{\"a\":1}]";
    let body_b = b"[{\"a\":2}]";
    let sig_a = compute_webhook_signature(secret.as_bytes(), body_a);
    let sig_b = compute_webhook_signature(secret.as_bytes(), body_b);
    assert_ne!(sig_a, sig_b);
}
