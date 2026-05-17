use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, InboundKind, SignalAllowlist, SignalInbound};

// ---------------------------------------------------------------------------
// Wire-shape fixtures captured from a real signal-cli 0.14.2 daemon during
// the 0.7.9 socket-transport rollout. Identifiers are sanitized but field
// shapes (key names, nesting, presence of extra timestamps and flags) are
// preserved so the parser is exercised against the actual superset signal-cli
// emits, not a hand-rolled subset.
//
// Two layers of fixtures:
//
// - This `fixtures` module: builder functions (hand-shaped, parameterized
//   by sub_id / text / timestamp) used by the end-to-end tests that
//   script a fake signal-cli. They mirror real-wire shape but need to
//   be mutable across test cases.
// - `tests/fixtures/signal_envelopes_20260423.json`: byte-accurate
//   captures of real signal-cli output, sanitized. Consumed by the
//   `real_wire_*` tests to prove the parser tolerates the exact key
//   ordering and extra fields (sourceDevice, serverReceivedTimestamp,
//   expiresInSeconds, etc.) that signal-cli actually emits.
//
// Group envelopes were not present in the 2026-04-23 capture. The
// `extract_data_message_with_groupv2_id` test uses a synthesized
// fixture until a group capture is available.
// ---------------------------------------------------------------------------

mod fixtures {
    /// E.164 of the inbound sender in fixture envelopes.
    pub const FIXTURE_SOURCE: &str = "+15559876543";
    /// Sanitized UUID — preserves field shape and length without leaking
    /// any real Signal account id.
    pub const FIXTURE_SOURCE_UUID: &str = "00000000-0000-4000-8000-000000000001";
    /// Display name as it arrives on the wire.
    pub const FIXTURE_SOURCE_NAME: &str = "Alice";
    /// E.164 of the wirken-side account.
    pub const FIXTURE_ACCOUNT: &str = "+15551112222";

    /// `subscribeReceive` response. Real wire shape:
    /// `{"jsonrpc":"2.0","result":<u64>,"id":<u64>}\n`.
    pub fn subscribe_response(req_id: u64, sub_id: u64) -> String {
        format!("{{\"jsonrpc\":\"2.0\",\"result\":{sub_id},\"id\":{req_id}}}\n")
    }

    /// `send` response. Real wire shape carries `result.timestamp` as
    /// the Signal message id (used by the adapter for self-echo dedupe).
    pub fn send_response(req_id: u64, ts: i64) -> String {
        format!("{{\"jsonrpc\":\"2.0\",\"result\":{{\"timestamp\":{ts}}},\"id\":{req_id}}}\n")
    }

    /// `dataMessage` envelope under `params.subscription` + `params.result.envelope`.
    /// Real-capture shape: includes `sourceNumber`, `sourceUuid`, `sourceDevice`,
    /// `serverReceivedTimestamp`, `serverDeliveredTimestamp`, and
    /// `expiresInSeconds`/`isExpirationUpdate`/`viewOnce` flags the
    /// adapter currently ignores.
    pub fn data_message_subscribed(sub_id: u64, ts: i64, text: &str) -> String {
        let envelope = serde_json::json!({
            "source": FIXTURE_SOURCE,
            "sourceNumber": FIXTURE_SOURCE,
            "sourceUuid": FIXTURE_SOURCE_UUID,
            "sourceName": FIXTURE_SOURCE_NAME,
            "sourceDevice": 1,
            "timestamp": ts,
            "serverReceivedTimestamp": ts + 100,
            "serverDeliveredTimestamp": ts + 101,
            "dataMessage": {
                "timestamp": ts,
                "message": text,
                "expiresInSeconds": 0,
                "isExpirationUpdate": false,
                "viewOnce": false
            },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "subscription": sub_id, "result": { "envelope": envelope } }
        });
        format!("{}\n", frame)
    }

    /// `dataMessage` envelope (subscribed form) from an arbitrary source.
    /// Used by the allowlist-enforcement test, which needs to push a
    /// message from a sender the adapter has NOT allowlisted.
    pub fn data_message_from(sub_id: u64, ts: i64, text: &str, source: &str) -> String {
        let envelope = serde_json::json!({
            "source": source,
            "sourceNumber": source,
            "sourceUuid": "00000000-0000-4000-8000-000000000099",
            "sourceName": "Stranger",
            "sourceDevice": 1,
            "timestamp": ts,
            "serverReceivedTimestamp": ts + 100,
            "serverDeliveredTimestamp": ts + 101,
            "dataMessage": {
                "timestamp": ts,
                "message": text,
                "expiresInSeconds": 0,
                "isExpirationUpdate": false,
                "viewOnce": false
            },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "subscription": sub_id, "result": { "envelope": envelope } }
        });
        format!("{}\n", frame)
    }

    /// `dataMessage` envelope in the legacy fan-out form: under
    /// `params.envelope` directly, no `subscription` field. signal-cli
    /// emits both forms for every event; the adapter must dedupe by
    /// dropping the legacy form.
    pub fn data_message_legacy(ts: i64, text: &str) -> String {
        let envelope = serde_json::json!({
            "source": FIXTURE_SOURCE,
            "sourceNumber": FIXTURE_SOURCE,
            "sourceUuid": FIXTURE_SOURCE_UUID,
            "sourceName": FIXTURE_SOURCE_NAME,
            "sourceDevice": 1,
            "timestamp": ts,
            "serverReceivedTimestamp": ts + 100,
            "serverDeliveredTimestamp": ts + 101,
            "dataMessage": {
                "timestamp": ts,
                "message": text,
                "expiresInSeconds": 0,
                "isExpirationUpdate": false,
                "viewOnce": false
            },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "envelope": envelope }
        });
        format!("{}\n", frame)
    }

    /// `typingMessage` envelope (subscribed form). Adapter must drop it.
    pub fn typing_subscribed(sub_id: u64, ts: i64) -> String {
        let envelope = serde_json::json!({
            "source": FIXTURE_SOURCE,
            "sourceNumber": FIXTURE_SOURCE,
            "sourceUuid": FIXTURE_SOURCE_UUID,
            "sourceName": FIXTURE_SOURCE_NAME,
            "sourceDevice": 1,
            "timestamp": ts,
            "serverReceivedTimestamp": ts + 5,
            "serverDeliveredTimestamp": ts + 6,
            "typingMessage": { "action": "STARTED", "timestamp": ts },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "subscription": sub_id, "result": { "envelope": envelope } }
        });
        format!("{}\n", frame)
    }

    /// `receiptMessage` envelope (subscribed form, delivered receipt).
    /// Adapter must drop it.
    pub fn receipt_delivered_subscribed(sub_id: u64, ts: i64) -> String {
        let envelope = serde_json::json!({
            "source": FIXTURE_SOURCE,
            "sourceNumber": FIXTURE_SOURCE,
            "sourceUuid": FIXTURE_SOURCE_UUID,
            "sourceName": FIXTURE_SOURCE_NAME,
            "sourceDevice": 1,
            "timestamp": ts,
            "serverReceivedTimestamp": ts - 50,
            "serverDeliveredTimestamp": ts - 49,
            "receiptMessage": {
                "when": ts,
                "isDelivery": true,
                "isRead": false,
                "isViewed": false,
                "timestamps": [ts - 100],
            },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "subscription": sub_id, "result": { "envelope": envelope } }
        });
        format!("{}\n", frame)
    }

    /// `syncMessage.sentMessage` envelope (subscribed form). Used to
    /// model the multi-device echo signal-cli sends back after every
    /// outbound send. Hand-shaped (not from the real capture, which
    /// did not include sync-sent traffic).
    pub fn sync_sent_subscribed(sub_id: u64, ts: i64, destination: &str, text: &str) -> String {
        let envelope = serde_json::json!({
            "source": FIXTURE_ACCOUNT,
            "sourceNumber": FIXTURE_ACCOUNT,
            "sourceName": "Operator",
            "sourceDevice": 1,
            "timestamp": ts,
            "syncMessage": {
                "sentMessage": {
                    "destination": destination,
                    "destinationNumber": destination,
                    "timestamp": ts,
                    "message": text,
                    "expiresInSeconds": 0,
                    "isExpirationUpdate": false,
                    "viewOnce": false,
                }
            },
            "account": FIXTURE_ACCOUNT,
        });
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": { "subscription": sub_id, "result": { "envelope": envelope } }
        });
        format!("{}\n", frame)
    }
}

// ---------------------------------------------------------------------------
// Inbound parsing: envelope -> SignalInbound (transport-independent)
// ---------------------------------------------------------------------------

#[test]
fn extract_data_message_from_envelope() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceNumber": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "Hello wirken!",
            "timestamp": 1711900000000_i64
        }
    });

    let (msg, kind) = convert::extract_inbound(&envelope).expect("data message must parse");
    assert_eq!(kind, InboundKind::Data);
    assert_eq!(msg.sender, "+15559876543");
    assert_eq!(msg.sender_name, "Alice");
    assert_eq!(msg.text, "Hello wirken!");
    assert_eq!(msg.timestamp, 1711900000000);
    assert!(msg.group_id.is_none());
}

#[test]
fn extract_sync_sent_uses_destination_as_sender() {
    // When the operator sends from their phone (device 1), signal-cli
    // mirrors the send to every linked device as a syncMessage. The
    // adapter treats the destination as the conversation key so the
    // allowlist matches the contact the operator was messaging.
    let envelope = serde_json::json!({
        "source": "+15551112222",
        "sourceNumber": "+15551112222",
        "sourceName": "Operator",
        "timestamp": 1711900000500_i64,
        "syncMessage": {
            "sentMessage": {
                "destination": "+15559876543",
                "destinationNumber": "+15559876543",
                "timestamp": 1711900000500_i64,
                "message": "Hi Alice"
            }
        }
    });

    let (msg, kind) = convert::extract_inbound(&envelope).expect("sync sent must parse");
    assert_eq!(kind, InboundKind::SyncSent);
    assert_eq!(msg.sender, "+15559876543");
    assert_eq!(msg.text, "Hi Alice");
}

#[test]
fn extract_ignores_receipt_messages() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "receiptMessage": { "when": 1711900000000_i64 }
    });
    assert!(convert::extract_inbound(&envelope).is_none());
}

#[test]
fn extract_ignores_typing_indicators() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "typingMessage": { "action": "STARTED" }
    });
    assert!(convert::extract_inbound(&envelope).is_none());
}

#[test]
fn extract_ignores_empty_sync_envelopes() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "syncMessage": {}
    });
    assert!(convert::extract_inbound(&envelope).is_none());
}

#[test]
fn extract_data_message_real_wire_shape() {
    // Pulled from fixtures::data_message_subscribed which mirrors the
    // shape captured from a real signal-cli 0.14.2 daemon (extra
    // sourceUuid, sourceDevice, serverReceivedTimestamp,
    // serverDeliveredTimestamp, expiresInSeconds, isExpirationUpdate,
    // viewOnce fields the hand-rolled fake omitted). Closes the
    // empirical-gap concern raised in the 0.7.9 transport rewrite:
    // extract_inbound must tolerate fields it does not consume.
    let line = fixtures::data_message_subscribed(1, 1776957645071, "Test");
    let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let envelope = frame
        .pointer("/params/result/envelope")
        .expect("subscribed envelope at /params/result/envelope");

    let (msg, kind) =
        convert::extract_inbound(envelope).expect("real-shape data message must parse");
    assert_eq!(kind, InboundKind::Data);
    assert_eq!(msg.sender, fixtures::FIXTURE_SOURCE);
    assert_eq!(msg.sender_name, fixtures::FIXTURE_SOURCE_NAME);
    assert_eq!(msg.text, "Test");
    assert_eq!(msg.timestamp, 1776957645071);
    assert!(msg.group_id.is_none());
}

#[test]
fn extract_typing_real_wire_shape_dropped() {
    let line = fixtures::typing_subscribed(1, 1776957643068);
    let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let envelope = frame.pointer("/params/result/envelope").unwrap();
    assert!(convert::extract_inbound(envelope).is_none());
}

#[test]
fn extract_receipt_real_wire_shape_dropped() {
    let line = fixtures::receipt_delivered_subscribed(1, 1776957674247);
    let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let envelope = frame.pointer("/params/result/envelope").unwrap();
    assert!(convert::extract_inbound(envelope).is_none());
}

// ---------------------------------------------------------------------------
// Real wire bytes. Parsed from tests/fixtures/signal_envelopes_20260423.json,
// captured from a live signal-cli 0.14.2 `daemon --socket` stream via socat
// during the 0.7.9 socket-transport smoke test. Identifiers sanitized; wire
// shape (key order, extra flags like expiresInSeconds/sourceDevice/
// serverReceivedTimestamp) preserved byte-for-byte. If signal-cli ever
// rearranges fields or adds keys the parser does not tolerate, these tests
// surface that drift before operators do.
// ---------------------------------------------------------------------------

const REAL_ENVELOPES_JSON: &str = include_str!("../tests/fixtures/signal_envelopes_20260423.json");

fn real_envelope(key: &str) -> serde_json::Value {
    let doc: serde_json::Value =
        serde_json::from_str(REAL_ENVELOPES_JSON).expect("fixture file must parse");
    let raw_line = doc[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture key '{key}' missing"));
    let frame: serde_json::Value =
        serde_json::from_str(raw_line).expect("fixture frame must parse");
    frame["params"]["result"]["envelope"].clone()
}

#[test]
fn real_wire_data_message_extracts_to_data_kind() {
    let env = real_envelope("data_message_subscribed");
    let (msg, kind) = convert::extract_inbound(&env).expect("real dataMessage must parse");
    assert_eq!(kind, InboundKind::Data);
    // Sanitized sender and account from the fixture.
    assert_eq!(msg.sender, "+15555550001");
    assert_eq!(msg.sender_name, "Alice");
    // Non-ASCII text (em-dash, accented char, emoji) survives through
    // extract_inbound.
    assert!(msg.text.contains("açcents"));
    assert!(msg.text.contains("🦀"));
    assert!(msg.text.contains("—"));
    assert!(msg.group_id.is_none());
    // sourceUuid is preserved even when a phone number is also present.
    assert_eq!(
        msg.sender_uuid.as_deref(),
        Some("00000000-0000-4000-a000-000000000001")
    );
}

#[test]
fn real_wire_sync_sent_extracts_to_syncsent_kind() {
    let env = real_envelope("sync_sent_subscribed");
    let (msg, kind) = convert::extract_inbound(&env).expect("real sentMessage must parse");
    assert_eq!(kind, InboundKind::SyncSent);
    // Sync-sent keys on destination so a reply routes back to the
    // contact the operator was messaging, not the operator's own number.
    assert_eq!(msg.sender, "+15555550001");
    assert_eq!(msg.text, "integration-test reply");
}

#[test]
fn real_wire_typing_returns_none() {
    let env = real_envelope("typing_subscribed");
    assert!(convert::extract_inbound(&env).is_none());
}

#[test]
fn real_wire_receipt_returns_none() {
    let env = real_envelope("receipt_subscribed");
    assert!(convert::extract_inbound(&env).is_none());
}

#[test]
fn extract_data_message_with_groupv2_id() {
    // Modern signal-cli routes group messages via
    // `dataMessage.groupV2.id`. Legacy `groupInfo.groupId` is still
    // accepted but groupV2 takes precedence when both are present.
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "new-style group hello",
            "timestamp": 1711900000000_i64,
            "groupV2": {
                "id": "W8Z6FYAeHrqO1CRc4xBBDRHVJzRjzYqP4wQr+IhsUCA=",
                "revision": 3
            }
        }
    });
    let (msg, _kind) = convert::extract_inbound(&envelope).expect("groupV2 must parse");
    assert_eq!(
        msg.group_id.as_deref(),
        Some("W8Z6FYAeHrqO1CRc4xBBDRHVJzRjzYqP4wQr+IhsUCA=")
    );
}

#[test]
fn extract_data_message_groupv2_takes_precedence_over_groupinfo() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "dual-shape",
            "timestamp": 1711900000000_i64,
            "groupV2": { "id": "v2-id=" },
            "groupInfo": { "groupId": "legacy-id" }
        }
    });
    let (msg, _kind) = convert::extract_inbound(&envelope).unwrap();
    assert_eq!(msg.group_id.as_deref(), Some("v2-id="));
}

#[test]
fn extract_uuid_only_sender_routes_via_uuid() {
    // Contact reached us with phone privacy: no sourceNumber, only
    // sourceUuid. Sender falls back to the UUID so the allowlist and
    // outbound routing can still target them.
    let envelope = serde_json::json!({
        "sourceUuid": "d48512b4-2571-404a-ac0c-500722870238",
        "sourceName": "Anonymous",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "uuid-only DM",
            "timestamp": 1711900000000_i64
        }
    });
    let (msg, _kind) = convert::extract_inbound(&envelope).expect("uuid-only must parse");
    assert_eq!(msg.sender, "d48512b4-2571-404a-ac0c-500722870238");
    assert_eq!(
        msg.sender_uuid.as_deref(),
        Some("d48512b4-2571-404a-ac0c-500722870238")
    );
}

#[test]
fn extract_populates_sender_uuid_when_both_phone_and_uuid_present() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceNumber": "+15559876543",
        "sourceUuid": "d48512b4-2571-404a-ac0c-500722870238",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "hi",
            "timestamp": 1711900000000_i64
        }
    });
    let (msg, _kind) = convert::extract_inbound(&envelope).unwrap();
    assert_eq!(msg.sender, "+15559876543");
    assert_eq!(
        msg.sender_uuid.as_deref(),
        Some("d48512b4-2571-404a-ac0c-500722870238")
    );
}

#[test]
fn allowlist_uuid_entry_matches_uuid_sender() {
    let list = SignalAllowlist::from_csv("d48512b4-2571-404a-ac0c-500722870238").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "d48512b4-2571-404a-ac0c-500722870238".into(),
        sender_name: "Anonymous".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: Some("d48512b4-2571-404a-ac0c-500722870238".into()),
        group_id: None,
    };
    assert!(list.allows(&msg));
}

#[test]
fn allowlist_phone_entry_still_matches_when_uuid_also_present() {
    // Backward compat: operators who only know their contacts by phone
    // must keep working even after the UUID fallback was added.
    let list = SignalAllowlist::from_csv("+15559876543").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "+15559876543".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: Some("d48512b4-2571-404a-ac0c-500722870238".into()),
        group_id: None,
    };
    assert!(list.allows(&msg));
}

#[test]
fn extract_data_message_with_group_id() {
    let envelope = serde_json::json!({
        "source": "+15559876543",
        "sourceName": "Alice",
        "timestamp": 1711900000000_i64,
        "dataMessage": {
            "message": "group hello",
            "timestamp": 1711900000000_i64,
            "groupInfo": { "groupId": "group.abc123=" }
        }
    });

    let (msg, _kind) = convert::extract_inbound(&envelope).expect("group msg must parse");
    assert_eq!(msg.group_id.as_deref(), Some("group.abc123="));
}

// ---------------------------------------------------------------------------
// should_process filter
// ---------------------------------------------------------------------------

fn allowlist_with(entries: &[&str]) -> SignalAllowlist {
    SignalAllowlist::from_csv(&entries.join(",")).expect("valid allowlist in test")
}

#[test]
fn empty_text_not_processed() {
    let msg = SignalInbound {
        message_id: "sig_1".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn valid_text_processed_when_sender_allowed() {
    let msg = SignalInbound {
        message_id: "sig_2".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(convert::should_process(&msg, &list));
}

#[test]
fn unknown_sender_dropped() {
    let msg = SignalInbound {
        message_id: "sig_3".into(),
        sender: "+15550001111".into(),
        sender_name: "Mallory".into(),
        text: "please run rm -rf /".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn empty_allowlist_drops_everything() {
    let msg = SignalInbound {
        message_id: "sig_4".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    let list = allowlist_with(&[]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn group_message_uses_group_id_for_allowlist() {
    // Allowlist contains only a group id, not the sender's phone.
    let list = allowlist_with(&["group.abc123="]);
    let msg = SignalInbound {
        message_id: "sig_5".into(),
        sender: "+15550001111".into(),
        sender_name: "Stranger".into(),
        text: "hello group".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: Some("group.abc123=".into()),
    };
    assert!(convert::should_process(&msg, &list));
}

#[test]
fn allowlist_parses_whitespace_and_empty_segments() {
    let list = SignalAllowlist::from_csv("  +15551234567 ,, +15559876543   ").unwrap();
    assert_eq!(list.len(), 2);
}

// ---------------------------------------------------------------------------
// Inbound -> Cap'n Proto frame
// ---------------------------------------------------------------------------

#[test]
fn group_message_uses_group_id_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_g1".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "group hello".into(),
        timestamp: 12345,
        sender_uuid: None,
        group_id: Some("group.xyz=".into()),
    };
    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &builder).unwrap();
    let reader =
        capnp::serialize::read_message(&mut bytes.as_slice(), capnp::message::ReaderOptions::new())
            .unwrap();
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "group.xyz="
            );
            assert!(m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn direct_message_uses_sender_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_d1".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hi".into(),
        timestamp: 12345,
        sender_uuid: None,
        group_id: None,
    };
    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &builder).unwrap();
    let reader =
        capnp::serialize::read_message(&mut bytes.as_slice(), capnp::message::ReaderOptions::new())
            .unwrap();
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "+15551234567"
            );
            assert!(!m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn build_heartbeat() {
    let mut builder = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut builder, 42);
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &builder).unwrap();
    let reader =
        capnp::serialize::read_message(&mut bytes.as_slice(), capnp::message::ReaderOptions::new())
            .unwrap();
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 42),
        _ => panic!("expected Heartbeat"),
    }
}

#[test]
fn build_outbound_result() {
    let mut builder = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut builder, true, "sig-123", "");
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &builder).unwrap();
    let reader =
        capnp::serialize::read_message(&mut bytes.as_slice(), capnp::message::ReaderOptions::new())
            .unwrap();
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "sig-123");
        }
        _ => panic!("expected OutboundResult"),
    }
}

fn serialize_and_read(
    msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, msg).unwrap();
    capnp::serialize::read_message(&mut bytes.as_slice(), capnp::message::ReaderOptions::new())
        .unwrap()
}

#[test]
fn parse_outbound_message() {
    let mut builder = capnp::message::Builder::new_default();
    {
        let fb = builder.init_root::<frame::Builder<'_>>();
        let mut o = fb.init_outbound();
        o.set_conversation_id("+15551234567");
        o.set_text("hello back");
        o.set_reply_to_id("orig-1");
        o.set_metadata("{}");
    }
    let reader = serialize_and_read(&builder);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "+15551234567");
    assert_eq!(fields.text, "hello back");
    assert_eq!(fields.reply_to_id.as_deref(), Some("orig-1"));
}

#[test]
fn parse_outbound_no_reply() {
    let mut builder = capnp::message::Builder::new_default();
    {
        let fb = builder.init_root::<frame::Builder<'_>>();
        let mut o = fb.init_outbound();
        o.set_conversation_id("+15551234567");
        o.set_text("hi");
        o.set_reply_to_id("");
        o.set_metadata("{}");
    }
    let reader = serialize_and_read(&builder);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert!(fields.reply_to_id.is_none());
}

// ---------------------------------------------------------------------------
// Endpoint parser: HTTP migration error, unix:// and bare paths both accepted
// ---------------------------------------------------------------------------

#[test]
fn endpoint_http_rejected_with_migration_error() {
    let err = super::adapter::test_parse_endpoint("http://localhost:8080/api/v1/rpc")
        .expect_err("http endpoint must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("JSON-RPC over a Unix socket"),
        "error must reference the migration path, got: {msg}"
    );
}

#[test]
fn endpoint_https_rejected() {
    assert!(super::adapter::test_parse_endpoint("https://example.com/").is_err());
}

#[test]
fn endpoint_unix_scheme_stripped() {
    let path = super::adapter::test_parse_endpoint("unix:///var/run/signal-cli.sock").unwrap();
    assert_eq!(path.to_str().unwrap(), "/var/run/signal-cli.sock");
}

#[test]
fn endpoint_bare_path_accepted() {
    let path = super::adapter::test_parse_endpoint("/tmp/signal-cli.sock").unwrap();
    assert_eq!(path.to_str().unwrap(), "/tmp/signal-cli.sock");
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("signal");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "signal");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "signal");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// End-to-end against a fake signal-cli Unix socket. Validates the socket
// transport, subscribe-then-push flow, self-echo suppression, and the
// outbound send RPC round trip.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_against_fake_signal_cli_socket() {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use crate::SignalAdapter;

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");

    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let captured_send: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_send_for_fake = captured_send.clone();

    // Fake signal-cli. Subscribes, then pushes one inbound DM envelope,
    // then waits for a `send` RPC and echoes back a fake timestamp. Also
    // pushes the multi-device sync echo that Signal emits for every send
    // — the adapter must filter that out via the self-echo cache so the
    // test cannot race-pass by double-counting.
    let fake_signal = tokio::spawn(async move {
        let (stream, _) = signal_listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        // First line is subscribeReceive.
        let line = lines.next_line().await.unwrap().expect("subscribe line");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["method"], "subscribeReceive");
        let req_id = req["id"].as_u64().unwrap();

        let sub_id: u64 = 777;
        write
            .write_all(fixtures::subscribe_response(req_id, sub_id).as_bytes())
            .await
            .unwrap();

        // Push one inbound DM for the allowlisted sender, then the
        // legacy fan-out form. Both come straight from fixtures so the
        // wire shape matches what real signal-cli emits.
        let inbound_ts: i64 = 1711900000000;
        write
            .write_all(
                fixtures::data_message_subscribed(sub_id, inbound_ts, "hello from socket test")
                    .as_bytes(),
            )
            .await
            .unwrap();
        write
            .write_all(
                fixtures::data_message_legacy(
                    inbound_ts,
                    "hello from socket test (legacy fan-out, must be dropped)",
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // Next line from the adapter should be the send RPC (after the
        // gateway pushes the outbound reply).
        let line = lines.next_line().await.unwrap().expect("send line");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["method"], "send");
        let send_id = req["id"].as_u64().unwrap();
        *captured_send_for_fake.lock().await = Some(req.clone());

        let sent_ts: i64 = 1711900000999;
        write
            .write_all(fixtures::send_response(send_id, sent_ts).as_bytes())
            .await
            .unwrap();

        // Immediately push the self-echo the real daemon would emit.
        // The adapter must suppress this; if it forwards it, the
        // gateway-side assert_no_further_inbound check below fails.
        write
            .write_all(
                fixtures::sync_sent_subscribed(
                    sub_id,
                    sent_ts,
                    fixtures::FIXTURE_SOURCE,
                    "integration test reply",
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // Keep the socket open so the adapter's read loop does not EOF
        // and reconnect mid-test.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);

        perform_gateway_handshake(&mut gr, &mut gw, |id, _pk| {
            assert_eq!(id, "signal");
            Ok(())
        })
        .await
        .unwrap();

        // Read frames until we see the first Inbound.
        let mut inbound_text = None;
        for _ in 0..40 {
            let msg = gr.read_message().await.unwrap();
            let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
            if let frame::Inbound(ib) = fr.which().unwrap() {
                let m = ib.unwrap();
                inbound_text = Some(m.get_text().unwrap().to_str().unwrap().to_string());
                break;
            }
        }

        // Send an outbound reply.
        let mut outbound = capnp::message::Builder::new_default();
        {
            let fb = outbound.init_root::<frame::Builder<'_>>();
            let mut o = fb.init_outbound();
            o.set_conversation_id("+15559876543");
            o.set_text("integration test reply");
            o.set_reply_to_id("");
            o.set_metadata("{}");
        }
        gw.write_message(&outbound).await.unwrap();

        // Drain until OutboundResult, asserting no further Inbound
        // appears (the self-echo must be suppressed).
        let mut outbound_success = None;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    match fr.which().unwrap() {
                        frame::OutboundResult(r) => {
                            outbound_success = Some(r.unwrap().get_success());
                        }
                        frame::Inbound(_) => {
                            panic!(
                                "gateway saw a second Inbound — self-echo filter or legacy \
                                 fan-out dedupe failed"
                            );
                        }
                        _ => {}
                    }
                    if outbound_success.is_some() {
                        // Continue reading in case the echo is still in flight.
                        continue;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        (inbound_text, outbound_success)
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv("+15559876543").unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        "+15551112222".into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task = tokio::spawn(async move {
        std::sync::Arc::new(adapter)
            .run(&gw_socket_for_adapter)
            .await
    });

    let (inbound_text, outbound_success) =
        tokio::time::timeout(std::time::Duration::from_secs(15), gateway_task)
            .await
            .expect("gateway side timed out — adapter never delivered expected frames")
            .expect("gateway task panicked");

    adapter_task.abort();
    fake_signal.abort();

    assert_eq!(
        inbound_text.as_deref(),
        Some("hello from socket test"),
        "inbound text mismatch"
    );
    assert_eq!(outbound_success, Some(true), "outbound result not success");

    let send_call = captured_send
        .lock()
        .await
        .clone()
        .expect("fake signal-cli never received a send call");
    assert_eq!(send_call["method"], "send");
    assert_eq!(send_call["params"]["account"], "+15551112222");
    assert_eq!(send_call["params"]["recipient"][0], "+15559876543");
    assert_eq!(send_call["params"]["message"], "integration test reply");
}

// ---------------------------------------------------------------------------
// Allowlist enforcement over the real adapter loop: fake signal-cli pushes a
// message from a sender NOT in the allowlist. The adapter must drop it, so
// the gateway should see only heartbeats (or nothing) within the window.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Formatter wiring: the adapter must rewrite markdown on the outbound side
// so Signal does not render `###`, `**`, or table pipes as literal text.
// This exercises the full path: the gateway pushes an Outbound frame with
// markdown; the adapter's `send_message` runs the formatter and calls
// signal-cli's `send` RPC with the rendered payload.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_markdown_is_rewritten_before_send_rpc() {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use crate::SignalAdapter;

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let captured_send: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_send_for_fake = captured_send.clone();

    let fake_signal = tokio::spawn(async move {
        let (stream, _) = signal_listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        let line = lines.next_line().await.unwrap().expect("subscribe");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let sub_id: u64 = 321;
        write
            .write_all(fixtures::subscribe_response(req_id, sub_id).as_bytes())
            .await
            .unwrap();
        write
            .write_all(
                fixtures::data_message_subscribed(sub_id, 1711900000000, "ask me something")
                    .as_bytes(),
            )
            .await
            .unwrap();

        let line = lines.next_line().await.unwrap().expect("send");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["method"], "send");
        let send_id = req["id"].as_u64().unwrap();
        *captured_send_for_fake.lock().await = Some(req.clone());
        write
            .write_all(fixtures::send_response(send_id, 1711900000999).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();

        // Drain the inbound first so the adapter is fully connected.
        for _ in 0..10 {
            let msg = gr.read_message().await.unwrap();
            let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
            if matches!(fr.which().unwrap(), frame::Inbound(_)) {
                break;
            }
        }

        // Send a markdown-heavy reply. Representative of the real
        // LLM outputs that leak raw markdown to Signal today.
        let markdown = "## Heading\n\n\
            This is **bold** and `code`.\n\n\
            | Col A | Col B |\n\
            |-------|-------|\n\
            | cell1 | cell2 |\n\n\
            - bullet\n\
            - another";

        let mut outbound = capnp::message::Builder::new_default();
        {
            let fb = outbound.init_root::<frame::Builder<'_>>();
            let mut o = fb.init_outbound();
            o.set_conversation_id(fixtures::FIXTURE_SOURCE);
            o.set_text(markdown);
            o.set_reply_to_id("");
            o.set_metadata("{}");
        }
        gw.write_message(&outbound).await.unwrap();

        // Wait for the OutboundResult so we know the send RPC
        // completed.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if matches!(fr.which().unwrap(), frame::OutboundResult(_)) {
                        return;
                    }
                }
                _ => return,
            }
        }
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        fixtures::FIXTURE_ACCOUNT.into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task = tokio::spawn(async move {
        std::sync::Arc::new(adapter)
            .run(&gw_socket_for_adapter)
            .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(10), gateway_task)
        .await
        .expect("gateway side timed out")
        .expect("gateway task panicked");

    adapter_task.abort();
    fake_signal.abort();

    let send_call = captured_send
        .lock()
        .await
        .clone()
        .expect("fake signal-cli never received a send call");
    let message = send_call["params"]["message"]
        .as_str()
        .expect("send params must carry message string")
        .to_string();

    // No markdown vocabulary reaches the wire.
    assert!(
        !message.contains("##"),
        "send payload still contains '##': {message:?}"
    );
    assert!(
        !message.contains("**"),
        "send payload still contains '**': {message:?}"
    );
    assert!(
        !message.contains('`'),
        "send payload still contains backticks: {message:?}"
    );
    for line in message.lines() {
        assert!(
            !line.trim_start().starts_with('|'),
            "send payload still has table pipe row: {line:?}"
        );
    }
    // Heading content survives in Signal-dialect bold.
    assert!(message.contains("*Heading*"));
    // Bullet list survives as round bullets.
    assert!(message.contains("• bullet"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_drops_messages_from_unknown_senders() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    use crate::SignalAdapter;

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let fake_signal = tokio::spawn(async move {
        let (stream, _) = signal_listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        let line = lines.next_line().await.unwrap().expect("subscribe");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let sub_id: u64 = 555;
        write
            .write_all(fixtures::subscribe_response(req_id, sub_id).as_bytes())
            .await
            .unwrap();

        write
            .write_all(
                fixtures::data_message_from(
                    sub_id,
                    1711900000000,
                    "this should never reach the agent",
                    "+15550001111",
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);

        perform_gateway_handshake(&mut gr, &mut gw, |id, _pk| {
            assert_eq!(id, "signal");
            Ok(())
        })
        .await
        .unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if let frame::Inbound(_) = fr.which().unwrap() {
                        panic!(
                            "gateway received an inbound frame from an unallowed sender — \
                             allowlist did NOT enforce"
                        );
                    }
                }
                Ok(Err(_)) | Err(_) => return,
            }
        }
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv("+15559999999").unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        "+15551112222".into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task = tokio::spawn(async move {
        std::sync::Arc::new(adapter)
            .run(&gw_socket_for_adapter)
            .await
    });

    gateway_task.await.expect("gateway task panicked");
    adapter_task.abort();
    fake_signal.abort();
}

// ---------------------------------------------------------------------------
// Feature-gated integration test against a real signal-cli daemon.
// Set WIRKEN_SIGNAL_E2E=1 to enable. Requires `signal-cli` on PATH and a
// registered test account whose number is supplied via
// WIRKEN_SIGNAL_TEST_ACCOUNT. Does not run in CI.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn integration_real_signal_cli_daemon() {
    if std::env::var("WIRKEN_SIGNAL_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipping: WIRKEN_SIGNAL_E2E=1 not set");
        return;
    }
    let account = match std::env::var("WIRKEN_SIGNAL_TEST_ACCOUNT") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("skipping: WIRKEN_SIGNAL_TEST_ACCOUNT not set");
            return;
        }
    };

    // The operator runs this one by hand with a test account they
    // control. Assertions stay loose — we only verify the adapter can
    // subscribe, receive, and shut down cleanly. Fine-grained
    // assertions would tie the test to specific message content.
    let tmp = tempfile::tempdir().unwrap();
    let signal_sock = tmp.path().join("real-signal.sock");
    let gw_sock = tmp.path().join("gw.sock");

    let mut daemon = tokio::process::Command::new("signal-cli")
        .arg("-a")
        .arg(&account)
        .arg("daemon")
        .arg("--socket")
        .arg(&signal_sock)
        .spawn()
        .expect("failed to spawn signal-cli");

    // Give the daemon time to bind the socket.
    for _ in 0..20 {
        if signal_sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(signal_sock.exists(), "signal-cli did not bind the socket");

    let gw_listener = tokio::net::UnixListener::bind(&gw_sock).unwrap();
    let gw_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv(&account).unwrap();
    let adapter = crate::SignalAdapter::new(
        identity,
        signal_sock.to_string_lossy().into_owned(),
        account,
        allowlist,
    )
    .expect("adapter construction");

    let gw_sock_for_adapter = gw_sock.clone();
    let adapter_task =
        tokio::spawn(async move { std::sync::Arc::new(adapter).run(&gw_sock_for_adapter).await });

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), gw_task).await;
    adapter_task.abort();
    let _ = daemon.kill().await;
}

// ---------------------------------------------------------------------------
// Vuln 11: allowlist normalization + parse-time rejection
// ---------------------------------------------------------------------------

use crate::convert::SignalAllowlistError;

#[test]
fn allowlist_normalizes_phone_formats_consistently() {
    let list = SignalAllowlist::from_csv("+1 (555) 123-4567").unwrap();
    for sender in [
        "+15551234567",
        "+1-555-123-4567",
        "+1 555 123 4567",
        "+1.555.123.4567",
        "+1 (555) 123-4567",
    ] {
        let msg = SignalInbound {
            message_id: "m".into(),
            sender: sender.into(),
            sender_name: "Op".into(),
            text: "hi".into(),
            timestamp: 0,
            sender_uuid: None,
            group_id: None,
        };
        assert!(
            list.allows(&msg),
            "sender '{sender}' should match normalized allowlist entry"
        );
    }
}

#[test]
fn allowlist_rejects_phone_without_plus_at_parse_time() {
    match SignalAllowlist::from_csv("15551234567") {
        Err(SignalAllowlistError::PhoneMissingPlus(_)) => {}
        other => panic!("expected PhoneMissingPlus, got {other:?}"),
    }
    match SignalAllowlist::from_csv("+15551234567, 14155550000") {
        Err(SignalAllowlistError::PhoneMissingPlus(_)) => {}
        other => panic!("expected PhoneMissingPlus on second entry, got {other:?}"),
    }
}

#[test]
fn allowlist_group_ids_are_a_separate_namespace() {
    let list = SignalAllowlist::from_csv("group.abcDEF123=,+15551234567").unwrap();
    assert_eq!(list.len(), 2);

    let group_msg = SignalInbound {
        message_id: "g".into(),
        sender: "+15550000000".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: Some("group.abcDEF123=".into()),
    };
    assert!(list.allows(&group_msg));

    let other_group = SignalInbound {
        message_id: "g2".into(),
        sender: "+15550000000".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: Some("group.other=".into()),
    };
    assert!(!list.allows(&other_group));
}

#[test]
fn allowlist_runtime_sender_without_plus_is_rejected() {
    let list = SignalAllowlist::from_csv("+15551234567").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "15551234567".into(),
        sender_name: "Op".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    assert!(!list.allows(&msg));
}

#[test]
fn allowlist_empty_still_parses() {
    let list = SignalAllowlist::from_csv("").unwrap();
    assert!(list.is_empty());
    let list = SignalAllowlist::from_csv("  ,  , ").unwrap();
    assert!(list.is_empty());
}

#[test]
fn allowlist_accepts_all_numeric_canonical_uuid() {
    // The bug we're fixing: a UUID whose hex digits happen to be
    // all 0-9 (no letters) used to be classified as a phone-shaped
    // string by `looks_like_phone`, then rejected by
    // `normalize_phone` for missing the leading `+`. Canonical
    // layout must win over phone-shape heuristics.
    let list = SignalAllowlist::from_csv("00000000-0000-4000-8000-000000000001").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "00000000-0000-4000-8000-000000000001".into(),
        sender_name: "Numeric".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: Some("00000000-0000-4000-8000-000000000001".into()),
        group_id: None,
    };
    assert!(list.allows(&msg));
}

#[test]
fn allowlist_hex_letter_uuid_still_parses() {
    // Pre-fix behavior on UUIDs containing hex letters relied on
    // `looks_like_phone` returning false (letters are not phone
    // chars). Post-fix, the canonical layout check accepts them
    // explicitly. Pin the existing case so a future refactor of
    // the classifier doesn't drop letter-containing UUIDs.
    let list = SignalAllowlist::from_csv("d48512b4-2571-404a-ac0c-500722870238").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "d48512b4-2571-404a-ac0c-500722870238".into(),
        sender_name: "Hex".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: Some("d48512b4-2571-404a-ac0c-500722870238".into()),
        group_id: None,
    };
    assert!(list.allows(&msg));
}

#[test]
fn allowlist_e164_phone_still_classified_as_phone() {
    // Reordering the classifier must not regress the happy-path
    // phone case. E.164 input has fewer than 36 chars so the UUID
    // check returns false immediately; phone parsing wins.
    let list = SignalAllowlist::from_csv("+15559876543").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "+15559876543".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    assert!(list.allows(&msg));
}

#[test]
fn allowlist_uuid_shaped_but_wrong_dash_position_rejected_as_phone() {
    // A 36-char digit/dash string whose dashes are NOT at
    // 8/13/18/23 fails the canonical UUID check. With only digits
    // and dashes it still matches `looks_like_phone`, then falls
    // through to `normalize_phone` which rejects on missing `+`.
    let err = SignalAllowlist::from_csv("000000000-0000-4000-8000-00000000001")
        .expect_err("ambiguous-shape input must not silently accept");
    matches!(err, SignalAllowlistError::PhoneMissingPlus(_));
}

#[test]
fn allowlist_uuid_shaped_but_non_hex_char_rejected() {
    // A 36-char string with dashes in the right places but with
    // a non-hex character (z) at a hex position fails the UUID
    // check. Non-phone characters mean it falls past the phone
    // branch too and lands as a verbatim group-id-style entry —
    // not great, but not the bug this slice is fixing. The
    // assertion documents the current shape: parsing succeeds
    // and the entry is kept as-is.
    let list = SignalAllowlist::from_csv("00000000-0000-4000-8000-00000000000z").unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn allowlist_digit_only_uuid_does_not_collide_with_normalize_phone() {
    // The digit-only UUID and a separately-listed phone live
    // peacefully in the same allowlist; neither path mutates the
    // other's canonical form on the way in.
    let csv = "00000000-0000-4000-8000-000000000001,+15559876543";
    let list = SignalAllowlist::from_csv(csv).unwrap();
    assert_eq!(list.len(), 2);
    let uuid_msg = SignalInbound {
        message_id: "m".into(),
        sender: "00000000-0000-4000-8000-000000000001".into(),
        sender_name: "u".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: Some("00000000-0000-4000-8000-000000000001".into()),
        group_id: None,
    };
    let phone_msg = SignalInbound {
        message_id: "m".into(),
        sender: "+15559876543".into(),
        sender_name: "p".into(),
        text: "hi".into(),
        timestamp: 0,
        sender_uuid: None,
        group_id: None,
    };
    assert!(list.allows(&uuid_msg));
    assert!(list.allows(&phone_msg));
}

// ---------------------------------------------------------------------------
// Approval-frame conversions (slice: signal approval gate)
// ---------------------------------------------------------------------------

#[test]
fn approval_decision_allow_round_trips_with_empty_deny_reason() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut msg,
        "req-uuid",
        true,
        "",
        "00000000-0000-4000-8000-000000000001",
        "Alice",
    );
    let reader = serialize_and_read(&msg);
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), "req-uuid");
            assert_eq!(
                d.get_actor_user_id().unwrap().to_str().unwrap(),
                "00000000-0000-4000-8000-000000000001"
            );
            assert_eq!(d.get_actor_display().unwrap().to_str().unwrap(), "Alice");
            match d.get_decision().unwrap().which().unwrap() {
                wirken_ipc::wirken_capnp::approval_decision_kind::Allow(_) => {}
                _ => panic!("expected Allow"),
            }
        }
        _ => panic!("expected ApprovalDecision"),
    }
}

#[test]
fn approval_decision_deny_round_trips_with_reason_text() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "r", false, "rm is too risky", "+15559876543", "");
    let reader = serialize_and_read(&msg);
    let fr = reader.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            // E.164 phone fallback when sender has no ACI UUID
            // surfaces here verbatim.
            assert_eq!(
                d.get_actor_user_id().unwrap().to_str().unwrap(),
                "+15559876543"
            );
            match d.get_decision().unwrap().which().unwrap() {
                wirken_ipc::wirken_capnp::approval_decision_kind::Deny(reason) => {
                    assert_eq!(reason.unwrap().to_str().unwrap(), "rm is too risky");
                }
                _ => panic!("expected Deny"),
            }
        }
        _ => panic!("expected ApprovalDecision"),
    }
}

#[test]
fn approval_request_failed_carries_reason_label() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_request_failed(&mut msg, "req-x", "signal_rpc_timeout");
    let reader = serialize_and_read(&msg);
    match reader
        .get_root::<frame::Reader<'_>>()
        .unwrap()
        .which()
        .unwrap()
    {
        frame::ApprovalRequestFailed(f) => {
            let f = f.unwrap();
            assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), "req-x");
            assert_eq!(
                f.get_reason().unwrap().to_str().unwrap(),
                "signal_rpc_timeout"
            );
        }
        _ => panic!("expected ApprovalRequestFailed"),
    }
}

/// Construct a `SignalAdapter` with no live signal-cli or gateway
/// connection. Useful for tests that exercise route-decision
/// branches without spinning up the full fake-cli harness; calls
/// into `send_message` will fail with `ConnectionClosed` which
/// the route_approval_command's clarification path absorbs.
fn test_adapter(allowlist: SignalAllowlist) -> std::sync::Arc<crate::SignalAdapter> {
    let identity = AdapterIdentity::generate("signal");
    let tmp = tempfile::tempdir().unwrap();
    std::sync::Arc::new(
        crate::SignalAdapter::new(
            identity,
            tmp.path()
                .join("nonexistent.sock")
                .to_string_lossy()
                .into_owned(),
            "+15551112222".into(),
            allowlist,
        )
        .expect("adapter construction"),
    )
}

/// First-attempt signal-cli connect failure must propagate out of
/// `run()` as `Err`, not silently retry. Operators who start
/// wirken before the signal-cli daemon see a meaningful startup
/// error rather than a degraded adapter that surfaces every
/// gateway frame as ApprovalRequestFailed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_failure_at_startup_returns_err_from_run() {
    use std::sync::Arc;
    use tokio::net::UnixListener;

    use crate::SignalAdapter;

    let tmp = tempfile::tempdir().unwrap();
    // Intentionally do NOT bind a listener at this path; the
    // adapter's first connect attempt will hit ENOENT or
    // ECONNREFUSED and bubble that up as SignalError::Io.
    let signal_socket = tmp.path().join("signal-cli-not-running.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        // Adapter must reach handshake before its first
        // signal-cli connect attempt.
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        fixtures::FIXTURE_ACCOUNT.into(),
        allowlist,
    )
    .expect("adapter construction");

    let run_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Arc::new(adapter).run(&gw_socket),
    )
    .await
    .expect("run() must return (not hang) on signal-cli connect failure");

    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), gateway_task).await;

    // The exact error variant depends on the OS error code
    // (ENOENT for missing path, ECONNREFUSED for path-exists-
    // no-listener). Either lands as SignalError::Io.
    match run_result {
        Err(crate::SignalError::Io(_)) => {}
        other => panic!("expected SignalError::Io from connect failure, got {other:?}"),
    }
}

#[tokio::test]
async fn approval_prefix_miss_does_not_remove_other_entries() {
    let adapter = test_adapter(SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap());
    {
        let mut map = adapter.approval_prefix_map_for_test().await;
        map.insert(
            "aaaa0000".into(),
            vec!["aaaa0000-1234-1234-1234-aaaa00000000".into()],
        );
    }
    let inbound = SignalInbound {
        message_id: "m".into(),
        sender: fixtures::FIXTURE_SOURCE.into(),
        sender_name: "Alice".into(),
        text: "!approve deadbeef".into(),
        timestamp: 1,
        sender_uuid: None,
        group_id: None,
    };
    let cmd = wirken_adapter_core::text_command::CommandKind::Approve {
        prefix: "deadbeef".into(),
    };
    adapter.route_approval_command_for_test(&inbound, cmd).await;
    let map = adapter.approval_prefix_map_for_test().await;
    assert!(
        map.contains_key("aaaa0000"),
        "miss-path must not touch unrelated entries"
    );
}

#[tokio::test]
async fn approval_prefix_collision_does_not_consume_entries() {
    let adapter = test_adapter(SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap());
    {
        let mut map = adapter.approval_prefix_map_for_test().await;
        map.insert(
            "abcd1234".into(),
            vec![
                "abcd1234-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
                "abcd1234-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
            ],
        );
    }
    let inbound = SignalInbound {
        message_id: "m".into(),
        sender: fixtures::FIXTURE_SOURCE.into(),
        sender_name: "Alice".into(),
        text: "!approve abcd1234".into(),
        timestamp: 1,
        sender_uuid: None,
        group_id: None,
    };
    let cmd = wirken_adapter_core::text_command::CommandKind::Approve {
        prefix: "abcd1234".into(),
    };
    adapter.route_approval_command_for_test(&inbound, cmd).await;
    let map = adapter.approval_prefix_map_for_test().await;
    let entries = map.get("abcd1234").expect("collision must not consume");
    assert_eq!(entries.len(), 2, "neither request resolved");
}

#[test]
fn approval_request_round_trips_signal_shape_target_conversation_id() {
    // Signal group ids are base64; the schema's Text-typed
    // targetConversationId carries them through unchanged. This
    // is the load-bearing property that motivated the wire
    // rename in this slice.
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut req = fb.init_approval_request();
        req.set_request_id("0f9d3c52-1234-5678-9abc-deadbeef0001");
        req.set_tool_name("shell");
        req.set_action_key("shell:rm");
        req.set_requested_tier("tier3");
        req.set_triggering_agent("default");
        req.set_trigger_message("clean logs");
        req.set_target_conversation_id("9LJqVbY9wKD2c3vH/abcDEF==");
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.request_id, "0f9d3c52-1234-5678-9abc-deadbeef0001");
    assert_eq!(fields.target_conversation_id, "9LJqVbY9wKD2c3vH/abcDEF==");
}

// ---------------------------------------------------------------------------
// End-to-end: gateway sends ApprovalRequest, the Signal adapter renders the
// text-command prompt, the allowlisted sender replies with `!approve <prefix>`,
// and the adapter emits ApprovalDecision back. Validates the prefix-map
// lifecycle and the full surface contract.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_round_trip_via_text_command() {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use crate::SignalAdapter;

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let captured_send: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_send_for_fake = captured_send.clone();

    // Pick a request_id whose first 8 hex chars form a unique
    // prefix the adapter will render.
    let request_id = "0f9d3c52-1234-5678-9abc-deadbeef0001";
    let expected_prefix = "0f9d3c52";

    let fake_signal = tokio::spawn(async move {
        let (stream, _) = signal_listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        // Subscribe.
        let line = lines.next_line().await.unwrap().expect("subscribe");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let sub_id: u64 = 555;
        write
            .write_all(fixtures::subscribe_response(req_id, sub_id).as_bytes())
            .await
            .unwrap();

        // The adapter renders the approval prompt; capture the
        // outgoing `send` RPC and reply with a fake timestamp.
        let line = lines.next_line().await.unwrap().expect("send approval");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["method"], "send");
        let send_id = req["id"].as_u64().unwrap();
        *captured_send_for_fake.lock().await = Some(req.clone());
        write
            .write_all(fixtures::send_response(send_id, 1711900000999).as_bytes())
            .await
            .unwrap();

        // Push an inbound `!approve <prefix>` from the
        // allowlisted sender. The adapter parses the command,
        // looks up the prefix in its prefix-map, and writes an
        // `ApprovalDecision` frame to the gateway. No further
        // signal-cli RPC is expected on this path.
        let cmd_body = format!("!approve {expected_prefix}");
        write
            .write_all(
                fixtures::data_message_subscribed(sub_id, 1711900001000, &cmd_body).as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    // The base64 group id we configure as the approval
    // conversation. The adapter sends the prompt to this id.
    let signal_group_id = "9LJqVbY9wKD2c3vH/abcDEF==";

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();

        // No cross-task readiness sync needed: the adapter's
        // `run()` now waits for the first signal-cli connect to
        // complete before spawning the outbound handler. The
        // gateway frame written here arrives at a handler that
        // already has a live signal-cli connection to dispatch
        // through. If this test starts racing again, the
        // connect-ordering fix has regressed.

        // Push an ApprovalRequest frame.
        let mut req_msg = capnp::message::Builder::new_default();
        {
            let fb = req_msg.init_root::<frame::Builder<'_>>();
            let mut req = fb.init_approval_request();
            req.set_request_id(request_id);
            req.set_tool_name("shell");
            req.set_action_key("shell:rm");
            req.set_requested_tier("tier3");
            req.set_triggering_agent("default");
            req.set_trigger_message("clean old logs");
            req.set_target_conversation_id(signal_group_id);
        }
        gw.write_message(&req_msg).await.unwrap();

        // The adapter responds with an ApprovalDecision after the
        // operator's `!approve` command arrives. Drain all
        // adapter-to-gateway traffic, ignoring heartbeats and
        // the inbound message the adapter does NOT forward
        // (because it parsed as a command), until we find the
        // ApprovalDecision.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if let frame::ApprovalDecision(d) = fr.which().unwrap() {
                        let d = d.unwrap();
                        assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), request_id);
                        // Allowlisted sender ACI surfaces as
                        // actor_user_id (preferred over the phone).
                        assert_eq!(
                            d.get_actor_user_id().unwrap().to_str().unwrap(),
                            fixtures::FIXTURE_SOURCE_UUID
                        );
                        match d.get_decision().unwrap().which().unwrap() {
                            wirken_ipc::wirken_capnp::approval_decision_kind::Allow(_) => {}
                            _ => panic!("expected Allow"),
                        }
                        return;
                    }
                }
                _ => break,
            }
        }
        panic!("never saw an ApprovalDecision frame");
    });

    let identity = AdapterIdentity::generate("signal");
    // Allowlist the fixture phone; the route_approval_command path
    // surfaces the sender's UUID as `actor_user_id` regardless
    // (UUID is preferred over phone when both are present), so
    // the gateway-side assertion still checks the UUID below.
    let allowlist = SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        fixtures::FIXTURE_ACCOUNT.into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task = tokio::spawn(async move {
        std::sync::Arc::new(adapter)
            .run(&gw_socket_for_adapter)
            .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(15), gateway_task)
        .await
        .expect("gateway side timed out")
        .expect("gateway task panicked");

    adapter_task.abort();
    fake_signal.abort();

    // Validate the captured outbound `send` RPC: it goes to the
    // configured Signal group id and the body embeds the prefix
    // the operator types back. The full request_id is no longer
    // rendered in the body (the umbrella majority sentence-with-
    // parens form dropped that line per #122); prefix presence is
    // the load-bearing assertion.
    let send_call = captured_send
        .lock()
        .await
        .clone()
        .expect("fake signal-cli never received the approval-prompt send");
    assert_eq!(send_call["params"]["groupId"], signal_group_id);
    let body = send_call["params"]["message"]
        .as_str()
        .expect("body must be a string")
        .to_string();
    assert!(
        body.contains(&format!("!approve {expected_prefix}")),
        "body missing approve directive: {body:?}"
    );
}

/// Serializes tests that touch `WIRKEN_SIGNAL_RECONNECT_WAIT_S`.
/// cargo test parallelizes within a binary; without this lock,
/// the two reconnect-cap tests below would race on env-var
/// reads/writes and intermittently observe each other's value.
static RECONNECT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------------
// Mid-session reconnect window. signal-cli disconnects, gateway pushes a
// frame, adapter parks in `wait_for_connection`, fake-signal-cli accepts the
// reconnect, frame delivers. The pre-fix behavior would have surfaced
// ApprovalRequestFailed with `channel_not_accessible` during the window;
// this test pins the post-fix happy-path delivery.
// ---------------------------------------------------------------------------

// Static-Mutex env-var serialization holds a std::sync::Mutex
// guard across awaits to keep WIRKEN_SIGNAL_RECONNECT_WAIT_S
// stable for the test's duration. Standard test-fixture idiom;
// allowed here.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_session_reconnect_delivers_queued_frame() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use crate::SignalAdapter;

    // SAFETY: the static RECONNECT_ENV_LOCK serializes this
    // test against the reconnect-cap test below so they don't
    // interleave on WIRKEN_SIGNAL_RECONNECT_WAIT_S. Generous
    // cap value so the reconnect window is the test's only
    // timing variable. Held across the entire test scope
    // because env reads happen anywhere inside adapter.run().
    let _env_guard = RECONNECT_ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("WIRKEN_SIGNAL_RECONNECT_WAIT_S", "10");
    }

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let captured_send: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_send_for_fake = captured_send.clone();

    let request_id = "abcd1234-1234-5678-9abc-deadbeef0042";
    let expected_prefix = "abcd1234";
    let signal_group_id = "group-reconnect-happy==";

    // Cross-task sync: fake_signal fires `conn1_closed_tx` after
    // dropping conn1, so the gateway side knows when to push the
    // ApprovalRequest. Without this, the gateway might write the
    // frame before the adapter has observed the EOF and cleared
    // `self.inner`, and send_message would proceed through the
    // dead conn1 rather than parking in wait_for_connection.
    let (conn1_closed_tx, conn1_closed_rx) = tokio::sync::oneshot::channel::<()>();

    let fake_signal = tokio::spawn(async move {
        // Connection 1: subscribe, then close.
        let (stream1, _) = signal_listener.accept().await.unwrap();
        let (read1, mut write1) = stream1.into_split();
        let mut lines1 = BufReader::new(read1).lines();
        let line = lines1.next_line().await.unwrap().expect("subscribe1");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        write1
            .write_all(fixtures::subscribe_response(req_id, 1).as_bytes())
            .await
            .unwrap();
        drop(write1);
        drop(lines1);
        let _ = conn1_closed_tx.send(());

        // Connection 2: subscribe, then capture the send RPC the
        // adapter dispatches once `wait_for_connection` unblocks.
        let (stream2, _) = signal_listener.accept().await.unwrap();
        let (read2, mut write2) = stream2.into_split();
        let mut lines2 = BufReader::new(read2).lines();
        let line = lines2.next_line().await.unwrap().expect("subscribe2");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        write2
            .write_all(fixtures::subscribe_response(req_id, 2).as_bytes())
            .await
            .unwrap();

        let line = lines2
            .next_line()
            .await
            .unwrap()
            .expect("send after reconnect");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["method"], "send");
        let send_id = req["id"].as_u64().unwrap();
        *captured_send_for_fake.lock().await = Some(req.clone());
        write2
            .write_all(fixtures::send_response(send_id, 1234567890999).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();

        // Wait for fake_signal to close conn1, then give the
        // adapter a beat to observe the EOF and clear
        // `self.inner`. EOF propagation is microseconds-to-
        // milliseconds; 200ms is a generous safety margin.
        conn1_closed_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Push the ApprovalRequest INSIDE the reconnect window.
        // Adapter's send_message must park in
        // wait_for_connection rather than failing the frame
        // through the dead conn1.
        let mut req_msg = capnp::message::Builder::new_default();
        {
            let fb = req_msg.init_root::<frame::Builder<'_>>();
            let mut req = fb.init_approval_request();
            req.set_request_id(request_id);
            req.set_tool_name("shell");
            req.set_action_key("shell:rm");
            req.set_requested_tier("tier3");
            req.set_triggering_agent("default");
            req.set_trigger_message("clean logs");
            req.set_target_conversation_id(signal_group_id);
        }
        gw.write_message(&req_msg).await.unwrap();

        // Confirm no ApprovalRequestFailed surfaces during the
        // reconnect window. The post-fix delivery is silent on
        // the gateway side until the gate's queue resolves (which
        // doesn't happen in this test because no operator
        // command arrives), so absence of failure is the
        // observable signal here. Captured signal-cli send_call
        // below is the positive-side assertion.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if let frame::ApprovalRequestFailed(f) = fr.which().unwrap() {
                        let f = f.unwrap();
                        let reason = f.get_reason().unwrap().to_str().unwrap().to_string();
                        panic!(
                            "unexpected ApprovalRequestFailed during reconnect window: \
                             reason={reason}"
                        );
                    }
                }
                _ => break,
            }
        }
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        fixtures::FIXTURE_ACCOUNT.into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task = tokio::spawn(async move {
        std::sync::Arc::new(adapter)
            .run(&gw_socket_for_adapter)
            .await
    });

    tokio::time::timeout(Duration::from_secs(15), gateway_task)
        .await
        .expect("gateway side timed out")
        .expect("gateway task panicked");

    adapter_task.abort();
    fake_signal.abort();

    unsafe {
        std::env::remove_var("WIRKEN_SIGNAL_RECONNECT_WAIT_S");
    }

    let send_call = captured_send
        .lock()
        .await
        .clone()
        .expect("send RPC must have been captured after reconnect");
    assert_eq!(send_call["params"]["groupId"], signal_group_id);
    let body = send_call["params"]["message"]
        .as_str()
        .expect("body must be a string")
        .to_string();
    assert!(
        body.contains(&format!("!approve {expected_prefix}")),
        "body missing approve directive: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// Reconnect-cap timeout. signal-cli goes away and never comes back; the
// adapter's `wait_for_connection` cap elapses and the gateway-side path
// emits ApprovalRequestFailed with reason `reconnect_timeout`, distinct
// from the immediate `channel_not_accessible` label that fires for cold-
// start ConnectionClosed.
// ---------------------------------------------------------------------------

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_cap_emits_approval_request_failed_with_reason() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    use crate::SignalAdapter;

    // SAFETY: the static RECONNECT_ENV_LOCK serializes this
    // test against the reconnect-happy test above so they don't
    // interleave on WIRKEN_SIGNAL_RECONNECT_WAIT_S. Short cap so
    // the test completes quickly; the adapter's reconnect inner
    // loop sleeps 500ms before its first attempt, so 1s leaves
    // room for the cap to fire after one failed attempt.
    let _env_guard = RECONNECT_ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("WIRKEN_SIGNAL_RECONNECT_WAIT_S", "1");
    }

    let tmp = tempfile::tempdir().unwrap();
    let signal_socket = tmp.path().join("signal-cli.sock");
    let gw_socket = tmp.path().join("gw.sock");
    let signal_listener = UnixListener::bind(&signal_socket).unwrap();
    let gw_listener = UnixListener::bind(&gw_socket).unwrap();

    let request_id = "deadbeef-1234-5678-9abc-cafebabe0001";
    let signal_group_id = "group-reconnect-timeout==";

    // Same conn1_closed signal as the happy-path test: gateway
    // sends only after fake_signal has dropped conn1, so the
    // adapter is observably in the reconnect window when the
    // frame arrives.
    let (conn1_closed_tx, conn1_closed_rx) = tokio::sync::oneshot::channel::<()>();

    let fake_signal = tokio::spawn(async move {
        // Accept one connection, respond to subscribe, then
        // close everything. Dropping `signal_listener` cleans
        // up the socket file so the adapter's reconnect
        // attempts hit ENOENT immediately.
        let (stream, _) = signal_listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let line = lines.next_line().await.unwrap().expect("subscribe");
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        write
            .write_all(fixtures::subscribe_response(req_id, 1).as_bytes())
            .await
            .unwrap();
        drop(write);
        drop(lines);
        drop(signal_listener);
        let _ = conn1_closed_tx.send(());
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = gw_listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);
        perform_gateway_handshake(&mut gr, &mut gw, |_, _| Ok(()))
            .await
            .unwrap();

        conn1_closed_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut req_msg = capnp::message::Builder::new_default();
        {
            let fb = req_msg.init_root::<frame::Builder<'_>>();
            let mut req = fb.init_approval_request();
            req.set_request_id(request_id);
            req.set_tool_name("shell");
            req.set_action_key("shell:rm");
            req.set_requested_tier("tier3");
            req.set_triggering_agent("default");
            req.set_trigger_message("clean logs");
            req.set_target_conversation_id(signal_group_id);
        }
        gw.write_message(&req_msg).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if let frame::ApprovalRequestFailed(f) = fr.which().unwrap() {
                        let f = f.unwrap();
                        assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), request_id);
                        assert_eq!(
                            f.get_reason().unwrap().to_str().unwrap(),
                            "reconnect_timeout",
                            "post-fix cap-exceeded reason must be `reconnect_timeout` \
                             (distinct from cold-start `channel_not_accessible`)"
                        );
                        return;
                    }
                }
                _ => break,
            }
        }
        panic!("never saw ApprovalRequestFailed");
    });

    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv(fixtures::FIXTURE_SOURCE).unwrap();
    let adapter = SignalAdapter::new(
        identity,
        signal_socket.to_string_lossy().into_owned(),
        fixtures::FIXTURE_ACCOUNT.into(),
        allowlist,
    )
    .expect("adapter construction");
    let gw_socket_for_adapter = gw_socket.clone();
    let adapter_task =
        tokio::spawn(async move { Arc::new(adapter).run(&gw_socket_for_adapter).await });

    tokio::time::timeout(Duration::from_secs(15), gateway_task)
        .await
        .expect("gateway side timed out")
        .expect("gateway task panicked");

    adapter_task.abort();
    fake_signal.abort();

    unsafe {
        std::env::remove_var("WIRKEN_SIGNAL_RECONNECT_WAIT_S");
    }
}
