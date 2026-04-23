use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, InboundKind, SignalAllowlist, SignalInbound};

// ---------------------------------------------------------------------------
// Hand-shaped envelope fixtures. Builder functions parameterized by sub_id /
// text / timestamp. Used by the end-to-end tests that script a fake
// signal-cli. The shape mirrors what signal-cli 0.14.2 emits (sourceNumber,
// sourceUuid, sourceDevice, serverReceivedTimestamp, expiresInSeconds, …);
// a byte-accurate capture replaces this in a later commit.
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
        group_id: Some("group.abcDEF123=".into()),
    };
    assert!(list.allows(&group_msg));

    let other_group = SignalInbound {
        message_id: "g2".into(),
        sender: "+15550000000".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
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
