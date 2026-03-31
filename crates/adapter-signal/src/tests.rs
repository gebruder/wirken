use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, SignalInbound};

// ---------------------------------------------------------------------------
// Inbound parsing from signal-cli JSON-RPC
// ---------------------------------------------------------------------------

#[test]
fn parse_signal_text_message() {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [{
            "envelope": {
                "source": "+15559876543",
                "sourceName": "Alice",
                "timestamp": 1711900000000_i64,
                "dataMessage": {
                    "message": "Hello wirken!",
                    "timestamp": 1711900000000_i64
                }
            }
        }],
        "id": 1
    });

    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, "+15559876543");
    assert_eq!(messages[0].sender_name, "Alice");
    assert_eq!(messages[0].text, "Hello wirken!");
    assert_eq!(messages[0].timestamp, 1711900000000);
    assert!(messages[0].group_id.is_none());
}

#[test]
fn ignore_non_text_messages() {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [{
            "envelope": {
                "source": "+15559876543",
                "sourceName": "Alice",
                "timestamp": 1711900000000_i64,
                "typingMessage": {
                    "action": "STARTED"
                }
            }
        }],
        "id": 1
    });

    // Envelope without dataMessage should be skipped
    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert!(messages.is_empty());
}

// ---------------------------------------------------------------------------
// should_process filter
// ---------------------------------------------------------------------------

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
    assert!(!convert::should_process(&msg));
}

#[test]
fn valid_text_processed() {
    let msg = SignalInbound {
        message_id: "sig_2".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        group_id: None,
    };
    assert!(convert::should_process(&msg));
}

// ---------------------------------------------------------------------------
// Conversation ID logic
// ---------------------------------------------------------------------------

#[test]
fn group_message_uses_group_id_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_3".into(),
        sender: "+15551234567".into(),
        sender_name: "Alice".into(),
        text: "group chat".into(),
        timestamp: 1711900000000,
        group_id: Some("group-abc-123".into()),
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "group-abc-123"
            );
            assert!(m.get_is_group());
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "signal");
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn direct_message_uses_sender_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_4".into(),
        sender: "+15559876543".into(),
        sender_name: "Bob".into(),
        text: "direct message".into(),
        timestamp: 1711900000000,
        group_id: None,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "+15559876543"
            );
            assert!(!m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Frame building smoke tests
// ---------------------------------------------------------------------------

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 42);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 42),
        _ => panic!("expected Heartbeat"),
    }
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "sig-msg-123", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "sig-msg-123");
            assert_eq!(r.get_error().unwrap().to_str().unwrap(), "");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Outbound parsing
// ---------------------------------------------------------------------------

fn serialize_and_read(
    builder: &capnp::message::Builder<capnp::message::HeapAllocator>,
) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, builder).unwrap();
    capnp::serialize::read_message(
        std::io::Cursor::new(buf),
        capnp::message::ReaderOptions::default(),
    )
    .unwrap()
}

#[test]
fn parse_outbound_message() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("+15559876543");
        outbound.set_text("Agent reply");
        outbound.set_reply_to_id("sig_1");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "+15559876543");
    assert_eq!(fields.text, "Agent reply");
    assert_eq!(fields.reply_to_id.unwrap(), "sig_1");
}

#[test]
fn parse_outbound_no_reply() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("+15551234567");
        outbound.set_text("New message");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert!(fields.reply_to_id.is_none());
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
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("signal");
    let expected_pk = identity.public_key_bytes();

    let (mut ar, mut aw) = split_stream(adapter_stream);
    let (mut gr, mut gw) = split_stream(gateway_stream);

    // Phase 1: Handshake
    let adapter_hs = tokio::spawn(async move {
        perform_adapter_handshake(&mut ar, &mut aw, &identity)
            .await
            .unwrap();
        (ar, aw)
    });
    let gateway_hs = tokio::spawn(async move {
        perform_gateway_handshake(&mut gr, &mut gw, |id, pk| {
            assert_eq!(id, "signal");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
        .unwrap();
        (gr, gw)
    });

    let (adapter_res, gateway_res) = tokio::join!(adapter_hs, gateway_hs);
    let (mut ar, mut aw) = adapter_res.unwrap();
    let (mut gr, mut gw) = gateway_res.unwrap();

    // Phase 2: Adapter sends inbound message
    let mut inbound = capnp::message::Builder::new_default();
    {
        let fb = inbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_inbound();
        m.set_id("sig_msg_1");
        m.set_sender_id("+15559876543");
        m.set_sender_name("Alice");
        m.set_channel("signal");
        m.set_conversation_id("+15559876543");
        m.set_text("What's the weather?");
        m.set_timestamp(1711900000000);
        m.set_is_group(false);
        m.set_reply_to_id("");
        m.set_metadata("{}");
    }
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "What's the weather?"
            );
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "signal");
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound reply
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("+15559876543");
        m.set_text("Sunny, 22C.");
        m.set_reply_to_id("sig_msg_1");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Sunny, 22C.");
    assert_eq!(fields.conversation_id, "+15559876543");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "sig-sent-999", "");
    aw.write_message(&result).await.unwrap();

    // Gateway reads result
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "sig-sent-999"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}
