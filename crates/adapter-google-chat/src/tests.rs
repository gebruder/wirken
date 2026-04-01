use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert;

// ---------------------------------------------------------------------------
// Payload extraction
// ---------------------------------------------------------------------------

fn message_event(space_type: &str, text: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "MESSAGE",
        "message": {
            "name": "spaces/SPACE_123/messages/MSG_456",
            "sender": {
                "name": "users/USER_789",
                "displayName": "Alice",
                "email": "alice@example.com"
            },
            "text": text,
            "createTime": "2024-01-01T00:00:00Z",
            "space": {
                "name": "spaces/SPACE_123",
                "type": space_type
            }
        }
    })
}

#[test]
fn parse_google_chat_message() {
    let payload = message_event("DM", "Hello wirken!");
    let msg = convert::extract_message(&payload).unwrap();

    assert_eq!(msg.message_id, "spaces/SPACE_123/messages/MSG_456");
    assert_eq!(msg.sender_email, "alice@example.com");
    assert_eq!(msg.sender_name, "Alice");
    assert_eq!(msg.text, "Hello wirken!");
    assert_eq!(msg.space_name, "spaces/SPACE_123");
    assert!(msg.is_dm);

    // 2024-01-01T00:00:00Z in millis
    let expected_ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
        .unwrap()
        .timestamp_millis();
    assert_eq!(msg.timestamp, expected_ts);
}

#[test]
fn ignore_non_message_events() {
    let added = serde_json::json!({
        "type": "ADDED_TO_SPACE",
        "space": { "name": "spaces/SPACE_123", "type": "ROOM" }
    });
    assert!(convert::extract_message(&added).is_none());

    let removed = serde_json::json!({
        "type": "REMOVED_FROM_SPACE",
        "space": { "name": "spaces/SPACE_123", "type": "ROOM" }
    });
    assert!(convert::extract_message(&removed).is_none());
}

#[test]
fn dm_always_processed() {
    let payload = message_event("DM", "hi there");
    let msg = convert::extract_message(&payload).unwrap();
    assert!(msg.is_dm);
    assert!(convert::should_process(&msg));
}

#[test]
fn room_message_processed() {
    let payload = message_event("ROOM", "hello room");
    let msg = convert::extract_message(&payload).unwrap();
    assert!(!msg.is_dm);
    assert!(convert::should_process(&msg));
}

#[test]
fn empty_text_not_processed() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    assert!(!convert::should_process(&msg));
}

#[test]
fn valid_text_processed() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    assert!(convert::should_process(&msg));
}

// ---------------------------------------------------------------------------
// Cap'n Proto inbound frame
// ---------------------------------------------------------------------------

#[test]
fn google_chat_to_inbound_frame() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "alice@example.com".into(),
        sender_name: "Alice".into(),
        text: "Hello from Google Chat".into(),
        timestamp: 1704067200000,
        space_name: "spaces/S".into(),
        is_dm: true,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "spaces/S/messages/M");
            assert_eq!(
                m.get_sender_id().unwrap().to_str().unwrap(),
                "alice@example.com"
            );
            assert_eq!(m.get_sender_name().unwrap().to_str().unwrap(), "Alice");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "google-chat");
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "spaces/S"
            );
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from Google Chat"
            );
            assert_eq!(m.get_timestamp(), 1704067200000);
            assert!(!m.get_is_group()); // DM -> not group
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn room_message_sets_is_group() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/R/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "hello room".into(),
        timestamp: 0,
        space_name: "spaces/R".into(),
        is_dm: false,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert!(m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Outbound parsing / frame building
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
        outbound.set_conversation_id("spaces/SPACE_123");
        outbound.set_text("Reply from agent");
        outbound.set_reply_to_id("spaces/SPACE_123/messages/MSG_456");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "spaces/SPACE_123");
    assert_eq!(fields.text, "Reply from agent");
    assert_eq!(
        fields.reply_to.unwrap(),
        "spaces/SPACE_123/messages/MSG_456"
    );
}

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
    convert::build_outbound_result(&mut msg, true, "spaces/S/messages/M", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "spaces/S/messages/M"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("google-chat");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "google-chat");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "google-chat");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("google-chat");
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
            assert_eq!(id, "google-chat");
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

    // Phase 2: Adapter sends inbound (simulating a Google Chat message)
    let chat_msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "alice@example.com".into(),
        sender_name: "Alice".into(),
        text: "Hello from Google Chat".into(),
        timestamp: 1704067200000,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    let mut inbound = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&chat_msg, &mut inbound);
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "google-chat");
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from Google Chat"
            );
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("spaces/S");
        m.set_text("Hello! How can I help?");
        m.set_reply_to_id("spaces/S/messages/M");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Hello! How can I help?");
    assert_eq!(fields.reply_to.unwrap(), "spaces/S/messages/M");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "spaces/S/messages/REPLY_1", "");
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
                "spaces/S/messages/REPLY_1"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}
