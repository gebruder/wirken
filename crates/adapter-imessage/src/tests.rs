use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert;

// ---------------------------------------------------------------------------
// BlueBubbles payload extraction
// ---------------------------------------------------------------------------

#[test]
fn parse_bluebubbles_text_message() {
    let payload = serde_json::json!({
        "type": "new-message",
        "data": {
            "guid": "MSG-ABC-123",
            "text": "Hello wirken!",
            "handle": {
                "address": "+15551234567",
                "firstName": "Alice",
                "lastName": "Smith"
            },
            "dateCreated": 1704067200000_i64,
            "chats": [{
                "guid": "iMessage;-;+15551234567",
                "displayName": "Alice"
            }],
            "isFromMe": false
        }
    });

    let msg = convert::extract_message(&payload).unwrap();
    assert_eq!(msg.message_id, "MSG-ABC-123");
    assert_eq!(msg.sender_handle, "+15551234567");
    assert_eq!(msg.sender_name, "Alice Smith");
    assert_eq!(msg.text, "Hello wirken!");
    assert_eq!(msg.timestamp, 1704067200000);
    assert_eq!(msg.chat_guid, "iMessage;-;+15551234567");
    assert!(!msg.is_group);
}

#[test]
fn ignore_from_me_messages() {
    let payload = serde_json::json!({
        "type": "new-message",
        "data": {
            "guid": "MSG-DEF-456",
            "text": "My own message",
            "handle": {
                "address": "+15559876543",
                "firstName": "Me",
                "lastName": ""
            },
            "dateCreated": 1704067200000_i64,
            "chats": [{
                "guid": "iMessage;-;+15559876543",
                "displayName": "Someone"
            }],
            "isFromMe": true
        }
    });

    assert!(convert::extract_message(&payload).is_none());
}

#[test]
fn ignore_non_text_events() {
    let payload = serde_json::json!({
        "type": "updated-message",
        "data": {
            "guid": "MSG-GHI-789",
            "text": "edited text",
            "handle": {
                "address": "+15551234567",
                "firstName": "Alice",
                "lastName": "Smith"
            },
            "dateCreated": 1704067200000_i64,
            "chats": [{
                "guid": "iMessage;-;+15551234567",
                "displayName": "Alice"
            }],
            "isFromMe": false
        }
    });

    assert!(convert::extract_message(&payload).is_none());
}

#[test]
fn group_message_uses_chat_guid() {
    let payload = serde_json::json!({
        "type": "new-message",
        "data": {
            "guid": "MSG-GRP-001",
            "text": "Group hello!",
            "handle": {
                "address": "+15551234567",
                "firstName": "Alice",
                "lastName": ""
            },
            "dateCreated": 1704067200000_i64,
            "chats": [{
                "guid": "iMessage;+;chat123456",
                "displayName": "Family Chat"
            }],
            "isFromMe": false
        }
    });

    let msg = convert::extract_message(&payload).unwrap();
    assert_eq!(msg.chat_guid, "iMessage;+;chat123456");
    assert!(msg.is_group);
}

#[test]
fn direct_message_processed() {
    let payload = serde_json::json!({
        "type": "new-message",
        "data": {
            "guid": "MSG-DM-001",
            "text": "Hey there",
            "handle": {
                "address": "alice@icloud.com",
                "firstName": "Alice",
                "lastName": "Jones"
            },
            "dateCreated": 1704067200000_i64,
            "chats": [{
                "guid": "iMessage;-;alice@icloud.com",
                "displayName": "Alice Jones"
            }],
            "isFromMe": false
        }
    });

    let msg = convert::extract_message(&payload).unwrap();
    assert_eq!(msg.sender_handle, "alice@icloud.com");
    assert_eq!(msg.chat_guid, "iMessage;-;alice@icloud.com");
    assert!(!msg.is_group);
}

// ---------------------------------------------------------------------------
// should_process
// ---------------------------------------------------------------------------

#[test]
fn empty_text_not_processed() {
    let msg = convert::IMessageInbound {
        message_id: "msg-1".into(),
        sender_handle: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        chat_guid: "iMessage;-;+15551234567".into(),
        is_group: false,
    };
    assert!(!convert::should_process(&msg));
}

#[test]
fn valid_text_processed() {
    let msg = convert::IMessageInbound {
        message_id: "msg-2".into(),
        sender_handle: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        chat_guid: "iMessage;-;+15551234567".into(),
        is_group: false,
    };
    assert!(convert::should_process(&msg));
}

// ---------------------------------------------------------------------------
// Frame building
// ---------------------------------------------------------------------------

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 42);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => {
            assert_eq!(hb.unwrap().get_seq(), 42);
        }
        _ => panic!("expected Heartbeat"),
    }
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "imsg-123", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "imsg-123");
            assert_eq!(r.get_error().unwrap().to_str().unwrap(), "");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("imessage");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "imessage");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "imessage");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("imessage");
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
            assert_eq!(id, "imessage");
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
        m.set_id("msg-imsg-1");
        m.set_sender_id("+15551234567");
        m.set_sender_name("Alice Smith");
        m.set_channel("imessage");
        m.set_conversation_id("iMessage;-;+15551234567");
        m.set_text("What's the weather?");
        m.set_timestamp(1704067200000);
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
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound reply
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("iMessage;-;+15551234567");
        m.set_text("Sunny, 22C.");
        m.set_reply_to_id("msg-imsg-1");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Sunny, 22C.");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "bb-msg-999", "");
    aw.write_message(&result).await.unwrap();

    // Gateway reads result
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "bb-msg-999");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Constructor + webhook auth
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_empty_server_password() {
    use crate::adapter::IMessageAdapter;
    use crate::error::IMessageError;

    let id = AdapterIdentity::generate("imessage");
    let r = IMessageAdapter::new(id, "http://localhost:1234".into(), String::new(), 3981);
    match r {
        Err(IMessageError::Config(msg)) => {
            assert!(msg.contains("server_password"), "msg: {msg}");
        }
        Err(other) => panic!("expected Config error, got {other:?}"),
        Ok(_) => panic!("empty server_password must fail at construction"),
    }
}

#[test]
fn new_accepts_non_empty_server_password() {
    use crate::adapter::IMessageAdapter;
    let id = AdapterIdentity::generate("imessage");
    assert!(
        IMessageAdapter::new(id, "http://localhost:1234".into(), "secret".into(), 3981).is_ok()
    );
}

// The verify_password and extract_webhook_password tests that
// previously lived here are deleted along with the helpers. See
// the comment on `handle_webhook` in adapter.rs for the protocol
// reality: BlueBubbles posts webhooks with no authentication, so a
// receiver-side password check was always going to fail (and did,
// silently, in 0.7.6). The trust boundary moved to the listener
// binding; tests on the loopback-only invariant belong at the
// integration level (the `run` method refuses to start if the
// bound local_addr is not loopback) rather than here.
