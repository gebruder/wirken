use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert;

// ---------------------------------------------------------------------------
// Conversion: outbound result frame building
// ---------------------------------------------------------------------------

#[test]
fn build_outbound_result_success() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "12345", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "12345");
            assert_eq!(r.get_error().unwrap().to_str().unwrap(), "");
        }
        _ => panic!("expected OutboundResult"),
    }
}

#[test]
fn build_outbound_result_failure() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, false, "", "rate limited");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(!r.get_success());
            assert_eq!(r.get_error().unwrap().to_str().unwrap(), "rate limited");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Conversion: heartbeat
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

// ---------------------------------------------------------------------------
// Conversion: outbound message parsing
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
        outbound.set_conversation_id("-1001234567890");
        outbound.set_text("Hello from the agent!");
        outbound.set_reply_to_id("42");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, -1001234567890);
    assert_eq!(fields.text, "Hello from the agent!");
    assert_eq!(fields.reply_to_id, Some(42));
}

#[test]
fn parse_outbound_no_reply() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("9876543");
        outbound.set_text("No reply");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, 9876543);
    assert!(fields.reply_to_id.is_none());
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("telegram");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "telegram");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "telegram");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// End-to-end IPC roundtrips
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inbound_frame_roundtrip_over_uds() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (_cr, mut cw) = split_stream(client);
    let (mut sr, _sw) = split_stream(server);

    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut inbound = fb.init_inbound();
        inbound.set_id("msg-99");
        inbound.set_sender_id("12345");
        inbound.set_sender_name("Alice");
        inbound.set_channel("telegram");
        inbound.set_conversation_id("-100999");
        inbound.set_text("Hello from Telegram!");
        inbound.set_timestamp(1711234567890);
        inbound.set_is_group(true);
        inbound.set_reply_to_id("");
        inbound.set_metadata("{\"username\":\"alice\"}");
    }
    cw.write_message(&msg).await.unwrap();

    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        sr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();

    match fr.which().unwrap() {
        frame::Inbound(inbound) => {
            let m = inbound.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "msg-99");
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from Telegram!"
            );
            assert!(m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

#[tokio::test]
async fn outbound_result_flow_over_uds() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, _cw) = split_stream(client);
    let (_sr, mut sw) = split_stream(server);

    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("12345");
        outbound.set_text("Agent reply");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }
    sw.write_message(&msg).await.unwrap();

    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        cr.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.conversation_id, 12345);
    assert_eq!(fields.text, "Agent reply");
}

// ---------------------------------------------------------------------------
// Full flow: handshake → inbound → outbound → result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("telegram");
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
            assert_eq!(id, "telegram");
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
        m.set_id("msg-1");
        m.set_sender_id("user-42");
        m.set_sender_name("Bob");
        m.set_channel("telegram");
        m.set_conversation_id("-1001234500");
        m.set_text("What's the weather?");
        m.set_timestamp(chrono::Utc::now().timestamp_millis());
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
        m.set_conversation_id("-1001234500");
        m.set_text("Sunny, 22C.");
        m.set_reply_to_id("msg-1");
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
    convert::build_outbound_result(&mut result, true, "tg-msg-999", "");
    aw.write_message(&result).await.unwrap();

    // Gateway reads result
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "tg-msg-999");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Approval-frame conversions (slice: telegram approval gate)
// ---------------------------------------------------------------------------

#[test]
fn approval_decision_allow_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "req-uuid", true, 12345, "davi");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), "req-uuid");
            assert_eq!(d.get_telegram_user_id(), 12345);
            assert_eq!(
                d.get_telegram_user_display().unwrap().to_str().unwrap(),
                "davi"
            );
            match d.get_decision().unwrap().which().unwrap() {
                wirken_ipc::wirken_capnp::approval_decision_kind::Allow(_) => {}
                _ => panic!("expected Allow"),
            }
        }
        _ => panic!("expected ApprovalDecision"),
    }
}

#[test]
fn approval_decision_deny_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "r", false, 99, "");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            match d.get_decision().unwrap().which().unwrap() {
                wirken_ipc::wirken_capnp::approval_decision_kind::Deny(_) => {}
                _ => panic!("expected Deny"),
            }
        }
        _ => panic!("expected ApprovalDecision"),
    }
}

#[test]
fn approval_request_failed_carries_reason() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_request_failed(&mut msg, "req-x", "chat_not_accessible");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalRequestFailed(f) => {
            let f = f.unwrap();
            assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), "req-x");
            assert_eq!(
                f.get_reason().unwrap().to_str().unwrap(),
                "chat_not_accessible"
            );
        }
        _ => panic!("expected ApprovalRequestFailed"),
    }
}

#[test]
fn approval_request_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut req = fb.init_approval_request();
        req.set_request_id("abc");
        req.set_tool_name("shell");
        req.set_action_key("shell:rm");
        req.set_requested_tier("tier3");
        req.set_triggering_agent("default");
        req.set_trigger_message("clean logs");
        req.set_target_chat_id(-100123);
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.request_id, "abc");
    assert_eq!(fields.tool_name, "shell");
    assert_eq!(fields.action_key, "shell:rm");
    assert_eq!(fields.requested_tier, "tier3");
    assert_eq!(fields.triggering_agent, "default");
    assert_eq!(fields.trigger_message, "clean logs");
    assert_eq!(fields.target_chat_id, -100123);
}

// ---------------------------------------------------------------------------
// Callback-data parse
// ---------------------------------------------------------------------------

#[test]
fn callback_data_parse_allow() {
    let (uuid, allow) = crate::adapter::parse_callback_data_for_test(
        "req:9b8f1c0a-1234-4abc-9def-0123456789ab:allow",
    )
    .unwrap();
    assert_eq!(uuid, "9b8f1c0a-1234-4abc-9def-0123456789ab");
    assert!(allow);
}

#[test]
fn callback_data_parse_deny() {
    let (uuid, allow) = crate::adapter::parse_callback_data_for_test("req:abc:deny").unwrap();
    assert_eq!(uuid, "abc");
    assert!(!allow);
}

#[test]
fn callback_data_parse_rejects_missing_prefix() {
    assert!(crate::adapter::parse_callback_data_for_test("abc:allow").is_none());
}

#[test]
fn callback_data_parse_rejects_unknown_suffix() {
    assert!(crate::adapter::parse_callback_data_for_test("req:abc:wat").is_none());
}

#[test]
fn callback_data_parse_rejects_empty_uuid() {
    assert!(crate::adapter::parse_callback_data_for_test("req::allow").is_none());
}
