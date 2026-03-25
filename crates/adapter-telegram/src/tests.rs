use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::transport::{split_stream, FrameReader, FrameWriter};
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
    ).unwrap()
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

    let adapter_side = tokio::spawn(async move {
        perform_adapter_handshake(&mut cr, &mut cw, &identity).await
    });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "telegram");
            assert_eq!(pk, &expected_pk);
            Ok(())
        }).await
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
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello from Telegram!");
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
        perform_adapter_handshake(&mut ar, &mut aw, &identity).await.unwrap();
        (ar, aw)
    });
    let gateway_hs = tokio::spawn(async move {
        perform_gateway_handshake(&mut gr, &mut gw, |id, pk| {
            assert_eq!(id, "telegram");
            assert_eq!(pk, &expected_pk);
            Ok(())
        }).await.unwrap();
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
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "What's the weather?");
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
