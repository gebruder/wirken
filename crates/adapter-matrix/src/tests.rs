use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, MatrixInbound};

// ---------------------------------------------------------------------------
// Inbound conversion
// ---------------------------------------------------------------------------

fn dm_message(text: &str) -> MatrixInbound {
    MatrixInbound {
        event_id: "$ev1:example.org".into(),
        sender_id: "@alice:example.org".into(),
        sender_name: "Alice".into(),
        room_id: "!dm123:example.org".into(),
        text: text.into(),
        timestamp_ms: 1711234567890,
        is_dm: true,
        reply_to_event: None,
        room_name: None,
        is_encrypted: true,
    }
}

fn room_message(text: &str, is_encrypted: bool) -> MatrixInbound {
    MatrixInbound {
        event_id: "$ev2:example.org".into(),
        sender_id: "@bob:example.org".into(),
        sender_name: "Bob".into(),
        room_id: "!room456:example.org".into(),
        text: text.into(),
        timestamp_ms: 1711234567890,
        is_dm: false,
        reply_to_event: None,
        room_name: Some("General".into()),
        is_encrypted,
    }
}

#[test]
fn dm_to_inbound_frame() {
    let msg = dm_message("Hello from Matrix");
    let mut builder = capnp::message::Builder::new_default();
    convert::matrix_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "$ev1:example.org");
            assert_eq!(
                m.get_sender_id().unwrap().to_str().unwrap(),
                "@alice:example.org"
            );
            assert_eq!(m.get_sender_name().unwrap().to_str().unwrap(), "Alice");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "matrix");
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "!dm123:example.org"
            );
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello from Matrix");
            assert_eq!(m.get_timestamp(), 1711234567890);
            assert!(!m.get_is_group()); // DM
            let meta: serde_json::Value =
                serde_json::from_str(m.get_metadata().unwrap().to_str().unwrap()).unwrap();
            assert_eq!(meta["encrypted"], true);
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn room_to_inbound_frame() {
    let msg = room_message("discussion", false);
    let mut builder = capnp::message::Builder::new_default();
    convert::matrix_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert!(m.get_is_group()); // room
            let meta: serde_json::Value =
                serde_json::from_str(m.get_metadata().unwrap().to_str().unwrap()).unwrap();
            assert_eq!(meta["room_name"], "General");
            assert_eq!(meta["encrypted"], false);
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn reply_event_preserved() {
    let mut msg = dm_message("replying");
    msg.reply_to_event = Some("$original:example.org".into());

    let mut builder = capnp::message::Builder::new_default();
    convert::matrix_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_reply_to_id().unwrap().to_str().unwrap(),
                "$original:example.org"
            );
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Mention gating
// ---------------------------------------------------------------------------

#[test]
fn dm_always_processed() {
    let msg = dm_message("hi");
    assert!(convert::should_process(
        &msg,
        "@wirken:example.org",
        "Wirken"
    ));
}

#[test]
fn room_without_mention_not_processed() {
    let msg = room_message("hello everyone", true);
    assert!(!convert::should_process(
        &msg,
        "@wirken:example.org",
        "Wirken"
    ));
}

#[test]
fn room_with_mxid_mention_processed() {
    let msg = room_message("@wirken:example.org what time is it?", true);
    assert!(convert::should_process(
        &msg,
        "@wirken:example.org",
        "Wirken"
    ));
}

#[test]
fn room_with_display_name_mention_processed() {
    let msg = room_message("Wirken what time is it?", true);
    assert!(convert::should_process(
        &msg,
        "@wirken:example.org",
        "Wirken"
    ));
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
        outbound.set_conversation_id("!room456:example.org");
        outbound.set_text("Agent reply");
        outbound.set_reply_to_id("$ev2:example.org");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.room_id, "!room456:example.org");
    assert_eq!(fields.text, "Agent reply");
    assert_eq!(fields.reply_to_event.unwrap(), "$ev2:example.org");
}

#[test]
fn parse_outbound_no_reply() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("!room:example.org");
        outbound.set_text("New message");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert!(fields.reply_to_event.is_none());
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "$sent:example.org", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "$sent:example.org"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 33);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 33),
        _ => panic!("expected Heartbeat"),
    }
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("matrix");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "matrix");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "matrix");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("matrix");
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
            assert_eq!(id, "matrix");
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

    // Phase 2: Adapter sends inbound
    let mut inbound = capnp::message::Builder::new_default();
    convert::matrix_to_inbound(&dm_message("Hello from E2EE Matrix"), &mut inbound);
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads it
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "matrix");
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from E2EE Matrix"
            );
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("!dm123:example.org");
        m.set_text("Reply from agent");
        m.set_reply_to_id("$ev1:example.org");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads it
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.room_id, "!dm123:example.org");
    assert_eq!(fields.text, "Reply from agent");

    // Phase 4: Delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "$sent:example.org", "");
    aw.write_message(&result).await.unwrap();

    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Compile-time isolation: all channel types are distinct
// ---------------------------------------------------------------------------

#[test]
fn six_channel_types_are_distinct() {
    use wirken_ipc::channels::{Discord, Matrix, Slack, Teams, Telegram};
    use wirken_ipc::{SessionHandle, SessionId};

    let tg: SessionHandle<Telegram> = SessionHandle::new(SessionId("s1".into()));
    let dc: SessionHandle<Discord> = SessionHandle::new(SessionId("s1".into()));
    let sl: SessionHandle<Slack> = SessionHandle::new(SessionId("s1".into()));
    let tm: SessionHandle<Teams> = SessionHandle::new(SessionId("s1".into()));
    let mx: SessionHandle<Matrix> = SessionHandle::new(SessionId("s1".into()));

    assert_eq!(tg.channel_id(), "telegram");
    assert_eq!(dc.channel_id(), "discord");
    assert_eq!(sl.channel_id(), "slack");
    assert_eq!(tm.channel_id(), "teams");
    assert_eq!(mx.channel_id(), "matrix");
}
