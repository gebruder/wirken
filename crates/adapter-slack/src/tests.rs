use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, SlackInbound};

// ---------------------------------------------------------------------------
// Conversion: inbound message building
// ---------------------------------------------------------------------------

#[test]
fn slack_inbound_to_frame() {
    let inbound = SlackInbound {
        message_ts: "1711234567.890123".into(),
        user_id: "U12345ABC".into(),
        user_name: "alice".into(),
        channel_id: "C98765XYZ".into(),
        text: "Hello from Slack!".into(),
        thread_ts: None,
        is_dm: false,
        bot_mentioned: true,
        files: vec![],
    };

    let mut msg = capnp::message::Builder::new_default();
    convert::slack_to_inbound(&inbound, &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "1711234567.890123");
            assert_eq!(m.get_sender_id().unwrap().to_str().unwrap(), "U12345ABC");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "slack");
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "C98765XYZ"
            );
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello from Slack!");
            assert_eq!(m.get_timestamp(), 1711234567890);
            assert!(m.get_is_group()); // not a DM
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn slack_dm_inbound() {
    let inbound = SlackInbound {
        message_ts: "1711234567.000000".into(),
        user_id: "U99999".into(),
        user_name: "bob".into(),
        channel_id: "D11111".into(),
        text: "DM to bot".into(),
        thread_ts: None,
        is_dm: true,
        bot_mentioned: false,
        files: vec![],
    };

    let mut msg = capnp::message::Builder::new_default();
    convert::slack_to_inbound(&inbound, &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert!(!m.get_is_group()); // DM
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn slack_threaded_message() {
    let inbound = SlackInbound {
        message_ts: "1711234567.890123".into(),
        user_id: "U12345".into(),
        user_name: "alice".into(),
        channel_id: "C98765".into(),
        text: "Reply in thread".into(),
        thread_ts: Some("1711234560.000000".into()),
        is_dm: false,
        bot_mentioned: true,
        files: vec![],
    };

    let mut msg = capnp::message::Builder::new_default();
    convert::slack_to_inbound(&inbound, &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_reply_to_id().unwrap().to_str().unwrap(),
                "1711234560.000000"
            );
            let meta_str = m.get_metadata().unwrap().to_str().unwrap();
            let meta: serde_json::Value = serde_json::from_str(meta_str).unwrap();
            assert_eq!(meta["thread_ts"], "1711234560.000000");
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn slack_message_with_files() {
    let inbound = SlackInbound {
        message_ts: "1711234567.890123".into(),
        user_id: "U12345".into(),
        user_name: "alice".into(),
        channel_id: "C98765".into(),
        text: "Check this file".into(),
        thread_ts: None,
        is_dm: false,
        bot_mentioned: true,
        files: vec!["https://files.slack.com/file1.pdf".into()],
    };

    let mut msg = capnp::message::Builder::new_default();
    convert::slack_to_inbound(&inbound, &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            let meta_str = m.get_metadata().unwrap().to_str().unwrap();
            let meta: serde_json::Value = serde_json::from_str(meta_str).unwrap();
            assert!(meta["files"].as_array().unwrap().len() == 1);
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Mention-gating
// ---------------------------------------------------------------------------

#[test]
fn mention_gate_dm_always_passes() {
    let msg = SlackInbound {
        message_ts: "1.0".into(),
        user_id: "U1".into(),
        user_name: "u".into(),
        channel_id: "D1".into(),
        text: "hi".into(),
        thread_ts: None,
        is_dm: true,
        bot_mentioned: false,
        files: vec![],
    };
    assert!(convert::should_process(&msg));
}

#[test]
fn mention_gate_channel_needs_mention() {
    let msg = SlackInbound {
        message_ts: "1.0".into(),
        user_id: "U1".into(),
        user_name: "u".into(),
        channel_id: "C1".into(),
        text: "hi".into(),
        thread_ts: None,
        is_dm: false,
        bot_mentioned: false,
        files: vec![],
    };
    assert!(!convert::should_process(&msg));
}

#[test]
fn mention_gate_channel_with_mention_passes() {
    let msg = SlackInbound {
        message_ts: "1.0".into(),
        user_id: "U1".into(),
        user_name: "u".into(),
        channel_id: "C1".into(),
        text: "<@U_BOT> help".into(),
        thread_ts: None,
        is_dm: false,
        bot_mentioned: true,
        files: vec![],
    };
    assert!(convert::should_process(&msg));
}

// ---------------------------------------------------------------------------
// Conversion: outbound result / heartbeat
// ---------------------------------------------------------------------------

#[test]
fn build_outbound_result_success() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "1711234567.890456", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "1711234567.890456"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 77);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 77),
        _ => panic!("expected Heartbeat"),
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
        outbound.set_conversation_id("C98765XYZ");
        outbound.set_text("Agent reply in Slack");
        outbound.set_reply_to_id("1711234560.000000");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.channel_id, "C98765XYZ");
    assert_eq!(fields.text, "Agent reply in Slack");
    assert_eq!(fields.thread_ts.unwrap(), "1711234560.000000");
}

#[test]
fn parse_outbound_no_thread() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("C11111");
        outbound.set_text("Top-level message");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.channel_id, "C11111");
    assert!(fields.thread_ts.is_none());
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("slack");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "slack");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "slack");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("slack");
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
            assert_eq!(id, "slack");
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
    let mut inbound_builder = capnp::message::Builder::new_default();
    {
        let inbound = SlackInbound {
            message_ts: "1711234567.890123".into(),
            user_id: "U12345".into(),
            user_name: "alice".into(),
            channel_id: "C98765".into(),
            text: "<@UBOT> what time is it?".into(),
            thread_ts: None,
            is_dm: false,
            bot_mentioned: true,
            files: vec![],
        };
        convert::slack_to_inbound(&inbound, &mut inbound_builder);
    }
    aw.write_message(&inbound_builder).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "slack");
            assert!(
                m.get_text()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("what time")
            );
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("C98765");
        m.set_text("It's 3:14 PM.");
        m.set_reply_to_id("1711234567.890123");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.channel_id, "C98765");
    assert_eq!(fields.text, "It's 3:14 PM.");
    assert_eq!(fields.thread_ts.unwrap(), "1711234567.890123");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "1711234568.000001", "");
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
                "1711234568.000001"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Compile-time isolation: all three channels are distinct types
// ---------------------------------------------------------------------------

#[test]
fn three_channel_types_are_distinct() {
    use wirken_ipc::channels::{Discord, Slack, Telegram};
    use wirken_ipc::{SessionHandle, SessionId};

    let tg: SessionHandle<Telegram> = SessionHandle::new(SessionId("s1".into()));
    let dc: SessionHandle<Discord> = SessionHandle::new(SessionId("s1".into()));
    let sl: SessionHandle<Slack> = SessionHandle::new(SessionId("s1".into()));

    assert_eq!(tg.channel_id(), "telegram");
    assert_eq!(dc.channel_id(), "discord");
    assert_eq!(sl.channel_id(), "slack");

    // None of these can be confused — each is a distinct type.
    // The following would NOT compile:
    // let _: SessionHandle<Telegram> = dc;
    // let _: SessionHandle<Discord> = sl;
    // let _: SessionHandle<Slack> = tg;
}
