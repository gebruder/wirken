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

// ---------------------------------------------------------------------------
// Vuln 10: bot mention exact-match
// ---------------------------------------------------------------------------

#[test]
fn bot_mention_detects_exact_match() {
    use crate::convert::is_bot_mentioned;
    assert!(is_bot_mentioned("hello <@U_BOT> please", "U_BOT"));
    assert!(is_bot_mentioned("<@U_BOT>", "U_BOT"));
}

#[test]
fn bot_mention_rejects_other_user_mention() {
    use crate::convert::is_bot_mentioned;
    // The bug fix: a mention of another user must NOT match.
    assert!(!is_bot_mentioned("<@U_TEAMMATE> can you help?", "U_BOT"));
    assert!(!is_bot_mentioned("hey <@U_ADMIN>", "U_BOT"));
}

#[test]
fn bot_mention_rejects_prefix_collision() {
    use crate::convert::is_bot_mentioned;
    // `<@U123>` must not match bot_user_id "U1234" — the closing `>`
    // in the format string prevents substring-prefix confusion.
    assert!(!is_bot_mentioned("<@U123>", "U1234"));
    assert!(!is_bot_mentioned("<@U1>", "U12"));
    // And vice versa: a longer id should not match a shorter bot id.
    assert!(!is_bot_mentioned("<@U1234>", "U123"));
}

#[test]
fn bot_mention_rejects_empty_bot_user_id() {
    use crate::convert::is_bot_mentioned;
    // If somehow bot_user_id is empty (should not happen after
    // auth.test succeeds), refuse to match anything rather than
    // matching every message via `<@` substring.
    assert!(!is_bot_mentioned("<@U_BOT>", ""));
    assert!(!is_bot_mentioned("any text", ""));
}

#[test]
fn bot_mention_no_mention_at_all() {
    use crate::convert::is_bot_mentioned;
    assert!(!is_bot_mentioned("hello everyone", "U_BOT"));
    assert!(!is_bot_mentioned("", "U_BOT"));
}

// ---------------------------------------------------------------------------
// Q3 regression: a Slack thread with mixed senders never leaks
// non-mentioning content into the gateway.
//
// Maps to CVE-2026-41358 (CWE-346) "Slack thread context bypass
// sender allowlist" and GHSA-7hrg-5w46-5r2x duplicate.
//
// Wirken's Slack adapter receives one push event per message
// (`crates/adapter-slack/src/adapter.rs:177`). Each event is
// gated by `should_process` (`crates/adapter-slack/src/convert.rs:56`)
// before being forwarded to the gateway. Non-mentioning channel
// messages are dropped at the adapter; they cannot enter the
// agent's per-conversation session as thread history because
// they never reach the gateway in the first place.
//
// The adapter does not fetch thread history from Slack — there is
// no path from a non-mentioning sender's message into the model
// context.
// ---------------------------------------------------------------------------

#[test]
fn thread_with_mixed_senders_only_mentioning_messages_pass_gate() {
    // Simulate three messages in the same Slack thread:
    //   t=1.0: alice (no mention) — drop at adapter
    //   t=2.0: bob (with `<@U_BOT> help`) — forward
    //   t=3.0: carol (no mention) — drop at adapter
    //
    // The gate is `should_process`. We assert exactly one of the
    // three would be forwarded.
    let alice = SlackInbound {
        message_ts: "1.0".into(),
        user_id: "U_ALICE".into(),
        user_name: "alice".into(),
        channel_id: "C_THREAD".into(),
        text: "anyone got a moment?".into(),
        thread_ts: Some("1.0".into()),
        is_dm: false,
        bot_mentioned: false,
        files: vec![],
    };
    let bob = SlackInbound {
        message_ts: "2.0".into(),
        user_id: "U_BOB".into(),
        user_name: "bob".into(),
        channel_id: "C_THREAD".into(),
        text: "<@U_BOT> can you summarize this thread?".into(),
        thread_ts: Some("1.0".into()),
        is_dm: false,
        bot_mentioned: true,
        files: vec![],
    };
    let carol = SlackInbound {
        message_ts: "3.0".into(),
        user_id: "U_CAROL".into(),
        user_name: "carol".into(),
        channel_id: "C_THREAD".into(),
        text: "I'll check the doc and report back".into(),
        thread_ts: Some("1.0".into()),
        is_dm: false,
        bot_mentioned: false,
        files: vec![],
    };

    assert!(
        !convert::should_process(&alice),
        "alice's non-mention must be dropped"
    );
    assert!(convert::should_process(&bob), "bob's mention must pass");
    assert!(
        !convert::should_process(&carol),
        "carol's non-mention must be dropped"
    );

    // The forwarded frame for bob carries thread_ts in metadata
    // (`crates/adapter-slack/src/convert.rs:42-44`), so an agent
    // that wanted thread history could reconstruct the pointer.
    // But Wirken's adapter does NOT call any Slack history API —
    // alice's and carol's content remains invisible to the agent.
    let mut bob_frame = capnp::message::Builder::new_default();
    convert::slack_to_inbound(&bob, &mut bob_frame);
    let reader = bob_frame.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let ib = ib.unwrap();
            let meta = ib.get_metadata().unwrap().to_str().unwrap();
            // thread_ts is in metadata for the agent to reference,
            // not as a fetch instruction.
            assert!(
                meta.contains("\"thread_ts\""),
                "thread_ts must be carried in metadata for context, not used to fetch: {meta}"
            );
            // Sanity: the text we forwarded is bob's, not alice's
            // or carol's.
            let text = ib.get_text().unwrap().to_str().unwrap();
            assert!(text.contains("summarize"));
            assert!(!text.contains("got a moment"));
            assert!(!text.contains("check the doc"));
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn dm_passes_gate_regardless_of_mention() {
    // Companion: DMs always pass with or without mention. Pinning
    // this so a future tightening of `should_process` does not
    // accidentally break 1:1 DMs by requiring `<@bot>` in DMs too.
    let dm_no_mention = SlackInbound {
        message_ts: "1.0".into(),
        user_id: "U_DM".into(),
        user_name: "dm-user".into(),
        channel_id: "D_DM".into(),
        text: "no mention but still 1:1".into(),
        thread_ts: None,
        is_dm: true,
        bot_mentioned: false,
        files: vec![],
    };
    assert!(convert::should_process(&dm_no_mention));
}

// ---------------------------------------------------------------------------
// from_push_event — echo-loop and noise filtering, thread_ts capture.
// Fixtures use serde_json::from_value to build SlackPushEventCallback the
// same way slack-morphism receives it over WSS, so the parse path is the
// production path.
// ---------------------------------------------------------------------------

mod from_push_event {
    use crate::convert::{SlackBotIdentity, from_push_event};
    use serde_json::json;
    use slack_morphism::prelude::SlackPushEventCallback;

    fn bot() -> SlackBotIdentity {
        SlackBotIdentity {
            user_id: "U_BOT".into(),
            bot_id: Some("B_BOT".into()),
        }
    }

    fn parse(payload: serde_json::Value) -> SlackPushEventCallback {
        serde_json::from_value(payload).expect("fixture must deserialize")
    }

    fn message_event(extra: serde_json::Value) -> SlackPushEventCallback {
        let mut event = json!({
            "type": "message",
            "ts": "1711234567.890123",
            "user": "U_USER",
            "text": "hello there",
            "channel": "C_CHANNEL",
            "channel_type": "channel",
        });
        if let serde_json::Value::Object(extra_map) = extra
            && let serde_json::Value::Object(base) = &mut event
        {
            for (k, v) in extra_map {
                base.insert(k, v);
            }
        }
        parse(json!({
            "team_id": "T1",
            "api_app_id": "A1",
            "event": event,
            "event_id": "Ev1",
            "event_time": 1711234567,
        }))
    }

    #[test]
    fn regular_user_message_passes() {
        let evt = message_event(json!({}));
        let result = from_push_event(&evt, &bot()).expect("regular message must convert");
        assert_eq!(result.user_id, "U_USER");
        assert_eq!(result.text, "hello there");
        assert_eq!(result.channel_id, "C_CHANNEL");
        assert_eq!(result.message_ts, "1711234567.890123");
        assert!(!result.is_dm);
        assert_eq!(result.thread_ts, None);
    }

    #[test]
    fn drops_when_sender_user_is_bot() {
        // The bot's own outbound comes back through `message.im` with
        // user=U_BOT. Forwarding it would drive an infinite echo loop
        // through the agent (one inbound → one response → one event
        // back → repeat).
        let evt = message_event(json!({ "user": "U_BOT" }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_when_sender_bot_id_matches_self() {
        // Some events carry the bot's `bot_id` without a user_id.
        // Belt-and-suspenders against the `subtype: bot_message`
        // path where Slack sometimes omits the user field.
        let evt = message_event(json!({
            "subtype": "bot_message",
            "bot_id": "B_BOT",
            "user": null,
        }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_subtype_bot_message_even_with_other_user() {
        // Defensive: even if Slack tags a `bot_message` with some
        // other user field, drop it. We treat `bot_message` as
        // "never forward to the agent" without exception.
        let evt = message_event(json!({
            "subtype": "bot_message",
            "bot_id": "B_OTHER",
        }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_subtype_message_changed() {
        // Edits of past messages are not user-driven turns. The
        // agent has no concept of editing its previous response, so
        // forwarding edits would silently re-process old text as
        // new input.
        let evt = message_event(json!({ "subtype": "message_changed" }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_subtype_message_deleted() {
        let evt = message_event(json!({
            "subtype": "message_deleted",
            "deleted_ts": "1711234560.000000",
        }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_subtype_channel_join() {
        // Channel-membership events are not messages to the agent.
        let evt = message_event(json!({ "subtype": "channel_join" }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_when_text_empty() {
        let evt = message_event(json!({ "text": "" }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn drops_when_user_missing() {
        let evt = message_event(json!({ "user": null }));
        assert!(from_push_event(&evt, &bot()).is_none());
    }

    #[test]
    fn thread_ts_present_propagates_to_inbound() {
        // The inbound was a reply inside a thread rooted at
        // 1711230000.000000. The bot's response must land in the
        // same thread; the gateway dispatcher and outbound path
        // depend on thread_ts riding on SlackInbound.
        let evt = message_event(json!({
            "thread_ts": "1711230000.000000",
        }));
        let result = from_push_event(&evt, &bot()).expect("threaded message must convert");
        assert_eq!(result.thread_ts, Some("1711230000.000000".to_string()));
    }

    #[test]
    fn thread_ts_absent_yields_none() {
        // Root-of-channel message has no thread_ts. The bot's reply
        // must NOT auto-thread; SlackInbound.thread_ts stays None
        // and propagates as an empty reply_to_id through the
        // capnp frame.
        let evt = message_event(json!({}));
        let result = from_push_event(&evt, &bot()).expect("root message must convert");
        assert_eq!(result.thread_ts, None);
    }

    #[test]
    fn dm_channel_type_is_recognized() {
        let evt = message_event(json!({
            "channel_type": "im",
            "channel": "D12345",
        }));
        let result = from_push_event(&evt, &bot()).expect("DM must convert");
        assert!(result.is_dm);
    }

    #[test]
    fn me_message_subtype_passes() {
        // /me actions are user-driven; pass them through.
        let evt = message_event(json!({ "subtype": "me_message" }));
        assert!(from_push_event(&evt, &bot()).is_some());
    }

    #[test]
    fn file_share_subtype_passes() {
        // file_share carries text + an attachment; the agent
        // should see the text part.
        let evt = message_event(json!({ "subtype": "file_share" }));
        assert!(from_push_event(&evt, &bot()).is_some());
    }
}
