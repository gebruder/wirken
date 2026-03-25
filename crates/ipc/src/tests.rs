use crate::auth::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};
use crate::channel::{Channel, Discord, Generic, SessionHandle, SessionId, Telegram};
use crate::error::HandshakeError;
use crate::transport::split_stream;
use crate::wirken_capnp::frame;

// ---------------------------------------------------------------------------
// Channel marker type safety tests
// ---------------------------------------------------------------------------

#[test]
fn session_handle_typed_to_channel() {
    let handle: SessionHandle<Telegram> = SessionHandle::new(SessionId("sess-1".into()));
    assert_eq!(handle.channel_id(), "telegram");
    assert_eq!(handle.id().0, "sess-1");
}

#[test]
fn session_handles_for_different_channels_are_distinct_types() {
    let tg: SessionHandle<Telegram> = SessionHandle::new(SessionId("s1".into()));
    let dc: SessionHandle<Discord> = SessionHandle::new(SessionId("s1".into()));

    // Same session ID, different types. These cannot be confused at compile time.
    assert_eq!(tg.channel_id(), "telegram");
    assert_eq!(dc.channel_id(), "discord");

    // The following would NOT compile (type mismatch):
    // let _: SessionHandle<Telegram> = dc;
}

#[test]
fn channel_id_strings() {
    assert_eq!(Telegram::id(), "telegram");
    assert_eq!(Discord::id(), "discord");
    assert_eq!(crate::channels::Slack::id(), "slack");
    assert_eq!(crate::channels::Matrix::id(), "matrix");
    assert_eq!(Generic::id(), "generic");
}

#[test]
fn session_handle_clone() {
    let handle: SessionHandle<Telegram> = SessionHandle::new(SessionId("s1".into()));
    let cloned = handle.clone();
    assert_eq!(handle.id().0, cloned.id().0);
    assert_eq!(handle.channel_id(), cloned.channel_id());
}

#[test]
fn session_handle_debug() {
    let handle: SessionHandle<Telegram> = SessionHandle::new(SessionId("debug-test".into()));
    let debug = format!("{:?}", handle);
    assert!(debug.contains("telegram"));
    assert!(debug.contains("debug-test"));
}

// ---------------------------------------------------------------------------
// Compile-time isolation demonstration
// ---------------------------------------------------------------------------

/// This function only accepts Telegram session handles.
/// Passing a Discord handle would be a compile error.
fn telegram_only(_handle: &SessionHandle<Telegram>) -> &'static str {
    "telegram"
}

/// This function only accepts Discord session handles.
fn discord_only(_handle: &SessionHandle<Discord>) -> &'static str {
    "discord"
}

#[test]
fn compile_time_channel_isolation() {
    let tg = SessionHandle::<Telegram>::new(SessionId("t1".into()));
    let dc = SessionHandle::<Discord>::new(SessionId("d1".into()));

    assert_eq!(telegram_only(&tg), "telegram");
    assert_eq!(discord_only(&dc), "discord");

    // The following lines would cause compile errors:
    // telegram_only(&dc); // expected Telegram, found Discord
    // discord_only(&tg);  // expected Discord, found Telegram
}

// ---------------------------------------------------------------------------
// Ed25519 identity tests
// ---------------------------------------------------------------------------

#[test]
fn adapter_identity_generate() {
    let id = AdapterIdentity::generate("telegram");
    assert_eq!(id.adapter_id(), "telegram");
    assert_eq!(id.public_key_bytes().len(), 32);
    assert_eq!(id.secret_key_bytes().len(), 32);
}

#[test]
fn adapter_identity_from_bytes() {
    let id1 = AdapterIdentity::generate("test");
    let secret = *id1.secret_key_bytes();
    let pubkey = id1.public_key_bytes();

    let id2 = AdapterIdentity::from_bytes(&secret, "test");
    assert_eq!(id2.public_key_bytes(), pubkey);
}

#[test]
fn different_identities_have_different_keys() {
    let id1 = AdapterIdentity::generate("adapter-1");
    let id2 = AdapterIdentity::generate("adapter-2");
    assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
}

// ---------------------------------------------------------------------------
// Transport: frame read/write roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn frame_roundtrip_inbound_message() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();

    let (client_reader, mut client_writer) = split_stream(client);
    let (mut server_reader, server_writer) = split_stream(server);

    // Client sends an inbound message
    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut inbound = frame_builder.init_inbound();
        inbound.set_id("msg-001");
        inbound.set_sender_id("user-123");
        inbound.set_sender_name("Alice");
        inbound.set_channel("telegram");
        inbound.set_conversation_id("chat-456");
        inbound.set_text("Hello, world!");
        inbound.set_timestamp(1711234567890);
        inbound.set_is_group(false);
        inbound.set_reply_to_id("");
        inbound.set_metadata("{}");
    }
    client_writer.write_message(&msg).await.unwrap();

    // Server reads it
    let received = server_reader.read_message().await.unwrap();
    let frame_reader = received.get_root::<frame::Reader<'_>>().unwrap();

    match frame_reader.which().unwrap() {
        frame::Inbound(inbound) => {
            let m = inbound.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "msg-001");
            assert_eq!(m.get_sender_id().unwrap().to_str().unwrap(), "user-123");
            assert_eq!(m.get_sender_name().unwrap().to_str().unwrap(), "Alice");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "telegram");
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello, world!");
            assert_eq!(m.get_timestamp(), 1711234567890);
            assert!(!m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

#[tokio::test]
async fn frame_roundtrip_outbound_message() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (_, mut client_writer) = split_stream(client);
    let (mut server_reader, _) = split_stream(server);

    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = frame_builder.init_outbound();
        outbound.set_conversation_id("chat-789");
        outbound.set_text("Reply from agent");
        outbound.set_reply_to_id("msg-001");
        outbound.set_metadata("{}");
    }
    client_writer.write_message(&msg).await.unwrap();

    let received = server_reader.read_message().await.unwrap();
    let frame_reader = received.get_root::<frame::Reader<'_>>().unwrap();

    match frame_reader.which().unwrap() {
        frame::Outbound(outbound) => {
            let m = outbound.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "chat-789"
            );
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Reply from agent");
            assert_eq!(m.get_reply_to_id().unwrap().to_str().unwrap(), "msg-001");
        }
        _ => panic!("expected Outbound"),
    }
}

#[tokio::test]
async fn frame_roundtrip_heartbeat() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (_, mut client_writer) = split_stream(client);
    let (mut server_reader, _) = split_stream(server);

    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut hb = frame_builder.init_heartbeat();
        hb.set_seq(42);
    }
    client_writer.write_message(&msg).await.unwrap();

    let received = server_reader.read_message().await.unwrap();
    let frame_reader = received.get_root::<frame::Reader<'_>>().unwrap();

    match frame_reader.which().unwrap() {
        frame::Heartbeat(hb) => {
            assert_eq!(hb.unwrap().get_seq(), 42);
        }
        _ => panic!("expected Heartbeat"),
    }
}

#[tokio::test]
async fn multiple_frames_sequential() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (_, mut writer) = split_stream(client);
    let (mut reader, _) = split_stream(server);

    // Send 100 heartbeats
    for i in 0..100u64 {
        let mut msg = capnp::message::Builder::new_default();
        {
            let fb = msg.init_root::<frame::Builder<'_>>();
            fb.init_heartbeat().set_seq(i);
        }
        writer.write_message(&msg).await.unwrap();
    }

    // Read them all back
    for i in 0..100u64 {
        let received = reader.read_message().await.unwrap();
        let fr = received.get_root::<frame::Reader<'_>>().unwrap();
        match fr.which().unwrap() {
            frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), i),
            _ => panic!("expected Heartbeat"),
        }
    }
}

#[tokio::test]
async fn connection_closed_detected() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut reader, _) = split_stream(server);

    // Drop client → server sees EOF
    drop(client);

    let result = reader.read_message().await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Ed25519 handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_success() {
    let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("telegram");
    let expected_pubkey = identity.public_key_bytes();

    let (mut client_reader, mut client_writer) = split_stream(client_stream);
    let (mut server_reader, mut server_writer) = split_stream(server_stream);

    // Run both sides concurrently
    let adapter_handle = tokio::spawn(async move {
        perform_adapter_handshake(&mut client_reader, &mut client_writer, &identity).await
    });

    let gateway_handle = tokio::spawn(async move {
        perform_gateway_handshake(
            &mut server_reader,
            &mut server_writer,
            |adapter_id, pubkey| {
                assert_eq!(adapter_id, "telegram");
                assert_eq!(pubkey, &expected_pubkey);
                Ok(())
            },
        )
        .await
    });

    let (adapter_result, gateway_result) = tokio::join!(adapter_handle, gateway_handle);
    adapter_result.unwrap().unwrap();
    let (id, pk) = gateway_result.unwrap().unwrap();
    assert_eq!(id, "telegram");
    assert_eq!(pk, expected_pubkey);
}

#[tokio::test]
async fn handshake_rejected_unknown_adapter() {
    let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("unknown-adapter");
    let (mut client_reader, mut client_writer) = split_stream(client_stream);
    let (mut server_reader, mut server_writer) = split_stream(server_stream);

    let adapter_handle = tokio::spawn(async move {
        perform_adapter_handshake(&mut client_reader, &mut client_writer, &identity).await
    });

    let gateway_handle = tokio::spawn(async move {
        // Gateway rejects — send rejection manually since perform_gateway_handshake
        // will return an error before sending a result
        let result = perform_gateway_handshake(
            &mut server_reader,
            &mut server_writer,
            |adapter_id, _pubkey| Err(HandshakeError::UnknownAdapter(adapter_id.to_string())),
        )
        .await;

        // Gateway should have errored
        assert!(result.is_err());

        // Send rejection to adapter so it doesn't hang
        crate::auth::send_rejection(&mut server_writer, "unknown adapter")
            .await
            .unwrap();
    });

    let (adapter_result, _) = tokio::join!(adapter_handle, gateway_handle);
    // Adapter should receive rejection
    let err = adapter_result.unwrap().unwrap_err();
    assert!(matches!(err, HandshakeError::Rejected(_)));
}

#[tokio::test]
async fn handshake_wrong_key_rejected() {
    let (client_stream, server_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("telegram");
    let different_key = AdapterIdentity::generate("telegram").public_key_bytes();

    let (mut client_reader, mut client_writer) = split_stream(client_stream);
    let (mut server_reader, mut server_writer) = split_stream(server_stream);

    let adapter_handle = tokio::spawn(async move {
        perform_adapter_handshake(&mut client_reader, &mut client_writer, &identity).await
    });

    let gateway_handle = tokio::spawn(async move {
        let result = perform_gateway_handshake(
            &mut server_reader,
            &mut server_writer,
            |_adapter_id, pubkey| {
                // Registered key doesn't match
                if pubkey != &different_key {
                    Err(HandshakeError::InvalidSignature)
                } else {
                    Ok(())
                }
            },
        )
        .await;

        assert!(result.is_err());
        crate::auth::send_rejection(&mut server_writer, "key mismatch")
            .await
            .unwrap();
    });

    let (adapter_result, _) = tokio::join!(adapter_handle, gateway_handle);
    let err = adapter_result.unwrap().unwrap_err();
    assert!(matches!(err, HandshakeError::Rejected(_)));
}
