use crate::auth::AdapterIdentity;
#[cfg(unix)]
use crate::auth::{perform_adapter_handshake, perform_gateway_handshake};
use crate::channel::{Channel, Discord, Generic, SessionHandle, SessionId, Telegram};
#[cfg(unix)]
use crate::error::HandshakeError;
#[cfg(unix)]
use crate::transport::split_stream;
#[cfg(unix)]
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

#[cfg(unix)]
#[tokio::test]
async fn frame_roundtrip_inbound_message() {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();

    let (_client_reader, mut client_writer) = split_stream(client);
    let (mut server_reader, _server_writer) = split_stream(server);

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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

// ---------------------------------------------------------------------------
// AuthenticatedChannel: gateway-side inbound channel pinning
// ---------------------------------------------------------------------------

#[test]
fn authenticated_channel_accepts_matching_claim() {
    use crate::AuthenticatedChannel;
    let auth = AuthenticatedChannel::new("telegram");
    assert!(auth.require_match("telegram").is_ok());
}

#[test]
fn authenticated_channel_rejects_cross_channel_claim() {
    use crate::{AuthenticatedChannel, ChannelMismatch};
    let auth = AuthenticatedChannel::new("telegram");
    match auth.require_match("slack") {
        Err(ChannelMismatch {
            authenticated,
            claimed,
        }) => {
            assert_eq!(authenticated, "telegram");
            assert_eq!(claimed, "slack");
        }
        Ok(_) => panic!("cross-channel claim must not match"),
    }
}

#[test]
fn authenticated_channel_is_case_sensitive() {
    use crate::AuthenticatedChannel;
    // A Unicode-lookalike or different-case channel must not
    // collide with the authenticated one. Channel ids are internal
    // enum names (per `Channel::id`) — any variance is a bug
    // upstream, and this check holds the line.
    let auth = AuthenticatedChannel::new("telegram");
    assert!(auth.require_match("Telegram").is_err());
    assert!(auth.require_match("TELEGRAM").is_err());
    assert!(auth.require_match(" telegram").is_err());
    assert!(auth.require_match("telegram ").is_err());
}

#[test]
fn authenticated_channel_rejects_empty_claim() {
    use crate::AuthenticatedChannel;
    let auth = AuthenticatedChannel::new("telegram");
    assert!(auth.require_match("").is_err());
}

// ---------------------------------------------------------------------------
// Principal: tagged-string round trip
// ---------------------------------------------------------------------------

#[test]
fn principal_uid_display() {
    assert_eq!(crate::Principal::Uid(1000).to_string(), "uid:1000");
    assert_eq!(crate::Principal::Uid(0).to_string(), "uid:0");
}

#[test]
fn principal_sid_display() {
    assert_eq!(
        crate::Principal::Sid("S-1-5-21-1234-5678".into()).to_string(),
        "sid:S-1-5-21-1234-5678"
    );
}

#[test]
fn principal_parse_uid() {
    let p: crate::Principal = "uid:1000".parse().unwrap();
    assert_eq!(p, crate::Principal::Uid(1000));
}

#[test]
fn principal_parse_sid() {
    let p: crate::Principal = "sid:S-1-5-21-1234".parse().unwrap();
    assert_eq!(p, crate::Principal::Sid("S-1-5-21-1234".into()));
}

#[test]
fn principal_parse_rejects_unknown_prefix() {
    assert!("user:1000".parse::<crate::Principal>().is_err());
    assert!("1000".parse::<crate::Principal>().is_err());
    assert!("".parse::<crate::Principal>().is_err());
}

#[test]
fn principal_parse_rejects_empty_sid() {
    assert!("sid:".parse::<crate::Principal>().is_err());
}

#[test]
fn principal_parse_rejects_non_numeric_uid() {
    assert!("uid:abc".parse::<crate::Principal>().is_err());
    assert!("uid:".parse::<crate::Principal>().is_err());
    assert!("uid:-1".parse::<crate::Principal>().is_err());
}

#[test]
fn principal_round_trip_via_string() {
    let cases = [
        crate::Principal::Uid(0),
        crate::Principal::Uid(u32::MAX),
        crate::Principal::Sid("S-1-5-21-1234-5678-90".into()),
    ];
    for original in cases {
        let s = original.to_string();
        let parsed: crate::Principal = s.parse().unwrap();
        assert_eq!(parsed, original);
    }
}

#[test]
fn principal_serde_uses_tagged_string() {
    let p = crate::Principal::Uid(1000);
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(json, "\"uid:1000\"");

    let back: crate::Principal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

#[test]
fn principal_serde_sid_round_trip() {
    let p = crate::Principal::Sid("S-1-5-21-1234".into());
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(json, "\"sid:S-1-5-21-1234\"");

    let back: crate::Principal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

#[test]
fn principal_deserialize_rejects_malformed() {
    let bad = "\"user:1000\"";
    let result: Result<crate::Principal, _> = serde_json::from_str(bad);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Stream trait + test_pair: in-process duplex through trait objects
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn test_pair_round_trips_bytes_through_trait_objects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut a, mut b) = crate::test_pair().expect("test_pair");

    a.write_all(b"ping").await.unwrap();
    a.flush().await.unwrap();

    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    b.write_all(b"pong").await.unwrap();
    b.flush().await.unwrap();

    let mut buf = [0u8; 4];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}

#[cfg(unix)]
#[tokio::test]
async fn test_pair_peer_principal_is_uid_variant() {
    let (a, b) = crate::test_pair().expect("test_pair");
    let pa = a.peer_principal().expect("peer_principal a");
    let pb = b.peer_principal().expect("peer_principal b");
    // socketpair sockets share the calling process's credentials, so
    // both ends report the same uid.
    assert!(matches!(pa, crate::Principal::Uid(_)));
    assert_eq!(pa, pb);
}

// ---------------------------------------------------------------------------
// Windows: named-pipe round-trip smoke
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[tokio::test]
async fn windows_named_pipe_round_trip() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = format!(r"\\.\pipe\wirken-ipc-test-{}-{}", std::process::id(), n,);

    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .expect("create server pipe");

    let path_for_client = path.clone();
    let client_handle =
        tokio::task::spawn_blocking(move || ClientOptions::new().open(&path_for_client));

    server.connect().await.expect("server connect");
    let mut server = server;
    let mut client = client_handle
        .await
        .expect("join client task")
        .expect("open client pipe");

    server.write_all(b"hello").await.expect("server write");
    server.flush().await.expect("server flush");

    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"hello");

    client.write_all(b"world").await.expect("client write");
    client.flush().await.expect("client flush");

    let mut buf = [0u8; 5];
    server.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"world");

    // peer_principal on the connected server returns the client's
    // user SID. Same process, so it's the SID of whoever's running
    // the test runner — we just assert it's a Sid variant of the
    // expected `S-...` shape.
    let principal = crate::Stream::peer_principal(&server).expect("peer_principal");
    match principal {
        crate::Principal::Sid(ref s) => {
            assert!(
                s.starts_with("S-"),
                "expected SID string starting with 'S-', got {s:?}"
            );
        }
        other => panic!("expected Principal::Sid on windows, got {other:?}"),
    }

    // The Stream trait is implemented for both ends; boxing as trait
    // objects exercises the supertrait bounds at the type level.
    let _server_box: Box<dyn crate::Stream + Send> = Box::new(server);
    let _client_box: Box<dyn crate::Stream + Send> = Box::new(client);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_named_pipe_peer_principal_errors_when_no_client() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::windows::named_pipe::ServerOptions;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = format!(r"\\.\pipe\wirken-ipc-noclient-{}-{}", std::process::id(), n);

    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .expect("create server pipe");

    // No client has connected. GetNamedPipeClientProcessId should
    // fail; peer_principal must surface that as an IO error rather
    // than fabricating a principal.
    let result = crate::Stream::peer_principal(&server);
    assert!(
        result.is_err(),
        "peer_principal should be Err when no client is connected"
    );
}

// ---------------------------------------------------------------------------
// Listener trait: bind/connect round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_round_trip_through_trait_objects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // On unix the path is a unix-domain socket file; on windows it
    // gets mapped to a named-pipe name internally by `bind`/`connect`.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("listener-test.sock");

    let mut listener = crate::bind(&path).expect("bind");
    let path_for_client = path.clone();
    let server_handle = tokio::spawn(async move {
        let mut server = listener.accept().await.expect("accept");
        // Echo one message.
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.expect("server read");
        server.write_all(&buf).await.expect("server write");
        server.flush().await.expect("server flush");
    });

    let mut client = crate::connect(&path_for_client).await.expect("connect");
    client.write_all(b"hello").await.expect("client write");
    client.flush().await.expect("client flush");
    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"hello");

    server_handle.await.expect("join");
}

#[cfg(windows)]
#[tokio::test]
async fn windows_named_pipe_client_peer_principal_is_unsupported() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = format!(
        r"\\.\pipe\wirken-ipc-clientstub-{}-{}",
        std::process::id(),
        n
    );

    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .expect("create server pipe");

    let path_for_client = path.clone();
    let client_handle =
        tokio::task::spawn_blocking(move || ClientOptions::new().open(&path_for_client));

    server.connect().await.expect("server connect");
    let client = client_handle
        .await
        .expect("join client task")
        .expect("open client pipe");

    let result = crate::Stream::peer_principal(&client);
    assert!(
        result.is_err(),
        "client-side peer_principal is intentionally Err until a caller asks for it"
    );

    // Drop server and client cleanly.
    let mut server = server;
    let _ = server.shutdown().await;
}
