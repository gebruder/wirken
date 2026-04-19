use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert::{self, Activity, ChannelAccount, ConversationAccount};
use crate::error::{AuthError, TeamsError};
use crate::adapter::TeamsAdapter;

// ---------------------------------------------------------------------------
// Activity construction helpers
// ---------------------------------------------------------------------------

fn personal_message(text: &str) -> Activity {
    Activity {
        activity_type: "message".into(),
        id: Some("msg-001".into()),
        timestamp: Some("2026-03-25T10:30:00Z".into()),
        text: Some(text.into()),
        from: Some(ChannelAccount {
            id: Some("user-123".into()),
            name: Some("Alice".into()),
            aad_object_id: Some("aad-456".into()),
        }),
        conversation: Some(ConversationAccount {
            id: Some("conv-789".into()),
            name: None,
            conversation_type: Some("personal".into()),
            is_group: Some(false),
            tenant_id: Some("tenant-abc".into()),
        }),
        channel_id: Some("msteams".into()),
        service_url: Some("https://smba.trafficmanager.net/teams/".into()),
        reply_to_id: None,
        channel_data: None,
        entities: None,
    }
}

fn group_message(text: &str, bot_mentioned: bool) -> Activity {
    let mut entities = Vec::new();
    if bot_mentioned {
        entities.push(serde_json::json!({
            "type": "mention",
            "mentioned": { "id": "bot-id-28:abc" },
            "text": "<at>WirkenBot</at>"
        }));
    }

    Activity {
        activity_type: "message".into(),
        id: Some("msg-002".into()),
        timestamp: Some("2026-03-25T10:31:00Z".into()),
        text: Some(text.into()),
        from: Some(ChannelAccount {
            id: Some("user-456".into()),
            name: Some("Bob".into()),
            aad_object_id: None,
        }),
        conversation: Some(ConversationAccount {
            id: Some("group-conv-111".into()),
            name: Some("Team Chat".into()),
            conversation_type: Some("groupChat".into()),
            is_group: Some(true),
            tenant_id: Some("tenant-abc".into()),
        }),
        channel_id: Some("msteams".into()),
        service_url: Some("https://smba.trafficmanager.net/teams/".into()),
        reply_to_id: None,
        channel_data: None,
        entities: Some(entities),
    }
}

// ---------------------------------------------------------------------------
// Activity to IPC conversion
// ---------------------------------------------------------------------------

#[test]
fn personal_message_to_inbound() {
    let activity = personal_message("Hello from Teams");
    let mut msg = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, "bot-id-28:abc", &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "msg-001");
            assert_eq!(m.get_sender_id().unwrap().to_str().unwrap(), "user-123");
            assert_eq!(m.get_sender_name().unwrap().to_str().unwrap(), "Alice");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "teams");
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "conv-789"
            );
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello from Teams");
            // 2026-03-25T10:30:00Z
            let expected_ts = chrono::DateTime::parse_from_rfc3339("2026-03-25T10:30:00Z")
                .unwrap()
                .timestamp_millis();
            assert_eq!(m.get_timestamp(), expected_ts);
            assert!(!m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn group_message_with_mention_to_inbound() {
    let activity = group_message("<at>WirkenBot</at> what time is it?", true);
    let mut msg = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, "bot-id-28:abc", &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            // Mention text should be stripped
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "what time is it?");
            assert!(m.get_is_group());
            let meta: serde_json::Value =
                serde_json::from_str(m.get_metadata().unwrap().to_str().unwrap()).unwrap();
            assert_eq!(meta["bot_mentioned"], true);
            assert_eq!(meta["conversation_type"], "groupChat");
            assert_eq!(meta["tenant_id"], "tenant-abc");
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn group_message_metadata_contains_service_url() {
    let activity = personal_message("hi");
    let mut msg = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, "bot-id", &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            let meta: serde_json::Value =
                serde_json::from_str(m.get_metadata().unwrap().to_str().unwrap()).unwrap();
            assert!(
                meta["service_url"]
                    .as_str()
                    .unwrap()
                    .contains("trafficmanager")
            );
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Mention gating
// ---------------------------------------------------------------------------

#[test]
fn personal_chat_always_processed() {
    let activity = personal_message("hello");
    assert!(convert::should_process(&activity, "bot-id-28:abc"));
}

#[test]
fn group_without_mention_not_processed() {
    let activity = group_message("hello everyone", false);
    assert!(!convert::should_process(&activity, "bot-id-28:abc"));
}

#[test]
fn group_with_mention_processed() {
    let activity = group_message("<at>WirkenBot</at> help", true);
    assert!(convert::should_process(&activity, "bot-id-28:abc"));
}

#[test]
fn non_message_activity_not_processed() {
    let mut activity = personal_message("hello");
    activity.activity_type = "conversationUpdate".into();
    assert!(!convert::should_process(&activity, "bot-id"));
}

// ---------------------------------------------------------------------------
// Mention stripping
// ---------------------------------------------------------------------------

#[test]
fn mention_stripped_from_text() {
    let activity = group_message("<at>WirkenBot</at> what is 2+2?", true);
    let mut msg = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, "bot-id-28:abc", &mut msg);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            let text = m.get_text().unwrap().to_str().unwrap();
            assert!(!text.contains("<at>"));
            assert!(text.contains("what is 2+2?"));
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
        outbound.set_conversation_id("conv-789");
        outbound.set_text("Reply from agent");
        outbound.set_reply_to_id("msg-001");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "conv-789");
    assert_eq!(fields.text, "Reply from agent");
    assert_eq!(fields.reply_to_id.unwrap(), "msg-001");
}

#[test]
fn build_outbound_result_success() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "teams-msg-42", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "teams-msg-42"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 55);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 55),
        _ => panic!("expected Heartbeat"),
    }
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("teams");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "teams");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "teams");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("teams");
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
            assert_eq!(id, "teams");
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

    // Phase 2: Adapter sends inbound (simulating a Teams activity)
    let activity = personal_message("Hello from Teams");
    let mut inbound = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, "bot-id", &mut inbound);
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "teams");
            assert_eq!(m.get_text().unwrap().to_str().unwrap(), "Hello from Teams");
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("conv-789");
        m.set_text("Hello! How can I help?");
        m.set_reply_to_id("msg-001");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Hello! How can I help?");
    assert_eq!(fields.reply_to_id.unwrap(), "msg-001");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "teams-reply-99", "");
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
                "teams-reply-99"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Compile-time isolation: five channel types are distinct
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_empty_app_id() {
    let id = AdapterIdentity::generate("teams");
    let r = TeamsAdapter::new(id, String::new(), "password".into(), 3978);
    match r {
        Err(TeamsError::Config(msg)) => assert!(msg.contains("app_id"), "msg: {msg}"),
        Err(other) => panic!("expected Config error for empty app_id, got {other:?}"),
        Ok(_) => panic!("empty app_id must fail at construction"),
    }
}

#[test]
fn new_rejects_empty_app_password() {
    let id = AdapterIdentity::generate("teams");
    let r = TeamsAdapter::new(id, "app-id".into(), String::new(), 3978);
    match r {
        Err(TeamsError::Config(msg)) => assert!(msg.contains("app_password"), "msg: {msg}"),
        Err(other) => panic!("expected Config error for empty app_password, got {other:?}"),
        Ok(_) => panic!("empty app_password must fail at construction"),
    }
}

#[test]
fn new_accepts_both_non_empty() {
    let id = AdapterIdentity::generate("teams");
    let r = TeamsAdapter::new(id, "app-id".into(), "password".into(), 3978);
    assert!(r.is_ok());
}

// ---------------------------------------------------------------------------
// Authorization header extraction
// ---------------------------------------------------------------------------

#[test]
fn bearer_token_extracted_from_authorization_header() {
    let req = "POST /api/messages HTTP/1.1\r\n\
               Host: bot.example\r\n\
               Authorization: Bearer abc.def.ghi\r\n\
               Content-Type: application/json\r\n\
               \r\n\
               {}";
    let token = extract_bearer_token(req).unwrap();
    assert_eq!(token, "abc.def.ghi");
}

#[test]
fn bearer_token_is_case_insensitive_on_header_name() {
    let req = "POST /api/messages HTTP/1.1\r\n\
               authorization: Bearer tok\r\n\
               \r\n";
    assert_eq!(extract_bearer_token(req).unwrap(), "tok");
}

#[test]
fn missing_authorization_header_is_rejected() {
    let req = "POST /api/messages HTTP/1.1\r\n\
               Host: bot.example\r\n\
               \r\n";
    match extract_bearer_token(req) {
        Err(AuthError::MissingHeader) => {}
        other => panic!("expected MissingHeader, got {other:?}"),
    }
}

#[test]
fn non_bearer_scheme_is_rejected() {
    let req = "POST /api/messages HTTP/1.1\r\n\
               Authorization: Basic dXNlcjpwYXNz\r\n\
               \r\n";
    match extract_bearer_token(req) {
        Err(AuthError::MalformedHeader) => {}
        other => panic!("expected MalformedHeader for Basic scheme, got {other:?}"),
    }
}

#[test]
fn empty_bearer_token_is_rejected() {
    let req = "POST /api/messages HTTP/1.1\r\n\
               Authorization: Bearer \r\n\
               \r\n";
    match extract_bearer_token(req) {
        Err(AuthError::MalformedHeader) => {}
        other => panic!("expected MalformedHeader for empty token, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// JWT validation
// ---------------------------------------------------------------------------

mod jwt {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use serde_json::json;

    const TEST_ISSUER: &str = "https://api.botframework.com";
    const TEST_AUD: &str = "11111111-2222-3333-4444-555555555555";
    const TEST_KID: &str = "test-kid-01";

    fn keypair() -> (EncodingKey, DecodingKey) {
        let mut rng = rand08::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = rsa::RsaPublicKey::from(&private);

        let priv_pem = private.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = public.to_pkcs1_pem(LineEnding::LF).unwrap();

        let enc = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let dec = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        (enc, dec)
    }

    fn sign(enc: &EncodingKey, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(&header, claims, enc).unwrap()
    }

    fn exp_future() -> i64 {
        chrono::Utc::now().timestamp() + 3600
    }

    fn exp_past() -> i64 {
        chrono::Utc::now().timestamp() - 3600
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        let token = sign(
            &enc,
            TEST_KID,
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        let claims = cache.validate_token(&token, TEST_AUD).await.unwrap();
        assert_eq!(claims.aud, TEST_AUD);
        assert_eq!(claims.iss, TEST_ISSUER);
    }

    #[tokio::test]
    async fn token_with_wrong_aud_is_rejected() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        let token = sign(
            &enc,
            TEST_KID,
            &json!({
                "iss": TEST_ISSUER,
                "aud": "some-other-app-id",
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtValidation(_)) => {}
            other => panic!("expected JwtValidation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        let token = sign(
            &enc,
            TEST_KID,
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_past(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtValidation(_)) => {}
            other => panic!("expected JwtValidation for expired token, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_with_wrong_issuer_is_rejected() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        let token = sign(
            &enc,
            TEST_KID,
            &json!({
                "iss": "https://evil.example",
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtValidation(_)) => {}
            other => panic!("expected issuer rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_signed_by_foreign_key_is_rejected() {
        let (_trusted_enc, trusted_dec) = keypair();
        let (attacker_enc, _attacker_dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), trusted_dec)], TEST_ISSUER);

        // Attacker signs with their own key but advertises the trusted kid.
        let token = sign(
            &attacker_enc,
            TEST_KID,
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtValidation(_)) => {}
            other => panic!(
                "signature verification must reject foreign-signed tokens, got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn token_with_unknown_kid_is_rejected() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        let token = sign(
            &enc,
            "unknown-kid",
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::UnknownKid(k)) => assert_eq!(k, "unknown-kid"),
            Err(AuthError::JwksFetch(_)) => {
                // for_test cache does not hit the network, but the
                // refresh path is exercised first on miss; an empty
                // openid_config_url means the refresh errors before
                // JwksFetch bubbles out. Accept either.
            }
            other => panic!("expected UnknownKid or JwksFetch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_without_kid_is_rejected() {
        let (enc, dec) = keypair();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), dec)], TEST_ISSUER);
        // Sign without setting the kid header.
        let header = Header::new(Algorithm::RS256);
        let claims = json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUD,
            "exp": exp_future(),
        });
        let token = encode(&header, &claims, &enc).unwrap();
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtHeader(_)) => {}
            other => panic!("expected JwtHeader rejection, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time isolation: five channel types are distinct
// ---------------------------------------------------------------------------

#[test]
fn five_channel_types_are_distinct() {
    use wirken_ipc::channels::{Discord, Slack, Teams, Telegram};
    use wirken_ipc::{SessionHandle, SessionId};

    let tg: SessionHandle<Telegram> = SessionHandle::new(SessionId("s1".into()));
    let dc: SessionHandle<Discord> = SessionHandle::new(SessionId("s1".into()));
    let sl: SessionHandle<Slack> = SessionHandle::new(SessionId("s1".into()));
    let tm: SessionHandle<Teams> = SessionHandle::new(SessionId("s1".into()));

    assert_eq!(tg.channel_id(), "telegram");
    assert_eq!(dc.channel_id(), "discord");
    assert_eq!(sl.channel_id(), "slack");
    assert_eq!(tm.channel_id(), "teams");
}
