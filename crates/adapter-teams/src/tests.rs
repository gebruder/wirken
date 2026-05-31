use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::adapter::TeamsAdapter;
use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert::{self, Activity, ChannelAccount, ConversationAccount};
use crate::error::{AuthError, TeamsError};

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
        value: None,
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
        value: None,
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
    use crate::auth::RsaPubKey;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    use serde_json::json;

    const TEST_ISSUER: &str = "https://api.botframework.com";
    const TEST_AUD: &str = "11111111-2222-3333-4444-555555555555";
    const TEST_KID: &str = "test-kid-01";

    // 2048-bit RSA test keypair, PKCS#8-DER encoded so ring's
    // `RsaKeyPair::from_pkcs8` can load it directly. Public n,e are
    // committed alongside (raw big-endian, no leading zeros) so the
    // JwksCache test seed mirrors what the production refresh path
    // stores after base64url-decoding JWKS values.
    const LEGIT_PKCS8: &[u8] = include_bytes!("test_rsa_legit.pkcs8.der");
    const LEGIT_N: &[u8] = include_bytes!("test_rsa_legit.n.bin");
    const LEGIT_E: &[u8] = include_bytes!("test_rsa_legit.e.bin");
    /// Second, independently generated 2048-bit RSA key used to
    /// exercise the "foreign signer" path in validation tests. Its
    /// public half is never trusted.
    const ATTACKER_PKCS8: &[u8] = include_bytes!("test_rsa_attacker.pkcs8.der");

    fn legit_signer() -> RsaKeyPair {
        RsaKeyPair::from_pkcs8(LEGIT_PKCS8).unwrap()
    }

    fn legit_pubkey() -> RsaPubKey {
        RsaPubKey {
            n: LEGIT_N.to_vec(),
            e: LEGIT_E.to_vec(),
        }
    }

    fn attacker_signer() -> RsaKeyPair {
        RsaKeyPair::from_pkcs8(ATTACKER_PKCS8).unwrap()
    }

    fn b64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn sign(kp: &RsaKeyPair, kid: Option<&str>, claims: &serde_json::Value) -> String {
        let header = match kid {
            Some(k) => json!({ "alg": "RS256", "kid": k, "typ": "JWT" }),
            None => json!({ "alg": "RS256", "typ": "JWT" }),
        };
        let header_b64 = b64url(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = b64url(&serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signing_input}.{}", b64url(&sig))
    }

    fn exp_future() -> i64 {
        chrono::Utc::now().timestamp() + 3600
    }

    fn exp_past() -> i64 {
        chrono::Utc::now().timestamp() - 3600
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
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
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
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
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
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
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
            &json!({
                "iss": "https://evil.example",
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::IssuerRejected(_)) => {}
            other => panic!("expected issuer rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_signed_by_foreign_key_is_rejected() {
        let attacker = attacker_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);

        // Attacker signs with their own key but advertises the trusted kid.
        let token = sign(
            &attacker,
            Some(TEST_KID),
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
        match cache.validate_token(&token, TEST_AUD).await {
            Err(AuthError::JwtValidation(_)) => {}
            other => {
                panic!("signature verification must reject foreign-signed tokens, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn token_with_unknown_kid_is_rejected() {
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some("unknown-kid"),
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
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            None,
            &json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUD,
                "exp": exp_future(),
            }),
        );
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

// ---------------------------------------------------------------------------
// Approval-frame conversions (slice: teams approval gate per umbrella #119)
// ---------------------------------------------------------------------------

#[test]
fn approval_decision_allow_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "req-uuid", true, "aad-object-id-guid", "Davi");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), "req-uuid");
            assert_eq!(
                d.get_actor_user_id().unwrap().to_str().unwrap(),
                "aad-object-id-guid"
            );
            assert_eq!(d.get_actor_display().unwrap().to_str().unwrap(), "Davi");
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
    convert::build_approval_decision(&mut msg, "r", false, "aad", "");
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
    convert::build_approval_request_failed(&mut msg, "req-x", "teams_api_error");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalRequestFailed(f) => {
            let f = f.unwrap();
            assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), "req-x");
            assert_eq!(f.get_reason().unwrap().to_str().unwrap(), "teams_api_error");
        }
        _ => panic!("expected ApprovalRequestFailed"),
    }
}

#[test]
fn approval_request_round_trips_compound_conversation_id() {
    // Teams conversation ids are compound strings with format
    // subcategories: meetings, 1:1 chats, channel threads. The
    // adapter rounds them through unchanged; the platform validates
    // shape on send.
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
        req.set_target_conversation_id("19:meeting_abc123@thread.v2");
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.request_id, "abc");
    assert_eq!(fields.tool_name, "shell");
    assert_eq!(fields.action_key, "shell:rm");
    assert_eq!(fields.requested_tier, "tier3");
    assert_eq!(fields.triggering_agent, "default");
    assert_eq!(fields.trigger_message, "clean logs");
    assert_eq!(fields.target_channel_id, "19:meeting_abc123@thread.v2");
    // serviceUrl was not set on the frame; parse must surface it as
    // an empty string (the gateway-did-not-populate case).
    assert_eq!(fields.service_url, "");
}

#[test]
fn approval_request_round_trips_service_url() {
    // The gateway populates serviceUrl with the originating
    // regional Bot Connector URL for the target conversation. The
    // adapter parses it through to ApprovalRequestFields without
    // modification.
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
        req.set_target_conversation_id("19:meeting_abc123@thread.v2");
        req.set_service_url("https://smba.eu.trafficmanager.net");
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.service_url, "https://smba.eu.trafficmanager.net");
    // Other fields unchanged.
    assert_eq!(fields.request_id, "abc");
    assert_eq!(fields.target_channel_id, "19:meeting_abc123@thread.v2");
}

#[test]
fn effective_service_url_uses_frame_value_when_populated() {
    let svc =
        crate::adapter::effective_service_url("https://smba.gov.trafficmanager.us", "req-001");
    assert_eq!(svc, "https://smba.gov.trafficmanager.us");
}

#[test]
fn effective_service_url_falls_back_when_empty() {
    // The frame-value-empty case is the "gateway did not populate
    // the field" path. The function returns the hardcoded
    // public-cloud default; the warning emit is a side effect not
    // asserted here (it lands in tracing).
    let svc = crate::adapter::effective_service_url("", "req-002");
    assert_eq!(svc, "https://smba.trafficmanager.net");
}

#[test]
fn approval_request_rejects_empty_conversation_id() {
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
        req.set_target_conversation_id("");
    }
    let reader = serialize_and_read(&msg);
    assert!(
        convert::parse_approval_request(&reader).is_err(),
        "empty conversation id must reject"
    );
}

// ---------------------------------------------------------------------------
// Cross-adapter wirken_approval round-trip
// ---------------------------------------------------------------------------

#[test]
fn wirken_approval_round_trip_through_shared_encoding() {
    use wirken_adapter_core::approval::{ApprovalPayload, Decision, decode, encode};
    let original = ApprovalPayload {
        request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        decision: Decision::Allow,
    };
    let wire = encode(&original).unwrap();
    let decoded = decode(&wire).unwrap();
    assert_eq!(decoded, original);
}

// ---------------------------------------------------------------------------
// extract_approval_payload + drop-path coverage
// ---------------------------------------------------------------------------

fn approval_press_activity(value: Option<serde_json::Value>) -> Activity {
    Activity {
        activity_type: "message".into(),
        id: Some("press-001".into()),
        timestamp: Some("2026-05-17T00:00:00Z".into()),
        text: None,
        from: Some(ChannelAccount {
            id: Some("user-123".into()),
            name: Some("Alice".into()),
            aad_object_id: Some("aad-guid-abc".into()),
        }),
        conversation: Some(ConversationAccount {
            id: Some("19:thread@thread.tacv2".into()),
            name: None,
            conversation_type: Some("channel".into()),
            is_group: Some(true),
            tenant_id: Some("tenant-abc".into()),
        }),
        channel_id: Some("msteams".into()),
        service_url: Some("https://smba.trafficmanager.net".into()),
        reply_to_id: None,
        channel_data: None,
        entities: None,
        value,
    }
}

#[test]
fn extract_approval_payload_returns_value() {
    let activity = approval_press_activity(Some(serde_json::json!({
        "wirken_approval": "req:550e8400-e29b-41d4-a716-446655440000:allow",
    })));
    let extracted = convert::extract_approval_payload(&activity);
    assert_eq!(
        extracted,
        Some("req:550e8400-e29b-41d4-a716-446655440000:allow")
    );
}

#[test]
fn extract_approval_payload_returns_none_when_missing() {
    // No value at all (chat message, not a press).
    let activity = approval_press_activity(None);
    assert_eq!(convert::extract_approval_payload(&activity), None);
}

#[test]
fn extract_approval_payload_returns_none_when_field_absent() {
    // Value is an object but no wirken_approval field (some other
    // Action.Submit unrelated to approval).
    let activity = approval_press_activity(Some(serde_json::json!({
        "other_field": "x",
    })));
    assert_eq!(convert::extract_approval_payload(&activity), None);
}

#[test]
fn extract_approval_payload_returns_none_when_value_is_not_object() {
    // Value is a JSON string, not an object. extract should
    // return None so the routing falls through to the regular
    // message path.
    let activity = approval_press_activity(Some(serde_json::json!("just a string")));
    assert_eq!(convert::extract_approval_payload(&activity), None);
}

#[test]
fn extract_approval_payload_returns_none_when_value_is_not_string() {
    // Value object has wirken_approval but it's a number, not
    // a string. extract returns None and the press drops cleanly.
    let activity = approval_press_activity(Some(serde_json::json!({
        "wirken_approval": 42,
    })));
    assert_eq!(convert::extract_approval_payload(&activity), None);
}
