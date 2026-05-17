use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::adapter::GoogleChatAdapter;
use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert;
use crate::error::{AuthError, GoogleChatError};

// ---------------------------------------------------------------------------
// Payload extraction
// ---------------------------------------------------------------------------

fn message_event(space_type: &str, text: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "MESSAGE",
        "message": {
            "name": "spaces/SPACE_123/messages/MSG_456",
            "sender": {
                "name": "users/USER_789",
                "displayName": "Alice",
                "email": "alice@example.com"
            },
            "text": text,
            "createTime": "2024-01-01T00:00:00Z",
            "space": {
                "name": "spaces/SPACE_123",
                "type": space_type
            }
        }
    })
}

#[test]
fn parse_google_chat_message() {
    let payload = message_event("DM", "Hello wirken!");
    let msg = convert::extract_message(&payload).unwrap();

    assert_eq!(msg.message_id, "spaces/SPACE_123/messages/MSG_456");
    assert_eq!(msg.sender_email, "alice@example.com");
    assert_eq!(msg.sender_name, "Alice");
    assert_eq!(msg.text, "Hello wirken!");
    assert_eq!(msg.space_name, "spaces/SPACE_123");
    assert!(msg.is_dm);

    // 2024-01-01T00:00:00Z in millis
    let expected_ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
        .unwrap()
        .timestamp_millis();
    assert_eq!(msg.timestamp, expected_ts);
}

#[test]
fn ignore_non_message_events() {
    let added = serde_json::json!({
        "type": "ADDED_TO_SPACE",
        "space": { "name": "spaces/SPACE_123", "type": "ROOM" }
    });
    assert!(convert::extract_message(&added).is_none());

    let removed = serde_json::json!({
        "type": "REMOVED_FROM_SPACE",
        "space": { "name": "spaces/SPACE_123", "type": "ROOM" }
    });
    assert!(convert::extract_message(&removed).is_none());
}

#[test]
fn dm_always_processed() {
    let payload = message_event("DM", "hi there");
    let msg = convert::extract_message(&payload).unwrap();
    assert!(msg.is_dm);
    assert!(convert::should_process(&msg));
}

#[test]
fn room_message_processed() {
    let payload = message_event("ROOM", "hello room");
    let msg = convert::extract_message(&payload).unwrap();
    assert!(!msg.is_dm);
    assert!(convert::should_process(&msg));
}

#[test]
fn empty_text_not_processed() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    assert!(!convert::should_process(&msg));
}

#[test]
fn valid_text_processed() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    assert!(convert::should_process(&msg));
}

// ---------------------------------------------------------------------------
// Cap'n Proto inbound frame
// ---------------------------------------------------------------------------

#[test]
fn google_chat_to_inbound_frame() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "alice@example.com".into(),
        sender_name: "Alice".into(),
        text: "Hello from Google Chat".into(),
        timestamp: 1704067200000,
        space_name: "spaces/S".into(),
        is_dm: true,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_id().unwrap().to_str().unwrap(), "spaces/S/messages/M");
            assert_eq!(
                m.get_sender_id().unwrap().to_str().unwrap(),
                "alice@example.com"
            );
            assert_eq!(m.get_sender_name().unwrap().to_str().unwrap(), "Alice");
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "google-chat");
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "spaces/S"
            );
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from Google Chat"
            );
            assert_eq!(m.get_timestamp(), 1704067200000);
            assert!(!m.get_is_group()); // DM -> not group
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn room_message_sets_is_group() {
    let msg = convert::GoogleChatInbound {
        message_id: "spaces/R/messages/M".into(),
        sender_email: "bob@example.com".into(),
        sender_name: "Bob".into(),
        text: "hello room".into(),
        timestamp: 0,
        space_name: "spaces/R".into(),
        is_dm: false,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert!(m.get_is_group());
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
        outbound.set_conversation_id("spaces/SPACE_123");
        outbound.set_text("Reply from agent");
        outbound.set_reply_to_id("spaces/SPACE_123/messages/MSG_456");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "spaces/SPACE_123");
    assert_eq!(fields.text, "Reply from agent");
    assert_eq!(
        fields.reply_to.unwrap(),
        "spaces/SPACE_123/messages/MSG_456"
    );
}

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 42);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 42),
        _ => panic!("expected Heartbeat"),
    }
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "spaces/S/messages/M", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "spaces/S/messages/M"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("google-chat");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "google-chat");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "google-chat");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("google-chat");
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
            assert_eq!(id, "google-chat");
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

    // Phase 2: Adapter sends inbound (simulating a Google Chat message)
    let chat_msg = convert::GoogleChatInbound {
        message_id: "spaces/S/messages/M".into(),
        sender_email: "alice@example.com".into(),
        sender_name: "Alice".into(),
        text: "Hello from Google Chat".into(),
        timestamp: 1704067200000,
        space_name: "spaces/S".into(),
        is_dm: true,
    };
    let mut inbound = capnp::message::Builder::new_default();
    convert::google_chat_to_inbound(&chat_msg, &mut inbound);
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "google-chat");
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "Hello from Google Chat"
            );
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("spaces/S");
        m.set_text("Hello! How can I help?");
        m.set_reply_to_id("spaces/S/messages/M");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Hello! How can I help?");
    assert_eq!(fields.reply_to.unwrap(), "spaces/S/messages/M");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "spaces/S/messages/REPLY_1", "");
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
                "spaces/S/messages/REPLY_1"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_empty_service_account_token() {
    let id = AdapterIdentity::generate("google-chat");
    let r = GoogleChatAdapter::new(id, String::new(), "123456".into(), 3980);
    match r {
        Err(GoogleChatError::Config(msg)) => {
            assert!(msg.contains("service_account_token"), "msg: {msg}");
        }
        Err(other) => panic!("expected Config error, got {other:?}"),
        Ok(_) => panic!("empty service_account_token must fail at construction"),
    }
}

#[test]
fn new_rejects_empty_project_number() {
    let id = AdapterIdentity::generate("google-chat");
    let r = GoogleChatAdapter::new(id, "token".into(), String::new(), 3980);
    match r {
        Err(GoogleChatError::Config(msg)) => {
            assert!(msg.contains("app_project_number"), "msg: {msg}");
        }
        Err(other) => panic!("expected Config error, got {other:?}"),
        Ok(_) => panic!("empty app_project_number must fail at construction"),
    }
}

#[test]
fn new_accepts_both_non_empty() {
    let id = AdapterIdentity::generate("google-chat");
    assert!(GoogleChatAdapter::new(id, "token".into(), "123456".into(), 3980).is_ok());
}

// ---------------------------------------------------------------------------
// Authorization header extraction
// ---------------------------------------------------------------------------

#[test]
fn bearer_token_extracted() {
    let req = "POST / HTTP/1.1\r\n\
               Host: bot.example\r\n\
               Authorization: Bearer abc.def.ghi\r\n\
               \r\n";
    assert_eq!(extract_bearer_token(req).unwrap(), "abc.def.ghi");
}

#[test]
fn missing_authorization_rejected() {
    let req = "POST / HTTP/1.1\r\n\r\n";
    match extract_bearer_token(req) {
        Err(AuthError::MissingHeader) => {}
        other => panic!("expected MissingHeader, got {other:?}"),
    }
}

#[test]
fn non_bearer_scheme_rejected() {
    let req = "POST / HTTP/1.1\r\nAuthorization: Basic creds\r\n\r\n";
    match extract_bearer_token(req) {
        Err(AuthError::MalformedHeader) => {}
        other => panic!("expected MalformedHeader, got {other:?}"),
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

    const TEST_ISSUER: &str = "chat@system.gserviceaccount.com";
    const TEST_AUD: &str = "123456789012";
    const TEST_KID: &str = "test-gchat-kid-01";

    // 2048-bit RSA test keypair, PKCS#8-DER encoded so ring's
    // `RsaKeyPair::from_pkcs8` can load it directly. Public n,e are
    // committed alongside (raw big-endian, no leading zeros) so the
    // JwksCache test seed mirrors what the production refresh path
    // stores after base64url-decoding JWKS values.
    const LEGIT_PKCS8: &[u8] = include_bytes!("test_rsa_legit.pkcs8.der");
    const LEGIT_N: &[u8] = include_bytes!("test_rsa_legit.n.bin");
    const LEGIT_E: &[u8] = include_bytes!("test_rsa_legit.e.bin");
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
            &json!({ "iss": TEST_ISSUER, "aud": TEST_AUD, "exp": exp_future() }),
        );
        let claims = cache.validate_token(&token, TEST_AUD).await.unwrap();
        assert_eq!(claims.aud, TEST_AUD);
        assert_eq!(claims.iss, TEST_ISSUER);
    }

    #[tokio::test]
    async fn wrong_aud_rejected() {
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
            &json!({ "iss": TEST_ISSUER, "aud": "other-project", "exp": exp_future() }),
        );
        assert!(matches!(
            cache.validate_token(&token, TEST_AUD).await,
            Err(AuthError::JwtValidation(_))
        ));
    }

    #[tokio::test]
    async fn expired_rejected() {
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
            &json!({ "iss": TEST_ISSUER, "aud": TEST_AUD, "exp": exp_past() }),
        );
        assert!(matches!(
            cache.validate_token(&token, TEST_AUD).await,
            Err(AuthError::JwtValidation(_))
        ));
    }

    #[tokio::test]
    async fn foreign_signed_rejected() {
        let attacker = attacker_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &attacker,
            Some(TEST_KID),
            &json!({ "iss": TEST_ISSUER, "aud": TEST_AUD, "exp": exp_future() }),
        );
        assert!(matches!(
            cache.validate_token(&token, TEST_AUD).await,
            Err(AuthError::JwtValidation(_))
        ));
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let kp = legit_signer();
        let cache = JwksCache::for_test(vec![(TEST_KID.into(), legit_pubkey())], TEST_ISSUER);
        let token = sign(
            &kp,
            Some(TEST_KID),
            &json!({ "iss": "https://evil.example", "aud": TEST_AUD, "exp": exp_future() }),
        );
        assert!(matches!(
            cache.validate_token(&token, TEST_AUD).await,
            Err(AuthError::IssuerRejected(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// Approval-frame conversions (slice: google chat approval gate per umbrella #119)
// ---------------------------------------------------------------------------

#[test]
fn approval_decision_allow_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "req-uuid", true, "users/12345", "Davi");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), "req-uuid");
            assert_eq!(
                d.get_actor_user_id().unwrap().to_str().unwrap(),
                "users/12345"
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
    convert::build_approval_decision(&mut msg, "r", false, "users/12345", "");
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
    convert::build_approval_request_failed(&mut msg, "req-x", "permission_denied");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalRequestFailed(f) => {
            let f = f.unwrap();
            assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), "req-x");
            assert_eq!(
                f.get_reason().unwrap().to_str().unwrap(),
                "permission_denied"
            );
        }
        _ => panic!("expected ApprovalRequestFailed"),
    }
}

#[test]
fn approval_request_round_trips_path_shaped_space_name() {
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
        req.set_target_conversation_id("spaces/AAAA123456");
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.request_id, "abc");
    assert_eq!(fields.tool_name, "shell");
    assert_eq!(fields.target_channel_id, "spaces/AAAA123456");
}

#[test]
fn approval_request_rejects_empty_space_name() {
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
    assert!(convert::parse_approval_request(&reader).is_err());
}

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
// extract_approval_press
// ---------------------------------------------------------------------------

fn card_click_event(parameters: serde_json::Value, user: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "CARD_CLICKED",
        "user": user,
        "common": { "parameters": parameters }
    })
}

#[test]
fn extract_approval_press_finds_payload() {
    let event = card_click_event(
        serde_json::json!({ "wirken_approval": "req:abc:allow" }),
        serde_json::json!({ "name": "users/12345", "displayName": "Alice" }),
    );
    let press = convert::extract_approval_press(&event).unwrap();
    assert_eq!(press.user_name, "users/12345");
    assert_eq!(press.user_display, "Alice");
    assert_eq!(press.encoded_payload, "req:abc:allow");
}

#[test]
fn extract_approval_press_falls_back_display_to_user_name() {
    let event = card_click_event(
        serde_json::json!({ "wirken_approval": "req:abc:allow" }),
        serde_json::json!({ "name": "users/12345" }),
    );
    let press = convert::extract_approval_press(&event).unwrap();
    assert_eq!(press.user_display, "users/12345");
}

#[test]
fn extract_approval_press_returns_none_when_parameter_missing() {
    let event = card_click_event(
        serde_json::json!({ "other_field": "x" }),
        serde_json::json!({ "name": "users/12345" }),
    );
    assert!(convert::extract_approval_press(&event).is_none());
}

#[test]
fn extract_approval_press_returns_none_when_user_name_missing() {
    let event = card_click_event(
        serde_json::json!({ "wirken_approval": "req:abc:allow" }),
        serde_json::json!({ "displayName": "Alice" }),
    );
    assert!(convert::extract_approval_press(&event).is_none());
}

#[test]
fn extract_approval_press_returns_none_when_user_name_empty() {
    let event = card_click_event(
        serde_json::json!({ "wirken_approval": "req:abc:allow" }),
        serde_json::json!({ "name": "", "displayName": "Alice" }),
    );
    assert!(convert::extract_approval_press(&event).is_none());
}

#[test]
fn extract_approval_press_returns_none_for_message_event() {
    let event = serde_json::json!({
        "type": "MESSAGE",
        "message": { "text": "hello" }
    });
    assert!(convert::extract_approval_press(&event).is_none());
}

#[test]
fn extract_approval_press_ignores_legacy_action_parameters_shape() {
    // The legacy CARD_CLICKED shape carried parameters as an
    // array of {key, value} under event.action.parameters. This
    // extractor handles only the newer common.parameters shape;
    // the legacy array does not match and the press drops with
    // None. If a deployment ever needs legacy-shape support, a
    // sibling extract_approval_press_legacy lands as a separate
    // change, not as an if-let chain inside this function.
    let event = serde_json::json!({
        "type": "CARD_CLICKED",
        "user": { "name": "users/12345" },
        "action": {
            "actionMethodName": "wirken_approve",
            "parameters": [{ "key": "wirken_approval", "value": "req:abc:allow" }]
        }
    });
    assert!(convert::extract_approval_press(&event).is_none());
}

// ---------------------------------------------------------------------------
// privateMessageViewer ephemeral response body
// ---------------------------------------------------------------------------

#[test]
fn approval_response_body_targets_clicker_with_private_message_viewer() {
    let body = super::adapter::build_approval_response_body("users/12345", true);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["text"], "Approved");
    assert_eq!(parsed["actionResponse"]["type"], "NEW_MESSAGE");
    assert_eq!(parsed["privateMessageViewer"]["name"], "users/12345");
}

#[test]
fn approval_response_body_deny_path() {
    let body = super::adapter::build_approval_response_body("users/12345", false);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["text"], "Denied");
}

// ---------------------------------------------------------------------------
// classify_send_error
// ---------------------------------------------------------------------------

#[test]
fn classify_send_error_maps_permission_denied() {
    let body = serde_json::json!({
        "error": {
            "code": 403,
            "status": "PERMISSION_DENIED",
            "message": "The caller does not have permission"
        }
    })
    .to_string();
    assert_eq!(
        super::adapter::classify_send_error(403, &body),
        "permission_denied"
    );
}

#[test]
fn classify_send_error_maps_not_found_to_space_not_found() {
    let body = serde_json::json!({
        "error": {
            "code": 404,
            "status": "NOT_FOUND",
            "message": "Space not found"
        }
    })
    .to_string();
    assert_eq!(
        super::adapter::classify_send_error(404, &body),
        "space_not_found"
    );
}

#[test]
fn classify_send_error_maps_unauthenticated() {
    let body = serde_json::json!({
        "error": { "code": 401, "status": "UNAUTHENTICATED" }
    })
    .to_string();
    assert_eq!(
        super::adapter::classify_send_error(401, &body),
        "googlechat_auth_error"
    );
}

#[test]
fn classify_send_error_falls_back_to_http_status_when_no_google_status() {
    assert_eq!(
        super::adapter::classify_send_error(403, ""),
        "googlechat_auth_error"
    );
    assert_eq!(
        super::adapter::classify_send_error(404, ""),
        "space_not_found"
    );
    assert_eq!(
        super::adapter::classify_send_error(500, ""),
        "googlechat_api_error"
    );
}
