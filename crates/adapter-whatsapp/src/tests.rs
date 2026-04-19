use crate::convert;

#[test]
fn parse_whatsapp_text_message() {
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "123456",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": "987654"
                    },
                    "contacts": [{
                        "profile": { "name": "Alice" },
                        "wa_id": "15559876543"
                    }],
                    "messages": [{
                        "from": "15559876543",
                        "id": "wamid.abc123",
                        "timestamp": "1711900000",
                        "text": { "body": "Hello wirken!" },
                        "type": "text"
                    }]
                },
                "field": "messages"
            }]
        }]
    });

    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].from, "15559876543");
    assert_eq!(messages[0].from_name, "Alice");
    assert_eq!(messages[0].text, "Hello wirken!");
    assert_eq!(messages[0].message_id, "wamid.abc123");
    assert_eq!(messages[0].phone_number_id, "987654");
    assert_eq!(messages[0].timestamp, 1711900000);
}

#[test]
fn ignore_non_text_messages() {
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "changes": [{
                "value": {
                    "metadata": { "phone_number_id": "987654" },
                    "messages": [{
                        "from": "15559876543",
                        "id": "wamid.img456",
                        "timestamp": "1711900000",
                        "type": "image",
                        "image": { "id": "img123" }
                    }]
                }
            }]
        }]
    });

    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert!(messages.is_empty());
}

#[test]
fn empty_text_not_processed() {
    let msg = convert::WhatsAppInbound {
        message_id: "wamid.1".into(),
        from: "15551234567".into(),
        from_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        phone_number_id: "123".into(),
    };
    assert!(!convert::should_process(&msg));
}

#[test]
fn valid_text_processed() {
    let msg = convert::WhatsAppInbound {
        message_id: "wamid.2".into(),
        from: "15551234567".into(),
        from_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        phone_number_id: "123".into(),
    };
    assert!(convert::should_process(&msg));
}

#[test]
fn new_rejects_empty_app_secret() {
    use super::WhatsAppAdapter;
    use crate::error::WhatsAppError;
    use wirken_ipc::AdapterIdentity;

    let identity = AdapterIdentity::generate("whatsapp-test");
    let result = WhatsAppAdapter::new(
        identity,
        "bot-token".into(),
        "phone-id".into(),
        "verify-token".into(),
        String::new(),
        3979,
    );
    match result {
        Err(WhatsAppError::Config(msg)) => {
            assert!(msg.contains("app_secret"), "error should name the field: {msg}");
        }
        Err(other) => panic!("expected Config error, got {other:?}"),
        Ok(_) => panic!("empty app_secret must fail at construction"),
    }
}

#[test]
fn new_accepts_non_empty_app_secret() {
    use super::WhatsAppAdapter;
    use wirken_ipc::AdapterIdentity;

    let identity = AdapterIdentity::generate("whatsapp-test");
    let adapter = WhatsAppAdapter::new(
        identity,
        "bot-token".into(),
        "phone-id".into(),
        "verify-token".into(),
        "a-real-secret".into(),
        3979,
    );
    assert!(adapter.is_ok(), "non-empty app_secret must construct");
}

#[test]
fn hmac_signature_verification() {
    // Test-only value — not a production secret.
    let secret = "whatsapp_test_hmac_key"; // CodeQL:hardcoded-credential-ok
    let body = r#"{"test":"data"}"#;

    // Compute expected signature
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let result = mac.finalize().into_bytes();
    let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    let header = format!("sha256={hex}");

    assert!(super::adapter::verify_signature(secret, body, &header));
    assert!(!super::adapter::verify_signature(
        secret,
        body,
        "sha256=invalid"
    ));
    assert!(!super::adapter::verify_signature(secret, body, ""));
}

#[test]
fn hmac_signature_wrong_length_rejected_before_decode() {
    let secret = "whatsapp_test_hmac_key";
    let body = r#"{"test":"data"}"#;
    // Exactly one byte short of the 64-char hex expectation; must
    // reject before any HMAC computation or hex decode.
    let short = format!("sha256={}", "a".repeat(63));
    assert!(!super::adapter::verify_signature(secret, body, &short));
    // And one byte too long.
    let long = format!("sha256={}", "a".repeat(65));
    assert!(!super::adapter::verify_signature(secret, body, &long));
}

#[test]
fn hmac_signature_non_hex_rejected() {
    let secret = "whatsapp_test_hmac_key";
    let body = r#"{"test":"data"}"#;
    // Exactly 64 chars but not all hex.
    let mixed: String = "z".repeat(64);
    let header = format!("sha256={mixed}");
    assert!(!super::adapter::verify_signature(secret, body, &header));
}

#[test]
fn hmac_signature_upper_case_hex_accepted() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let secret = "whatsapp_test_hmac_key";
    let body = r#"{"test":"data"}"#;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let result = mac.finalize().into_bytes();
    let hex_upper: String = result.iter().map(|b| format!("{b:02X}")).collect();
    let header = format!("sha256={hex_upper}");

    // The decoder accepts either case; Meta emits lowercase in
    // practice, but accepting upper case keeps verification robust
    // to any variant of the documented format.
    assert!(super::adapter::verify_signature(secret, body, &header));
}

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 42);
    // Should not panic
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "wamid.123", "");
    // Should not panic
}
