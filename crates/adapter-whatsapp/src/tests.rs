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
