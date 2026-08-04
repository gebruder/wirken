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
            assert!(
                msg.contains("app_secret"),
                "error should name the field: {msg}"
            );
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
    use hmac::{Hmac, KeyInit, Mac};
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
    use hmac::{Hmac, KeyInit, Mac};
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

// ---------------------------------------------------------------------------
// Approval-frame conversions (slice: whatsapp approval gate per umbrella #119)
// ---------------------------------------------------------------------------

use wirken_ipc::wirken_capnp::frame;

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
fn approval_decision_allow_round_trips() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(&mut msg, "req-uuid", true, "16505551234", "Alice");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalDecision(d) => {
            let d = d.unwrap();
            assert_eq!(d.get_request_id().unwrap().to_str().unwrap(), "req-uuid");
            assert_eq!(
                d.get_actor_user_id().unwrap().to_str().unwrap(),
                "16505551234"
            );
            assert_eq!(d.get_actor_display().unwrap().to_str().unwrap(), "Alice");
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
    convert::build_approval_decision(&mut msg, "r", false, "16505551234", "");
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
    convert::build_approval_request_failed(&mut msg, "req-x", "window_closed");
    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::ApprovalRequestFailed(f) => {
            let f = f.unwrap();
            assert_eq!(f.get_request_id().unwrap().to_str().unwrap(), "req-x");
            assert_eq!(f.get_reason().unwrap().to_str().unwrap(), "window_closed");
        }
        _ => panic!("expected ApprovalRequestFailed"),
    }
}

#[test]
fn approval_request_round_trips_phone_number_conversation_id() {
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
        req.set_target_conversation_id("16505551234");
    }
    let reader = serialize_and_read(&msg);
    let fields = convert::parse_approval_request(&reader).unwrap();
    assert_eq!(fields.request_id, "abc");
    assert_eq!(fields.tool_name, "shell");
    assert_eq!(fields.action_key, "shell:rm");
    assert_eq!(fields.requested_tier, "tier3");
    assert_eq!(fields.triggering_agent, "default");
    assert_eq!(fields.trigger_message, "clean logs");
    assert_eq!(fields.target_channel_id, "16505551234");
}

#[test]
fn approval_request_rejects_empty_phone_number() {
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
        "empty phone number must reject"
    );
}

// ---------------------------------------------------------------------------
// Cross-adapter button_reply.id round-trip
// ---------------------------------------------------------------------------

#[test]
fn button_id_encoded_by_adapter_core_decodes_to_original_payload() {
    use wirken_adapter_core::approval::{ApprovalPayload, Decision, decode, encode};
    let original = ApprovalPayload {
        request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        decision: Decision::Allow,
    };
    let button_id = encode(&original).unwrap();
    // Worst-case encoded length: 46 bytes. WhatsApp reply-button
    // id cap is 256 chars; the encoding fits comfortably.
    assert!(button_id.len() <= 256);
    let decoded = decode(&button_id).unwrap();
    assert_eq!(decoded, original);
}

// ---------------------------------------------------------------------------
// extract_button_replies sibling extractor
// ---------------------------------------------------------------------------

fn webhook_button_reply_payload(button_id: &str) -> serde_json::Value {
    serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "biz-123",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": "987654"
                    },
                    "contacts": [{
                        "profile": { "name": "Alice" },
                        "wa_id": "16505551234"
                    }],
                    "messages": [{
                        "from": "16505551234",
                        "id": "wamid.PRESS123",
                        "timestamp": "1717000000",
                        "type": "interactive",
                        "interactive": {
                            "type": "button_reply",
                            "button_reply": {
                                "id": button_id,
                                "title": "Approve"
                            }
                        }
                    }]
                },
                "field": "messages"
            }]
        }]
    })
}

#[test]
fn extract_button_replies_finds_approval_press() {
    let payload = webhook_button_reply_payload("req:550e8400-e29b-41d4-a716-446655440000:allow");
    let presses = super::adapter::extract_button_replies(&payload);
    assert_eq!(presses.len(), 1);
    let press = &presses[0];
    assert_eq!(press.from, "16505551234");
    assert_eq!(press.from_name, "Alice");
    assert_eq!(
        press.encoded_payload,
        "req:550e8400-e29b-41d4-a716-446655440000:allow"
    );
    assert_eq!(press.message_id, "wamid.PRESS123");
}

#[test]
fn extract_button_replies_ignores_text_messages() {
    // A normal text-message webhook payload should produce zero
    // button presses; that path stays the responsibility of
    // extract_messages.
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "biz",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": { "display_phone_number": "1555", "phone_number_id": "987" },
                    "messages": [{
                        "from": "16505551234",
                        "id": "wamid.TEXT",
                        "timestamp": "1717",
                        "type": "text",
                        "text": { "body": "hello" }
                    }]
                },
                "field": "messages"
            }]
        }]
    });
    let presses = super::adapter::extract_button_replies(&payload);
    assert!(presses.is_empty());
}

#[test]
fn extract_button_replies_ignores_non_button_interactive() {
    // interactive.type == list_reply is a different interactive
    // class. The approval flow only handles button_reply; other
    // interactive types drop here (and route nowhere else in this
    // adapter).
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "biz",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": { "display_phone_number": "1555", "phone_number_id": "987" },
                    "messages": [{
                        "from": "16505551234",
                        "id": "wamid.LIST",
                        "timestamp": "1717",
                        "type": "interactive",
                        "interactive": {
                            "type": "list_reply",
                            "list_reply": { "id": "x", "title": "y" }
                        }
                    }]
                },
                "field": "messages"
            }]
        }]
    });
    let presses = super::adapter::extract_button_replies(&payload);
    assert!(presses.is_empty());
}

#[test]
fn extract_button_replies_drops_missing_button_id() {
    // interactive.button_reply present but missing id. Drop
    // silently; the downstream decode would fail too, but we
    // never even hand it raw bytes.
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "biz",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": { "display_phone_number": "1555", "phone_number_id": "987" },
                    "messages": [{
                        "from": "16505551234",
                        "id": "wamid.NOID",
                        "timestamp": "1717",
                        "type": "interactive",
                        "interactive": {
                            "type": "button_reply",
                            "button_reply": { "title": "Approve" }
                        }
                    }]
                },
                "field": "messages"
            }]
        }]
    });
    let presses = super::adapter::extract_button_replies(&payload);
    assert!(presses.is_empty());
}

#[test]
fn extract_button_replies_falls_back_to_from_when_no_profile_name() {
    // No matching contact in the payload: from_name falls back to
    // the phone number itself. This keeps the display field
    // non-empty for the audit row.
    let payload = serde_json::json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "biz",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": { "display_phone_number": "1555", "phone_number_id": "987" },
                    "messages": [{
                        "from": "16505551234",
                        "id": "wamid.NONAME",
                        "timestamp": "1717",
                        "type": "interactive",
                        "interactive": {
                            "type": "button_reply",
                            "button_reply": { "id": "req:abc:allow", "title": "Approve" }
                        }
                    }]
                },
                "field": "messages"
            }]
        }]
    });
    let presses = super::adapter::extract_button_replies(&payload);
    assert_eq!(presses.len(), 1);
    assert_eq!(presses[0].from_name, "16505551234");
}

// ---------------------------------------------------------------------------
// classify_send_error: Meta error-taxonomy mapping
// ---------------------------------------------------------------------------

#[test]
fn classify_send_error_maps_code_131047_to_window_closed() {
    let body = serde_json::json!({
        "error": {
            "message": "(#131047) Message failed to send because more than 24 hours \
                        have passed since the customer last replied to this number.",
            "code": 131047,
            "type": "OAuthException",
            "fbtrace_id": "abc"
        }
    })
    .to_string();
    assert_eq!(super::adapter::classify_send_error(&body), "window_closed");
}

#[test]
fn classify_send_error_maps_code_131026_to_window_closed() {
    let body = serde_json::json!({
        "error": {
            "message": "Message Undeliverable.",
            "code": 131026,
            "type": "OAuthException"
        }
    })
    .to_string();
    assert_eq!(super::adapter::classify_send_error(&body), "window_closed");
}

#[test]
fn classify_send_error_maps_other_codes_to_generic_api_error() {
    let body = serde_json::json!({
        "error": {
            "message": "Invalid parameter.",
            "code": 100,
            "type": "OAuthException"
        }
    })
    .to_string();
    assert_eq!(
        super::adapter::classify_send_error(&body),
        "whatsapp_api_error"
    );
}

#[test]
fn classify_send_error_maps_non_json_body_to_generic_api_error() {
    assert_eq!(
        super::adapter::classify_send_error("not even JSON"),
        "whatsapp_api_error"
    );
}

#[test]
fn classify_send_error_maps_missing_code_to_generic_api_error() {
    let body = serde_json::json!({ "error": { "message": "no code field" } }).to_string();
    assert_eq!(
        super::adapter::classify_send_error(&body),
        "whatsapp_api_error"
    );
}
