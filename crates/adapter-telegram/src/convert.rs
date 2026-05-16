use teloxide::types::Message as TgMessage;
use wirken_ipc::wirken_capnp::frame;

/// Build a Cap'n Proto InboundMessage frame from a Telegram message.
pub fn telegram_to_inbound(
    msg: &TgMessage,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    inbound.set_id(msg.id.0.to_string());

    let sender_id = msg
        .from
        .as_ref()
        .map(|u| u.id.0.to_string())
        .unwrap_or_default();
    inbound.set_sender_id(&sender_id);

    let sender_name = msg
        .from
        .as_ref()
        .map(|u| {
            let mut name = u.first_name.clone();
            if let Some(last) = &u.last_name {
                name.push(' ');
                name.push_str(last);
            }
            name
        })
        .unwrap_or_default();
    inbound.set_sender_name(&sender_name);

    inbound.set_channel("telegram");
    inbound.set_conversation_id(msg.chat.id.0.to_string());

    let text = msg.text().unwrap_or("");
    inbound.set_text(text);

    inbound.set_timestamp(msg.date.timestamp_millis());

    // Groups have negative chat IDs in Telegram, or we can check the chat type
    let is_group = msg.chat.is_group() || msg.chat.is_supergroup();
    inbound.set_is_group(is_group);

    let reply_to_id = msg
        .reply_to_message()
        .map(|r| r.id.0.to_string())
        .unwrap_or_default();
    inbound.set_reply_to_id(&reply_to_id);

    // Metadata: structured JSON, not string interpolation
    let mut meta = serde_json::json!({});
    if let Some(username) = msg.from.as_ref().and_then(|u| u.username.as_ref()) {
        meta["username"] = serde_json::Value::String(username.clone());
    }
    inbound.set_metadata(meta.to_string());
}

/// Parse a Cap'n Proto OutboundMessage frame into fields for sending via Telegram.
pub struct OutboundFields {
    pub conversation_id: i64,
    pub text: String,
    pub reply_to_id: Option<i32>,
}

pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let conv_id: i64 = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not utf8: {e}")))?
                .parse()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not i64: {e}")))?;

            let text = o
                .get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();

            let reply_to_str = o
                .get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to_id not utf8: {e}")))?;
            let reply_to_id = if reply_to_str.is_empty() {
                None
            } else {
                reply_to_str.parse().ok()
            };

            Ok(OutboundFields {
                conversation_id: conv_id,
                text,
                reply_to_id,
            })
        }
        _ => Err(capnp::Error::failed("expected Outbound frame".to_string())),
    }
}

/// Build a Cap'n Proto OutboundResult frame.
pub fn build_outbound_result(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    success: bool,
    message_id: &str,
    error: &str,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut result = frame_builder.init_outbound_result();
    result.set_success(success);
    result.set_message_id(message_id);
    result.set_error(error);
}

/// Build a Cap'n Proto Heartbeat frame.
pub fn build_heartbeat(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    seq: u64,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut hb = frame_builder.init_heartbeat();
    hb.set_seq(seq);
}

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an inline-keyboard button. The
/// callback_data encoding is documented at the parse site
/// (`adapter.rs::parse_callback_data`); the decision bool is
/// derived there and passed in. Telegram's numeric user id is
/// stringified into `actorUserId`; the gateway side calls
/// `approver_registry::verify("telegram", &actor_user_id)`
/// against the registered allowlist.
pub fn build_approval_decision(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    request_id: &str,
    is_allow: bool,
    user_id: i64,
    user_display: &str,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut decision = frame_builder.init_approval_decision();
    decision.set_request_id(request_id);
    decision.set_actor_user_id(user_id.to_string());
    decision.set_actor_display(user_display);
    let mut kind = decision.init_decision();
    if is_allow {
        kind.set_allow(());
    } else {
        // Telegram inline keyboard has no ForceReply pattern
        // wired today; the deny path carries no operator
        // reason. Empty string maps to `denial_reason: None` on
        // the gateway side.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as an inline-keyboard message in the configured
/// approval chat. Telegram parses the platform-neutral
/// `targetConversationId` Text field as an `i64` chat id (the
/// shape `ChatId` requires); a non-numeric value indicates a
/// gateway/operator misconfiguration and surfaces here as a
/// capnp parse error rather than a runtime Telegram API error.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_chat_id: i64,
}

pub fn parse_approval_request(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<ApprovalRequestFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;
    match frame_reader.which()? {
        frame::ApprovalRequest(req) => {
            let r = req?;
            let request_id = r
                .get_request_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("request_id not utf8: {e}")))?
                .to_string();
            let tool_name = r
                .get_tool_name()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("tool_name not utf8: {e}")))?
                .to_string();
            let action_key = r
                .get_action_key()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("action_key not utf8: {e}")))?
                .to_string();
            let requested_tier = r
                .get_requested_tier()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("requested_tier not utf8: {e}")))?
                .to_string();
            let triggering_agent = r
                .get_triggering_agent()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("triggering_agent not utf8: {e}")))?
                .to_string();
            let trigger_message = r
                .get_trigger_message()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("trigger_message not utf8: {e}")))?
                .to_string();
            let target_chat_id = r
                .get_target_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("target_conversation_id not utf8: {e}")))?
                .parse::<i64>()
                .map_err(|e| {
                    capnp::Error::failed(format!(
                        "telegram target_conversation_id must be a numeric chat id: {e}"
                    ))
                })?;
            Ok(ApprovalRequestFields {
                request_id,
                tool_name,
                action_key,
                requested_tier,
                triggering_agent,
                trigger_message,
                target_chat_id,
            })
        }
        _ => Err(capnp::Error::failed(
            "expected ApprovalRequest frame".to_string(),
        )),
    }
}

/// Build an `ApprovalRequestFailed` frame for the adapter→gateway
/// direction. Sent when the inline-keyboard message cannot be
/// delivered (chat not accessible, Telegram API rejection, etc.).
pub fn build_approval_request_failed(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    request_id: &str,
    reason: &str,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut failed = frame_builder.init_approval_request_failed();
    failed.set_request_id(request_id);
    failed.set_reason(reason);
}
