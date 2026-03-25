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
