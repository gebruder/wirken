use wirken_ipc::wirken_capnp::frame;

/// Fields extracted from a Matrix room message event.
#[derive(Debug, Clone)]
pub struct MatrixInbound {
    pub event_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub room_id: String,
    pub text: String,
    pub timestamp_ms: i64,
    pub is_dm: bool,
    pub reply_to_event: Option<String>,
    pub room_name: Option<String>,
    pub is_encrypted: bool,
}

/// Build a Cap'n Proto InboundMessage from Matrix event fields.
pub fn matrix_to_inbound(
    msg: &MatrixInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    inbound.set_id(&msg.event_id);
    inbound.set_sender_id(&msg.sender_id);
    inbound.set_sender_name(&msg.sender_name);
    inbound.set_channel("matrix");
    inbound.set_conversation_id(&msg.room_id);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp_ms);
    inbound.set_is_group(!msg.is_dm);
    inbound.set_reply_to_id(msg.reply_to_event.as_deref().unwrap_or(""));

    let mut meta = serde_json::json!({});
    if let Some(ref name) = msg.room_name {
        meta["room_name"] = serde_json::Value::String(name.clone());
    }
    meta["encrypted"] = serde_json::json!(msg.is_encrypted);

    inbound.set_metadata(meta.to_string());
}

/// Check if a message should be processed.
/// In DMs: always. In rooms: only if the bot's display name or MXID is mentioned.
pub fn should_process(msg: &MatrixInbound, bot_user_id: &str, bot_display_name: &str) -> bool {
    if msg.is_dm {
        return true;
    }
    // Check if bot is mentioned in the text
    msg.text.contains(bot_user_id)
        || (!bot_display_name.is_empty() && msg.text.contains(bot_display_name))
}

/// Fields for sending a message via Matrix.
pub struct OutboundFields {
    pub room_id: String,
    pub text: String,
    pub reply_to_event: Option<String>,
}

pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let room_id = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("room_id not utf8: {e}")))?
                .to_string();
            let text = o
                .get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();
            let reply_to_str = o
                .get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to not utf8: {e}")))?;
            let reply_to_event = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                room_id,
                text,
                reply_to_event,
            })
        }
        _ => Err(capnp::Error::failed("expected Outbound frame".to_string())),
    }
}

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

pub fn build_heartbeat(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    seq: u64,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut hb = frame_builder.init_heartbeat();
    hb.set_seq(seq);
}
