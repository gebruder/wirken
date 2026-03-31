use wirken_ipc::wirken_capnp::frame;

/// Parsed inbound Google Chat message.
pub struct GoogleChatInbound {
    pub message_id: String,
    pub sender_email: String,
    pub sender_name: String,
    pub text: String,
    pub timestamp: i64,
    /// The space (room/DM) identifier, e.g. "spaces/SPACE_ID".
    pub space_name: String,
    /// Whether this message is from a direct message space.
    pub is_dm: bool,
}

/// Fields extracted from an outbound frame.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to: Option<String>,
}

/// Check if an inbound message should be processed.
pub fn should_process(msg: &GoogleChatInbound) -> bool {
    !msg.text.is_empty()
}

/// Convert a Google Chat inbound message to a Cap'n Proto inbound frame.
pub fn google_chat_to_inbound(
    msg: &GoogleChatInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();
    inbound.set_id(&msg.message_id);
    inbound.set_sender_id(&msg.sender_email);
    inbound.set_sender_name(&msg.sender_name);
    inbound.set_channel("google-chat");
    inbound.set_conversation_id(&msg.space_name);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp);
    inbound.set_is_group(!msg.is_dm);
}

/// Parse an outbound frame from the gateway.
pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;
    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let conversation_id = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not utf8: {e}")))?
                .to_string();
            let text = o
                .get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();
            let reply_to_str = o
                .get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to_id not utf8: {e}")))?;
            let reply_to = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                conversation_id,
                text,
                reply_to,
            })
        }
        _ => Err(capnp::Error::failed("expected Outbound frame".to_string())),
    }
}

/// Build a heartbeat frame.
pub fn build_heartbeat(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    seq: u64,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut hb = frame_builder.init_heartbeat();
    hb.set_seq(seq);
}

/// Build an outbound result frame.
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

/// Extract a Google Chat message from the webhook JSON payload.
///
/// Google Chat sends events with the following structure:
/// ```json
/// {
///   "type": "MESSAGE",
///   "message": {
///     "name": "spaces/SPACE_ID/messages/MSG_ID",
///     "sender": {"name": "users/USER_ID", "displayName": "Alice", "email": "alice@example.com"},
///     "text": "hello",
///     "createTime": "2024-01-01T00:00:00Z",
///     "space": {"name": "spaces/SPACE_ID", "type": "DM"|"ROOM"}
///   }
/// }
/// ```
pub fn extract_message(json: &serde_json::Value) -> Option<GoogleChatInbound> {
    let event_type = json.get("type")?.as_str()?;
    if event_type != "MESSAGE" {
        return None;
    }

    let message = json.get("message")?;

    let message_id = message
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    let sender = message.get("sender");
    let sender_email = sender
        .and_then(|s| s.get("email"))
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string();
    let sender_name = sender
        .and_then(|s| s.get("displayName"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();

    let text = message
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();

    let timestamp = message
        .get("createTime")
        .and_then(|t| t.as_str())
        .and_then(|ts| {
            // Parse RFC 3339 timestamp to Unix millis
            chrono::DateTime::parse_from_rfc3339(ts)
                .ok()
                .map(|dt| dt.timestamp_millis())
        })
        .unwrap_or(0);

    let space = message.get("space");
    let space_name = space
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    let space_type = space
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let is_dm = space_type == "DM";

    Some(GoogleChatInbound {
        message_id,
        sender_email,
        sender_name,
        text,
        timestamp,
        space_name,
        is_dm,
    })
}
