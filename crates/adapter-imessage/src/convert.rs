use wirken_ipc::wirken_capnp::frame;

/// Parsed inbound iMessage from BlueBubbles.
pub struct IMessageInbound {
    pub message_id: String,
    pub sender_handle: String,
    pub sender_name: String,
    pub text: String,
    pub timestamp: i64,
    /// BlueBubbles chat identifier (e.g., "iMessage;-;+15551234567").
    pub chat_guid: String,
    pub is_group: bool,
}

/// Fields extracted from an outbound frame.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to: Option<String>,
}

/// Check if an inbound message should be processed.
pub fn should_process(msg: &IMessageInbound) -> bool {
    !msg.text.is_empty()
}

/// Convert an iMessage inbound to a Cap'n Proto inbound frame.
pub fn imessage_to_inbound(
    msg: &IMessageInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();
    inbound.set_id(&msg.message_id);
    inbound.set_sender_id(&msg.sender_handle);
    inbound.set_sender_name(&msg.sender_name);
    inbound.set_channel("imessage");
    inbound.set_conversation_id(&msg.chat_guid);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp);
    inbound.set_is_group(msg.is_group);
    inbound.set_reply_to_id("");
    inbound.set_metadata("{}");
}

/// Parse an outbound frame from the gateway.
pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;
    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            Ok(OutboundFields {
                conversation_id: o.get_conversation_id()?.to_string()?,
                text: o.get_text()?.to_string()?,
                reply_to: {
                    let r = o.get_reply_to_id()?.to_str()?;
                    if r.is_empty() {
                        None
                    } else {
                        Some(r.to_string())
                    }
                },
            })
        }
        _ => Err(capnp::Error::failed("expected Outbound frame".into())),
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

/// Extract an iMessage from a BlueBubbles webhook payload.
///
/// Expected format:
/// ```json
/// {
///   "type": "new-message",
///   "data": {
///     "guid": "MSG_GUID",
///     "text": "hello",
///     "handle": {"address": "+15551234567", "firstName": "Alice", "lastName": "Smith"},
///     "dateCreated": 1704067200000,
///     "chats": [{"guid": "iMessage;-;+15551234567", "displayName": "Alice"}],
///     "isFromMe": false
///   }
/// }
/// ```
pub fn extract_message(json: &serde_json::Value) -> Option<IMessageInbound> {
    let event_type = json.get("type")?.as_str()?;
    if event_type != "new-message" {
        return None;
    }

    let data = json.get("data")?;

    // Skip messages sent by the local user
    if data
        .get("isFromMe")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return None;
    }

    let message_id = data.get("guid")?.as_str()?.to_string();

    let text = data
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();

    let handle = data.get("handle");
    let sender_handle = handle
        .and_then(|h| h.get("address"))
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_string();

    let first_name = handle
        .and_then(|h| h.get("firstName"))
        .and_then(|n| n.as_str())
        .unwrap_or("");
    let last_name = handle
        .and_then(|h| h.get("lastName"))
        .and_then(|n| n.as_str())
        .unwrap_or("");
    let sender_name = format!("{first_name} {last_name}").trim().to_string();
    let sender_name = if sender_name.is_empty() {
        sender_handle.clone()
    } else {
        sender_name
    };

    let timestamp = data
        .get("dateCreated")
        .and_then(|t| t.as_i64())
        .unwrap_or(0);

    let chats = data.get("chats").and_then(|c| c.as_array());
    let chat_guid = chats
        .and_then(|c| c.first())
        .and_then(|c| c.get("guid"))
        .and_then(|g| g.as_str())
        .unwrap_or("")
        .to_string();

    // "iMessage;+;" prefix indicates a group chat, "iMessage;-;" indicates DM
    let is_group = chat_guid.contains(";+;");

    Some(IMessageInbound {
        message_id,
        sender_handle,
        sender_name,
        text,
        timestamp,
        chat_guid,
        is_group,
    })
}
