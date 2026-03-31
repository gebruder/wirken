use wirken_ipc::wirken_capnp::frame;

/// Parsed inbound WhatsApp message.
pub struct WhatsAppInbound {
    pub message_id: String,
    pub from: String,
    pub from_name: String,
    pub text: String,
    pub timestamp: i64,
    /// WhatsApp phone number ID (identifies the business phone receiving the message)
    pub phone_number_id: String,
}

/// Fields extracted from an outbound frame.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to: Option<String>,
}

/// Check if an inbound message should be processed.
pub fn should_process(msg: &WhatsAppInbound) -> bool {
    !msg.text.is_empty()
}

/// Convert a WhatsApp inbound message to a Cap'n Proto inbound frame.
pub fn whatsapp_to_inbound(
    msg: &WhatsAppInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();
    inbound.set_id(&msg.message_id);
    inbound.set_sender_id(&msg.from);
    inbound.set_sender_name(&msg.from_name);
    inbound.set_channel("whatsapp");
    inbound.set_conversation_id(&msg.from); // 1:1 chats use sender phone as conversation ID
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp);
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
