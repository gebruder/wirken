use serenity::all::Message as DcMessage;
use wirken_ipc::wirken_capnp::frame;

/// Build a Cap'n Proto InboundMessage frame from a Discord message.
pub fn discord_to_inbound(
    msg: &DcMessage,
    bot_id: u64,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    inbound.set_id(&msg.id.to_string());
    inbound.set_sender_id(&msg.author.id.to_string());

    let sender_name = if let Some(ref nick) = msg.member.as_ref().and_then(|m| m.nick.as_ref()) {
        nick.to_string()
    } else {
        msg.author.name.clone()
    };
    inbound.set_sender_name(&sender_name);

    inbound.set_channel("discord");
    inbound.set_conversation_id(&msg.channel_id.to_string());

    inbound.set_text(&msg.content);
    inbound.set_timestamp(msg.timestamp.unix_timestamp() * 1000);

    // Guild messages are "group" — DMs are not
    let is_group = msg.guild_id.is_some();
    inbound.set_is_group(is_group);

    let reply_to_id = msg
        .referenced_message
        .as_ref()
        .map(|r| r.id.to_string())
        .unwrap_or_default();
    inbound.set_reply_to_id(&reply_to_id);

    // Metadata: guild_id, attachments, embeds
    let mut meta = serde_json::json!({});
    if let Some(guild_id) = msg.guild_id {
        meta["guild_id"] = serde_json::Value::String(guild_id.to_string());
    }
    if !msg.attachments.is_empty() {
        let urls: Vec<String> = msg.attachments.iter().map(|a| a.url.clone()).collect();
        meta["attachments"] = serde_json::json!(urls);
    }
    if !msg.embeds.is_empty() {
        meta["embed_count"] = serde_json::json!(msg.embeds.len());
    }
    // Check if bot was mentioned (for mention-gating in guilds)
    let bot_mentioned = msg.mentions.iter().any(|u| u.id.get() == bot_id);
    meta["bot_mentioned"] = serde_json::json!(bot_mentioned);

    inbound.set_metadata(&meta.to_string());
}

/// Check if a guild message should be processed (mention-gating).
/// In guilds, only respond when the bot is @mentioned.
/// In DMs, always respond.
pub fn should_process(msg: &DcMessage, bot_id: u64) -> bool {
    // Always process DMs
    if msg.guild_id.is_none() {
        return true;
    }

    // In guilds, require bot mention
    msg.mentions.iter().any(|u| u.id.get() == bot_id)
}

/// Fields extracted from an OutboundMessage for sending via Discord.
pub struct OutboundFields {
    pub channel_id: u64,
    pub text: String,
    pub reply_to_id: Option<u64>,
}

/// Parse a Cap'n Proto OutboundMessage into Discord-ready fields.
pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let channel_id: u64 = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not utf8: {e}")))?
                .parse()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not u64: {e}")))?;

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
                channel_id,
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
