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

    inbound.set_id(msg.id.to_string());
    inbound.set_sender_id(msg.author.id.to_string());

    let sender_name = if let Some(ref nick) = msg.member.as_ref().and_then(|m| m.nick.as_ref()) {
        nick.to_string()
    } else {
        msg.author.name.clone()
    };
    inbound.set_sender_name(&sender_name);

    inbound.set_channel("discord");
    inbound.set_conversation_id(msg.channel_id.to_string());

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

    inbound.set_metadata(meta.to_string());
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

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an approval button. The `custom_id`
/// decoding lives at the press site in `adapter.rs`; the decision
/// bool is derived there and passed in. Discord's u64 user id is
/// stringified into `actorUserId`; the gateway side calls
/// `approver_registry::verify("discord", &actor_user_id)` against
/// the registered allowlist. The adapter does not call verify
/// directly (layering: adapters do not depend on gateway state);
/// unauthorized presses are silently dropped on the gateway side,
/// matching the Telegram adapter's posture.
pub fn build_approval_decision(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    request_id: &str,
    is_allow: bool,
    user_id: u64,
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
        // Discord component buttons carry no operator reason field
        // (a follow-up modal would; out of scope for the first
        // adapter slice). Empty string maps to `denial_reason:
        // None` on the gateway side, matching Telegram.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as a Components-v2 button row in the configured
/// approval channel.
///
/// `target_channel_id` is parsed as `u64` because Discord channel
/// ids are unsigned 64-bit snowflakes. The platform-neutral
/// `targetConversationId` IPC field is a string; each adapter
/// parses it according to its platform's identifier shape:
///
/// - Telegram chat ids are signed 64-bit (`i64`).
/// - Discord channel ids are unsigned 64-bit (`u64`).
/// - Slack, Teams, WhatsApp, Google Chat each have their own
///   shape (string channel id, GUID, phone number, path id) and
///   will land their own parse here in their respective adapter
///   slices.
///
/// A non-numeric value indicates a gateway/operator
/// misconfiguration and surfaces here as a capnp parse error
/// rather than a runtime Discord API error.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_channel_id: u64,
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
            let target_channel_id = r
                .get_target_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("target_conversation_id not utf8: {e}")))?
                .parse::<u64>()
                .map_err(|e| {
                    capnp::Error::failed(format!(
                        "discord target_conversation_id must be a numeric channel id: {e}"
                    ))
                })?;
            Ok(ApprovalRequestFields {
                request_id,
                tool_name,
                action_key,
                requested_tier,
                triggering_agent,
                trigger_message,
                target_channel_id,
            })
        }
        _ => Err(capnp::Error::failed(
            "expected ApprovalRequest frame".to_string(),
        )),
    }
}

/// Build an `ApprovalRequestFailed` frame back to the gateway when
/// the adapter cannot deliver the approval message (channel
/// inaccessible, Discord API rejection, etc.). The gateway-side
/// audit row records the failure distinctly from a generic
/// timeout.
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
