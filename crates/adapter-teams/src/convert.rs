use serde::{Deserialize, Serialize};
use wirken_ipc::wirken_capnp::frame;

/// Bot Framework Activity (inbound from Teams).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    #[serde(rename = "type")]
    pub activity_type: String,
    pub id: Option<String>,
    pub timestamp: Option<String>,
    pub text: Option<String>,
    pub from: Option<ChannelAccount>,
    pub conversation: Option<ConversationAccount>,
    pub channel_id: Option<String>,
    pub service_url: Option<String>,
    pub reply_to_id: Option<String>,
    /// Channel data — Teams-specific metadata
    pub channel_data: Option<serde_json::Value>,
    /// Entities — includes mentions
    pub entities: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAccount {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "aadObjectId")]
    pub aad_object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationAccount {
    pub id: Option<String>,
    pub name: Option<String>,
    pub conversation_type: Option<String>,
    pub is_group: Option<bool>,
    pub tenant_id: Option<String>,
}

/// Build a Cap'n Proto InboundMessage from a Teams Activity.
pub fn activity_to_inbound(
    activity: &Activity,
    bot_id: &str,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    let msg_id = activity.id.as_deref().unwrap_or("");
    inbound.set_id(msg_id);

    let sender_id = activity.from.as_ref()
        .and_then(|f| f.id.as_deref())
        .unwrap_or("");
    inbound.set_sender_id(sender_id);

    let sender_name = activity.from.as_ref()
        .and_then(|f| f.name.as_deref())
        .unwrap_or("");
    inbound.set_sender_name(sender_name);

    inbound.set_channel("teams");

    let conversation_id = activity.conversation.as_ref()
        .and_then(|c| c.id.as_deref())
        .unwrap_or("");
    inbound.set_conversation_id(conversation_id);

    let text = strip_mention(
        activity.text.as_deref().unwrap_or(""),
        bot_id,
        &activity.entities,
    );
    inbound.set_text(&text);

    let ts_millis = activity.timestamp.as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);
    inbound.set_timestamp(ts_millis);

    let is_group = activity.conversation.as_ref()
        .and_then(|c| c.is_group)
        .unwrap_or(false);
    inbound.set_is_group(is_group);

    let reply_to = activity.reply_to_id.as_deref().unwrap_or("");
    inbound.set_reply_to_id(reply_to);

    let mut meta = serde_json::json!({});
    if let Some(ref svc_url) = activity.service_url {
        meta["service_url"] = serde_json::Value::String(svc_url.clone());
    }
    if let Some(ref conv) = activity.conversation {
        if let Some(ref conv_type) = conv.conversation_type {
            meta["conversation_type"] = serde_json::Value::String(conv_type.clone());
        }
        if let Some(ref tenant_id) = conv.tenant_id {
            meta["tenant_id"] = serde_json::Value::String(tenant_id.clone());
        }
    }
    let bot_mentioned = is_bot_mentioned(&activity.entities, bot_id);
    meta["bot_mentioned"] = serde_json::json!(bot_mentioned);

    inbound.set_metadata(&meta.to_string());
}

/// Check if a message should be processed (mention-gating).
/// 1:1 chats: always process.
/// Group/channel: only if bot is @mentioned.
pub fn should_process(activity: &Activity, bot_id: &str) -> bool {
    if activity.activity_type != "message" {
        return false;
    }

    let is_group = activity.conversation.as_ref()
        .and_then(|c| c.is_group)
        .unwrap_or(false);

    let conv_type = activity.conversation.as_ref()
        .and_then(|c| c.conversation_type.as_deref())
        .unwrap_or("");

    // 1:1 (personal) chat — always process
    if !is_group && conv_type == "personal" {
        return true;
    }

    // Group or channel — require mention
    is_bot_mentioned(&activity.entities, bot_id)
}

/// Check if the bot is mentioned in the entities list.
fn is_bot_mentioned(entities: &Option<Vec<serde_json::Value>>, bot_id: &str) -> bool {
    entities.as_ref()
        .map(|ents| {
            ents.iter().any(|e| {
                e.get("type").and_then(|t| t.as_str()) == Some("mention")
                    && e.get("mentioned")
                        .and_then(|m| m.get("id"))
                        .and_then(|id| id.as_str())
                        == Some(bot_id)
            })
        })
        .unwrap_or(false)
}

/// Strip @mention text from the message (Teams includes it in the text).
fn strip_mention(text: &str, bot_id: &str, entities: &Option<Vec<serde_json::Value>>) -> String {
    let mut result = text.to_string();

    if let Some(ents) = entities {
        for entity in ents {
            if entity.get("type").and_then(|t| t.as_str()) != Some("mention") {
                continue;
            }
            let mentioned_id = entity.get("mentioned")
                .and_then(|m| m.get("id"))
                .and_then(|id| id.as_str())
                .unwrap_or("");
            if mentioned_id != bot_id {
                continue;
            }
            // Remove the <at>BotName</at> tag from text
            if let Some(mention_text) = entity.get("text").and_then(|t| t.as_str()) {
                result = result.replace(mention_text, "");
            }
        }
    }

    result.trim().to_string()
}

/// Fields extracted from an OutboundMessage for sending via Bot Framework.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to_id: Option<String>,
}

pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let conversation_id = o.get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not utf8: {e}")))?
                .to_string();
            let text = o.get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();
            let reply_to_str = o.get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to_id not utf8: {e}")))?;
            let reply_to_id = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields { conversation_id, text, reply_to_id })
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
