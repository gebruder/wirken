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
    /// Action.Submit payload. Bot Framework delivers a card-button
    /// press as a `message` activity with `value` populated from the
    /// card's `data` field. For approval buttons the adapter
    /// publishes, `value` is an object containing
    /// `wirken_approval: "req:<uuid>:allow|deny"` per the
    /// cross-adapter encoding in `wirken_adapter_core::approval`.
    pub value: Option<serde_json::Value>,
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

    let sender_id = activity
        .from
        .as_ref()
        .and_then(|f| f.id.as_deref())
        .unwrap_or("");
    inbound.set_sender_id(sender_id);

    let sender_name = activity
        .from
        .as_ref()
        .and_then(|f| f.name.as_deref())
        .unwrap_or("");
    inbound.set_sender_name(sender_name);

    inbound.set_channel("teams");

    let conversation_id = activity
        .conversation
        .as_ref()
        .and_then(|c| c.id.as_deref())
        .unwrap_or("");
    inbound.set_conversation_id(conversation_id);

    let text = strip_mention(
        activity.text.as_deref().unwrap_or(""),
        bot_id,
        &activity.entities,
    );
    inbound.set_text(&text);

    let ts_millis = activity
        .timestamp
        .as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);
    inbound.set_timestamp(ts_millis);

    let is_group = activity
        .conversation
        .as_ref()
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

    inbound.set_metadata(meta.to_string());
}

/// Check if a message should be processed (mention-gating).
/// 1:1 chats: always process.
/// Group/channel: only if bot is @mentioned.
pub fn should_process(activity: &Activity, bot_id: &str) -> bool {
    if activity.activity_type != "message" {
        return false;
    }

    let is_group = activity
        .conversation
        .as_ref()
        .and_then(|c| c.is_group)
        .unwrap_or(false);

    let conv_type = activity
        .conversation
        .as_ref()
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
    entities
        .as_ref()
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
            let mentioned_id = entity
                .get("mentioned")
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
            let reply_to_id = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                conversation_id,
                text,
                reply_to_id,
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

/// JSON field name carrying the cross-adapter approval payload
/// inside an Action.Submit `data` object. Outbound: set
/// `data.wirken_approval = encode(...)`. Inbound: read
/// `activity.value.wirken_approval` and pass to `decode(...)`.
pub const APPROVAL_FIELD: &str = "wirken_approval";

/// Extract the cross-adapter encoded approval payload from an
/// activity's Action.Submit `value` object. Returns `None` when the
/// value is absent, not an object, or missing the
/// `wirken_approval` string field — none of which are errors;
/// they just mean the press is not an approval interaction.
pub fn extract_approval_payload(activity: &Activity) -> Option<&str> {
    activity
        .value
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|obj| obj.get(APPROVAL_FIELD))
        .and_then(|v| v.as_str())
}

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an approval button. The decoded
/// payload from `wirken_adapter_core::approval` is unpacked at the
/// press site in `adapter.rs`; the decision bool is derived there
/// and passed in.
///
/// `user_id` is the Azure AD object id from
/// `activity.from.aad_object_id`. The gateway side calls
/// `approver_registry::verify("teams", &actor_user_id)` against
/// the registered allowlist. The adapter does not call verify
/// directly (layering: adapters do not depend on gateway state);
/// unauthorized presses are silently dropped on the gateway side,
/// matching Telegram, Discord, and Slack.
pub fn build_approval_decision(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    request_id: &str,
    is_allow: bool,
    user_id: &str,
    user_display: &str,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut decision = frame_builder.init_approval_decision();
    decision.set_request_id(request_id);
    decision.set_actor_user_id(user_id);
    decision.set_actor_display(user_display);
    let mut kind = decision.init_decision();
    if is_allow {
        kind.set_allow(());
    } else {
        // Teams Action.Submit buttons carry no operator reason
        // field. Empty string maps to `denial_reason: None` on the
        // gateway side, matching the other button-native adapters.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as an Adaptive Card with two Action.Submit buttons.
///
/// `target_channel_id` is forwarded verbatim. Teams conversation
/// ids are compound strings with format-specific subcategories
/// (`19:meeting_...@thread.v2` for meetings, `a:...` for 1:1
/// chats, `19:abc...@thread.tacv2` for channel threads); the
/// adapter rounds them through unchanged.
///
/// ## Per-adapter `target_channel_id` parse spectrum
///
/// Each button-native adapter parses the platform-neutral
/// `targetConversationId` IPC string according to its platform's
/// identifier shape. Four shapes have landed against umbrella #119
/// so far, on a spectrum from most-constrained to least:
///
/// - **Numeric, fixed-width**: Telegram (`i64`, including negative
///   group ids), Discord (`u64`, snowflakes). Parse rejects on
///   non-numeric input.
/// - **Opaque string, short**: Slack (`String`, e.g. `"C0123ABCD"`).
///   No format check beyond non-empty.
/// - **Opaque string, compound**: Teams (this adapter). Compound
///   ids with channel-specific format subcategories. No format
///   check beyond non-empty; the platform validates shape on
///   send.
///
/// The next adapters slot into the spectrum: WhatsApp uses phone
/// numbers (`String`, opaque-with-loose-format), Google Chat uses
/// path ids (`String`, opaque-with-path-shape). Each lands its own
/// parse in its adapter slice; the comment is the convention.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_channel_id: String,
    /// Bot Connector regional `service_url` populated by the gateway
    /// when it has the value for the target conversation. Empty when
    /// the gateway did not populate it (e.g. legacy approval gates
    /// that have not yet been updated to set the field); the adapter
    /// falls back to a single hardcoded public-cloud default with a
    /// warning log in that case.
    pub service_url: String,
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
                .to_string();
            if target_channel_id.is_empty() {
                return Err(capnp::Error::failed(
                    "teams target_conversation_id must be a non-empty conversation id".to_string(),
                ));
            }
            // serviceUrl is optional; Cap'n Proto Text fields return
            // "" when absent. Empty string here is the "gateway did
            // not populate the field" case; the adapter handles
            // fallback with a warning log at send time.
            let service_url = r
                .get_service_url()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("service_url not utf8: {e}")))?
                .to_string();
            Ok(ApprovalRequestFields {
                request_id,
                tool_name,
                action_key,
                requested_tier,
                triggering_agent,
                trigger_message,
                target_channel_id,
                service_url,
            })
        }
        _ => Err(capnp::Error::failed(
            "expected ApprovalRequest frame".to_string(),
        )),
    }
}

/// Build an `ApprovalRequestFailed` frame back to the gateway when
/// the adapter cannot deliver the approval message (token mint
/// failure, Bot Connector REST rejection, encode failure on a
/// malformed `request_id`). The gateway-side audit row records the
/// failure distinctly from a generic timeout.
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
