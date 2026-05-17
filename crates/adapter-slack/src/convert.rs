use slack_morphism::prelude::{
    SlackEventCallbackBody, SlackMessageEventType, SlackPushEventCallback,
};
use wirken_ipc::wirken_capnp::frame;

/// Bot self-identity used to filter the bot's own messages out of the
/// inbound stream. `bot_id` is `None` if Slack did not return one for
/// this app, in which case the bot_id branch of the filter is a no-op.
#[derive(Debug, Clone)]
pub struct SlackBotIdentity {
    pub user_id: String,
    pub bot_id: Option<String>,
}

/// Extracted fields from a Slack message event for IPC.
#[derive(Debug, Clone)]
pub struct SlackInbound {
    pub message_ts: String,
    pub user_id: String,
    pub user_name: String,
    pub channel_id: String,
    pub text: String,
    pub thread_ts: Option<String>,
    pub is_dm: bool,
    pub bot_mentioned: bool,
    pub files: Vec<String>,
}

/// Build a Cap'n Proto InboundMessage frame from Slack message fields.
pub fn slack_to_inbound(
    msg: &SlackInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    inbound.set_id(&msg.message_ts);
    inbound.set_sender_id(&msg.user_id);
    inbound.set_sender_name(&msg.user_name);
    inbound.set_channel("slack");
    inbound.set_conversation_id(&msg.channel_id);
    inbound.set_text(&msg.text);

    // Slack timestamps are like "1711234567.890123" — convert to millis
    let ts_millis = parse_slack_ts(&msg.message_ts);
    inbound.set_timestamp(ts_millis);

    inbound.set_is_group(!msg.is_dm);

    let reply_to = msg.thread_ts.as_deref().unwrap_or("");
    inbound.set_reply_to_id(reply_to);

    let mut meta = serde_json::json!({});
    if let Some(ref thread_ts) = msg.thread_ts {
        meta["thread_ts"] = serde_json::Value::String(thread_ts.clone());
    }
    if !msg.files.is_empty() {
        meta["files"] = serde_json::json!(msg.files);
    }
    meta["bot_mentioned"] = serde_json::json!(msg.bot_mentioned);

    inbound.set_metadata(meta.to_string());
}

/// Convert a Slack push event into a [`SlackInbound`], applying every
/// echo-loop and noise filter. Returns `None` for any event that
/// must not reach the agent. Centralised here so the filter logic is
/// unit-testable without spinning up the adapter task graph.
///
/// Filter rules, in order:
///
/// 1. Body must be a `Message` event. AppHomeOpened, ReactionAdded,
///    UserChange, and the dozens of other [`SlackEventCallbackBody`]
///    variants are dropped.
/// 2. `subtype` must be one of the allowed user-message variants
///    (`None`, `me_message`, `thread_broadcast`, `file_share`).
///    `bot_message` (the bot's own outbound coming back through
///    `message.im`), `message_changed`/`message_deleted` (edits and
///    deletions), and every system / membership / channel-metadata
///    subtype are dropped.
/// 3. `sender.user` must be present.
/// 4. `sender.user` must not equal `bot.user_id`. Belt-and-suspenders
///    against an event whose subtype passed the allowlist but whose
///    sender is the bot itself.
/// 5. If the event carries a `sender.bot_id` and `bot.bot_id` is
///    known, they must not match. Some events carry `bot_id` without
///    a `user_id`; this branch handles them.
/// 6. Text must be non-empty.
pub fn from_push_event(
    event: &SlackPushEventCallback,
    bot: &SlackBotIdentity,
) -> Option<SlackInbound> {
    let SlackEventCallbackBody::Message(msg_event) = &event.event else {
        return None;
    };

    match &msg_event.subtype {
        None => {}
        Some(t) => match t {
            SlackMessageEventType::MeMessage
            | SlackMessageEventType::ThreadBroadcast
            | SlackMessageEventType::FileShare => {}
            _ => return None,
        },
    }

    let user_id = msg_event.sender.user.as_ref()?.0.clone();

    if user_id == bot.user_id {
        return None;
    }
    if let (Some(self_bot_id), Some(event_bot_id)) =
        (bot.bot_id.as_ref(), msg_event.sender.bot_id.as_ref())
        && self_bot_id == &event_bot_id.0
    {
        return None;
    }

    let text = msg_event
        .content
        .as_ref()
        .and_then(|c| c.text.as_ref())
        .map(|t| t.to_string())
        .unwrap_or_default();
    if text.is_empty() {
        return None;
    }

    let channel_id = msg_event
        .origin
        .channel
        .as_ref()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let message_ts = msg_event.origin.ts.0.clone();
    let thread_ts = msg_event.origin.thread_ts.as_ref().map(|t| t.0.clone());

    let is_dm = msg_event
        .origin
        .channel_type
        .as_ref()
        .map(|ct| ct.0 == "im")
        .unwrap_or(false);

    let bot_mentioned = is_bot_mentioned(&text, &bot.user_id);

    let files: Vec<String> = msg_event
        .content
        .as_ref()
        .and_then(|c| c.files.as_ref())
        .map(|fl| {
            fl.iter()
                .filter_map(|f| f.url_private.as_ref().map(|u| u.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Some(SlackInbound {
        message_ts,
        user_id,
        user_name: String::new(),
        channel_id,
        text,
        thread_ts,
        is_dm,
        bot_mentioned,
        files,
    })
}

/// Check whether the bot is mentioned by its exact Slack user id.
///
/// Slack mention syntax is `<@Uxxxxx>`. An earlier implementation used
/// `text.contains("<@")` which matched any user mention, not just the
/// bot — a workspace member mentioning a colleague would trigger the
/// bot's mention gate. The exact form `<@{bot_user_id}>` (with the
/// closing `>`) also prevents substring collisions between user ids
/// that share a prefix (e.g. `<@U123>` must not match bot id `U1234`).
pub(crate) fn is_bot_mentioned(text: &str, bot_user_id: &str) -> bool {
    if bot_user_id.is_empty() {
        return false;
    }
    text.contains(&format!("<@{bot_user_id}>"))
}

/// Check if a channel message should be processed (mention-gating).
/// In channels, only respond when the bot is @mentioned.
/// In DMs (im), always respond.
pub fn should_process(msg: &SlackInbound) -> bool {
    if msg.is_dm {
        return true;
    }
    msg.bot_mentioned
}

/// Fields extracted from an OutboundMessage for sending via Slack.
pub struct OutboundFields {
    pub channel_id: String,
    pub text: String,
    pub thread_ts: Option<String>,
}

/// Parse a Cap'n Proto OutboundMessage into Slack-ready fields.
pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let channel_id = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("conversation_id not utf8: {e}")))?
                .to_string();

            let text = o
                .get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();

            // reply_to_id carries the thread_ts for threaded replies
            let reply_to_str = o
                .get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to_id not utf8: {e}")))?;
            let thread_ts = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                channel_id,
                text,
                thread_ts,
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

/// Parse a Slack timestamp ("1711234567.890123") to milliseconds.
fn parse_slack_ts(ts: &str) -> i64 {
    let parts: Vec<&str> = ts.split('.').collect();
    match parts.as_slice() {
        [secs, frac] => {
            let s: i64 = secs.parse().unwrap_or(0);
            // Slack uses 6-digit fractional seconds (microseconds)
            let us: i64 = frac.parse().unwrap_or(0);
            s * 1000 + us / 1000
        }
        [secs] => {
            let s: i64 = secs.parse().unwrap_or(0);
            s * 1000
        }
        _ => 0,
    }
}

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an approval button. The `action_id`
/// decoding lives at the press site in `adapter.rs`; the decision
/// bool is derived there and passed in. Slack user ids are typed
/// strings (`SlackUserId(String)`, e.g. `"UA8RXUSPL"`); the
/// adapter forwards the inner string as `actorUserId`. The gateway
/// side calls `approver_registry::verify("slack", &actor_user_id)`
/// against the registered allowlist. The adapter does not call
/// verify directly (layering: adapters do not depend on gateway
/// state); unauthorized presses are silently dropped on the
/// gateway side, matching the Telegram and Discord adapters.
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
        // Slack block-action buttons carry no operator reason field
        // (a follow-up modal trigger would; out of scope for the
        // first adapter slice). Empty string maps to `denial_reason:
        // None` on the gateway side, matching Telegram and Discord.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as a Block Kit message in the configured approval
/// channel.
///
/// `target_channel_id` is parsed as `String` and forwarded
/// verbatim, because Slack channel ids are typed strings (e.g.
/// `"C0123ABCD"`) and slack-morphism's `SlackChannelId` is a
/// newtype over `String`. The platform-neutral `targetConversationId`
/// IPC field is a string; each adapter parses it according to its
/// platform's identifier shape:
///
/// - Telegram chat ids are signed 64-bit (`i64`).
/// - Discord channel ids are unsigned 64-bit (`u64`).
/// - Slack channel ids are strings (this adapter).
/// - Teams uses GUIDs, WhatsApp uses phone numbers, Google Chat
///   uses path ids: each lands its own parse here in its adapter
///   slice. The pattern is: parse the platform-neutral string
///   into whichever shape the platform SDK expects.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_channel_id: String,
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
                    "slack target_conversation_id must be a non-empty channel id".to_string(),
                ));
            }
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
/// inaccessible, Slack Web API rejection, encode failure on a
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

#[cfg(test)]
mod ts_tests {
    use super::parse_slack_ts;

    #[test]
    fn parse_standard_ts() {
        assert_eq!(parse_slack_ts("1711234567.890123"), 1711234567890);
    }

    #[test]
    fn parse_no_fraction() {
        assert_eq!(parse_slack_ts("1711234567"), 1711234567000);
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_slack_ts(""), 0);
    }
}
