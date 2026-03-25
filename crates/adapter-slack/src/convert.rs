use wirken_ipc::wirken_capnp::frame;

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
