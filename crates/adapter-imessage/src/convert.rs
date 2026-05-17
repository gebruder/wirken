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

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an allowlisted operator types `!approve <prefix>` or
/// `!deny <prefix> [reason]` in the configured approval chat. The
/// prefix-to-`request_id` resolution and the decision derivation
/// happen at the call site in `adapter.rs`; the values are passed
/// in.
///
/// `user_id` is the sender's iMessage handle (phone number or
/// email, as it appears on `data.handle.address`). The gateway
/// side calls `approver_registry::verify("imessage", &actor_user_id)`
/// against the registered allowlist. The adapter does not call
/// verify directly; unauthorized senders are silently dropped on
/// the gateway side, matching the other adapters.
pub fn build_approval_decision(
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
    request_id: &str,
    is_allow: bool,
    user_id: &str,
    user_display: &str,
    denial_reason: Option<&str>,
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
        kind.set_deny(denial_reason.unwrap_or(""));
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as a BlueBubbles text message in the configured
/// approval chat. `target_chat_guid` is forwarded verbatim; the
/// BlueBubbles compound chat-guid format encodes group-vs-DM in
/// the separator itself (`iMessage;-;<handle>` for DMs,
/// `iMessage;+;<group_id>` for groups), and the platform validates
/// the shape on send.
///
/// ## Per-adapter `target_channel_id` parse spectrum (closing entry)
///
/// Eight shapes have landed against umbrella #119, arranged on a
/// format-constraint axis from most-constrained to least:
///
/// - **Fixed-width numeric**: Telegram (`i64`, signed), Discord
///   (`u64`, snowflakes).
/// - **Short string with format**: Slack (alphanumeric channel
///   ids), WhatsApp (digits with optional `+`).
/// - **Compound string with format**: Teams (channel-specific
///   subcategories like `19:meeting_...@thread.v2`), Google Chat
///   (path-shaped `spaces/AAAA...`), Matrix
///   (`!opaque:server.tld`), iMessage (BlueBubbles
///   `iMessage;-;<handle>` or `iMessage;+;<group_id>`).
///
/// iMessage is the eighth-and-final shape closing the cross-
/// adapter coverage arc. The compound-string-with-format slot
/// carries four examples now, validating the spectrum's
/// cross-adapter generality: distinct delimiters, distinct
/// internal structures, one shared property ("structured string
/// with platform-validated shape").
///
/// ## Encoding-site spectrum (closing entry)
///
/// iMessage joins Signal in the text-command correlation-table
/// group:
///
/// - **Encoded payload in click** (six adapters): Telegram,
///   Discord, Slack, Teams, WhatsApp, Google Chat. Press carries
///   `req:<uuid>:allow|deny` per `wirken_adapter_core::approval`.
/// - **Correlation table model** (three adapters):
///   - **Reaction-based**: Matrix (m.reaction with event_id-keyed
///     table mapping `(room_id, event_id)` to `request_id`).
///   - **Text-command**: Signal, iMessage (operator types
///     `!approve <8-hex-prefix>` / `!deny <8-hex-prefix>
///     [reason]`; adapter maps prefix to `request_id`).
///
/// The umbrella's mandate completes with this slice. The shared-
/// crate factoring of the text-command parser, anticipated by
/// the Signal `commands.rs` comment in its original form,
/// becomes a real follow-up now that two consumers exist.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_chat_guid: String,
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
            let target_chat_guid = r
                .get_target_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("target_conversation_id not utf8: {e}")))?
                .to_string();
            if target_chat_guid.is_empty() {
                return Err(capnp::Error::failed(
                    "imessage target_conversation_id must be a non-empty chat guid".to_string(),
                ));
            }
            Ok(ApprovalRequestFields {
                request_id,
                tool_name,
                action_key,
                requested_tier,
                triggering_agent,
                trigger_message,
                target_chat_guid,
            })
        }
        _ => Err(capnp::Error::failed(
            "expected ApprovalRequest frame".to_string(),
        )),
    }
}

/// Build an `ApprovalRequestFailed` frame back to the gateway when
/// the adapter cannot deliver the approval message. The
/// `reason` is a stable snake_case label produced by
/// `classify_send_error` in `adapter.rs`.
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
