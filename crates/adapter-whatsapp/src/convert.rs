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

/// One inbound button-press from WhatsApp. Produced by
/// [`super::adapter::extract_button_replies`] and consumed by the
/// approval-decision forwarding path in `handle_webhook`.
///
/// Kept separate from [`WhatsAppInbound`] (the text-message
/// extractor's output) because the two are different message
/// classes from the gateway's perspective: a text message becomes
/// `frame::Inbound`, a press becomes `frame::ApprovalDecision`.
/// Two extractors, two output types is the honest shape; folding
/// them into one would mix unrelated domain objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPress {
    /// Sender's phone number as Meta returns it: digits without
    /// the leading `+`. Forward to gateway verbatim; phone-number
    /// normalization across registry conventions is a gateway-side
    /// concern, not adapter-side.
    pub from: String,
    /// Profile name carried alongside the press, used for the
    /// audit row's display field. Falls back to `from` if absent.
    pub from_name: String,
    /// Cross-adapter encoded approval payload from the button's
    /// `id` field. Decoded at the consumer site via
    /// `wirken_adapter_core::approval::decode`.
    pub encoded_payload: String,
    /// Meta's message id for the press itself, in case future
    /// audit-row work wants it. Not currently forwarded to gateway.
    pub message_id: String,
}

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an approval button. The decoded
/// payload from `wirken_adapter_core::approval` is unpacked at the
/// press site in `adapter.rs`; the decision bool is derived there
/// and passed in.
///
/// `user_id` is the sender's phone number as Meta delivered it
/// (digits, no leading `+`). The gateway side calls
/// `approver_registry::verify("whatsapp", &actor_user_id)` against
/// the registered allowlist; phone-number normalization between
/// registry convention and inbound shape happens at the verify
/// call site (gateway), not in the adapter.
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
        // WhatsApp interactive buttons carry no operator reason
        // field. Empty string maps to `denial_reason: None` on the
        // gateway side, matching the other button-native adapters.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as a WhatsApp interactive button message.
///
/// `target_channel_id` is the recipient's phone number, forwarded
/// verbatim. Convention: digits without leading `+`, matching the
/// shape Meta returns on inbound. Meta's outbound `/messages`
/// endpoint accepts both `+`-prefixed and unprefixed forms, so the
/// chosen convention preserves round-trip identity: a press from
/// `"16505551234"` and an outbound approval `to: "16505551234"`
/// use the same string both directions.
///
/// ## Per-adapter `target_channel_id` parse spectrum
///
/// Each button-native adapter parses the platform-neutral
/// `targetConversationId` IPC string according to its platform's
/// identifier shape. The shapes that have landed against umbrella
/// #119 fall along a format-constraint axis from most-constrained
/// to least:
///
/// - **Fixed-width numeric**: Telegram (`i64`, signed, group ids
///   negative), Discord (`u64`, snowflakes). Parse rejects on
///   non-numeric input or wrong sign.
/// - **Short string with format**: Slack (alphanumeric channel
///   ids like `"C0123ABCD"`), WhatsApp (digits, optionally
///   prefixed with `+`). No length cap beyond what the platform
///   imposes; the format-constraint axis is the validation
///   surface, not the length.
/// - **Compound string with format**: Teams (channel-specific
///   format subcategories: `19:meeting_...@thread.v2` for
///   meetings, `a:...` for 1:1 chats, `19:abc...@thread.tacv2`
///   for channel threads). Each subcategory has its own
///   format-shape; the adapter rounds the string through
///   unchanged and the platform validates on send.
///
/// The next adapter (Google Chat) slots in as a second
/// compound-string-with-format example, with path-shaped ids
/// like `spaces/AAAA.../messages/BBBB...`. The format-constraint
/// axis is the convention; concrete subcategories are
/// platform-specific.
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
                    "whatsapp target_conversation_id must be a non-empty phone number".to_string(),
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
/// the adapter cannot deliver the approval message. The gateway-
/// side audit row records the failure distinctly from a generic
/// timeout; the `reason` label is stable snake_case (see
/// `classify_send_error` in adapter.rs for the mapping).
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
