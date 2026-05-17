use wirken_ipc::wirken_capnp::frame;

/// Parsed inbound Google Chat message.
pub struct GoogleChatInbound {
    pub message_id: String,
    /// Sender's path-shaped canonical identifier
    /// (`"users/<id>"`). Sourced from `message.sender.name`. The
    /// load-bearing identity assertion: this is what flows into
    /// `frame::Inbound.sender_id`, and what
    /// `approver_registry::verify("googlechat", &id)` matches
    /// against the registered allowlist. Same shape the
    /// approval-press path uses (`event.user.name`), so a user
    /// who sends a text command and a user who presses a button
    /// are identified by the same string.
    pub sender_path: String,
    /// Human-readable display name from `message.sender.displayName`.
    /// Used for the audit row's display field; not load-bearing
    /// for identity.
    pub sender_display: String,
    /// Supplementary email from `message.sender.email`. Forwarded
    /// to the gateway via the `frame::Inbound.metadata` JSON field
    /// (under key `"sender_email"`) so operators reading audit
    /// rows can correlate path identifiers with human-readable
    /// email addresses. Not the identity binding; the path
    /// identifier is.
    pub sender_email: String,
    pub text: String,
    pub timestamp: i64,
    /// The space (room/DM) identifier, e.g. "spaces/SPACE_ID".
    pub space_name: String,
    /// Whether this message is from a direct message space.
    pub is_dm: bool,
}

/// Fields extracted from an outbound frame.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to: Option<String>,
}

/// Check if an inbound message should be processed.
pub fn should_process(msg: &GoogleChatInbound) -> bool {
    !msg.text.is_empty()
}

/// Convert a Google Chat inbound message to a Cap'n Proto inbound
/// frame. The `sender_id` field carries the path-shaped canonical
/// identifier (`users/<id>`); the email goes to the `metadata`
/// JSON under the `sender_email` key as supplementary audit data.
///
/// This is the first consumer of `InboundMessage.metadata` for
/// cross-adapter audit-readability metadata. If other adapters
/// have similar supplementary-metadata candidates (Telegram
/// username vs phone, Slack workspace id, etc.), the convention
/// is now: load-bearing identity in `sender_id`, audit-supplementary
/// fields under named keys in `metadata`.
pub fn google_chat_to_inbound(
    msg: &GoogleChatInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();
    inbound.set_id(&msg.message_id);
    inbound.set_sender_id(&msg.sender_path);
    inbound.set_sender_name(&msg.sender_display);
    inbound.set_channel("google-chat");
    inbound.set_conversation_id(&msg.space_name);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp);
    inbound.set_is_group(!msg.is_dm);
    let meta = serde_json::json!({
        "sender_email": msg.sender_email,
    });
    inbound.set_metadata(meta.to_string());
}

/// Parse an outbound frame from the gateway.
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
            let reply_to = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                conversation_id,
                text,
                reply_to,
            })
        }
        _ => Err(capnp::Error::failed("expected Outbound frame".to_string())),
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

/// Extract a Google Chat message from the webhook JSON payload.
///
/// Google Chat sends events with the following structure:
/// ```json
/// {
///   "type": "MESSAGE",
///   "message": {
///     "name": "spaces/SPACE_ID/messages/MSG_ID",
///     "sender": {"name": "users/USER_ID", "displayName": "Alice", "email": "alice@example.com"},
///     "text": "hello",
///     "createTime": "2024-01-01T00:00:00Z",
///     "space": {"name": "spaces/SPACE_ID", "type": "DM"|"ROOM"}
///   }
/// }
/// ```
pub fn extract_message(json: &serde_json::Value) -> Option<GoogleChatInbound> {
    let event_type = json.get("type")?.as_str()?;
    if event_type != "MESSAGE" {
        return None;
    }

    let message = json.get("message")?;

    let message_id = message
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    let sender = message.get("sender");
    let sender_path = sender
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    if sender_path.is_empty() {
        // Canonical path identifier is the load-bearing identity
        // assertion; events that lack it cannot be authenticated
        // against the approver registry by design. Mirrors the
        // approval-press path's drop-on-missing-user.name in
        // `extract_approval_press`.
        return None;
    }
    let sender_display = sender
        .and_then(|s| s.get("displayName"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();
    let sender_email = sender
        .and_then(|s| s.get("email"))
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string();

    let text = message
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();

    let timestamp = message
        .get("createTime")
        .and_then(|t| t.as_str())
        .and_then(|ts| {
            // Parse RFC 3339 timestamp to Unix millis
            chrono::DateTime::parse_from_rfc3339(ts)
                .ok()
                .map(|dt| dt.timestamp_millis())
        })
        .unwrap_or(0);

    let space = message.get("space");
    let space_name = space
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    let space_type = space
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let is_dm = space_type == "DM";

    Some(GoogleChatInbound {
        message_id,
        sender_path,
        sender_display,
        sender_email,
        text,
        timestamp,
        space_name,
        is_dm,
    })
}

/// One inbound button-press from Google Chat. Produced by
/// [`extract_approval_press`] and consumed by the approval-decision
/// forwarding path in `adapter.rs`. Sibling to [`GoogleChatInbound`]
/// for the same reason the WhatsApp adapter has separate
/// `WhatsAppInbound` and `ApprovalPress` types: a text message
/// becomes `frame::Inbound`, a button press becomes
/// `frame::ApprovalDecision`. Two different output types from two
/// different JSON walks, no shared union type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPress {
    /// Clicker's canonical path identifier (`"users/<id>"`). Used
    /// both as the `actorUserId` on the outbound
    /// `ApprovalDecision` frame and as the `privateMessageViewer`
    /// target on the inline 200-OK response body so the ephemeral
    /// toast goes only to the clicker.
    pub user_name: String,
    /// Clicker's display name from the event. Falls back to
    /// `user_name` when the event omits a display name; keeps the
    /// audit row's display field populated.
    pub user_display: String,
    /// Cross-adapter encoded approval payload from
    /// `event.common.parameters.wirken_approval`. Decoded at the
    /// consumer site via `wirken_adapter_core::approval::decode`.
    pub encoded_payload: String,
}

/// JSON field name carrying the cross-adapter approval payload
/// inside a Google Chat interaction event's
/// `common.parameters` map. Outbound buttons set
/// `onClick.action.parameters` with an entry whose `key` is this
/// constant and whose `value` is the encoded payload; inbound
/// presses read this key back out of `event.common.parameters`.
pub const APPROVAL_FIELD: &str = "wirken_approval";

/// Extract an approval button-press from a Google Chat webhook
/// payload. Recognises the newer `event.common.parameters` shape
/// (flat `key -> value` map) only. Returns `None` when:
///
/// - The event type is not a card-click interaction.
/// - `common.parameters` is absent or missing the
///   [`APPROVAL_FIELD`] key.
/// - `user.name` is absent or empty (anonymous-event drop, parallel
///   to Teams' missing-aadObjectId drop).
///
/// ## Scope: newer `common.parameters` shape only
///
/// Google Chat is in the middle of migrating from the legacy
/// CARD_CLICKED format (with `action.parameters` as an array of
/// `{key, value}` objects) to the newer interaction event format
/// (with `common.parameters` as a flat map). This extractor
/// deliberately handles only the newer shape because the umbrella
/// consistency property is "one named encoding convention per
/// adapter"; supporting both legacy and newer shapes in one
/// adapter would bifurcate the parse path for a deployment that
/// does not yet exist (no wirken Chat app is configured against
/// the legacy shape today).
///
/// If a deployment ever needs the legacy `action.parameters`
/// array, the fix is a sibling extractor function calling this
/// one as a fallback, not an `if let` chain inside this function.
/// Don't extend this function to walk the array; add a separate
/// `extract_approval_press_legacy` if the case ever surfaces.
pub fn extract_approval_press(json: &serde_json::Value) -> Option<ApprovalPress> {
    // Walk: event -> common -> parameters -> wirken_approval value.
    let encoded = json
        .get("common")
        .and_then(|c| c.get("parameters"))
        .and_then(|p| p.get(APPROVAL_FIELD))
        .and_then(|v| v.as_str())?;

    let user = json.get("user")?;
    let user_name = user.get("name").and_then(|n| n.as_str())?;
    if user_name.is_empty() {
        return None;
    }
    let user_display = user
        .get("displayName")
        .and_then(|d| d.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(user_name)
        .to_string();

    Some(ApprovalPress {
        user_name: user_name.to_string(),
        user_display,
        encoded_payload: encoded.to_string(),
    })
}

/// Build an `ApprovalDecision` frame to send back to the gateway
/// when an operator presses an approval button. The decoded
/// payload from `wirken_adapter_core::approval` is unpacked at the
/// press site in `adapter.rs`; the decision bool is derived there
/// and passed in.
///
/// `user_id` is the Google Chat path-shaped user name
/// (`"users/<id>"`). The gateway side calls
/// `approver_registry::verify("googlechat", &actor_user_id)`
/// against the registered allowlist. The adapter does not call
/// verify directly (layering: adapters do not depend on gateway
/// state); unauthorized presses are silently dropped on the
/// gateway side, matching the other button-native adapters.
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
        // Google Chat button presses carry no operator reason
        // field. Empty string maps to `denial_reason: None` on the
        // gateway side, matching the other button-native adapters.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as a Cards v2 button message.
///
/// `target_channel_id` is the space's path-shaped resource name
/// (`"spaces/AAAAxxx"` for both DMs and rooms; the form is the
/// same, only the space type differs). Forwarded verbatim.
///
/// ## Per-adapter `target_channel_id` parse spectrum
///
/// Each button-native adapter parses the platform-neutral
/// `targetConversationId` IPC string according to its platform's
/// identifier shape. Six shapes have landed against umbrella #119,
/// arranged on a format-constraint axis from most-constrained to
/// least:
///
/// - **Fixed-width numeric**: Telegram (`i64`, signed, group ids
///   negative), Discord (`u64`, snowflakes). Parse rejects on
///   non-numeric input or wrong sign.
/// - **Short string with format**: Slack (alphanumeric channel
///   ids like `"C0123ABCD"`), WhatsApp (digits, optionally
///   prefixed with `+`). Validation is format-shape, not length.
/// - **Compound string with format**: Teams (channel-specific
///   subcategories like `19:meeting_...@thread.v2` for meetings,
///   `a:...` for 1:1 chats, `19:abc...@thread.tacv2` for channel
///   threads), Google Chat (path-shaped resource names like
///   `spaces/AAAAxxx`). The format-constraint axis is the
///   convention; concrete subcategories are platform-specific.
///
/// Google Chat is the second example in the
/// compound-string-with-format slot, validating that the slot
/// carries cross-adapter weight. The slot accommodates both
/// Teams' colon-and-at-separated form and Google Chat's
/// path-shaped form; what they share is "structured string with
/// platform-validated shape," not any specific delimiter.
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
                    "googlechat target_conversation_id must be a non-empty space name".to_string(),
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
/// timeout via the `reason` snake_case label.
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
