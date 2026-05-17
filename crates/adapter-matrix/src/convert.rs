use wirken_adapter_core::approval::Decision;
use wirken_ipc::wirken_capnp::frame;

/// Fields extracted from a Matrix room message event.
#[derive(Debug, Clone)]
pub struct MatrixInbound {
    pub event_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub room_id: String,
    pub text: String,
    pub timestamp_ms: i64,
    pub is_dm: bool,
    pub reply_to_event: Option<String>,
    pub room_name: Option<String>,
    pub is_encrypted: bool,
}

/// Build a Cap'n Proto InboundMessage from Matrix event fields.
pub fn matrix_to_inbound(
    msg: &MatrixInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();

    inbound.set_id(&msg.event_id);
    inbound.set_sender_id(&msg.sender_id);
    inbound.set_sender_name(&msg.sender_name);
    inbound.set_channel("matrix");
    inbound.set_conversation_id(&msg.room_id);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp_ms);
    inbound.set_is_group(!msg.is_dm);
    inbound.set_reply_to_id(msg.reply_to_event.as_deref().unwrap_or(""));

    let mut meta = serde_json::json!({});
    if let Some(ref name) = msg.room_name {
        meta["room_name"] = serde_json::Value::String(name.clone());
    }
    meta["encrypted"] = serde_json::json!(msg.is_encrypted);

    inbound.set_metadata(meta.to_string());
}

/// Check if a message should be processed.
/// In DMs: always. In rooms: only if the bot's display name or MXID is mentioned.
pub fn should_process(msg: &MatrixInbound, bot_user_id: &str, bot_display_name: &str) -> bool {
    if msg.is_dm {
        return true;
    }
    // Check if bot is mentioned in the text
    msg.text.contains(bot_user_id)
        || (!bot_display_name.is_empty() && msg.text.contains(bot_display_name))
}

/// Fields for sending a message via Matrix.
pub struct OutboundFields {
    pub room_id: String,
    pub text: String,
    pub reply_to_event: Option<String>,
}

pub fn parse_outbound(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> Result<OutboundFields, capnp::Error> {
    let frame_reader = msg.get_root::<frame::Reader<'_>>()?;

    match frame_reader.which()? {
        frame::Outbound(outbound) => {
            let o = outbound?;
            let room_id = o
                .get_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("room_id not utf8: {e}")))?
                .to_string();
            let text = o
                .get_text()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("text not utf8: {e}")))?
                .to_string();
            let reply_to_str = o
                .get_reply_to_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("reply_to not utf8: {e}")))?;
            let reply_to_event = if reply_to_str.is_empty() {
                None
            } else {
                Some(reply_to_str.to_string())
            };

            Ok(OutboundFields {
                room_id,
                text,
                reply_to_event,
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

// ---------------------------------------------------------------------------
// Approval gate (per umbrella #119): m.reaction-based, correlation-table model
// ---------------------------------------------------------------------------
//
// Matrix has no application-data affordance equivalent to button
// custom_id / action_id / data fields. The cross-adapter encoding
// `req:<uuid>:allow|deny` from `wirken_adapter_core::approval` has
// nowhere to live on the press. Matrix joins Signal in the
// correlation-table group: the adapter maintains a per-room map from
// the bot's outbound approval-request `event_id` to the gateway-minted
// `request_id`, looks up on inbound `m.reaction`, and removes on use.
//
// The decision encoding is a closed enum of two emoji codepoints:
// ✅ (U+2705) for allow, ❌ (U+274C) for deny. The Matrix spec
// (MSC2677) allows either codepoint to ship with an optional Unicode
// variation selector (U+FE0E text presentation or U+FE0F emoji
// presentation) on the wire. [`normalize_reaction_key`] strips both
// selectors at the parse boundary and returns the canonical base
// codepoint mapped to a [`wirken_adapter_core::approval::Decision`].
// Same shape as Lyrik's stable-ID grammar decision: pick one
// canonical form, normalize at the boundary, do not normalize
// elsewhere.

/// One inbound reaction event. Produced by [`extract_reactions`]
/// and consumed by the approval-decision forwarding path in
/// `adapter.rs`. Sibling to [`MatrixInbound`] (`m.room.message`
/// extractor output) because a reaction is a structurally
/// different event class with a different downstream IPC frame
/// (`ApprovalDecision` vs `Inbound`). Two output types from two
/// extractors, parallel to WhatsApp's `extract_button_replies` and
/// Google Chat's `extract_approval_press`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    /// Reactor's MXID (`"@user:server.tld"`). Forwarded as
    /// `actor_user_id` on the outbound `ApprovalDecision` frame.
    pub reactor_mxid: String,
    /// Room the reaction occurred in. Used together with the
    /// reacted-to event id to look up the pending approval.
    pub room_id: String,
    /// Event id of the message the reactor reacted to. For
    /// approval gating this should match the bot's outbound
    /// approval-request event id stored in `pending_approvals`.
    pub reacted_to_event_id: String,
    /// Reaction key on the wire, post-normalization. Callers run
    /// this through [`normalize_reaction_key`] to map to a
    /// [`Decision`]; reactions whose key does not map to one of
    /// the closed-enum forms drop with a debug log.
    pub key: String,
}

/// Extract reaction events from a Matrix sync timeline events
/// array. Sibling to [`crate::adapter::parse_sync_event`]: same
/// JSON shape walked twice, two different domain objects
/// extracted. Reactions to bot self-messages and reactions to
/// non-text events are not filtered here; the table lookup at
/// the call site drops anything not corresponding to a pending
/// approval.
pub fn extract_reactions(events: &[serde_json::Value], room_id: &str) -> Vec<ReactionEvent> {
    let mut out = Vec::new();
    for event in events {
        if event.get("type").and_then(|t| t.as_str()) != Some("m.reaction") {
            continue;
        }
        let Some(reactor_mxid) = event.get("sender").and_then(|s| s.as_str()) else {
            continue;
        };
        let Some(content) = event.get("content") else {
            continue;
        };
        let Some(relates) = content.get("m.relates_to") else {
            continue;
        };
        // m.reaction's `rel_type` should be "m.annotation"; we don't
        // strictly enforce it here because the `event_id` + `key`
        // pair is what we need, and the table lookup naturally
        // rejects anything not pointing at a pending approval.
        let Some(reacted_to_event_id) = relates.get("event_id").and_then(|e| e.as_str()) else {
            continue;
        };
        let Some(key) = relates.get("key").and_then(|k| k.as_str()) else {
            continue;
        };
        out.push(ReactionEvent {
            reactor_mxid: reactor_mxid.to_string(),
            room_id: room_id.to_string(),
            reacted_to_event_id: reacted_to_event_id.to_string(),
            key: key.to_string(),
        });
    }
    out
}

/// Strip the Unicode variation selectors U+FE0E (text presentation)
/// and U+FE0F (emoji presentation) and compare the result to the
/// canonical decision codepoints ✅ (U+2705, Allow) and ❌
/// (U+274C, Deny). Any other key returns `None`.
///
/// Per Matrix spec MSC2677, m.reaction event keys for these
/// codepoints may appear in any of three byte sequences for what
/// users perceive as the same emoji: the bare codepoint, the
/// codepoint plus U+FE0E, or the codepoint plus U+FE0F. All three
/// must round-trip to the same `Decision`; normalization happens
/// here at the parse boundary, once, and the rest of the adapter
/// works in canonical form.
pub fn normalize_reaction_key(key: &str) -> Option<Decision> {
    let stripped: String = key
        .chars()
        .filter(|c| *c != '\u{FE0E}' && *c != '\u{FE0F}')
        .collect();
    match stripped.as_str() {
        "\u{2705}" => Some(Decision::Allow),
        "\u{274C}" => Some(Decision::Deny),
        _ => None,
    }
}

/// Build an `ApprovalDecision` frame for the gateway when a
/// reactor reacts with an in-enum emoji to a stored bot approval
/// message. The decision is derived from [`normalize_reaction_key`]
/// at the call site; the bool is passed in.
///
/// `user_id` is the reactor's MXID (`"@user:server.tld"`), the
/// stable Matrix identifier across servers and time. The gateway
/// side calls `approver_registry::verify("matrix", &actor_user_id)`
/// against the registered allowlist. The adapter does not call
/// verify directly (layering: adapters do not depend on gateway
/// state); unauthorized reactions are silently dropped on the
/// gateway side, matching the other adapters.
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
        // Reaction-based approval carries no operator reason field
        // (no text channel on a reaction). Empty string maps to
        // `denial_reason: None` on the gateway side, matching the
        // other adapters.
        kind.set_deny("");
    }
}

/// Fields parsed from an `ApprovalRequest` frame the adapter
/// renders as an `m.room.message` with the canonical reaction
/// instruction. `target_room_id` is the Matrix room id
/// (`"!opaque:server.tld"` form), forwarded verbatim.
///
/// ## Per-adapter `target_channel_id` parse spectrum
///
/// Seven shapes have landed against umbrella #119, on a
/// format-constraint axis from most-constrained to least:
///
/// - **Fixed-width numeric**: Telegram (`i64`, signed), Discord
///   (`u64`, snowflakes). Parse rejects on non-numeric input.
/// - **Short string with format**: Slack (alphanumeric channel
///   ids), WhatsApp (digits, optional `+`). Format-shape
///   validation, not length.
/// - **Compound string with format**: Teams (channel-specific
///   subcategories like `19:meeting_...@thread.v2`), Google Chat
///   (path-shaped `spaces/AAAA...`), Matrix (opaque room ids
///   like `!opaque:server.tld` with `!` prefix and `:server`
///   suffix). Each subcategory has its own platform-specific
///   format-shape; the adapter rounds the string through
///   unchanged.
///
/// Matrix is the third compound-string-with-format example,
/// further validating the spectrum's cross-adapter use. The
/// only common property of the slot is "structured string with
/// platform-validated shape"; specific delimiters vary.
///
/// ## Encoding-site spectrum (new for this slice)
///
/// The encoding-site comment chain across umbrella adapters
/// also gains a seventh shape, with Matrix as the first non-
/// button-native entry after the encoding spec was lifted into
/// `wirken_adapter_core::approval`:
///
/// - **Encoded payload in click**: Telegram `callback_data`,
///   Discord `custom_id`, Slack `action_id`, Teams
///   `data.wirken_approval`, WhatsApp `interactive.button_reply.id`,
///   Google Chat `common.parameters.wirken_approval`. All six
///   carry the `req:<uuid>:allow|deny` shape.
/// - **Correlation table model**: Signal (text-command with
///   `request_id` prefix), Matrix (m.reaction with reacted-to
///   `event_id` as the table key). The press itself carries no
///   `request_id`; the adapter maintains the binding.
///
/// The umbrella accommodates both groups because the
/// trust-model property is "the press identifies a unique
/// pending approval and the presser," and a correlation table
/// satisfies it as long as the table is one-shot, in-process,
/// and the table-lookup miss path drops cleanly.
pub struct ApprovalRequestFields {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    pub triggering_agent: String,
    pub trigger_message: String,
    pub target_room_id: String,
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
            let target_room_id = r
                .get_target_conversation_id()?
                .to_str()
                .map_err(|e| capnp::Error::failed(format!("target_conversation_id not utf8: {e}")))?
                .to_string();
            if target_room_id.is_empty() {
                return Err(capnp::Error::failed(
                    "matrix target_conversation_id must be a non-empty room id".to_string(),
                ));
            }
            Ok(ApprovalRequestFields {
                request_id,
                tool_name,
                action_key,
                requested_tier,
                triggering_agent,
                trigger_message,
                target_room_id,
            })
        }
        _ => Err(capnp::Error::failed(
            "expected ApprovalRequest frame".to_string(),
        )),
    }
}

/// Build an `ApprovalRequestFailed` frame back to the gateway
/// when the adapter cannot deliver the approval message.
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
