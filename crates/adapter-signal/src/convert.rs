use std::collections::HashSet;

use wirken_ipc::wirken_capnp::frame;

/// Parsed inbound Signal message.
pub struct SignalInbound {
    pub message_id: String,
    pub sender: String,
    pub sender_name: String,
    pub text: String,
    pub timestamp: i64,
    /// Group ID if this message was sent to a group, None for 1:1 DMs.
    pub group_id: Option<String>,
}

/// Fields extracted from an outbound frame.
pub struct OutboundFields {
    pub conversation_id: String,
    pub text: String,
    pub reply_to_id: Option<String>,
}

/// Sender allowlist for the Signal adapter.
///
/// Entries are matched against the `conversation_id` of each inbound message:
/// - For 1:1 DMs, the sender's phone number (E.164) must be in the set.
/// - For group messages, the group ID must be in the set.
///
/// An empty allowlist drops every message (fail-closed). This is deliberate:
/// without an explicit list, any Signal contact who knows the linked number
/// can drive the agent, which is rarely the intent. See `docs/channels/signal.md`.
#[derive(Debug, Clone, Default)]
pub struct SignalAllowlist {
    entries: HashSet<String>,
}

impl SignalAllowlist {
    /// Parse from a comma-separated string, as stored in the credential vault.
    /// Whitespace is trimmed; empty segments are ignored.
    pub fn from_csv(s: &str) -> Self {
        let entries = s
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(String::from)
            .collect();
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true iff this message should be delivered to the gateway.
    /// Group messages are keyed on the group ID; DMs on the sender number.
    pub fn allows(&self, msg: &SignalInbound) -> bool {
        let key = msg.group_id.as_deref().unwrap_or(msg.sender.as_str());
        self.entries.contains(key)
    }
}

/// Check if an inbound message should be processed.
///
/// A message is processed only if it has non-empty text AND its sender (or
/// group, for group messages) is in the allowlist. An empty allowlist drops
/// every message.
pub fn should_process(msg: &SignalInbound, allowlist: &SignalAllowlist) -> bool {
    if msg.text.is_empty() {
        return false;
    }
    allowlist.allows(msg)
}

/// Convert a Signal inbound message to a Cap'n Proto inbound frame.
pub fn signal_to_inbound(
    msg: &SignalInbound,
    builder: &mut capnp::message::Builder<capnp::message::HeapAllocator>,
) {
    let frame_builder = builder.init_root::<frame::Builder<'_>>();
    let mut inbound = frame_builder.init_inbound();
    inbound.set_id(&msg.message_id);
    inbound.set_sender_id(&msg.sender);
    inbound.set_sender_name(&msg.sender_name);
    inbound.set_channel("signal");
    // Group messages use the group ID as conversation; DMs use the sender phone number.
    let conversation_id = msg.group_id.as_deref().unwrap_or(&msg.sender);
    inbound.set_conversation_id(conversation_id);
    inbound.set_text(&msg.text);
    inbound.set_timestamp(msg.timestamp);
    inbound.set_is_group(msg.group_id.is_some());
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
                reply_to_id: {
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
