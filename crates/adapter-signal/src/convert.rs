use std::collections::HashSet;

use wirken_ipc::wirken_capnp::frame;

/// Reason an allowlist entry failed to parse. Surfaced to the
/// operator at adapter startup so misconfigured entries do not
/// silently drop legitimate senders at runtime.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignalAllowlistError {
    #[error(
        "allowlist entry '{0}' looks like a phone number but is missing the leading '+'; use E.164 format (e.g. +15551234567)"
    )]
    PhoneMissingPlus(String),
    #[error("allowlist entry '{0}' looks like a phone number but contains no digits")]
    PhoneNoDigits(String),
}

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
    /// Parse from a comma-separated string, as stored in the
    /// credential vault. Whitespace is trimmed and empty segments are
    /// ignored. Phone-shaped entries are normalized to digits with a
    /// leading `+` so runtime senders that arrive in a slightly
    /// different format (extra spaces, dashes) still match. Group ids
    /// are a separate namespace and are kept verbatim.
    ///
    /// Entries that look like phone numbers but cannot be normalized
    /// (e.g., no leading `+`) are rejected here so the operator sees
    /// the error at startup rather than discovering silent drops in
    /// production.
    pub fn from_csv(s: &str) -> Result<Self, SignalAllowlistError> {
        let mut entries = HashSet::new();
        for raw in s.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            entries.insert(normalize_entry(trimmed)?);
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true iff this message should be delivered to the gateway.
    /// Group messages are keyed on the group ID; DMs on the sender number.
    ///
    /// The runtime sender goes through the same normalization as the
    /// allowlist entries so format drift between signal-cli and the
    /// operator-configured list does not cause silent drops.
    pub fn allows(&self, msg: &SignalInbound) -> bool {
        let key = match msg.group_id.as_deref() {
            Some(g) => g.to_string(),
            None => match normalize_phone(msg.sender.as_str()) {
                Ok(p) => p,
                Err(_) => return false,
            },
        };
        self.entries.contains(&key)
    }
}

/// Normalize a single allowlist entry. Phone-shaped inputs go
/// through `normalize_phone`; anything else (group ids) is returned
/// verbatim after the caller has already trimmed it.
fn normalize_entry(entry: &str) -> Result<String, SignalAllowlistError> {
    if looks_like_phone(entry) {
        normalize_phone(entry)
    } else {
        Ok(entry.to_string())
    }
}

/// `true` if every character is one of `+0-9` plus the common
/// human-written separators (space, `-`, `(`, `)`, `.`) AND there is
/// at least one digit. Group ids contain other characters and fail
/// this test, which is what routes them past the phone normalizer.
fn looks_like_phone(s: &str) -> bool {
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let only_phone_chars = s
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'));
    has_digit && only_phone_chars
}

/// Produce the canonical E.164 form `+<digits>`. Requires a leading
/// `+` in the input to avoid heuristically assuming country code.
pub(crate) fn normalize_phone(raw: &str) -> Result<String, SignalAllowlistError> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('+') {
        return Err(SignalAllowlistError::PhoneMissingPlus(raw.to_string()));
    }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(SignalAllowlistError::PhoneNoDigits(raw.to_string()));
    }
    Ok(format!("+{digits}"))
}

/// Envelope kind, used by the adapter to gate linked-device sends and to
/// record the self-echo fingerprint for outgoing `send` RPCs. Consumers
/// downstream of the adapter do not distinguish; allowlist and gateway
/// both see a single [`SignalInbound`] shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    /// `envelope.dataMessage` — an inbound DM or group message from
    /// another contact. Production case for an allowlisted sender.
    Data,
    /// `envelope.syncMessage.sentMessage` — a message the operator sent
    /// from another linked device (e.g., their phone), mirrored to this
    /// daemon by Signal's multi-device protocol. Gated by the adapter's
    /// `forward_linked_device_sends` flag and the self-echo filter.
    SyncSent,
}

/// Parse a single envelope JSON value (as carried inside a
/// `subscribeReceive` notification's `params.result.envelope`) into the
/// adapter's internal inbound shape. Returns `None` for envelopes the
/// adapter should drop silently: receipts, typing indicators, and empty
/// sync envelopes that carry no user text.
///
/// Extraction rules:
/// - `source` prefers the legacy `source` field but falls back to
///   `sourceNumber`; both carry E.164 in 0.14.x. Contacts reachable
///   only by UUID (Signal's phone-privacy feature) have empty
///   `source` and will be dropped by the allowlist. That path is a
///   known gap; see the follow-up for sourceUuid handling.
/// - Data messages use the message text from `dataMessage.message`.
///   Group id (if any) is drawn from `dataMessage.groupV2.id` (modern
///   signal-cli emits v2 for all new groups) with a fallback to the
///   legacy `dataMessage.groupInfo.groupId` so pre-v2 group backlogs
///   still route.
/// - Sync-sent messages use the destination as the conversation key so
///   the allowlist matches the contact the operator was messaging, not
///   their own number. Tests-to-self work when the operator's own
///   number is in the allowlist.
pub fn extract_inbound(envelope: &serde_json::Value) -> Option<(SignalInbound, InboundKind)> {
    let source = envelope
        .get("source")
        .or_else(|| envelope.get("sourceNumber"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let source_name = envelope
        .get("sourceName")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let timestamp = envelope
        .get("timestamp")
        .and_then(|t| t.as_i64())
        .unwrap_or(0);

    if let Some(dm) = envelope.get("dataMessage") {
        let text = dm
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        if text.is_empty() {
            return None;
        }
        // Modern signal-cli emits `dataMessage.groupV2.id` (base64) for
        // group messages. Legacy envelopes used
        // `dataMessage.groupInfo.groupId`; accept both so pre-v2 group
        // backlogs still route. groupV2 takes precedence when both are
        // present.
        let group_id = dm
            .get("groupV2")
            .and_then(|g| g.get("id"))
            .and_then(|id| id.as_str())
            .or_else(|| {
                dm.get("groupInfo")
                    .and_then(|g| g.get("groupId"))
                    .and_then(|id| id.as_str())
            })
            .map(|s| s.to_string());
        let message_id = format!("{source}_{timestamp}");
        return Some((
            SignalInbound {
                message_id,
                sender: source,
                sender_name: source_name,
                text,
                timestamp,
                group_id,
            },
            InboundKind::Data,
        ));
    }

    if let Some(sent) = envelope
        .get("syncMessage")
        .and_then(|s| s.get("sentMessage"))
    {
        let text = sent
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        if text.is_empty() {
            return None;
        }
        let destination = sent
            .get("destination")
            .or_else(|| sent.get("destinationNumber"))
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        if destination.is_empty() {
            return None;
        }
        let message_id = format!("sync_{timestamp}");
        return Some((
            SignalInbound {
                message_id,
                sender: destination,
                sender_name: source_name,
                text,
                timestamp,
                group_id: None,
            },
            InboundKind::SyncSent,
        ));
    }

    None
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
