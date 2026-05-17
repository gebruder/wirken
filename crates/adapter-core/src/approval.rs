//! Shared cross-adapter encoding for approval-button payloads.
//!
//! The button-native channel adapters (Telegram inline keyboards,
//! Discord interactive components, Slack block-kit, Teams Adaptive
//! Cards, WhatsApp reply buttons, Google Chat Card v2) each carry a
//! small per-button string back to the bot when an operator presses
//! the button: `callback_data` on Telegram, `custom_id` on Discord,
//! `action_id` on Slack, and so on. The string round-trips opaquely
//! through the platform; the adapter encodes it on outbound and
//! decodes it on the inbound press.
//!
//! This module is the cross-adapter convention. The encoding is
//! lifted verbatim from the Telegram adapter's existing
//! `req:<uuid>:allow|deny` shape (see
//! `crates/adapter-telegram/src/adapter.rs::parse_callback_data`):
//! Telegram has been the reference implementation since the approval
//! gate landed there, and the shape proved adequate. Lifting it into
//! a shared module gives the next button-native adapter slices one
//! named convention instead of four independent re-implementations,
//! and pins byte-budget constants near the encoder so a future
//! field addition has the cross-adapter constraint right there at
//! the call site.
//!
//! ## Binding mechanism
//!
//! The encoded payload is intentionally minimal: `request_id` plus
//! `decision`. Two bindings the payload does not carry, and why:
//!
//! - **Session binding.** The `request_id` is a fresh `Uuid::new_v4`
//!   minted by the gateway's pending-approval queue
//!   (`pending_approvals.rs::PendingApprovalQueue::register`), and
//!   the queue is one-shot: `resolve` consumes the entry. A replayed
//!   payload from one session cannot apply to another because there
//!   is at most one pending entry per request_id in the entire
//!   gateway, and successful resolution consumes it.
//!
//! - **Issuer binding.** The platform supplies authenticated user
//!   identity at the press site. Discord, Slack, Teams, WhatsApp,
//!   Google Chat, and Telegram all sign their inbound callbacks and
//!   tell the adapter who clicked. The adapter forwards that
//!   platform-supplied user_id to the gateway in the
//!   `ApprovalDecision` IPC frame, and the gateway verifies via
//!   `approver_registry`. Embedding `issuer_user_id` in the payload
//!   would not add anything the platform's webhook signature does
//!   not already vouch for.
//!
//! Embedding either binding in the payload would defend against
//! threats outside the current model (untrusted platform identity,
//! forged request_id collisions); adding fields for those threats
//! without a concrete motivation would be speculative abstraction.
//!
//! ## Encoding
//!
//! ```text
//! payload    := "req:" request_id ":" decision
//! request_id := UUID string, canonical 8-4-4-4-12 hex form (36 chars)
//! decision   := "allow" | "deny"
//! ```
//!
//! Worst-case encoded length is `4 + 36 + 1 + 5 = 46` bytes, well
//! under the smallest channel cap in scope ([`DISCORD_CUSTOM_ID_MAX`]
//! at 100 bytes). The `"req:"` prefix is a version marker: a future
//! encoding can ship under `"req2:"` so adapters can co-deploy
//! mixed-version button populations without a breaking switch.
//!
//! Decode parses right-to-left at the trailing decision separator,
//! not left-to-right. The current `request_id` shape (canonical UUID)
//! contains no `:`, but parsing right-to-left lets a future
//! `request_id` format with internal colons (composite identifier,
//! prefixed UUID, etc.) extend the shape without re-parsing.

use std::fmt;

/// Hard cap on Discord interactive-component `custom_id` length, in
/// bytes. The encoded payload must fit within this budget on every
/// adapter we ship a button-native approval gate for; Discord is the
/// tightest of the set.
pub const DISCORD_CUSTOM_ID_MAX: usize = 100;

/// Hard cap on Slack block-kit `action_id` length, in bytes. Slack
/// is more generous than Discord but constrained nonetheless.
pub const SLACK_ACTION_ID_MAX: usize = 255;

/// Hard cap on Telegram inline-button `callback_data` length, in
/// bytes. Telegram is the reference implementation; pinned here so
/// the shared encoding documents the per-channel budgets in one
/// place.
pub const TELEGRAM_CALLBACK_DATA_MAX: usize = 64;

/// Version prefix on the encoded payload. A future encoding can
/// ship under `"req2:"` without colliding with this one.
const PAYLOAD_PREFIX: &str = "req:";

const DECISION_ALLOW: &str = "allow";
const DECISION_DENY: &str = "deny";

/// One approval-button press intent. Outbound: the adapter encodes
/// one of these and writes the result to the platform's
/// callback-data slot. Inbound: the adapter decodes the platform's
/// callback-data slot back into this shape and forwards the
/// `request_id` to the gateway in an `ApprovalDecision` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPayload {
    /// Server-minted approval identifier. Matches the `request_id`
    /// field on the gateway's `ApprovalRequest` and
    /// `ApprovalDecision` IPC frames. Globally unique
    /// (`Uuid::new_v4()`), one-shot at resolution.
    pub request_id: String,
    /// Operator-pressed verdict.
    pub decision: Decision,
}

/// Operator verdict carried back on a button press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    /// String form on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => DECISION_ALLOW,
            Decision::Deny => DECISION_DENY,
        }
    }
}

/// Failure encoding an [`ApprovalPayload`] for an outbound button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// `request_id` was empty. The pending-approval queue mints
    /// non-empty UUIDs, so this only fires on a programmer error
    /// upstream.
    EmptyRequestId,
    /// `request_id` contains a `:`. Reserved for forward-compatible
    /// composite identifier formats; current callers must pass a
    /// canonical UUID.
    RequestIdContainsColon,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::EmptyRequestId => write!(f, "request_id is empty"),
            EncodeError::RequestIdContainsColon => {
                write!(f, "request_id must not contain ':' under this encoding")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Failure decoding an inbound platform callback-data string back
/// into an [`ApprovalPayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Payload did not start with [`PAYLOAD_PREFIX`]. Could be a
    /// version skew (a future encoding), a foreign callback the
    /// adapter received by mistake, or a corrupted payload.
    UnknownPrefix,
    /// Payload missing the decision separator (no second `:` after
    /// the prefix).
    MissingDecisionSeparator,
    /// `request_id` segment was empty between the prefix and the
    /// decision separator.
    EmptyRequestId,
    /// Decision token after the decision separator was not in
    /// [`DECISION_ALLOW`] / [`DECISION_DENY`].
    UnknownDecision(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnknownPrefix => {
                write!(f, "payload does not start with the expected version prefix")
            }
            DecodeError::MissingDecisionSeparator => {
                write!(f, "payload missing decision separator")
            }
            DecodeError::EmptyRequestId => write!(f, "request_id segment is empty"),
            DecodeError::UnknownDecision(s) => write!(f, "unknown decision token: {s:?}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode an [`ApprovalPayload`] into the cross-adapter wire form.
/// Outbound adapters write the result into their channel SDK's
/// button callback-data slot.
pub fn encode(payload: &ApprovalPayload) -> Result<String, EncodeError> {
    if payload.request_id.is_empty() {
        return Err(EncodeError::EmptyRequestId);
    }
    if payload.request_id.contains(':') {
        return Err(EncodeError::RequestIdContainsColon);
    }
    Ok(format!(
        "{PAYLOAD_PREFIX}{}:{}",
        payload.request_id,
        payload.decision.as_str()
    ))
}

/// Decode an inbound platform callback-data string into an
/// [`ApprovalPayload`]. Parses right-to-left at the trailing
/// decision separator so a future `request_id` format with internal
/// colons can extend the shape without re-parsing.
pub fn decode(data: &str) -> Result<ApprovalPayload, DecodeError> {
    let stripped = data
        .strip_prefix(PAYLOAD_PREFIX)
        .ok_or(DecodeError::UnknownPrefix)?;
    let (request_id, decision_token) = stripped
        .rsplit_once(':')
        .ok_or(DecodeError::MissingDecisionSeparator)?;
    if request_id.is_empty() {
        return Err(DecodeError::EmptyRequestId);
    }
    let decision = match decision_token {
        DECISION_ALLOW => Decision::Allow,
        DECISION_DENY => Decision::Deny,
        other => return Err(DecodeError::UnknownDecision(other.to_string())),
    };
    Ok(ApprovalPayload {
        request_id: request_id.to_string(),
        decision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid_fixture() -> String {
        // Canonical UUID-shaped string. Fixed value so byte-budget
        // assertions are stable across runs.
        "550e8400-e29b-41d4-a716-446655440000".to_string()
    }

    fn allow_payload() -> ApprovalPayload {
        ApprovalPayload {
            request_id: uuid_fixture(),
            decision: Decision::Allow,
        }
    }

    fn deny_payload() -> ApprovalPayload {
        ApprovalPayload {
            request_id: uuid_fixture(),
            decision: Decision::Deny,
        }
    }

    #[test]
    fn round_trip_allow() {
        let original = allow_payload();
        let encoded = encode(&original).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_deny() {
        let original = deny_payload();
        let encoded = encode(&original).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encoded_form_matches_telegram_reference_shape() {
        // Byte-for-byte identity with the existing Telegram
        // adapter's `req:<uuid>:allow|deny` form. If this diverges,
        // the Telegram retrofit slice will detect it; pinning here
        // catches it earlier.
        let encoded = encode(&allow_payload()).unwrap();
        assert_eq!(encoded, format!("req:{}:allow", uuid_fixture()));
        let encoded = encode(&deny_payload()).unwrap();
        assert_eq!(encoded, format!("req:{}:deny", uuid_fixture()));
    }

    #[test]
    fn encoded_length_fits_discord_custom_id_budget() {
        // With a canonical UUID request_id this is the worst-case
        // length under the current shape. If a future encoding
        // change pushes past 100 bytes, Discord adapter wiring
        // fails before merge.
        let encoded = encode(&allow_payload()).unwrap();
        assert!(
            encoded.len() <= DISCORD_CUSTOM_ID_MAX,
            "encoded length {} exceeds Discord cap {DISCORD_CUSTOM_ID_MAX}",
            encoded.len()
        );
        // 46 bytes by construction: "req:" + 36-char UUID + ":" + "allow".
        assert_eq!(encoded.len(), 46);
    }

    #[test]
    fn encoded_length_fits_every_channel_budget() {
        // Sanity over the full set of caps the shared module
        // exposes. Catches the case where a future cap is added
        // smaller than the current encoded form.
        let encoded = encode(&allow_payload()).unwrap();
        assert!(encoded.len() <= TELEGRAM_CALLBACK_DATA_MAX);
        assert!(encoded.len() <= DISCORD_CUSTOM_ID_MAX);
        assert!(encoded.len() <= SLACK_ACTION_ID_MAX);
    }

    #[test]
    fn cross_adapter_byte_identity() {
        // The encoding has no adapter input; verifying via
        // construction. Documented as a property so future
        // refactors that thread an adapter-context parameter
        // through `encode` are caught by this assertion.
        let from_telegram_caller = encode(&allow_payload()).unwrap();
        let from_discord_caller = encode(&allow_payload()).unwrap();
        let from_slack_caller = encode(&allow_payload()).unwrap();
        assert_eq!(from_telegram_caller, from_discord_caller);
        assert_eq!(from_discord_caller, from_slack_caller);
    }

    #[test]
    fn encode_rejects_empty_request_id() {
        let p = ApprovalPayload {
            request_id: String::new(),
            decision: Decision::Allow,
        };
        assert_eq!(encode(&p), Err(EncodeError::EmptyRequestId));
    }

    #[test]
    fn encode_rejects_colon_in_request_id() {
        let p = ApprovalPayload {
            request_id: "uuid:with:colons".into(),
            decision: Decision::Allow,
        };
        assert_eq!(encode(&p), Err(EncodeError::RequestIdContainsColon));
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        assert_eq!(
            decode(&format!("foo:{}:allow", uuid_fixture())),
            Err(DecodeError::UnknownPrefix)
        );
    }

    #[test]
    fn decode_rejects_future_version_prefix() {
        // A `req2:` payload from a future encoding round-trips to
        // UnknownPrefix today. The adapter drops it, which is the
        // right behaviour during a mixed-version button population.
        assert_eq!(
            decode(&format!("req2:{}:allow", uuid_fixture())),
            Err(DecodeError::UnknownPrefix)
        );
    }

    #[test]
    fn decode_rejects_missing_decision_separator() {
        assert_eq!(
            decode(&format!("req:{}", uuid_fixture())),
            Err(DecodeError::MissingDecisionSeparator)
        );
    }

    #[test]
    fn decode_rejects_empty_request_id() {
        assert_eq!(decode("req::allow"), Err(DecodeError::EmptyRequestId));
    }

    #[test]
    fn decode_rejects_unknown_decision_token() {
        assert_eq!(
            decode(&format!("req:{}:maybe", uuid_fixture())),
            Err(DecodeError::UnknownDecision("maybe".into()))
        );
    }

    #[test]
    fn decode_rejects_truncated_input() {
        // Empty string lacks the prefix.
        assert_eq!(decode(""), Err(DecodeError::UnknownPrefix));
        // Prefix-only: after stripping `req:` the remainder is
        // empty and contains no `:`, so the separator check fires
        // before the empty-request-id check.
        assert_eq!(decode("req:"), Err(DecodeError::MissingDecisionSeparator));
    }

    #[test]
    fn decode_uses_right_to_left_parse_for_decision_separator() {
        // Documented forward-compat rule: a future request_id format
        // with internal colons must still round-trip. Today's
        // canonical UUID has no colons, so this property is forced
        // by construction. Pinning the behaviour means a future
        // encoder that emits a colon-bearing request_id stays
        // decodable as long as it terminates with `:allow` or
        // `:deny`.
        let crafted = "req:future:composite:id:allow";
        let decoded = decode(crafted).unwrap();
        assert_eq!(decoded.request_id, "future:composite:id");
        assert_eq!(decoded.decision, Decision::Allow);
    }
}
