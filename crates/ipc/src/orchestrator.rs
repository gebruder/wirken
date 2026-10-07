//! Orchestrator → gateway push-message protocol.
//!
//! Distinct from the adapter ↔ gateway capnp transport. Orchestrators
//! (e.g. `wirken-zirkel`) running locally as the same UID that owns
//! the gateway data dir send outbound text through this socket. The
//! gateway forwards each push to the live adapter writer for the
//! named channel using the existing capnp `Outbound` frame.
//!
//! ## This is not an adapter
//!
//! Adapters cross a trust boundary: they hold third-party
//! credentials, they're the funnel for attacker-controlled inbound
//! text, and they authenticate over Ed25519. An orchestrator pushing
//! a digest to the operator's own thread is not crossing a trust
//! boundary — it lives in the same data dir, runs under the same
//! UID, and reads the same vault. SO_PEERCRED + 0600 file perms admit
//! the connection, then the operator handshake (`crate::operator`):
//! the push is signed with the operator key, so it is recorded against
//! that key and a same-UID process without it is refused. No capnp;
//! line-delimited JSON after the handshake.

use serde::{Deserialize, Serialize};

/// How long the gateway waits for an adapter's delivery result before
/// answering a push with [`DeliveryStatus::Unknown`].
pub const DELIVERY_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorPushRequest {
    pub channel: String,
    pub conversation_id: String,
    pub text: String,
    /// Empty string means "no thread root" — root-level message in
    /// the channel. Mirrors the capnp `Outbound.reply_to_id`
    /// semantic (adapters have always treated an empty string as
    /// "no parent").
    #[serde(default)]
    pub reply_to_id: String,
}

/// The gateway's answer to one push.
///
/// `ok: false` with `error` when the gateway did not hand the frame to
/// an adapter at all. `ok: true` with `delivery` once it did: what the
/// adapter reported back for that frame, or `Unknown` when no report
/// came within the gateway's wait.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorPushResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delivery: Option<DeliveryStatus>,
}

impl OrchestratorPushResponse {
    /// The gateway did not hand the frame to an adapter.
    pub fn rejected(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            delivery: None,
        }
    }

    /// The gateway handed the frame to the adapter, and this is what
    /// came back for it.
    pub fn handed_off(delivery: DeliveryStatus) -> Self {
        Self {
            ok: true,
            error: None,
            delivery: Some(delivery),
        }
    }
}

/// What the platform did with a pushed frame, as its adapter reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// The platform accepted the message and assigned it this id.
    Delivered { message_id: String },
    /// The platform refused the message; `error` is the adapter's
    /// reason.
    Failed { error: String },
    /// The adapter took the frame and reported nothing back in time.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips() {
        let req = OrchestratorPushRequest {
            channel: "signal".into(),
            conversation_id: "+15551234567".into(),
            text: "Daily digest:\n- A\n- B".into(),
            reply_to_id: "".into(),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: OrchestratorPushRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.channel, "signal");
        assert_eq!(parsed.conversation_id, "+15551234567");
        assert_eq!(parsed.text, "Daily digest:\n- A\n- B");
        assert_eq!(parsed.reply_to_id, "");
    }

    #[test]
    fn request_reply_to_id_defaults_to_empty_when_missing() {
        let s = r#"{"channel":"signal","conversation_id":"+15551234567","text":"hi"}"#;
        let req: OrchestratorPushRequest = serde_json::from_str(s).unwrap();
        assert_eq!(req.reply_to_id, "");
    }

    #[test]
    fn response_skips_error_when_handed_off() {
        let resp = OrchestratorPushResponse::handed_off(DeliveryStatus::Delivered {
            message_id: "1789645555.016219".into(),
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            s,
            r#"{"ok":true,"delivery":{"status":"delivered","message_id":"1789645555.016219"}}"#
        );
    }

    #[test]
    fn delivery_status_round_trips() {
        for status in [
            DeliveryStatus::Delivered {
                message_id: "m".into(),
            },
            DeliveryStatus::Failed {
                error: "channel_not_found".into(),
            },
            DeliveryStatus::Unknown,
        ] {
            let s = serde_json::to_string(&OrchestratorPushResponse::handed_off(status.clone()))
                .unwrap();
            let parsed: OrchestratorPushResponse = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed.delivery, Some(status));
        }
    }

    #[test]
    fn response_includes_error_when_failed() {
        let resp = OrchestratorPushResponse::rejected("no adapter connected on channel 'signal'");
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: OrchestratorPushResponse = serde_json::from_str(&s).unwrap();
        assert!(!parsed.ok);
        assert_eq!(
            parsed.error.unwrap(),
            "no adapter connected on channel 'signal'"
        );
    }
}
