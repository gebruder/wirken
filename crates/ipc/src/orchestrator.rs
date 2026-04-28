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
//! UID, and reads the same vault. SO_PEERCRED + 0600 file perms is
//! the gate. Wire format is line-delimited JSON; no capnp, no
//! handshake, no signature.

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorPushResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
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
    fn response_skips_error_when_ok() {
        let resp = OrchestratorPushResponse {
            ok: true,
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert_eq!(s, r#"{"ok":true}"#);
    }

    #[test]
    fn response_includes_error_when_failed() {
        let resp = OrchestratorPushResponse {
            ok: false,
            error: Some("no adapter connected on channel 'signal'".into()),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: OrchestratorPushResponse = serde_json::from_str(&s).unwrap();
        assert!(!parsed.ok);
        assert_eq!(
            parsed.error.unwrap(),
            "no adapter connected on channel 'signal'"
        );
    }
}
