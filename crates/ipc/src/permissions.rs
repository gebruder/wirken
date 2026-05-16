//! Operator → gateway permissions-decide protocol.
//!
//! Distinct from the adapter ↔ gateway capnp transport and from the
//! hook ↔ gateway capnp transport. `wirken permissions pending
//! {list,show,approve,deny}` invocations connect to a dedicated
//! Unix socket and exchange one line-delimited JSON request and
//! response.
//!
//! ## This is not an adapter or a hook
//!
//! Adapters cross a trust boundary: third-party credentials,
//! attacker-influenced inbound text, Ed25519 handshake. Hooks cross
//! a trust boundary: external runtimes participating in tool-call
//! decisions, Ed25519 handshake.
//!
//! Operator-tool RPC does NOT cross a trust boundary. The CLI
//! subcommand process lives in the same data dir, runs under the
//! same UID, and reads the same vault as the gateway. SO_PEERCRED
//! plus 0600 file perms is the gate. Wire format is line-delimited
//! JSON; no capnp, no handshake, no signature. This precedent is
//! documented at `crates/ipc/src/orchestrator.rs`; permissions-IPC
//! matches it.

use serde::{Deserialize, Serialize};

/// One line from the CLI to the gateway. Tagged enum so future
/// operator-tool actions (e.g. `pending watch` streaming) extend
/// the request set without breaking single-shot consumers that
/// match on `kind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionsRequest {
    /// `wirken permissions pending list` — summary view of every
    /// in-flight `NeedsApproval` request.
    PendingList,
    /// `wirken permissions pending show <request_id>` — full
    /// `PermissionDenialContext` rendered including the trigger
    /// message.
    PendingShow { request_id: String },
    /// `wirken permissions pending approve <request_id>` — resume
    /// the agent task with `ApprovalOutcome::Approved`. `approved_by`
    /// is the OS username the CLI process detected (falls back to
    /// the literal `"cli"`); the gateway forwards it onto the
    /// audit-row's actor-label field.
    PendingApprove {
        request_id: String,
        approved_by: String,
    },
    /// `wirken permissions pending deny <request_id> [reason]` —
    /// resume the agent task with `ApprovalOutcome::Denied { reason }`.
    /// Operator-supplied reason surfaces to the LLM as the failed
    /// tool result's output and to the audit row's `denial_reason`.
    PendingDeny {
        request_id: String,
        denied_by: String,
        reason: Option<String>,
    },
}

/// One line back from the gateway to the CLI. Variants per request
/// kind; the CLI matches on `kind` and prints accordingly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionsResponse {
    /// Per-entry summary for `PendingList`. The CLI renders this as
    /// a table.
    PendingList { entries: Vec<PendingSummary> },
    /// Full context for `PendingShow`.
    PendingShow { entry: Option<PendingDetail> },
    /// Outcome of an `Approve` or `Deny` request. The CLI prints the
    /// result verbatim.
    Decision { result: DecisionResult },
    /// Protocol-level error: malformed request, gateway internal
    /// error. Distinct from `Decision { UnknownKey }` which is the
    /// queue saying "no such pending entry"; this variant is for
    /// failures BEFORE the queue was consulted.
    Error { message: String },
}

/// Compact per-entry shape for the list table. Omits the
/// `trigger_message` (which can be operator-supplied free text and
/// is potentially long); `PendingDetail` carries it for the show
/// path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSummary {
    pub request_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub requested_tier: String,
    /// RFC3339 timestamp the queue entry was minted.
    pub requested_at: String,
    /// Wall-clock seconds since the entry was minted, rendered by
    /// the gateway at response time. The CLI does not redo the
    /// arithmetic so a slow operator terminal does not produce
    /// drifting "age" values across re-runs.
    pub age_seconds: u64,
}

/// Full per-entry shape for the show path. Adds the trigger
/// message to the summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDetail {
    #[serde(flatten)]
    pub summary: PendingSummary,
    /// Inbound user message that triggered this tool call. Present
    /// when the agent loop captured one; `None` for system-driven
    /// or subagent-driven calls.
    pub trigger_message: Option<String>,
}

/// Per-decision outcome. `Accepted` means the queue accepted the
/// decision and the agent task was resumed; `UnknownKey` means the
/// request_id was never seen OR has already been resolved (by
/// another operator's decision, by a timeout, or by gateway
/// shutdown). The two cases are intentionally collapsed: the queue
/// does not keep a tombstone of resolved request_ids, so the
/// gateway cannot tell "never existed" from "already resolved"
/// without unbounded memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionResult {
    Accepted,
    UnknownKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_list_request_roundtrips() {
        let req = PermissionsRequest::PendingList;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"kind":"pending_list"}"#);
        let parsed: PermissionsRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(parsed, PermissionsRequest::PendingList));
    }

    #[test]
    fn pending_approve_request_roundtrips() {
        let req = PermissionsRequest::PendingApprove {
            request_id: "9b8f1c0a-1234-4abc-9def-0123456789ab".into(),
            approved_by: "davi".into(),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: PermissionsRequest = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsRequest::PendingApprove {
                request_id,
                approved_by,
            } => {
                assert_eq!(request_id, "9b8f1c0a-1234-4abc-9def-0123456789ab");
                assert_eq!(approved_by, "davi");
            }
            other => panic!("expected PendingApprove, got {other:?}"),
        }
    }

    #[test]
    fn pending_deny_request_with_reason_roundtrips() {
        let req = PermissionsRequest::PendingDeny {
            request_id: "9b8f1c0a-1234-4abc-9def-0123456789ab".into(),
            denied_by: "davi".into(),
            reason: Some("looks dangerous".into()),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: PermissionsRequest = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsRequest::PendingDeny { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("looks dangerous"));
            }
            other => panic!("expected PendingDeny, got {other:?}"),
        }
    }

    #[test]
    fn pending_deny_request_without_reason_roundtrips() {
        let req = PermissionsRequest::PendingDeny {
            request_id: "x".into(),
            denied_by: "davi".into(),
            reason: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: PermissionsRequest = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsRequest::PendingDeny { reason, .. } => {
                assert_eq!(reason, None);
            }
            other => panic!("expected PendingDeny, got {other:?}"),
        }
    }

    #[test]
    fn decision_response_roundtrips() {
        let resp = PermissionsResponse::Decision {
            result: DecisionResult::Accepted,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: PermissionsResponse = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsResponse::Decision { result } => {
                assert_eq!(result, DecisionResult::Accepted);
            }
            other => panic!("expected Decision, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_response_roundtrips() {
        let resp = PermissionsResponse::Decision {
            result: DecisionResult::UnknownKey,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: PermissionsResponse = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsResponse::Decision { result } => {
                assert_eq!(result, DecisionResult::UnknownKey);
            }
            other => panic!("expected Decision, got {other:?}"),
        }
    }

    #[test]
    fn list_response_carries_summaries() {
        let resp = PermissionsResponse::PendingList {
            entries: vec![PendingSummary {
                request_id: "abc".into(),
                agent_id: "default".into(),
                tool_name: "exec".into(),
                action_key: "shell:rm".into(),
                requested_tier: "tier3".into(),
                requested_at: "2026-05-16T10:20:30Z".into(),
                age_seconds: 12,
            }],
        };
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: PermissionsResponse = serde_json::from_str(&s).unwrap();
        match parsed {
            PermissionsResponse::PendingList { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].action_key, "shell:rm");
                assert_eq!(entries[0].age_seconds, 12);
            }
            other => panic!("expected PendingList, got {other:?}"),
        }
    }
}
