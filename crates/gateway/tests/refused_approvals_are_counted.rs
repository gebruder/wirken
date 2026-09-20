//! An approval attempt that fails the authority check leaves a row.
//!
//! Three sites refuse on authority: a caller who is not on the
//! channel's approver list, a page deciding a request raised on
//! another channel, and one deciding a request from another
//! conversation. All three used to leave a warn-level log and nothing
//! on the chain, so a detection could not count attempts. Attempts
//! are the interesting number: one is a misconfigured client, a run
//! of them from one caller is not.
//!
//! The refusal itself is unchanged and is not what this covers. What
//! is covered is that the attempt is recorded, beside the request it
//! was aimed at, with enough on the row to group by caller.

use std::sync::Arc;

use wirken_audit::{
    ApprovalRefusalReason, AuditSigningKey, ChainHeadReason, SessionEvent, SessionId, SessionLog,
    SqliteSessionLog,
};
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingRequest};
use wirken_gateway::permissions::{OPERATOR_PERMISSIONS_SESSION, emit_approval_refused};

const SESSION: &str = "default/webchat/c-0123456789ab";

struct Fixture {
    _tmp: tempfile::TempDir,
    log: Arc<SqliteSessionLog>,
    queue: PendingApprovalQueue,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Arc::new(AuditSigningKey::load_or_create(tmp.path()).expect("signing key"));
    let log = Arc::new(
        SqliteSessionLog::open_with_signer(&tmp.path().join("audit.db"), signer)
            .expect("signed session log"),
    );
    Fixture {
        _tmp: tmp,
        log,
        queue: PendingApprovalQueue::new(),
    }
}

fn pending(queue: &PendingApprovalQueue) -> String {
    let (id, _rx) = queue.register(PendingRequest {
        agent_id: SESSION.to_string(),
        tool_name: "exec".to_string(),
        action_key: "shell:ls".to_string(),
        requested_tier: "tier2".to_string(),
        trigger_message: Some("roll staging back".to_string()),
        assistant_text: None,
    });
    id
}

fn rows(log: &SqliteSessionLog, session: &str) -> Vec<SessionEvent> {
    let handle = log.handle_for(SessionId::new(session.to_string()));
    log.get_since(&handle, 0)
        .expect("read the session")
        .into_iter()
        .map(|r| r.event)
        .collect()
}

/// The row lands on the session that raised the request, names the
/// key, the caller and the reason, and is covered by a chain head.
#[test]
fn a_refused_attempt_lands_beside_the_request_it_targeted() {
    let f = fixture();
    let request_id = pending(&f.queue);

    emit_approval_refused(
        f.log.as_ref(),
        &f.queue,
        &request_id,
        "telegram:99887766",
        ApprovalRefusalReason::UnauthorizedActor,
        Some("telegram"),
    );
    let handle = f.log.handle_for(SessionId::new(SESSION.to_string()));
    f.log
        .emit_chain_head(&handle, ChainHeadReason::SessionEnd)
        .expect("seal");

    let found = rows(f.log.as_ref(), SESSION)
        .into_iter()
        .find_map(|e| match e {
            SessionEvent::PermissionApprovalRefused {
                request_id,
                action_key,
                caller,
                reason,
                adapter_id,
            } => Some((request_id, action_key, caller, reason, adapter_id)),
            _ => None,
        })
        .expect("the refusal is on the chain");
    let (rid, key, caller, reason, adapter) = found;
    assert_eq!(rid, request_id, "the row names the request");
    assert_eq!(
        key.as_deref(),
        Some("shell:ls"),
        "and the action it was raised for"
    );
    assert_eq!(caller, "telegram:99887766", "and who tried");
    assert_eq!(reason, ApprovalRefusalReason::UnauthorizedActor);
    assert_eq!(adapter.as_deref(), Some("telegram"));

    let sigs = f
        .log
        .verify_signatures(&handle)
        .expect("signature verification runs");
    assert_eq!(sigs.matched_heads_count, sigs.signed_heads_count);
    assert_eq!(sigs.unsigned_tail_len, 0, "the row is covered by a head");
}

/// A request id that matches nothing has no session to attribute the
/// attempt to, so it goes to the operator lane with no action key.
/// This is the enumeration case and it must not be dropped for
/// lacking a home.
#[test]
fn an_attempt_against_an_unknown_request_still_lands() {
    let f = fixture();

    emit_approval_refused(
        f.log.as_ref(),
        &f.queue,
        "no-such-request",
        "telegram:99887766",
        ApprovalRefusalReason::UnauthorizedActor,
        Some("telegram"),
    );

    let found = rows(f.log.as_ref(), OPERATOR_PERMISSIONS_SESSION)
        .into_iter()
        .find_map(|e| match e {
            SessionEvent::PermissionApprovalRefused {
                request_id,
                action_key,
                ..
            } => Some((request_id, action_key)),
            _ => None,
        })
        .expect("the refusal is on the operator lane");
    assert_eq!(found.0, "no-such-request");
    assert_eq!(found.1, None, "there is no action key to name");
}

/// The three reasons stay distinct on the wire, because a run of
/// unauthorized-actor attempts means something different from a run
/// of approvers reaching outside what they may decide.
#[test]
fn the_three_reasons_are_distinct_on_the_wire() {
    let f = fixture();
    for reason in [
        ApprovalRefusalReason::UnauthorizedActor,
        ApprovalRefusalReason::WrongChannel,
        ApprovalRefusalReason::WrongConversation,
    ] {
        let id = pending(&f.queue);
        emit_approval_refused(f.log.as_ref(), &f.queue, &id, "caller", reason, None);
    }

    let seen: Vec<ApprovalRefusalReason> = rows(f.log.as_ref(), SESSION)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::PermissionApprovalRefused { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen,
        vec![
            ApprovalRefusalReason::UnauthorizedActor,
            ApprovalRefusalReason::WrongChannel,
            ApprovalRefusalReason::WrongConversation,
        ]
    );

    let wire: Vec<String> = seen
        .iter()
        .map(|r| {
            serde_json::to_value(r)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        wire,
        vec!["unauthorized_actor", "wrong_channel", "wrong_conversation"],
        "a detection selects on these strings"
    );
}
