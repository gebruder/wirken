//! A grant or revoke an operator makes from the CLI is on the signed
//! audit chain.
//!
//! The permission store is the only production writer of persisted
//! grants, and its DELETE leaves nothing behind, so the chain is the
//! only place a decision survives. These rows go to the
//! `gateway-permissions` lane rather than an agent session, because a
//! grant made out of band of any conversation belongs to none.
//!
//! What runs here is the gateway-side composition the CLI commands
//! are a thin shell over: the same store, emitters, lane and signer.
//! The commands themselves call `config()`, a process global with no
//! injectable path, so their argument wiring is the part this does
//! not reach.

use std::sync::Arc;

use wirken_audit::{
    AuditSigningKey, ChainHeadReason, SessionEvent, SessionId, SessionLog, SqliteSessionLog,
};
use wirken_gateway::permissions::{
    ApprovalScope, OPERATOR_PERMISSIONS_SESSION, PermissionStore,
    approve_and_log_by_key_with_expiry, emit_permission_revoked,
};

struct Fixture {
    _tmp: tempfile::TempDir,
    log: Arc<SqliteSessionLog>,
    store: PermissionStore,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Arc::new(AuditSigningKey::load_or_create(tmp.path()).expect("signing key"));
    let log = Arc::new(
        SqliteSessionLog::open_with_signer(&tmp.path().join("audit.db"), signer)
            .expect("signed session log"),
    );
    let store = PermissionStore::open(&tmp.path().join("permissions.db")).expect("store");
    Fixture {
        _tmp: tmp,
        log,
        store,
    }
}

fn lane(log: &SqliteSessionLog) -> wirken_audit::SessionHandle<wirken_audit::OwnSession> {
    log.handle_for(SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()))
}

fn rows(log: &SqliteSessionLog) -> Vec<SessionEvent> {
    log.get_since(&lane(log), 0)
        .expect("read the operator lane")
        .into_iter()
        .map(|r| r.event)
        .collect()
}

/// The grant is on the lane, names key, tier, scope, window and the
/// operator, and the chain it landed on verifies under its head.
#[test]
fn an_operator_grant_lands_on_the_lane_and_verifies() {
    let f = fixture();
    let handle = lane(f.log.as_ref());

    let approval = approve_and_log_by_key_with_expiry(
        &f.store,
        "shell:ls",
        "default",
        "davi",
        ApprovalScope::Persisted,
        f.log.as_ref(),
        &handle,
        None,
        None,
        Some(7),
    )
    .expect("the grant is written and recorded");
    f.log
        .emit_chain_head(&handle, ChainHeadReason::SessionEnd)
        .expect("seal the lane");

    let found = rows(f.log.as_ref())
        .into_iter()
        .find_map(|e| match e {
            SessionEvent::PermissionApproved {
                action_key,
                agent_id,
                approved_by,
                scope,
                tier,
                expires_at,
                ..
            } => Some((action_key, agent_id, approved_by, scope, tier, expires_at)),
            _ => None,
        })
        .expect("the approval is on the chain");
    let (key, agent, by, scope, tier, expires) = found;
    assert_eq!(key, "shell:ls", "the row names the key");
    assert_eq!(agent, "default");
    assert_eq!(by, "davi", "the row names the local operator");
    assert_eq!(scope, wirken_audit::ApprovalScopeKind::Persisted);
    assert_eq!(tier.as_deref(), Some("tier2"), "the row names the tier");
    assert_eq!(expires, Some(approval.expires_at), "and the window");

    assert!(
        matches!(
            f.log.verify(&handle).expect("verify runs"),
            wirken_audit::SessionVerifyResult::Ok { .. }
        ),
        "the chain is intact"
    );
    let sigs = f.log.verify_signatures(&handle).expect("signatures verify");
    assert!(sigs.signed_heads_count >= 1, "a head covers it: {sigs:?}");
    assert_eq!(
        sigs.matched_heads_count, sigs.signed_heads_count,
        "every head verifies: {sigs:?}"
    );
    assert_eq!(sigs.unsigned_tail_len, 0, "nothing left unsigned");
}

/// The store keeps nothing after a revoke, so the row is the only
/// record, and it names the window that was cut short.
#[test]
fn an_operator_revoke_records_the_window_it_cut_short() {
    let f = fixture();
    let handle = lane(f.log.as_ref());
    let approval = f
        .store
        .approve_by_key("shell:cat", "default", "davi")
        .expect("granted");

    let removed = f
        .store
        .revoke_reporting("shell:cat", "default")
        .expect("revoke runs");
    assert_eq!(removed, Some(approval.expires_at), "the window is reported");

    emit_permission_revoked(
        f.log.as_ref(),
        &handle,
        "shell:cat",
        "default",
        "davi",
        removed,
    )
    .expect("recorded");
    f.log
        .emit_chain_head(&handle, ChainHeadReason::SessionEnd)
        .expect("seal the lane");

    let found = rows(f.log.as_ref())
        .into_iter()
        .find_map(|e| match e {
            SessionEvent::PermissionRevoked {
                action_key,
                revoked_by,
                tier,
                expires_at,
                ..
            } => Some((action_key, revoked_by, tier, expires_at)),
            _ => None,
        })
        .expect("the revoke is on the chain");
    let (key, by, tier, expires) = found;
    assert_eq!(key, "shell:cat");
    assert_eq!(by, "davi");
    assert_eq!(tier.as_deref(), Some("tier2"));
    assert_eq!(expires, Some(approval.expires_at));

    assert!(matches!(
        f.log.verify(&handle).expect("verify runs"),
        wirken_audit::SessionVerifyResult::Ok { .. }
    ));
    let sigs = f.log.verify_signatures(&handle).expect("signatures verify");
    assert_eq!(sigs.matched_heads_count, sigs.signed_heads_count);
    assert_eq!(sigs.unsigned_tail_len, 0);
}

/// Revoking a key that was never granted is recorded too: the store
/// answers the same either way, so the chain is the only place the
/// difference survives.
#[test]
fn revoking_a_key_that_was_never_granted_is_still_recorded() {
    let f = fixture();
    let handle = lane(f.log.as_ref());

    let removed = f
        .store
        .revoke_reporting("shell:head", "default")
        .expect("revoke runs");
    assert_eq!(removed, None, "there was no row to remove");

    emit_permission_revoked(
        f.log.as_ref(),
        &handle,
        "shell:head",
        "default",
        "davi",
        removed,
    )
    .expect("recorded anyway");

    assert!(
        rows(f.log.as_ref()).iter().any(|e| matches!(
            e,
            SessionEvent::PermissionRevoked { expires_at: None, action_key, .. }
                if action_key == "shell:head"
        )),
        "a revoke against an ungranted key is on the chain with no window"
    );
}
