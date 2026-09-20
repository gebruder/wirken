//! A session-scoped grant stops working when its session closes,
//! without restarting the process that cached it.
//!
//! The grant lived in `PermissionStore`'s in-memory cache. Closing a
//! session from the CLI marked the store row expired and wrote a
//! tombstone the next `wake` replays, and neither reached the running
//! daemon: the cached entry went on answering `Allowed` until the
//! process restarted. An operator who revoked a grant by closing its
//! session had not revoked it.
//!
//! What is assembled here is what the daemon assembles: a session
//! store, a permission store, and the liveness predicate between
//! them. `run.rs` builds the same predicate over its own read
//! connection.

use std::sync::{Arc, Mutex};

use wirken_gateway::permissions::{
    Action, ApprovalScope, PermissionCheck, PermissionStore, PermissionTier,
};
use wirken_gateway::session::SessionStore;

const AGENT: &str = "default";
const CHANNEL: &str = "webchat";
const CONVERSATION: &str = "c-0123456789ab";

fn composite() -> String {
    format!("{AGENT}/{CHANNEL}/{CONVERSATION}")
}

/// The predicate `run.rs` installs, over the same store.
fn liveness(store: Arc<Mutex<SessionStore>>) -> Arc<dyn Fn(&str) -> bool + Send + Sync> {
    Arc::new(move |session_id: &str| {
        let mut parts = session_id.splitn(3, '/');
        let (Some(_agent), Some(channel), Some(conversation)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return true;
        };
        match store.lock() {
            Ok(s) => s.is_live(channel, conversation),
            Err(_) => true,
        }
    })
}

struct Fixture {
    _tmp: tempfile::TempDir,
    sessions: Arc<Mutex<SessionStore>>,
    permissions: PermissionStore,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let sessions = Arc::new(Mutex::new(
        SessionStore::open(&tmp.path().join("sessions.db"), 86_400).expect("session store"),
    ));
    // The session exists and is live, as it would be after the first
    // message on the conversation.
    sessions
        .lock()
        .unwrap()
        .get_or_create(CHANNEL, CONVERSATION)
        .expect("session row");

    let mut permissions =
        PermissionStore::open(&tmp.path().join("permissions.db")).expect("permission store");
    permissions.set_session_liveness(liveness(sessions.clone()));
    Fixture {
        _tmp: tmp,
        sessions,
        permissions,
    }
}

fn ls() -> Action {
    Action::ShellExec {
        pattern: "ls".to_string(),
    }
}

/// Grant, then close the session the way `wirken sessions close`
/// does, and the very next check refuses. No restart, no eviction
/// call, nothing else touched.
#[test]
fn a_grant_stops_working_when_its_session_closes() {
    let f = fixture();
    let session = composite();

    f.permissions
        .approve_with_scope(
            &ls(),
            AGENT,
            "davi",
            ApprovalScope::Session {
                session_id: session.clone(),
            },
        )
        .expect("session-scoped grant");

    assert_eq!(
        f.permissions
            .check(&ls(), &session, Some(AGENT))
            .expect("check runs"),
        PermissionCheck::Allowed,
        "the grant covers the action while the session is live"
    );

    // What the CLI does: mark the store row expired.
    let store_id = {
        let s = f.sessions.lock().unwrap();
        s.get_or_create(CHANNEL, CONVERSATION).expect("row").id
    };
    f.sessions
        .lock()
        .unwrap()
        .close(&store_id)
        .expect("close the session");

    assert_eq!(
        f.permissions
            .check(&ls(), &session, Some(AGENT))
            .expect("check runs"),
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier2,
            lapsed_at: None,
        },
        "a closed session's grant no longer answers"
    );
}

/// The dead entry is dropped rather than left to be re-tested. A
/// second check after the session is gone finds nothing in the cache,
/// which is what keeps the liveness query off the hot path once it
/// has answered.
#[test]
fn the_dead_entry_is_dropped_on_the_first_miss() {
    let f = fixture();
    let session = composite();

    f.permissions
        .approve_with_scope(
            &ls(),
            AGENT,
            "davi",
            ApprovalScope::Session {
                session_id: session.clone(),
            },
        )
        .expect("session-scoped grant");

    let store_id = {
        let s = f.sessions.lock().unwrap();
        s.get_or_create(CHANNEL, CONVERSATION).expect("row").id
    };
    f.sessions.lock().unwrap().close(&store_id).expect("closed");

    let _ = f.permissions.check(&ls(), &session, Some(AGENT));
    assert_eq!(
        f.permissions.clear_session_scope(&session),
        0,
        "the entry was already dropped by the first miss"
    );
}

/// A live session is unaffected: the gate consults liveness, it does
/// not distrust the cache.
#[test]
fn a_live_session_still_answers_from_the_cache() {
    let f = fixture();
    let session = composite();

    f.permissions
        .approve_with_scope(
            &ls(),
            AGENT,
            "davi",
            ApprovalScope::Session {
                session_id: session.clone(),
            },
        )
        .expect("session-scoped grant");

    for _ in 0..3 {
        assert_eq!(
            f.permissions
                .check(&ls(), &session, Some(AGENT))
                .expect("check runs"),
            PermissionCheck::Allowed
        );
    }
    assert_eq!(
        f.permissions.clear_session_scope(&session),
        1,
        "the entry is still cached"
    );
}

/// With no predicate installed every session reads as live, which is
/// the shape a CLI invocation or a test has. The cache does not
/// survive the process there, so there is nothing for it to be wrong
/// about.
#[test]
fn without_a_predicate_the_cache_answers_as_before() {
    let tmp = tempfile::tempdir().unwrap();
    let permissions =
        PermissionStore::open(&tmp.path().join("permissions.db")).expect("permission store");
    let session = composite();
    permissions
        .approve_with_scope(
            &ls(),
            AGENT,
            "davi",
            ApprovalScope::Session {
                session_id: session.clone(),
            },
        )
        .expect("session-scoped grant");
    assert_eq!(
        permissions
            .check(&ls(), &session, Some(AGENT))
            .expect("check runs"),
        PermissionCheck::Allowed
    );
}
