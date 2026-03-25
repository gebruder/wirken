use tempfile::TempDir;

use crate::adapter_registry::AdapterRegistry;
use crate::config::GatewayConfig;
use crate::permissions::{Action, PermissionCheck, PermissionStore, PermissionTier};
use crate::rate_limit::{AuthRateLimiter, ControlPlaneRateLimiter};
use crate::router::{RouteBinding, Router};
use crate::session::SessionStore;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn default_config_paths() {
    let config = GatewayConfig::default();
    assert!(config.vault_db_path().ends_with("vault.db"));
    assert!(config.audit_db_path().ends_with("audit.db"));
    assert!(config.sessions_db_path().ends_with("sessions.db"));
    assert!(config.permissions_db_path().ends_with("permissions.db"));
    assert_eq!(config.session_expiry_secs, 86400);
    assert_eq!(config.audit_retention_days, 90);
}

// ---------------------------------------------------------------------------
// Adapter Registry
// ---------------------------------------------------------------------------

#[test]
fn register_and_lookup_adapter() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    let pk = [42u8; 32];
    reg.register("telegram", &pk, "telegram").unwrap();

    let entry = reg.get("telegram").unwrap();
    assert_eq!(entry.adapter_id, "telegram");
    assert_eq!(entry.public_key, pk);
    assert_eq!(entry.channel, "telegram");
    assert!(!entry.connected);
}

#[test]
fn register_duplicate_fails() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    let pk = [1u8; 32];
    reg.register("telegram", &pk, "telegram").unwrap();

    let result = reg.register("telegram", &pk, "telegram");
    assert!(result.is_err());
}

#[test]
fn unregister_adapter() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    reg.register("discord", &[2u8; 32], "discord").unwrap();
    reg.unregister("discord").unwrap();

    assert!(reg.get("discord").is_none());
}

#[test]
fn verify_adapter_correct_key() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    let pk = [99u8; 32];
    reg.register("slack", &pk, "slack").unwrap();

    assert!(reg.verify("slack", &pk).is_ok());
}

#[test]
fn verify_adapter_wrong_key() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    let pk = [99u8; 32];
    let wrong = [88u8; 32];
    reg.register("slack", &pk, "slack").unwrap();

    assert!(reg.verify("slack", &wrong).is_err());
}

#[test]
fn verify_unknown_adapter() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    assert!(reg.verify("nonexistent", &[0u8; 32]).is_err());
}

#[test]
fn adapter_connected_state() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    reg.register("telegram", &[1u8; 32], "telegram").unwrap();
    assert!(!reg.get("telegram").unwrap().connected);

    reg.set_connected("telegram", true);
    assert!(reg.get("telegram").unwrap().connected);

    reg.set_connected("telegram", false);
    assert!(!reg.get("telegram").unwrap().connected);
}

#[test]
fn list_adapters() {
    let tmp = TempDir::new().unwrap();
    let reg = AdapterRegistry::open(&tmp.path().join("adapters.db")).unwrap();

    reg.register("telegram", &[1u8; 32], "telegram").unwrap();
    reg.register("discord", &[2u8; 32], "discord").unwrap();

    let list = reg.list();
    assert_eq!(list.len(), 2);
}

#[test]
fn registry_persists_across_opens() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("adapters.db");

    {
        let reg = AdapterRegistry::open(&db_path).unwrap();
        reg.register("telegram", &[1u8; 32], "telegram").unwrap();
    }

    let reg = AdapterRegistry::open(&db_path).unwrap();
    assert!(reg.get("telegram").is_some());
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[test]
fn create_session() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let session = store.get_or_create("telegram", "chat-123").unwrap();
    assert_eq!(session.channel, "telegram");
    assert_eq!(session.conversation_id, "chat-123");
    assert_eq!(session.message_count, 0);
    assert!(!session.expired);
}

#[test]
fn get_existing_session() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let s1 = store.get_or_create("telegram", "chat-123").unwrap();
    let s2 = store.get_or_create("telegram", "chat-123").unwrap();

    // Same session returned
    assert_eq!(s1.id, s2.id);
}

#[test]
fn different_conversations_get_different_sessions() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let s1 = store.get_or_create("telegram", "chat-1").unwrap();
    let s2 = store.get_or_create("telegram", "chat-2").unwrap();

    assert_ne!(s1.id, s2.id);
}

#[test]
fn record_message_increments_count() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let session = store.get_or_create("telegram", "chat-1").unwrap();
    store.record_message(&session.id).unwrap();
    store.record_message(&session.id).unwrap();
    store.record_message(&session.id).unwrap();

    let updated = store.get(&session.id).unwrap();
    assert_eq!(updated.message_count, 3);
}

#[test]
fn close_session() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let session = store.get_or_create("telegram", "chat-1").unwrap();
    store.close(&session.id).unwrap();

    let closed = store.get(&session.id).unwrap();
    assert!(closed.expired);

    // get_or_create should create a new session now
    let new_session = store.get_or_create("telegram", "chat-1").unwrap();
    assert_ne!(new_session.id, session.id);
}

#[test]
fn session_expires_by_inactivity() {
    let tmp = TempDir::new().unwrap();
    // 1 second expiry
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 1).unwrap();

    let s1 = store.get_or_create("telegram", "chat-1").unwrap();
    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let s2 = store.get_or_create("telegram", "chat-1").unwrap();

    assert_ne!(s1.id, s2.id);
}

#[test]
fn list_active_sessions() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    store.get_or_create("telegram", "chat-1").unwrap();
    store.get_or_create("telegram", "chat-2").unwrap();
    store.get_or_create("discord", "guild-1").unwrap();

    let all = store.list_active(None).unwrap();
    assert_eq!(all.len(), 3);

    let tg = store.list_active(Some("telegram")).unwrap();
    assert_eq!(tg.len(), 2);

    let dc = store.list_active(Some("discord")).unwrap();
    assert_eq!(dc.len(), 1);
}

#[test]
fn expire_inactive_sessions() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 1).unwrap();

    store.get_or_create("telegram", "chat-1").unwrap();
    store.get_or_create("telegram", "chat-2").unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let expired = store.expire_inactive().unwrap();
    assert_eq!(expired, 2);

    let active = store.list_active(None).unwrap();
    assert_eq!(active.len(), 0);
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[test]
fn tier1_always_allowed() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let check = perms.check(&Action::WorkspaceFileAccess, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::Allowed);

    let check = perms.check(&Action::WebSearch, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::Allowed);
}

#[test]
fn tier2_needs_approval_first_time() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec { pattern: "git *".into() };
    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::NeedsApproval { tier: PermissionTier::Tier2 });
}

#[test]
fn tier2_allowed_after_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec { pattern: "git *".into() };
    perms.approve(&action, "agent-1", "telegram").unwrap();

    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::Allowed);
}

#[test]
fn tier2_approval_scoped_to_agent() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec { pattern: "git *".into() };
    perms.approve(&action, "agent-1", "telegram").unwrap();

    // Different agent — not approved
    let check = perms.check(&action, "agent-2").unwrap();
    assert_eq!(check, PermissionCheck::NeedsApproval { tier: PermissionTier::Tier2 });
}

#[test]
fn tier3_always_needs_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let check = perms.check(&Action::CredentialAccess, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::NeedsApproval { tier: PermissionTier::Tier3 });

    let check = perms.check(&Action::DestructiveFileOp, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::NeedsApproval { tier: PermissionTier::Tier3 });
}

#[test]
fn revoke_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec { pattern: "npm *".into() };
    perms.approve(&action, "agent-1", "slack").unwrap();

    perms.revoke(&action.approval_key(), "agent-1").unwrap();

    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::NeedsApproval { tier: PermissionTier::Tier2 });
}

#[test]
fn list_approvals() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    perms.approve(&Action::ShellExec { pattern: "git *".into() }, "agent-1", "tg").unwrap();
    perms.approve(&Action::ShellExec { pattern: "npm *".into() }, "agent-1", "tg").unwrap();
    perms.approve(&Action::ExternalFileAccess { path: "/tmp/*".into() }, "agent-1", "dc").unwrap();

    let approvals = perms.list("agent-1").unwrap();
    assert_eq!(approvals.len(), 3);
}

// ---------------------------------------------------------------------------
// Rate Limiting
// ---------------------------------------------------------------------------

#[test]
fn auth_rate_limit_allows_under_threshold() {
    let rl = AuthRateLimiter::new(5, 60, 600);

    // 4 failures — still under limit
    for _ in 0..4 {
        assert!(rl.record_failure("127.0.0.1").is_ok());
    }

    assert!(!rl.is_locked("127.0.0.1"));
}

#[test]
fn auth_rate_limit_locks_at_threshold() {
    let rl = AuthRateLimiter::new(5, 60, 600);

    // 5 failures — locked
    for _ in 0..4 {
        rl.record_failure("127.0.0.1").unwrap();
    }
    let result = rl.record_failure("127.0.0.1");
    assert!(result.is_err());
    assert!(rl.is_locked("127.0.0.1"));
}

#[test]
fn auth_rate_limit_no_loopback_exemption() {
    // This is the critical test: 127.0.0.1 is NOT exempt
    let rl = AuthRateLimiter::new(3, 60, 600);

    rl.record_failure("127.0.0.1").unwrap();
    rl.record_failure("127.0.0.1").unwrap();
    let result = rl.record_failure("127.0.0.1");
    assert!(result.is_err());
    assert!(rl.is_locked("127.0.0.1"));
}

#[test]
fn auth_rate_limit_different_sources_independent() {
    let rl = AuthRateLimiter::new(3, 60, 600);

    rl.record_failure("192.168.1.1").unwrap();
    rl.record_failure("192.168.1.1").unwrap();
    let _ = rl.record_failure("192.168.1.1"); // locked

    // Different source — not affected
    assert!(rl.record_failure("192.168.1.2").is_ok());
    assert!(!rl.is_locked("192.168.1.2"));
}

#[test]
fn auth_rate_limit_success_clears() {
    let rl = AuthRateLimiter::new(5, 60, 600);

    rl.record_failure("10.0.0.1").unwrap();
    rl.record_failure("10.0.0.1").unwrap();
    rl.record_success("10.0.0.1");

    // Counter reset — can fail again
    for _ in 0..4 {
        assert!(rl.record_failure("10.0.0.1").is_ok());
    }
}

#[test]
fn control_plane_rate_limit() {
    let rl = ControlPlaneRateLimiter::new(10);

    // First request should be allowed
    assert!(rl.check().is_ok());
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

#[test]
fn route_exact_match() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "chat-123".into(),
        agent_id: "agent-personal".into(),
    });

    let agent = router.resolve("telegram", "chat-123").unwrap();
    assert_eq!(agent, "agent-personal");
}

#[test]
fn route_wildcard_match() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-default".into(),
    });

    let agent = router.resolve("telegram", "any-chat").unwrap();
    assert_eq!(agent, "agent-default");
}

#[test]
fn route_exact_takes_priority_over_wildcard() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-default".into(),
    });
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "vip-chat".into(),
        agent_id: "agent-vip".into(),
    });

    assert_eq!(router.resolve("telegram", "vip-chat").unwrap(), "agent-vip");
    assert_eq!(router.resolve("telegram", "other-chat").unwrap(), "agent-default");
}

#[test]
fn route_no_match() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-1".into(),
    });

    let result = router.resolve("discord", "some-guild");
    assert!(result.is_err());
}

#[test]
fn unbind_channel() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-1".into(),
    });
    router.bind(RouteBinding {
        channel: "discord".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-2".into(),
    });

    router.unbind_channel("telegram");

    assert!(router.resolve("telegram", "any").is_err());
    assert!(router.resolve("discord", "any").is_ok());
}

#[test]
fn list_bindings() {
    let router = Router::new();
    router.bind(RouteBinding {
        channel: "telegram".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-1".into(),
    });
    router.bind(RouteBinding {
        channel: "discord".into(),
        conversation_pattern: "*".into(),
        agent_id: "agent-2".into(),
    });

    assert_eq!(router.list_bindings().len(), 2);
}
