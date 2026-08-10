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

// `get_or_create` moves `last_activity` on every call and deliberately
// leaves `message_count` alone, so a caller that resolves the session
// without also calling `record_message` reports a live conversation as
// `0 msg` forever. Webchat did exactly that. Pinned here so the split
// stays a decision rather than a surprise for the next call site.
#[test]
fn get_or_create_advances_activity_without_counting() {
    let tmp = TempDir::new().unwrap();
    let store = SessionStore::open(&tmp.path().join("sessions.db"), 86400).unwrap();

    let first = store.get_or_create("webchat", "webchat-default").unwrap();
    for _ in 0..3 {
        store.get_or_create("webchat", "webchat-default").unwrap();
    }

    let resolved = store.get(&first.id).unwrap();
    assert_eq!(
        resolved.message_count, 0,
        "get_or_create must not count messages"
    );
    assert!(
        resolved.last_activity >= first.last_activity,
        "get_or_create must advance last_activity"
    );

    // The pairing every inbound path owes the counter.
    let session = store.get_or_create("webchat", "webchat-default").unwrap();
    store.record_message(&session.id).unwrap();
    assert_eq!(store.get(&first.id).unwrap().message_count, 1);
}

// `expired = 0` only means nothing has marked the row dead yet, and
// nothing sweeps in the background: `expire_inactive` has no caller
// outside tests. Listing therefore has to apply the age bound itself,
// or it reports sessions as active that `get_or_create` would refuse to
// resume.
#[test]
fn list_active_hides_sessions_past_the_expiry_window() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("sessions.db");

    let live = SessionStore::open(&path, 86400).unwrap();
    let session = live.get_or_create("webchat", "webchat-default").unwrap();
    assert_eq!(live.list_active(None).unwrap().len(), 1);
    assert_eq!(live.list_active(Some("webchat")).unwrap().len(), 1);
    drop(live);

    // Same row, zero-length window, so it is past expiry.
    let stale = SessionStore::open(&path, 0).unwrap();
    assert!(stale.list_active(None).unwrap().is_empty());
    assert!(stale.list_active(Some("webchat")).unwrap().is_empty());

    // Filtering does not write. The flag is still clear, so
    // `expire_inactive` and `get_or_create` remain the only paths that
    // set it and a later widening of the window would list it again.
    assert!(!stale.get(&session.id).unwrap().expired);
    assert_eq!(stale.expire_inactive().unwrap(), 1);
    assert!(stale.get(&session.id).unwrap().expired);
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

    let check = perms
        .check(&Action::WorkspaceFileAccess, "agent-1")
        .unwrap();
    assert_eq!(check, PermissionCheck::Allowed);

    let check = perms.check(&Action::WebSearch, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::Allowed);
}

#[test]
fn tier2_needs_approval_first_time() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    // `ls` is on the Tier 2 allowlist; first use needs approval.
    let action = Action::ShellExec {
        pattern: "ls".into(),
    };
    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(
        check,
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier2
        }
    );
}

#[test]
fn tier2_allowed_after_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec {
        pattern: "ls".into(),
    };
    perms.approve(&action, "agent-1", "telegram").unwrap();

    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(check, PermissionCheck::Allowed);
}

#[test]
fn tier2_approval_scoped_to_agent() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec {
        pattern: "ls".into(),
    };
    perms.approve(&action, "agent-1", "telegram").unwrap();

    // Different agent — not approved
    let check = perms.check(&action, "agent-2").unwrap();
    assert_eq!(
        check,
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier2
        }
    );
}

#[test]
fn shell_exec_uppercase_variants_are_tier3() {
    for variant in ["CURL", "Curl", "cURL", "SuDo", "GIT", "DOCKER"] {
        let action = Action::ShellExec {
            pattern: variant.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "case variant {variant} must not bypass Tier 3"
        );
    }
}

#[test]
fn shell_exec_path_qualified_high_risk_is_tier3() {
    for variant in [
        "/usr/bin/curl",
        "./curl",
        "../tools/curl",
        "/opt/bin/SuDo",
        "/usr/local/bin/docker",
    ] {
        let action = Action::ShellExec {
            pattern: variant.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "path-qualified form {variant} must not bypass Tier 3"
        );
    }
}

#[test]
fn shell_wrappers_are_tier3() {
    for wrapper in [
        "sh", "bash", "dash", "zsh", "env", "xargs", "nohup", "timeout", "nice", "ionice",
        "setsid", "stdbuf",
    ] {
        let action = Action::ShellExec {
            pattern: wrapper.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "shell/process wrapper {wrapper} must be Tier 3 so it cannot launder an inner verb"
        );
    }
}

#[test]
fn allowlisted_verbs_are_tier2() {
    for verb in [
        "ls", "cat", "head", "tail", "grep", "diff", "cmp", "stat", "file", "wc", "tree",
        "readlink", "realpath", "basename", "dirname", "pwd", "whoami", "id", "uname", "hostname",
        "date", "echo", "printf", "which", "type",
    ] {
        let action = Action::ShellExec {
            pattern: verb.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier2,
            "allowlisted verb {verb} must be Tier 2"
        );
    }
}

#[test]
fn interpreters_with_eval_flags_are_tier3() {
    // Language interpreters with -c / -e / BEGIN{} can launder any
    // inner command. They must fall to Tier 3 so each invocation
    // prompts rather than getting a blanket 30-day approval.
    for interp in [
        "python", "python3", "node", "perl", "ruby", "lua", "deno", "awk", "sed",
    ] {
        let action = Action::ShellExec {
            pattern: interp.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "interpreter {interp} must be Tier 3"
        );
    }
}

#[test]
fn exec_hatch_looking_tools_are_tier3() {
    // Tools that look inspection-only but have an exec flag at arms
    // length. rg --pre runs a preprocessor; find -exec runs a
    // command; sort --compress-program runs a filter; less / more /
    // man shell out via `!` and $PAGER. All Tier 3.
    for verb in ["rg", "ag", "find", "sort", "less", "more", "man"] {
        let action = Action::ShellExec {
            pattern: verb.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "verb with known exec hatch {verb} must be Tier 3"
        );
    }
}

#[test]
fn network_and_vcs_verbs_are_tier3() {
    // Carried over from the old denylist: network-egress, remote
    // shells, cluster mutations, privilege elevation, file
    // transfer, version control. All excluded from the allowlist
    // by absence.
    for verb in [
        "curl", "wget", "scp", "sftp", "ssh", "kubectl", "helm", "docker", "podman", "sudo", "su",
        "doas", "nc", "ncat", "socat", "git",
    ] {
        let action = Action::ShellExec {
            pattern: verb.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "{verb} must be Tier 3"
        );
    }
}

#[test]
fn unknown_verbs_default_tier3() {
    // Any verb not on the allowlist is Tier 3 by default. This is
    // the shape change: previous model was "unknown -> Tier 2";
    // new model is "unknown -> Tier 3".
    for verb in [
        "make",
        "cargo",
        "rustc",
        "go",
        "docker-compose",
        "aws",
        "gcloud",
        "my-custom-tool",
    ] {
        let action = Action::ShellExec {
            pattern: verb.into(),
        };
        assert_eq!(
            action.tier(),
            PermissionTier::Tier3,
            "unknown verb {verb} must default to Tier 3"
        );
    }
}

#[test]
fn approval_key_normalizes_pattern_across_forms() {
    for pattern in ["curl", "CURL", "/usr/bin/curl", "./curl", "  curl  "] {
        let key = Action::ShellExec {
            pattern: pattern.into(),
        }
        .approval_key();
        assert_eq!(
            key, "shell:curl",
            "variant {pattern} must canonicalize to shell:curl"
        );
    }
}

#[test]
fn tier3_always_needs_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let check = perms.check(&Action::CredentialAccess, "agent-1").unwrap();
    assert_eq!(
        check,
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier3
        }
    );

    let check = perms.check(&Action::DestructiveFileOp, "agent-1").unwrap();
    assert_eq!(
        check,
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier3
        }
    );
}

#[test]
fn revoke_approval() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    let action = Action::ShellExec {
        pattern: "cat".into(),
    };
    perms.approve(&action, "agent-1", "slack").unwrap();

    perms.revoke(&action.approval_key(), "agent-1").unwrap();

    let check = perms.check(&action, "agent-1").unwrap();
    assert_eq!(
        check,
        PermissionCheck::NeedsApproval {
            tier: PermissionTier::Tier2
        }
    );
}

#[test]
fn list_approvals() {
    let tmp = TempDir::new().unwrap();
    let perms = PermissionStore::open(&tmp.path().join("perms.db")).unwrap();

    perms
        .approve(
            &Action::ShellExec {
                pattern: "ls".into(),
            },
            "agent-1",
            "tg",
        )
        .unwrap();
    perms
        .approve(
            &Action::ShellExec {
                pattern: "grep".into(),
            },
            "agent-1",
            "tg",
        )
        .unwrap();
    perms
        .approve(
            &Action::ExternalFileAccess {
                path: "/tmp/*".into(),
            },
            "agent-1",
            "dc",
        )
        .unwrap();

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
    assert_eq!(
        router.resolve("telegram", "other-chat").unwrap(),
        "agent-default"
    );
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
