//! `AgentFactory` — the only public way to construct an [`Agent`]
//! after item 2 slice 2.
//!
//! The factory holds per-agent static configuration (workspace,
//! LLM config, API key, skills, MCP client, permissions) plus a
//! shared session log. Inbound messages are routed by the gateway
//! to `factory.wake(agent_id, session_id)`, which returns an
//! `Arc<Mutex<Agent>>` whose conversation has been reconstructed
//! from the session log via [`Agent::from_session_log`].
//!
//! ## Per-conversation isolation
//!
//! The session id format is `{agent_id}/{channel}/{conversation_id}`.
//! [`session_id_for`] is the canonical helper. Two channels routed
//! to the same agent get separate sessions and separate conversation
//! state — slice 2 fixes the slice 1 / pre-slice-1 bug where multi-
//! channel agents mashed all conversations into one history.
//!
//! ## Cache contract
//!
//! An LRU cache (default 64 entries) keyed by session id holds the
//! `Arc<Mutex<Agent>>` for hot sessions. The cache is a pure
//! optimization: cache-hit and cache-miss MUST produce identical
//! session log output. The `WIRKEN_CACHE_MODE=drop` env var bypasses
//! the cache for the entire factory lifetime; the CI test uses it
//! to assert behavioral equivalence.
//!
//! ## Concurrency
//!
//! The cache uses double-checked locking. Construction (replay from
//! the session log) happens outside the cache mutex so other threads
//! waking different sessions are not blocked. Two threads racing on
//! the same session id may both construct, but only one inserts —
//! the second discards its build and returns the cached entry.
//! Subsequent callers serialize through the inner `Mutex<Agent>` on
//! the cached entry, which is the existing single-writer guarantee.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, Weak};

use lru::LruCache;
use tokio::sync::Mutex as AsyncMutex;
use wirken_audit::{ApprovalScopeKind, SessionEvent, SessionId, SessionLog};
use wirken_gateway::agent_config::SubagentCeiling;
use wirken_gateway::org::OrgPermissions;
use wirken_gateway::permissions::{
    PermissionStore, SESSION_CLEAR_REASON_ENDED, emit_session_scoped_approvals_cleared,
};

use crate::error::AgentError;
use crate::llm::LlmConfig;
use crate::mcp::McpProxyClient;
use crate::runtime::Agent;
use crate::skill::Skill;
use crate::wasm_sandbox::WasmSkill;

/// Default LRU capacity. 64 hot sessions per process — covers
/// chatty Slack DM bots and most expected workloads. Override with
/// `WIRKEN_AGENT_CACHE_SIZE`.
const DEFAULT_CACHE_CAPACITY: usize = 64;

/// Build the canonical session id for `(agent_id, channel,
/// conversation_id)`. Format is human-readable for debugging:
/// `{agent_id}/{channel}/{conversation_id}`. None of the supported
/// channel conversation_ids contain `/`, so collisions are not a
/// concern in practice. Reserved sentinels `__system__` and
/// `__pre_migration__` from item 1 slice 2 are unaffected — they
/// don't go through this helper.
pub fn session_id_for(agent_id: &str, channel: &str, conversation_id: &str) -> String {
    format!("{agent_id}/{channel}/{conversation_id}")
}

/// Extract the channel segment from a canonical session id built by
/// [`session_id_for`]. Returns `None` for reserved sentinel ids
/// (`__system__`, `__pre_migration__`) and any id that does not
/// contain at least two `/` separators. Callers that need channel
/// routing should treat `None` as "fall back to the agent's default
/// `llm_config`" — the per-channel override is skipped.
pub(crate) fn channel_from_session_id(session_id: &str) -> Option<&str> {
    let mut parts = session_id.splitn(3, '/');
    let _agent = parts.next()?;
    let channel = parts.next()?;
    // A well-formed session id always has a conversation_id too;
    // require the third part so `{agent}/` prefix-only ids don't
    // accidentally match.
    parts.next()?;
    Some(channel)
}

/// Paired LLM config + API key selected for a specific channel. A
/// provider and its credential are always chosen together, so the
/// factory treats them as one record rather than two parallel maps
/// that can drift out of sync.
///
/// In-memory this struct carries the raw key, matching the default
/// `AgentStaticConfig::api_key` pattern. On-disk config files should
/// instead name a vault slot (`"provider-api-key"` etc.) and let
/// startup resolve the slot to the key material before constructing
/// the `AgentStaticConfig`.
#[derive(Clone, Debug)]
pub struct ChannelOverride {
    pub llm_config: LlmConfig,
    pub api_key: Option<String>,
    /// Vault entry name that resolved to `api_key`. Carried alongside
    /// the secret so the waked Agent can stamp it on every
    /// `LlmRequest` / `LlmResponse` for SIEM correlation. `None` for
    /// overrides whose `api_key` came from a path that doesn't surface
    /// a slot name (raw value, env override).
    pub api_key_credential: Option<String>,
}

/// Per-agent static configuration held by the factory and injected
/// into every waked Agent.
pub struct AgentStaticConfig {
    pub agent_id: String,
    pub workspace: PathBuf,
    pub llm_config: LlmConfig,
    /// Optional per-channel (LLM config + API key) override
    /// (closes #60). When the waked session id names a channel
    /// with an entry in this map, the factory builds the Agent
    /// with that override's provider and credential instead of
    /// the defaults. Missing channels fall through to the
    /// agent-wide defaults. Empty map = no overrides, same as
    /// pre-#60 behavior.
    #[doc(alias = "per-channel-provider")]
    pub channel_overrides: HashMap<String, ChannelOverride>,
    pub api_key: Option<String>,
    /// Vault entry name that resolved to `api_key`. See
    /// [`ChannelOverride::api_key_credential`]; same role at the
    /// agent-wide-default level.
    pub api_key_credential: Option<String>,
    pub skills: Vec<Skill>,
    pub wasm_skills: Vec<WasmSkill>,
    /// Long-lived MCP proxy connection shared across every waked
    /// Agent for this agent_id. Concurrent waked Agents serialize
    /// through this Mutex on each MCP call. The contention is
    /// bounded by MCP call latency which already dwarfs lock
    /// acquisition; per-wake fresh MCP connections are a future
    /// optimization if profiling shows it.
    pub mcp_client: Option<Arc<AsyncMutex<McpProxyClient>>>,
    /// Optional Ed25519 signing identity for session attestation.
    /// Item 8 slice 2: when set, the harness loop auto-signs the
    /// chain head after every turn that crosses the trigger
    /// threshold. The factory clones this into every waked Agent.
    pub identity: Option<crate::identity::AgentIdentity>,
    /// Item 6 slice 1: child agents this agent may spawn via the
    /// built-in `spawn_subagent` tool, with per-child capability
    /// ceilings. Empty by default. The factory injects a clone into
    /// every waked Agent so the harness can read the ceiling
    /// without re-querying the gateway config store.
    pub allowed_subagents: BTreeMap<String, SubagentCeiling>,
    /// Sandbox configuration for shell exec. Defaults to
    /// `SandboxMode::ExecOnly`. Operators override via
    /// `provider.json` (or per-agent config in a future pass). The
    /// factory clones this into every waked Agent's `ToolRegistry`.
    pub sandbox: crate::sandbox::SandboxConfig,
    /// Additional [`InboundInterceptor`]s registered on every waked
    /// Agent for this agent_id, in registration order, after the
    /// built-in slash interceptor. The Arc is shared across wakes —
    /// interceptors hold their own internal state (SQLite handle,
    /// etc.) and are `Send + Sync`. Empty by default; the gateway's
    /// startup wire-up populates this from `wirken_zirkel`'s
    /// bindings table when zirkel is configured.
    ///
    /// [`InboundInterceptor`]: crate::inbound_interceptor::InboundInterceptor
    pub extra_interceptors: Vec<Arc<dyn crate::inbound_interceptor::InboundInterceptor>>,
    /// Path to the zirkel aggregator SQLite database, configured for
    /// agents that carry the librarian skill. The factory calls
    /// [`crate::runtime::Agent::attach_zirkel_db`] on every waked
    /// Agent when this is `Some`. None disables the `sqlite_query`
    /// tool for the agent (the tool returns a clear error if invoked
    /// without the path bound).
    pub zirkel_db_path: Option<PathBuf>,
}

/// Cache mode resolved at factory construction time. Tests pass it
/// explicitly; production code reads `WIRKEN_CACHE_MODE` via
/// [`CacheMode::from_env`] and forwards the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Standard production mode: LRU cache active.
    Cached,
    /// Drop mode: bypass the cache, wake on every call. Used by the
    /// CI test that asserts behavioral equivalence between cached
    /// and uncached operation. Set via `WIRKEN_CACHE_MODE=drop` in
    /// production; passed directly in tests to avoid env-var leakage
    /// across parallel tests.
    Drop,
}

impl CacheMode {
    pub fn from_env() -> Self {
        match std::env::var("WIRKEN_CACHE_MODE").as_deref() {
            Ok("drop") => Self::Drop,
            _ => Self::Cached,
        }
    }
}

/// The agent factory.
pub struct AgentFactory {
    static_configs: HashMap<String, AgentStaticConfig>,
    session_log: Arc<dyn SessionLog>,
    permissions: Option<Arc<StdMutex<PermissionStore>>>,
    /// Org-level tool allow/deny policy, applied before the per-tier
    /// permission check. Shared across every waked Agent because org
    /// policy is a gateway-wide setting, not a per-agent one.
    org_permissions: Option<Arc<OrgPermissions>>,
    cache: StdMutex<LruCache<String, Arc<AsyncMutex<Agent>>>>,
    cache_mode: CacheMode,
    /// `Weak<Self>` of this very factory, captured at construction
    /// via [`Arc::new_cyclic`]. Item 6 slice 1: the harness uses
    /// this to re-enter the factory from inside `spawn_subagent`
    /// without leaking the strong Arc into every waked Agent (which
    /// would form an unbreakable cycle through the LRU cache).
    self_weak: Weak<AgentFactory>,
}

impl AgentFactory {
    /// Create a new factory with the given static configs and
    /// session log, in cached mode with the default capacity.
    /// Convenience for tests and the common production path; the
    /// CLI uses [`Self::with_options`] to wire up `WIRKEN_CACHE_MODE`
    /// and `WIRKEN_AGENT_CACHE_SIZE`.
    pub fn new(
        static_configs: HashMap<String, AgentStaticConfig>,
        session_log: Arc<dyn SessionLog>,
        permissions: Option<Arc<StdMutex<PermissionStore>>>,
    ) -> Arc<Self> {
        Self::with_options(
            static_configs,
            session_log,
            permissions,
            None,
            CacheMode::Cached,
            DEFAULT_CACHE_CAPACITY,
        )
    }

    /// Construct with explicit cache mode and capacity. The CLI
    /// reads the env vars (`WIRKEN_CACHE_MODE`,
    /// `WIRKEN_AGENT_CACHE_SIZE`) and forwards them. Tests pass the
    /// mode directly so parallel test runs don't fight over env
    /// state.
    ///
    /// Returns `Arc<Self>` so [`Arc::new_cyclic`] can capture a
    /// `Weak<Self>` reference for the spawn_subagent re-entry path.
    pub fn with_options(
        static_configs: HashMap<String, AgentStaticConfig>,
        session_log: Arc<dyn SessionLog>,
        permissions: Option<Arc<StdMutex<PermissionStore>>>,
        org_permissions: Option<Arc<OrgPermissions>>,
        cache_mode: CacheMode,
        cache_capacity: usize,
    ) -> Arc<Self> {
        if cache_mode == CacheMode::Drop {
            tracing::info!("AgentFactory: cache disabled (drop mode)");
        }
        let capacity = NonZeroUsize::new(cache_capacity)
            .unwrap_or_else(|| NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).unwrap());
        Arc::new_cyclic(|weak| Self {
            static_configs,
            session_log,
            permissions,
            org_permissions,
            cache: StdMutex::new(LruCache::new(capacity)),
            cache_mode,
            self_weak: weak.clone(),
        })
    }

    /// A `Weak<Self>` reference to this factory. Used internally by
    /// `wake` to inject the back-pointer into newly constructed
    /// Agents so they can re-enter the factory from
    /// `spawn_subagent`.
    pub(crate) fn weak(&self) -> Weak<AgentFactory> {
        self.self_weak.clone()
    }

    /// List the agent ids known to this factory.
    pub fn known_agent_ids(&self) -> Vec<String> {
        self.static_configs.keys().cloned().collect()
    }

    /// Whether this factory has a static config for `agent_id`.
    pub fn has_agent(&self, agent_id: &str) -> bool {
        self.static_configs.contains_key(agent_id)
    }

    /// Wake the agent that owns `session_id`. Returns the cached
    /// `Arc<Mutex<Agent>>` if present (cache mode), or a fresh Agent
    /// reconstructed by replaying the session log (cache miss or
    /// drop mode).
    ///
    /// `agent_id` must be a known static config; otherwise returns
    /// `AgentError::ToolNotFound` (slightly abusive but the closest
    /// existing variant; a dedicated `UnknownAgent` would be a
    /// future cleanup).
    pub fn wake(
        &self,
        agent_id: &str,
        session_id: &str,
    ) -> Result<Arc<AsyncMutex<Agent>>, AgentError> {
        // Cache lookup (cached mode only).
        if self.cache_mode == CacheMode::Cached
            && let Some(cached) = self.cache.lock().unwrap().get(session_id).cloned()
        {
            return Ok(cached);
        }

        // Build a fresh Agent for this session id.
        let cfg = self
            .static_configs
            .get(agent_id)
            .ok_or_else(|| AgentError::ToolNotFound(format!("unknown agent_id '{agent_id}'")))?;

        // #60: per-channel LLM override. Extract the channel segment
        // from the session id and pick the matching entry from
        // `channel_overrides` — an override carries both the
        // `LlmConfig` and the `api_key` so the agent ends up with
        // the credential that matches the provider it will call.
        // Any non-conforming session id (system sentinels,
        // unit-test short ids) falls back to the defaults.
        let override_for_channel =
            channel_from_session_id(session_id).and_then(|ch| cfg.channel_overrides.get(ch));
        let (llm_config, api_key, api_key_credential) = match override_for_channel {
            Some(ov) => (
                ov.llm_config.clone(),
                ov.api_key.clone(),
                ov.api_key_credential.clone(),
            ),
            None => (
                cfg.llm_config.clone(),
                cfg.api_key.clone(),
                cfg.api_key_credential.clone(),
            ),
        };

        let mut agent = Agent::from_session_log(
            session_id.to_string(),
            cfg.workspace.clone(),
            llm_config,
            api_key,
            api_key_credential,
            self.session_log.clone(),
            cfg.sandbox.clone(),
        )?;
        // Inject the per-agent shared resources.
        agent.attach_skills(cfg.skills.clone(), cfg.wasm_skills.clone())?;
        if let Some(perms) = &self.permissions {
            agent.set_permissions(perms.clone());
            // Replay session-scoped approval events for this
            // session id so a wake-after-crash re-establishes any
            // grants the operator made before the crash. Persisted
            // approvals are not touched: SQLite is their source of
            // truth and PermissionStore::open already loads them.
            // Best-effort: a read failure logs and continues with an
            // empty cache (deny-by-default is the conservative
            // failure mode and matches `heal_partial_tool_rounds`'s
            // recovery posture).
            if let Err(err) = replay_session_scoped_approvals(perms, &self.session_log, session_id)
            {
                tracing::warn!(
                    session_id,
                    error = %err,
                    "factory: failed to replay session-scoped approvals; cache starts empty"
                );
            }
        }
        // Slice 4 of the per-pass deny overlay: replay PhaseEntered /
        // PhaseExited events to re-establish any active phase
        // overlay across the wake. Runs AFTER `attach_skills` so the
        // base `PhasedEffective` is in place: `attach_skills` resets
        // the overlay slot, so the replay's `set_overlay` is the
        // last write. Best-effort: a read failure logs and continues
        // with no overlay, matching the deny-by-default posture of
        // the session-scoped approval replay above.
        if let Err(err) = replay_phase_overlay(&mut agent, &self.session_log, session_id) {
            tracing::warn!(
                session_id,
                error = %err,
                "factory: failed to replay phase overlay; agent starts with no active phase"
            );
        }
        if let Some(org) = &self.org_permissions {
            agent.set_org_permissions(org.clone());
        }
        if let Some(mcp) = &cfg.mcp_client {
            agent.attach_mcp(mcp.clone());
        }
        if let Some(identity) = &cfg.identity {
            agent.attach_identity(identity.clone());
        }
        // Item 6 slice 1: hand the freshly built Agent its own
        // factory back-pointer plus the per-agent subagent ceilings
        // so the spawn_subagent intercept inside the harness loop
        // can validate and dispatch a child without re-querying
        // the gateway config store.
        agent.attach_factory(self.weak());
        agent.attach_subagent_ceilings(cfg.allowed_subagents.clone());
        for interceptor in &cfg.extra_interceptors {
            agent.attach_interceptor(interceptor.clone());
        }
        if let Some(path) = &cfg.zirkel_db_path {
            agent.attach_zirkel_db(path.clone());
        }

        let arc = Arc::new(AsyncMutex::new(agent));

        // Insert into cache (cached mode only). Double-checked: if
        // another thread inserted between our lookup and now, return
        // theirs and discard ours.
        if self.cache_mode == CacheMode::Cached {
            let mut cache = self.cache.lock().unwrap();
            if let Some(existing) = cache.get(session_id).cloned() {
                return Ok(existing);
            }
            cache.put(session_id.to_string(), arc.clone());
        }

        Ok(arc)
    }

    /// Drop a session from the cache. Used by callers that know the
    /// session is finished (e.g., after a `wirken sessions close`).
    /// No-op in drop mode.
    ///
    /// Also clears any session-scoped approvals held under
    /// `session_id` and appends a `SessionScopedApprovalsCleared`
    /// audit event when at least one approval was cleared. Audit
    /// emission failures are logged and swallowed: the in-memory
    /// clear has already happened, so a missed audit row is a
    /// reconciliation issue, not a correctness one (the cache is
    /// gone with the process anyway). No emit when count is zero,
    /// matching the rest of the audit surface's "no noise for
    /// no-op" pattern.
    pub fn evict(&self, session_id: &str) {
        if self.cache_mode == CacheMode::Cached {
            self.cache.lock().unwrap().pop(session_id);
        }

        if let Some(perms) = &self.permissions {
            let cleared = {
                let store = match perms.lock() {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::warn!(
                            session_id,
                            error = %err,
                            "factory.evict: permission store poisoned; skipping session-scope clear"
                        );
                        return;
                    }
                };
                store.clear_session_scope(session_id)
            };

            if cleared > 0
                && let Err(err) = emit_session_scoped_approvals_cleared(
                    self.session_log.as_ref(),
                    session_id,
                    cleared,
                    SESSION_CLEAR_REASON_ENDED,
                )
            {
                tracing::warn!(
                    session_id,
                    cleared,
                    error = %err,
                    "factory.evict: failed to append SessionScopedApprovalsCleared; in-memory clear already applied"
                );
            }
        }
    }
}

/// Walk the session log for `session_id` and re-apply any
/// session-scoped approval lifecycle events to the perm-store
/// cache. Insertion order matches the log's `seq` order, so a
/// `SessionScopedApprovalsCleared` followed by a fresh
/// `PermissionApproved` correctly re-establishes the later grant
/// (the user's "clear wins iff no further grants" semantics fall
/// out of last-event-wins replay).
///
/// `PermissionApproved` with `scope == Persisted` is intentionally a
/// no-op here: SQLite is the source of truth for persisted
/// approvals, and `PermissionStore::open` has already loaded them.
/// Variants other than the two permission-lifecycle ones are
/// ignored; this pass is concerned with the cache only.
fn replay_session_scoped_approvals(
    perms: &Arc<StdMutex<PermissionStore>>,
    log: &Arc<dyn SessionLog>,
    session_id: &str,
) -> Result<(), wirken_audit::AuditError> {
    let handle = log.handle_for(SessionId::new(session_id.to_string()));
    let events = log.get_since(&handle, 0)?;
    let store = perms
        .lock()
        .expect("factory: permission store poisoned during replay");
    for stored in events {
        match stored.event {
            SessionEvent::PermissionApproved {
                action_key,
                agent_id,
                approved_by,
                scope: ApprovalScopeKind::Session,
                session_id: Some(sid),
            } => {
                store.restore_session_scoped_approval(
                    action_key,
                    agent_id,
                    approved_by,
                    sid,
                    stored.ts,
                );
            }
            SessionEvent::SessionScopedApprovalsCleared {
                session_id: sid, ..
            } => {
                store.clear_session_scope(&sid);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Walk the session log for `session_id` and re-apply the
/// PhaseEntered / PhaseExited lifecycle events to the agent's
/// effective permissions, last-event-wins. Mirrors
/// `replay_session_scoped_approvals` in shape but targets the
/// per-pass deny overlay added in slices 1-3.
///
/// Semantics:
/// - `PhaseEntered` reconstructs a [`PhaseDenyOverlay`] from the
///   wire-shape [`wirken_audit::PhaseDenyContent`] on the event and
///   makes it the current overlay. Multiple `PhaseEntered` events
///   without an intervening `PhaseExited` (a corrupted-log shape
///   the live path's `AlreadyActive` guard normally prevents) are
///   tolerated defensively: the latest one wins.
/// - `PhaseExited` clears the current overlay. An orphan
///   `PhaseExited` (no preceding `PhaseEntered`) is a no-op.
/// - The reason on `PhaseExited` is intentionally ignored at
///   replay: `TurnEnd`, `PhaseChange`, and `SkillUnloaded` all
///   produce the same "no active phase" terminal state.
///
/// Variants other than the two phase-lifecycle ones are ignored;
/// this pass is concerned with the overlay only. Runs AFTER
/// [`Agent::attach_skills`] because attach_skills resets the overlay
/// slot to None; the replay's final write wins.
fn replay_phase_overlay(
    agent: &mut Agent,
    log: &Arc<dyn SessionLog>,
    session_id: &str,
) -> Result<(), wirken_audit::AuditError> {
    let handle = log.handle_for(SessionId::new(session_id.to_string()));
    let events = log.get_since(&handle, 0)?;
    let mut current: Option<crate::skill_perms::PhaseDenyOverlay> = None;
    for stored in events {
        match stored.event {
            SessionEvent::PhaseEntered {
                skill_id,
                phase_name,
                denied,
            } => {
                current = Some(crate::skill_perms::PhaseDenyOverlay {
                    skill_id,
                    phase_name,
                    entered_at: stored.ts,
                    tools: denied.tools.into_iter().collect(),
                    egress_hosts: denied.egress_hosts.into_iter().collect(),
                    paths_read: denied.paths_read.into_iter().map(PathBuf::from).collect(),
                    paths_write: denied.paths_write.into_iter().map(PathBuf::from).collect(),
                    inference_providers: denied.inference_providers.into_iter().collect(),
                });
            }
            SessionEvent::PhaseExited { .. } => {
                current = None;
            }
            _ => {}
        }
    }
    if let Some(overlay) = current {
        agent.restore_phase_overlay(overlay);
    }
    Ok(())
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use wirken_audit::{SqliteSessionLog, TrustLevel};
    use wirken_gateway::permissions::{Action, PermissionCheck, PermissionStore, PermissionTier};

    fn make_store() -> Arc<StdMutex<PermissionStore>> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Leak the tempfile path: each test owns a fresh one in
        // process-wide /tmp, dropped on test process exit. The
        // NamedTempFile guard would otherwise drop the DB the
        // moment this helper returns. The leak is bounded to the
        // test process; no shipping code path is affected.
        let path = tmp.into_temp_path();
        let perm_path = path.keep().unwrap();
        Arc::new(StdMutex::new(PermissionStore::open(&perm_path).unwrap()))
    }

    fn make_log() -> Arc<dyn SessionLog> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.into_temp_path();
        let audit_path = path.keep().unwrap();
        Arc::new(SqliteSessionLog::open(&audit_path).unwrap()) as Arc<dyn SessionLog>
    }

    fn shell_ls() -> Action {
        Action::ShellExec {
            pattern: "ls".to_string(),
        }
    }

    fn shell_cat() -> Action {
        Action::ShellExec {
            pattern: "cat".to_string(),
        }
    }

    /// Append a synthetic PermissionApproved(Session) event for
    /// `action_key` under `session_id`. Mirrors what slice 4's CLI
    /// surface will emit through `approve_and_log`; the test path
    /// fakes the emission to keep the replay assertion focused.
    fn append_session_grant(
        log: &Arc<dyn SessionLog>,
        session_id: &str,
        action_key: &str,
        agent_id: &str,
    ) {
        let handle = log.handle_for(SessionId::new(session_id.to_string()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: action_key.to_string(),
                agent_id: agent_id.to_string(),
                approved_by: "operator".to_string(),
                scope: ApprovalScopeKind::Session,
                session_id: Some(session_id.to_string()),
            },
        )
        .unwrap();
    }

    fn append_session_clear(log: &Arc<dyn SessionLog>, session_id: &str, count: u32) {
        let handle = log.handle_for(SessionId::new(session_id.to_string()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::SessionScopedApprovalsCleared {
                session_id: session_id.to_string(),
                count,
                reason: SESSION_CLEAR_REASON_ENDED.to_string(),
            },
        )
        .unwrap();
    }

    #[test]
    fn replay_reconstructs_cache_from_permission_approved_session() {
        let perms = make_store();
        let log = make_log();
        let session = "default/webchat/conv-1";

        append_session_grant(&log, session, "shell:ls", "default");
        append_session_grant(&log, session, "shell:cat", "default");

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        let store = perms.lock().unwrap();
        assert_eq!(
            store.check(&shell_ls(), session).unwrap(),
            PermissionCheck::Allowed,
        );
        assert_eq!(
            store.check(&shell_cat(), session).unwrap(),
            PermissionCheck::Allowed,
        );
    }

    #[test]
    fn replay_respects_session_scoped_approvals_cleared_tombstone() {
        // grant + clear → cache empty on wake. Mirrors the clean
        // session-end path: evict cleared the cache and emitted the
        // tombstone; a later wake on the same session id must not
        // re-establish the grants from the earlier PermissionApproved
        // rows that survived in the log.
        let perms = make_store();
        let log = make_log();
        let session = "default/webchat/conv-2";

        append_session_grant(&log, session, "shell:ls", "default");
        append_session_clear(&log, session, 1);

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        let store = perms.lock().unwrap();
        assert_eq!(
            store.check(&shell_ls(), session).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
            },
        );
    }

    #[test]
    fn replay_re_grants_after_clear_when_log_has_later_approval() {
        // grant + clear + grant → cache has the last grant. The
        // user's "if both, the clear wins" applies when the clear
        // is the terminal event; a later grant on the same session
        // is a fresh authorization that supersedes the clear.
        let perms = make_store();
        let log = make_log();
        let session = "default/webchat/conv-3";

        append_session_grant(&log, session, "shell:ls", "default");
        append_session_clear(&log, session, 1);
        append_session_grant(&log, session, "shell:ls", "default");

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        let store = perms.lock().unwrap();
        assert_eq!(
            store.check(&shell_ls(), session).unwrap(),
            PermissionCheck::Allowed,
        );
    }

    #[test]
    fn replay_skips_permission_approved_with_persisted_scope() {
        // Persisted grants in the log are no-ops on the cache path:
        // SQLite is the source of truth for them. The replay must
        // not double-apply by inserting them into the in-memory
        // cache (it would still work, but it would be wrong by
        // design and would leak persisted grants into a structure
        // sized for ephemeral state).
        let perms = make_store();
        let log = make_log();
        let session = "default/webchat/conv-4";

        let handle = log.handle_for(SessionId::new(session.to_string()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: "shell:ls".to_string(),
                agent_id: "default".to_string(),
                approved_by: "operator".to_string(),
                scope: ApprovalScopeKind::Persisted,
                session_id: None,
            },
        )
        .unwrap();

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        // Cache must be empty (no session entry). Check returns
        // NeedsApproval because SQLite is also empty in this test.
        let store = perms.lock().unwrap();
        assert_eq!(
            store.check(&shell_ls(), session).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
            },
        );
    }

    #[test]
    fn replay_crash_mid_session_re_establishes_active_grants() {
        // The canonical "crash recovery" path: the session log has
        // a PermissionApproved(Session) row but no terminal
        // SessionScopedApprovalsCleared. A later wake replays the
        // log and resurrects the grant.
        let perms = make_store();
        let log = make_log();
        let session = "default/signal/sender-1";

        append_session_grant(&log, session, "shell:ls", "default");
        // No clear event: crash happened before evict ran.

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        let store = perms.lock().unwrap();
        assert_eq!(
            store.check(&shell_ls(), session).unwrap(),
            PermissionCheck::Allowed,
        );
    }

    #[test]
    fn replay_clean_session_end_leaves_cache_empty() {
        // Symmetric counterpart to the crash test: the log has
        // matching grant + clear pairs (evict ran cleanly), so a
        // wake on this session must produce an empty cache.
        let perms = make_store();
        let log = make_log();
        let session = "default/signal/sender-2";

        append_session_grant(&log, session, "shell:ls", "default");
        append_session_grant(&log, session, "shell:cat", "default");
        append_session_clear(&log, session, 2);

        replay_session_scoped_approvals(&perms, &log, session).unwrap();

        let store = perms.lock().unwrap();
        for action in [shell_ls(), shell_cat()] {
            assert_eq!(
                store.check(&action, session).unwrap(),
                PermissionCheck::NeedsApproval {
                    tier: PermissionTier::Tier2,
                },
                "{} must require approval after clean clear",
                action,
            );
        }
    }

    // -----------------------------------------------------------------
    // replay_phase_overlay (slice 4 of per-pass deny overlay)
    // -----------------------------------------------------------------

    use crate::llm::LlmConfig;
    use crate::runtime::Agent;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use wirken_audit::PhaseDenyContent;

    /// Build an Agent with a fresh-per-test SqliteSessionLog so the
    /// replay function can read its own log. Returns
    /// `(agent, log_arc, session_id, _tmp)` where `_tmp` keeps the
    /// audit DB alive for the test's lifetime. The agent's
    /// permission profile is the default `Legacy` shape; the phase
    /// overlay sits on top of it and is what slice 4 reconstructs.
    fn agent_for_phase_replay() -> (Agent, Arc<SqliteSessionLog>, String, TempDir) {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.db");
        let concrete = Arc::new(SqliteSessionLog::open(&log_path).unwrap());
        let log_dyn: Arc<dyn SessionLog> = concrete.clone();
        let session_id = "default/webchat/replay-phase".to_string();
        let agent = Agent::new(
            session_id.clone(),
            tmp.path().to_path_buf(),
            LlmConfig::ollama("test"),
            None,
            None,
            log_dyn,
        )
        .unwrap();
        (agent, concrete, session_id, tmp)
    }

    /// Append a PhaseEntered event for `session_id`. Mirrors the
    /// emission shape of `Agent::enter_phase_intercept`.
    fn append_phase_entered(
        log: &Arc<SqliteSessionLog>,
        session_id: &str,
        skill_id: &str,
        phase_name: &str,
        denied_tools: &[&str],
    ) {
        let handle = log.handle_for(SessionId::new(session_id.to_string()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PhaseEntered {
                skill_id: skill_id.to_string(),
                phase_name: phase_name.to_string(),
                denied: PhaseDenyContent {
                    tools: denied_tools.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
            },
        )
        .unwrap();
    }

    fn append_phase_exited(
        log: &Arc<SqliteSessionLog>,
        session_id: &str,
        skill_id: &str,
        phase_name: &str,
    ) {
        let handle = log.handle_for(SessionId::new(session_id.to_string()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PhaseExited {
                skill_id: skill_id.to_string(),
                phase_name: phase_name.to_string(),
                reason: wirken_audit::PhaseExitReason::PhaseChange,
            },
        )
        .unwrap();
    }

    #[test]
    fn replay_reconstructs_overlay_from_phase_entered() {
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        // Drive a full-payload PhaseEntered: tools axis plus another
        // axis to confirm reconstruction covers more than tools.
        let handle = log.handle_for(SessionId::new(session_id.clone()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PhaseEntered {
                skill_id: "test-skill".to_string(),
                phase_name: "scoring".to_string(),
                denied: PhaseDenyContent {
                    tools: vec!["read_file".to_string(), "exec".to_string()],
                    paths_read: vec!["/etc/secrets".to_string()],
                    inference_providers: vec!["openai".to_string()],
                    ..Default::default()
                },
            },
        )
        .unwrap();
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        let overlay = agent.current_phase().expect("overlay re-established");
        assert_eq!(overlay.skill_id, "test-skill");
        assert_eq!(overlay.phase_name, "scoring");
        assert!(overlay.tools.contains("read_file"));
        assert!(overlay.tools.contains("exec"));
        assert!(overlay.paths_read.contains(&PathBuf::from("/etc/secrets")));
        assert!(overlay.inference_providers.contains("openai"));
    }

    #[test]
    fn replay_clears_overlay_on_phase_exited_tombstone() {
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        append_phase_entered(&log, &session_id, "test-skill", "scoring", &["exec"]);
        append_phase_exited(&log, &session_id, "test-skill", "scoring");
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        assert!(agent.current_phase().is_none());
    }

    #[test]
    fn replay_takes_latest_unmatched_enter() {
        // Enter-Exit-Enter: the third event is the live phase at the
        // end of the log; replay should re-establish it.
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        append_phase_entered(&log, &session_id, "test-skill", "recon", &["read_file"]);
        append_phase_exited(&log, &session_id, "test-skill", "recon");
        append_phase_entered(&log, &session_id, "test-skill", "scoring", &["exec"]);
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        let overlay = agent.current_phase().expect("scoring overlay active");
        assert_eq!(overlay.phase_name, "scoring");
        assert!(overlay.tools.contains("exec"));
        assert!(!overlay.tools.contains("read_file"));
    }

    #[test]
    fn replay_ignores_orphan_phase_exited() {
        // PhaseExited with no preceding PhaseEntered: defensive
        // tolerance for log-corruption or out-of-order replay.
        // Replay leaves the overlay empty, no panic, no error.
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        append_phase_exited(&log, &session_id, "test-skill", "scoring");
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        assert!(agent.current_phase().is_none());
    }

    #[test]
    fn replay_crash_mid_phase() {
        // Crash-recovery framing: the log has PhaseEntered with no
        // PhaseExited (the host crashed before exit_phase or
        // clear_phase_at_turn_end ran). Replay re-establishes the
        // overlay so the next wake's tool calls are still subject
        // to the deny.
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        append_phase_entered(&log, &session_id, "lyrik", "scoring", &["exec"]);
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        let overlay = agent
            .current_phase()
            .expect("crash recovery resurrects overlay");
        assert_eq!(overlay.skill_id, "lyrik");
        assert_eq!(overlay.phase_name, "scoring");
    }

    #[test]
    fn replay_clean_phase_exit_leaves_no_overlay() {
        // Symmetric counterpart to the crash test: the log has a
        // matching Enter/Exit pair, so the wake produces no
        // overlay. The reason on the Exit does not matter at
        // replay (PhaseChange, SkillUnloaded, and TurnEnd are all
        // treated as terminal).
        let (mut agent, log, session_id, _tmp) = agent_for_phase_replay();
        append_phase_entered(&log, &session_id, "lyrik", "scoring", &["exec"]);
        let handle = log.handle_for(SessionId::new(session_id.clone()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::PhaseExited {
                skill_id: "lyrik".to_string(),
                phase_name: "scoring".to_string(),
                reason: wirken_audit::PhaseExitReason::TurnEnd,
            },
        )
        .unwrap();
        let log_dyn: Arc<dyn SessionLog> = log.clone();

        super::replay_phase_overlay(&mut agent, &log_dyn, &session_id).unwrap();

        assert!(agent.current_phase().is_none());
    }
}
