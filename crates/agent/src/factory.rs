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
use wirken_audit::SessionLog;
use wirken_gateway::agent_config::SubagentCeiling;
use wirken_gateway::org::OrgPermissions;
use wirken_gateway::permissions::PermissionStore;

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
        let (llm_config, api_key) = match override_for_channel {
            Some(ov) => (ov.llm_config.clone(), ov.api_key.clone()),
            None => (cfg.llm_config.clone(), cfg.api_key.clone()),
        };

        let mut agent = Agent::from_session_log(
            session_id.to_string(),
            cfg.workspace.clone(),
            llm_config,
            api_key,
            self.session_log.clone(),
            cfg.sandbox.clone(),
        )?;
        // Inject the per-agent shared resources.
        agent.attach_skills(cfg.skills.clone(), cfg.wasm_skills.clone())?;
        if let Some(perms) = &self.permissions {
            agent.set_permissions(perms.clone());
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
    pub fn evict(&self, session_id: &str) {
        if self.cache_mode == CacheMode::Cached {
            self.cache.lock().unwrap().pop(session_id);
        }
    }
}
