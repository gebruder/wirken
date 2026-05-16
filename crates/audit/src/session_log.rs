//! Per-session, type-scoped event log with a Merkle-frontier hash chain.
//!
//! This is the keystone of the Managed Agents parity work — item 1 in
//! `docs/managed-agents-parity.md`. The session log records every
//! interaction in a typed transcript that can be:
//!
//! - sliced by position via [`SessionLog::get_range`] and
//!   [`SessionLog::get_since`],
//! - rewound to N events before a given index via [`SessionLog::rewind`],
//! - verified for tamper detection via [`SessionLog::verify`], and
//! - extended with Merkle inclusion proofs (item 11) without a schema
//!   migration, because every leaf hash is stored alongside the chain
//!   hash.
//!
//! Slice 1 ships the data layer alone. No production [`AuditWriter`]
//! callers are converted yet — the existing `audit_events` table
//! remains the write target for legacy callers. `session_events` is a
//! parallel table that slice 2 will turn into the source of truth.
//!
//! ## Type-scoped reads
//!
//! [`SessionHandle`] is parameterized by a sealed [`SessionScope`]
//! marker. Slice 1 only defines [`OwnSession`]; future admin scopes
//! will plug into the same pattern. The handle's `id` field is the
//! only session it can address through any method on this trait.
//!
//! The phantom type catches accidental cross-session bugs in trusted
//! code at compile time. It does **not** defend against a malicious
//! tool that already holds a [`SessionLog`] reference — the real
//! defense for that is keeping `SessionLog` operations out of the
//! LLM tool dispatch surface.
//!
//! ## Sync API
//!
//! Methods are blocking (rusqlite is sync). Async callers must wrap
//! invocations in `tokio::task::spawn_blocking` if they sit on the
//! main reactor.
//!
//! [`AuditWriter`]: crate::AuditWriter

use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::signing::{AuditSigningKey, CHAIN_HEAD_SCHEMA_VERSION};

// ---------------------------------------------------------------------------
// Sealed scope marker
// ---------------------------------------------------------------------------

mod private {
    /// Sealing supertrait. Cannot be implemented outside this crate.
    pub trait Sealed {}
    impl Sealed for super::OwnSession {}
}

/// Marker trait for session handle scopes. Sealed at compile time —
/// new scopes can only be added inside this crate. The sealing is
/// real (private supertrait), not a documentation comment.
pub trait SessionScope: private::Sealed + Send + Sync + 'static {}

/// The harness's own session — minted by the harness for the
/// `session_id` of the agent loop currently running. Read-write.
///
/// Slice 1 only defines this scope. Future scopes (e.g.
/// `AdminScope` for cross-session debugging tooling) will be added
/// when there is a real caller.
#[derive(Debug, Clone, Copy)]
pub struct OwnSession;
impl SessionScope for OwnSession {}

// ---------------------------------------------------------------------------
// Session id and handle
// ---------------------------------------------------------------------------

/// Opaque session identifier. The harness picks the format; slice 1
/// makes no assumptions beyond non-empty UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Capability handle to a single session, parameterized by scope.
///
/// `SessionHandle::new` is `pub(crate)`. Callers in other crates
/// mint handles via [`SessionLog::handle_for`]. The phantom type
/// makes accidental cross-session reads in trusted code a compile
/// error.
pub struct SessionHandle<S: SessionScope> {
    id: SessionId,
    _scope: PhantomData<S>,
}

impl<S: SessionScope> SessionHandle<S> {
    /// Crate-private constructor. External callers go through
    /// [`SessionLog::handle_for`].
    pub(crate) fn new(id: SessionId) -> Self {
        Self {
            id,
            _scope: PhantomData,
        }
    }

    /// The session id this handle is bound to. The handle cannot
    /// address any other session.
    pub fn id(&self) -> &SessionId {
        &self.id
    }
}

impl<S: SessionScope> std::fmt::Debug for SessionHandle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("scope", &std::any::type_name::<S>())
            .finish()
    }
}

impl<S: SessionScope> Clone for SessionHandle<S> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            _scope: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Trust level
// ---------------------------------------------------------------------------

/// Trust label for a session event. Drives the context engine
/// (item 4) — `Compaction` events are treated as untrusted and
/// scanned through the injection detector before replay.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Harness-controlled. System prompts, attestations, internal
    /// markers.
    System,
    /// User-supplied. Inbound messages and replies.
    User,
    /// Output from a verified internal tool.
    Tool,
    /// Output that originated from a model call (compaction
    /// summaries, free-text fallbacks). Treat as untrusted — must
    /// be scanned before replay into a prompt.
    Compaction,
}

// ---------------------------------------------------------------------------
// Event payload
// ---------------------------------------------------------------------------

/// Why a [`SessionEvent::ChainHead`] was emitted. The verifier treats
/// every reason uniformly; the field exists so a reviewer can tell
/// the boundary kind apart from a checkpoint without re-deriving it
/// from sequence cadence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChainHeadReason {
    /// First event in a fresh session.
    SessionStart,
    /// Explicit session-close head, also emitted on graceful gateway
    /// shutdown.
    SessionEnd,
    /// Cadence-driven head: every 1000 appends or 5 minutes of
    /// wall-clock since the last head, whichever comes first.
    Checkpoint,
    /// Audit-log file rotation. Emitted before the rotate so the
    /// pre-rotate file ends with a signed head.
    Rotation,
}

/// Why [`SessionEvent::PermissionDenied`] fired: the tier gate
/// (operator-approval model) or an org-policy block (centrally
/// configured allow/deny list). The pre-1.2.0 shape conflated these
/// by overloading the `tier` string with the sentinel `"org_policy"`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DenialSource {
    /// Tier gate: a Tier 2/3 action was attempted without standing
    /// approval. `tier` on the same event carries the requested tier
    /// label (`"tier2"` / `"tier3"`). Default so pre-1.2.0 rows whose
    /// payload lacks the field deserialize as Tier-source (the only
    /// kind the pre-1.2.0 emit path produced).
    #[default]
    Tier,
    /// Org-policy block: the tool name was on the org's denylist or
    /// outside its allowlist. `tier` is `None` for this source.
    OrgPolicy,
}

/// Which surface mediated an operator's approve / deny decision.
/// `ApprovalScopeKind` answers "how long does this grant last"
/// (Persisted vs Session); [`ApprovalSource`] answers "which UI did
/// the operator click through". Both are useful for SIEM detections;
/// they answer different questions.
///
/// `tag = "kind"` so future surfaces (channel adapters with
/// `channel: String`, future SDK) slot in without breaking the wire
/// for existing consumers. `Stdin` is the first surface to ship;
/// `Sse`, `Cli`, `ChannelAdapter` are reserved for follow-up slices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalSource {
    /// `wirken ask` reading a y/n prompt from stdin under a TTY.
    Stdin,
    /// Webchat SSE approval surface (next slice).
    Sse,
    /// `wirken permissions approve` CLI subcommand (next slice).
    Cli,
    /// Channel adapter approval (Telegram, Slack, etc.).
    /// `channel` carries the adapter id exactly as the registry
    /// stores it, so a SIEM detection can pivot per-channel.
    ChannelAdapter { channel: String },
}

/// Storage lifetime of a recorded permission approval. Defined here
/// rather than in `wirken-gateway::permissions` because audit cannot
/// depend on gateway (the dependency direction is `gateway →
/// audit`); the gateway-side `ApprovalScope` enum maps onto this on
/// emit. `serde` snake_case wire shape mirrors gateway's so a SIEM
/// consumer querying audit events sees the same labels as
/// `wirken permissions list`.
///
/// `Default` returns `Persisted`, matching gateway's
/// `ApprovalScope::Persisted` so a row written by the pre-slice-1
/// emit path (none exist yet, but the variant lands defaulted for
/// future forward-compat) reads cleanly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScopeKind {
    /// SQLite-backed, default expiry. The pre-slice-1 default.
    #[default]
    Persisted,
    /// In-memory only, cleared on session end. `session_id` on the
    /// same event names the session.
    Session,
}

/// Wire-stable content of a phase deny overlay as recorded on
/// [`SessionEvent::PhaseEntered`]. Lives in audit rather than
/// `wirken-agent::skill_perms` because audit cannot depend on agent
/// (gateway → audit is the only direction); the agent-side
/// `PhaseDenyOverlay` maps onto this on emit. Paths are recorded as
/// `String` rather than `PathBuf` so the wire shape is portable
/// across platforms; the agent-side reconstructor parses them back
/// into `PathBuf` at replay time.
///
/// Every axis is defaulted to empty on deserialize and skipped on
/// serialize when empty, so a future axis addition (e.g. credential
/// names) stays forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PhaseDenyContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths_read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths_write: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inference_providers: Vec<String>,
}

/// Why a phase overlay was exited. Carried on
/// [`SessionEvent::PhaseExited`] so a SIEM consumer or replay path
/// can distinguish a clean skill-driven exit from a host-driven one
/// (turn end, skill unload) without inferring from surrounding
/// context. `Default` is `PhaseChange` (the skill-initiated case)
/// for forward-compat with rows written before this field existed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PhaseExitReason {
    /// Skill explicitly called `wirken_exit_phase`, typically to
    /// enter the next phase.
    #[default]
    PhaseChange,
    /// Agent turn ended; the host auto-exited any still-active phase
    /// before clearing the turn-scoped overlay slot.
    TurnEnd,
    /// Skill was unloaded mid-phase; the host auto-exited so the
    /// dangling overlay does not survive the skill's lifetime.
    SkillUnloaded,
}

/// Why a [`SessionEvent::SkillPermissionDenied`] event fired:
/// the agent's base permission profile refused the call
/// (`Profile`), or an active phase deny overlay refused it
/// (`Phase { phase_name }`). SIEM consumers correlate the
/// `Phase` variant with the triggering `PhaseEntered` row by
/// `phase_name`; the `Profile` variant is the pre-slice-2 default
/// and the only shape any row written before this field existed
/// carries.
///
/// Serde tag = "kind" so the wire shape stays extensible (a future
/// org-policy variant could land without renaming the existing
/// two). Defaulted to `Profile` on deserialize so pre-upgrade audit
/// rows read cleanly without a migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkillDeniedReason {
    /// The agent's effective per-skill permission profile refused
    /// the call. Pre-slice-2 default; carries no extra data.
    #[default]
    Profile,
    /// An active phase deny overlay refused the call. `phase_name`
    /// names which phase fired so SIEM consumers can correlate with
    /// the triggering `PhaseEntered` row for the same agent.
    Phase { phase_name: String },
}

/// Outcome of one HTTP fetch as recorded on
/// [`SessionEvent::HttpFetch`]. The pre-1.2.0 shape was a free-form
/// string (`"ok"`, `"http_error_404"`, `"network_error"`, ...); the
/// 1.2.0 form splits the success/failure category from the HTTP
/// status code so SIEM consumers can group on a stable label and
/// filter on the code without parsing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpFetchOutcome {
    /// Server returned a 2xx response.
    Success,
    /// Egress allowlist refused the host before the connection.
    EgressDenied,
    /// Per-source rate-limit budget exhausted.
    RateLimited,
    /// Server returned a non-2xx response. `http_status_code` carries
    /// the code on the same event.
    HttpError,
    /// Transport-level failure (DNS, TCP, TLS, body parse).
    NetworkError,
}

/// Terminal status of a sub-agent run, recorded on
/// [`SessionEvent::SubagentResult`]. Replaces the pre-1.2.0 free-form
/// status string with a closed set so SIEM consumers can group on
/// stable labels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubagentStatus {
    /// Child returned a normal response.
    Ok,
    /// Child raised an error that the parent envelope captured.
    Error,
    /// Child exceeded the parent's `max_rounds` ceiling.
    RoundsExceeded,
    /// Subagent nesting depth cap reached before the child could spawn.
    DepthExceeded,
    /// Child ran past the parent's runtime ceiling and was cut.
    Timeout,
}

/// Default `actor_kind` for `SessionEvent::AuditLegacy` rows that
/// were written by a pre-1.2.0 path and therefore have no
/// `actor_kind` field on the wire. See the variant's doc for the
/// trade-off.
fn default_legacy_actor_kind() -> crate::event::ActorKind {
    crate::event::ActorKind::Service
}

/// One event in a session transcript.
///
/// New variants may be added without breaking older readers when the
/// reader is forward-compatible (serde `tag = "kind"` representation).
/// Removing or renaming variants is a breaking change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    /// Inbound user message that triggered an agent turn.
    ///
    /// `inbound_id` carries the platform-supplied message identifier
    /// (Telegram `message_id`, Slack `ts`, Discord `id`, etc.) when
    /// the source has one, or a UUID synthesized at the gateway
    /// boundary for sources that don't (`webchat`, `cron`,
    /// `wirken ask`). The harness uses this for crash-recovery
    /// dedup: if the most recent UserMessage in the session has the
    /// same inbound_id as a fresh delivery, it's a re-delivery and
    /// process_message returns the prior assistant response without
    /// re-running the LLM. `Option` is for wire-format flexibility —
    /// production callers always supply Some.
    UserMessage {
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inbound_id: Option<String>,
        /// Adapter that delivered this message (e.g. `slack`, `signal`,
        /// `webchat`, `cli`). Source-of-record for which channel was
        /// the trigger of the agent turn. `None` for callers that do
        /// not have a platform adapter (subagent recursion).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        adapter_id: Option<String>,
        /// Platform-side sender identity (Telegram user id, Slack uid,
        /// the literal `webchat-user`, ...). `None` for subagent
        /// recursion.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sender_id: Option<String>,
    },
    /// Final assistant text response for a turn.
    AssistantMessage {
        content: String,
        /// Agent id whose runtime emitted the response. Required so a
        /// multi-agent session log can be split by agent without
        /// re-traversing the chain.
        #[serde(default)]
        agent_id: String,
    },
    /// Assistant requested one or more tool calls.
    AssistantToolCalls {
        calls: Vec<ToolCallRecord>,
        #[serde(default)]
        agent_id: String,
        /// Adapter that delivered the inbound message that drove
        /// this tool round. Carried so a SIEM detection on
        /// `AssistantToolCalls` can pivot to the channel without
        /// joining back to the sibling `UserMessage` row by
        /// `session_id`. `None` for CLI / cron / subagent paths.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        adapter_id: Option<String>,
        /// Platform sender that drove this tool round. Same source
        /// and `None` semantics as `adapter_id`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sender_id: Option<String>,
    },
    /// Result of a single tool call.
    ToolResult {
        call_id: String,
        tool_name: String,
        output: String,
        success: bool,
        #[serde(default)]
        agent_id: String,
        /// See [`Self::AssistantToolCalls::adapter_id`]. Mirrored
        /// onto the result so a SIEM rule observing only the result
        /// row still gets the inbound channel without a join.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        adapter_id: Option<String>,
        /// See [`Self::AssistantToolCalls::sender_id`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sender_id: Option<String>,
    },
    /// LLM request metadata. Full request body is reconstructible
    /// from prior session events; this carries hashes for the
    /// reproducible-replay verifier (item 10).
    ///
    /// `credential_id` is the vault entry NAME (the slot the operator
    /// configured in `provider.json` or `channel_overrides`) under
    /// which the api key was stored. Never the raw secret. Populated
    /// when the gateway resolved the api key from a named vault slot;
    /// `None` for paths that pass an api key directly (raw value in
    /// `provider.json`, env-var override, tests with a hardcoded
    /// key). Defaulted on deserialize so pre-credential_id rows read
    /// cleanly. The field is omitted from the serialized form when
    /// `None` so the wire shape stays back-compatible with consumers
    /// that pin column names.
    LlmRequest {
        provider: String,
        model: String,
        request_id: String,
        tools_hash: HashHex,
        messages_hash: HashHex,
        #[serde(default)]
        agent_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_id: Option<String>,
    },
    /// LLM response metadata.
    ///
    /// `tokens_in` and `tokens_out` come from the provider's usage
    /// block. `cache_creation_input_tokens` and
    /// `cache_read_input_tokens` are anthropic-specific (prompt
    /// caching) and stay zero for other providers; both are
    /// defaulted on deserialize so logs written before these fields
    /// existed continue to read cleanly. Endpoints that do not
    /// populate a usage block (some custom OpenAI-compatible servers,
    /// including ollama) record zeros across the board.
    ///
    /// The three `*_cost_usd_micros` fields carry per-call cost
    /// derived from the baked pricing table (`crates/audit/src/pricing.toml`,
    /// `include_str!`'d at compile time). `None` when the
    /// (provider, model) pair is absent from the table; a warning is
    /// logged at the emit site so a stale binary against a new model
    /// is visible without blocking the call. All three default on
    /// deserialize so pre-cost rows read cleanly.
    LlmResponse {
        request_id: String,
        finish_reason: String,
        /// Defaulted so a pre-1.2.0 row carrying `tokens_in` (the
        /// pre-1.2.0 name, intentionally not aliased; see C4) reads
        /// as `input_tokens: 0` rather than failing. The legacy value
        /// is silently dropped; the snapshot tests assert this is the
        /// documented behaviour so a future revert can't pass tests
        /// accidentally.
        #[serde(default)]
        input_tokens: u32,
        /// See [`Self::LlmResponse::input_tokens`] for the legacy
        /// drop note.
        #[serde(default)]
        output_tokens: u32,
        #[serde(default, skip_serializing_if = "is_zero_u32")]
        cache_creation_input_tokens: u32,
        #[serde(default, skip_serializing_if = "is_zero_u32")]
        cache_read_input_tokens: u32,
        latency_ms: u64,
        #[serde(default)]
        agent_id: String,
        /// See the corresponding field on
        /// [`Self::LlmRequest::credential_id`]. Populated on emit
        /// from the same Agent state so a `LlmRequest` and its
        /// paired `LlmResponse` always agree.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_id: Option<String>,
        /// Cost of input tokens in USD micros (1 USD = 1_000_000
        /// micros), floor-rounded. `None` if the (provider, model)
        /// pair is missing from the baked pricing table.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_cost_usd_micros: Option<u64>,
        /// Cost of output tokens in USD micros, floor-rounded. Same
        /// `None` semantics as [`Self::LlmResponse::input_cost_usd_micros`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_cost_usd_micros: Option<u64>,
        /// `input_cost_usd_micros + output_cost_usd_micros`, computed
        /// once at emit time so SIEM consumers do not have to redo the
        /// arithmetic. `None` if either operand is `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total_cost_usd_micros: Option<u64>,
    },
    /// Permission denial recorded by the harness. `action_key` is
    /// the canonical key under which an operator can grant approval
    /// (e.g., `shell:curl`); kept alongside `tool` so reviewers can
    /// map the denial back to a permissions.db entry without having
    /// to reparse tool arguments. `denial_source` distinguishes a
    /// tier gate from an org-policy block; `tier` is populated only
    /// when `denial_source == Tier` (the prior shape conflated the
    /// two by overloading the tier string with the sentinel
    /// `"org_policy"`).
    PermissionDenied {
        tool: String,
        /// Defaulted for rows written before this field existed; old
        /// audit events deserialize with an empty key so a pre-upgrade
        /// session log stays readable.
        #[serde(default)]
        action_key: String,
        /// Default `Tier` so pre-1.2.0 rows (which only carried a
        /// `tier: String` field) deserialize cleanly.
        #[serde(default)]
        denial_source: DenialSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tier: Option<String>,
        agent_id: String,
        trigger: Option<String>,
        /// Which surface mediated the operator decision, when one
        /// did. `None` for tier-gate or org-policy denials that
        /// short-circuited without operator interaction (the
        /// pre-slice default and the `approval_gate == None`
        /// agent path); `Some` when an [`ApprovalGate`] returned
        /// `Denied` or timed out. SIEM detections separate
        /// "denied because of policy" (`denied_via == None`) from
        /// "operator explicitly refused" (`denied_via == Some(_)`)
        /// using this field alone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_via: Option<ApprovalSource>,
        /// Operator-supplied reason on a `Denied` outcome, or a
        /// synthetic reason like `"approval timeout"` on a
        /// `Timeout` outcome. `None` when the denial path is
        /// non-operator (tier-gate / org-policy). The free-form
        /// content surfaces directly to the LLM as the failed
        /// tool result's output, so anything operator-typed lands
        /// in the conversation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denial_reason: Option<String>,
    },
    /// Operator approved a Tier 2 action. `scope` distinguishes
    /// SQLite-persisted approvals (the default) from session-scoped
    /// approvals which live only in-memory; session-scoped grants
    /// survive a crash only when this event is replayed from the
    /// session log on agent re-wake, which is the only audit-side
    /// trace of their existence.
    ///
    /// `session_id` is populated iff `scope == Session`; the field
    /// is omitted from the wire shape otherwise so SIEM consumers
    /// pivoting on it do not match persisted approvals by accident.
    /// `approved_by` carries the operator label exactly as the
    /// gateway recorded it (`approved_by` on
    /// `crate::permissions::Approval`).
    PermissionApproved {
        action_key: String,
        agent_id: String,
        approved_by: String,
        #[serde(default)]
        scope: ApprovalScopeKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        /// Which surface mediated the operator's approval. `None`
        /// for pre-slice rows and for non-operator approval paths
        /// (none ship today, but the field is `Option` so any
        /// future automation path stays representable). `Some` for
        /// every `ApprovalGate`-driven approval starting with the
        /// stdin gate slice. Distinct from `approved_by` which
        /// carries the actor label (operator's name when known);
        /// `approved_via` carries the mediation surface so a SIEM
        /// detection can pivot per-surface without parsing
        /// free-form actor strings.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved_via: Option<ApprovalSource>,
    },
    /// Session-scoped approvals were cleared for `session_id`.
    /// Emitted once per session end (clean shutdown or crash
    /// recovery) so a replay path sees the boundary and does not
    /// re-establish entries that were intentionally let go.
    /// `count` is the number of in-memory rows that were dropped;
    /// `reason` is a stable snake_case label (`"session_end"`,
    /// `"session_replaced"`, `"operator_revoke"`).
    SessionScopedApprovalsCleared {
        session_id: String,
        count: u32,
        reason: String,
    },
    /// A skill entered a phase with a deny overlay active. The
    /// overlay denies the listed tools / egress hosts / filesystem
    /// paths / inference providers for the remainder of the turn or
    /// until the skill calls `wirken_exit_phase`. `skill_id`
    /// attributes the overlay; `phase_name` is the skill-supplied
    /// label (e.g. `"recon"`, `"scoring"`) for operator-readable
    /// audit. `denied` is defaulted on deserialize so a row written
    /// before this variant existed (none today, but future-compat)
    /// reads cleanly.
    PhaseEntered {
        skill_id: String,
        phase_name: String,
        #[serde(default)]
        denied: PhaseDenyContent,
    },
    /// The active phase deny overlay was cleared. Emitted by the
    /// host on every overlay clear: skill-initiated
    /// (`PhaseChange`), turn-end auto-exit (`TurnEnd`), or
    /// skill-unload (`SkillUnloaded`). `phase_name` matches the
    /// phase named by the most recent `PhaseEntered` event for the
    /// same `skill_id`; replay walks `PhaseEntered`/`PhaseExited`
    /// pairs last-event-wins to reconstruct the active overlay.
    PhaseExited {
        skill_id: String,
        phase_name: String,
        #[serde(default)]
        reason: PhaseExitReason,
    },
    /// Skill-permission-block denial recorded by the harness. Distinct
    /// from `PermissionDenied` (which is tier-based, operator-approval
    /// shaped). This event fires when an agent's effective per-skill
    /// `permissions:` profile rejects a request: a tool not in
    /// `tools.allow`, a host not in `egress.domains`, a path not in
    /// `filesystem.{read,write}_paths`, or a provider not in
    /// `inference.allow`. `axis` names which axis fired; `requested`
    /// is the bare resource string (tool name, hostname, path,
    /// provider name); the agent's identity and the surrounding
    /// trigger message are kept for post-hoc audit.
    SkillPermissionDenied {
        axis: String,
        requested: String,
        agent_id: String,
        trigger: Option<String>,
        /// Why the call was denied: by the base permission profile
        /// (`Profile`, the pre-slice-2 default) or by an active
        /// phase deny overlay (`Phase { phase_name }`). Defaulted on
        /// deserialize so a row written before this field existed
        /// reads back as `Profile`, matching the only deny path the
        /// pre-upgrade emit produced.
        #[serde(default)]
        denied_reason: SkillDeniedReason,
    },
    /// Zirkel: the librarian ran a perspective-expansion turn for
    /// `topic`. `perspectives` carries the ephemeral noun-phrase
    /// labels produced by the LLM from concatenated Wikipedia
    /// section headings; the labels are not persisted in the
    /// candidates table or anywhere else outside the audit chain.
    /// `expansion_id` is a fresh UUID minted once per turn and
    /// threaded through every subsequent `HttpFetch` and
    /// `CandidateScored` event the turn caused, so a downstream
    /// auditor can reconstruct what the expansion actually fetched.
    /// Zirkel: a perspective-expansion turn was attempted for
    /// `topic` but cut by the orchestrator before any retriever
    /// fetch. Distinct from a successful `PerspectiveExpansion`
    /// emission so a downstream auditor can count "expansion
    /// rejected" events directly. `reason` is a stable snake_case
    /// label (today: `"over_budget"`) so consumers can group by
    /// rejection cause without re-parsing free text.
    PerspectiveSkipped {
        run_id: String,
        topic: String,
        reason: String,
    },
    PerspectiveExpansion {
        run_id: String,
        topic: String,
        perspectives: Vec<String>,
        expansion_id: String,
        /// Labels the LLM emitted that slug-collided with an earlier
        /// label and were therefore not dispatched. The orchestrator
        /// folds labels to slugs to derive synthetic
        /// `SourceConfig.name` values; two slug-identical labels
        /// would name the same fetch and overstate the turn's
        /// coverage. Recorded here so a downstream auditor sees the
        /// LLM emitted them and the orchestrator dropped them.
        /// Empty when no collisions occurred. Defaulted on
        /// deserialize for forward-compat with rows written before
        /// the field existed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        dropped_for_collision: Vec<String>,
    },
    /// Zirkel orchestrator: an HTTP fetch went out through the policed
    /// transport. `source` is the source's name in `sources.toml`;
    /// `host` is the URL host. `bytes` is the response payload size on
    /// success, `0` on transport-layer denial. `outcome` distinguishes
    /// success / `egress_denied` / `rate_limited` / `http_error_<code>`
    /// / `network_error`.
    HttpFetch {
        source: String,
        host: String,
        url: String,
        /// Closed-set outcome label. SIEM consumers group on this
        /// without parsing the prior free-form string.
        outcome: HttpFetchOutcome,
        /// Server-side HTTP status when `outcome == HttpError`.
        /// `None` for transport-layer outcomes (success counted via
        /// `Success`, but no code is recorded; egress denial, rate
        /// limit, and network errors have no status code).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_status_code: Option<u16>,
        /// Response payload size on success. Zero on any non-success
        /// outcome (egress denial, rate limit, HTTP error, network
        /// error). The overload is preserved from the pre-1.2.0 shape
        /// so the existing `bytes_total` aggregations stay accurate
        /// against new and old rows alike.
        bytes: u64,
        run_id: Option<String>,
        /// Correlates this fetch with a perspective-expansion turn.
        /// `Some` when the fetch was driven by a synthetic
        /// per-perspective `SourceConfig`; `None` for the default
        /// manifest-only loop. Defaulted on deserialize so audit rows
        /// written before the field existed read cleanly.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expansion_id: Option<String>,
        /// Agent that drove the fetch. `None` when the fetcher ran
        /// outside an agent turn (cron orchestrator, ad-hoc run).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<String>,
        /// Skill that owns the fetcher (e.g. `zirkel`). `None` when
        /// the fetcher is not skill-attributable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        skill_name: Option<String>,
    },
    /// Zirkel: a fetched item passed exclusion + keyword screening and
    /// landed in the candidates table with its keyword-match score.
    /// `keyword_match_score` is the count of distinct keyword matches.
    /// The LLM-relevance pass emits a separate `CandidateLlmScored`
    /// event after this one — the two-event split keeps each pass
    /// independently auditable, so a failed LLM pass leaves the
    /// keyword event in the chain rather than orphaning the candidate.
    /// `matched_keywords` is the list of matched keyword strings, kept
    /// verbatim so the chain-verifier can replay the screening
    /// decision. Serialized as a JSON array of strings (1.2.0+); the
    /// pre-1.2.0 shape was a JSON-encoded string (a stringified
    /// array).
    CandidateScored {
        run_id: String,
        candidate_id: i64,
        keyword_match_score: u32,
        matched_keywords: Vec<String>,
        /// Correlates this candidate with a perspective-expansion
        /// turn. Same semantics as on `HttpFetch`: `Some` only for
        /// candidates landed under a synthetic per-perspective
        /// `SourceConfig`. Defaulted on deserialize.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expansion_id: Option<String>,
    },
    /// Zirkel: the LLM relevance pass scored a candidate.
    /// `llm_relevance_score` is 0–100. `matched_keyword` is the single
    /// user keyword the LLM identified as the strongest signal (one of
    /// the keywords in the matched-keywords list from the keyword
    /// pass). `why_surfaced` is the LLM's one-line rationale.
    CandidateLlmScored {
        run_id: String,
        candidate_id: i64,
        llm_relevance_score: u32,
        matched_keyword: String,
        why_surfaced: String,
    },
    /// Zirkel: the user marked a candidate as kept from the digest.
    /// Emitted by C-Signal when the keep button (or numbered reply) is
    /// processed.
    CandidateKept {
        run_id: String,
        candidate_id: i64,
        via: String,
    },
    /// Zirkel: the user marked a candidate as skipped, or the
    /// orchestrator dropped it pre-scoring (exclusion match, score 0,
    /// dedup hit). `reason` distinguishes user-skipped /
    /// exclusion_match / score_zero / duplicate_url.
    CandidateSkipped {
        run_id: String,
        url_hash: HashHex,
        source: String,
        reason: String,
    },
    /// Zirkel: a per-run cluster was named by the LLM (C-LLM scope).
    ThemeNamed {
        run_id: String,
        theme_id: i64,
        name: String,
        member_count: u32,
    },
    /// Zirkel: the interests file changed between runs. `before_hash`
    /// is the hash recorded on the previous run's snapshot;
    /// `after_hash` is the current hash. Emitted at the start of every
    /// run that detects a delta.
    InterestsEdited {
        before_hash: HashHex,
        after_hash: HashHex,
    },
    /// Compaction event from the context engine (item 4). The
    /// `extracts` are structured key-value claims, not free-text.
    /// `via_model: true` flags the rare free-text fallback path
    /// which the context engine treats as untrusted on replay.
    Compaction {
        spans: Vec<u64>,
        extracts: serde_json::Value,
        via_model: bool,
        /// Agent whose context engine produced this compaction.
        #[serde(default)]
        agent_id: String,
        /// LLM provider used to summarise when `via_model: true`.
        /// `None` for the deterministic structured-extract path
        /// (`via_model: false`), which is the only path Compaction
        /// emits today.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        /// LLM model used to summarise when `via_model: true`. Same
        /// `None` semantics as `provider`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
    /// Periodic chain-head signature (item 8). Self-contained proof
    /// that the chain up to `chain_head_seq` is intact.
    Attestation {
        chain_head_seq: u64,
        chain_head_hash: HashHex,
        signature: HexBytes,
        signer_pubkey: HashHex,
    },
    /// Gateway-keyed signature over a contiguous range of this
    /// session's chain. Emitted at session boundaries and on a
    /// checkpoint cadence so an offline verifier with the gateway's
    /// audit public key can prove the recorded hashes are this
    /// gateway's record. Distinct from `Attestation`, which uses a
    /// per-agent identity key.
    ///
    /// `sequence_range` covers `[start, end]` inclusive: the seqs of
    /// the events the head anchors. `prev_chain_hash` is the chain
    /// hash at `start - 1`, or the empty string when this head
    /// covers from seq 0. `current_chain_hash` is the chain hash at
    /// `end`. The signature is over the canonical message defined in
    /// [`crate::signing::build_signed_message`] and binds in
    /// [`crate::signing::CHAIN_HEAD_SCHEMA_VERSION`] so a future
    /// payload-layout bump does not silently invalidate old heads.
    /// `signing_pubkey` is the hex-encoded 32-byte Ed25519 public
    /// key that produced the signature; the verifier reads it from
    /// the event itself for offline replay.
    ChainHead {
        reason: ChainHeadReason,
        sequence_range_start: u64,
        sequence_range_end: u64,
        prev_chain_hash: HashHex,
        current_chain_hash: HashHex,
        signature: HexBytes,
        signing_pubkey: HashHex,
        schema_version: u32,
    },
    /// Item 10 follow-up — the harness records its current effective
    /// system prompt as a session event before the first
    /// `LlmRequest` of every session, and again whenever the prompt
    /// drifts (e.g., a skill is installed or the default prompt
    /// changes between binary versions). The verifier uses the most
    /// recent `SystemPromptSet` at or before each `LlmRequest` to
    /// reconstruct the exact conversation prefix that was hashed,
    /// so a future system-prompt update does not silently invalidate
    /// every historical session's verification. Sessions whose
    /// `LlmRequest` events have no preceding `SystemPromptSet`
    /// (legacy sessions written before this variant existed) are
    /// reported as `events_unverifiable` rather than divergent.
    SystemPromptSet {
        content: String,
        #[serde(default)]
        agent_id: String,
    },
    /// Record of a [`SessionLog::rewind`] call. Appended immediately
    /// after the DELETE so the chain picks up cleanly from whatever
    /// row survived the cut. The event is the new chain head, which
    /// means an attestation written after the rewind cryptographically
    /// covers it. An attacker with raw SQLite access can still DELETE
    /// rows without inserting this marker — but an *honest* caller
    /// going through the trait can no longer silently rewrite
    /// history.
    ///
    /// - `old_last_seq` is the sequence number that was at the head
    ///   of the session immediately before the rewind.
    /// - `deleted_count` is how many rows the DELETE actually removed.
    /// - `reason` is the caller-supplied justification, stored
    ///   verbatim so a reviewer can search for e.g. "crash recovery".
    Rewind {
        old_last_seq: u64,
        deleted_count: u64,
        reason: String,
    },
    /// Sub-agent spawned by the harness (item 6).
    SubagentSpawned {
        child_session_id: String,
        child_agent_id: String,
        tools_granted: Vec<String>,
    },
    /// Sub-agent result. The parent harness writes this to its own
    /// session AFTER the child completes.
    SubagentResult {
        child_session_id: String,
        output: String,
        status: SubagentStatus,
    },
    /// Backward-compatibility wrapper for the pre-slice-2 audit
    /// log. The 1.2.0 schema splits `actor` into
    /// `actor_kind` + `actor_id` and makes `channel` an
    /// `Option<String>`; pre-1.2.0 rows persisted as plain `actor` +
    /// empty-string `channel`. The `audit_events` SQL view COALESCEs
    /// both wire shapes so existing SIEM consumers see every row.
    ///
    /// Pre-1.2.0 payloads that landed in `session_events` (e.g., from
    /// a 1.1.x writer) are missing `actor_kind` entirely. Reading
    /// them must not break chain verification, which is what 1.5.1
    /// regressed: the variant declared `actor_kind: ActorKind`
    /// without a default, so `serde_json::from_str::<SessionEvent>`
    /// failed with `missing field actor_kind` and halted the audit
    /// writer after three consecutive verify-pass errors.
    ///
    /// The fields below tolerate the pre-1.2.0 shape:
    ///   - `actor_kind` defaults to `Service`. Conservative because
    ///     the rows that lack the field tend to be internal events
    ///     (gateway lifecycle, alarm-log writes). User messages
    ///     written by the pre-1.2.0 path get classified Service
    ///     instead of User; the variant comment treats that
    ///     misclassification as acceptable because the row hashes
    ///     are already sealed and the precise classify-from-actor
    ///     heuristic requires a custom Deserialize (deferred until
    ///     a future schema migration justifies it).
    ///   - `actor_id` aliases `actor` so a pre-split row with
    ///     `{"actor":"alice",...}` populates `actor_id` with the
    ///     original identifier.
    AuditLegacy {
        #[serde(default = "default_legacy_actor_kind")]
        actor_kind: crate::event::ActorKind,
        #[serde(default, alias = "actor")]
        actor_id: String,
        action: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
        detail: serde_json::Value,
    },
    /// A hook completed its inbound handshake and is now connected.
    /// `signature_status` distinguishes the production path (a
    /// registered pubkey matched in `hook_registry`) from the dev
    /// escape hatch (`WIRKEN_ALLOW_UNREGISTERED_HOOKS=1` accepted an
    /// unregistered peer). The dev path always emits a warning at
    /// the gateway too; this audit row is the durable record.
    HookRegistered {
        hook_id: String,
        hook_type: HookKind,
        #[serde(default)]
        signature_status: HookSignatureStatus,
    },
    /// One veto-hook invocation completed. Emitted per hook per tool
    /// call (in series, in `hook_registry` insertion order). The
    /// invocation runs after Wirken's tier and per-skill permission
    /// gates already accepted the call, so a `Deny` here represents
    /// an external policy refusing what the built-in gates already
    /// allowed.
    HookDispatched {
        hook_id: String,
        /// The tool name whose call triggered the invocation.
        tool_name: String,
        /// Agent that drove the tool call.
        agent_id: String,
        decision: HookDecision,
    },
    /// A hook's connection dropped or its veto invocation hit the
    /// timeout / failed cleanly. `error` is a short snake_case label
    /// (`"connection_dropped"`, `"veto_timeout"`,
    /// `"veto_response_malformed"`, `"observe_send_failed"`) so SIEM
    /// consumers can group on a stable string. The longer error
    /// detail goes to gateway logs, not the audit chain.
    HookCrashed { hook_id: String, error: String },
}

/// What kind of hook a [`SessionEvent::HookRegistered`] row
/// describes. Mirrors `wirken_ipc::HookType` on the wire so audit
/// consumers don't have to depend on the IPC crate to deserialize.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    Observe,
    Veto,
}

/// Whether a [`SessionEvent::HookRegistered`] row represents an
/// authenticated registered pubkey or an unregistered peer accepted
/// under the dev escape hatch. `Default` is `Registered` so a row
/// written by a future code path that forgets the field still
/// classifies under the conservative production posture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookSignatureStatus {
    /// Pubkey looked up in `hook_registry` and matched. Production
    /// path.
    #[default]
    Registered,
    /// `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1` accepted an unregistered
    /// peer. Dev mode only.
    Unregistered,
}

/// The decision a veto hook returned for one invocation. `Deny`
/// carries the operator-readable reason the hook returned on the
/// wire; this text is also surfaced to the LLM as the tool call's
/// failure message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookDecision {
    Allow,
    Deny {
        reason: String,
    },
    /// The hook did not respond within the configured timeout.
    /// Production posture: fail-closed (the tool call is refused).
    /// Dev posture (`WIRKEN_ALLOW_UNREGISTERED_HOOKS=1`):
    /// fail-open with a warning. Either way this variant lands on
    /// the chain so a reviewer can distinguish a timeout from an
    /// explicit deny.
    Timeout,
}

/// A single tool call request from the assistant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallRecord {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Hex-encoded SHA-256 hash. 64 ASCII chars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HashHex(pub String);

impl HashHex {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(hex_encode(bytes))
    }
}

/// Hex-encoded arbitrary-length byte string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexBytes(pub String);

impl HexBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(bytes))
    }
}

// ---------------------------------------------------------------------------
// Stored row
// ---------------------------------------------------------------------------

/// A row from `session_events` returned by query methods.
#[derive(Debug, Clone)]
pub struct StoredSessionEvent {
    pub id: i64,
    pub session_id: SessionId,
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub trust: TrustLevel,
    pub event: SessionEvent,
    pub leaf_hash: HashHex,
    pub prev_hash: HashHex,
    pub hash: HashHex,
}

// ---------------------------------------------------------------------------
// Verify result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerifyResult {
    Ok {
        rows_verified: usize,
    },
    Empty,
    /// The chain broke at `seq`. `expected_hash` and `actual_hash`
    /// are the two values that disagreed (which two specifically
    /// depends on the kind of break — prev_hash, leaf_hash, or chain
    /// hash mismatch — but consumers receive them as opaque strings).
    /// `verified_count` is the number of events in this session that
    /// verified before the break.
    Broken {
        seq: u64,
        expected_hash: String,
        actual_hash: String,
        verified_count: u64,
    },
}

/// Per-session signature-verification result. Pulled out from the
/// chain-only [`SessionVerifyResult`] so the chain check stays
/// composable with the existing verifier shape and a signature pass
/// is a separate, additive method on [`SqliteSessionLog`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSignatureVerifyResult {
    /// Number of `ChainHead` rows in this session whose Ed25519
    /// signature verified against the embedded `signing_key_id`.
    pub signed_heads_count: usize,
    /// Number of `ChainHead` rows whose claimed
    /// `current_chain_hash` matched the actual stored chain hash at
    /// `sequence_range_end`. Always equal to `signed_heads_count`
    /// in the success case; tracked separately so a future audit
    /// can distinguish a signature-only break from a hash-claim
    /// break.
    pub matched_heads_count: usize,
    /// Hex-encoded distinct signing keys observed in this session,
    /// sorted ascending. Used to surface key rotation in the
    /// aggregate verifier output.
    pub signing_key_ids_seen: Vec<String>,
    /// Last `sequence_range_end` covered by a signed head, or
    /// `None` when this session has no `ChainHead` rows.
    pub last_head_end_seq: Option<u64>,
    /// Sequence number of the last `ChainHead` row itself, or
    /// `None` when this session has no `ChainHead` rows.
    pub last_head_seq: Option<u64>,
    /// Number of rows after the last signed head. Zero when the
    /// last row in the session is a `ChainHead`.
    pub unsigned_tail_len: usize,
    /// Total rows in the session.
    pub session_total_events: usize,
    /// First invalid signature observed, if any. The session-level
    /// caller treats any invalid signature as a hard fail.
    pub first_invalid: Option<InvalidSignatureDetail>,
}

/// Details of the first invalid `ChainHead` signature in a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSignatureDetail {
    /// `seq` of the offending `ChainHead` row.
    pub seq: u64,
    /// Hex-encoded `signing_key_id` from the row.
    pub signing_key_id: String,
    /// Short reason: bad signature, mismatched current_chain_hash,
    /// mismatched prev_chain_hash, malformed key, schema mismatch.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Read/write API for the session log. Slice 1 only takes
/// `SessionHandle<OwnSession>` — future scopes will plug in by adding
/// generic methods or scope-specific traits.
pub trait SessionLog: Send + Sync {
    /// Mint a handle for `id`. Anyone with a `SessionLog` reference
    /// can mint a handle for any id — the security claim is that
    /// `SessionLog` references are not handed to untrusted code, not
    /// that the constructor is locked.
    fn handle_for(&self, id: SessionId) -> SessionHandle<OwnSession>;

    /// Append an event. Returns the new sequence number for this
    /// session, starting from 0.
    fn append(
        &self,
        handle: &SessionHandle<OwnSession>,
        trust: TrustLevel,
        event: SessionEvent,
    ) -> Result<u64, AuditError>;

    /// Read a half-open range of events `[start, end)` by sequence.
    /// Returns rows ordered ascending by `seq`.
    fn get_range(
        &self,
        handle: &SessionHandle<OwnSession>,
        range: Range<u64>,
    ) -> Result<Vec<StoredSessionEvent>, AuditError>;

    /// Read all events from `start` (inclusive) to the end of the
    /// session.
    fn get_since(
        &self,
        handle: &SessionHandle<OwnSession>,
        start: u64,
    ) -> Result<Vec<StoredSessionEvent>, AuditError>;

    /// The highest sequence number in this session, or `None` if
    /// the session has no events.
    fn last_index(&self, handle: &SessionHandle<OwnSession>) -> Result<Option<u64>, AuditError>;

    /// Delete the most recent `n_before` events from this session
    /// and append a [`SessionEvent::Rewind`] audit marker so the
    /// operation is not a silent delete. Returns the count of rows
    /// actually deleted by the DELETE — the Rewind marker itself is
    /// appended afterwards and is not included in the count.
    ///
    /// `reason` is stored verbatim in the Rewind event payload.
    /// Callers should use a short, stable string ("crash_recovery",
    /// "user_undo", etc.) rather than free-form text so reviewers can
    /// filter the log.
    ///
    /// No Rewind event is appended when the call is a no-op
    /// (`n_before == 0`, or the session has no events). In that case
    /// the session log is untouched.
    fn rewind(
        &self,
        handle: &SessionHandle<OwnSession>,
        n_before: u64,
        reason: &str,
    ) -> Result<u64, AuditError>;

    /// Walk the per-session hash chain and verify every row's
    /// `leaf_hash` matches its payload and every row's chain `hash`
    /// matches `SHA-256(prev_hash || leaf_hash)`. Returns
    /// [`SessionVerifyResult::Ok`] for an intact chain,
    /// [`SessionVerifyResult::Broken`] at the first mismatch, or
    /// [`SessionVerifyResult::Empty`] for a session with no events.
    fn verify(&self, handle: &SessionHandle<OwnSession>)
    -> Result<SessionVerifyResult, AuditError>;
}

/// A flattened `PermissionDenied` event, tagged with its session
/// and sequence so operators can correlate against the session log.
#[derive(Debug, Clone)]
pub struct PermissionDenialRecord {
    pub session_id: String,
    pub seq: u64,
    pub ts: String,
    pub tool: String,
    pub action_key: String,
    pub denial_source: DenialSource,
    pub tier: Option<String>,
    pub trigger: Option<String>,
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

/// Per-session counters that drive the chain-head checkpoint cadence.
/// One entry per session id this log has appended to since open.
#[derive(Debug, Clone, Copy)]
struct SessionCheckpointState {
    /// Wall clock when the most recent ChainHead for this session was
    /// emitted. Set at session-start so the 5-minute window starts on
    /// the first append, not on `Utc::now()` of `open`.
    last_head_ts: DateTime<Utc>,
    /// Count of ordinary appends (any variant other than ChainHead)
    /// since the most recent ChainHead. Reset to zero each time a
    /// ChainHead lands.
    appends_since_head: u64,
    /// Sequence at which the most recent ChainHead landed, or
    /// [`SeqRangeStart::Pending`] when no head has been written yet.
    last_head_seq: SeqRangeStart,
}

/// Sequence range start tracking. Distinguishes the initial state
/// (no ChainHead emitted yet, the next head covers from seq 0) from
/// the post-emission state (next head covers from `seq + 1`).
#[derive(Debug, Clone, Copy)]
enum SeqRangeStart {
    /// No ChainHead has been written for this session in this
    /// process lifetime. The next head's sequence range starts at 0.
    Pending,
    /// A ChainHead has been written. The next head covers from
    /// `seq + 1`.
    AtSeq(u64),
}

/// Default checkpoint cadence: emit a ChainHead after this many
/// ordinary appends since the last head, even when wall-clock has
/// not elapsed.
const CHECKPOINT_APPENDS: u64 = 1000;

/// Default checkpoint cadence: emit a ChainHead after this much
/// wall-clock has elapsed since the last head, even on a quiet
/// session.
const CHECKPOINT_WALL_CLOCK_SECS: i64 = 5 * 60;

/// SQLite-backed [`SessionLog`]. Uses WAL mode and an interior
/// `Mutex<Connection>` to allow `&self` access from multiple threads.
pub struct SqliteSessionLog {
    conn: Mutex<Connection>,
    /// Optional gateway-keyed audit signer. When `Some`, ChainHead
    /// records are emitted automatically at session boundaries and
    /// on the cadence defined by [`CHECKPOINT_APPENDS`] /
    /// [`CHECKPOINT_WALL_CLOCK_SECS`]. When `None`, ChainHead
    /// emission is opt-in via [`SqliteSessionLog::emit_chain_head`].
    signer: Option<Arc<AuditSigningKey>>,
    /// Per-session checkpoint state. Holds the cadence counters that
    /// decide whether the post-append path emits a ChainHead.
    checkpoint_state: Mutex<HashMap<String, SessionCheckpointState>>,
}

impl SqliteSessionLog {
    /// Open or create a session log at `db_path`. Creates the
    /// `session_events` table if it does not exist. On unix, when the
    /// file is created here, it is created with mode 0o600 — SQLite's
    /// `Connection::open` does not honor a custom umask/mode, so the
    /// file is pre-created with `OpenOptions::mode(0o600)` first.
    pub fn open(db_path: &Path) -> Result<Self, AuditError> {
        Self::open_inner(db_path, None)
    }

    /// Open or create a session log at `db_path` with an audit
    /// signing key. ChainHead records are emitted at session
    /// boundaries (first append in a fresh session, explicit
    /// [`SqliteSessionLog::emit_chain_head`] calls) and on the
    /// checkpoint cadence (every 1000 appends or 5 minutes of
    /// wall-clock since the last head, whichever comes first).
    pub fn open_with_signer(
        db_path: &Path,
        signer: Arc<AuditSigningKey>,
    ) -> Result<Self, AuditError> {
        Self::open_inner(db_path, Some(signer))
    }

    fn open_inner(
        db_path: &Path,
        signer: Option<Arc<AuditSigningKey>>,
    ) -> Result<Self, AuditError> {
        precreate_owner_only(db_path)?;
        // SQLite WAL mode also creates `-wal` and `-shm` sidecar files
        // alongside the database. They contain pages in flight and must
        // share the database's confidentiality posture; pre-create them
        // at 0o600 so SQLite reuses our handle rather than creating its
        // own with default umask permissions.
        precreate_owner_only(&with_suffix(db_path, "-wal"))?;
        precreate_owner_only(&with_suffix(db_path, "-shm"))?;
        let conn = Connection::open(db_path)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            signer,
            checkpoint_state: Mutex::new(HashMap::new()),
        })
    }

    /// Open an in-memory session log (test helper).
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            signer: None,
            checkpoint_state: Mutex::new(HashMap::new()),
        })
    }

    /// In-memory session log with an audit signing key (test helper).
    pub fn open_in_memory_with_signer(signer: Arc<AuditSigningKey>) -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            signer: Some(signer),
            checkpoint_state: Mutex::new(HashMap::new()),
        })
    }

    /// Emit a `ChainHead` event for `handle` with the given reason.
    /// Returns the sequence number of the appended ChainHead, or
    /// `None` when this log has no signer configured (callers that
    /// expect signed heads should hold an `Arc<AuditSigningKey>`
    /// already, so observing `None` here is a configuration bug
    /// rather than a runtime condition).
    ///
    /// Idempotent only with respect to its own row: calling twice
    /// in a row writes two ChainHead rows. Callers that want
    /// "emit-if-not-just-emitted" semantics should track that
    /// state themselves.
    pub fn emit_chain_head(
        &self,
        handle: &SessionHandle<OwnSession>,
        reason: ChainHeadReason,
    ) -> Result<Option<u64>, AuditError> {
        let signer = match self.signer.as_ref() {
            Some(s) => s.clone(),
            None => return Ok(None),
        };
        let conn = self.conn.lock().expect("session log mutex");
        let seq = self.append_chain_head_locked(&conn, handle, reason, &signer)?;
        Ok(Some(seq))
    }

    /// Internal: compose and insert a ChainHead row inside the
    /// caller's connection lock. Updates the checkpoint state on
    /// success.
    fn append_chain_head_locked(
        &self,
        conn: &Connection,
        handle: &SessionHandle<OwnSession>,
        reason: ChainHeadReason,
        signer: &AuditSigningKey,
    ) -> Result<u64, AuditError> {
        // Snapshot the current chain state. The ChainHead covers the
        // range from `last_head_seq + 1` (or 0) up to the current
        // session head. `current_chain_hash` is the chain hash at
        // that head; `prev_chain_hash` is the chain hash at the row
        // immediately before the range start, or empty for the very
        // first head.
        let last_seq: Option<i64> = conn
            .query_row(
                "SELECT MAX(seq) FROM session_events WHERE session_id = ?1",
                params![handle.id.as_str()],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        let last_seq = last_seq.map(|n| n as u64);

        let state = self.read_checkpoint_state(handle.id.as_str());
        let range_start = match state.last_head_seq {
            SeqRangeStart::Pending => 0u64,
            SeqRangeStart::AtSeq(s) => s + 1,
        };

        let (range_end, current_chain_hash) = match last_seq {
            Some(s) => {
                let h: String = conn.query_row(
                    "SELECT hash FROM session_events
                     WHERE session_id = ?1 AND seq = ?2",
                    params![handle.id.as_str(), s as i64],
                    |row| row.get(0),
                )?;
                (s, h)
            }
            None => {
                // The session has no rows yet. Emit a ChainHead at
                // seq 0 covering the empty range. `current_chain_hash`
                // is the empty string; signature still binds the
                // schema_version + reason context.
                (0u64, String::new())
            }
        };

        let prev_chain_hash = if range_start == 0 {
            String::new()
        } else {
            // chain hash at the row immediately before the new head's
            // covered range. This is the chain hash recorded on the
            // previous ChainHead row, by construction.
            conn.query_row(
                "SELECT hash FROM session_events
                 WHERE session_id = ?1 AND seq = ?2",
                params![handle.id.as_str(), (range_start - 1) as i64],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_default()
        };

        let sig = signer.sign_chain_head(
            (range_start, range_end),
            &prev_chain_hash,
            &current_chain_hash,
        );

        let event = SessionEvent::ChainHead {
            reason,
            sequence_range_start: range_start,
            sequence_range_end: range_end,
            prev_chain_hash: HashHex(prev_chain_hash),
            current_chain_hash: HashHex(current_chain_hash),
            signature: HexBytes::from_bytes(&sig.to_bytes()),
            signing_pubkey: HashHex(signer.key_id_hex()),
            schema_version: CHAIN_HEAD_SCHEMA_VERSION,
        };

        let next_seq = append_inner(conn, handle, TrustLevel::System, event, None)?;
        self.update_checkpoint_state(handle.id.as_str(), next_seq, Utc::now());
        Ok(next_seq)
    }

    fn read_checkpoint_state(&self, session_id: &str) -> SessionCheckpointState {
        let map = self
            .checkpoint_state
            .lock()
            .expect("checkpoint state mutex");
        map.get(session_id)
            .copied()
            .unwrap_or(SessionCheckpointState {
                last_head_ts: Utc::now(),
                appends_since_head: 0,
                last_head_seq: SeqRangeStart::Pending,
            })
    }

    fn update_checkpoint_state(&self, session_id: &str, head_seq: u64, ts: DateTime<Utc>) {
        let mut map = self
            .checkpoint_state
            .lock()
            .expect("checkpoint state mutex");
        map.insert(
            session_id.to_string(),
            SessionCheckpointState {
                last_head_ts: ts,
                appends_since_head: 0,
                last_head_seq: SeqRangeStart::AtSeq(head_seq),
            },
        );
    }

    fn bump_appends_since_head(&self, session_id: &str) {
        let mut map = self
            .checkpoint_state
            .lock()
            .expect("checkpoint state mutex");
        let entry = map
            .entry(session_id.to_string())
            .or_insert(SessionCheckpointState {
                last_head_ts: Utc::now(),
                appends_since_head: 0,
                last_head_seq: SeqRangeStart::Pending,
            });
        entry.appends_since_head = entry.appends_since_head.saturating_add(1);
    }

    /// Decide whether the post-append cadence has tripped and
    /// returns a reason if it has. Pure read of state plus a clock
    /// check; the caller mutates state via the emission path.
    fn checkpoint_due(&self, session_id: &str, now: DateTime<Utc>) -> Option<ChainHeadReason> {
        let state = self.read_checkpoint_state(session_id);
        let elapsed = (now - state.last_head_ts).num_seconds();
        if state.appends_since_head >= CHECKPOINT_APPENDS || elapsed >= CHECKPOINT_WALL_CLOCK_SECS {
            return Some(ChainHeadReason::Checkpoint);
        }
        None
    }

    /// Detect a fresh session at append time. A session is fresh when
    /// the in-memory checkpoint state has no entry for it AND the
    /// underlying table has no rows. Both conditions are required:
    /// in-memory absence alone fires on every gateway restart, which
    /// would emit duplicate SessionStart heads.
    fn is_session_start(&self, conn: &Connection, session_id: &str) -> bool {
        let map = self
            .checkpoint_state
            .lock()
            .expect("checkpoint state mutex");
        if map.contains_key(session_id) {
            return false;
        }
        drop(map);
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM session_events WHERE session_id = ?1 LIMIT 1",
                params![session_id],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        exists.is_none()
    }

    /// Test-only access to the inner connection. Used by tampering
    /// tests that need to corrupt rows without going through the
    /// public API.
    #[cfg(test)]
    pub(crate) fn raw_conn_for_test(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Test-only: backdate a session's last_head_ts so the
    /// wall-clock checkpoint trigger fires on the next append even
    /// when the per-append counter is well below 1000. Used by the
    /// regression test that exercises the elapsed-time path of the
    /// cadence independently of the append-count path.
    #[cfg(test)]
    pub(crate) fn backdate_checkpoint_for_test(&self, session_id: &str, secs_ago: i64) {
        let mut map = self
            .checkpoint_state
            .lock()
            .expect("checkpoint state mutex");
        if let Some(state) = map.get_mut(session_id) {
            state.last_head_ts = Utc::now() - chrono::Duration::seconds(secs_ago);
        }
    }

    /// Walk this session and verify every `ChainHead` signature.
    /// Builds the canonical signed message from each `ChainHead`'s
    /// claimed sequence range and chain hashes, then checks the
    /// embedded signature with the embedded `signing_key_id`. Also
    /// confirms the `current_chain_hash` claim matches the stored
    /// chain hash at the row at `sequence_range_end`, and the
    /// `prev_chain_hash` claim matches the stored hash at
    /// `sequence_range_start - 1` (or empty when start is 0).
    ///
    /// Returns aggregated counts, the set of distinct signing key
    /// ids observed, and the unsigned-tail length. The first
    /// invalid signature short-circuits the walk and is reported in
    /// `first_invalid` with a verdict reason.
    pub fn verify_signatures(
        &self,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<SessionSignatureVerifyResult, AuditError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let rows = self.session_rows(handle)?;
        let total = rows.len();
        let mut result = SessionSignatureVerifyResult {
            session_total_events: total,
            ..Default::default()
        };
        if rows.is_empty() {
            return Ok(result);
        }

        let mut last_head_idx: Option<usize> = None;
        let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for (idx, row) in rows.iter().enumerate() {
            let SessionEvent::ChainHead {
                sequence_range_start,
                sequence_range_end,
                prev_chain_hash,
                current_chain_hash,
                signature,
                signing_pubkey: signing_key_id,
                schema_version,
                ..
            } = &row.event
            else {
                continue;
            };

            if *schema_version != crate::signing::CHAIN_HEAD_SCHEMA_VERSION {
                result.first_invalid = Some(InvalidSignatureDetail {
                    seq: row.seq,
                    signing_key_id: signing_key_id.0.clone(),
                    reason: format!(
                        "chain head schema_version {} != verifier {}",
                        schema_version,
                        crate::signing::CHAIN_HEAD_SCHEMA_VERSION
                    ),
                });
                return Ok(result);
            }

            // current_chain_hash must match stored hash at sequence_range_end
            // (or be empty when the session was empty at head time).
            let actual_current = rows
                .iter()
                .find(|r| r.seq == *sequence_range_end)
                .map(|r| r.hash.0.clone())
                .unwrap_or_default();
            if !current_chain_hash.0.is_empty() && current_chain_hash.0 != actual_current {
                result.first_invalid = Some(InvalidSignatureDetail {
                    seq: row.seq,
                    signing_key_id: signing_key_id.0.clone(),
                    reason: format!(
                        "current_chain_hash claim {} does not match stored hash {} at seq {}",
                        current_chain_hash.0, actual_current, sequence_range_end
                    ),
                });
                return Ok(result);
            }

            // prev_chain_hash must match stored hash at start - 1, or be
            // empty when the head covers from seq 0.
            if *sequence_range_start == 0 {
                if !prev_chain_hash.0.is_empty() {
                    result.first_invalid = Some(InvalidSignatureDetail {
                        seq: row.seq,
                        signing_key_id: signing_key_id.0.clone(),
                        reason: "prev_chain_hash must be empty when sequence_range_start is 0"
                            .into(),
                    });
                    return Ok(result);
                }
            } else {
                let prev_seq = sequence_range_start - 1;
                let actual_prev = rows
                    .iter()
                    .find(|r| r.seq == prev_seq)
                    .map(|r| r.hash.0.clone())
                    .unwrap_or_default();
                if prev_chain_hash.0 != actual_prev {
                    result.first_invalid = Some(InvalidSignatureDetail {
                        seq: row.seq,
                        signing_key_id: signing_key_id.0.clone(),
                        reason: format!(
                            "prev_chain_hash claim {} does not match stored hash {} at seq {}",
                            prev_chain_hash.0, actual_prev, prev_seq
                        ),
                    });
                    return Ok(result);
                }
            }

            // Decode the signing key and signature.
            let pk_bytes = match decode_hex(&signing_key_id.0) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    result.first_invalid = Some(InvalidSignatureDetail {
                        seq: row.seq,
                        signing_key_id: signing_key_id.0.clone(),
                        reason: "signing_key_id is not 32 bytes of hex".into(),
                    });
                    return Ok(result);
                }
            };
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
                Ok(k) => k,
                Err(e) => {
                    result.first_invalid = Some(InvalidSignatureDetail {
                        seq: row.seq,
                        signing_key_id: signing_key_id.0.clone(),
                        reason: format!("signing_key_id decode: {e}"),
                    });
                    return Ok(result);
                }
            };

            let sig_bytes = match decode_hex(&signature.0) {
                Ok(b) if b.len() == 64 => b,
                _ => {
                    result.first_invalid = Some(InvalidSignatureDetail {
                        seq: row.seq,
                        signing_key_id: signing_key_id.0.clone(),
                        reason: "signature is not 64 bytes of hex".into(),
                    });
                    return Ok(result);
                }
            };
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);
            let sig = Signature::from_bytes(&sig_arr);

            let payload = crate::signing::build_signed_message(
                (*sequence_range_start, *sequence_range_end),
                &prev_chain_hash.0,
                &current_chain_hash.0,
                *schema_version,
            );
            if verifying_key.verify(&payload, &sig).is_err() {
                result.first_invalid = Some(InvalidSignatureDetail {
                    seq: row.seq,
                    signing_key_id: signing_key_id.0.clone(),
                    reason: "ed25519 chain head signature did not verify".into(),
                });
                return Ok(result);
            }

            result.signed_heads_count += 1;
            result.matched_heads_count += 1;
            keys.insert(signing_key_id.0.clone());
            last_head_idx = Some(idx);
            result.last_head_seq = Some(row.seq);
            result.last_head_end_seq = Some(*sequence_range_end);
        }

        result.signing_key_ids_seen = keys.into_iter().collect();
        result.unsigned_tail_len = match last_head_idx {
            Some(i) => total.saturating_sub(i + 1),
            None => total,
        };
        Ok(result)
    }

    fn session_rows(
        &self,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<Vec<StoredSessionEvent>, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        let raw = collect_rows(
            &conn,
            "SELECT id, session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash
             FROM session_events
             WHERE session_id = ?1
             ORDER BY seq ASC",
            params![handle.id.as_str()],
        )?;
        raw.into_iter().map(parse_row).collect()
    }

    /// Scan every session for `PermissionDenied` events belonging to
    /// `agent_id`. Returns one row per stored event, most recent
    /// first. Used by `wirken permissions list-pending` to build its
    /// view of denials that may want an approval. Scans are linear
    /// in the size of the log; the caller is expected to run this
    /// interactively, not on a hot path.
    pub fn find_permission_denials(&self, agent_id: &str) -> Vec<PermissionDenialRecord> {
        let conn = self.conn.lock().expect("session log mutex");
        let mut stmt = match conn.prepare(
            "SELECT session_id, seq, ts, payload FROM session_events
             WHERE payload LIKE '%\"PermissionDenied\"%'
             ORDER BY ts DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows: Vec<(String, u64, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map(|iter| iter.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();

        rows.into_iter()
            .filter_map(|(session_id, seq, ts, payload)| {
                let event: SessionEvent = serde_json::from_str(&payload).ok()?;
                match event {
                    SessionEvent::PermissionDenied {
                        tool,
                        action_key,
                        denial_source,
                        tier,
                        agent_id: ev_agent,
                        trigger,
                        ..
                    } if ev_agent == agent_id => Some(PermissionDenialRecord {
                        session_id,
                        seq,
                        ts,
                        tool,
                        action_key,
                        denial_source,
                        tier,
                        trigger,
                    }),
                    _ => None,
                }
            })
            .collect()
    }

    /// Distinct session ids present in `session_events`, ordered
    /// ascending. Used at gateway shutdown to enumerate which
    /// sessions need a `SessionEnd` chain head before flush.
    pub fn list_session_ids(&self) -> Result<Vec<String>, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        let mut stmt =
            conn.prepare("SELECT DISTINCT session_id FROM session_events ORDER BY session_id ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Item 6 slice 2: list child session IDs whose session_id
    /// starts with `{parent_id}#sub-`. Returns distinct session IDs
    /// in ascending order. Used by `wirken sessions list --parent`.
    pub fn list_child_sessions(&self, parent_id: &str) -> Vec<String> {
        let prefix = format!("{parent_id}#sub-");
        let conn = self.conn.lock().expect("session log mutex");
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT session_id FROM session_events
                 WHERE session_id LIKE ?1
                 ORDER BY session_id ASC",
            )
            .unwrap_or_else(|e| panic!("prepare list_child_sessions: {e}"));
        let pattern = format!("{prefix}%");
        stmt.query_map(params![pattern], |row| row.get::<_, String>(0))
            .unwrap_or_else(|e| panic!("query list_child_sessions: {e}"))
            .filter_map(|r| r.ok())
            .collect()
    }

    /// Crate-private accessor for code that needs raw SQL access to
    /// the same underlying connection. Used by `legacy_compat` to
    /// run the SIEM view query, the global verify, and the prune.
    /// External crates have no business calling this — every
    /// supported operation goes through the [`SessionLog`] trait.
    pub(crate) fn with_conn<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Connection) -> R,
    {
        let conn = self.conn.lock().expect("session log mutex");
        f(&conn)
    }

    /// Append an event with a caller-supplied timestamp. Used by
    /// [`crate::legacy_compat`] to preserve the original
    /// `audit_events.ts` values when wrapping legacy events. Live
    /// flushes also reach this through `write_legacy`, so the
    /// chain-head cadence applies here too.
    pub(crate) fn append_with_ts(
        &self,
        handle: &SessionHandle<OwnSession>,
        trust: TrustLevel,
        event: SessionEvent,
        ts: DateTime<Utc>,
    ) -> Result<u64, AuditError> {
        self.append_with_cadence(handle, trust, event, Some(ts))
    }

    /// Shared body for the public append paths. Wraps `append_inner`
    /// with chain-head cadence: emits a `SessionStart` head when the
    /// event is the first row in a fresh session, and a `Checkpoint`
    /// head when the per-session cadence trips.
    fn append_with_cadence(
        &self,
        handle: &SessionHandle<OwnSession>,
        trust: TrustLevel,
        event: SessionEvent,
        ts_override: Option<DateTime<Utc>>,
    ) -> Result<u64, AuditError> {
        // Skip cadence on incoming ChainHead events. The caller is
        // already driving emission; layering another head on top
        // would diverge from the canonical "head every N or T,
        // whichever comes first" cadence.
        let is_chain_head = matches!(event, SessionEvent::ChainHead { .. });

        let conn = self.conn.lock().expect("session log mutex");

        let session_id = handle.id.as_str().to_string();
        let fresh =
            !is_chain_head && self.signer.is_some() && self.is_session_start(&conn, &session_id);

        let next_seq = append_inner(&conn, handle, trust, event, ts_override)?;
        if !is_chain_head {
            self.bump_appends_since_head(&session_id);
        }

        if let Some(signer) = self.signer.clone() {
            if fresh {
                self.append_chain_head_locked(
                    &conn,
                    handle,
                    ChainHeadReason::SessionStart,
                    &signer,
                )?;
            } else if !is_chain_head
                && let Some(reason) = self.checkpoint_due(&session_id, Utc::now())
            {
                self.append_chain_head_locked(&conn, handle, reason, &signer)?;
            }
        }

        Ok(next_seq)
    }

    fn init_schema(conn: &Connection) -> Result<(), AuditError> {
        // Pragmas are per-connection. Every `SqliteSessionLog::open`
        // — including each reopen inside `AuditWriter::flush` every
        // 50ms — MUST set them, or the connection falls back to the
        // SQLite defaults (`DELETE` journal, no busy-wait) and
        // concurrent writers immediately fail with `SQLITE_BUSY`
        // ("database is locked") instead of serializing on the write
        // lock. WAL lets concurrent readers through and keeps a
        // single logical writer at a time; `busy_timeout` gives
        // contending writers a 5-second window to wait for their
        // turn rather than erroring to the caller on the first miss.
        //
        // `synchronous=NORMAL` is the SQLite-recommended pairing
        // with WAL — still fsyncs the WAL on checkpoint but not on
        // every transaction, which is where we need the throughput
        // for the flush path that writes in 50 ms batches.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS session_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 ts TEXT NOT NULL,
                 trust TEXT NOT NULL,
                 payload TEXT NOT NULL,
                 leaf_hash TEXT NOT NULL,
                 prev_hash TEXT NOT NULL,
                 hash TEXT NOT NULL,
                 UNIQUE(session_id, seq)
             );
             CREATE INDEX IF NOT EXISTS idx_session_events_session_seq
                 ON session_events(session_id, seq);
             CREATE INDEX IF NOT EXISTS idx_session_events_session_ts
                 ON session_events(session_id, ts);",
        )?;
        Ok(())
    }
}

impl SessionLog for SqliteSessionLog {
    fn handle_for(&self, id: SessionId) -> SessionHandle<OwnSession> {
        SessionHandle::new(id)
    }

    fn append(
        &self,
        handle: &SessionHandle<OwnSession>,
        trust: TrustLevel,
        event: SessionEvent,
    ) -> Result<u64, AuditError> {
        self.append_with_cadence(handle, trust, event, None)
    }

    fn get_range(
        &self,
        handle: &SessionHandle<OwnSession>,
        range: Range<u64>,
    ) -> Result<Vec<StoredSessionEvent>, AuditError> {
        if range.start >= range.end {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().expect("session log mutex");
        let raw = collect_rows(
            &conn,
            "SELECT id, session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash
             FROM session_events
             WHERE session_id = ?1 AND seq >= ?2 AND seq < ?3
             ORDER BY seq ASC",
            params![handle.id.as_str(), range.start as i64, range.end as i64],
        )?;
        raw.into_iter().map(parse_row).collect()
    }

    fn get_since(
        &self,
        handle: &SessionHandle<OwnSession>,
        start: u64,
    ) -> Result<Vec<StoredSessionEvent>, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        let raw = collect_rows(
            &conn,
            "SELECT id, session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash
             FROM session_events
             WHERE session_id = ?1 AND seq >= ?2
             ORDER BY seq ASC",
            params![handle.id.as_str(), start as i64],
        )?;
        raw.into_iter().map(parse_row).collect()
    }

    fn last_index(&self, handle: &SessionHandle<OwnSession>) -> Result<Option<u64>, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        let result: Option<i64> = conn
            .query_row(
                "SELECT MAX(seq) FROM session_events WHERE session_id = ?1",
                params![handle.id.as_str()],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        Ok(result.map(|n| n as u64))
    }

    fn rewind(
        &self,
        handle: &SessionHandle<OwnSession>,
        n_before: u64,
        reason: &str,
    ) -> Result<u64, AuditError> {
        if n_before == 0 {
            return Ok(0);
        }

        // Phase 1: look up the current chain head and DELETE the
        // tail under a single connection lock. We release it before
        // calling `append` so the Rewind event reuses the same
        // per-session lock via the public append path.
        let (old_last_seq, deleted) = {
            let conn = self.conn.lock().expect("session log mutex");
            let last: Option<i64> = conn
                .query_row(
                    "SELECT MAX(seq) FROM session_events WHERE session_id = ?1",
                    params![handle.id.as_str()],
                    |row| row.get(0),
                )
                .ok()
                .flatten();
            let last = match last {
                Some(n) => n as u64,
                None => return Ok(0),
            };
            let cutoff = last.saturating_sub(n_before - 1);
            let deleted = conn.execute(
                "DELETE FROM session_events WHERE session_id = ?1 AND seq >= ?2",
                params![handle.id.as_str(), cutoff as i64],
            )? as u64;
            (last, deleted)
        };

        // Phase 2: append the Rewind audit marker. The marker's
        // `prev_hash` picks up cleanly from whichever row survived
        // the delete (or from the empty string if everything was
        // removed), so `verify()` stays green while still recording
        // that a rewind happened.
        self.append(
            handle,
            TrustLevel::System,
            SessionEvent::Rewind {
                old_last_seq,
                deleted_count: deleted,
                reason: reason.to_string(),
            },
        )?;

        Ok(deleted)
    }

    fn verify(
        &self,
        handle: &SessionHandle<OwnSession>,
    ) -> Result<SessionVerifyResult, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        let mut stmt = conn.prepare(
            "SELECT seq, payload, leaf_hash, prev_hash, hash
             FROM session_events
             WHERE session_id = ?1
             ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![handle.id.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        let mut count = 0usize;
        let mut expected_prev = String::new();
        for row in rows {
            let (seq, payload, leaf_hash, prev_hash, stored_hash) = row?;

            if prev_hash != expected_prev {
                return Ok(SessionVerifyResult::Broken {
                    seq,
                    expected_hash: expected_prev,
                    actual_hash: prev_hash,
                    verified_count: count as u64,
                });
            }

            // Hashes the raw stored `payload` text, not a
            // deserialize-then-reserialize round-trip. This is what
            // keeps schema renames safe: an event variant can gain
            // or rename a field between versions and the leaf hash
            // on rows already on disk still verifies, because the
            // bytes that were stored at append time are the bytes
            // being rehashed here. Any future schema work can rely
            // on this; there is no migration path needed for chain
            // integrity.
            let recomputed_leaf = sha256_hex(payload.as_bytes());
            if recomputed_leaf != leaf_hash {
                return Ok(SessionVerifyResult::Broken {
                    seq,
                    expected_hash: recomputed_leaf,
                    actual_hash: leaf_hash,
                    verified_count: count as u64,
                });
            }

            let recomputed_chain = chain_hex(&prev_hash, &leaf_hash);
            if recomputed_chain != stored_hash {
                return Ok(SessionVerifyResult::Broken {
                    seq,
                    expected_hash: recomputed_chain,
                    actual_hash: stored_hash,
                    verified_count: count as u64,
                });
            }

            expected_prev = stored_hash;
            count += 1;
        }

        if count == 0 {
            Ok(SessionVerifyResult::Empty)
        } else {
            Ok(SessionVerifyResult::Ok {
                rows_verified: count,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Raw row tuple as it comes back from SQLite, before parsing the
/// payload JSON and trust label.
type RawRow = (
    i64,    // id
    String, // session_id
    i64,    // seq
    String, // ts
    String, // trust
    String, // payload
    String, // leaf_hash
    String, // prev_hash
    String, // hash
);

fn collect_rows(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<RawRow>, AuditError> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params, |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn parse_row(row: RawRow) -> Result<StoredSessionEvent, AuditError> {
    let (id, session_id, seq, ts_str, trust_str, payload, leaf_hash, prev_hash, hash) = row;
    let event: SessionEvent = serde_json::from_str(&payload)?;
    let trust = trust_from_str(&trust_str)?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map_err(|e| AuditError::SiemConfig(format!("invalid timestamp in session_events: {e}")))?
        .with_timezone(&Utc);
    Ok(StoredSessionEvent {
        id,
        session_id: SessionId(session_id),
        seq: seq as u64,
        ts,
        trust,
        event,
        leaf_hash: HashHex(leaf_hash),
        prev_hash: HashHex(prev_hash),
        hash: HashHex(hash),
    })
}

/// Canonical wire encoding for hashing. The canonical form is
/// "whatever `serde_json::to_vec` produces from the [`SessionEvent`]
/// definition in this module." Adding fields to existing variants is
/// a wire-incompatible change because old hashes will not match.
/// Internal append shared by [`SessionLog::append`] (which stamps
/// `Utc::now()`) and [`SqliteSessionLog::append_with_ts`] (which
/// preserves the caller's timestamp for migration use). The
/// transaction is opened on `conn` directly so the caller controls
/// the lock.
fn append_inner(
    conn: &Connection,
    handle: &SessionHandle<OwnSession>,
    trust: TrustLevel,
    event: SessionEvent,
    ts_override: Option<DateTime<Utc>>,
) -> Result<u64, AuditError> {
    // IMMEDIATE (not DEFERRED) so the write lock is claimed up front.
    // DEFERRED promotes read-to-write on the first INSERT, and in WAL
    // mode that upgrade path returns `SQLITE_BUSY` immediately when
    // another connection already holds the write lock — `busy_timeout`
    // only applies to the initial acquisition, not the upgrade. With
    // IMMEDIATE the timeout is effective and concurrent writers
    // serialize instead of erroring. Session-log appends are small so
    // holding the write lock for the full SELECT+INSERT is fine.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    // Compute next seq atomically inside the transaction. SQLite
    // serializes writers in WAL mode so the read-then-insert is
    // safe against concurrent appenders to the same session.
    let next_seq: u64 = {
        let max: Option<i64> = tx
            .query_row(
                "SELECT MAX(seq) FROM session_events WHERE session_id = ?1",
                params![handle.id.as_str()],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        match max {
            Some(n) => (n as u64) + 1,
            None => 0,
        }
    };

    // Previous chain hash for this session, or empty for the first
    // event.
    let prev_hash: String = tx
        .query_row(
            "SELECT hash FROM session_events
             WHERE session_id = ?1
             ORDER BY seq DESC LIMIT 1",
            params![handle.id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_default();

    let payload_bytes = canonicalize_payload(&event)?;
    let leaf_hash = sha256_hex(&payload_bytes);
    let row_hash = chain_hex(&prev_hash, &leaf_hash);
    let payload_str =
        String::from_utf8(payload_bytes).expect("serde_json output is always valid utf-8");

    let ts = ts_override.unwrap_or_else(Utc::now).to_rfc3339();
    let trust_str = trust_to_str(trust);

    tx.execute(
        "INSERT INTO session_events
             (session_id, seq, ts, trust, payload, leaf_hash, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            handle.id.as_str(),
            next_seq as i64,
            ts,
            trust_str,
            payload_str,
            leaf_hash,
            prev_hash,
            row_hash,
        ],
    )?;

    tx.commit()?;
    Ok(next_seq)
}

fn canonicalize_payload(event: &SessionEvent) -> Result<Vec<u8>, AuditError> {
    Ok(serde_json::to_vec(event)?)
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn chain_hex(prev_hash: &str, leaf_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(leaf_hash.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn trust_to_str(t: TrustLevel) -> &'static str {
    match t {
        TrustLevel::System => "system",
        TrustLevel::User => "user",
        TrustLevel::Tool => "tool",
        TrustLevel::Compaction => "compaction",
    }
}

fn trust_from_str(s: &str) -> Result<TrustLevel, AuditError> {
    match s {
        "system" => Ok(TrustLevel::System),
        "user" => Ok(TrustLevel::User),
        "tool" => Ok(TrustLevel::Tool),
        "compaction" => Ok(TrustLevel::Compaction),
        other => Err(AuditError::SiemConfig(format!(
            "unknown trust level in session_events: {other}"
        ))),
    }
}

/// Build a sibling path by appending `suffix` to `path`'s file name.
/// `with_suffix("/x/y/audit.db", "-wal")` returns `/x/y/audit.db-wal`.
fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

/// On unix, ensure `path` exists with mode 0o600 before SQLite opens
/// it. SQLite's open routine creates the file with default umask
/// permissions and does not expose a hook to change the mode at
/// creation time, so the only way to land 0o600 is to create the file
/// first ourselves and let SQLite open the existing handle. No-op on
/// non-unix; emits a warning the first time a database is opened
/// without an owner-only equivalent.
fn precreate_owner_only(path: &Path) -> Result<(), AuditError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            AuditError::SiemConfig(format!("create parent {}: {e}", parent.display()))
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => Ok(()),
            // Another opener won the race against the `path.exists()`
            // check. SQLite creates `-wal` and `-shm` sidecars on
            // every WAL-mode connection, so concurrent gateway
            // components (the AuditWriter's flush loop and the
            // typed-event forwarder both open the audit db at
            // startup) routinely race here. Treat the loss as
            // success after re-stat'ing the mode and chmod'ing
            // down if the winner didn't land 0o600.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure_owner_only_perms(path)
            }
            Err(e) => Err(AuditError::SiemConfig(format!(
                "create {}: {e}",
                path.display()
            ))),
        }
    }
    #[cfg(not(unix))]
    {
        tracing::warn!(
            "creating audit database at {} without 0o600-equivalent file permissions; \
             relying on user profile isolation for confidentiality",
            path.display()
        );
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(AuditError::SiemConfig(format!(
                "create {}: {e}",
                path.display()
            ))),
        }
    }
}

/// Stat `path` and chmod to 0o600 if it isn't already. Used by
/// [`precreate_owner_only`] when another caller won the create race;
/// our 0o600-or-else guarantee still has to hold against whatever
/// mode the winner created the file with (in practice SQLite creates
/// WAL/SHM sidecars at the process umask, which is typically 0o644).
#[cfg(unix)]
fn ensure_owner_only_perms(path: &Path) -> Result<(), AuditError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| AuditError::SiemConfig(format!("stat {}: {e}", path.display())))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AuditError::SiemConfig(format!("chmod 0o600 {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod precreate_perms_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn precreate_handles_existing_file_with_wrong_mode() {
        // Direct test of `ensure_owner_only_perms`: drop a 0o644
        // file at the target path, then call precreate. The
        // path.exists() early-return covers the file-already-there
        // case; this test verifies the chmod path that
        // `precreate_owner_only`'s race-loss branch relies on.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("audit.db-wal");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        ensure_owner_only_perms(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "race-loss branch must chmod down to 0o600");
    }

    #[test]
    fn precreate_owner_only_concurrent_calls_all_succeed() {
        // Race-condition coverage: spawn N threads that all call
        // `precreate_owner_only` against the same fresh path. Without
        // the AlreadyExists handling on `create_new`, the losing
        // threads return Err and the gateway's flush_loop or typed
        // forwarder exits at startup. With the fix, every thread
        // returns Ok and the file ends up at 0o600 regardless of
        // who won the create.
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::thread;

        let tmp = TempDir::new().unwrap();
        let path = Arc::new(tmp.path().join("audit.db-wal"));
        let barrier = Arc::new(Barrier::new(16));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let p = Arc::clone(&path);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                precreate_owner_only(&p)
            }));
        }
        for h in handles {
            h.join()
                .unwrap()
                .expect("every concurrent precreate must return Ok");
        }
        let mode = std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn open_lands_0o600_on_db_and_wal_and_shm_after_first_transaction() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = SqliteSessionLog::open(&db_path).unwrap();

        // Force a write so SQLite materializes the WAL/SHM files. The
        // schema-init runs in `open` but the WAL/SHM sidecars are not
        // necessarily fully populated until a real transaction commits.
        let h = log.handle_for(SessionId::new("perm-test"));
        log.append(
            &h,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "hi".into(),
                inbound_id: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();

        for suffix in ["", "-wal", "-shm"] {
            let p = with_suffix(&db_path, suffix);
            if !p.exists() {
                continue;
            }
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{}: expected 0o600, got 0o{mode:o}",
                p.display()
            );
        }
    }
}

#[cfg(test)]
mod audit_legacy_deserialize_tests {
    //! Regression tests for the `actor_kind` deserialization gap
    //! that halted the audit writer on 1.5.1 first-run against an
    //! existing audit.db. Pre-1.2.0 rows lacked `actor_kind`; the
    //! variant declared it without a default, so chain verification
    //! failed with `serialization error: missing field actor_kind`
    //! after three flushes.
    //!
    //! The fix makes `actor_kind` default to `Service` and aliases
    //! `actor_id` to accept the pre-split `actor` field. These tests
    //! pin both shapes against the same `SessionEvent` deserializer
    //! the live writer uses.

    use super::SessionEvent;
    use crate::event::ActorKind;

    #[test]
    fn deserializes_legacy_row_missing_actor_kind() {
        let payload = r#"{
            "kind": "audit_legacy",
            "actor_id": "alice",
            "action": "exec",
            "target": "ls",
            "detail": {}
        }"#;
        let event: SessionEvent =
            serde_json::from_str(payload).expect("legacy row must deserialize");
        match event {
            SessionEvent::AuditLegacy {
                actor_kind,
                actor_id,
                action,
                ..
            } => {
                assert_eq!(actor_kind, ActorKind::Service);
                assert_eq!(actor_id, "alice");
                assert_eq!(action, "exec");
            }
            other => panic!("expected AuditLegacy, got {other:?}"),
        }
    }

    #[test]
    fn deserializes_pre_split_row_with_actor_field() {
        // Pre-1.2.0 wire shape: single `actor` string, no
        // `actor_kind`. The alias on actor_id picks up the value;
        // actor_kind defaults to Service.
        let payload = r#"{
            "kind": "audit_legacy",
            "actor": "gateway",
            "action": "channel.open",
            "target": "slack",
            "detail": {}
        }"#;
        let event: SessionEvent =
            serde_json::from_str(payload).expect("pre-split row must deserialize");
        match event {
            SessionEvent::AuditLegacy {
                actor_kind,
                actor_id,
                ..
            } => {
                assert_eq!(actor_kind, ActorKind::Service);
                assert_eq!(actor_id, "gateway");
            }
            other => panic!("expected AuditLegacy, got {other:?}"),
        }
    }

    #[test]
    fn deserializes_post_1_2_0_row_unchanged() {
        // Pin the wire shape: rows written by 1.2.0+ with explicit
        // actor_kind + actor_id must deserialize without the default
        // or alias firing.
        let payload = r#"{
            "kind": "audit_legacy",
            "actor_kind": "user",
            "actor_id": "bob",
            "action": "message.send",
            "target": "slack",
            "channel": "slack",
            "detail": {}
        }"#;
        let event: SessionEvent =
            serde_json::from_str(payload).expect("post-1.2.0 row must deserialize");
        match event {
            SessionEvent::AuditLegacy {
                actor_kind,
                actor_id,
                channel,
                ..
            } => {
                assert_eq!(actor_kind, ActorKind::User);
                assert_eq!(actor_id, "bob");
                assert_eq!(channel.as_deref(), Some("slack"));
            }
            other => panic!("expected AuditLegacy, got {other:?}"),
        }
    }

    #[test]
    fn fully_populated_audit_legacy_roundtrips() {
        // Symmetric regression coverage: pin that a fully-populated
        // typed event survives serialize -> deserialize equal. The
        // hand-written payload tests above only confirm the
        // deserializer accepts an expected wire shape; this catches
        // the inverse failure (renamed field, dropped field on the
        // Serialize side, asymmetric alias handling) that a wire-shape
        // test cannot.
        let original = SessionEvent::AuditLegacy {
            actor_kind: ActorKind::User,
            actor_id: "bob".to_string(),
            action: "message.send".to_string(),
            target: "slack".to_string(),
            channel: Some("slack".to_string()),
            detail: serde_json::json!({"trust": "low", "reply_to": 42}),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: SessionEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
    }
}
