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

use std::marker::PhantomData;
use std::ops::Range;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuditError;

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
    },
    /// Final assistant text response for a turn.
    AssistantMessage { content: String },
    /// Assistant requested one or more tool calls.
    AssistantToolCalls { calls: Vec<ToolCallRecord> },
    /// Result of a single tool call.
    ToolResult {
        call_id: String,
        tool_name: String,
        output: String,
        success: bool,
    },
    /// LLM request metadata. Full request body is reconstructible
    /// from prior session events; this carries hashes for the
    /// reproducible-replay verifier (item 10).
    LlmRequest {
        provider: String,
        model: String,
        request_id: String,
        tools_hash: HashHex,
        messages_hash: HashHex,
    },
    /// LLM response metadata.
    LlmResponse {
        request_id: String,
        finish_reason: String,
        tokens_in: u32,
        tokens_out: u32,
        latency_ms: u64,
    },
    /// Permission denial recorded by the harness. `action_key` is
    /// the canonical key under which an operator can grant approval
    /// (e.g., `shell:curl`); kept alongside `tool` so reviewers can
    /// map the denial back to a permissions.db entry without having
    /// to reparse tool arguments.
    PermissionDenied {
        tool: String,
        /// Defaulted for rows written before this field existed; old
        /// audit events deserialize with an empty key so a pre-upgrade
        /// session log stays readable.
        #[serde(default)]
        action_key: String,
        tier: String,
        agent_id: String,
        trigger: Option<String>,
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
        outcome: String,
        bytes: u64,
        run_id: Option<String>,
    },
    /// Zirkel: a fetched item passed exclusion + keyword screening and
    /// landed in the candidates table with its keyword-match score.
    /// `keyword_match_score` is the count of distinct keyword matches.
    /// The LLM-relevance pass emits a separate `CandidateLlmScored`
    /// event after this one — the two-event split keeps each pass
    /// independently auditable, so a failed LLM pass leaves the
    /// keyword event in the chain rather than orphaning the candidate.
    /// `matched_keywords` is the JSON-encoded list, kept verbatim so
    /// the chain-verifier can replay the screening decision.
    CandidateScored {
        run_id: String,
        candidate_id: i64,
        keyword_match_score: u32,
        matched_keywords: String,
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
    /// Zirkel: the daily digest was rendered and pushed to the
    /// configured channel (C-Signal scope).
    DigestPushed {
        run_id: String,
        channel_adapter: String,
        item_count: u32,
    },
    /// Zirkel: the interests file changed between runs. `before_hash`
    /// is the hash recorded on the previous run's snapshot;
    /// `after_hash` is the current hash. Emitted at the start of every
    /// run that detects a delta.
    InterestsEdited {
        before_hash: HashHex,
        after_hash: HashHex,
    },
    /// Sandbox lazily provisioned (item 3 emits this once at first
    /// use).
    SandboxProvisioned { name: String, mode: String },
    /// Compaction event from the context engine (item 4). The
    /// `extracts` are structured key-value claims, not free-text.
    /// `via_model: true` flags the rare free-text fallback path
    /// which the context engine treats as untrusted on replay.
    Compaction {
        spans: Vec<u64>,
        extracts: serde_json::Value,
        via_model: bool,
    },
    /// Periodic chain-head signature (item 8). Self-contained proof
    /// that the chain up to `chain_head_seq` is intact.
    Attestation {
        chain_head_seq: u64,
        chain_head_hash: HashHex,
        signature: HexBytes,
        signer_pubkey: HashHex,
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
    SystemPromptSet { content: String },
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
        status: String,
    },
    /// Backward-compatibility wrapper for the pre-slice-2 audit
    /// log. Carries the legacy `(actor, action, target, channel,
    /// detail)` tuple verbatim. Slice 2 of item 1 makes this the
    /// only kind that the legacy `AuditWriter` writes; the existing
    /// `audit_events` table becomes a SQL view that COALESCEs the
    /// `action` field out of legacy events and the `kind` field out
    /// of typed events so SIEM consumers see both.
    AuditLegacy {
        actor: String,
        action: String,
        target: String,
        channel: String,
        detail: serde_json::Value,
    },
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
    Ok { rows_verified: usize },
    Empty,
    Broken { seq: u64, reason: String },
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
    pub tier: String,
    pub trigger: Option<String>,
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

/// SQLite-backed [`SessionLog`]. Uses WAL mode and an interior
/// `Mutex<Connection>` to allow `&self` access from multiple threads.
pub struct SqliteSessionLog {
    conn: Mutex<Connection>,
}

impl SqliteSessionLog {
    /// Open or create a session log at `db_path`. Creates the
    /// `session_events` table if it does not exist.
    pub fn open(db_path: &Path) -> Result<Self, AuditError> {
        let conn = Connection::open(db_path)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory session log (test helper).
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Test-only access to the inner connection. Used by tampering
    /// tests that need to corrupt rows without going through the
    /// public API.
    #[cfg(test)]
    pub(crate) fn raw_conn_for_test(&self) -> &Mutex<Connection> {
        &self.conn
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
                        tier,
                        agent_id: ev_agent,
                        trigger,
                    } if ev_agent == agent_id => Some(PermissionDenialRecord {
                        session_id,
                        seq,
                        ts,
                        tool,
                        action_key,
                        tier,
                        trigger,
                    }),
                    _ => None,
                }
            })
            .collect()
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

    /// Append an event with a caller-supplied timestamp. Used by the
    /// migration code in [`crate::legacy_compat`] to preserve the
    /// original `audit_events.ts` values when copying legacy rows
    /// into `session_events`. Production callers should use
    /// [`SessionLog::append`] which stamps `Utc::now()`.
    pub(crate) fn append_with_ts(
        &self,
        handle: &SessionHandle<OwnSession>,
        trust: TrustLevel,
        event: SessionEvent,
        ts: DateTime<Utc>,
    ) -> Result<u64, AuditError> {
        let conn = self.conn.lock().expect("session log mutex");
        append_inner(&conn, handle, trust, event, Some(ts))
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
        let conn = self.conn.lock().expect("session log mutex");
        append_inner(&conn, handle, trust, event, None)
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
                    reason: format!(
                        "prev_hash {prev_hash} does not match expected {expected_prev}"
                    ),
                });
            }

            let recomputed_leaf = sha256_hex(payload.as_bytes());
            if recomputed_leaf != leaf_hash {
                return Ok(SessionVerifyResult::Broken {
                    seq,
                    reason: format!(
                        "leaf_hash {leaf_hash} does not match payload sha256 {recomputed_leaf}"
                    ),
                });
            }

            let recomputed_chain = chain_hex(&prev_hash, &leaf_hash);
            if recomputed_chain != stored_hash {
                return Ok(SessionVerifyResult::Broken {
                    seq,
                    reason: format!(
                        "chain hash {stored_hash} does not match expected {recomputed_chain}"
                    ),
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
