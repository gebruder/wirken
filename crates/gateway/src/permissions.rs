use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;

use crate::error::GatewayError;

/// Permission tiers from the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionTier {
    /// Always allowed — no approval needed.
    Tier1,
    /// First-use approval, then remembered.
    Tier2,
    /// Always prompt.
    Tier3,
}

impl PermissionTier {
    /// Human-readable label for the tier.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
        }
    }
}

/// An action that requires permission checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    // Tier 1 — always allowed
    WorkspaceFileAccess,
    ChannelConverse,
    WebSearch,
    /// The `http_request` built-in tool. Tier 1 means the interactive
    /// approval flow adds no prompt; authorization is not a prompt but
    /// the skill's permissions block (`tools.allow`, `credentials.allow`,
    /// `http.post_paths`, `egress.domains`), enforced as hard refusals
    /// at the gate and by `EgressClient`. A non-allowlisted request is
    /// refused, never escalated to a prompt.
    HttpRequest,

    // Tier 2 — first-use approval
    ShellExec {
        pattern: String,
    },
    ExternalFileAccess {
        path: String,
    },
    CrossConversationMessage,

    // Tier 3 — always prompt
    DestructiveFileOp,
    NetworkRequest {
        domain: String,
    },
    CredentialAccess,
    CronCreate,
    /// An MCP-proxied tool call. Named by the whole prefixed
    /// `mcp_{server}_{tool}` string the proxy generates; the server
    /// segment is not parsed out because operator-chosen server names
    /// can contain underscores, so the prefix is not unambiguously
    /// splittable. Always Tier 3: MCP children run at the wirken UID
    /// with no process sandbox, so every call is gated.
    McpToolCall {
        tool: String,
    },
    /// A tool name matching no built-in, MCP, or known Wasm-skill
    /// classification. Default-denied at Tier 3 so an unregistered
    /// tool cannot run ungated. Constructed by the runtime tier gate
    /// for the residual case, never by `tool_to_action`.
    UnknownTool {
        tool: String,
    },
    /// A tool call dispatching to a loaded Wasm skill (`wasm_{skill}`).
    /// Always Tier 3: the Wasm sandbox and the per-skill permission
    /// profile bound what the call can reach, but neither asks the
    /// operator, so the tier gate makes every Wasm dispatch default-deny
    /// like any other unclassified call. The sandbox and profile remain
    /// additional constraints layered on top, not replacements.
    /// Constructed by the runtime tier gate for known Wasm skills;
    /// `tool_to_action` returns `None` for `wasm_`-prefixed names so they
    /// are not confused with the `mcp_` arm.
    WasmSkillCall {
        skill: String,
    },
    /// Reading an agent's memory entries that were written on a
    /// different channel. Always Tier 3: channels are distinct trust
    /// zones, so pulling one channel's history into another is a
    /// boundary crossing and prompts on every use.
    ///
    /// Keyed by the channel being read *from*, so approving a read of
    /// one channel's history does not approve any other. The
    /// destination channel is not part of the key; it is the channel
    /// the turn is already running on and is recorded on the audit
    /// row instead.
    CrossChannelMemoryRead {
        from_channel: String,
    },
    /// Reading a conversation out of an imported archive. Always
    /// Tier 3.
    ///
    /// The argument is not that imported text is untrustworthy, which
    /// is a separate axis. It is what the corpus reveals: an archive is
    /// the whole conversation history of an account, written with no
    /// expectation that an agent would ever read it.
    /// `CrossChannelMemoryRead` gates a smaller disclosure, one other
    /// channel's deliberately labelled entries for the same agent, at
    /// this tier; gating the larger one lower would invert the model.
    ///
    /// Keyed by the source read *from*, exactly as the cross-channel
    /// key is keyed by the channel read from, so approving one archive
    /// approves no other. A missing or empty source argument yields a
    /// key no source carries, so it denies rather than widening.
    ImportedChatRead {
        source_id: String,
    },
    /// Searching imported archives. Always Tier 3, for the same reason
    /// reading one is: what answers a query is the corpus.
    ///
    /// The scope is optional, and the two forms take different keys
    /// rather than two values of one key. A scoped search is keyed by
    /// the source, like a read. An unscoped search reaches every
    /// archive on the instance, which is a different question to be
    /// asked, so it takes a key of its own that no source id can
    /// produce.
    ///
    /// Search and read keys are separate namespaces and neither
    /// implies the other. Approving a read of a conversation the
    /// operator named is not approving a sweep for conversations they
    /// have not; approving a sweep is not approving the reads of
    /// whatever it turns up.
    ImportedChatSearch {
        source_id: Option<String>,
    },
}

impl std::fmt::Display for Action {
    /// Stable snake_case label. SIEM consumers group by this string;
    /// the `Debug` form would carry struct payloads (`ShellExec { pattern: "curl" }`)
    /// which is not stable wire shape.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Action::WorkspaceFileAccess => "workspace_file_access",
            Action::ChannelConverse => "channel_converse",
            Action::WebSearch => "web_search",
            Action::HttpRequest => "http_request",
            Action::ShellExec { .. } => "shell_exec",
            Action::ExternalFileAccess { .. } => "external_file_access",
            Action::CrossConversationMessage => "cross_conversation_message",
            Action::DestructiveFileOp => "destructive_file_op",
            Action::NetworkRequest { .. } => "network_request",
            Action::CredentialAccess => "credential_access",
            Action::CronCreate => "cron_create",
            Action::McpToolCall { .. } => "mcp_tool_call",
            Action::UnknownTool { .. } => "unknown_tool",
            Action::WasmSkillCall { .. } => "wasm_skill_call",
            Action::CrossChannelMemoryRead { .. } => "cross_channel_memory_read",
            Action::ImportedChatRead { .. } => "imported_chat_read",
            Action::ImportedChatSearch { .. } => "imported_chat_search",
        };
        f.write_str(label)
    }
}

/// Commands whose shell-exec pattern keeps the default Tier 2
/// ("first-use approval, remembered for 30 days") behaviour. Every
/// other exec prefix escalates to Tier 3 ("always prompt"). This is
/// an allowlist, not a denylist: the previous denylist grew without
/// bound because every new shell wrapper (`sh`/`env`/`xargs`/...)
/// and every language interpreter with `-c`/`-e` eval (`python`,
/// `node`, `perl`, `ruby`, `lua`, `awk`, `sed` with GNU `s///e`,
/// ...) can launder an arbitrary inner verb past the gate. The
/// allowlist collapses the wrapper-laundering class in one rule:
/// if a verb is not on this list, it prompts.
///
/// Every verb here is pure inspection / identity / path math with
/// no documented `-exec`, `--*-program`, `!`, `$PAGER`, or
/// `system()`-style escape hatch after man-page review. Notable
/// exclusions even among "read-only looking" tools:
/// - `rg` has `--pre <cmd>` that runs a preprocessor.
/// - `sort` has `--compress-program`.
/// - `find` has `-exec`.
/// - `git` honours hooks, `-c core.pager`, and aliases.
/// - `less` / `more` / `man` shell out via `!` and `$PAGER`.
/// - `sed` (GNU) has `s///e`; `awk` has `system()`.
///
/// Match is against the canonical (basename + lowercase) form of
/// the first whitespace-separated token, so `/usr/bin/ls`,
/// `./ls`, and `LS` all reduce to `ls`.
pub const TIER2_ALLOWLIST: &[&str] = &[
    // inspection (read/stat)
    "ls", "cat", "head", "tail", "grep", "diff", "cmp", "stat", "file", "wc", "tree",
    // pure path math
    "readlink", "realpath", "basename", "dirname", // identity / system info (read-only)
    "pwd", "whoami", "id", "uname", "hostname", "date", "echo", "printf", "which", "type",
];

/// Canonicalize a shell-exec pattern's first token for tier matching
/// and approval-key stability.
///
/// - Strips any leading path components so `/usr/bin/curl` and
///   `./curl` both reduce to `curl`.
/// - Lowercases the basename so `CURL` / `SuDo` match on
///   case-insensitive hosts (macOS default APFS, Windows).
///
/// The return is always an owned `String` so callers can form
/// approval keys and slice comparisons without borrow gymnastics.
pub fn canonical_exec_prefix(pattern: &str) -> String {
    let token = pattern.trim();
    let basename = Path::new(token)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(token);
    basename.to_ascii_lowercase()
}

impl Action {
    /// Determine which tier this action belongs to.
    pub fn tier(&self) -> PermissionTier {
        match self {
            Action::WorkspaceFileAccess
            | Action::ChannelConverse
            | Action::WebSearch
            | Action::HttpRequest => PermissionTier::Tier1,

            // Shell exec: Tier 2 only for inspection verbs on the
            // curated allowlist (read/identity/path math, no exec
            // escape hatch). Everything else is Tier 3. The prefix
            // is canonicalized (basename + lowercase) before the
            // lookup so `/usr/bin/ls`, `./ls`, and `LS` all reduce
            // to `ls`. Wrappers (`sh`, `env`, `xargs`, ...) and
            // interpreters (`python`, `node`, `awk`, `sed`, ...)
            // fall to Tier 3 naturally by absence from the list.
            Action::ShellExec { pattern } => {
                let canonical = canonical_exec_prefix(pattern);
                if TIER2_ALLOWLIST.contains(&canonical.as_str()) {
                    PermissionTier::Tier2
                } else {
                    PermissionTier::Tier3
                }
            }

            Action::ExternalFileAccess { .. } | Action::CrossConversationMessage => {
                PermissionTier::Tier2
            }

            Action::DestructiveFileOp
            | Action::NetworkRequest { .. }
            | Action::CredentialAccess
            | Action::CronCreate
            | Action::McpToolCall { .. }
            | Action::UnknownTool { .. }
            | Action::WasmSkillCall { .. }
            | Action::CrossChannelMemoryRead { .. }
            | Action::ImportedChatRead { .. }
            | Action::ImportedChatSearch { .. } => PermissionTier::Tier3,
        }
    }

    /// The canonical key for storing approval (Tier 2 actions).
    ///
    /// Shell-exec keys canonicalize the pattern (basename + lowercase)
    /// so path-qualified and case-variant invocations share a single
    /// approval row. Without this, `curl`, `/usr/bin/curl`, and `CURL`
    /// would each generate their own key and an operator's "approve
    /// shell:curl" would not cover the other forms.
    pub fn approval_key(&self) -> String {
        match self {
            Action::ShellExec { pattern } => format!("shell:{}", canonical_exec_prefix(pattern)),
            Action::ExternalFileAccess { path } => format!("file:{path}"),
            Action::CrossConversationMessage => "cross-conversation".to_string(),
            Action::McpToolCall { tool } => format!("mcp:{tool}"),
            Action::UnknownTool { tool } => format!("tool:{tool}"),
            Action::WasmSkillCall { skill } => format!("wasm:{skill}"),
            Action::CrossChannelMemoryRead { from_channel } => {
                format!("cross_channel_memory:{from_channel}")
            }
            Action::ImportedChatRead { source_id } => format!("imported_chat:{source_id}"),
            Action::ImportedChatSearch { source_id } => match source_id {
                Some(id) => format!("imported_search:{id}"),
                // A key of its own rather than a value inside the
                // scoped namespace, so no source id can ever produce
                // it and an approval for one archive can never be
                // mistaken for an approval to sweep them all.
                None => "imported_search_corpus".to_string(),
            },
            other => format!("{other:?}"),
        }
    }
}

/// Scope under which an approval applies. Discriminated so the
/// check path can branch on storage lifetime without re-deriving it
/// from `expires_at` heuristics.
///
/// - `Persisted` writes to `permissions.db` with the
///   default-30-day expiry; this is the historical default and the
///   only form pre-existing callers produce.
/// - `Session { session_id }` is in-memory only, scoped to the named
///   agent session, never written to SQLite. Survives crashes only
///   if the session-log replay re-emits the `PermissionApproved`
///   audit event; otherwise it is gone with the process. See
///   `~/code/wirken-ironcurtain/04-surpass.md` for the rationale
///   (the "actually-useful version" of policy hot-swap framed for
///   wirken's single-process model).
///
/// Wire shape: `serde(tag = "kind", ...)` so a future scope (e.g.
/// per-channel) can be added without breaking the persisted rows
/// that did not carry a `kind` field; back-compat handled by the
/// `Default` impl which returns `Persisted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// SQLite-backed, default expiry, survives process restart.
    #[default]
    Persisted,
    /// In-memory only, cleared on session end.
    Session {
        /// Logical agent session id (the `{agent}/{channel}/{conversation}`
        /// shape produced by `wirken_agent::factory::session_id_for`).
        /// Stored verbatim, never normalized; the in-memory cache keys
        /// on it exactly.
        session_id: String,
    },
}

impl ApprovalScope {
    /// True when this scope is session-bounded (in-memory only).
    pub fn is_session_scoped(&self) -> bool {
        matches!(self, Self::Session { .. })
    }

    /// The session id this scope is bound to, if any.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Persisted => None,
            Self::Session { session_id } => Some(session_id.as_str()),
        }
    }

    /// Split into the audit-side `(ApprovalScopeKind, Option<session_id>)`
    /// pair used when emitting `SessionEvent::PermissionApproved`. The
    /// audit crate cannot depend on gateway, so the wire shape there
    /// uses a flat enum + an optional `session_id` field; this method
    /// is the only place the mapping happens.
    pub fn to_audit_repr(&self) -> (wirken_audit::ApprovalScopeKind, Option<String>) {
        match self {
            Self::Persisted => (wirken_audit::ApprovalScopeKind::Persisted, None),
            Self::Session { session_id } => (
                wirken_audit::ApprovalScopeKind::Session,
                Some(session_id.clone()),
            ),
        }
    }
}

/// Fallback expiry for persisted grants when no store-level default
/// and no per-grant override is given. The value `PermissionStore::open`
/// has always used.
pub const DEFAULT_GRANT_EXPIRY_DAYS: u32 = 30;

/// Whether `action_key` names a Tier 2 action, and so may be written
/// to `permissions.db`.
///
/// This is an allowlist over the key namespaces `Action::approval_key`
/// produces, not a denylist of the Tier 3 ones. The denylist form was
/// already here in two hand-written special cases (`shell:` verbs off
/// [`TIER2_ALLOWLIST`], and `cross_channel_memory:`) and it had the
/// shape every denylist has: `mcp:`, `tool:`, `wasm:`,
/// `imported_chat:`, `imported_search:` and `imported_search_corpus`
/// are all Tier 3 and all of them were accepted. Those rows never took
/// effect, because [`PermissionStore::check`] answers Tier 3 without
/// consulting storage at all, but they listed in
/// `wirken permissions list` as if they had, which is the exact
/// failure the `shell:` refusal exists to prevent.
///
/// Inverting it also fixes the next one before it is written: a key
/// namespace added later is refused until someone adds it here
/// deliberately, rather than admitted by default because nobody
/// remembered to deny it.
///
/// Tier 1 keys are refused too. Tier 1 is allowed without a lookup,
/// so a stored Tier 1 row is dead weight in the same way a Tier 3 row
/// is, and it would read as though it were doing something.
pub fn is_storable_approval_key(action_key: &str) -> bool {
    match action_key {
        // Action::CrossConversationMessage, Tier 2.
        "cross-conversation" => true,
        // Action::ShellExec, Tier 2 only for the inspection verbs.
        // The key is already canonicalized by `approval_key`.
        key if key.starts_with("shell:") => {
            TIER2_ALLOWLIST.contains(&key.trim_start_matches("shell:"))
        }
        // Action::ExternalFileAccess, Tier 2. An empty path is not a
        // path any access carries, so it refuses rather than storing
        // a row that matches nothing.
        key if key.starts_with("file:") => key.len() > "file:".len(),
        _ => false,
    }
}

/// A stored permission approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub action_key: String,
    pub agent_id: String,
    pub approved_at: DateTime<Utc>,
    pub approved_by: String,
    pub expires_at: DateTime<Utc>,
    /// Storage lifetime. Defaulted on deserialize so rows persisted
    /// before this field existed read back as `ApprovalScope::Persisted`,
    /// which is the only form the pre-slice-1 emit path produced.
    #[serde(default)]
    pub scope: ApprovalScope,
}

/// What a grant write did, as opposed to what it wrote.
///
/// [`PermissionStore::approve_by_key_with_expiry`] returns this so
/// the caller can emit `PermissionApproved` or `PermissionRenewed`
/// without a second lookup. Reading the prior row and writing the
/// new one in one call is what makes the two events trustworthy:
/// a caller that queried the expiry first and then approved would be
/// reporting a window that another writer could have changed in
/// between.
#[derive(Debug, Clone)]
pub struct GrantOutcome {
    /// The row now in the store.
    pub approval: Approval,
    /// `Some(expiry)` when this write replaced an existing row for
    /// the same `(action_key, agent_id)`, carrying that row's
    /// expiry. `None` when the key was not previously granted.
    ///
    /// A lapsed row still counts as a replacement: the operator is
    /// renewing a grant they made before, and losing that history
    /// because the window happened to close first would be the same
    /// gap this field exists to close. Always `None` for
    /// session-scoped writes.
    pub renewed_from: Option<DateTime<Utc>>,
}

/// Normalize a runtime `agent_id` to the logical agent id used in
/// `permissions.db`. The runtime hands permission checks the full
/// session-scoped id `{agent}/{channel}/{conversation}` (see
/// `session_id_for` in `wirken_agent::factory`); approvals are stored
/// per logical agent so a single approval applies across every
/// conversation on every channel for that agent. Returns the prefix
/// before the first `/`, or the input unchanged if no `/` is present.
fn canonical_agent_id(agent_id: &str) -> &str {
    agent_id.split('/').next().unwrap_or(agent_id)
}

/// One row the open-time sweep removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleGrant {
    pub action_key: String,
    pub agent_id: String,
    /// The window the row carried. In the past for a lapsed grant;
    /// possibly in the future for a not-storable one, which is part
    /// of why it read as live.
    pub expires_at: DateTime<Utc>,
}

/// What [`PermissionStore::sweep_stale_grants`] removed.
///
/// Returned rather than logged from inside the store because the
/// store holds no session handle, and an audit row belongs in a
/// chain. [`PermissionStore::open`] keeps the report so a caller
/// that does have a log can emit it; see
/// `PermissionStore::take_sweep_report`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Keys the gate can never read: Tier 1 or Tier 3.
    pub not_storable: Vec<StaleGrant>,
    /// Storable keys whose window closed with nothing calling them.
    pub lapsed: Vec<StaleGrant>,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        self.not_storable.is_empty() && self.lapsed.is_empty()
    }

    pub fn len(&self) -> usize {
        self.not_storable.len() + self.lapsed.len()
    }
}

/// Permission store backed by SQLite.
///
/// `session_cache` holds session-scoped approvals: nested map of
/// `session_id` (the full `{agent}/{channel}/{conversation}` form
/// the runtime passes into `check`) to `action_key` to `Approval`.
/// Pure in-memory; never persisted, never consulted by `list()`.
/// `RefCell` matches the existing interior-mutability posture (the
/// `rusqlite::Connection` field also mutates through `&self`); the
/// outer `Arc<Mutex<PermissionStore>>` that callers hold (see
/// `crates/agent/src/runtime.rs:2049-2051`) provides the
/// thread-safety bound, so a finer-grained inner lock would be
/// redundant.
pub struct PermissionStore {
    conn: Connection,
    default_expiry_days: u32,
    session_cache: RefCell<HashMap<String, HashMap<String, Approval>>>,
    /// What the open-time sweep removed, held until a caller with a
    /// session log takes it. Empty on the overwhelmingly common
    /// open, where there was nothing stale to remove.
    last_sweep: SweepReport,
}

impl PermissionStore {
    /// Open or create the permission store.
    ///
    /// Runs a one-shot prune of approvals for shell verbs that are no
    /// longer Tier 2 eligible under the current allowlist. When the
    /// Tier 2 model flipped from a denylist (everything except a
    /// small set of high-risk verbs was Tier 2) to an allowlist (only
    /// a small set of inspection verbs is Tier 2), previously stored
    /// approvals for now-Tier-3 verbs (`shell:git`, `shell:kubectl`,
    /// `shell:make`, language interpreters, ...) became dead rows.
    /// Dropping them on open keeps the store honest: the permission
    /// gate does not consult them, and the operator sees a log line
    /// enumerating what was pruned rather than discovering later that
    /// `wirken permissions list` shows approvals that no longer take
    /// effect.
    /// Open with the built-in [`DEFAULT_GRANT_EXPIRY_DAYS`] window.
    /// Equivalent to `open_with_expiry(db_path, DEFAULT_GRANT_EXPIRY_DAYS)`.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        Self::open_with_expiry(db_path, DEFAULT_GRANT_EXPIRY_DAYS)
    }

    /// Open with an operator-chosen default grant window, in days.
    ///
    /// The window applies to every persisted grant written through
    /// this handle that does not carry its own override. It is a
    /// default, not a cap: a per-grant override may exceed it (see
    /// [`Self::approve_by_key_with_expiry`]).
    ///
    /// Zero is refused. A zero-day default writes grants that are
    /// already expired when [`Self::check`] next reads them, so every
    /// Tier 2 action would prompt on every call while
    /// `wirken permissions list` showed a table of grants. An
    /// operator who wants that should be revoking, and an operator
    /// who typed it by accident should be told.
    pub fn open_with_expiry(
        db_path: &Path,
        default_expiry_days: u32,
    ) -> Result<Self, GatewayError> {
        if default_expiry_days == 0 {
            return Err(GatewayError::Config(
                "permissions: default_expiry_days must be at least 1. A zero-day window \
                 stores grants that have already expired by the time the gate reads them, \
                 so every Tier 2 action prompts on every call while `wirken permissions \
                 list` still shows the grant. To stop granting an action, revoke it."
                    .to_string(),
            ));
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS approvals (
                 action_key TEXT NOT NULL,
                 agent_id TEXT NOT NULL,
                 approved_at TEXT NOT NULL,
                 approved_by TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 PRIMARY KEY (action_key, agent_id)
             );",
        )?;

        let mut store = Self {
            conn,
            default_expiry_days,
            session_cache: RefCell::new(HashMap::new()),
            last_sweep: SweepReport::default(),
        };
        store.last_sweep = store.sweep_stale_grants()?;
        Ok(store)
    }

    /// The default grant window in days, for callers that report it
    /// to an operator before a grant is written.
    pub fn default_expiry_days(&self) -> u32 {
        self.default_expiry_days
    }

    /// Take the open-time sweep report, leaving the store's copy
    /// empty.
    ///
    /// Taking rather than borrowing so the rows cannot be emitted
    /// twice by two callers that both hold the store. The removal
    /// already happened and is durable; this is the record of it,
    /// and the record has exactly one owner.
    pub fn take_sweep_report(&mut self) -> SweepReport {
        std::mem::take(&mut self.last_sweep)
    }

    /// Drop every stored row the gate can no longer act on, and
    /// report what went so the caller can put it in the audit chain.
    ///
    /// Two kinds, kept apart because they are different situations:
    ///
    /// - **Not storable.** The key names a Tier 1 or Tier 3 action
    ///   (see [`is_storable_approval_key`]). Nothing about the row
    ///   ran out; it was inert from the moment it was written,
    ///   because the gate answers those tiers without reading
    ///   storage. Rows like this exist because the write path used
    ///   to accept them, and because the Tier 2 model flipped from a
    ///   denylist to an allowlist and stranded `shell:git`,
    ///   `shell:kubectl`, `shell:make` and every language
    ///   interpreter.
    /// - **Lapsed.** The key is storable and the window closed.
    ///   [`Self::check`] drops these too, but only when something
    ///   calls the action. A grant that lapsed while nothing used it
    ///   sits in the table until it is next read, which for a key
    ///   nothing calls is never.
    ///
    /// Both left `wirken permissions list` printing rows that read
    /// as grants and were not. Refusing the writes fixed that going
    /// forward and did nothing for anyone who had already upgraded,
    /// which is what this is for.
    ///
    /// Called from [`Self::open`], so the table is honest from the
    /// moment it opens rather than from the first call that happens
    /// to touch each key. Idempotent: a second run over a swept
    /// store reports nothing.
    pub fn sweep_stale_grants(&mut self) -> Result<SweepReport, GatewayError> {
        let now = Utc::now();
        let mut report = SweepReport::default();
        {
            let mut select = self
                .conn
                .prepare("SELECT action_key, agent_id, expires_at FROM approvals")?;
            let rows = select.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (action_key, agent_id, expires_raw) = row?;
                let expires_at = parse_dt(&expires_raw);
                // Storability first. A row that is both unreadable
                // and lapsed is reported as unreadable, because that
                // is the older and more surprising fact about it:
                // it would not have worked even inside its window.
                if !is_storable_approval_key(&action_key) {
                    report.not_storable.push(StaleGrant {
                        action_key,
                        agent_id,
                        expires_at,
                    });
                } else if now > expires_at {
                    report.lapsed.push(StaleGrant {
                        action_key,
                        agent_id,
                        expires_at,
                    });
                }
            }
        }

        if report.is_empty() {
            return Ok(report);
        }

        let tx = self.conn.transaction()?;
        {
            let mut delete =
                tx.prepare("DELETE FROM approvals WHERE action_key = ?1 AND agent_id = ?2")?;
            for grant in report.not_storable.iter().chain(report.lapsed.iter()) {
                delete.execute(params![grant.action_key, grant.agent_id])?;
            }
        }
        tx.commit()?;

        // Logged after the commit, not before it. The line claims
        // the rows are gone, and it is only true once they are.
        tracing::info!(
            not_storable = report.not_storable.len(),
            lapsed = report.lapsed.len(),
            "permissions: swept stored grants the gate cannot act on. Rows whose action key is \
             Tier 1 or Tier 3 were never read by the gate; rows past their window had lapsed \
             without anything calling them. Both listed in `wirken permissions list` as grants."
        );

        Ok(report)
    }

    /// Check if an action is allowed for a given agent.
    /// Returns:
    /// - Ok(true) for Tier 1 (always allowed) or approved Tier 2
    /// - Ok(false) for unapproved Tier 2 or any Tier 3
    /// - Err for database errors
    ///
    /// Session-scoped approvals win over persisted ones: the cache is
    /// consulted against the raw `agent_id` (which the runtime passes
    /// as the full `{agent}/{channel}/{conversation}` form, matching
    /// the `session_id` recorded under `ApprovalScope::Session`)
    /// before the canonical-prefix SQLite lookup.
    pub fn check(&self, action: &Action, agent_id: &str) -> Result<PermissionCheck, GatewayError> {
        // Session-cache short-circuit. Applies to every tier so a
        // Tier 3 action could in principle be session-granted in a
        // future slice; for now the only emitters target Tier 2, but
        // gating the lookup on tier here would make session-scoped
        // semantics tier-coupled in a way the data model is not.
        let session_hit = {
            let cache = self.session_cache.borrow();
            cache
                .get(agent_id)
                .and_then(|per_session| {
                    per_session
                        .contains_key(&action.approval_key())
                        .then_some(())
                })
                .is_some()
        };
        if session_hit {
            return Ok(PermissionCheck::Allowed);
        }

        let agent_id = canonical_agent_id(agent_id);
        match action.tier() {
            PermissionTier::Tier1 => Ok(PermissionCheck::Allowed),
            PermissionTier::Tier2 => {
                let key = action.approval_key();
                match self.get_approval(&key, agent_id)? {
                    Some(approval) => {
                        if Utc::now() > approval.expires_at {
                            // Expired — needs re-approval. The row is
                            // dropped here and its expiry is handed
                            // back on `lapsed_at`, because after the
                            // revoke this is the last point that knows
                            // the window existed. The caller has the
                            // session handle and emits
                            // `PermissionGrantExpired`.
                            self.revoke(&key, agent_id)?;
                            Ok(PermissionCheck::NeedsApproval {
                                tier: PermissionTier::Tier2,
                                lapsed_at: Some(approval.expires_at),
                            })
                        } else {
                            Ok(PermissionCheck::Allowed)
                        }
                    }
                    None => Ok(PermissionCheck::NeedsApproval {
                        tier: PermissionTier::Tier2,
                        lapsed_at: None,
                    }),
                }
            }
            // Tier 3 never consults storage, so it can never have
            // found a grant to lapse.
            PermissionTier::Tier3 => Ok(PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier3,
                lapsed_at: None,
            }),
        }
    }

    /// Record an approval for a Tier 2 action.
    ///
    /// Defaults to [`ApprovalScope::Persisted`]; for session-scoped
    /// grants call [`Self::approve_with_scope`] directly.
    pub fn approve(
        &self,
        action: &Action,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        self.approve_with_scope(action, agent_id, approved_by, ApprovalScope::Persisted)
    }

    /// Record an approval with an explicit scope. Persisted grants go
    /// to SQLite via [`Self::approve_by_key`]; session-scoped grants
    /// land in the in-memory cache keyed on `scope.session_id`. The
    /// caller-supplied `agent_id` is used by both paths (canonicalized
    /// for SQLite, recorded verbatim on the in-memory `Approval`), so
    /// the audit emitter (slice 3) can record both fields without
    /// re-deriving either.
    ///
    /// Session-scoped approvals do not have a meaningful time-based
    /// expiry; the cache lookup in [`Self::check`] does not consult
    /// `expires_at`. The field is populated with
    /// `DateTime::<Utc>::MAX_UTC` as a sentinel so a future caller
    /// reading the `Approval` directly does not interpret a stale
    /// 30-day window as "still valid" or "already expired"; both are
    /// wrong, and a far-future value makes the intent explicit.
    pub fn approve_with_scope(
        &self,
        action: &Action,
        agent_id: &str,
        approved_by: &str,
        scope: ApprovalScope,
    ) -> Result<Approval, GatewayError> {
        self.approve_with_scope_by_key(&action.approval_key(), agent_id, approved_by, scope)
    }

    /// Key-driven counterpart to [`Self::approve_with_scope`]. CLI
    /// callers (`wirken permission approve <action-key>`) already
    /// have the action key as a string and re-parsing it into a
    /// typed [`Action`] is lossy (a `shell:ls` key matches
    /// `Action::ShellExec { pattern: "ls" }` but the original
    /// pattern was operator input that may have included a path
    /// prefix). Both forms dispatch through this method so the
    /// scope-match logic lives in one place.
    pub fn approve_with_scope_by_key(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
        scope: ApprovalScope,
    ) -> Result<Approval, GatewayError> {
        Ok(self
            .approve_with_scope_by_key_with_expiry(action_key, agent_id, approved_by, scope, None)?
            .approval)
    }

    /// [`Self::approve_with_scope_by_key`] with a per-grant window
    /// and a report of what the write did.
    ///
    /// `expires_in_days` is ignored for `ApprovalScope::Session`:
    /// session grants end with the session and carry the
    /// `DateTime::<Utc>::MAX_UTC` sentinel rather than a window, so
    /// there is nothing for a day count to shorten. Session writes
    /// likewise always report `renewed_from: None`; re-granting one
    /// is idempotent, not a renewal.
    pub fn approve_with_scope_by_key_with_expiry(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
        scope: ApprovalScope,
        expires_in_days: Option<u32>,
    ) -> Result<GrantOutcome, GatewayError> {
        match scope {
            ApprovalScope::Persisted => {
                self.approve_by_key_with_expiry(action_key, agent_id, approved_by, expires_in_days)
            }
            ApprovalScope::Session { session_id } => Ok(GrantOutcome {
                approval: self.approve_session_scoped_by_key(
                    action_key,
                    agent_id,
                    approved_by,
                    session_id,
                )?,
                renewed_from: None,
            }),
        }
    }

    /// In-memory session-scoped insert. Internal helper for
    /// [`Self::approve_with_scope_by_key`]. Never writes to SQLite.
    /// Unlike [`Self::approve_by_key`] this does NOT refuse Tier-3
    /// shell verbs: session-scoped grants are bounded by session
    /// lifetime, not the 30-day window that motivated the persisted
    /// refusal (a "dead row in `wirken permission list`" is the
    /// failure mode the persisted refusal exists to prevent, and
    /// the in-memory cache has no such surface).
    fn approve_session_scoped_by_key(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
        session_id: String,
    ) -> Result<Approval, GatewayError> {
        let now = Utc::now();
        let approval = Approval {
            action_key: action_key.to_string(),
            agent_id: agent_id.to_string(),
            approved_at: now,
            approved_by: approved_by.to_string(),
            expires_at: DateTime::<Utc>::MAX_UTC,
            scope: ApprovalScope::Session {
                session_id: session_id.clone(),
            },
        };
        self.session_cache
            .borrow_mut()
            .entry(session_id)
            .or_default()
            .insert(action_key.to_string(), approval.clone());
        Ok(approval)
    }

    /// Drop every session-scoped approval recorded under `session_id`.
    /// Returns the number of action-keys removed; zero when the
    /// session had no entries (clean-shutdown path on a fresh session
    /// is the common no-op caller). The session-id row is removed
    /// from the cache so a subsequent re-use of the same id starts
    /// from an empty set.
    pub fn clear_session_scope(&self, session_id: &str) -> u32 {
        match self.session_cache.borrow_mut().remove(session_id) {
            Some(per_session) => per_session.len() as u32,
            None => 0,
        }
    }

    /// Replay-side cache insert. Builds an [`Approval`] from the raw
    /// fields recovered from a `SessionEvent::PermissionApproved` event
    /// (where scope is `Session`) and inserts it into the in-memory
    /// cache. Does NOT emit any audit event; the replayed event is
    /// already in the log. `approved_at` is the original event
    /// timestamp so the restored `Approval` carries the same wall-clock
    /// the operator saw at grant time.
    ///
    /// This bypasses `approve_with_scope`'s `Action` parameter because
    /// `action_key` is the only thing the audit event records and
    /// reverse-engineering an `Action` from a key is lossy (a
    /// `shell:ls` key matches `Action::ShellExec { pattern: "ls" }`
    /// but the original pattern was operator-supplied input that may
    /// have included a leading path).
    pub fn restore_session_scoped_approval(
        &self,
        action_key: String,
        agent_id: String,
        approved_by: String,
        session_id: String,
        approved_at: DateTime<Utc>,
    ) {
        let approval = Approval {
            action_key: action_key.clone(),
            agent_id,
            approved_at,
            approved_by,
            expires_at: DateTime::<Utc>::MAX_UTC,
            scope: ApprovalScope::Session {
                session_id: session_id.clone(),
            },
        };
        self.session_cache
            .borrow_mut()
            .entry(session_id)
            .or_default()
            .insert(action_key, approval);
    }

    /// Record an approval using a pre-computed action key. Callers
    /// that already have the key (e.g., the CLI `permissions approve`
    /// command, reading it off a past `PermissionDenied` audit entry)
    /// use this to avoid reparsing the key back into an [`Action`].
    ///
    /// Refuses to write a `shell:<prefix>` approval whose prefix is
    /// not on [`TIER2_ALLOWLIST`]. Those verbs are Tier 3 under the
    /// current policy — the gate would ignore the stored approval
    /// anyway — and accepting the CLI call silently would let an
    /// operator believe they had pre-approved a verb that still
    /// prompts on every use.
    pub fn approve_by_key(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
    ) -> Result<Approval, GatewayError> {
        Ok(self
            .approve_by_key_with_expiry(action_key, agent_id, approved_by, None)?
            .approval)
    }

    /// [`Self::approve_by_key`] with an explicit window and a report
    /// of what the write did.
    ///
    /// `expires_in_days` overrides the store default for this grant
    /// only; `None` takes the default. The override may be longer
    /// than the default. The default is what an operator gets when
    /// they say nothing, not a ceiling on what they can ask for, and
    /// a ceiling here would be enforcing an approval policy in the
    /// same call that carries out an approval the operator already
    /// decided on.
    ///
    /// Zero is refused, for the reason [`Self::open_with_expiry`]
    /// refuses a zero default.
    ///
    /// The row is still written with `INSERT OR REPLACE`, so a
    /// renewal overwrites in place and the store holds one window per
    /// key. `GrantOutcome::renewed_from` carries the window that was
    /// overwritten so the caller can put it in the audit chain, which
    /// is where the history lives.
    pub fn approve_by_key_with_expiry(
        &self,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
        expires_in_days: Option<u32>,
    ) -> Result<GrantOutcome, GatewayError> {
        if !is_storable_approval_key(action_key) {
            return Err(GatewayError::Config(format!(
                "refusing to store approval for '{action_key}': only Tier 2 action keys can be \
                 pre-approved (shell verbs on the Tier 2 allowlist, 'file:<path>', and \
                 'cross-conversation'). Every other action is Tier 1, which is allowed without \
                 a stored grant, or Tier 3, which prompts on every use by design. A stored row \
                 for either would list in `wirken permissions list` without the gate ever \
                 reading it."
            )));
        }
        if expires_in_days == Some(0) {
            return Err(GatewayError::Config(format!(
                "refusing to store approval for '{action_key}': a zero-day window expires \
                 before the gate next reads it. To stop granting an action, revoke it."
            )));
        }

        let agent_id = canonical_agent_id(agent_id);
        let now = Utc::now();
        let days = expires_in_days.unwrap_or(self.default_expiry_days);
        let expires = now + Duration::days(days as i64);

        // Read the window we are about to overwrite before
        // overwriting it. Same call, same `&self`, so no caller can
        // observe or interleave the two halves.
        let renewed_from = self
            .get_approval(action_key, agent_id)?
            .map(|prior| prior.expires_at);

        self.conn.execute(
            "INSERT OR REPLACE INTO approvals (action_key, agent_id, approved_at, approved_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![action_key, agent_id, now.to_rfc3339(), approved_by, expires.to_rfc3339()],
        )?;

        Ok(GrantOutcome {
            approval: Approval {
                action_key: action_key.to_string(),
                agent_id: agent_id.to_string(),
                approved_at: now,
                approved_by: approved_by.to_string(),
                expires_at: expires,
                scope: ApprovalScope::Persisted,
            },
            renewed_from,
        })
    }

    /// Check whether a specific `action_key` has a current (non-expired)
    /// approval for `agent_id`. Used by `list-pending` to exclude
    /// already-approved denials.
    pub fn has_approval(&self, action_key: &str, agent_id: &str) -> Result<bool, GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        let mut stmt = self
            .conn
            .prepare("SELECT expires_at FROM approvals WHERE action_key = ?1 AND agent_id = ?2")?;
        let row = stmt
            .query_row(params![action_key, agent_id], |row| row.get::<_, String>(0))
            .optional()?;
        match row {
            None => Ok(false),
            Some(expires) => {
                let expires_at = parse_dt(&expires);
                Ok(Utc::now() < expires_at)
            }
        }
    }

    /// Revoke an approval.
    pub fn revoke(&self, action_key: &str, agent_id: &str) -> Result<(), GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        self.conn.execute(
            "DELETE FROM approvals WHERE action_key = ?1 AND agent_id = ?2",
            params![action_key, agent_id],
        )?;
        Ok(())
    }

    /// List all approvals for an agent.
    pub fn list(&self, agent_id: &str) -> Result<Vec<Approval>, GatewayError> {
        let agent_id = canonical_agent_id(agent_id);
        let mut stmt = self.conn.prepare(
            "SELECT action_key, agent_id, approved_at, approved_by, expires_at
             FROM approvals WHERE agent_id = ?1 ORDER BY approved_at DESC",
        )?;

        let rows = stmt.query_map(params![agent_id], |row| {
            Ok(Approval {
                action_key: row.get(0)?,
                agent_id: row.get(1)?,
                approved_at: parse_dt(&row.get::<_, String>(2)?),
                approved_by: row.get(3)?,
                expires_at: parse_dt(&row.get::<_, String>(4)?),
                scope: ApprovalScope::Persisted,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    fn get_approval(
        &self,
        action_key: &str,
        agent_id: &str,
    ) -> Result<Option<Approval>, GatewayError> {
        let result = self.conn.query_row(
            "SELECT action_key, agent_id, approved_at, approved_by, expires_at
             FROM approvals WHERE action_key = ?1 AND agent_id = ?2",
            params![action_key, agent_id],
            |row| {
                Ok(Approval {
                    action_key: row.get(0)?,
                    agent_id: row.get(1)?,
                    approved_at: parse_dt(&row.get::<_, String>(2)?),
                    approved_by: row.get(3)?,
                    expires_at: parse_dt(&row.get::<_, String>(4)?),
                    scope: ApprovalScope::Persisted,
                })
            },
        );

        match result {
            Ok(approval) => Ok(Some(approval)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GatewayError::Database(e)),
        }
    }
}

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionCheck {
    /// Action is allowed (Tier 1 or approved Tier 2).
    Allowed,
    /// Action needs user approval before proceeding.
    NeedsApproval {
        tier: PermissionTier,
        /// `Some(expiry)` when a stored grant was found lapsed and
        /// dropped by this check, carrying the expiry it held.
        /// `None` when no grant was stored, or when the tier never
        /// consults storage.
        ///
        /// This is a field on the existing variant rather than a
        /// variant of its own on purpose. A new variant would slip
        /// past the `if let PermissionCheck::NeedsApproval` in the
        /// runtime's tier gate and let a lapsed grant run the tool,
        /// and the compiler would not have said a word. A new field
        /// breaks every match site instead, which is the direction
        /// this wants to fail in.
        lapsed_at: Option<DateTime<Utc>>,
    },
}

/// Stable label for the `reason` field on
/// `SessionEvent::SessionScopedApprovalsCleared`. The audit variant
/// docstring lists `"session_ended"`, `"session_replaced"`, and
/// `"operator_revoke"` as the recognised values; this constant
/// centralises the "clean shutdown" case so the emitter and any
/// downstream pattern-match share one string.
pub const SESSION_CLEAR_REASON_ENDED: &str = "session_ended";

/// Session id the audit chain uses for operator actions on the
/// permission store that belong to no agent session.
///
/// `wirken permissions approve <key>` without `--session` writes a
/// persisted grant out of band of any conversation, so there is no
/// agent session to attribute it to. Before this constant those
/// grants were simply not recorded, which is a hole exactly where the
/// record matters: the persisted CLI path is the only production
/// writer of persisted grants, so `PermissionRenewed` would have had
/// nothing to fire on.
///
/// A sentinel lane rather than a synthetic agent session. The gateway
/// already keeps `gateway-hooks` (`crates/cli/src/commands/run.rs`)
/// and `gateway-mcp` for the same reason, and none of them show up as
/// agent sessions in `wirken sessions list`, which is what the
/// earlier objection to recording these was about.
pub const OPERATOR_PERMISSIONS_SESSION: &str = "gateway-permissions";

/// Append a `SessionEvent::SessionScopedApprovalsCleared` tombstone
/// to `log` under `session_id`. The shared emission point for any
/// caller that ends a session: today the in-daemon
/// [`AgentFactory::evict`] hook and the CLI `wirken sessions close`
/// shim. Centralising the call shape here keeps the trust level
/// (`System`), the field layout, and the wire-stable `reason`
/// constant in one place, so a future caller cannot accidentally
/// emit a tombstone the replay path does not recognise.
///
/// `count` is the number of session-scoped grants the caller
/// observed; replay treats the tombstone as authoritative
/// regardless of count, but SIEM consumers use it to size the
/// blast radius of the clear.
///
/// [`AgentFactory::evict`]: crate::permissions
// Note: the link target lives in crates/agent; rustdoc cannot resolve
// it from here without pulling agent in as a doc dep. Plain prose
// references it instead.
pub fn emit_session_scoped_approvals_cleared(
    log: &dyn wirken_audit::SessionLog,
    session_id: &str,
    count: u32,
    reason: &str,
) -> Result<(), wirken_audit::AuditError> {
    let handle = log.handle_for(wirken_audit::SessionId::new(session_id.to_string()));
    log.append(
        &handle,
        wirken_audit::TrustLevel::System,
        wirken_audit::SessionEvent::SessionScopedApprovalsCleared {
            session_id: session_id.to_string(),
            count,
            reason: reason.to_string(),
        },
    )?;
    Ok(())
}

/// Replay the session log to count active session-scoped grants for
/// `session_id`: number of distinct `action_key`s under
/// `PermissionApproved(Session)` events minus those tombstoned by a
/// subsequent `SessionScopedApprovalsCleared`. Used by out-of-process
/// callers (the CLI `wirken sessions close` shim) that do not share
/// the daemon's in-memory cache but need to know whether emitting a
/// tombstone is meaningful: returning zero lets the caller skip the
/// emit and preserve the "no audit noise for no-op" convention.
///
/// Returns the same number that `factory.evict`'s
/// `clear_session_scope` would have returned if it had run inside the
/// daemon, modulo grants made and not yet replayed (which an
/// out-of-process caller has no way to see anyway). Replay walks
/// events in seq order, so `grant + clear + grant` reports `1`.
pub fn count_active_session_scoped_approvals(
    log: &dyn wirken_audit::SessionLog,
    session_id: &str,
) -> Result<u32, wirken_audit::AuditError> {
    Ok(list_active_session_scoped_grants_in_session(log, session_id)?.len() as u32)
}

/// One row in an active session-scoped approval listing. Returned by
/// [`list_active_session_scoped_grants_in_session`] and
/// [`list_active_session_scoped_grants_for_agent`]. `approved_at` is
/// the timestamp from the original `PermissionApproved` audit row,
/// not the moment the listing was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSessionScopedGrant {
    pub session_id: String,
    pub action_key: String,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
}

/// Replay the session log for `session_id` and return one row per
/// `action_key` whose most-recent
/// `PermissionApproved(Session)` was not tombstoned by a later
/// `SessionScopedApprovalsCleared`. Same last-event-wins semantics
/// as `replay_session_scoped_approvals` in `wirken_agent::factory`,
/// but returns the rows instead of mutating a cache. Used by the
/// CLI list path (followup 2) to surface session-scoped grants
/// without crossing the daemon process boundary.
pub fn list_active_session_scoped_grants_in_session(
    log: &dyn wirken_audit::SessionLog,
    session_id: &str,
) -> Result<Vec<ActiveSessionScopedGrant>, wirken_audit::AuditError> {
    let handle = log.handle_for(wirken_audit::SessionId::new(session_id.to_string()));
    let events = log.get_since(&handle, 0)?;
    let mut active: std::collections::BTreeMap<String, (String, DateTime<Utc>)> =
        std::collections::BTreeMap::new();
    for stored in events {
        match stored.event {
            wirken_audit::SessionEvent::PermissionApproved {
                action_key,
                approved_by,
                scope: wirken_audit::ApprovalScopeKind::Session,
                session_id: Some(sid),
                ..
            } if sid == session_id => {
                active.insert(action_key, (approved_by, stored.ts));
            }
            wirken_audit::SessionEvent::SessionScopedApprovalsCleared {
                session_id: sid, ..
            } if sid == session_id => {
                active.clear();
            }
            _ => {}
        }
    }
    Ok(active
        .into_iter()
        .map(
            |(action_key, (approved_by, approved_at))| ActiveSessionScopedGrant {
                session_id: session_id.to_string(),
                action_key,
                approved_by,
                approved_at,
            },
        )
        .collect())
}

/// List every active session-scoped approval whose session id starts
/// with `{agent_id}/` (the canonical composite-id prefix produced by
/// `session_id_for`). Walks
/// `SqliteSessionLog::list_session_ids` and replays each candidate;
/// returns rows sorted by `(session_id, action_key)` for stable CLI
/// output. Out-of-process safe: the daemon's in-memory cache is not
/// consulted, only the on-disk session log.
///
/// Takes the concrete [`wirken_audit::SqliteSessionLog`] rather than
/// `&dyn SessionLog` because the cross-session enumeration is not on
/// the trait (the trait is per-session-handle by design). Callers
/// that hold a `&dyn SessionLog` cannot use this helper today;
/// none exist in production.
pub fn list_active_session_scoped_grants_for_agent(
    log: &wirken_audit::SqliteSessionLog,
    agent_id: &str,
) -> Result<Vec<ActiveSessionScopedGrant>, wirken_audit::AuditError> {
    let prefix = format!("{agent_id}/");
    let session_ids = log.list_session_ids()?;
    let mut out: Vec<ActiveSessionScopedGrant> = Vec::new();
    for sid in session_ids {
        if !sid.starts_with(&prefix) {
            continue;
        }
        let mut rows = list_active_session_scoped_grants_in_session(log, &sid)?;
        out.append(&mut rows);
    }
    out.sort_by(|a, b| {
        a.session_id
            .cmp(&b.session_id)
            .then_with(|| a.action_key.cmp(&b.action_key))
    });
    Ok(out)
}

/// Approve an action and append a `SessionEvent::PermissionApproved`
/// audit entry to `log` under `handle`. The orchestration helper for
/// any caller that has both the perm store and a session-log handle
/// in scope; the CLI session-scoped approval surface (slice 4) is
/// the first production caller. PermissionStore stays a pure data
/// layer; this function lives alongside it because it composes the
/// gateway-owned store with the audit-owned log.
///
/// Emission semantics:
/// - The event fires for every successful approval, regardless of
///   scope. `scope = Persisted` emits with `session_id: None`;
///   `scope = Session { .. }` emits with `session_id: Some(_)`.
/// - The persisted-from-CLI path (`commands::permission::approve`)
///   does NOT route through here today: it has no session-log
///   handle and no obvious session id to attribute the event to.
///   That call site stays silent for slice 3; a future slice can
///   wire a synthetic operator-action audit channel for it
///   without changing this function's shape.
/// - On audit failure the store-side write has already happened;
///   the helper returns `Err(GatewayError::Audit)` so the caller can
///   surface the inconsistency. This matches the existing pattern
///   where `?` on an `AuditError` short-circuits gateway flows that
///   require audit integrity.
#[allow(clippy::too_many_arguments)]
pub fn approve_and_log(
    store: &PermissionStore,
    action: &Action,
    agent_id: &str,
    approved_by: &str,
    scope: ApprovalScope,
    log: &dyn wirken_audit::SessionLog,
    handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    adapter_id: Option<&str>,
    sender_id: Option<&str>,
) -> Result<Approval, GatewayError> {
    approve_and_log_by_key(
        store,
        &action.approval_key(),
        agent_id,
        approved_by,
        scope,
        log,
        handle,
        adapter_id,
        sender_id,
    )
}

/// Key-driven counterpart to [`approve_and_log`]. CLI callers that
/// already hold a stringly-typed `action_key` (e.g. read off a
/// prior `PermissionDenied` audit row) skip the typed [`Action`]
/// reconstruction. Same emission semantics as [`approve_and_log`]:
/// every successful approval emits a `PermissionApproved` event,
/// `session_id` populated iff `scope == Session`.
#[allow(clippy::too_many_arguments)]
pub fn approve_and_log_by_key(
    store: &PermissionStore,
    action_key: &str,
    agent_id: &str,
    approved_by: &str,
    scope: ApprovalScope,
    log: &dyn wirken_audit::SessionLog,
    handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    adapter_id: Option<&str>,
    sender_id: Option<&str>,
) -> Result<Approval, GatewayError> {
    approve_and_log_by_key_with_expiry(
        store,
        action_key,
        agent_id,
        approved_by,
        scope,
        log,
        handle,
        adapter_id,
        sender_id,
        None,
    )
}

/// [`approve_and_log_by_key`] with a per-grant window.
///
/// Emits `PermissionRenewed` instead of `PermissionApproved` when
/// the write replaced a row that was already there, carrying both
/// the window it discarded and the one it installed. The store
/// reports which happened from inside the write itself, so the two
/// events cannot disagree with what landed in the table.
#[allow(clippy::too_many_arguments)]
pub fn approve_and_log_by_key_with_expiry(
    store: &PermissionStore,
    action_key: &str,
    agent_id: &str,
    approved_by: &str,
    scope: ApprovalScope,
    log: &dyn wirken_audit::SessionLog,
    handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    adapter_id: Option<&str>,
    sender_id: Option<&str>,
    expires_in_days: Option<u32>,
) -> Result<Approval, GatewayError> {
    let outcome = store.approve_with_scope_by_key_with_expiry(
        action_key,
        agent_id,
        approved_by,
        scope,
        expires_in_days,
    )?;
    let approval = outcome.approval;
    let (scope_kind, session_id) = approval.scope.to_audit_repr();
    let event = match outcome.renewed_from {
        Some(previous_expires_at) => wirken_audit::SessionEvent::PermissionRenewed {
            action_key: approval.action_key.clone(),
            agent_id: approval.agent_id.clone(),
            approved_by: approval.approved_by.clone(),
            previous_expires_at,
            expires_at: approval.expires_at,
            // Same reasoning as the `approved_via: None` below.
            approved_via: None,
            adapter_id: adapter_id.map(str::to_string),
            sender_id: sender_id.map(str::to_string),
        },
        None => wirken_audit::SessionEvent::PermissionApproved {
            action_key: approval.action_key.clone(),
            agent_id: approval.agent_id.clone(),
            approved_by: approval.approved_by.clone(),
            scope: scope_kind,
            session_id,
            // `approve_and_log` is the durable path (writes to the
            // store and emits the row); it predates `ApprovalSource`
            // and is called by paths that do not carry surface info.
            // The operator-mediated stdin / sse / cli paths call
            // `emit_operator_approval` (below) which carries the
            // structured surface.
            approved_via: None,
            adapter_id: adapter_id.map(str::to_string),
            sender_id: sender_id.map(str::to_string),
        },
    };
    log.append(handle, wirken_audit::TrustLevel::System, event)?;
    Ok(approval)
}

/// Operator-mediated approval that records the audit row WITHOUT
/// writing to the permission store. This is the path the
/// `ApprovalGate`-driven flow takes: an operator approved this one
/// invocation via a specific surface (stdin, sse, channel-adapter),
/// the agent retries the call once via the one-shot bypass, and the
/// next call to the same tool prompts fresh. The lack of a store
/// write is what makes this one-shot rather than session- or
/// persistently-scoped.
///
/// The audit row carries `approved_via: Some(source)` so a SIEM
/// detection can pivot per-surface, and `approved_by` for the actor
/// label (operator username when available, surface name otherwise).
/// `scope` is recorded as `Persisted` for wire-compat with prior
/// approval rows; the absence of a store row is the truth and the
/// audit chain is its only durable record.
///
/// Naming: sits alongside `approve_and_log` (Persisted) and a
/// future `approve_and_log_with_scope(Session)` so the family is
/// `emit_operator_approval` (one-shot) / `approve_and_log` (persisted) /
/// `approve_and_log_with_scope(Session)` (session-scoped). Three
/// functions, three scopes, one file.
#[allow(clippy::too_many_arguments)]
pub fn emit_operator_approval(
    action_key: &str,
    agent_id: &str,
    approved_by: &str,
    approved_via: wirken_audit::ApprovalSource,
    log: &dyn wirken_audit::SessionLog,
    handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
    adapter_id: Option<&str>,
    sender_id: Option<&str>,
) -> Result<(), GatewayError> {
    log.append(
        handle,
        wirken_audit::TrustLevel::System,
        wirken_audit::SessionEvent::PermissionApproved {
            action_key: action_key.to_string(),
            agent_id: agent_id.to_string(),
            approved_by: approved_by.to_string(),
            scope: wirken_audit::ApprovalScopeKind::Persisted,
            session_id: None,
            approved_via: Some(approved_via),
            adapter_id: adapter_id.map(str::to_string),
            sender_id: sender_id.map(str::to_string),
        },
    )?;
    Ok(())
}

/// Append one audit row per grant the open-time sweep removed.
///
/// Split from the sweep itself because the store holds no session
/// handle. The rows are already gone from SQLite by the time this
/// runs, so a failure here loses the record, not the removal; the
/// caller surfaces the `Err` rather than proceeding as though the
/// chain were complete.
///
/// Lapsed rows carry `detected_by: StoreOpen` and no tool, because
/// no call was involved. Not-storable rows are
/// `PermissionGrantPruned`, which is a different fact: they were
/// never readable, window or no window.
pub fn emit_sweep_report(
    report: &SweepReport,
    log: &dyn wirken_audit::SessionLog,
    handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
) -> Result<(), GatewayError> {
    for grant in &report.not_storable {
        log.append(
            handle,
            wirken_audit::TrustLevel::System,
            wirken_audit::SessionEvent::PermissionGrantPruned {
                action_key: grant.action_key.clone(),
                agent_id: grant.agent_id.clone(),
                expires_at: grant.expires_at,
            },
        )?;
    }
    for grant in &report.lapsed {
        log.append(
            handle,
            wirken_audit::TrustLevel::System,
            wirken_audit::SessionEvent::PermissionGrantExpired {
                action_key: grant.action_key.clone(),
                agent_id: grant.agent_id.clone(),
                // No call, so no tool and no tier. The sweep reads a
                // stored key, and recovering a typed action from one
                // is lossy; guessing a tier to fill the field would
                // put a guess in the chain.
                tool: None,
                tier: None,
                expired_at: grant.expires_at,
                detected_by: wirken_audit::GrantExpiryDetection::StoreOpen,
                adapter_id: None,
                sender_id: None,
            },
        )?;
    }
    Ok(())
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tier_tests {
    use super::*;

    fn shell(pattern: &str) -> Action {
        Action::ShellExec {
            pattern: pattern.into(),
        }
    }

    #[test]
    fn every_tier2_allowlist_verb_is_tier2() {
        for p in TIER2_ALLOWLIST {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier2,
                "allowlisted verb `{p}` must be Tier 2"
            );
        }
    }

    #[test]
    fn expected_verbs_are_in_allowlist() {
        // Regression: trimming the allowlist requires the change to
        // fail this test in review, since any of these becoming
        // Tier 3 is a user-facing policy change worth flagging.
        let expected = [
            "ls", "cat", "head", "tail", "grep", "stat", "pwd", "whoami", "date", "echo",
        ];
        for p in &expected {
            assert!(
                TIER2_ALLOWLIST.contains(p),
                "`{p}` must be in TIER2_ALLOWLIST"
            );
        }
    }

    #[test]
    fn formerly_tier2_unknown_verbs_are_now_tier3() {
        // Under the old denylist these were Tier 2 (just not on the
        // high-risk list). Under the allowlist they are Tier 3
        // because they are not on the allowlist. Locks in the
        // intentional shape change.
        for p in ["rg", "jq", "make", "cargo", "python", "node"] {
            assert_eq!(
                shell(p).tier(),
                PermissionTier::Tier3,
                "non-allowlisted verb `{p}` must now be Tier 3"
            );
        }
    }

    #[test]
    fn other_action_tiers_unchanged() {
        assert_eq!(Action::WorkspaceFileAccess.tier(), PermissionTier::Tier1);
        assert_eq!(Action::WebSearch.tier(), PermissionTier::Tier1);
        assert_eq!(Action::ChannelConverse.tier(), PermissionTier::Tier1);
        assert_eq!(
            Action::ExternalFileAccess {
                path: "/etc/passwd".into(),
            }
            .tier(),
            PermissionTier::Tier2
        );
        assert_eq!(
            Action::CrossConversationMessage.tier(),
            PermissionTier::Tier2
        );
        assert_eq!(Action::DestructiveFileOp.tier(), PermissionTier::Tier3);
        assert_eq!(
            Action::NetworkRequest {
                domain: "example.com".into(),
            }
            .tier(),
            PermissionTier::Tier3
        );
        assert_eq!(Action::CredentialAccess.tier(), PermissionTier::Tier3);
        assert_eq!(Action::CronCreate.tier(), PermissionTier::Tier3);
    }

    /// Compile-time tripwire: this match must remain exhaustive
    /// without a wildcard. Any new `Action` variant added without
    /// updating this list fails to compile. The check exists
    /// because `Action::SkillInstall` was previously defined here
    /// as a Tier 3 action but was never reachable from the CLI
    /// install path (install gates on signature verification, not
    /// tier classification); a future contributor reintroducing
    /// that variant or any other "added but never wired" variant
    /// will be forced to either wire it through or update this
    /// guard. See `crates/cli/src/commands/skills.rs::install`
    /// for the actual install gate.
    #[test]
    fn action_variant_set_is_pinned() {
        fn variant_label(a: &Action) -> &'static str {
            match a {
                Action::WorkspaceFileAccess => "workspace_file_access",
                Action::ChannelConverse => "channel_converse",
                Action::WebSearch => "web_search",
                Action::HttpRequest => "http_request",
                Action::ShellExec { .. } => "shell_exec",
                Action::ExternalFileAccess { .. } => "external_file_access",
                Action::CrossConversationMessage => "cross_conversation_message",
                Action::DestructiveFileOp => "destructive_file_op",
                Action::NetworkRequest { .. } => "network_request",
                Action::CredentialAccess => "credential_access",
                Action::CronCreate => "cron_create",
                Action::McpToolCall { .. } => "mcp_tool_call",
                Action::UnknownTool { .. } => "unknown_tool",
                Action::WasmSkillCall { .. } => "wasm_skill_call",
                Action::CrossChannelMemoryRead { .. } => "cross_channel_memory_read",
                Action::ImportedChatRead { .. } => "imported_chat_read",
                Action::ImportedChatSearch { .. } => "imported_chat_search",
            }
        }
        // Smoke a representative variant so the function isn't
        // dead-code-eliminated and the compile-time match still
        // gets exercised.
        assert_eq!(variant_label(&Action::WebSearch), "web_search");
    }

    #[test]
    fn an_imported_chat_read_is_tier_three_and_keyed_per_source() {
        let a = Action::ImportedChatRead {
            source_id: "src-1".into(),
        };
        assert_eq!(a.tier(), PermissionTier::Tier3);
        assert_eq!(a.approval_key(), "imported_chat:src-1");

        // The same shape the cross-channel precedent uses: approving
        // one archive approves no other, exactly as approving one
        // channel's history approves no other channel's.
        let b = Action::ImportedChatRead {
            source_id: "src-2".into(),
        };
        assert_ne!(a.approval_key(), b.approval_key());

        // An empty source yields a key no source carries, so it denies
        // rather than widening to every archive.
        let blank = Action::ImportedChatRead {
            source_id: String::new(),
        };
        assert_eq!(blank.approval_key(), "imported_chat:");
        assert_ne!(blank.approval_key(), a.approval_key());
    }

    #[test]
    fn a_scoped_and_an_unscoped_search_take_different_keys() {
        let scoped = Action::ImportedChatSearch {
            source_id: Some("src-1".into()),
        };
        let corpus = Action::ImportedChatSearch { source_id: None };
        assert_eq!(scoped.tier(), PermissionTier::Tier3);
        assert_eq!(corpus.tier(), PermissionTier::Tier3);
        assert_eq!(scoped.approval_key(), "imported_search:src-1");
        assert_eq!(corpus.approval_key(), "imported_search_corpus");

        // The corpus key is not in the scoped namespace, so no source
        // id can produce it however it is named.
        assert!(!corpus.approval_key().starts_with("imported_search:"));
        for id in ["corpus", "src-1", "", "*"] {
            let any = Action::ImportedChatSearch {
                source_id: Some(id.into()),
            };
            assert_ne!(any.approval_key(), corpus.approval_key(), "id {id:?}");
        }
    }

    #[test]
    fn search_and_read_approvals_never_imply_each_other() {
        // Different questions. Reading a conversation the operator
        // named is not sweeping for ones they did not; sweeping is not
        // reading what the sweep turns up.
        let read = Action::ImportedChatRead {
            source_id: "src-1".into(),
        };
        let search = Action::ImportedChatSearch {
            source_id: Some("src-1".into()),
        };
        assert_ne!(read.approval_key(), search.approval_key());
        let corpus = Action::ImportedChatSearch { source_id: None };
        assert_ne!(read.approval_key(), corpus.approval_key());
    }

    #[test]
    fn curl_cannot_be_pre_approved_and_always_prompts() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        // curl is Tier 3 under the allowlist. Two invariants:
        // 1. approve() refuses to store an approval for it (would
        //    otherwise be a dead row).
        // 2. check() returns Tier 3 NeedsApproval on every call.
        let err = store
            .approve(&shell("curl"), "default", "test-operator")
            .expect_err("approve for Tier 3 shell verb must refuse");
        match err {
            GatewayError::Config(msg) => assert!(msg.contains("Tier 3"), "msg: {msg}"),
            other => panic!("expected Config error, got {other:?}"),
        }
        let result = store.check(&shell("curl"), "default").unwrap();
        assert_eq!(
            result,
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier3,
                lapsed_at: None,
            },
        );
    }

    #[test]
    fn prune_drops_stale_non_allowlist_shell_rows_on_open() {
        let tmp = tempfile::NamedTempFile::new().unwrap();

        // Seed the DB with rows for verbs that WERE Tier 2 under the
        // old denylist and are now Tier 3. We bypass approve() since
        // it now refuses these, and insert directly.
        {
            let conn = rusqlite::Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS approvals (
                     action_key TEXT NOT NULL,
                     agent_id TEXT NOT NULL,
                     approved_at TEXT NOT NULL,
                     approved_by TEXT NOT NULL,
                     expires_at TEXT NOT NULL,
                     PRIMARY KEY (action_key, agent_id)
                 );",
            )
            .unwrap();
            for key in [
                "shell:git",
                "shell:kubectl",
                "shell:make",
                "shell:ls",
                "shell:cat",
            ] {
                conn.execute(
                    "INSERT INTO approvals VALUES (?1, 'default', '2026-01-01T00:00:00Z', 'seed', '2100-01-01T00:00:00Z')",
                    rusqlite::params![key],
                )
                .unwrap();
            }
            // Also seed a non-shell approval that must survive.
            conn.execute(
                "INSERT INTO approvals VALUES ('file:/tmp/*', 'default', '2026-01-01T00:00:00Z', 'seed', '2100-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Open runs the migration.
        let store = PermissionStore::open(tmp.path()).unwrap();

        // Allowlisted shell verbs survive. Non-allowlisted are gone.
        let remaining = store.list("default").unwrap();
        let keys: std::collections::BTreeSet<String> =
            remaining.iter().map(|a| a.action_key.clone()).collect();
        assert!(
            keys.contains("shell:ls"),
            "allowlisted shell:ls must survive"
        );
        assert!(
            keys.contains("shell:cat"),
            "allowlisted shell:cat must survive"
        );
        assert!(
            keys.contains("file:/tmp/*"),
            "non-shell approvals must survive"
        );
        assert!(!keys.contains("shell:git"), "shell:git must be pruned");
        assert!(
            !keys.contains("shell:kubectl"),
            "shell:kubectl must be pruned"
        );
        assert!(!keys.contains("shell:make"), "shell:make must be pruned");
    }

    #[test]
    fn sweep_is_idempotent_and_noop_on_clean_store() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut store = PermissionStore::open(tmp.path()).unwrap();
        // Fresh store is already clean.
        assert!(store.sweep_stale_grants().unwrap().is_empty());
        // Running again is still a no-op.
        assert!(store.sweep_stale_grants().unwrap().is_empty());
    }

    #[test]
    fn ls_is_first_use_then_silent_until_expiry() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        // First call: no record, needs approval at Tier 2.
        let first = store.check(&shell("ls"), "default").unwrap();
        assert_eq!(
            first,
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );
        // Operator approves once.
        store
            .approve(&shell("ls"), "default", "test-operator")
            .unwrap();
        // Subsequent calls within the 30-day window: allowed
        // without prompting. We check two calls to mirror the user
        // behavior "prompts once then runs silently".
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::Allowed
        );
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::Allowed
        );
    }

    #[test]
    fn approval_for_logical_agent_covers_session_scoped_check() {
        // The agent runtime passes the full session-scoped id
        // `{agent}/{channel}/{conversation}` into `check`. Approvals
        // are stored per logical agent, so the check must normalize
        // on the prefix before the first `/` or a webchat/Telegram
        // caller would never see a stored Tier 2 approval.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        store
            .approve(&shell("ls"), "default", "test-operator")
            .unwrap();

        assert_eq!(
            store
                .check(&shell("ls"), "default/webchat/webchat-default")
                .unwrap(),
            PermissionCheck::Allowed,
        );
        assert_eq!(
            store
                .check(&shell("ls"), "default/telegram/chat-42")
                .unwrap(),
            PermissionCheck::Allowed,
        );
        // approve_by_key called with a session-scoped id must also
        // normalize, so the stored row matches later checks.
        store
            .approve_by_key("shell:cat", "default/webchat/x", "test-operator")
            .unwrap();
        assert_eq!(
            store.check(&shell("cat"), "default").unwrap(),
            PermissionCheck::Allowed,
        );
    }

    // -----------------------------------------------------------------
    // Session-scoped approval cache (slice 2)
    // -----------------------------------------------------------------

    fn session_scope(id: &str) -> ApprovalScope {
        ApprovalScope::Session {
            session_id: id.to_string(),
        }
    }

    #[test]
    fn session_scoped_approval_does_not_write_to_sqlite() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let session = "default/webchat/conv-1";

        let approval = store
            .approve_with_scope(&shell("ls"), "default", "operator", session_scope(session))
            .unwrap();
        // The returned Approval carries the session scope verbatim.
        assert!(approval.scope.is_session_scoped());
        assert_eq!(approval.scope.session_id(), Some(session));

        // SQLite-side enumeration must show no rows: list() only
        // reads SQLite, so an empty list proves the cache write did
        // not leak into the durable store.
        let persisted = store.list("default").unwrap();
        assert!(
            persisted.is_empty(),
            "session-scoped approve must not write to SQLite, found: {:?}",
            persisted.iter().map(|a| &a.action_key).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn check_returns_allow_for_session_scoped_grant_within_same_session() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let session = "default/webchat/conv-1";

        // Baseline: no grant, Tier 2 needs approval.
        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );

        store
            .approve_with_scope(&shell("ls"), "default", "operator", session_scope(session))
            .unwrap();

        // Same session id passed to check resolves to Allowed.
        // Two calls in a row prove the cache survives the first read.
        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::Allowed,
        );
        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::Allowed,
        );
    }

    #[test]
    fn session_scoped_grant_does_not_leak_to_other_sessions() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let granted = "default/webchat/conv-1";
        let other = "default/webchat/conv-2";

        store
            .approve_with_scope(&shell("ls"), "default", "operator", session_scope(granted))
            .unwrap();

        // Different session id under the same logical agent: still
        // needs approval. Session-scoping is finer than the
        // canonical-agent-id lookup the SQLite path uses.
        assert_eq!(
            store.check(&shell("ls"), other).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );

        // Bare agent id (no `/`) is also not the session id and must
        // fall through to the SQLite path, which is empty.
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );
    }

    #[test]
    fn clear_session_scope_removes_entries_and_returns_count() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let session = "default/telegram/chat-7";

        store
            .approve_with_scope(&shell("ls"), "default", "operator", session_scope(session))
            .unwrap();
        store
            .approve_with_scope(&shell("cat"), "default", "operator", session_scope(session))
            .unwrap();
        // Separate session must not be cleared by the targeted call.
        store
            .approve_with_scope(
                &shell("head"),
                "default",
                "operator",
                session_scope("default/webchat/other"),
            )
            .unwrap();

        let cleared = store.clear_session_scope(session);
        assert_eq!(cleared, 2, "two action keys lived under this session");

        // Cleared session: back to needing approval.
        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );
        assert_eq!(
            store.check(&shell("cat"), session).unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );
        // Untouched session still allowed.
        assert_eq!(
            store
                .check(&shell("head"), "default/webchat/other")
                .unwrap(),
            PermissionCheck::Allowed,
        );

        // Clearing an empty session id is a 0-count no-op.
        assert_eq!(store.clear_session_scope("nonexistent/session"), 0);
        // Clearing the same session twice is a 0-count no-op (the
        // row was already removed).
        assert_eq!(store.clear_session_scope(session), 0);
    }

    #[test]
    fn persisted_approve_path_unchanged_when_session_cache_empty() {
        // Regression: the cache-first check must not interfere with
        // the existing SQLite-backed flow when no session-scoped
        // grant exists. Mirrors `ls_is_first_use_then_silent_until_expiry`
        // with the cache stable at empty.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::NeedsApproval {
                tier: PermissionTier::Tier2,
                lapsed_at: None,
            },
        );
        store.approve(&shell("ls"), "default", "operator").unwrap();
        assert_eq!(
            store.check(&shell("ls"), "default").unwrap(),
            PermissionCheck::Allowed,
        );
        // Persisted approvals are still listed by `list()`.
        let listed = store.list("default").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].action_key, "shell:ls");
        assert!(!listed[0].scope.is_session_scoped());
    }

    #[test]
    fn session_scoped_check_wins_over_persisted_lookup() {
        // Order matters: the cache short-circuit runs before the
        // SQLite check, so a session-scoped grant covers an action
        // even when no persisted approval exists. This is the
        // canonical path slice 3 will exercise via the CLI.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let session = "default/webchat/conv-x";
        store
            .approve_with_scope(&shell("ls"), "default", "operator", session_scope(session))
            .unwrap();

        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::Allowed,
        );
        // And the SQLite store is still empty under this agent id.
        assert!(store.list("default").unwrap().is_empty());
    }

    // -----------------------------------------------------------------
    // approve_and_log emission (slice 3)
    // -----------------------------------------------------------------

    #[test]
    fn approve_and_log_emits_permission_approved_with_session_scope() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let perms_tmp = tempfile::NamedTempFile::new().unwrap();
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(perms_tmp.path()).unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();

        let session = "default/webchat/conv-1";
        let handle = log.handle_for(SessionId::new(session.to_string()));
        let approval = super::approve_and_log(
            &store,
            &shell("ls"),
            "default",
            "operator",
            session_scope(session),
            &log,
            &handle,
            None,
            None,
        )
        .unwrap();

        // Store side: cache populated, SQLite empty.
        assert!(approval.scope.is_session_scoped());
        assert!(store.list("default").unwrap().is_empty());

        // Audit side: exactly one PermissionApproved row, fields exact.
        let events = log.get_since(&handle, 0).unwrap();
        let approved: Vec<_> = events
            .iter()
            .filter_map(|e| match &e.event {
                SessionEvent::PermissionApproved { .. } => Some(&e.event),
                _ => None,
            })
            .collect();
        assert_eq!(approved.len(), 1, "exactly one PermissionApproved emitted");
        match approved[0] {
            SessionEvent::PermissionApproved {
                action_key,
                agent_id,
                approved_by,
                scope,
                session_id,
                ..
            } => {
                assert_eq!(action_key, "shell:ls");
                assert_eq!(agent_id, "default");
                assert_eq!(approved_by, "operator");
                assert_eq!(*scope, wirken_audit::ApprovalScopeKind::Session);
                assert_eq!(session_id.as_deref(), Some(session));
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    #[test]
    fn approve_and_log_emits_permission_approved_with_persisted_scope() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let perms_tmp = tempfile::NamedTempFile::new().unwrap();
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(perms_tmp.path()).unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();

        // Persisted path still emits, but session_id is None on the
        // wire so a SIEM consumer pivoting on session-id does not
        // match. The store-side row lands in SQLite.
        let handle = log.handle_for(SessionId::new("__operator__".to_string()));
        super::approve_and_log(
            &store,
            &shell("ls"),
            "default",
            "operator",
            ApprovalScope::Persisted,
            &log,
            &handle,
            None,
            None,
        )
        .unwrap();

        let listed = store.list("default").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].action_key, "shell:ls");

        let events = log.get_since(&handle, 0).unwrap();
        let approved = events
            .iter()
            .find(|e| matches!(e.event, SessionEvent::PermissionApproved { .. }))
            .expect("one PermissionApproved emitted");
        match &approved.event {
            SessionEvent::PermissionApproved {
                scope, session_id, ..
            } => {
                assert_eq!(*scope, wirken_audit::ApprovalScopeKind::Persisted);
                assert!(session_id.is_none());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn approve_and_log_by_key_session_path_skips_sqlite() {
        // The CLI session-scoped surface
        // (`wirken permission approve <key> --session <id>`) drives
        // this overload directly with a stringly-typed action key.
        // Assert: no SQLite row, exactly one PermissionApproved
        // emitted with session_id populated, and a subsequent
        // check() inside the same session id is Allowed.
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let perms_tmp = tempfile::NamedTempFile::new().unwrap();
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(perms_tmp.path()).unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();

        let session = "default/webchat/conv-42";
        let handle = log.handle_for(SessionId::new(session.to_string()));
        let approval = super::approve_and_log_by_key(
            &store,
            "shell:ls",
            "default",
            "operator",
            session_scope(session),
            &log,
            &handle,
            None,
            None,
        )
        .unwrap();

        assert!(approval.scope.is_session_scoped());
        assert!(store.list("default").unwrap().is_empty());

        let events = log.get_since(&handle, 0).unwrap();
        let approved_rows: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event, SessionEvent::PermissionApproved { .. }))
            .collect();
        assert_eq!(approved_rows.len(), 1);
        match &approved_rows[0].event {
            SessionEvent::PermissionApproved {
                action_key,
                scope,
                session_id,
                ..
            } => {
                assert_eq!(action_key, "shell:ls");
                assert_eq!(*scope, wirken_audit::ApprovalScopeKind::Session);
                assert_eq!(session_id.as_deref(), Some(session));
            }
            _ => unreachable!(),
        }

        // check() inside the same session id is Allowed.
        assert_eq!(
            store.check(&shell("ls"), session).unwrap(),
            PermissionCheck::Allowed,
        );
    }

    // -----------------------------------------------------------------
    // Session-end emit + count helpers (followup 1)
    // -----------------------------------------------------------------

    #[test]
    fn emit_session_scoped_approvals_cleared_writes_tombstone() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let session = "default/webchat/conv-emit";

        super::emit_session_scoped_approvals_cleared(
            &log,
            session,
            3,
            super::SESSION_CLEAR_REASON_ENDED,
        )
        .unwrap();

        let handle = log.handle_for(SessionId::new(session.to_string()));
        let events = log.get_since(&handle, 0).unwrap();
        let cleared: Vec<_> = events
            .iter()
            .filter_map(|e| match &e.event {
                SessionEvent::SessionScopedApprovalsCleared { .. } => Some(&e.event),
                _ => None,
            })
            .collect();
        assert_eq!(cleared.len(), 1);
        match cleared[0] {
            SessionEvent::SessionScopedApprovalsCleared {
                session_id,
                count,
                reason,
            } => {
                assert_eq!(session_id, session);
                assert_eq!(*count, 3);
                assert_eq!(reason, super::SESSION_CLEAR_REASON_ENDED);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn count_active_session_scoped_approvals_walks_events() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let session = "default/webchat/conv-count";

        // Empty log: zero.
        assert_eq!(
            super::count_active_session_scoped_approvals(&log, session).unwrap(),
            0,
        );

        // Two grants under this session: active set = {shell:ls, shell:cat} → 2.
        let handle = log.handle_for(SessionId::new(session.to_string()));
        for key in ["shell:ls", "shell:cat"] {
            log.append(
                &handle,
                wirken_audit::TrustLevel::System,
                SessionEvent::PermissionApproved {
                    action_key: key.to_string(),
                    agent_id: "default".to_string(),
                    approved_by: "operator".to_string(),
                    scope: wirken_audit::ApprovalScopeKind::Session,
                    session_id: Some(session.to_string()),
                    approved_via: None,
                    adapter_id: None,
                    sender_id: None,
                },
            )
            .unwrap();
        }
        assert_eq!(
            super::count_active_session_scoped_approvals(&log, session).unwrap(),
            2,
        );

        // Tombstone clears the active set → 0.
        super::emit_session_scoped_approvals_cleared(
            &log,
            session,
            2,
            super::SESSION_CLEAR_REASON_ENDED,
        )
        .unwrap();
        assert_eq!(
            super::count_active_session_scoped_approvals(&log, session).unwrap(),
            0,
        );

        // Re-grant after the tombstone: active set = {shell:ls} → 1.
        // Matches the user's "clear wins iff no further grants"
        // semantics from slice 3.
        log.append(
            &handle,
            wirken_audit::TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: "shell:ls".to_string(),
                agent_id: "default".to_string(),
                approved_by: "operator".to_string(),
                scope: wirken_audit::ApprovalScopeKind::Session,
                session_id: Some(session.to_string()),
                approved_via: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();
        assert_eq!(
            super::count_active_session_scoped_approvals(&log, session).unwrap(),
            1,
        );
    }

    #[test]
    fn count_active_skips_persisted_and_other_sessions() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let target = "default/webchat/conv-target";
        let other = "default/webchat/conv-other";

        // A persisted PermissionApproved row inside the target session
        // log: must not count. Same target session log gets a Session-
        // scoped row that does count.
        let handle = log.handle_for(SessionId::new(target.to_string()));
        log.append(
            &handle,
            wirken_audit::TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: "shell:ls".to_string(),
                agent_id: "default".to_string(),
                approved_by: "operator".to_string(),
                scope: wirken_audit::ApprovalScopeKind::Persisted,
                session_id: None,
                approved_via: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();
        log.append(
            &handle,
            wirken_audit::TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: "shell:cat".to_string(),
                agent_id: "default".to_string(),
                approved_by: "operator".to_string(),
                scope: wirken_audit::ApprovalScopeKind::Session,
                session_id: Some(target.to_string()),
                approved_via: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();
        // A Session-scoped row whose inner session_id names a
        // different session (`other`): pathological, but the count
        // helper must reject the mismatch and not count it.
        log.append(
            &handle,
            wirken_audit::TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: "shell:head".to_string(),
                agent_id: "default".to_string(),
                approved_by: "operator".to_string(),
                scope: wirken_audit::ApprovalScopeKind::Session,
                session_id: Some(other.to_string()),
                approved_via: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();

        assert_eq!(
            super::count_active_session_scoped_approvals(&log, target).unwrap(),
            1,
            "only the session-scoped grant whose inner session_id matches target counts",
        );
    }

    // -----------------------------------------------------------------
    // list_active_session_scoped_grants_for_agent (followup 2)
    // -----------------------------------------------------------------

    fn append_session_grant(
        log: &wirken_audit::SqliteSessionLog,
        session_id: &str,
        action_key: &str,
        agent_id: &str,
        approved_by: &str,
    ) {
        use wirken_audit::{SessionEvent, SessionId, SessionLog};
        let handle = log.handle_for(SessionId::new(session_id.to_string()));
        log.append(
            &handle,
            wirken_audit::TrustLevel::System,
            SessionEvent::PermissionApproved {
                action_key: action_key.to_string(),
                agent_id: agent_id.to_string(),
                approved_by: approved_by.to_string(),
                scope: wirken_audit::ApprovalScopeKind::Session,
                session_id: Some(session_id.to_string()),
                approved_via: None,
                adapter_id: None,
                sender_id: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn list_active_grants_for_agent_returns_rows_across_sessions() {
        use wirken_audit::SqliteSessionLog;
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();

        // Same agent, two sessions, three distinct action keys.
        append_session_grant(&log, "default/webchat/conv-a", "shell:ls", "default", "op");
        append_session_grant(&log, "default/webchat/conv-a", "shell:cat", "default", "op");
        append_session_grant(
            &log,
            "default/signal/sender-1",
            "shell:head",
            "default",
            "op",
        );
        // Different agent: must not appear.
        append_session_grant(
            &log,
            "researcher/webchat/conv-x",
            "shell:wc",
            "researcher",
            "op",
        );

        let rows = super::list_active_session_scoped_grants_for_agent(&log, "default").unwrap();
        assert_eq!(
            rows.len(),
            3,
            "three grants for `default` across two sessions"
        );
        // Sort is (session_id, action_key) ascending.
        assert_eq!(rows[0].session_id, "default/signal/sender-1");
        assert_eq!(rows[0].action_key, "shell:head");
        assert_eq!(rows[1].session_id, "default/webchat/conv-a");
        assert_eq!(rows[1].action_key, "shell:cat");
        assert_eq!(rows[2].session_id, "default/webchat/conv-a");
        assert_eq!(rows[2].action_key, "shell:ls");

        // Cross-agent isolation: list for the other agent.
        let other = super::list_active_session_scoped_grants_for_agent(&log, "researcher").unwrap();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].action_key, "shell:wc");
    }

    #[test]
    fn list_active_grants_for_agent_skips_tombstoned_sessions() {
        use wirken_audit::SqliteSessionLog;
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();

        // Session A: grant then clear → no rows from A.
        append_session_grant(&log, "default/webchat/conv-a", "shell:ls", "default", "op");
        super::emit_session_scoped_approvals_cleared(
            &log,
            "default/webchat/conv-a",
            1,
            super::SESSION_CLEAR_REASON_ENDED,
        )
        .unwrap();

        // Session B: grant survives.
        append_session_grant(&log, "default/webchat/conv-b", "shell:cat", "default", "op");

        let rows = super::list_active_session_scoped_grants_for_agent(&log, "default").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "default/webchat/conv-b");
        assert_eq!(rows[0].action_key, "shell:cat");
    }

    #[test]
    fn list_active_grants_for_agent_empty_when_no_session_log_rows() {
        use wirken_audit::SqliteSessionLog;
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let rows = super::list_active_session_scoped_grants_for_agent(&log, "default").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_active_grants_re_grant_after_clear_includes_only_active() {
        // grant + clear + grant under same session = one row for the
        // most-recent grant, sourced from the post-clear event's
        // approved_by + approved_at fields.
        use wirken_audit::SqliteSessionLog;
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let session = "default/webchat/conv-c";

        append_session_grant(&log, session, "shell:ls", "default", "operator-a");
        super::emit_session_scoped_approvals_cleared(
            &log,
            session,
            1,
            super::SESSION_CLEAR_REASON_ENDED,
        )
        .unwrap();
        append_session_grant(&log, session, "shell:ls", "default", "operator-b");

        let rows = super::list_active_session_scoped_grants_for_agent(&log, "default").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action_key, "shell:ls");
        assert_eq!(
            rows[0].approved_by, "operator-b",
            "post-clear grant wins; pre-clear approved_by is gone",
        );
    }

    // -----------------------------------------------------------------
    // Grant expiry: store default, per-grant override, renewal, lapse
    // -----------------------------------------------------------------

    #[test]
    fn open_uses_the_documented_thirty_day_default() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        assert_eq!(store.default_expiry_days(), DEFAULT_GRANT_EXPIRY_DAYS);
        assert_eq!(DEFAULT_GRANT_EXPIRY_DAYS, 30);
    }

    #[test]
    fn store_default_window_applies_to_grants_that_name_none() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open_with_expiry(tmp.path(), 7).unwrap();
        let before = Utc::now();
        let approval = store
            .approve_by_key("shell:ls", "agent-a", "operator")
            .unwrap();
        let window = approval.expires_at - before;
        assert!(
            window >= Duration::days(7) - Duration::minutes(1)
                && window <= Duration::days(7) + Duration::minutes(1),
            "expected a 7-day window from the store default, got {window}",
        );
    }

    #[test]
    fn per_grant_override_beats_the_store_default_in_both_directions() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open_with_expiry(tmp.path(), 7).unwrap();

        // Shorter than the default.
        let before = Utc::now();
        let short = store
            .approve_by_key_with_expiry("shell:ls", "agent-a", "operator", Some(1))
            .unwrap();
        assert!(short.approval.expires_at - before < Duration::days(2));

        // Longer than the default. The default is what an operator
        // gets when they say nothing, not a ceiling on what they can
        // ask for.
        let before = Utc::now();
        let long = store
            .approve_by_key_with_expiry("shell:cat", "agent-a", "operator", Some(90))
            .unwrap();
        assert!(long.approval.expires_at - before > Duration::days(89));
    }

    #[test]
    fn zero_day_windows_are_refused_at_open_and_at_grant() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(
            PermissionStore::open_with_expiry(tmp.path(), 0).is_err(),
            "a zero-day store default stores grants that are already expired",
        );

        let store = PermissionStore::open(tmp.path()).unwrap();
        assert!(
            store
                .approve_by_key_with_expiry("shell:ls", "agent-a", "operator", Some(0))
                .is_err(),
            "a zero-day per-grant override has the same problem",
        );
    }

    #[test]
    fn first_grant_reports_no_prior_window_and_a_regrant_reports_the_one_it_replaced() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();

        let first = store
            .approve_by_key_with_expiry("shell:ls", "agent-a", "operator", Some(3))
            .unwrap();
        assert!(first.renewed_from.is_none(), "nothing was there to replace",);

        let second = store
            .approve_by_key_with_expiry("shell:ls", "agent-a", "operator", Some(30))
            .unwrap();
        assert_eq!(
            second.renewed_from,
            Some(first.approval.expires_at),
            "the renewal carries the window it discarded",
        );
        assert!(
            second.approval.expires_at > first.approval.expires_at,
            "and the window it installed",
        );

        // INSERT OR REPLACE, so one row per key, not two.
        assert_eq!(store.list("agent-a").unwrap().len(), 1);
    }

    #[test]
    fn a_lapsed_grant_is_still_a_renewal_when_regranted() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let lapsed = Utc::now() - Duration::days(2);
        store
            .conn
            .execute(
                "INSERT INTO approvals (action_key, agent_id, approved_at, approved_by, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "shell:ls",
                    "agent-a",
                    (lapsed - Duration::days(30)).to_rfc3339(),
                    "operator",
                    lapsed.to_rfc3339()
                ],
            )
            .unwrap();

        let outcome = store
            .approve_by_key_with_expiry("shell:ls", "agent-a", "operator", None)
            .unwrap();
        assert!(
            outcome.renewed_from.is_some(),
            "losing the history because the window closed first is the gap this closes",
        );
    }

    #[test]
    fn check_reports_the_window_a_lapsed_grant_held_then_drops_the_row() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let action = Action::ShellExec {
            pattern: "ls".into(),
        };
        let lapsed = Utc::now() - Duration::hours(1);
        store
            .conn
            .execute(
                "INSERT INTO approvals (action_key, agent_id, approved_at, approved_by, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "shell:ls",
                    "agent-a",
                    (lapsed - Duration::days(30)).to_rfc3339(),
                    "operator",
                    lapsed.to_rfc3339()
                ],
            )
            .unwrap();

        match store.check(&action, "agent-a").unwrap() {
            PermissionCheck::NeedsApproval {
                tier,
                lapsed_at: Some(at),
            } => {
                assert_eq!(tier, PermissionTier::Tier2);
                // Whole-second RFC3339 round-trip through SQLite.
                assert!((at - lapsed).num_seconds().abs() <= 1);
            }
            other => panic!("expected a reported lapse, got {other:?}"),
        }

        // The row is gone, so the second check reports no grant
        // rather than reporting the same lapse twice.
        assert!(
            matches!(
                store.check(&action, "agent-a").unwrap(),
                PermissionCheck::NeedsApproval {
                    lapsed_at: None,
                    ..
                }
            ),
            "the lapse is reported once, by the check that dropped the row",
        );
    }

    #[test]
    fn a_live_grant_and_an_ungranted_key_both_report_no_lapse() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let action = Action::ShellExec {
            pattern: "ls".into(),
        };

        assert!(matches!(
            store.check(&action, "agent-a").unwrap(),
            PermissionCheck::NeedsApproval {
                lapsed_at: None,
                ..
            }
        ));

        store.approve(&action, "agent-a", "operator").unwrap();
        assert_eq!(
            store.check(&action, "agent-a").unwrap(),
            PermissionCheck::Allowed,
        );
    }

    // -----------------------------------------------------------------
    // Storable-key allowlist
    // -----------------------------------------------------------------

    #[test]
    fn only_tier2_keys_are_storable() {
        for key in ["shell:ls", "shell:cat", "file:/tmp/x", "cross-conversation"] {
            assert!(
                is_storable_approval_key(key),
                "{key} is Tier 2 and must be storable",
            );
        }
        for key in [
            // Tier 3, refused before this change.
            "shell:curl",
            "cross_channel_memory:slack",
            // Tier 3, accepted before this change.
            "mcp:mcp_github_create_issue",
            "tool:something_unregistered",
            "wasm:my_skill",
            "imported_chat:src-1",
            "imported_search:src-1",
            "imported_search_corpus",
            "NetworkRequest { domain: \"api.openai.com\" }",
            "CredentialAccess",
            "CronCreate",
            "DestructiveFileOp",
            // Tier 1: allowed with no lookup, so a stored row is
            // dead weight that reads as though it did something.
            "WorkspaceFileAccess",
            "WebSearch",
            "HttpRequest",
            // Degenerate.
            "file:",
            "",
        ] {
            assert!(
                !is_storable_approval_key(key),
                "{key} is not Tier 2 and must not be storable",
            );
        }
    }

    #[test]
    fn every_tier3_approval_key_is_refused_by_approve_by_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();

        let tier3 = [
            Action::McpToolCall {
                tool: "mcp_github_create_issue".into(),
            },
            Action::UnknownTool {
                tool: "unregistered".into(),
            },
            Action::WasmSkillCall {
                skill: "my_skill".into(),
            },
            Action::CrossChannelMemoryRead {
                from_channel: "slack".into(),
            },
            Action::ImportedChatRead {
                source_id: "src-1".into(),
            },
            Action::ImportedChatSearch {
                source_id: Some("src-1".into()),
            },
            Action::ImportedChatSearch { source_id: None },
            Action::DestructiveFileOp,
            Action::CredentialAccess,
            Action::CronCreate,
            Action::NetworkRequest {
                domain: "api.openai.com".into(),
            },
            Action::ShellExec {
                pattern: "curl".into(),
            },
        ];
        for action in &tier3 {
            assert_eq!(action.tier(), PermissionTier::Tier3, "{action} sanity");
            let key = action.approval_key();
            assert!(
                store.approve_by_key(&key, "agent-a", "operator").is_err(),
                "storing '{key}' would list a grant the gate never reads",
            );
        }
        assert!(
            store.list("agent-a").unwrap().is_empty(),
            "no refused key left a row behind",
        );
    }

    // -----------------------------------------------------------------
    // Audit: renewal is a distinct event from first grant
    // -----------------------------------------------------------------

    #[test]
    fn first_grant_logs_approved_and_the_regrant_logs_renewed() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let handle = log.handle_for(SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()));

        let first = super::approve_and_log_by_key_with_expiry(
            &store,
            "shell:ls",
            "agent-a",
            "operator",
            ApprovalScope::Persisted,
            &log,
            &handle,
            None,
            None,
            Some(3),
        )
        .unwrap();
        let second = super::approve_and_log_by_key_with_expiry(
            &store,
            "shell:ls",
            "agent-a",
            "operator",
            ApprovalScope::Persisted,
            &log,
            &handle,
            None,
            None,
            Some(30),
        )
        .unwrap();

        let events = log.get_since(&handle, 0).unwrap();
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| match &e.event {
                SessionEvent::PermissionApproved { .. } => "approved",
                SessionEvent::PermissionRenewed { .. } => "renewed",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["approved", "renewed"]);

        match &events[1].event {
            SessionEvent::PermissionRenewed {
                action_key,
                agent_id,
                previous_expires_at,
                expires_at,
                ..
            } => {
                assert_eq!(action_key, "shell:ls");
                assert_eq!(agent_id, "agent-a");
                assert_eq!(*previous_expires_at, first.expires_at);
                assert_eq!(*expires_at, second.expires_at);
            }
            other => panic!("expected PermissionRenewed, got {other:?}"),
        }
    }

    #[test]
    fn regranting_a_session_scope_stays_an_approval_not_a_renewal() {
        use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = PermissionStore::open(tmp.path()).unwrap();
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let session = "agent-a/webchat/conv-1";
        let handle = log.handle_for(SessionId::new(session.to_string()));
        let scope = ApprovalScope::Session {
            session_id: session.to_string(),
        };

        for _ in 0..2 {
            super::approve_and_log_by_key(
                &store,
                "shell:ls",
                "agent-a",
                "operator",
                scope.clone(),
                &log,
                &handle,
                None,
                None,
            )
            .unwrap();
        }

        let events = log.get_since(&handle, 0).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| matches!(e.event, SessionEvent::PermissionApproved { .. })),
            "a session grant has no window to have discarded, so re-granting is idempotent, \
             not a renewal",
        );
    }

    // -----------------------------------------------------------------
    // Open-time sweep of rows the gate cannot act on
    // -----------------------------------------------------------------

    /// Write a row straight to the table, bypassing the write-path
    /// allowlist. Reproduces what an older build left behind.
    fn seed_row(path: &std::path::Path, key: &str, agent: &str, expires_at: DateTime<Utc>) {
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS approvals (
                 action_key TEXT NOT NULL,
                 agent_id TEXT NOT NULL,
                 approved_at TEXT NOT NULL,
                 approved_by TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 PRIMARY KEY (action_key, agent_id)
             );",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO approvals
             (action_key, agent_id, approved_at, approved_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                key,
                agent,
                (expires_at - Duration::days(30)).to_rfc3339(),
                "operator",
                expires_at.to_rfc3339()
            ],
        )
        .unwrap();
    }

    #[test]
    fn open_sweeps_rows_an_upgrade_left_behind_and_leaves_live_tier2_alone() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let future = Utc::now() + Duration::days(10);
        let past = Utc::now() - Duration::days(1);

        // Not storable, and not expired, so nothing else would ever
        // have removed them. This is the false floor: an operator
        // reading `wirken permissions list` saw grants.
        for key in [
            "mcp:mcp_github_create_issue",
            "tool:unregistered",
            "wasm:my_skill",
            "imported_chat:src-1",
            "imported_search_corpus",
            "cross_channel_memory:slack",
            "shell:kubectl",
            "CredentialAccess",
            "WebSearch",
        ] {
            seed_row(tmp.path(), key, "agent-a", future);
        }
        // Storable but lapsed, with nothing having called it.
        seed_row(tmp.path(), "shell:ls", "agent-a", past);
        // Storable and live: must survive.
        seed_row(tmp.path(), "shell:cat", "agent-a", future);
        seed_row(tmp.path(), "file:/tmp/x", "agent-a", future);

        let mut store = PermissionStore::open(tmp.path()).unwrap();
        let report = store.take_sweep_report();

        assert_eq!(report.not_storable.len(), 9, "{report:#?}");
        assert_eq!(report.lapsed.len(), 1, "{report:#?}");
        assert_eq!(report.lapsed[0].action_key, "shell:ls");
        assert!((report.lapsed[0].expires_at - past).num_seconds().abs() <= 1);

        let survivors: std::collections::HashSet<String> = store
            .list("agent-a")
            .unwrap()
            .into_iter()
            .map(|a| a.action_key)
            .collect();
        assert_eq!(
            survivors,
            ["shell:cat", "file:/tmp/x"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
    }

    #[test]
    fn a_row_that_is_both_unreadable_and_lapsed_reports_as_unreadable() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        seed_row(
            tmp.path(),
            "mcp:mcp_vendor_tool",
            "agent-a",
            Utc::now() - Duration::days(1),
        );
        let mut store = PermissionStore::open(tmp.path()).unwrap();
        let report = store.take_sweep_report();
        assert_eq!(report.not_storable.len(), 1);
        assert!(
            report.lapsed.is_empty(),
            "the older and more surprising fact is that it never worked at all",
        );
    }

    #[test]
    fn the_sweep_report_has_one_owner() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        seed_row(
            tmp.path(),
            "mcp:x",
            "agent-a",
            Utc::now() + Duration::days(5),
        );
        let mut store = PermissionStore::open(tmp.path()).unwrap();
        assert_eq!(store.take_sweep_report().len(), 1);
        assert!(
            store.take_sweep_report().is_empty(),
            "a second taker must not emit the same removal twice",
        );
    }

    #[test]
    fn reopening_a_swept_store_sweeps_nothing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        seed_row(
            tmp.path(),
            "mcp:x",
            "agent-a",
            Utc::now() + Duration::days(5),
        );
        seed_row(
            tmp.path(),
            "shell:ls",
            "agent-a",
            Utc::now() - Duration::days(1),
        );
        let mut first = PermissionStore::open(tmp.path()).unwrap();
        assert_eq!(first.take_sweep_report().len(), 2);
        drop(first);

        let mut second = PermissionStore::open(tmp.path()).unwrap();
        assert!(second.take_sweep_report().is_empty());
    }

    #[test]
    fn the_sweep_writes_one_audit_row_per_removal_with_the_right_kind() {
        use wirken_audit::{
            GrantExpiryDetection, SessionEvent, SessionId, SessionLog, SqliteSessionLog,
        };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let lapsed_at = Utc::now() - Duration::days(2);
        let live = Utc::now() + Duration::days(5);
        seed_row(tmp.path(), "mcp:mcp_vendor_tool", "agent-a", live);
        seed_row(tmp.path(), "shell:ls", "agent-a", lapsed_at);

        let mut store = PermissionStore::open(tmp.path()).unwrap();
        let report = store.take_sweep_report();

        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let handle = log.handle_for(SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()));
        super::emit_sweep_report(&report, &log, &handle).unwrap();

        let events = log.get_since(&handle, 0).unwrap();
        assert_eq!(events.len(), 2, "{events:#?}");

        match &events[0].event {
            SessionEvent::PermissionGrantPruned {
                action_key,
                agent_id,
                expires_at,
            } => {
                assert_eq!(action_key, "mcp:mcp_vendor_tool");
                assert_eq!(agent_id, "agent-a");
                assert!(
                    (*expires_at - live).num_seconds().abs() <= 1,
                    "the window the operator would have seen listed",
                );
            }
            other => panic!("expected PermissionGrantPruned, got {other:?}"),
        }
        match &events[1].event {
            SessionEvent::PermissionGrantExpired {
                action_key,
                tool,
                tier,
                expired_at,
                detected_by,
                ..
            } => {
                assert_eq!(action_key, "shell:ls");
                assert_eq!(*detected_by, GrantExpiryDetection::StoreOpen);
                assert!(tool.is_none(), "no call was involved");
                assert!(
                    tier.is_none(),
                    "a guessed tier would be a guess in the chain"
                );
                assert!((*expired_at - lapsed_at).num_seconds().abs() <= 1);
            }
            other => panic!("expected PermissionGrantExpired, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_report_writes_nothing() {
        use wirken_audit::{SessionId, SessionLog, SqliteSessionLog};
        let audit_tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteSessionLog::open(audit_tmp.path()).unwrap();
        let handle = log.handle_for(SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()));
        super::emit_sweep_report(&SweepReport::default(), &log, &handle).unwrap();
        assert!(log.get_since(&handle, 0).unwrap().is_empty());
    }
}
