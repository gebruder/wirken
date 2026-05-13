//! Per-skill permission profile parsed from SKILL.md frontmatter.
//!
//! Four axes, default-deny on every one:
//! - `tools` — which tool names this skill needs the agent to expose.
//! - `egress` — which network hosts this skill needs the agent to reach.
//! - `filesystem` — which paths this skill needs the agent to read or write.
//! - `inference` — which LLM providers this skill needs the agent to call.
//!
//! Enforcement is per-agent: the agent computes its effective profile at init
//! as the union of all loaded skills' declared profiles. The `permissions:`
//! block is optional: when omitted, the loader falls back to
//! `PermissionProfile::default()`, least-privilege on every axis (empty tool
//! allowlist, deny-all egress, empty filesystem allowlists, empty inference
//! allowlist). A skill without the block loads, but cannot do anything beyond
//! emitting text through the prompt; the operator opts into capability by
//! writing the block. The only path that produces `EffectiveProfile::Legacy`
//! is the empty-attach case (no skills loaded at all).
//!
//! Wildcard `"*"` is supported on `tools`, `egress.domains`, and
//! `inference.allow`. Filesystem wildcards are rejected: cap-std workspace
//! is the outer bound and `"*"` for paths is meaningless inside it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;

const WILDCARD: &str = "*";
/// Token in `filesystem.{read,write}_paths` that resolves to the agent's
/// workspace at attach time. Skills that need general workspace access
/// (the common case for general-purpose skills) declare
/// `read_paths: ["<workspace>"]` rather than hard-coding a per-user path
/// that the skill bundle cannot know.
pub const WORKSPACE_TOKEN: &str = "<workspace>";

/// Resolved profile after parse + validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionProfile {
    pub tools: ToolPolicy,
    pub egress: EgressPolicy,
    pub filesystem: FilesystemPolicy,
    pub inference: InferencePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowSet {
    Wildcard,
    Set(BTreeSet<String>),
}

impl Default for AllowSet {
    fn default() -> Self {
        AllowSet::Set(BTreeSet::new())
    }
}

impl AllowSet {
    pub fn allows(&self, name: &str) -> bool {
        match self {
            AllowSet::Wildcard => true,
            AllowSet::Set(set) => set.contains(name),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, AllowSet::Set(s) if s.is_empty())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPolicy {
    pub allow: AllowSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    pub mode: EgressMode,
    pub domains: AllowSet,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            mode: EgressMode::Deny,
            domains: AllowSet::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    Allowlist,
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemPolicy {
    pub write_paths: BTreeSet<PathBuf>,
    pub read_paths: BTreeSet<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InferencePolicy {
    pub allow: AllowSet,
    pub default: Option<String>,
}

/// On-disk YAML shape under the `permissions:` key.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PermissionsBlock {
    #[serde(default)]
    pub tools: Option<ToolsRaw>,
    #[serde(default)]
    pub egress: Option<EgressRaw>,
    #[serde(default)]
    pub filesystem: Option<FilesystemRaw>,
    #[serde(default)]
    pub inference: Option<InferenceRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ToolsRaw {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRaw {
    #[serde(default = "default_egress_mode")]
    pub mode: String,
    #[serde(default)]
    pub domains: Vec<String>,
}

fn default_egress_mode() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRaw {
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub read_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InferenceRaw {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PermissionsError {
    #[error("invalid YAML in permissions block: {0}")]
    Yaml(String),
    #[error("invalid egress mode '{0}' (expected 'allowlist' or 'deny')")]
    InvalidEgressMode(String),
    #[error("wildcard '*' not allowed for filesystem paths")]
    FilesystemWildcard,
    #[error("permissions.{axis}.allow mixes wildcard '*' with specific entries")]
    MixedWildcard { axis: String },
    #[error("filesystem.write_paths entry '{0}' is inside skill bundle root")]
    WritePathInsideSkillRoot(PathBuf),
    #[error("filesystem path '{0}' must be absolute (use '~/' for home-relative)")]
    NonAbsolutePath(PathBuf),
    #[error("invalid host pattern: '{0}'")]
    InvalidHost(String),
    #[error("inference.default '{0}' is not in inference.allow")]
    DefaultNotInAllow(String),
    #[error("egress.mode is 'deny' but domains is non-empty")]
    DenyWithDomains,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MergeError {
    #[error("skills declare conflicting inference.default values: {found:?}")]
    DefaultConflict { found: BTreeSet<String> },
}

/// Parse + validate a `permissions:` block from a YAML string.
///
/// `skill_root` is the directory containing SKILL.md; used to reject
/// `write_paths` entries inside the bundle. `home` is the user's home for
/// `~/` expansion; `None` keeps `~`-prefixed paths literal (and they will
/// fail the absolute-path check downstream).
pub fn parse_block(
    yaml: &str,
    skill_root: &Path,
    home: Option<&Path>,
) -> Result<PermissionProfile, PermissionsError> {
    let block: PermissionsBlock =
        serde_yaml::from_str(yaml).map_err(|e| PermissionsError::Yaml(e.to_string()))?;
    resolve_block(block, skill_root, home)
}

/// Validate and convert a deserialized block to a resolved profile.
pub fn resolve_block(
    block: PermissionsBlock,
    skill_root: &Path,
    home: Option<&Path>,
) -> Result<PermissionProfile, PermissionsError> {
    let tools = match block.tools {
        Some(t) => ToolPolicy {
            allow: resolve_allow(&t.allow, "tools")?,
        },
        None => ToolPolicy::default(),
    };

    let egress = match block.egress {
        Some(e) => {
            let mode = match e.mode.as_str() {
                "allowlist" => EgressMode::Allowlist,
                "deny" => EgressMode::Deny,
                other => return Err(PermissionsError::InvalidEgressMode(other.to_string())),
            };
            let domains = resolve_allow(&e.domains, "egress")?;
            if matches!(mode, EgressMode::Deny) && !domains.is_empty() {
                return Err(PermissionsError::DenyWithDomains);
            }
            for d in iter_set(&domains) {
                validate_host(d)?;
            }
            EgressPolicy { mode, domains }
        }
        None => EgressPolicy::default(),
    };

    let filesystem = match block.filesystem {
        Some(f) => {
            let write_paths = resolve_paths(&f.write_paths, home, /*allow_wildcard=*/ false)?;
            let read_paths = resolve_paths(&f.read_paths, home, /*allow_wildcard=*/ false)?;
            let canonical_root = canonicalize_or(skill_root);
            for p in &write_paths {
                if p.starts_with(&canonical_root) {
                    return Err(PermissionsError::WritePathInsideSkillRoot(p.clone()));
                }
            }
            FilesystemPolicy {
                write_paths,
                read_paths,
            }
        }
        None => FilesystemPolicy::default(),
    };

    let inference = match block.inference {
        Some(i) => {
            let allow = resolve_allow(&i.allow, "inference")?;
            if let Some(ref d) = i.default {
                if !allow.allows(d) {
                    return Err(PermissionsError::DefaultNotInAllow(d.clone()));
                }
            }
            InferencePolicy {
                allow,
                default: i.default,
            }
        }
        None => InferencePolicy::default(),
    };

    Ok(PermissionProfile {
        tools,
        egress,
        filesystem,
        inference,
    })
}

fn resolve_allow(items: &[String], axis: &str) -> Result<AllowSet, PermissionsError> {
    let has_wildcard = items.iter().any(|s| s == WILDCARD);
    let specifics: BTreeSet<String> = items
        .iter()
        .filter(|s| s.as_str() != WILDCARD)
        .cloned()
        .collect();

    if has_wildcard && !specifics.is_empty() {
        return Err(PermissionsError::MixedWildcard {
            axis: axis.to_string(),
        });
    }

    if has_wildcard {
        Ok(AllowSet::Wildcard)
    } else {
        Ok(AllowSet::Set(specifics))
    }
}

fn iter_set(allow: &AllowSet) -> Box<dyn Iterator<Item = &String> + '_> {
    match allow {
        AllowSet::Wildcard => Box::new(std::iter::empty()),
        AllowSet::Set(s) => Box::new(s.iter()),
    }
}

fn resolve_paths(
    raw: &[String],
    home: Option<&Path>,
    allow_wildcard: bool,
) -> Result<BTreeSet<PathBuf>, PermissionsError> {
    let mut out = BTreeSet::new();
    for entry in raw {
        if entry == WILDCARD {
            if allow_wildcard {
                continue;
            }
            return Err(PermissionsError::FilesystemWildcard);
        }
        // `<workspace>` and `<workspace>/<rel>` are kept as-is; the agent
        // expands the leading token at `attach_skills` time when the
        // workspace path is known.
        if entry == WORKSPACE_TOKEN || entry.starts_with(&format!("{WORKSPACE_TOKEN}/")) {
            out.insert(PathBuf::from(entry));
            continue;
        }
        let expanded = expand_home(entry, home);
        if !expanded.is_absolute() {
            return Err(PermissionsError::NonAbsolutePath(expanded));
        }
        out.insert(expanded);
    }
    Ok(out)
}

fn expand_home(entry: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = entry.strip_prefix("~/")
        && let Some(home) = home
    {
        return home.join(rest);
    }
    if entry == "~"
        && let Some(home) = home
    {
        return home.to_path_buf();
    }
    PathBuf::from(entry)
}

fn canonicalize_or(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

fn validate_host(s: &str) -> Result<(), PermissionsError> {
    if s.is_empty() {
        return Err(PermissionsError::InvalidHost(s.to_string()));
    }
    // Reject schemes, paths, and credentials. Hosts are bare authorities:
    // `example.com`, `api.example.com`, `*.example.com`.
    if s.contains("://") || s.contains('/') || s.contains('@') || s.contains(':') || s.contains(' ')
    {
        return Err(PermissionsError::InvalidHost(s.to_string()));
    }
    // Each label is letters/digits/hyphen/dot; leading wildcard label allowed.
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*';
    if !s.chars().all(allowed) {
        return Err(PermissionsError::InvalidHost(s.to_string()));
    }
    Ok(())
}

/// Effective per-agent profile after attaching all skills. The agent's
/// enforcement points consult this; `Legacy` short-circuits all checks
/// (full surface) and is only reachable when the agent has zero skills
/// attached. Post-migration-window the loader hard-fails on a missing
/// `permissions:` block, so every loaded skill carries a profile and
/// any non-empty attach produces `Resolved`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EffectiveProfile {
    /// Full surface, no checks. Reached only when zero skills are attached.
    #[default]
    Legacy,
    /// Union of declared profiles. Every enforcement point honors it.
    Resolved(PermissionProfile),
}

impl EffectiveProfile {
    pub fn allows_tool(&self, name: &str) -> bool {
        match self {
            EffectiveProfile::Legacy => true,
            EffectiveProfile::Resolved(p) => p.tools.allow.allows(name),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        match self {
            EffectiveProfile::Legacy => true,
            EffectiveProfile::Resolved(p) => match p.egress.mode {
                EgressMode::Allowlist => host_in_set(host, &p.egress.domains),
                EgressMode::Deny => false,
            },
        }
    }

    pub fn allows_provider(&self, name: &str) -> bool {
        match self {
            EffectiveProfile::Legacy => true,
            EffectiveProfile::Resolved(p) => p.inference.allow.allows(name),
        }
    }

    pub fn allows_read_path(&self, path: &Path) -> bool {
        match self {
            EffectiveProfile::Legacy => true,
            EffectiveProfile::Resolved(p) => path_under_any(path, &p.filesystem.read_paths),
        }
    }

    pub fn allows_write_path(&self, path: &Path) -> bool {
        match self {
            EffectiveProfile::Legacy => true,
            EffectiveProfile::Resolved(p) => path_under_any(path, &p.filesystem.write_paths),
        }
    }

    pub fn inference_default(&self) -> Option<&str> {
        match self {
            EffectiveProfile::Legacy => None,
            EffectiveProfile::Resolved(p) => p.inference.default.as_deref(),
        }
    }

    /// Replace every literal `<workspace>` token in filesystem paths with
    /// the agent's actual workspace. No-op for `Legacy`.
    pub fn expand_workspace(self, workspace: &Path) -> Self {
        match self {
            EffectiveProfile::Legacy => EffectiveProfile::Legacy,
            EffectiveProfile::Resolved(mut p) => {
                p.filesystem.write_paths =
                    expand_workspace_set(p.filesystem.write_paths, workspace);
                p.filesystem.read_paths = expand_workspace_set(p.filesystem.read_paths, workspace);
                EffectiveProfile::Resolved(p)
            }
        }
    }
}

fn expand_workspace_set(set: BTreeSet<PathBuf>, workspace: &Path) -> BTreeSet<PathBuf> {
    set.into_iter()
        .map(|p| {
            if p == Path::new(WORKSPACE_TOKEN) {
                return workspace.to_path_buf();
            }
            // Strip the leading `<workspace>` component when present and
            // re-anchor on the actual workspace path.
            if let Ok(rest) = p.strip_prefix(WORKSPACE_TOKEN) {
                workspace.join(rest)
            } else {
                p
            }
        })
        .collect()
}

fn host_in_set(host: &str, domains: &AllowSet) -> bool {
    match domains {
        AllowSet::Wildcard => true,
        AllowSet::Set(set) => set.iter().any(|pat| host_matches(host, pat)),
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some(dotidx) = host.find('.') {
            return &host[dotidx + 1..] == suffix;
        }
    }
    false
}

fn path_under_any(path: &Path, allowed: &BTreeSet<PathBuf>) -> bool {
    allowed.iter().any(|root| path.starts_with(root))
}

/// Compute the effective profile for a set of attached skills. Returns
/// `Legacy` for the empty case (no skills attached — no enforcement);
/// otherwise returns `Resolved(merge(...))`. Propagates
/// `inference.default` conflict.
pub fn effective_for_skills(
    profiles: &[PermissionProfile],
) -> Result<EffectiveProfile, MergeError> {
    if profiles.is_empty() {
        return Ok(EffectiveProfile::Legacy);
    }
    Ok(EffectiveProfile::Resolved(merge(profiles)?))
}

// ---------------------------------------------------------------------------
// Phase deny overlay (per-pass denylist)
// ---------------------------------------------------------------------------

/// In-memory deny overlay layered on top of an Agent's
/// [`EffectiveProfile`]. Entries listed here are denied even when the
/// base profile would have allowed them. The overlay is single-slot:
/// only one phase can be active per Agent at a time. Set by a skill
/// via the `wirken_enter_phase` host function (slice 3); cleared via
/// `wirken_exit_phase`, turn-end, or skill-unload.
///
/// The four deny axes mirror the four `allows_*` methods on
/// [`EffectiveProfile`]: tools, egress hosts, filesystem read/write
/// paths, and inference providers. An axis with an empty set denies
/// nothing on that axis. The overlay is a denylist over an allowlist
/// base; it cannot widen what the base profile allows.
///
/// `skill_id` and `phase_name` are recorded for audit attribution
/// and replay; `entered_at` is the wall-clock at the
/// `wirken_enter_phase` call site, preserved across replay from the
/// audit row's `ts`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PhaseDenyOverlay {
    pub skill_id: String,
    pub phase_name: String,
    pub entered_at: DateTime<Utc>,
    pub tools: BTreeSet<String>,
    pub egress_hosts: BTreeSet<String>,
    pub paths_read: BTreeSet<PathBuf>,
    pub paths_write: BTreeSet<PathBuf>,
    pub inference_providers: BTreeSet<String>,
}

impl PhaseDenyOverlay {
    /// True when the overlay would deny `name` on the tools axis.
    /// Slice 2 wires this into the agent's permission gate; slice 1
    /// only defines the predicate so the type's shape is testable.
    pub fn denies_tool(&self, name: &str) -> bool {
        self.tools.contains(name)
    }

    /// True when the overlay would deny `host` on the egress axis.
    /// Plain string equality; the existing
    /// [`EffectiveProfile::allows_host`] pattern-matches with `*.`
    /// wildcards on the allow side, but the overlay is a closed deny
    /// list: a skill enters a phase with concrete hosts to refuse,
    /// not wildcard patterns.
    pub fn denies_host(&self, host: &str) -> bool {
        self.egress_hosts.contains(host)
    }

    /// True when the overlay would deny `path` on the filesystem read
    /// axis. Matches by directory prefix (a denied root denies every
    /// descendant), mirroring the base profile's
    /// [`EffectiveProfile::allows_read_path`] containment check.
    pub fn denies_read_path(&self, path: &Path) -> bool {
        self.paths_read.iter().any(|root| path.starts_with(root))
    }

    /// True when the overlay would deny `path` on the filesystem write
    /// axis. Same prefix-match semantics as
    /// [`Self::denies_read_path`].
    pub fn denies_write_path(&self, path: &Path) -> bool {
        self.paths_write.iter().any(|root| path.starts_with(root))
    }

    /// True when the overlay would deny `name` on the inference axis.
    pub fn denies_provider(&self, name: &str) -> bool {
        self.inference_providers.contains(name)
    }
}

/// The five axes that an Agent's tool-call gate consults. Each gate
/// call site already knows which axis it represents (a call to
/// `gate_tool` returning [`GateDecision::DeniedByPhase`] implies
/// [`PhaseAxis::Tool`]), but carrying the axis on the deny variant
/// lets the gate site emit a uniform [`SessionEvent::SkillPermissionDenied`]
/// regardless of which method produced the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseAxis {
    Tool,
    EgressHost,
    PathRead,
    PathWrite,
    InferenceProvider,
}

impl PhaseAxis {
    /// Stable snake_case label for the `axis` field on
    /// [`wirken_audit::SessionEvent::SkillPermissionDenied`].
    /// Matches the strings the runtime already used for the
    /// profile-denial path (`"tools"`, `"egress"`,
    /// `"filesystem.read"`, `"filesystem.write"`, `"inference"`) so
    /// SIEM consumers see one vocabulary across both deny reasons.
    pub fn axis_label(&self) -> &'static str {
        match self {
            Self::Tool => "tools",
            Self::EgressHost => "egress",
            Self::PathRead => "filesystem.read",
            Self::PathWrite => "filesystem.write",
            Self::InferenceProvider => "inference",
        }
    }
}

/// Result of one gate consultation on [`PhasedEffective`]. Carries
/// enough discriminator for the gate-site caller to emit the right
/// audit shape (profile-denial vs phase-denial) without re-querying
/// the overlay.
///
/// Pre-slice-2 the gate methods returned `bool`; the explicit enum
/// is the typed-reason channel the audit layer needs to distinguish
/// "phase overlay" from "permission profile mismatch" in the SIEM
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Tool call is allowed: neither the active overlay (if any) nor
    /// the base profile refused.
    Allow,
    /// An active phase deny overlay refused the call. `phase_name`
    /// names the phase for SIEM correlation with the triggering
    /// `PhaseEntered` row; `axis` is the gate axis the overlay
    /// matched on.
    DeniedByPhase { phase_name: String, axis: PhaseAxis },
    /// The base [`EffectiveProfile`] refused the call. The pre-slice-2
    /// shape: gate site knows its own axis statically, so no extra
    /// data carried on the variant.
    DeniedByProfile,
}

/// Error returned when a skill calls `enter_phase` while a phase
/// overlay is already active. Single-slot semantics: the host
/// declines to nest overlays so the audit chain stays unambiguous
/// (every `PhaseEntered` pairs cleanly with one `PhaseExited`).
/// Skills MUST call `exit_phase` before `enter_phase`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PhaseError {
    #[error("a phase overlay is already active; skill must call exit_phase before enter_phase")]
    AlreadyActive,
}

/// Agent-side wrapper layering a phase deny overlay over the base
/// [`EffectiveProfile`]. Single-slot: at most one overlay is active
/// at a time. The `gate_*` methods consult the overlay first
/// (deny short-circuits) and fall through to the base profile,
/// returning a typed [`GateDecision`] so the audit layer can record
/// which side denied.
///
/// The overlay's lifetime is bounded by the agent turn that owns
/// it: `enter_phase` is called from inside a turn (slice 3 wires
/// the WASM host fn), `exit_phase` is called either by the same
/// skill before the next phase (`PhaseExitReason::PhaseChange`) or
/// by the host at turn end (`PhaseExitReason::TurnEnd`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PhasedEffective {
    base: EffectiveProfile,
    overlay: Option<PhaseDenyOverlay>,
}

impl PhasedEffective {
    /// Wrap an [`EffectiveProfile`] with an empty overlay slot.
    /// Pre-slice-2 callers that held an `EffectiveProfile` directly
    /// land here via `PhasedEffective::from_base(...)`.
    pub fn from_base(base: EffectiveProfile) -> Self {
        Self {
            base,
            overlay: None,
        }
    }

    /// The base profile underneath the overlay. Existing call sites
    /// that need an `EffectiveProfile` for non-gate purposes (egress
    /// enforcement wiring, system-prompt rendering) read it here.
    pub fn base(&self) -> &EffectiveProfile {
        &self.base
    }

    /// The currently-active overlay, if any. Returns `None` outside
    /// a phase. Read-only access; mutation goes through
    /// [`Self::enter_phase`] / [`Self::exit_phase`].
    pub fn overlay(&self) -> Option<&PhaseDenyOverlay> {
        self.overlay.as_ref()
    }

    /// Pass-through to [`EffectiveProfile::inference_default`].
    /// Overlay does not modify inference defaults; only the
    /// allow/deny decision via [`Self::gate_provider`].
    pub fn inference_default(&self) -> Option<&str> {
        self.base.inference_default()
    }

    /// Gate a tool-call dispatch by tool name.
    pub fn gate_tool(&self, name: &str) -> GateDecision {
        if let Some(overlay) = &self.overlay
            && overlay.denies_tool(name)
        {
            return GateDecision::DeniedByPhase {
                phase_name: overlay.phase_name.clone(),
                axis: PhaseAxis::Tool,
            };
        }
        if self.base.allows_tool(name) {
            GateDecision::Allow
        } else {
            GateDecision::DeniedByProfile
        }
    }

    /// Gate an egress destination host.
    pub fn gate_host(&self, host: &str) -> GateDecision {
        if let Some(overlay) = &self.overlay
            && overlay.denies_host(host)
        {
            return GateDecision::DeniedByPhase {
                phase_name: overlay.phase_name.clone(),
                axis: PhaseAxis::EgressHost,
            };
        }
        if self.base.allows_host(host) {
            GateDecision::Allow
        } else {
            GateDecision::DeniedByProfile
        }
    }

    /// Gate a filesystem read path.
    pub fn gate_read_path(&self, path: &Path) -> GateDecision {
        if let Some(overlay) = &self.overlay
            && overlay.denies_read_path(path)
        {
            return GateDecision::DeniedByPhase {
                phase_name: overlay.phase_name.clone(),
                axis: PhaseAxis::PathRead,
            };
        }
        if self.base.allows_read_path(path) {
            GateDecision::Allow
        } else {
            GateDecision::DeniedByProfile
        }
    }

    /// Gate a filesystem write path.
    pub fn gate_write_path(&self, path: &Path) -> GateDecision {
        if let Some(overlay) = &self.overlay
            && overlay.denies_write_path(path)
        {
            return GateDecision::DeniedByPhase {
                phase_name: overlay.phase_name.clone(),
                axis: PhaseAxis::PathWrite,
            };
        }
        if self.base.allows_write_path(path) {
            GateDecision::Allow
        } else {
            GateDecision::DeniedByProfile
        }
    }

    /// Gate an inference provider selection.
    pub fn gate_provider(&self, name: &str) -> GateDecision {
        if let Some(overlay) = &self.overlay
            && overlay.denies_provider(name)
        {
            return GateDecision::DeniedByPhase {
                phase_name: overlay.phase_name.clone(),
                axis: PhaseAxis::InferenceProvider,
            };
        }
        if self.base.allows_provider(name) {
            GateDecision::Allow
        } else {
            GateDecision::DeniedByProfile
        }
    }

    /// Install `overlay` as the active phase. Errors with
    /// [`PhaseError::AlreadyActive`] when one is already active;
    /// the skill must `exit_phase` first. Slice 3 wires this through
    /// the `wirken_enter_phase` host function.
    pub fn enter_phase(&mut self, overlay: PhaseDenyOverlay) -> Result<(), PhaseError> {
        if self.overlay.is_some() {
            return Err(PhaseError::AlreadyActive);
        }
        self.overlay = Some(overlay);
        Ok(())
    }

    /// Clear the active overlay, returning it if one was present.
    /// The caller emits a `PhaseExited` audit row carrying the
    /// returned overlay's `skill_id` / `phase_name` plus the
    /// caller-supplied [`wirken_audit::PhaseExitReason`].
    pub fn exit_phase(&mut self) -> Option<PhaseDenyOverlay> {
        self.overlay.take()
    }

    /// Slice-4 replay-side setter. Unconditionally installs
    /// `overlay`, replacing whatever is currently active. Skips the
    /// `AlreadyActive` check the live [`Self::enter_phase`] enforces
    /// because replay needs to set the final state observed in the
    /// session log without diagnosing intermediate corrupted-log
    /// patterns (a `PhaseEntered` without a preceding `PhaseExited`
    /// becomes last-event-wins). The replay caller is responsible
    /// for not emitting a duplicate `PhaseEntered` audit row.
    pub fn set_overlay(&mut self, overlay: PhaseDenyOverlay) {
        self.overlay = Some(overlay);
    }

    /// True iff at least one attached skill's declared
    /// `permissions.tools.allow` admits `name`. Distinct from
    /// [`Self::gate_tool`] in that the [`EffectiveProfile::Legacy`]
    /// base (no skills attached) returns `false` here, not `true`:
    /// the synthetic phase tools `wirken_enter_phase` /
    /// `wirken_exit_phase` should only become discoverable to the
    /// LLM when at least one skill has opted in by listing them in
    /// its SKILL.md `tools.allow`. Legacy mode skips them entirely.
    /// Wildcard `tools.allow: ["*"]` counts as opting in.
    pub fn skills_admit_tool(&self, name: &str) -> bool {
        match &self.base {
            EffectiveProfile::Legacy => false,
            EffectiveProfile::Resolved(p) => p.tools.allow.allows(name),
        }
    }
}

/// Union-merge a slice of declared per-skill profiles into one effective
/// agent profile. Set-typed fields are unioned; wildcards win. The single
/// scalar field (`inference.default`) must be unanimous among the skills
/// that declare it; conflict is an attach-time error.
pub fn merge(profiles: &[PermissionProfile]) -> Result<PermissionProfile, MergeError> {
    let mut tools = AllowSet::Set(BTreeSet::new());
    let mut egress_mode = EgressMode::Deny;
    let mut egress_domains = AllowSet::Set(BTreeSet::new());
    let mut write_paths = BTreeSet::new();
    let mut read_paths = BTreeSet::new();
    let mut inference_allow = AllowSet::Set(BTreeSet::new());
    let mut inference_defaults = BTreeSet::new();

    for p in profiles {
        tools = union_allow(tools, p.tools.allow.clone());
        if matches!(p.egress.mode, EgressMode::Allowlist) {
            egress_mode = EgressMode::Allowlist;
        }
        egress_domains = union_allow(egress_domains, p.egress.domains.clone());
        write_paths.extend(p.filesystem.write_paths.iter().cloned());
        read_paths.extend(p.filesystem.read_paths.iter().cloned());
        inference_allow = union_allow(inference_allow, p.inference.allow.clone());
        if let Some(ref d) = p.inference.default {
            inference_defaults.insert(d.clone());
        }
    }

    let inference_default = match inference_defaults.len() {
        0 => None,
        1 => inference_defaults.into_iter().next(),
        _ => {
            return Err(MergeError::DefaultConflict {
                found: inference_defaults,
            });
        }
    };

    Ok(PermissionProfile {
        tools: ToolPolicy { allow: tools },
        egress: EgressPolicy {
            mode: egress_mode,
            domains: egress_domains,
        },
        filesystem: FilesystemPolicy {
            write_paths,
            read_paths,
        },
        inference: InferencePolicy {
            allow: inference_allow,
            default: inference_default,
        },
    })
}

fn union_allow(a: AllowSet, b: AllowSet) -> AllowSet {
    match (a, b) {
        (AllowSet::Wildcard, _) | (_, AllowSet::Wildcard) => AllowSet::Wildcard,
        (AllowSet::Set(mut x), AllowSet::Set(y)) => {
            x.extend(y);
            AllowSet::Set(x)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/tmp/test-skill-root-does-not-exist")
    }

    fn home() -> Option<&'static Path> {
        Some(Path::new("/home/testuser"))
    }

    #[test]
    fn empty_block_is_default_deny() {
        let p = parse_block("{}", &root(), home()).unwrap();
        assert_eq!(p, PermissionProfile::default());
        assert!(matches!(p.tools.allow, AllowSet::Set(ref s) if s.is_empty()));
        assert!(matches!(p.egress.mode, EgressMode::Deny));
        assert!(p.filesystem.write_paths.is_empty());
        assert!(matches!(p.inference.allow, AllowSet::Set(ref s) if s.is_empty()));
    }

    #[test]
    fn full_block_round_trips() {
        let yaml = r#"
tools:
  allow: ["read_file", "write_file"]
egress:
  mode: allowlist
  domains: ["api.example.com", "export.arxiv.org"]
filesystem:
  write_paths: ["~/.wirken/zirkel/"]
  read_paths: ["~/.wirken/zirkel/", "/etc/hosts"]
inference:
  allow: ["ollama", "privatemode"]
  default: "ollama"
"#;
        let p = parse_block(yaml, &root(), home()).unwrap();
        assert!(p.tools.allow.allows("read_file"));
        assert!(p.tools.allow.allows("write_file"));
        assert!(!p.tools.allow.allows("exec"));
        assert_eq!(p.egress.mode, EgressMode::Allowlist);
        assert!(p.egress.domains.allows("api.example.com"));
        assert!(
            p.filesystem
                .write_paths
                .contains(&PathBuf::from("/home/testuser/.wirken/zirkel/"))
        );
        assert!(
            p.filesystem
                .read_paths
                .contains(&PathBuf::from("/etc/hosts"))
        );
        assert_eq!(p.inference.default.as_deref(), Some("ollama"));
    }

    #[test]
    fn wildcard_tools_passes_anything() {
        let p = parse_block(r#"tools: { allow: ["*"] }"#, &root(), home()).unwrap();
        assert!(matches!(p.tools.allow, AllowSet::Wildcard));
        assert!(p.tools.allow.allows("anything_at_all"));
    }

    #[test]
    fn mixed_wildcard_rejected() {
        let yaml = r#"tools: { allow: ["*", "read_file"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::MixedWildcard { .. }));
    }

    #[test]
    fn invalid_egress_mode_rejected() {
        let yaml = r#"egress: { mode: "foo" }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::InvalidEgressMode(_)));
    }

    #[test]
    fn deny_with_domains_rejected() {
        let yaml = r#"egress: { mode: "deny", domains: ["foo.com"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::DenyWithDomains));
    }

    #[test]
    fn filesystem_wildcard_rejected() {
        let yaml = r#"filesystem: { write_paths: ["*"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::FilesystemWildcard));
    }

    #[test]
    fn relative_filesystem_path_rejected() {
        let yaml = r#"filesystem: { write_paths: ["relative/path"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::NonAbsolutePath(_)));
    }

    #[test]
    fn invalid_host_rejected() {
        let yaml = r#"egress: { mode: "allowlist", domains: ["http://foo.com"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::InvalidHost(_)));

        let yaml = r#"egress: { mode: "allowlist", domains: ["foo.com:8080"] }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::InvalidHost(_)));
    }

    #[test]
    fn wildcard_host_label_accepted() {
        let yaml = r#"egress: { mode: "allowlist", domains: ["*.example.com"] }"#;
        let p = parse_block(yaml, &root(), home()).unwrap();
        // Wildcard label is treated as a literal entry; matching is
        // string-equality at this layer. The HTTP wrapper does the
        // glob matching itself.
        assert!(p.egress.domains.allows("*.example.com"));
    }

    #[test]
    fn write_path_inside_skill_root_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let inside = format!(
            "filesystem: {{ write_paths: [\"{}/inside\"] }}",
            root.display()
        );
        let err = parse_block(&inside, root, None).unwrap_err();
        assert!(matches!(err, PermissionsError::WritePathInsideSkillRoot(_)));
    }

    #[test]
    fn default_not_in_allow_rejected() {
        let yaml = r#"
inference:
  allow: ["ollama"]
  default: "openai"
"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::DefaultNotInAllow(_)));
    }

    #[test]
    fn default_with_wildcard_allow_passes() {
        let yaml = r#"
inference:
  allow: ["*"]
  default: "anything"
"#;
        let p = parse_block(yaml, &root(), home()).unwrap();
        assert_eq!(p.inference.default.as_deref(), Some("anything"));
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r#"unknown_axis: { foo: bar }"#;
        let err = parse_block(yaml, &root(), home()).unwrap_err();
        assert!(matches!(err, PermissionsError::Yaml(_)));
    }

    fn profile_with(yaml: &str) -> PermissionProfile {
        parse_block(yaml, &root(), home()).unwrap()
    }

    #[test]
    fn merge_unions_tool_sets() {
        let a = profile_with(r#"tools: { allow: ["read_file"] }"#);
        let b = profile_with(r#"tools: { allow: ["write_file"] }"#);
        let merged = merge(&[a, b]).unwrap();
        assert!(merged.tools.allow.allows("read_file"));
        assert!(merged.tools.allow.allows("write_file"));
    }

    #[test]
    fn merge_wildcard_wins() {
        let a = profile_with(r#"tools: { allow: ["read_file"] }"#);
        let b = profile_with(r#"tools: { allow: ["*"] }"#);
        let merged = merge(&[a, b]).unwrap();
        assert!(matches!(merged.tools.allow, AllowSet::Wildcard));
    }

    #[test]
    fn merge_egress_mode_allowlist_if_any_skill_declares() {
        let a = profile_with(r#"egress: { mode: "deny" }"#);
        let b = profile_with(r#"egress: { mode: "allowlist", domains: ["foo.com"] }"#);
        let merged = merge(&[a, b]).unwrap();
        assert_eq!(merged.egress.mode, EgressMode::Allowlist);
        assert!(merged.egress.domains.allows("foo.com"));
    }

    #[test]
    fn merge_filesystem_paths_union() {
        let a = profile_with(r#"filesystem: { write_paths: ["/a"] }"#);
        let b = profile_with(r#"filesystem: { write_paths: ["/b"] }"#);
        let merged = merge(&[a, b]).unwrap();
        assert!(merged.filesystem.write_paths.contains(&PathBuf::from("/a")));
        assert!(merged.filesystem.write_paths.contains(&PathBuf::from("/b")));
    }

    #[test]
    fn merge_inference_default_unanimous_passes() {
        let a = profile_with(
            r#"
inference:
  allow: ["ollama"]
  default: "ollama"
"#,
        );
        let b = profile_with(
            r#"
inference:
  allow: ["ollama"]
  default: "ollama"
"#,
        );
        let merged = merge(&[a, b]).unwrap();
        assert_eq!(merged.inference.default.as_deref(), Some("ollama"));
    }

    #[test]
    fn merge_inference_default_one_declarer_passes() {
        let a = profile_with(
            r#"
inference:
  allow: ["ollama"]
  default: "ollama"
"#,
        );
        let b = profile_with(r#"inference: { allow: ["ollama"] }"#);
        let merged = merge(&[a, b]).unwrap();
        assert_eq!(merged.inference.default.as_deref(), Some("ollama"));
    }

    #[test]
    fn merge_inference_default_conflict_rejected() {
        let a = profile_with(
            r#"
inference:
  allow: ["ollama"]
  default: "ollama"
"#,
        );
        let b = profile_with(
            r#"
inference:
  allow: ["privatemode"]
  default: "privatemode"
"#,
        );
        let err = merge(&[a, b]).unwrap_err();
        assert!(matches!(err, MergeError::DefaultConflict { .. }));
    }

    #[test]
    fn merge_empty_returns_default_deny() {
        let merged = merge(&[]).unwrap();
        assert_eq!(merged, PermissionProfile::default());
    }

    #[test]
    fn effective_no_skills_is_legacy() {
        let eff = effective_for_skills(&[]).unwrap();
        assert_eq!(eff, EffectiveProfile::Legacy);
    }

    #[test]
    fn effective_resolves_for_any_non_empty_attach() {
        let a = profile_with(r#"tools: { allow: ["read_file"] }"#);
        let b = profile_with(r#"tools: { allow: ["write_file"] }"#);
        let eff = effective_for_skills(&[a, b]).unwrap();
        assert!(eff.allows_tool("read_file"));
        assert!(eff.allows_tool("write_file"));
        assert!(!eff.allows_tool("exec"));
    }

    #[test]
    fn legacy_allows_everything() {
        let eff = EffectiveProfile::Legacy;
        assert!(eff.allows_tool("anything"));
        assert!(eff.allows_host("anywhere.example.com"));
        assert!(eff.allows_provider("any_provider"));
        assert!(eff.allows_read_path(Path::new("/tmp/anything")));
        assert!(eff.allows_write_path(Path::new("/tmp/anywhere")));
    }

    #[test]
    fn resolved_egress_deny_mode_blocks_everything() {
        let p = profile_with("{}"); // default-deny
        let eff = EffectiveProfile::Resolved(p);
        assert!(!eff.allows_host("foo.com"));
    }

    #[test]
    fn resolved_egress_allowlist_with_specific_host() {
        let p = profile_with(r#"egress: { mode: "allowlist", domains: ["api.example.com"] }"#);
        let eff = EffectiveProfile::Resolved(p);
        assert!(eff.allows_host("api.example.com"));
        assert!(!eff.allows_host("other.example.com"));
    }

    #[test]
    fn resolved_egress_wildcard_label_matches_subdomains() {
        let p = profile_with(r#"egress: { mode: "allowlist", domains: ["*.example.com"] }"#);
        let eff = EffectiveProfile::Resolved(p);
        assert!(eff.allows_host("api.example.com"));
        assert!(eff.allows_host("foo.example.com"));
        assert!(!eff.allows_host("example.com"));
        assert!(!eff.allows_host("api.other.com"));
    }

    #[test]
    fn resolved_egress_global_wildcard_matches_anything() {
        let p = profile_with(r#"egress: { mode: "allowlist", domains: ["*"] }"#);
        let eff = EffectiveProfile::Resolved(p);
        assert!(eff.allows_host("anywhere.example.com"));
    }

    #[test]
    fn resolved_filesystem_paths_match_under_root() {
        let p = profile_with(r#"filesystem: { write_paths: ["/home/x/work/"] }"#);
        let eff = EffectiveProfile::Resolved(p);
        assert!(eff.allows_write_path(Path::new("/home/x/work/")));
        assert!(eff.allows_write_path(Path::new("/home/x/work/file.txt")));
        assert!(eff.allows_write_path(Path::new("/home/x/work/sub/dir/file.txt")));
        assert!(!eff.allows_write_path(Path::new("/home/x/other/")));
        assert!(!eff.allows_write_path(Path::new("/home/x/")));
    }

    #[test]
    fn workspace_token_paths_round_trip_through_parse() {
        let yaml = r#"
filesystem:
  read_paths: ["<workspace>"]
  write_paths: ["<workspace>/.lyrik", "<workspace>/notes"]
"#;
        let p = parse_block(yaml, &root(), home()).unwrap();
        assert!(
            p.filesystem
                .read_paths
                .contains(&PathBuf::from("<workspace>"))
        );
        assert!(
            p.filesystem
                .write_paths
                .contains(&PathBuf::from("<workspace>/.lyrik"))
        );
        assert!(
            p.filesystem
                .write_paths
                .contains(&PathBuf::from("<workspace>/notes"))
        );
    }

    #[test]
    fn workspace_token_expands_to_real_workspace() {
        let yaml = r#"
filesystem:
  read_paths: ["<workspace>"]
  write_paths: ["<workspace>/.lyrik"]
"#;
        let p = parse_block(yaml, &root(), home()).unwrap();
        let workspace = Path::new("/home/x/code/repo");
        let eff = EffectiveProfile::Resolved(p).expand_workspace(workspace);
        assert!(eff.allows_read_path(Path::new("/home/x/code/repo/foo.rs")));
        assert!(eff.allows_write_path(Path::new("/home/x/code/repo/.lyrik/rubric.md")));
        assert!(!eff.allows_write_path(Path::new("/home/x/code/repo/elsewhere/foo")));
        assert!(!eff.allows_read_path(Path::new("/some/other/path")));
    }

    #[test]
    fn effective_propagates_default_conflict() {
        let a = profile_with(
            r#"
inference:
  allow: ["ollama"]
  default: "ollama"
"#,
        );
        let b = profile_with(
            r#"
inference:
  allow: ["privatemode"]
  default: "privatemode"
"#,
        );
        let err = effective_for_skills(&[a, b]).unwrap_err();
        assert!(matches!(err, MergeError::DefaultConflict { .. }));
    }

    // -----------------------------------------------------------------
    // PhasedEffective + GateDecision (slice 2 per-pass deny overlay)
    // -----------------------------------------------------------------

    fn overlay_with_tool(phase_name: &str, tool: &str) -> PhaseDenyOverlay {
        let mut tools = BTreeSet::new();
        tools.insert(tool.to_string());
        PhaseDenyOverlay {
            skill_id: "test-skill".to_string(),
            phase_name: phase_name.to_string(),
            entered_at: Utc::now(),
            tools,
            ..Default::default()
        }
    }

    fn allowed_profile_with_tools(names: &[&str]) -> EffectiveProfile {
        let mut profile = PermissionProfile::default();
        let mut set = BTreeSet::new();
        for n in names {
            set.insert(n.to_string());
        }
        profile.tools.allow = AllowSet::Set(set);
        EffectiveProfile::Resolved(profile)
    }

    #[test]
    fn phased_gate_tool_allow_when_overlay_absent_and_base_allows() {
        let phased = PhasedEffective::from_base(allowed_profile_with_tools(&["read_file"]));
        assert_eq!(phased.gate_tool("read_file"), GateDecision::Allow);
    }

    #[test]
    fn phased_gate_tool_denied_by_profile_when_overlay_absent_and_base_refuses() {
        let phased = PhasedEffective::from_base(allowed_profile_with_tools(&["read_file"]));
        assert_eq!(phased.gate_tool("exec"), GateDecision::DeniedByProfile);
    }

    #[test]
    fn phased_gate_tool_denied_by_phase_when_overlay_denies() {
        let mut phased = PhasedEffective::from_base(allowed_profile_with_tools(&["read_file"]));
        phased
            .enter_phase(overlay_with_tool("scoring", "read_file"))
            .unwrap();
        assert_eq!(
            phased.gate_tool("read_file"),
            GateDecision::DeniedByPhase {
                phase_name: "scoring".to_string(),
                axis: PhaseAxis::Tool,
            },
        );
    }

    #[test]
    fn phased_gate_tool_falls_through_to_base_when_overlay_does_not_match() {
        // Overlay denies `read_file`; base allows `write_file`. A call
        // to `write_file` is not in the overlay's denied set, so the
        // overlay short-circuit is skipped and the base verdict wins.
        let mut phased = PhasedEffective::from_base(allowed_profile_with_tools(&["write_file"]));
        phased
            .enter_phase(overlay_with_tool("scoring", "read_file"))
            .unwrap();
        assert_eq!(phased.gate_tool("write_file"), GateDecision::Allow);
        // And a tool the base also refuses still surfaces as
        // `DeniedByProfile` (the overlay does not invent allows or
        // synthesize an axis when it would not have fired).
        assert_eq!(phased.gate_tool("exec"), GateDecision::DeniedByProfile);
    }

    #[test]
    fn phased_exit_phase_clears_overlay_and_base_decision_returns() {
        let mut phased = PhasedEffective::from_base(allowed_profile_with_tools(&["read_file"]));
        phased
            .enter_phase(overlay_with_tool("scoring", "read_file"))
            .unwrap();
        let cleared = phased.exit_phase().expect("overlay was active");
        assert_eq!(cleared.phase_name, "scoring");
        // The overlay is gone; `read_file` is allowed again by the
        // base profile alone.
        assert_eq!(phased.gate_tool("read_file"), GateDecision::Allow);
        // Calling exit_phase again with no overlay returns None.
        assert!(phased.exit_phase().is_none());
    }

    #[test]
    fn phased_enter_phase_while_active_errors() {
        let mut phased = PhasedEffective::from_base(allowed_profile_with_tools(&["read_file"]));
        phased
            .enter_phase(overlay_with_tool("scoring", "read_file"))
            .unwrap();
        let err = phased
            .enter_phase(overlay_with_tool("framings", "write_file"))
            .unwrap_err();
        assert_eq!(err, PhaseError::AlreadyActive);
        // The original overlay is still active; the second
        // `enter_phase` did not partially apply.
        assert_eq!(
            phased.overlay().map(|o| o.phase_name.as_str()),
            Some("scoring")
        );
    }

    #[test]
    fn phased_gate_host_overlay_takes_precedence() {
        let mut profile = PermissionProfile::default();
        let mut domains = BTreeSet::new();
        domains.insert("api.example.com".to_string());
        profile.egress = EgressPolicy {
            mode: EgressMode::Allowlist,
            domains: AllowSet::Set(domains),
        };
        let mut phased = PhasedEffective::from_base(EffectiveProfile::Resolved(profile));

        // Without overlay: base allows.
        assert_eq!(phased.gate_host("api.example.com"), GateDecision::Allow);

        // Enter a phase that denies the host.
        let mut overlay = overlay_with_tool("scoring", "ignored_tool");
        overlay.egress_hosts.insert("api.example.com".to_string());
        phased.enter_phase(overlay).unwrap();

        assert_eq!(
            phased.gate_host("api.example.com"),
            GateDecision::DeniedByPhase {
                phase_name: "scoring".to_string(),
                axis: PhaseAxis::EgressHost,
            },
        );
    }

    #[test]
    fn phased_gate_paths_overlay_uses_prefix_match() {
        let mut profile = PermissionProfile::default();
        profile
            .filesystem
            .read_paths
            .insert(PathBuf::from("/home/x/code"));
        let mut phased = PhasedEffective::from_base(EffectiveProfile::Resolved(profile));

        // Base allows /home/x/code/anything.
        assert_eq!(
            phased.gate_read_path(Path::new("/home/x/code/foo.rs")),
            GateDecision::Allow,
        );

        // Overlay denies /home/x/code/secrets; every descendant is
        // refused even though the base profile allows the parent.
        let mut overlay = overlay_with_tool("scoring", "ignored");
        overlay
            .paths_read
            .insert(PathBuf::from("/home/x/code/secrets"));
        phased.enter_phase(overlay).unwrap();

        assert_eq!(
            phased.gate_read_path(Path::new("/home/x/code/secrets/creds.json")),
            GateDecision::DeniedByPhase {
                phase_name: "scoring".to_string(),
                axis: PhaseAxis::PathRead,
            },
        );
        // Sibling path not under the denied root: still allowed.
        assert_eq!(
            phased.gate_read_path(Path::new("/home/x/code/foo.rs")),
            GateDecision::Allow,
        );
    }

    #[test]
    fn phased_default_is_legacy_with_no_overlay() {
        // Regression: with the default-constructed PhasedEffective
        // (matching the `Legacy` pre-slice-2 initializer in
        // runtime.rs), every gate_* call returns Allow.
        let phased = PhasedEffective::default();
        assert_eq!(phased.gate_tool("anything"), GateDecision::Allow);
        assert_eq!(phased.gate_host("api.example.com"), GateDecision::Allow);
        assert_eq!(phased.gate_provider("any"), GateDecision::Allow);
        assert_eq!(
            phased.gate_read_path(Path::new("/tmp/x")),
            GateDecision::Allow,
        );
        assert_eq!(
            phased.gate_write_path(Path::new("/tmp/x")),
            GateDecision::Allow,
        );
    }
}
