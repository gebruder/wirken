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
}
