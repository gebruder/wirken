//! Per-skill permission profile parsed from SKILL.md frontmatter.
//!
//! Four axes, default-deny on every one:
//! - `tools` — which tool names this skill needs the agent to expose.
//! - `egress` — which network hosts this skill needs the agent to reach.
//! - `filesystem` — which paths this skill needs the agent to read or write.
//! - `inference` — which LLM providers this skill needs the agent to call.
//!
//! Enforcement is per-agent: the agent computes its effective profile at init
//! as the union of all loaded skills' declared profiles. A skill with no
//! `permissions:` block is treated as `Legacy` — the loader warns and the
//! agent gets the full surface for that skill during the migration window.
//!
//! Wildcard `"*"` is supported on `tools`, `egress.domains`, and
//! `inference.allow`. Filesystem wildcards are rejected: cap-std workspace
//! is the outer bound and `"*"` for paths is meaningless inside it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

const WILDCARD: &str = "*";

/// Resolved profile after parse + validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionProfile {
    pub tools: ToolPolicy,
    pub egress: EgressPolicy,
    pub filesystem: FilesystemPolicy,
    pub inference: InferencePolicy,
}

/// What the loader produces per-skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionsSource {
    /// The skill declared a `permissions:` block (possibly empty). Empty
    /// resolves to a fully default-deny profile.
    Explicit(PermissionProfile),
    /// The skill omitted the `permissions:` block. Transitional: agent gets
    /// the full surface and the loader logs a deprecation warning. After the
    /// migration window flips, missing block becomes a hard load failure.
    Legacy,
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
}
