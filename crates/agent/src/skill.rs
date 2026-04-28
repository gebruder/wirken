use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::error::AgentError;
use crate::skill_perms::{PermissionsBlock, PermissionsSource, resolve_block};

/// A loaded markdown skill.
#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub required_bins: Vec<String>,
    pub body: String,
    pub path: PathBuf,
    pub available: bool,
    /// Per-skill permissions declared in the frontmatter `permissions:` block,
    /// or `Legacy` if the block is absent. The agent merges declared profiles
    /// from all loaded skills into one effective per-agent profile at init.
    pub permissions: PermissionsSource,
}

/// YAML frontmatter parsed from SKILL.md files.
/// Matches OpenClaw's format for compatibility.
#[derive(Debug, Deserialize)]
struct SkillFrontmatter {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    permissions: Option<PermissionsBlock>,
}

/// Loads SKILL.md files from a directory.
pub struct SkillLoader;

impl SkillLoader {
    /// Load all skills from a directory.
    /// Each subdirectory containing a SKILL.md is loaded as a skill.
    pub fn load_dir(dir: &Path) -> Result<Vec<Skill>, AgentError> {
        if !dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut skills = Vec::new();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| AgentError::SkillLoad(format!("read dir {}: {e}", dir.display())))?;

        for entry in entries {
            let entry = entry.map_err(|e| AgentError::SkillLoad(format!("dir entry: {e}")))?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let skill_file = path.join("SKILL.md");
            if !skill_file.exists() {
                continue;
            }

            match Self::load_file(&skill_file) {
                Ok(skill) => skills.push(skill),
                Err(e) => {
                    tracing::warn!("Failed to load skill at {}: {e}", skill_file.display());
                }
            }
        }

        skills.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(skills)
    }

    /// Load a single SKILL.md file.
    pub fn load_file(path: &Path) -> Result<Skill, AgentError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AgentError::SkillLoad(format!("read {}: {e}", path.display())))?;

        let (frontmatter, body) = parse_frontmatter(&content)?;

        let required_bins = extract_required_bins(&frontmatter);
        let available = check_bins_available(&required_bins);

        let dir_name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let skill_root = path.parent().unwrap_or_else(|| Path::new("."));
        let home = std::env::var("HOME").ok().map(PathBuf::from);
        let permissions = match frontmatter.permissions {
            Some(block) => {
                let profile = resolve_block(block, skill_root, home.as_deref()).map_err(|e| {
                    AgentError::SkillLoad(format!("permissions block in {}: {e}", path.display()))
                })?;
                PermissionsSource::Explicit(profile)
            }
            None => {
                tracing::warn!(
                    "skill {} has no `permissions:` block; treating as legacy. \
                     This will become a hard load failure in a future release. \
                     See gebruder/wirken#76.",
                    path.display()
                );
                PermissionsSource::Legacy
            }
        };

        Ok(Skill {
            name: frontmatter.name.unwrap_or(dir_name),
            description: frontmatter.description.unwrap_or_default(),
            required_bins,
            body,
            path: path.to_path_buf(),
            available,
            permissions,
        })
    }

    /// Build a system prompt fragment from loaded skills.
    /// Only includes skills whose required binaries are available.
    pub fn build_prompt(skills: &[Skill]) -> String {
        let available: Vec<&Skill> = skills.iter().filter(|s| s.available).collect();

        if available.is_empty() {
            return String::new();
        }

        let mut prompt = String::from("\n\n## Available Skills\n\n");
        for skill in &available {
            prompt.push_str(&format!("### {}\n", skill.name));
            if !skill.description.is_empty() {
                prompt.push_str(&skill.description);
                prompt.push('\n');
            }
            prompt.push('\n');
            prompt.push_str(&skill.body);
            prompt.push_str("\n\n");
        }

        prompt
    }
}

/// Parse YAML frontmatter from a SKILL.md file.
/// Expects the format: --- <YAML> --- <body>
fn parse_frontmatter(content: &str) -> Result<(SkillFrontmatter, String), AgentError> {
    let content = content.trim();

    if !content.starts_with("---") {
        // No frontmatter — treat entire content as body
        return Ok((
            SkillFrontmatter {
                name: None,
                description: None,
                metadata: None,
                permissions: None,
            },
            content.to_string(),
        ));
    }

    // Find the closing ---
    let rest = &content[3..];
    let end = rest
        .find("---")
        .ok_or_else(|| AgentError::SkillLoad("unclosed frontmatter".into()))?;

    let yaml_str = &rest[..end].trim();
    let body = rest[end + 3..].trim().to_string();

    let frontmatter: SkillFrontmatter = serde_yaml::from_str(yaml_str)
        .map_err(|e| AgentError::SkillLoad(format!("invalid frontmatter YAML: {e}")))?;

    Ok((frontmatter, body))
}

/// Extract required binary names from the metadata field.
/// Primary key is `metadata.wirken.requires.bins`. `metadata.openclaw.*`
/// is accepted as a deprecated alias for back-compat; a migration hint
/// is logged when only the alias is present.
fn extract_required_bins(fm: &SkillFrontmatter) -> Vec<String> {
    let metadata = match fm.metadata.as_ref() {
        Some(m) => m,
        None => return Vec::new(),
    };

    let section = metadata.get("wirken").or_else(|| {
        let openclaw = metadata.get("openclaw");
        if openclaw.is_some() {
            tracing::warn!(
                "skill frontmatter uses deprecated 'openclaw' metadata key; rename to 'wirken'"
            );
        }
        openclaw
    });

    section
        .and_then(|s| s.get("requires"))
        .and_then(|req| req.get("bins"))
        .and_then(|bins| bins.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Check if all required binaries are available on PATH.
fn check_bins_available(bins: &[String]) -> bool {
    bins.iter().all(|bin| which_exists(bin))
}

fn which_exists(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
