//! Organization policy: centralized config pulled from a company endpoint.
//!
//! IT manages one JSON document at a URL. Each developer's wirken instance
//! pulls it on setup and periodically on run.
//!
//! Example org config served at https://wirken.corp.example.com/config:
//!
//! ```json
//! {
//!     "provider": {
//!         "provider": "openai",
//!         "model": "gpt-4o",
//!         "base_url": "https://api.openai.com/v1"
//!     },
//!     "api_key_name": "openai-api-key",
//!     "siem": {
//!         "target": "datadog",
//!         "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
//!         "api_key": "dd-org-key",
//!         "service": "wirken",
//!         "environment": "production"
//!     },
//!     "mcp": {
//!         "servers": {
//!             "datadog": {
//!                 "command": "npx",
//!                 "args": ["-y", "@datadog/mcp-server"],
//!                 "env": {}
//!             }
//!         }
//!     },
//!     "permissions": {
//!         "sandbox_mode": "exec-only",
//!         "allowed_tools": ["exec", "read_file", "write_file", "list_files", "web_search"],
//!         "blocked_tools": ["generate_image"]
//!     },
//!     "skills": {
//!         "auto_install": ["github", "git", "web-fetch"],
//!         "blocked": []
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Organization config pulled from a central endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgConfig {
    /// LLM provider configuration (provider, model, base_url).
    #[serde(default)]
    pub provider: Option<serde_json::Value>,

    /// Vault credential name for the org API key.
    /// If set, the developer is prompted to enter it during setup.
    #[serde(default)]
    pub api_key_name: Option<String>,

    /// SIEM forwarding configuration.
    #[serde(default)]
    pub siem: Option<serde_json::Value>,

    /// MCP server configuration.
    #[serde(default)]
    pub mcp: Option<serde_json::Value>,

    /// Permission policy.
    #[serde(default)]
    pub permissions: Option<OrgPermissions>,

    /// Skill policy.
    #[serde(default)]
    pub skills: Option<OrgSkillPolicy>,
}

/// Organization-level permission controls.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgPermissions {
    /// Sandbox mode: "off", "exec-only", "gvisor"
    #[serde(default)]
    pub sandbox_mode: Option<String>,

    /// Tools the agent is allowed to use. Empty means all.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Tools explicitly blocked.
    #[serde(default)]
    pub blocked_tools: Vec<String>,
}

/// Organization-level skill policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgSkillPolicy {
    /// Skills to install automatically during setup.
    #[serde(default)]
    pub auto_install: Vec<String>,

    /// Skills that are blocked from installation.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Fetch org config from a URL.
pub async fn fetch_org_config(url: &str) -> Result<OrgConfig, String> {
    let http = reqwest::Client::new();
    let resp = http
        .get(url)
        .header("User-Agent", "wirken")
        .send()
        .await
        .map_err(|e| format!("fetch org config: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("org config returned HTTP {}", resp.status()));
    }

    resp.json::<OrgConfig>()
        .await
        .map_err(|e| format!("parse org config: {e}"))
}

/// Save the org endpoint URL for periodic refresh.
pub fn save_org_url(data_dir: &Path, url: &str) -> std::io::Result<()> {
    std::fs::write(data_dir.join("org.url"), url)
}

/// Load the saved org endpoint URL.
pub fn load_org_url(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("org.url");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Apply org config to the local data directory.
/// Writes provider.json, siem.json, mcp.json as appropriate.
/// Does not overwrite files that already exist unless force is true.
pub fn apply_org_config(
    data_dir: &Path,
    org: &OrgConfig,
    force: bool,
) -> Result<Vec<String>, String> {
    let mut applied = Vec::new();

    // Provider
    if let Some(ref provider) = org.provider {
        let path = data_dir.join("provider.json");
        if force || !path.exists() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(provider).unwrap_or_default(),
            )
            .map_err(|e| format!("write provider.json: {e}"))?;
            applied.push("provider".into());
        }
    }

    // SIEM
    if let Some(ref siem) = org.siem {
        let path = data_dir.join("siem.json");
        if force || !path.exists() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(siem).unwrap_or_default(),
            )
            .map_err(|e| format!("write siem.json: {e}"))?;
            applied.push("siem".into());
        }
    }

    // MCP
    if let Some(ref mcp) = org.mcp {
        let path = data_dir.join("mcp.json");
        if force || !path.exists() {
            std::fs::write(&path, serde_json::to_string_pretty(mcp).unwrap_or_default())
                .map_err(|e| format!("write mcp.json: {e}"))?;
            applied.push("mcp".into());
        }
    }

    // Sandbox mode, driven by `permissions.sandbox_mode` on the pulled
    // org config. Stored as a separate `sandbox.json` file so an org
    // update does not disturb unrelated provider config. The CLI's
    // `load_sandbox_config` helper reads this file on each gateway
    // start.
    if let Some(ref perms) = org.permissions
        && let Some(ref mode) = perms.sandbox_mode
    {
        let path = data_dir.join("sandbox.json");
        if force || !path.exists() {
            let body = serde_json::json!({ "mode": mode });
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&body).unwrap_or_default(),
            )
            .map_err(|e| format!("write sandbox.json: {e}"))?;
            applied.push("sandbox".into());
        }
    }

    // Tool allow/deny policy. Persisted to `tool_policy.json` on the
    // same principle as `sandbox.json`: a single-purpose file the
    // gateway reads on every start. Absent or empty lists disable
    // the corresponding check in `crates/agent/src/runtime.rs::execute_tool`.
    if let Some(ref perms) = org.permissions
        && (!perms.allowed_tools.is_empty() || !perms.blocked_tools.is_empty())
    {
        let path = data_dir.join("tool_policy.json");
        if force || !path.exists() {
            let body = serde_json::json!({
                "allowed_tools": perms.allowed_tools,
                "blocked_tools": perms.blocked_tools,
            });
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&body).unwrap_or_default(),
            )
            .map_err(|e| format!("write tool_policy.json: {e}"))?;
            applied.push("tool_policy".into());
        }
    }

    Ok(applied)
}

/// Read `tool_policy.json` from the gateway data directory and
/// return it as an [`OrgPermissions`] carrying only the allow/deny
/// lists (sandbox_mode is None — sandbox is already loaded separately).
/// Returns `None` if the file is absent or unreadable; malformed
/// JSON is logged and treated as absent (fail-open on policy load is
/// intentional: a corrupted policy file should not brick the
/// gateway, but the operator sees a warning).
pub fn load_tool_policy(data_dir: &Path) -> Option<OrgPermissions> {
    let path = data_dir.join("tool_policy.json");
    let body = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<OrgPermissions>(&body) {
        Ok(perms) => Some(perms),
        Err(e) => {
            tracing::warn!(
                "tool_policy.json at {} is malformed: {e}; \
                 continuing with no org tool policy",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn apply_org_config_writes_sandbox_json_from_permissions() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(applied.contains(&"sandbox".to_string()));
        let body = std::fs::read_to_string(tmp.path().join("sandbox.json")).unwrap();
        let val: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(val["mode"].as_str(), Some("gvisor"));
    }

    #[test]
    fn apply_org_config_no_sandbox_without_permissions() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig::default();
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(!applied.contains(&"sandbox".to_string()));
        assert!(!tmp.path().join("sandbox.json").exists());
    }

    #[test]
    fn apply_org_config_writes_tool_policy_when_lists_non_empty() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: None,
                allowed_tools: vec!["read_file".into(), "web_search".into()],
                blocked_tools: vec!["exec".into()],
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(applied.contains(&"tool_policy".to_string()));
        let loaded = load_tool_policy(tmp.path()).unwrap();
        assert_eq!(loaded.allowed_tools, vec!["read_file", "web_search"]);
        assert_eq!(loaded.blocked_tools, vec!["exec"]);
    }

    #[test]
    fn apply_org_config_skips_tool_policy_when_both_lists_empty() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                allowed_tools: vec![],
                blocked_tools: vec![],
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(!applied.contains(&"tool_policy".to_string()));
        assert!(!tmp.path().join("tool_policy.json").exists());
    }

    #[test]
    fn load_tool_policy_returns_none_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        assert!(load_tool_policy(tmp.path()).is_none());
    }

    #[test]
    fn load_tool_policy_returns_none_for_malformed_json() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("tool_policy.json"), "{ not json").unwrap();
        assert!(load_tool_policy(tmp.path()).is_none());
    }

    #[test]
    fn apply_org_config_preserves_existing_sandbox_when_not_forced() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"mode":"exec-only"}"#).unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_org_config(tmp.path(), &org, false).unwrap();
        let body = std::fs::read_to_string(tmp.path().join("sandbox.json")).unwrap();
        let val: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(val["mode"].as_str(), Some("exec-only"));
    }
}
