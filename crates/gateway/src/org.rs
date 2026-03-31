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

    Ok(applied)
}
