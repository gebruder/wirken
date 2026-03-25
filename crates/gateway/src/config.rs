use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Base data directory (default: ~/.wirken)
    pub data_dir: PathBuf,

    /// Session expiry in seconds (default: 86400 = 24 hours)
    pub session_expiry_secs: u64,

    /// Audit log retention in days (default: 90)
    pub audit_retention_days: u32,

    /// Auth rate limit: max failed attempts per window
    pub auth_rate_limit_max: u32,

    /// Auth rate limit: window in seconds
    pub auth_rate_limit_window_secs: u64,

    /// Auth rate limit: lockout duration in seconds
    pub auth_rate_limit_lockout_secs: u64,

    /// Control plane write rate limit: max per minute
    pub control_plane_rate_limit: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            session_expiry_secs: 86400, // 24 hours
            audit_retention_days: 90,
            auth_rate_limit_max: 5,
            auth_rate_limit_window_secs: 60,
            auth_rate_limit_lockout_secs: 600, // 10 minutes
            control_plane_rate_limit: 10,
        }
    }
}

impl GatewayConfig {
    pub fn vault_db_path(&self) -> PathBuf {
        self.data_dir.join("vault.db")
    }

    pub fn audit_db_path(&self) -> PathBuf {
        self.data_dir.join("audit.db")
    }

    pub fn sessions_db_path(&self) -> PathBuf {
        self.data_dir.join("sessions.db")
    }

    pub fn permissions_db_path(&self) -> PathBuf {
        self.data_dir.join("permissions.db")
    }

    pub fn adapters_db_path(&self) -> PathBuf {
        self.data_dir.join("adapters.db")
    }

    pub fn agent_config_db_path(&self) -> PathBuf {
        self.data_dir.join("agent_config.db")
    }

    /// Per-agent workspace directory.
    pub fn agent_workspace(&self, agent_id: &str) -> PathBuf {
        self.data_dir
            .join("agents")
            .join(agent_id)
            .join("workspace")
    }

    /// Per-agent skills directory.
    pub fn agent_skills_dir(&self, agent_id: &str) -> PathBuf {
        self.data_dir.join("agents").join(agent_id).join("skills")
    }

    pub fn socket_dir(&self) -> PathBuf {
        self.data_dir.join("sockets")
    }

    /// Ensure all required directories exist.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(self.socket_dir())?;
        Ok(())
    }
}

fn default_data_dir() -> PathBuf {
    dirs_home().join(".wirken")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
