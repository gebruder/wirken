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

    pub fn siem_config_path(&self) -> PathBuf {
        self.data_dir.join("siem.json")
    }

    pub fn cron_db_path(&self) -> PathBuf {
        self.data_dir.join("cron.db")
    }

    pub fn agent_config_db_path(&self) -> PathBuf {
        self.data_dir.join("agent_config.db")
    }

    /// Durable per-agent budget spend ledger.
    pub fn budget_db_path(&self) -> PathBuf {
        self.data_dir.join("budget.db")
    }

    /// Labelled cross-channel memory entries (#64).
    pub fn memory_db_path(&self) -> PathBuf {
        self.data_dir.join("memory.db")
    }

    /// Imported assistant data-export archives.
    pub fn imported_db_path(&self) -> PathBuf {
        self.data_dir.join("imported.db")
    }

    /// Budget configuration: a global default plus per-agent
    /// overrides. Absent means no budgets are configured (enforcement
    /// off).
    pub fn budget_config_path(&self) -> PathBuf {
        self.data_dir.join("budget.json")
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

    /// MCP config path for an agent (per-agent or shared).
    pub fn mcp_config_path(&self, agent_id: &str) -> PathBuf {
        let per_agent = self.data_dir.join("agents").join(agent_id).join("mcp.json");
        if per_agent.exists() {
            per_agent
        } else {
            self.data_dir.join("mcp.json")
        }
    }

    pub fn socket_dir(&self) -> PathBuf {
        self.data_dir.join("sockets")
    }

    /// Ensure all required directories exist with owner-only perms.
    ///
    /// The data dir holds the vault, audit DB, signing keys, and the
    /// IPC sockets. Each sensitive file is individually chmod'd 0o600,
    /// but the directory itself is the cheap outer containment layer:
    /// at 0o700 no other local user can traverse into `sockets/` (which
    /// would otherwise expose the bind-then-chmod window on each socket)
    /// or read a file that some future path forgot to lock down. We
    /// chmod even when the dir already exists so a loose 0o755 left by
    /// an earlier run, or by `create_dir_all` under a permissive umask,
    /// converges back to 0o700 — the same posture `org.rs` applies to
    /// secret files.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        create_dir_owner_only(&self.data_dir)?;
        create_dir_owner_only(&self.socket_dir())?;
        Ok(())
    }
}

/// Create `path` (and parents) and, on unix, pin it to mode 0o700.
fn create_dir_owner_only(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The single source of truth for the operator data directory.
///
/// `GatewayConfig::default` uses this, and so does the skill-load
/// signature gate when it resolves the operator-set registry root.
/// Both must agree on where operator state lives: the gate and the
/// running gateway never look in different directories, because they
/// call this same function. `GatewayConfig` is only ever constructed
/// via `default()`, so for the process that loads skills `data_dir`
/// and this function cannot diverge.
///
/// `WIRKEN_DATA_DIR` overrides the default when set to a non-empty
/// value. The gateway exports it to the adapter and MCP-proxy
/// processes it spawns, and those resolve their own data dir through
/// this same function, so one host cannot end up with a gateway
/// writing `audit.db` in one directory while a child reads
/// credentials from another. An empty value is treated as unset
/// rather than as the relative path `""`: an exported-but-blank
/// variable is a misconfiguration, and resolving it to the process's
/// working directory would scatter vault and audit state wherever the
/// operator happened to be standing.
pub fn default_data_dir() -> PathBuf {
    match std::env::var_os("WIRKEN_DATA_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => dirs_home().join(".wirken"),
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Env-var resolution for the data directory. Separate from the
/// unix-only permissions tests below because the behaviour is
/// cross-platform.
///
/// These tests write a process-global variable, and cargo runs a
/// crate's tests on parallel threads, so they serialise on one lock
/// and restore the prior value before releasing it.
#[cfg(test)]
mod data_dir_tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set `WIRKEN_DATA_DIR` to `value` (or remove it for `None`),
    /// run `f`, then put the variable back the way it was.
    fn with_data_dir_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _serial = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var_os("WIRKEN_DATA_DIR");
        unsafe {
            match value {
                Some(v) => std::env::set_var("WIRKEN_DATA_DIR", v),
                None => std::env::remove_var("WIRKEN_DATA_DIR"),
            }
        }
        let out = f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var("WIRKEN_DATA_DIR", v),
                None => std::env::remove_var("WIRKEN_DATA_DIR"),
            }
        }
        out
    }

    #[test]
    fn env_override_wins_over_home() {
        let dir = with_data_dir_env(Some("/srv/wirken-state"), default_data_dir);
        assert_eq!(dir, PathBuf::from("/srv/wirken-state"));
    }

    #[test]
    fn unset_falls_back_to_home_dot_wirken() {
        let dir = with_data_dir_env(None, default_data_dir);
        assert_eq!(dir, dirs_home().join(".wirken"));
    }

    #[test]
    fn empty_value_is_treated_as_unset() {
        // An exported-but-blank variable must not resolve to the
        // working directory; that would scatter vault and audit state.
        let dir = with_data_dir_env(Some(""), default_data_dir);
        assert_eq!(dir, dirs_home().join(".wirken"));
    }

    #[test]
    fn gateway_config_default_follows_the_override() {
        // The gate that loads skills calls `default_data_dir` and the
        // running gateway carries `GatewayConfig::data_dir`. This is
        // the assertion that the two cannot diverge.
        let (cfg_dir, fn_dir) = with_data_dir_env(Some("/srv/wirken-state"), || {
            (GatewayConfig::default().data_dir, default_data_dir())
        });
        assert_eq!(cfg_dir, fn_dir);
        assert_eq!(cfg_dir, PathBuf::from("/srv/wirken-state"));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ensure_dirs_lands_0o700_on_data_dir_and_socket_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = GatewayConfig {
            data_dir: tmp.path().join("data"),
            ..GatewayConfig::default()
        };
        cfg.ensure_dirs().unwrap();
        assert_eq!(mode_of(&cfg.data_dir), 0o700, "data_dir must be owner-only");
        assert_eq!(
            mode_of(&cfg.socket_dir()),
            0o700,
            "socket_dir must be owner-only"
        );
    }

    #[test]
    fn ensure_dirs_converges_existing_loose_dir_back_to_0o700() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        // Simulate a dir left world-traversable by an earlier run or a
        // permissive umask.
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = GatewayConfig {
            data_dir,
            ..GatewayConfig::default()
        };
        cfg.ensure_dirs().unwrap();
        assert_eq!(
            mode_of(&cfg.data_dir),
            0o700,
            "loose 0o755 data_dir must converge to 0o700"
        );
    }
}
