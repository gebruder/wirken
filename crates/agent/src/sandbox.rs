//! Docker/Podman sandbox for tool execution.

use std::path::Path;

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::models::HostConfig;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, WaitContainerOptions,
};
use futures_util::StreamExt;

use crate::error::AgentError;
use crate::tool::ToolResult;

const DEFAULT_IMAGE: &str = "debian:bookworm-slim";
const MEMORY_LIMIT: i64 = 512 * 1024 * 1024; // 512 MB
const PIDS_LIMIT: i64 = 256;

/// Sandbox mode for tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// No sandboxing. Direct host execution. Opt-in only; set
    /// `"mode": "off"` in `sandbox.json` to use this.
    Off,
    /// Only the `exec` tool runs in a Docker container (default runc runtime).
    /// This is the default as of 0.7.5. If Docker is not reachable at
    /// gateway start, the ToolRegistry logs a warning and falls back
    /// to host execution for the agent's lifetime.
    #[default]
    ExecOnly,
    /// Only the `exec` tool runs in a gVisor container (runsc runtime).
    /// Provides kernel attack surface reduction: syscalls are intercepted by
    /// gVisor's Sentry rather than reaching the host kernel. Requires
    /// `runsc` registered as a Docker runtime.
    GVisor,
}

impl SandboxMode {
    /// Parse a sandbox mode from a config string. Unknown modes fall
    /// back to [`SandboxMode::default`] rather than forcing `Off`, so
    /// a config typo does not silently strip the sandbox; the
    /// operator gets the secure default instead, with a warning.
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "exec-only" => Self::ExecOnly,
            "gvisor" => Self::GVisor,
            "off" => Self::Off,
            "" => Self::default(),
            _ => {
                tracing::warn!(
                    "Unknown sandbox_mode '{s}', falling back to default ({:?})",
                    Self::default()
                );
                Self::default()
            }
        }
    }

    /// The OCI runtime name to pass to Docker, or None for the default (runc).
    pub(crate) fn runtime_name(self) -> Option<String> {
        match self {
            Self::GVisor => Some("runsc".to_string()),
            _ => None,
        }
    }
}

/// Configuration for the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub mode: SandboxMode,
    pub image: String,
    pub timeout_secs: u64,
    /// Allow network access from sandbox (default: false).
    pub network: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::ExecOnly,
            image: DEFAULT_IMAGE.into(),
            timeout_secs: 300,
            network: false,
        }
    }
}

/// Docker sandbox executor.
pub struct DockerSandbox {
    client: Docker,
    config: SandboxConfig,
}

impl DockerSandbox {
    /// Connect to the Docker daemon.
    pub fn new(config: SandboxConfig) -> Result<Self, AgentError> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| AgentError::Sandbox(format!("Docker connect: {e}")))?;
        Ok(Self { client, config })
    }

    /// Execute a command inside an ephemeral container.
    /// The workspace is bind-mounted at /workspace.
    pub async fn exec(&self, command: &str, workspace: &Path) -> Result<ToolResult, AgentError> {
        let workspace_str = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.to_path_buf())
            .to_string_lossy()
            .to_string();

        let container_config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            cmd: Some(vec!["sh".into(), "-c".into(), command.into()]),
            working_dir: Some("/workspace".into()),
            user: Some("1000:1000".into()),
            host_config: Some(build_host_config(&self.config, &workspace_str)),
            ..Default::default()
        };

        let container_name = format!("wirken-sandbox-{}", short_id());

        let create_opts = CreateContainerOptions {
            name: Some(container_name.clone()),
            platform: String::new(),
        };

        let container = self
            .client
            .create_container(Some(create_opts), container_config)
            .await
            .map_err(|e| AgentError::Sandbox(format!("create container: {e}")))?;

        self.client
            .start_container(&container.id, None)
            .await
            .map_err(|e| AgentError::Sandbox(format!("start container: {e}")))?;

        // Wait for container to finish, with timeout
        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);
        let wait_result = tokio::time::timeout(timeout, async {
            let mut stream = self.client.wait_container(
                &container.id,
                Some(WaitContainerOptions {
                    condition: "not-running".into(),
                }),
            );
            if let Some(result) = stream.next().await {
                match result {
                    Ok(exit) => return Ok(exit.status_code),
                    Err(e) => return Err(AgentError::Sandbox(format!("wait: {e}"))),
                }
            }
            Ok(0i64)
        })
        .await;

        let exit_code = match wait_result {
            Ok(Ok(code)) => code,
            Ok(Err(e)) => {
                let _ = self.kill_and_remove(&container.id).await;
                return Err(e);
            }
            Err(_) => {
                let _ = self.kill_and_remove(&container.id).await;
                return Ok(ToolResult {
                    output: format!(
                        "Command timed out after {}s (sandbox)",
                        self.config.timeout_secs
                    ),
                    success: false,
                });
            }
        };

        // Collect logs
        let mut stdout = String::new();
        let mut stderr = String::new();

        let mut log_stream = self.client.logs(
            &container.id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        while let Some(log) = log_stream.next().await {
            match log {
                Ok(LogOutput::StdOut { message }) => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(LogOutput::StdErr { message }) => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                _ => {}
            }
        }

        // Cleanup (auto_remove should handle it, but be safe)
        let _ = self.kill_and_remove(&container.id).await;

        let mut result = String::new();
        if !stdout.is_empty() {
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str("[stderr] ");
            result.push_str(&stderr);
        }
        if result.is_empty() {
            result.push_str("(no output)");
        }

        if result.len() > 32_000 {
            result.truncate(32_000);
            result.push_str("\n... (truncated)");
        }

        Ok(ToolResult {
            output: result,
            success: exit_code == 0,
        })
    }

    async fn kill_and_remove(&self, id: &str) {
        let _ = self.client.kill_container(id, None).await;
        let _ = self
            .client
            .remove_container(
                id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    /// Check if Docker is available.
    pub async fn check(&self) -> Result<String, AgentError> {
        let version = self
            .client
            .version()
            .await
            .map_err(|e| AgentError::Sandbox(format!("Docker version: {e}")))?;

        let ver_str = version.version.unwrap_or_else(|| "unknown".into());
        Ok(format!("Docker {ver_str}"))
    }
}

/// Build the `HostConfig` for a sandboxed exec. Extracted so the
/// hardening settings can be asserted without spinning up Docker.
///
/// Kernel-level hardening, in addition to the memory, PID, network,
/// and user caps already set below:
///
/// * `cap_drop=ALL`: strip every Linux capability. The agent never
///   needs `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, etc. If a real use
///   case breaks this, re-evaluate rather than loosening by default.
/// * `no-new-privileges`: block setuid/setgid elevation inside the
///   container. Pairs with `cap_drop`.
/// * `seccomp=default`: pin Docker's default seccomp profile
///   explicitly, so a daemon-wide `"seccomp": "unconfined"`
///   misconfiguration does not silently disable syscall filtering
///   for our containers.
/// * `readonly_rootfs`: make the container's `/` read-only. The
///   workspace bind-mount stays RW, and a tmpfs at `/tmp` gives the
///   shell somewhere to scratch.
pub(crate) fn build_host_config(config: &SandboxConfig, workspace_str: &str) -> HostConfig {
    let network_mode = if config.network {
        None
    } else {
        Some("none".to_string())
    };
    let tmpfs_mounts: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        m.insert("/tmp".into(), "size=64m,mode=1777".into());
        m
    };
    HostConfig {
        binds: Some(vec![format!("{workspace_str}:/workspace:rw")]),
        network_mode,
        memory: Some(MEMORY_LIMIT),
        pids_limit: Some(PIDS_LIMIT),
        auto_remove: Some(true),
        runtime: config.mode.runtime_name(),
        cap_drop: Some(vec!["ALL".into()]),
        cap_add: Some(Vec::new()),
        security_opt: Some(vec![
            "no-new-privileges:true".into(),
            "seccomp=default".into(),
        ]),
        readonly_rootfs: Some(true),
        tmpfs: Some(tmpfs_mounts),
        ..Default::default()
    }
}

/// Detect if Docker is available.
pub async fn detect_runtime() -> Option<String> {
    if let Ok(docker) = Docker::connect_with_local_defaults()
        && docker.version().await.is_ok()
    {
        return Some("docker".into());
    }
    None
}

/// Detect if gVisor (runsc) is available as a Docker runtime.
/// Checks both that Docker is running and that `runsc` is listed in its runtimes.
pub async fn detect_gvisor() -> bool {
    let Ok(docker) = Docker::connect_with_local_defaults() else {
        return false;
    };
    let Ok(info) = docker.info().await else {
        return false;
    };
    // Docker info returns runtimes as a map. Check if "runsc" is a key.
    if let Some(runtimes) = info.runtimes {
        return runtimes.contains_key("runsc");
    }
    false
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}
