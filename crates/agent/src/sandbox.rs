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
    /// No sandboxing — direct host execution.
    #[default]
    Off,
    /// Only the `exec` tool runs in a container.
    ExecOnly,
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
            mode: SandboxMode::Off,
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

        let network_mode = if self.config.network {
            None
        } else {
            Some("none".to_string())
        };

        let container_config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            cmd: Some(vec!["sh".into(), "-c".into(), command.into()]),
            working_dir: Some("/workspace".into()),
            user: Some("1000:1000".into()),
            host_config: Some(HostConfig {
                binds: Some(vec![format!("{workspace_str}:/workspace:rw")]),
                network_mode,
                memory: Some(MEMORY_LIMIT),
                pids_limit: Some(PIDS_LIMIT),
                auto_remove: Some(true),
                ..Default::default()
            }),
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

/// Detect if Docker is available.
pub async fn detect_runtime() -> Option<String> {
    if let Ok(docker) = Docker::connect_with_local_defaults()
        && docker.version().await.is_ok()
    {
        return Some("docker".into());
    }
    None
}

fn short_id() -> String {
    let mut bytes = [0u8; 6];
    // Simple counter-based ID since we don't need crypto randomness here
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    bytes[0..4].copy_from_slice(&ns.to_le_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
