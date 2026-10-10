//! Stdio MCP servers in containers.
//!
//! A server whose `mcp.json` entry carries a `sandbox` block runs in its
//! own container, one per agent and server, under the hardening `exec`
//! containers get ([`wirken_sandbox::hardened_host_config`]). The proxy
//! attaches to the container's stdin and stdout before starting it and
//! speaks the same line-delimited JSON-RPC it speaks to a host child.
//!
//! Every container carries labels naming this data directory's
//! instance, the agent and the server. The proxy stops and removes its
//! containers on shutdown, and on start removes any its instance left
//! behind, for example after the gateway killed it.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use bollard::Docker;
use bollard::models::{ContainerCreateBody, Mount, MountType};
use bollard::query_parameters::{
    ListContainersOptions, RemoveContainerOptions, StopContainerOptions,
};
use sha2::{Digest, Sha256};

use crate::mcp_config::{ContainerSandbox, INSTALL_DIR_TARGET, SCRATCH_TARGET};

/// Marks a container as an MCP server container.
pub const LABEL_ROLE: &str = "wirken.mcp";
/// The data directory's instance; see [`instance_id`].
pub const LABEL_INSTANCE: &str = "wirken.mcp.instance";
/// The agent the server runs for.
pub const LABEL_AGENT: &str = "wirken.mcp.agent";
/// The server's name in `mcp.json`.
pub const LABEL_SERVER: &str = "wirken.mcp.server";

/// Paths inside the container a declared mount may not cover or sit
/// under: the install and scratch targets, and what the runtime or the
/// hardening already owns.
const RESERVED_TARGETS: &[&str] = &[
    INSTALL_DIR_TARGET,
    SCRATCH_TARGET,
    "/tmp",
    "/proc",
    "/sys",
    "/dev",
];

/// Default CPU cap: one CPU, in the billionths Docker counts in.
const DEFAULT_NANO_CPUS: i64 = 1_000_000_000;

/// What every container this proxy starts has in common.
#[derive(Clone)]
pub struct SandboxHost {
    /// `None` when no Docker client could be built. A daemon that is
    /// down still yields a client; it fails at the first call.
    pub docker: Option<Docker>,
    /// Names this data directory on container labels without putting
    /// its path there.
    pub instance: String,
    /// Where per-server scratch directories live.
    pub data_dir: PathBuf,
    /// OCI runtime from `sandbox.json`'s mode; `None` is runc.
    pub runtime: Option<String>,
}

impl SandboxHost {
    /// The host for the proxy serving `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            docker: Docker::connect_with_local_defaults().ok(),
            instance: instance_id(data_dir),
            data_dir: data_dir.to_path_buf(),
            runtime: sandbox_runtime(data_dir),
        }
    }

    /// A host with no container runtime, for callers that never start
    /// containers.
    pub fn unavailable() -> Self {
        Self {
            docker: None,
            instance: String::new(),
            data_dir: PathBuf::new(),
            runtime: None,
        }
    }
}

/// A short, stable name for `data_dir`: the first 16 hex characters of
/// its path's SHA-256. Two gateways with different data directories on
/// one Docker daemon never sweep each other's containers.
pub fn instance_id(data_dir: &Path) -> String {
    let digest = Sha256::digest(data_dir.to_string_lossy().as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// The OCI runtime `sandbox.json`'s mode asks for. `gvisor` is `runsc`;
/// anything else, including `off`, is Docker's default. `off` turns off
/// the `exec` sandbox only; MCP servers stay contained.
pub fn sandbox_runtime(data_dir: &Path) -> Option<String> {
    let body = std::fs::read_to_string(data_dir.join("sandbox.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    let mode = value.get("mode").and_then(|m| m.as_str()).unwrap_or("");
    wirken_sandbox::SandboxMode::from_str_config(mode).runtime_name()
}

/// One server's container, decided from its config. Building a plan is
/// where the `sandbox` block is checked: a plan exists only for a block
/// the proxy can start.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerPlan {
    pub agent_id: String,
    pub server: String,
    pub image: String,
    pub cmd: Vec<String>,
    /// `NAME=value`, sorted.
    pub env: Vec<String>,
    pub user: String,
    pub working_dir: Option<String>,
    pub mounts: Vec<Mount>,
    pub network_mode: String,
    pub memory_bytes: i64,
    pub pids: i64,
    pub nano_cpus: i64,
    pub runtime: Option<String>,
    pub labels: HashMap<String, String>,
    /// Host directory to create before the container starts.
    pub scratch_dir: Option<PathBuf>,
}

impl ContainerPlan {
    /// Plan `server`'s container for `agent_id`, or say why its block
    /// cannot be started.
    pub fn new(
        host: &SandboxHost,
        agent_id: &str,
        server: &str,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        block: &ContainerSandbox,
    ) -> Result<Self, String> {
        let image = block
            .image
            .as_deref()
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .ok_or("no image: a stdio server's sandbox block must name the image it runs in")?
            .to_string();

        let mut mounts = Vec::new();
        let working_dir = match &block.install_dir {
            Some(dir) => {
                let dir = existing_absolute(dir, "install_dir")?;
                mounts.push(bind(&dir, INSTALL_DIR_TARGET, false));
                Some(INSTALL_DIR_TARGET.to_string())
            }
            None => None,
        };

        let mut targets = Vec::new();
        for m in &block.mounts {
            let source = existing_absolute(&m.source, "mount source")?;
            let target = container_target(&m.target)?;
            if targets.contains(&target) {
                return Err(format!("two mounts target {target}"));
            }
            mounts.push(bind(&source, &target, m.writable));
            targets.push(target);
        }

        let scratch_dir = if block.scratch {
            let dir = host
                .data_dir
                .join("mcp-scratch")
                .join(path_component(agent_id, "agent id")?)
                .join(path_component(server, "server name")?);
            mounts.push(bind(&dir, SCRATCH_TARGET, true));
            Some(dir)
        } else {
            None
        };

        let memory_bytes = match block.limits.memory_mb {
            Some(0) => return Err("limits.memory_mb must be above zero".into()),
            Some(mb) => i64::try_from(mb.saturating_mul(1024 * 1024))
                .map_err(|_| "limits.memory_mb is too large".to_string())?,
            None => wirken_sandbox::MEMORY_LIMIT,
        };
        let pids = match block.limits.pids {
            Some(0) => return Err("limits.pids must be above zero".into()),
            Some(p) => i64::try_from(p).map_err(|_| "limits.pids is too large".to_string())?,
            None => wirken_sandbox::PIDS_LIMIT,
        };
        let nano_cpus = match block.limits.cpus {
            Some(c) if !(c.is_finite() && c > 0.0) => {
                return Err("limits.cpus must be a positive number".into());
            }
            Some(c) => (c * 1e9) as i64,
            None => DEFAULT_NANO_CPUS,
        };

        let mut env: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        env.sort();

        let labels = HashMap::from([
            (LABEL_ROLE.to_string(), "1".to_string()),
            (LABEL_INSTANCE.to_string(), host.instance.clone()),
            (LABEL_AGENT.to_string(), agent_id.to_string()),
            (LABEL_SERVER.to_string(), server.to_string()),
        ]);

        Ok(Self {
            agent_id: agent_id.to_string(),
            server: server.to_string(),
            image,
            cmd: std::iter::once(command.to_string())
                .chain(args.iter().cloned())
                .collect(),
            env,
            user: container_user(),
            working_dir,
            mounts,
            network_mode: "none".to_string(),
            memory_bytes,
            pids,
            nano_cpus,
            runtime: host.runtime.clone(),
            labels,
            scratch_dir,
        })
    }

    /// The body sent to Docker. Stdin stays open for the JSON-RPC
    /// stream and closes when the proxy's attach does, so a server that
    /// exits at end of input exits with the proxy.
    pub fn create_body(&self) -> ContainerCreateBody {
        ContainerCreateBody {
            image: Some(self.image.clone()),
            cmd: Some(self.cmd.clone()),
            env: Some(self.env.clone()),
            user: Some(self.user.clone()),
            working_dir: self.working_dir.clone(),
            labels: Some(self.labels.clone()),
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(false),
            open_stdin: Some(true),
            stdin_once: Some(true),
            tty: Some(false),
            host_config: Some(wirken_sandbox::hardened_host_config(
                wirken_sandbox::HostSettings {
                    binds: Vec::new(),
                    mounts: self.mounts.clone(),
                    network_mode: Some(self.network_mode.clone()),
                    dns: None,
                    memory: self.memory_bytes,
                    pids: self.pids,
                    nano_cpus: Some(self.nano_cpus),
                    runtime: self.runtime.clone(),
                },
            )),
            ..Default::default()
        }
    }
}

fn bind(source: &Path, target: &str, writable: bool) -> Mount {
    Mount {
        target: Some(target.to_string()),
        source: Some(source.to_string_lossy().into_owned()),
        typ: Some(MountType::BIND),
        read_only: Some(!writable),
        ..Default::default()
    }
}

fn existing_absolute(path: &str, what: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(format!("{what} {} is not an absolute path", path.display()));
    }
    if !path.exists() {
        return Err(format!("{what} {} does not exist", path.display()));
    }
    Ok(path)
}

/// A mount target: absolute, no `..`, and clear of the reserved paths.
fn container_target(target: &str) -> Result<String, String> {
    let path = Path::new(target);
    if !target.starts_with('/') {
        return Err(format!("mount target {target} is not an absolute path"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("mount target {target} contains .."));
    }
    let trimmed = target.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("a mount cannot target /".into());
    }
    for reserved in RESERVED_TARGETS {
        if trimmed == *reserved || trimmed.starts_with(&format!("{reserved}/")) {
            return Err(format!("mount target {target} is reserved ({reserved})"));
        }
    }
    Ok(trimmed.to_string())
}

/// A name used as one path component on the host.
fn path_component<'a>(name: &'a str, what: &str) -> Result<&'a str, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(format!("{what} {name:?} cannot name a scratch directory"));
    }
    Ok(name)
}

/// The uid:gid the server runs as: the operator's own, so it can read
/// the install directory and write its scratch directory, and nothing
/// else on the host that the operator could not.
#[cfg(unix)]
fn container_user() -> String {
    // SAFETY: `geteuid` and `getegid` are always-safe FFI; documented
    // as never failing.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    format!("{uid}:{gid}")
}

#[cfg(not(unix))]
fn container_user() -> String {
    "1000:1000".to_string()
}

/// A running server container.
pub struct ContainerHandle {
    pub docker: Docker,
    pub id: String,
}

impl ContainerHandle {
    /// Stop the container, giving the server two seconds, and remove it.
    pub async fn stop_and_remove(&self) {
        let _ = self
            .docker
            .stop_container(
                &self.id,
                Some(StopContainerOptions {
                    t: Some(2),
                    signal: None,
                }),
            )
            .await;
        self.remove().await;
    }

    /// Remove the container, running or not.
    pub async fn remove(&self) {
        let _ = self
            .docker
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }
}

/// Remove every container `instance` left behind. Returns how many.
pub async fn sweep(docker: &Docker, instance: &str) -> usize {
    let filters = HashMap::from([(
        "label".to_string(),
        vec![format!("{LABEL_INSTANCE}={instance}")],
    )]);
    let Ok(containers) = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        }))
        .await
    else {
        return 0;
    };
    let mut removed = 0;
    for id in containers.into_iter().filter_map(|c| c.id) {
        ContainerHandle {
            docker: docker.clone(),
            id,
        }
        .remove()
        .await;
        removed += 1;
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_config::{SandboxLimits, SandboxMount};

    fn host(data_dir: &Path) -> SandboxHost {
        SandboxHost {
            docker: None,
            instance: instance_id(data_dir),
            data_dir: data_dir.to_path_buf(),
            runtime: Some("runsc".into()),
        }
    }

    fn plan(host: &SandboxHost, block: &ContainerSandbox) -> Result<ContainerPlan, String> {
        ContainerPlan::new(
            host,
            "agent-1",
            "github",
            "node",
            &["/opt/mcp/index.js".to_string()],
            &HashMap::from([("LOG".to_string(), "info".to_string())]),
            block,
        )
    }

    fn block(dirs: &tempfile::TempDir) -> ContainerSandbox {
        let install = dirs.path().join("install");
        let data = dirs.path().join("data");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        ContainerSandbox {
            image: Some("node:22-slim".into()),
            install_dir: Some(install.to_string_lossy().into_owned()),
            mounts: vec![SandboxMount {
                source: data.to_string_lossy().into_owned(),
                target: "/data".into(),
                writable: false,
            }],
            ..Default::default()
        }
    }

    fn mount<'a>(plan: &'a ContainerPlan, target: &str) -> Option<&'a Mount> {
        plan.mounts
            .iter()
            .find(|m| m.target.as_deref() == Some(target))
    }

    #[test]
    fn a_block_that_declares_nothing_more_gets_no_network_and_default_limits() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        let plan = plan(&host, &block(&dirs)).unwrap();
        let body = plan.create_body();
        let host_config = body.host_config.as_ref().unwrap();

        assert_eq!(body.image.as_deref(), Some("node:22-slim"));
        assert_eq!(
            body.cmd,
            Some(vec!["node".to_string(), "/opt/mcp/index.js".to_string()])
        );
        assert_eq!(body.env, Some(vec!["LOG=info".to_string()]));
        assert_eq!(body.working_dir.as_deref(), Some(INSTALL_DIR_TARGET));
        assert_eq!(body.open_stdin, Some(true));
        assert_eq!(body.stdin_once, Some(true));
        assert_eq!(body.attach_stdin, Some(true));
        assert_eq!(body.tty, Some(false));

        assert_eq!(host_config.network_mode.as_deref(), Some("none"));
        assert_eq!(host_config.memory, Some(wirken_sandbox::MEMORY_LIMIT));
        assert_eq!(host_config.pids_limit, Some(wirken_sandbox::PIDS_LIMIT));
        assert_eq!(host_config.nano_cpus, Some(DEFAULT_NANO_CPUS));
        assert_eq!(host_config.runtime.as_deref(), Some("runsc"));
        assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host_config.readonly_rootfs, Some(true));
        assert_eq!(
            host_config.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(host_config.binds, Some(Vec::new()));
    }

    #[test]
    fn mounts_are_the_install_dir_and_the_declared_ones_read_only_unless_writable() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        let mut block = block(&dirs);
        block.mounts.push(SandboxMount {
            source: dirs.path().to_string_lossy().into_owned(),
            target: "/out".into(),
            writable: true,
        });
        block.scratch = true;
        let plan = plan(&host, &block).unwrap();

        assert_eq!(plan.mounts.len(), 4);
        assert_eq!(
            mount(&plan, INSTALL_DIR_TARGET).unwrap().read_only,
            Some(true)
        );
        assert_eq!(mount(&plan, "/data").unwrap().read_only, Some(true));
        assert_eq!(mount(&plan, "/out").unwrap().read_only, Some(false));
        let scratch = mount(&plan, SCRATCH_TARGET).unwrap();
        assert_eq!(scratch.read_only, Some(false));
        assert_eq!(
            plan.scratch_dir.as_deref(),
            Some(dirs.path().join("mcp-scratch/agent-1/github").as_path())
        );
        assert!(plan.mounts.iter().all(|m| m.typ == Some(MountType::BIND)));
    }

    #[test]
    fn limits_override_the_defaults() {
        let dirs = tempfile::tempdir().unwrap();
        let mut block = block(&dirs);
        block.limits = SandboxLimits {
            memory_mb: Some(256),
            pids: Some(64),
            cpus: Some(0.5),
        };
        let plan = plan(&host(dirs.path()), &block).unwrap();
        assert_eq!(plan.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(plan.pids, 64);
        assert_eq!(plan.nano_cpus, 500_000_000);
    }

    #[test]
    fn labels_name_the_instance_agent_and_server() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        let plan = plan(&host, &block(&dirs)).unwrap();
        assert_eq!(plan.labels[LABEL_ROLE], "1");
        assert_eq!(plan.labels[LABEL_INSTANCE], host.instance);
        assert_eq!(plan.labels[LABEL_AGENT], "agent-1");
        assert_eq!(plan.labels[LABEL_SERVER], "github");
    }

    #[test]
    fn blocks_that_cannot_be_started_are_refused_with_a_reason() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        type Mutation = Box<dyn Fn(&mut ContainerSandbox)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            ("no image", Box::new(|b| b.image = None)),
            ("blank image", Box::new(|b| b.image = Some(" ".into()))),
            (
                "relative install_dir",
                Box::new(|b| b.install_dir = Some("srv/mcp".into())),
            ),
            (
                "missing install_dir",
                Box::new(|b| b.install_dir = Some("/nonexistent/wirken/mcp".into())),
            ),
            (
                "mount over the install dir",
                Box::new(|b| b.mounts[0].target = "/opt/mcp/lib".into()),
            ),
            (
                "mount over /tmp",
                Box::new(|b| b.mounts[0].target = "/tmp".into()),
            ),
            (
                "relative target",
                Box::new(|b| b.mounts[0].target = "data".into()),
            ),
            (
                "target with ..",
                Box::new(|b| b.mounts[0].target = "/data/../etc".into()),
            ),
            ("target /", Box::new(|b| b.mounts[0].target = "/".into())),
            (
                "two mounts on one target",
                Box::new(|b| {
                    let again = b.mounts[0].clone();
                    b.mounts.push(again);
                }),
            ),
            ("zero memory", Box::new(|b| b.limits.memory_mb = Some(0))),
            ("zero pids", Box::new(|b| b.limits.pids = Some(0))),
            ("negative cpus", Box::new(|b| b.limits.cpus = Some(-1.0))),
            ("NaN cpus", Box::new(|b| b.limits.cpus = Some(f64::NAN))),
        ];
        for (what, mutate) in mutations {
            let mut block = block(&dirs);
            mutate(&mut block);
            assert!(plan(&host, &block).is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn a_server_name_that_is_not_one_path_component_gets_no_scratch_dir() {
        let dirs = tempfile::tempdir().unwrap();
        let mut block = block(&dirs);
        block.scratch = true;
        let result = ContainerPlan::new(
            &host(dirs.path()),
            "agent-1",
            "../escape",
            "node",
            &[],
            &HashMap::new(),
            &block,
        );
        assert!(result.is_err());
    }

    #[test]
    fn instance_ids_are_stable_and_differ_by_data_dir() {
        let a = instance_id(Path::new("/srv/wirken-a"));
        assert_eq!(a, instance_id(Path::new("/srv/wirken-a")));
        assert_ne!(a, instance_id(Path::new("/srv/wirken-b")));
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn the_runtime_follows_the_sandbox_json_mode() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sandbox_runtime(dir.path()), None);
        for (mode, runtime) in [
            ("gvisor", Some("runsc")),
            ("exec-only", None),
            ("off", None),
        ] {
            std::fs::write(
                dir.path().join("sandbox.json"),
                format!(r#"{{"mode":"{mode}"}}"#),
            )
            .unwrap();
            assert_eq!(sandbox_runtime(dir.path()).as_deref(), runtime, "{mode}");
        }
    }
}

/// Tests against a real Docker daemon. Each returns early, passing,
/// when no daemon is reachable or the image is not pulled, as the exec
/// sandbox's live tests do.
#[cfg(all(test, unix))]
mod live_tests {
    use super::*;
    use crate::mcp_transport::StdioTransport;

    const IMAGE: &str = "debian:bookworm-slim";

    async fn docker() -> Option<Docker> {
        let docker = Docker::connect_with_local_defaults().ok()?;
        docker.ping().await.ok()?;
        docker.inspect_image(IMAGE).await.ok()?;
        Some(docker)
    }

    fn host(docker: &Docker, data_dir: &Path) -> SandboxHost {
        SandboxHost {
            docker: Some(docker.clone()),
            instance: instance_id(data_dir),
            data_dir: data_dir.to_path_buf(),
            runtime: None,
        }
    }

    fn plan(host: &SandboxHost, script: &str) -> ContainerPlan {
        ContainerPlan::new(
            host,
            "agent-1",
            "echo",
            "sh",
            &["-c".to_string(), script.to_string()],
            &HashMap::new(),
            &ContainerSandbox {
                image: Some(IMAGE.into()),
                ..Default::default()
            },
        )
        .unwrap()
    }

    async fn exists(docker: &Docker, id: &str) -> bool {
        docker.inspect_container(id, None).await.is_ok()
    }

    /// JSON-RPC goes over the attached stdin and stdout, the container
    /// carries its labels and hardening, and shutdown removes it.
    #[tokio::test]
    async fn a_contained_server_answers_on_stdio_and_is_removed_at_shutdown() {
        let Some(docker) = docker().await else {
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let host = host(&docker, data.path());
        let plan = plan(
            &host,
            r#"read line; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'; read rest"#,
        );
        let mut transport = StdioTransport::spawn_container(&docker, &plan)
            .await
            .unwrap();
        let id = transport.container_id().unwrap().to_string();

        let response = transport.request("ping", None).await.unwrap();
        assert_eq!(response.result, Some(serde_json::json!({ "ok": true })));

        let inspected = docker.inspect_container(&id, None).await.unwrap();
        let labels = inspected.config.unwrap().labels.unwrap();
        assert_eq!(labels[LABEL_INSTANCE], host.instance);
        assert_eq!(labels[LABEL_SERVER], "echo");
        let host_config = inspected.host_config.unwrap();
        assert_eq!(host_config.network_mode.as_deref(), Some("none"));
        assert_eq!(host_config.readonly_rootfs, Some(true));

        transport.shutdown().await;
        assert!(!exists(&docker, &id).await, "container outlived shutdown");
    }

    /// A container a dead proxy left behind is removed by the sweep the
    /// next proxy for the same data directory runs.
    #[tokio::test]
    async fn the_sweep_removes_what_a_dead_proxy_left() {
        let Some(docker) = docker().await else {
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let host = host(&docker, data.path());
        let transport = StdioTransport::spawn_container(&docker, &plan(&host, "sleep 300"))
            .await
            .unwrap();
        let id = transport.container_id().unwrap().to_string();
        // The proxy dies without shutting the server down.
        drop(transport);
        assert!(exists(&docker, &id).await);

        assert!(sweep(&docker, &host.instance).await >= 1);
        assert!(!exists(&docker, &id).await, "the sweep left the container");
    }
}
