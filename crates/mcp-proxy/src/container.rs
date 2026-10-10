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
//!
//! A server with no `egress.hosts` has no network. One with hosts gets
//! an internal network shared only with its own egress sidecar, which
//! is its HTTP(S) proxy; see [`crate::egress`]. The sidecar and both
//! networks carry the same labels and go with the server.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bollard::Docker;
use bollard::models::{ContainerCreateBody, Mount, MountType};
use bollard::query_parameters::{
    ListContainersOptions, ListNetworksOptions, RemoveContainerOptions, StopContainerOptions,
};
use sha2::{Digest, Sha256};
use wirken_audit::SessionLog;
use wirken_sandbox::RuntimeFacts;

use crate::mcp_config::{ContainerSandbox, INSTALL_DIR_TARGET, SCRATCH_TARGET};

/// Marks a container as an MCP server container.
pub const LABEL_ROLE: &str = "wirken.mcp";
/// The data directory's instance; see [`instance_id`].
pub const LABEL_INSTANCE: &str = "wirken.mcp.instance";
/// The agent the server runs for.
pub const LABEL_AGENT: &str = "wirken.mcp.agent";
/// The server's name in `mcp.json`.
pub const LABEL_SERVER: &str = "wirken.mcp.server";

/// Where a server's secret files appear inside its container.
pub const SECRETS_TARGET: &str = "/run/wirken-secrets";

/// Paths inside the container a declared mount may not cover or sit
/// under: the install, scratch and secrets targets, and what the
/// runtime or the hardening already owns.
const RESERVED_TARGETS: &[&str] = &[
    INSTALL_DIR_TARGET,
    SCRATCH_TARGET,
    SECRETS_TARGET,
    "/tmp",
    "/proc",
    "/sys",
    "/dev",
];

/// How many stderr lines of a failed or exited server reach the log.
const STDERR_TAIL_LINES: usize = 20;

/// The most bytes of them, so one long line cannot flood the log.
const STDERR_TAIL_BYTES: usize = 4096;

/// `raw` as text fit for a log line: control characters other than
/// newline and tab shown as `?`, cut to the last [`STDERR_TAIL_BYTES`]
/// on a character boundary, and `None` when nothing is left.
fn printable_tail(raw: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut start = text.len().saturating_sub(STDERR_TAIL_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    #[allow(clippy::string_slice, reason = "start was moved to a char boundary")]
    Some(text[start..].to_string())
}

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
    /// RAM-backed directory secret files are written under; `None`
    /// where there is none, which refuses any server needing one.
    pub secrets_base: Option<PathBuf>,
    /// What the runtime is, once [`Self::probe`] has asked. `None`
    /// until then, or when it could not be asked.
    pub facts: Option<RuntimeFacts>,
    /// The statically linked binary egress sidecars run:
    /// `sandbox.json`'s `sidecar_binary`, else this executable.
    pub sidecar_binary: Option<PathBuf>,
}

impl SandboxHost {
    /// The host for the proxy serving `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            docker: Docker::connect_with_local_defaults().ok(),
            instance: instance_id(data_dir),
            data_dir: data_dir.to_path_buf(),
            runtime: sandbox_runtime(data_dir),
            secrets_base: ram_backed_dir(),
            facts: None,
            sidecar_binary: sidecar_binary(data_dir).or_else(|| std::env::current_exe().ok()),
        }
    }

    /// Ask the runtime what it is. Without an answer, a server that
    /// declares egress hosts is not refused here and fails at start if
    /// the runtime is unreachable.
    pub async fn probe(&mut self) {
        if let Some(docker) = &self.docker {
            match RuntimeFacts::probe(docker).await {
                Ok(facts) => self.facts = Some(facts),
                Err(e) => tracing::warn!("could not ask the container runtime what it is: {e}"),
            }
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
            secrets_base: None,
            facts: None,
            sidecar_binary: None,
        }
    }

    /// The directory this instance's secret files live under.
    fn secrets_root(&self) -> Option<PathBuf> {
        self.secrets_base
            .as_ref()
            .map(|base| base.join(format!("wirken-mcp-{}", self.instance)))
    }

    /// The sidecar binary, if it is there to mount.
    pub fn ready_sidecar_binary(&self) -> Result<PathBuf, String> {
        let binary = self
            .sidecar_binary
            .clone()
            .ok_or("no binary for the egress sidecar")?;
        if binary.exists() {
            Ok(binary)
        } else {
            Err(format!(
                "egress sidecar binary {} does not exist; set sidecar_binary in sandbox.json",
                binary.display()
            ))
        }
    }

    /// Prefix of this instance's egress socket directories.
    fn egress_socket_prefix(&self) -> String {
        format!("wirken-mcp-egress-{}-", self.instance)
    }

    /// The uid:gid servers and sidecars run as. Under a rootless
    /// runtime, container uid 0 is the operator and every other uid a
    /// subordinate one that could not read the install directory or the
    /// secret files.
    fn container_user(&self) -> String {
        wirken_sandbox::operator_user(self.facts.is_some_and(|f| f.rootless))
    }
}

/// A directory backed by memory, for secret files: `$XDG_RUNTIME_DIR`,
/// else `/dev/shm`, whichever is a tmpfs. Elsewhere there is none.
#[cfg(target_os = "linux")]
pub fn ram_backed_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain(std::iter::once(PathBuf::from("/dev/shm")))
        .find(|dir| is_tmpfs(dir))
}

#[cfg(not(target_os = "linux"))]
pub fn ram_backed_dir() -> Option<PathBuf> {
    None
}

/// Whether `dir` is on a tmpfs.
#[cfg(target_os = "linux")]
fn is_tmpfs(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is a valid NUL-terminated string and `stat` points
    // at writable memory the size of `struct statfs`.
    let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: statfs returned 0, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast, reason = "f_type's width differs by target")]
    let f_type = stat.f_type as i64;
    f_type == TMPFS_MAGIC
}

/// Why a block cannot be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The block itself is wrong.
    Invalid(String),
    /// The block is fine but this host cannot provide what it needs.
    Unavailable(String),
    /// The block lists egress hosts and this runtime cannot proxy them.
    EgressUnsupported(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(why) | Self::Unavailable(why) | Self::EgressUnsupported(why) => {
                f.write_str(why)
            }
        }
    }
}

impl From<String> for PlanError {
    fn from(why: String) -> Self {
        Self::Invalid(why)
    }
}

impl From<&str> for PlanError {
    fn from(why: &str) -> Self {
        Self::Invalid(why.to_string())
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
    let value = sandbox_json(data_dir)?;
    let mode = value.get("mode").and_then(|m| m.as_str()).unwrap_or("");
    wirken_sandbox::SandboxMode::from_str_config(mode).runtime_name()
}

/// `sandbox.json`'s `sidecar_binary`, the override `exec` reads too.
pub fn sidecar_binary(data_dir: &Path) -> Option<PathBuf> {
    sandbox_json(data_dir)?
        .get("sidecar_binary")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

fn sandbox_json(data_dir: &Path) -> Option<serde_json::Value> {
    let body = std::fs::read_to_string(data_dir.join("sandbox.json")).ok()?;
    serde_json::from_str(&body).ok()
}

/// One server's container, decided from its config. Building a plan is
/// where the `sandbox` block is checked: a plan exists only for a block
/// the proxy can start.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerPlan {
    pub agent_id: String,
    pub server: String,
    pub image: String,
    /// The entry's `command` then its `args`. The command runs as the
    /// container's entrypoint, so the image's own entrypoint never sees
    /// it: what runs is what the signed entry says.
    pub cmd: Vec<String>,
    /// `NAME=value` for the variables that are not secrets, and
    /// `NAME_FILE=<path>` for each secret delivered as a file. Sorted.
    pub env: Vec<String>,
    /// Secrets delivered as environment variables, by name, because
    /// the block lists them in `secrets_in_env`. Their values are added
    /// only when the container is created.
    pub env_secret_names: Vec<String>,
    /// Secrets delivered as files, by name.
    pub secret_file_names: Vec<String>,
    /// Host directory holding the secret files, bind-mounted read-only
    /// at [`SECRETS_TARGET`]. `None` when there are none.
    pub secrets_dir: Option<PathBuf>,
    pub user: String,
    pub working_dir: Option<String>,
    pub mounts: Vec<Mount>,
    /// `none`. A server with egress hosts joins its route's internal
    /// network instead; see [`Self::create_body`].
    pub network_mode: String,
    /// The block's `egress.hosts`, checked, sorted and deduplicated.
    /// Empty means no network.
    pub egress_hosts: Vec<String>,
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
    ) -> Result<Self, PlanError> {
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
                return Err(format!("two mounts target {target}").into());
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

        // `env` is the config's, so a `vault:` value is still a
        // reference here: it marks the variable as a secret.
        for name in &block.secrets_in_env {
            if !env.get(name).is_some_and(|v| v.starts_with("vault:")) {
                return Err(format!(
                    "secrets_in_env names {name}, which is not a vault: value in env"
                )
                .into());
            }
        }
        let mut plain = Vec::new();
        let mut env_secret_names = Vec::new();
        let mut secret_file_names = Vec::new();
        for (name, value) in env {
            if !value.starts_with("vault:") {
                plain.push(format!("{name}={value}"));
            } else if block.secrets_in_env.contains(name) {
                env_secret_names.push(name.clone());
            } else {
                secret_file_name(name)?;
                plain.push(format!("{name}_FILE={SECRETS_TARGET}/{name}"));
                secret_file_names.push(name.clone());
            }
        }
        plain.sort();
        env_secret_names.sort();
        secret_file_names.sort();

        let secrets_dir = if secret_file_names.is_empty() {
            None
        } else {
            let root = host.secrets_root().ok_or_else(|| {
                PlanError::Unavailable(
                    "no memory-backed directory for secret files on this host; \
                     list the secrets in secrets_in_env to deliver them as environment \
                     variables instead"
                        .to_string(),
                )
            })?;
            let dir = root
                .join(path_component(agent_id, "agent id")?)
                .join(path_component(server, "server name")?);
            mounts.push(bind(&dir, SECRETS_TARGET, false));
            Some(dir)
        };

        let mut egress_hosts = block
            .egress
            .as_ref()
            .map(|e| e.hosts.clone())
            .unwrap_or_default();
        for pattern in &egress_hosts {
            crate::egress::check_host_pattern(pattern)?;
        }
        egress_hosts.sort();
        egress_hosts.dedup();
        if !egress_hosts.is_empty()
            && let Some(why) = host.facts.and_then(|f| f.egress_unsupported())
        {
            return Err(PlanError::EgressUnsupported(format!(
                "{why}; egress.hosts needs rootful Docker on Linux. Remove egress.hosts \
                 to run the server with no network"
            )));
        }

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
            env: plain,
            env_secret_names,
            secret_file_names,
            secrets_dir,
            user: host.container_user(),
            working_dir,
            mounts,
            network_mode: "none".to_string(),
            egress_hosts,
            memory_bytes,
            pids,
            nano_cpus,
            runtime: host.runtime.clone(),
            labels,
            scratch_dir,
        })
    }

    /// Each mount as `source:target:ro` or `source:target:rw`, for the
    /// start row.
    pub fn mount_summary(&self) -> Vec<String> {
        self.mounts
            .iter()
            .map(|m| {
                format!(
                    "{}:{}:{}",
                    m.source.as_deref().unwrap_or_default(),
                    m.target.as_deref().unwrap_or_default(),
                    if m.read_only == Some(false) {
                        "rw"
                    } else {
                        "ro"
                    }
                )
            })
            .collect()
    }

    /// The body sent to Docker. Stdin stays open for the JSON-RPC
    /// stream and closes when the proxy's attach does, so a server that
    /// exits at end of input exits with the proxy.
    ///
    /// `secrets` holds the resolved `vault:` values; only those named in
    /// [`Self::env_secret_names`] go into the body. With a `route`, the
    /// container joins its internal network, gets the sidecar as its
    /// proxy, and has no working resolver: names are resolved by the
    /// broker, after the policy decision.
    pub fn create_body(
        &self,
        secrets: &HashMap<String, String>,
        route: Option<&ServerRoute>,
    ) -> ContainerCreateBody {
        let mut env = self.env.clone();
        for name in &self.env_secret_names {
            if let Some(value) = secrets.get(name) {
                env.push(format!("{name}={value}"));
            }
        }
        let (network_mode, dns) = match route {
            Some(route) => {
                env.extend(route.proxy_env());
                (route.network(), Some(vec!["127.0.0.1".to_string()]))
            }
            None => (self.network_mode.clone(), None),
        };
        let (entrypoint, args) = self.cmd.split_at(self.cmd.len().min(1));
        ContainerCreateBody {
            image: Some(self.image.clone()),
            entrypoint: Some(entrypoint.to_vec()),
            cmd: Some(args.to_vec()),
            env: Some(env),
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
                    network_mode: Some(network_mode),
                    dns,
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

/// A secret's variable name as a file name: letters, digits and `_`,
/// not starting with a digit, as environment variable names are.
fn secret_file_name(name: &str) -> Result<(), PlanError> {
    let ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(PlanError::Invalid(format!(
            "env name {name:?} cannot name a secret file"
        )))
    }
}

/// Write each named secret from `resolved` to its own 0600 file in
/// `dir`, which is created 0700. A name missing from `resolved` is
/// written empty, as an unresolved env value would have been passed.
pub fn write_secret_files(
    dir: &Path,
    names: &[String],
    resolved: &HashMap<String, String>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for name in names {
        let path = dir.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        std::io::Write::write_all(
            &mut file,
            resolved.get(name).map(String::as_bytes).unwrap_or_default(),
        )?;
    }
    Ok(())
}

/// A name used as one path component on the host.
fn path_component<'a>(name: &'a str, what: &str) -> Result<&'a str, PlanError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(format!("{what} {name:?} cannot name a host directory").into());
    }
    Ok(name)
}

/// A contained server's route out: its networks, sidecar and broker.
/// Held with the server's container and torn down after it.
#[cfg(unix)]
pub struct ServerRoute(wirken_sandbox::egress_net::EgressRoute);

/// No route can exist without a Unix socket for the broker; a plan
/// with egress hosts is refused on this host before one is asked for.
#[cfg(not(unix))]
pub enum ServerRoute {}

impl ServerRoute {
    #[cfg(unix)]
    fn network(&self) -> String {
        self.0.internal_network.clone()
    }

    #[cfg(unix)]
    fn proxy_env(&self) -> Vec<String> {
        self.0.proxy_env()
    }

    #[cfg(unix)]
    pub async fn teardown(self, docker: &Docker) {
        self.0.teardown(docker).await;
    }

    #[cfg(not(unix))]
    fn network(&self) -> String {
        match *self {}
    }

    #[cfg(not(unix))]
    fn proxy_env(&self) -> Vec<String> {
        match *self {}
    }

    #[cfg(not(unix))]
    pub async fn teardown(self, _docker: &Docker) {
        match self {}
    }
}

/// Provision `plan`'s route: networks, sidecar, and a broker deciding
/// on its egress hosts. The sidecar runs the server's image with the
/// sidecar binary mounted in, as the server's user, so its socket
/// needs no wider permissions than the operator's own.
#[cfg(unix)]
pub async fn start_route(
    docker: &Docker,
    host: &SandboxHost,
    plan: &ContainerPlan,
    audit: Option<Arc<dyn SessionLog>>,
) -> Result<ServerRoute, String> {
    let binary = host.ready_sidecar_binary()?;
    let id = crate::mcp_transport::random_suffix();
    let spec = wirken_sandbox::egress_net::SidecarSpec {
        name_prefix: "wirken-mcp-egress".into(),
        socket_dir: std::env::temp_dir().join(format!("{}{id}", host.egress_socket_prefix())),
        id,
        image: plan.image.clone(),
        binary,
        labels: plan.labels.clone(),
        user: Some(plan.user.clone()),
        socket_dir_mode: 0o700,
        socket_mode: 0o600,
    };
    let policy = crate::egress::McpEgressPolicy {
        agent_id: plan.agent_id.clone(),
        server: plan.server.clone(),
        hosts: plan.egress_hosts.clone(),
        audit,
    };
    wirken_sandbox::egress_net::provision(docker, spec, Arc::new(policy))
        .await
        .map(ServerRoute)
}

#[cfg(not(unix))]
pub async fn start_route(
    _docker: &Docker,
    _host: &SandboxHost,
    _plan: &ContainerPlan,
    _audit: Option<Arc<dyn SessionLog>>,
) -> Result<ServerRoute, String> {
    Err("the egress broker needs a Unix socket, which this host does not have".into())
}

/// A running server container.
pub struct ContainerHandle {
    pub docker: Docker,
    pub id: String,
    /// Its secret files, removed with it.
    pub secrets_dir: Option<PathBuf>,
    /// Its route out, torn down after it.
    pub route: Option<ServerRoute>,
}

impl ContainerHandle {
    /// The last lines the server wrote to stderr, for the operator log
    /// when it failed or exited. Read before the container is removed,
    /// since the runtime keeps them only until then. `None` when it
    /// wrote nothing or the runtime could not be asked.
    pub async fn stderr_tail(&self) -> Option<String> {
        use futures_util::StreamExt;
        let mut logs = self.docker.logs(
            &self.id,
            Some(bollard::query_parameters::LogsOptions {
                stdout: false,
                stderr: true,
                tail: STDERR_TAIL_LINES.to_string(),
                ..Default::default()
            }),
        );
        let mut raw = Vec::new();
        while let Some(Ok(chunk)) = logs.next().await {
            raw.extend_from_slice(&chunk.into_bytes());
        }
        printable_tail(&raw)
    }

    /// Stop the container, giving the server two seconds, and remove it.
    /// Returns the exit code the runtime recorded, when it gave one.
    pub async fn stop_and_remove(&mut self) -> Option<i64> {
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
        let exit_code = self
            .docker
            .inspect_container(
                &self.id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .ok()
            .and_then(|c| c.state)
            .and_then(|s| s.exit_code);
        self.remove().await;
        exit_code
    }

    /// Remove the container, running or not, its secret files, and its
    /// route.
    pub async fn remove(&mut self) {
        // Empty until the container exists; the secrets and the route
        // may already need removing before then.
        if !self.id.is_empty() {
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
        if let Some(dir) = &self.secrets_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
        if let Some(route) = self.route.take() {
            route.teardown(&self.docker).await;
        }
    }
}

/// Remove every container and network `host`'s instance left behind,
/// its secret files, and its egress socket directories. Returns how
/// many containers.
pub async fn sweep(docker: &Docker, host: &SandboxHost) -> usize {
    if let Some(root) = host.secrets_root() {
        let _ = std::fs::remove_dir_all(root);
    }
    if !host.instance.is_empty()
        && let Ok(entries) = std::fs::read_dir(std::env::temp_dir())
    {
        let prefix = host.egress_socket_prefix();
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    let instance = &host.instance;
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
            secrets_dir: None,
            route: None,
        }
        .remove()
        .await;
        removed += 1;
    }
    // Networks after containers: one with a container still attached
    // cannot be removed.
    let filters = HashMap::from([(
        "label".to_string(),
        vec![format!("{LABEL_INSTANCE}={instance}")],
    )]);
    if let Ok(networks) = docker
        .list_networks(Some(ListNetworksOptions {
            filters: Some(filters),
        }))
        .await
    {
        for name in networks.into_iter().filter_map(|n| n.name) {
            if let Err(e) = docker.remove_network(&name).await {
                tracing::warn!("could not remove MCP egress network {name}: {e}");
            }
        }
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
            secrets_base: Some(data_dir.join("ram")),
            facts: Some(RuntimeFacts::default()),
            sidecar_binary: None,
        }
    }

    fn plan(host: &SandboxHost, block: &ContainerSandbox) -> Result<ContainerPlan, PlanError> {
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
        let body = plan.create_body(&HashMap::new(), None);
        let host_config = body.host_config.as_ref().unwrap();

        assert_eq!(body.image.as_deref(), Some("node:22-slim"));
        assert_eq!(body.entrypoint, Some(vec!["node".to_string()]));
        assert_eq!(body.cmd, Some(vec!["/opt/mcp/index.js".to_string()]));
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

    fn vault_env() -> HashMap<String, String> {
        HashMap::from([
            ("GITHUB_TOKEN".to_string(), "vault:github-token".to_string()),
            ("LOG".to_string(), "info".to_string()),
        ])
    }

    fn resolved() -> HashMap<String, String> {
        HashMap::from([
            (
                "GITHUB_TOKEN".to_string(),
                "resolved-token-value".to_string(),
            ),
            ("LOG".to_string(), "info".to_string()),
        ])
    }

    fn plan_with_env(
        host: &SandboxHost,
        block: &ContainerSandbox,
        env: &HashMap<String, String>,
    ) -> Result<ContainerPlan, PlanError> {
        ContainerPlan::new(host, "agent-1", "github", "node", &[], env, block)
    }

    #[test]
    fn a_vault_value_is_delivered_as_a_file_by_default() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        let plan = plan_with_env(&host, &block(&dirs), &vault_env()).unwrap();

        assert_eq!(
            plan.env,
            [
                format!("GITHUB_TOKEN_FILE={SECRETS_TARGET}/GITHUB_TOKEN"),
                "LOG=info".to_string()
            ]
        );
        assert_eq!(plan.secret_file_names, ["GITHUB_TOKEN"]);
        assert!(plan.env_secret_names.is_empty());
        assert_eq!(
            plan.secrets_dir.as_deref(),
            Some(
                dirs.path()
                    .join("ram")
                    .join(format!("wirken-mcp-{}", host.instance))
                    .join("agent-1/github")
                    .as_path()
            )
        );
        assert_eq!(mount(&plan, SECRETS_TARGET).unwrap().read_only, Some(true));
        let body_env = plan.create_body(&resolved(), None).env.unwrap();
        assert!(
            body_env.iter().all(|e| !e.contains("resolved-token-value")),
            "{body_env:?}"
        );
    }

    #[test]
    fn a_secret_listed_in_secrets_in_env_goes_into_the_environment() {
        let dirs = tempfile::tempdir().unwrap();
        let mut block = block(&dirs);
        block.secrets_in_env = vec!["GITHUB_TOKEN".into()];
        let plan = plan_with_env(&host(dirs.path()), &block, &vault_env()).unwrap();

        assert_eq!(plan.env_secret_names, ["GITHUB_TOKEN"]);
        assert!(plan.secret_file_names.is_empty());
        assert!(plan.secrets_dir.is_none());
        assert!(mount(&plan, SECRETS_TARGET).is_none());
        let body_env = plan.create_body(&resolved(), None).env.unwrap();
        assert!(body_env.contains(&"GITHUB_TOKEN=resolved-token-value".to_string()));
    }

    #[test]
    fn secrets_in_env_must_name_a_vault_value() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        for name in ["LOG", "MISSING"] {
            let mut block = block(&dirs);
            block.secrets_in_env = vec![name.into()];
            assert!(
                matches!(
                    plan_with_env(&host, &block, &vault_env()),
                    Err(PlanError::Invalid(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn a_secret_whose_name_cannot_be_a_file_name_is_refused() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        for name in ["A/B", "..", "1TOKEN", ""] {
            let env = HashMap::from([(name.to_string(), "vault:x".to_string())]);
            assert!(
                matches!(
                    plan_with_env(&host, &block(&dirs), &env),
                    Err(PlanError::Invalid(_))
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn without_a_memory_backed_dir_file_secrets_are_unavailable() {
        let dirs = tempfile::tempdir().unwrap();
        let mut host = host(dirs.path());
        host.secrets_base = None;
        assert!(matches!(
            plan_with_env(&host, &block(&dirs), &vault_env()),
            Err(PlanError::Unavailable(_))
        ));
        let no_secrets = HashMap::from([("LOG".to_string(), "info".to_string())]);
        assert!(plan_with_env(&host, &block(&dirs), &no_secrets).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_0600_in_a_0700_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dirs = tempfile::tempdir().unwrap();
        let dir = dirs.path().join("secrets");
        write_secret_files(&dir, &["GITHUB_TOKEN".to_string()], &resolved()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("GITHUB_TOKEN")), 0o600);
        assert_eq!(
            std::fs::read_to_string(dir.join("GITHUB_TOKEN")).unwrap(),
            "resolved-token-value"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dev_shm_is_found_as_memory_backed_and_proc_is_not() {
        if Path::new("/dev/shm").exists() {
            assert!(is_tmpfs(Path::new("/dev/shm")));
            assert!(ram_backed_dir().is_some());
        }
        assert!(!is_tmpfs(Path::new("/proc")));
    }

    fn with_hosts(dirs: &tempfile::TempDir, hosts: &[&str]) -> ContainerSandbox {
        ContainerSandbox {
            egress: Some(crate::mcp_config::SandboxEgress {
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
            }),
            ..block(dirs)
        }
    }

    #[test]
    fn egress_hosts_are_checked_sorted_and_deduplicated() {
        let dirs = tempfile::tempdir().unwrap();
        let host = host(dirs.path());
        let plan = plan(
            &host,
            &with_hosts(&dirs, &["b.example", "*.a.example", "b.example"]),
        )
        .unwrap();
        assert_eq!(plan.egress_hosts, ["*.a.example", "b.example"]);
        // The plan alone has no network; the route supplies one.
        assert_eq!(plan.network_mode, "none");

        for bad in ["1.2.3.4", "api.example.com:443", ""] {
            assert!(
                matches!(
                    plan_with_env(&host, &with_hosts(&dirs, &[bad]), &HashMap::new()),
                    Err(PlanError::Invalid(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn egress_hosts_are_refused_where_the_runtime_cannot_proxy_them() {
        let dirs = tempfile::tempdir().unwrap();
        let listed = with_hosts(&dirs, &["api.example.com"]);
        for facts in [
            RuntimeFacts {
                rootless: true,
                ..Default::default()
            },
            RuntimeFacts {
                podman: true,
                ..Default::default()
            },
            RuntimeFacts {
                windows: true,
                ..Default::default()
            },
        ] {
            let mut host = host(dirs.path());
            host.facts = Some(facts);
            assert!(
                matches!(plan(&host, &listed), Err(PlanError::EgressUnsupported(_))),
                "{facts:?}"
            );
            // No hosts, no network: that runs on any runtime.
            assert!(plan(&host, &block(&dirs)).is_ok(), "{facts:?}");
        }
    }

    #[test]
    fn under_a_rootless_runtime_the_server_runs_as_the_operator() {
        let dirs = tempfile::tempdir().unwrap();
        let mut host = host(dirs.path());
        assert_eq!(
            plan(&host, &block(&dirs)).unwrap().user,
            wirken_sandbox::operator_user(false)
        );
        host.facts = Some(RuntimeFacts {
            rootless: true,
            ..Default::default()
        });
        assert_eq!(plan(&host, &block(&dirs)).unwrap().user, "0:0");
    }

    #[test]
    fn a_stderr_tail_is_printable_and_bounded() {
        assert_eq!(printable_tail(b""), None);
        assert_eq!(printable_tail(b"  \n "), None);
        assert_eq!(
            printable_tail(b"error: \x1b[31mno token\x1b[0m\n\tat main\n").as_deref(),
            Some("error: ?[31mno token?[0m\n\tat main")
        );
        let long = "\u{e4}".repeat(STDERR_TAIL_BYTES);
        let tail = printable_tail(long.as_bytes()).unwrap();
        assert!(tail.len() <= STDERR_TAIL_BYTES, "{}", tail.len());
        assert!(tail.chars().all(|c| c == '\u{e4}'));
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
            secrets_base: Some(data_dir.join("ram")),
            facts: None,
            sidecar_binary: None,
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
        let mut transport = StdioTransport::spawn_container(&docker, &plan, &HashMap::new(), None)
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

    /// Every host process environment this test can read, joined.
    fn readable_host_environments() -> Vec<u8> {
        let mut all = Vec::new();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_ok()
                && let Ok(env) = std::fs::read(entry.path().join("environ"))
            {
                all.extend(env);
            }
        }
        all
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    /// The server reads its secret from the mounted file. The value is
    /// in no host process environment this user can read, the
    /// container's own processes included, and not in the container's
    /// recorded config. Its file is gone after shutdown.
    #[tokio::test]
    async fn a_secret_file_reaches_the_server_and_no_environment() {
        let Some(docker) = docker().await else {
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let host = host(&docker, data.path());
        let secret = format!("wirken-test-secret-{}", instance_id(data.path()));
        let plan = ContainerPlan::new(
            &host,
            "agent-1",
            "echo",
            "sh",
            &[
                "-c".to_string(),
                r#"read line; v=$(cat "$TOKEN_FILE"); printf '{"jsonrpc":"2.0","id":1,"result":{"v":"%s"}}\n' "$v"; read rest"#
                    .to_string(),
            ],
            &HashMap::from([("TOKEN".to_string(), "vault:token".to_string())]),
            &ContainerSandbox {
                image: Some(IMAGE.into()),
                ..Default::default()
            },
        )
        .unwrap();
        let secrets = HashMap::from([("TOKEN".to_string(), secret.clone())]);
        let mut transport = StdioTransport::spawn_container(&docker, &plan, &secrets, None)
            .await
            .unwrap();
        let id = transport.container_id().unwrap().to_string();

        let response = transport.request("ping", None).await.unwrap();
        assert_eq!(response.result, Some(serde_json::json!({ "v": secret })));

        assert!(
            !contains(&readable_host_environments(), &secret),
            "the secret is in a host process environment"
        );
        let config_env = docker
            .inspect_container(&id, None)
            .await
            .unwrap()
            .config
            .unwrap()
            .env
            .unwrap_or_default();
        assert!(
            config_env.iter().all(|e| !e.contains(&secret)),
            "{config_env:?}"
        );

        transport.shutdown().await;
        assert!(
            !plan.secrets_dir.unwrap().exists(),
            "secret files outlived shutdown"
        );
    }

    /// A secret listed in `secrets_in_env` is in the container's
    /// environment, where `docker inspect` shows it: the exposure the
    /// operator opted into, which the start row names.
    #[tokio::test]
    async fn an_env_delivered_secret_is_in_the_container_config() {
        let Some(docker) = docker().await else {
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let host = host(&docker, data.path());
        let secret = format!("wirken-test-env-secret-{}", instance_id(data.path()));
        let plan = ContainerPlan::new(
            &host,
            "agent-1",
            "echo",
            "sh",
            &["-c".to_string(), "sleep 300".to_string()],
            &HashMap::from([("TOKEN".to_string(), "vault:token".to_string())]),
            &ContainerSandbox {
                image: Some(IMAGE.into()),
                secrets_in_env: vec!["TOKEN".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let secrets = HashMap::from([("TOKEN".to_string(), secret.clone())]);
        let mut transport = StdioTransport::spawn_container(&docker, &plan, &secrets, None)
            .await
            .unwrap();
        let id = transport.container_id().unwrap().to_string();
        let config_env = docker
            .inspect_container(&id, None)
            .await
            .unwrap()
            .config
            .unwrap()
            .env
            .unwrap_or_default();
        transport.shutdown().await;
        assert!(config_env.contains(&format!("TOKEN={secret}")));
    }

    /// The statically linked binary a sidecar can run in any image:
    /// `WIRKEN_SIDECAR_BINARY`, else the musl build next to this test's
    /// target directory. The exec sandbox's live tests look in the same
    /// places.
    fn sidecar_binary() -> Option<PathBuf> {
        let path = match std::env::var_os("WIRKEN_SIDECAR_BINARY") {
            Some(p) => PathBuf::from(p),
            None => std::env::current_exe()
                .ok()?
                .parent()?
                .parent()?
                .parent()?
                .join("x86_64-unknown-linux-musl/debug/wirken"),
        };
        path.exists().then_some(path)
    }

    /// A server with egress hosts reaches the sidecar and nothing else:
    /// a listed host is tunnelled, an unlisted one is refused, a direct
    /// connection has no route, and each verdict is a row naming the
    /// agent and the server. The route goes with the server.
    #[tokio::test]
    async fn a_server_with_egress_hosts_reaches_only_those_through_its_sidecar() {
        let Some(docker) = docker().await else {
            return;
        };
        let Some(binary) = sidecar_binary() else {
            eprintln!(
                "skipping: no static sidecar binary; set WIRKEN_SIDECAR_BINARY or build \
                 `cargo build -p wirken-cli --bin wirken --target x86_64-unknown-linux-musl`"
            );
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let mut host = host(&docker, data.path());
        host.sidecar_binary = Some(binary);
        host.probe().await;
        if let Some(why) = host.facts.and_then(|f| f.egress_unsupported()) {
            eprintln!("skipping: {why}");
            return;
        }
        // Whether the listed host can be reached depends on this host's
        // own connectivity; the refusals do not.
        let online = tokio::net::lookup_host("example.com:443").await.is_ok();

        let script = r#"read line
p=${HTTPS_PROXY#http://}; ph=${p%:*}; pp=${p##*:}
ask() { exec 3<>/dev/tcp/$ph/$pp; printf 'CONNECT %s:443 HTTP/1.1\r\n\r\n' "$1" >&3; read -r s <&3; exec 3>&-; s=${s%$'\r'}; echo "${s:9:3}"; }
denied=$(ask evil.example.com)
allowed=$(ask example.com)
if (exec 4<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then direct=open; else direct=closed; fi
printf '{"jsonrpc":"2.0","id":1,"result":{"denied":"%s","allowed":"%s","direct":"%s"}}\n' "$denied" "$allowed" "$direct"
read rest"#;
        let plan = ContainerPlan::new(
            &host,
            "agent-1",
            "fetch",
            "bash",
            &["-c".to_string(), script.to_string()],
            &HashMap::new(),
            &ContainerSandbox {
                image: Some(IMAGE.into()),
                egress: Some(crate::mcp_config::SandboxEgress {
                    hosts: vec!["example.com".into()],
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let log: Arc<dyn SessionLog> =
            Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap());
        let route = start_route(&docker, &host, &plan, Some(log.clone()))
            .await
            .unwrap();
        let network = route.network();
        let mut transport =
            StdioTransport::spawn_container(&docker, &plan, &HashMap::new(), Some(route))
                .await
                .unwrap();

        let response = transport.request("probe", None).await.unwrap();
        let result = response.result.unwrap();
        eprintln!("egress probe: online={online} result={result}");
        assert_eq!(result["denied"], "403", "{result}");
        assert_eq!(result["direct"], "closed", "{result}");
        if online {
            assert_eq!(result["allowed"], "200", "{result}");
        }

        let handle = log.handle_for(wirken_audit::SessionId::new(
            crate::mcp_registry::MCP_SENTINEL_SESSION,
        ));
        let rows: Vec<_> = log
            .get_since(&handle, 0)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                wirken_audit::SessionEvent::SandboxEgressVerdict {
                    host,
                    allowed,
                    agent_id,
                    mcp_server,
                    ..
                } => Some((host, allowed, agent_id, mcp_server)),
                _ => None,
            })
            .collect();
        assert!(
            rows.contains(&(
                "evil.example.com".to_string(),
                false,
                "agent-1".to_string(),
                Some("fetch".to_string())
            )),
            "{rows:?}"
        );
        if online {
            assert!(
                rows.contains(&(
                    "example.com".to_string(),
                    true,
                    "agent-1".to_string(),
                    Some("fetch".to_string())
                )),
                "{rows:?}"
            );
        }

        transport.shutdown().await;
        let left = docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([(
                    "label".to_string(),
                    vec![format!("{LABEL_INSTANCE}={}", host.instance)],
                )])),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert!(left.is_empty(), "containers outlived shutdown: {left:?}");
        assert!(
            docker
                .inspect_network(
                    &network,
                    None::<bollard::query_parameters::InspectNetworkOptions>
                )
                .await
                .is_err(),
            "the internal network outlived shutdown"
        );
    }

    /// What a server wrote to stderr can still be read after its
    /// container has exited, until the container is removed.
    #[tokio::test]
    async fn a_servers_stderr_is_read_after_it_exits() {
        let Some(docker) = docker().await else {
            return;
        };
        let data = tempfile::tempdir().unwrap();
        let host = host(&docker, data.path());
        let plan = plan(
            &host,
            "echo 'fatal: no config at /etc/srv.toml' >&2; exit 2",
        );
        let mut transport = StdioTransport::spawn_container(&docker, &plan, &HashMap::new(), None)
            .await
            .unwrap();
        let id = transport.container_id().unwrap().to_string();
        let mut wait =
            docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
        let _ = futures_util::StreamExt::next(&mut wait).await;

        let tail = transport.stderr_tail().await;
        transport.shutdown().await;
        assert_eq!(tail.as_deref(), Some("fatal: no config at /etc/srv.toml"));
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
        let transport = StdioTransport::spawn_container(
            &docker,
            &plan(&host, "sleep 300"),
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let id = transport.container_id().unwrap().to_string();
        // The proxy dies without shutting the server down.
        drop(transport);
        assert!(exists(&docker, &id).await);

        assert!(sweep(&docker, &host).await >= 1);
        assert!(!exists(&docker, &id).await, "the sweep left the container");
    }
}
