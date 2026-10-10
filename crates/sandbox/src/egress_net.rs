//! The networks and sidecar container that give one sandbox its only
//! route out.
//!
//! Two networks, because the sandbox and its proxy need different
//! reach. The internal network is `Internal`, so nothing on it has a
//! route off the host; the sandbox joins only this one. The sidecar
//! joins it too, plus the egress network, which is an ordinary bridge
//! and is the only path to the internet. The sandbox therefore cannot
//! reach anything except the sidecar, and the sidecar is the only
//! thing that can reach out, to addresses the broker hands it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest};
use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, LogsOptions, RemoveContainerOptions,
};
use futures_util::StreamExt;

use crate::egress::{EgressBroker, EgressDecider};
use crate::{MEMORY_LIMIT, PIDS_LIMIT};

/// Port the sidecar listens on inside the internal network. Fixed
/// rather than ephemeral: it is a container-private port on a network
/// of its own, so there is nothing to collide with.
pub const SIDECAR_PORT: u16 = 3128;

/// How long to wait for the sidecar to report its listener is up.
pub const SIDECAR_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the sidecar binary is mounted inside the sidecar container.
const SIDECAR_BIN_TARGET: &str = "/wirken-sidecar";

/// Where the broker socket's directory is mounted inside the sidecar.
const SOCKET_DIR_TARGET: &str = "/run/wirken-egress";

/// File name of the broker socket inside its directory.
const SOCKET_NAME: &str = "egress.sock";

/// Everything that varies between the sandboxes a route is built for.
pub struct SidecarSpec {
    /// Names the networks and the sidecar container:
    /// `<prefix>-<id>`, `<prefix>-out-<id>`, `<prefix>-sidecar-<id>`.
    pub name_prefix: String,
    pub id: String,
    /// Image the sidecar container runs. The binary is mounted into it
    /// and set as the entrypoint, so any Linux image serves.
    pub image: String,
    /// The statically linked binary that runs `egress-sidecar`.
    pub binary: PathBuf,
    /// Labels for both networks and the sidecar container.
    pub labels: HashMap<String, String>,
    /// `uid:gid` the sidecar runs as. `None` keeps the image's user.
    pub user: Option<String>,
    /// Directory created to hold the broker socket, bind-mounted into
    /// the sidecar. Removed at teardown.
    pub socket_dir: PathBuf,
    /// Permission bits for that directory and for the socket. They
    /// must let the sidecar's uid in.
    pub socket_dir_mode: u32,
    pub socket_mode: u32,
}

/// One sandbox's provisioned route out. Hold it for as long as the
/// sandbox runs, then [`EgressRoute::teardown`].
pub struct EgressRoute {
    pub internal_network: String,
    pub egress_network: String,
    pub sidecar_id: String,
    pub socket_dir: PathBuf,
    pub sidecar_ip: IpAddr,
    broker: EgressBroker,
}

impl EgressRoute {
    /// Address the sandbox is handed as its proxy: the sidecar on the
    /// internal network. No host port is involved.
    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.sidecar_ip, SIDECAR_PORT)
    }

    /// The proxy variables the sandbox is started with.
    pub fn proxy_env(&self) -> Vec<String> {
        let url = self.proxy_url();
        vec![
            format!("HTTP_PROXY={url}"),
            format!("HTTPS_PROXY={url}"),
            format!("http_proxy={url}"),
            format!("https_proxy={url}"),
            // An inherited NO_PROXY would carve holes in the
            // allowlist for whatever it names; pin it empty.
            "NO_PROXY=".to_string(),
            "no_proxy=".to_string(),
        ]
    }

    /// Whether the sidecar is still running.
    pub async fn sidecar_running(&self, docker: &Docker) -> bool {
        docker
            .inspect_container(&self.sidecar_id, None::<InspectContainerOptions>)
            .await
            .ok()
            .and_then(|c| c.state)
            .and_then(|s| s.running)
            .unwrap_or(false)
    }

    /// Stop the broker, remove the sidecar, both networks, and the
    /// socket directory. Best-effort: the sandbox is already gone, so
    /// a failure here leaks a Docker object rather than leaving reach
    /// open.
    pub async fn teardown(self, docker: &Docker) {
        kill_and_remove(docker, &self.sidecar_id).await;
        drop(self.broker);
        for net in [&self.internal_network, &self.egress_network] {
            if let Err(e) = docker.remove_network(net).await {
                tracing::warn!("could not remove egress network {net}: {e}");
            }
        }
        if let Err(e) = std::fs::remove_dir_all(&self.socket_dir) {
            tracing::warn!(
                "could not remove egress socket dir {}: {e}",
                self.socket_dir.display()
            );
        }
    }
}

/// Create the two networks, bind the broker, and start the sidecar.
///
/// Every failure is an error and removes what was already created:
/// the caller must refuse to start the sandbox, never start it with
/// wider networking or none.
pub async fn provision(
    docker: &Docker,
    spec: SidecarSpec,
    decider: Arc<dyn EgressDecider>,
) -> Result<EgressRoute, String> {
    let internal_network = format!("{}-{}", spec.name_prefix, spec.id);
    let egress_network = format!("{}-out-{}", spec.name_prefix, spec.id);
    let labels = (!spec.labels.is_empty()).then(|| spec.labels.clone());

    // Inter-container communication stays enabled on the internal
    // network: the sandbox reaching its sidecar is the whole point,
    // and that traffic is container-to-container. The isolation comes
    // from the network being `Internal` and per-sandbox, so the only
    // peer on it is this sandbox's own sidecar.
    docker
        .create_network(NetworkCreateRequest {
            name: internal_network.clone(),
            driver: Some("bridge".to_string()),
            internal: Some(true),
            attachable: Some(false),
            enable_ipv6: Some(false),
            labels: labels.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("create internal network: {e}"))?;

    if let Err(e) = docker
        .create_network(NetworkCreateRequest {
            name: egress_network.clone(),
            driver: Some("bridge".to_string()),
            enable_ipv6: Some(false),
            labels: labels.clone(),
            ..Default::default()
        })
        .await
    {
        let _ = docker.remove_network(&internal_network).await;
        return Err(format!("create egress network: {e}"));
    }

    let cleanup = |sidecar: Option<String>| {
        let internal_network = internal_network.clone();
        let egress_network = egress_network.clone();
        let socket_dir = spec.socket_dir.clone();
        async move {
            if let Some(id) = sidecar {
                kill_and_remove(docker, &id).await;
            }
            let _ = docker.remove_network(&internal_network).await;
            let _ = docker.remove_network(&egress_network).await;
            let _ = std::fs::remove_dir_all(&socket_dir);
        }
    };

    // The broker socket lives in a directory bind-mounted into the
    // sidecar, so the sidecar reaches the host over the filesystem
    // rather than the network and no host port exists.
    if let Err(e) = create_socket_dir(&spec.socket_dir, spec.socket_dir_mode) {
        cleanup(None).await;
        return Err(format!(
            "create egress socket dir {}: {e}",
            spec.socket_dir.display()
        ));
    }
    let socket_path = spec.socket_dir.join(SOCKET_NAME);
    let mut broker = match EgressBroker::bind(socket_path.clone(), decider, spec.socket_mode).await
    {
        Ok(b) => b,
        Err(e) => {
            cleanup(None).await;
            return Err(format!(
                "bind egress decision broker at {}: {e}",
                socket_path.display()
            ));
        }
    };

    let sidecar_name = format!("{}-sidecar-{}", spec.name_prefix, spec.id);
    let created = match docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(sidecar_name.clone()),
                platform: String::new(),
            }),
            sidecar_body(&spec, &internal_network, labels),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            cleanup(None).await;
            return Err(format!("create egress sidecar: {e}"));
        }
    };

    // Second network for the sidecar's own outbound reach. The
    // sandbox never joins it.
    if let Err(e) = docker
        .connect_network(
            &egress_network,
            bollard::models::NetworkConnectRequest {
                container: created.id.clone(),
                ..Default::default()
            },
        )
        .await
    {
        cleanup(Some(created.id)).await;
        return Err(format!("attach sidecar to egress network: {e}"));
    }

    if let Err(e) = docker.start_container(&created.id, None).await {
        cleanup(Some(created.id)).await;
        return Err(format!("start egress sidecar: {e}"));
    }

    if let Err(e) = broker.await_sidecar(SIDECAR_READY_TIMEOUT).await {
        let logs = container_logs(docker, &created.id).await;
        cleanup(Some(created.id)).await;
        return Err(format!(
            "egress sidecar never became ready: {e}. Sidecar output: {logs}"
        ));
    }

    let sidecar_ip = match container_ip(docker, &created.id, &internal_network).await {
        Some(ip) => ip,
        None => {
            cleanup(Some(created.id)).await;
            return Err(format!(
                "egress sidecar reported no address on {internal_network}"
            ));
        }
    };

    tracing::info!(
        "egress sidecar {sidecar_name} ready at {sidecar_ip}:{SIDECAR_PORT} on {internal_network}"
    );

    Ok(EgressRoute {
        internal_network,
        egress_network,
        sidecar_id: created.id,
        socket_dir: spec.socket_dir,
        sidecar_ip,
        broker,
    })
}

/// The sidecar's create body: the binary and the socket directory
/// mounted in, the internal network only until the egress network is
/// connected, and the same floor as any sandbox container.
fn sidecar_body(
    spec: &SidecarSpec,
    internal_network: &str,
    labels: Option<HashMap<String, String>>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        image: Some(spec.image.clone()),
        entrypoint: Some(vec![SIDECAR_BIN_TARGET.into()]),
        cmd: Some(vec![
            "egress-sidecar".into(),
            "--socket".into(),
            format!("{SOCKET_DIR_TARGET}/{SOCKET_NAME}"),
            "--listen".into(),
            format!("0.0.0.0:{SIDECAR_PORT}"),
        ]),
        user: spec.user.clone(),
        labels,
        host_config: Some(HostConfig {
            binds: Some(vec![
                format!("{}:{SIDECAR_BIN_TARGET}:ro", spec.binary.display()),
                format!("{}:{SOCKET_DIR_TARGET}:rw", spec.socket_dir.display()),
            ]),
            network_mode: Some(internal_network.to_string()),
            memory: Some(MEMORY_LIMIT),
            pids_limit: Some(PIDS_LIMIT),
            auto_remove: Some(false),
            cap_drop: Some(vec!["ALL".into()]),
            cap_add: Some(Vec::new()),
            security_opt: Some(vec!["no-new-privileges:true".into()]),
            readonly_rootfs: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn create_socket_dir(dir: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
}

async fn kill_and_remove(docker: &Docker, id: &str) {
    let _ = docker.kill_container(id, None).await;
    let _ = docker
        .remove_container(
            id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

/// The container's address on `network`, which is what the sandbox
/// is pointed at.
async fn container_ip(docker: &Docker, id: &str, network: &str) -> Option<IpAddr> {
    docker
        .inspect_container(id, None::<InspectContainerOptions>)
        .await
        .ok()
        .and_then(|c| c.network_settings)
        .and_then(|n| n.networks)
        .and_then(|nets| nets.get(network).and_then(|e| e.ip_address.clone()))
        .and_then(|ip| ip.parse().ok())
}

/// Best-effort log capture, used to explain a sidecar that never
/// reported ready.
async fn container_logs(docker: &Docker, id: &str) -> String {
    let mut out = String::new();
    let mut stream = docker.logs(
        id,
        Some(LogsOptions {
            stdout: true,
            stderr: true,
            ..Default::default()
        }),
    );
    while let Some(Ok(chunk)) = stream.next().await {
        out.push_str(&chunk.to_string());
        if out.len() > 2_000 {
            break;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SidecarSpec {
        SidecarSpec {
            name_prefix: "wirken-mcp-egress".into(),
            id: "abc".into(),
            image: "img:1".into(),
            binary: "/bin/wirken".into(),
            labels: HashMap::from([("k".to_string(), "v".to_string())]),
            user: Some("1000:1000".into()),
            socket_dir: "/run/x".into(),
            socket_dir_mode: 0o700,
            socket_mode: 0o600,
        }
    }

    #[test]
    fn the_sidecar_runs_the_mounted_binary_with_the_sandbox_floor() {
        let body = sidecar_body(&spec(), "wirken-mcp-egress-abc", Some(spec().labels));
        assert_eq!(body.entrypoint, Some(vec![SIDECAR_BIN_TARGET.to_string()]));
        assert_eq!(body.cmd.as_ref().unwrap()[0], "egress-sidecar");
        assert_eq!(body.user.as_deref(), Some("1000:1000"));
        assert_eq!(body.labels, Some(spec().labels));
        let host = body.host_config.unwrap();
        assert_eq!(
            host.binds.unwrap(),
            [
                "/bin/wirken:/wirken-sidecar:ro".to_string(),
                "/run/x:/run/wirken-egress:rw".to_string()
            ]
        );
        assert_eq!(host.network_mode.as_deref(), Some("wirken-mcp-egress-abc"));
        assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host.readonly_rootfs, Some(true));
        assert_eq!(host.memory, Some(MEMORY_LIMIT));
        assert_eq!(host.pids_limit, Some(PIDS_LIMIT));
    }
}
