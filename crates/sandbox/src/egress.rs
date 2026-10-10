//! The egress proxy shared by sandboxed `exec` and contained MCP
//! servers: a sidecar forwarder that holds no policy, and a host-side
//! decision broker it asks over a Unix socket.
//!
//! The sandbox reaches nothing but the sidecar. The sidecar reaches
//! nothing it was not handed by the broker. The broker asks an
//! [`EgressDecider`] whether a target may be reached, resolves the
//! name itself, drops every answer outside global unicast, and records
//! each verdict through the decider. What a decider allows, and how it
//! records, belongs to the caller: exec decides per channel and
//! conditions on what the session has read, an MCP server decides on
//! the hosts its signed entry declares.
//!
//! # Properties
//!
//! * **HTTP(S) or nothing.** CONNECT on 443 and plain HTTP on 80 are
//!   the only shapes proxied. There is no generic TCP forward.
//! * **Domain match only.** IP-literal targets are refused by
//!   [`check_shape`], before any allowlist is consulted.
//! * **The broker resolves.** The sandbox has no working resolver,
//!   and resolved addresses outside the global unicast range are
//!   dropped.
//!
//! # Known limit
//!
//! CONNECT allowlisting is decided on the CONNECT target, and the
//! tunnel is not inspected after that. A client that CONNECTs to an
//! allowed host and then presents a different SNI reaches whatever
//! the allowed host's address serves for that name. Closing this
//! would require terminating TLS in the proxy, which this design
//! deliberately does not do.

#[cfg(unix)]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::TcpStream;

use wirken_audit::SandboxEgressDenyReason;

#[cfg(unix)]
/// Cap on the request head the proxy will buffer before deciding.
const MAX_HEAD: usize = 8 * 1024;

#[cfg(unix)]
/// How long a connection may take to deliver a complete request head.
const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The only port CONNECT may target.
pub const CONNECT_PORT: u16 = 443;

/// The only port plain HTTP may target.
pub const PLAIN_PORT: u16 = 80;

/// Which request shape a target came from. Decides the legal port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// `CONNECT host:443`.
    Connect,
    /// Plain HTTP with an absolute-form request target.
    Plain,
}

impl RequestKind {
    /// The one port this request shape may target.
    pub fn allowed_port(self) -> u16 {
        match self {
            Self::Connect => CONNECT_PORT,
            Self::Plain => PLAIN_PORT,
        }
    }
}

/// The structural rules every proxied request is held to, whatever
/// policy then applies: a name, not an address, on the one port its
/// shape may use.
pub fn check_shape(
    host: &str,
    port: u16,
    kind: RequestKind,
) -> Result<(), SandboxEgressDenyReason> {
    if host.is_empty() {
        return Err(SandboxEgressDenyReason::Malformed);
    }
    if is_ip_literal(host) {
        return Err(SandboxEgressDenyReason::IpLiteral);
    }
    if port != kind.allowed_port() {
        return Err(SandboxEgressDenyReason::PortNotAllowed);
    }
    Ok(())
}

/// Whether `host` matches one allowlist `pattern`: the exact name, or
/// `*.suffix` for exactly one label in front of `suffix`. The bare `*`
/// wildcard is not a pattern here; callers that accept it decide what
/// it means before matching.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.")
        && let Some(dotidx) = host.find('.')
    {
        #[allow(
            clippy::string_slice,
            reason = "idx + 1 is just past an ASCII '.' found by find"
        )]
        return &host[dotidx + 1..] == suffix;
    }
    false
}

/// Whether `host` is an IP address rather than a name. Accepts the
/// bracketed IPv6 authority form so `[::1]` is caught too.
pub fn is_ip_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok()
}

/// Whether an address is global unicast and therefore a legitimate
/// egress destination. Excludes loopback, unspecified, multicast,
/// broadcast, private, link-local (which covers the 169.254.169.254
/// metadata address), documentation, and IPv6 unique-local ranges.
///
/// Applied after resolution, so an allowlisted name whose DNS answer
/// points inside the host's own network is dropped rather than
/// connected to.
pub fn is_global_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10 carrier-grade NAT.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                // 0.0.0.0/8 "this network".
                || v4.octets()[0] == 0
                // 240.0.0.0/4 reserved.
                || v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                // IPv4-mapped addresses re-enter the v4 rules.
                || v6.to_ipv4_mapped().is_some_and(|v4| !is_global_unicast(IpAddr::V4(v4))))
        }
    }
}

/// `fc00::/7`.
fn is_unique_local_v6(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// `fe80::/10`.
fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Wire format between the sidecar and the host broker. One JSON
/// object per line, request then reply, one exchange per connection.
///
/// The sidecar never decides anything. It reports the target it was
/// asked for and receives either a set of already-resolved addresses
/// or a refusal. Policy, DNS, the global-unicast filter, and the
/// audit row all stay in the host process, so a compromised sidecar
/// can lie about what it wants but cannot widen what it gets, and
/// cannot forge the attribution on a denial row.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DecisionRequest {
    pub host: String,
    pub port: u16,
    pub connect: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DecisionReply {
    pub allow: bool,
    /// Resolved, global-unicast `ip:port` candidates. Only set when
    /// `allow`. The sidecar dials these verbatim and never resolves.
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<SandboxEgressDenyReason>,
}

/// Greeting the sidecar sends once its listener is accepting. The
/// host waits for it before starting the sandbox, so a sandbox is
/// never startable against a proxy that is not yet serving.
pub const SIDECAR_HELLO: &str = "hello";

/// One request's outcome, as the broker records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    /// Set when `allowed` is false.
    pub reason: Option<SandboxEgressDenyReason>,
    /// True when something beyond the static policy changed the
    /// verdict, such as an operator being asked.
    pub escalated: bool,
    /// What the verdict was conditioned on, sorted for stable rows.
    pub basis: Vec<String>,
}

impl Verdict {
    /// Allowed on the static policy alone.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
            escalated: false,
            basis: Vec::new(),
        }
    }

    /// Refused on the static policy alone.
    pub fn deny(reason: SandboxEgressDenyReason) -> Self {
        Self {
            allowed: false,
            reason: Some(reason),
            escalated: false,
            basis: Vec::new(),
        }
    }
}

/// The policy and the audit sink behind one broker.
#[async_trait::async_trait]
pub trait EgressDecider: Send + Sync + 'static {
    /// Whether `host:port` may be reached. Called for every request
    /// the sidecar forwards; an allow is followed by resolution in
    /// the broker, which can still refuse.
    async fn decide(&self, host: &str, port: u16, kind: RequestKind) -> Verdict;

    /// Record a final verdict, allow or deny.
    fn record(&self, host: &str, port: u16, verdict: &Verdict);
}

#[cfg(unix)]
/// The host-side decision broker for one sandbox.
///
/// Listens on a Unix socket rather than a TCP port. A socket is a
/// filesystem object, so nothing here is reachable over the network
/// and a default-deny host firewall has no bearing on it. The socket
/// is created per sandbox and bind-mounted into that sandbox's
/// sidecar, which is what makes attribution structural: every request
/// arriving on this socket belongs to the sandbox it was created for.
pub struct EgressBroker {
    socket_path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    ready: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(unix)]
impl EgressBroker {
    /// Bind the broker socket and start serving decisions.
    ///
    /// `socket_mode` is the socket's permission bits. It has to let
    /// the uid the sidecar runs as connect, and nothing wider than
    /// that needs to.
    pub async fn bind(
        socket_path: std::path::PathBuf,
        decider: Arc<dyn EgressDecider>,
        socket_mode: u32,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(socket_mode))?;
        let (ready_tx, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut ready_tx = Some(ready_tx);
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                // The greeting arrives on its own connection and is
                // the readiness signal.
                let decider = decider.clone();
                let tx = ready_tx.take();
                tokio::spawn(async move {
                    if let Err(e) = serve_decision(stream, decider, tx).await {
                        tracing::debug!("sandbox egress decision ended: {e}");
                    }
                });
            }
        });
        Ok(Self {
            socket_path,
            task,
            ready,
        })
    }

    /// Wait for the sidecar to report its listener is accepting.
    /// Timing out is a hard failure: the caller refuses to start the
    /// sandbox rather than start one whose only route may be dead.
    pub async fn await_sidecar(&mut self, timeout: std::time::Duration) -> Result<(), String> {
        match tokio::time::timeout(timeout, &mut self.ready).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err("broker stopped before the sidecar reported ready".into()),
            Err(_) => Err(format!(
                "sidecar did not report ready within {}s",
                timeout.as_secs()
            )),
        }
    }

    /// Where the broker socket is bound.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

#[cfg(unix)]
impl Drop for EgressBroker {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
/// Serve one decision exchange, or consume the readiness greeting.
async fn serve_decision(
    stream: tokio::net::UnixStream,
    decider: Arc<dyn EgressDecider>,
    ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(());
    };

    if line.trim() == SIDECAR_HELLO {
        if let Some(tx) = ready_tx {
            let _ = tx.send(());
        }
        return Ok(());
    }
    // A greeting we were not waiting for still must not be mistaken
    // for a decision request.
    let req: DecisionRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_) => {
            let reply = DecisionReply {
                allow: false,
                addrs: Vec::new(),
                reason: Some(SandboxEgressDenyReason::Malformed),
            };
            let _ = write_reply(&mut wr, &reply).await;
            return Ok(());
        }
    };

    let kind = if req.connect {
        RequestKind::Connect
    } else {
        RequestKind::Plain
    };

    let verdict = decider.decide(&req.host, req.port, kind).await;
    if !verdict.allowed {
        decider.record(&req.host, req.port, &verdict);
        let reply = DecisionReply {
            allow: false,
            addrs: Vec::new(),
            reason: verdict.reason,
        };
        return write_reply(&mut wr, &reply).await;
    }

    // Resolution happens here, never in the sandbox or the sidecar,
    // and answers outside global unicast are dropped so an allowed
    // name cannot be rebound onto loopback, private space, or the
    // link-local metadata address.
    let addrs = match tokio::net::lookup_host((req.host.as_str(), req.port)).await {
        Ok(iter) => iter
            .filter(|a| {
                if is_global_unicast(a.ip()) {
                    true
                } else {
                    tracing::warn!(
                        "sandbox egress: dropping non-global address {} for allowed host {}",
                        a.ip(),
                        req.host
                    );
                    false
                }
            })
            .map(|a| a.to_string())
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    if addrs.is_empty() {
        let refused = Verdict {
            allowed: false,
            reason: Some(SandboxEgressDenyReason::ResolutionFailed),
            ..verdict
        };
        decider.record(&req.host, req.port, &refused);
        let reply = DecisionReply {
            allow: false,
            addrs: Vec::new(),
            reason: refused.reason,
        };
        return write_reply(&mut wr, &reply).await;
    }

    // The allow row is recorded too: it lets the chain assert that
    // this connection was permitted, not only that other ones were
    // refused.
    decider.record(&req.host, req.port, &verdict);
    write_reply(
        &mut wr,
        &DecisionReply {
            allow: true,
            addrs,
            reason: None,
        },
    )
    .await
}

#[cfg(unix)]
async fn write_reply<W: tokio::io::AsyncWrite + Unpin>(
    wr: &mut W,
    reply: &DecisionReply,
) -> std::io::Result<()> {
    let mut body = serde_json::to_vec(reply).unwrap_or_default();
    body.push(b'\n');
    wr.write_all(&body).await
}

#[cfg(unix)]
/// Run the sidecar forwarder. Executed inside the sidecar container
/// by the hidden `egress-sidecar` subcommand.
///
/// This process holds no policy. For each connection it parses the
/// request head, asks the host broker over the bind-mounted socket,
/// and either refuses or dials the addresses the host returned.
pub async fn run_sidecar(
    socket_path: std::path::PathBuf,
    listen: SocketAddr,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    // Announce readiness only once the listener is accepting, so the
    // host never starts a sandbox against a proxy that is not up.
    {
        let mut s = tokio::net::UnixStream::connect(&socket_path).await?;
        s.write_all(format!("{SIDECAR_HELLO}\n").as_bytes()).await?;
        s.flush().await?;
    }
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let socket_path = socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = sidecar_connection(stream, socket_path).await {
                tracing::debug!("sidecar connection ended: {e}");
            }
        });
    }
}

#[cfg(unix)]
/// Ask the host broker for a decision on one target.
async fn ask_broker(
    socket_path: &std::path::Path,
    req: &DecisionRequest,
) -> std::io::Result<DecisionReply> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stream = tokio::net::UnixStream::connect(socket_path).await?;
    let (rd, mut wr) = stream.into_split();
    let mut body = serde_json::to_vec(req).unwrap_or_default();
    body.push(b'\n');
    wr.write_all(&body).await?;
    wr.flush().await?;
    let mut lines = BufReader::new(rd).lines();
    let line = lines.next_line().await?.unwrap_or_default();
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(unix)]
/// Serve one client connection inside the sidecar.
async fn sidecar_connection(
    mut stream: TcpStream,
    socket_path: std::path::PathBuf,
) -> std::io::Result<()> {
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(reason)) => {
            let _ = write_refusal(&mut stream, reason).await;
            return Ok(());
        }
        Err(_) => return Ok(()),
    };

    let request = match parse_request(&head.bytes[..head.head_len]) {
        Ok(r) => r,
        Err(reason) => {
            let _ = write_refusal(&mut stream, reason).await;
            return Ok(());
        }
    };

    let reply = match ask_broker(
        &socket_path,
        &DecisionRequest {
            host: request.host.clone(),
            port: request.port,
            connect: matches!(request.kind, RequestKind::Connect),
        },
    )
    .await
    {
        Ok(r) => r,
        // The broker is the only authority. If it cannot be reached,
        // nothing is authorized.
        Err(e) => {
            tracing::warn!("sidecar could not reach the decision broker: {e}");
            let _ = write_refusal(&mut stream, SandboxEgressDenyReason::Malformed).await;
            return Ok(());
        }
    };

    if !reply.allow {
        let reason = reply.reason.unwrap_or(SandboxEgressDenyReason::NotAllowed);
        let _ = write_refusal(&mut stream, reason).await;
        return Ok(());
    }

    let mut upstream = None;
    for addr in &reply.addrs {
        if let Ok(s) = TcpStream::connect(addr).await {
            upstream = Some(s);
            break;
        }
    }
    let Some(upstream) = upstream else {
        let _ = write_refusal(&mut stream, SandboxEgressDenyReason::ResolutionFailed).await;
        return Ok(());
    };

    match request.kind {
        RequestKind::Connect => tunnel(stream, upstream, &head.bytes[head.head_len..]).await,
        RequestKind::Plain => {
            forward_plain(stream, upstream, &request, &head.bytes[head.head_len..]).await
        }
    }
}

#[cfg(unix)]
/// A buffered request head plus whatever followed it in the same
/// read. The trailing bytes are the request body (or, for CONNECT,
/// the start of the TLS handshake) and must be forwarded intact.
struct Head {
    bytes: Vec<u8>,
    head_len: usize,
}

#[cfg(unix)]
async fn read_head(stream: &mut TcpStream) -> Result<Head, SandboxEgressDenyReason> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| SandboxEgressDenyReason::Malformed)?;
        if n == 0 {
            return Err(SandboxEgressDenyReason::Malformed);
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&bytes) {
            return Ok(Head {
                bytes,
                head_len: end,
            });
        }
        if bytes.len() > MAX_HEAD {
            return Err(SandboxEgressDenyReason::Malformed);
        }
    }
}

#[cfg(unix)]
/// Index just past the terminating CRLFCRLF, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[cfg(unix)]
/// A parsed proxy request, reduced to what policy needs.
struct ProxyRequest {
    kind: RequestKind,
    host: String,
    port: u16,
    /// Origin-form request line to send upstream. Empty for CONNECT.
    rewritten_head: Vec<u8>,
}

#[cfg(unix)]
/// Parse the request head. Only two shapes are accepted: CONNECT
/// with an authority-form target, and a plain-HTTP verb with an
/// absolute-form target. Origin-form targets are refused because a
/// proxy cannot derive the destination from them without trusting
/// the `Host` header, which is request content.
fn parse_request(head: &[u8]) -> Result<ProxyRequest, SandboxEgressDenyReason> {
    let text = std::str::from_utf8(head).map_err(|_| SandboxEgressDenyReason::Malformed)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(SandboxEgressDenyReason::Malformed)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(SandboxEgressDenyReason::Malformed)?;
    let target = parts.next().ok_or(SandboxEgressDenyReason::Malformed)?;
    let version = parts.next().ok_or(SandboxEgressDenyReason::Malformed)?;
    if parts.next().is_some() {
        return Err(SandboxEgressDenyReason::Malformed);
    }
    if !version.starts_with("HTTP/1.") {
        return Err(SandboxEgressDenyReason::Malformed);
    }

    if method == "CONNECT" {
        let (host, port) = split_authority(target)?;
        return Ok(ProxyRequest {
            kind: RequestKind::Connect,
            host,
            port,
            rewritten_head: Vec::new(),
        });
    }

    if !matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err(SandboxEgressDenyReason::MethodNotAllowed);
    }

    let url = url::Url::parse(target).map_err(|_| SandboxEgressDenyReason::MethodNotAllowed)?;
    if url.scheme() != "http" {
        // An `https://` absolute-form target on the plain path would
        // mean the proxy speaks TLS for the client. It does not;
        // TLS is the client's job inside a CONNECT tunnel.
        return Err(SandboxEgressDenyReason::MethodNotAllowed);
    }
    let host = url
        .host_str()
        .ok_or(SandboxEgressDenyReason::Malformed)?
        .to_string();
    let port = url.port().unwrap_or(PLAIN_PORT);

    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }

    // Rebuild the head in origin form. Hop-by-hop proxy headers are
    // dropped, and the connection is forced closed so a second
    // request cannot ride the same upstream socket under a head this
    // proxy never inspected.
    let mut rewritten = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive"
        ) {
            continue;
        }
        rewritten.extend_from_slice(line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    Ok(ProxyRequest {
        kind: RequestKind::Plain,
        host,
        port,
        rewritten_head: rewritten,
    })
}

#[cfg(unix)]
/// Split an authority-form CONNECT target into host and port. The
/// port is required: a bare host would have to default to something,
/// and defaulting is how a port rule gets quietly widened.
fn split_authority(target: &str) -> Result<(String, u16), SandboxEgressDenyReason> {
    if let Some(rest) = target.strip_prefix('[') {
        // Bracketed IPv6 literal. Kept parseable so it reaches the
        // IP-literal refusal with the right reason rather than
        // landing on `Malformed`.
        let (addr, tail) = rest
            .split_once(']')
            .ok_or(SandboxEgressDenyReason::Malformed)?;
        let port = tail
            .strip_prefix(':')
            .ok_or(SandboxEgressDenyReason::Malformed)?
            .parse::<u16>()
            .map_err(|_| SandboxEgressDenyReason::Malformed)?;
        return Ok((format!("[{addr}]"), port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or(SandboxEgressDenyReason::Malformed)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| SandboxEgressDenyReason::Malformed)?;
    Ok((host.to_string(), port))
}

#[cfg(unix)]
/// Refusal sent back to the sandboxed client. Deliberately terse:
/// the operator-facing detail is on the audit row, not in a body a
/// sandboxed process could scrape for allowlist contents.
async fn write_refusal(
    stream: &mut TcpStream,
    reason: SandboxEgressDenyReason,
) -> std::io::Result<()> {
    let status = match reason {
        SandboxEgressDenyReason::Malformed | SandboxEgressDenyReason::MethodNotAllowed => {
            "400 Bad Request"
        }
        SandboxEgressDenyReason::ResolutionFailed => "502 Bad Gateway",
        _ => "403 Forbidden",
    };
    let body = "sandbox egress denied\n";
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(unix)]
/// CONNECT: acknowledge, then move bytes both ways without looking
/// at them.
async fn tunnel(
    mut client: TcpStream,
    mut upstream: TcpStream,
    buffered: &[u8],
) -> std::io::Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

#[cfg(unix)]
/// Plain HTTP: send the origin-form head, then pump. Any bytes that
/// arrived with the head are the request body and go out intact.
async fn forward_plain(
    mut client: TcpStream,
    mut upstream: TcpStream,
    request: &ProxyRequest,
    buffered: &[u8],
) -> std::io::Result<()> {
    upstream.write_all(&request.rewritten_head).await?;
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_refuses_addresses_and_wrong_ports_before_any_policy() {
        assert_eq!(
            check_shape("api.example.com", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_shape("api.example.com", 80, RequestKind::Plain),
            Ok(())
        );
        assert_eq!(
            check_shape("", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::Malformed)
        );
        for host in ["93.184.216.34", "169.254.169.254", "[::1]"] {
            assert_eq!(
                check_shape(host, 443, RequestKind::Connect),
                Err(SandboxEgressDenyReason::IpLiteral),
                "{host}"
            );
        }
        for port in [22u16, 80, 8080] {
            assert_eq!(
                check_shape("api.example.com", port, RequestKind::Connect),
                Err(SandboxEgressDenyReason::PortNotAllowed),
                "{port}"
            );
        }
        assert_eq!(
            check_shape("api.example.com", 8080, RequestKind::Plain),
            Err(SandboxEgressDenyReason::PortNotAllowed)
        );
    }

    #[test]
    fn patterns_match_the_name_or_one_label_under_a_suffix() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(!host_matches("example.com", "*.example.com"));
        assert!(!host_matches("a.b.example.com", "*.example.com"));
        assert!(!host_matches("evil.example.com", "api.example.com"));
        assert!(!host_matches("api.example.com", "*"));
    }

    #[test]
    fn metadata_and_private_addresses_are_not_global() {
        for addr in [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "0.0.0.0",
        ] {
            assert!(
                !is_global_unicast(addr.parse().unwrap()),
                "{addr} must not be a permitted egress destination"
            );
        }
        for addr in ["::1", "fd00::1", "fe80::1"] {
            assert!(
                !is_global_unicast(addr.parse().unwrap()),
                "{addr} must not be a permitted egress destination"
            );
        }
        assert!(is_global_unicast("93.184.216.34".parse().unwrap()));
        assert!(is_global_unicast("2606:2800:220:1::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_metadata_address_is_not_global() {
        assert!(!is_global_unicast(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn connect_parses_authority_form() {
        let head = b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let req = parse_request(head).unwrap();
        assert_eq!(req.kind, RequestKind::Connect);
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 443);
    }

    #[cfg(unix)]
    #[test]
    fn connect_without_explicit_port_is_malformed() {
        let head = b"CONNECT api.example.com HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::Malformed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn plain_origin_form_is_refused() {
        // Origin form would force the proxy to trust the Host
        // header, which is request content.
        let head = b"GET /path HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::MethodNotAllowed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn plain_absolute_form_parses_and_rewrites_to_origin_form() {
        let head = b"GET http://api.example.com/v1/x?q=1 HTTP/1.1\r\nHost: api.example.com\r\n\
                     Proxy-Connection: keep-alive\r\n\r\n";
        let req = parse_request(head).unwrap();
        assert_eq!(req.kind, RequestKind::Plain);
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 80);
        let rewritten = String::from_utf8(req.rewritten_head.clone()).unwrap();
        assert!(rewritten.starts_with("GET /v1/x?q=1 HTTP/1.1\r\n"));
        assert!(!rewritten.to_ascii_lowercase().contains("proxy-connection"));
        assert!(rewritten.ends_with("Connection: close\r\n\r\n"));
    }

    #[cfg(unix)]
    #[test]
    fn https_absolute_form_on_plain_path_is_refused() {
        let head = b"GET https://api.example.com/ HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::MethodNotAllowed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_http_verb_is_refused() {
        let head = b"SSH api.example.com:22 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::MethodNotAllowed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn head_end_found_across_segment_boundary() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    /// A decider that answers from a fixed verdict and keeps what it
    /// was asked to record.
    #[cfg(unix)]
    struct Fixed {
        verdict: Verdict,
        recorded: std::sync::Mutex<Vec<(String, u16, Verdict)>>,
    }

    #[cfg(unix)]
    #[async_trait::async_trait]
    impl EgressDecider for Fixed {
        async fn decide(&self, _host: &str, _port: u16, _kind: RequestKind) -> Verdict {
            self.verdict.clone()
        }
        fn record(&self, host: &str, port: u16, verdict: &Verdict) {
            self.recorded
                .lock()
                .unwrap()
                .push((host.to_string(), port, verdict.clone()));
        }
    }

    #[cfg(unix)]
    async fn ask(verdict: Verdict, host: &str) -> (DecisionReply, Vec<(String, u16, Verdict)>) {
        let dir = std::env::temp_dir().join(format!(
            "wirken-broker-test-{}-{}",
            std::process::id(),
            host.replace('.', "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let decider = Arc::new(Fixed {
            verdict,
            recorded: Default::default(),
        });
        let socket = dir.join("egress.sock");
        let broker = EgressBroker::bind(socket.clone(), decider.clone(), 0o600)
            .await
            .unwrap();
        let reply = ask_broker(
            &socket,
            &DecisionRequest {
                host: host.into(),
                port: 443,
                connect: true,
            },
        )
        .await
        .unwrap();
        drop(broker);
        let _ = std::fs::remove_dir_all(&dir);
        let recorded = decider.recorded.lock().unwrap().clone();
        (reply, recorded)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_refusal_is_recorded_and_returned_with_its_reason() {
        let (reply, recorded) = ask(
            Verdict::deny(SandboxEgressDenyReason::NotAllowed),
            "evil.example.com",
        )
        .await;
        assert!(!reply.allow);
        assert!(reply.addrs.is_empty());
        assert_eq!(reply.reason, Some(SandboxEgressDenyReason::NotAllowed));
        assert_eq!(
            recorded,
            [(
                "evil.example.com".to_string(),
                443,
                Verdict::deny(SandboxEgressDenyReason::NotAllowed)
            )]
        );
    }

    /// An allowed name that resolves only to loopback is refused after
    /// resolution, and the row keeps what the decider conditioned on.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_allowed_name_on_a_non_global_address_is_refused() {
        let allowed = Verdict {
            escalated: true,
            basis: vec!["workspace".into()],
            ..Verdict::allow()
        };
        let (reply, recorded) = ask(allowed, "localhost").await;
        assert!(!reply.allow);
        assert_eq!(
            reply.reason,
            Some(SandboxEgressDenyReason::ResolutionFailed)
        );
        assert_eq!(
            recorded,
            [(
                "localhost".to_string(),
                443,
                Verdict {
                    allowed: false,
                    reason: Some(SandboxEgressDenyReason::ResolutionFailed),
                    escalated: true,
                    basis: vec!["workspace".into()],
                }
            )]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_socket_has_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wirken-broker-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("egress.sock");
        let decider = Arc::new(Fixed {
            verdict: Verdict::allow(),
            recorded: Default::default(),
        });
        let broker = EgressBroker::bind(socket.clone(), decider, 0o600)
            .await
            .unwrap();
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        drop(broker);
        assert!(!socket.exists(), "the socket outlived the broker");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o600);
    }
}
