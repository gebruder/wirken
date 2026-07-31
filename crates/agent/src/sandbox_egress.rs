//! Default-deny egress proxy for sandboxed `exec`.
//!
//! The container-level floor is `--network none`: with egress mode
//! `none` (the default) a sandboxed `exec` has no network namespace
//! connectivity at all and this module is never instantiated. This
//! proxy exists for the two modes that grant some reach, and it is
//! the only route out of the sandbox in those modes.
//!
//! # Topology
//!
//! The sandbox container is attached to a per-exec Docker network
//! created with `Internal: true` and inter-container communication
//! disabled, so it has no default route and no reach to any sibling
//! container. The single reachable endpoint is this proxy, listening
//! on the network's gateway address. A process in the container that
//! ignores `HTTP_PROXY` and opens a raw socket does not bypass the
//! allowlist; it fails to route anywhere.
//!
//! # Properties
//!
//! * **HTTP(S) or nothing.** CONNECT on 443 and plain HTTP on 80 are
//!   the only shapes proxied. There is no generic TCP forward, so
//!   SSH, raw sockets, and every non-HTTP protocol are unreachable
//!   from a sandbox regardless of allowlist contents.
//! * **Domain match only.** IP-literal targets are refused before
//!   the allowlist is consulted. An allowlist entry is a domain
//!   pattern and can never authorize a bare address.
//! * **The proxy resolves.** The container has no working resolver.
//!   Hostname resolution happens here, after the allowlist decision,
//!   and resolved addresses outside the global unicast range are
//!   dropped so an allowlisted name cannot be rebound onto loopback,
//!   link-local (including the cloud metadata address), or private
//!   space.
//! * **Attribution is structural.** Each `exec` call gets its own
//!   listener carrying the agent, channel, and sender it was bound
//!   to. Nothing on an audit row is parsed out of request content,
//!   so a sandboxed process cannot forge its own attribution.
//!
//! # Known limit
//!
//! CONNECT allowlisting is decided on the CONNECT target, and the
//! tunnel is not inspected after that. A client that CONNECTs to an
//! allowlisted host and then presents a different SNI reaches
//! whatever the allowlisted host's address serves for that name.
//! Where a shared-IP CDN fronts both an allowed and a denied origin,
//! the allowlist is only as tight as that address. Closing this
//! would require terminating TLS in the proxy, which this design
//! deliberately does not do.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wirken_audit::{
    OwnSession, SandboxEgressDenyReason, SandboxEgressModeLabel, SessionEvent, SessionHandle,
    SessionLog, TrustLevel,
};
use wirken_gateway::agent_config::ChannelEgress;

use crate::skill_perms::{AllowSet, host_in_set};

/// Cap on the request head the proxy will buffer before deciding.
const MAX_HEAD: usize = 8 * 1024;

/// How long a connection may take to deliver a complete request head.
const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The only port CONNECT may target.
const CONNECT_PORT: u16 = 443;

/// The only port plain HTTP may target.
const PLAIN_PORT: u16 = 80;

/// Operator-selected egress posture for one channel's sandboxed
/// `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxEgressMode {
    /// No egress. The container runs with `--network none` and no
    /// proxy is started. The default, and the posture any
    /// unrecognized or missing configuration resolves to.
    #[default]
    None,
    /// Egress limited to an operator-configured domain allowlist.
    Allowlist,
    /// Any host reachable, subject to the port, IP-literal, and
    /// address-range rules. Explicit operator configuration only;
    /// never a fallback.
    Open,
}

impl SandboxEgressMode {
    /// Parse a mode from config. Unknown, empty, and malformed
    /// values resolve to [`SandboxEgressMode::None`]: egress is the
    /// axis where a config typo must not widen reach, so this does
    /// not mirror `SandboxMode::from_str_config`'s fall-back-to-
    /// default behaviour.
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "allowlist" => Self::Allowlist,
            "open" => Self::Open,
            "none" | "" => Self::None,
            _ => {
                tracing::warn!("Unknown sandbox egress mode '{s}', denying all sandbox egress");
                Self::None
            }
        }
    }

    /// Stable label for config round-trips and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Allowlist => "allowlist",
            Self::Open => "open",
        }
    }

    /// Audit-crate mirror of this mode.
    pub fn label(self) -> SandboxEgressModeLabel {
        match self {
            Self::None => SandboxEgressModeLabel::None,
            Self::Allowlist => SandboxEgressModeLabel::Allowlist,
            Self::Open => SandboxEgressModeLabel::Open,
        }
    }

    /// Whether this mode needs a proxy and an internal network.
    /// `None` runs the container on `--network none` instead.
    pub fn needs_proxy(self) -> bool {
        matches!(self, Self::Allowlist | Self::Open)
    }
}

/// One channel's resolved egress policy.
#[derive(Debug, Clone, Default)]
pub struct SandboxEgressPolicy {
    pub mode: SandboxEgressMode,
    pub domains: AllowSet,
}

impl SandboxEgressPolicy {
    /// The deny-everything policy. What an absent, unreadable, or
    /// malformed configuration resolves to.
    pub fn denied() -> Self {
        Self {
            mode: SandboxEgressMode::None,
            domains: AllowSet::Set(Default::default()),
        }
    }

    /// Build an allowlist policy over `domains`.
    pub fn allowlist(domains: AllowSet) -> Self {
        Self {
            mode: SandboxEgressMode::Allowlist,
            domains,
        }
    }

    /// Resolve a stored `ChannelEgress` entry into an enforced
    /// policy. The gateway crate holds the stored shape as plain
    /// strings because the dependency runs agent → gateway, so the
    /// interpretation lives here.
    ///
    /// A `*` entry becomes a wildcard allowset, matching skill-side
    /// `egress.domains`. An unrecognized mode resolves to `none`.
    pub fn from_config(mode: &str, domains: &[String]) -> Self {
        let mode = SandboxEgressMode::from_str_config(mode);
        let domains = if domains.iter().any(|d| d == "*") {
            AllowSet::Wildcard
        } else {
            AllowSet::Set(domains.iter().cloned().collect())
        };
        Self { mode, domains }
    }

    /// Resolve the policy for `channel` from an agent's per-channel
    /// config map. A turn with no channel, or a channel with no
    /// entry, gets the deny posture: adding a channel without
    /// configuring egress never grants reach.
    pub fn for_channel(
        channel: Option<&str>,
        configured: &BTreeMap<String, ChannelEgress>,
    ) -> Self {
        let Some(channel) = channel else {
            return Self::denied();
        };
        match configured.get(channel) {
            Some(entry) => Self::from_config(&entry.mode, &entry.domains),
            None => Self::denied(),
        }
    }
}

/// Which request shape a target came from. Decides the legal port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// `CONNECT host:443`.
    Connect,
    /// Plain HTTP with an absolute-form request target.
    Plain,
}

impl RequestKind {
    fn allowed_port(self) -> u16 {
        match self {
            Self::Connect => CONNECT_PORT,
            Self::Plain => PLAIN_PORT,
        }
    }
}

/// Decide whether one request may proceed. Pure, so the policy can
/// be asserted without sockets.
///
/// Order is deliberate. Mode comes first so a `none` sandbox reports
/// one unambiguous reason rather than whichever structural rule
/// happened to trip. The structural rules follow, and the allowlist
/// is consulted last: a refusal that never reached the allowlist is
/// a different operator problem from a host that simply is not on
/// it.
pub fn check_target(
    policy: &SandboxEgressPolicy,
    host: &str,
    port: u16,
    kind: RequestKind,
) -> Result<(), SandboxEgressDenyReason> {
    if policy.mode == SandboxEgressMode::None {
        return Err(SandboxEgressDenyReason::ModeNone);
    }
    if host.is_empty() {
        return Err(SandboxEgressDenyReason::Malformed);
    }
    if is_ip_literal(host) {
        return Err(SandboxEgressDenyReason::IpLiteral);
    }
    if port != kind.allowed_port() {
        return Err(SandboxEgressDenyReason::PortNotAllowed);
    }
    match policy.mode {
        SandboxEgressMode::Open => Ok(()),
        SandboxEgressMode::Allowlist => {
            if host_in_set(host, &policy.domains) {
                Ok(())
            } else {
                Err(SandboxEgressDenyReason::NotAllowed)
            }
        }
        // Handled above; repeated so a future mode addition is a
        // compile error rather than a silent allow.
        SandboxEgressMode::None => Err(SandboxEgressDenyReason::ModeNone),
    }
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

/// Where an audit row's identity fields come from. Populated when
/// the listener is bound, never from request content.
#[derive(Debug, Clone, Default)]
pub struct SandboxEgressAttribution {
    pub agent_id: String,
    pub channel: Option<String>,
    pub adapter_id: Option<String>,
    pub sender_id: Option<String>,
}

/// Audit sink for proxy denials, mirroring
/// [`crate::http_tool::HttpAuditCtx`].
#[derive(Clone)]
pub struct SandboxEgressAudit {
    pub log: Arc<dyn SessionLog>,
    pub handle: SessionHandle<OwnSession>,
}

/// Everything one listener needs to serve and account for a single
/// `exec` call.
#[derive(Clone)]
pub struct SandboxEgressContext {
    pub policy: SandboxEgressPolicy,
    pub attribution: SandboxEgressAttribution,
    pub audit: Option<SandboxEgressAudit>,
}

impl SandboxEgressContext {
    fn record_denial(&self, host: &str, port: u16, reason: SandboxEgressDenyReason) {
        tracing::warn!(
            "sandbox egress denied: host={host} port={port} reason={reason:?} \
             agent={} mode={}",
            self.attribution.agent_id,
            self.policy.mode.as_str(),
        );
        let Some(audit) = &self.audit else {
            return;
        };
        let event = SessionEvent::SandboxEgressDenied {
            host: host.to_string(),
            port,
            reason,
            mode: self.policy.mode.label(),
            agent_id: self.attribution.agent_id.clone(),
            channel: self.attribution.channel.clone(),
            adapter_id: self.attribution.adapter_id.clone(),
            sender_id: self.attribution.sender_id.clone(),
        };
        if let Err(e) = audit.log.append(&audit.handle, TrustLevel::System, event) {
            tracing::warn!("could not record sandbox egress denial: {e}");
        }
    }
}

/// A running per-exec proxy. Dropping the handle aborts the accept
/// loop, so the listener's lifetime is exactly the `exec` call it
/// was bound to.
pub struct SandboxEgressProxy {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl SandboxEgressProxy {
    /// Bind a listener on `bind_ip` (the internal network's gateway
    /// address) and start serving. Port 0 lets the OS choose, so
    /// concurrent `exec` calls never contend.
    pub async fn bind(bind_ip: IpAddr, ctx: SandboxEgressContext) -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(stream, ctx).await {
                        tracing::debug!("sandbox egress connection ended: {e}");
                    }
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// The address to hand the container as `HTTP_PROXY`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://host:port`, the proxy env-var form.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for SandboxEgressProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve one client connection: parse a single request head, apply
/// policy, then either tunnel or forward.
async fn serve_connection(mut stream: TcpStream, ctx: SandboxEgressContext) -> std::io::Result<()> {
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(reason)) => {
            ctx.record_denial("<unparsed>", 0, reason);
            let _ = write_refusal(&mut stream, reason).await;
            return Ok(());
        }
        Err(_) => {
            ctx.record_denial("<unparsed>", 0, SandboxEgressDenyReason::Malformed);
            return Ok(());
        }
    };

    let request = match parse_request(&head.bytes[..head.head_len]) {
        Ok(r) => r,
        Err(reason) => {
            ctx.record_denial("<unparsed>", 0, reason);
            let _ = write_refusal(&mut stream, reason).await;
            return Ok(());
        }
    };

    if let Err(reason) = check_target(&ctx.policy, &request.host, request.port, request.kind) {
        ctx.record_denial(&request.host, request.port, reason);
        let _ = write_refusal(&mut stream, reason).await;
        return Ok(());
    }

    let upstream = match connect_upstream(&request.host, request.port).await {
        Ok(s) => s,
        Err(reason) => {
            ctx.record_denial(&request.host, request.port, reason);
            let _ = write_refusal(&mut stream, reason).await;
            return Ok(());
        }
    };

    match request.kind {
        RequestKind::Connect => tunnel(stream, upstream, &head.bytes[head.head_len..]).await,
        RequestKind::Plain => {
            forward_plain(stream, upstream, &request, &head.bytes[head.head_len..]).await
        }
    }
}

/// Resolve and connect, refusing any answer outside global unicast.
async fn connect_upstream(host: &str, port: u16) -> Result<TcpStream, SandboxEgressDenyReason> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| SandboxEgressDenyReason::ResolutionFailed)?;
    let mut last_err = None;
    let mut saw_candidate = false;
    for addr in addrs {
        if !is_global_unicast(addr.ip()) {
            tracing::warn!(
                "sandbox egress: dropping non-global address {} for allowlisted host {host}",
                addr.ip(),
            );
            continue;
        }
        saw_candidate = true;
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    if !saw_candidate {
        return Err(SandboxEgressDenyReason::ResolutionFailed);
    }
    let _ = last_err;
    Err(SandboxEgressDenyReason::ResolutionFailed)
}

/// A buffered request head plus whatever followed it in the same
/// read. The trailing bytes are the request body (or, for CONNECT,
/// the start of the TLS handshake) and must be forwarded intact.
struct Head {
    bytes: Vec<u8>,
    head_len: usize,
}

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

/// Index just past the terminating CRLFCRLF, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// A parsed proxy request, reduced to what policy needs.
struct ProxyRequest {
    kind: RequestKind,
    host: String,
    port: u16,
    /// Origin-form request line to send upstream. Empty for CONNECT.
    rewritten_head: Vec<u8>,
}

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
    use std::collections::BTreeSet;

    fn allowlist(hosts: &[&str]) -> SandboxEgressPolicy {
        SandboxEgressPolicy::allowlist(AllowSet::Set(
            hosts.iter().map(|h| h.to_string()).collect::<BTreeSet<_>>(),
        ))
    }

    #[test]
    fn default_mode_is_none() {
        assert_eq!(SandboxEgressMode::default(), SandboxEgressMode::None);
        assert_eq!(SandboxEgressPolicy::default().mode, SandboxEgressMode::None);
    }

    #[test]
    fn unknown_mode_denies_rather_than_defaulting_open() {
        assert_eq!(
            SandboxEgressMode::from_str_config("allow-all"),
            SandboxEgressMode::None
        );
        assert_eq!(
            SandboxEgressMode::from_str_config(""),
            SandboxEgressMode::None
        );
    }

    #[test]
    fn mode_none_denies_even_an_allowlisted_host() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::None,
            domains: AllowSet::Wildcard,
        };
        assert_eq!(
            check_target(&policy, "example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::ModeNone)
        );
    }

    #[test]
    fn allowlisted_host_on_443_passes() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Ok(())
        );
    }

    #[test]
    fn unlisted_host_denied() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "evil.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn wildcard_suffix_matches_like_skill_egress() {
        let policy = allowlist(&["*.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn ip_literal_denied_even_when_allowlisted_verbatim() {
        let policy = allowlist(&["93.184.216.34"]);
        assert_eq!(
            check_target(&policy, "93.184.216.34", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
    }

    #[test]
    fn ip_literal_denied_under_open_mode() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::Open,
            domains: AllowSet::Wildcard,
        };
        assert_eq!(
            check_target(&policy, "169.254.169.254", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
        assert_eq!(
            check_target(&policy, "[::1]", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::IpLiteral)
        );
    }

    #[test]
    fn connect_restricted_to_443() {
        let policy = allowlist(&["api.example.com"]);
        for port in [22u16, 80, 8080, 3306] {
            assert_eq!(
                check_target(&policy, "api.example.com", port, RequestKind::Connect),
                Err(SandboxEgressDenyReason::PortNotAllowed),
                "port {port} must not tunnel"
            );
        }
    }

    #[test]
    fn plain_http_restricted_to_80() {
        let policy = allowlist(&["api.example.com"]);
        assert_eq!(
            check_target(&policy, "api.example.com", 80, RequestKind::Plain),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "api.example.com", 8080, RequestKind::Plain),
            Err(SandboxEgressDenyReason::PortNotAllowed)
        );
    }

    #[test]
    fn open_mode_allows_any_name_but_still_bounds_port() {
        let policy = SandboxEgressPolicy {
            mode: SandboxEgressMode::Open,
            domains: AllowSet::Set(BTreeSet::new()),
        };
        assert_eq!(
            check_target(&policy, "anything.example.com", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&policy, "anything.example.com", 22, RequestKind::Connect),
            Err(SandboxEgressDenyReason::PortNotAllowed)
        );
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

    #[test]
    fn connect_parses_authority_form() {
        let head = b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let req = parse_request(head).unwrap();
        assert_eq!(req.kind, RequestKind::Connect);
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 443);
    }

    #[test]
    fn connect_without_explicit_port_is_malformed() {
        let head = b"CONNECT api.example.com HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::Malformed)
        );
    }

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

    #[test]
    fn https_absolute_form_on_plain_path_is_refused() {
        let head = b"GET https://api.example.com/ HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::MethodNotAllowed)
        );
    }

    #[test]
    fn non_http_verb_is_refused() {
        let head = b"SSH api.example.com:22 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(head).err(),
            Some(SandboxEgressDenyReason::MethodNotAllowed)
        );
    }

    #[test]
    fn head_end_found_across_segment_boundary() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn unconfigured_channel_resolves_to_deny() {
        let configured = BTreeMap::new();
        let policy = SandboxEgressPolicy::for_channel(Some("slack"), &configured);
        assert_eq!(policy.mode, SandboxEgressMode::None);
        assert!(!policy.mode.needs_proxy());
    }

    #[test]
    fn turn_with_no_channel_resolves_to_deny() {
        let mut configured = BTreeMap::new();
        configured.insert(
            "slack".to_string(),
            ChannelEgress {
                mode: "open".to_string(),
                domains: vec![],
            },
        );
        // A cron or CLI turn carries no channel and must not inherit
        // another channel's reach.
        let policy = SandboxEgressPolicy::for_channel(None, &configured);
        assert_eq!(policy.mode, SandboxEgressMode::None);
    }

    #[test]
    fn each_channel_gets_only_its_own_allowlist() {
        let mut configured = BTreeMap::new();
        configured.insert(
            "slack".to_string(),
            ChannelEgress {
                mode: "allowlist".to_string(),
                domains: vec!["slack-ok.example".to_string()],
            },
        );
        configured.insert(
            "signal".to_string(),
            ChannelEgress {
                mode: "allowlist".to_string(),
                domains: vec!["signal-ok.example".to_string()],
            },
        );

        let slack = SandboxEgressPolicy::for_channel(Some("slack"), &configured);
        assert_eq!(
            check_target(&slack, "slack-ok.example", 443, RequestKind::Connect),
            Ok(())
        );
        assert_eq!(
            check_target(&slack, "signal-ok.example", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed),
            "one channel's allowlist must not leak into another's"
        );
    }

    #[test]
    fn wildcard_entry_becomes_a_wildcard_allowset() {
        let policy = SandboxEgressPolicy::from_config("allowlist", &["*".to_string()]);
        assert!(matches!(policy.domains, AllowSet::Wildcard));
        assert_eq!(
            check_target(&policy, "anything.example", 443, RequestKind::Connect),
            Ok(())
        );
    }

    #[test]
    fn allowlist_mode_with_no_domains_denies_everything() {
        let policy = SandboxEgressPolicy::from_config("allowlist", &[]);
        assert_eq!(policy.mode, SandboxEgressMode::Allowlist);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::NotAllowed)
        );
    }

    #[test]
    fn unknown_stored_mode_resolves_to_deny_not_to_its_domains() {
        // A mode string a newer build wrote must not be honoured as
        // an allowlist by an older one.
        let policy = SandboxEgressPolicy::from_config("permissive", &["api.example.com".into()]);
        assert_eq!(policy.mode, SandboxEgressMode::None);
        assert_eq!(
            check_target(&policy, "api.example.com", 443, RequestKind::Connect),
            Err(SandboxEgressDenyReason::ModeNone)
        );
    }

    #[test]
    fn only_allowlist_and_open_provision_a_proxy() {
        assert!(!SandboxEgressMode::None.needs_proxy());
        assert!(SandboxEgressMode::Allowlist.needs_proxy());
        assert!(SandboxEgressMode::Open.needs_proxy());
    }
}
