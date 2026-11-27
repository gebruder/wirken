//! Credential injection for contained stdio MCP servers.
//!
//! A server whose `sandbox` block carries `inject` never holds the
//! credential the block names. Its container gets a placeholder in the
//! credential's variable and a plain-HTTP base URL on its own loopback.
//! What it sends there travels through the loopback relay and the
//! sidecar, neither of which reads it, to this process, which holds
//! the value already.
//!
//! For each request the proxy maps the path through the entry's path
//! map, removes whatever credential headers the server sent, sets the
//! configured header from the vault value, and makes an HTTPS request
//! to the bound host itself. Nothing is substituted: a placeholder in
//! a body, a query, a path or another header stays a placeholder.
//!
//! Every request made is one `McpCredentialInjected` row, written
//! before it is sent, and every refusal one `McpInjectRefused` row.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use wirken_audit::{McpInjectRefusal, SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_sandbox::egress::{InjectRoute, InjectStream, is_global_unicast, is_ip_literal};

use crate::credentials::{ServerPin, SharedCredentials};
use crate::mcp_config::SandboxInject;
use crate::mcp_registry::MCP_SENTINEL_SESSION;

/// The most of a request head the forwarder reads.
const MAX_HEAD: usize = 8 * 1024;

/// How many redirects on the bound host the forwarder follows.
const MAX_REDIRECTS: usize = 3;

/// The most of a path a row carries.
const ROW_PATH_BYTES: usize = 512;

/// Headers the configured header may not be: the forwarder sets or
/// drops each of them itself.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "te",
    "trailer",
    "keep-alive",
];

/// Headers that describe one connection and are not forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One rule of the path map, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    from: String,
    to: String,
    /// `from` ends in `/` and matches every path under it.
    prefix: bool,
}

/// An `inject` block, checked. A plan exists only for a block the
/// proxy can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectPlan {
    /// The variable that holds a placeholder in the container.
    pub credential_env: String,
    /// The vault name that variable's `vault:` value references.
    pub credential: String,
    /// The bound host, lowercase.
    pub host: String,
    header: HeaderName,
    scheme: Option<String>,
    /// The variable the base URL is put in.
    pub base_url_env: String,
    rules: Vec<Rule>,
}

fn is_env_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_domain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !is_ip_literal(name)
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn check_rule_path(path: &str, what: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!(
            "inject.paths {what} {path:?} does not start with /"
        ));
    }
    if path.contains("..") || path.contains(['%', '?', '#', '\\']) {
        return Err(format!(
            "inject.paths {what} {path:?} contains one of .. % ? # \\"
        ));
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'<' && b != b'>')
    {
        return Err(format!(
            "inject.paths {what} {path:?} is not a plain ASCII path"
        ));
    }
    Ok(())
}

impl InjectPlan {
    /// Check `block` against the entry's `env` and `secrets_in_env`.
    pub fn new(
        block: &SandboxInject,
        env: &HashMap<String, String>,
        secrets_in_env: &[String],
    ) -> Result<Self, String> {
        let credential = env
            .get(&block.credential_env)
            .and_then(|v| v.strip_prefix("vault:"))
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                format!(
                    "inject.credential_env names {}, which is not a vault: value in env",
                    block.credential_env
                )
            })?;
        if secrets_in_env.contains(&block.credential_env) {
            return Err(format!(
                "inject.credential_env {} is also listed in secrets_in_env",
                block.credential_env
            ));
        }
        let host = block.host.to_ascii_lowercase();
        if !is_domain_name(&host) {
            return Err(format!(
                "inject.host {:?} is not one domain name without a port",
                block.host
            ));
        }
        let header = HeaderName::from_bytes(block.header.as_bytes())
            .map_err(|_| format!("inject.header {:?} is not a header name", block.header))?;
        if RESERVED_HEADERS.contains(&header.as_str()) {
            return Err(format!("inject.header {header} is set by the proxy itself"));
        }
        if let Some(scheme) = &block.scheme
            && (scheme.is_empty()
                || !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            return Err(format!("inject.scheme {scheme:?} is not one word"));
        }
        if !is_env_name(&block.base_url_env) {
            return Err(format!(
                "inject.base_url_env {:?} is not a variable name",
                block.base_url_env
            ));
        }
        if env.contains_key(&block.base_url_env) {
            return Err(format!(
                "inject.base_url_env {} is set in env; the proxy sets it",
                block.base_url_env
            ));
        }
        if block.paths.is_empty() {
            return Err("inject.paths is empty: no path would be forwarded".into());
        }
        let mut rules: Vec<Rule> = Vec::new();
        for path in &block.paths {
            check_rule_path(&path.from, "from")?;
            check_rule_path(&path.to, "to")?;
            let prefix = path.from.ends_with('/');
            if prefix && !path.to.ends_with('/') {
                return Err(format!(
                    "inject.paths from {:?} is a prefix, so its to {:?} must end in / too",
                    path.from, path.to
                ));
            }
            if rules.iter().any(|r| r.from == path.from) {
                return Err(format!("inject.paths repeats from {:?}", path.from));
            }
            rules.push(Rule {
                from: path.from.clone(),
                to: path.to.clone(),
                prefix,
            });
        }
        Ok(Self {
            credential_env: block.credential_env.clone(),
            credential: credential.to_string(),
            host,
            header,
            scheme: block.scheme.clone(),
            base_url_env: block.base_url_env.clone(),
            rules,
        })
    }

    /// The path on the bound host that `path` is forwarded to. The
    /// longest matching `from` wins.
    fn map(&self, path: &str) -> Result<String, McpInjectRefusal> {
        check_request_path(path)?;
        self.rules
            .iter()
            .filter_map(|rule| {
                if rule.prefix {
                    path.strip_prefix(rule.from.as_str())
                        .map(|rest| (rule.from.len(), format!("{}{rest}", rule.to)))
                } else {
                    (path == rule.from).then(|| (rule.from.len(), rule.to.clone()))
                }
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, mapped)| mapped)
            .ok_or(McpInjectRefusal::UnmappedPath)
    }

    /// Whether `path` on the bound host is one the path map can
    /// produce: under a prefix rule's `to`, or an exact rule's `to`.
    fn covers(&self, path: &str) -> bool {
        check_request_path(path).is_ok()
            && self.rules.iter().any(|rule| {
                if rule.prefix {
                    path.starts_with(rule.to.as_str())
                } else {
                    path == rule.to
                }
            })
    }

    /// The header value for `secret`.
    fn header_value(&self, secret: &str) -> Option<HeaderValue> {
        let text = match &self.scheme {
            Some(scheme) => format!("{scheme} {secret}"),
            None => secret.to_string(),
        };
        let mut value = HeaderValue::from_str(&text).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
}

/// A request path the forwarder will map: origin form, with no dot
/// segment, no encoded slash, backslash or dot.
fn check_request_path(path: &str) -> Result<(), McpInjectRefusal> {
    if !path.starts_with('/') {
        return Err(McpInjectRefusal::Malformed);
    }
    let lower = path.to_ascii_lowercase();
    if path.split('/').any(|s| s == "." || s == "..")
        || path.contains('\\')
        || ["%2f", "%2e", "%5c"].iter().any(|enc| lower.contains(enc))
    {
        return Err(McpInjectRefusal::PathShape);
    }
    Ok(())
}

/// A random stand-in for a credential, for the container's variable.
pub fn new_placeholder() -> String {
    format!(
        "wirken-placeholder-{}",
        crate::mcp_transport::random_suffix()
    )
}

/// Returned by the resolver when a name has no global-unicast address.
#[derive(Debug)]
struct NoGlobalAddress(String);

impl std::fmt::Display for NoGlobalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} resolved to no global-unicast address", self.0)
    }
}

impl std::error::Error for NoGlobalAddress {}

/// Resolves a name and keeps only its global-unicast addresses, as the
/// egress broker does for the sidecar.
struct GlobalUnicast;

impl reqwest::dns::Resolve for GlobalUnicast {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map(|found| found.filter(|a| is_global_unicast(a.ip())).collect())
                .unwrap_or_default();
            if addrs.is_empty() {
                return Err(Box::new(NoGlobalAddress(host)) as _);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Where the forwarder sends requests: the bound host's origin and the
/// client that reaches it.
#[derive(Clone)]
pub struct Upstream {
    client: reqwest::Client,
    origin: url::Url,
}

impl Upstream {
    /// `https://<host>` on port 443, reached at a global-unicast
    /// address the proxy resolved itself. Redirects are not followed
    /// by the client, no proxy variable is read, and response bodies
    /// are passed on as received.
    pub fn https(host: &str) -> Result<Self, String> {
        let client = Self::client()
            .dns_resolver(Arc::new(GlobalUnicast))
            .build()
            .map_err(|e| format!("build the injected route's client: {e}"))?;
        let origin = url::Url::parse(&format!("https://{host}/"))
            .map_err(|e| format!("inject.host {host:?}: {e}"))?;
        Ok(Self { client, origin })
    }

    /// The client every upstream is reached with, before its resolver
    /// is chosen.
    fn client() -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(std::time::Duration::from_secs(15))
            .read_timeout(std::time::Duration::from_secs(120))
    }

    /// A stand-in at `origin`, reached with the same client and the
    /// system resolver.
    #[cfg(test)]
    pub(crate) fn at(origin: url::Url) -> Self {
        Self {
            client: Self::client().build().unwrap(),
            origin,
        }
    }

    /// `path_and_query` on the origin.
    fn url(&self, path_and_query: &str) -> Option<url::Url> {
        let mut url = self.origin.clone();
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        url.set_path(path);
        url.set_query(query);
        Some(url)
    }

    /// Whether `url` is on this origin.
    fn same_origin(&self, url: &url::Url) -> bool {
        url.scheme() == self.origin.scheme()
            && url.host_str() == self.origin.host_str()
            && url.port_or_known_default() == self.origin.port_or_known_default()
    }
}

type ReplyBody = BoxBody<Bytes, std::io::Error>;

fn text_reply(status: StatusCode, text: &'static str) -> Response<ReplyBody> {
    let mut reply = Response::new(
        Full::new(Bytes::from_static(text.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *reply.status_mut() = status;
    // Whatever the server sent after the head is not read.
    reply
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    reply
}

/// One contained server's injected route.
pub struct Injector {
    pub plan: InjectPlan,
    pub agent_id: String,
    pub server: String,
    /// The entry the credential is read for.
    pub pin: ServerPin,
    pub credentials: SharedCredentials,
    pub audit: Option<Arc<dyn SessionLog>>,
    pub upstream: Upstream,
}

/// A request's method and path, as rows carry them.
struct Seen {
    method: String,
    path: String,
}

fn row_path(path: &str) -> String {
    let mut end = path.len().min(ROW_PATH_BYTES);
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    path.get(..end).unwrap_or_default().to_string()
}

/// What makes a request something other than a plain HTTP/1.1 request
/// in origin form.
fn malformed(req: &Request<Incoming>) -> bool {
    req.method() == Method::CONNECT
        || req.uri().scheme().is_some()
        || req.uri().authority().is_some()
        || !matches!(
            req.version(),
            hyper::Version::HTTP_11 | hyper::Version::HTTP_10
        )
        || unsafe_framing(req.headers())
}

/// An upgrade, or both a length and a transfer coding.
fn unsafe_framing(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        || (headers.contains_key(header::CONTENT_LENGTH)
            && headers.contains_key(header::TRANSFER_ENCODING))
}

/// The names a `Connection` header lists, lowercase.
fn connection_names(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// `headers` without the ones that describe one connection.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let listed = connection_names(headers);
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if HOP_BY_HOP.contains(&name.as_str()) || listed.iter().any(|l| l == name.as_str()) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Whether any header of a response carries `secret`'s exact bytes.
fn head_carries(headers: &reqwest::header::HeaderMap, secret: &str) -> bool {
    let needle = secret.as_bytes();
    !needle.is_empty()
        && headers.iter().any(|(name, value)| {
            name.as_str()
                .as_bytes()
                .windows(needle.len())
                .any(|w| w == needle)
                || value.as_bytes().windows(needle.len()).any(|w| w == needle)
        })
}

fn is_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 307 | 308)
}

impl Injector {
    fn record(&self, event: SessionEvent) -> Result<(), String> {
        let Some(log) = &self.audit else {
            return Ok(());
        };
        let handle = log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
        log.append(&handle, TrustLevel::System, event)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Record a refusal and build the answer the server gets. Terse:
    /// the detail is on the row.
    fn refuse(&self, seen: &Seen, reason: McpInjectRefusal) -> Response<ReplyBody> {
        tracing::warn!(
            agent_id = %self.agent_id,
            server = %self.server,
            "MCP injected route refused: method={} path={} reason={}",
            seen.method,
            seen.path,
            reason.as_str(),
        );
        if let Err(e) = self.record(SessionEvent::McpInjectRefused {
            server_name: self.server.clone(),
            agent_id: self.agent_id.clone(),
            host: self.plan.host.clone(),
            method: seen.method.clone(),
            path: seen.path.clone(),
            reason,
        }) {
            tracing::error!("MCP injected route: refusal not recorded: {e}");
        }
        let status = match reason {
            McpInjectRefusal::UnmappedPath => StatusCode::NOT_FOUND,
            McpInjectRefusal::PathShape | McpInjectRefusal::Malformed => StatusCode::BAD_REQUEST,
            McpInjectRefusal::ResolutionFailed
            | McpInjectRefusal::CredentialUnavailable
            | McpInjectRefusal::CredentialInResponse
            | McpInjectRefusal::RecordFailed => StatusCode::BAD_GATEWAY,
        };
        text_reply(status, "injected route refused\n")
    }

    /// Answer one request from the server.
    async fn handle(&self, req: Request<Incoming>) -> Response<ReplyBody> {
        let mut seen = Seen {
            method: req.method().as_str().to_string(),
            path: row_path(req.uri().path()),
        };
        if malformed(&req) {
            return self.refuse(&seen, McpInjectRefusal::Malformed);
        }
        let mapped = match self.plan.map(req.uri().path()) {
            Ok(mapped) => mapped,
            Err(reason) => return self.refuse(&seen, reason),
        };
        let Some(secret) = self
            .credentials
            .get_for(&self.pin, &self.plan.credential)
            .filter(|s| !s.expose().is_empty())
        else {
            return self.refuse(&seen, McpInjectRefusal::CredentialUnavailable);
        };
        let Some(credential_header) = self.plan.header_value(secret.expose()) else {
            return self.refuse(&seen, McpInjectRefusal::CredentialUnavailable);
        };

        let method = req.method().clone();
        let mut headers = end_to_end(req.headers());
        headers.remove(header::HOST);
        headers.remove(header::AUTHORIZATION);
        headers.remove(&self.plan.header);
        headers.insert(self.plan.header.clone(), credential_header);

        let mut target = match req.uri().query() {
            Some(query) => format!("{mapped}?{query}"),
            None => mapped,
        };
        let has_body = !req.body().is_end_stream();
        let mut body = has_body.then(|| {
            reqwest::Body::wrap_stream(http_body_util::BodyDataStream::new(req.into_body()))
        });
        // A redirect is followed only for a request that can be sent
        // again as it was.
        let follows = !has_body && matches!(method, Method::GET | Method::HEAD);

        let mut hops = 0;
        loop {
            let Some(url) = self.upstream.url(&target) else {
                return self.refuse(&seen, McpInjectRefusal::Malformed);
            };
            // The row first: no request carries the credential without
            // one saying so.
            if let Err(e) = self.record(SessionEvent::McpCredentialInjected {
                server_name: self.server.clone(),
                agent_id: self.agent_id.clone(),
                credential: self.plan.credential.clone(),
                host: self.plan.host.clone(),
                method: seen.method.clone(),
                path: row_path(url.path()),
                exchanged_for: None,
            }) {
                tracing::error!("MCP injected route: request not recorded, so not made: {e}");
                return self.refuse(&seen, McpInjectRefusal::RecordFailed);
            }
            let mut request = self
                .upstream
                .client
                .request(method.clone(), url.clone())
                .headers(headers.clone());
            if let Some(body) = body.take() {
                request = request.body(body);
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(e) => {
                    if error_is::<NoGlobalAddress>(&e) {
                        return self.refuse(&seen, McpInjectRefusal::ResolutionFailed);
                    }
                    tracing::warn!(
                        agent_id = %self.agent_id,
                        server = %self.server,
                        "MCP injected route: request to {} failed: {}",
                        self.plan.host,
                        e.without_url(),
                    );
                    return text_reply(
                        StatusCode::BAD_GATEWAY,
                        "injected route: upstream failed\n",
                    );
                }
            };
            if head_carries(response.headers(), secret.expose()) {
                seen.path = row_path(url.path());
                return self.refuse(&seen, McpInjectRefusal::CredentialInResponse);
            }
            if follows
                && hops < MAX_REDIRECTS
                && is_redirect(response.status())
                && let Some(next) = self.redirect_target(&url, response.headers())
            {
                hops += 1;
                target = next;
                continue;
            }
            return relay_response(response);
        }
    }

    /// Where a redirect leads, when it stays on the bound host and
    /// inside the path map. Anything else is not followed.
    fn redirect_target(
        &self,
        from: &url::Url,
        headers: &reqwest::header::HeaderMap,
    ) -> Option<String> {
        let location = headers.get(reqwest::header::LOCATION)?.to_str().ok()?;
        let next = from.join(location).ok()?;
        if !self.upstream.same_origin(&next) || !self.plan.covers(next.path()) {
            return None;
        }
        Some(match next.query() {
            Some(query) => format!("{}?{query}", next.path()),
            None => next.path().to_string(),
        })
    }
}

/// Whether `error` or anything it wraps is a `T`.
fn error_is<T: std::error::Error + 'static>(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(e) = current {
        if e.is::<T>() {
            return true;
        }
        current = e.source();
    }
    false
}

/// The upstream response, passed on with its body as received and
/// without the headers that described the upstream connection.
fn relay_response(response: reqwest::Response) -> Response<ReplyBody> {
    use futures_util::TryStreamExt;

    let status = response.status();
    let headers = end_to_end(response.headers());
    let body = StreamBody::new(
        response
            .bytes_stream()
            .map_ok(Frame::data)
            .map_err(std::io::Error::other),
    );
    let mut reply = Response::new(BodyExt::boxed(body));
    *reply.status_mut() = status;
    *reply.headers_mut() = headers;
    reply
}

#[async_trait::async_trait]
impl InjectRoute for Injector {
    async fn serve(&self, stream: Box<dyn InjectStream>) {
        let service = hyper::service::service_fn(|req| async move {
            Ok::<_, std::convert::Infallible>(self.handle(req).await)
        });
        let served = hyper::server::conn::http1::Builder::new()
            .max_buf_size(MAX_HEAD)
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(std::time::Duration::from_secs(30))
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await;
        if let Err(e) = served
            && (e.is_parse() || e.is_parse_too_large())
        {
            // Hyper answered the server itself; the row is ours.
            let _ = self.refuse(
                &Seen {
                    method: String::new(),
                    path: String::new(),
                },
                McpInjectRefusal::Malformed,
            );
        }
    }
}

/// A plain-HTTP stand-in for a bound host, for this crate's tests.
#[cfg(test)]
pub(crate) mod stub {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One request the stub upstream received.
    #[derive(Debug, Clone)]
    pub(crate) struct Got {
        pub(crate) method: String,
        pub(crate) target: String,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: Vec<u8>,
    }

    impl Got {
        pub(crate) fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    pub(crate) type Answer = fn(&Got, &str) -> String;

    /// A plain-HTTP stand-in for the bound host: keeps each request and
    /// answers with what `answer` returns, given the request and the
    /// stub's own origin.
    pub(crate) async fn upstream(answer: Answer) -> (url::Url, Arc<Mutex<Vec<Got>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let got = Arc::new(Mutex::new(Vec::new()));
        let (kept, base) = (got.clone(), origin.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (kept, base) = (kept.clone(), base.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let head_end = loop {
                            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break at + 4;
                            }
                            let mut chunk = [0u8; 4096];
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                        let mut lines = head.split("\r\n");
                        let mut first = lines.next().unwrap_or_default().split(' ');
                        let method = first.next().unwrap_or_default().to_string();
                        let target = first.next().unwrap_or_default().to_string();
                        let headers: Vec<(String, String)> = lines
                            .filter_map(|l| l.split_once(':'))
                            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
                            .collect();
                        let length: usize = headers
                            .iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, v)| v.parse().ok())
                            .unwrap_or(0);
                        while buf.len() < head_end + length {
                            let mut chunk = [0u8; 4096];
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let body = buf[head_end..head_end + length].to_vec();
                        buf.drain(..head_end + length);
                        let request = Got {
                            method,
                            target,
                            headers,
                            body,
                        };
                        let reply = answer(&request, &base);
                        kept.lock().unwrap().push(request);
                        if stream.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (url::Url::parse(&origin).unwrap(), got)
    }

    pub(crate) fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    pub(crate) fn redirect(status: &str, location: &str) -> String {
        format!("HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::stub::{Answer, Got, ok, redirect, upstream};
    use super::*;
    use crate::credentials::ProxyCredentials;
    use crate::mcp_config::InjectPath;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wirken_audit::{OwnSession, SessionHandle, SqliteSessionLog, StoredSessionEvent};
    use wirken_vault::VaultSecret;

    const SECRET: &str = "ghp_realSecretValue0123456789";
    const PLACEHOLDER: &str = "wirken-placeholder-abcdef";

    fn block() -> SandboxInject {
        SandboxInject {
            credential_env: "GITHUB_PERSONAL_ACCESS_TOKEN".into(),
            host: "api.github.com".into(),
            header: "Authorization".into(),
            scheme: Some("Bearer".into()),
            base_url_env: "GITHUB_HOST".into(),
            paths: vec![
                InjectPath {
                    from: "/api/v3/".into(),
                    to: "/".into(),
                },
                InjectPath {
                    from: "/api/graphql".into(),
                    to: "/graphql".into(),
                },
            ],
        }
    }

    fn env() -> HashMap<String, String> {
        HashMap::from([
            (
                "GITHUB_PERSONAL_ACCESS_TOKEN".to_string(),
                "vault:github-token".to_string(),
            ),
            ("LOG".to_string(), "info".to_string()),
        ])
    }

    fn plan() -> InjectPlan {
        InjectPlan::new(&block(), &env(), &[]).unwrap()
    }

    #[test]
    fn a_checked_block_names_the_vault_entry_and_lowercases_the_host() {
        let plan = InjectPlan::new(
            &SandboxInject {
                host: "API.GitHub.com".into(),
                ..block()
            },
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(plan.credential, "github-token");
        assert_eq!(plan.host, "api.github.com");
        assert_eq!(plan.credential_env, "GITHUB_PERSONAL_ACCESS_TOKEN");
        assert_eq!(plan.base_url_env, "GITHUB_HOST");
    }

    /// Each thing an entry may not say, refused when the entry is
    /// loaded, with the field named.
    #[test]
    fn each_block_the_proxy_cannot_serve_is_refused() {
        let path = |from: &str, to: &str| InjectPath {
            from: from.into(),
            to: to.into(),
        };
        let cases: Vec<(&str, SandboxInject, Vec<String>)> = vec![
            (
                "credential_env",
                SandboxInject {
                    credential_env: "LOG".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "credential_env",
                SandboxInject {
                    credential_env: "MISSING".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "secrets_in_env",
                block(),
                vec!["GITHUB_PERSONAL_ACCESS_TOKEN".into()],
            ),
            (
                "inject.host",
                SandboxInject {
                    host: "140.82.112.5".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.host",
                SandboxInject {
                    host: "*.github.com".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.host",
                SandboxInject {
                    host: "api.github.com:8443".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.host",
                SandboxInject {
                    host: "https://api.github.com".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.header",
                SandboxInject {
                    header: "Bad Header".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.header",
                SandboxInject {
                    header: "Host".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.header",
                SandboxInject {
                    header: "Transfer-Encoding".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.scheme",
                SandboxInject {
                    scheme: Some("Bearer x".into()),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.base_url_env",
                SandboxInject {
                    base_url_env: "LOG".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.base_url_env",
                SandboxInject {
                    base_url_env: "1BAD".into(),
                    ..block()
                },
                vec![],
            ),
            (
                "inject.paths is empty",
                SandboxInject {
                    paths: vec![],
                    ..block()
                },
                vec![],
            ),
            (
                "does not start with /",
                SandboxInject {
                    paths: vec![path("api/", "/")],
                    ..block()
                },
                vec![],
            ),
            (
                "contains one of",
                SandboxInject {
                    paths: vec![path("/api/", "/../")],
                    ..block()
                },
                vec![],
            ),
            (
                "contains one of",
                SandboxInject {
                    paths: vec![path("/api/%2e/", "/")],
                    ..block()
                },
                vec![],
            ),
            (
                "contains one of",
                SandboxInject {
                    paths: vec![path("/api/", "/x?y=1/")],
                    ..block()
                },
                vec![],
            ),
            (
                "must end in /",
                SandboxInject {
                    paths: vec![path("/api/", "/v1")],
                    ..block()
                },
                vec![],
            ),
            (
                "repeats from",
                SandboxInject {
                    paths: vec![path("/api/", "/"), path("/api/", "/v1/")],
                    ..block()
                },
                vec![],
            ),
        ];
        for (says, block, in_env) in cases {
            let err = InjectPlan::new(&block, &env(), &in_env).unwrap_err();
            assert!(err.contains(says), "{err:?} does not name {says:?}");
        }
    }

    #[test]
    fn the_path_map_takes_the_longest_match_and_refuses_the_rest() {
        let plan = InjectPlan::new(
            &SandboxInject {
                paths: vec![
                    InjectPath {
                        from: "/api/v3/".into(),
                        to: "/".into(),
                    },
                    InjectPath {
                        from: "/api/v3/enterprise/".into(),
                        to: "/ent/".into(),
                    },
                    InjectPath {
                        from: "/api/graphql".into(),
                        to: "/graphql".into(),
                    },
                ],
                ..block()
            },
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(plan.map("/api/v3/user").unwrap(), "/user");
        assert_eq!(plan.map("/api/v3/").unwrap(), "/");
        assert_eq!(plan.map("/api/v3/enterprise/x").unwrap(), "/ent/x");
        assert_eq!(plan.map("/api/graphql").unwrap(), "/graphql");
        for unmapped in [
            "/api/v3",
            "/api/graphql/x",
            "/raw/o/r/HEAD/f",
            "/",
            "/api/uploads/x",
        ] {
            assert_eq!(
                plan.map(unmapped),
                Err(McpInjectRefusal::UnmappedPath),
                "{unmapped}"
            );
        }
        for shaped in [
            "/api/v3/a/../b",
            "/api/v3/./a",
            "/api/v3/a/..",
            "/api/v3/%2e%2e/x",
            "/api/v3/a%2Fb",
            "/api/v3/a%5Cb",
            "/api/v3/a\\b",
        ] {
            assert_eq!(
                plan.map(shaped),
                Err(McpInjectRefusal::PathShape),
                "{shaped}"
            );
        }
    }

    #[test]
    fn a_redirect_target_is_covered_only_inside_the_path_map() {
        let exact_only = InjectPlan::new(
            &SandboxInject {
                paths: vec![InjectPath {
                    from: "/api/graphql".into(),
                    to: "/graphql".into(),
                }],
                ..block()
            },
            &env(),
            &[],
        )
        .unwrap();
        assert!(exact_only.covers("/graphql"));
        assert!(!exact_only.covers("/graphql/x"));
        assert!(!exact_only.covers("/repositories/1"));
        assert!(plan().covers("/repositories/1"));
        assert!(!plan().covers("/a/../b"));
    }

    #[test]
    fn an_upgrade_or_two_framings_is_not_forwarded() {
        let mut both = HeaderMap::new();
        both.insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        both.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(unsafe_framing(&both));
        let mut upgrade = HeaderMap::new();
        upgrade.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(unsafe_framing(&upgrade));
        let mut plain = HeaderMap::new();
        plain.insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        assert!(!unsafe_framing(&plain));
    }

    #[test]
    fn headers_a_connection_header_lists_are_not_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close, X-Hop"));
        headers.insert("x-hop", HeaderValue::from_static("1"));
        headers.insert("x-kept", HeaderValue::from_static("1"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        let kept = end_to_end(&headers);
        assert_eq!(kept.len(), 1);
        assert!(kept.contains_key("x-kept"));
    }

    struct Rig {
        injector: Arc<Injector>,
        log: Arc<dyn SessionLog>,
        got: Arc<Mutex<Vec<Got>>>,
    }

    async fn rig_with(answer: Answer, plan: InjectPlan, log: Arc<dyn SessionLog>) -> Rig {
        let (origin, got) = upstream(answer).await;
        let credentials = Arc::new(ProxyCredentials::new(
            HashMap::from([("github-token".to_string(), VaultSecret::new(SECRET.into()))]),
            None,
        ));
        let injector = Arc::new(Injector {
            plan,
            agent_id: "agent-1".into(),
            server: "github".into(),
            pin: ServerPin {
                server: "github".into(),
                entry: "sha256:aa".into(),
            },
            credentials,
            audit: Some(log.clone()),
            upstream: Upstream::at(origin),
        });
        Rig { injector, log, got }
    }

    async fn rig(answer: Answer) -> Rig {
        rig_with(
            answer,
            plan(),
            Arc::new(SqliteSessionLog::open_in_memory().unwrap()),
        )
        .await
    }

    impl Rig {
        /// Send `raw` as the server would and return the whole answer.
        async fn send(&self, raw: &str) -> String {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let injector = self.injector.clone();
            let served = tokio::spawn(async move { injector.serve(Box::new(server)).await });
            client.write_all(raw.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client.read_to_end(&mut answer),
            )
            .await;
            drop(client);
            let _ = served.await;
            String::from_utf8_lossy(&answer).into_owned()
        }

        fn rows(&self) -> Vec<SessionEvent> {
            let handle: SessionHandle<OwnSession> =
                self.log.handle_for(SessionId::new(MCP_SENTINEL_SESSION));
            self.log
                .get_since(&handle, 0)
                .unwrap()
                .into_iter()
                .map(|row: StoredSessionEvent| row.event)
                .collect()
        }

        fn injected(&self) -> Vec<(String, String)> {
            self.rows()
                .into_iter()
                .filter_map(|e| match e {
                    SessionEvent::McpCredentialInjected {
                        server_name,
                        agent_id,
                        credential,
                        host,
                        method,
                        path,
                        exchanged_for,
                    } => {
                        assert_eq!(exchanged_for, None);
                        assert_eq!(
                            (server_name.as_str(), agent_id.as_str()),
                            ("github", "agent-1")
                        );
                        assert_eq!(
                            (credential.as_str(), host.as_str()),
                            ("github-token", "api.github.com")
                        );
                        Some((method, path))
                    }
                    _ => None,
                })
                .collect()
        }

        fn refused(&self) -> Vec<(String, String, McpInjectRefusal)> {
            self.rows()
                .into_iter()
                .filter_map(|e| match e {
                    SessionEvent::McpInjectRefused {
                        method,
                        path,
                        reason,
                        ..
                    } => Some((method, path, reason)),
                    _ => None,
                })
                .collect()
        }

        fn got(&self) -> Vec<Got> {
            self.got.lock().unwrap().clone()
        }

        /// No row carries the credential's value.
        fn assert_no_value_in_rows(&self) {
            let rows = serde_json::to_string(&self.rows()).unwrap();
            assert!(!rows.contains(SECRET), "{rows}");
        }
    }

    fn get(target: &str) -> String {
        format!(
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:3180\r\n\
             Authorization: Bearer {PLACEHOLDER}\r\nConnection: close\r\n\r\n"
        )
    }

    /// The header the server sent is dropped and the vault value set in
    /// its place; `Host` is the upstream's; the path is mapped and the
    /// query kept. A placeholder in the body or another header arrives
    /// as it was sent. One row, with the path and no query or value.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn the_credential_header_is_set_and_nothing_else_is_substituted() {
        let rig = rig(|_, _| ok("{\"data\":1}")).await;
        let body = format!("{{\"query\":\"{PLACEHOLDER}\"}}");
        let answer = rig
            .send(&format!(
                "POST /api/graphql?x={PLACEHOLDER} HTTP/1.1\r\nHost: 127.0.0.1:3180\r\n\
                 Authorization: Bearer {PLACEHOLDER}\r\nX-Other: {PLACEHOLDER}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ))
            .await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.ends_with("{\"data\":1}"), "{answer}");

        let got = rig.got();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].method, "POST");
        assert_eq!(got[0].target, format!("/graphql?x={PLACEHOLDER}"));
        assert_eq!(
            got[0].header("authorization"),
            Some(format!("Bearer {SECRET}").as_str())
        );
        assert_eq!(got[0].header("x-other"), Some(PLACEHOLDER));
        assert_eq!(got[0].body, body.as_bytes());
        assert_ne!(got[0].header("host"), Some("127.0.0.1:3180"));
        assert!(got[0].header("connection").is_none_or(|c| c != "close"));

        assert_eq!(
            rig.injected(),
            [("POST".to_string(), "/graphql".to_string())]
        );
        assert!(rig.refused().is_empty());
        rig.assert_no_value_in_rows();
    }

    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_prefix_rule_maps_the_path_and_keeps_the_query() {
        let rig = rig(|_, _| ok("[]")).await;
        let answer = rig
            .send(&get("/api/v3/repos/o/r/commits?page=2&per_page=3"))
            .await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert_eq!(rig.got()[0].target, "/repos/o/r/commits?page=2&per_page=3");
        assert_eq!(
            rig.injected(),
            [("GET".to_string(), "/repos/o/r/commits".to_string())]
        );
    }

    /// Each request the forwarder turns away: the server gets a terse
    /// 4xx, the upstream is never asked, and one row says why.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn each_refused_request_gets_a_row_and_reaches_nothing() {
        let cases: Vec<(String, &str, McpInjectRefusal)> = vec![
            (
                get("/raw/o/r/HEAD/f"),
                "404",
                McpInjectRefusal::UnmappedPath,
            ),
            (get("/api/uploads/x"), "404", McpInjectRefusal::UnmappedPath),
            (get("/api/v3/a/../b"), "400", McpInjectRefusal::PathShape),
            (get("/api/v3/%2e%2e/b"), "400", McpInjectRefusal::PathShape),
            (get("/api/v3/a%2Fb"), "400", McpInjectRefusal::PathShape),
            (
                get("http://api.github.com/api/v3/user"),
                "400",
                McpInjectRefusal::Malformed,
            ),
            (
                "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n".into(),
                "400",
                McpInjectRefusal::Malformed,
            ),
            (
                "GET /api/v3/user HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\n\r\n"
                    .into(),
                "400",
                McpInjectRefusal::Malformed,
            ),
        ];
        for (raw, status, reason) in cases {
            let rig = rig(|_, _| ok("never")).await;
            let answer = rig.send(&raw).await;
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {status} ")),
                "{raw:?} -> {answer:?}"
            );
            assert!(!answer.contains("never"));
            assert!(rig.got().is_empty(), "{raw:?} reached the upstream");
            let refused = rig.refused();
            assert_eq!(refused.len(), 1, "{raw:?}");
            assert_eq!(refused[0].2, reason, "{raw:?}");
            assert!(rig.injected().is_empty());
        }
    }

    /// A head over the limit, and bytes that are not HTTP/1.1, are
    /// turned away with a row that names no method or path.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_head_that_is_too_long_or_not_http1_is_refused_with_a_row() {
        let long = format!(
            "GET /api/v3/user HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(2 * MAX_HEAD)
        );
        for raw in [long.as_str(), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"] {
            let rig = rig(|_, _| ok("never")).await;
            let answer = rig.send(raw).await;
            assert!(!answer.contains("never"));
            assert!(rig.got().is_empty());
            assert_eq!(
                rig.refused(),
                [(String::new(), String::new(), McpInjectRefusal::Malformed)]
            );
        }
    }

    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_credential_the_proxy_does_not_hold_for_the_entry_is_not_sent() {
        let (origin, got) = upstream(|_, _| ok("never")).await;
        let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let pin = ServerPin {
            server: "github".into(),
            entry: "sha256:aa".into(),
        };
        // Handed over for another entry only.
        let credentials = Arc::new(
            ProxyCredentials::new(
                HashMap::from([("github-token".to_string(), VaultSecret::new(SECRET.into()))]),
                None,
            )
            .with_pins(HashMap::from([(
                "github-token".to_string(),
                std::collections::BTreeSet::from([ServerPin {
                    server: "github".into(),
                    entry: "sha256:bb".into(),
                }]),
            )])),
        );
        let rig = Rig {
            injector: Arc::new(Injector {
                plan: plan(),
                agent_id: "agent-1".into(),
                server: "github".into(),
                pin,
                credentials,
                audit: Some(log.clone()),
                upstream: Upstream::at(origin),
            }),
            log,
            got,
        };
        let answer = rig.send(&get("/api/v3/user")).await;
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(rig.got().is_empty());
        assert_eq!(rig.refused()[0].2, McpInjectRefusal::CredentialUnavailable);
    }

    /// A GET redirect that stays on the bound host and inside the path
    /// map is followed with the credential, one row per request, and
    /// the final response is what the server gets.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_same_host_get_redirect_is_followed_with_a_row_for_each_request() {
        let rig = rig(|request, origin| {
            if request.target.starts_with("/repos/old/name") {
                redirect(
                    "301 Moved Permanently",
                    &format!("{origin}/repositories/7?page=2"),
                )
            } else {
                ok("moved-here")
            }
        })
        .await;
        let answer = rig.send(&get("/api/v3/repos/old/name?page=2")).await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.ends_with("moved-here"));
        let got = rig.got();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].target, "/repositories/7?page=2");
        assert_eq!(
            got[1].header("authorization"),
            Some(format!("Bearer {SECRET}").as_str())
        );
        assert_eq!(
            rig.injected(),
            [
                ("GET".to_string(), "/repos/old/name".to_string()),
                ("GET".to_string(), "/repositories/7".to_string()),
            ]
        );
    }

    /// What is not followed goes back to the server as it came: a
    /// redirect off the bound host, one answering a POST, and one whose
    /// target the path map cannot produce.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn other_redirects_are_returned_to_the_server() {
        // Off the bound host.
        let rig = rig(|_, _| redirect("302 Found", "https://blob.example/signed?sig=1")).await;
        let answer = rig
            .send(&get("/api/v3/repos/o/r/actions/jobs/1/logs"))
            .await;
        assert!(answer.starts_with("HTTP/1.1 302 "), "{answer}");
        assert!(
            answer
                .to_ascii_lowercase()
                .contains("location: https://blob.example/signed?sig=1"),
            "{answer}"
        );
        assert_eq!(rig.got().len(), 1);

        // A POST.
        let rig = rig_post_redirect().await;
        let answer = rig
            .send(
                "POST /api/v3/repos/old/name/issues HTTP/1.1\r\nHost: x\r\n\
                 Content-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await;
        assert!(answer.starts_with("HTTP/1.1 307 "), "{answer}");
        assert_eq!(rig.got().len(), 1);

        // A target outside the path map.
        let exact_only = InjectPlan::new(
            &SandboxInject {
                paths: vec![InjectPath {
                    from: "/api/graphql".into(),
                    to: "/graphql".into(),
                }],
                ..block()
            },
            &env(),
            &[],
        )
        .unwrap();
        let rig = rig_with(
            |_, origin| redirect("301 Moved Permanently", &format!("{origin}/elsewhere")),
            exact_only,
            Arc::new(SqliteSessionLog::open_in_memory().unwrap()),
        )
        .await;
        let answer = rig.send(&get("/api/graphql")).await;
        assert!(answer.starts_with("HTTP/1.1 301 "), "{answer}");
        assert_eq!(rig.got().len(), 1);
    }

    async fn rig_post_redirect() -> Rig {
        rig(|_, origin| {
            redirect(
                "307 Temporary Redirect",
                &format!("{origin}/repositories/7/issues"),
            )
        })
        .await
    }

    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn at_most_three_redirects_are_followed() {
        let rig = rig(|_, origin| redirect("302 Found", &format!("{origin}/loop"))).await;
        let answer = rig.send(&get("/api/v3/loop")).await;
        assert!(answer.starts_with("HTTP/1.1 302 "), "{answer}");
        assert_eq!(rig.got().len(), 1 + MAX_REDIRECTS);
        assert_eq!(rig.injected().len(), 1 + MAX_REDIRECTS);
    }

    /// A response whose head carries the credential's exact bytes does
    /// not reach the server.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_response_head_that_carries_the_credential_is_refused() {
        let rig = rig(|request, _| {
            format!(
                "HTTP/1.1 200 OK\r\nX-Echo: {}\r\nContent-Length: 2\r\n\r\nok",
                request.header("authorization").unwrap_or_default()
            )
        })
        .await;
        let answer = rig.send(&get("/api/v3/user")).await;
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(!answer.contains(SECRET));
        assert_eq!(
            rig.refused(),
            [(
                "GET".to_string(),
                "/user".to_string(),
                McpInjectRefusal::CredentialInResponse
            )]
        );
        rig.assert_no_value_in_rows();
    }

    /// A log that takes refusals and no injection row.
    struct NoInjectionRows(Arc<dyn SessionLog>);

    impl SessionLog for NoInjectionRows {
        fn handle_for(&self, id: SessionId) -> SessionHandle<OwnSession> {
            self.0.handle_for(id)
        }
        fn append(
            &self,
            handle: &SessionHandle<OwnSession>,
            trust: TrustLevel,
            event: SessionEvent,
        ) -> Result<u64, wirken_audit::AuditError> {
            if matches!(event, SessionEvent::McpCredentialInjected { .. }) {
                return Err(wirken_audit::AuditError::ChannelClosed);
            }
            self.0.append(handle, trust, event)
        }
        fn get_range(
            &self,
            handle: &SessionHandle<OwnSession>,
            range: std::ops::Range<u64>,
        ) -> Result<Vec<StoredSessionEvent>, wirken_audit::AuditError> {
            self.0.get_range(handle, range)
        }
        fn get_since(
            &self,
            handle: &SessionHandle<OwnSession>,
            start: u64,
        ) -> Result<Vec<StoredSessionEvent>, wirken_audit::AuditError> {
            self.0.get_since(handle, start)
        }
        fn last_index(
            &self,
            handle: &SessionHandle<OwnSession>,
        ) -> Result<Option<u64>, wirken_audit::AuditError> {
            self.0.last_index(handle)
        }
        fn rewind(
            &self,
            handle: &SessionHandle<OwnSession>,
            n_before: u64,
            reason: &str,
        ) -> Result<u64, wirken_audit::AuditError> {
            self.0.rewind(handle, n_before, reason)
        }
        fn verify(
            &self,
            handle: &SessionHandle<OwnSession>,
        ) -> Result<wirken_audit::SessionVerifyResult, wirken_audit::AuditError> {
            self.0.verify(handle)
        }
    }

    /// A request whose row does not land is not made.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_request_that_cannot_be_recorded_is_not_made() {
        let log: Arc<dyn SessionLog> = Arc::new(NoInjectionRows(Arc::new(
            SqliteSessionLog::open_in_memory().unwrap(),
        )));
        let rig = rig_with(|_, _| ok("never"), plan(), log).await;
        let answer = rig.send(&get("/api/v3/user")).await;
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(rig.got().is_empty());
        assert_eq!(rig.refused()[0].2, McpInjectRefusal::RecordFailed);
    }

    /// The bound host's client takes only global-unicast addresses, so
    /// a name that resolves to loopback is not connected to.
    #[cfg_attr(miri, ignore = "opens a socket; miri has no I/O")]
    #[tokio::test]
    async fn a_bound_host_that_resolves_to_loopback_is_not_reached() {
        let upstream = Upstream::https("localhost").unwrap();
        let err = upstream
            .client
            .get("https://localhost/")
            .send()
            .await
            .unwrap_err();
        assert!(error_is::<NoGlobalAddress>(&err), "{err:?}");
    }

    #[test]
    fn a_placeholder_is_long_enough_to_be_matched_and_differs_each_time() {
        let (a, b) = (new_placeholder(), new_placeholder());
        assert_ne!(a, b);
        assert!(a.len() >= 24);
    }
}
