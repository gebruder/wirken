//! The `http_request` built-in tool: a scoped outbound HTTPS request
//! that attaches a vault-held credential the model never sees.
//!
//! Spec: `docs/design/http-request-tool.md`. The gating (tools.allow,
//! credentials.allow, http.post_paths) is enforced in `runtime.rs`
//! before dispatch; the egress allowlist is enforced in-flight by
//! [`crate::egress::EgressClient`]. This module owns the request
//! construction, credential injection, redaction, response cap, and the
//! audit row.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use serde_json::json;
use wirken_audit::{OwnSession, SessionEvent, SessionHandle, SessionLog, TrustLevel};

use crate::egress::{EgressClient, HttpAccessDenied};
use crate::error::AgentError;
use crate::tool::ToolResult;

/// Max response-body bytes buffered for `http_request`. Tighter than
/// the 32 MiB `read_capped` used by `web_search` because the body is
/// returned into model context; on overflow it truncates (and signals
/// truncation) rather than erroring.
pub const HTTP_TOOL_BODY_CAP: usize = 1024 * 1024;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 60_000;

/// A credential value resolved from the vault host-side. Deliberately
/// no `Debug`, `Display`, `Serialize`, or `Clone`: it cannot be logged,
/// formatted into a tool result, serialized into an audit payload, or
/// copied by accident. Mirrors `wirken_vault::VaultSecret`.
pub struct ResolvedSecret(String);

impl ResolvedSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    /// Short-lived borrow of the plaintext. The only caller sets the
    /// `Authorization` header and drops the borrow.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Host-side resolver for a named vault credential, injected into the
/// tool registry so the agent crate does not depend on the vault crate.
/// The CLI implements this over `wirken_vault::CredentialStore`; tests
/// inject a fake.
///
/// `host` is the request's target host. The resolver MUST enforce the
/// credential's own host binding against it and refuse
/// (`HostNotPermitted`) when the credential is not bound to that host.
/// This is the load-bearing control: the binding lives in vault metadata
/// set by the operator, so a skill's own permissions block can never
/// widen where a secret may travel.
pub trait CredentialResolver: Send + Sync {
    fn resolve(&self, name: &str, host: &str) -> Result<ResolvedSecret, CredentialError>;
}

#[derive(Debug)]
pub enum CredentialError {
    NotFound(String),
    /// The credential exists but is not bound to the request's host.
    HostNotPermitted {
        name: String,
        host: String,
    },
    Backend(String),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Names and hosts, never secret values.
            CredentialError::NotFound(name) => write!(f, "vault slot '{name}' not found"),
            CredentialError::HostNotPermitted { name, host } => write!(
                f,
                "vault slot '{name}' is not bound to host '{host}' \
                 (bind it with `wirken credential add --host {host}`)"
            ),
            CredentialError::Backend(msg) => write!(f, "vault error: {msg}"),
        }
    }
}

/// Audit context for the `http_request` row, built from the agent's own
/// session log + handle + id and pushed into the registry at attach
/// time. The registry has no session log of its own.
#[derive(Clone)]
pub struct HttpAuditCtx {
    pub log: Arc<dyn SessionLog>,
    pub handle: SessionHandle<OwnSession>,
    pub agent_id: String,
}

/// Execute one `http_request` tool call.
///
/// Preconditions enforced upstream by `runtime.rs`: `tools.allow`
/// contains `http_request`; if `credential` is set it is in
/// `credentials.allow`; if method is POST the URL is a declared
/// `http.post_paths` endpoint. This function still independently
/// validates the method and URL (defense in depth) but trusts those
/// scope decisions.
pub async fn execute(
    http: &EgressClient,
    resolver: Option<&Arc<dyn CredentialResolver>>,
    audit: Option<&HttpAuditCtx>,
    args: &serde_json::Value,
) -> Result<ToolResult, AgentError> {
    let method_str = args["method"]
        .as_str()
        .ok_or_else(|| AgentError::Tool("missing 'method' argument".into()))?;
    let method = match parse_method(method_str) {
        Ok(m) => m,
        Err(e) => return Ok(fail(e)),
    };

    let url_str = args["url"]
        .as_str()
        .ok_or_else(|| AgentError::Tool("missing 'url' argument".into()))?;
    let url = match validate_url(url_str) {
        Ok(u) => u,
        Err(e) => return Ok(fail(e)),
    };

    // Model-supplied headers. An Authorization / Proxy-Authorization
    // header is refused, not silently stripped: only the vault-resolved
    // credential sets that header, and the model's attempt fails loudly.
    let mut header_pairs: Vec<(String, String)> = Vec::new();
    if let Some(obj) = args.get("headers").and_then(|h| h.as_object()) {
        for (k, v) in obj {
            if is_auth_header(k) {
                return Ok(fail(format!(
                    "the '{k}' header may not be set by the model; \
                     use the 'credential' field instead"
                )));
            }
            let val = v
                .as_str()
                .ok_or_else(|| AgentError::Tool(format!("header '{k}' must be a string")))?;
            header_pairs.push((k.clone(), val.to_string()));
        }
    }

    let body = args.get("body").and_then(|b| b.as_str());
    let credential = args
        .get("credential")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|t| t.as_u64())
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1, MAX_TIMEOUT_MS);

    // Resolve the credential host-side. The secret lives only in this
    // `ResolvedSecret` and the header line built from it; it is never
    // stored on a struct, returned, logged, or audited.
    let resolved = match &credential {
        Some(name) => {
            let r = resolver.ok_or_else(|| {
                AgentError::Tool(
                    "no credential resolver configured; this wirken build cannot resolve \
                     vault credentials for http_request"
                        .into(),
                )
            })?;
            // The credential's own host binding is enforced here against
            // the request host, independent of the skill's egress
            // allowlist, so a skill cannot widen where the secret goes.
            match r.resolve(name, url.host_str().unwrap_or_default()) {
                Ok(secret) => Some(secret),
                Err(e) => return Ok(fail(format!("credential '{name}': {e}"))),
            }
        }
        None => None,
    };

    // Build through EgressClient: egress allowlist check + rate reserve
    // + no-redirect client. A non-allowlisted host returns EgressDenied,
    // which the runtime records as SkillPermissionDenied (a refusal, not
    // a prompt).
    let mut builder = http
        .request(method.clone(), url.as_str())
        .await
        .map_err(map_denied)?
        .timeout(Duration::from_millis(timeout_ms));

    for (k, v) in &header_pairs {
        builder = builder.header(k, v);
    }
    if method == Method::POST
        && let Some(b) = body
    {
        builder = builder.body(b.to_string());
    }
    // Inject the vault credential as the sole auth header, last.
    if let Some(secret) = &resolved {
        builder = builder.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", secret.expose()),
        );
    }

    let resp = match builder.send().await {
        Ok(r) => r,
        // reqwest's Display carries the URL (userinfo-free here) and the
        // transport kind, never request header values, so the secret
        // cannot appear in this message.
        Err(e) => return Ok(fail(format!("request failed: {e}"))),
    };

    let status = resp.status().as_u16();
    let resp_headers = collect_headers(resp.headers());
    let (body_bytes, truncated) = read_capped_truncating(resp).await?;
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();

    if let Some(ctx) = audit {
        ctx.log
            .append(
                &ctx.handle,
                TrustLevel::Tool,
                SessionEvent::HttpRequest {
                    method: method.as_str().to_string(),
                    host: url.host_str().unwrap_or_default().to_string(),
                    path: url.path().to_string(),
                    status,
                    credential: credential.clone(),
                    truncated,
                    agent_id: ctx.agent_id.clone(),
                },
            )
            .map_err(|e| AgentError::SessionLog(e.to_string()))?;
    }

    let output = json!({
        "status": status,
        "headers": resp_headers,
        "body": body_text,
        "truncated": truncated,
    })
    .to_string();
    Ok(ToolResult {
        output,
        success: (200..300).contains(&status),
    })
}

fn parse_method(s: &str) -> Result<Method, String> {
    match s.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "HEAD" => Ok(Method::HEAD),
        "POST" => Ok(Method::POST),
        other => Err(format!(
            "method '{other}' is not allowed; http_request permits GET, HEAD, POST"
        )),
    }
}

/// Parse + validate a request URL: absolute `https://`, a real host,
/// no userinfo, and not an IP literal. Matching against the allowlist
/// happens on the parsed host component, so the `user@host` trick
/// resolves to the real host (and is refused outright here anyway).
pub(crate) fn validate_url(raw: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw).map_err(|e| format!("invalid url: {e}"))?;
    if !scheme_permitted(&url) {
        return Err(format!(
            "scheme '{}' is not allowed; http_request requires https",
            url.scheme()
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("url must not contain a userinfo component (user:pass@host)".into());
    }
    match url.host() {
        None => Err("url has no host".into()),
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {
            Err("IP-literal hosts are not allowed; use a DNS hostname".into())
        }
        Some(url::Host::Domain(_)) => Ok(url),
    }
}

fn scheme_permitted(url: &url::Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    // Test-only seam: allow plain http to `localhost` so unit tests can
    // drive the full request path against a loopback listener without
    // standing up TLS. Production builds (no cfg(test)) permit https
    // only; this branch does not compile into the shipped binary.
    #[cfg(test)]
    if url.scheme() == "http" && url.host_str() == Some("localhost") {
        return true;
    }
    false
}

/// Pre-dispatch gate for `http_request` beyond `tools.allow`, called
/// from the runtime gate block: method must be GET/HEAD/POST (write
/// verbs refused), a POST must target a declared `http.post_paths`
/// endpoint, and a named `credential` must be in `credentials.allow`.
/// Returns `Some((axis, message))` to refuse, `None` to allow.
/// Unparseable args return `None`; the handler surfaces the parse error.
pub(crate) fn gate(
    perms: &crate::skill_perms::PhasedEffective,
    arguments: &str,
) -> Option<(&'static str, String)> {
    use crate::skill_perms::GateDecision;
    let raw = if arguments.is_empty() {
        "{}"
    } else {
        arguments
    };
    let args: serde_json::Value = serde_json::from_str(raw).ok()?;

    let method = args.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let method_up = method.to_ascii_uppercase();
    if !matches!(method_up.as_str(), "GET" | "HEAD" | "POST") {
        return Some((
            "http_method",
            format!("method '{method}' is not allowed; http_request permits GET, HEAD, POST"),
        ));
    }

    if method_up == "POST" {
        let allowed = args
            .get("url")
            .and_then(|u| u.as_str())
            .and_then(|s| url::Url::parse(s).ok())
            .as_ref()
            .is_some_and(|u| perms.allows_post_path(u));
        if !allowed {
            return Some((
                "http_post_path",
                "POST is only allowed to an endpoint declared in the skill's \
                 permissions.http.post_paths"
                    .to_string(),
            ));
        }
    }

    if let Some(cred) = args.get("credential").and_then(|c| c.as_str())
        && !matches!(perms.gate_credential(cred), GateDecision::Allow)
    {
        return Some((
            "credentials",
            format!("credential '{cred}' is not in the skill's permissions.credentials.allow"),
        ));
    }

    None
}

fn is_auth_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("proxy-authorization")
}

fn collect_headers(
    headers: &reqwest::header::HeaderMap,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (name, value) in headers {
        if is_auth_header(name.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.insert(
                name.as_str().to_string(),
                serde_json::Value::String(v.to_string()),
            );
        }
    }
    out
}

async fn read_capped_truncating(resp: reqwest::Response) -> Result<(Vec<u8>, bool), AgentError> {
    use futures_util::StreamExt as _;
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AgentError::Tool(format!("read response chunk: {e}")))?;
        let remaining = HTTP_TOOL_BODY_CAP.saturating_sub(buf.len());
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((buf, truncated))
}

fn map_denied(e: HttpAccessDenied) -> AgentError {
    match e {
        HttpAccessDenied::Egress(d) => AgentError::EgressDenied(d),
        HttpAccessDenied::RateLimit(d) => AgentError::Tool(format!("{d}")),
    }
}

fn fail(msg: impl Into<String>) -> ToolResult {
    ToolResult {
        output: msg.into(),
        success: false,
    }
}
