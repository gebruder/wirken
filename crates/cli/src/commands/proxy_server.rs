//! The inference proxy listener.
//!
//! A client Wirken does not run sets its model base URL to this
//! listener and sends what it would send its provider: an OpenAI chat
//! completion (`POST /v1/chat/completions`) or an Anthropic message
//! (`POST /v1/messages`), streamed or not. It authenticates with a
//! token issued by `wirken proxy token issue`.
//!
//! A request that passes the token's checks is forwarded as it is, in
//! its own shape, to one of the upstreams in `proxy.json`, through the
//! provider client agent calls use ([`LlmClient::forward`]). The
//! provider's key is read from the vault for that call and put on the
//! outgoing request; the client never has it. The provider's response
//! goes back byte for byte.
//!
//! Every forwarded call is two rows on the token's lane: a
//! `ProxyRequest` before it is sent and a `ProxyResponse` once it has
//! been answered, each with the hash of the body as exchanged. Every
//! refusal is a `ProxyRefused` row.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use wirken_agent::llm::{LlmClient, LlmConfig, ProviderKeySource, provider_speaks};
use wirken_audit::{
    HashHex, PROXY_SESSION, ProxyRefusal, ProxyShape, SessionEvent, SessionId, SessionLog,
    TrustLevel, proxy_session,
};
use wirken_gateway::budget::{BudgetStore, now_unix_secs};
use wirken_gateway::leak::LeakMatcher;
use wirken_gateway::proxy::{ProxyToken, ProxyTokenStore, TokenCheck, Upstream, is_name};

/// The header a client may send to name the session its calls belong
/// to. Calls with the same token and label share a lane.
pub const SESSION_HEADER: &str = "x-wirken-session";

/// The most of a non-streamed response kept to read its token counts.
const USAGE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Response headers that describe one connection and are not passed on.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Which body of an exchange an archived object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Request,
    Response,
}

impl BodyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// Where full bodies are written, when the operator configured it.
#[async_trait::async_trait]
pub trait BodySink: Send + Sync {
    /// Keep `body`, whose SHA-256 is `sha256`, so the row carrying that
    /// hash finds it.
    async fn put(&self, kind: BodyKind, sha256: &str, body: &[u8]) -> Result<(), String>;
}

/// One configured upstream, ready to forward to.
pub struct UpstreamClient {
    pub upstream: Upstream,
    pub client: LlmClient,
    /// Where the provider's key is read from on each call. `None` for
    /// an upstream that takes no key.
    pub key: Option<Arc<dyn ProviderKeySource>>,
}

impl UpstreamClient {
    /// The client for `upstream`, or why its endpoint cannot be used.
    pub fn new(
        upstream: Upstream,
        key: Option<Arc<dyn ProviderKeySource>>,
        leak: Arc<LeakMatcher>,
        idle: std::time::Duration,
    ) -> anyhow::Result<Self> {
        let mut client = LlmClient::new(LlmConfig::from_provider(
            &upstream.provider,
            &upstream.base_url,
            "",
        ))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        client.set_leak_matcher(leak);
        client
            .set_forward_idle_timeout(idle)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(key) = &key {
            client.set_key_source(key.clone());
        }
        Ok(Self {
            upstream,
            client,
            key,
        })
    }
}

/// Everything the listener works with.
pub struct ProxyState {
    pub max_body_bytes: u64,
    pub upstreams: BTreeMap<String, UpstreamClient>,
    pub tokens: ProxyTokenStore,
    pub log: Arc<dyn SessionLog>,
    /// The spend ledger. A token with a spend ceiling is refused when
    /// there is none.
    pub budget: Option<Arc<std::sync::Mutex<BudgetStore>>>,
    pub leak: Arc<LeakMatcher>,
    pub archive: Option<Arc<dyn BodySink>>,
    /// When the last refusal of an unknown token was recorded: at most
    /// one such row a second, so a stranger cannot fill the chain.
    pub last_unknown_row: std::sync::Mutex<Option<Instant>>,
}

type ReplyBody = UnsyncBoxBody<Bytes, std::io::Error>;

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An error answer in the shape the client speaks.
fn error_reply(
    status: StatusCode,
    shape: Option<ProxyShape>,
    kind: &str,
    message: &str,
) -> Response<ReplyBody> {
    let body = match shape {
        Some(ProxyShape::AnthropicMessages) => serde_json::json!({
            "type": "error",
            "error": { "type": kind, "message": message },
        }),
        _ => serde_json::json!({
            "error": { "message": message, "type": kind, "code": kind },
        }),
    };
    let mut reply = Response::new(
        Full::new(Bytes::from(body.to_string()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *reply.status_mut() = status;
    reply.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    reply
}

/// The token a client presented, from the header its SDK uses.
fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(value.trim().to_string());
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(|v| v.trim().to_string())
}

/// The token counts a provider reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    input: Option<u32>,
    output: Option<u32>,
    cache_read: Option<u32>,
    cache_creation: Option<u32>,
}

fn as_u32(value: &serde_json::Value) -> Option<u32> {
    value.as_u64().and_then(|n| u32::try_from(n).ok())
}

impl Counts {
    /// Take what a `usage` object says, in either provider's naming.
    /// A count already known is kept when this object has none.
    fn read(&mut self, usage: &serde_json::Value) {
        if !usage.is_object() {
            return;
        }
        let pick = |names: &[&str]| names.iter().find_map(|n| as_u32(&usage[*n]));
        if let Some(n) = pick(&["input_tokens", "prompt_tokens"]) {
            self.input = Some(n);
        }
        if let Some(n) = pick(&["output_tokens", "completion_tokens"]) {
            self.output = Some(n);
        }
        if let Some(n) = pick(&["cache_read_input_tokens"])
            .or_else(|| as_u32(&usage["prompt_tokens_details"]["cached_tokens"]))
        {
            self.cache_read = Some(n);
        }
        if let Some(n) = pick(&["cache_creation_input_tokens"]) {
            self.cache_creation = Some(n);
        }
    }

    /// Read one JSON value of a response: a whole non-streamed body, or
    /// the data of one stream event.
    fn read_value(&mut self, value: &serde_json::Value) {
        self.read(&value["usage"]);
        // Anthropic's first stream event carries the message.
        self.read(&value["message"]["usage"]);
    }
}

/// Reads token counts out of a response as it passes.
enum UsageReader {
    /// A JSON body, kept until it ends.
    Json(Vec<u8>),
    /// A server-sent event stream, read a line at a time.
    Sse { partial: Vec<u8>, counts: Counts },
}

impl UsageReader {
    fn for_content_type(content_type: Option<&str>) -> Self {
        if content_type.is_some_and(|c| c.starts_with("text/event-stream")) {
            Self::Sse {
                partial: Vec::new(),
                counts: Counts::default(),
            }
        } else {
            Self::Json(Vec::new())
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        match self {
            Self::Json(body) => {
                if body.len() + chunk.len() <= USAGE_BODY_BYTES {
                    body.extend_from_slice(chunk);
                }
            }
            Self::Sse { partial, counts } => {
                partial.extend_from_slice(chunk);
                while let Some(end) = partial.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = partial.drain(..=end).collect();
                    let line = String::from_utf8_lossy(&line);
                    if let Some(data) = line.trim_end().strip_prefix("data:")
                        && let Ok(value) = serde_json::from_str::<serde_json::Value>(data.trim())
                    {
                        counts.read_value(&value);
                    }
                }
                // A line that never ends is not kept forever.
                if partial.len() > USAGE_BODY_BYTES {
                    partial.clear();
                }
            }
        }
    }

    fn finish(self) -> Counts {
        match self {
            Self::Json(body) => {
                let mut counts = Counts::default();
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                    counts.read_value(&value);
                }
                counts
            }
            Self::Sse { counts, .. } => counts,
        }
    }
}

/// What a call cost, where the pricing table has the model. The two
/// providers count cached input differently: one inside the prompt
/// count, one beside it.
fn cost_micros(provider: &str, model: &str, shape: ProxyShape, counts: Counts) -> Option<u64> {
    let (input, output) = (counts.input?, counts.output.unwrap_or(0));
    let cache_read = counts.cache_read.unwrap_or(0);
    let input = match shape {
        ProxyShape::OpenaiChat => input.saturating_sub(cache_read),
        ProxyShape::AnthropicMessages => input,
    };
    wirken_audit::pricing::cost_micros_cached(
        provider,
        model,
        input,
        output,
        counts.cache_creation.unwrap_or(0),
        cache_read,
    )
    .2
}

/// One forwarded call, from the request row to the response row.
struct Exchange {
    state: Arc<ProxyState>,
    session: String,
    request_id: String,
    token: ProxyToken,
    provider: String,
    model: String,
    shape: ProxyShape,
    started: Instant,
    status: u16,
    hasher: Sha256,
    bytes: u64,
    usage: UsageReader,
    /// The whole body, kept only when it is archived.
    body: Option<Vec<u8>>,
    /// The length the provider declared for its answer, when it did.
    expected: Option<u64>,
}

impl Exchange {
    fn feed(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
        self.usage.feed(chunk);
        if let Some(body) = &mut self.body {
            body.extend_from_slice(chunk);
        }
    }

    /// Record the answer: archive it, charge the token, write the row.
    async fn finish(self, complete: bool) {
        let sha256 = hex(&self.hasher.finalize());
        let counts = self.usage.finish();
        let cost = cost_micros(&self.provider, &self.model, self.shape, counts);
        let mut archived = false;
        if let (Some(archive), Some(body)) = (&self.state.archive, &self.body) {
            match archive.put(BodyKind::Response, &sha256, body).await {
                Ok(()) => archived = true,
                Err(e) => tracing::error!(
                    token = %self.token.id,
                    request_id = %self.request_id,
                    "proxy: the {} body was not archived: {e}",
                    BodyKind::Response.as_str()
                ),
            }
        }
        if let (Some(micros), Some(budget)) = (cost, &self.state.budget)
            && micros > 0
        {
            let window = self.token.window.window_start(now_unix_secs());
            let charged = budget
                .lock()
                .map_err(|_| "ledger mutex poisoned".to_string())
                .and_then(|b| {
                    b.add_spend(&self.token.budget_key(), window, micros)
                        .map_err(|e| e.to_string())
                });
            if let Err(e) = charged {
                tracing::error!(token = %self.token.id, "proxy: spend not recorded: {e}");
            }
        }
        let row = SessionEvent::ProxyResponse {
            request_id: self.request_id.clone(),
            token_id: self.token.id.clone(),
            status: self.status,
            latency_ms: self.started.elapsed().as_millis() as u64,
            input_tokens: counts.input,
            output_tokens: counts.output,
            cache_read_input_tokens: counts.cache_read,
            cache_creation_input_tokens: counts.cache_creation,
            total_cost_usd_micros: cost,
            response_sha256: HashHex(sha256),
            response_bytes: self.bytes,
            complete,
            archived,
        };
        if let Err(e) = self.state.record(&self.session, row) {
            tracing::error!(
                token = %self.token.id,
                request_id = %self.request_id,
                "proxy: the response row was not written: {e}"
            );
        }
    }
}

/// Holds an [`Exchange`] while its response is streamed. If the stream
/// is dropped before it ends, because the client went away, what was
/// exchanged up to then is still recorded.
struct Open(Option<Exchange>);

impl Drop for Open {
    fn drop(&mut self) {
        if let Some(exchange) = self.0.take() {
            tokio::spawn(exchange.finish(false));
        }
    }
}

impl ProxyState {
    fn record(&self, session: &str, event: SessionEvent) -> Result<(), String> {
        let handle = self.log.handle_for(SessionId::new(session.to_string()));
        self.log
            .append(&handle, TrustLevel::System, event)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Record a refusal and build the answer. The message says what
    /// was refused and why; nothing was forwarded.
    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &self,
        session: &str,
        token: Option<&ProxyToken>,
        shape: Option<ProxyShape>,
        model: Option<&str>,
        reason: ProxyRefusal,
        status: StatusCode,
        message: &str,
    ) -> Response<ReplyBody> {
        tracing::warn!(
            token = token.map(|t| t.id.as_str()).unwrap_or("none"),
            reason = reason.as_str(),
            "proxy: request refused: {message}"
        );
        let record = match (token, reason) {
            // A stranger's requests are rows too, but not one each.
            (None, _) => {
                let mut last = self
                    .last_unknown_row
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let due = last.is_none_or(|at| at.elapsed().as_secs() >= 1);
                if due {
                    *last = Some(Instant::now());
                }
                due
            }
            _ => true,
        };
        if record
            && let Err(e) = self.record(
                session,
                SessionEvent::ProxyRefused {
                    token_id: token.map(|t| t.id.clone()),
                    shape,
                    model: model.map(str::to_string),
                    reason,
                },
            )
        {
            tracing::error!("proxy: refusal not recorded: {e}");
        }
        error_reply(status, shape, reason.as_str(), message)
    }

    /// The first of the token's upstreams that takes `shape`.
    fn upstream_for(
        &self,
        token: &ProxyToken,
        shape: ProxyShape,
    ) -> Option<(&str, &UpstreamClient)> {
        token.upstreams.iter().find_map(|name| {
            let (name, upstream) = self.upstreams.get_key_value(name)?;
            provider_speaks(&upstream.upstream.provider, shape).then_some((name.as_str(), upstream))
        })
    }

    /// Why the token may not make another call in this window, if it
    /// may not. A ledger that cannot be read refuses the call.
    fn over_budget(&self, token: &ProxyToken, provider: &str, model: &str) -> Option<String> {
        let window = token.window.window_start(now_unix_secs());
        if let Some(ceiling) = token.ceiling_calls {
            match self.tokens.window_calls(&token.id, window) {
                Ok(calls) if calls < ceiling => {}
                Ok(calls) => {
                    return Some(format!(
                        "token {} has made {calls} of its {ceiling} calls this {}",
                        token.name,
                        token.window.label()
                    ));
                }
                Err(e) => return Some(format!("the call count could not be read: {e}")),
            }
        }
        if let Some(ceiling) = token.ceiling_usd_micros {
            if !wirken_audit::pricing::is_priced(provider, model) {
                return Some(format!(
                    "token {} has a spend ceiling and {provider}/{model} has no price, so its \
                     calls cannot be counted against it",
                    token.name
                ));
            }
            let spent = self
                .budget
                .as_ref()
                .ok_or_else(|| "there is no spend ledger".to_string())
                .and_then(|b| {
                    b.lock()
                        .map_err(|_| "ledger mutex poisoned".to_string())?
                        .window_spend(&token.budget_key(), window)
                        .map_err(|e| e.to_string())
                });
            match spent {
                Ok(spent) if spent < ceiling => {}
                Ok(spent) => {
                    return Some(format!(
                        "token {} has spent ${:.2} of its ${:.2} this {}",
                        token.name,
                        spent as f64 / 1e6,
                        ceiling as f64 / 1e6,
                        token.window.label()
                    ));
                }
                Err(e) => return Some(format!("the spend ledger could not be read: {e}")),
            }
        }
        None
    }

    /// Answer one request.
    async fn handle(self: &Arc<Self>, req: Request<Incoming>) -> Response<ReplyBody> {
        let shape = match (req.method(), req.uri().path()) {
            (&Method::POST, "/v1/chat/completions") => ProxyShape::OpenaiChat,
            (&Method::POST, "/v1/messages") => ProxyShape::AnthropicMessages,
            _ => {
                return error_reply(
                    StatusCode::NOT_FOUND,
                    None,
                    "not_found",
                    "this listener serves POST /v1/chat/completions and POST /v1/messages",
                );
            }
        };

        let token = match presented_token(req.headers()).map(|t| self.tokens.check(&t)) {
            Some(Ok(TokenCheck::Valid(token))) => token,
            Some(Ok(TokenCheck::Revoked(token))) => {
                return self.refuse(
                    &proxy_session(&token.id, None),
                    Some(&token),
                    Some(shape),
                    None,
                    ProxyRefusal::RevokedToken,
                    StatusCode::UNAUTHORIZED,
                    "this token was revoked",
                );
            }
            Some(Err(e)) => {
                tracing::error!("proxy: token store: {e}");
                return error_reply(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some(shape),
                    "unavailable",
                    "the token store could not be read",
                );
            }
            Some(Ok(TokenCheck::Unknown)) | None => {
                return self.refuse(
                    PROXY_SESSION,
                    None,
                    Some(shape),
                    None,
                    ProxyRefusal::UnknownToken,
                    StatusCode::UNAUTHORIZED,
                    "no valid Wirken proxy token: send one as a bearer token or as x-api-key",
                );
            }
        };

        let label = req
            .headers()
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|label| is_name(label));
        let session = proxy_session(&token.id, label);
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
            })
            .collect();

        let limit = usize::try_from(self.max_body_bytes).unwrap_or(usize::MAX);
        let body = match Limited::new(req.into_body(), limit).collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => {
                return self.refuse(
                    &session,
                    Some(&token),
                    Some(shape),
                    None,
                    ProxyRefusal::Malformed,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!(
                        "the request body is over {} bytes or could not be read",
                        self.max_body_bytes
                    ),
                );
            }
        };
        let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
        let Some(model) = parsed
            .as_ref()
            .and_then(|v| v["model"].as_str())
            .filter(|m| !m.is_empty())
            .map(str::to_string)
        else {
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                None,
                ProxyRefusal::Malformed,
                StatusCode::BAD_REQUEST,
                "the request body is not a JSON object with a model",
            );
        };
        let stream = parsed
            .as_ref()
            .and_then(|v| v["stream"].as_bool())
            .unwrap_or(false);

        let Some((upstream_name, upstream)) = self.upstream_for(&token, shape) else {
            let providers: Vec<String> = token
                .upstreams
                .iter()
                .filter_map(|name| {
                    let u = self.upstreams.get(name)?;
                    Some(format!("{name} ({})", u.upstream.provider))
                })
                .collect();
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                Some(&model),
                ProxyRefusal::ShapeNotSpoken,
                StatusCode::BAD_REQUEST,
                &format!(
                    "no upstream of token {} takes {} requests: {}. A request is forwarded in \
                     the shape it arrives in and is not translated",
                    token.name,
                    shape.as_str(),
                    if providers.is_empty() {
                        "none of its upstreams is configured".to_string()
                    } else {
                        providers.join(", ")
                    }
                ),
            );
        };
        let provider = upstream.upstream.provider.clone();

        if !token.allows_model(&model) {
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                Some(&model),
                ProxyRefusal::ModelNotAllowed,
                StatusCode::FORBIDDEN,
                &format!("token {} may not ask for model {model}", token.name),
            );
        }
        if let Some(why) = self.over_budget(&token, &provider, &model) {
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                Some(&model),
                ProxyRefusal::BudgetExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                &why,
            );
        }
        if let Some(credential) = self.leak.find(&String::from_utf8_lossy(&body)) {
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                Some(&model),
                ProxyRefusal::LeakRefused,
                StatusCode::BAD_REQUEST,
                &format!("the request carries the stored credential {credential}"),
            );
        }
        let key = match upstream.key.as_ref().map(|source| source.key()) {
            Some(Ok(key)) => Some(key),
            Some(Err(why)) => {
                return self.refuse(
                    &session,
                    Some(&token),
                    Some(shape),
                    Some(&model),
                    ProxyRefusal::CredentialRefused,
                    StatusCode::BAD_GATEWAY,
                    &format!("the key for upstream {upstream_name} is not usable: {why}"),
                );
            }
            None => None,
        };

        let request_sha256 = sha256_hex(&body);
        let mut archived = false;
        if let Some(archive) = &self.archive {
            if let Err(e) = archive.put(BodyKind::Request, &request_sha256, &body).await {
                return self.refuse(
                    &session,
                    Some(&token),
                    Some(shape),
                    Some(&model),
                    ProxyRefusal::ArchiveFailed,
                    StatusCode::BAD_GATEWAY,
                    &format!("the request could not be archived, so it was not sent: {e}"),
                );
            }
            archived = true;
        }

        let request_id = uuid::Uuid::new_v4().to_string();
        // The row first: nothing is forwarded that the chain does not
        // show.
        if let Err(e) = self.record(
            &session,
            SessionEvent::ProxyRequest {
                request_id: request_id.clone(),
                token_id: token.id.clone(),
                token_name: token.name.clone(),
                upstream: upstream_name.to_string(),
                provider: provider.clone(),
                model: model.clone(),
                shape,
                stream,
                request_sha256: HashHex(request_sha256),
                request_bytes: body.len() as u64,
                credential_id: upstream.key.as_ref().map(|k| k.credential().to_string()),
                archived,
            },
        ) {
            return self.refuse(
                &session,
                Some(&token),
                Some(shape),
                Some(&model),
                ProxyRefusal::RecordFailed,
                StatusCode::BAD_GATEWAY,
                &format!("the request could not be recorded, so it was not sent: {e}"),
            );
        }
        let window = token.window.window_start(now_unix_secs());
        if let Err(e) = self.tokens.add_call(&token.id, window) {
            tracing::error!(token = %token.id, "proxy: call not counted: {e}");
        }

        let mut exchange = Exchange {
            state: self.clone(),
            session,
            request_id,
            token,
            provider,
            model,
            shape,
            started: Instant::now(),
            status: StatusCode::BAD_GATEWAY.as_u16(),
            hasher: Sha256::new(),
            bytes: 0,
            usage: UsageReader::Json(Vec::new()),
            body: self.archive.as_ref().map(|_| Vec::new()),
            expected: None,
        };
        let response = match upstream
            .client
            .forward(shape, body.to_vec(), &headers, key.as_deref())
            .await
        {
            Ok(response) => response,
            Err(e) => {
                let message = format!("the request to upstream {upstream_name} failed: {e}");
                exchange.finish(false).await;
                return error_reply(StatusCode::BAD_GATEWAY, Some(shape), "upstream", &message);
            }
        };

        exchange.status = response.status().as_u16();
        exchange.expected = response.content_length();
        exchange.usage = UsageReader::for_content_type(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
        );
        let status = response.status();
        let mut reply_headers = HeaderMap::new();
        for (name, value) in response.headers() {
            if !HOP_BY_HOP.contains(&name.as_str()) {
                reply_headers.append(name.clone(), value.clone());
            }
        }
        let mut open = Open(Some(exchange));
        if open.0.as_ref().is_some_and(|e| e.expected == Some(0))
            && let Some(exchange) = open.0.take()
        {
            exchange.finish(true).await;
        }
        let stream = futures_util::stream::unfold(
            (response.bytes_stream(), open),
            |(mut upstream, mut open)| async move {
                open.0.as_ref()?;
                match upstream.next().await {
                    Some(Ok(chunk)) => {
                        if let Some(exchange) = &mut open.0 {
                            exchange.feed(&chunk);
                        }
                        // An answer of declared length ends here: the
                        // body is not polled again once it is all sent.
                        if open
                            .0
                            .as_ref()
                            .is_some_and(|e| e.expected.is_some_and(|n| e.bytes >= n))
                            && let Some(exchange) = open.0.take()
                        {
                            exchange.finish(true).await;
                        }
                        Some((Ok(Frame::data(chunk)), (upstream, open)))
                    }
                    Some(Err(e)) => {
                        if let Some(exchange) = open.0.take() {
                            exchange.finish(false).await;
                        }
                        Some((Err(std::io::Error::other(e)), (upstream, open)))
                    }
                    None => {
                        if let Some(exchange) = open.0.take() {
                            exchange.finish(true).await;
                        }
                        None
                    }
                }
            },
        );
        let mut reply = Response::new(BodyExt::boxed_unsync(StreamBody::new(stream)));
        *reply.status_mut() = status;
        *reply.headers_mut() = reply_headers;
        reply
    }
}

/// Serve the listener until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, state: Arc<ProxyState>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(|req| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(state.handle(req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(30))
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("proxy connection ended: {e}");
            }
        });
    }
}

/// Bind `addr` for the listener.
pub async fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wirken_audit::SqliteSessionLog;
    use wirken_gateway::budget::BudgetWindow;
    use wirken_gateway::proxy::{PROXY_TOKENS_FILE, TokenGrant};

    const PROVIDER_KEY: &str = "sk-provider-key-0123456789";

    /// How long a test listener waits for a provider's next bytes.
    const TEST_IDLE: std::time::Duration = std::time::Duration::from_millis(600);

    /// A provider's key, or the reason there is none.
    #[derive(Debug)]
    struct FixedKey(Result<String, String>);

    impl ProviderKeySource for FixedKey {
        fn credential(&self) -> &str {
            "provider-api-key"
        }
        fn key(&self) -> Result<String, String> {
            self.0.clone()
        }
    }

    /// A loopback provider: keeps each whole request and answers every
    /// one with `reply`, written in the pieces given.
    async fn provider(reply: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let got = Arc::new(Mutex::new(Vec::new()));
        let kept = got.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (kept, reply) = (kept.clone(), reply.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        let text = String::from_utf8_lossy(&buf).into_owned();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let length = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if body.len() >= length {
                                break;
                            }
                        }
                    }
                    kept.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf).into_owned());
                    for piece in reply {
                        if stream.write_all(piece.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        (base, got)
    }

    fn json_reply(body: &str) -> Vec<String> {
        vec![format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: req-1\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )]
    }

    /// One upstream of a test listener: its name, provider, base URL
    /// and what reading its key gives.
    type TestUpstream<'a> = (&'a str, &'a str, String, Option<Result<String, String>>);

    struct Rig {
        base: String,
        state: Arc<ProxyState>,
        log: Arc<SqliteSessionLog>,
        _tmp: tempfile::TempDir,
    }

    /// A listener over the given upstreams, `(name, provider, base_url,
    /// key)`.
    async fn rig(upstreams: Vec<TestUpstream<'_>>) -> Rig {
        rig_with(upstreams, None, None).await
    }

    async fn rig_with(
        upstreams: Vec<TestUpstream<'_>>,
        log: Option<Arc<dyn SessionLog>>,
        archive: Option<Arc<dyn BodySink>>,
    ) -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let sqlite = Arc::new(SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap());
        let leak = Arc::new(LeakMatcher::new());
        leak.learn(
            "stored-secret",
            "sk-stored-secret-0123456789",
            wirken_vault::CredentialKind::Secret,
        );
        let mut clients = BTreeMap::new();
        for (name, provider, base_url, key) in upstreams {
            let key = key.map(|k| Arc::new(FixedKey(k)) as Arc<dyn ProviderKeySource>);
            clients.insert(
                name.to_string(),
                UpstreamClient::new(
                    Upstream {
                        provider: provider.to_string(),
                        base_url,
                        credential: key.as_ref().map(|_| "provider-api-key".to_string()),
                    },
                    key,
                    leak.clone(),
                    TEST_IDLE,
                )
                .unwrap(),
            );
        }
        let state = Arc::new(ProxyState {
            max_body_bytes: 64 * 1024,
            upstreams: clients,
            tokens: ProxyTokenStore::open(&tmp.path().join(PROXY_TOKENS_FILE)).unwrap(),
            log: log.unwrap_or_else(|| sqlite.clone() as Arc<dyn SessionLog>),
            budget: Some(Arc::new(std::sync::Mutex::new(
                BudgetStore::open_in_memory().unwrap(),
            ))),
            leak,
            archive,
            last_unknown_row: std::sync::Mutex::new(None),
        });
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(serve(listener, state.clone()));
        Rig {
            base,
            state,
            log: sqlite,
            _tmp: tmp,
        }
    }

    impl Rig {
        fn issue(&self, name: &str, upstreams: &[&str]) -> (ProxyToken, String) {
            self.issue_with(TokenGrant {
                name: name.into(),
                upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            })
        }

        fn issue_with(&self, grant: TokenGrant) -> (ProxyToken, String) {
            self.state.tokens.issue(&grant).unwrap()
        }

        fn rows(&self, session: &str) -> Vec<SessionEvent> {
            let handle = self.log.handle_for(SessionId::new(session.to_string()));
            self.log
                .get_since(&handle, 0)
                .unwrap()
                .into_iter()
                .map(|r| r.event)
                .collect()
        }

        fn refusals(&self, session: &str) -> Vec<ProxyRefusal> {
            self.rows(session)
                .into_iter()
                .filter_map(|e| match e {
                    SessionEvent::ProxyRefused { reason, .. } => Some(reason),
                    _ => None,
                })
                .collect()
        }

        async fn post(&self, path: &str, token: &str, body: &str) -> reqwest::Response {
            reqwest::Client::new()
                .post(format!("{}{path}", self.base))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .unwrap()
        }
    }

    const CHAT: &str = "/v1/chat/completions";
    const MESSAGES: &str = "/v1/messages";

    /// An OpenAI-shaped call is forwarded byte for byte with the
    /// provider's key, the answer comes back byte for byte, and the two
    /// rows carry the hashes of exactly those bodies, the token's id
    /// and the provider's token counts. The client's token is not sent
    /// on, and the provider's key is not sent back.
    #[tokio::test]
    async fn a_chat_completion_is_forwarded_and_recorded_with_both_hashes() {
        let answer = "{ \"id\":\"c1\", \"choices\":[], \"usage\": {\"prompt_tokens\": 11, \"completion_tokens\": 7} }";
        let (upstream, got) = provider(json_reply(answer)).await;
        let rig = rig(vec![(
            "local",
            "custom",
            upstream,
            Some(Ok(PROVIDER_KEY.into())),
        )])
        .await;
        let (token, value) = rig.issue("laptop", &["local"]);

        let body = "{ \"model\": \"m1\",  \"messages\":[{\"role\":\"user\",\"content\":\"hi\"}] }";
        let response = rig.post(CHAT, &value, body).await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-request-id"], "req-1");
        let received = response.text().await.unwrap();
        assert_eq!(received, answer);
        assert!(!received.contains(PROVIDER_KEY));

        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let (head, sent) = got[0].split_once("\r\n\r\n").unwrap();
        assert_eq!(sent, body);
        assert!(head.starts_with("POST /v1/chat/completions "), "{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("authorization: bearer {PROVIDER_KEY}")),
            "{head}"
        );
        assert!(!got[0].contains(&value), "the client's token was forwarded");

        let rows = rig.rows(&proxy_session(&token.id, None));
        let [
            SessionEvent::ProxyRequest {
                request_id,
                token_id,
                token_name,
                upstream,
                provider,
                model,
                shape,
                stream,
                request_sha256,
                request_bytes,
                credential_id,
                archived,
            },
            SessionEvent::ProxyResponse {
                request_id: answered,
                status,
                input_tokens,
                output_tokens,
                response_sha256,
                response_bytes,
                complete,
                ..
            },
        ] = rows.as_slice()
        else {
            panic!("{rows:?}");
        };
        assert_eq!(request_id, answered);
        assert_eq!((token_id, token_name), (&token.id, &"laptop".to_string()));
        assert_eq!((upstream.as_str(), provider.as_str()), ("local", "custom"));
        assert_eq!(
            (model.as_str(), *shape, *stream),
            ("m1", ProxyShape::OpenaiChat, false)
        );
        assert_eq!(request_sha256.0, sha256_hex(body.as_bytes()));
        assert_eq!(*request_bytes, body.len() as u64);
        assert_eq!(credential_id.as_deref(), Some("provider-api-key"));
        assert!(!archived);
        assert_eq!(*status, 200);
        assert_eq!((*input_tokens, *output_tokens), (Some(11), Some(7)));
        assert_eq!(response_sha256.0, sha256_hex(answer.as_bytes()));
        assert_eq!(*response_bytes, answer.len() as u64);
        assert!(complete);
        let rows = serde_json::to_string(&rows).unwrap();
        assert!(
            !rows.contains(PROVIDER_KEY) && !rows.contains(&value),
            "{rows}"
        );
    }

    /// An Anthropic-shaped stream reaches the client event for event,
    /// the token arrives as `x-api-key` as that provider's SDK sends
    /// it, and the response row has the hash of every byte in order
    /// and the counts read out of the stream.
    #[tokio::test]
    async fn an_anthropic_stream_is_passed_through_and_its_usage_read() {
        let events = [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":4,\"output_tokens\":1}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ];
        let whole: String = events.concat();
        let mut reply = vec![
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
                .to_string(),
        ];
        // Split mid-event, so a line arrives in two pieces.
        let (first, second) = whole.split_at(whole.len() / 2 + 7);
        reply.push(first.to_string());
        reply.push(second.to_string());
        let (upstream, got) = provider(reply).await;
        let rig = rig(vec![(
            "messages",
            "anthropic",
            upstream,
            Some(Ok(PROVIDER_KEY.into())),
        )])
        .await;
        let (token, value) = rig.issue("ide", &["messages"]);

        let body = "{\"model\":\"m-large\",\"stream\":true,\"max_tokens\":64,\"messages\":[]}";
        let response = reqwest::Client::new()
            .post(format!("{}{MESSAGES}", rig.base))
            .header("x-api-key", &value)
            .header("anthropic-version", "2023-06-01")
            .header(SESSION_HEADER, "run-7")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.text().await.unwrap(), whole);

        let head = got.lock().unwrap()[0].to_ascii_lowercase();
        assert!(
            head.contains(&format!("x-api-key: {PROVIDER_KEY}")),
            "{head}"
        );
        assert!(head.contains("anthropic-version: 2023-06-01"), "{head}");
        assert!(head.starts_with("post /v1/messages "), "{head}");

        // The session label the client sent names the lane.
        let rows = rig.rows(&proxy_session(&token.id, Some("run-7")));
        assert!(rig.rows(&proxy_session(&token.id, None)).is_empty());
        let Some(SessionEvent::ProxyRequest { stream, shape, .. }) = rows.first() else {
            panic!("{rows:?}");
        };
        assert!(*stream);
        assert_eq!(*shape, ProxyShape::AnthropicMessages);
        let Some(SessionEvent::ProxyResponse {
            input_tokens,
            output_tokens,
            cache_read_input_tokens,
            response_sha256,
            response_bytes,
            complete,
            ..
        }) = rows.get(1)
        else {
            panic!("{rows:?}");
        };
        assert_eq!((*input_tokens, *output_tokens), (Some(25), Some(9)));
        assert_eq!(*cache_read_input_tokens, Some(4));
        assert_eq!(response_sha256.0, sha256_hex(whole.as_bytes()));
        assert_eq!(*response_bytes, whole.len() as u64);
        assert!(complete);
    }

    /// The provider's own error is the client's answer, recorded with
    /// its status.
    #[tokio::test]
    async fn a_provider_error_is_passed_back_and_recorded() {
        let (upstream, _) = provider(vec![
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\
             Content-Length: 16\r\nConnection: close\r\n\r\n{\"error\":\"slow\"}"
                .to_string(),
        ])
        .await;
        let rig = rig(vec![("local", "custom", upstream, None)]).await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 429);
        assert_eq!(response.text().await.unwrap(), "{\"error\":\"slow\"}");
        let rows = rig.rows(&proxy_session(&token.id, None));
        assert!(
            matches!(
                rows.get(1),
                Some(SessionEvent::ProxyResponse {
                    status: 429,
                    complete: true,
                    ..
                })
            ),
            "{rows:?}"
        );
    }

    /// A request with no token, a token nobody issued, or a revoked
    /// one is refused with a row and reaches no provider. A stranger's
    /// refusals are at most one row a second.
    #[tokio::test]
    async fn an_unknown_or_revoked_token_is_refused_with_a_row() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig(vec![("local", "custom", upstream, None)]).await;
        let (token, value) = rig.issue("laptop", &["local"]);

        for stranger in ["", "sk-not-ours", "wkp_deadbeef_00"] {
            let response = rig.post(CHAT, stranger, "{\"model\":\"m\"}").await;
            assert_eq!(response.status(), 401, "{stranger}");
        }
        let none = reqwest::Client::new()
            .post(format!("{}{CHAT}", rig.base))
            .body("{\"model\":\"m\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(none.status(), 401);
        assert_eq!(rig.refusals(PROXY_SESSION), [ProxyRefusal::UnknownToken]);

        rig.state.tokens.revoke("laptop").unwrap();
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 401);
        assert_eq!(
            rig.refusals(&proxy_session(&token.id, None)),
            [ProxyRefusal::RevokedToken]
        );
        assert!(got.lock().unwrap().is_empty());
    }

    /// A shape none of the token's upstreams takes is refused, and the
    /// answer names the shape and the providers. A token with an
    /// upstream for each shape reaches the right one for each.
    #[tokio::test]
    async fn a_shape_the_upstream_does_not_take_is_refused_by_name() {
        let (openai_like, got_openai) = provider(json_reply("{\"from\":\"openai\"}")).await;
        let (anthropic_like, got_anthropic) =
            provider(json_reply("{\"from\":\"anthropic\"}")).await;
        let (gemini_like, got_gemini) = provider(json_reply("{}")).await;
        let rig = rig(vec![
            ("chat", "custom", openai_like, None),
            ("messages", "anthropic", anthropic_like, None),
            ("google", "gemini", gemini_like, None),
        ])
        .await;

        let (only_chat, chat_token) = rig.issue("chat-only", &["chat"]);
        let response = rig.post(MESSAGES, &chat_token, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        // Refused in the shape the client speaks.
        assert_eq!(body["type"], "error");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains("anthropic_messages"), "{message}");
        assert!(message.contains("chat (custom)"), "{message}");
        assert!(message.contains("not translated"), "{message}");
        assert_eq!(
            rig.refusals(&proxy_session(&only_chat.id, None)),
            [ProxyRefusal::ShapeNotSpoken]
        );

        let (_, google_token) = rig.issue("google-only", &["google"]);
        for path in [CHAT, MESSAGES] {
            let response = rig.post(path, &google_token, "{\"model\":\"m\"}").await;
            assert_eq!(response.status(), 400, "{path}");
        }
        assert!(got_gemini.lock().unwrap().is_empty());

        let (_, both) = rig.issue("both", &["chat", "messages"]);
        let chat = rig.post(CHAT, &both, "{\"model\":\"m\"}").await;
        assert_eq!(chat.text().await.unwrap(), "{\"from\":\"openai\"}");
        let messages = rig.post(MESSAGES, &both, "{\"model\":\"m\"}").await;
        assert_eq!(messages.text().await.unwrap(), "{\"from\":\"anthropic\"}");
        assert_eq!(got_openai.lock().unwrap().len(), 1);
        assert_eq!(got_anthropic.lock().unwrap().len(), 1);
    }

    /// The token's model list, its call ceiling and its spend ceiling
    /// each refuse a call, with a row, before anything is sent.
    #[tokio::test]
    async fn a_tokens_model_list_and_ceilings_are_enforced() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig(vec![("local", "custom", upstream, None)]).await;

        let (listed, value) = rig.issue_with(TokenGrant {
            name: "listed".into(),
            upstreams: vec!["local".into()],
            models: vec!["m1".into()],
            ceiling_calls: Some(2),
            window: BudgetWindow::Hour,
            ..Default::default()
        });
        assert_eq!(
            rig.post(CHAT, &value, "{\"model\":\"m2\"}").await.status(),
            403
        );
        assert_eq!(
            rig.post(CHAT, &value, "{\"model\":\"m1\"}").await.status(),
            200
        );
        assert_eq!(
            rig.post(CHAT, &value, "{\"model\":\"m1\"}").await.status(),
            200
        );
        let third = rig.post(CHAT, &value, "{\"model\":\"m1\"}").await;
        assert_eq!(third.status(), 429);
        let message = third.text().await.unwrap();
        assert!(message.contains("2 of its 2 calls this hour"), "{message}");
        assert_eq!(
            rig.refusals(&proxy_session(&listed.id, None)),
            [ProxyRefusal::ModelNotAllowed, ProxyRefusal::BudgetExceeded]
        );
        assert_eq!(got.lock().unwrap().len(), 2);

        // A spend ceiling cannot count a model with no price.
        let (capped, value) = rig.issue_with(TokenGrant {
            name: "capped".into(),
            upstreams: vec!["local".into()],
            ceiling_usd_micros: Some(1_000_000),
            ..Default::default()
        });
        let refused = rig
            .post(CHAT, &value, "{\"model\":\"no-such-model\"}")
            .await;
        assert_eq!(refused.status(), 429);
        assert!(refused.text().await.unwrap().contains("has no price"));
        assert_eq!(
            rig.refusals(&proxy_session(&capped.id, None)),
            [ProxyRefusal::BudgetExceeded]
        );
        assert_eq!(got.lock().unwrap().len(), 2);
    }

    /// A spend ceiling that is reached refuses the next call.
    #[tokio::test]
    async fn a_reached_spend_ceiling_refuses_the_call() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig(vec![("local", "custom", upstream, None)]).await;
        let (token, _) = rig.issue_with(TokenGrant {
            name: "capped".into(),
            upstreams: vec!["local".into()],
            ceiling_usd_micros: Some(1_000_000),
            ..Default::default()
        });
        let window = token.window.window_start(now_unix_secs());
        rig.state
            .budget
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .add_spend(&token.budget_key(), window, 1_000_000)
            .unwrap();
        // Checked with a model the ledger can price, so only the spend
        // decides.
        let priced = wirken_audit::pricing::is_priced("custom", "m");
        let why = rig.state.over_budget(&token, "custom", "m").unwrap();
        if priced {
            assert!(why.contains("has spent $1.00 of its $1.00"), "{why}");
        } else {
            assert!(why.contains("has no price"), "{why}");
        }
        assert!(got.lock().unwrap().is_empty());
    }

    /// A body that is not a JSON object with a model, one over the
    /// size limit, and one carrying a stored secret are refused.
    #[tokio::test]
    async fn a_malformed_oversized_or_leaking_body_is_refused() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig(vec![("local", "custom", upstream, None)]).await;
        let (token, value) = rig.issue("laptop", &["local"]);

        for body in ["not json", "{}", "{\"model\":\"\"}", "[1]"] {
            assert_eq!(rig.post(CHAT, &value, body).await.status(), 400, "{body}");
        }
        let big = format!("{{\"model\":\"m\",\"pad\":\"{}\"}}", "a".repeat(80 * 1024));
        assert_eq!(rig.post(CHAT, &value, &big).await.status(), 413);
        let leaking =
            "{\"model\":\"m\",\"messages\":[{\"content\":\"sk-stored-secret-0123456789\"}]}";
        let response = rig.post(CHAT, &value, leaking).await;
        assert_eq!(response.status(), 400);
        let message = response.text().await.unwrap();
        assert!(message.contains("stored-secret"), "{message}");
        assert!(
            !message.contains("sk-stored-secret-0123456789"),
            "{message}"
        );

        let refusals = rig.refusals(&proxy_session(&token.id, None));
        assert_eq!(refusals.len(), 6, "{refusals:?}");
        assert_eq!(refusals[5], ProxyRefusal::LeakRefused);
        assert!(refusals[..5].iter().all(|r| *r == ProxyRefusal::Malformed));
        assert!(got.lock().unwrap().is_empty());
    }

    /// A provider key the vault will not give for this upstream stops
    /// the call: nothing is sent without it.
    #[tokio::test]
    async fn a_key_that_may_not_be_sent_refuses_the_call() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig(vec![(
            "cloud",
            "custom",
            upstream,
            Some(Err("it may no longer be sent to custom at https://x".into())),
        )])
        .await;
        let (token, value) = rig.issue("laptop", &["cloud"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 502);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("may no longer be sent")
        );
        assert_eq!(
            rig.refusals(&proxy_session(&token.id, None)),
            [ProxyRefusal::CredentialRefused]
        );
        assert!(got.lock().unwrap().is_empty());
    }

    /// A log that takes refusals and no request row.
    struct NoRequestRows(Arc<dyn SessionLog>);

    impl SessionLog for NoRequestRows {
        fn handle_for(
            &self,
            id: SessionId,
        ) -> wirken_audit::SessionHandle<wirken_audit::OwnSession> {
            self.0.handle_for(id)
        }
        fn append(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
            trust: TrustLevel,
            event: SessionEvent,
        ) -> Result<u64, wirken_audit::AuditError> {
            if matches!(event, SessionEvent::ProxyRequest { .. }) {
                return Err(wirken_audit::AuditError::ChannelClosed);
            }
            self.0.append(handle, trust, event)
        }
        fn get_range(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
            range: std::ops::Range<u64>,
        ) -> Result<Vec<wirken_audit::StoredSessionEvent>, wirken_audit::AuditError> {
            self.0.get_range(handle, range)
        }
        fn get_since(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
            start: u64,
        ) -> Result<Vec<wirken_audit::StoredSessionEvent>, wirken_audit::AuditError> {
            self.0.get_since(handle, start)
        }
        fn last_index(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
        ) -> Result<Option<u64>, wirken_audit::AuditError> {
            self.0.last_index(handle)
        }
        fn rewind(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
            n_before: u64,
            reason: &str,
        ) -> Result<u64, wirken_audit::AuditError> {
            self.0.rewind(handle, n_before, reason)
        }
        fn verify(
            &self,
            handle: &wirken_audit::SessionHandle<wirken_audit::OwnSession>,
        ) -> Result<wirken_audit::SessionVerifyResult, wirken_audit::AuditError> {
            self.0.verify(handle)
        }
    }

    /// A call whose request row cannot be written is not forwarded.
    #[tokio::test]
    async fn a_call_that_cannot_be_recorded_is_not_forwarded() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let inner: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
        let rig = rig_with(
            vec![("local", "custom", upstream, None)],
            Some(Arc::new(NoRequestRows(inner.clone()))),
            None,
        )
        .await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 502);
        assert!(got.lock().unwrap().is_empty());
        let handle = inner.handle_for(SessionId::new(proxy_session(&token.id, None)));
        let rows = inner.get_since(&handle, 0).unwrap();
        assert!(
            matches!(
                rows.as_slice(),
                [r] if matches!(r.event, SessionEvent::ProxyRefused { reason: ProxyRefusal::RecordFailed, .. })
            ),
            "{rows:?}"
        );
    }

    /// Keeps what it is given, or fails for one kind of body.
    #[derive(Default)]
    struct TestSink {
        fails: Option<BodyKind>,
        kept: Mutex<Vec<(BodyKind, String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl BodySink for TestSink {
        async fn put(&self, kind: BodyKind, sha256: &str, body: &[u8]) -> Result<(), String> {
            if self.fails == Some(kind) {
                return Err("the bucket is unreachable".into());
            }
            self.kept
                .lock()
                .unwrap()
                .push((kind, sha256.to_string(), body.to_vec()));
            Ok(())
        }
    }

    /// With an archive, each body is written under the hash its row
    /// carries, the request before the call is sent, and both rows say
    /// so.
    #[tokio::test]
    async fn both_bodies_are_archived_under_the_hashes_on_their_rows() {
        let answer = "{\"choices\":[]}";
        let (upstream, _) = provider(json_reply(answer)).await;
        let sink = Arc::new(TestSink::default());
        let rig = rig_with(
            vec![("local", "custom", upstream, None)],
            None,
            Some(sink.clone()),
        )
        .await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let body = "{\"model\":\"m\"}";
        assert_eq!(
            rig.post(CHAT, &value, body).await.text().await.unwrap(),
            answer
        );

        let kept = sink.kept.lock().unwrap().clone();
        assert_eq!(
            kept,
            [
                (
                    BodyKind::Request,
                    sha256_hex(body.as_bytes()),
                    body.as_bytes().to_vec()
                ),
                (
                    BodyKind::Response,
                    sha256_hex(answer.as_bytes()),
                    answer.as_bytes().to_vec()
                ),
            ]
        );
        let rows = rig.rows(&proxy_session(&token.id, None));
        assert!(
            matches!(
                rows.as_slice(),
                [
                    SessionEvent::ProxyRequest { archived: true, .. },
                    SessionEvent::ProxyResponse { archived: true, .. }
                ]
            ),
            "{rows:?}"
        );
    }

    /// A request that cannot be archived is not sent. A response that
    /// cannot be archived has been answered already: the client gets
    /// it, and the row says it was not archived.
    #[tokio::test]
    async fn an_archive_failure_stops_the_request_and_is_recorded_for_the_response() {
        let (upstream, got) = provider(json_reply("{}")).await;
        let rig = rig_with(
            vec![("local", "custom", upstream, None)],
            None,
            Some(Arc::new(TestSink {
                fails: Some(BodyKind::Request),
                ..Default::default()
            })),
        )
        .await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 502);
        assert!(response.text().await.unwrap().contains("archive_failed"));
        assert!(got.lock().unwrap().is_empty());
        assert_eq!(
            rig.refusals(&proxy_session(&token.id, None)),
            [ProxyRefusal::ArchiveFailed]
        );

        let (upstream, _) = provider(json_reply("{}")).await;
        let rig = rig_with(
            vec![("local", "custom", upstream, None)],
            None,
            Some(Arc::new(TestSink {
                fails: Some(BodyKind::Response),
                ..Default::default()
            })),
        )
        .await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "{}");
        let rows = rig.rows(&proxy_session(&token.id, None));
        assert!(
            matches!(
                rows.as_slice(),
                [
                    SessionEvent::ProxyRequest { archived: true, .. },
                    SessionEvent::ProxyResponse {
                        archived: false,
                        complete: true,
                        ..
                    }
                ]
            ),
            "{rows:?}"
        );
    }

    /// A provider that sends the start of a stream and then nothing:
    /// the stream ends at the idle timeout, and the row has the hash
    /// of what was exchanged and says the exchange did not complete.
    #[tokio::test]
    async fn a_stream_that_goes_idle_is_ended_and_recorded_as_incomplete() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}/v1", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
                              data: {\"partial\":1}\n\n",
                        )
                        .await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                });
            }
        });
        let rig = rig(vec![("local", "custom", upstream, None)]).await;
        let (token, value) = rig.issue("laptop", &["local"]);
        let started = Instant::now();
        let response = rig
            .post(CHAT, &value, "{\"model\":\"m\",\"stream\":true}")
            .await;
        assert_eq!(response.status(), 200);
        // The client's read ends when the proxy ends the stream.
        let _ = response.bytes().await;
        assert!(started.elapsed() < std::time::Duration::from_secs(10));

        let sent = "data: {\"partial\":1}\n\n";
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let rows = rig.rows(&proxy_session(&token.id, None));
            if let Some(SessionEvent::ProxyResponse {
                complete,
                response_sha256,
                response_bytes,
                ..
            }) = rows.get(1)
            {
                assert!(!complete);
                assert_eq!(*response_bytes, sent.len() as u64);
                assert_eq!(response_sha256.0, sha256_hex(sent.as_bytes()));
                break;
            }
            assert!(Instant::now() < deadline, "no response row: {rows:?}");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// A provider that cannot be reached answers 502, and the response
    /// row says the exchange did not complete.
    #[tokio::test]
    async fn an_unreachable_provider_is_recorded_as_incomplete() {
        let rig = rig(vec![(
            "down",
            "custom",
            "http://127.0.0.1:9/v1".into(),
            None,
        )])
        .await;
        let (token, value) = rig.issue("laptop", &["down"]);
        let response = rig.post(CHAT, &value, "{\"model\":\"m\"}").await;
        assert_eq!(response.status(), 502);
        let rows = rig.rows(&proxy_session(&token.id, None));
        assert!(
            matches!(
                rows.as_slice(),
                [
                    SessionEvent::ProxyRequest { .. },
                    SessionEvent::ProxyResponse {
                        status: 502,
                        complete: false,
                        response_bytes: 0,
                        ..
                    }
                ]
            ),
            "{rows:?}"
        );
    }

    #[tokio::test]
    async fn another_path_or_method_is_not_served() {
        let rig = rig(vec![(
            "local",
            "custom",
            "http://127.0.0.1:9/v1".into(),
            None,
        )])
        .await;
        for request in [
            reqwest::Client::new().get(format!("{}{CHAT}", rig.base)),
            reqwest::Client::new().post(format!("{}/v1/embeddings", rig.base)),
            reqwest::Client::new().get(format!("{}/", rig.base)),
        ] {
            assert_eq!(request.send().await.unwrap().status(), 404);
        }
        assert!(rig.rows(PROXY_SESSION).is_empty());
    }

    #[test]
    fn counts_are_read_in_either_providers_naming() {
        let mut openai = Counts::default();
        openai.read_value(&serde_json::json!({"usage": {
            "prompt_tokens": 10, "completion_tokens": 3,
            "prompt_tokens_details": {"cached_tokens": 4}
        }}));
        assert_eq!(
            openai,
            Counts {
                input: Some(10),
                output: Some(3),
                cache_read: Some(4),
                cache_creation: None
            }
        );
        let mut none = Counts::default();
        none.read_value(&serde_json::json!({"usage": null, "choices": []}));
        assert_eq!(none, Counts::default());
    }
}
