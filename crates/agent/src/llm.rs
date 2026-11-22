use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::conversation::{Message, Role, ToolCallRequest};
use crate::error::AgentError;
use crate::recovery::{MAX_RATE_LIMIT_RETRIES, RecoveryObserver, RetryDecision, classify_429};
use crate::tool::ToolDef;
pub use wirken_gateway::agent_config::ProviderAuth;

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name: "openai", "anthropic", "gemini", "bedrock", "ollama", "custom"
    pub provider: String,
    /// Model ID, as the provider names it (e.g., "gpt-4o", "gemini-2.0-flash")
    pub model: String,
    /// API base URL
    pub base_url: String,
    /// Max tokens in response
    pub max_tokens: u32,
    /// Temperature (0.0 - 2.0)
    pub temperature: f32,
    /// AWS region for Bedrock. Ignored for other providers.
    #[serde(default)]
    pub region: Option<String>,
    /// Whether to send tool definitions to the LLM. Defaults to true for
    /// every provider; a per-agent override turns it off.
    #[serde(default = "default_tools_enabled")]
    pub tools_enabled: bool,
    /// Total context window in tokens. The [`crate::context::ContextEngine`]
    /// uses this as the budget ceiling for trimming conversations before
    /// each LLM call. Defaults to a conservative 32_000 when missing,
    /// which is the value [`LlmConfig`] entries deserialized from older
    /// data files pick up.
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    /// How the provider is authenticated. [`ProviderAuth::Plan`] sends
    /// the agent through the plan client
    /// ([`crate::llm_responses`]), which talks to a fixed endpoint and
    /// takes its bearer from a [`crate::plan_auth::PlanTokenSource`]
    /// per call; `base_url` and the static key are not used for it.
    /// Absent in everything serialized before it existed, which reads
    /// as `Key`.
    #[serde(default, skip_serializing_if = "ProviderAuth::is_key")]
    pub auth: ProviderAuth,
}

/// Where an agent's model key comes from on each call, so a key rotated
/// in the vault reaches the next call and one removed, or no longer
/// allowed to the provider, fails it.
pub trait ProviderKeySource: Send + Sync + std::fmt::Debug {
    /// The vault entry the key is read from.
    fn credential(&self) -> &str;
    /// The key now, or why there is none.
    fn key(&self) -> Result<String, String>;
    /// Whether the key may be sent to `origin` (`scheme://host`), an
    /// origin other than the configured base URL's that a provider's
    /// own discovery named. A source that says no records the refusal.
    /// The default allows none.
    fn permits_origin(&self, _origin: &str) -> bool {
        false
    }
}

/// The context window assumed for every model on a plan. No figure is
/// documented for them, so this is a conservative fixed value: an
/// understated window only compacts earlier than needed, an overstated
/// one builds requests a model cannot hold.
pub const PLAN_CONTEXT_WINDOW: usize = 128_000;

fn default_tools_enabled() -> bool {
    true
}

fn default_context_window() -> usize {
    32_000
}

impl LlmConfig {
    /// OpenAI defaults
    pub fn openai(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: "https://api.openai.com/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 128_000,
        }
    }

    /// The [`crate::plan_auth::PROVIDER`] provider in plan mode.
    /// `base_url` is set to the
    /// pinned plan endpoint so every surface that prints it prints the
    /// one used; the plan client does not read it.
    ///
    /// The provider documents no context window for the models a plan
    /// serves, and the catalogue is the signed-in account's, so the
    /// window is the fixed [`PLAN_CONTEXT_WINDOW`] rather than a
    /// per-model figure.
    pub fn plan(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: crate::plan_auth::API_BASE.into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Plan,
            context_window: PLAN_CONTEXT_WINDOW,
        }
    }

    /// Anthropic defaults
    pub fn anthropic(model: &str) -> Self {
        Self {
            provider: "anthropic".into(),
            model: model.into(),
            base_url: "https://api.anthropic.com/v1".into(),
            max_tokens: ANTHROPIC_DEFAULT_MAX_TOKENS,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 200_000,
        }
    }

    /// Google Gemini defaults
    pub fn gemini(model: &str) -> Self {
        Self {
            provider: "gemini".into(),
            model: model.into(),
            base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 1_000_000,
        }
    }

    /// AWS Bedrock defaults
    pub fn bedrock(model: &str, region: &str) -> Self {
        Self {
            provider: "bedrock".into(),
            model: model.into(),
            base_url: format!("https://bedrock-runtime.{region}.amazonaws.com"),
            max_tokens: 4096,
            temperature: 0.7,
            region: Some(region.into()),
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 200_000,
        }
    }

    /// Ollama defaults (local). 32_768 is the safe intersection
    /// across qwen2.5, llama3.1, llama3.2, mistral, and gemma. Models
    /// with smaller native context get clamped by ollama itself when
    /// `num_ctx` is requested over its native maximum; larger models
    /// (rare in current local releases) need an explicit override
    /// via the lyrik config's `phases.<phase>.context_window`.
    pub fn ollama(model: &str) -> Self {
        Self {
            provider: "ollama".into(),
            model: model.into(),
            base_url: "http://localhost:11434/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 32_768,
        }
    }

    /// Tinfoil confidential inference. Dispatches through the
    /// tinfoil-rs SDK so each session is gated on a successful
    /// AMD SEV-SNP attestation + Sigstore code provenance check
    /// against the published enclave repo, and chat traffic flows
    /// over a TLS connection pinned to the attested certificate.
    /// `base_url` names the enclave the key is sent to when no router
    /// the SDK's discovery lists is allowed the key; see
    /// [`tinfoil_hosts`].
    pub fn tinfoil(model: &str) -> Self {
        Self {
            provider: "tinfoil".into(),
            model: model.into(),
            base_url: "https://inference.tinfoil.sh/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 128_000,
        }
    }

    /// Privatemode confidential inference (OpenAI-compatible via local proxy)
    pub fn privatemode(model: &str) -> Self {
        Self {
            provider: "openai".into(),
            model: model.into(),
            base_url: "http://localhost:8080/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 128_000,
        }
    }

    /// Custom OpenAI-compatible endpoint
    pub fn custom(base_url: &str, model: &str) -> Self {
        Self {
            provider: "custom".into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window: 32_000,
        }
    }

    /// Construct from explicit provider, base_url, and model.
    /// Preserves the provider name for correct dispatch.
    pub fn from_provider(provider: &str, base_url: &str, model: &str) -> Self {
        let context_window = match provider {
            "openai" => 128_000,
            "anthropic" => 200_000,
            "gemini" => 1_000_000,
            "bedrock" => 200_000,
            "ollama" => 32_768,
            "tinfoil" => 128_000,
            // Hetzner's catalog spans 262,144 (Qwen3.6, Kimi-K2.7) to
            // 512,000 (DeepSeek-V4-Flash, GLM-5.2) as of August 2026.
            // This table keys on provider rather than model, so one
            // number has to cover all of them, and the catalog minimum
            // is the safe direction: understating the window only
            // compacts earlier than necessary, while overstating builds
            // a request the model cannot hold.
            "hetzner" => 262_144,
            _ => 32_000,
        };
        Self {
            provider: provider.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: if provider == "anthropic" {
                ANTHROPIC_DEFAULT_MAX_TOKENS
            } else {
                4096
            },
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            auth: ProviderAuth::Key,
            context_window,
        }
    }
}

/// Response from the LLM.
#[derive(Debug, Clone)]
pub enum LlmResponse {
    /// Text response — the assistant replied with content.
    Text(String),
    /// Tool calls: the assistant wants to call tools, and may have
    /// said something alongside them.
    ///
    /// `text` is the assistant's own content from the same message.
    /// Providers send it in the same turn as the calls, and every
    /// parse path used to drop it on the floor: the variant carried
    /// only the calls, so the sentence explaining what the model was
    /// about to do never reached the conversation, the chain, or the
    /// operator being asked to approve it. `None` where the model
    /// sent calls and no text.
    ToolCalls {
        calls: Vec<ToolCallRequest>,
        text: Option<String>,
        /// The reasoning the provider returned with the message, where
        /// it returns any. Recorded beside the calls and used for
        /// nothing else: it is not sent back to the model and no gate
        /// reads it.
        reasoning: Option<String>,
    },
    /// Empty response (shouldn't happen but handle gracefully).
    Empty,
}

/// Token-usage metadata returned alongside an LLM response. Captured
/// from each provider's `usage` block. Cache fields are
/// anthropic-specific and stay zero for other providers.
///
/// Callers receive `Option<Usage>` from `complete` and `complete_stream`.
/// `None` means the provider did not include a usage block on the
/// response (some custom OpenAI-compatible servers, older ollama
/// versions, streaming-without-`include_usage`). `Some(Usage)` means
/// the block was present, whatever the numeric values inside. The
/// runtime projects `None` to "tokens=0, cost=None" on the audit row
/// so a billing consumer can distinguish "provider reported zero"
/// from "we don't know". Flattening these together would silently
/// undercount cost.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub cache_read_input_tokens: u32,
}

/// Output tokens an Anthropic reply may use when nothing sets another
/// limit. A reply that writes a file or a patch in one tool call does
/// not fit in the 4096 the other providers default to, and a reply
/// this long still returns inside the request timeout without
/// streaming.
pub const ANTHROPIC_DEFAULT_MAX_TOKENS: u32 = 16_000;

/// Why a provider says a reply ended, in one vocabulary across
/// providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    /// The reply reached the output token limit and is cut off. A tool
    /// call at the end of it may hold only part of its arguments.
    MaxTokens,
    /// The provider or its safety system declined to answer.
    Refusal,
    StopSequence,
    /// A reason this table does not name.
    Other,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::EndTurn => "end_turn",
            StopReason::ToolUse => "tool_use",
            StopReason::MaxTokens => "max_tokens",
            StopReason::Refusal => "refusal",
            StopReason::StopSequence => "stop_sequence",
            StopReason::Other => "other",
        }
    }

    /// A provider's own word for it. Anthropic: `stop_reason`.
    /// OpenAI-compatible: `finish_reason`. Gemini: `finishReason`.
    /// Bedrock Converse: `stopReason`. Ollama: `done_reason`.
    pub fn from_provider(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "end_turn" | "stop" | "eos" | "complete" => StopReason::EndTurn,
            "tool_use" | "tool_calls" | "function_call" => StopReason::ToolUse,
            "max_tokens" | "length" | "model_context_window_exceeded" => StopReason::MaxTokens,
            "refusal"
            | "content_filter"
            | "content_filtered"
            | "guardrail_intervened"
            | "safety"
            | "recitation"
            | "blocklist"
            | "prohibited_content"
            | "spii" => StopReason::Refusal,
            "stop_sequence" => StopReason::StopSequence,
            _ => StopReason::Other,
        }
    }
}

/// Mark the end of an Anthropic conversation as a cache breakpoint: the
/// last content block of the last message. The provider caches
/// everything up to a breakpoint, so each call of a tool loop reads the
/// calls before it from the cache and writes only what the last round
/// added. Without it only the system prompt and the tool definitions
/// are cached and the whole conversation is billed as fresh input on
/// every round. A message whose content is a string is rewritten as one
/// text block, which is the same message to the provider.
pub(crate) fn cache_conversation_prefix(messages: &mut [serde_json::Value]) {
    let Some(last) = messages.last_mut() else {
        return;
    };
    let Some(content) = last.get_mut("content") else {
        return;
    };
    if let Some(text) = content.as_str() {
        if text.is_empty() {
            return;
        }
        *content = serde_json::json!([{ "type": "text", "text": text }]);
    }
    if let Some(block) = content.as_array_mut().and_then(|blocks| blocks.last_mut())
        && block.is_object()
    {
        block["cache_control"] = wirken_audit::pricing::requested_cache_control();
    }
}

/// The stop reason in a provider's response body, whichever shape the
/// body has. `None` when the body carries none.
pub fn stop_reason_in(body: &serde_json::Value) -> Option<StopReason> {
    stop_reason_raw_in(body).map(StopReason::from_provider)
}

/// The provider's own word for why the reply ended, as the body
/// carries it. [`stop_reason_in`] maps it; this is the value mapped.
pub fn stop_reason_raw_in(body: &serde_json::Value) -> Option<&str> {
    body.get("stop_reason")
        .or_else(|| body.get("stopReason"))
        .or_else(|| body.get("done_reason"))
        .or_else(|| body.pointer("/choices/0/finish_reason"))
        .or_else(|| body.pointer("/candidates/0/finishReason"))
        .and_then(|v| v.as_str())
}

/// A provider's stop word as it goes on the audit row: cut to a
/// bounded length, since it is the provider's text.
pub(crate) fn bounded_raw(raw: &str) -> String {
    raw.chars().take(64).collect()
}

/// LLM client that makes completion requests.
pub struct LlmClient {
    config: LlmConfig,
    http: reqwest::Client,
    /// Recovery observer registered by the harness (lyrik dispatch
    /// runner, …). Receives per-attempt rate-limit notifications from
    /// `send_with_retry` so the harness can emit audit records as
    /// retries happen, not only at the end. Mutex (rather than
    /// RwLock) because the field is set rarely and never held across
    /// awaits — the lock is acquired, the inner `Arc` cloned out, and
    /// released before the observer's hooks run.
    observer: Mutex<Option<Arc<dyn RecoveryObserver>>>,
    /// The stop reason of the reply the last call returned. Set by
    /// each call, read by the runtime straight after it.
    last_stop: Mutex<Option<(StopReason, String)>>,
    /// How many times a request that failed in transport is sent
    /// again. Zero, the default, sends it once.
    transport_retries: std::sync::atomic::AtomicU32,
    /// Transport retries made by this client, for a caller's records.
    transport_retries_made: std::sync::atomic::AtomicU32,
    /// Lazy-initialized tinfoil SDK client. Construction performs
    /// AMD SEV-SNP attestation + Sigstore verification + TLS pinning
    /// against an enclave the key may be sent to; the result is cached for the
    /// process lifetime. Reset to `None` by `complete_tinfoil` when
    /// an attestation or TLS-pinning error surfaces, so the next
    /// call re-attests rather than retrying against a stale pinned
    /// transport. `tokio::sync::Mutex` rather than `std::sync::Mutex`
    /// because the lock is held across the SDK's `await`s during
    /// initialization.
    tinfoil: tokio::sync::Mutex<Option<Arc<tinfoil::Client>>>,
    /// The stored secrets a request to the model may not carry. Empty
    /// until the agent attaches one.
    leak_matcher: Arc<wirken_gateway::leak::LeakMatcher>,
    /// Asked whether the model key may go to an origin other than the
    /// configured base URL's. With none, it goes to no other.
    key_source: Option<Arc<dyn ProviderKeySource>>,
    /// The bearer for every call in plan mode, asked for per call. In
    /// plan mode a call without one is refused before anything is sent.
    plan_source: Option<Arc<crate::plan_auth::PlanTokenSource>>,
    /// Where plan-mode calls go. The pinned endpoints outside tests.
    plan_endpoints: crate::plan_auth::Endpoints,
    /// The waits between attempts after a 503 on the plan route.
    plan_unavailable_backoff: Vec<std::time::Duration>,
}

impl LlmClient {
    /// Create a new LLM client.
    /// Enforces HTTPS for non-localhost endpoints to prevent API key leakage.
    pub fn new(config: LlmConfig) -> Result<Self, AgentError> {
        let is_localhost = plain_http_to_loopback(&config.base_url);

        if !config.base_url.starts_with("https://") && !is_localhost {
            return Err(AgentError::Http(format!(
                "LLM endpoint must use HTTPS (got {}). Use HTTPS or localhost.",
                config.base_url
            )));
        }

        // No redirect is followed, for any provider. The key was read
        // for the origin of `base_url`, and a redirect would send the
        // request on to an origin nothing checked: the client drops
        // `Authorization` across hosts but not `x-api-key`,
        // `x-goog-api-key` or a signed request's session token, and it
        // sends the conversation along with a 307 or 308.
        let mut builder = reqwest::Client::builder()
            .https_only(!is_localhost)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(300));
        if config.auth.is_plan() {
            // The plan route's bearer is the operator's plan; it goes to
            // the pinned endpoint only.
            builder = builder.https_only(true);
        }
        let http = builder
            .build()
            .map_err(|e| AgentError::Http(format!("HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            observer: Mutex::new(None),
            last_stop: Mutex::new(None),
            transport_retries: std::sync::atomic::AtomicU32::new(0),
            transport_retries_made: std::sync::atomic::AtomicU32::new(0),
            tinfoil: tokio::sync::Mutex::new(None),
            leak_matcher: Arc::new(wirken_gateway::leak::LeakMatcher::new()),
            key_source: None,
            plan_source: None,
            plan_endpoints: crate::plan_auth::Endpoints::pinned(),
            plan_unavailable_backoff: crate::llm_responses::UNAVAILABLE_BACKOFF.to_vec(),
        })
    }

    /// Ask `source` before the model key is sent to an origin other
    /// than the configured base URL's.
    pub fn set_key_source(&mut self, source: Arc<dyn ProviderKeySource>) {
        self.key_source = Some(source);
    }

    /// Take the bearer for every plan-mode call from `source`.
    pub fn set_plan_token_source(&mut self, source: Arc<crate::plan_auth::PlanTokenSource>) {
        self.plan_source = Some(source);
    }

    pub(crate) fn plan_source(&self) -> Option<Arc<crate::plan_auth::PlanTokenSource>> {
        self.plan_source.clone()
    }

    pub(crate) fn plan_endpoints(&self) -> &crate::plan_auth::Endpoints {
        &self.plan_endpoints
    }

    pub(crate) fn plan_unavailable_backoff(&self) -> &[std::time::Duration] {
        &self.plan_unavailable_backoff
    }

    /// Point plan-mode calls at a loopback stub, with no backoff waits.
    #[cfg(test)]
    pub(crate) fn set_plan_endpoints_for_test(&mut self, endpoints: crate::plan_auth::Endpoints) {
        self.plan_endpoints = endpoints;
        self.plan_unavailable_backoff = vec![std::time::Duration::ZERO; 3];
        self.http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test http client");
    }

    /// Refuse to send a request that carries a stored secret in `matcher`.
    pub fn set_leak_matcher(&mut self, matcher: Arc<wirken_gateway::leak::LeakMatcher>) {
        self.leak_matcher = matcher;
    }

    /// The backstop before any request leaves: every message, every
    /// tool call's arguments and every tool definition. Content is
    /// checked where it enters the conversation; this catches what got
    /// past those checks, and refuses the whole request.
    pub(crate) fn refuse_leaked_request(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
    ) -> Result<(), AgentError> {
        let found = messages
            .iter()
            .flat_map(|m| {
                std::iter::once(m.content.as_str())
                    .chain(m.tool_calls.iter().flatten().map(|c| c.arguments.as_str()))
            })
            .find_map(|text| self.leak_matcher.find(text))
            .or_else(|| {
                tools.iter().find_map(|t| {
                    self.leak_matcher
                        .find(&t.description)
                        .or_else(|| self.leak_matcher.find(&t.parameters.to_string()))
                })
            });
        match found {
            Some(credential) => Err(AgentError::LeakRefused { credential }),
            None => Ok(()),
        }
    }

    /// Register a recovery observer. Replaces any previously set
    /// observer. The observer's `on_rate_limited` and
    /// `on_rate_limit_exhausted` hooks are called from
    /// `send_with_retry` as 429 retries are scheduled and exhausted.
    pub fn set_recovery_observer(&self, observer: Arc<dyn RecoveryObserver>) {
        *self.observer.lock().unwrap() = Some(observer);
    }

    /// Send a request that failed in transport again, up to `retries`
    /// times. A transport failure is one where no response arrived: the
    /// connection could not be made, timed out or was dropped while the
    /// request was being sent. Zero, the default, sends once.
    pub fn set_transport_retries(&self, retries: u32) {
        self.transport_retries
            .store(retries, std::sync::atomic::Ordering::Relaxed);
    }

    /// Transport retries this client has made.
    pub fn transport_retries_made(&self) -> u32 {
        self.transport_retries_made
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Send a request through `build` with HTTP-429 retry/backoff.
    /// `build` is called fresh per attempt — `reqwest::RequestBuilder`
    /// is not cheaply cloneable across awaits, and Bedrock requires a
    /// freshly-signed `x-amz-date` header on every retry, so the
    /// closure's job is to rebuild the request each time including any
    /// per-attempt signing.
    ///
    /// 429 responses retry with backoff up to
    /// [`MAX_RATE_LIMIT_RETRIES`] attempts. Any other status (success
    /// or non-429 error) is returned to the caller unchanged. A network
    /// error propagates at once unless the caller set
    /// [`Self::set_transport_retries`]; then a request that got no
    /// response is sent again that many times, one, two, four and at
    /// most eight seconds apart, before the error is returned.
    pub(crate) async fn send_with_retry<F>(
        &self,
        mut build: F,
    ) -> Result<reqwest::Response, AgentError>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        let mut attempt: u32 = 1;
        let transport_retries = self
            .transport_retries
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut transport_attempt: u32 = 0;
        loop {
            let resp = match build().send().await {
                Ok(resp) => resp,
                Err(e) => {
                    let no_response = e.is_connect() || e.is_timeout() || e.is_request();
                    if !no_response || transport_attempt >= transport_retries {
                        return Err(AgentError::Http(e.to_string()));
                    }
                    transport_attempt += 1;
                    self.transport_retries_made
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let delay_secs = 1u64 << (transport_attempt - 1).min(3);
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    continue;
                }
            };
            if resp.status().as_u16() != 429 {
                return Ok(resp);
            }
            let status_u16 = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            // Drop the response body so the connection can be reused.
            drop(resp);
            if attempt >= MAX_RATE_LIMIT_RETRIES {
                if let Some(obs) = self.observer.lock().unwrap().clone() {
                    obs.on_rate_limit_exhausted(attempt);
                }
                return Err(AgentError::RateLimitExhausted { attempts: attempt });
            }
            let delay_ms = match classify_429(status_u16, retry_after.as_deref(), attempt) {
                RetryDecision::Retry { delay_ms } => delay_ms,
                RetryDecision::NoRetry => {
                    // classify_429 always returns Retry for 429; reaching this
                    // branch is a contract violation. Surface as an Llm error.
                    return Err(AgentError::Llm(
                        "classify_429 returned NoRetry for status 429".into(),
                    ));
                }
            };
            if let Some(obs) = self.observer.lock().unwrap().clone() {
                obs.on_rate_limited(attempt, delay_ms, status_u16);
            }
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            attempt += 1;
        }
    }

    /// Send a chat completion request.
    /// The API key is passed in as a parameter — the client never stores it.
    /// Returns the response paired with the usage metadata extracted from
    /// the provider's `usage` block. Endpoints without a usage block yield
    /// `Usage::default()`.
    /// Why the provider says the reply of the last call ended, when it
    /// said. Read it straight after the call it belongs to.
    pub fn last_stop_reason(&self) -> Option<StopReason> {
        self.last_stop
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|(reason, _)| *reason)
    }

    /// The provider's own word the last stop reason was mapped from.
    pub fn last_stop_reason_raw(&self) -> Option<String> {
        self.last_stop
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|(_, raw)| raw.clone())
    }

    /// Record the stop word of the reply just read, or clear it.
    pub(crate) fn set_stop_reason(&self, raw: Option<&str>) {
        *self.last_stop.lock().unwrap_or_else(|e| e.into_inner()) =
            raw.map(|raw| (StopReason::from_provider(raw), bounded_raw(raw)));
    }

    pub async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        self.refuse_leaked_request(messages, tools)?;
        self.set_stop_reason(None);
        if self.config.auth.is_plan() {
            return self.complete_plan(messages, tools, None).await;
        }
        match self.config.provider.as_str() {
            "anthropic" => self.complete_anthropic(messages, tools, api_key).await,
            "gemini" => self.complete_gemini(messages, tools, api_key).await,
            "bedrock" => self.complete_bedrock(messages, tools, api_key).await,
            "ollama" => self.complete_ollama(messages, tools).await,
            "tinfoil" => self.complete_tinfoil(messages, tools, api_key).await,
            _ => self.complete_openai(messages, tools, api_key).await,
        }
    }

    /// Tinfoil completion through the attested + TLS-pinned transport.
    ///
    /// The SDK's `Client::new_default_with_api_key` runs the full
    /// three-step verification (AMD SEV-SNP hardware attestation,
    /// Sigstore code provenance against the published enclave repo,
    /// measurement comparison) and returns a `reqwest::Client`
    /// pinned to the attested TLS certificate. We cache the verified
    /// client for the process lifetime and reuse the pinned reqwest
    /// for chat traffic, building the same OpenAI-compat request body
    /// `complete_openai` builds and parsing the response with the
    /// same `parse_completion_response`. No async-openai type
    /// translation; the request shape is already what the enclave
    /// serves on `/v1/chat/completions`.
    ///
    /// One failure drops the cached client and forces re-attestation
    /// on the next call: a chat request that fails at the connection
    /// ([`is_pinned_tls_failure`]), which a rotated certificate and an
    /// unreachable network both produce. A failed verification never
    /// cached a client. Every other failure (an HTTP error, a response
    /// that does not parse) leaves the cached client in place and
    /// surfaces to the caller for the existing retry layers (lyrik,
    /// send-loop) to handle.
    async fn complete_tinfoil(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let api_key = api_key.ok_or_else(|| {
            AgentError::Llm(
                "tinfoil provider requires an API key; none was passed to complete()".into(),
            )
        })?;
        let client = self.tinfoil_client().await?;

        let messages_json: Vec<serde_json::Value> = messages.iter().map(message_to_json).collect();
        let body = build_openai_request_body(&self.config, messages_json, tools);

        let pinned = client
            .http_client()
            .map_err(|e| AgentError::Llm(format!("tinfoil pinned client unavailable: {e}")))?;
        let url = format!("{}/v1/chat/completions", client.secure_client().base_url());

        let response = pinned
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&body)
            .send()
            .await;

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                // reqwest-level failures from a pinned client carry
                // the TLS-fingerprint-mismatch case. Drop the cached
                // client so the next call re-attests against a fresh
                // certificate rather than retrying the same pinned
                // transport.
                if is_pinned_tls_failure(&e) {
                    self.invalidate_tinfoil_cache().await;
                }
                return Err(AgentError::Http(format!("tinfoil request: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_completion_response(&response_body)
    }

    /// Lazy-init the tinfoil SDK client, caching the verified instance
    /// for the process lifetime. Holds the lock across the SDK's
    /// async verification call so two concurrent `complete()` calls
    /// share the same attestation rather than triggering two parallel
    /// SEV-SNP + Sigstore round trips.
    ///
    /// The enclave is one the key may be sent to ([`tinfoil_hosts`]):
    /// a router the SDK's discovery lists is attested only when the
    /// key source allows its origin, and the host of the configured
    /// base URL, which the key was read for, is tried last. The SDK is
    /// handed no key; [`Self::complete_tinfoil`] puts it on the request
    /// it builds for the attested host.
    async fn tinfoil_client(&self) -> Result<Arc<tinfoil::Client>, AgentError> {
        let mut guard = self.tinfoil.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let configured = tinfoil_configured_host(&self.config.base_url)?;
        // A discovery that cannot be reached names no router, as in
        // the SDK, and the configured host is attested.
        let discovered = tinfoil::discovery::fetch_routers()
            .await
            .unwrap_or_default();
        let hosts = tinfoil_hosts(&discovered, &configured, |origin| {
            self.key_source
                .as_ref()
                .is_some_and(|source| source.permits_origin(origin))
        });
        let mut failure = None;
        for host in hosts {
            match tinfoil::Client::new(&host, tinfoil::constants::DEFAULT_REPO, "").await {
                Ok(client) => {
                    let arc = Arc::new(client);
                    *guard = Some(arc.clone());
                    return Ok(arc);
                }
                Err(e) => {
                    tracing::warn!(enclave = %host, error = %e, "tinfoil enclave not verified");
                    failure = Some(e);
                }
            }
        }
        Err(match failure {
            Some(e) if e.is_attestation() => {
                AgentError::Llm(format!("tinfoil attestation failed: {e}"))
            }
            Some(e) if e.is_configuration() => {
                AgentError::Llm(format!("tinfoil misconfigured: {e}"))
            }
            Some(e) => AgentError::Http(format!("tinfoil verification: {e}")),
            None => AgentError::Llm("tinfoil misconfigured: no enclave host".into()),
        })
    }

    /// Forward a request a client outside Wirken built, as it is, to
    /// this client's provider, and hand back the provider's response
    /// unread.
    ///
    /// `body` is sent byte for byte to the endpoint that takes `shape`
    /// at the configured `base_url`, through the client every agent
    /// call uses: HTTPS or loopback only, no redirect followed, and for
    /// Tinfoil the attested, pinned connection. `api_key` is the
    /// provider's key, put in the provider's own header; whatever
    /// credential the client sent is not in `headers` and is not
    /// forwarded. Of `headers`, only the few that describe the request
    /// to the provider are sent on ([`FORWARDED_HEADERS`]).
    ///
    /// Refused before anything is sent: a shape the provider's endpoint
    /// does not take ([`provider_speaks`]), and a body that carries a
    /// stored secret. Sent once; a failure or a 429 is the client's to
    /// retry.
    pub async fn forward(
        &self,
        shape: wirken_audit::ProxyShape,
        body: Vec<u8>,
        headers: &[(String, String)],
        api_key: Option<&str>,
    ) -> Result<reqwest::Response, AgentError> {
        use wirken_audit::ProxyShape;

        let provider = self.config.provider.as_str();
        if self.config.auth.is_plan() || !provider_speaks(provider, shape) {
            return Err(AgentError::Llm(format!(
                "provider {provider} does not take {} requests",
                shape.as_str()
            )));
        }
        if let Some(credential) = self.leak_matcher.find(&String::from_utf8_lossy(&body)) {
            return Err(AgentError::LeakRefused { credential });
        }
        let path = match shape {
            ProxyShape::OpenaiChat => "chat/completions",
            ProxyShape::AnthropicMessages => "messages",
        };
        let (http, url) = if provider == "tinfoil" {
            let client = self.tinfoil_client().await?;
            let pinned = client
                .http_client()
                .map_err(|e| AgentError::Llm(format!("tinfoil pinned client unavailable: {e}")))?
                .clone();
            (
                pinned,
                format!("{}/v1/{path}", client.secure_client().base_url()),
            )
        } else {
            (
                self.http.clone(),
                format!("{}/{path}", self.config.base_url),
            )
        };
        let mut request = http.post(&url);
        for (name, value) in headers {
            if FORWARDED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        if let Some(key) = api_key {
            request = match provider {
                "anthropic" => request.header("x-api-key", key),
                _ => request.header("Authorization", format!("Bearer {key}")),
            };
        }
        request
            .body(body)
            .send()
            .await
            .map_err(|e| AgentError::Http(e.without_url().to_string()))
    }

    /// The models the Tinfoil enclave at this client's `base_url`
    /// lists for `api_key`. The enclave is attested and the connection
    /// pinned exactly as for a chat call ([`Self::tinfoil_client`]),
    /// and the key goes on the request to the attested host only: a
    /// listing sends the key, so it gets the checks a chat call gets.
    pub async fn tinfoil_models(&self, api_key: &str) -> Result<Vec<String>, AgentError> {
        let client = self.tinfoil_client().await?;
        let pinned = client
            .http_client()
            .map_err(|e| AgentError::Llm(format!("tinfoil pinned client unavailable: {e}")))?;
        let url = format!("{}/v1/models", client.secure_client().base_url());
        let response = pinned
            .get(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .await
            .map_err(|e| AgentError::Http(e.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(AgentError::Llm(format!("HTTP {}", response.status())));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;
        Ok(listed_model_ids(&body))
    }

    /// Drop the cached tinfoil client. The next `complete_tinfoil`
    /// call will re-run verification and rebuild the pinned transport.
    /// Called when a pinned-TLS failure surfaces from the chat path,
    /// because the cert may have rotated under us.
    async fn invalidate_tinfoil_cache(&self) {
        let mut guard = self.tinfoil.lock().await;
        *guard = None;
    }

    /// Ollama native `/api/chat` completion. The OpenAI-compat bridge
    /// at `/v1/chat/completions` silently drops `options.num_ctx`,
    /// which means a 32K context declaration in [`LlmConfig`] is
    /// fiction over that path — ollama serves the model under its 4K
    /// (or 2K) default, and large prompts (e.g. a Lyrik SKILL.md
    /// body plus tool specs) get truncated invisibly. The native
    /// endpoint honors `options.num_ctx`, so the declared window is
    /// what the model actually receives.
    async fn complete_ollama(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let url = ollama_chat_url(&self.config.base_url);
        let messages_json: Vec<serde_json::Value> = messages.iter().map(message_to_json).collect();
        let body = build_ollama_request_body(&self.config, messages_json, tools);

        let response = self
            .send_with_retry(|| {
                self.http
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body)
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_ollama_response(&response_body)
    }

    /// OpenAI-compatible completion (OpenAI, Ollama, custom endpoints).
    async fn complete_openai(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let url = format!("{}/chat/completions", self.config.base_url);

        let messages_json: Vec<serde_json::Value> = messages.iter().map(message_to_json).collect();
        let body = build_openai_request_body(&self.config, messages_json, tools);

        let response = self
            .send_with_retry(|| {
                let mut req = self
                    .http
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body);
                if let Some(key) = api_key {
                    req = req.header("Authorization", format!("Bearer {key}"));
                }
                req
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_completion_response(&response_body)
    }

    /// Anthropic Messages API completion.
    async fn complete_anthropic(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let url = format!("{}/messages", self.config.base_url);

        // Anthropic separates system prompt from messages.
        // Role::Compaction is folded into the system slot too, with
        // its content wrapped in the compaction fence, so a summary
        // of trimmed turns arrives as harness text rather than as
        // something the model could read as a user turn.
        let system_prompt: String = messages
            .iter()
            .filter(|m| m.role == Role::System || m.role == Role::Compaction)
            .map(|m| {
                if m.role == Role::Compaction {
                    format!(
                        "{}\n{}\n{}",
                        crate::conversation::COMPACTION_FENCE_OPEN,
                        m.content,
                        crate::conversation::COMPACTION_FENCE_CLOSE,
                    )
                } else {
                    m.content.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let messages_json: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System && m.role != Role::Compaction)
            .map(|m| {
                let role = match m.role {
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "user", // Anthropic: tool results go in user messages
                    Role::System | Role::Compaction => unreachable!(),
                };
                if m.role == Role::Tool
                    && let Some(ref id) = m.tool_call_id
                {
                    serde_json::json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": m.content,
                        }]
                    })
                } else if m.role == Role::Assistant
                    && let Some(ref tool_calls) = m.tool_calls
                {
                    let mut blocks: Vec<serde_json::Value> = Vec::new();
                    if !m.content.is_empty() {
                        blocks.push(serde_json::json!({"type": "text", "text": m.content}));
                    }
                    for tc in tool_calls {
                        let input: serde_json::Value =
                            serde_json::from_str(&tc.arguments).unwrap_or(serde_json::json!({}));
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": input,
                        }));
                    }
                    serde_json::json!({
                        "role": "assistant",
                        "content": blocks,
                    })
                } else {
                    serde_json::json!({
                        "role": role,
                        "content": m.content,
                    })
                }
            })
            .collect();

        let mut messages_json = messages_json;
        cache_conversation_prefix(&mut messages_json);
        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages_json,
            "max_tokens": self.config.max_tokens,
        });

        // Send the system prompt as a content-block array with
        // cache_control on the last block. Anthropic
        // caches everything up to and including the last block
        // marked ephemeral, so the system prompt (which is stable
        // across turns) gets a prompt-cache hit on repeat calls
        // within the 5-minute TTL.
        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!([{
                "type": "text",
                "text": system_prompt,
                "cache_control": wirken_audit::pricing::requested_cache_control(),
            }]);
        }

        if !tools.is_empty() {
            let mut tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.parameters,
                    })
                })
                .collect();
            // Mark the last tool def as cacheable so the full tool
            // surface is inside the prompt cache prefix.
            if let Some(last) = tools_json.last_mut() {
                last["cache_control"] = wirken_audit::pricing::requested_cache_control();
            }
            body["tools"] = serde_json::Value::Array(tools_json);
        }

        let response = self
            .send_with_retry(|| {
                let mut req = self
                    .http
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("anthropic-version", "2023-06-01");
                if let Some(key) = api_key {
                    req = req.header("x-api-key", key);
                }
                req.json(&body)
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_anthropic_response(&response_body)
    }

    /// Google Gemini generateContent API.
    async fn complete_gemini(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let key = api_key.ok_or_else(|| AgentError::Llm("Gemini requires an API key".into()))?;
        let url = format!(
            "{}/models/{}:generateContent",
            self.config.base_url, self.config.model
        );

        // Extract system prompt. Role::Compaction is folded in here
        // with the fence wrapper, same as the Anthropic path.
        let system_text: String = messages
            .iter()
            .filter(|m| m.role == Role::System || m.role == Role::Compaction)
            .map(|m| {
                if m.role == Role::Compaction {
                    format!(
                        "{}\n{}\n{}",
                        crate::conversation::COMPACTION_FENCE_OPEN,
                        m.content,
                        crate::conversation::COMPACTION_FENCE_CLOSE,
                    )
                } else {
                    m.content.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Build contents array
        let contents: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System && m.role != Role::Compaction)
            .map(|m| {
                let role = match m.role {
                    Role::User => "user",
                    Role::Assistant => "model",
                    Role::Tool => "user",
                    Role::System | Role::Compaction => unreachable!(),
                };
                let parts = if m.role == Role::Tool
                    && m.tool_call_id.is_some()
                    && let Some(ref name) = m.tool_name
                {
                    // Tool result -> functionResponse
                    let response_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "functionResponse": {
                            "name": name,
                            "response": response_val,
                        }
                    }])
                } else if m.role == Role::Tool {
                    // Tool result without structured info — use tool_name or call ID
                    let fn_name = m
                        .tool_name
                        .as_deref()
                        .or(m.tool_call_id.as_deref())
                        .unwrap_or("unknown");
                    let response_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "functionResponse": {
                            "name": fn_name,
                            "response": response_val,
                        }
                    }])
                } else {
                    serde_json::json!([{"text": m.content}])
                };
                serde_json::json!({
                    "role": role,
                    "parts": parts,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            },
        });

        if !system_text.is_empty() {
            body["systemInstruction"] = serde_json::json!({
                "parts": [{"text": system_text}]
            });
        }

        if !tools.is_empty() {
            let decls: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    })
                })
                .collect();
            body["tools"] = serde_json::json!([{
                "functionDeclarations": decls,
            }]);
        }

        let response = self
            .send_with_retry(|| {
                self.http
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("x-goog-api-key", key)
                    .json(&body)
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_gemini_response(&response_body)
    }

    /// AWS Bedrock Converse API.
    async fn complete_bedrock(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Option<Usage>), AgentError> {
        let credentials =
            api_key.ok_or_else(|| AgentError::Llm("Bedrock requires AWS credentials".into()))?;

        // Parse access_key_id:secret_access_key[:session_token]
        let parts: Vec<&str> = credentials.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(AgentError::Llm(
                "Bedrock credentials must be access_key_id:secret_access_key".into(),
            ));
        }
        let access_key = parts[0];
        let secret_key = parts[1];
        let session_token = parts.get(2).copied();

        let region = self
            .config
            .region
            .as_deref()
            .or_else(|| {
                // Extract region from base_url
                self.config
                    .base_url
                    .strip_prefix("https://bedrock-runtime.")
                    .and_then(|s| s.strip_suffix(".amazonaws.com"))
            })
            .ok_or_else(|| AgentError::Llm("Bedrock requires a region".into()))?;

        let url = format!(
            "{}/model/{}/converse",
            self.config.base_url, self.config.model
        );

        // Extract system prompt. Role::Compaction is folded in here
        // as another system block with the fence wrapper.
        let system_blocks: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role == Role::System || m.role == Role::Compaction)
            .map(|m| {
                if m.role == Role::Compaction {
                    serde_json::json!({
                        "text": format!(
                            "{}\n{}\n{}",
                            crate::conversation::COMPACTION_FENCE_OPEN,
                            m.content,
                            crate::conversation::COMPACTION_FENCE_CLOSE,
                        )
                    })
                } else {
                    serde_json::json!({"text": m.content})
                }
            })
            .collect();

        // Build messages array
        let bedrock_messages: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != Role::System && m.role != Role::Compaction)
            .map(|m| {
                let role = match m.role {
                    Role::User | Role::Tool => "user",
                    Role::Assistant => "assistant",
                    Role::System | Role::Compaction => unreachable!(),
                };
                let content = if m.role == Role::Tool
                    && let Some(ref id) = m.tool_call_id
                {
                    let result_val: serde_json::Value = serde_json::from_str(&m.content)
                        .unwrap_or_else(|_| serde_json::json!({"result": m.content}));
                    serde_json::json!([{
                        "toolResult": {
                            "toolUseId": id,
                            "content": [{"json": result_val}],
                        }
                    }])
                } else {
                    serde_json::json!([{"text": m.content}])
                };
                serde_json::json!({
                    "role": role,
                    "content": content,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "messages": bedrock_messages,
            "inferenceConfig": {
                "maxTokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            },
        });

        if !system_blocks.is_empty() {
            body["system"] = serde_json::Value::Array(system_blocks);
        }

        if !tools.is_empty() {
            let tool_specs: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "toolSpec": {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": {"json": t.parameters},
                        }
                    })
                })
                .collect();
            body["toolConfig"] = serde_json::json!({
                "tools": tool_specs,
            });
        }

        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| AgentError::Llm(format!("serialize request: {e}")))?;

        let parsed_url =
            url::Url::parse(&url).map_err(|e| AgentError::Llm(format!("invalid URL: {e}")))?;

        // SigV4 timestamps live in the headers, so each retry must
        // re-sign — a stale `x-amz-date` over five minutes old gets a
        // 403 from Bedrock. The closure rebuilds the auth headers per
        // attempt.
        let response = self
            .send_with_retry(|| {
                let auth_headers = crate::sigv4::sign(
                    access_key,
                    secret_key,
                    session_token,
                    region,
                    "bedrock",
                    "POST",
                    &parsed_url,
                    &body_bytes,
                );
                let mut req = self
                    .http
                    .post(&url)
                    .header("Content-Type", "application/json");
                for (name, value) in &auth_headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                req.body(body_bytes.clone())
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentError::Llm(format!("HTTP {status}: {body}")));
        }

        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::Http(format!("parse response: {e}")))?;

        self.set_stop_reason(stop_reason_raw_in(&response_body));

        parse_bedrock_response(&response_body)
    }

    /// Get the current config.
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }

    /// Get the HTTP client (for streaming).
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http
    }
}

/// The request headers a forwarded call keeps: the ones that describe
/// the body or select the provider's API version. Everything else a
/// client sent, its own credential included, stays behind.
pub const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "anthropic-version",
    "anthropic-beta",
];

/// Whether `provider`'s endpoint takes requests of `shape` as they
/// are, with no translation. Gemini and Bedrock have request shapes of
/// their own and take neither.
pub fn provider_speaks(provider: &str, shape: wirken_audit::ProxyShape) -> bool {
    use wirken_audit::ProxyShape;
    match (provider, shape) {
        ("gemini" | "bedrock", _) => false,
        // Anthropic's own API, and Ollama's compatible endpoint.
        ("anthropic" | "ollama", ProxyShape::AnthropicMessages) => true,
        (_, ProxyShape::AnthropicMessages) => false,
        ("anthropic", ProxyShape::OpenaiChat) => false,
        // OpenAI and every OpenAI-compatible provider, Ollama included.
        (_, ProxyShape::OpenaiChat) => true,
    }
}

/// The ids in an OpenAI-compatible model listing, sorted, each once.
fn listed_model_ids(body: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|models| {
            models
                .iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids.dedup();
    ids
}

/// The enclave host a tinfoil config's `base_url` names: an `https`
/// URL on the default port, since the SDK attests and pins port 443.
fn tinfoil_configured_host(base_url: &str) -> Result<String, AgentError> {
    url::Url::parse(base_url)
        .ok()
        .filter(|u| u.scheme() == "https" && u.port().is_none())
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .ok_or_else(|| {
            AgentError::Llm(format!(
                "tinfoil misconfigured: base_url {base_url:?} is not an https URL on port 443"
            ))
        })
}

/// The enclave hosts a tinfoil key may be sent to, in the order they
/// are attested: each router `discovered` lists whose origin
/// `permits` allows, then `configured`, the host of the base URL the
/// key was read for. A listed router that is not allowed is never
/// attested and never sent the key. `permits` is asked once for each
/// distinct router other than the configured host.
fn tinfoil_hosts(
    discovered: &[String],
    configured: &str,
    permits: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut asked: Vec<String> = Vec::new();
    for router in discovered {
        let host = router.trim().to_ascii_lowercase();
        if host.is_empty() || host == configured || asked.contains(&host) {
            continue;
        }
        if permits(&format!("https://{host}")) {
            hosts.push(host.clone());
        }
        asked.push(host);
    }
    hosts.push(configured.to_string());
    hosts
}

/// True when a `reqwest::Error` indicates the connection was rejected
/// before HTTP semantics applied. Covers TLS-handshake failure (which
/// is the surface tinfoil's cert-pinning rejection takes) and plain
/// network unavailability. Used by [`LlmClient::complete_tinfoil`] to
/// decide whether to drop the cached `tinfoil::Client` and re-attest
/// on the next call: the false-positive case (network was down, cert
/// is fine) costs at most one extra attestation round trip on the
/// subsequent successful call.
fn is_pinned_tls_failure(e: &reqwest::Error) -> bool {
    e.is_connect()
}

/// Build the JSON body for the OpenAI-compatible chat-completion
/// request. Extracted from [`LlmClient::complete_openai`] so unit
/// tests can verify the body shape (notably the ollama-side
/// `options.num_ctx` injection) without a live HTTP round-trip.
pub(crate) fn build_openai_request_body(
    config: &LlmConfig,
    messages_json: Vec<serde_json::Value>,
    tools: &[ToolDef],
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "model": config.model,
        "messages": messages_json,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "stream": false,
    });
    if !tools.is_empty() {
        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect();
        body["tools"] = serde_json::Value::Array(tools_json);
    }
    if config.provider == "ollama" {
        // Defense-in-depth: ollama configs that go through the
        // OpenAI-compat path (e.g. tests, custom-routed callers) still
        // get `num_ctx` injected. The native `/api/chat` path used by
        // [`LlmClient::complete_ollama`] is the canonical route; the
        // compat bridge silently drops this anyway, but emitting it
        // keeps the request shape consistent with what ollama
        // documents.
        body["options"] = serde_json::json!({ "num_ctx": config.context_window });
    }
    body
}

/// Walk one message and convert any `tool_calls[].function.arguments`
/// from JSON-encoded string form (the OpenAI shape) to parsed JSON
/// value form (the ollama shape). Non-tool-call messages and messages
/// whose arguments don't parse as JSON are returned unchanged.
fn normalize_tool_call_args_for_ollama(mut msg: serde_json::Value) -> serde_json::Value {
    if let Some(tool_calls) = msg.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
        for tc in tool_calls.iter_mut() {
            let parsed = tc
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
            if let Some(parsed_args) = parsed
                && let Some(func) = tc.get_mut("function")
            {
                func["arguments"] = parsed_args;
            }
        }
    }
    msg
}

/// Construct the URL for ollama's native `/api/chat` endpoint, given a
/// `base_url` that may include a trailing `/v1` (the OpenAI-compat
/// bridge path) or end with `/`. The native endpoint sits at
/// `<host>/api/chat` regardless of the configured base.
pub(crate) fn ollama_chat_url(base_url: &str) -> String {
    let host = base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/');
    format!("{host}/api/chat")
}

/// Build the request body for ollama's native `/api/chat` endpoint.
/// Differences from OpenAI-compat: `max_tokens` and `temperature`
/// move into `options`; `num_predict` is the ollama spelling of
/// max-tokens; `num_ctx` declares the model context window so ollama
/// loads the model with that window rather than its 4K (or 2K)
/// default.
pub(crate) fn build_ollama_request_body(
    config: &LlmConfig,
    messages_json: Vec<serde_json::Value>,
    tools: &[ToolDef],
) -> serde_json::Value {
    // Ollama's `/api/chat` expects `tool_calls[].function.arguments`
    // as a JSON object. The shared `message_to_json` helper emits it
    // as a JSON-encoded string (the OpenAI shape). Walk the messages
    // and parse the argument string back to a value so ollama's
    // request-body parser doesn't bail with "Value looks like object,
    // but can't find closing '}'" when it tries to read the encoded
    // string as a nested object.
    let messages_json: Vec<serde_json::Value> = messages_json
        .into_iter()
        .map(normalize_tool_call_args_for_ollama)
        .collect();
    let mut body = serde_json::json!({
        "model": config.model,
        "messages": messages_json,
        "options": {
            "num_ctx": config.context_window,
            "num_predict": config.max_tokens,
            "temperature": config.temperature,
        },
        "stream": false,
    });
    if !tools.is_empty() {
        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect();
        body["tools"] = serde_json::Value::Array(tools_json);
    }
    body
}

/// Parse an ollama `/api/chat` response into [`LlmResponse`] +
/// [`Usage`]. Ollama tool_calls do not carry an `id` field, so the
/// parser synthesizes a stable index-keyed id (`call_0`, `call_1`,
/// …); the rest of the agent pipeline uses the synthesized id to
/// match later tool-result messages to their requests. Tool-call
/// arguments may arrive as a JSON object (ollama's native shape) or
/// as a JSON-encoded string; both are normalized to the
/// JSON-encoded-string shape that [`crate::conversation::ToolCallRequest`] holds.
pub fn parse_ollama_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Option<Usage>), AgentError> {
    let message = body
        .get("message")
        .ok_or_else(|| AgentError::Llm("no message in ollama response".into()))?;

    // Ollama's `/api/chat` non-streaming reply carries
    // `prompt_eval_count` and `eval_count` on the top-level object.
    // Returning `None` when neither key is present keeps the runtime's
    // distinction between "provider reported zero" and "we don't know"
    // intact: a malformed/legacy ollama response without these fields
    // records cost as `None` rather than `Some(0)`.
    let usage = if body.get("prompt_eval_count").is_some() || body.get("eval_count").is_some() {
        Some(Usage {
            input_tokens: body
                .get("prompt_eval_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            output_tokens: body.get("eval_count").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        })
    } else {
        None
    };

    if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
        let calls: Vec<ToolCallRequest> = tool_calls
            .iter()
            .enumerate()
            .filter_map(|(i, tc)| {
                let func = tc.get("function")?;
                let name = func.get("name")?.as_str()?.to_string();
                // Arguments may be a string (JSON-encoded) or an object.
                let arguments = match func.get("arguments") {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(v) => serde_json::to_string(v).ok()?,
                    None => return None,
                };
                let id = tc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("call_{i}"));
                Some(ToolCallRequest {
                    id,
                    name,
                    arguments,
                })
            })
            .collect();
        if !calls.is_empty() {
            // The content field of the same message. Providers put
            // the model's own sentence here beside the calls.
            let text = message
                .get("content")
                .and_then(|c| c.as_str())
                .map(str::to_string)
                .filter(|t| !t.is_empty());
            return Ok((
                LlmResponse::ToolCalls {
                    calls,
                    text,
                    reasoning: message_reasoning(message),
                },
                usage,
            ));
        }
    }

    if let Some(content) = message.get("content").and_then(|c| c.as_str())
        && !content.is_empty()
    {
        return Ok((LlmResponse::Text(content.to_string()), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// The reasoning an OpenAI-compatible or Ollama message carries beside
/// its content. Providers name the field differently: `reasoning_content`,
/// `reasoning`, and `thinking` on Ollama's own API.
pub(crate) fn message_reasoning(message: &serde_json::Value) -> Option<String> {
    ["reasoning_content", "reasoning", "thinking"]
        .iter()
        .filter_map(|key| message.get(key).and_then(|v| v.as_str()))
        .find(|text| !text.is_empty())
        .map(str::to_string)
}

/// Reasoning collected in parts, as one string, or `None` for none.
pub(crate) fn joined_reasoning(parts: &[String]) -> Option<String> {
    Some(parts.join("")).filter(|t| !t.is_empty())
}

pub(crate) fn message_to_json(msg: &Message) -> serde_json::Value {
    // Role::Compaction is folded into the provider's `system` role
    // with the content wrapped in the compaction fence. The agent's
    // system prompt instructs the
    // model to treat fenced blocks as harness-controlled facts.
    let (wire_role, wire_content) = if msg.role == Role::Compaction {
        (
            "system".to_string(),
            format!(
                "{}\n{}\n{}",
                crate::conversation::COMPACTION_FENCE_OPEN,
                msg.content,
                crate::conversation::COMPACTION_FENCE_CLOSE,
            ),
        )
    } else {
        (
            serde_json::to_value(&msg.role)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "user".into()),
            msg.content.clone(),
        )
    };

    let mut obj = serde_json::json!({
        "role": wire_role,
        "content": wire_content,
    });

    if let Some(ref tool_call_id) = msg.tool_call_id {
        obj["tool_call_id"] = serde_json::Value::String(tool_call_id.clone());
    }

    if let Some(ref tool_calls) = msg.tool_calls {
        let calls: Vec<serde_json::Value> = tool_calls
            .iter()
            .map(|tc| {
                serde_json::json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                })
            })
            .collect();
        obj["tool_calls"] = serde_json::Value::Array(calls);
    }

    obj
}

pub fn parse_completion_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Option<Usage>), AgentError> {
    let choice = body
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| AgentError::Llm("no choices in response".into()))?;

    let message = choice
        .get("message")
        .ok_or_else(|| AgentError::Llm("no message in choice".into()))?;

    let usage = extract_openai_usage(body);

    // Check for tool calls
    if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
        let calls: Vec<ToolCallRequest> = tool_calls
            .iter()
            .filter_map(|tc| {
                let id = tc.get("id")?.as_str()?.to_string();
                let func = tc.get("function")?;
                let name = func.get("name")?.as_str()?.to_string();
                let arguments = func.get("arguments")?.as_str()?.to_string();
                Some(ToolCallRequest {
                    id,
                    name,
                    arguments,
                })
            })
            .collect();

        if !calls.is_empty() {
            // The content field of the same message. Providers put
            // the model's own sentence here beside the calls.
            let text = message
                .get("content")
                .and_then(|c| c.as_str())
                .map(str::to_string)
                .filter(|t| !t.is_empty());
            return Ok((
                LlmResponse::ToolCalls {
                    calls,
                    text,
                    reasoning: message_reasoning(message),
                },
                usage,
            ));
        }
    }

    // Text response
    if let Some(content) = message.get("content").and_then(|c| c.as_str())
        && !content.is_empty()
    {
        return Ok((LlmResponse::Text(content.to_string()), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Parse an Anthropic Messages API response.
pub fn parse_anthropic_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Option<Usage>), AgentError> {
    let content = body
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no content array in Anthropic response".into()))?;

    let mut text_parts = Vec::new();
    let mut reasoning_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in content {
        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match block_type {
            "text" => {
                if let Some(text) = block.get("text").and_then(|t| t.as_str())
                    && !text.is_empty()
                {
                    text_parts.push(text.to_string());
                }
            }
            "thinking" => {
                if let Some(text) = block.get("thinking").and_then(|t| t.as_str())
                    && !text.is_empty()
                {
                    reasoning_parts.push(text.to_string());
                }
            }
            "tool_use" => {
                let id = block
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = block.get("input").unwrap_or(&serde_json::Value::Null);
                let arguments = input.to_string();
                tool_calls.push(ToolCallRequest {
                    id,
                    name,
                    arguments,
                });
            }
            _ => {}
        }
    }

    let usage = extract_anthropic_usage(body);

    if !tool_calls.is_empty() {
        // The text blocks of the same message, joined the way the
        // text-only path below joins them.
        let text = Some(text_parts.join("")).filter(|t| !t.is_empty());
        return Ok((
            LlmResponse::ToolCalls {
                calls: tool_calls,
                text,
                reasoning: joined_reasoning(&reasoning_parts),
            },
            usage,
        ));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Parse a Google Gemini generateContent response.
pub fn parse_gemini_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Option<Usage>), AgentError> {
    let parts = body
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .ok_or_else(|| AgentError::Llm("no candidates/content/parts in Gemini response".into()))?;

    let mut text_parts = Vec::new();
    let mut reasoning_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for part in parts {
        if let Some(text) = part.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            // A part marked `thought` is the model's reasoning, not
            // its reply.
            if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                reasoning_parts.push(text.to_string());
            } else {
                text_parts.push(text.to_string());
            }
        }

        if let Some(fc) = part.get("functionCall") {
            let name = fc
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args = fc.get("args").unwrap_or(&serde_json::Value::Null);
            // Gemini doesn't return tool call IDs — generate one
            let id = format!("gemini_{}", uuid::Uuid::new_v4());
            tool_calls.push(ToolCallRequest {
                id,
                name,
                arguments: args.to_string(),
            });
        }
    }

    let usage = extract_gemini_usage(body);

    if !tool_calls.is_empty() {
        // The text blocks of the same message, joined the way the
        // text-only path below joins them.
        let text = Some(text_parts.join("")).filter(|t| !t.is_empty());
        return Ok((
            LlmResponse::ToolCalls {
                calls: tool_calls,
                text,
                reasoning: joined_reasoning(&reasoning_parts),
            },
            usage,
        ));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Parse an AWS Bedrock Converse API response.
pub fn parse_bedrock_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Option<Usage>), AgentError> {
    let content = body
        .get("output")
        .and_then(|o| o.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no output/message/content in Bedrock response".into()))?;

    let mut text_parts = Vec::new();
    let mut reasoning_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in content {
        if let Some(text) = block.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            text_parts.push(text.to_string());
        }

        if let Some(text) = block
            .pointer("/reasoningContent/reasoningText/text")
            .and_then(|t| t.as_str())
            && !text.is_empty()
        {
            reasoning_parts.push(text.to_string());
        }

        if let Some(tu) = block.get("toolUse") {
            let id = tu
                .get("toolUseId")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let name = tu
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let input = tu.get("input").unwrap_or(&serde_json::Value::Null);
            tool_calls.push(ToolCallRequest {
                id,
                name,
                arguments: input.to_string(),
            });
        }
    }

    let usage = extract_bedrock_usage(body);

    if !tool_calls.is_empty() {
        // The text blocks of the same message, joined the way the
        // text-only path below joins them.
        let text = Some(text_parts.join("")).filter(|t| !t.is_empty());
        return Ok((
            LlmResponse::ToolCalls {
                calls: tool_calls,
                text,
                reasoning: joined_reasoning(&reasoning_parts),
            },
            usage,
        ));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Pull the anthropic `usage` block. Reads `input_tokens`,
/// `output_tokens`, plus optional `cache_creation_input_tokens` and
/// `cache_read_input_tokens` (anthropic prompt-caching).
///
/// Returns `None` iff the provider did NOT include a `usage` block on
/// the response. Returning `Some(Usage { ..zero })` instead would
/// flatten "provider reported zero" into "provider reported nothing"
/// and lose the distinction the audit chain needs to honestly record
/// cost as `None` rather than `Some(0)`. See [`Usage`].
pub(crate) fn extract_anthropic_usage(body: &serde_json::Value) -> Option<Usage> {
    let u = body.get("usage")?;
    Some(Usage {
        input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        cache_creation_input_tokens: u
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        cache_read_input_tokens: u
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
    })
}

/// Pull the OpenAI-shape `usage` block. Reads `prompt_tokens` and
/// `completion_tokens`. Endpoints that do not populate the block (some
/// custom OpenAI-compatible servers, older ollama versions) yield
/// `None` so the runtime can record cost as `None` rather than
/// `Some(0)`.
pub(crate) fn extract_openai_usage(body: &serde_json::Value) -> Option<Usage> {
    let u = body.get("usage")?;
    Some(Usage {
        input_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        output_tokens: u
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    })
}

/// Pull the gemini `usageMetadata` block. Reads `promptTokenCount` and
/// `candidatesTokenCount`. `None` iff the block is absent.
fn extract_gemini_usage(body: &serde_json::Value) -> Option<Usage> {
    let u = body.get("usageMetadata")?;
    Some(Usage {
        input_tokens: u
            .get("promptTokenCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        output_tokens: u
            .get("candidatesTokenCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    })
}

/// Pull the bedrock Converse `usage` block. Reads `inputTokens` and
/// `outputTokens`. `None` iff the block is absent.
fn extract_bedrock_usage(body: &serde_json::Value) -> Option<Usage> {
    let u = body.get("usage")?;
    Some(Usage {
        input_tokens: u.get("inputTokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        output_tokens: u.get("outputTokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    })
}

/// Build the tool definitions in OpenAI function calling format.
pub fn tools_to_json(tools: &[ToolDef]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            })
        })
        .collect()
}

/// Whether `url` is plain HTTP to this host, the one case reached
/// without TLS. The host is parsed out and compared whole, so a name
/// that only starts like a loopback one is not one.
pub(crate) fn plain_http_to_loopback(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    })
}

#[cfg(test)]
mod tinfoil_host_tests {
    use super::{tinfoil_configured_host, tinfoil_hosts};
    use std::cell::RefCell;

    const CONFIGURED: &str = "inference.tinfoil.sh";

    fn discovered() -> Vec<String> {
        vec![
            "router-0.tinfoil.sh".to_string(),
            "inference.tinfoil.sh".to_string(),
            "Router-0.tinfoil.sh".to_string(),
        ]
    }

    /// A discovered router at an origin the key is not allowed is not
    /// among the hosts attested and sent the key; the configured host
    /// is. The router is asked about once, by its origin.
    #[test]
    fn a_discovered_router_the_key_may_not_go_to_is_left_out() {
        let asked = RefCell::new(Vec::new());
        let hosts = tinfoil_hosts(&discovered(), CONFIGURED, |origin| {
            asked.borrow_mut().push(origin.to_string());
            false
        });
        assert_eq!(hosts, [CONFIGURED]);
        assert_eq!(*asked.borrow(), ["https://router-0.tinfoil.sh"]);
    }

    /// An allowed router is tried first, the configured host last.
    #[test]
    fn an_allowed_discovered_router_comes_before_the_configured_host() {
        let hosts = tinfoil_hosts(&discovered(), CONFIGURED, |_| true);
        assert_eq!(hosts, ["router-0.tinfoil.sh", CONFIGURED]);
    }

    /// With no discovery answer the configured host is the only one.
    #[test]
    fn no_discovery_leaves_the_configured_host() {
        assert_eq!(tinfoil_hosts(&[], CONFIGURED, |_| true), [CONFIGURED]);
    }

    #[test]
    fn a_listing_gives_each_model_id_once_in_order() {
        let body = serde_json::json!({"data": [
            {"id": "qwen"}, {"id": "deepseek"}, {"object": "model"}, {"id": "qwen"}
        ]});
        assert_eq!(super::listed_model_ids(&body), ["deepseek", "qwen"]);
        assert!(super::listed_model_ids(&serde_json::json!({})).is_empty());
    }

    /// A model listing is refused for an endpoint that cannot be
    /// attested, before anything is sent: the key is not put on a
    /// request to a host no attestation covers.
    #[tokio::test]
    async fn a_listing_sends_no_key_to_an_endpoint_that_is_not_attested() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = got.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                kept.lock().unwrap().push(buf[..n].to_vec());
            }
        });
        let client =
            super::LlmClient::new(super::LlmConfig::from_provider("tinfoil", &base, "m")).unwrap();
        let err = client
            .tinfoil_models("tk-listing-key-0123456789")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("tinfoil misconfigured"), "{err}");
        assert!(got.lock().unwrap().is_empty());
    }

    #[test]
    fn the_configured_host_is_an_https_host_on_the_default_port() {
        assert_eq!(
            tinfoil_configured_host("https://Inference.tinfoil.sh/v1").unwrap(),
            CONFIGURED
        );
        for url in [
            "http://inference.tinfoil.sh/v1",
            "https://inference.tinfoil.sh:8443/v1",
            "inference.tinfoil.sh",
        ] {
            assert!(tinfoil_configured_host(url).is_err(), "{url}");
        }
    }
}

#[cfg(test)]
mod plain_http_tests {
    use super::{LlmClient, LlmConfig};

    fn accepted(base_url: &str) -> bool {
        LlmClient::new(LlmConfig::custom(base_url, "m")).is_ok()
    }

    /// Plain HTTP reaches this host and no other: a name that only
    /// starts like a loopback one is some other host.
    #[test]
    fn plain_http_is_for_a_loopback_host_and_no_name_that_starts_like_one() {
        for url in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:11434/v1",
            "http://[::1]:11434/v1",
            "https://llm.example.com/v1",
        ] {
            assert!(accepted(url), "{url}");
        }
        for url in [
            "http://localhost.example.com/v1",
            "http://127.0.0.1.example.com/v1",
            "http://localhost@example.com/v1",
            "http://example.com/v1",
        ] {
            assert!(!accepted(url), "{url}");
        }
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::{LlmClient, LlmConfig};
    use crate::conversation::{Message, Role};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A loopback server that keeps the head of each request and
    /// answers every one with `reply`.
    async fn server(reply: String) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = heads.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (kept, reply) = (kept.clone(), reply.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    kept.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (base, heads)
    }

    /// A provider endpoint that answers 307 to `elsewhere`, a second
    /// server that would take whatever followed it.
    async fn redirecting() -> (String, Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<String>>>) {
        let (elsewhere, followed) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\
             Connection: close\r\n\r\n{}"
                .to_string(),
        )
        .await;
        let (base, asked) = server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/taken\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ))
        .await;
        (base, asked, followed)
    }

    fn hello() -> Vec<Message> {
        vec![Message {
            role: Role::User,
            content: "hello".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }]
    }

    const KEY: &str = "sk-redirect-test-key-0123456789";

    /// The provider answered with a redirect: the call fails, the key
    /// went to the configured origin under `header`, and nothing was
    /// sent to where the redirect pointed.
    async fn assert_not_followed(config: LlmConfig, key: &str, header: &str, streamed: bool) {
        let (base, asked, followed) = redirecting().await;
        let config = LlmConfig {
            base_url: format!("{base}/v1"),
            ..config
        };
        let provider = config.provider.clone();
        let client = LlmClient::new(config).unwrap();
        let result = if streamed {
            let (tx, _rx) = tokio::sync::mpsc::channel(16);
            client.complete_stream(&hello(), &[], Some(key), tx).await
        } else {
            client.complete(&hello(), &[], Some(key)).await
        };
        assert!(result.is_err(), "{provider}: a redirect was answered");
        let asked = asked.lock().unwrap().clone();
        assert_eq!(asked.len(), 1, "{provider}: {asked:?}");
        assert!(asked[0].contains(header), "{provider}: {}", asked[0]);
        let followed = followed.lock().unwrap().clone();
        assert!(
            followed.is_empty(),
            "{provider}: the redirect target was sent {followed:?}"
        );
    }

    #[tokio::test]
    async fn an_anthropic_key_is_not_sent_where_a_redirect_points() {
        let config = LlmConfig::anthropic("m");
        assert_not_followed(config.clone(), KEY, "x-api-key: sk-redirect", false).await;
        assert_not_followed(config, KEY, "x-api-key: sk-redirect", true).await;
    }

    #[tokio::test]
    async fn a_gemini_key_is_not_sent_where_a_redirect_points() {
        let config = LlmConfig::gemini("m");
        assert_not_followed(config, KEY, "x-goog-api-key: sk-redirect", false).await;
    }

    #[tokio::test]
    async fn an_openai_compatible_key_is_not_sent_where_a_redirect_points() {
        for provider in ["openai", "custom", "hetzner"] {
            let config = LlmConfig::from_provider(provider, "http://127.0.0.1:9/v1", "m");
            let header = "authorization: bearer sk-redirect";
            assert_not_followed(config.clone(), KEY, header, false).await;
            assert_not_followed(config, KEY, header, true).await;
        }
    }

    /// A signed Bedrock request carries its session token in a header
    /// of its own, which is not sent on either.
    #[tokio::test]
    async fn a_bedrock_session_token_is_not_sent_where_a_redirect_points() {
        let config = LlmConfig::bedrock("m", "us-east-1");
        assert_not_followed(
            config,
            "AKIAEXAMPLE:secretkey0123456789:session-token-0123456789",
            "x-amz-security-token: session-token-0123456789",
            false,
        )
        .await;
    }
}

#[cfg(test)]
mod forward_tests {
    use super::{LlmClient, LlmConfig, provider_speaks};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wirken_audit::ProxyShape;

    /// A loopback server that keeps each whole request and answers
    /// with `reply`.
    async fn server(reply: String) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
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
                    let mut chunk = [0u8; 4096];
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
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (base, got)
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn each_provider_takes_its_own_shape_and_no_other() {
        use ProxyShape::{AnthropicMessages, OpenaiChat};
        for provider in [
            "openai",
            "custom",
            "hetzner",
            "infomaniak",
            "tinfoil",
            "ollama",
        ] {
            assert!(provider_speaks(provider, OpenaiChat), "{provider}");
        }
        for provider in ["anthropic", "ollama"] {
            assert!(provider_speaks(provider, AnthropicMessages), "{provider}");
        }
        for provider in ["openai", "custom", "hetzner", "tinfoil"] {
            assert!(!provider_speaks(provider, AnthropicMessages), "{provider}");
        }
        assert!(!provider_speaks("anthropic", OpenaiChat));
        for provider in ["gemini", "bedrock"] {
            assert!(!provider_speaks(provider, OpenaiChat), "{provider}");
            assert!(!provider_speaks(provider, AnthropicMessages), "{provider}");
        }
    }

    /// The body reaches the provider byte for byte at the endpoint for
    /// its shape, with the provider's key in the provider's header.
    /// The client's own credential and its other headers stay behind,
    /// and the response comes back as the provider sent it.
    #[tokio::test]
    async fn a_request_is_forwarded_byte_for_byte_with_the_providers_key() {
        // Odd spacing, key order and an unknown field: a re-serialized
        // body would differ.
        let body = "{ \"model\":\"m\",  \"unknown_field\": [1,2 ,3],\"messages\":[]}";
        for (provider, shape, path, key_header) in [
            (
                "anthropic",
                ProxyShape::AnthropicMessages,
                "/v1/messages",
                "x-api-key: sk-provider-key",
            ),
            (
                "custom",
                ProxyShape::OpenaiChat,
                "/v1/chat/completions",
                "authorization: Bearer sk-provider-key",
            ),
        ] {
            let (base, got) = server(ok("{ \"answer\" : 1 }")).await;
            let client = LlmClient::new(LlmConfig::from_provider(
                provider,
                &format!("{base}/v1"),
                "unused",
            ))
            .unwrap();
            let headers = [
                ("Content-Type".to_string(), "application/json".to_string()),
                ("anthropic-version".to_string(), "2023-06-01".to_string()),
                (
                    "Authorization".to_string(),
                    "Bearer wkp_client_token".to_string(),
                ),
                ("X-Api-Key".to_string(), "wkp_client_token".to_string()),
                ("Cookie".to_string(), "a=b".to_string()),
            ];
            let response = client
                .forward(
                    shape,
                    body.as_bytes().to_vec(),
                    &headers,
                    Some("sk-provider-key"),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.text().await.unwrap(), "{ \"answer\" : 1 }");

            let got = got.lock().unwrap().clone();
            assert_eq!(got.len(), 1, "{provider}");
            let (head, sent) = got[0].split_once("\r\n\r\n").unwrap();
            assert_eq!(sent, body, "{provider}");
            assert!(head.starts_with(&format!("POST {path} ")), "{head}");
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains(&key_header.to_ascii_lowercase()), "{head}");
            assert!(lower.contains("anthropic-version: 2023-06-01"), "{head}");
            assert!(!head.contains("wkp_client_token"), "{head}");
            assert!(!lower.contains("cookie"), "{head}");
        }
    }

    /// A shape the provider does not take is refused by name before
    /// anything is sent, and so is a body carrying a stored secret.
    #[tokio::test]
    async fn a_shape_the_provider_does_not_take_and_a_leaking_body_are_not_sent() {
        let (base, got) = server(ok("{}")).await;
        let client = LlmClient::new(LlmConfig::from_provider(
            "custom",
            &format!("{base}/v1"),
            "m",
        ))
        .unwrap();
        let err = client
            .forward(ProxyShape::AnthropicMessages, b"{}".to_vec(), &[], None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("custom does not take anthropic_messages"),
            "{err}"
        );

        let mut client = LlmClient::new(LlmConfig::from_provider(
            "custom",
            &format!("{base}/v1"),
            "m",
        ))
        .unwrap();
        let matcher = wirken_gateway::leak::LeakMatcher::new();
        matcher.learn(
            "other-key",
            "sk-stored-secret-0123456789",
            wirken_vault::CredentialKind::Secret,
        );
        client.set_leak_matcher(Arc::new(matcher));
        let err = client
            .forward(
                ProxyShape::OpenaiChat,
                b"{\"messages\":[{\"content\":\"sk-stored-secret-0123456789\"}]}".to_vec(),
                &[],
                None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::error::AgentError::LeakRefused { credential } if credential == "other-key"),
            "{err}"
        );
        assert!(got.lock().unwrap().is_empty());
    }

    /// A forwarded call follows no redirect, as an agent call does not.
    #[tokio::test]
    async fn a_forwarded_request_follows_no_redirect() {
        let (elsewhere, followed) = server(ok("{}")).await;
        let (base, _) = server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/taken\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ))
        .await;
        let client = LlmClient::new(LlmConfig::from_provider(
            "anthropic",
            &format!("{base}/v1"),
            "m",
        ))
        .unwrap();
        let response = client
            .forward(
                ProxyShape::AnthropicMessages,
                b"{}".to_vec(),
                &[],
                Some("sk-provider-key"),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 307);
        assert!(followed.lock().unwrap().is_empty());
    }
}
