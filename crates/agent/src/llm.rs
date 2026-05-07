use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::conversation::{Message, Role, ToolCallRequest};
use crate::error::AgentError;
use crate::recovery::{MAX_RATE_LIMIT_RETRIES, RecoveryObserver, RetryDecision, classify_429};
use crate::tool::ToolDef;

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name: "openai", "anthropic", "gemini", "bedrock", "ollama", "custom"
    pub provider: String,
    /// Model ID (e.g., "gpt-4o", "claude-sonnet-4-20250514", "gemini-2.0-flash")
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
    /// providers with reliable tool support, false for local models.
    #[serde(default = "default_tools_enabled")]
    pub tools_enabled: bool,
    /// Total context window in tokens. The [`crate::context::ContextEngine`]
    /// uses this as the budget ceiling for trimming conversations before
    /// each LLM call. Item 4 slice 1 in `docs/managed-agents-parity.md`.
    /// Defaults to a conservative 32_000 if missing — existing
    /// [`LlmConfig`] entries deserialized from older data files get this.
    #[serde(default = "default_context_window")]
    pub context_window: usize,
}

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
            context_window: 128_000,
        }
    }

    /// Anthropic defaults
    pub fn anthropic(model: &str) -> Self {
        Self {
            provider: "anthropic".into(),
            model: model.into(),
            base_url: "https://api.anthropic.com/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
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
            context_window: 32_768,
        }
    }

    /// Tinfoil confidential inference. Dispatches through the
    /// tinfoil-rs SDK so each session is gated on a successful
    /// AMD SEV-SNP attestation + Sigstore code provenance check
    /// against the published enclave repo, and chat traffic flows
    /// over a TLS connection pinned to the attested certificate.
    /// `base_url` is vestigial here: the SDK's discovery endpoint
    /// picks the host at construction time and the value is unused
    /// by the tinfoil dispatch path.
    pub fn tinfoil(model: &str) -> Self {
        Self {
            provider: "tinfoil".into(),
            model: model.into(),
            base_url: "https://inference.tinfoil.sh/v1".into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
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
            _ => 32_000,
        };
        Self {
            provider: provider.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: 4096,
            temperature: 0.7,
            region: None,
            tools_enabled: true,
            context_window,
        }
    }
}

/// Response from the LLM.
#[derive(Debug, Clone)]
pub enum LlmResponse {
    /// Text response — the assistant replied with content.
    Text(String),
    /// Tool calls — the assistant wants to call tools.
    ToolCalls(Vec<ToolCallRequest>),
    /// Empty response (shouldn't happen but handle gracefully).
    Empty,
}

/// Token-usage metadata returned alongside an LLM response. Captured
/// from each provider's `usage` block. Cache fields are
/// anthropic-specific and stay zero for other providers. Endpoints
/// that do not populate a usage block (some custom OpenAI-compatible
/// servers, including ollama) yield an all-zero `Usage`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub cache_read_input_tokens: u32,
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
    /// Lazy-initialized tinfoil SDK client. Construction performs
    /// AMD SEV-SNP attestation + Sigstore verification + TLS pinning
    /// against the discovered enclave; the result is cached for the
    /// process lifetime. Reset to `None` by `complete_tinfoil` when
    /// an attestation or TLS-pinning error surfaces, so the next
    /// call re-attests rather than retrying against a stale pinned
    /// transport. `tokio::sync::Mutex` rather than `std::sync::Mutex`
    /// because the lock is held across the SDK's `await`s during
    /// initialization.
    tinfoil: tokio::sync::Mutex<Option<Arc<tinfoil::Client>>>,
}

impl LlmClient {
    /// Create a new LLM client.
    /// Enforces HTTPS for non-localhost endpoints to prevent API key leakage.
    pub fn new(config: LlmConfig) -> Result<Self, AgentError> {
        let is_localhost = config.base_url.starts_with("http://localhost")
            || config.base_url.starts_with("http://127.0.0.1")
            || config.base_url.starts_with("http://[::1]");

        if !config.base_url.starts_with("https://") && !is_localhost {
            return Err(AgentError::Http(format!(
                "LLM endpoint must use HTTPS (got {}). Use HTTPS or localhost.",
                config.base_url
            )));
        }

        let http = reqwest::Client::builder()
            .https_only(!is_localhost)
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Http(format!("HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            observer: Mutex::new(None),
            tinfoil: tokio::sync::Mutex::new(None),
        })
    }

    /// Register a recovery observer. Replaces any previously set
    /// observer. The observer's `on_rate_limited` and
    /// `on_rate_limit_exhausted` hooks are called from
    /// `send_with_retry` as 429 retries are scheduled and exhausted.
    pub fn set_recovery_observer(&self, observer: Arc<dyn RecoveryObserver>) {
        *self.observer.lock().unwrap() = Some(observer);
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
    /// or non-429 error) is returned to the caller unchanged. Network
    /// errors propagate immediately (no retry) so a wedged client
    /// doesn't sit in a backoff loop.
    async fn send_with_retry<F>(&self, mut build: F) -> Result<reqwest::Response, AgentError>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        let mut attempt: u32 = 1;
        loop {
            let resp = build()
                .send()
                .await
                .map_err(|e| AgentError::Http(e.to_string()))?;
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
    pub async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
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
    /// Failure modes that drop the cached client and force re-
    /// attestation on the next call: `Error::is_attestation()`,
    /// `Error::CertificateMismatch`, and `Error::Tls(_)`. Other
    /// failures (network, configuration, API errors) leave the
    /// cached client intact and surface to the caller for the
    /// existing retry layers (lyrik, send-loop) to handle.
    async fn complete_tinfoil(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
        let api_key = api_key.ok_or_else(|| {
            AgentError::Llm(
                "tinfoil provider requires an API key; none was passed to complete()".into(),
            )
        })?;
        let client = self.tinfoil_client(api_key).await?;

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

        parse_completion_response(&response_body)
    }

    /// Lazy-init the tinfoil SDK client, caching the verified instance
    /// for the process lifetime. Holds the lock across the SDK's
    /// async verification call so two concurrent `complete()` calls
    /// share the same attestation rather than triggering two parallel
    /// SEV-SNP + Sigstore round trips.
    async fn tinfoil_client(&self, api_key: &str) -> Result<Arc<tinfoil::Client>, AgentError> {
        let mut guard = self.tinfoil.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = tinfoil::Client::new_default_with_api_key(api_key)
            .await
            .map_err(|e| {
                if e.is_attestation() {
                    AgentError::Llm(format!("tinfoil attestation failed: {e}"))
                } else if e.is_configuration() {
                    AgentError::Llm(format!("tinfoil misconfigured: {e}"))
                } else {
                    AgentError::Http(format!("tinfoil verification: {e}"))
                }
            })?;
        let arc = Arc::new(client);
        *guard = Some(arc.clone());
        Ok(arc)
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
    ) -> Result<(LlmResponse, Usage), AgentError> {
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

        parse_ollama_response(&response_body)
    }

    /// OpenAI-compatible completion (OpenAI, Ollama, custom endpoints).
    async fn complete_openai(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
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

        parse_completion_response(&response_body)
    }

    /// Anthropic Messages API completion.
    async fn complete_anthropic(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
        let url = format!("{}/messages", self.config.base_url);

        // Anthropic separates system prompt from messages.
        // Item 4 slice 2: Role::Compaction is also folded into the
        // system slot, with content wrapped in the compaction fence.
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

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages_json,
            "max_tokens": self.config.max_tokens,
        });

        // Item 4 slice 3: send the system prompt as a content-block
        // array with cache_control on the last block. Anthropic
        // caches everything up to and including the last block
        // marked ephemeral, so the system prompt (which is stable
        // across turns) gets a prompt-cache hit on repeat calls
        // within the 5-minute TTL.
        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!([{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
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
            // Item 4 slice 3: mark the last tool def as cacheable
            // so the full tool surface is included in the prompt
            // cache prefix.
            if let Some(last) = tools_json.last_mut() {
                last["cache_control"] = serde_json::json!({"type": "ephemeral"});
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

        parse_anthropic_response(&response_body)
    }

    /// Google Gemini generateContent API.
    async fn complete_gemini(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
        let key = api_key.ok_or_else(|| AgentError::Llm("Gemini requires an API key".into()))?;
        let url = format!(
            "{}/models/{}:generateContent",
            self.config.base_url, self.config.model
        );

        // Extract system prompt. Item 4 slice 2: Role::Compaction
        // is folded in here with the fence wrapper, same pattern as
        // Anthropic.
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

        parse_gemini_response(&response_body)
    }

    /// AWS Bedrock Converse API.
    async fn complete_bedrock(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        api_key: Option<&str>,
    ) -> Result<(LlmResponse, Usage), AgentError> {
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

        // Extract system prompt. Item 4 slice 2: Role::Compaction
        // is folded in here as another system block with the fence
        // wrapper.
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
pub fn parse_ollama_response(body: &serde_json::Value) -> Result<(LlmResponse, Usage), AgentError> {
    let message = body
        .get("message")
        .ok_or_else(|| AgentError::Llm("no message in ollama response".into()))?;

    let usage = Usage {
        input_tokens: body
            .get("prompt_eval_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        output_tokens: body.get("eval_count").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
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
            return Ok((LlmResponse::ToolCalls(calls), usage));
        }
    }

    if let Some(content) = message.get("content").and_then(|c| c.as_str())
        && !content.is_empty()
    {
        return Ok((LlmResponse::Text(content.to_string()), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

pub(crate) fn message_to_json(msg: &Message) -> serde_json::Value {
    // Item 4 slice 2: Role::Compaction is folded into the
    // provider's `system` role with the content wrapped in the
    // compaction fence. The agent's system prompt instructs the
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
) -> Result<(LlmResponse, Usage), AgentError> {
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
            return Ok((LlmResponse::ToolCalls(calls), usage));
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
) -> Result<(LlmResponse, Usage), AgentError> {
    let content = body
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no content array in Anthropic response".into()))?;

    let mut text_parts = Vec::new();
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
        return Ok((LlmResponse::ToolCalls(tool_calls), usage));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Parse a Google Gemini generateContent response.
pub fn parse_gemini_response(body: &serde_json::Value) -> Result<(LlmResponse, Usage), AgentError> {
    let parts = body
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .ok_or_else(|| AgentError::Llm("no candidates/content/parts in Gemini response".into()))?;

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for part in parts {
        if let Some(text) = part.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            text_parts.push(text.to_string());
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
        return Ok((LlmResponse::ToolCalls(tool_calls), usage));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Parse an AWS Bedrock Converse API response.
pub fn parse_bedrock_response(
    body: &serde_json::Value,
) -> Result<(LlmResponse, Usage), AgentError> {
    let content = body
        .get("output")
        .and_then(|o| o.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| AgentError::Llm("no output/message/content in Bedrock response".into()))?;

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in content {
        if let Some(text) = block.get("text").and_then(|t| t.as_str())
            && !text.is_empty()
        {
            text_parts.push(text.to_string());
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
        return Ok((LlmResponse::ToolCalls(tool_calls), usage));
    }

    if !text_parts.is_empty() {
        return Ok((LlmResponse::Text(text_parts.join("")), usage));
    }

    Ok((LlmResponse::Empty, usage))
}

/// Pull the anthropic `usage` block. Reads `input_tokens`,
/// `output_tokens`, plus optional `cache_creation_input_tokens` and
/// `cache_read_input_tokens` (anthropic prompt-caching). Missing fields
/// default to zero.
fn extract_anthropic_usage(body: &serde_json::Value) -> Usage {
    let Some(u) = body.get("usage") else {
        return Usage::default();
    };
    Usage {
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
    }
}

/// Pull the OpenAI-shape `usage` block. Reads `prompt_tokens` and
/// `completion_tokens`. Endpoints that do not populate the block (some
/// custom OpenAI-compatible servers, including ollama) yield
/// `Usage::default()`.
fn extract_openai_usage(body: &serde_json::Value) -> Usage {
    let Some(u) = body.get("usage") else {
        return Usage::default();
    };
    Usage {
        input_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        output_tokens: u
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    }
}

/// Pull the gemini `usageMetadata` block. Reads `promptTokenCount` and
/// `candidatesTokenCount`.
fn extract_gemini_usage(body: &serde_json::Value) -> Usage {
    let Some(u) = body.get("usageMetadata") else {
        return Usage::default();
    };
    Usage {
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
    }
}

/// Pull the bedrock Converse `usage` block. Reads `inputTokens` and
/// `outputTokens`.
fn extract_bedrock_usage(body: &serde_json::Value) -> Usage {
    let Some(u) = body.get("usage") else {
        return Usage::default();
    };
    Usage {
        input_tokens: u.get("inputTokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        output_tokens: u.get("outputTokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    }
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
