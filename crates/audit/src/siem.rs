//! SIEM log forwarding — sends audit events to external systems via HTTP.
//!
//! Supports Datadog, Splunk HEC, Microsoft Sentinel (Logs Ingestion API
//! over a Data Collection Rule), and generic webhook endpoints. Events
//! are serialized as structured JSON and POSTed in batches.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::event::{ActorKind, AuditEvent};

fn actor_kind_label(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::User => "user",
        ActorKind::Agent => "agent",
        ActorKind::Service => "service",
    }
}

type HmacSha256 = Hmac<Sha256>;

/// SIEM forwarder configuration.
#[derive(Debug, Clone)]
pub struct SiemConfig {
    /// Target type determines the request format and headers.
    pub target: SiemTarget,
    /// HTTP endpoint URL.
    pub endpoint: String,
    /// API key or token for authentication.
    pub api_key: String,
    /// Service name tag (default: "wirken").
    pub service: String,
    /// Environment tag (e.g., "production", "staging").
    pub environment: String,
    /// Shared secret for webhook payload authentication. When set, the
    /// webhook target adds `X-Wirken-Signature: sha256=<hex>` whose hex
    /// is HMAC-SHA-256 over the exact serialized request body. Unset
    /// means no header. Other targets ignore this field.
    pub hmac_secret: Option<String>,
    /// Sentinel-only: typed-event stream endpoint and bearer token.
    /// Required when the operator opts into typed forwarding on the
    /// Sentinel target because the DCR for the legacy stream
    /// (`Custom-WirkenAudit`) is column-pinned and cannot carry
    /// typed-event payloads. Other targets carry typed events on
    /// the same endpoint as the legacy events and leave this field
    /// `None`.
    pub sentinel_typed: Option<SentinelTypedEndpoint>,
    /// Operator-provided allowlist of variant names to forward
    /// typed events for. `None` means "use the default
    /// forwardable-variant set" (see
    /// [`crate::siem_typed::default_forward_variant`]). Matched
    /// against each event's `kind` tag. Include wins over exclude.
    pub typed_include_variants: Option<Vec<String>>,
    /// Operator-provided denylist of variant names to suppress.
    /// Honored only when [`Self::typed_include_variants`] is `None`.
    pub typed_exclude_variants: Option<Vec<String>>,
    /// Explicit opt-in/opt-out for the typed-event SIEM pipe.
    ///
    /// - `Some(true)`: spawn the worker with the default
    ///   forwardable-variant set, even when no include/exclude or
    ///   `sentinel_typed` override is set. Use this to subscribe
    ///   to the default set without writing the full variant
    ///   list in `siem.json`.
    /// - `Some(false)`: explicit off switch. Overrides the other
    ///   typed fields; the worker is not spawned even if
    ///   `typed_include_variants`, `typed_exclude_variants`, or
    ///   `sentinel_typed` are present. Use this to test the
    ///   legacy-only path against a config that already has the
    ///   typed fields populated.
    /// - `None` (default): opt-in is inferred from the other
    ///   three typed fields. Any of them set = spawn; all
    ///   unset = no typed pipe (back-compatible with 1.3.0
    ///   `siem.json` shapes).
    pub typed_forwarding_enabled: Option<bool>,
    /// Poll interval, in milliseconds, for the typed-event forwarder
    /// worker. `None` uses the default [`crate::TYPED_POLL_INTERVAL`]
    /// (50ms), which matches the legacy writer flush cadence so a SOC
    /// team sees consistent latency across both pipes. A configured
    /// value is clamped up to a small floor to avoid a busy-spin; see
    /// [`crate::siem_typed::resolve_poll_interval`].
    pub typed_poll_interval_ms: Option<u64>,
}

impl SiemConfig {
    /// Whether the operator has opted into the typed-event SIEM
    /// pipe. Returns `false` when `typed_forwarding_enabled ==
    /// Some(false)` (explicit off, overrides every other typed
    /// field). Otherwise returns `true` when any of
    /// `typed_forwarding_enabled == Some(true)`,
    /// `typed_include_variants`, `typed_exclude_variants`, or
    /// `sentinel_typed` is set. All-null returns `false` (the 1.3.0
    /// default; back-compat with operators who never wrote any of
    /// these fields).
    ///
    /// Single source of truth for the spawn-guard so the gateway
    /// and the audit-crate tests cannot drift.
    pub fn typed_forwarding_opted_in(&self) -> bool {
        if self.typed_forwarding_enabled == Some(false) {
            return false;
        }
        self.typed_forwarding_enabled == Some(true)
            || self.typed_include_variants.is_some()
            || self.typed_exclude_variants.is_some()
            || self.sentinel_typed.is_some()
    }
}

/// Sentinel-only second endpoint for typed-event forwarding.
/// Required because the Sentinel target's legacy DCR is column-
/// pinned to the `Custom-WirkenAudit` schema and rejects rows that
/// do not match it. The typed-event stream points at a separate
/// DCR (typically `Custom-WirkenSession`) with its own column set.
#[derive(Debug, Clone)]
pub struct SentinelTypedEndpoint {
    /// Full DCR stream URL for typed events. Same shape as the
    /// legacy `endpoint`, but pointing at a different stream
    /// segment.
    pub endpoint: String,
    /// Azure AD bearer token for the typed-event DCR. When `None`,
    /// the legacy `api_key` is reused (the operator's app
    /// registration usually has Monitoring Metrics Publisher on
    /// both DCRs).
    pub api_key: Option<String>,
}

/// Supported SIEM targets.
#[derive(Debug, Clone)]
pub enum SiemTarget {
    /// Datadog Log Intake API (https://http-intake.logs.datadoghq.com/api/v2/logs)
    Datadog,
    /// Splunk HTTP Event Collector (https://<host>:8088/services/collector/event)
    Splunk,
    /// Microsoft Sentinel via the Logs Ingestion API. The operator
    /// provides the full Data Collection Endpoint URL — including the
    /// stream segment that selects the custom table — as `endpoint`,
    /// e.g. `https://<dce>.<region>.ingest.monitor.azure.com\
    /// /dataCollectionRules/<dcr-immutable-id>/streams/Custom-WirkenAudit\
    /// ?api-version=2023-01-01`. Authentication is an Azure AD bearer
    /// token in `api_key`. Wirken does not refresh the token; the
    /// operator's responsibility (typically a sidecar that rewrites
    /// `~/.wirken/siem.json` before expiry).
    Sentinel,
    /// Generic webhook — POSTs JSON array of events.
    Webhook,
}

/// Forwards audit events to a SIEM via HTTP.
pub struct SiemForwarder {
    config: SiemConfig,
    http: reqwest::Client,
}

impl SiemForwarder {
    /// Create a new SIEM forwarder.
    /// Returns an error if the endpoint uses plaintext HTTP (credential leakage risk).
    /// Localhost endpoints are exempt for development use.
    pub fn new(config: SiemConfig) -> Result<Self, String> {
        let is_localhost = config.endpoint.starts_with("http://localhost")
            || config.endpoint.starts_with("http://127.0.0.1")
            || config.endpoint.starts_with("http://[::1]");

        if !config.endpoint.starts_with("https://") && !is_localhost {
            return Err(format!(
                "SIEM endpoint must use HTTPS (got {}). \
                 API keys would be sent in plaintext over HTTP.",
                config.endpoint
            ));
        }

        Ok(Self {
            config,
            http: reqwest::Client::new(),
        })
    }

    /// Forward a batch of audit events. Errors are logged, not propagated —
    /// SIEM forwarding must not block or fail the audit pipeline.
    pub async fn forward(&self, events: &[AuditEvent]) {
        if events.is_empty() {
            return;
        }

        let result = match self.config.target {
            SiemTarget::Datadog => self.forward_datadog(events).await,
            SiemTarget::Splunk => self.forward_splunk(events).await,
            SiemTarget::Sentinel => self.forward_sentinel(events).await,
            SiemTarget::Webhook => self.forward_webhook(events).await,
        };

        if let Err(e) = result {
            tracing::warn!("SIEM forward failed: {e}");
        }
    }

    async fn forward_datadog(&self, events: &[AuditEvent]) -> Result<(), String> {
        let logs = build_datadog_payload(events, &self.config);
        self.http
            .post(&self.config.endpoint)
            .header("DD-API-KEY", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&logs)
            .send()
            .await
            .map_err(|e| format!("Datadog: {e}"))?;
        Ok(())
    }

    async fn forward_splunk(&self, events: &[AuditEvent]) -> Result<(), String> {
        let body = build_splunk_body(events);
        self.http
            .post(&self.config.endpoint)
            .header("Authorization", format!("Splunk {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("Splunk: {e}"))?;
        Ok(())
    }

    async fn forward_sentinel(&self, events: &[AuditEvent]) -> Result<(), String> {
        if self.config.api_key.is_empty() {
            return Err(
                "Sentinel: api_key (Azure AD bearer token) is required, not optional".into(),
            );
        }
        let payload = build_sentinel_payload(events, &self.config);
        self.http
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Sentinel: {e}"))?;
        Ok(())
    }

    async fn forward_webhook(&self, events: &[AuditEvent]) -> Result<(), String> {
        let (body, signature) = build_webhook_request(events, &self.config)?;

        let mut request = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json");

        if !self.config.api_key.is_empty() {
            request = request.header("Authorization", format!("Bearer {}", self.config.api_key));
        }
        if let Some(sig) = signature {
            request = request.header("X-Wirken-Signature", format!("sha256={sig}"));
        }

        request
            .body(body)
            .send()
            .await
            .map_err(|e| format!("Webhook: {e}"))?;

        Ok(())
    }
}

/// Build the Datadog Log-Intake payload (one entry per event).
/// Pure; no HTTP. Extracted so the wire snapshot tests can assert
/// the envelope shape without running an HTTP server.
pub fn build_datadog_payload(events: &[AuditEvent], config: &SiemConfig) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|e| {
            let channel_tag = e.channel.as_deref().unwrap_or("");
            serde_json::json!({
                "message": format!("{} {} {}", e.action, e.target, e.actor_id),
                "ddsource": "wirken",
                "ddtags": format!(
                    "service:{},env:{},action:{},channel:{}",
                    config.service, config.environment, e.action, channel_tag
                ),
                "hostname": hostname(),
                "service": config.service,
                "status": action_to_severity(&e.action),
                "timestamp": e.ts.timestamp_millis(),
                "wirken": {
                    "actor_kind": actor_kind_label(e.actor_kind),
                    "actor_id": e.actor_id,
                    "action": e.action,
                    "target": e.target,
                    "channel": e.channel,
                    "session": e.session,
                    "detail": e.detail,
                }
            })
        })
        .collect()
}

/// Build the Splunk HEC body (one newline-delimited JSON object per
/// event). Pure; no HTTP.
pub fn build_splunk_body(events: &[AuditEvent]) -> String {
    let mut body = String::new();
    for event in events {
        let hec_event = serde_json::json!({
            "event": {
                "actor_kind": actor_kind_label(event.actor_kind),
                "actor_id": event.actor_id,
                "action": event.action,
                "target": event.target,
                "channel": event.channel,
                "session": event.session,
                "detail": event.detail,
            },
            "time": event.ts.timestamp(),
            "sourcetype": "wirken:audit",
            "source": "wirken",
            "host": hostname(),
        });
        body.push_str(&hec_event.to_string());
        body.push('\n');
    }
    body
}

/// Build the Microsoft Sentinel Logs-Ingestion payload. Same flat
/// shape as the webhook path so a single DCR transform covers both.
/// Pure; no HTTP.
pub fn build_sentinel_payload(
    events: &[AuditEvent],
    config: &SiemConfig,
) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|e| {
            serde_json::json!({
                "TimeGenerated": e.ts.to_rfc3339(),
                "ActorKind": actor_kind_label(e.actor_kind),
                "ActorId": e.actor_id,
                "Action": e.action,
                "Target": e.target,
                "Channel": e.channel,
                "Session": e.session,
                "Detail": e.detail,
                "Service": config.service,
                "Environment": config.environment,
                "Hostname": hostname(),
            })
        })
        .collect()
}

/// Build the exact body bytes the webhook target sends and the
/// `X-Wirken-Signature` value paired with them. Extracted from
/// [`SiemForwarder::forward_webhook`] so tests can assert the
/// signature is computed over the *same* bytes that go on the wire,
/// not over a re-serialized envelope (any field-ordering drift would
/// produce a different signature than the receiver computes).
///
/// Returns `(body, signature)`. `signature` is `Some` only when
/// `config.hmac_secret` is set to a non-empty string; otherwise
/// `None` and the caller omits the header.
pub fn build_webhook_request(
    events: &[AuditEvent],
    config: &SiemConfig,
) -> Result<(Vec<u8>, Option<String>), String> {
    let payload: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "timestamp": e.ts.to_rfc3339(),
                "actor_kind": actor_kind_label(e.actor_kind),
                "actor_id": e.actor_id,
                "action": e.action,
                "target": e.target,
                "channel": e.channel,
                "session": e.session,
                "detail": e.detail,
                "service": config.service,
                "environment": config.environment,
                "hostname": hostname(),
            })
        })
        .collect();

    let body = serde_json::to_vec(&payload).map_err(|e| format!("Webhook serialize: {e}"))?;

    let signature = config
        .hmac_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|secret| compute_webhook_signature(secret.as_bytes(), &body));

    Ok((body, signature))
}

// ---------------------------------------------------------------------------
// Typed-event builders
// ---------------------------------------------------------------------------

/// Datadog Log-Intake entry for one typed [`StoredSessionEvent`].
/// Surfaces the variant kind tag, the row metadata (`session_id`,
/// `seq`, `ts`, `trust`), and the variant payload under a `wirken`
/// sub-object whose shape is the SessionEvent serde JSON form
/// (kind-tagged, snake_case fields).
///
/// `message` is a short human-readable summary so the Datadog log
/// stream is greppable without expanding the structured payload.
pub fn build_datadog_typed_entry(
    event: &crate::session_log::StoredSessionEvent,
    config: &SiemConfig,
) -> serde_json::Value {
    let kind = crate::siem_typed::variant_kind_for(&event.event);
    let summary = typed_summary(&event.event);
    serde_json::json!({
        "message": format!("{} session={} seq={}", summary, event.session_id.as_str(), event.seq),
        "ddsource": "wirken",
        "ddtags": format!(
            "service:{},env:{},kind:{}",
            config.service, config.environment, kind
        ),
        "hostname": hostname(),
        "service": config.service,
        "status": "info",
        "timestamp": event.ts.timestamp_millis(),
        "wirken": {
            "kind": kind,
            "session_id": event.session_id.as_str(),
            "seq": event.seq,
            "trust": trust_label(event.trust),
            "event": event.event,
        }
    })
}

/// Datadog payload for a batch of typed events.
pub fn build_datadog_typed_payload(
    events: &[&crate::session_log::StoredSessionEvent],
    config: &SiemConfig,
) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|e| build_datadog_typed_entry(e, config))
        .collect()
}

/// Splunk HEC body (newline-delimited JSON) for typed events.
/// `sourcetype: "wirken:session"` distinguishes from the legacy
/// `"wirken:audit"` stream so Splunk operators route the two
/// independently in `props.conf`.
pub fn build_splunk_typed_body(events: &[&crate::session_log::StoredSessionEvent]) -> String {
    let mut body = String::new();
    for stored in events {
        let kind = crate::siem_typed::variant_kind_for(&stored.event);
        let hec = serde_json::json!({
            "event": {
                "kind": kind,
                "session_id": stored.session_id.as_str(),
                "seq": stored.seq,
                "trust": trust_label(stored.trust),
                "event": stored.event,
            },
            "time": stored.ts.timestamp(),
            "sourcetype": "wirken:session",
            "source": "wirken",
            "host": hostname(),
        });
        body.push_str(&hec.to_string());
        body.push('\n');
    }
    body
}

/// Sentinel DCR payload for typed events. PascalCase column names
/// matching a `Custom-WirkenSession` schema (sibling to the legacy
/// `Custom-WirkenAudit` stream).
pub fn build_sentinel_typed_payload(
    events: &[&crate::session_log::StoredSessionEvent],
) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|stored| {
            let kind = crate::siem_typed::variant_kind_for(&stored.event);
            let (adapter_id, sender_id, agent_id) = extract_identity_for_sentinel(&stored.event);
            serde_json::json!({
                "TimeGenerated": stored.ts.to_rfc3339(),
                "SessionId": stored.session_id.as_str(),
                "Seq": stored.seq,
                "Kind": kind,
                "Trust": trust_label(stored.trust),
                "AgentId": agent_id,
                "AdapterId": adapter_id,
                "SenderId": sender_id,
                "Event": stored.event,
                "Hostname": hostname(),
            })
        })
        .collect()
}

/// Build the webhook request body for typed events, paired with an
/// optional HMAC over the exact serialized bytes. Same factoring as
/// [`build_webhook_request`]: one [`serde_json::to_vec`] call drives
/// both the wire body and the signature so the receiver's recompute
/// over the request body always matches.
pub fn build_webhook_typed_request(
    events: &[&crate::session_log::StoredSessionEvent],
    config: &SiemConfig,
) -> Result<(Vec<u8>, Option<String>), String> {
    let payload: Vec<serde_json::Value> = events
        .iter()
        .map(|stored| {
            let kind = crate::siem_typed::variant_kind_for(&stored.event);
            serde_json::json!({
                "timestamp": stored.ts.to_rfc3339(),
                "session_id": stored.session_id.as_str(),
                "seq": stored.seq,
                "kind": kind,
                "trust": trust_label(stored.trust),
                "event": stored.event,
                "service": config.service,
                "environment": config.environment,
                "hostname": hostname(),
            })
        })
        .collect();

    let body = serde_json::to_vec(&payload).map_err(|e| format!("Webhook typed serialize: {e}"))?;

    let signature = config
        .hmac_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|secret| compute_webhook_signature(secret.as_bytes(), &body));

    Ok((body, signature))
}

/// Pull adapter_id / sender_id / agent_id out of any variant that
/// carries them. Returns `(adapter_id, sender_id, agent_id)`. None
/// for variants that have no such field; the Sentinel and webhook
/// envelopes already include the typed payload separately so a
/// missing column does not lose information.
fn extract_identity_for_sentinel(
    event: &crate::session_log::SessionEvent,
) -> (Option<String>, Option<String>, Option<String>) {
    use crate::session_log::SessionEvent;
    match event {
        SessionEvent::UserMessage {
            adapter_id,
            sender_id,
            ..
        } => (adapter_id.clone(), sender_id.clone(), None),
        SessionEvent::AssistantToolCalls {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::ToolResult {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::HttpFetch { agent_id, .. } => (None, None, agent_id.clone()),
        SessionEvent::MemoryEntryWritten {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            Some(adapter_id.clone()),
            Some(sender_id.clone()),
            Some(agent_id.clone()),
        ),
        SessionEvent::CrossChannelMemoryRead {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::SandboxEgressUnsupported {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::SandboxEgressVerdict {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::LlmRequest {
            agent_id,
            sender_id,
            ..
        }
        | SessionEvent::LlmResponse {
            agent_id,
            sender_id,
            ..
        } => (None, sender_id.clone(), Some(agent_id.clone())),
        // No agent ran an import: it is an operator CLI action. The
        // actor label goes in the principal position, and agent stays
        // genuinely absent rather than being invented. Without this
        // arm the catch-all below would leave the row with nothing,
        // which would look the same as an event that had no actor.
        SessionEvent::ImportStarted { actor, .. } | SessionEvent::ImportCompleted { actor, .. } => {
            (None, Some(actor.clone()), None)
        }
        // An agent ran this one, unlike an import, so it attributes
        // like every other agent event rather than to an operator.
        SessionEvent::ImportedChatRead {
            agent_id,
            adapter_id,
            sender_id,
            ..
        }
        | SessionEvent::ImportedChatSearched {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::PermissionDenied { agent_id, .. }
        | SessionEvent::SkillPermissionDenied { agent_id, .. }
        | SessionEvent::AssistantMessage { agent_id, .. }
        | SessionEvent::SystemPromptSet { agent_id, .. }
        | SessionEvent::Compaction { agent_id, .. }
        | SessionEvent::BudgetExceeded { agent_id, .. }
        | SessionEvent::ExternalToolOutput { agent_id, .. } => (None, None, Some(agent_id.clone())),
        // No column is filled. A "carries" note below means the row
        // holds that field and this function does not read it, which
        // is a gap rather than an absence.
        // Carries an agent_id these columns do not read.
        SessionEvent::HttpRequest { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::PermissionApproved { .. } => (None, None, None),
        // Carries an adapter_id these columns do not read; its actor is a
        // caller, not a sender.
        SessionEvent::PermissionApprovalRefused { .. } => (None, None, None),
        // Carries an agent_id these columns do not read.
        SessionEvent::PermissionRevoked { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::PermissionRenewed { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::PermissionGrantExpired { .. } => (None, None, None),
        // Carries an agent_id these columns do not read.
        SessionEvent::PermissionGrantPruned { .. } => (None, None, None),
        // Carries an agent_id these columns do not read.
        SessionEvent::SubagentSessionBound { .. } => (None, None, None),
        // A session id, a count and a reason; none of the three.
        SessionEvent::SessionScopedApprovalsCleared { .. } => (None, None, None),
        // A skill and a phase name; none of the three.
        SessionEvent::PhaseEntered { .. } => (None, None, None),
        // A skill and a phase name; none of the three.
        SessionEvent::PhaseExited { .. } => (None, None, None),
        // A Zirkel run id and a topic; none of the three.
        SessionEvent::PerspectiveSkipped { .. } => (None, None, None),
        // A Zirkel run id and its perspectives; none of the three.
        SessionEvent::PerspectiveExpansion { .. } => (None, None, None),
        // A Zirkel run id and a candidate; none of the three.
        SessionEvent::CandidateScored { .. } => (None, None, None),
        // A Zirkel run id and a candidate; none of the three.
        SessionEvent::CandidateLlmScored { .. } => (None, None, None),
        // A Zirkel run id and a candidate; none of the three.
        SessionEvent::CandidateKept { .. } => (None, None, None),
        // A Zirkel run id and a url hash; none of the three.
        SessionEvent::CandidateSkipped { .. } => (None, None, None),
        // A Zirkel run id and a theme; none of the three.
        SessionEvent::ThemeNamed { .. } => (None, None, None),
        // Two hashes; none of the three.
        SessionEvent::InterestsEdited { .. } => (None, None, None),
        // A chain head and a signature; none of the three.
        SessionEvent::Attestation { .. } => (None, None, None),
        // A sequence range and a signature; none of the three.
        SessionEvent::ChainHead { .. } => (None, None, None),
        // A sequence and a count; none of the three.
        SessionEvent::Rewind { .. } => (None, None, None),
        // The child's id and grants; the parent's identity is on its own
        // rows.
        SessionEvent::SubagentSpawned { .. } => (None, None, None),
        // The child's id and status; the same.
        SessionEvent::SubagentResult { .. } => (None, None, None),
        // Carries an adapter_id these columns do not read.
        SessionEvent::DeliveryConfirmed { .. } => (None, None, None),
        // Carries an adapter_id these columns do not read.
        SessionEvent::DeliveryFailed { .. } => (None, None, None),
        // An actor and a channel in the legacy shape, not the three.
        SessionEvent::AuditLegacy { .. } => (None, None, None),
        // A hook id and its signature status; none of the three.
        SessionEvent::HookRegistered { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::HookDispatched { .. } => (None, None, None),
        // A hook id and an error; none of the three.
        SessionEvent::HookCrashed { .. } => (None, None, None),
        // A server name and a signer; none of the three.
        SessionEvent::McpEntryVerified { .. } => (None, None, None),
        // A server name and a reason; none of the three.
        SessionEvent::McpEntryRefused { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::EgressHookDispatched { .. } => (None, None, None),
        // Carries all three these columns do not read.
        SessionEvent::ToolOutputRedacted { .. } => (None, None, None),
    }
}

/// The fallback summary: the row's own debug form, cut to 80
/// characters. What every kind with no hand-written line gets.
fn debug_summary(event: &crate::session_log::SessionEvent) -> String {
    format!("{:?}", event).chars().take(80).collect()
}

fn typed_summary(event: &crate::session_log::SessionEvent) -> String {
    use crate::session_log::SessionEvent;
    match event {
        SessionEvent::AssistantToolCalls {
            calls, agent_id, ..
        } => {
            let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();
            format!("tool_calls={} agent={agent_id}", names.join(","))
        }
        SessionEvent::ToolResult {
            tool_name,
            success,
            agent_id,
            ..
        } => format!("tool_result name={tool_name} success={success} agent={agent_id}"),
        SessionEvent::HttpFetch { host, outcome, .. } => {
            format!("http_fetch host={host} outcome={outcome:?}")
        }
        SessionEvent::CrossChannelMemoryRead {
            from_channel,
            to_channel,
            entry_count,
            ..
        } => format!(
            "cross_channel_memory_read from={from_channel} to={to_channel} entries={entry_count}"
        ),
        SessionEvent::MemoryEntryWritten { channel, .. } => {
            format!("memory_entry_written channel={channel}")
        }
        SessionEvent::SandboxEgressVerdict {
            host,
            port,
            allowed,
            reason,
            escalated,
            ..
        } => format!(
            "sandbox_egress_verdict host={host} port={port} allowed={allowed} \
             escalated={escalated} reason={reason:?}"
        ),
        SessionEvent::SandboxEgressUnsupported { mode, .. } => {
            format!("sandbox_egress_unsupported mode={mode:?}")
        }
        SessionEvent::PermissionDenied {
            tool,
            denial_source,
            ..
        } => format!("permission_denied tool={tool} source={denial_source:?}"),
        SessionEvent::BudgetExceeded {
            action,
            window_spend_usd_micros,
            ceiling_usd_micros,
            ..
        } => format!(
            "budget_exceeded action={action:?} spend={window_spend_usd_micros} ceiling={ceiling_usd_micros}"
        ),
        SessionEvent::SubagentSpawned { child_agent_id, .. } => {
            format!("subagent_spawned child={child_agent_id}")
        }
        SessionEvent::SubagentResult { status, .. } => format!("subagent_result status={status:?}"),
        SessionEvent::ChainHead { reason, .. } => format!("chain_head reason={reason:?}"),
        SessionEvent::ExternalToolOutput {
            tool,
            item_count,
            run_id,
            ..
        } => format!("external_tool_output tool={tool} items={item_count} run={run_id}"),
        // No hand-written line: the row's own debug form is the
        // summary. What each row holds is named so the choice can be
        // revisited per kind.
        // Reaches this line only when an operator opted the variant in; the
        // debug form then carries up to 80 characters of the message.
        SessionEvent::UserMessage { .. } => debug_summary(event),
        // The same, for the agent's reply.
        SessionEvent::AssistantMessage { .. } => debug_summary(event),
        // Method, host and status are already the whole row.
        SessionEvent::HttpRequest { .. } => debug_summary(event),
        // Provider, model and hashes; the debug form is the summary.
        SessionEvent::LlmRequest { .. } => debug_summary(event),
        // Token and cost accounting; the debug form is the summary.
        SessionEvent::LlmResponse { .. } => debug_summary(event),
        // An action key and who approved it.
        SessionEvent::PermissionApproved { .. } => debug_summary(event),
        // A request id and why it was refused.
        SessionEvent::PermissionApprovalRefused { .. } => debug_summary(event),
        // An action key and who revoked it.
        SessionEvent::PermissionRevoked { .. } => debug_summary(event),
        // An action key and the two expiries.
        SessionEvent::PermissionRenewed { .. } => debug_summary(event),
        // An action key and when it lapsed.
        SessionEvent::PermissionGrantExpired { .. } => debug_summary(event),
        // An action key and the expiry it was pruned for.
        SessionEvent::PermissionGrantPruned { .. } => debug_summary(event),
        // A parent id, a depth and the grants.
        SessionEvent::SubagentSessionBound { .. } => debug_summary(event),
        // A session id and a count.
        SessionEvent::SessionScopedApprovalsCleared { .. } => debug_summary(event),
        // A skill and a phase name.
        SessionEvent::PhaseEntered { .. } => debug_summary(event),
        // A skill, a phase name and why it ended.
        SessionEvent::PhaseExited { .. } => debug_summary(event),
        // An axis and what was asked for.
        SessionEvent::SkillPermissionDenied { .. } => debug_summary(event),
        // A Zirkel run id and a topic.
        SessionEvent::PerspectiveSkipped { .. } => debug_summary(event),
        // A Zirkel run id and its perspectives.
        SessionEvent::PerspectiveExpansion { .. } => debug_summary(event),
        // A Zirkel candidate and its keyword score.
        SessionEvent::CandidateScored { .. } => debug_summary(event),
        // A Zirkel candidate and its model score.
        SessionEvent::CandidateLlmScored { .. } => debug_summary(event),
        // A Zirkel candidate and how it was kept.
        SessionEvent::CandidateKept { .. } => debug_summary(event),
        // A Zirkel url hash and why it was skipped.
        SessionEvent::CandidateSkipped { .. } => debug_summary(event),
        // A Zirkel theme and its member count.
        SessionEvent::ThemeNamed { .. } => debug_summary(event),
        // Two hashes.
        SessionEvent::InterestsEdited { .. } => debug_summary(event),
        // Spans and extract counts.
        SessionEvent::Compaction { .. } => debug_summary(event),
        // A chain head sequence and a signature.
        SessionEvent::Attestation { .. } => debug_summary(event),
        // Opt-in only; the debug form then carries up to 80 characters of
        // the prompt.
        SessionEvent::SystemPromptSet { .. } => debug_summary(event),
        // A sequence, a count and a reason.
        SessionEvent::Rewind { .. } => debug_summary(event),
        // A target and a message id.
        SessionEvent::DeliveryConfirmed { .. } => debug_summary(event),
        // A target and an error.
        SessionEvent::DeliveryFailed { .. } => debug_summary(event),
        // The legacy row's own actor, action and target.
        SessionEvent::AuditLegacy { .. } => debug_summary(event),
        // A hook id and its signature status.
        SessionEvent::HookRegistered { .. } => debug_summary(event),
        // A hook id, a tool and a decision.
        SessionEvent::HookDispatched { .. } => debug_summary(event),
        // A hook id and an error.
        SessionEvent::HookCrashed { .. } => debug_summary(event),
        // A server name and a signer.
        SessionEvent::McpEntryVerified { .. } => debug_summary(event),
        // A server name and a reason.
        SessionEvent::McpEntryRefused { .. } => debug_summary(event),
        // A hook id, a tool and an egress decision.
        SessionEvent::EgressHookDispatched { .. } => debug_summary(event),
        // A call id, a hook id and the two sizes.
        SessionEvent::ToolOutputRedacted { .. } => debug_summary(event),
        // A source, a conversation and a message count.
        SessionEvent::ImportedChatRead { .. } => debug_summary(event),
        // A source, an outcome and a match count.
        SessionEvent::ImportedChatSearched { .. } => debug_summary(event),
        // A source, a provider and an archive hash.
        SessionEvent::ImportStarted { .. } => debug_summary(event),
        // The same, with what the import did to the store.
        SessionEvent::ImportCompleted { .. } => debug_summary(event),
    }
}

fn trust_label(t: crate::session_log::TrustLevel) -> &'static str {
    use crate::session_log::TrustLevel;
    match t {
        TrustLevel::System => "system",
        TrustLevel::User => "user",
        TrustLevel::Tool => "tool",
        TrustLevel::ExternalTool => "external_tool",
        TrustLevel::Compaction => "compaction",
    }
}

/// HMAC-SHA-256 over `body` keyed by `secret`, hex-encoded.
/// Used by [`SiemForwarder::forward_webhook`] when
/// [`SiemConfig::hmac_secret`] is set; receivers verify by recomputing
/// over the raw request body bytes.
pub fn compute_webhook_signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

/// Map audit action to syslog-compatible severity for Datadog.
fn action_to_severity(action: &str) -> &'static str {
    if action.contains("error") || action.contains("fail") {
        "error"
    } else if action.contains("permission.denied")
        || action.contains("threat_flagged")
        || action.contains("auth")
        || action.contains("credential")
    {
        "warn"
    } else {
        "info"
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "wirken".into())
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::session_log::SessionEvent;

    /// The identity extractor is not compiler-forced: its catch-all
    /// would leave an unregistered variant with no attribution, which
    /// looks the same as an event that had nobody to name.
    #[test]
    fn import_rows_carry_the_operator_actor() {
        let started = SessionEvent::ImportStarted {
            source_id: "src-1".into(),
            provider: "anthropic".into(),
            source_account: "acct-1".into(),
            archive_sha256: "abc".into(),
            actor: "an-operator".into(),
        };
        let completed = SessionEvent::ImportCompleted {
            source_id: "src-1".into(),
            provider: "anthropic".into(),
            source_account: "acct-1".into(),
            archive_sha256: "abc".into(),
            actor: "an-operator".into(),
            added: 1,
            updated: 0,
            unchanged: 0,
            unorderable: 0,
            skipped: 0,
        };
        for event in [started, completed] {
            let (channel, sender, agent) = extract_identity_for_sentinel(&event);
            assert_eq!(sender.as_deref(), Some("an-operator"));
            assert_eq!(channel, None);
            assert_eq!(agent, None, "no agent ran an import");
        }
    }
}
