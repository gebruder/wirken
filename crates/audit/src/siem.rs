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
/// carries them. Returns `(adapter_id, sender_id, agent_id)`.
///
/// Each column holds the field it is named after and nothing else.
/// `sender_id` in particular is a platform sender id (a Telegram user
/// id, a Slack uid, the literal `webchat-user`) or `None`; an
/// operator label like an import's `actor`, a refused approval's
/// `caller`, or a revocation's `revoked_by` never goes there, because
/// a column that sometimes holds a platform id and sometimes a
/// human-readable role name cannot be joined on either.
///
/// Those labels are not lost: the Sentinel and webhook envelopes
/// carry the typed payload beside these columns, so every field stays
/// on the row. If an operator identity ever needs a column of its
/// own, it gets one under its own name and covers every variant that
/// carries such a label, not just the one that prompted it.
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
        SessionEvent::PermissionDenied {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::SkillPermissionDenied { agent_id, .. }
        | SessionEvent::AssistantMessage { agent_id, .. }
        | SessionEvent::SystemPromptSet { agent_id, .. }
        | SessionEvent::Compaction { agent_id, .. }
        | SessionEvent::BudgetExceeded { agent_id, .. }
        | SessionEvent::ExternalToolOutput { agent_id, .. } => (None, None, Some(agent_id.clone())),
        // The built-in tool's row names the agent that made the call
        // and nothing about the inbound channel.
        SessionEvent::HttpRequest { agent_id, .. } => (None, None, Some(agent_id.clone())),
        SessionEvent::PermissionApproved {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        // The channel the decision came in on. `caller` stays off the
        // sender column: it is an actor label like "webchat", not the
        // platform sender id every other row puts there.
        SessionEvent::PermissionApprovalRefused { adapter_id, .. } => {
            (adapter_id.clone(), None, None)
        }
        // `revoked_by` is an operator label, off the sender column for
        // the same reason as the refusal's caller above.
        SessionEvent::PermissionRevoked { agent_id, .. } => (None, None, Some(agent_id.clone())),
        SessionEvent::PermissionRenewed {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::PermissionGrantExpired {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        // Swept at store open, with no inbound channel behind it.
        SessionEvent::PermissionGrantPruned { agent_id, .. } => {
            (None, None, Some(agent_id.clone()))
        }
        // The child's own agent id. Its parent is named by
        // `parent_session_id` on the row, not by these columns.
        SessionEvent::SubagentSessionBound { agent_id, .. } => (None, None, Some(agent_id.clone())),
        // The adapter that carried the message out. `target` is the
        // destination, not the sender that drove the turn.
        SessionEvent::DeliveryConfirmed { adapter_id, .. }
        | SessionEvent::DeliveryFailed { adapter_id, .. } => (adapter_id.clone(), None, None),
        SessionEvent::HookDispatched {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        SessionEvent::EgressHookDispatched {
            agent_id,
            adapter_id,
            sender_id,
            ..
        }
        | SessionEvent::ToolOutputRedacted {
            agent_id,
            adapter_id,
            sender_id,
            ..
        } => (
            adapter_id.clone(),
            sender_id.clone(),
            Some(agent_id.clone()),
        ),
        // No column is filled: none of the rows below carries any of
        // the three. What each one carries instead is named so the
        // absence reads as a fact about the row.
        // An operator CLI action, so `actor` is an operator label and
        // not one of the three. It stays on the row in `Event`.
        SessionEvent::ImportStarted { .. } | SessionEvent::ImportCompleted { .. } => {
            (None, None, None)
        }
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
        // An actor and a channel in the legacy shape, not the three.
        SessionEvent::AuditLegacy { .. } => (None, None, None),
        // A hook id and its signature status; none of the three.
        SessionEvent::HookRegistered { .. } => (None, None, None),
        // A hook id and an error; none of the three.
        SessionEvent::HookCrashed { .. } => (None, None, None),
        // A server name and a signer; none of the three.
        SessionEvent::McpEntryVerified { .. } => (None, None, None),
        // A server name and a reason; none of the three.
        SessionEvent::McpEntryRefused { .. } => (None, None, None),
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
            sandbox,
            ..
        } => {
            let mut line =
                format!("tool_result name={tool_name} success={success} agent={agent_id}");
            // Where it ran, for the rows that say. A detection that
            // cares whether a command reached the host should not
            // have to parse the payload to find out.
            if let Some(p) = sandbox {
                line.push_str(&format!(
                    " sandbox_mode={:?} runtime={:?}",
                    p.mode, p.runtime
                ));
                if let Some(id) = &p.container_id {
                    line.push_str(&format!(" container={}", &id[..id.len().min(12)]));
                }
            }
            line
        }
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

    /// The extractor is exhaustive, so a new variant is a compile
    /// error here rather than a row with no attribution. What it
    /// takes from each variant that carries one of the three columns
    /// is asserted below.
    /// An import is an operator CLI action, so its `actor` is a role
    /// name and not a platform sender. It leaves the identity columns
    /// empty and stays on the row in the typed payload.
    #[test]
    fn an_import_fills_no_identity_column() {
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
            assert_eq!(channel, None);
            assert_eq!(sender, None, "an actor label is not a platform sender");
            assert_eq!(agent, None, "no agent ran an import");
            // The actor is still on the row: the envelope carries the
            // typed payload beside the columns.
            let payload = serde_json::to_value(&event).expect("the row serializes");
            assert_eq!(payload["actor"], "an-operator");
        }
    }

    /// The identity columns hold the field they are named after. An
    /// operator or role label is a different kind of name, and a
    /// column that sometimes holds a platform id and sometimes a role
    /// cannot be joined on either. Each row below carries a label in
    /// a field that is not one of the three; none of it may come back
    /// in a column.
    #[test]
    fn no_row_puts_an_actor_label_in_an_identity_column() {
        use crate::session_log::{ApprovalScopeKind, DenialSource};
        const LABEL: &str = "an-operator";
        let stamp = |s: &str| {
            s.parse::<chrono::DateTime<chrono::Utc>>()
                .expect("a timestamp")
        };
        let rows = vec![
            // `actor` on the two import rows.
            SessionEvent::ImportStarted {
                source_id: "src-1".into(),
                provider: "anthropic".into(),
                source_account: "acct-1".into(),
                archive_sha256: "abc".into(),
                actor: LABEL.into(),
            },
            SessionEvent::ImportCompleted {
                source_id: "src-1".into(),
                provider: "anthropic".into(),
                source_account: "acct-1".into(),
                archive_sha256: "abc".into(),
                actor: LABEL.into(),
                added: 1,
                updated: 0,
                unchanged: 0,
                unorderable: 0,
                skipped: 0,
            },
            // `caller` on a refused approval.
            SessionEvent::PermissionApprovalRefused {
                request_id: "req-1".into(),
                action_key: None,
                caller: LABEL.into(),
                reason: crate::ApprovalRefusalReason::WrongChannel,
                adapter_id: Some("slack".into()),
            },
            // `revoked_by` on a revocation.
            SessionEvent::PermissionRevoked {
                action_key: "shell:ls".into(),
                agent_id: "worker".into(),
                revoked_by: LABEL.into(),
                tier: None,
                expires_at: None,
            },
            // `approved_by` on a grant and on its renewal.
            SessionEvent::PermissionApproved {
                action_key: "shell:ls".into(),
                agent_id: "worker".into(),
                approved_by: LABEL.into(),
                scope: ApprovalScopeKind::Persisted,
                session_id: None,
                approved_via: None,
                adapter_id: Some("slack".into()),
                sender_id: Some("U123".into()),
                tier: None,
                expires_at: None,
            },
            SessionEvent::PermissionRenewed {
                action_key: "shell:ls".into(),
                agent_id: "worker".into(),
                approved_by: LABEL.into(),
                previous_expires_at: stamp("2026-09-20T00:00:00Z"),
                expires_at: stamp("2026-10-20T00:00:00Z"),
                approved_via: None,
                adapter_id: Some("slack".into()),
                sender_id: Some("U123".into()),
            },
            // `denied_via` and `trigger` on a denial, neither of them
            // an identity either.
            SessionEvent::PermissionDenied {
                tool: "exec".into(),
                action_key: "shell:rm".into(),
                denial_source: DenialSource::Tier,
                tier: None,
                agent_id: "worker".into(),
                trigger: Some(LABEL.into()),
                denied_via: None,
                denial_reason: Some(LABEL.into()),
                adapter_id: Some("slack".into()),
                sender_id: Some("U123".into()),
            },
            // `actor_id` on a bridged legacy row.
            SessionEvent::AuditLegacy {
                actor_kind: crate::event::ActorKind::User,
                actor_id: LABEL.into(),
                action: "config.changed".into(),
                target: "provider.json".into(),
                channel: Some("cli".into()),
                detail: serde_json::json!({}),
            },
        ];
        for event in rows {
            let kind = crate::siem_typed::variant_kind(&event);
            let (adapter_id, sender_id, agent_id) = extract_identity_for_sentinel(&event);
            for (column, value) in [
                ("adapter_id", adapter_id),
                ("sender_id", sender_id),
                ("agent_id", agent_id),
            ] {
                assert_ne!(
                    value.as_deref(),
                    Some(LABEL),
                    "{kind} put a role label in {column}"
                );
            }
            // And the label is still on the row.
            let payload = serde_json::to_string(&event).expect("the row serializes");
            assert!(payload.contains(LABEL), "{kind} lost the label entirely");
        }
    }

    /// One row and the three columns it should come back with:
    /// adapter, sender, agent.
    type IdentityCase = (
        SessionEvent,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );

    /// One row per variant that carries an `adapter_id`, a
    /// `sender_id` or an `agent_id`, asserting the columns come back
    /// as the row holds them. A variant here with a field the
    /// extractor drops is a Sentinel column that reads empty for rows
    /// that could have filled it.
    #[test]
    fn every_row_that_carries_an_identity_hands_it_over() {
        use crate::session_log::{
            ApprovalScopeKind, BudgetAction, DenialSource, EgressDecision, GrantExpiryDetection,
            HashHex, HookDecision, HttpFetchOutcome, PhaseDenyContent, PhaseExitReason,
            SkillDeniedReason, ToolCallRecord, ToolsHashVersion,
        };
        let adapter = || Some("slack".to_string());
        let sender = || Some("U123".to_string());
        let agent = || "worker".to_string();
        let stamp = |s: &str| {
            s.parse::<chrono::DateTime<chrono::Utc>>()
                .expect("a timestamp")
        };

        let cases: Vec<IdentityCase> = vec![
            (
                SessionEvent::UserMessage {
                    content: "hi".into(),
                    inbound_id: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                None,
            ),
            (
                SessionEvent::AssistantMessage {
                    content: "hello".into(),
                    agent_id: agent(),
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::AssistantToolCalls {
                    calls: vec![ToolCallRecord {
                        id: "c1".into(),
                        name: "exec".into(),
                        arguments: "{}".into(),
                    }],
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                    text: None,
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "exec".into(),
                    output: "ok".into(),
                    success: true,
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                    sandbox: None,
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::HttpRequest {
                    method: "GET".into(),
                    host: "api.example.com".into(),
                    path: "/v1".into(),
                    status: 200,
                    credential: None,
                    truncated: false,
                    agent_id: agent(),
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::LlmRequest {
                    provider: "ollama".into(),
                    model: "local".into(),
                    request_id: "r1".into(),
                    tools_hash: HashHex::from_bytes(&[1u8; 32]),
                    tools_hash_version: ToolsHashVersion::V2,
                    messages_hash: HashHex::from_bytes(&[2u8; 32]),
                    agent_id: agent(),
                    credential_id: None,
                    sender_id: sender(),
                },
                None,
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::LlmResponse {
                    request_id: "r1".into(),
                    finish_reason: "stop".into(),
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_creation_input_tokens: 0,
                    cache_read_input_tokens: 0,
                    latency_ms: 5,
                    agent_id: agent(),
                    credential_id: None,
                    input_cost_usd_micros: None,
                    output_cost_usd_micros: None,
                    total_cost_usd_micros: None,
                    sender_id: sender(),
                },
                None,
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::BudgetExceeded {
                    agent_id: agent(),
                    credential_id: None,
                    window_spend_usd_micros: 2,
                    ceiling_usd_micros: 1,
                    window: "day".into(),
                    action: BudgetAction::Blocked,
                    tool: None,
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::PermissionDenied {
                    tool: "exec".into(),
                    action_key: "shell:rm".into(),
                    denial_source: DenialSource::Tier,
                    tier: None,
                    agent_id: agent(),
                    trigger: None,
                    denied_via: None,
                    denial_reason: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::PermissionApproved {
                    action_key: "shell:ls".into(),
                    agent_id: agent(),
                    approved_by: "operator".into(),
                    scope: ApprovalScopeKind::Persisted,
                    session_id: None,
                    approved_via: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                    tier: None,
                    expires_at: None,
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::PermissionApprovalRefused {
                    request_id: "req-1".into(),
                    action_key: None,
                    caller: "webchat".into(),
                    reason: crate::ApprovalRefusalReason::WrongChannel,
                    adapter_id: adapter(),
                },
                Some("slack"),
                None,
                None,
            ),
            (
                SessionEvent::PermissionRevoked {
                    action_key: "shell:ls".into(),
                    agent_id: agent(),
                    revoked_by: "operator".into(),
                    tier: None,
                    expires_at: None,
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::PermissionRenewed {
                    action_key: "shell:ls".into(),
                    agent_id: agent(),
                    approved_by: "operator".into(),
                    previous_expires_at: stamp("2026-09-20T00:00:00Z"),
                    expires_at: stamp("2026-10-20T00:00:00Z"),
                    approved_via: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::PermissionGrantExpired {
                    action_key: "shell:ls".into(),
                    agent_id: agent(),
                    tool: None,
                    tier: None,
                    expired_at: stamp("2026-09-19T00:00:00Z"),
                    detected_by: GrantExpiryDetection::ToolCall,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::PermissionGrantPruned {
                    action_key: "shell:ls".into(),
                    agent_id: agent(),
                    expires_at: stamp("2026-09-19T00:00:00Z"),
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::SubagentSessionBound {
                    agent_id: agent(),
                    parent_session_id: "default/slack/C1".into(),
                    depth: 1,
                    max_permission_tier: "tier1".into(),
                    tools_granted: vec![],
                    offered_tools: vec![],
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::SkillPermissionDenied {
                    axis: "egress".into(),
                    requested: "api.example.com".into(),
                    agent_id: agent(),
                    trigger: None,
                    denied_reason: SkillDeniedReason::Profile,
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::HttpFetch {
                    source: "skill".into(),
                    host: "api.example.com".into(),
                    url: "https://api.example.com/v1".into(),
                    outcome: HttpFetchOutcome::Success,
                    http_status_code: Some(200),
                    bytes: 10,
                    run_id: None,
                    expansion_id: None,
                    agent_id: Some(agent()),
                    skill_name: None,
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::Compaction {
                    spans: vec![],
                    extracts: serde_json::json!({}),
                    via_model: false,
                    agent_id: agent(),
                    provider: None,
                    model: None,
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::ExternalToolOutput {
                    tool: "semgrep".into(),
                    run_id: "run-1".into(),
                    item_count: 0,
                    items: serde_json::json!([]),
                    ruleset_sha: None,
                    agent_id: agent(),
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::SystemPromptSet {
                    content: "PROMPT".into(),
                    agent_id: agent(),
                },
                None,
                None,
                Some("worker"),
            ),
            (
                SessionEvent::DeliveryConfirmed {
                    target: "C1".into(),
                    message_id: "m1".into(),
                    adapter_id: adapter(),
                },
                Some("slack"),
                None,
                None,
            ),
            (
                SessionEvent::DeliveryFailed {
                    target: "C1".into(),
                    error: "boom".into(),
                    adapter_id: adapter(),
                },
                Some("slack"),
                None,
                None,
            ),
            (
                SessionEvent::HookDispatched {
                    hook_id: "h1".into(),
                    tool_name: "exec".into(),
                    agent_id: agent(),
                    decision: HookDecision::Allow,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::EgressHookDispatched {
                    hook_id: "h1".into(),
                    tool_name: "exec".into(),
                    agent_id: agent(),
                    decision: EgressDecision::Allow,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::ToolOutputRedacted {
                    call_id: "c1".into(),
                    hook_id: "h1".into(),
                    reason: "secret".into(),
                    original_sha256: HashHex::from_bytes(&[1u8; 32]),
                    original_size: 10,
                    redacted_sha256: HashHex::from_bytes(&[2u8; 32]),
                    redacted_size: 4,
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::MemoryEntryWritten {
                    entry_id: "e1".into(),
                    channel: "slack".into(),
                    adapter_id: "slack".into(),
                    sender_id: "U123".into(),
                    agent_id: agent(),
                    origin_session_id: "default/slack/C1".into(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::CrossChannelMemoryRead {
                    from_channel: "telegram".into(),
                    to_channel: "slack".into(),
                    entry_count: 1,
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::ImportedChatRead {
                    source_id: "src-1".into(),
                    source_account: None,
                    conversation_uuid: "u1".into(),
                    message_count: 1,
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::ImportedChatSearched {
                    source_id: None,
                    outcome: crate::ImportedSearchOutcome::Hits,
                    match_count: 1,
                    query_digest: None,
                    agent_id: agent(),
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::SandboxEgressVerdict {
                    host: "api.example.com".into(),
                    port: 443,
                    allowed: true,
                    reason: None,
                    mode: crate::SandboxEgressModeLabel::Allowlist,
                    sensitivity_basis: vec![],
                    escalated: false,
                    agent_id: agent(),
                    channel: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::SandboxEgressUnsupported {
                    mode: crate::SandboxEgressModeLabel::Allowlist,
                    agent_id: agent(),
                    channel: None,
                    adapter_id: adapter(),
                    sender_id: sender(),
                },
                Some("slack"),
                Some("U123"),
                Some("worker"),
            ),
            (
                SessionEvent::PhaseEntered {
                    skill_id: "demo".into(),
                    phase_name: "review".into(),
                    denied: PhaseDenyContent::default(),
                },
                None,
                None,
                None,
            ),
            (
                SessionEvent::PhaseExited {
                    skill_id: "demo".into(),
                    phase_name: "review".into(),
                    reason: PhaseExitReason::TurnEnd,
                },
                None,
                None,
                None,
            ),
        ];

        for (event, want_adapter, want_sender, want_agent) in cases {
            let kind = crate::siem_typed::variant_kind(&event);
            let (adapter_id, sender_id, agent_id) = extract_identity_for_sentinel(&event);
            assert_eq!(adapter_id.as_deref(), want_adapter, "{kind} adapter_id");
            assert_eq!(sender_id.as_deref(), want_sender, "{kind} sender_id");
            assert_eq!(agent_id.as_deref(), want_agent, "{kind} agent_id");
        }
    }

    /// The summary line says where the command ran, for each of the
    /// three runtimes, so a detection on "a command reached the host"
    /// does not have to parse the payload to find out.
    #[test]
    fn the_summary_says_which_runtime_ran_the_command() {
        use crate::session_log::{SandboxModeLabel, SandboxProvenance, SandboxRuntimeLabel};

        let row = |sandbox| SessionEvent::ToolResult {
            call_id: "c1".into(),
            tool_name: "exec".into(),
            output: "ok".into(),
            success: true,
            agent_id: "worker".into(),
            adapter_id: None,
            sender_id: None,
            sandbox,
        };

        let docker = typed_summary(&row(Some(SandboxProvenance {
            mode: SandboxModeLabel::ExecOnly,
            runtime: SandboxRuntimeLabel::Docker,
            container_id: Some("70f792320e59b7c016b16ff2ebba57669af17efb".into()),
        })));
        assert!(docker.contains("sandbox_mode=ExecOnly"), "{docker}");
        assert!(docker.contains("runtime=Docker"), "{docker}");
        assert!(
            docker.contains("container=70f792320e59"),
            "the id, cut to the prefix an operator pastes: {docker}"
        );

        let gvisor = typed_summary(&row(Some(SandboxProvenance {
            mode: SandboxModeLabel::Gvisor,
            runtime: SandboxRuntimeLabel::Gvisor,
            container_id: Some("abc123abc123abc123".into()),
        })));
        assert!(gvisor.contains("sandbox_mode=Gvisor"), "{gvisor}");
        assert!(gvisor.contains("runtime=Gvisor"), "{gvisor}");

        let host = typed_summary(&row(Some(SandboxProvenance {
            mode: SandboxModeLabel::Off,
            runtime: SandboxRuntimeLabel::Host,
            container_id: None,
        })));
        assert!(host.contains("sandbox_mode=Off"), "{host}");
        assert!(host.contains("runtime=Host"), "{host}");
        assert!(
            !host.contains("container="),
            "there is no container to name: {host}"
        );

        // A tool that ran in this process says nothing, rather than
        // saying host.
        let in_process = typed_summary(&row(None));
        assert!(!in_process.contains("runtime="), "{in_process}");
        assert!(in_process.contains("tool_result name=exec"), "{in_process}");
    }

    /// The field is additive: a row written before it existed reads
    /// back with no provenance rather than failing to parse, and a
    /// row that has one round-trips.
    #[test]
    fn a_row_without_the_field_reads_as_no_provenance() {
        use crate::session_log::{SandboxModeLabel, SandboxProvenance, SandboxRuntimeLabel};

        let old = r#"{"kind":"tool_result","call_id":"c1","tool_name":"exec",
                      "output":"ok","success":true,"agent_id":"worker"}"#;
        match serde_json::from_str::<SessionEvent>(old).expect("an older row still parses") {
            SessionEvent::ToolResult { sandbox, .. } => assert_eq!(sandbox, None),
            other => panic!("expected ToolResult, got {other:?}"),
        }

        let row = SessionEvent::ToolResult {
            call_id: "c1".into(),
            tool_name: "exec".into(),
            output: "ok".into(),
            success: true,
            agent_id: "worker".into(),
            adapter_id: None,
            sender_id: None,
            sandbox: Some(SandboxProvenance {
                mode: SandboxModeLabel::ExecOnly,
                runtime: SandboxRuntimeLabel::Docker,
                container_id: Some("70f792320e59".into()),
            }),
        };
        let wire = serde_json::to_string(&row).expect("serializes");
        assert!(wire.contains(r#""mode":"exec_only""#), "{wire}");
        assert!(wire.contains(r#""runtime":"docker""#), "{wire}");
        assert_eq!(
            serde_json::from_str::<SessionEvent>(&wire).expect("round-trips"),
            row
        );

        // The host shape omits the container rather than sending null.
        let host = SessionEvent::ToolResult {
            call_id: "c1".into(),
            tool_name: "exec".into(),
            output: "ok".into(),
            success: true,
            agent_id: "worker".into(),
            adapter_id: None,
            sender_id: None,
            sandbox: Some(SandboxProvenance {
                mode: SandboxModeLabel::Off,
                runtime: SandboxRuntimeLabel::Host,
                container_id: None,
            }),
        };
        let wire = serde_json::to_string(&host).expect("serializes");
        assert!(!wire.contains("container_id"), "{wire}");
    }
}
