//! SIEM log forwarding — sends audit events to external systems via HTTP.
//!
//! Supports Datadog, Splunk HEC, Microsoft Sentinel (Logs Ingestion API
//! over a Data Collection Rule), and generic webhook endpoints. Events
//! are serialized as structured JSON and POSTed in batches.

use hmac::{Hmac, Mac};
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
