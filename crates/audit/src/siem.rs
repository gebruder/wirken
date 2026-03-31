//! SIEM log forwarding — sends audit events to external systems via HTTP.
//!
//! Supports Datadog, Splunk HEC, and generic webhook endpoints.
//! Events are serialized as structured JSON and POSTed in batches.

use crate::event::AuditEvent;

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
}

/// Supported SIEM targets.
#[derive(Debug, Clone)]
pub enum SiemTarget {
    /// Datadog Log Intake API (https://http-intake.logs.datadoghq.com/api/v2/logs)
    Datadog,
    /// Splunk HTTP Event Collector (https://<host>:8088/services/collector/event)
    Splunk,
    /// Generic webhook — POSTs JSON array of events.
    Webhook,
}

/// Forwards audit events to a SIEM via HTTP.
pub struct SiemForwarder {
    config: SiemConfig,
    http: reqwest::Client,
}

impl SiemForwarder {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
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
            SiemTarget::Webhook => self.forward_webhook(events).await,
        };

        if let Err(e) = result {
            tracing::warn!("SIEM forward failed: {e}");
        }
    }

    async fn forward_datadog(&self, events: &[AuditEvent]) -> Result<(), String> {
        let logs: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "message": format!("{} {} {}", e.action, e.target, e.actor),
                    "ddsource": "wirken",
                    "ddtags": format!(
                        "service:{},env:{},action:{},channel:{}",
                        self.config.service, self.config.environment, e.action, e.channel
                    ),
                    "hostname": hostname(),
                    "service": self.config.service,
                    "status": action_to_severity(&e.action),
                    "timestamp": e.ts.timestamp_millis(),
                    "wirken": {
                        "actor": e.actor,
                        "action": e.action,
                        "target": e.target,
                        "channel": e.channel,
                        "session": e.session,
                        "detail": e.detail,
                    }
                })
            })
            .collect();

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
        // Splunk HEC expects one JSON object per event, newline-delimited
        let mut body = String::new();
        for event in events {
            let hec_event = serde_json::json!({
                "event": {
                    "actor": event.actor,
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

    async fn forward_webhook(&self, events: &[AuditEvent]) -> Result<(), String> {
        let payload: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.ts.to_rfc3339(),
                    "actor": e.actor,
                    "action": e.action,
                    "target": e.target,
                    "channel": e.channel,
                    "session": e.session,
                    "detail": e.detail,
                    "service": self.config.service,
                    "environment": self.config.environment,
                    "hostname": hostname(),
                })
            })
            .collect();

        let mut request = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json");

        if !self.config.api_key.is_empty() {
            request = request.header("Authorization", format!("Bearer {}", self.config.api_key));
        }

        request
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Webhook: {e}"))?;

        Ok(())
    }
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
