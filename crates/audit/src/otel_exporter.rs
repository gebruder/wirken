//! OpenTelemetry GenAI semantic-convention exporter for the audit chain.
//!
//! Projects `SessionEvent` rows from the per-session log into
//! OTLP/HTTP+JSON spans following the OpenTelemetry GenAI semantic
//! conventions. Targets any OTLP-compatible backend; the Microsoft
//! Agent 365 ingestion endpoint is one such backend, documented at
//! `docs/integrations/agent365.md`.
//!
//! ## Architectural twin
//!
//! Mirrors the polling shape of [`crate::siem_typed`]: a background
//! worker reads `SessionLog::get_since` on a tick, projects rows to
//! spans, and ships batches via OTLP/HTTP+JSON. The cursor advances
//! only after a successful 2xx response, so transient transport
//! failures replay rather than drop.
//!
//! ## Trait placement
//!
//! [`FederatedIdentity`] lives here rather than in the agent crate
//! because audit is the only crate that needs it and the workspace
//! dependency direction is agent to audit. Production implementations
//! (Keycloak OIDC client credentials, Microsoft Entra client
//! credentials with the `Agent365.Observability.OtelWrite` role) live
//! in the agent crate and depend on audit; the trait sits at the
//! boundary they consume.
//!
//! ## Module status
//!
//! Foundation commit. Defines the trait, the config shape, the static
//! testing identity, and the error type. The projector, batcher, and
//! local-collector smoke test arrive in follow-up commits on the same
//! issue.

use std::collections::HashMap;

use async_trait::async_trait;
use thiserror::Error;

/// Source of the bearer token and run-wide identity attributes the
/// OTel exporter stamps on outbound spans.
///
/// IdP-agnostic by design. The same exporter accepts any
/// implementation: Microsoft Entra (client credentials with a
/// documented role claim), Keycloak (OIDC client credentials), or a
/// static config for testing against a non-authenticated collector.
///
/// User identity (the `user.id` attribute on `invoke_agent` spans) is
/// resolved separately by a `UserResolver`; `FederatedIdentity` is
/// purely about the agent's own credential. The two abstractions are
/// kept apart so the Microsoft-Entra impl does not carry a
/// federation-irrelevant resolve-user method, and the
/// `UserResolver` does not have to know which IdP issued the agent's
/// token.
#[async_trait]
pub trait FederatedIdentity: Send + Sync {
    /// Tenant identifier interpolated into the exporter's outbound
    /// URL (the `{tenantId}` URL segment for Agent 365). For
    /// non-Microsoft backends this is the configured tenant
    /// equivalent or an arbitrary string the operator picks.
    fn tenant_id(&self) -> &str;

    /// Agent identifier interpolated into the exporter's outbound
    /// URL (the `{agentId}` URL segment for Agent 365). Must match
    /// the authenticated app id of the token returned by
    /// [`Self::current_token`] for Agent 365 acceptance; a mismatch
    /// is a documented 403.
    fn agent_id(&self) -> &str;

    /// Acquire (or return a cached) bearer token for the outbound
    /// POST. Implementations are expected to refresh ahead of expiry
    /// and to surface acquisition failures as
    /// [`OtelError::TokenAcquisition`].
    async fn current_token(&self) -> Result<String, OtelError>;

    /// Run-wide attributes the projector stamps on every span.
    ///
    /// Vendor-neutral pairs only at the trait level
    /// (`gen_ai.agent.id`, `gen_ai.agent.name`); Microsoft-namespaced
    /// attributes such as `microsoft.tenant.id` and
    /// `microsoft.a365.agent.blueprint.id` are returned here by the
    /// Microsoft-Entra implementation specifically, as
    /// `(String, String)` pairs the projector concatenates onto each
    /// span's attribute set.
    fn span_attributes(&self) -> Vec<(String, String)>;
}

/// Static `FederatedIdentity` implementation for testing the exporter
/// against a local OTel collector or against an authentication-free
/// endpoint. Not for production use.
///
/// Production deployments wire a `FederatedIdentity` implementation
/// from the agent crate that performs real OAuth2 or OIDC flows.
#[derive(Clone, Debug)]
pub struct StaticFederatedIdentity {
    tenant_id: String,
    agent_id: String,
    bearer: String,
    attributes: Vec<(String, String)>,
}

impl StaticFederatedIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        bearer: impl Into<String>,
        attributes: Vec<(String, String)>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            bearer: bearer.into(),
            attributes,
        }
    }
}

#[async_trait]
impl FederatedIdentity for StaticFederatedIdentity {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    async fn current_token(&self) -> Result<String, OtelError> {
        Ok(self.bearer.clone())
    }

    fn span_attributes(&self) -> Vec<(String, String)> {
        self.attributes.clone()
    }
}

/// Configuration for the OTel exporter background worker.
///
/// Loaded from `otel.json` in the wirken data directory at gateway
/// startup. Schema parallel to `siem.json`.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Full OTLP/HTTP+JSON endpoint URL the exporter POSTs to. The
    /// exporter performs no URL interpolation against the
    /// `FederatedIdentity`; deployments that need per-call tenant or
    /// agent path segments (Agent 365) provide the already-interpolated
    /// URL here at config time, or a future revision can grow a
    /// template form.
    ///
    /// For Agent 365 this is shaped as
    /// `https://agent365.svc.cloud.microsoft/observabilityService/tenants/{tenantId}/otlp/agents/{agentId}/traces?api-version=1`
    /// with `{tenantId}` and `{agentId}` resolved from the
    /// `FederatedIdentity` at config-construction time.
    pub endpoint: String,

    /// Poll interval for `SessionLog::get_since`. Cadence parity with
    /// the typed SIEM forwarder
    /// ([`crate::siem_typed::TYPED_POLL_INTERVAL`]) is the default so
    /// operators observing both pipes see consistent latency.
    pub poll_interval_ms: u64,

    /// Soft batch size cap before the worker splits a batch into two
    /// requests. The Agent 365 ingestion endpoint enforces a 1 MiB
    /// hard limit on the request body; this cap is set below that so
    /// the recursive-halve path on 413 is rare. Single spans whose
    /// serialized size exceeds the cap are dropped with an audit-row
    /// noting the drop; that path is exercised by the projector's
    /// over-cap test.
    pub max_batch_bytes: usize,

    /// Channel-name overrides. Maps wirken adapter id to the
    /// `microsoft.channel.name` attribute value emitted on spans for
    /// that adapter. The default constructor installs the
    /// `teams` to `msteams` override so wirken's Microsoft Teams
    /// adapter lands in Defender's built-in channel pivot; other
    /// adapters default to their wirken adapter id when no override
    /// is configured.
    pub channel_name_overrides: HashMap<String, String>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        let mut channel_name_overrides = HashMap::new();
        channel_name_overrides.insert("teams".to_string(), "msteams".to_string());
        Self {
            endpoint: String::new(),
            poll_interval_ms: 50,
            max_batch_bytes: 900 * 1024,
            channel_name_overrides,
        }
    }
}

/// Errors raised by the OTel exporter.
#[derive(Debug, Error)]
pub enum OtelError {
    /// [`FederatedIdentity::current_token`] failed. The exporter does
    /// not advance the cursor; the next poll retries.
    #[error("federated identity could not acquire bearer token: {0}")]
    TokenAcquisition(String),

    /// Network-level failure (DNS, TLS, connection reset). Retried
    /// with the existing transient-retry pattern; cursor stays put.
    #[error("OTel exporter HTTP transport: {0}")]
    Transport(String),

    /// Server returned a non-2xx status. The exporter classifies 413
    /// and 429 specially (split-on-413, honor `Retry-After` on 429)
    /// and treats other non-2xx as transient.
    #[error("OTel exporter received HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },

    /// The projector could not map a `SessionEvent` variant to a
    /// span shape. Surfaces as an audit-row noting the drop rather
    /// than a transport retry, since replaying the row would not
    /// produce a different outcome.
    #[error("OTel projector rejected the SessionEvent: {0}")]
    ProjectorRejection(String),

    /// Operator-provided config rejected at load. Fail-closed at
    /// gateway startup; the exporter worker is not spawned.
    #[error("OTel exporter config invalid: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_identity_returns_configured_values() {
        let id = StaticFederatedIdentity::new(
            "tenant-xyz",
            "agent-abc",
            "bearer-token",
            vec![("gen_ai.agent.name".to_string(), "wirken".to_string())],
        );
        assert_eq!(id.tenant_id(), "tenant-xyz");
        assert_eq!(id.agent_id(), "agent-abc");
        assert_eq!(id.current_token().await.unwrap(), "bearer-token");
        assert_eq!(
            id.span_attributes(),
            vec![("gen_ai.agent.name".to_string(), "wirken".to_string())]
        );
    }

    #[test]
    fn default_config_installs_teams_to_msteams_override() {
        let config = OtelConfig::default();
        assert_eq!(
            config.channel_name_overrides.get("teams"),
            Some(&"msteams".to_string())
        );
    }

    #[test]
    fn default_config_batch_cap_below_one_mib() {
        let config = OtelConfig::default();
        assert!(
            config.max_batch_bytes < 1024 * 1024,
            "max_batch_bytes must stay below the 1 MiB Agent 365 hard limit"
        );
    }

    #[test]
    fn otel_error_display_format_is_stable() {
        let err = OtelError::HttpStatus {
            status: 403,
            body: "missing role".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "OTel exporter received HTTP 403: missing role"
        );
    }
}
