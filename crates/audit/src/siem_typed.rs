//! Typed SessionEvent forwarder. Polls `session_events` via
//! [`SessionLog::get_since`] and dispatches new rows to the
//! configured SIEM target.
//!
//! Hybrid path: targets that tolerate mixed payload shapes (Datadog,
//! Splunk HEC, generic webhook) carry typed events on the same
//! endpoint as the legacy `AuditEvent` batch. The Sentinel target,
//! whose Data Collection Rule pins the legacy stream
//! (`Custom-WirkenAudit`) to a column set the typed events do not
//! match, requires a second endpoint configured in
//! [`crate::SentinelTypedEndpoint`].
//!
//! The polling seam is the cheapest write-path cost: the typed-event
//! append path in [`SessionLog::append`] is zero-touch. The forwarder
//! runs on its own tokio task, queries `get_since` on a tick, and
//! advances its per-session cursor only after a successful POST.
//! Failed POSTs leave the cursor where it was so the next tick retries
//! the same rows.
//!
//! Chain integrity: this module never writes. The SQLite chain is
//! source-of-truth; a forwarder restart that re-reads from cursor
//! zero replays cleanly because the chain is append-only.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::interval;

use crate::session_log::{SessionEvent, SqliteSessionLog, StoredSessionEvent};
use crate::siem::{SiemConfig, SiemTarget};

/// How often the typed forwarder polls `session_events` for new
/// rows. Matches the legacy [`crate::writer::AuditWriter`] flush
/// cadence so a SOC team observes consistent latency across both
/// pipes.
pub const TYPED_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Floor for an operator-configured poll interval. A `0` or
/// near-zero `typed_poll_interval_ms` is clamped up to this so a
/// misconfiguration cannot busy-spin the poll loop.
const POLL_INTERVAL_FLOOR_MS: u64 = 10;

/// Resolve the forwarder poll interval from config (#106). `None`
/// uses [`TYPED_POLL_INTERVAL`] (the 50ms default). A configured value
/// is clamped up to [`POLL_INTERVAL_FLOOR_MS`].
pub fn resolve_poll_interval(config: &SiemConfig) -> Duration {
    match config.typed_poll_interval_ms {
        None => TYPED_POLL_INTERVAL,
        Some(ms) => Duration::from_millis(ms.max(POLL_INTERVAL_FLOOR_MS)),
    }
}

/// Decide whether a freshly read row should be forwarded under the
/// caller's typed-event configuration.
///
/// Default-include set (the variants Detections 1-4 plus close
/// neighbours need):
///
/// - `AssistantToolCalls`, `ToolResult`: shell-sink + binary-write
///   detections.
/// - `HttpFetch`: out-of-process fetch detections (zirkel-driven).
/// - `PermissionDenied`, `SkillPermissionDenied`: gate-denial alerts.
/// - `SubagentSpawned`, `SubagentResult`: child-process fork
///   correlation.
/// - `ChainHead`: per-session signed-head feed.
/// - `McpEntryVerified`, `McpEntryRefused`: MCP load-time signature
///   posture on the `gateway-mcp` sentinel session.
/// - `EgressHookDispatched`, `ToolOutputRedacted`: post-execution
///   egress-hook outcomes and redaction events. Plaintext is never
///   on the row; both carry sha256 hashes only.
///
/// Default-exclude (PII or noisy by default; opt-in only):
///
/// - `UserMessage`, `AssistantMessage`: carry message bodies.
/// - `LlmRequest`, `LlmResponse`: token accounting.
/// - `SystemPromptSet`, `Compaction`, `Rewind`, `Attestation`.
/// - Zirkel pipeline events: `CandidateScored`, `CandidateLlmScored`,
///   `CandidateKept`, `CandidateSkipped`, `ThemeNamed`,
///   `InterestsEdited`, `PerspectiveExpansion`,
///   `PerspectiveSkipped`.
/// - `AuditLegacy`: already on the legacy pipe.
///
/// Operator overrides via
/// [`SiemConfig::typed_include_variants`] and
/// [`SiemConfig::typed_exclude_variants`]. Include wins over
/// exclude when both are present.
pub fn should_forward(event: &SessionEvent, config: &SiemConfig) -> bool {
    let kind = variant_kind(event);

    if let Some(include) = &config.typed_include_variants {
        return include.iter().any(|k| k == kind);
    }
    let in_default = matches!(
        event,
        SessionEvent::AssistantToolCalls { .. }
            | SessionEvent::ToolResult { .. }
            | SessionEvent::HttpFetch { .. }
            | SessionEvent::PermissionDenied { .. }
            | SessionEvent::SkillPermissionDenied { .. }
            | SessionEvent::SubagentSpawned { .. }
            | SessionEvent::SubagentResult { .. }
            | SessionEvent::ChainHead { .. }
            | SessionEvent::McpEntryVerified { .. }
            | SessionEvent::McpEntryRefused { .. }
            | SessionEvent::EgressHookDispatched { .. }
            | SessionEvent::ToolOutputRedacted { .. }
    );
    if !in_default {
        return false;
    }
    if let Some(exclude) = &config.typed_exclude_variants
        && exclude.iter().any(|k| k == kind)
    {
        return false;
    }
    true
}

/// Snake_case kind tag that matches the serde rename on
/// [`SessionEvent`]'s `tag = "kind"` enum repr. Stable across
/// rename refactors because the source of truth is the variant
/// itself.
pub(crate) fn variant_kind_for(event: &SessionEvent) -> &'static str {
    variant_kind(event)
}

fn variant_kind(event: &SessionEvent) -> &'static str {
    match event {
        SessionEvent::UserMessage { .. } => "user_message",
        SessionEvent::AssistantMessage { .. } => "assistant_message",
        SessionEvent::AssistantToolCalls { .. } => "assistant_tool_calls",
        SessionEvent::ToolResult { .. } => "tool_result",
        SessionEvent::LlmRequest { .. } => "llm_request",
        SessionEvent::LlmResponse { .. } => "llm_response",
        SessionEvent::PermissionDenied { .. } => "permission_denied",
        SessionEvent::PermissionApproved { .. } => "permission_approved",
        SessionEvent::SessionScopedApprovalsCleared { .. } => "session_scoped_approvals_cleared",
        SessionEvent::PhaseEntered { .. } => "phase_entered",
        SessionEvent::PhaseExited { .. } => "phase_exited",
        SessionEvent::SkillPermissionDenied { .. } => "skill_permission_denied",
        SessionEvent::PerspectiveSkipped { .. } => "perspective_skipped",
        SessionEvent::PerspectiveExpansion { .. } => "perspective_expansion",
        SessionEvent::HttpFetch { .. } => "http_fetch",
        SessionEvent::CandidateScored { .. } => "candidate_scored",
        SessionEvent::CandidateLlmScored { .. } => "candidate_llm_scored",
        SessionEvent::CandidateKept { .. } => "candidate_kept",
        SessionEvent::CandidateSkipped { .. } => "candidate_skipped",
        SessionEvent::ThemeNamed { .. } => "theme_named",
        SessionEvent::InterestsEdited { .. } => "interests_edited",
        SessionEvent::Compaction { .. } => "compaction",
        SessionEvent::ExternalToolOutput { .. } => "external_tool_output",
        SessionEvent::Attestation { .. } => "attestation",
        SessionEvent::ChainHead { .. } => "chain_head",
        SessionEvent::SystemPromptSet { .. } => "system_prompt_set",
        SessionEvent::Rewind { .. } => "rewind",
        SessionEvent::SubagentSpawned { .. } => "subagent_spawned",
        SessionEvent::SubagentResult { .. } => "subagent_result",
        SessionEvent::AuditLegacy { .. } => "audit_legacy",
        SessionEvent::HookRegistered { .. } => "hook_registered",
        SessionEvent::HookDispatched { .. } => "hook_dispatched",
        SessionEvent::HookCrashed { .. } => "hook_crashed",
        SessionEvent::McpEntryVerified { .. } => "mcp_entry_verified",
        SessionEvent::McpEntryRefused { .. } => "mcp_entry_refused",
        SessionEvent::EgressHookDispatched { .. } => "egress_hook_dispatched",
        SessionEvent::ToolOutputRedacted { .. } => "tool_output_redacted",
    }
}

/// Outgoing transport for typed events. Pulled out as a trait so
/// the end-to-end test can swap in a stub that records what would
/// have been sent. The production impl is
/// [`HttpTypedSink`].
#[async_trait::async_trait]
pub trait TypedSink: Send + Sync {
    /// Forward a batch of typed events. Return an error on transport
    /// or upstream failure; the forwarder treats `Err` as "do not
    /// advance the cursor for these rows" and retries on the next
    /// tick.
    async fn forward(&self, events: &[StoredSessionEvent]) -> Result<(), String>;
}

/// Production HTTP transport for typed events. Dispatches per the
/// [`TypedTransport`] decision: shared endpoint (Datadog / Splunk
/// HEC / webhook) or Sentinel's separate DCR stream.
pub struct HttpTypedSink {
    config: SiemConfig,
    http: reqwest::Client,
}

impl HttpTypedSink {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl TypedSink for HttpTypedSink {
    async fn forward(&self, events: &[StoredSessionEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let stored_refs: Vec<&StoredSessionEvent> = events.iter().collect();

        match TypedTransport::for_config(&self.config) {
            None => {
                tracing::debug!("typed-SIEM: no transport for this config; dropping batch");
                Ok(())
            }
            Some(TypedTransport::SentinelSeparate { endpoint, api_key }) => {
                let payload = crate::siem::build_sentinel_typed_payload(&stored_refs);
                self.http
                    .post(endpoint)
                    .header("Authorization", format!("Bearer {api_key}"))
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| format!("Sentinel typed: {e}"))?;
                Ok(())
            }
            Some(TypedTransport::Shared { target, config }) => match target {
                SiemTarget::Datadog => {
                    let payload = crate::siem::build_datadog_typed_payload(&stored_refs, config);
                    self.http
                        .post(&config.endpoint)
                        .header("DD-API-KEY", &config.api_key)
                        .header("Content-Type", "application/json")
                        .json(&payload)
                        .send()
                        .await
                        .map_err(|e| format!("Datadog typed: {e}"))?;
                    Ok(())
                }
                SiemTarget::Splunk => {
                    let body = crate::siem::build_splunk_typed_body(&stored_refs);
                    self.http
                        .post(&config.endpoint)
                        .header("Authorization", format!("Splunk {}", config.api_key))
                        .header("Content-Type", "application/json")
                        .body(body)
                        .send()
                        .await
                        .map_err(|e| format!("Splunk typed: {e}"))?;
                    Ok(())
                }
                SiemTarget::Webhook => {
                    let (body, signature) =
                        crate::siem::build_webhook_typed_request(&stored_refs, config)?;
                    let mut req = self
                        .http
                        .post(&config.endpoint)
                        .header("Content-Type", "application/json");
                    if !config.api_key.is_empty() {
                        req = req.header("Authorization", format!("Bearer {}", config.api_key));
                    }
                    if let Some(sig) = signature {
                        req = req.header("X-Wirken-Signature", format!("sha256={sig}"));
                    }
                    req.body(body)
                        .send()
                        .await
                        .map_err(|e| format!("Webhook typed: {e}"))?;
                    Ok(())
                }
                SiemTarget::Sentinel => {
                    // Unreachable under `TypedTransport::Shared`; the
                    // for_config dispatch routes Sentinel to
                    // SentinelSeparate or returns None.
                    Err("Sentinel typed transport not configured".into())
                }
            },
        }
    }
}

/// Standalone polling worker handle. Carries the spawn handle and a
/// shutdown signal channel so the caller (gateway startup) can stop
/// the worker on graceful shutdown.
pub struct TypedEventForwarder {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TypedEventForwarder {
    /// Spawn a polling worker against `log`. Returns the handle on
    /// the spawned task plus a `shutdown` channel; the caller is
    /// responsible for signalling shutdown.
    ///
    /// The worker drives [`run_one_pass`] every
    /// [`TYPED_POLL_INTERVAL`] until the shutdown signal fires.
    pub fn spawn(log: Arc<SqliteSessionLog>, sink: Arc<dyn TypedSink>, config: SiemConfig) -> Self {
        let (tx, mut rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            // Single global cursor over the `session_events.id` primary
            // key, not a per-session map: one indexed query per tick
            // regardless of how many sessions exist (#105). Starts at 0,
            // so a fresh worker re-reads from the start and relies on
            // SIEM dedup, the same restart-replay contract as before.
            let mut cursor: i64 = 0;
            let mut tick = interval(resolve_poll_interval(&config));
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    _ = tick.tick() => {
                        let _ = run_one_pass(&log, sink.as_ref(), &config, &mut cursor).await;
                    }
                }
            }
        });
        Self {
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// Signal shutdown. The worker exits at the next tick boundary.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Wait for the worker task to exit. Call after [`Self::shutdown`].
    pub async fn join(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

/// Maximum rows pulled per polling pass. Bounds the batch handed to
/// the sink and the memory held per tick; a backlog larger than this
/// (a forwarder restart reading from `id` 0, or a burst) drains over
/// successive ticks rather than in one query. Chosen well above a
/// steady-state tick's row count so normal operation always clears in
/// a single pass.
const POLL_BATCH_LIMIT: i64 = 1000;

/// One polling pass. Pulled out for direct test invocation so the
/// end-to-end test does not need to race a spawned worker.
///
/// Issues a single [`SqliteSessionLog::get_events_after`] query for
/// rows past the global `id` cursor, across all sessions, filters via
/// [`should_forward`], hands the batch to `sink`, and on success
/// advances the cursor to the highest `id` read. This is O(1) queries
/// per tick rather than one-per-session (#105); the cursor is the
/// monotonic `session_events.id`, not a per-session seq.
///
/// On sink error the cursor is not advanced. The next pass replays the
/// same rows; SIEM destinations idempotent on event identity (most
/// are; HEC dedups by ack id, Sentinel by `_ResourceId` + timestamp,
/// Datadog by `id`) will deduplicate. For a destination that does not
/// dedup, replay produces double-counts on transient failure; that is
/// the documented trade-off of "no advance on failure". Because the
/// batch now spans sessions, a failed pass replays every new row since
/// the cursor, not one session's rows; the dedup contract is the same.
pub async fn run_one_pass(
    log: &Arc<SqliteSessionLog>,
    sink: &dyn TypedSink,
    config: &SiemConfig,
    cursor: &mut i64,
) -> Result<(), String> {
    let rows = log
        .get_events_after(*cursor, POLL_BATCH_LIMIT)
        .map_err(|e| format!("get_events_after start={cursor}: {e}"))?;
    if rows.is_empty() {
        return Ok(());
    }

    // Highest id read, including rows filtered out below: advancing
    // past them is correct, they have been seen and are not
    // forwardable. Rows arrive ordered by id, so the last is the max.
    let new_high = rows.last().map(|r| r.id).unwrap_or(*cursor);
    let forwardable: Vec<StoredSessionEvent> = rows
        .into_iter()
        .filter(|r| should_forward(&r.event, config))
        .collect();

    if !forwardable.is_empty() {
        sink.forward(&forwardable).await.map_err(|e| {
            tracing::warn!(
                error = %e,
                up_to_id = new_high,
                "typed-event forward failed; cursor not advanced"
            );
            e
        })?;
    }
    *cursor = new_high;
    Ok(())
}

/// Filter for a runtime-configurable variant list.
///
/// Used by the worker when the operator overrides the default set
/// via env or config; kept separate from [`should_forward`] so the
/// match arm there stays a closed enum without runtime allocation
/// in the hot path. The wrapper [`should_forward`] checks the
/// override lists first and falls through to the closed-enum
/// default.
pub fn variants_from_list(items: &[String]) -> HashSet<&str> {
    items.iter().map(|s| s.as_str()).collect()
}

/// Compose the on-the-wire HTTP request for the typed-event
/// Sentinel stream. Returns `(body, signature)` mirroring
/// [`crate::siem::build_webhook_request`]; the signature is `None`
/// because Sentinel uses Azure AD bearer auth, not HMAC.
pub fn build_sentinel_typed_request(events: &[&StoredSessionEvent]) -> Result<Vec<u8>, String> {
    let payload = crate::siem::build_sentinel_typed_payload(events);
    serde_json::to_vec(&payload).map_err(|e| format!("Sentinel typed serialize: {e}"))
}

/// Determine which target hosts the typed-event pipe. Returns the
/// endpoint URL and optional bearer for the Sentinel parallel pipe;
/// for every other target the legacy `endpoint` is reused (mixed
/// batch on the same wire).
pub enum TypedTransport<'a> {
    /// Same endpoint as the legacy pipe; mixed-batch.
    Shared {
        target: &'a SiemTarget,
        config: &'a SiemConfig,
    },
    /// Separate Sentinel DCR stream for typed events.
    SentinelSeparate { endpoint: &'a str, api_key: &'a str },
}

impl<'a> TypedTransport<'a> {
    /// Pick the transport for `config`. For Sentinel a configured
    /// `sentinel_typed` is required; without it the typed pipe is
    /// disabled (`None`).
    pub fn for_config(config: &'a SiemConfig) -> Option<Self> {
        match config.target {
            SiemTarget::Sentinel => {
                let typed = config.sentinel_typed.as_ref()?;
                let api_key = typed.api_key.as_deref().unwrap_or(config.api_key.as_str());
                Some(Self::SentinelSeparate {
                    endpoint: typed.endpoint.as_str(),
                    api_key,
                })
            }
            _ => Some(Self::Shared {
                target: &config.target,
                config,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ActorKind;
    use crate::session_log::{
        HashHex, HexBytes, SessionEvent, SessionId, SubagentStatus, ToolCallRecord,
    };

    fn config_default() -> SiemConfig {
        SiemConfig {
            target: SiemTarget::Webhook,
            endpoint: "http://127.0.0.1:0/x".into(),
            api_key: String::new(),
            service: "wirken".into(),
            environment: "test".into(),
            hmac_secret: None,
            sentinel_typed: None,
            typed_include_variants: None,
            typed_exclude_variants: None,
            typed_forwarding_enabled: None,
            typed_poll_interval_ms: None,
        }
    }

    fn sample_tool_calls() -> SessionEvent {
        SessionEvent::AssistantToolCalls {
            calls: vec![ToolCallRecord {
                id: "c1".into(),
                name: "exec".into(),
                arguments: "{}".into(),
            }],
            agent_id: "default".into(),
            adapter_id: Some("slack".into()),
            sender_id: Some("U123".into()),
        }
    }

    #[test]
    fn default_includes_shell_sink_relevant_variants() {
        let cfg = config_default();
        assert!(should_forward(&sample_tool_calls(), &cfg));
        let tr = SessionEvent::ToolResult {
            call_id: "c1".into(),
            tool_name: "exec".into(),
            output: "ok".into(),
            success: true,
            agent_id: "default".into(),
            adapter_id: None,
            sender_id: None,
        };
        assert!(should_forward(&tr, &cfg));
        let http = SessionEvent::HttpFetch {
            source: "x".into(),
            host: "h".into(),
            url: "u".into(),
            outcome: crate::session_log::HttpFetchOutcome::Success,
            http_status_code: None,
            bytes: 0,
            run_id: None,
            expansion_id: None,
            agent_id: None,
            skill_name: None,
        };
        assert!(should_forward(&http, &cfg));
    }

    #[test]
    fn default_excludes_pii_carrying_variants() {
        let cfg = config_default();
        let user = SessionEvent::UserMessage {
            content: "secret".into(),
            inbound_id: None,
            adapter_id: None,
            sender_id: None,
        };
        assert!(!should_forward(&user, &cfg));
        let asm = SessionEvent::AssistantMessage {
            content: "reply".into(),
            agent_id: "default".into(),
        };
        assert!(!should_forward(&asm, &cfg));
        let req = SessionEvent::LlmRequest {
            provider: "p".into(),
            model: "m".into(),
            request_id: "r".into(),
            tools_hash: HashHex("aa".repeat(32)),
            messages_hash: HashHex("bb".repeat(32)),
            agent_id: "default".into(),
            credential_id: None,
        };
        assert!(!should_forward(&req, &cfg));
    }

    #[test]
    fn include_list_overrides_default() {
        let mut cfg = config_default();
        cfg.typed_include_variants = Some(vec!["user_message".into()]);
        let user = SessionEvent::UserMessage {
            content: "x".into(),
            inbound_id: None,
            adapter_id: None,
            sender_id: None,
        };
        assert!(
            should_forward(&user, &cfg),
            "include list lets opt-in variants through"
        );
        // Variants outside the include list are now excluded even if
        // they were in the default set.
        assert!(
            !should_forward(&sample_tool_calls(), &cfg),
            "include list is exhaustive"
        );
    }

    #[test]
    fn exclude_list_drops_otherwise_default_variant() {
        let mut cfg = config_default();
        cfg.typed_exclude_variants = Some(vec!["tool_result".into()]);
        let tr = SessionEvent::ToolResult {
            call_id: "c1".into(),
            tool_name: "exec".into(),
            output: "ok".into(),
            success: true,
            agent_id: "default".into(),
            adapter_id: None,
            sender_id: None,
        };
        assert!(!should_forward(&tr, &cfg));
        // Variants not on the exclude list still pass.
        assert!(should_forward(&sample_tool_calls(), &cfg));
    }

    #[test]
    fn audit_legacy_is_excluded_so_we_do_not_double_forward() {
        let cfg = config_default();
        let legacy = SessionEvent::AuditLegacy {
            actor_kind: ActorKind::Service,
            actor_id: "gateway".into(),
            action: "gateway.start".into(),
            target: "daemon".into(),
            channel: None,
            detail: serde_json::Value::Null,
        };
        assert!(!should_forward(&legacy, &cfg));
    }

    #[test]
    fn resolve_poll_interval_defaults_and_clamps() {
        let mut cfg = config_default();
        // None -> the 50ms default.
        assert_eq!(resolve_poll_interval(&cfg), TYPED_POLL_INTERVAL);
        // A sane configured value is honored as-is.
        cfg.typed_poll_interval_ms = Some(250);
        assert_eq!(resolve_poll_interval(&cfg), Duration::from_millis(250));
        // 0 is clamped up off the busy-spin floor.
        cfg.typed_poll_interval_ms = Some(0);
        assert_eq!(
            resolve_poll_interval(&cfg),
            Duration::from_millis(POLL_INTERVAL_FLOOR_MS)
        );
    }

    #[test]
    fn typed_transport_returns_sentinel_separate_when_configured() {
        let mut cfg = config_default();
        cfg.target = SiemTarget::Sentinel;
        cfg.sentinel_typed = Some(crate::SentinelTypedEndpoint {
            endpoint: "https://example.invalid/typed".into(),
            api_key: None,
        });
        cfg.api_key = "shared-bearer".into();
        match TypedTransport::for_config(&cfg).unwrap() {
            TypedTransport::SentinelSeparate { endpoint, api_key } => {
                assert_eq!(endpoint, "https://example.invalid/typed");
                assert_eq!(
                    api_key, "shared-bearer",
                    "falls back to legacy api_key when typed.api_key is None"
                );
            }
            _ => panic!("expected SentinelSeparate"),
        }
    }

    #[test]
    fn typed_transport_is_disabled_on_sentinel_without_typed_endpoint() {
        let mut cfg = config_default();
        cfg.target = SiemTarget::Sentinel;
        assert!(
            TypedTransport::for_config(&cfg).is_none(),
            "no typed pipe when Sentinel is configured without sentinel_typed"
        );
    }

    #[test]
    fn typed_transport_shares_endpoint_on_non_sentinel_targets() {
        let cfg = config_default();
        match TypedTransport::for_config(&cfg).unwrap() {
            TypedTransport::Shared { .. } => {}
            _ => panic!("expected Shared transport on webhook"),
        }
    }

    #[test]
    fn build_sentinel_typed_request_round_trips() {
        let stored = StoredSessionEvent {
            id: 1,
            session_id: SessionId::new("s1"),
            seq: 0,
            ts: chrono::Utc::now(),
            trust: crate::session_log::TrustLevel::System,
            event: sample_tool_calls(),
            leaf_hash: HashHex("aa".repeat(32)),
            prev_hash: HashHex("bb".repeat(32)),
            hash: HashHex("cc".repeat(32)),
        };
        let body = build_sentinel_typed_request(&[&stored]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let entry = &arr[0];
        assert!(entry.get("Kind").is_some());
        assert_eq!(
            entry.get("AdapterId").and_then(|v| v.as_str()),
            Some("slack")
        );
        let _ = HexBytes::from_bytes(b"unused"); // keep the HexBytes import alive in cfg(test)
        let _ = SubagentStatus::Ok; // same for SubagentStatus
    }
}
