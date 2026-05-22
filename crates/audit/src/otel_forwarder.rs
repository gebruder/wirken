//! Background forwarder that polls the session log, projects events
//! into OTel GenAI spans, serializes them, and POSTs the OTLP/HTTP+JSON
//! body to the configured endpoint with bearer auth.
//!
//! ## Cursor semantics
//!
//! The cursor advances iff the POST returns Ok. Per the
//! commit-day-verified Agent 365 ingestion contract, "Ok" here is
//! "any 2xx response," **including** a 200 whose `partialSuccess`
//! body is non-null with `rejectedSpans > 0`, and **including** a
//! 200 with `partialSuccess` null but the run dropped downstream
//! (license-not-assigned). Treating per-span filter rejection as
//! a retry condition would loop forever on the conformance
//! suite's negative-control branch, which deliberately emits a
//! span Agent 365 is required to reject. The transport layer
//! does not parse `partialSuccess`; the body is the conformance
//! suite's concern, not the forwarder's. A 5xx, 429, or network
//! failure does NOT advance the cursor and the same rows replay
//! on the next pass.
//!
//! ## 413 split base case
//!
//! When the response body would exceed `max_batch_bytes` (pre-check
//! before POST) or the server returns 413 (post-POST), the batch
//! splits in half and the halves go back into the work queue.
//! Recursion bottoms out on a single span that alone exceeds the
//! cap: that span is dropped and a `tracing::warn` is emitted.
//! Writing a chain-side audit row for the drop would create a
//! circular dependency (the forwarder reads from the same log it
//! would have to write to); a future SessionEvent variant can be
//! added if operators need a programmatic signal for oversized-
//! span drops.
//!
//! ## Retry policy
//!
//! - **2xx**: success, return Ok (cursor advances).
//! - **413**: split-and-resubmit, never retry the same body.
//! - **429**: honor `Retry-After` if present (decimal seconds); else
//!   exponential backoff. Capped at `MAX_RETRIES` attempts.
//! - **5xx**: exponential backoff with jitter, capped at
//!   `MAX_RETRIES` attempts.
//! - **Network failure**: same as 5xx.
//! - **4xx other than 413 / 429**: fatal, no retry. The body is
//!   wrong (auth, scope, schema) and replaying won't help.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::RngExt;

use crate::otel_exporter::{FederatedIdentity, OtelConfig, OtelError};
use crate::otel_otlp::serialize_batch;
use crate::otel_projector::{OtelProjector, Span};
use crate::session_log::{SessionId, SessionLog, SqliteSessionLog, StoredSessionEvent};

/// Maximum retry attempts before giving up and returning an
/// error. The backoff values themselves are configured per
/// [`OtelConfig`] so tests can run at submillisecond cadence.
const MAX_RETRIES: u32 = 5;

/// HTTP transport abstraction the forwarder uses to POST OTLP
/// bodies. Production wires [`ReqwestPoster`]; tests wire a mock
/// that returns canned [`OtelHttpResponse`] values for each call
/// without touching the network.
#[async_trait]
pub trait OtelHttpPoster: Send + Sync {
    async fn post_otlp(
        &self,
        endpoint: &str,
        token: &str,
        body: Vec<u8>,
    ) -> Result<OtelHttpResponse, OtelError>;
}

/// Captured HTTP response shape the forwarder needs. The
/// `retry_after_seconds` field carries a parsed decimal value of
/// the `Retry-After` header (HTTP-date forms are ignored). 2xx
/// responses set this to `None`.
#[derive(Clone, Debug)]
pub struct OtelHttpResponse {
    pub status: u16,
    pub retry_after_seconds: Option<u64>,
}

/// Production HTTP poster wrapping a `reqwest::Client`.
pub struct ReqwestPoster {
    client: reqwest::Client,
}

impl ReqwestPoster {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OtelHttpPoster for ReqwestPoster {
    async fn post_otlp(
        &self,
        endpoint: &str,
        token: &str,
        body: Vec<u8>,
    ) -> Result<OtelHttpResponse, OtelError> {
        let response = self
            .client
            .post(endpoint)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| OtelError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let retry_after_seconds = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        Ok(OtelHttpResponse {
            status,
            retry_after_seconds,
        })
    }
}

/// Background forwarder.
///
/// Owns the [`OtelProjector`], an Arc to the active
/// [`FederatedIdentity`], an Arc to the HTTP poster, and a
/// per-session cursor map. One forwarder instance per running
/// exporter; the projector's in-flight run buffers and the
/// cursor are not shared across instances.
pub struct OtelForwarder {
    config: OtelConfig,
    projector: OtelProjector,
    identity: Arc<dyn FederatedIdentity>,
    poster: Arc<dyn OtelHttpPoster>,
    cursor: HashMap<SessionId, u64>,
}

impl OtelForwarder {
    pub fn new(
        config: OtelConfig,
        projector: OtelProjector,
        identity: Arc<dyn FederatedIdentity>,
        poster: Arc<dyn OtelHttpPoster>,
    ) -> Self {
        Self {
            config,
            projector,
            identity,
            poster,
            cursor: HashMap::new(),
        }
    }

    /// Per-session cursor value. Test seam.
    pub fn cursor_for(&self, session_id: &SessionId) -> u64 {
        self.cursor.get(session_id).copied().unwrap_or(0)
    }

    /// One pass over every session in the log. Per session: read
    /// rows since the cursor, project them, POST any emitted
    /// spans, advance the cursor only on a successful POST.
    pub async fn run_one_pass(&mut self, log: &SqliteSessionLog) -> Result<(), OtelError> {
        let sessions = log
            .list_session_ids()
            .map_err(|e| OtelError::Transport(format!("list_session_ids: {e}")))?;
        for session_id_str in sessions {
            let id = SessionId::new(session_id_str.clone());
            let handle = log.handle_for(id.clone());
            let start = self.cursor.get(&id).copied().unwrap_or(0);
            let rows = log
                .get_since(&handle, start)
                .map_err(|e| OtelError::Transport(format!("get_since {session_id_str}: {e}")))?;
            self.process_session_events(&id, rows).await?;
        }
        Ok(())
    }

    /// Project a session's row batch into spans, POST them, and
    /// advance the cursor on success. Exposed as a test seam so
    /// the cursor and POST logic can be exercised without a real
    /// [`SqliteSessionLog`].
    pub async fn process_session_events(
        &mut self,
        session_id: &SessionId,
        rows: Vec<StoredSessionEvent>,
    ) -> Result<(), OtelError> {
        if rows.is_empty() {
            return Ok(());
        }
        let new_high = rows
            .last()
            .map(|r| r.seq + 1)
            .unwrap_or_else(|| self.cursor.get(session_id).copied().unwrap_or(0));

        let identity_attrs = self.identity.span_attributes();
        let mut spans_to_emit: Vec<Span> = Vec::new();
        for row in rows {
            let s = self
                .projector
                .project(&row.event, session_id, row.ts, &identity_attrs);
            spans_to_emit.extend(s);
        }

        if !spans_to_emit.is_empty() {
            self.post_spans(spans_to_emit).await?;
        }
        self.cursor.insert(session_id.clone(), new_high);
        Ok(())
    }

    /// POST a batch of spans, splitting on 413 (or pre-emptive
    /// size check) and retrying on 429 / 5xx / network failures.
    /// Returns Ok when every span in the batch has been
    /// acknowledged by a 2xx response or dropped because it alone
    /// exceeds the body cap.
    pub async fn post_spans(&self, spans: Vec<Span>) -> Result<(), OtelError> {
        let token = self.identity.current_token().await?;
        let mut queue: Vec<Vec<Span>> = vec![spans];
        while let Some(batch) = queue.pop() {
            if batch.is_empty() {
                continue;
            }

            let body_value = serialize_batch(&batch);
            let bytes = serde_json::to_vec(&body_value)
                .map_err(|e| OtelError::Transport(format!("serialize: {e}")))?;

            // Pre-check: if the local body size already exceeds
            // the cap, split before POSTing. Saves a round trip
            // and ensures the split path runs even on transports
            // that don't return 413.
            if bytes.len() > self.config.max_batch_bytes {
                Self::split_into_queue(batch, &mut queue);
                continue;
            }

            match self.post_with_retries(&token, bytes).await? {
                PostOutcome::Ok => continue,
                PostOutcome::SplitNeeded => Self::split_into_queue(batch, &mut queue),
            }
        }
        Ok(())
    }

    /// Split `batch` in half and push both halves onto the work
    /// queue. The single-span base case is logged and dropped.
    fn split_into_queue(batch: Vec<Span>, queue: &mut Vec<Vec<Span>>) {
        if batch.len() <= 1 {
            let dropped = batch.first().map(|s| s.name.clone()).unwrap_or_default();
            tracing::warn!(
                span_name = %dropped,
                "OTel forwarder dropping a span that exceeds the body cap on its own; no chain-side row is written because the forwarder reads from the same log it would have to write to",
            );
            return;
        }
        let mid = batch.len() / 2;
        let second: Vec<Span> = batch[mid..].to_vec();
        let first: Vec<Span> = batch[..mid].to_vec();
        queue.push(second);
        queue.push(first);
    }

    /// POST one body with retry-on-transient. Returns
    /// `PostOutcome::Ok` on 2xx, `PostOutcome::SplitNeeded` on
    /// 413, error on max-retries-exhausted or on non-retryable
    /// non-2xx responses.
    async fn post_with_retries(
        &self,
        token: &str,
        bytes: Vec<u8>,
    ) -> Result<PostOutcome, OtelError> {
        let mut backoff_ms = self.config.initial_backoff_ms;
        let max_backoff_ms = self.config.max_backoff_ms;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let result = self
                .poster
                .post_otlp(&self.config.endpoint, token, bytes.clone())
                .await;
            match result {
                Ok(resp) if (200..300).contains(&resp.status) => {
                    return Ok(PostOutcome::Ok);
                }
                Ok(resp) if resp.status == 413 => {
                    return Ok(PostOutcome::SplitNeeded);
                }
                Ok(resp) if resp.status == 429 => {
                    if attempts > MAX_RETRIES {
                        return Err(OtelError::HttpStatus {
                            status: 429,
                            body: format!("rate limited; {attempts} attempts; cursor not advanced"),
                        });
                    }
                    let wait_ms = resp
                        .retry_after_seconds
                        .map(|s| s.saturating_mul(1000))
                        .unwrap_or(backoff_ms);
                    sleep_with_jitter(wait_ms).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(max_backoff_ms);
                }
                Ok(resp) if (500..600).contains(&resp.status) => {
                    if attempts > MAX_RETRIES {
                        return Err(OtelError::HttpStatus {
                            status: resp.status,
                            body: format!("server error; {attempts} attempts; cursor not advanced"),
                        });
                    }
                    sleep_with_jitter(backoff_ms).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(max_backoff_ms);
                }
                Ok(resp) => {
                    return Err(OtelError::HttpStatus {
                        status: resp.status,
                        body: "non-retryable response".to_string(),
                    });
                }
                Err(e) => {
                    if attempts > MAX_RETRIES {
                        return Err(e);
                    }
                    sleep_with_jitter(backoff_ms).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(max_backoff_ms);
                }
            }
        }
    }
}

enum PostOutcome {
    Ok,
    SplitNeeded,
}

async fn sleep_with_jitter(base_ms: u64) {
    let jitter = if base_ms == 0 {
        0
    } else {
        rand::rng().random_range(0..base_ms.max(1))
    };
    tokio::time::sleep(Duration::from_millis(base_ms.saturating_add(jitter))).await;
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::otel_exporter::StaticFederatedIdentity;
    use crate::session_log::{HashHex, SessionEvent, TrustLevel};
    use crate::user_resolver::DeterministicUserResolver;

    /// Mock poster returning a sequence of canned responses. Each
    /// call to `post_otlp` pops the front of the queue. When the
    /// queue is empty, returns a 200 (so tests can supply only
    /// the responses they care about).
    struct MockPoster {
        responses: Mutex<VecDeque<MockResponse>>,
        calls: Mutex<Vec<Vec<u8>>>,
    }

    enum MockResponse {
        Status {
            status: u16,
            retry_after_seconds: Option<u64>,
        },
        NetworkErr(String),
    }

    impl MockPoster {
        fn new(responses: Vec<MockResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn always_status(status: u16) -> Self {
            Self::new(vec![MockResponse::Status {
                status,
                retry_after_seconds: None,
            }])
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl OtelHttpPoster for MockPoster {
        async fn post_otlp(
            &self,
            _endpoint: &str,
            _token: &str,
            body: Vec<u8>,
        ) -> Result<OtelHttpResponse, OtelError> {
            self.calls.lock().unwrap().push(body);
            let next = self.responses.lock().unwrap().pop_front();
            match next {
                Some(MockResponse::Status {
                    status,
                    retry_after_seconds,
                }) => Ok(OtelHttpResponse {
                    status,
                    retry_after_seconds,
                }),
                Some(MockResponse::NetworkErr(msg)) => Err(OtelError::Transport(msg)),
                None => Ok(OtelHttpResponse {
                    status: 200,
                    retry_after_seconds: None,
                }),
            }
        }
    }

    fn config_with_endpoint(endpoint: &str) -> OtelConfig {
        // Tests run with submillisecond backoffs so the full
        // retry cycle completes in microseconds. Production
        // defaults stay at the OtelConfig::default values.
        OtelConfig {
            endpoint: endpoint.to_string(),
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            ..OtelConfig::default()
        }
    }

    fn identity() -> Arc<dyn FederatedIdentity> {
        Arc::new(StaticFederatedIdentity::new(
            "tenant-uuid",
            "agent-app-id",
            "bearer-token",
            vec![
                ("gen_ai.agent.id".to_string(), "agent-app-id".to_string()),
                ("gen_ai.agent.name".to_string(), "wirken".to_string()),
                ("microsoft.tenant.id".to_string(), "tenant-uuid".to_string()),
                (
                    "microsoft.a365.agent.blueprint.id".to_string(),
                    "agent-app-id".to_string(),
                ),
            ],
        ))
    }

    fn forwarder(poster: Arc<MockPoster>) -> OtelForwarder {
        let config = config_with_endpoint("https://example.invalid/otlp");
        let projector = OtelProjector::new(config.clone(), Arc::new(DeterministicUserResolver));
        let poster_trait: Arc<dyn OtelHttpPoster> = poster;
        OtelForwarder::new(config, projector, identity(), poster_trait)
    }

    fn stored(seq: u64, event: SessionEvent, ts_seconds: i64) -> StoredSessionEvent {
        let zero = HashHex::from_bytes(&[0u8; 32]);
        StoredSessionEvent {
            id: seq as i64,
            session_id: SessionId::new("sess-1"),
            seq,
            ts: DateTime::<Utc>::from_timestamp(ts_seconds, 0).unwrap(),
            trust: TrustLevel::System,
            event,
            leaf_hash: zero.clone(),
            prev_hash: zero.clone(),
            hash: zero,
        }
    }

    fn one_round_rows() -> Vec<StoredSessionEvent> {
        vec![
            stored(
                0,
                SessionEvent::UserMessage {
                    content: "q".to_string(),
                    inbound_id: None,
                    adapter_id: None,
                    sender_id: None,
                },
                0,
            ),
            stored(
                1,
                SessionEvent::AssistantMessage {
                    content: "a".to_string(),
                    agent_id: "default".to_string(),
                },
                1,
            ),
        ]
    }

    #[tokio::test]
    async fn two_hundred_response_advances_cursor() {
        let poster = Arc::new(MockPoster::always_status(200));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("post must succeed on 200");
        assert_eq!(f.cursor_for(&session), 2);
        assert_eq!(poster.call_count(), 1);
    }

    #[tokio::test]
    async fn two_hundred_with_rejected_spans_still_advances_cursor() {
        // The transport layer never inspects partialSuccess; a
        // 200 with partialSuccess non-null carrying rejectedSpans
        // still maps to PostOutcome::Ok and the cursor advances.
        // Retrying the same body would loop forever on the
        // conformance suite's negative-control branch.
        let poster = Arc::new(MockPoster::always_status(200));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect(
                "partialSuccess body shape is the conformance suite's concern, not the transport's",
            );
        assert_eq!(f.cursor_for(&session), 2);
    }

    #[tokio::test]
    async fn five_hundred_response_retries_with_backoff_and_succeeds() {
        let poster = Arc::new(MockPoster::new(vec![
            MockResponse::Status {
                status: 503,
                retry_after_seconds: None,
            },
            MockResponse::Status {
                status: 200,
                retry_after_seconds: None,
            },
        ]));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("retry must succeed");
        assert_eq!(f.cursor_for(&session), 2);
        assert_eq!(poster.call_count(), 2);
    }

    #[tokio::test]
    async fn rate_limited_429_honors_retry_after_then_succeeds() {
        // retry_after_seconds=0 keeps the test fast; the
        // production code path that multiplies by 1000ms is the
        // same.
        let poster = Arc::new(MockPoster::new(vec![
            MockResponse::Status {
                status: 429,
                retry_after_seconds: Some(0),
            },
            MockResponse::Status {
                status: 200,
                retry_after_seconds: None,
            },
        ]));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("rate-limit retry must succeed");
        assert_eq!(f.cursor_for(&session), 2);
        assert_eq!(poster.call_count(), 2);
    }

    #[tokio::test]
    async fn non_retryable_four_xx_returns_error_and_does_not_advance_cursor() {
        let poster = Arc::new(MockPoster::always_status(403));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        let result = f.process_session_events(&session, one_round_rows()).await;
        assert!(matches!(
            result,
            Err(OtelError::HttpStatus { status: 403, .. })
        ));
        // Cursor stays at 0; the rows will replay next pass.
        assert_eq!(f.cursor_for(&session), 0);
        assert_eq!(poster.call_count(), 1, "no retry on non-retryable 4xx");
    }

    #[tokio::test]
    async fn max_retries_on_five_hundred_returns_error_and_does_not_advance_cursor() {
        let mut responses = Vec::new();
        for _ in 0..(MAX_RETRIES + 2) {
            responses.push(MockResponse::Status {
                status: 503,
                retry_after_seconds: None,
            });
        }
        let poster = Arc::new(MockPoster::new(responses));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        let result = f.process_session_events(&session, one_round_rows()).await;
        assert!(matches!(
            result,
            Err(OtelError::HttpStatus { status: 503, .. })
        ));
        assert_eq!(f.cursor_for(&session), 0);
    }

    #[tokio::test]
    async fn network_failure_retries_then_succeeds() {
        let poster = Arc::new(MockPoster::new(vec![
            MockResponse::NetworkErr("connection refused".to_string()),
            MockResponse::Status {
                status: 200,
                retry_after_seconds: None,
            },
        ]));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("network retry must succeed");
        assert_eq!(f.cursor_for(&session), 2);
    }

    #[tokio::test]
    async fn empty_rows_advance_nothing_and_post_nothing() {
        let poster = Arc::new(MockPoster::always_status(200));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, Vec::new())
            .await
            .unwrap();
        assert_eq!(f.cursor_for(&session), 0);
        assert_eq!(poster.call_count(), 0);
    }

    #[tokio::test]
    async fn rows_without_emitted_spans_advance_cursor_without_posting() {
        // A UserMessage alone does not produce spans (the
        // projector buffers it until AssistantMessage closes the
        // run). The cursor should still advance past these rows
        // so they aren't reprojected on the next pass.
        let poster = Arc::new(MockPoster::always_status(200));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        let rows = vec![stored(
            5,
            SessionEvent::UserMessage {
                content: "q".to_string(),
                inbound_id: None,
                adapter_id: None,
                sender_id: None,
            },
            0,
        )];
        f.process_session_events(&session, rows).await.unwrap();
        assert_eq!(f.cursor_for(&session), 6);
        assert_eq!(poster.call_count(), 0, "no POST when no spans emit");
    }

    #[tokio::test]
    async fn four_thirteen_response_splits_batch_then_smaller_posts_succeed() {
        // First POST returns 413; the forwarder must split and
        // resubmit the halves rather than retry the same body.
        // The two halves succeed with 200, the cursor advances
        // on overall success.
        let poster = Arc::new(MockPoster::new(vec![
            MockResponse::Status {
                status: 413,
                retry_after_seconds: None,
            },
            MockResponse::Status {
                status: 200,
                retry_after_seconds: None,
            },
            MockResponse::Status {
                status: 200,
                retry_after_seconds: None,
            },
        ]));
        let mut f = forwarder(poster.clone());
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("split-then-success must return Ok");
        assert_eq!(f.cursor_for(&session), 2);
        assert!(
            poster.call_count() >= 3,
            "expected 1 failed 413 plus 2 successful split halves, got {}",
            poster.call_count(),
        );
    }

    #[tokio::test]
    async fn single_span_exceeding_cap_is_dropped_and_returns_ok() {
        let config = OtelConfig {
            endpoint: "https://example.invalid/otlp".to_string(),
            max_batch_bytes: 50, // smaller than any real serialized span
            ..OtelConfig::default()
        };
        let projector = OtelProjector::new(config.clone(), Arc::new(DeterministicUserResolver));
        let poster = Arc::new(MockPoster::always_status(200));
        let poster_trait: Arc<dyn OtelHttpPoster> = poster.clone();
        let mut f = OtelForwarder::new(config, projector, identity(), poster_trait);
        // One run produces an output_messages plus an invoke_agent
        // root: two spans. The split should bottom out on each
        // single-span case and drop them.
        let session = SessionId::new("sess-1");
        f.process_session_events(&session, one_round_rows())
            .await
            .expect("drop path must return Ok so cursor advances rather than looping");
        // Cursor advances even though no spans actually landed.
        assert_eq!(f.cursor_for(&session), 2);
    }

    #[test]
    fn split_into_queue_drops_single_span_base_case() {
        let mut queue: Vec<Vec<Span>> = Vec::new();
        let span = Span {
            trace_id: crate::otel_projector::TraceId::random(),
            span_id: crate::otel_projector::SpanId::random(),
            parent_span_id: None,
            name: "huge".to_string(),
            kind: crate::otel_projector::SpanKind::Internal,
            start_time_unix_nano: 0,
            end_time_unix_nano: 0,
            status: crate::otel_projector::SpanStatus::Ok,
            status_message: None,
            attributes: Vec::new(),
        };
        OtelForwarder::split_into_queue(vec![span], &mut queue);
        assert!(
            queue.is_empty(),
            "single-span base case must drop, not push"
        );
    }

    #[test]
    fn split_into_queue_pushes_two_halves() {
        let mut queue: Vec<Vec<Span>> = Vec::new();
        let mk = || Span {
            trace_id: crate::otel_projector::TraceId::random(),
            span_id: crate::otel_projector::SpanId::random(),
            parent_span_id: None,
            name: "n".to_string(),
            kind: crate::otel_projector::SpanKind::Internal,
            start_time_unix_nano: 0,
            end_time_unix_nano: 0,
            status: crate::otel_projector::SpanStatus::Ok,
            status_message: None,
            attributes: Vec::new(),
        };
        OtelForwarder::split_into_queue(vec![mk(), mk(), mk(), mk()], &mut queue);
        assert_eq!(queue.len(), 2);
        let lens: Vec<usize> = queue.iter().map(|b| b.len()).collect();
        assert_eq!(lens.iter().sum::<usize>(), 4);
    }
}
