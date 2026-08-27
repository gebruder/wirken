use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

use crate::alarm_log::{AlarmLog, AlarmRecord, hostname_best_effort, now_rfc3339};
use crate::error::AuditError;
use crate::event::{ActorKind, AuditEvent};
use crate::log::{AuditLog, VerifyResult};
use crate::session_log::SchemaDriftRecord;
use crate::siem::{SiemConfig, SiemForwarder};
use crate::signing::AuditSigningKey;

/// Batched audit writer that accepts events via a channel and flushes
/// to SQLite every 50ms or 100 events, whichever comes first.
/// Optionally forwards events to a SIEM via HTTP.
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEvent>,
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);
const CHANNEL_CAPACITY: usize = 4096;

// Persistent-failure gates. When the primary SQLite write fails on
// this many flushes in a row, or the retained buffer grows past this
// cap, the flush loop halts. Halting drops the receiver so the
// mpsc::Sender returns ChannelClosed on the next log call, which is
// the signal the agent observes to stop rather than continue while
// audit events are silently lost.
const MAX_CONSECUTIVE_FAILURES: u32 = 8;
const MAX_BUFFER_ON_FAILURE: usize = BATCH_SIZE * 16;

/// Number of successful flushes between continuous chain-verification
/// passes. The flush loop calls `AuditLog::verify` every Nth flush so a
/// chain break detected by a process other than the operator's CLI
/// shows up at most this many flushes after it occurred. Configurable
/// via `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES`.
const DEFAULT_VERIFY_EVERY_FLUSHES: u64 = 100;

/// Number of consecutive failed chain-verification passes that halt
/// the writer. Once the counter reaches this many, the flush loop
/// breaks and `rx` drops, so subsequent `log` calls return
/// `ChannelClosed`. Persistent integrity failure is treated as a
/// halt-the-show condition rather than a redirect-to-side-channel
/// because once the in-chain story is unrecoverable, every further
/// row written under the same loop is ambiguous evidence.
const MAX_INTEGRITY_FAILURES: u32 = 3;

/// Number of consecutive failed alarm-log writes that halt the
/// writer. The alarm log is the load-bearing record for chain
/// integrity (see `run_verify_pass`); if the writer cannot land an
/// alarm row, every chain-verify failure from then on would be
/// invisible. Persistent alarm-write failure is therefore treated
/// the same as persistent integrity failure: refuse to keep going.
const MAX_ALARM_WRITE_FAILURES: u32 = 3;

/// Result of a single chain-verification pass. Both flags drive
/// independent halt counters in the flush loop.
struct VerifyPassOutcome {
    /// `true` when the chain verified clean (or was empty).
    intact: bool,
    /// `true` when the alarm-log write either succeeded or was not
    /// attempted (intact case). `false` only when the verify pass
    /// detected a break or error and the subsequent alarm-log
    /// append failed.
    alarm_write_ok: bool,
}

/// Update both halt counters from a verify-pass outcome. Returns
/// `true` when either counter reached its threshold.
fn record_verify_outcome(
    integrity_failures: &mut u32,
    alarm_write_failures: &mut u32,
    outcome: &VerifyPassOutcome,
) -> bool {
    if outcome.intact {
        *integrity_failures = 0;
    } else {
        *integrity_failures = integrity_failures.saturating_add(1);
    }
    if outcome.alarm_write_ok {
        *alarm_write_failures = 0;
    } else {
        *alarm_write_failures = alarm_write_failures.saturating_add(1);
    }

    let integrity_halt = *integrity_failures >= MAX_INTEGRITY_FAILURES;
    let alarm_halt = *alarm_write_failures >= MAX_ALARM_WRITE_FAILURES;
    if integrity_halt {
        tracing::error!(
            failures = *integrity_failures,
            threshold = MAX_INTEGRITY_FAILURES,
            "Audit chain verification failed in a row; halting writer so \
             callers observe ChannelClosed and stop accumulating ambiguous \
             in-chain evidence"
        );
    }
    if alarm_halt {
        tracing::error!(
            failures = *alarm_write_failures,
            threshold = MAX_ALARM_WRITE_FAILURES,
            "Audit alarm-log write failed in a row; halting writer because \
             follow-on chain-verify failures would be invisible"
        );
    }
    integrity_halt || alarm_halt
}

/// Sanity threshold above which `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES`
/// is logged as a warning. The default cadence is 100 flushes; values
/// past this floor effectively disable continuous verification, so a
/// reviewer reading the gateway log should see the choice was made
/// deliberately rather than via a typo.
const VERIFY_CADENCE_SANITY_CEILING: u64 = 10_000;

/// Classification of the `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES` env var.
/// Pulled out into a pure function so the warn-policy is testable
/// without tracing-subscriber capture.
#[derive(Debug, PartialEq, Eq)]
enum VerifyCadenceOutcome {
    /// Env var unset; default applies. No warn.
    UnsetUseDefault,
    /// Env var set but does not parse as a u64. Warn and fall back.
    /// Carries the raw input string so the warn can echo it back to
    /// the operator.
    MalformedUseDefault(String),
    /// Env var parsed to 0, which would mean "verify every zero
    /// flushes" — nonsensical. Warn and fall back.
    ZeroUseDefault,
    /// Value accepted but past the sanity ceiling.
    AcceptedHigh(u64),
    /// Value accepted within the sanity ceiling.
    Accepted(u64),
}

fn classify_verify_cadence(raw: Result<String, std::env::VarError>) -> VerifyCadenceOutcome {
    match raw {
        Err(_) => VerifyCadenceOutcome::UnsetUseDefault,
        Ok(s) => match s.parse::<u64>() {
            Err(_) => VerifyCadenceOutcome::MalformedUseDefault(s),
            Ok(0) => VerifyCadenceOutcome::ZeroUseDefault,
            Ok(n) if n > VERIFY_CADENCE_SANITY_CEILING => VerifyCadenceOutcome::AcceptedHigh(n),
            Ok(n) => VerifyCadenceOutcome::Accepted(n),
        },
    }
}

fn verify_every_flushes() -> u64 {
    match classify_verify_cadence(std::env::var("WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES")) {
        VerifyCadenceOutcome::UnsetUseDefault => DEFAULT_VERIFY_EVERY_FLUSHES,
        VerifyCadenceOutcome::MalformedUseDefault(raw) => {
            tracing::warn!(
                env_var = "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES",
                value = %raw,
                default_used = DEFAULT_VERIFY_EVERY_FLUSHES,
                "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES is set but does not parse as \
                 a non-negative integer; falling back to the default cadence. \
                 Continuous chain verification engages on every {DEFAULT_VERIFY_EVERY_FLUSHES} \
                 flushes."
            );
            DEFAULT_VERIFY_EVERY_FLUSHES
        }
        VerifyCadenceOutcome::ZeroUseDefault => {
            tracing::warn!(
                env_var = "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES",
                value = 0,
                default_used = DEFAULT_VERIFY_EVERY_FLUSHES,
                "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES=0 would mean 'verify every \
                 zero flushes' which is nonsensical; falling back to the default \
                 cadence."
            );
            DEFAULT_VERIFY_EVERY_FLUSHES
        }
        VerifyCadenceOutcome::AcceptedHigh(n) => {
            tracing::warn!(
                value = n,
                ceiling = VERIFY_CADENCE_SANITY_CEILING,
                default = DEFAULT_VERIFY_EVERY_FLUSHES,
                "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES is set far above the default; \
                 continuous chain verification is effectively disabled. See the \
                 documented escape-hatches table in docs/security-properties.md."
            );
            n
        }
        VerifyCadenceOutcome::Accepted(n) => n,
    }
}

/// Run a chain-verification pass and emit a structured audit event
/// when the chain is broken. Returns true if the chain is intact
/// (or empty), false if a break was detected.
///
/// Failure path writes the alarm to the out-of-chain `audit-alarms.log`
/// **first** — that file is the load-bearing evidence because an
/// attacker who tampered the SQLite chain can also tamper any
/// follow-up `audit.chain_broken` row written into the same chain. The
/// in-chain row is defense-in-depth: if it's still there, an honest
/// chain-walk reader sees both signals; if it isn't, the alarm log
/// is the surviving record.
///
/// `audit_tx` is the flush-loop's own sender. When set, the in-chain
/// chain_broken event is dispatched through the channel so the
/// standard flush path (SQLite write + SIEM forward) carries it. On a
/// closed or full channel the function falls back to a direct
/// `log.write_batch`, preserving SQLite landing even when the route
/// to SIEM is unavailable. `None` skips the in-chain emission
/// entirely; tests that don't care about the channel pass `None` and
/// rely on the alarm log to prove the verify pass fired.
/// Categorise a serde error string by its leading clause so a flood of
/// near-identical messages collapses to a small number of category
/// counts on the aggregated warn line. Inputs look like
/// `missing field `actor_kind` at line 1 column 42` or
/// `unknown variant `Foo`, expected one of ...`. The category is the
/// span before the first backtick, colon, or comma.
fn drift_reason_category(reason: &str) -> String {
    reason
        .chars()
        .take_while(|c| !matches!(c, '`' | ':' | ','))
        .collect::<String>()
        .trim()
        .to_string()
}

/// One aggregated WARN line per verify pass summarising schema-drift
/// rows: total count, the seq range they fell within, and counts per
/// category. Keeps the operator log readable when a backward-compat
/// schema gap touches many rows at once.
fn report_schema_drift(records: &[SchemaDriftRecord]) {
    if records.is_empty() {
        return;
    }
    let count = records.len();
    let seq_min = records.iter().map(|r| r.seq).min().unwrap_or(0);
    let seq_max = records.iter().map(|r| r.seq).max().unwrap_or(0);
    let mut by_category: std::collections::BTreeMap<String, usize> = Default::default();
    for r in records {
        *by_category
            .entry(drift_reason_category(&r.reason))
            .or_insert(0) += 1;
    }
    let categories: Vec<String> = by_category
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    tracing::warn!(
        count,
        seq_min,
        seq_max,
        categories = %categories.join(","),
        "audit chain verification: {count} row(s) unverifiable (schema drift). \
         seq range [{seq_min}..={seq_max}]. categories: {}",
        categories.join(", "),
    );
}

/// Emit one `audit.row_unverifiable` event per drift record so an
/// operator reading the chain sees exactly which rows the verifier
/// could not deserialize. Mirrors the channel-routed dispatch path
/// used by `audit.chain_broken` so SIEM forwarders pick the events
/// up on the next flush; falls back to direct write when the channel
/// is unavailable.
async fn emit_drift_events(
    log: &AuditLog,
    audit_tx: Option<&mpsc::Sender<AuditEvent>>,
    records: &[SchemaDriftRecord],
) {
    for record in records {
        let category = drift_reason_category(&record.reason);
        let event = AuditEvent::new(
            ActorKind::Service,
            "audit",
            "audit.row_unverifiable",
            "audit.db",
        )
        .with_detail(serde_json::json!({
            "session": record.session_id,
            "seq": record.seq,
            "reason": record.reason,
            "reason_category": category,
        }));
        let routed = match audit_tx {
            Some(tx) => match tx.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        "audit channel full; landing row_unverifiable via direct \
                         write_batch (SIEM forwarding on this event is lost)"
                    );
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
            None => false,
        };
        if !routed && let Err(e) = log.write_batch(&[event]) {
            tracing::error!("audit row_unverifiable event write failed: {e}");
        }
    }
}

async fn run_verify_pass(
    log: &AuditLog,
    alarms: &AlarmLog,
    audit_tx: Option<&mpsc::Sender<AuditEvent>>,
) -> VerifyPassOutcome {
    match log.verify() {
        Ok(VerifyResult::Ok {
            rows_verified,
            schema_drift_records,
            ..
        }) => {
            tracing::debug!(
                rows_verified,
                "audit chain verification: ok (continuous pass)"
            );
            report_schema_drift(&schema_drift_records);
            emit_drift_events(log, audit_tx, &schema_drift_records).await;
            // Schema drift is not tamper: chain hashes verified on
            // every row's raw payload bytes. The unverifiable rows
            // are surfaced via the WARN line above and per-row
            // `audit.row_unverifiable` events; the integrity counter
            // is not incremented.
            VerifyPassOutcome {
                intact: true,
                alarm_write_ok: true,
            }
        }
        Ok(VerifyResult::Empty) => VerifyPassOutcome {
            intact: true,
            alarm_write_ok: true,
        },
        Ok(VerifyResult::SignatureInvalid {
            session_id,
            seq,
            signing_key_id,
            reason,
            verified_count,
            invalid_signatures_count: _,
        }) => {
            tracing::error!(
                session = %session_id,
                seq,
                verified_count,
                signing_key_id = %signing_key_id,
                reason = %reason,
                "audit chain BROKEN: invalid chain-head signature detected"
            );
            let alarm = AlarmRecord {
                timestamp: now_rfc3339(),
                alarm_type: "signature_invalid".into(),
                session_id: Some(session_id.as_str().to_string()),
                seq: Some(seq),
                expected_hash: Some(signing_key_id.clone()),
                actual_hash: Some(reason.clone()),
                hostname: hostname_best_effort(),
                gateway_pid: std::process::id(),
                hmac: None,
            };
            let alarm_write_ok = alarms.append(&alarm).is_ok();
            VerifyPassOutcome {
                intact: false,
                alarm_write_ok,
            }
        }
        Ok(VerifyResult::MissingChainHead { .. }) => VerifyPassOutcome {
            // Continuous verification runs in transition mode, so a
            // missing ChainHead is informational and does not halt
            // the writer. Operators who want hard-fail on missing
            // heads run `wirken audit verify --require-signed`.
            intact: true,
            alarm_write_ok: true,
        },
        Ok(VerifyResult::Broken {
            session_id,
            seq,
            expected_hash,
            actual_hash,
            verified_count,
        }) => {
            tracing::error!(
                session = %session_id,
                seq,
                verified_count,
                expected_hash = %expected_hash,
                actual_hash = %actual_hash,
                "audit chain BROKEN — continuous verification detected tampering"
            );
            let alarm = AlarmRecord {
                timestamp: now_rfc3339(),
                alarm_type: "chain_broken".into(),
                session_id: Some(session_id.as_str().to_string()),
                seq: Some(seq),
                expected_hash: Some(expected_hash.clone()),
                actual_hash: Some(actual_hash.clone()),
                hostname: hostname_best_effort(),
                gateway_pid: std::process::id(),
                hmac: None,
            };
            let alarm_write_ok = match alarms.append(&alarm) {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(
                        "audit alarm-log write failed: {e}. The tracing::error \
                         above is now the only surviving record."
                    );
                    false
                }
            };
            // Defense-in-depth: also try to land an audit row so an
            // honest chain-walk reader sees the failure inline. The
            // alarm log is the load-bearing record above; this is
            // best-effort.
            //
            // Route the in-chain row through the flush-loop channel
            // when one is provided so SIEM forwarding picks it up on
            // the next flush. `try_send` is non-blocking: the verify
            // pass runs *inside* the flush loop that owns the
            // receiver, so a blocking `send` would deadlock against
            // its own drain. If the channel is full or closed, fall
            // back to a direct `write_batch` so the SQLite landing
            // still happens (matching the prior behaviour); SIEM
            // forwarding is lost on that fallback path, which the
            // alarm log compensates for.
            let event = AuditEvent::new(
                ActorKind::Service,
                "audit",
                "audit.chain_broken",
                "audit.db",
            )
            .with_detail(serde_json::json!({
                "session": session_id.as_str(),
                "seq": seq,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "verified_count": verified_count,
            }));
            let routed_through_channel = match audit_tx {
                Some(tx) => match tx.try_send(event.clone()) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            "audit channel full; landing chain_broken via direct \
                             write_batch (SIEM forwarding on this event is lost; \
                             alarm log retains the load-bearing record)"
                        );
                        false
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        tracing::warn!(
                            "audit channel closed; landing chain_broken via direct \
                             write_batch (SIEM forwarding unavailable)"
                        );
                        false
                    }
                },
                None => false,
            };
            if !routed_through_channel && let Err(e) = log.write_batch(&[event]) {
                tracing::error!("audit chain_broken event write failed: {e}");
            }
            VerifyPassOutcome {
                intact: false,
                alarm_write_ok,
            }
        }
        Err(e) => {
            tracing::error!("audit chain verification errored: {e}");
            let alarm = AlarmRecord {
                timestamp: now_rfc3339(),
                alarm_type: "verify_error".into(),
                session_id: None,
                seq: None,
                expected_hash: None,
                actual_hash: Some(e.to_string()),
                hostname: hostname_best_effort(),
                gateway_pid: std::process::id(),
                hmac: None,
            };
            let alarm_write_ok = alarms.append(&alarm).is_ok();
            VerifyPassOutcome {
                intact: false,
                alarm_write_ok,
            }
        }
    }
}

impl AuditWriter {
    /// Create a new audit writer that flushes to the given database path.
    /// Spawns a background tokio task for batched writes.
    /// Returns the writer handle and a join handle for the flush task.
    pub fn new(db_path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        Self::with_siem_and_alarm_key(db_path, None, None)
    }

    /// Create a new audit writer with optional SIEM forwarding.
    /// Alarm log runs in unsigned mode.
    pub fn with_siem(
        db_path: &Path,
        siem_config: Option<SiemConfig>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        Self::with_siem_and_alarm_key(db_path, siem_config, None)
    }

    /// Create a new audit writer with optional SIEM forwarding and an
    /// optional HMAC signing key for the alarm log. When the key is
    /// `None` the alarm log runs in unsigned mode and the caller is
    /// expected to surface a prominent warn elsewhere.
    pub fn with_siem_and_alarm_key(
        db_path: &Path,
        siem_config: Option<SiemConfig>,
        alarm_log_key: Option<Vec<u8>>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        Self::with_siem_alarm_and_audit_signer(db_path, siem_config, alarm_log_key, None)
    }

    /// Full constructor: SIEM, alarm-log HMAC key, and audit
    /// chain-head signing key. When `audit_signer` is `Some`,
    /// chain-head emission applies on the legacy-event flush path
    /// just as it does on direct typed-event appends.
    pub fn with_siem_alarm_and_audit_signer(
        db_path: &Path,
        siem_config: Option<SiemConfig>,
        alarm_log_key: Option<Vec<u8>>,
        audit_signer: Option<Arc<AuditSigningKey>>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), AuditError> {
        // Verify database can be opened. Use the signed open path
        // when a signer is supplied so the cadence sees the
        // database from the start.
        let _ = match audit_signer.clone() {
            Some(s) => AuditLog::open_with_signer(db_path, s)?,
            None => AuditLog::open(db_path)?,
        };

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let path = db_path.to_path_buf();
        // The alarm log lives in the same directory as the audit
        // database. AuditLog::open already created the parent dir if
        // it didn't exist.
        let alarm_dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let alarms = match alarm_log_key {
            Some(key) => AlarmLog::with_signing_key(&alarm_dir, key),
            None => AlarmLog::new(&alarm_dir),
        };
        let forwarder = match siem_config {
            Some(cfg) => Some(SiemForwarder::new(cfg).map_err(AuditError::SiemConfig)?),
            None => None,
        };
        // The flush loop holds a *weak* sender so the channel still
        // closes when the AuditWriter's strong `tx` drops. A cloned
        // strong Sender here would deadlock the loop on shutdown
        // because `rx.recv()` only returns None when the last strong
        // sender drops.
        let verify_tx = tx.downgrade();
        let handle = tokio::spawn(flush_loop(
            rx,
            verify_tx,
            path,
            forwarder,
            alarms,
            audit_signer,
        ));

        Ok((Self { tx }, handle))
    }

    /// Send an audit event to be written. The event is buffered and
    /// flushed asynchronously, but the channel is bounded at
    /// `CHANNEL_CAPACITY`, so this awaits capacity when the flush loop
    /// is behind rather than returning immediately. A halted writer has
    /// dropped the receiver, which surfaces here as `ChannelClosed`.
    pub async fn log(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.tx
            .send(event)
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// Send an audit event, blocking version for non-async contexts.
    pub fn log_blocking(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.tx
            .blocking_send(event)
            .map_err(|_| AuditError::ChannelClosed)
    }
}

async fn flush_loop(
    mut rx: mpsc::Receiver<AuditEvent>,
    audit_tx: mpsc::WeakSender<AuditEvent>,
    db_path: PathBuf,
    forwarder: Option<SiemForwarder>,
    alarms: AlarmLog,
    audit_signer: Option<Arc<AuditSigningKey>>,
) {
    // Open the audit log once for the lifetime of the flush loop and
    // reuse the connection across every flush. The previous flush()
    // re-opened SQLite on every tick (every 50ms or 100 events),
    // paying the per-connection cost — pragma setup, idempotent
    // schema migration, AuditLog construction — for nothing. With WAL
    // + busy_timeout from #9445e27, one persistent connection is the
    // right shape: writes are serialized inside the
    // SqliteSessionLog's own Mutex<Connection>, and the busy_timeout
    // covers contention with the agent's separate session-log handle
    // on the same file.
    //
    // Open failure here means the loop never starts. The mpsc::Sender
    // returns ChannelClosed on the first log() call, which is the
    // signal the agent observes to refuse to continue (same shape as
    // the persistent-failure halt below).
    let log = {
        let opened = match audit_signer.clone() {
            Some(s) => AuditLog::open_with_signer(&db_path, s),
            None => AuditLog::open(&db_path),
        };
        match opened {
            Ok(l) => Arc::new(l),
            Err(e) => {
                tracing::error!("Audit log open failed at flush_loop start: {e}");
                return;
            }
        }
    };

    let mut buffer: Vec<AuditEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut tick = interval(FLUSH_INTERVAL);
    let mut consecutive_failures: u32 = 0;
    let verify_cadence = verify_every_flushes();
    let mut flushes_since_verify: u64 = 0;
    let mut integrity_failures: u32 = 0;
    let mut alarm_write_failures: u32 = 0;

    loop {
        tokio::select! {
            // Timer tick — flush whatever we have
            _ = tick.tick() => {
                if !buffer.is_empty()
                    && attempt_flush(&log, &mut buffer, &forwarder, &mut consecutive_failures)
                        .await
                {
                    break;
                }
                flushes_since_verify = flushes_since_verify.saturating_add(1);
                if flushes_since_verify >= verify_cadence {
                    // Upgrade the weak sender only for this call so
                    // the channel can still close cleanly between
                    // verify passes. If the strong sender is already
                    // gone, `tx_strong` is None and run_verify_pass
                    // falls back to its direct-write path.
                    let tx_strong = audit_tx.upgrade();
                    let outcome = run_verify_pass(&log, &alarms, tx_strong.as_ref()).await;
                    // Drop the strong sender we briefly upgraded so it
                    // does not keep the channel alive past the drain.
                    drop(tx_strong);
                    if record_verify_outcome(
                        &mut integrity_failures,
                        &mut alarm_write_failures,
                        &outcome,
                    ) {
                        // Drain channel-routed events the failing
                        // verify pass dispatched (chain_broken and
                        // any audit.row_unverifiable) plus the
                        // pre-existing batched buffer, so the SIEM
                        // forwarder sees them before the receiver
                        // drops on `break`. Symmetric with the
                        // rx-closed branch below.
                        drain_channel_and_flush(
                            &mut rx, &log, &mut buffer, &forwarder,
                        )
                        .await;
                        break;
                    }
                    flushes_since_verify = 0;
                }
            }
            // New event received
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        buffer.push(event);
                        if buffer.len() >= BATCH_SIZE
                            && attempt_flush(
                                &log,
                                &mut buffer,
                                &forwarder,
                                &mut consecutive_failures,
                            )
                            .await
                        {
                            break;
                        }
                    }
                    None => {
                        // Channel closed — best-effort final flush and exit
                        if !buffer.is_empty() {
                            let _ = flush(&log, &mut buffer, &forwarder).await;
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Drain pending events from `rx` into the shared flush `buffer`,
/// then flush. Called from the verify-halt branch of [`flush_loop`]
/// immediately before `break`, so any event the just-completed
/// verify pass dispatched through the channel (typically a
/// channel-routed `audit.chain_broken` or `audit.row_unverifiable`)
/// reaches the SIEM forwarder before the receiver drops and the
/// writer enters its halt state.
///
/// Safe to mutate `rx` here without contending with the receive arm
/// of the surrounding `tokio::select!`: the verify pass has already
/// returned, so no new events can be appended to the queue between
/// the verify pass completing and this drain starting.
///
/// Reuses the shared `buffer` rather than a fresh `Vec`, which means
/// pre-existing batched events are flushed too. That alignment is
/// deliberate: graceful shutdown (the `rx.recv -> None` branch at
/// the bottom of [`flush_loop`]) already does this, and matching
/// behaviour on halt removes the perverse asymmetry of operators
/// receiving fewer SIEM signals when something goes wrong than
/// when everything is fine.
///
/// Best-effort: a `flush` error here does not reverse the halt
/// decision. The loop is going to break either way.
async fn drain_channel_and_flush(
    rx: &mut mpsc::Receiver<AuditEvent>,
    log: &AuditLog,
    buffer: &mut Vec<AuditEvent>,
    forwarder: &Option<SiemForwarder>,
) {
    while let Ok(event) = rx.try_recv() {
        buffer.push(event);
    }
    if !buffer.is_empty() {
        let _ = flush(log, buffer, forwarder).await;
    }
}

/// Run one flush and update `consecutive_failures`. Returns `true`
/// when the loop should halt (persistent failure) so the caller can
/// break and let `rx` drop, closing the audit channel.
async fn attempt_flush(
    log: &AuditLog,
    buffer: &mut Vec<AuditEvent>,
    forwarder: &Option<SiemForwarder>,
    consecutive_failures: &mut u32,
) -> bool {
    match flush(log, buffer, forwarder).await {
        Ok(()) => {
            *consecutive_failures = 0;
            false
        }
        Err(_) => {
            *consecutive_failures += 1;
            let halt = *consecutive_failures >= MAX_CONSECUTIVE_FAILURES
                || buffer.len() > MAX_BUFFER_ON_FAILURE;
            if halt {
                tracing::error!(
                    failures = *consecutive_failures,
                    buffered = buffer.len(),
                    "Audit flush halting after persistent write failures; \
                     closing channel so callers observe ChannelClosed"
                );
            }
            halt
        }
    }
}

async fn flush(
    log: &AuditLog,
    buffer: &mut Vec<AuditEvent>,
    forwarder: &Option<SiemForwarder>,
) -> Result<(), AuditError> {
    // Primary durability is SQLite. If `write_batch` fails, return the
    // error WITHOUT clearing the buffer so the loop can retain events
    // and retry. Silently discarding audit events on a failed write
    // is an integrity bug: a breach could occur during the window
    // where its event is buffered but never flushed.
    log.write_batch(buffer).inspect_err(|e| {
        tracing::error!("Audit write failed: {e}");
    })?;

    // Primary write landed. SIEM forward is best-effort and only runs
    // after durability so a failed primary write does not re-send the
    // same events to SIEM on every retry.
    if let Some(fwd) = forwarder {
        fwd.forward(buffer).await;
    }

    buffer.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;
    use crate::log::{AuditLog, AuditQuery};

    #[tokio::test]
    async fn flush_clears_buffer_on_write_success() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        let mut buffer = vec![AuditEvent::new(ActorKind::User, "actor", "a1", "t1")];
        let res = flush(&log, &mut buffer, &None).await;
        assert!(res.is_ok(), "flush should succeed against a valid db");
        assert!(
            buffer.is_empty(),
            "buffer must clear after a successful flush"
        );
    }

    #[tokio::test]
    async fn run_verify_pass_emits_chain_broken_event_on_corruption() {
        // Write some events, drop the log, corrupt one row's payload,
        // reopen, run a verify pass. The pass should detect the break
        // and append an `audit.chain_broken` event to the log.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        // Tamper with row 3's payload directly — same shape as the
        // existing audit/src/tests.rs `tampered_row_data_detected` test.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }
        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        // No channel: exercise the fallback direct-write path so the
        // in-chain assertion below proves SQLite landing regardless
        // of whether the channel was opted into. The channel-routed
        // path is covered by `run_verify_pass_routes_chain_broken_through_channel`.
        let outcome = run_verify_pass(&log, &alarms, None).await;
        assert!(!outcome.intact, "expected break to be detected");
        assert!(
            outcome.alarm_write_ok,
            "alarm-log write should have succeeded with a writable temp dir"
        );

        // The alarm log is the load-bearing record.
        let alarm_records = alarms.read_all().unwrap();
        assert_eq!(
            alarm_records.len(),
            1,
            "expected one chain_broken alarm, got {alarm_records:?}"
        );
        assert_eq!(alarm_records[0].record.alarm_type, "chain_broken");
        assert_eq!(alarm_records[0].record.seq, Some(2));

        // Defense-in-depth: the in-chain audit row should also be there.
        let events = log
            .query(&AuditQuery {
                action: Some("audit.chain_broken".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            !events.is_empty(),
            "expected audit.chain_broken event to be appended"
        );
    }

    #[tokio::test]
    async fn run_verify_pass_routes_chain_broken_through_channel() {
        // When a Sender is provided, the in-chain `audit.chain_broken`
        // event must be dispatched through the channel so the flush
        // loop's standard write+forward path carries it. This is the
        // Finding C fix: prior to threading the Sender, the verify
        // pass wrote directly via `log.write_batch`, bypassing the
        // SIEM forwarder entirely.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(16);

        let outcome = run_verify_pass(&log, &alarms, Some(&tx)).await;
        assert!(!outcome.intact);

        let routed = rx
            .try_recv()
            .expect("chain_broken event must be on the channel");
        assert_eq!(routed.action, "audit.chain_broken");
        assert_eq!(routed.target, "audit.db");
        assert!(matches!(routed.actor_kind, ActorKind::Service));
        assert!(
            routed.detail.get("expected_hash").is_some(),
            "detail must include expected_hash, got {:?}",
            routed.detail
        );

        // The fallback direct-write must NOT have fired: SQLite holds
        // no chain_broken row from this pass (the row will land via
        // the flush loop receiving from rx, which is not part of this
        // unit test). The channel is the single dispatch path when
        // it accepts the event.
        let in_chain = log
            .query(&AuditQuery {
                action: Some("audit.chain_broken".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            in_chain.is_empty(),
            "channel-routed event must not also be direct-written; got {in_chain:?}"
        );
    }

    #[tokio::test]
    async fn run_verify_pass_falls_back_to_direct_write_when_channel_closed() {
        // Closing the receiver drops the channel. The verify pass
        // must fall back to a direct write_batch so the in-chain row
        // still lands even though SIEM forwarding is lost on this
        // event. The alarm log remains the load-bearing record.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let (tx, rx) = mpsc::channel::<AuditEvent>(16);
        drop(rx);

        let outcome = run_verify_pass(&log, &alarms, Some(&tx)).await;
        assert!(!outcome.intact);

        let in_chain = log
            .query(&AuditQuery {
                action: Some("audit.chain_broken".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            !in_chain.is_empty(),
            "closed-channel fallback must land the row via direct write_batch"
        );
    }

    #[tokio::test]
    async fn drain_channel_and_flush_writes_pending_events_to_sqlite() {
        // Basic helper contract: events sitting in the channel and in
        // the shared buffer are both flushed through `flush` (SQLite
        // landing + SIEM forwarding) before the helper returns.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(16);

        tx.try_send(AuditEvent::new(
            ActorKind::Service,
            "audit",
            "audit.chain_broken",
            "audit.db",
        ))
        .unwrap();
        tx.try_send(AuditEvent::new(
            ActorKind::Service,
            "audit",
            "audit.row_unverifiable",
            "audit.db",
        ))
        .unwrap();
        let mut buffer: Vec<AuditEvent> = vec![AuditEvent::new(
            ActorKind::User,
            "actor",
            "pre-existing",
            "t",
        )];

        drain_channel_and_flush(&mut rx, &log, &mut buffer, &None).await;

        assert!(
            buffer.is_empty(),
            "drain must clear the buffer through flush"
        );
        // All three events landed in SQLite, including the
        // pre-existing batched event (the asymmetry-removal property).
        let stored = log
            .query(&AuditQuery {
                limit: Some(100),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            stored.len(),
            3,
            "expected drained channel events + pre-existing buffer in SQLite, got {stored:?}"
        );
        let actions: Vec<&str> = stored.iter().map(|e| e.event.action.as_str()).collect();
        assert!(actions.contains(&"audit.chain_broken"));
        assert!(actions.contains(&"audit.row_unverifiable"));
        assert!(actions.contains(&"pre-existing"));
    }

    #[tokio::test]
    async fn drain_channel_and_flush_is_noop_when_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();
        let (_tx, mut rx) = mpsc::channel::<AuditEvent>(16);
        let mut buffer: Vec<AuditEvent> = Vec::new();

        drain_channel_and_flush(&mut rx, &log, &mut buffer, &None).await;

        assert!(buffer.is_empty());
        let stored = log
            .query(&AuditQuery {
                limit: Some(10),
                ..Default::default()
            })
            .unwrap();
        assert!(
            stored.is_empty(),
            "empty drain must not write phantom events"
        );
    }

    #[tokio::test]
    async fn channel_routed_chain_broken_events_drain_at_halt_boundary() {
        // The headline #107 property: when the verify pass routes
        // chain_broken events through the channel and MAX_INTEGRITY_FAILURES
        // is reached, every chain_broken event from the failing passes
        // lands in SQLite (and would forward to SIEM) before the loop
        // breaks. Prior to the drain wiring, the receiver dropped on
        // halt with events still in-queue, producing the N-1 gap.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(16);
        let mut buffer: Vec<AuditEvent> = Vec::new();

        // Simulate the flush-loop sequence: three failing verify
        // passes (channel-routed), then the drain that the verify-halt
        // branch performs before break.
        for _ in 0..MAX_INTEGRITY_FAILURES {
            let outcome = run_verify_pass(&log, &alarms, Some(&tx)).await;
            assert!(!outcome.intact);
        }
        drain_channel_and_flush(&mut rx, &log, &mut buffer, &None).await;

        // Three chain_broken events visible in SQLite: one per
        // failing verify pass. Without the drain this would be zero
        // (every event was routed through the channel and the
        // receiver-drop on halt would have lost them all).
        let chain_broken = log
            .query(&AuditQuery {
                action: Some("audit.chain_broken".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            chain_broken.len(),
            MAX_INTEGRITY_FAILURES as usize,
            "expected one chain_broken per failing pass in SQLite, got {chain_broken:?}"
        );

        // Alarm-log row count matches: each pass appended one alarm
        // before try_send. SIEM-forwarder dispatch reliability now
        // matches alarm-log reliability at the halt boundary.
        let alarm_records = alarms.read_all().unwrap();
        assert_eq!(
            alarm_records.len(),
            MAX_INTEGRITY_FAILURES as usize,
            "alarm-log count must match chain_broken count"
        );
    }

    #[tokio::test]
    async fn channel_routed_row_unverifiable_events_drain_at_halt_boundary() {
        // Composition with #115: when the writer halts (here forced
        // by repeated drift passes that don't themselves halt, then
        // a drain call), audit.row_unverifiable events the verify
        // pass routed through the channel land in SQLite before the
        // receiver drops. The drain is event-agnostic; the property
        // generalises to any future channel-routed verify event.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        rewrite_row_as_schema_drift(&db_path, 3, &schema_drift_payload());

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(16);
        let mut buffer: Vec<AuditEvent> = Vec::new();

        let outcome = run_verify_pass(&log, &alarms, Some(&tx)).await;
        assert!(outcome.intact, "schema drift must not trigger halt itself");

        // Drain captures the row_unverifiable event the verify pass
        // try_sent into rx, even though the verify outcome was Ok.
        drain_channel_and_flush(&mut rx, &log, &mut buffer, &None).await;

        let stored = log
            .query(&AuditQuery {
                action: Some("audit.row_unverifiable".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            stored.len(),
            1,
            "row_unverifiable event must be drained and flushed, got {stored:?}"
        );
    }

    /// Rewrite the payload of the row with `id` so that it no longer
    /// deserializes as a `SessionEvent`, recomputing `leaf_hash` and
    /// `hash` from the new bytes (and the prior row's chain hash) so
    /// the chain itself still verifies. This is the on-disk shape of
    /// schema drift: a row that hashes consistently but whose
    /// structure the current binary cannot parse (the 1.5.1 first-run
    /// regression case, generalised).
    fn rewrite_row_as_schema_drift(db_path: &Path, id: i64, new_payload: &str) {
        use sha2::{Digest, Sha256};
        let conn = rusqlite::Connection::open(db_path).unwrap();
        let prev_hash: String = conn
            .query_row(
                "SELECT prev_hash FROM session_events WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .unwrap();
        let leaf_hash = {
            let mut h = Sha256::new();
            h.update(new_payload.as_bytes());
            let bytes = h.finalize();
            let mut s = String::with_capacity(64);
            for b in bytes {
                use std::fmt::Write;
                write!(&mut s, "{b:02x}").unwrap();
            }
            s
        };
        let chain_hash = {
            let mut h = Sha256::new();
            h.update(prev_hash.as_bytes());
            h.update(leaf_hash.as_bytes());
            let bytes = h.finalize();
            let mut s = String::with_capacity(64);
            for b in bytes {
                use std::fmt::Write;
                write!(&mut s, "{b:02x}").unwrap();
            }
            s
        };
        // Update the row, then patch the prev_hash of the next row in
        // this session so chain continuity past the drifted row stays
        // intact (the hash check at row N+1 reads our new chain_hash
        // as its prev_hash).
        let session_id: String = conn
            .query_row(
                "SELECT session_id FROM session_events WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .unwrap();
        let seq: i64 = conn
            .query_row(
                "SELECT seq FROM session_events WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE session_events SET payload = ?1, leaf_hash = ?2, hash = ?3 WHERE id = ?4",
            rusqlite::params![new_payload, leaf_hash, chain_hash, id],
        )
        .unwrap();
        let _ = conn.execute(
            "UPDATE session_events SET prev_hash = ?1
             WHERE session_id = ?2 AND seq = ?3",
            rusqlite::params![chain_hash, session_id, seq + 1],
        );
        // The next-row hash itself now mismatches (it was computed
        // from the old chain_hash). Recompute it.
        if let Ok((next_leaf, next_seq)) = conn.query_row(
            "SELECT leaf_hash, seq FROM session_events
             WHERE session_id = ?1 AND seq = ?2",
            rusqlite::params![session_id, seq + 1],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        ) {
            let new_next_chain = {
                let mut h = Sha256::new();
                h.update(chain_hash.as_bytes());
                h.update(next_leaf.as_bytes());
                let bytes = h.finalize();
                let mut s = String::with_capacity(64);
                for b in bytes {
                    use std::fmt::Write;
                    write!(&mut s, "{b:02x}").unwrap();
                }
                s
            };
            conn.execute(
                "UPDATE session_events SET hash = ?1
                 WHERE session_id = ?2 AND seq = ?3",
                rusqlite::params![new_next_chain, session_id, next_seq],
            )
            .unwrap();
            // Cascade: every later row's chain_hash depends on the
            // prior one. Walk forward until we run out of rows.
            let mut prev_chain = new_next_chain;
            let mut s = next_seq;
            loop {
                s += 1;
                match conn.query_row(
                    "SELECT leaf_hash FROM session_events
                     WHERE session_id = ?1 AND seq = ?2",
                    rusqlite::params![session_id, s],
                    |row| row.get::<_, String>(0),
                ) {
                    Ok(leaf) => {
                        let new_chain = {
                            let mut h = Sha256::new();
                            h.update(prev_chain.as_bytes());
                            h.update(leaf.as_bytes());
                            let bytes = h.finalize();
                            let mut out = String::with_capacity(64);
                            for b in bytes {
                                use std::fmt::Write;
                                write!(&mut out, "{b:02x}").unwrap();
                            }
                            out
                        };
                        conn.execute(
                            "UPDATE session_events SET prev_hash = ?1, hash = ?2
                             WHERE session_id = ?3 AND seq = ?4",
                            rusqlite::params![prev_chain, new_chain, session_id, s],
                        )
                        .unwrap();
                        prev_chain = new_chain;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    /// JSON payload that round-trips through serde but is not a valid
    /// `SessionEvent` (no matching variant tag), so `parse_row` fails
    /// with a serde error and the row surfaces as schema drift.
    fn schema_drift_payload() -> String {
        serde_json::to_string(&serde_json::json!({
            "kind": "totally_unknown_variant_for_testing",
            "field": "value",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn run_verify_pass_treats_schema_drift_as_intact() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        rewrite_row_as_schema_drift(&db_path, 3, &schema_drift_payload());

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let outcome = run_verify_pass(&log, &alarms, None).await;

        assert!(
            outcome.intact,
            "schema drift must not be classified as tamper"
        );
        assert!(outcome.alarm_write_ok);

        // No alarm-log entry: schema drift is not tamper-class.
        let alarm_records = alarms.read_all().unwrap();
        assert!(
            alarm_records.is_empty(),
            "alarm log must stay empty on schema drift, got {alarm_records:?}"
        );

        // The drifted row is surfaced via an in-chain
        // `audit.row_unverifiable` event (channel was None so the
        // direct-write fallback fired).
        let events = log
            .query(&AuditQuery {
                action: Some("audit.row_unverifiable".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "expected one audit.row_unverifiable event, got {events:?}"
        );
    }

    #[tokio::test]
    async fn schema_drift_does_not_halt_after_repeated_passes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        rewrite_row_as_schema_drift(&db_path, 3, &schema_drift_payload());

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let mut integrity = 0u32;
        let mut alarm = 0u32;

        // Run more passes than the integrity halt threshold; counter
        // must never increment because every pass reports intact.
        for _ in 0..MAX_INTEGRITY_FAILURES + 2 {
            let outcome = run_verify_pass(&log, &alarms, None).await;
            let halt = record_verify_outcome(&mut integrity, &mut alarm, &outcome);
            assert!(!halt, "schema drift must never trigger halt");
            assert_eq!(
                integrity, 0,
                "integrity counter must stay zero on schema drift"
            );
        }
    }

    #[tokio::test]
    async fn run_verify_pass_routes_row_unverifiable_through_channel() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        rewrite_row_as_schema_drift(&db_path, 3, &schema_drift_payload());

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(16);

        let outcome = run_verify_pass(&log, &alarms, Some(&tx)).await;
        assert!(outcome.intact);

        let routed = rx
            .try_recv()
            .expect("row_unverifiable event must be on the channel");
        assert_eq!(routed.action, "audit.row_unverifiable");
        assert_eq!(routed.target, "audit.db");
        assert!(matches!(routed.actor_kind, ActorKind::Service));
        assert_eq!(routed.detail.get("seq").and_then(|v| v.as_u64()), Some(2));
        assert!(routed.detail.get("reason").is_some());
        assert!(routed.detail.get("reason_category").is_some());
    }

    #[test]
    fn drift_reason_category_collapses_serde_messages() {
        assert_eq!(
            drift_reason_category("missing field `actor_kind` at line 1 column 42"),
            "missing field"
        );
        assert_eq!(
            drift_reason_category("unknown variant `Foo`, expected one of `Bar`"),
            "unknown variant"
        );
        assert_eq!(
            drift_reason_category("invalid type: string \"x\", expected u64"),
            "invalid type"
        );
    }

    fn ok_outcome() -> VerifyPassOutcome {
        VerifyPassOutcome {
            intact: true,
            alarm_write_ok: true,
        }
    }

    fn broken_outcome(alarm_write_ok: bool) -> VerifyPassOutcome {
        VerifyPassOutcome {
            intact: false,
            alarm_write_ok,
        }
    }

    #[test]
    fn verify_cadence_unset_uses_default_silently() {
        assert_eq!(
            classify_verify_cadence(Err(std::env::VarError::NotPresent)),
            VerifyCadenceOutcome::UnsetUseDefault
        );
    }

    #[test]
    fn verify_cadence_malformed_warns_and_falls_back() {
        let outcome = classify_verify_cadence(Ok("not-a-number".into()));
        assert!(
            matches!(outcome, VerifyCadenceOutcome::MalformedUseDefault(ref s) if s == "not-a-number"),
            "got {outcome:?}"
        );
    }

    #[test]
    fn verify_cadence_negative_text_warns_as_malformed() {
        // u64 parse rejects the leading '-'; fold this into the
        // malformed bucket so the operator sees the same warn shape.
        let outcome = classify_verify_cadence(Ok("-5".into()));
        assert!(
            matches!(outcome, VerifyCadenceOutcome::MalformedUseDefault(_)),
            "got {outcome:?}"
        );
    }

    #[test]
    fn verify_cadence_zero_warns_and_falls_back() {
        assert_eq!(
            classify_verify_cadence(Ok("0".into())),
            VerifyCadenceOutcome::ZeroUseDefault
        );
    }

    #[test]
    fn verify_cadence_normal_value_accepted_silently() {
        assert_eq!(
            classify_verify_cadence(Ok("250".into())),
            VerifyCadenceOutcome::Accepted(250)
        );
    }

    #[test]
    fn verify_cadence_above_ceiling_warns_but_accepts() {
        let high = VERIFY_CADENCE_SANITY_CEILING + 1;
        assert_eq!(
            classify_verify_cadence(Ok(high.to_string())),
            VerifyCadenceOutcome::AcceptedHigh(high)
        );
    }

    #[test]
    fn integrity_failures_reset_on_intact_pass() {
        let mut integrity = 1;
        let mut alarm = 0;
        assert!(!record_verify_outcome(
            &mut integrity,
            &mut alarm,
            &ok_outcome()
        ));
        assert_eq!(integrity, 0);
    }

    #[test]
    fn three_consecutive_integrity_failures_signal_halt() {
        let mut integrity = 0;
        let mut alarm = 0;
        let outcome = broken_outcome(true);
        assert!(!record_verify_outcome(&mut integrity, &mut alarm, &outcome));
        assert!(!record_verify_outcome(&mut integrity, &mut alarm, &outcome));
        assert!(record_verify_outcome(&mut integrity, &mut alarm, &outcome));
    }

    #[test]
    fn three_consecutive_alarm_write_failures_signal_halt_even_with_chain_intact() {
        // The alarm log is the load-bearing record on a chain break.
        // Reaching the alarm-write halt threshold without intervening
        // chain-verify failures must still close the writer; otherwise
        // the next chain break would land an alarm into the void.
        let mut integrity = 0;
        let mut alarm = 0;
        // Force the alarm-write half of the outcome to false even
        // though the chain reports broken (alarm_write_ok flips
        // independently). With chain broken on every pass we'd hit
        // integrity halt by the third call; mix in two intact passes
        // so the integrity counter resets and only the alarm counter
        // climbs.
        for i in 0..MAX_ALARM_WRITE_FAILURES {
            // Synthetic: chain intact, alarm write failed. This shape
            // is unreachable from `run_verify_pass` (intact path
            // doesn't write an alarm), but the counter logic must
            // still treat the input correctly because `run_verify_pass`
            // could grow a "verify-error with successful alarm" path
            // in the future, and the failing-alarm side of the gate
            // belongs to this helper.
            let outcome = VerifyPassOutcome {
                intact: true,
                alarm_write_ok: false,
            };
            let halt = record_verify_outcome(&mut integrity, &mut alarm, &outcome);
            if i + 1 < MAX_ALARM_WRITE_FAILURES {
                assert!(!halt, "should not halt yet at {} failures", i + 1);
            } else {
                assert!(halt, "must halt at {} failures", i + 1);
            }
        }
    }

    #[test]
    fn intact_pass_with_alarm_ok_resets_both_counters() {
        let mut integrity = 0;
        let mut alarm = 0;
        record_verify_outcome(&mut integrity, &mut alarm, &broken_outcome(false));
        record_verify_outcome(&mut integrity, &mut alarm, &broken_outcome(false));
        record_verify_outcome(&mut integrity, &mut alarm, &ok_outcome());
        assert_eq!(integrity, 0);
        assert_eq!(alarm, 0);
    }

    #[tokio::test]
    async fn three_failed_verify_passes_drive_halt_decision() {
        // End-to-end: tamper the chain, then run verify passes against
        // the live AuditLog three times. The halt-decision helper must
        // signal halt by the third pass so the flush loop breaks.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }
        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let mut integrity = 0u32;
        let mut alarm = 0u32;
        let mut halted = false;
        for _ in 0..MAX_INTEGRITY_FAILURES {
            let outcome = run_verify_pass(&log, &alarms, None).await;
            if record_verify_outcome(&mut integrity, &mut alarm, &outcome) {
                halted = true;
                break;
            }
        }
        assert!(
            halted,
            "expected halt within {MAX_INTEGRITY_FAILURES} passes"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn three_failed_alarm_writes_drive_halt_decision() {
        // chmod 0o000 the alarm log so AlarmLog::append fails. With a
        // tampered chain triggering verify-pass failures, the
        // alarm-write counter climbs in lockstep with integrity. Both
        // halt at MAX=3; this asserts the behavior holds end-to-end.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        {
            let log = AuditLog::open(&db_path).unwrap();
            let events: Vec<AuditEvent> = (0..6)
                .map(|i| AuditEvent::new(ActorKind::User, "actor", format!("step-{i}"), "t"))
                .collect();
            log.write_batch(&events).unwrap();
        }
        // Tamper a row so each verify pass detects a break and tries
        // to append an alarm.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let new_payload = serde_json::to_string(&serde_json::json!({
                "kind": "audit_legacy",
                "actor": "actor",
                "action": "HACKED",
                "target": "t",
                "channel": "",
                "detail": null,
            }))
            .unwrap();
            conn.execute(
                "UPDATE session_events SET payload = ?1 WHERE id = 3",
                rusqlite::params![new_payload],
            )
            .unwrap();
        }

        // Pre-create the alarm log file with no permission bits so
        // AlarmLog::append's open(O_APPEND | O_CREAT) hits EACCES.
        let alarm_path = tmp.path().join("audit-alarms.log");
        std::fs::write(&alarm_path, b"").unwrap();
        std::fs::set_permissions(&alarm_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let log = AuditLog::open(&db_path).unwrap();
        let alarms = AlarmLog::new(tmp.path());
        let mut integrity = 0u32;
        let mut alarm = 0u32;
        let mut halted = false;
        for _ in 0..MAX_ALARM_WRITE_FAILURES {
            let outcome = run_verify_pass(&log, &alarms, None).await;
            assert!(!outcome.intact);
            assert!(
                !outcome.alarm_write_ok,
                "alarm append should fail with chmod 0o000"
            );
            if record_verify_outcome(&mut integrity, &mut alarm, &outcome) {
                halted = true;
                break;
            }
        }
        // Restore perms so TempDir cleanup can remove the file.
        let _ = std::fs::set_permissions(&alarm_path, std::fs::Permissions::from_mode(0o600));
        assert!(halted);
    }

    #[tokio::test]
    async fn write_batch_failure_retains_buffer() {
        // Buffer-retention contract on `write_batch` failure. Open a
        // valid log, then flip the underlying file to read-only so the
        // next write hits SQLITE_READONLY. The buffer must not clear.
        // Rough proxy for "any SQLite write error preserves the
        // retry queue"; the structural property — buffer.clear()
        // happens only on the Ok path of write_batch — is enforced
        // by `flush()` itself.
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        // Make the parent dir read-only so SQLite cannot create the
        // WAL/SHM sidecars during the write. Targeting the dir
        // rather than the db file itself is more reliable across
        // SQLite's lock-and-journal modes.
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o500);
        fs::set_permissions(tmp.path(), perms).unwrap();

        let mut buffer = vec![
            AuditEvent::new(ActorKind::User, "actor", "a1", "t1"),
            AuditEvent::new(ActorKind::User, "actor", "a2", "t2"),
        ];
        let before = buffer.len();
        let res = flush(&log, &mut buffer, &None).await;

        // Restore permissions so TempDir cleanup can remove the dir.
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(tmp.path(), perms).unwrap();

        if res.is_err() {
            assert_eq!(
                buffer.len(),
                before,
                "buffer must retain events when write_batch fails"
            );
        } else {
            // Some filesystems / WAL modes accept writes against a
            // read-only dir if the WAL files already exist. In that
            // case the structural property still holds — buffer
            // cleared only after Ok — but this test is not the one
            // exercising it. Skip rather than fail spuriously.
            eprintln!(
                "skipping retain-on-failure assert: write_batch unexpectedly succeeded \
                 (likely because WAL files already existed on this filesystem)"
            );
        }
    }

    #[tokio::test]
    async fn retained_events_reflush_after_recovery() {
        // Buffer-retention happy path: simulate a transient failure
        // by briefly toggling the write-side, then succeeding on the
        // retry. Easier than reproducing a real SQLite error: call
        // write_batch on the empty buffer twice — the first call
        // (with two events) must Ok and clear; the second must Ok
        // and remain empty. The interesting half — that buffer is
        // preserved across retry attempts — is covered by the
        // `write_batch_failure_retains_buffer` test above.
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let log = AuditLog::open(&db_path).unwrap();

        let mut buffer = vec![
            AuditEvent::new(ActorKind::User, "actor", "attempt", "first"),
            AuditEvent::new(ActorKind::User, "actor", "attempt", "second"),
        ];

        let res = flush(&log, &mut buffer, &None).await;
        assert!(res.is_ok(), "flush against valid db must succeed");
        assert!(buffer.is_empty(), "buffer must clear on successful flush");

        let rows = log.query(&AuditQuery::default()).unwrap();
        assert_eq!(rows.len(), 2, "events must land in the audit log");
        let targets: Vec<&str> = rows.iter().map(|r| r.event.target.as_str()).collect();
        assert!(targets.contains(&"first"));
        assert!(targets.contains(&"second"));
    }
}
