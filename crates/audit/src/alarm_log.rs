//! Out-of-chain alarm log for audit-integrity failures.
//!
//! The continuous-verify loop in [`crate::writer`] calls
//! [`AlarmLog::append`] when [`crate::AuditLog::verify`] reports a
//! broken chain. The alarm record is the load-bearing evidence: an
//! attacker who tampered the SQLite chain can also tamper any
//! follow-up `audit.chain_broken` row written into the same chain,
//! so that row is defense-in-depth, not the primary record.
//!
//! The alarm log is an append-only newline-delimited JSON file at
//! `<data_dir>/audit-alarms.log`, created with `O_APPEND | O_CREAT |
//! O_EXCL` and mode 0o600 on first append. Each line is one
//! [`AlarmRecord`].
//!
//! ## HMAC integrity
//!
//! When constructed via [`AlarmLog::with_signing_key`], every record
//! carries an HMAC-SHA256 tag over the record's canonical JSON
//! (excluding the `hmac` field itself). [`AlarmLog::read_all`] returns
//! a per-record [`AlarmVerifyStatus`] so a reviewer can tell which
//! records are signed-and-verified, signed-but-tampered, or unsigned.
//!
//! On non-unix the file is created without 0o600; the gateway already
//! warns about file-permission posture there.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::AuditError;

type HmacSha256 = Hmac<Sha256>;

/// Alarm-type strings that the boot-time check treats as
/// proceed-class on `wirken run` start. Refuse-by-default: any
/// `alarm_type` not in this list is treated as a tamper-class
/// block until an operator acknowledges it via
/// `wirken audit acknowledge --all`.
///
/// The single entry is the upgrade-compat case: pre-#115 gateways
/// emitted a `verify_error` bucket for "verify pass errored,
/// classification unknown." The #115 slice replaced that bucket
/// with structured tamper-class / schema-class discriminants, so
/// any `verify_error` record on disk today comes from an older
/// gateway version and is not evidence of tampering by the
/// current binary.
///
/// New `alarm_type` strings must be added here explicitly to be
/// treated as proceed-class. The symmetry is intentional: the
/// `tool_to_action` permissions table uses explicit registration
/// to grant capability, not to deny it, and the boot-time
/// integrity surface follows the same posture.
pub const ACKNOWLEDGE_PROCEED_TYPES: &[&str] = &["verify_error"];

/// Outcome of [`AlarmLog::unacknowledged_blocks`]. Carries the
/// count of records per blocking `alarm_type` so the operator
/// message can name what they are unblocking from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnacknowledgedBlocksReport {
    /// Path the boot check scanned.
    pub path: PathBuf,
    /// `alarm_type` -> count, for records whose `alarm_type` is
    /// not on [`ACKNOWLEDGE_PROCEED_TYPES`].
    pub blocking_by_type: BTreeMap<String, usize>,
    /// Total blocking-record count. Equal to the sum of
    /// `blocking_by_type` values; carried separately so the CLI
    /// message can lead with the total.
    pub total: usize,
}

/// One entry in the audit-alarm log. Field shape is intentionally
/// flat so a SIEM ingestor or operator with `tail` and `jq` can
/// read it without a schema doc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlarmRecord {
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// `chain_broken`, `attestation_broken`, etc. Free-form so future
    /// alarm classes don't require an enum bump.
    pub alarm_type: String,
    /// Session whose chain failed to verify, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Per-session sequence at which the break was detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Hash the verifier expected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    /// Hash that was present in the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_hash: Option<String>,
    /// Best-effort host name at alarm time.
    pub hostname: String,
    /// Gateway process id at alarm time.
    pub gateway_pid: u32,
    /// Hex-encoded HMAC-SHA256 over the canonical JSON of this
    /// record with `hmac` set to `None`. Present iff the writer was
    /// constructed with a signing key. A reader without the key
    /// cannot validate the tag but can still parse the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

/// Verification verdict for a record returned by
/// [`AlarmLog::read_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmVerifyStatus {
    /// Record carries an HMAC and the tag matched the configured key.
    Verified,
    /// Record carries an HMAC but no key was configured at read time.
    /// The reader cannot judge integrity.
    NoKey,
    /// Record does not carry an HMAC. Either the writer ran in
    /// unsigned mode or the record predates the HMAC field.
    Unsigned,
    /// Record carries an HMAC and a key was configured, but the tag
    /// did not match. Treat as tampered.
    Tampered,
}

/// One record returned by [`AlarmLog::read_all`], paired with its
/// verification status under whichever key the reader holds.
#[derive(Debug, Clone)]
pub struct VerifiedAlarmRecord {
    pub record: AlarmRecord,
    pub status: AlarmVerifyStatus,
}

/// Append-only handle to the alarm log file. Cheap to clone if needed
/// (each `append` opens, writes, and closes the file so concurrent
/// writes from independent handles interleave safely under the kernel's
/// `O_APPEND` semantics).
#[derive(Debug, Clone)]
pub struct AlarmLog {
    path: PathBuf,
    /// HMAC signing key. `None` means unsigned mode.
    signing_key: Option<Vec<u8>>,
}

impl AlarmLog {
    /// Build an unsigned-mode handle. Records written through this
    /// handle have no `hmac` field; readers that hold a key see them
    /// as [`AlarmVerifyStatus::Unsigned`].
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("audit-alarms.log"),
            signing_key: None,
        }
    }

    /// Build a signed-mode handle. Every appended record carries an
    /// HMAC-SHA256 tag computed under `key`.
    pub fn with_signing_key(data_dir: &Path, key: Vec<u8>) -> Self {
        Self {
            path: data_dir.join("audit-alarms.log"),
            signing_key: Some(key),
        }
    }

    /// Path the alarm log is configured to write to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `true` when this handle will sign appended records.
    pub fn is_signed(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Append one alarm record. Creates the file with mode 0o600 on
    /// first write; subsequent writes use `O_APPEND` so concurrent
    /// callers don't clobber each other's records.
    pub fn append(&self, record: &AlarmRecord) -> Result<(), AuditError> {
        use std::io::Write;
        let mut record = record.clone();
        record.hmac = None;
        if let Some(ref key) = self.signing_key {
            let canonical = serde_json::to_vec(&record).map_err(|e| {
                AuditError::SiemConfig(format!("serialize alarm record for HMAC: {e}"))
            })?;
            record.hmac = Some(compute_hmac_hex(key, &canonical));
        }
        let mut line = serde_json::to_vec(&record)
            .map_err(|e| AuditError::SiemConfig(format!("serialize alarm record: {e}")))?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuditError::SiemConfig(format!("create alarm-log parent {}: {e}", parent.display()))
            })?;
        }

        let mut f = open_append_owner_only(&self.path)?;
        f.write_all(&line)
            .map_err(|e| AuditError::SiemConfig(format!("write alarm: {e}")))?;
        f.flush()
            .map_err(|e| AuditError::SiemConfig(format!("flush alarm: {e}")))?;
        Ok(())
    }

    /// Read every record currently in the alarm log. Used by
    /// `wirken doctor` to surface alarms that accumulated between
    /// gateway runs. Returns an empty vector when the file does not
    /// exist (no alarms is the common case).
    ///
    /// Records are returned with a per-record verification verdict
    /// based on whichever signing key this handle holds. A handle
    /// constructed via [`AlarmLog::new`] always returns
    /// [`AlarmVerifyStatus::Unsigned`] for unsigned records and
    /// [`AlarmVerifyStatus::NoKey`] for signed records.
    pub fn read_all(&self) -> Result<Vec<VerifiedAlarmRecord>, AuditError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let body = std::fs::read_to_string(&self.path).map_err(|e| {
            AuditError::SiemConfig(format!("read alarm log {}: {e}", self.path.display()))
        })?;
        let mut out = Vec::new();
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AlarmRecord>(line) {
                Ok(r) => {
                    let status = self.verify_record(&r);
                    out.push(VerifiedAlarmRecord { record: r, status });
                }
                Err(e) => {
                    tracing::warn!("malformed alarm record skipped: {e}");
                }
            }
        }
        Ok(out)
    }

    /// Scan the alarm log for records whose `alarm_type` is not on
    /// the proceed allowlist [`ACKNOWLEDGE_PROCEED_TYPES`]. Returns
    /// `Ok(None)` when the log is missing, empty, or contains only
    /// proceed-class records; `Ok(Some(report))` when blocking
    /// records are present.
    ///
    /// Called from the gateway's startup path before opening the
    /// audit writer for writes. Tamper records that survived a
    /// prior session's halt must be acknowledged by an operator
    /// (via `wirken audit acknowledge --all`) before the gateway
    /// will start writing to the same chain again.
    pub fn unacknowledged_blocks(&self) -> Result<Option<UnacknowledgedBlocksReport>, AuditError> {
        let records = self.read_all()?;
        let mut blocking_by_type: BTreeMap<String, usize> = BTreeMap::new();
        for r in &records {
            if !ACKNOWLEDGE_PROCEED_TYPES.contains(&r.record.alarm_type.as_str()) {
                *blocking_by_type
                    .entry(r.record.alarm_type.clone())
                    .or_insert(0) += 1;
            }
        }
        if blocking_by_type.is_empty() {
            return Ok(None);
        }
        let total = blocking_by_type.values().sum();
        Ok(Some(UnacknowledgedBlocksReport {
            path: self.path.clone(),
            blocking_by_type,
            total,
        }))
    }

    /// Rename the alarm log to `audit-alarms.log.<rfc3339>` so the
    /// next `wirken run` starts with an empty alarm-log surface
    /// while the tamper history is preserved on disk for forensic
    /// review. Returns the new path, or `None` when the log did
    /// not exist (acknowledgement is a no-op against a fresh
    /// install).
    ///
    /// RFC 3339 colons are illegal in Windows filenames, so the
    /// archive timestamp uses hyphens in their place; the encoded
    /// form is unambiguous (RFC 3339 has no other use of `:`).
    pub fn acknowledge_all(&self) -> Result<Option<PathBuf>, AuditError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let ts = chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .replace(':', "-");
        let filename = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "audit-alarms.log".to_string());
        let archive = self.path.with_file_name(format!("{filename}.{ts}"));
        std::fs::rename(&self.path, &archive).map_err(|e| {
            AuditError::SiemConfig(format!(
                "rename {} to {}: {e}",
                self.path.display(),
                archive.display()
            ))
        })?;
        Ok(Some(archive))
    }

    fn verify_record(&self, record: &AlarmRecord) -> AlarmVerifyStatus {
        match (&self.signing_key, &record.hmac) {
            (Some(key), Some(claimed_hex)) => {
                let mut canonical_record = record.clone();
                canonical_record.hmac = None;
                let canonical = match serde_json::to_vec(&canonical_record) {
                    Ok(b) => b,
                    Err(_) => return AlarmVerifyStatus::Tampered,
                };
                let expected = compute_hmac_hex(key, &canonical);
                if constant_time_eq(expected.as_bytes(), claimed_hex.as_bytes()) {
                    AlarmVerifyStatus::Verified
                } else {
                    AlarmVerifyStatus::Tampered
                }
            }
            (None, Some(_)) => AlarmVerifyStatus::NoKey,
            (_, None) => AlarmVerifyStatus::Unsigned,
        }
    }
}

/// Keyed digest of a search query, for an audit row that must not
/// carry the query itself.
///
/// Over the query bytes exactly as issued. No trimming, no case
/// folding, no normalization of any kind: two queries that differ by a
/// byte are two queries, and folding them together would make the
/// trail claim a repetition that did not happen. The cost is that a
/// caller who retypes a query with different spacing produces a
/// different digest, which is the honest answer.
///
/// Keyed rather than a plain hash because an agent under injection can
/// echo archive content into a query, which makes the query a content
/// path out of the corpus and into every SIEM the forwarder feeds. The
/// space of plausible queries is small enough to enumerate, so an
/// unkeyed digest would be recoverable by anyone holding the rows. A
/// keyed one is not, and still compares equal for the same query,
/// which is what preserves repetition and correlation for an auditor.
pub fn imported_search_digest(key: &[u8], query: &str) -> String {
    compute_hmac_hex(key, query.as_bytes())
}

fn compute_hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(unix)]
fn open_append_owner_only(path: &Path) -> Result<std::fs::File, AuditError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AuditError::SiemConfig(format!("open alarm log {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn open_append_owner_only(path: &Path) -> Result<std::fs::File, AuditError> {
    tracing::warn!(
        "creating alarm log at {} without 0o600-equivalent file permissions; \
         relying on user profile isolation for confidentiality",
        path.display()
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| AuditError::SiemConfig(format!("open alarm log {}: {e}", path.display())))
}

/// Best-effort hostname lookup. Tries `HOSTNAME` env, then
/// `/etc/hostname`, then returns `"unknown"`. Does not block on
/// network DNS or NSS.
pub fn hostname_best_effort() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    #[cfg(unix)]
    {
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = h.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "unknown".to_string()
}

/// RFC 3339 UTC timestamp at second precision.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture(tmp: &TempDir, alarm_type: &str) -> AlarmRecord {
        let _ = tmp;
        AlarmRecord {
            timestamp: now_rfc3339(),
            alarm_type: alarm_type.to_string(),
            session_id: Some("sess".into()),
            seq: Some(7),
            expected_hash: Some("a".into()),
            actual_hash: Some("b".into()),
            hostname: hostname_best_effort(),
            gateway_pid: std::process::id(),
            hmac: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_file_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got 0o{mode:o}");
    }

    #[test]
    fn unsigned_append_then_read_round_trips() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        let r1 = fixture(&tmp, "chain_broken");
        let r2 = fixture(&tmp, "attestation_broken");
        log.append(&r1).unwrap();
        log.append(&r2).unwrap();
        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].record.alarm_type, "chain_broken");
        assert_eq!(read_back[0].status, AlarmVerifyStatus::Unsigned);
        assert_eq!(read_back[1].record.alarm_type, "attestation_broken");
    }

    #[test]
    fn read_all_returns_empty_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        assert!(log.read_all().unwrap().is_empty());
    }

    #[test]
    fn malformed_line_is_skipped_not_erroring() {
        use std::io::Write as _;
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        // Append a non-JSON line directly.
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        log.append(&fixture(&tmp, "after_garbage")).unwrap();
        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 2, "malformed line skipped, others kept");
    }

    #[test]
    fn signed_round_trip_verifies() {
        let tmp = TempDir::new().unwrap();
        let key = vec![0xa5u8; 32];
        let log = AlarmLog::with_signing_key(tmp.path(), key.clone());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, AlarmVerifyStatus::Verified);
        assert!(read_back[0].record.hmac.is_some());
    }

    #[test]
    fn signed_record_with_no_key_at_read_returns_no_key() {
        let tmp = TempDir::new().unwrap();
        let key = vec![0xa5u8; 32];
        let writer = AlarmLog::with_signing_key(tmp.path(), key);
        writer.append(&fixture(&tmp, "chain_broken")).unwrap();

        let reader = AlarmLog::new(tmp.path());
        let read_back = reader.read_all().unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, AlarmVerifyStatus::NoKey);
    }

    #[test]
    fn tampered_hmac_field_detected() {
        // Mutate the HMAC field of an on-disk record. Verifier must
        // surface Tampered.
        let tmp = TempDir::new().unwrap();
        let key = vec![0xa5u8; 32];
        let log = AlarmLog::with_signing_key(tmp.path(), key.clone());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();

        let body = std::fs::read_to_string(log.path()).unwrap();
        // Flip the last hex digit of the hmac field. Find a quote-d hex
        // tag we wrote and replace it with a same-length tag of zeros.
        let bad = body.replace(
            &body[body.find("\"hmac\":\"").unwrap()..body.find("\"}").unwrap()],
            "\"hmac\":\"00000000000000000000000000000000000000000000000000000000000000aa",
        );
        std::fs::write(log.path(), bad).unwrap();

        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, AlarmVerifyStatus::Tampered);
    }

    #[test]
    fn tampered_payload_detected() {
        // Same key on the writer and reader, but mutate a non-hmac
        // field in the on-disk record. The hmac no longer matches the
        // canonical bytes; verifier must surface Tampered.
        let tmp = TempDir::new().unwrap();
        let key = vec![0xa5u8; 32];
        let log = AlarmLog::with_signing_key(tmp.path(), key);
        log.append(&fixture(&tmp, "chain_broken")).unwrap();

        let body = std::fs::read_to_string(log.path()).unwrap();
        let bad = body.replace("chain_broken", "chain_intact");
        std::fs::write(log.path(), bad).unwrap();

        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, AlarmVerifyStatus::Tampered);
    }

    #[test]
    fn unacknowledged_blocks_returns_none_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        assert_eq!(log.unacknowledged_blocks().unwrap(), None);
    }

    #[test]
    fn unacknowledged_blocks_returns_none_when_file_empty() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        std::fs::write(log.path(), b"").unwrap();
        assert_eq!(log.unacknowledged_blocks().unwrap(), None);
    }

    #[test]
    fn chain_broken_record_blocks_boot() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        let report = log
            .unacknowledged_blocks()
            .unwrap()
            .expect("chain_broken must block");
        assert_eq!(report.total, 1);
        assert_eq!(report.blocking_by_type.get("chain_broken"), Some(&1));
    }

    #[test]
    fn signature_invalid_record_blocks_boot() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "signature_invalid")).unwrap();
        let report = log
            .unacknowledged_blocks()
            .unwrap()
            .expect("signature_invalid must block");
        assert_eq!(report.total, 1);
    }

    #[test]
    fn verify_error_record_alone_does_not_block() {
        // Pre-#115 upgrade-compat: a `verify_error` record from an
        // older gateway is the one explicit proceed-class type.
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "verify_error")).unwrap();
        assert_eq!(log.unacknowledged_blocks().unwrap(), None);
    }

    #[test]
    fn unknown_alarm_type_blocks_by_default() {
        // Refuse-by-default: an alarm_type the current binary does
        // not recognise must block. Catches future record types
        // that get added without an explicit proceed-class
        // classification.
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "some_future_alarm_type"))
            .unwrap();
        let report = log
            .unacknowledged_blocks()
            .unwrap()
            .expect("unknown alarm_type must block by default");
        assert_eq!(
            report.blocking_by_type.get("some_future_alarm_type"),
            Some(&1)
        );
    }

    #[test]
    fn mixed_records_block_when_any_non_allowlisted_present() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "verify_error")).unwrap();
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        log.append(&fixture(&tmp, "verify_error")).unwrap();
        let report = log
            .unacknowledged_blocks()
            .unwrap()
            .expect("mixed with chain_broken must block");
        assert_eq!(report.total, 1);
        assert_eq!(report.blocking_by_type.get("chain_broken"), Some(&1));
        // verify_error entries are proceed-class so they are not
        // counted in `blocking_by_type`.
        assert!(!report.blocking_by_type.contains_key("verify_error"));
    }

    #[test]
    fn acknowledge_all_renames_file_to_timestamped_archive() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        assert!(log.path().exists());
        let archive = log
            .acknowledge_all()
            .unwrap()
            .expect("rename must produce an archive path");
        assert!(!log.path().exists(), "original log must be moved");
        assert!(archive.exists(), "archive must exist");
        let archive_name = archive.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            archive_name.starts_with("audit-alarms.log."),
            "archive name {archive_name:?} must extend the original"
        );
        // Timestamp segment encodes RFC 3339 with `:` replaced by
        // `-` (illegal on Windows). Verify the colon substitution.
        assert!(
            !archive_name.contains(':'),
            "archive name {archive_name:?} must not contain colons"
        );
    }

    #[test]
    fn acknowledge_unblocks_subsequent_boot_check() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        log.append(&fixture(&tmp, "chain_broken")).unwrap();
        assert!(log.unacknowledged_blocks().unwrap().is_some());
        log.acknowledge_all().unwrap();
        // After acknowledgement the original log path no longer
        // exists; the next boot check sees a clean slate.
        assert_eq!(log.unacknowledged_blocks().unwrap(), None);
    }

    #[test]
    fn acknowledge_on_missing_file_is_a_no_op() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        assert_eq!(log.acknowledge_all().unwrap(), None);
    }

    #[test]
    fn wrong_key_at_read_reports_tampered() {
        let tmp = TempDir::new().unwrap();
        let writer = AlarmLog::with_signing_key(tmp.path(), vec![0xa5u8; 32]);
        writer.append(&fixture(&tmp, "chain_broken")).unwrap();

        let reader = AlarmLog::with_signing_key(tmp.path(), vec![0x00u8; 32]);
        let read_back = reader.read_all().unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, AlarmVerifyStatus::Tampered);
    }
}

#[cfg(test)]
mod imported_search_digest_tests {
    use super::*;

    #[test]
    fn the_digest_is_over_the_query_exactly_as_issued() {
        let key = [7u8; 32];
        // Anything that would fold two distinct queries together is a
        // claim of repetition that did not happen.
        let variants = [" term", "term ", "Term", "term", "te rm"];
        let digests: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|q| imported_search_digest(&key, q))
            .collect();
        assert_eq!(
            digests.len(),
            variants.len(),
            "distinct queries must produce distinct digests"
        );
    }

    #[test]
    fn the_same_query_digests_the_same_and_a_different_key_does_not() {
        let query = "borogove";
        assert_eq!(
            imported_search_digest(&[1u8; 32], query),
            imported_search_digest(&[1u8; 32], query),
            "repetition is what the digest preserves"
        );
        assert_ne!(
            imported_search_digest(&[1u8; 32], query),
            imported_search_digest(&[2u8; 32], query),
            "the key is what makes it unrecoverable"
        );
    }

    #[test]
    fn the_query_does_not_appear_in_its_digest() {
        let digest = imported_search_digest(&[3u8; 32], "a distinctive secret phrase");
        assert!(!digest.contains("secret"));
        assert!(!digest.contains("phrase"));
        assert_eq!(digest.len(), 64, "hex of a sha256 tag");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn an_empty_query_still_digests() {
        // The tool emits an event for every attempt, including ones
        // that carried nothing, so this must not panic or be special.
        assert_eq!(imported_search_digest(&[0u8; 32], "").len(), 64);
    }
}
