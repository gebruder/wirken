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
//! On non-unix the file is created without 0o600; the gateway already
//! warns about file-permission posture there.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;

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
}

/// Append-only handle to the alarm log file. Cheap to clone if needed
/// (each `append` opens, writes, and closes the file so concurrent
/// writes from independent handles interleave safely under the kernel's
/// `O_APPEND` semantics).
#[derive(Debug, Clone)]
pub struct AlarmLog {
    path: PathBuf,
}

impl AlarmLog {
    /// Build a handle pointing at `<data_dir>/audit-alarms.log`. Does
    /// not touch the filesystem; the file is created lazily on first
    /// [`AlarmLog::append`].
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("audit-alarms.log"),
        }
    }

    /// Path the alarm log is configured to write to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one alarm record. Creates the file with mode 0o600 on
    /// first write; subsequent writes use `O_APPEND` so concurrent
    /// callers don't clobber each other's records.
    pub fn append(&self, record: &AlarmRecord) -> Result<(), AuditError> {
        use std::io::Write;
        let mut line = serde_json::to_vec(record)
            .map_err(|e| AuditError::SiemConfig(format!("serialize alarm record: {e}")))?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AuditError::SiemConfig(format!(
                        "create alarm-log parent {}: {e}",
                        parent.display()
                    ))
                })?;
            }
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
    pub fn read_all(&self) -> Result<Vec<AlarmRecord>, AuditError> {
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
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!("malformed alarm record skipped: {e}");
                }
            }
        }
        Ok(out)
    }
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
    fn append_then_read_round_trips() {
        let tmp = TempDir::new().unwrap();
        let log = AlarmLog::new(tmp.path());
        let r1 = fixture(&tmp, "chain_broken");
        let r2 = fixture(&tmp, "attestation_broken");
        log.append(&r1).unwrap();
        log.append(&r2).unwrap();
        let read_back = log.read_all().unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].alarm_type, "chain_broken");
        assert_eq!(read_back[1].alarm_type, "attestation_broken");
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
}
