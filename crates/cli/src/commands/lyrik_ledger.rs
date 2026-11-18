//! The ledger: what earlier runs established about a target.
//!
//! One record per claim, kept under the target's `.lyrik/ledger/` as
//! one JSON file per record. A record says what was claimed, where,
//! at which revision, against which content of the file, whether the
//! claim was observed by an executed run or only reasoned, and which
//! run produced it. Nothing in a record names a model, a provider, a
//! walk or a harness: it is a statement about the target.
//!
//! The runner reads the ledger before a run's walks start and writes
//! it after the run's findings are final. A walk is handed the records
//! for the files it can read. A record with evidence `observed` is
//! settled while its file is unchanged: a staged finding that makes
//! the same claim again is refused with a pointer to the record. A
//! record with evidence `reasoned` is context a walk may re-examine.
//! A record whose file no longer has the content it was established
//! against is `stale`: it is kept, it is marked, and it blocks nothing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// How a claim was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// A command was run and its result is on record.
    Observed,
    /// Read from the source; nothing was run.
    Reasoned,
}

/// What kind of claim a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The defect is there.
    Finding,
    /// A proposed defect was examined and set aside.
    Rejection,
    /// A check of a patch against the defect gave a result.
    ArmResult,
}

/// One established claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Stable for a `(kind, key)` pair; also the file name.
    pub id: String,
    pub kind: Kind,
    /// `<class>::<file>:<line>`, the key a finding is known by.
    pub key: String,
    /// The claim in words.
    pub claim: String,
    /// The file the claim is about, relative to the target's root.
    pub file: String,
    /// The 1-based line the claim surfaces at.
    pub line: u64,
    /// The revision the claim was established at, when the target is
    /// a git checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// SHA-256 of the file's content when the claim was established.
    /// Absent when the file could not be read then; such a record is
    /// never treated as settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    pub evidence: Evidence,
    /// The run that produced the record.
    pub run: String,
    /// Set when the file's content is no longer the content the claim
    /// was established against.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

impl Record {
    /// Whether the record stands in the way of the same claim being
    /// checked again: observed, and against the file as it is now.
    pub fn settled(&self) -> bool {
        self.evidence == Evidence::Observed && !self.stale && self.file_sha256.is_some()
    }
}

/// `<target>/.lyrik/ledger`.
pub fn ledger_dir(target: &Path) -> PathBuf {
    target.join(".lyrik").join("ledger")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file under the target, or `None` when it cannot be
/// read or is not inside the target.
pub fn file_sha256(target: &Path, rel: &str) -> Option<String> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    let bytes = std::fs::read(target.join(rel_path)).ok()?;
    Some(hex(&Sha256::digest(&bytes)))
}

/// The id of the record for `(kind, key)`: 16 hex characters.
pub fn record_id(kind: Kind, key: &str) -> String {
    let tag = match kind {
        Kind::Finding => "finding",
        Kind::Rejection => "rejection",
        Kind::ArmResult => "arm_result",
    };
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0]);
    h.update(key.as_bytes());
    hex(&h.finalize()[..8])
}

/// Read every record, marking as stale each one whose file no longer
/// has the content it was established against. A mark that changed is
/// written back, so the ledger on disk says what the next reader will
/// see. A file that is not a record is skipped.
pub fn load(target: &Path) -> Result<Vec<Record>> {
    let dir = ledger_dir(target);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut record) = serde_json::from_str::<Record>(&text) else {
            continue;
        };
        let stale = match &record.file_sha256 {
            Some(was) => file_sha256(target, &record.file).as_ref() != Some(was),
            None => false,
        };
        if stale != record.stale {
            record.stale = stale;
            write_record(&dir, &record)?;
        }
        out.push(record);
    }
    Ok(out)
}

fn write_record(dir: &Path, record: &Record) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", record.id));
    let tmp = dir.join(format!("{}.json.tmp", record.id));
    std::fs::write(&tmp, serde_json::to_string_pretty(record)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("write {}", path.display()))
}

/// Write `records` into the ledger. A record replaces the one with
/// its id, except that a reasoned record never replaces a settled
/// one: what a run observed is not overwritten by what a later run
/// only read. Returns how many records were written.
pub fn upsert(target: &Path, records: &[Record]) -> Result<usize> {
    let existing = load(target)?;
    let dir = ledger_dir(target);
    let mut written = 0;
    for record in records {
        let held = existing.iter().find(|e| e.id == record.id);
        if let Some(held) = held
            && held.settled()
            && record.evidence == Evidence::Reasoned
        {
            continue;
        }
        if held == Some(record) {
            continue;
        }
        write_record(&dir, record)?;
        written += 1;
    }
    Ok(written)
}

/// `(key, file, line)` of a finding-shaped object: its `stable_id`
/// when it has one, else the key built from its first `framing` and
/// its `location`.
pub fn claim_key(finding: &Value) -> Option<(String, String, u64)> {
    let location = finding.get("location")?;
    let file = location.get("file")?.as_str()?.to_string();
    let line = location.get("line_start")?.as_u64()?;
    let key = match finding.get("stable_id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            let class = finding.get("framing")?.as_array()?.first()?.as_str()?;
            format!("{class}::{file}:{line}")
        }
    };
    Some((key, file, line))
}

/// The records a finished run establishes, from its `findings.json`
/// body and its rejection records.
///
/// - A kept finding is a `finding` record: `observed` when a
///   reproduction of it ran and its replay agreed, else `reasoned`.
/// - A rejection is a `rejection` record: `observed` when the replay
///   rule (8) made it, since a command was run and showed otherwise,
///   else `reasoned`.
/// - Each arm of a fix record that passed or failed on an executed run
///   is an `arm_result` record, `observed`. An arm that did not run or
///   was inconclusive establishes nothing and writes none.
pub fn records_from_run(
    target: &Path,
    body: &Value,
    rejections: &[Value],
    run_id: &str,
) -> Vec<Record> {
    let commit = body
        .get("target_sha")
        .and_then(Value::as_str)
        .map(str::to_string);
    let empty = Vec::new();
    let reproductions = body
        .get("reproductions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let observed = |key: &str| {
        reproductions.iter().any(|r| {
            r.get("stable_id").and_then(Value::as_str) == Some(key)
                && r.get("outcome").and_then(Value::as_str) == Some("reproduced")
                && r.get("agreement").and_then(Value::as_bool) == Some(true)
        })
    };
    let record =
        |kind: Kind, key: String, claim: String, file: String, line: u64, ev: Evidence| Record {
            id: record_id(kind, &key),
            kind,
            file_sha256: file_sha256(target, &file),
            key,
            claim,
            file,
            line,
            commit: commit.clone(),
            evidence: ev,
            run: run_id.to_string(),
            stale: false,
        };
    let mut out: Vec<Record> = Vec::new();
    let findings = body
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for f in findings {
        let Some((key, file, line)) = claim_key(f) else {
            continue;
        };
        let claim = f
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ev = if observed(&key) {
            Evidence::Observed
        } else {
            Evidence::Reasoned
        };
        out.push(record(Kind::Finding, key, claim, file, line, ev));
    }
    for r in rejections {
        let Some((key, file, line)) = claim_key(r) else {
            continue;
        };
        let title = r.get("title").and_then(Value::as_str).unwrap_or_default();
        let reason = r.get("reason").and_then(Value::as_str).unwrap_or_default();
        let ev = if r.get("rule").and_then(Value::as_u64) == Some(8) {
            Evidence::Observed
        } else {
            Evidence::Reasoned
        };
        out.push(record(
            Kind::Rejection,
            key,
            format!("set aside: {title}: {reason}"),
            file,
            line,
            ev,
        ));
    }
    let fixes = body
        .get("fixes")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for fix in fixes {
        let Some(stable_id) = fix.get("stable_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(finding) = findings
            .iter()
            .find(|f| f.get("stable_id").and_then(Value::as_str) == Some(stable_id))
        else {
            continue;
        };
        let Some((_, file, line)) = claim_key(finding) else {
            continue;
        };
        let arms = fix.get("arms").and_then(Value::as_array).unwrap_or(&empty);
        for arm in arms {
            let (Some(name), Some(state)) = (
                arm.get("arm").and_then(Value::as_str),
                arm.get("state").and_then(Value::as_str),
            ) else {
                continue;
            };
            let executed = arm.get("basis").and_then(Value::as_str) == Some("executed");
            if !executed || !matches!(state, "pass" | "fail") {
                continue;
            }
            let verb = if state == "pass" { "passed" } else { "failed" };
            out.push(record(
                Kind::ArmResult,
                format!("{stable_id}#{name}"),
                format!("a patch for this finding {verb} the {name} check"),
                file.clone(),
                line,
                Evidence::Observed,
            ));
        }
    }
    // One record per id: the first stands.
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert(r.id.clone()));
    out
}

/// What a walk is handed: the records that are not stale, split by
/// whether they are settled, and how many were left out as stale.
pub fn for_walk(records: &[Record]) -> Value {
    let settled: Vec<&Record> = records.iter().filter(|r| r.settled()).collect();
    let context: Vec<&Record> = records
        .iter()
        .filter(|r| !r.stale && !r.settled())
        .collect();
    serde_json::json!({
        "settled": settled,
        "context": context,
        "stale_left_out": records.iter().filter(|r| r.stale).count(),
    })
}

/// A staged finding the runner refused because the ledger already
/// holds the same claim, observed, against the file as it is now.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Refused {
    pub walk: String,
    /// The staged file's name.
    pub file: String,
    pub key: String,
    /// The ledger record that settles it.
    pub record: String,
    /// The run that record came from.
    pub established_by_run: String,
}

/// Move each staged finding of `walk` that repeats a settled record
/// out of `findings/` into `ledger-refused/` beside it, so it is not
/// aggregated, and return what was refused. A finding record or an
/// observed rejection settles a claim; an arm result is about a patch
/// and settles no claim about the code.
pub fn refuse_duplicates(walk_dir: &Path, walk: &str, records: &[Record]) -> Result<Vec<Refused>> {
    let findings = walk_dir.join("findings");
    if !findings.is_dir() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&findings)
        .with_context(|| format!("read {}", findings.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some((key, _, _)) = claim_key(&parsed) else {
            continue;
        };
        let Some(held) = records
            .iter()
            .find(|r| r.settled() && r.kind != Kind::ArmResult && r.key == key)
        else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let dest_dir = walk_dir.join("ledger-refused");
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("create {}", dest_dir.display()))?;
        std::fs::rename(&path, dest_dir.join(&name))
            .with_context(|| format!("move {}", path.display()))?;
        out.push(Refused {
            walk: walk.to_string(),
            file: name,
            key,
            record: held.id.clone(),
            established_by_run: held.run.clone(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn target_with(file: &str, content: &str) -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        tmp
    }

    fn run_body() -> Value {
        json!({
            "target_sha": "abc123",
            "findings": [
                {"stable_id": "auth::src/a.rs:10", "title": "no check before the write",
                 "framing": ["auth"], "location": {"file": "src/a.rs", "line_start": 10}},
                {"stable_id": "injection::src/a.rs:20", "title": "argument reaches a shell",
                 "framing": ["injection"], "location": {"file": "src/a.rs", "line_start": 20}}
            ],
            "reproductions": [
                {"stable_id": "auth::src/a.rs:10", "outcome": "reproduced", "agreement": true}
            ],
            "fixes": [
                {"stable_id": "auth::src/a.rs:10", "arms": [
                    {"arm": "original", "state": "pass", "basis": "executed"},
                    {"arm": "variant", "state": "inconclusive"},
                    {"arm": "relocation", "state": "not_run"}
                ]}
            ]
        })
    }

    fn rejections() -> Vec<Value> {
        vec![
            json!({"stable_id": "auth::src/a.rs:30", "title": "open handler", "reason": "the caller already holds the key",
                   "rule": 2, "location": {"file": "src/a.rs", "line_start": 30}}),
            json!({"stable_id": "auth::src/a.rs:40", "title": "missing bound", "reason": "the replay did not show it",
                   "rule": 8, "location": {"file": "src/a.rs", "line_start": 40}}),
        ]
    }

    /// A run's findings, rejections and arm results each become one
    /// record, with the evidence state the run earned.
    #[test]
    fn a_run_populates_the_ledger_from_findings_rejections_and_arm_results() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        let by_key = |k: &str| records.iter().find(|r| r.key == k).unwrap();
        assert_eq!(records.len(), 5);
        // Reproduced and replayed: observed. Read only: reasoned.
        assert_eq!(by_key("auth::src/a.rs:10").evidence, Evidence::Observed);
        assert_eq!(by_key("auth::src/a.rs:10").kind, Kind::Finding);
        assert_eq!(
            by_key("injection::src/a.rs:20").evidence,
            Evidence::Reasoned
        );
        // A judgment rejection is reasoned; a replay rejection is observed.
        assert_eq!(by_key("auth::src/a.rs:30").evidence, Evidence::Reasoned);
        assert_eq!(by_key("auth::src/a.rs:40").evidence, Evidence::Observed);
        assert_eq!(by_key("auth::src/a.rs:40").kind, Kind::Rejection);
        // Only the arm that ran and gave a result.
        let arm = by_key("auth::src/a.rs:10#original");
        assert_eq!(arm.kind, Kind::ArmResult);
        assert_eq!(arm.evidence, Evidence::Observed);
        assert!(!records.iter().any(|r| r.key.ends_with("#variant")));
        for r in &records {
            assert_eq!(r.commit.as_deref(), Some("abc123"));
            assert_eq!(r.run, "r1");
            assert_eq!(r.file, "src/a.rs");
            assert_eq!(r.file_sha256, file_sha256(tmp.path(), "src/a.rs"));
            assert_eq!(r.id, record_id(r.kind, &r.key));
        }
        assert_eq!(upsert(tmp.path(), &records).unwrap(), 5);
        assert_eq!(load(tmp.path()).unwrap().len(), 5);
        // Writing the same records again changes nothing.
        assert_eq!(upsert(tmp.path(), &records).unwrap(), 0);
    }

    /// A record is plain data about the target: its fields are the
    /// claim, where, at which revision and file content, the evidence
    /// state and the run. No field names a model, a provider, a walk
    /// or a harness.
    #[test]
    fn a_record_carries_no_model_or_harness_field() {
        let tmp = target_with("src/a.rs", "x\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        for r in &records {
            let v = serde_json::to_value(r).unwrap();
            let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            for k in &keys {
                assert!(
                    [
                        "id",
                        "kind",
                        "key",
                        "claim",
                        "file",
                        "line",
                        "commit",
                        "file_sha256",
                        "evidence",
                        "run",
                        "stale"
                    ]
                    .contains(k),
                    "{k}"
                );
            }
            let text = v.to_string().to_lowercase();
            for word in ["model", "provider", "harness", "walk", "prompt", "token"] {
                assert!(!text.contains(word), "{word} in {text}");
            }
        }
        // An unknown field is not a record.
        let extra = r#"{"id":"x","kind":"finding","key":"k","claim":"c","file":"f","line":1,
                        "evidence":"observed","run":"r","model":"m"}"#;
        assert!(serde_json::from_str::<Record>(extra).is_err());
    }

    fn stage(walk_dir: &Path, name: &str, finding: &Value) {
        let dir = walk_dir.join("findings");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), finding.to_string()).unwrap();
    }

    /// A staged finding that repeats a claim the ledger holds as
    /// observed is refused, with a pointer to the record and the run
    /// it came from. One that repeats a reasoned record is kept.
    #[test]
    fn a_check_that_duplicates_an_observed_record_is_refused_with_a_pointer() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        let ledger = load(tmp.path()).unwrap();

        let walk_dir = tmp.path().join("staging/sink-walk");
        stage(
            &walk_dir,
            "finding-001.json",
            &json!({"stable_id": "auth::src/a.rs:10", "framing": ["auth"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 10}}),
        );
        stage(
            &walk_dir,
            "finding-002.json",
            &json!({"stable_id": "injection::src/a.rs:20", "framing": ["injection"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 20}}),
        );
        stage(
            &walk_dir,
            "finding-003.json",
            &json!({"framing": ["auth"], "title": "the replay-rejected one, no stable_id",
                    "location": {"file": "src/a.rs", "line_start": 40}}),
        );
        stage(
            &walk_dir,
            "finding-004.json",
            &json!({"stable_id": "auth::src/a.rs:99", "framing": ["auth"], "title": "new",
                    "location": {"file": "src/a.rs", "line_start": 99}}),
        );

        let refused = refuse_duplicates(&walk_dir, "sink-walk", &ledger).unwrap();
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert_eq!(refused[0].file, "finding-001.json");
        assert_eq!(refused[0].key, "auth::src/a.rs:10");
        assert_eq!(
            refused[0].record,
            record_id(Kind::Finding, "auth::src/a.rs:10")
        );
        assert_eq!(refused[0].established_by_run, "r1");
        // The observed rejection settles its claim too.
        assert_eq!(refused[1].file, "finding-003.json");
        assert_eq!(
            refused[1].record,
            record_id(Kind::Rejection, "auth::src/a.rs:40")
        );
        // The refused files left findings/; the reasoned and the new one stayed.
        let left: Vec<String> = std::fs::read_dir(walk_dir.join("findings"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left.len(), 2);
        assert!(left.contains(&"finding-002.json".to_string()));
        assert!(left.contains(&"finding-004.json".to_string()));
        assert!(walk_dir.join("ledger-refused/finding-001.json").is_file());

        // What a walk is handed says which is which.
        let handed = for_walk(&ledger);
        let settled: Vec<&str> = handed["settled"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["key"].as_str().unwrap())
            .collect();
        assert!(settled.contains(&"auth::src/a.rs:10"));
        assert!(!settled.contains(&"injection::src/a.rs:20"));
        let context: Vec<&str> = handed["context"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["key"].as_str().unwrap())
            .collect();
        assert!(context.contains(&"injection::src/a.rs:20"));
    }

    /// When the file changes, every record established against the old
    /// content is marked stale on disk and stops blocking.
    #[test]
    fn a_record_whose_file_changed_is_stale_and_blocks_nothing() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        assert!(load(tmp.path()).unwrap().iter().all(|r| !r.stale));

        std::fs::write(tmp.path().join("src/a.rs"), "fn a() { check(); }\n").unwrap();
        let ledger = load(tmp.path()).unwrap();
        assert!(ledger.iter().all(|r| r.stale));
        assert!(ledger.iter().all(|r| !r.settled()));
        // The mark is on disk.
        let id = record_id(Kind::Finding, "auth::src/a.rs:10");
        let on_disk: Record = serde_json::from_str(
            &std::fs::read_to_string(ledger_dir(tmp.path()).join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert!(on_disk.stale);

        let walk_dir = tmp.path().join("staging/sink-walk");
        stage(
            &walk_dir,
            "finding-001.json",
            &json!({"stable_id": "auth::src/a.rs:10", "framing": ["auth"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 10}}),
        );
        assert!(
            refuse_duplicates(&walk_dir, "sink-walk", &ledger)
                .unwrap()
                .is_empty()
        );
        let handed = for_walk(&ledger);
        assert_eq!(handed["stale_left_out"], 5);
        assert!(handed["settled"].as_array().unwrap().is_empty());

        // The file put back: the records stand again.
        std::fs::write(tmp.path().join("src/a.rs"), "fn a() {}\n").unwrap();
        assert!(load(tmp.path()).unwrap().iter().all(|r| !r.stale));
    }

    /// What was observed is not overwritten by a later run that only
    /// read the code; a later observation replaces a reasoned record.
    #[test]
    fn a_reasoned_record_does_not_replace_an_observed_one() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let first = records_from_run(tmp.path(), &run_body(), &[], "r1");
        upsert(tmp.path(), &first).unwrap();
        let mut later = run_body();
        later["reproductions"] = json!([
            {"stable_id": "injection::src/a.rs:20", "outcome": "reproduced", "agreement": true}
        ]);
        later["fixes"] = json!([]);
        let second = records_from_run(tmp.path(), &later, &[], "r2");
        upsert(tmp.path(), &second).unwrap();
        let ledger = load(tmp.path()).unwrap();
        let by_key = |k: &str| ledger.iter().find(|r| r.key == k).unwrap();
        // r2 only read this one: r1's observation stands.
        assert_eq!(by_key("auth::src/a.rs:10").run, "r1");
        assert_eq!(by_key("auth::src/a.rs:10").evidence, Evidence::Observed);
        // r2 observed this one: it replaces r1's reasoned record.
        assert_eq!(by_key("injection::src/a.rs:20").run, "r2");
        assert_eq!(
            by_key("injection::src/a.rs:20").evidence,
            Evidence::Observed
        );
    }

    #[test]
    fn a_path_that_leaves_the_target_has_no_hash() {
        let tmp = target_with("src/a.rs", "x");
        assert!(file_sha256(tmp.path(), "src/a.rs").is_some());
        assert!(file_sha256(tmp.path(), "../outside").is_none());
        assert!(file_sha256(tmp.path(), "/etc/hostname").is_none());
        assert!(file_sha256(tmp.path(), "src/missing.rs").is_none());
    }
}
