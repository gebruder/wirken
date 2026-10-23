//! Step records for Lyrik walks.
//!
//! A walk's text is a sequence of numbered steps. Under `wirken lyrik
//! run` each step ends by writing one record under
//! `staging/<walk>/steps/step-NN.json`, and the next step starts by
//! reading that file. The record, not the model's memory of the step,
//! is what the later step works from. The runner validates the files,
//! refuses the ones that do not hold, and carries the accepted ones in
//! `findings.json` under `step_records`, outside schema 1.1.
//!
//! The chain is checked mechanically: the first record names no
//! `prior`, and every later record's `prior` is the file name of the
//! record before it. A record whose `code_revision` is not the revision
//! the run scanned is refused, so a step cannot quietly report on a
//! tree the run did not look at.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One step's record, as the walk wrote it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRecord {
    /// The step's name in the walk text, such as `target_selection`.
    pub step: String,
    /// One falsifiable sentence the step established.
    pub claim: String,
    /// The target revision the step read, as the dispatch prompt gave
    /// it.
    pub code_revision: String,
    /// The check the step ran: the command, or the read and the range.
    pub check: String,
    /// Raw evidence the check produced: quoted lines with `file:line`,
    /// or command output. Never a paraphrase.
    pub evidence: Vec<String>,
    /// What the step could not settle. Empty when nothing is open.
    pub open_questions: Vec<String>,
    /// The file name of the record the step read before starting.
    /// Absent on the first record only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<String>,
}

/// An accepted record with where it came from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AcceptedStep {
    /// The walk that wrote it. Absent in single-call mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walk: Option<String>,
    /// The staged file name, `step-NN.json`.
    pub file: String,
    #[serde(flatten)]
    pub record: StepRecord,
}

/// A refused file and why.
#[derive(Debug, Clone, PartialEq)]
pub struct RefusedStep {
    pub file: String,
    pub reason: String,
}

/// Read the step records in `dir`, in file-name order. Returns the
/// accepted records and the refused files. A missing directory is an
/// empty result. `expected_revision` is the run's target revision;
/// `None` when the target's git state could not be read, in which case
/// any non-blank `code_revision` is accepted.
pub fn read_walk_steps(
    dir: &Path,
    walk: Option<&str>,
    expected_revision: Option<&str>,
) -> Result<(Vec<AcceptedStep>, Vec<RefusedStep>)> {
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    if !dir.is_dir() {
        return Ok((accepted, refused));
    }
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.ends_with(".json"))
        .collect();
    files.sort();
    let mut previous: Option<String> = None;
    for file in files {
        let path = dir.join(&file);
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        match parse_record(&body, previous.as_deref(), expected_revision) {
            Ok(record) => accepted.push(AcceptedStep {
                walk: walk.map(str::to_string),
                file: file.clone(),
                record,
            }),
            Err(reason) => refused.push(RefusedStep {
                file: file.clone(),
                reason,
            }),
        }
        previous = Some(file);
    }
    Ok((accepted, refused))
}

/// Parse one record and check it against the file before it and the
/// run's revision. The error is the one-line reason the runner records.
fn parse_record(
    body: &str,
    previous_file: Option<&str>,
    expected_revision: Option<&str>,
) -> std::result::Result<StepRecord, String> {
    let record: StepRecord =
        serde_json::from_str(body).map_err(|e| format!("does not parse: {e}"))?;
    for (name, value) in [
        ("step", &record.step),
        ("claim", &record.claim),
        ("code_revision", &record.code_revision),
        ("check", &record.check),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} is blank"));
        }
    }
    if record.evidence.iter().all(|e| e.trim().is_empty()) {
        return Err("evidence is empty".to_string());
    }
    if let Some(expected) = expected_revision
        && record.code_revision != expected
    {
        return Err(format!(
            "code_revision {} is not the scanned revision {expected}",
            record.code_revision
        ));
    }
    match (previous_file, record.prior.as_deref()) {
        (None, None) => {}
        (None, Some(p)) => return Err(format!("first record names a prior, {p}")),
        (Some(prev), None) => return Err(format!("prior is missing; expected {prev}")),
        (Some(prev), Some(p)) if p != prev => {
            return Err(format!("prior {p} is not the record before it, {prev}"));
        }
        (Some(_), Some(_)) => {}
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn record(step: &str, prior: Option<&str>) -> String {
        let prior = match prior {
            Some(p) => format!(r#","prior":"{p}""#),
            None => String::new(),
        };
        format!(
            r#"{{"step":"{step}","claim":"the parser bounds the length","code_revision":"abc123","check":"read_file src/parse.rs:10-40","evidence":["src/parse.rs:12: let n = min(len, MAX);"],"open_questions":[]{prior}}}"#
        )
    }

    #[test]
    fn a_missing_directory_is_an_empty_result() {
        let tmp = tempdir().unwrap();
        let (ok, bad) =
            read_walk_steps(&tmp.path().join("steps"), Some("sink-walk"), None).unwrap();
        assert!(ok.is_empty() && bad.is_empty());
    }

    #[test]
    fn a_chained_pair_is_accepted_in_file_order() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("step-02.json"),
            record("second", Some("step-01.json")),
        )
        .unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), Some("sink-walk"), Some("abc123")).unwrap();
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].file, "step-01.json");
        assert_eq!(ok[0].record.step, "first");
        assert_eq!(ok[1].record.prior.as_deref(), Some("step-01.json"));
        assert_eq!(ok[1].walk.as_deref(), Some("sink-walk"));
    }

    #[test]
    fn the_accepted_record_serializes_flat_with_its_walk_and_file() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (ok, _) = read_walk_steps(tmp.path(), Some("sink-walk"), None).unwrap();
        let v = serde_json::to_value(&ok[0]).unwrap();
        assert_eq!(v["walk"], "sink-walk");
        assert_eq!(v["file"], "step-01.json");
        assert_eq!(v["claim"], "the parser bounds the length");
        assert!(v.get("prior").is_none(), "{v}");
    }

    #[test]
    fn a_broken_chain_is_refused_with_the_expected_file_named() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        std::fs::write(tmp.path().join("step-02.json"), record("second", None)).unwrap();
        std::fs::write(
            tmp.path().join("step-03.json"),
            record("third", Some("step-01.json")),
        )
        .unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0].file, "step-02.json");
        assert!(
            bad[0].reason.contains("expected step-01.json"),
            "{}",
            bad[0].reason
        );
        assert!(bad[1].reason.contains("step-02.json"), "{}", bad[1].reason);
    }

    #[test]
    fn a_prior_on_the_first_record_is_refused() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("step-01.json"),
            record("first", Some("step-00.json")),
        )
        .unwrap();
        let (_, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert!(
            bad[0].reason.starts_with("first record names a prior"),
            "{}",
            bad[0].reason
        );
    }

    #[test]
    fn the_wrong_revision_is_refused_and_an_unknown_run_revision_accepts_any() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (_, bad) = read_walk_steps(tmp.path(), None, Some("def456")).unwrap();
        assert!(
            bad[0].reason.contains("not the scanned revision def456"),
            "{}",
            bad[0].reason
        );
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert_eq!((ok.len(), bad.len()), (1, 0));
    }

    #[test]
    fn blank_fields_empty_evidence_and_bad_json_are_refused() {
        let tmp = tempdir().unwrap();
        let blank = record("first", None).replace(
            r#""claim":"the parser bounds the length""#,
            r#""claim":"  ""#,
        );
        std::fs::write(tmp.path().join("step-01.json"), blank).unwrap();
        let empty = record("second", Some("step-01.json"))
            .replace(r#"["src/parse.rs:12: let n = min(len, MAX);"]"#, r#"[""]"#);
        std::fs::write(tmp.path().join("step-02.json"), empty).unwrap();
        std::fs::write(tmp.path().join("step-03.json"), "{not json").unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert!(ok.is_empty());
        let reasons: Vec<&str> = bad.iter().map(|b| b.reason.as_str()).collect();
        assert_eq!(reasons[0], "claim is blank");
        assert_eq!(reasons[1], "evidence is empty");
        assert!(reasons[2].starts_with("does not parse"), "{}", reasons[2]);
    }
}
