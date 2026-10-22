//! Brocard rejection record for Lyrik candidates.
//!
//! A candidate that fails one of the seven brocard rules is recorded
//! in `findings.json` under `rejected_candidates`, never silently
//! dropped. Each record names the rule, a one-line reason, and the
//! gate or walk that applied it. SARIF carries the same records as
//! results with a `suppressions` entry whose kind is `external` and
//! whose justification is the reason.
//!
//! The rule text is written here in the repo's own words. The
//! source list is linked from the walk wrapper and the docs, not
//! copied.
//!
//! The record is also the calibration corpus's negative-label form:
//! one row per rejection, `label` is always negative. No corpus
//! consumer exists yet.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Brocard rule numbers, in the order the walks apply them.
pub const RULE_COUNT: u8 = 7;

/// Short name and one-line statement for each rule, indexed by
/// `rule - 1`. Rule 1 runs first.
pub const RULES: [(&str, &str); RULE_COUNT as usize] = [
    (
        "No threat model",
        "A finding states an attacker capability and a harm path.",
    ),
    (
        "Precondition at least as strong as impact",
        "An attacker precondition that already grants the impact is not an exploit.",
    ),
    (
        "No vulnerability outside usage",
        "A sink reached only through callers that bound the input is not a finding.",
    ),
    (
        "No vulnerability from standard behavior",
        "Behavior the relevant specification permits is not a finding.",
    ),
    (
        "No vulnerability from documented behavior",
        "Behavior the project documents as intended is not a finding unless downstream usage ignores the documentation.",
    ),
    (
        "No cure worse than the disease",
        "Remediation cost that exceeds the impact lowers severity.",
    ),
    (
        "The report is neither necessary nor sufficient",
        "A scanner seed records provenance and earns no credit for existing.",
    ),
];

/// Name of the SARIF rule for brocard `rule`.
pub fn sarif_rule_id(rule: u8) -> String {
    format!("lyrik.brocard.{rule}")
}

/// Where the rejected candidate points, copied from its location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectionLocation {
    pub file: String,
    pub line_start: u32,
}

/// One candidate that a brocard rule rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rejection {
    /// Brocard rule number, `1..=RULE_COUNT`.
    pub rule: u8,
    /// Walk that emitted the candidate. Absent for Semgrep-only seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<RejectionLocation>,
    /// One line, why the rule applies.
    pub reason: String,
    /// The gate or walk that applied the rule, e.g. `brocard_structural`
    /// or `walk:doc-walk`.
    pub applied_by: String,
}

/// One judgment rejection a walk wrote under `staging/<walk>/rejections/`.
#[derive(Debug, Deserialize)]
struct WalkRejection {
    rule: u8,
    #[serde(default)]
    stable_id: Option<String>,
    reason: String,
}

/// Read the walk-side rejections in `dir`, in file-name order. Returns
/// the accepted records and the file names that did not parse or named
/// a rule outside `1..=RULE_COUNT`. The caller records the refusals.
/// A missing directory is an empty result.
pub fn read_walk_rejections(
    dir: &Path,
    walk: Option<&str>,
) -> Result<(Vec<Rejection>, Vec<String>)> {
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    if !dir.is_dir() {
        return Ok((accepted, refused));
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    for p in &paths {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let body = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        match serde_json::from_str::<WalkRejection>(&body) {
            Ok(w) if (1..=RULE_COUNT).contains(&w.rule) => accepted.push(Rejection {
                rule: w.rule,
                walk: walk.map(str::to_string),
                stable_id: w.stable_id,
                title: None,
                location: None,
                reason: w.reason,
                applied_by: match walk {
                    Some(w) => format!("walk:{w}"),
                    None => "single_call".to_string(),
                },
            }),
            _ => refused.push(name),
        }
    }
    Ok((accepted, refused))
}

/// Copy title and location from the finding a rejection names, when the
/// finding is in the run. A rejection with no matching finding keeps
/// the fields it has.
pub fn fill_from_finding(rejection: &mut Rejection, finding: &Value) {
    let Some(id) = rejection.stable_id.as_deref() else {
        return;
    };
    if finding.get("stable_id").and_then(Value::as_str) != Some(id) {
        return;
    }
    let from = record(finding, None, rejection.rule, String::new());
    rejection.title = from.title;
    rejection.location = from.location;
}

/// What a rejection does to the candidate it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Rejections halve the grade, once per distinct applied rule. The
    /// finding stays.
    Pentest,
    /// Rejections remove the finding. The record stays.
    Defender,
}

/// Read `mode` from `.lyrik/config.json`. Absent means pentest. Any
/// other value is an error: an unreadable mode must not default to a
/// mode the operator did not choose.
pub fn parse_mode(config: &Value) -> Result<Mode> {
    match config.get("mode") {
        None => Ok(Mode::Pentest),
        Some(v) => match v.as_str() {
            Some("pentest") => Ok(Mode::Pentest),
            Some("defender") => Ok(Mode::Defender),
            _ => bail!("mode must be \"pentest\" or \"defender\", got {v}"),
        },
    }
}

/// Every brocard rule that applies to one candidate: the structural
/// rules, plus any walk-side rejection that names its stable_id. Marks
/// each walk-side rejection that matched, so the caller can record the
/// rest on their own.
pub fn applied_for(
    finding: &Value,
    walk: Option<&str>,
    walk_side: &[Rejection],
    matched: &mut [bool],
) -> Vec<Rejection> {
    let mut out = check_structural(finding, walk);
    let id = finding.get("stable_id").and_then(Value::as_str);
    if id.is_some() {
        for (i, r) in walk_side.iter().enumerate() {
            if r.stable_id.as_deref() == id {
                matched[i] = true;
                out.push(r.clone());
            }
        }
    }
    for r in &mut out {
        fill_from_finding(r, finding);
    }
    out
}

/// Calibration corpus form: one JSON object per line, each a rejection
/// with `label` set to `negative`. Written beside `findings.json`. No
/// reader in this repo consumes it yet.
pub fn calibration_jsonl(rejected: &[Rejection]) -> Result<String> {
    let mut out = String::new();
    for r in rejected {
        let mut row = serde_json::to_value(r)?;
        row["label"] = Value::String("negative".to_string());
        out.push_str(&serde_json::to_string(&row)?);
        out.push('\n');
    }
    Ok(out)
}

/// Number of distinct rules in `applied`. Two rejections under the same
/// rule halve the grade once.
pub fn distinct_rules(applied: &[Rejection]) -> usize {
    applied
        .iter()
        .map(|r| r.rule)
        .collect::<BTreeSet<_>>()
        .len()
}

/// Pentest demotion: halve the grade `rules` times, so each distinct
/// applied rule halves it once. Returns the original and new grade, or
/// `None` when the finding carries no numeric grade. Only lowers.
pub fn demote_grade(finding: &mut Value, rules: usize) -> Option<(f64, f64)> {
    let obj = finding.as_object_mut()?;
    let original = obj.get("grade")?.as_f64()?;
    let halvings = i32::try_from(rules).ok()?;
    let new = original * 0.5_f64.powi(halvings);
    obj.insert("grade".to_string(), serde_json::json!(new));
    Some((original, new))
}

/// Structural brocard checks on one staged candidate, run before the
/// citation gate. Rule 1 runs first. Rules 2 through 6 are judgment
/// and live in walk text, so they never appear here.
///
/// Rule 7 has no rejection path. Nothing in the gate grants a seed
/// credit, so a seed can change no decision. The invariant test below
/// holds that: `detection_source` is never read here.
///
/// Returns one record per applied rule. The caller stamps nothing:
/// every field comes from the candidate or from `walk`.
pub fn check_structural(finding: &Value, walk: Option<&str>) -> Vec<Rejection> {
    let mut out = Vec::new();
    if let Some(reason) = missing_threat_model(finding) {
        out.push(record(finding, walk, 1, reason));
    }
    out
}

/// The reason rule 1 applies, or `None` when both threat-model strings
/// are present and non-blank.
fn missing_threat_model(finding: &Value) -> Option<String> {
    let model = finding.get("threat_model").and_then(Value::as_object);
    let filled = |key: &str| {
        model
            .and_then(|m| m.get(key))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    };
    let missing: Vec<&str> = ["attacker_capability", "harm_path"]
        .into_iter()
        .filter(|k| !filled(k))
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(format!("threat_model lacks {}", missing.join(" and ")))
    }
}

fn record(finding: &Value, walk: Option<&str>, rule: u8, reason: String) -> Rejection {
    let location = finding.get("location").and_then(|loc| {
        Some(RejectionLocation {
            file: loc.get("file")?.as_str()?.to_string(),
            line_start: u32::try_from(loc.get("line_start")?.as_u64()?).ok()?,
        })
    });
    Rejection {
        rule,
        walk: walk.map(str::to_string),
        stable_id: finding
            .get("stable_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: finding
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string),
        location,
        reason,
        applied_by: "brocard_structural".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(threat_model: Value) -> Value {
        json!({
            "id": "f1",
            "stable_id": "sid-1",
            "title": "t",
            "location": { "file": "src/a.rs", "line_start": 4 },
            "threat_model": threat_model,
        })
    }

    #[test]
    fn complete_threat_model_passes_rule_1() {
        let f = candidate(json!({
            "attacker_capability": "unauthenticated network peer",
            "harm_path": "reads another user's session",
        }));
        assert!(check_structural(&f, Some("sink-walk")).is_empty());
    }

    #[test]
    fn absent_threat_model_is_rule_1() {
        let f = json!({ "stable_id": "sid-1", "location": { "file": "a", "line_start": 1 } });
        let out = check_structural(&f, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, 1);
        assert_eq!(
            out[0].reason,
            "threat_model lacks attacker_capability and harm_path"
        );
        assert_eq!(out[0].applied_by, "brocard_structural");
        assert!(out[0].walk.is_none());
    }

    #[test]
    fn blank_harm_path_is_rule_1() {
        let f = candidate(json!({
            "attacker_capability": "local user",
            "harm_path": "   ",
        }));
        let out = check_structural(&f, Some("chain-walk"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].reason, "threat_model lacks harm_path");
        assert_eq!(out[0].walk.as_deref(), Some("chain-walk"));
        assert_eq!(out[0].stable_id.as_deref(), Some("sid-1"));
        assert_eq!(
            out[0].location,
            Some(RejectionLocation {
                file: "src/a.rs".to_string(),
                line_start: 4,
            })
        );
    }

    #[test]
    fn non_string_capability_is_rule_1() {
        let f = candidate(json!({
            "attacker_capability": 3,
            "harm_path": "x",
        }));
        let out = check_structural(&f, None);
        assert_eq!(out[0].reason, "threat_model lacks attacker_capability");
    }

    #[test]
    fn seed_provenance_changes_no_decision() {
        let mut seeded = candidate(json!({}));
        seeded["detection_source"] = json!("static_prescreen");
        let mut unseeded = candidate(json!({}));
        unseeded["detection_source"] = json!("model_reasoning");
        let mut bare = candidate(json!({}));
        bare.as_object_mut().unwrap().remove("detection_source");
        assert_eq!(
            check_structural(&seeded, None),
            check_structural(&unseeded, None)
        );
        assert_eq!(
            check_structural(&seeded, None),
            check_structural(&bare, None)
        );
    }

    #[test]
    fn rule_table_covers_every_number() {
        assert_eq!(RULES.len(), RULE_COUNT as usize);
        assert_eq!(RULES[0].0, "No threat model");
        assert_eq!(RULES[6].0, "The report is neither necessary nor sufficient");
    }

    #[test]
    fn sarif_rule_id_is_numbered() {
        assert_eq!(sarif_rule_id(3), "lyrik.brocard.3");
    }

    #[test]
    fn absent_optionals_are_omitted_on_write() {
        let r = Rejection {
            rule: 1,
            walk: None,
            stable_id: None,
            title: None,
            location: None,
            reason: "no attacker capability stated".to_string(),
            applied_by: "brocard_structural".to_string(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({
                "rule": 1,
                "reason": "no attacker capability stated",
                "applied_by": "brocard_structural",
            })
        );
    }

    #[test]
    fn full_record_round_trips() {
        let body = json!({
            "rule": 5,
            "walk": "doc-walk",
            "stable_id": "sid-1",
            "title": "t",
            "location": { "file": "src/a.rs", "line_start": 7 },
            "reason": "documented as intended",
            "applied_by": "walk:doc-walk",
        });
        let r: Rejection = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), body);
    }

    #[test]
    fn report_with_rejections_still_validates_at_schema_1_1() {
        let report = json!({
            "schema_version": "1.1",
            "run_id": "r",
            "produced_at": "2026-05-03T00:00:00Z",
            "findings": [],
            "rejected_candidates": [{
                "rule": 2,
                "reason": "attacker already holds the impact",
                "applied_by": "walk:invariant-walk",
            }],
        });
        assert!(super::super::lyrik_validate::validate_value(&report).is_empty());
    }

    #[test]
    fn walk_rejections_read_in_order_and_refuse_bad_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rej = dir.path().join("rejections");
        std::fs::create_dir_all(&rej).unwrap();
        std::fs::write(
            rej.join("rejection-001.json"),
            r#"{"rule":5,"stable_id":"sid-1","reason":"documented as intended"}"#,
        )
        .unwrap();
        std::fs::write(
            rej.join("rejection-002.json"),
            r#"{"rule":9,"reason":"no such rule"}"#,
        )
        .unwrap();
        std::fs::write(rej.join("rejection-003.json"), "not json").unwrap();
        let (accepted, refused) = read_walk_rejections(&rej, Some("doc-walk")).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].rule, 5);
        assert_eq!(accepted[0].walk.as_deref(), Some("doc-walk"));
        assert_eq!(accepted[0].applied_by, "walk:doc-walk");
        assert_eq!(accepted[0].stable_id.as_deref(), Some("sid-1"));
        assert_eq!(refused, vec!["rejection-002.json", "rejection-003.json"]);
    }

    #[test]
    fn single_call_rejections_carry_no_walk_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rejection-001.json"),
            r#"{"rule":2,"reason":"precondition grants impact"}"#,
        )
        .unwrap();
        let (accepted, _) = read_walk_rejections(dir.path(), None).unwrap();
        assert!(accepted[0].walk.is_none());
        assert_eq!(accepted[0].applied_by, "single_call");
    }

    #[test]
    fn missing_rejections_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (accepted, refused) =
            read_walk_rejections(&dir.path().join("absent"), Some("sink-walk")).unwrap();
        assert!(accepted.is_empty() && refused.is_empty());
    }

    #[test]
    fn fill_from_finding_copies_title_and_location_on_matching_id_only() {
        let finding = candidate(json!({}));
        let mut hit = Rejection {
            rule: 3,
            walk: Some("graph-walk".to_string()),
            stable_id: Some("sid-1".to_string()),
            title: None,
            location: None,
            reason: "x".to_string(),
            applied_by: "walk:graph-walk".to_string(),
        };
        fill_from_finding(&mut hit, &finding);
        assert_eq!(hit.title.as_deref(), Some("t"));
        assert_eq!(hit.location.as_ref().map(|l| l.line_start), Some(4));

        let mut miss = hit.clone();
        miss.title = None;
        miss.location = None;
        miss.stable_id = Some("sid-2".to_string());
        fill_from_finding(&mut miss, &finding);
        assert!(miss.title.is_none() && miss.location.is_none());
    }

    #[test]
    fn mode_defaults_to_pentest_and_rejects_unknown_values() {
        assert_eq!(parse_mode(&json!({})).unwrap(), Mode::Pentest);
        assert_eq!(
            parse_mode(&json!({ "mode": "pentest" })).unwrap(),
            Mode::Pentest
        );
        assert_eq!(
            parse_mode(&json!({ "mode": "defender" })).unwrap(),
            Mode::Defender
        );
        assert!(parse_mode(&json!({ "mode": "Defender" })).is_err());
        assert!(parse_mode(&json!({ "mode": 1 })).is_err());
    }

    #[test]
    fn demotion_halves_once_per_distinct_rule() {
        let mut f = json!({ "grade": 0.5 });
        assert_eq!(demote_grade(&mut f, 1), Some((0.5, 0.25)));
        let mut g = json!({ "grade": 0.5 });
        assert_eq!(demote_grade(&mut g, 2), Some((0.5, 0.125)));
        assert_eq!(g["grade"], json!(0.125));
    }

    #[test]
    fn demotion_never_reaches_zero_from_a_positive_grade() {
        let mut f = json!({ "grade": 0.5 });
        let (_, new) = demote_grade(&mut f, 7).unwrap();
        assert!(new > 0.0);
    }

    #[test]
    fn demotion_skips_a_finding_without_a_grade() {
        let mut f = json!({ "stable_id": "sid-1" });
        assert_eq!(demote_grade(&mut f, 1), None);
        assert!(f.get("grade").is_none());
    }

    #[test]
    fn calibration_rows_are_negative_labels_one_per_line() {
        let rejected = vec![Rejection {
            rule: 4,
            walk: Some("crypto-walk".to_string()),
            stable_id: Some("sid-1".to_string()),
            title: None,
            location: None,
            reason: "spec permits it".to_string(),
            applied_by: "walk:crypto-walk".to_string(),
        }];
        let out = calibration_jsonl(&rejected).unwrap();
        assert!(out.ends_with('\n'));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        let row: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(row["label"], "negative");
        assert_eq!(row["rule"], 4);
        assert_eq!(calibration_jsonl(&[]).unwrap(), "");
    }

    #[test]
    fn distinct_rules_counts_each_rule_once() {
        let r = |rule| Rejection {
            rule,
            walk: None,
            stable_id: None,
            title: None,
            location: None,
            reason: String::new(),
            applied_by: String::new(),
        };
        assert_eq!(distinct_rules(&[r(1), r(1), r(5)]), 2);
        assert_eq!(distinct_rules(&[]), 0);
    }

    #[test]
    fn applied_for_joins_structural_and_matching_walk_rejections() {
        let finding = candidate(json!({}));
        let walk_side = vec![
            Rejection {
                rule: 5,
                walk: Some("doc-walk".to_string()),
                stable_id: Some("sid-1".to_string()),
                title: None,
                location: None,
                reason: "documented".to_string(),
                applied_by: "walk:doc-walk".to_string(),
            },
            Rejection {
                rule: 3,
                walk: Some("doc-walk".to_string()),
                stable_id: Some("sid-other".to_string()),
                title: None,
                location: None,
                reason: "elsewhere".to_string(),
                applied_by: "walk:doc-walk".to_string(),
            },
        ];
        let mut matched = vec![false; walk_side.len()];
        let applied = applied_for(&finding, Some("doc-walk"), &walk_side, &mut matched);
        assert_eq!(matched, vec![true, false]);
        let rules: Vec<u8> = applied.iter().map(|r| r.rule).collect();
        assert_eq!(rules, vec![1, 5]);
        assert_eq!(applied[1].title.as_deref(), Some("t"));
    }
}
