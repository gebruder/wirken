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
}
