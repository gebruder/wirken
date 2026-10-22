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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
