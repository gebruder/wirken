//! `wirken lyrik validate <path>`: conformance check for
//! `findings.json` files against the 1.1 spec at
//! `docs/lyrik-json-schema.md`. The grammar and the required-field
//! list live in the spec; this module is the reference enforcement.
//!
//! The validator embeds the canonical JSON Schema as a static string
//! so callers can validate offline. The `$id` URL in the schema is
//! used as identity only; the validator never fetches it.
//!
//! Schema 1.1 changes from 1.0: `detection_source` promoted from
//! the allowed-extras band to a closed enum enforced when present.
//! `schema_version` strictly equals `"1.1"`. Pre-1.1 archives
//! continue to be readable by a pre-1.1 binary (tag-pinned).

use std::path::Path;

use anyhow::{Context, Result};

/// Canonical `$id` of the lyrik 1.1 schema. Reports that carry a
/// `$schema` field (current producer does not, future ones may)
/// must string-equal this value.
pub const SCHEMA_ID: &str =
    "https://raw.githubusercontent.com/gebruder/wirken/schema-v1.1/docs/lyrik-json-schema.json";

const ALLOWED_FRAMINGS: &[&str] = &["auth", "injection"];
const ALLOWED_TIERS: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const ALLOWED_DETECTION_SOURCES: &[&str] = &["static_prescreen", "model_reasoning", "both"];

/// One conformance error, scoped to a JSON pointer-like path so a
/// user can find the offending value in their report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// CLI entry point. Reads `path`, validates, prints errors (if
/// any), exits the process non-zero on failure. Separated from the
/// pure `validate_value` helper so the validation logic stays
/// testable without process exit.
pub fn run(path: &Path) -> Result<()> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("parse {} as JSON", path.display()))?;

    let errors = validate_value(&value);
    if errors.is_empty() {
        println!("{}: conforms to lyrik schema 1.1", path.display());
        return Ok(());
    }
    eprintln!(
        "{}: {} conformance error(s) against lyrik schema 1.1",
        path.display(),
        errors.len()
    );
    for e in &errors {
        eprintln!("  {e}");
    }
    std::process::exit(1);
}

/// Validate a parsed JSON value against the lyrik 1.1 spec. Returns
/// the full list of errors so callers can report them all rather
/// than stopping at the first. Empty vec means conformance.
pub fn validate_value(root: &serde_json::Value) -> Vec<ValidationError> {
    let mut errs = Vec::new();

    let obj = match root.as_object() {
        Some(o) => o,
        None => {
            errs.push(ValidationError {
                path: "/".into(),
                message: "top-level value must be a JSON object".into(),
            });
            return errs;
        }
    };

    // Optional $schema must string-equal the canonical $id when present.
    if let Some(v) = obj.get("$schema") {
        match v.as_str() {
            Some(s) if s == SCHEMA_ID => {}
            Some(s) => errs.push(ValidationError {
                path: "/$schema".into(),
                message: format!("must equal {SCHEMA_ID:?}, got {s:?}"),
            }),
            None => errs.push(ValidationError {
                path: "/$schema".into(),
                message: "must be a string when present".into(),
            }),
        }
    }

    // Required top-level fields.
    match obj.get("schema_version").and_then(|v| v.as_str()) {
        Some("1.1") => {}
        Some(other) => errs.push(ValidationError {
            path: "/schema_version".into(),
            message: format!("must be \"1.1\", got {other:?}"),
        }),
        None => errs.push(ValidationError {
            path: "/schema_version".into(),
            message: "missing required string field".into(),
        }),
    }
    match obj.get("run_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {}
        Some(_) => errs.push(ValidationError {
            path: "/run_id".into(),
            message: "must be a non-empty string".into(),
        }),
        None => errs.push(ValidationError {
            path: "/run_id".into(),
            message: "missing required string field".into(),
        }),
    }
    match obj.get("produced_at").and_then(|v| v.as_str()) {
        Some(s) => {
            if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                errs.push(ValidationError {
                    path: "/produced_at".into(),
                    message: format!("must be an RFC 3339 timestamp, got {s:?}"),
                });
            }
        }
        None => errs.push(ValidationError {
            path: "/produced_at".into(),
            message: "missing required string field".into(),
        }),
    }

    match obj.get("findings") {
        Some(serde_json::Value::Array(arr)) => {
            for (i, finding) in arr.iter().enumerate() {
                validate_finding(finding, i, &mut errs);
            }
        }
        Some(_) => errs.push(ValidationError {
            path: "/findings".into(),
            message: "must be an array".into(),
        }),
        None => errs.push(ValidationError {
            path: "/findings".into(),
            message: "missing required array field".into(),
        }),
    }

    errs
}

fn validate_finding(value: &serde_json::Value, index: usize, errs: &mut Vec<ValidationError>) {
    let prefix = format!("/findings/{index}");
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            errs.push(ValidationError {
                path: prefix,
                message: "must be a JSON object".into(),
            });
            return;
        }
    };

    require_nonempty_string(obj, &prefix, "id", errs);
    require_nonempty_string(obj, &prefix, "title", errs);
    require_nonempty_string(obj, &prefix, "summary", errs);

    // framing: non-empty array of strings, each in the closed enum.
    match obj.get("framing") {
        Some(serde_json::Value::Array(arr)) if !arr.is_empty() => {
            for (i, entry) in arr.iter().enumerate() {
                match entry.as_str() {
                    Some(s) if ALLOWED_FRAMINGS.contains(&s) => {}
                    Some(s) => errs.push(ValidationError {
                        path: format!("{prefix}/framing/{i}"),
                        message: format!("must be one of {ALLOWED_FRAMINGS:?}, got {s:?}"),
                    }),
                    None => errs.push(ValidationError {
                        path: format!("{prefix}/framing/{i}"),
                        message: "must be a string".into(),
                    }),
                }
            }
        }
        Some(serde_json::Value::Array(_)) => errs.push(ValidationError {
            path: format!("{prefix}/framing"),
            message: "must contain at least one framing string".into(),
        }),
        Some(_) => errs.push(ValidationError {
            path: format!("{prefix}/framing"),
            message: "must be an array".into(),
        }),
        None => errs.push(ValidationError {
            path: format!("{prefix}/framing"),
            message: "missing required array field".into(),
        }),
    }

    // tier: closed enum.
    match obj.get("tier").and_then(|v| v.as_str()) {
        Some(s) if ALLOWED_TIERS.contains(&s) => {}
        Some(s) => errs.push(ValidationError {
            path: format!("{prefix}/tier"),
            message: format!("must be one of {ALLOWED_TIERS:?}, got {s:?}"),
        }),
        None => errs.push(ValidationError {
            path: format!("{prefix}/tier"),
            message: "missing required string field".into(),
        }),
    }

    // location: object with file (string) and line_start (>=1 integer).
    match obj.get("location") {
        Some(serde_json::Value::Object(loc)) => {
            require_nonempty_string(loc, &format!("{prefix}/location"), "file", errs);
            match loc.get("line_start") {
                Some(v) => match v.as_u64() {
                    Some(n) if n >= 1 => {}
                    Some(_) => errs.push(ValidationError {
                        path: format!("{prefix}/location/line_start"),
                        message: "must be >= 1".into(),
                    }),
                    None => errs.push(ValidationError {
                        path: format!("{prefix}/location/line_start"),
                        message: "must be a positive integer".into(),
                    }),
                },
                None => errs.push(ValidationError {
                    path: format!("{prefix}/location/line_start"),
                    message: "missing required integer field".into(),
                }),
            }
        }
        Some(_) => errs.push(ValidationError {
            path: format!("{prefix}/location"),
            message: "must be a JSON object".into(),
        }),
        None => errs.push(ValidationError {
            path: format!("{prefix}/location"),
            message: "missing required object field".into(),
        }),
    }

    // stable_id grammar: <framing>::<rel_file>:<line>.
    match obj.get("stable_id").and_then(|v| v.as_str()) {
        Some(s) => {
            if let Err(reason) = parse_stable_id(s) {
                errs.push(ValidationError {
                    path: format!("{prefix}/stable_id"),
                    message: reason,
                });
            }
        }
        None => errs.push(ValidationError {
            path: format!("{prefix}/stable_id"),
            message: "missing required string field".into(),
        }),
    }

    // detection_source: optional in 1.1; when present must be one
    // of the closed enum (static_prescreen, model_reasoning, both).
    // Absence is not an error — a producer that does not run the
    // scanner pass emits findings without the field.
    if let Some(v) = obj.get("detection_source") {
        match v.as_str() {
            Some(s) if ALLOWED_DETECTION_SOURCES.contains(&s) => {}
            Some(s) => errs.push(ValidationError {
                path: format!("{prefix}/detection_source"),
                message: format!(
                    "must be one of {ALLOWED_DETECTION_SOURCES:?} when present, got {s:?}"
                ),
            }),
            None => errs.push(ValidationError {
                path: format!("{prefix}/detection_source"),
                message: "must be a string when present".into(),
            }),
        }
    }
}

fn require_nonempty_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    field: &str,
    errs: &mut Vec<ValidationError>,
) {
    match obj.get(field).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {}
        Some(_) => errs.push(ValidationError {
            path: format!("{prefix}/{field}"),
            message: "must be a non-empty string".into(),
        }),
        None => errs.push(ValidationError {
            path: format!("{prefix}/{field}"),
            message: "missing required string field".into(),
        }),
    }
}

/// Parsed view of a stable_id; emitted by [`parse_stable_id`] on
/// success so future call sites can read components without re-
/// parsing. Today only the format check is used.
#[derive(Debug, PartialEq, Eq)]
pub struct StableId<'a> {
    pub framing: &'a str,
    pub rel_file: &'a str,
    pub line: u64,
}

/// Apply the spec's grammar: `<framing>::<rel_file>:<line>` with a
/// right-to-left parse for the line separator (admits colons in
/// `rel_file` without an escape character), closed-enum framing,
/// decimal-integer line, workspace-relative path (no leading `/`).
pub fn parse_stable_id(s: &str) -> Result<StableId<'_>, String> {
    let sep = "::";
    let sep_idx = s
        .find(sep)
        .ok_or_else(|| format!("missing \"::\" separator between framing and path: {s:?}"))?;
    let framing = &s[..sep_idx];
    let rest = &s[sep_idx + sep.len()..];

    if framing.is_empty() {
        return Err(format!("framing segment is empty: {s:?}"));
    }
    if !ALLOWED_FRAMINGS.contains(&framing) {
        return Err(format!(
            "framing {framing:?} not in {ALLOWED_FRAMINGS:?}: {s:?}"
        ));
    }

    // Right-to-left: the final `:` separates `line` from `rel_file`.
    let last_colon = rest
        .rfind(':')
        .ok_or_else(|| format!("missing line separator after path: {s:?}"))?;
    let rel_file = &rest[..last_colon];
    let line_str = &rest[last_colon + 1..];

    if rel_file.is_empty() {
        return Err(format!("rel_file segment is empty: {s:?}"));
    }
    if rel_file.starts_with('/') {
        return Err(format!(
            "rel_file must be workspace-relative, got absolute path: {s:?}"
        ));
    }
    if line_str.is_empty() {
        return Err(format!("line segment is empty: {s:?}"));
    }
    let line: u64 = line_str
        .parse()
        .map_err(|_| format!("line is not a decimal integer: {line_str:?} in {s:?}"))?;

    Ok(StableId {
        framing,
        rel_file,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good_finding() -> serde_json::Value {
        json!({
            "id": "F001",
            "stable_id": "auth::src/foo.rs:42",
            "framing": ["auth"],
            "location": { "file": "src/foo.rs", "line_start": 42 },
            "title": "stub",
            "summary": "stub",
            "tier": "HIGH",
        })
    }

    fn good_report() -> serde_json::Value {
        json!({
            "schema_version": "1.1",
            "run_id": "run-001",
            "produced_at": "2026-05-17T00:00:00Z",
            "findings": [ good_finding() ],
        })
    }

    #[test]
    fn known_good_report_validates() {
        let errs = validate_value(&good_report());
        assert!(errs.is_empty(), "expected clean, got {errs:?}");
    }

    #[test]
    fn empty_findings_array_is_valid() {
        let mut r = good_report();
        r["findings"] = json!([]);
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn extra_fields_are_ignored() {
        let mut r = good_report();
        r["funnel"] = json!({ "anything": 1 });
        r["findings"][0]["scoring_passes"] = json!([{ "real_bug": "yes" }]);
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn dollar_schema_must_match_canonical_id_when_present() {
        let mut r = good_report();
        r["$schema"] = json!("https://example.com/wrong");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/$schema"), "got {errs:?}");
    }

    #[test]
    fn dollar_schema_correct_value_passes() {
        let mut r = good_report();
        r["$schema"] = json!(SCHEMA_ID);
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn missing_top_level_field_rejects() {
        let mut r = good_report();
        r.as_object_mut().unwrap().remove("run_id");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/run_id"));
    }

    #[test]
    fn wrong_schema_version_rejects() {
        let mut r = good_report();
        r["schema_version"] = json!("0.9");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/schema_version"));
    }

    #[test]
    fn non_rfc3339_produced_at_rejects() {
        let mut r = good_report();
        r["produced_at"] = json!("yesterday");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/produced_at"));
    }

    #[test]
    fn missing_finding_field_rejects() {
        let mut r = good_report();
        r["findings"][0].as_object_mut().unwrap().remove("title");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/findings/0/title"));
    }

    #[test]
    fn unknown_framing_rejects() {
        let mut r = good_report();
        r["findings"][0]["framing"] = json!(["unknown_framing"]);
        let errs = validate_value(&r);
        assert!(
            errs.iter()
                .any(|e| e.path.starts_with("/findings/0/framing"))
        );
    }

    #[test]
    fn empty_framing_array_rejects() {
        let mut r = good_report();
        r["findings"][0]["framing"] = json!([]);
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/findings/0/framing"));
    }

    #[test]
    fn unknown_tier_rejects() {
        let mut r = good_report();
        r["findings"][0]["tier"] = json!("SEVERE");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/findings/0/tier"));
    }

    #[test]
    fn line_start_zero_rejects() {
        let mut r = good_report();
        r["findings"][0]["location"]["line_start"] = json!(0);
        let errs = validate_value(&r);
        assert!(
            errs.iter()
                .any(|e| e.path == "/findings/0/location/line_start")
        );
    }

    #[test]
    fn parse_stable_id_accepts_canonical_form() {
        let parsed = parse_stable_id("auth::src/foo.rs:42").unwrap();
        assert_eq!(parsed.framing, "auth");
        assert_eq!(parsed.rel_file, "src/foo.rs");
        assert_eq!(parsed.line, 42);
    }

    #[test]
    fn parse_stable_id_accepts_colon_in_filename_via_right_to_left() {
        let parsed = parse_stable_id("auth::a:b:c.rs:7").unwrap();
        assert_eq!(parsed.framing, "auth");
        assert_eq!(parsed.rel_file, "a:b:c.rs");
        assert_eq!(parsed.line, 7);
    }

    #[test]
    fn parse_stable_id_accepts_deeply_nested_path() {
        let parsed = parse_stable_id("injection::deeply/nested/path/file.py:1").unwrap();
        assert_eq!(parsed.framing, "injection");
        assert_eq!(parsed.rel_file, "deeply/nested/path/file.py");
        assert_eq!(parsed.line, 1);
    }

    #[test]
    fn parse_stable_id_rejects_unknown_framing() {
        assert!(parse_stable_id("scope_path::file.rs:1").is_err());
    }

    #[test]
    fn parse_stable_id_rejects_empty_framing() {
        assert!(parse_stable_id("::file.rs:1").is_err());
    }

    #[test]
    fn parse_stable_id_rejects_missing_line() {
        assert!(parse_stable_id("auth::file.rs:").is_err());
    }

    #[test]
    fn parse_stable_id_rejects_non_integer_line() {
        assert!(parse_stable_id("auth::file.rs:1.5").is_err());
    }

    #[test]
    fn parse_stable_id_rejects_missing_line_separator() {
        assert!(parse_stable_id("auth::file.rs").is_err());
    }

    #[test]
    fn parse_stable_id_rejects_absolute_path() {
        assert!(parse_stable_id("auth::/abs/path.rs:1").is_err());
    }

    /// The canonical schema file must parse as valid JSON and
    /// advertise the canonical `$id`. Catches the case where
    /// someone edits the schema file but the `SCHEMA_ID` constant
    /// drifts.
    #[test]
    fn schema_file_is_valid_json_and_advertises_canonical_id() {
        let body = include_str!("../../../../docs/lyrik-json-schema.json");
        let v: serde_json::Value =
            serde_json::from_str(body).expect("schema file must be valid JSON");
        assert_eq!(
            v.get("$id").and_then(|s| s.as_str()),
            Some(SCHEMA_ID),
            "schema file $id must match SCHEMA_ID constant"
        );
    }

    #[test]
    fn detection_source_absent_is_valid() {
        let r = good_report();
        assert!(r["findings"][0].get("detection_source").is_none());
        let errs = validate_value(&r);
        assert!(
            errs.is_empty(),
            "absent detection_source must be valid: {errs:?}"
        );
    }

    #[test]
    fn detection_source_static_prescreen_is_valid() {
        let mut r = good_report();
        r["findings"][0]["detection_source"] = json!("static_prescreen");
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn detection_source_model_reasoning_is_valid() {
        let mut r = good_report();
        r["findings"][0]["detection_source"] = json!("model_reasoning");
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn detection_source_both_is_valid() {
        let mut r = good_report();
        r["findings"][0]["detection_source"] = json!("both");
        assert!(validate_value(&r).is_empty());
    }

    #[test]
    fn detection_source_unknown_value_rejects() {
        let mut r = good_report();
        r["findings"][0]["detection_source"] = json!("semgrep_seeded");
        let errs = validate_value(&r);
        assert!(
            errs.iter()
                .any(|e| e.path == "/findings/0/detection_source"),
            "got {errs:?}"
        );
    }

    #[test]
    fn detection_source_non_string_rejects() {
        let mut r = good_report();
        r["findings"][0]["detection_source"] = json!(42);
        let errs = validate_value(&r);
        assert!(
            errs.iter()
                .any(|e| e.path == "/findings/0/detection_source")
        );
    }

    #[test]
    fn schema_version_one_zero_rejects_under_one_one_validator() {
        let mut r = good_report();
        r["schema_version"] = json!("1.0");
        let errs = validate_value(&r);
        assert!(errs.iter().any(|e| e.path == "/schema_version"));
    }
}
