//! SARIF 2.1.0 emitter for Lyrik findings.json.
//!
//! Type-driven structural validity: structs mirror the SARIF spec
//! field-for-field. A document that serializes is structurally valid.
//! GitHub Code Scanning ingest is the authoritative validator at
//! fixture-upload time.
//!
//! Slice 5 ships per-finding results, the nine framing rules, the
//! rung+deferral pair, the property template, and the lyrik-specific
//! properties bag. SARIF-native `fixes[]` for patch_localized lands
//! in slice 6.
//!
//! Dependency floor: `serde` + `serde_json` only.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json";
const SARIF_VERSION: &str = "2.1.0";
const LYRIK_INFO_URI: &str = "https://lyrik.wirken.ai";

/// Nine framings, the analytic-class rules. Stable across runs.
const FRAMINGS: &[(&str, &str, &str)] = &[
    ("auth", "AuthFraming", "Authentication and authorization: missing checks, broken authorization, replay, session fixation, identity confusion."),
    ("crypto", "CryptoFraming", "Cryptographic primitive misuse: nonce reuse, non-constant-time compare, malleable signature verification, KDF misuse, AEAD AAD misuse, downgrade."),
    ("injection", "InjectionFraming", "Classical injection: SQL, shell, command, log."),
    ("deserialization", "DeserializationFraming", "Untrusted-data deserialization across pickle, JSON, YAML, MessagePack, etc."),
    ("memory_safety", "MemorySafetyFraming", "Memory-safety bugs: out-of-bounds, use-after-free, integer overflow into bounds calculation."),
    ("secrets", "SecretsFraming", "Credential leakage: serialization, logging, environment exposure, storage hygiene."),
    ("supply_chain", "SupplyChainFraming", "Supply chain compromise paths: dependency, build, signing anchor, plugin/skill load."),
    ("race_condition", "RaceConditionFraming", "Concurrency-related findings: TOCTOU, lock-elision, atomicity gap on shared state."),
    ("prompt_injection", "PromptInjectionFraming", "Untrusted text reaching model context: system-prompt content, tool-output amplification, retrieval payload trust, cross-tool prompt-relay."),
];

// ===========================================================================
// Input: Lyrik findings.json schema (subset we consume).
// All optional fields tolerate absence so slice 5 reads pre-schema-update
// findings.json files.
// ===========================================================================

#[derive(Debug, Deserialize)]
struct LyrikReport {
    run_id: String,
    #[serde(default)]
    target: Option<Target>,
    #[serde(default)]
    findings: Vec<Finding>,
    #[serde(default)]
    audit: Option<AuditRef>,
    #[serde(default)]
    concentration: Option<Concentration>,
}

#[derive(Debug, Deserialize)]
struct Target {
    #[serde(default)]
    source_state: Option<SourceState>,
}

#[derive(Debug, Deserialize)]
struct SourceState {
    #[serde(default)]
    sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Concentration {
    #[serde(default)]
    concentration_index_top_5: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct AuditRef {
    #[serde(default)]
    log_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Finding {
    id: String,
    stable_id: String,
    #[serde(default)]
    stream: Option<String>,
    #[serde(default)]
    framing: Vec<String>,
    #[serde(default)]
    detection_source: Option<String>,
    location: Location,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    grade: Option<f64>,
    #[serde(default)]
    rung: Option<RungInput>,
    #[serde(default)]
    deferral: Option<DeferralInput>,
    #[serde(default)]
    property_template: Option<PropertyTemplate>,
    #[serde(default)]
    scoring_passes: Vec<serde_json::Value>,
    #[serde(default)]
    gate_routed: Option<GateRouted>,
    #[serde(default)]
    dedup_match: Option<DedupMatch>,
}

#[derive(Debug, Deserialize)]
struct Location {
    file: String,
    line_start: u32,
    #[serde(default)]
    line_end: Option<u32>,
}

/// Either a numeric rung (1-6), a name string, or an object with both.
/// Tolerates the absent-field case (default to suspicion).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RungInput {
    Number(u8),
    Name(String),
    Object {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        number: Option<u8>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DeferralInput {
    Name(String),
    Object {
        #[serde(default)]
        reason: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct PropertyTemplate {
    #[serde(default)]
    proposition: Option<String>,
    #[serde(default)]
    slots: Option<serde_json::Value>,
    #[serde(default)]
    witness: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GateRouted {
    #[serde(default)]
    gate: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DedupMatch {
    #[serde(default)]
    tier_used: Option<String>,
    #[serde(default)]
    prior_path: Option<String>,
}

// ===========================================================================
// Output: SARIF 2.1.0.
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct Sarif {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: Tool,
    #[serde(rename = "automationDetails")]
    automation_details: AutomationDetails,
    invocations: Vec<Invocation>,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "fullDescription")]
    full_description: Text,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: DefaultConfig,
    properties: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Text {
    text: String,
}

#[derive(Debug, Serialize)]
struct DefaultConfig {
    level: Level,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Level {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Serialize)]
struct AutomationDetails {
    id: String,
}

#[derive(Debug, Serialize)]
struct Invocation {
    #[serde(rename = "executionSuccessful")]
    execution_successful: bool,
    properties: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: Level,
    message: Text,
    locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: serde_json::Value,
    properties: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: &'static str,
}

#[derive(Debug, Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "endLine")]
    end_line: u32,
}

// ===========================================================================
// Conversion
// ===========================================================================

/// Read a Lyrik findings.json from `findings_path`, build the SARIF
/// document. Pure: does not touch the filesystem beyond reading the
/// input.
pub fn build_sarif(findings_path: &Path, driver_version: &str) -> Result<Sarif> {
    let body = std::fs::read_to_string(findings_path)
        .with_context(|| format!("read {}", findings_path.display()))?;
    let report: LyrikReport = serde_json::from_str(&body)
        .with_context(|| format!("parse findings.json at {}", findings_path.display()))?;

    let rules = build_rules();
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| build_result(f, &report.run_id))
        .collect();

    let invocation_props = serde_json::json!({
        "lyrik": {
            "audit_log_ref": report.audit.as_ref().and_then(|a| a.log_path.clone()),
            "concentration_index_top_5": report
                .concentration
                .as_ref()
                .and_then(|c| c.concentration_index_top_5),
            "target_sha": report
                .target
                .as_ref()
                .and_then(|t| t.source_state.as_ref())
                .and_then(|s| s.sha.clone()),
        }
    });

    Ok(Sarif {
        schema: SARIF_SCHEMA_URL,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: Tool {
                driver: Driver {
                    name: "lyrik",
                    version: driver_version.to_string(),
                    information_uri: LYRIK_INFO_URI,
                    rules,
                },
            },
            automation_details: AutomationDetails {
                id: format!("lyrik/run/{}", report.run_id),
            },
            invocations: vec![Invocation {
                execution_successful: true,
                properties: invocation_props,
            }],
            results,
        }],
    })
}

fn build_rules() -> Vec<Rule> {
    FRAMINGS
        .iter()
        .map(|(framing, name, description)| Rule {
            id: format!("lyrik.framing.{framing}"),
            name: (*name).to_string(),
            short_description: Text {
                text: description_short(framing),
            },
            full_description: Text {
                text: (*description).to_string(),
            },
            default_configuration: DefaultConfig {
                level: Level::Warning,
            },
            properties: serde_json::json!({ "lyrik_framing": framing }),
        })
        .collect()
}

fn description_short(framing: &str) -> String {
    format!("Findings produced by the {framing} framing pass.")
}

fn build_result(f: &Finding, run_id: &str) -> SarifResult {
    let primary_framing = f.framing.first().map(String::as_str).unwrap_or("auth");
    let rule_id = format!("lyrik.framing.{primary_framing}");

    let level = level_for_tier(f.tier.as_deref());

    let title = f.title.clone().unwrap_or_else(|| f.id.clone());
    let message_text = match (f.title.clone(), f.summary.clone()) {
        (Some(t), Some(s)) => format!("{t}\n\n{s}"),
        (Some(t), None) => t,
        (None, Some(s)) => s,
        (None, None) => f.id.clone(),
    };

    let line_end = f.location.line_end.unwrap_or(f.location.line_start);

    let (rung_name, rung_number) = resolve_rung(f.rung.as_ref());
    let deferral_reason = resolve_deferral(f.deferral.as_ref(), f.gate_routed.as_ref());

    let properties = serde_json::json!({
        "lyrik": {
            "run_id": run_id,
            "stable_id": f.stable_id,
            "id": f.id,
            "framing": f.framing,
            "stream": f.stream,
            "detection_source": f.detection_source,
            "tier": f.tier,
            "grade": f.grade,
            "title": title,
            "scoring_passes": f.scoring_passes.len(),
            "rung": { "name": rung_name, "number": rung_number },
            "deferral": { "reason": deferral_reason },
            "property_template": f.property_template,
            "regression_match": f.dedup_match.as_ref().map(|d| serde_json::json!({
                "tier_used": d.tier_used,
                "prior_path": d.prior_path,
            })),
            "gate_routed": f.gate_routed.as_ref().map(|g| serde_json::json!({
                "gate": g.gate,
                "tag": g.tag,
            })),
        }
    });

    let partial_fingerprints = serde_json::json!({
        "lyrik/finding_stable_id/v1": f.stable_id,
    });

    SarifResult {
        rule_id,
        level,
        message: Text { text: message_text },
        locations: vec![SarifLocation {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: f.location.file.clone(),
                    uri_base_id: "%SRCROOT%",
                },
                region: Region {
                    start_line: f.location.line_start,
                    end_line: line_end,
                },
            },
        }],
        partial_fingerprints,
        properties,
    }
}

fn level_for_tier(tier: Option<&str>) -> Level {
    match tier.unwrap_or("") {
        "CRITICAL" | "HIGH" => Level::Error,
        "MEDIUM" => Level::Warning,
        _ => Level::Note,
    }
}

fn resolve_rung(rung: Option<&RungInput>) -> (&'static str, u8) {
    let (name, number) = match rung {
        Some(RungInput::Number(n)) => (rung_name_for_number(*n), *n),
        Some(RungInput::Name(n)) => (rung_name_static(n), rung_number_for_name(n)),
        Some(RungInput::Object { name, number }) => {
            let n = name.as_deref().unwrap_or("suspicion");
            let num = number.unwrap_or_else(|| rung_number_for_name(n));
            (rung_name_static(n), num)
        }
        None => ("suspicion", 1),
    };
    (name, number)
}

fn rung_name_for_number(n: u8) -> &'static str {
    match n {
        1 => "suspicion",
        2 => "static_corroboration",
        3 => "property_violated",
        4 => "root_cause_explained",
        5 => "variant_observed",
        6 => "patch_localized",
        _ => "suspicion",
    }
}

fn rung_number_for_name(name: &str) -> u8 {
    match name {
        "suspicion" => 1,
        "static_corroboration" => 2,
        "property_violated" => 3,
        "root_cause_explained" => 4,
        "variant_observed" => 5,
        "patch_localized" => 6,
        _ => 1,
    }
}

fn rung_name_static(name: &str) -> &'static str {
    match name {
        "suspicion" => "suspicion",
        "static_corroboration" => "static_corroboration",
        "property_violated" => "property_violated",
        "root_cause_explained" => "root_cause_explained",
        "variant_observed" => "variant_observed",
        "patch_localized" => "patch_localized",
        _ => "suspicion",
    }
}

fn resolve_deferral(
    deferral: Option<&DeferralInput>,
    gate_routed: Option<&GateRouted>,
) -> Option<&'static str> {
    let from_field = deferral.and_then(|d| match d {
        DeferralInput::Name(n) => Some(n.as_str()),
        DeferralInput::Object { reason } => reason.as_deref(),
    });
    let from_gate = gate_routed.and_then(|g| {
        g.tag.as_deref().or_else(|| match g.gate.as_deref() {
            Some("scope_bound") => Some("scope_bound"),
            _ => None,
        })
    });
    match from_field.or(from_gate)? {
        "scope_bound" => Some("scope_bound"),
        "rubric_clarification" => Some("rubric_clarification"),
        "rubric_silent" => Some("rubric_silent"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_findings_produces_minimal_valid_sarif() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.json");
        std::fs::write(
            &path,
            r#"{"run_id":"r","produced_at":"2026-05-03T00:00:00Z","findings":[]}"#,
        )
        .unwrap();
        let sarif = build_sarif(&path, "0.0.0").unwrap();
        assert_eq!(sarif.version, SARIF_VERSION);
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 0);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), FRAMINGS.len());
    }

    #[test]
    fn finding_with_rung_and_deferral_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.json");
        std::fs::write(
            &path,
            r#"{
                "run_id": "run-001",
                "produced_at": "2026-05-03T00:00:00Z",
                "findings": [{
                    "id": "A1",
                    "stable_id": "scope::file.c:100:fn",
                    "stream": "regression",
                    "framing": ["auth", "memory_safety"],
                    "detection_source": "model_reasoning",
                    "location": {"file": "file.c", "line_start": 100, "line_end": 110, "function": "fn"},
                    "title": "Stack overflow",
                    "tier": "CRITICAL",
                    "grade": 0.5,
                    "rung": "patch_localized",
                    "deferral": null,
                    "property_template": {
                        "proposition": "every <write to X> must be preceded by <bound check on Y>",
                        "slots": {"X": "memcpy at 100", "Y": "len <= 96"},
                        "witness": {"call_path": ["fn", "memcpy at 100"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        let sarif = build_sarif(&path, "0.0.0").unwrap();
        let r = &sarif.runs[0].results[0];
        assert_eq!(r.rule_id, "lyrik.framing.auth");
        assert!(matches!(r.level, Level::Error));
        let props = serde_json::to_value(&r.properties).unwrap();
        assert_eq!(props["lyrik"]["rung"]["name"], "patch_localized");
        assert_eq!(props["lyrik"]["rung"]["number"], 6);
        assert!(props["lyrik"]["deferral"]["reason"].is_null());
        assert_eq!(
            props["lyrik"]["property_template"]["proposition"],
            "every <write to X> must be preceded by <bound check on Y>"
        );
    }

    #[test]
    fn gate_routed_finding_pulls_deferral_from_gate_tag() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.json");
        std::fs::write(
            &path,
            r#"{
                "run_id": "run-001",
                "produced_at": "2026-05-03T00:00:00Z",
                "findings": [{
                    "id": "A6",
                    "stable_id": "scope::file.c:1620:fn",
                    "framing": ["auth", "crypto"],
                    "location": {"file": "file.c", "line_start": 1620},
                    "gate_routed": {"gate": "scoring_disagreement", "tag": "rubric_clarification"}
                }]
            }"#,
        )
        .unwrap();
        let sarif = build_sarif(&path, "0.0.0").unwrap();
        let r = &sarif.runs[0].results[0];
        let props = serde_json::to_value(&r.properties).unwrap();
        assert_eq!(props["lyrik"]["deferral"]["reason"], "rubric_clarification");
        assert_eq!(props["lyrik"]["rung"]["name"], "suspicion");
    }

    #[test]
    fn missing_rung_defaults_to_suspicion() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.json");
        std::fs::write(
            &path,
            r#"{
                "run_id": "r",
                "produced_at": "2026-05-03T00:00:00Z",
                "findings": [{
                    "id": "X1",
                    "stable_id": "s",
                    "framing": ["injection"],
                    "location": {"file": "x.py", "line_start": 1}
                }]
            }"#,
        )
        .unwrap();
        let sarif = build_sarif(&path, "0.0.0").unwrap();
        let props = serde_json::to_value(&sarif.runs[0].results[0].properties).unwrap();
        assert_eq!(props["lyrik"]["rung"]["name"], "suspicion");
        assert_eq!(props["lyrik"]["rung"]["number"], 1);
    }

    #[test]
    fn structurally_valid_sarif_serializes_to_required_top_level_keys() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.json");
        std::fs::write(
            &path,
            r#"{"run_id":"r","produced_at":"2026-05-03T00:00:00Z","findings":[]}"#,
        )
        .unwrap();
        let sarif = build_sarif(&path, "0.0.0").unwrap();
        let v = serde_json::to_value(&sarif).unwrap();
        assert!(v.get("$schema").is_some());
        assert!(v.get("version").is_some());
        assert!(v.get("runs").is_some());
        let run = &v["runs"][0];
        assert!(run.get("tool").is_some());
        assert!(run.get("results").is_some());
        assert!(run.get("automationDetails").is_some());
        assert!(run.get("invocations").is_some());
    }
}
