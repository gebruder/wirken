//! The defender-mode fix step.
//!
//! In defender mode, after the findings are aggregated, each confirmed
//! finding gets one agent with a fresh context whose job is a fix
//! for the invariant the finding names, not for the input that showed
//! it. Confirmed means kept by the brocard gate and backed by a
//! reproduction the fresh-context replay agreed with, so there is a
//! command that shows the defect.
//!
//! The agent writes under `staging/fix/<slug>/` only: `fix.patch`,
//! `apply.sh` and `proof.json`. Nothing is written into the target
//! tree; the arms run in copies the agent extracts from the scanned
//! revision under that directory. The proof has three arms against the
//! live build: the reproduction fails on the baseline copy, passes on
//! the patched copy, and fails again after a full revert that leaves
//! the copy identical to the baseline. The runner judges the proof: a
//! proof with all three arms in that shape is a fix; anything less is
//! inconclusive, recorded as such with its reasons, never as a fix.
//!
//! Every command the agent runs goes through the same `exec` gate as a
//! walk's: the operator is asked before each one, an approval is a
//! one-shot bypass that stores nothing, and a refused command is a
//! skipped step.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::lyrik_replay::{ReproductionOutcome, ReproductionRecord};

/// The commands the fix skill runs through `exec`, besides the
/// reproduction command as the walk recorded it.
pub const FIX_EXEC_COMMANDS: &[&str] = &["git archive", "tar", "git apply", "diff"];

/// A finding the fix step takes on, with the reproduction that confirms it.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmed {
    pub stable_id: String,
    pub finding: Value,
    pub reproduction: ReproductionRecord,
}

/// The kept findings backed by a reproduction the replay agreed with,
/// in `findings.json` order. The first agreeing reproduction per
/// finding is the one the arms run.
pub fn confirmed_findings(body: &Value) -> Vec<Confirmed> {
    let empty = Vec::new();
    let reproductions = body
        .get("reproductions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let findings = body
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    findings
        .iter()
        .filter_map(|f| {
            let stable_id = f.get("stable_id")?.as_str()?.to_string();
            let repro = reproductions.iter().find_map(|r| {
                if r.get("stable_id")?.as_str()? != stable_id {
                    return None;
                }
                if !r.get("agreement")?.as_bool()? {
                    return None;
                }
                let record: ReproductionRecord = serde_json::from_value(r.clone()).ok()?;
                (record.outcome == ReproductionOutcome::Reproduced).then_some(record)
            })?;
            Some(Confirmed {
                stable_id,
                finding: f.clone(),
                reproduction: repro,
            })
        })
        .collect()
}

/// A directory name for a finding: its stable id with every byte
/// outside `[A-Za-z0-9._-]` replaced by `-`, runs collapsed.
pub fn slug(stable_id: &str) -> String {
    let mut out = String::with_capacity(stable_id.len());
    let mut last_dash = false;
    for c in stable_id.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmOutcome {
    /// The reproduction showed the defect.
    Fails,
    /// The reproduction ran and did not show it.
    Passes,
}

/// One arm of the proof, as the agent ran it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Arm {
    /// The command run, which must be the reproduction's command.
    pub command: String,
    /// The copy it ran in, under the fix directory.
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// The output line, exit status or diagnostic, quoted.
    pub observed: String,
    pub outcome: ArmOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Arms {
    pub baseline: Arm,
    pub patched: Arm,
    pub reverted: Arm,
}

/// `proof.json` as the agent writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    pub stable_id: String,
    /// The property the code must hold, from the finding, that the
    /// patch restores.
    pub invariant: String,
    /// The patch file name under the fix directory.
    pub patch: String,
    pub arms: Arms,
    /// Whether `diff -r` found the reverted copy identical to the
    /// baseline copy before the third arm ran.
    pub reverted_tree_identical: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Fix,
    Inconclusive,
}

/// One finding's fix outcome, as `findings.json` carries it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FixOutcome {
    pub stable_id: String,
    /// The fix directory, relative to the run directory.
    pub dir: String,
    pub verdict: Verdict,
    /// Why the verdict is inconclusive. Empty for a fix.
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Judge one fix directory against the reproduction it was to prove.
/// `target_modified` is whether the target tree changed during the fix
/// step, which no fix may do.
pub fn judge(
    fix_dir: &Path,
    rel_dir: &str,
    confirmed: &Confirmed,
    target_modified: bool,
) -> FixOutcome {
    let mut reasons = Vec::new();
    let proof_path = fix_dir.join("proof.json");
    let proof: Option<Proof> = match std::fs::read_to_string(&proof_path) {
        Err(_) => {
            reasons.push("no proof.json".to_string());
            None
        }
        Ok(body) => match serde_json::from_str::<Proof>(&body) {
            Ok(p) => Some(p),
            Err(e) => {
                reasons.push(format!("proof.json does not parse: {e}"));
                None
            }
        },
    };
    if let Some(p) = &proof {
        if p.stable_id != confirmed.stable_id {
            reasons.push(format!(
                "proof names {} not {}",
                p.stable_id, confirmed.stable_id
            ));
        }
        if p.invariant.trim().is_empty() {
            reasons.push("no invariant named".to_string());
        }
        let patch = fix_dir.join(&p.patch);
        match std::fs::metadata(&patch) {
            Ok(m) if m.len() > 0 => {}
            _ => reasons.push(format!("patch {} is missing or empty", p.patch)),
        }
        let command = confirmed.reproduction.command.trim();
        for (name, arm, wanted) in [
            ("baseline", &p.arms.baseline, ArmOutcome::Fails),
            ("patched", &p.arms.patched, ArmOutcome::Passes),
            ("reverted", &p.arms.reverted, ArmOutcome::Fails),
        ] {
            if arm.command.trim() != command {
                reasons.push(format!("{name} arm ran a different command"));
            }
            if arm.outcome != wanted {
                let want = match wanted {
                    ArmOutcome::Fails => "fail",
                    ArmOutcome::Passes => "pass",
                };
                reasons.push(format!("{name} arm did not {want}"));
            }
        }
        if !p.reverted_tree_identical {
            reasons.push("reverted copy is not identical to the baseline".to_string());
        }
    }
    if target_modified {
        reasons.push("the target tree changed during the fix step".to_string());
    }
    FixOutcome {
        stable_id: confirmed.stable_id.clone(),
        dir: rel_dir.to_string(),
        verdict: if reasons.is_empty() {
            Verdict::Fix
        } else {
            Verdict::Inconclusive
        },
        reasons,
        proof,
    }
}

/// Add `fixes` to a written `findings.json`.
pub fn record_fixes(dest: &Path, outcomes: &[FixOutcome]) -> Result<()> {
    let body = std::fs::read_to_string(dest).with_context(|| format!("read {}", dest.display()))?;
    let mut body: Value =
        serde_json::from_str(&body).with_context(|| format!("parse {}", dest.display()))?;
    body["fixes"] = serde_json::to_value(outcomes)?;
    std::fs::write(dest, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", dest.display()))?;
    Ok(())
}

/// The staged skill the fix agent runs under. Written by this crate.
pub fn fix_skill_text(run_id: &str, tools: &str) -> String {
    let commands = FIX_EXEC_COMMANDS
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "---\nname: fix\ndescription: Fix one confirmed finding at its invariant and prove it in three arms\n\
         disable-model-invocation: true\npermissions:\n  tools:\n    allow: [{tools}]\n  egress:\n    \
         mode: deny\n  filesystem:\n    read_paths: [\"<workspace>\"]\n    write_paths: \
         [\"<workspace>/.lyrik/state/runs/{run_id}\"]\n  inference:\n    allow: [\"*\"]\n---\n\n\
         # Fix\n\n\
         You are given one confirmed finding, the invariant it names, and the reproduction \
         that showed it. Produce a patch that restores the invariant, and prove it in three \
         arms against the live build. The prompt names the fix directory; every file you \
         write goes there. You do not write into the project's tree: not a source file, \
         not a test, not a build artifact.\n\n\
         The patch targets the invariant, not the input. A check that rejects the one \
         reproduction's bytes and nothing else is not a fix; the property named as the \
         invariant must hold for every input the code path admits. Keep the patch to that \
         mechanism: no refactors, no renames, no changes to code the invariant does not \
         touch.\n\n\
         Commands this skill runs through `exec`: {commands}, and the reproduction command \
         exactly as the record gives it. The operator is asked before each one; a refused \
         command is a step not taken, and you say so in `proof.json` under `notes` and \
         stop. Run nothing else.\n\n\
         Steps, in order:\n\n\
         1. Read the code the finding points at and the reproduction's expected and \
         observed output. Name the invariant in your own words only if the finding's is \
         blank; otherwise carry it as given.\n\
         2. Extract two copies of the scanned revision under the fix directory: \
         `git archive --format=tar <revision> | tar -x -C <fix-dir>/baseline` and the same \
         into `<fix-dir>/patched`. The revision is in the prompt.\n\
         3. Write the patch as a unified diff with `a/` and `b/` prefixes to \
         `<fix-dir>/fix.patch`, and `<fix-dir>/apply.sh` holding \
         `git apply --check fix.patch && git apply fix.patch`, to be run from the \
         project root by the operator.\n\
         4. Arm one, baseline: run the reproduction command in `<fix-dir>/baseline`. It \
         must show the defect, outcome `fails`.\n\
         5. Apply the patch in `<fix-dir>/patched` with `git apply <fix-dir>/fix.patch` \
         from that directory. Arm two, patched: run the reproduction command there. It \
         must not show the defect, outcome `passes`.\n\
         6. Revert in full: `git apply -R <fix-dir>/fix.patch` in `<fix-dir>/patched`, \
         then `diff -r <fix-dir>/baseline <fix-dir>/patched` excluding build output; it \
         must print nothing. Arm three, reverted: run the reproduction command in \
         `<fix-dir>/patched` again. It must show the defect, outcome `fails`.\n\
         7. Write `<fix-dir>/proof.json`: `stable_id`, `invariant`, `patch` \
         (`fix.patch`), `arms` with `baseline`, `patched` and `reverted`, each carrying \
         `command` (the reproduction command, verbatim), `cwd`, `exit_status`, `observed` \
         (quoted output) and `outcome` (`fails` or `passes`), `reverted_tree_identical` \
         (whether step 6's diff printed nothing) and `notes`.\n\n\
         Write each arm's record as you observe it. Do not infer an arm you did not run; \
         leave it out and say why in `notes`. The runner judges the proof: all three arms \
         in that shape is a fix, anything else is inconclusive. Your reply is one \
         sentence saying the proof was written.\n"
    )
}

/// The prompt the fix agent receives: the finding, its invariant, the
/// reproduction, the revision, and where to write.
pub fn build_fix_prompt(
    confirmed: &Confirmed,
    run_id: &str,
    code_revision: Option<&str>,
    fix_dir_rel: &str,
) -> String {
    let mut finding = serde_json::Map::new();
    for key in [
        "stable_id",
        "title",
        "summary",
        "location",
        "framing",
        "tier",
        "threat_model",
        "invariant",
    ] {
        if let Some(v) = confirmed.finding.get(key) {
            finding.insert(key.to_string(), v.clone());
        }
    }
    let invariant = confirmed
        .finding
        .get("invariant")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("Invariant: {s}"))
        .unwrap_or_else(|| {
            "Invariant: the finding names none; state it in `proof.json` from the code and \
             the finding, as the property the patch restores."
                .to_string()
        });
    let revision = code_revision.unwrap_or(&confirmed.reproduction.code_revision);
    format!(
        "/fix Fix this confirmed finding and prove the fix in three arms. Run-id: `{run_id}`. \
         Code revision: `{revision}`. Fix directory: `.lyrik/state/runs/{run_id}/{fix_dir_rel}`. \
         {invariant}\n\n\
         Finding:\n```json\n{}\n```\n\n\
         Reproduction:\n```json\n{}\n```",
        serde_json::to_string_pretty(&Value::Object(finding)).unwrap_or_default(),
        serde_json::to_string_pretty(&confirmed.reproduction).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn body() -> Value {
        serde_json::json!({
            "findings": [
                {"stable_id": "auth::src/a.rs:10", "title": "t", "summary": "s",
                 "location": {"file": "src/a.rs", "line_start": 10}, "invariant": "len is bounded"},
                {"stable_id": "auth::src/b.rs:5", "title": "u", "summary": "v",
                 "location": {"file": "src/b.rs", "line_start": 5}}
            ],
            "reproductions": [
                {"walk": "fuzz-walk", "file": "repro-001.json", "stable_id": "auth::src/a.rs:10",
                 "command": "cargo test -p x one", "expected": "fails", "observed": "failed",
                 "outcome": "reproduced", "code_revision": "abc",
                 "replay": {"command_run": "cargo test -p x one", "observed": "failed", "outcome": "reproduced"},
                 "agreement": true},
                {"walk": "fuzz-walk", "file": "repro-002.json", "stable_id": "auth::src/b.rs:5",
                 "command": "cargo test -p x two", "expected": "fails", "observed": "failed",
                 "outcome": "reproduced", "code_revision": "abc",
                 "replay": {"command_run": "cargo test -p x two", "observed": "passed", "outcome": "not_reproduced"},
                 "agreement": false}
            ]
        })
    }

    fn proof(cmd: &str) -> String {
        let arm = |cwd: &str, outcome: &str| {
            format!(
                r#"{{"command":"{cmd}","cwd":"{cwd}","exit_status":1,"observed":"x","outcome":"{outcome}"}}"#
            )
        };
        format!(
            r#"{{"stable_id":"auth::src/a.rs:10","invariant":"len is bounded","patch":"fix.patch","arms":{{"baseline":{},"patched":{},"reverted":{}}},"reverted_tree_identical":true,"notes":[]}}"#,
            arm("baseline", "fails"),
            arm("patched", "passes"),
            arm("patched", "fails")
        )
    }

    #[test]
    fn only_a_kept_finding_with_an_agreed_reproduction_is_confirmed() {
        let c = confirmed_findings(&body());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].stable_id, "auth::src/a.rs:10");
        assert_eq!(c[0].reproduction.command, "cargo test -p x one");
    }

    #[test]
    fn slugs_keep_only_safe_bytes() {
        assert_eq!(slug("auth::src/a.rs:10"), "auth-src-a.rs-10");
        assert_eq!(slug("::/x//"), "x");
    }

    #[test]
    fn a_complete_proof_is_a_fix_and_each_gap_is_a_named_reason() {
        let tmp = tempdir().unwrap();
        let c = confirmed_findings(&body()).remove(0);
        // No directory at all.
        let out = judge(&tmp.path().join("none"), "staging/fix/none", &c, false);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.reasons, vec!["no proof.json"]);
        // Complete.
        let dir = tmp.path().join("ok");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("proof.json"), proof("cargo test -p x one")).unwrap();
        std::fs::write(dir.join("fix.patch"), "--- a/x\n+++ b/x\n").unwrap();
        let out = judge(&dir, "staging/fix/ok", &c, false);
        assert_eq!(out.verdict, Verdict::Fix, "{:?}", out.reasons);
        assert!(out.proof.is_some());
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["verdict"], "fix");
        assert_eq!(v["dir"], "staging/fix/ok");
        // Target modified during the step: never a fix.
        let out = judge(&dir, "staging/fix/ok", &c, true);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(
            out.reasons,
            vec!["the target tree changed during the fix step"]
        );
        // Wrong command, missing patch, arms in the wrong shape, no revert check.
        let bad = tmp.path().join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        let text = proof("cargo test -p x other")
            .replace(r#""outcome":"passes""#, r#""outcome":"fails""#)
            .replace(
                r#""reverted_tree_identical":true"#,
                r#""reverted_tree_identical":false"#,
            )
            .replace(r#""invariant":"len is bounded""#, r#""invariant":" ""#);
        std::fs::write(bad.join("proof.json"), text).unwrap();
        let out = judge(&bad, "staging/fix/bad", &c, false);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        for want in [
            "no invariant named",
            "patch fix.patch is missing or empty",
            "baseline arm ran a different command",
            "patched arm did not pass",
            "reverted copy is not identical to the baseline",
        ] {
            assert!(
                out.reasons.iter().any(|r| r == want),
                "{want} in {:?}",
                out.reasons
            );
        }
        assert!(!out.reasons.iter().any(|r| r == "baseline arm did not fail"));
    }

    #[test]
    fn fixes_are_added_to_a_written_findings_json() {
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("findings.json");
        std::fs::write(&dest, r#"{"schema_version":"1.1","findings":[]}"#).unwrap();
        let c = confirmed_findings(&body()).remove(0);
        let out = judge(&tmp.path().join("none"), "staging/fix/none", &c, false);
        record_fixes(&dest, &[out]).unwrap();
        let body: Value = serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(body["schema_version"], "1.1");
        assert_eq!(body["fixes"][0]["stable_id"], "auth::src/a.rs:10");
        assert_eq!(body["fixes"][0]["verdict"], "inconclusive");
    }

    #[test]
    fn the_prompt_carries_the_finding_the_invariant_the_record_and_the_directory() {
        let c = confirmed_findings(&body()).remove(0);
        let p = build_fix_prompt(
            &c,
            "sample/run-001",
            Some("abc"),
            "staging/fix/auth-src-a.rs-10",
        );
        assert!(p.starts_with("/fix "), "{p}");
        assert!(p.contains("Invariant: len is bounded"), "{p}");
        assert!(p.contains("Code revision: `abc`"), "{p}");
        assert!(
            p.contains(".lyrik/state/runs/sample/run-001/staging/fix/auth-src-a.rs-10"),
            "{p}"
        );
        assert!(p.contains(r#""command": "cargo test -p x one""#), "{p}");
        let text = fix_skill_text("sample/run-001", "exec, read_file, write_file, list_files");
        assert!(text.starts_with("---\nname: fix\n"), "{text}");
        for c in FIX_EXEC_COMMANDS {
            assert!(text.contains(&format!("`{c}`")), "{c}");
        }
        assert!(text.contains("reverted_tree_identical"), "{text}");
    }
}
