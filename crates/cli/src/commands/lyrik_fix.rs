//! The defender-mode fix step.
//!
//! In defender mode, after the findings are aggregated, each confirmed
//! finding gets a candidate fix and a set of arms that check it.
//! Confirmed means kept by the brocard gate and backed by a
//! reproduction the fresh-context replay agreed with, so there is a
//! command that shows the defect.
//!
//! Three agents run per finding, each with a fresh context, and none of
//! them decides anything. The `fix` agent writes `fix.patch` for the
//! invariant the finding names, unless a patch was supplied for the
//! finding under `.lyrik/fix-patches/`, and runs the reproduction in
//! three copies of the scanned revision. The `fix-attack` agent lists
//! the other paths to the same sink or invariant and writes a proof of
//! concept for some of them. The `fix-recheck` agent re-walks the code
//! reachable from the patched functions, runs the project's tests and
//! a benign-input differential, and lists the same pattern elsewhere.
//!
//! The runner composes every command the arms rest on, and judges from
//! the `exec` results the session log recorded for exactly those
//! commands. What an agent says it saw is not read. The arms and their
//! states are in [`super::lyrik_fix_arms`].
//!
//! A fix no arm failed, whose reproduction arm passed, is a
//! `candidate_fix`: never "fixed", never "verified". Each record lists
//! every arm, its state and whether it rests on executed commands or a
//! model's reading. A failed arm rejects the fix, and the rejection is
//! written to `rejections.jsonl` with the arm and the reason. A
//! rejected fix is not retried.
//!
//! Nothing is written into the target tree. Every command goes through
//! the same `exec` gate as a walk's: the operator is asked before each
//! one, an approval is a one-shot bypass that stores nothing, and a
//! refused command is an arm not run.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::lyrik_fix_arms::{
    self as arms, ArmResult, ArmState, ClassOpenSites, FunctionalityConfig, Layout, Locality,
    Observed, RootCauseClaim, UntestedPath,
};
use super::lyrik_replay::{ReproductionOutcome, ReproductionRecord};

/// The command words the fix step runs through `exec`, besides each
/// finding's reproduction, variant, test, coverage and fuzz commands.
pub const FIX_EXEC_COMMANDS: &[&str] = &["mkdir", "git archive", "tar", "git apply", "diff"];

/// The staged skills of the fix step, in the order they run.
pub const FIX_SKILLS: [&str; 3] = ["fix", "fix-attack", "fix-recheck"];

/// Where an operator puts a patch to be checked in place of Lyrik's
/// own, relative to the target root: `<slug>.patch` per finding.
pub const SUPPLIED_PATCH_DIR: &str = ".lyrik/fix-patches";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The reproduction arm passed and no arm failed. The other arms'
    /// states are on the record; this is not a claim that they passed.
    CandidateFix,
    /// An arm failed.
    Rejected,
    /// The reproduction arm did not pass, so nothing shows the patch
    /// stops even the original reproduction.
    Inconclusive,
}

/// The label a fix carries when it is not rejected.
pub const CANDIDATE_LABEL: &str = "candidate fix";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchSource {
    /// Written by the fix agent in this run.
    Lyrik,
    /// Supplied under [`SUPPLIED_PATCH_DIR`]: a maintainer's, an
    /// upstream fix, any other. Where it came from earns it nothing.
    Supplied,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PatchInfo {
    /// The patch, relative to the run directory.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub source: PatchSource,
    pub files: Vec<String>,
    /// Test files the patch edits. Any makes the suite unusable as a
    /// functionality check.
    pub test_files: Vec<String>,
    /// Dependency manifests the patch edits, for a reviewer to confirm
    /// each added package is the one intended.
    pub dependency_manifests: Vec<String>,
}

/// Paths, relative to the run directory, a maintainer needs to re-run
/// what the arms ran.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Artifacts {
    pub apply_script: String,
    /// The reproduction command, as the walk recorded it.
    pub reproduction_command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction_harness: Option<String>,
    /// The variants' proofs of concept.
    pub variants: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recheck: Option<String>,
    /// Every command the arms read, with its exit status and output.
    pub observed: String,
}

/// One finding's fix record, as `findings.json` carries it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FixOutcome {
    pub stable_id: String,
    /// The fix directory, relative to the run directory.
    pub dir: String,
    pub verdict: Verdict,
    /// `candidate fix`, on a fix that was not rejected and whose
    /// reproduction arm passed. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'static str>,
    /// Why the verdict is not `candidate_fix`.
    pub reasons: Vec<String>,
    /// `symptom_patch`, `asserted_only_root_cause`,
    /// `root_cause_suspect`, `functionality_unverified`.
    pub labels: Vec<&'static str>,
    pub arms: Vec<ArmResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_locality: Option<Locality>,
    /// Variants by different paths the variant arm required.
    pub variant_minimum: usize,
    pub root_cause_claim: RootCauseClaim,
    /// Paths to the same sink or invariant with no variant that held.
    pub untested_paths: Vec<UntestedPath>,
    pub class_open_sites: ClassOpenSites,
    pub patch: PatchInfo,
    /// The model that produced the patch, or that ran the arms on a
    /// supplied one.
    pub fix_model: String,
    pub artifacts: Artifacts,
}

/// What [`judge`] reads.
pub struct JudgeInput<'a> {
    pub run_dir: &'a Path,
    /// The fix directory, relative to the run directory.
    pub rel_dir: &'a str,
    pub run_id: &'a str,
    pub confirmed: &'a Confirmed,
    pub revision: &'a str,
    /// Every `exec` result the session log holds for the run.
    pub observed: &'a [Observed],
    pub target: &'a Path,
    /// Whether the target tree changed during the fix step.
    pub target_modified: bool,
    pub fix_model: &'a str,
    /// The digest of the patch supplied for this finding, when one was.
    pub supplied_sha256: Option<&'a str>,
    pub functionality: &'a FunctionalityConfig,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Judge one fix directory. The patch is whatever `fix.patch` holds;
/// every arm state comes from `input.observed` and the files under the
/// directory.
pub fn judge(input: &JudgeInput) -> FixOutcome {
    let fix_dir = input.run_dir.join(input.rel_dir);
    let layout = Layout::new(input.run_id, input.rel_dir);
    let log = arms::Log(input.observed);
    let mut reasons = Vec::new();

    let patch_bytes = std::fs::read(fix_dir.join("fix.patch")).unwrap_or_default();
    let patch_text = String::from_utf8_lossy(&patch_bytes);
    let shape = arms::parse_patch(&patch_text);
    if shape.hunks.is_empty() {
        reasons.push("fix.patch is missing or holds no hunk".to_string());
    }
    let sha256 = (!patch_bytes.is_empty()).then(|| sha256_hex(&patch_bytes));
    if let Some(supplied) = input.supplied_sha256
        && sha256.as_deref() != Some(supplied)
    {
        reasons.push("the supplied patch was changed during the fix step".to_string());
    }
    let locality = (!shape.hunks.is_empty()).then(|| shape.locality());
    let variant_minimum = match locality {
        Some(Locality::CrossCutting) => arms::VARIANT_MIN_CROSS_CUTTING,
        _ => arms::VARIANT_MIN_LOCALIZED,
    };

    let command = input.confirmed.reproduction.command.trim();
    let reproduction = arms::reproduction_arm(&log, &layout, command, input.revision);
    let mut claim = arms::root_cause_claim(&input.confirmed.finding, &reproduction);
    let attack = arms::read_json::<arms::Attack>(&fix_dir.join("attack.json"));
    let variant_files: Vec<String> = attack
        .as_ref()
        .ok()
        .and_then(|a| a.as_ref())
        .map(|a| {
            a.variants
                .iter()
                .map(|v| format!("{}/{}", input.rel_dir, v.poc))
                .collect()
        })
        .unwrap_or_default();
    let (variant, untested_paths) =
        arms::variant_arm(&log, &layout, attack, command, variant_minimum, &fix_dir);
    claim.suspect = variant.state == ArmState::Fail;
    let (root_cause, symptom_patch) =
        arms::root_cause_arm(&shape, &input.confirmed.finding, &claim);
    let recheck = arms::read_json::<arms::Recheck>(&fix_dir.join("recheck.json"));
    let relocation = arms::relocation_arm(&log, &layout, &recheck);
    let functionality =
        arms::functionality_arm(&log, &layout, &recheck, &shape, input.functionality);
    let class_open_sites = arms::class_report(&recheck, input.target);

    if input.target_modified {
        reasons.push("the target tree changed during the fix step".to_string());
    }
    let mut labels = Vec::new();
    if symptom_patch {
        labels.push("symptom_patch");
    }
    if claim.evidence_state == arms::ClaimEvidence::AssertedOnly {
        labels.push("asserted_only_root_cause");
    }
    if claim.suspect {
        labels.push("root_cause_suspect");
    }
    if functionality
        .reasons
        .iter()
        .any(|r| r.starts_with("functionality unverified"))
    {
        labels.push("functionality_unverified");
    }
    let reproduction_passed = reproduction.arm.state == ArmState::Pass;
    let arms_list = vec![
        reproduction.arm,
        variant,
        root_cause,
        relocation,
        functionality,
    ];
    let failed: Vec<&ArmResult> = arms_list
        .iter()
        .filter(|a| a.state == ArmState::Fail)
        .collect();
    let verdict = if !failed.is_empty() {
        for a in &failed {
            reasons.push(format!("{} arm failed: {}", a.arm, a.reasons.join("; ")));
        }
        Verdict::Rejected
    } else if !reproduction_passed || !reasons.is_empty() {
        if !reproduction_passed {
            reasons.push("the reproduction arm did not pass".to_string());
        }
        Verdict::Inconclusive
    } else {
        Verdict::CandidateFix
    };
    let exists = |name: &str| {
        fix_dir
            .join(name)
            .is_file()
            .then(|| format!("{}/{name}", input.rel_dir))
    };
    FixOutcome {
        stable_id: input.confirmed.stable_id.clone(),
        dir: input.rel_dir.to_string(),
        verdict,
        label: (verdict == Verdict::CandidateFix).then_some(CANDIDATE_LABEL),
        reasons,
        labels,
        arms: arms_list,
        fix_locality: locality,
        variant_minimum,
        root_cause_claim: claim,
        untested_paths,
        class_open_sites,
        patch: PatchInfo {
            path: format!("{}/fix.patch", input.rel_dir),
            sha256,
            source: if input.supplied_sha256.is_some() {
                PatchSource::Supplied
            } else {
                PatchSource::Lyrik
            },
            test_files: shape.test_files().iter().map(|s| s.to_string()).collect(),
            dependency_manifests: shape
                .dependency_manifests()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            files: shape.files,
        },
        fix_model: input.fix_model.to_string(),
        artifacts: Artifacts {
            apply_script: format!("{}/apply.sh", input.rel_dir),
            reproduction_command: command.to_string(),
            reproduction_harness: input.confirmed.reproduction.harness.clone(),
            variants: variant_files,
            attack: exists("attack.json"),
            recheck: exists("recheck.json"),
            observed: format!("{}/observed.json", input.rel_dir),
        },
    }
}

/// Save the `exec` results that ran under a fix directory beside the
/// patch, so a maintainer can read what each arm saw and run it again.
pub fn save_observed(fix_dir: &Path, layout: &Layout, observed: &[Observed]) -> Result<()> {
    let mine: Vec<&Observed> = observed
        .iter()
        .filter(|o| o.command.contains(&layout.dir))
        .collect();
    let dest = fix_dir.join("observed.json");
    std::fs::write(&dest, serde_json::to_string_pretty(&mine)?)
        .with_context(|| format!("write {}", dest.display()))
}

/// `apply.sh` for the operator, written by the runner.
pub fn write_apply_script(fix_dir: &Path) -> Result<()> {
    let dest = fix_dir.join("apply.sh");
    std::fs::write(
        &dest,
        "#!/bin/sh\n# Run from the project root.\nset -e\nhere=$(dirname \"$0\")\n\
         git apply --check \"$here/fix.patch\"\ngit apply \"$here/fix.patch\"\n",
    )
    .with_context(|| format!("write {}", dest.display()))
}

/// The run's counts: fixes by verdict and by each arm's outcome.
pub fn summary(outcomes: &[FixOutcome]) -> Value {
    let mut verdicts: BTreeMap<&str, usize> = BTreeMap::new();
    for o in outcomes {
        let key = match o.verdict {
            Verdict::CandidateFix => "candidate_fix",
            Verdict::Rejected => "rejected",
            Verdict::Inconclusive => "inconclusive",
        };
        *verdicts.entry(key).or_default() += 1;
    }
    serde_json::json!({
        "fixes": outcomes.len(),
        "by_verdict": verdicts,
        "by_arm": arms::count_by_arm(outcomes.iter().flat_map(|o| o.arms.iter())),
    })
}

/// One line for the terminal from [`summary`].
pub fn summary_line(summary: &Value) -> String {
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let by_verdict = &summary["by_verdict"];
    let mut line = format!(
        "{} candidate, {} rejected, {} inconclusive",
        n(by_verdict, "candidate_fix"),
        n(by_verdict, "rejected"),
        n(by_verdict, "inconclusive")
    );
    if let Some(by_arm) = summary["by_arm"].as_object() {
        for (arm, states) in by_arm {
            line.push_str(&format!(
                "; {arm} {}/{}/{}/{}",
                n(states, "pass"),
                n(states, "fail"),
                n(states, "inconclusive"),
                n(states, "not_run")
            ));
        }
        if !by_arm.is_empty() {
            line.push_str(" (pass/fail/inconclusive/not_run)");
        }
    }
    line
}

/// Add `fixes` and `fix_summary` to a written `findings.json`.
pub fn record_fixes(dest: &Path, outcomes: &[FixOutcome]) -> Result<()> {
    let body = std::fs::read_to_string(dest).with_context(|| format!("read {}", dest.display()))?;
    let mut body: Value =
        serde_json::from_str(&body).with_context(|| format!("parse {}", dest.display()))?;
    body["fixes"] = serde_json::to_value(outcomes)?;
    body["fix_summary"] = summary(outcomes);
    std::fs::write(dest, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", dest.display()))?;
    Ok(())
}

/// Append one line per failed arm of each rejected fix to the
/// rejections log: the finding, the arm and the reason.
pub fn log_rejections(log_path: &Path, outcomes: &[FixOutcome]) -> Result<usize> {
    use std::io::Write;
    let mut lines = String::new();
    let mut count = 0;
    for o in outcomes.iter().filter(|o| o.verdict == Verdict::Rejected) {
        for a in o.arms.iter().filter(|a| a.state == ArmState::Fail) {
            let line = serde_json::json!({
                "kind": "fix",
                "stable_id": o.stable_id,
                "arm": a.arm,
                "basis": a.basis,
                "reason": a.reasons.join("; "),
                "patch": o.patch.path,
                "applied_by": "fix",
            });
            lines.push_str(&serde_json::to_string(&line)?);
            lines.push('\n');
            count += 1;
        }
    }
    if count > 0 {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .and_then(|mut f| f.write_all(lines.as_bytes()))
            .with_context(|| format!("append to {}", log_path.display()))?;
    }
    Ok(count)
}

/// The functionality commands `.lyrik/config.json` names under `fix`.
pub fn functionality_config(config: &Value) -> FunctionalityConfig {
    let get = |key: &str| {
        config
            .get("fix")
            .and_then(|f| f.get(key))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    FunctionalityConfig {
        test_command: get("test_command"),
        coverage_command: get("coverage_command"),
    }
}

fn frontmatter(name: &str, description: &str, run_id: &str, tools: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: {description}\n\
         disable-model-invocation: true\npermissions:\n  tools:\n    allow: [{tools}]\n  egress:\n    \
         mode: deny\n  filesystem:\n    read_paths: [\"<workspace>\"]\n    write_paths: \
         [\"<workspace>/.lyrik/state/runs/{run_id}\"]\n  inference:\n    allow: [\"*\"]\n---\n\n"
    )
}

/// What every fix-step skill says about commands and verdicts.
const NO_VERDICT: &str = "You decide nothing. The runner reads each command's exit status and \
     output from its own log of what `exec` ran, for exactly the command strings the prompt \
     gives or the ones this text tells you to compose. It does not read your account of a \
     run, so do not write one. Run each such command through `exec` once, exactly as \
     written, one command per call, in the order given. Do not repair, wrap or repeat a \
     command: a second run with a different result makes the arm inconclusive. The operator \
     is asked before each command; a refused command is a step not taken, and you carry on \
     with the next. You write only under the fix directory, and never into the project's \
     tree: not a source file, not a test, not a build artifact.";

/// The contract a command that shows a defect follows.
fn poc_contract() -> String {
    format!(
        "A proof of concept follows one contract. It prints `{}` on a line of its own, \
         flushed, immediately before its assertion; it exits non-zero when the defect shows \
         and zero when it does not. It prints the line only once the code under test has \
         run and returned what the assertion reads: a harness that could not build or call \
         that code exits non-zero without printing it. The same command string runs \
         unchanged in each copy, \
         from the copy's root, so it must not name a copy (`baseline`, `patched`, \
         `reverted`) and must not look at which copy it is in. A run with no `{}` line is \
         read as a harness that never reached its assertion, whatever it exited with.",
        arms::REACHED,
        arms::REACHED
    )
}

/// The staged skill the fix agent runs under. Written by this crate.
pub fn fix_skill_text(run_id: &str, tools: &str) -> String {
    format!(
        "{}# Fix\n\n\
         You are given one confirmed finding, the invariant it names, where the walks place \
         the origin of the violation, and the reproduction that showed it. Produce a patch \
         that restores the invariant, then run the commands the prompt lists.\n\n\
         {NO_VERDICT}\n\n\
         The patch targets the invariant at its origin, not the input and not the place the \
         failure surfaces. A check that rejects the one reproduction's bytes, a guard at the \
         crash site while the bad value is produced elsewhere, or deleting the operation \
         that fails, is not a fix: the property named as the invariant must hold for every \
         input and every caller the code path admits. Keep the patch to that mechanism: no \
         refactors, no renames, no new dependency, no edits to tests, no changes to code the \
         invariant does not touch. If the finding's root-cause claim looks wrong against the \
         code you read, say so in `notes.md` in the fix directory and patch what the code \
         shows.\n\n\
         Steps, in order:\n\n\
         1. Read the code the finding and its origin point at, and the reproduction.\n\
         2. Run the three extraction commands from the prompt.\n\
         3. Write the patch as a unified diff with `a/` and `b/` prefixes to `fix.patch` in \
         the fix directory. If the prompt says a patch was supplied, it is already there: \
         do not edit it. You may check the patch with \
         `git apply --check --directory=<fix-dir>/patched <fix-dir>/fix.patch` and rewrite it \
         until that \
         is clean; do this before the first apply command, never after.\n\
         4. Run the remaining commands from the prompt, in order.\n\n\
         Your reply is one sentence saying the commands were run.\n",
        frontmatter(
            "fix",
            "Write a candidate fix for one confirmed finding and run its reproduction in three copies",
            run_id,
            tools
        )
    )
}

/// The staged skill the variant agent runs under.
pub fn attack_skill_text(run_id: &str, tools: &str) -> String {
    format!(
        "{}# Fix attack\n\n\
         A patch has been written for one confirmed finding. You did not write it and you \
         have a fresh context. Your job is to reach the same sink, or violate the same \
         invariant, by a route the patch may not cover.\n\n\
         {NO_VERDICT}\n\n\
         {}\n\n\
         Steps, in order:\n\n\
         1. Read the finding, the patch, and the `graph-walk` and `chain-walk` entries under \
         `step_records` in the run's `findings.json`. From the code in the `baseline` copy, \
         list every caller and path that reaches the same sink or bears on the same \
         invariant: sibling call sites, alternate entry points, callbacks, cleanup, \
         teardown and error paths, other input shapes. Each is one entry of `paths`.\n\
         2. For at least the number of paths the prompt names, each by a different route \
         from the original reproduction and from each other (another caller, another input \
         shape, a cleanup or error path), write a proof of concept under \
         `variants/<id>/` in the fix directory. Derive each from the root cause. Changing \
         only a literal, a file name or a size is not another route unless that boundary \
         is the invariant.\n\
         3. For each variant run `cd <fix-dir>/baseline && <command>` and then \
         `cd <fix-dir>/patched && <command>`, with `<fix-dir>` exactly as the prompt gives \
         it and `<command>` exactly as you record it.\n\
         4. Write `attack.json` in the fix directory: `paths`, a list of \
         `{{\"id\", \"route\", \"location\", \"description\"}}` with `route` one of `caller`, \
         `input_shape`, `cleanup`, `error_path`, `other` and `location` as `file:line`; and \
         `variants`, a list of `{{\"id\", \"path\", \"poc\", \"command\"}}` with `path` the id of \
         the path it goes through, `poc` the file relative to the fix directory and \
         `command` the command as run from a copy's root. List every path you found, \
         including those you wrote nothing for: a path with no attempt is reported as \
         untested.\n\n\
         Do not edit the copies' source or the patch. Your reply is one sentence saying \
         `attack.json` was written.\n",
        frontmatter(
            "fix-attack",
            "List the other paths to a patched finding's sink and write a proof of concept for some",
            run_id,
            tools
        ),
        poc_contract()
    )
}

/// The staged skill the recheck agent runs under.
pub fn recheck_skill_text(run_id: &str, tools: &str) -> String {
    format!(
        "{}# Fix recheck\n\n\
         A patch has been written for one confirmed finding. You did not write it and you \
         have a fresh context. You look at what the patch did to the code around it.\n\n\
         {NO_VERDICT}\n\n\
         {}\n\n\
         Steps, in order:\n\n\
         1. Regression and relocation. Read the staged `invariant-walk` and \
         `differential-walk` texts under `.lyrik/state/runs/<run-id>/walks-skills/`, where \
         the run staged them, and apply their method to everything reachable from the \
         functions the patch changes, in the `patched` copy against the `baseline` copy: \
         their callees, the callbacks they register, their cleanup and error paths, and the \
         callers that rely on what changed. Not only the patched lines. Look for the \
         violation moved rather than removed, for example into a callback or a second \
         pointer, and for a new one. `scope` lists what you walked as `function at \
         file:line`. Each candidate is `{{\"title\", \"location\", \"kind\"}}` with `kind` \
         `new` or `relocated` and `location` as `file:line` in the patched copy. If the \
         project has a fuzz harness that reaches the patched functions, give a bounded \
         command for it, fixed seed and fixed run count, under the contract above, and run \
         `cd <fix-dir>/patched && <command>`.\n\
         2. Functionality. Use the test command the prompt gives; if it gives none, the \
         project's own, the narrowest that exercises the patched files. Run \
         `cd <fix-dir>/baseline && <command>` and then `cd <fix-dir>/patched && <command>`. \
         If the prompt gives a coverage command, or the project has coverage tooling, run \
         `cd <fix-dir>/patched && <coverage command>`; its output must list each file with \
         a percentage. Then write a benign-input harness under `benign/` in the fix \
         directory: inputs the code accepted before the patch and must still accept, sent \
         through the patched functions. It prints the marker line, then each input's output \
         and observable state, with nothing that varies between runs (no times, addresses, \
         random ids or unordered listings), and exits zero. Run it in the `baseline` copy \
         twice and in the `patched` copy once.\n\
         3. Class. List the other sites in the project where the same invariant pattern \
         appears: `{{\"file\", \"line\", \"quote\", \"guarded\"}}`, with `file` relative to the \
         project root, `quote` the line at that site copied exactly, and `guarded` whether \
         the invariant is enforced there. The patch closes one instance; this list is what \
         it leaves.\n\
         4. Write `recheck.json` in the fix directory: `relocation` with `scope`, \
         `candidates` and, when there is one, `fuzz` as `{{\"command\"}}`; `functionality` \
         with `suite`, `coverage` and `benign`, each `{{\"command\"}}` or absent, the command \
         as run from a copy's root; and `class_sites`.\n\n\
         Do not edit the copies' source or the patch. Your reply is one sentence saying \
         `recheck.json` was written.\n",
        frontmatter(
            "fix-recheck",
            "Re-walk the code a patch reaches, run the tests and a benign-input differential, list the class",
            run_id,
            tools
        ),
        poc_contract()
    )
}

/// The text of one of [`FIX_SKILLS`].
pub fn skill_text(name: &str, run_id: &str, tools: &str) -> String {
    match name {
        "fix" => fix_skill_text(run_id, tools),
        "fix-attack" => attack_skill_text(run_id, tools),
        _ => recheck_skill_text(run_id, tools),
    }
}

fn finding_brief(confirmed: &Confirmed) -> String {
    let mut finding = serde_json::Map::new();
    for key in [
        "stable_id",
        "title",
        "summary",
        "location",
        "origin",
        "framing",
        "tier",
        "threat_model",
        "invariant",
    ] {
        if let Some(v) = confirmed.finding.get(key) {
            finding.insert(key.to_string(), v.clone());
        }
    }
    serde_json::to_string_pretty(&Value::Object(finding)).unwrap_or_default()
}

/// The commands the reproduction arm reads, in the order they run.
pub fn reproduction_commands(layout: &Layout, command: &str, revision: &str) -> Vec<String> {
    let mut out: Vec<String> = arms::SIDES
        .iter()
        .map(|side| layout.extract(side, revision))
        .collect();
    out.push(layout.apply("patched"));
    out.push(layout.apply("reverted"));
    out.push(layout.revert());
    out.push(layout.diff());
    for side in arms::SIDES {
        out.push(layout.in_copy(side, command));
    }
    out
}

fn numbered(commands: &[String]) -> String {
    commands
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{}. `{c}`", i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The prompt the fix agent receives: the finding, its invariant and
/// origin, the reproduction, and the commands to run.
pub fn build_fix_prompt(
    confirmed: &Confirmed,
    run_id: &str,
    revision: &str,
    fix_dir_rel: &str,
    supplied: bool,
) -> String {
    let layout = Layout::new(run_id, fix_dir_rel);
    let invariant = confirmed
        .finding
        .get("invariant")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("Invariant: {s}"))
        .unwrap_or_else(|| {
            "Invariant: the finding names none; write it in `notes.md` from the code and the \
             finding, as the property the patch restores."
                .to_string()
        });
    let origin = if arms::site(&confirmed.finding, "origin").is_some() {
        "The finding's `origin` is where the walks place the start of the violation. It is \
         their claim, not an established fact."
    } else {
        "The finding records no `origin`: find where the violation starts before patching."
    };
    let patch = if supplied {
        "A patch was supplied for this finding and is at `fix.patch` in the fix directory. \
         Do not write or edit a patch."
    } else {
        "Write the patch to `fix.patch` in the fix directory."
    };
    let commands = reproduction_commands(&layout, &confirmed.reproduction.command, revision);
    format!(
        "/fix Write a candidate fix for this confirmed finding. Run-id: `{run_id}`. \
         Code revision: `{revision}`. Fix directory: `{}`. {invariant} {origin} {patch}\n\n\
         Commands, in this order, each exactly as written. The first three before the \
         patch, the rest after it:\n\n{}\n\n\
         Finding:\n```json\n{}\n```\n\n\
         Reproduction:\n```json\n{}\n```",
        layout.dir,
        numbered(&commands),
        finding_brief(confirmed),
        serde_json::to_string_pretty(&confirmed.reproduction).unwrap_or_default()
    )
}

/// The prompt the variant agent receives.
pub fn build_attack_prompt(
    confirmed: &Confirmed,
    run_id: &str,
    fix_dir_rel: &str,
    minimum: usize,
) -> String {
    let layout = Layout::new(run_id, fix_dir_rel);
    format!(
        "/fix-attack Find other routes to this patched finding. Run-id: `{run_id}`. Fix \
         directory: `{0}`. The patch is `{0}/fix.patch`; the copies are `{0}/baseline` and \
         `{0}/patched`. Step records are in `.lyrik/state/runs/{run_id}/findings.json`. \
         Write a proof of concept for at least {minimum} paths by different routes. The \
         original reproduction's command is `{1}`; a variant is not that command.\n\n\
         Finding:\n```json\n{2}\n```",
        layout.dir,
        confirmed.reproduction.command,
        finding_brief(confirmed)
    )
}

/// The prompt the recheck agent receives.
pub fn build_recheck_prompt(
    confirmed: &Confirmed,
    run_id: &str,
    fix_dir_rel: &str,
    functionality: &FunctionalityConfig,
    benign_required: bool,
) -> String {
    let layout = Layout::new(run_id, fix_dir_rel);
    let named = |what: &str, cmd: &Option<String>| match cmd {
        Some(c) => format!("The {what} command is `{c}`; use it as given."),
        None => format!("The run's configuration names no {what} command."),
    };
    let benign = if benign_required {
        "The patch is cross-cutting: the benign-input differential is required."
    } else {
        ""
    };
    format!(
        "/fix-recheck Recheck the code around this patched finding. Run-id: `{run_id}`. Fix \
         directory: `{0}`. The patch is `{0}/fix.patch`; the copies are `{0}/baseline` and \
         `{0}/patched`. {1} {2} {benign}\n\n\
         Finding:\n```json\n{3}\n```",
        layout.dir,
        named("test", &functionality.test_command),
        named("coverage", &functionality.coverage_command),
        finding_brief(confirmed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const REV: &str = "abc";
    const RUN: &str = "sample/run-001";
    const REL: &str = "staging/fix/auth-src-a.rs-10";
    const REPRO: &str = "python3 .lyrik/state/runs/sample/run-001/staging/fuzz-walk/harness/p.py";

    fn body() -> Value {
        serde_json::json!({
            "findings": [
                {"stable_id": "auth::src/a.rs:10", "title": "t", "summary": "s",
                 "location": {"file": "src/a.rs", "line_start": 10},
                 "origin": {"file": "src/len.rs", "line_start": 4, "function": "decode_len"},
                 "invariant": "len is bounded"},
                {"stable_id": "auth::src/b.rs:5", "title": "u", "summary": "v",
                 "location": {"file": "src/b.rs", "line_start": 5}}
            ],
            "reproductions": [
                {"walk": "fuzz-walk", "file": "repro-001.json", "stable_id": "auth::src/a.rs:10",
                 "command": REPRO, "expected": "fails", "observed": "failed",
                 "outcome": "reproduced", "code_revision": "abc",
                 "replay": {"command_run": REPRO, "observed": "failed", "outcome": "reproduced"},
                 "agreement": true},
                {"walk": "fuzz-walk", "file": "repro-002.json", "stable_id": "auth::src/b.rs:5",
                 "command": "cargo test -p x two", "expected": "fails", "observed": "failed",
                 "outcome": "reproduced", "code_revision": "abc",
                 "replay": {"command_run": "cargo test -p x two", "observed": "passed", "outcome": "not_reproduced"},
                 "agreement": false}
            ]
        })
    }

    const ORIGIN_PATCH: &str = "--- a/src/len.rs\n+++ b/src/len.rs\n\
        @@ -2,5 +2,7 @@ fn decode_len(b: &[u8]) {\n ctx\n+check\n ctx\n";
    const SINK_PATCH: &str = "--- a/src/a.rs\n+++ b/src/a.rs\n\
        @@ -8,5 +8,7 @@ fn read(b: &[u8]) {\n ctx\n+guard\n ctx\n";

    fn shown() -> String {
        format!("{}\npanic in decode_len at src/len.rs:4", arms::REACHED)
    }

    fn clean() -> String {
        format!("{}\nok", arms::REACHED)
    }

    /// A run directory holding `patch`, and the observed runs of a
    /// reproduction that shows the defect, stops, and shows it again.
    struct Case {
        tmp: tempfile::TempDir,
        observed: Vec<Observed>,
        confirmed: Confirmed,
    }

    impl Case {
        fn new(patch: &str) -> Self {
            let tmp = tempdir().unwrap();
            let dir = tmp.path().join(REL);
            std::fs::create_dir_all(dir.join("variants")).unwrap();
            if !patch.is_empty() {
                std::fs::write(dir.join("fix.patch"), patch).unwrap();
            }
            let confirmed = confirmed_findings(&body()).remove(0);
            let layout = Layout::new(RUN, REL);
            let mut case = Self {
                tmp,
                observed: Vec::new(),
                confirmed,
            };
            for c in reproduction_commands(&layout, REPRO, REV) {
                let (ok, out) = if c == layout.in_copy("patched", REPRO) {
                    (true, clean())
                } else if c.ends_with("p.py") {
                    (false, shown())
                } else {
                    (true, "(no output)".to_string())
                };
                case.add(c, ok, &out);
            }
            case
        }

        fn add(&mut self, command: String, success: bool, output: &str) {
            self.observed.push(Observed {
                seq: self.observed.len(),
                command,
                success,
                output: output.to_string(),
            });
        }

        /// Two variants by different paths; the second holds or not.
        fn with_variants(mut self, second_shown_on_patched: bool) -> Self {
            let layout = Layout::new(RUN, REL);
            let dir = self.tmp.path().join(REL);
            for (id, patched_shown) in [("v1", false), ("v2", second_shown_on_patched)] {
                std::fs::write(dir.join(format!("variants/{id}.py")), "x").unwrap();
                let cmd = format!("python3 ../variants/{id}.py");
                self.add(layout.in_copy("baseline", &cmd), false, &shown());
                let out = if patched_shown { shown() } else { clean() };
                self.add(layout.in_copy("patched", &cmd), !patched_shown, &out);
            }
            std::fs::write(
                dir.join("attack.json"),
                r#"{"paths":[{"id":"p1","route":"caller","location":"src/c.rs:3"},
                             {"id":"p2","route":"error_path","location":"src/d.rs:9"},
                             {"id":"p3","route":"cleanup","location":"src/e.rs:2"}],
                    "variants":[{"id":"v1","path":"p1","poc":"variants/v1.py","command":"python3 ../variants/v1.py"},
                                {"id":"v2","path":"p2","poc":"variants/v2.py","command":"python3 ../variants/v2.py"}]}"#,
            )
            .unwrap();
            self
        }

        fn judge(&self) -> FixOutcome {
            self.judge_with(false, None)
        }

        fn judge_with(&self, target_modified: bool, supplied: Option<&str>) -> FixOutcome {
            judge(&JudgeInput {
                run_dir: self.tmp.path(),
                rel_dir: REL,
                run_id: RUN,
                confirmed: &self.confirmed,
                revision: REV,
                observed: &self.observed,
                target: self.tmp.path(),
                target_modified,
                fix_model: "some-model",
                supplied_sha256: supplied,
                functionality: &FunctionalityConfig::default(),
            })
        }
    }

    fn arm<'a>(out: &'a FixOutcome, name: &str) -> &'a ArmResult {
        out.arms.iter().find(|a| a.arm == name).unwrap()
    }

    #[test]
    fn only_a_kept_finding_with_an_agreed_reproduction_is_confirmed() {
        let c = confirmed_findings(&body());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].stable_id, "auth::src/a.rs:10");
        assert_eq!(c[0].reproduction.command, REPRO);
    }

    #[test]
    fn slugs_keep_only_safe_bytes() {
        assert_eq!(slug("auth::src/a.rs:10"), "auth-src-a.rs-10");
        assert_eq!(slug("::/x//"), "x");
    }

    #[test]
    fn a_fix_no_arm_failed_is_a_candidate_fix_with_every_arm_listed() {
        let out = Case::new(ORIGIN_PATCH).with_variants(false).judge();
        assert_eq!(out.verdict, Verdict::CandidateFix, "{:?}", out.reasons);
        assert_eq!(out.label, Some("candidate fix"));
        let names: Vec<&str> = out.arms.iter().map(|a| a.arm).collect();
        assert_eq!(
            names,
            [
                "reproduction",
                "variant",
                "root_cause",
                "relocation",
                "functionality"
            ]
        );
        assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
        assert_eq!(arm(&out, "variant").state, ArmState::Pass);
        // The baseline output names the origin: the claim is confirmed.
        assert_eq!(arm(&out, "root_cause").state, ArmState::Pass);
        // Arms that did not run are listed as such, not as passes.
        assert_eq!(arm(&out, "relocation").state, ArmState::NotRun);
        assert_eq!(arm(&out, "functionality").state, ArmState::NotRun);
        assert_eq!(out.fix_locality, Some(Locality::Localized));
        assert_eq!(out.variant_minimum, 2);
        assert_eq!(out.untested_paths.len(), 1);
        assert_eq!(out.untested_paths[0].id, "p3");
        assert!(!out.class_open_sites.listed);
        assert_eq!(out.fix_model, "some-model");
        assert_eq!(out.patch.source, PatchSource::Lyrik);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["verdict"], "candidate_fix");
        assert_eq!(v["arms"][0]["basis"], "executed");
        assert_eq!(v["arms"][3]["state"], "not_run");
        assert!(v["arms"][3].get("basis").is_none());
        assert_eq!(
            v["root_cause_claim"]["evidence_state"],
            "confirmed_by_executed_poc"
        );
        assert_eq!(
            v["artifacts"]["variants"][0],
            format!("{REL}/variants/v1.py")
        );
        let text = v.to_string();
        assert!(
            !text.contains("\"fixed\"") && !text.contains("\"verified\""),
            "{text}"
        );
    }

    #[test]
    fn a_working_variant_rejects_the_fix_and_marks_the_root_cause_suspect() {
        let out = Case::new(ORIGIN_PATCH).with_variants(true).judge();
        assert_eq!(out.verdict, Verdict::Rejected);
        assert_eq!(out.label, None);
        assert!(out.root_cause_claim.suspect);
        assert!(out.labels.contains(&"root_cause_suspect"));
        assert!(
            out.reasons[0].starts_with("variant arm failed: variant v2: shows the defect"),
            "{:?}",
            out.reasons
        );
    }

    #[test]
    fn a_symptom_patch_is_rejected_though_the_reproduction_stops() {
        let out = Case::new(SINK_PATCH).with_variants(false).judge();
        assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(out.labels.contains(&"symptom_patch"));
        assert!(out.reasons[0].starts_with("root_cause arm failed: symptom_patch:"));
    }

    #[test]
    fn a_fix_built_on_an_asserted_claim_is_labelled_so() {
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        // The baseline output no longer names the origin.
        let baseline = Layout::new(RUN, REL).in_copy("baseline", REPRO);
        for o in case.observed.iter_mut().filter(|o| o.command == baseline) {
            o.output = format!("{}\nboom", arms::REACHED);
        }
        let out = case.judge();
        assert_eq!(out.verdict, Verdict::CandidateFix);
        assert!(out.labels.contains(&"asserted_only_root_cause"));
        assert_eq!(arm(&out, "root_cause").state, ArmState::Inconclusive);
    }

    #[test]
    fn nothing_less_than_an_observed_reproduction_arm_is_a_candidate() {
        // No runs observed: whatever the agent wrote, nothing is a pass.
        let mut case = Case::new(ORIGIN_PATCH);
        case.observed.clear();
        std::fs::write(
            case.tmp.path().join(REL).join("proof.json"),
            r#"{"arms":{"baseline":"fails","patched":"passes","reverted":"fails"}}"#,
        )
        .unwrap();
        let out = case.judge();
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert!(out.arms.iter().all(|a| a.state != ArmState::Pass));
        assert_eq!(arm(&out, "reproduction").state, ArmState::NotRun);
        // No patch.
        let out = Case::new("").judge();
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.reasons[0], "fix.patch is missing or holds no hunk");
        assert_eq!(out.fix_locality, None);
        // Target modified during the step.
        let out = Case::new(ORIGIN_PATCH).judge_with(true, None);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert!(
            out.reasons
                .contains(&"the target tree changed during the fix step".to_string())
        );
    }

    #[test]
    fn a_supplied_patch_runs_the_same_arms_and_earns_nothing_by_its_source() {
        // A reference fix that is a symptom patch is rejected like any other.
        let case = Case::new(SINK_PATCH).with_variants(false);
        let digest = sha256_hex(SINK_PATCH.as_bytes());
        let out = case.judge_with(false, Some(&digest));
        assert_eq!(out.patch.source, PatchSource::Supplied);
        assert_eq!(out.patch.sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(out.verdict, Verdict::Rejected);
        // A supplied patch that was edited during the step.
        let out = case.judge_with(false, Some("00"));
        assert!(
            out.reasons
                .contains(&"the supplied patch was changed during the fix step".to_string())
        );
    }

    #[test]
    fn a_cross_cutting_patch_needs_four_variants() {
        let patch = format!("{ORIGIN_PATCH}{SINK_PATCH}");
        let out = Case::new(&patch).with_variants(false).judge();
        assert_eq!(out.fix_locality, Some(Locality::CrossCutting));
        assert_eq!(out.variant_minimum, 4);
        assert_eq!(arm(&out, "variant").state, ArmState::Inconclusive);
        assert_eq!(out.patch.files, ["src/len.rs", "src/a.rs"]);
        // The script is not withheld: the fix is still a candidate.
        assert_eq!(out.verdict, Verdict::CandidateFix);
    }

    #[test]
    fn fixes_the_summary_and_the_rejections_are_written() {
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("findings.json");
        std::fs::write(&dest, r#"{"schema_version":"1.1","findings":[]}"#).unwrap();
        let outcomes = [
            Case::new(ORIGIN_PATCH).with_variants(false).judge(),
            Case::new(ORIGIN_PATCH).with_variants(true).judge(),
            Case::new("").judge(),
        ];
        record_fixes(&dest, &outcomes).unwrap();
        let body: Value = serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(body["schema_version"], "1.1");
        assert_eq!(body["fixes"][0]["stable_id"], "auth::src/a.rs:10");
        assert_eq!(body["fixes"][1]["verdict"], "rejected");
        let s = &body["fix_summary"];
        assert_eq!(s["fixes"], 3);
        assert_eq!(s["by_verdict"]["candidate_fix"], 1);
        assert_eq!(s["by_verdict"]["rejected"], 1);
        assert_eq!(s["by_verdict"]["inconclusive"], 1);
        assert_eq!(s["by_arm"]["variant"]["pass"], 1);
        assert_eq!(s["by_arm"]["variant"]["fail"], 1);
        assert_eq!(s["by_arm"]["variant"]["not_run"], 1);
        assert!(
            summary_line(s).starts_with("1 candidate, 1 rejected, 1 inconclusive; "),
            "{}",
            summary_line(s)
        );
        // One line per failed arm, appended after what is there.
        let log = tmp.path().join("rejections.jsonl");
        std::fs::write(&log, "{\"rule\":1,\"reason\":\"r\",\"applied_by\":\"x\"}\n").unwrap();
        assert_eq!(log_rejections(&log, &outcomes).unwrap(), 1);
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let line: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(line["kind"], "fix");
        assert_eq!(line["arm"], "variant");
        assert_eq!(line["stable_id"], "auth::src/a.rs:10");
        assert!(line["reason"].as_str().unwrap().contains("variant v2"));
    }

    #[test]
    fn observed_runs_are_saved_beside_the_patch() {
        let case = Case::new(ORIGIN_PATCH);
        let dir = case.tmp.path().join(REL);
        let mut observed = case.observed.clone();
        observed.push(Observed {
            seq: observed.len(),
            command: "git log".into(),
            success: true,
            output: "x".into(),
        });
        save_observed(&dir, &Layout::new(RUN, REL), &observed).unwrap();
        let saved: Vec<Observed> =
            serde_json::from_str(&std::fs::read_to_string(dir.join("observed.json")).unwrap())
                .unwrap();
        assert_eq!(saved.len(), case.observed.len());
        write_apply_script(&dir).unwrap();
        assert!(
            std::fs::read_to_string(dir.join("apply.sh"))
                .unwrap()
                .contains("git apply --check")
        );
    }

    #[test]
    fn the_configuration_names_the_functionality_commands() {
        let c = functionality_config(&serde_json::json!({
            "fix": {"test_command": " cargo test ", "coverage_command": ""}
        }));
        assert_eq!(c.test_command.as_deref(), Some("cargo test"));
        assert_eq!(c.coverage_command, None);
        assert_eq!(
            functionality_config(&serde_json::json!({})),
            FunctionalityConfig::default()
        );
    }

    #[test]
    fn the_prompts_carry_the_exact_commands_the_arms_read() {
        let c = confirmed_findings(&body()).remove(0);
        let layout = Layout::new(RUN, REL);
        let p = build_fix_prompt(&c, RUN, REV, REL, false);
        assert!(p.starts_with("/fix "), "{p}");
        assert!(p.contains("Invariant: len is bounded"), "{p}");
        assert!(p.contains("Code revision: `abc`"), "{p}");
        assert!(p.contains("\"origin\""), "{p}");
        for command in reproduction_commands(&layout, REPRO, REV) {
            assert!(p.contains(&format!("`{command}`")), "{command} in {p}");
        }
        assert!(p.contains("Write the patch to `fix.patch`"), "{p}");
        let supplied = build_fix_prompt(&c, RUN, REV, REL, true);
        assert!(
            supplied.contains("Do not write or edit a patch"),
            "{supplied}"
        );
        let a = build_attack_prompt(&c, RUN, REL, 4);
        assert!(a.starts_with("/fix-attack "), "{a}");
        assert!(a.contains("at least 4 paths"), "{a}");
        assert!(a.contains(&layout.dir), "{a}");
        let config = FunctionalityConfig {
            test_command: Some("make check".into()),
            coverage_command: None,
        };
        let r = build_recheck_prompt(&c, RUN, REL, &config, true);
        assert!(r.starts_with("/fix-recheck "), "{r}");
        assert!(r.contains("The test command is `make check`"), "{r}");
        assert!(r.contains("names no coverage command"), "{r}");
        assert!(r.contains("differential is required"), "{r}");
    }

    #[test]
    fn the_skill_texts_hold_the_contract_and_ask_for_no_verdict() {
        let tools = "exec, read_file, write_file, list_files";
        for name in FIX_SKILLS {
            let text = skill_text(name, RUN, tools);
            assert!(text.starts_with(&format!("---\nname: {name}\n")), "{text}");
            assert!(text.contains("mode: deny"), "{name}");
            assert!(
                text.contains(&format!("[\"<workspace>/.lyrik/state/runs/{RUN}\"]")),
                "{name}"
            );
            assert!(text.contains("You decide nothing."), "{name}");
            assert!(!text.contains("proof.json"), "{name}");
        }
        for name in ["fix-attack", "fix-recheck"] {
            assert!(
                skill_text(name, RUN, tools).contains(arms::REACHED),
                "{name}"
            );
        }
        assert!(attack_skill_text(RUN, tools).contains("attack.json"));
        assert!(recheck_skill_text(RUN, tools).contains("class_sites"));
    }

    /// The arms over commands that really ran: a small git project with
    /// a known unbounded length, its copies made with `git archive`, the
    /// patch applied with `git apply`, and each proof of concept run by
    /// a shell. Only the agents and the gate are absent; every exit
    /// status and output the judge reads came from a process.
    #[cfg(unix)]
    mod real_runs {
        use super::*;
        use std::process::Command;

        const RUN: &str = "r1";
        const REL: &str = "staging/fix/len-a.sh-2";
        const REPRO: &str = "sh .lyrik/state/runs/r1/staging/fuzz-walk/harness/poc.sh";

        struct Project {
            tmp: tempfile::TempDir,
            observed: Vec<Observed>,
        }

        fn write(path: &Path, body: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }

        impl Project {
            fn root(&self) -> &Path {
                self.tmp.path()
            }

            fn fix_dir(&self) -> std::path::PathBuf {
                self.root().join(".lyrik/state/runs").join(RUN).join(REL)
            }

            /// Run `command` from the project root, as `exec` does, and
            /// keep what it did.
            fn exec(&mut self, command: &str) -> bool {
                let out = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .current_dir(self.root())
                    .output()
                    .expect("sh runs");
                let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
                output.push_str(&String::from_utf8_lossy(&out.stderr));
                self.observed.push(Observed {
                    seq: self.observed.len(),
                    command: command.to_string(),
                    success: out.status.success(),
                    output,
                });
                out.status.success()
            }

            fn git(&self, args: &[&str]) -> String {
                let out = Command::new("git")
                    .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
                    .args(args)
                    .current_dir(self.root())
                    .output()
                    .expect("git runs");
                assert!(out.status.success(), "git {args:?}: {out:?}");
                String::from_utf8_lossy(&out.stdout).into_owned()
            }

            /// `decode_len` in `len.sh` returns a length with no bound;
            /// `a.sh` and `b.sh` both copy that many bytes.
            fn new() -> Self {
                let p = Self {
                    tmp: tempdir().unwrap(),
                    observed: Vec::new(),
                };
                let r = p.root();
                write(
                    &r.join("len.sh"),
                    "decode_len() {\n  printf '%s' \"$1\"\n}\n",
                );
                write(
                    &r.join("a.sh"),
                    ". ./len.sh\nn=$(decode_len \"$1\")\necho \"a copies $n\"\n",
                );
                write(
                    &r.join("b.sh"),
                    ". ./len.sh\nn=$(decode_len \"$1\")\necho \"b copies $n\"\n",
                );
                write(
                    &r.join("test.sh"),
                    "[ \"$(sh a.sh 3)\" = \"a copies 3\" ] && [ \"$(sh b.sh 5)\" = \"b copies 5\" ]\n",
                );
                write(&r.join(".gitignore"), ".lyrik/state/\n");
                p.git(&["init", "-q"]);
                p.git(&["add", "."]);
                p.git(&["commit", "-q", "-m", "init"]);
                // The reproduction a walk left, under the marker contract.
                let poc = |script: &str, arg: &str| {
                    format!(
                        "out=$(sh {script} {arg}) || exit 2\necho {}\nn=${{out##* }}\n\
                         [ \"$n\" -le 8 ] || {{ echo \"decode_len in len.sh gave $n\"; exit 1; }}\n",
                        arms::REACHED
                    )
                };
                write(
                    &r.join(".lyrik/state/runs/r1/staging/fuzz-walk/harness/poc.sh"),
                    &poc("a.sh", "99"),
                );
                let fix = p.fix_dir();
                write(&fix.join("variants/v1/poc.sh"), &poc("b.sh", "99"));
                write(&fix.join("variants/v2/poc.sh"), &poc("a.sh", "0099"));
                write(
                    &fix.join("attack.json"),
                    r#"{"paths":[
                        {"id":"p1","route":"caller","location":"b.sh:2","description":"b.sh calls decode_len"},
                        {"id":"p2","route":"input_shape","location":"a.sh:2","description":"leading zeros"},
                        {"id":"p3","route":"error_path","location":"a.sh:3","description":"not attempted"}],
                      "variants":[
                        {"id":"v1","path":"p1","poc":"variants/v1/poc.sh","command":"sh ../variants/v1/poc.sh"},
                        {"id":"v2","path":"p2","poc":"variants/v2/poc.sh","command":"sh ../variants/v2/poc.sh"}]}"#,
                );
                write(
                    &fix.join("benign/run.sh"),
                    &format!("echo {}\nsh a.sh 3\nsh b.sh 5\nsh a.sh 8\n", arms::REACHED),
                );
                write(
                    &fix.join("recheck.json"),
                    r#"{"relocation":{"scope":["decode_len at len.sh:1","a.sh:2","b.sh:2"],"candidates":[]},
                        "functionality":{"suite":{"command":"sh test.sh"},"benign":{"command":"sh ../benign/run.sh"}},
                        "class_sites":[{"file":"b.sh","line":2,"quote":"n=$(decode_len \"$1\")","guarded":false},
                                       {"file":"b.sh","line":9,"quote":"no such line","guarded":false}]}"#,
                );
                p
            }

            /// Edit `file` in the tree, take the diff as the patch, and
            /// put the tree back.
            fn patch(&self, file: &str, body: &str) {
                write(&self.root().join(file), body);
                let diff = self.git(&["diff"]);
                self.git(&["checkout", "-q", "."]);
                write(&self.fix_dir().join("fix.patch"), &diff);
            }

            /// Every command the three agents would run, in order.
            fn run_all(&mut self) -> FixOutcome {
                let layout = Layout::new(RUN, REL);
                for c in reproduction_commands(&layout, REPRO, "HEAD") {
                    self.exec(&c);
                }
                for v in ["v1", "v2"] {
                    let cmd = format!("sh ../variants/{v}/poc.sh");
                    self.exec(&layout.in_copy("baseline", &cmd));
                    self.exec(&layout.in_copy("patched", &cmd));
                }
                for side in ["baseline", "patched"] {
                    self.exec(&layout.in_copy(side, "sh test.sh"));
                }
                self.exec(&layout.in_copy("baseline", "sh ../benign/run.sh"));
                self.exec(&layout.in_copy("baseline", "sh ../benign/run.sh"));
                self.exec(&layout.in_copy("patched", "sh ../benign/run.sh"));
                let finding = serde_json::json!({
                    "stable_id": "len::a.sh:2",
                    "invariant": "a copy is never longer than 8",
                    "location": {"file": "a.sh", "line_start": 2},
                    "origin": {"file": "len.sh", "line_start": 2, "function": "decode_len"}
                });
                let confirmed = Confirmed {
                    stable_id: "len::a.sh:2".into(),
                    finding,
                    reproduction: serde_json::from_value(serde_json::json!({
                        "stable_id": "len::a.sh:2", "command": REPRO, "expected": "exits 1",
                        "observed": "exit 1", "outcome": "reproduced", "code_revision": "HEAD"
                    }))
                    .unwrap(),
                };
                let run_dir = self.root().join(".lyrik/state/runs").join(RUN);
                save_observed(&self.fix_dir(), &layout, &self.observed).unwrap();
                let out = judge(&JudgeInput {
                    run_dir: &run_dir,
                    rel_dir: REL,
                    run_id: RUN,
                    confirmed: &confirmed,
                    revision: "HEAD",
                    observed: &self.observed,
                    target: self.root(),
                    target_modified: false,
                    fix_model: "none: commands run by the test",
                    supplied_sha256: None,
                    functionality: &FunctionalityConfig::default(),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                out
            }
        }

        #[test]
        fn a_fix_at_the_origin_is_a_candidate_with_its_open_arms_on_the_record() {
            let mut p = Project::new();
            p.patch(
                "len.sh",
                "decode_len() {\n  n=$1\n  [ \"$n\" -le 8 ] || n=8\n  printf '%s' \"$n\"\n}\n",
            );
            let out = p.run_all();
            assert_eq!(out.verdict, Verdict::CandidateFix, "{:?}", out.reasons);
            assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
            assert_eq!(arm(&out, "variant").state, ArmState::Pass);
            assert_eq!(arm(&out, "root_cause").state, ArmState::Pass);
            // No fuzz harness: the re-walk's silence is not a pass.
            assert_eq!(arm(&out, "relocation").state, ArmState::Inconclusive);
            // The suite is green both sides, with no coverage report.
            assert_eq!(arm(&out, "functionality").state, ArmState::Inconclusive);
            assert!(out.labels.contains(&"functionality_unverified"));
            assert_eq!(out.untested_paths.len(), 1);
            assert_eq!(out.class_open_sites.count, 1);
            assert_eq!(out.class_open_sites.unverified.len(), 1);
            assert_eq!(out.fix_locality, Some(Locality::Localized));
        }

        #[test]
        fn a_guard_at_the_sink_stops_the_reproduction_and_is_rejected() {
            let mut p = Project::new();
            p.patch(
                "a.sh",
                ". ./len.sh\nn=$(decode_len \"$1\")\n[ \"$n\" -le 8 ] || n=8\necho \"a copies $n\"\n",
            );
            let out = p.run_all();
            // The original reproduction no longer shows the defect.
            assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
            assert_eq!(out.verdict, Verdict::Rejected);
            // The other caller still does.
            assert_eq!(arm(&out, "variant").state, ArmState::Fail);
            assert_eq!(arm(&out, "root_cause").state, ArmState::Fail);
            assert!(out.labels.contains(&"symptom_patch"));
            assert!(out.root_cause_claim.suspect);
        }

        #[test]
        fn a_patch_that_breaks_the_build_is_neither_a_reproduction_nor_a_pass() {
            let mut p = Project::new();
            // A syntax error: every script that sources len.sh dies
            // before its assertion, and exits non-zero.
            p.patch("len.sh", "decode_len() {\n  printf '%s' \"$1\"\n");
            let out = p.run_all();
            assert_eq!(out.verdict, Verdict::Rejected, "{:?}", out.reasons);
            // The suite newly fails: that is attributed to the patch.
            assert_eq!(arm(&out, "functionality").state, ArmState::Fail);
            // No variant is counted as stopped by a copy that cannot run.
            assert_ne!(arm(&out, "variant").state, ArmState::Pass);
        }
    }
}
