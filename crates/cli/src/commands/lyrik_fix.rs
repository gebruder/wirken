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
//! two copies of the scanned revision. The runner then runs, itself,
//! every other confirmed reproduction of the same finding in both
//! copies: another deployment or another caller is a variant no agent
//! has to think of. The `fix-attack` agent writes proofs of concept
//! for other paths to the same sink or invariant, one directory each,
//! and the runner runs any it wrote and did not get to run. The
//! `fix-recheck` agent re-walks the code
//! reachable from the patched functions, runs the project's tests and
//! a benign-input differential, and lists the same pattern elsewhere.
//!
//! The runner composes every command the arms rest on, and judges from
//! the `exec` results the session log recorded for exactly those
//! commands. What an agent says it saw is not read. The arms and their
//! states are in [`super::lyrik_fix_arms`].
//!
//! A fix no arm failed, whose reproduction and variant arms both
//! passed, is a `candidate_fix`: never "fixed", never "verified". Each record lists
//! every arm, its state and whether it rests on executed commands or a
//! model's reading. A failed arm rejects the fix, and the rejection is
//! written to `rejections.jsonl` with the arm and the reason. A
//! rejected fix is not retried.
//!
//! Nothing is written into the target tree. Every command goes through
//! the same `exec` gate as a walk's: the operator is asked before each
//! one, an approval is a one-shot bypass that stores nothing, and a
//! refused command is an arm not run.

use std::collections::{BTreeMap, BTreeSet};
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
pub const FIX_EXEC_COMMANDS: &[&str] = &["mkdir", "git archive", "tar", "cp", "git apply", "diff"];

/// The staged skills of the fix step, in the order they run.
pub const FIX_SKILLS: [&str; 3] = ["fix", "fix-attack", "fix-recheck"];

/// Where an operator puts a patch to be checked in place of Lyrik's
/// own, relative to the target root: `<slug>.patch` per finding.
pub const SUPPLIED_PATCH_DIR: &str = ".lyrik/fix-patches";

/// Where an operator puts a reproduction for a finding:
/// `<slug>.sh` or `<slug>.py`, under the same rules as a supplied
/// patch. Read once at run start; what is there later is only compared.
pub const SUPPLIED_REPRODUCTION_DIR: &str = ".lyrik/fix-reproductions";

/// A finding the fix step takes on, with the reproduction that confirms it.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmed {
    pub stable_id: String,
    pub finding: Value,
    pub reproduction: ReproductionRecord,
    /// The finding's other reproductions the replay agreed with, each
    /// by a different command: other deployments, other callers. The
    /// runner runs each as a variant.
    pub others: Vec<ReproductionRecord>,
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
            let mut agreed = reproductions.iter().filter_map(|r| {
                if r.get("stable_id")?.as_str()? != stable_id {
                    return None;
                }
                if !r.get("agreement")?.as_bool()? {
                    return None;
                }
                let record: ReproductionRecord = serde_json::from_value(r.clone()).ok()?;
                (record.outcome == ReproductionOutcome::Reproduced).then_some(record)
            });
            let repro = agreed.next()?;
            let mut others: Vec<ReproductionRecord> = Vec::new();
            for record in agreed {
                let command = record.command.trim();
                if command != repro.command.trim()
                    && !others.iter().any(|o| o.command.trim() == command)
                {
                    others.push(record);
                }
            }
            Some(Confirmed {
                stable_id,
                finding: f.clone(),
                reproduction: repro,
                others,
            })
        })
        .collect()
}

/// The finding's other confirmed reproductions as variants. The list
/// is fixed by `findings.json` before any fix agent runs.
pub fn carried_variants(confirmed: &Confirmed, run_id: &str) -> Vec<arms::VariantSpec> {
    let staging = format!(".lyrik/state/runs/{run_id}/staging/");
    confirmed
        .others
        .iter()
        .enumerate()
        .map(|(i, record)| {
            // `<walk>/<script>` when the command names a walk's harness.
            let name = record
                .command
                .split(&staging)
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .map(|path| path.replacen("/harness/", "/", 1))
                .unwrap_or_else(|| format!("{}", i + 1));
            arms::VariantSpec {
                id: format!("reproduction:{name}"),
                source: arms::VariantSource::Reproduction,
                path: record.expected.chars().take(240).collect(),
                command: record.command.trim().to_string(),
            }
        })
        .collect()
}

/// The layout for a finding: its copies carry the harness of every
/// walk the reproduction or a carried variant names.
pub fn layout_for(confirmed: &Confirmed, run_id: &str, rel_dir: &str) -> Layout {
    Layout::for_commands(
        run_id,
        rel_dir,
        std::iter::once(confirmed.reproduction.command.as_str())
            .chain(confirmed.others.iter().map(|o| o.command.as_str())),
    )
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
    /// The reproduction and variant arms passed, no arm failed, and the
    /// patch, the run inputs and the target tree are as they were. The
    /// other three arms' states are on the record; this is not a claim
    /// that they passed.
    CandidateFix,
    /// An arm failed.
    Rejected,
    /// No arm failed, and the reproduction arm or the variant arm did
    /// not pass, or the patch, an input or the target tree changed:
    /// nothing shows the patch stops the defect by more than one path.
    Inconclusive,
}

/// The label a fix carries when it is not rejected.
pub const CANDIDATE_LABEL: &str = "candidate fix";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchSource {
    /// Written by the fix agent in this run.
    Generated,
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
    /// The variants: an agent's proof of concept as a path, another
    /// reproduction as its command.
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
    /// On a `candidate_fix` only, and never without the arm tally:
    /// `candidate fix: 3 of 5 arms passed, 2 inconclusive, 0 not_run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// How many arms ended in each state.
    pub arm_tally: ArmTally,
    /// `supplied` for a patch read from the run's inputs, `generated`
    /// for one the fix agent wrote.
    pub patch_source: PatchSource,
    /// The run inputs the arms rested on, as read at run start.
    pub inputs: InputDigests,
    /// Why the verdict is not `candidate_fix`.
    pub reasons: Vec<String>,
    /// `symptom_patch`, `symptom_patch_claimed`,
    /// `asserted_only_root_cause`, `root_cause_suspect`,
    /// `functionality_unverified`.
    pub labels: Vec<&'static str>,
    pub arms: Vec<ArmResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_locality: Option<Locality>,
    /// Variants by different paths the variant arm required.
    pub variant_minimum: usize,
    pub root_cause_claim: RootCauseClaim,
    /// Every variant on record and what its runs showed.
    pub variants: Vec<arms::VariantResult>,
    /// Set when the reproduction no longer shows the defect and a
    /// variant still does: the patch closes one path and leaves the
    /// ones named here open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<Partial>,
    /// Variants still open in the patched copy because their script
    /// sets a setting the run's configuration declares an explicit
    /// opt-out of the control. They do not fail the variant arm.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_by_configuration: Vec<OpenByConfiguration>,
    /// Paths to the same sink or invariant with no variant that held.
    pub untested_paths: Vec<UntestedPath>,
    pub class_open_sites: ClassOpenSites,
    pub patch: PatchInfo,
    /// The model that produced the patch, or that ran the arms on a
    /// supplied one.
    pub fix_model: String,
    /// Whether the tracked files of the target changed during the run.
    pub target_tree: TreeRecord,
    /// The fix step's agents: how many tool rounds each used, its
    /// limit, and whether it was stopped at the limit.
    pub agents: Vec<AgentRounds>,
    pub artifacts: Artifacts,
}

/// The paths a partial fix leaves open.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Partial {
    pub open_paths: Vec<OpenPath>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpenByConfiguration {
    pub id: String,
    pub path: String,
    pub command: String,
    /// The declared opt-out the variant's script sets.
    pub setting: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpenPath {
    pub id: String,
    pub path: String,
    pub command: String,
}

/// Whether the target's tracked files changed between run start and
/// the end of the fix step, read from two fingerprints of them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TreeRecord {
    Unchanged,
    Changed,
    /// It could not be told, and why.
    Unknown {
        reason: String,
    },
}

impl TreeRecord {
    /// From the fingerprint taken at run start and the one taken now.
    pub fn of(before: &Result<String, String>, after: &Result<String, String>) -> Self {
        match (before, after) {
            (Ok(a), Ok(b)) if a == b => TreeRecord::Unchanged,
            (Ok(_), Ok(_)) => TreeRecord::Changed,
            (Err(e), _) | (_, Err(e)) => TreeRecord::Unknown { reason: e.clone() },
        }
    }
}

/// One fix-step agent's use of its tool rounds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentRounds {
    /// `fix`, `fix-attack` or `fix-recheck`.
    pub step: String,
    /// Model calls the agent made.
    pub rounds: usize,
    pub round_limit: usize,
    /// True when the agent was stopped at the limit, not finished.
    pub incomplete: bool,
}

impl AgentRounds {
    fn note(&self) -> String {
        format!(
            "the {} agent was stopped at its limit of {} tool rounds before it finished",
            self.step, self.round_limit
        )
    }
}

/// One combined record: the patches of several findings applied to
/// one copy and checked together. Written when findings of a run share
/// an origin or an invariant and each one's own patch was rejected as
/// partial: each closes the path its finding reproduced and leaves
/// another open, and the question is what the patches do as a set.
/// The runner makes the copy, applies the patches and runs every
/// command; no agent takes part and no patch is written or merged.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CombinedOutcome {
    /// The member findings, by stable id.
    pub members: Vec<String>,
    /// What the members share: an origin or an invariant.
    pub shared: String,
    /// The combined directory, relative to the run directory.
    pub dir: String,
    pub verdict: Verdict,
    /// On a `candidate_fix` only, with the arm tally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub arm_tally: ArmTally,
    pub reasons: Vec<String>,
    /// Whether every member patch applied to the one copy, in order.
    pub patches_apply_together: bool,
    /// `reproduction`, `variant` and `functionality`. There is no
    /// re-walk of a union, so no `root_cause` and no `relocation`.
    pub arms: Vec<ArmResult>,
    pub variants: Vec<arms::VariantResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<Partial>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_by_configuration: Vec<OpenByConfiguration>,
    /// The member patches, relative to the run directory, in the order
    /// they were applied.
    pub patches: Vec<String>,
    pub target_tree: TreeRecord,
}

/// One member of a combined record.
pub struct CombinedMember<'a> {
    pub confirmed: &'a Confirmed,
    /// Its fix directory, relative to the run directory.
    pub rel_dir: &'a str,
}

fn squeeze(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Where a finding's violation starts, as a key two findings can share:
/// the origin's file with its function, or its line when it names none.
fn origin_key(finding: &Value) -> Option<String> {
    let origin = finding.get("origin")?;
    let file = origin.get("file")?.as_str()?.trim();
    let part = origin
        .get("function")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .or_else(|| {
            origin
                .get("line_start")
                .and_then(Value::as_u64)
                .map(|n| n.to_string())
        })?;
    (!file.is_empty()).then(|| format!("{file}:{part}"))
}

fn invariant_key(finding: &Value) -> Option<String> {
    finding
        .get("invariant")
        .and_then(Value::as_str)
        .map(squeeze)
        .filter(|s| !s.is_empty())
}

/// The findings to check together: among those whose own fix was
/// rejected as partial, each set of two or more connected by a shared
/// origin or a shared invariant, with what they share. Indexes are
/// into `members`.
pub fn combined_groups(members: &[(&Confirmed, &FixOutcome)]) -> Vec<(Vec<usize>, String)> {
    let partial: Vec<usize> = (0..members.len())
        .filter(|i| members[*i].1.partial.is_some())
        .collect();
    let shares = |a: usize, b: usize| -> Option<String> {
        let (fa, fb) = (&members[a].0.finding, &members[b].0.finding);
        match (origin_key(fa), origin_key(fb)) {
            (Some(x), Some(y)) if x == y => return Some(format!("origin {x}")),
            _ => {}
        }
        match (invariant_key(fa), invariant_key(fb)) {
            (Some(x), Some(y)) if x == y => Some("the same invariant".to_string()),
            _ => None,
        }
    };
    let mut groups: Vec<(Vec<usize>, String)> = Vec::new();
    let mut placed = vec![false; members.len()];
    for &start in &partial {
        if placed[start] {
            continue;
        }
        let mut group = vec![start];
        let mut shared: Option<String> = None;
        placed[start] = true;
        let mut i = 0;
        while i < group.len() {
            for &other in &partial {
                if !placed[other]
                    && let Some(why) = shares(group[i], other)
                {
                    placed[other] = true;
                    group.push(other);
                    shared.get_or_insert(why);
                }
            }
            i += 1;
        }
        if let (true, Some(shared)) = (group.len() > 1, shared) {
            group.sort_unstable();
            groups.push((group, shared));
        }
    }
    groups
}

/// The layout of a combined record: its one patched copy carries the
/// harness of every walk any member's reproductions name.
pub fn combined_layout(members: &[CombinedMember], run_id: &str, rel_dir: &str) -> Layout {
    Layout::for_commands(
        run_id,
        rel_dir,
        members.iter().flat_map(|m| {
            std::iter::once(m.confirmed.reproduction.command.as_str())
                .chain(m.confirmed.others.iter().map(|o| o.command.as_str()))
        }),
    )
}

/// A variant of a combined record with the member it came from.
pub struct CombinedVariant {
    pub spec: arms::VariantSpec,
    /// The member's fix directory, and the variant's id there.
    pub member_dir: String,
    pub member_id: String,
}

/// Every variant the members have on record, once each by command: the
/// members' other confirmed reproductions and the scripts their variant
/// agents wrote. A member's own reproduction is not a variant here; the
/// combined reproduction arm reads it.
pub fn combined_variants(
    members: &[CombinedMember],
    run_dir: &Path,
    run_id: &str,
    observed: &[Observed],
) -> Vec<CombinedVariant> {
    let mut out: Vec<CombinedVariant> = Vec::new();
    for m in members {
        let layout = layout_for(m.confirmed, run_id, m.rel_dir);
        let mut specs = carried_variants(m.confirmed, run_id);
        specs.extend(arms::registered_variants(
            &run_dir.join(m.rel_dir),
            &layout,
            observed,
        ));
        for spec in specs {
            let is_reproduction = members
                .iter()
                .any(|x| x.confirmed.reproduction.command.trim() == spec.command.trim());
            if is_reproduction || out.iter().any(|v| v.spec.command == spec.command) {
                continue;
            }
            let member_id = spec.id.clone();
            let id = match spec.source {
                arms::VariantSource::Agent => {
                    format!("{}/{}", slug(&m.confirmed.stable_id), spec.id)
                }
                arms::VariantSource::Reproduction => spec.id.clone(),
            };
            out.push(CombinedVariant {
                spec: arms::VariantSpec { id, ..spec },
                member_dir: m.rel_dir.to_string(),
                member_id,
            });
        }
    }
    out
}

/// The commands of a combined record the runner composes itself, in
/// the order it runs them: make the copies, apply each member patch,
/// then every member reproduction, every other confirmed reproduction
/// and the test command, in the baseline and in the combined copy.
/// The first value is how many of them set the copy up. Scripts the
/// variant agents wrote are not here; each is asked on its own.
pub fn combined_plan(
    members: &[CombinedMember],
    run_id: &str,
    layout: &Layout,
    revision: &str,
    functionality: &FunctionalityConfig,
    variants: &[CombinedVariant],
) -> (usize, Vec<String>) {
    let mut out = vec![
        layout.extract_baseline(revision),
        layout.ensure_patched(revision),
    ];
    out.extend(layout.carry_into("baseline"));
    out.extend(layout.carry_into("patched"));
    for m in members {
        out.push(arms::apply_member(
            layout,
            &Layout::new(run_id, m.rel_dir).dir,
        ));
    }
    let setup = out.len();
    for m in members {
        let command = m.confirmed.reproduction.command.trim();
        out.push(layout.in_copy("baseline", command));
        out.push(layout.in_copy("patched", command));
    }
    for v in variants
        .iter()
        .filter(|v| v.spec.source == arms::VariantSource::Reproduction)
    {
        out.push(layout.in_copy("baseline", &v.spec.command));
        out.push(layout.in_copy("patched", &v.spec.command));
    }
    if let Some(test) = &functionality.test_command {
        out.push(layout.in_copy("baseline", test));
        out.push(layout.in_copy("patched", test));
    }
    let mut seen = BTreeSet::new();
    out.retain(|c| seen.insert(c.trim().to_string()));
    (setup.min(out.len()), out)
}

/// What [`judge_combined`] reads.
pub struct CombinedInput<'a> {
    pub run_dir: &'a Path,
    pub rel_dir: &'a str,
    pub run_id: &'a str,
    pub members: &'a [CombinedMember<'a>],
    pub shared: &'a str,
    pub observed: &'a [Observed],
    pub target: &'a Path,
    pub tree: &'a TreeRecord,
    pub inputs: &'a FixInputs,
    /// The most variants any member's own patch required.
    pub variant_minimum: usize,
}

/// Judge a combined record from the runs on the log.
pub fn judge_combined(input: &CombinedInput) -> CombinedOutcome {
    let layout = combined_layout(input.members, input.run_id, input.rel_dir);
    let log = arms::Log(input.observed);
    let mut reasons = Vec::new();
    // Each member patch has to have gone into the one copy.
    let mut applied = true;
    for m in input.members {
        let dir = Layout::new(input.run_id, m.rel_dir).dir;
        match log.run(&arms::apply_member(&layout, &dir)) {
            arms::Run::Done { success: true, .. } => {}
            arms::Run::Done { .. } => {
                applied = false;
                reasons.push(format!(
                    "the member patches do not apply together: the patch of {} does not apply \
                     on top of the ones before it",
                    m.confirmed.stable_id
                ));
                break;
            }
            _ => {
                applied = false;
                reasons.push(format!(
                    "the patch of {} was not applied to the combined copy",
                    m.confirmed.stable_id
                ));
                break;
            }
        }
    }
    let variants = combined_variants(input.members, input.run_dir, input.run_id, input.observed);
    let specs: Vec<arms::VariantSpec> = variants.iter().map(|v| v.spec.clone()).collect();
    let reproductions: Vec<(&str, &str)> = input
        .members
        .iter()
        .map(|m| {
            (
                m.confirmed.stable_id.as_str(),
                m.confirmed.reproduction.command.trim(),
            )
        })
        .collect();
    let (arms_list, results) = if applied {
        let reproduction = arms::combined_reproduction_arm(&log, &layout, &reproductions);
        let commands: Vec<&str> = reproductions.iter().map(|(_, c)| *c).collect();
        let (variant, _, results) = arms::variant_arm_in(
            &log,
            &layout,
            &specs,
            Ok(None),
            &commands,
            input.variant_minimum,
            &|spec| {
                let v = variants.iter().find(|v| v.spec.command == spec.command)?;
                opt_out_set(
                    &arms::VariantSpec {
                        id: v.member_id.clone(),
                        ..spec.clone()
                    },
                    &input.inputs.opt_outs,
                    input.target,
                    input.run_dir,
                    &v.member_dir,
                )
            },
            // The combined copy only ever holds the patches.
            &|command| arms::poc(&log.run(command)),
        );
        let functionality = arms::combined_functionality_arm(
            &log,
            &layout,
            input.inputs.functionality.test_command.as_deref(),
        );
        (vec![reproduction, variant, functionality], results)
    } else {
        (Vec::new(), Vec::new())
    };
    match input.tree {
        TreeRecord::Unchanged => {}
        TreeRecord::Changed => {
            reasons.push("the target tree changed during the fix step".to_string())
        }
        TreeRecord::Unknown { reason } => reasons.push(format!(
            "whether the target tree changed during the run is unknown: {reason}"
        )),
    }
    let passed = |arm: &str| {
        arms_list
            .iter()
            .any(|a| a.arm == arm && a.state == ArmState::Pass)
    };
    let open_paths: Vec<OpenPath> = results
        .iter()
        .filter(|v| v.outcome == "open")
        .map(|v| OpenPath {
            id: v.id.clone(),
            path: v.path.clone(),
            command: v.command.clone(),
        })
        .collect();
    let partial =
        (passed("reproduction") && !open_paths.is_empty()).then_some(Partial { open_paths });
    if let Some(p) = &partial {
        reasons.insert(
            0,
            format!(
                "partial fix: no member's reproduction shows the defect with the patches \
                 together and {} other path(s) still do: {}",
                p.open_paths.len(),
                p.open_paths
                    .iter()
                    .map(|o| o.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let arm_tally = ArmTally::of(&arms_list);
    let failed: Vec<&ArmResult> = arms_list
        .iter()
        .filter(|a| a.state == ArmState::Fail)
        .collect();
    let verdict = if !failed.is_empty() {
        for a in &failed {
            reasons.push(format!("{} arm failed: {}", a.arm, a.reasons.join("; ")));
        }
        Verdict::Rejected
    } else if !applied || !passed("reproduction") || !passed("variant") || !reasons.is_empty() {
        if applied && !passed("reproduction") {
            reasons.push("the reproduction arm did not pass".to_string());
        }
        if applied && !passed("variant") {
            reasons.push("the variant arm did not pass".to_string());
        }
        Verdict::Inconclusive
    } else {
        Verdict::CandidateFix
    };
    CombinedOutcome {
        members: input
            .members
            .iter()
            .map(|m| m.confirmed.stable_id.clone())
            .collect(),
        shared: input.shared.to_string(),
        dir: input.rel_dir.to_string(),
        verdict,
        label: (verdict == Verdict::CandidateFix).then(|| candidate_label(&arm_tally)),
        arm_tally,
        reasons,
        patches_apply_together: applied,
        open_by_configuration: results
            .iter()
            .filter_map(|v| {
                Some(OpenByConfiguration {
                    id: v.id.clone(),
                    path: v.path.clone(),
                    command: v.command.clone(),
                    setting: v.opt_out.clone()?,
                })
            })
            .collect(),
        arms: arms_list,
        variants: results,
        partial,
        patches: input
            .members
            .iter()
            .map(|m| format!("{}/fix.patch", m.rel_dir))
            .collect(),
        target_tree: input.tree.clone(),
    }
}

/// The tool rounds a fix-step agent gets when the operator sets none.
pub const FIX_TOOL_ROUNDS_DEFAULT: usize = 60;

// More than a turn gets anywhere else: these agents read a codebase,
// write a patch or several scripts, and run them.
const _: () = assert!(FIX_TOOL_ROUNDS_DEFAULT > wirken_agent::runtime::MAX_TOOL_ROUNDS);

/// How many of a fix's arms ended in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct ArmTally {
    pub pass: usize,
    pub fail: usize,
    pub inconclusive: usize,
    pub not_run: usize,
}

impl ArmTally {
    pub fn of(arms_list: &[ArmResult]) -> Self {
        let mut t = Self::default();
        for a in arms_list {
            match a.state {
                ArmState::Pass => t.pass += 1,
                ArmState::Fail => t.fail += 1,
                ArmState::Inconclusive => t.inconclusive += 1,
                ArmState::NotRun => t.not_run += 1,
            }
        }
        t
    }

    fn total(&self) -> usize {
        self.pass + self.fail + self.inconclusive + self.not_run
    }
}

/// The candidate label. There is no form of it without the tally.
pub fn candidate_label(tally: &ArmTally) -> String {
    format!(
        "{CANDIDATE_LABEL}: {} of {} arms passed, {} inconclusive, {} not_run",
        tally.pass,
        tally.total(),
        tally.inconclusive,
        tally.not_run
    )
}

/// The digests of the run inputs a fix record rested on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputDigests {
    /// `.lyrik/config.json` as read at run start.
    pub config_sha256: String,
    /// The supplied patch as read at run start, when one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplied_patch_sha256: Option<String>,
    /// The supplied reproduction as read at run start, when the arms
    /// ran on one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplied_reproduction_sha256: Option<String>,
}

/// A reproduction supplied for a finding, as read at run start.
#[derive(Debug, Clone, PartialEq)]
pub struct SuppliedReproduction {
    pub bytes: Vec<u8>,
    pub sha256: String,
    /// `sh` for a `.sh` file, `python3` for a `.py` file.
    pub interpreter: &'static str,
    /// `sh` or `py`.
    pub extension: &'static str,
}

/// What the runner observed when it ran a supplied reproduction on the
/// baseline copy. A supplied script is a claim until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedStatus {
    /// It printed the marker and exited non-zero: the defect shows.
    Confirmed,
    /// It printed the marker and exited zero.
    NotShown,
    /// It was not run, was refused, timed out, or never reached its
    /// assertion.
    Inconclusive,
}

/// One supplied reproduction on the run's record.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuppliedReproductionRecord {
    pub stable_id: String,
    /// The script as read at run start.
    pub sha256: String,
    /// The command the runner composed for it, from the project root.
    pub command: String,
    pub status: SuppliedStatus,
    /// Why it is not `confirmed`, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The status of a supplied reproduction from the run the log holds
/// for it on the baseline copy. With no run there is no confirmation.
pub fn supplied_status(run: &arms::Run) -> (SuppliedStatus, Option<String>) {
    match arms::poc(run) {
        arms::Poc::Shown => (SuppliedStatus::Confirmed, None),
        arms::Poc::NotShown => (
            SuppliedStatus::NotShown,
            Some("it reached its assertion and exited zero in the baseline copy".to_string()),
        ),
        arms::Poc::Inconclusive(why) | arms::Poc::NotRun(why) => {
            (SuppliedStatus::Inconclusive, Some(why))
        }
    }
}

/// Where the runner puts a supplied reproduction for a finding, and
/// the command that runs it from the project root.
pub fn supplied_reproduction_paths(
    run_id: &str,
    rel_dir: &str,
    script: &SuppliedReproduction,
) -> (String, String) {
    let rel = format!("{rel_dir}/supplied/reproduction.{}", script.extension);
    let command = format!("{} .lyrik/state/runs/{run_id}/{rel}", script.interpreter);
    (rel, command)
}

/// The finding `stable_id` names as a confirmed finding whose
/// reproduction is the supplied script, observed to show the defect.
/// Reproductions the walks confirmed for the same finding become its
/// variants.
pub fn confirm_with_supplied(
    body: &Value,
    walk_confirmed: Option<&Confirmed>,
    stable_id: &str,
    command: &str,
    revision: &str,
) -> Option<Confirmed> {
    let finding = body
        .get("findings")?
        .as_array()?
        .iter()
        .find(|f| f.get("stable_id").and_then(Value::as_str) == Some(stable_id))?
        .clone();
    let reproduction: ReproductionRecord = serde_json::from_value(serde_json::json!({
        "stable_id": stable_id,
        "command": command,
        "expected": "supplied by the operator: prints the marker and exits non-zero when the defect shows",
        "observed": "the runner ran it in the baseline copy: the marker, then a non-zero exit",
        "outcome": "reproduced",
        "code_revision": revision,
    }))
    .ok()?;
    let mut others = Vec::new();
    if let Some(c) = walk_confirmed {
        others.push(c.reproduction.clone());
        others.extend(c.others.iter().cloned());
    }
    Some(Confirmed {
        stable_id: stable_id.to_string(),
        finding,
        reproduction,
        others,
    })
}

fn read_supplied_reproductions(target: &Path) -> BTreeMap<String, SuppliedReproduction> {
    let dir = target.join(SUPPLIED_REPRODUCTION_DIR);
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    let mut paths: Vec<std::path::PathBuf> =
        entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // A regular file only: a link could point anywhere.
        let regular = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let (slug, interpreter, extension) = if let Some(s) = name.strip_suffix(".sh") {
            (s, "sh", "sh")
        } else if let Some(s) = name.strip_suffix(".py") {
            (s, "python3", "py")
        } else {
            continue;
        };
        if let (true, Ok(bytes)) = (regular, std::fs::read(&path)) {
            // With both a .sh and a .py for one finding, the .py, read
            // first, stands.
            out.entry(slug.to_string()).or_insert(SuppliedReproduction {
                sha256: sha256_hex(&bytes),
                bytes,
                interpreter,
                extension,
            });
        }
    }
    out
}

/// A patch supplied for a finding, as read at run start.
#[derive(Debug, Clone, PartialEq)]
pub struct SuppliedPatch {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// The inputs the fix step takes from the target: the functionality
/// commands in `.lyrik/config.json` and the patches under
/// [`SUPPLIED_PATCH_DIR`]. Both sit in the tree an approved `exec`
/// can write, so they are read once, at run start, before any agent
/// runs, and nothing reads them again except to see whether they
/// changed. What a walk or a fix agent writes there during the run is
/// never used.
#[derive(Debug, Clone, PartialEq)]
pub struct FixInputs {
    pub config_sha256: String,
    pub functionality: FunctionalityConfig,
    /// By slug.
    pub patches: BTreeMap<String, SuppliedPatch>,
    /// Reproductions the operator supplied, by slug.
    pub reproductions: BTreeMap<String, SuppliedReproduction>,
    /// The target's tracked files as they were at run start, as
    /// [`super::lyrik_git::tree_fingerprint`] reads them.
    pub tree: Result<String, String>,
    /// `fix.explicit_opt_outs`: the settings by which an operator
    /// switches the control under test off on purpose, each as the
    /// text a script would carry (`STRICT_MODE=off`). A variant
    /// still open in the patched copy whose script sets one is
    /// recorded as open by configuration.
    pub opt_outs: Vec<String>,
}

/// Which run inputs differ on disk from what was read at run start.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InputChanges {
    pub config: bool,
    /// Slugs whose supplied patch changed, appeared or went away.
    pub patches: BTreeSet<String>,
    /// Slugs whose supplied reproduction changed, appeared or went away.
    pub reproductions: BTreeSet<String>,
}

impl InputChanges {
    pub fn any(&self) -> bool {
        self.config || !self.patches.is_empty() || !self.reproductions.is_empty()
    }
}

fn read_supplied_patches(target: &Path) -> BTreeMap<String, SuppliedPatch> {
    let dir = target.join(SUPPLIED_PATCH_DIR);
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        // A regular file only: a link could point anywhere.
        let regular = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        let Some(slug) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".patch"))
        else {
            continue;
        };
        if let (true, Ok(bytes)) = (regular, std::fs::read(&path)) {
            out.insert(
                slug.to_string(),
                SuppliedPatch {
                    sha256: sha256_hex(&bytes),
                    bytes,
                },
            );
        }
    }
    out
}

impl FixInputs {
    /// Read the inputs. `config_body` is the bytes of
    /// `.lyrik/config.json` the run parsed `config` from.
    pub fn capture(target: &Path, config_body: &str, config: &Value) -> Self {
        Self {
            config_sha256: sha256_hex(config_body.as_bytes()),
            functionality: functionality_config(config),
            patches: read_supplied_patches(target),
            reproductions: read_supplied_reproductions(target),
            tree: super::lyrik_git::tree_fingerprint(target),
            opt_outs: explicit_opt_outs(config),
        }
    }

    /// Compare what is on disk now with what was read.
    pub fn changes(&self, target: &Path) -> InputChanges {
        let config = std::fs::read(target.join(".lyrik").join("config.json"))
            .map(|b| sha256_hex(&b) != self.config_sha256)
            .unwrap_or(true);
        let now = read_supplied_patches(target);
        let patches = self
            .patches
            .keys()
            .chain(now.keys())
            .filter(|slug| {
                self.patches.get(*slug).map(|p| &p.sha256) != now.get(*slug).map(|p| &p.sha256)
            })
            .cloned()
            .collect();
        let now = read_supplied_reproductions(target);
        let reproductions = self
            .reproductions
            .keys()
            .chain(now.keys())
            .filter(|slug| {
                self.reproductions.get(*slug).map(|p| &p.sha256)
                    != now.get(*slug).map(|p| &p.sha256)
            })
            .cloned()
            .collect();
        InputChanges {
            config,
            patches,
            reproductions,
        }
    }
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
    /// Whether the target's tracked files changed during the run.
    pub tree: &'a TreeRecord,
    /// The fix step's agents and their tool rounds.
    pub agents: &'a [AgentRounds],
    pub fix_model: &'a str,
    /// The run's inputs as read at run start.
    pub inputs: &'a FixInputs,
    /// Which of them differ on disk now.
    pub changes: &'a InputChanges,
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
    let layout = layout_for(input.confirmed, input.run_id, input.rel_dir);
    let log = arms::Log(input.observed);
    let mut reasons = Vec::new();

    let patch_bytes = std::fs::read(fix_dir.join("fix.patch")).unwrap_or_default();
    let patch_text = String::from_utf8_lossy(&patch_bytes);
    let shape = arms::parse_patch(&patch_text);
    if shape.hunks.is_empty() {
        reasons.push("fix.patch is missing or holds no hunk".to_string());
    }
    let sha256 = (!patch_bytes.is_empty()).then(|| sha256_hex(&patch_bytes));
    let slug = slug(&input.confirmed.stable_id);
    let supplied = input.inputs.patches.get(&slug).map(|p| p.sha256.as_str());
    if let Some(supplied) = supplied
        && sha256.as_deref() != Some(supplied)
    {
        reasons.push("the supplied patch was changed during the fix step".to_string());
    }
    // The arms ran on a supplied reproduction when the finding's
    // reproduction is the command the runner composed for one.
    let supplied_reproduction = input.inputs.reproductions.get(&slug).filter(|r| {
        supplied_reproduction_paths(input.run_id, input.rel_dir, r).1
            == input.confirmed.reproduction.command.trim()
    });
    let locality = (!shape.hunks.is_empty()).then(|| shape.locality());
    let variant_minimum = match locality {
        Some(Locality::CrossCutting) => arms::VARIANT_MIN_CROSS_CUTTING,
        _ => arms::VARIANT_MIN_LOCALIZED,
    };

    let command = input.confirmed.reproduction.command.trim();
    // The fix agent ran the reproduction's own commands, composed for
    // the copies as the reproduction alone needs them.
    let reproduction = arms::reproduction_arm(
        &log,
        &Layout::for_reproduction(input.run_id, input.rel_dir, command),
        command,
        input.revision,
    );
    let left_reverted = reproduction.left_reverted;
    let mut claim = arms::root_cause_claim(&input.confirmed.finding, &reproduction);
    let attack = arms::read_json::<arms::Attack>(&fix_dir.join("attack.json"));
    // The variants on record: the finding's other confirmed
    // reproductions, then the scripts under variants/.
    let mut specs = carried_variants(input.confirmed, input.run_id);
    specs.extend(arms::registered_variants(&fix_dir, &layout, input.observed));
    let variant_files: Vec<String> = specs
        .iter()
        .map(|v| match v.source {
            arms::VariantSource::Agent => format!("{}/{}", input.rel_dir, v.id),
            arms::VariantSource::Reproduction => v.command.clone(),
        })
        .collect();
    let (variant, untested_paths, variants) = arms::variant_arm(
        &log,
        &layout,
        &specs,
        attack,
        command,
        variant_minimum,
        &|spec| {
            opt_out_set(
                spec,
                &input.inputs.opt_outs,
                input.target,
                input.run_dir,
                input.rel_dir,
            )
        },
    );
    claim.suspect = variant.state == ArmState::Fail;
    let (root_cause, symptom_patch) = arms::root_cause_arm(
        &shape,
        &input.confirmed.finding,
        &claim,
        &reproduction.patched,
        claim.suspect,
    );
    let recheck = arms::read_json::<arms::Recheck>(&fix_dir.join("recheck.json"));
    let relocation = arms::relocation_arm(&log, &layout, &recheck);
    let functionality =
        arms::functionality_arm(&log, &layout, &recheck, &shape, &input.inputs.functionality);
    // The commands this arm ran came from the configuration read at run
    // start. If the file differs now, something wrote it mid-run.
    const CONFIG_CHANGED: &str = ".lyrik/config.json changed during the run";
    let functionality = if input.changes.config {
        functionality.withheld(CONFIG_CHANGED)
    } else {
        functionality
    };
    let class_open_sites = arms::class_report(&recheck, input.target);

    match input.tree {
        TreeRecord::Unchanged => {}
        TreeRecord::Changed => {
            reasons.push("the target tree changed during the fix step".to_string())
        }
        TreeRecord::Unknown { reason } => reasons.push(format!(
            "whether the target tree changed during the run is unknown: {reason}"
        )),
    }
    let mut labels = Vec::new();
    if symptom_patch {
        labels.push("symptom_patch");
    } else if root_cause
        .model_claims
        .iter()
        .any(|c| c.starts_with("symptom_patch"))
    {
        // The walks place the origin away from the patch and nothing
        // executed says so: a claim for a maintainer, not a rejection.
        labels.push("symptom_patch_claimed");
    }
    if claim.evidence_state == arms::ClaimEvidence::AssertedOnly {
        labels.push("asserted_only_root_cause");
    }
    if claim.suspect {
        labels.push("root_cause_suspect");
    }
    // Anything short of a pass, on a fix the arm did not reject.
    if matches!(
        functionality.state,
        ArmState::Inconclusive | ArmState::NotRun
    ) {
        labels.push("functionality_unverified");
    }
    let mut arms_list = vec![
        reproduction.arm,
        variant,
        root_cause,
        relocation,
        functionality,
    ];
    // The patch the arms ran on was read at run start. If the file
    // supplied for this finding differs now, no arm stands.
    if input.changes.patches.contains(&slug) {
        const PATCH_CHANGED: &str = "the patch supplied for this finding changed during the run";
        arms_list = arms_list
            .into_iter()
            .map(|a| a.withheld(PATCH_CHANGED))
            .collect();
        reasons.push(PATCH_CHANGED.to_string());
    }
    // The same for a reproduction the operator supplied: every arm was
    // run on, or beside, the script read at run start.
    if supplied_reproduction.is_some() && input.changes.reproductions.contains(&slug) {
        const REPRODUCTION_CHANGED: &str =
            "the reproduction supplied for this finding changed during the run";
        arms_list = arms_list
            .into_iter()
            .map(|a| a.withheld(REPRODUCTION_CHANGED))
            .collect();
        reasons.push(REPRODUCTION_CHANGED.to_string());
    }
    if input.changes.config {
        reasons.push(CONFIG_CHANGED.to_string());
    }
    // The patched copy is one directory. If the patch was taken out for
    // the revert check and not put back, what ran there afterwards ran
    // on unpatched code and says nothing about the patch.
    if left_reverted {
        const LEFT_OUT: &str = "the patch was not applied again after the revert check, so later runs in the \
             patched copy did not run on patched code";
        arms_list = arms_list
            .into_iter()
            .map(|a| {
                if matches!(a.arm, "variant" | "relocation" | "functionality")
                    && matches!(a.state, ArmState::Pass | ArmState::Fail)
                {
                    a.withheld(LEFT_OUT)
                } else {
                    a
                }
            })
            .collect();
    }
    // An agent stopped at its round limit left the arms it feeds
    // short of what it would have run. The arm says so; its state is
    // still what the runs it did get show.
    for agent in input.agents.iter().filter(|a| a.incomplete) {
        let fed: &[&str] = match agent.step.as_str() {
            "fix" => &["reproduction"],
            "fix-attack" => &["variant"],
            _ => &["relocation", "functionality"],
        };
        arms_list = arms_list
            .into_iter()
            .map(|a| {
                if fed.contains(&a.arm) {
                    a.incomplete(&agent.note())
                } else {
                    a
                }
            })
            .collect();
    }
    let reproduction_passed = arms_list[0].state == ArmState::Pass;
    let variant_passed = arms_list[1].state == ArmState::Pass;
    let arm_tally = ArmTally::of(&arms_list);
    let failed: Vec<&ArmResult> = arms_list
        .iter()
        .filter(|a| a.state == ArmState::Fail)
        .collect();
    let verdict = if !failed.is_empty() {
        for a in &failed {
            reasons.push(format!("{} arm failed: {}", a.arm, a.reasons.join("; ")));
        }
        Verdict::Rejected
    } else if !reproduction_passed || !variant_passed || !reasons.is_empty() {
        if !reproduction_passed {
            reasons.push("the reproduction arm did not pass".to_string());
        }
        if !variant_passed {
            reasons.push("the variant arm did not pass".to_string());
        }
        Verdict::Inconclusive
    } else {
        Verdict::CandidateFix
    };
    // Partial: the reproduction is stopped and a variant is not.
    let open_paths: Vec<OpenPath> = variants
        .iter()
        .filter(|v| v.outcome == "open")
        .map(|v| OpenPath {
            id: v.id.clone(),
            path: v.path.clone(),
            command: v.command.clone(),
        })
        .collect();
    let partial =
        (reproduction_passed && arms_list[1].state == ArmState::Fail && !open_paths.is_empty())
            .then_some(Partial { open_paths });
    if let Some(p) = &partial {
        reasons.insert(
            0,
            format!(
                "partial fix: the reproduction no longer shows the defect and {} other path(s) \
                 still do: {}",
                p.open_paths.len(),
                p.open_paths
                    .iter()
                    .map(|o| o.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
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
        label: (verdict == Verdict::CandidateFix).then(|| candidate_label(&arm_tally)),
        arm_tally,
        patch_source: if supplied.is_some() {
            PatchSource::Supplied
        } else {
            PatchSource::Generated
        },
        inputs: InputDigests {
            config_sha256: input.inputs.config_sha256.clone(),
            supplied_patch_sha256: supplied.map(str::to_string),
            supplied_reproduction_sha256: supplied_reproduction.map(|r| r.sha256.clone()),
        },
        reasons,
        labels,
        arms: arms_list,
        fix_locality: locality,
        variant_minimum,
        root_cause_claim: claim,
        open_by_configuration: variants
            .iter()
            .filter_map(|v| {
                Some(OpenByConfiguration {
                    id: v.id.clone(),
                    path: v.path.clone(),
                    command: v.command.clone(),
                    setting: v.opt_out.clone()?,
                })
            })
            .collect(),
        variants,
        partial,
        untested_paths,
        class_open_sites,
        patch: PatchInfo {
            path: format!("{}/fix.patch", input.rel_dir),
            sha256,
            test_files: shape.test_files().iter().map(|s| s.to_string()).collect(),
            dependency_manifests: shape
                .dependency_manifests()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            files: shape.files,
        },
        fix_model: input.fix_model.to_string(),
        target_tree: input.tree.clone(),
        agents: input.agents.to_vec(),
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

/// Save the `exec` results that ran under a fix directory, or in the
/// run's shared baseline copy, beside the patch, so a maintainer can read what each arm saw and run it again.
pub fn save_observed(fix_dir: &Path, layout: &Layout, observed: &[Observed]) -> Result<()> {
    let mine: Vec<&Observed> = observed
        .iter()
        .filter(|o| {
            // This finding's own directory, and the run's shared baseline.
            o.command.contains(&layout.dir) || o.command.contains(&layout.copy("baseline"))
        })
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

/// The run's counts. A candidate count is an object that carries the
/// arm tally of those candidates and how many of them have a
/// functionality arm that did not pass; there is no bare count of
/// candidates.
pub fn summary(outcomes: &[FixOutcome]) -> Value {
    let count = |v: Verdict| outcomes.iter().filter(|o| o.verdict == v).count();
    let candidates: Vec<&FixOutcome> = outcomes
        .iter()
        .filter(|o| o.verdict == Verdict::CandidateFix)
        .collect();
    let mut arms_of_candidates = ArmTally::default();
    for o in &candidates {
        arms_of_candidates.pass += o.arm_tally.pass;
        arms_of_candidates.inconclusive += o.arm_tally.inconclusive;
        arms_of_candidates.not_run += o.arm_tally.not_run;
    }
    serde_json::json!({
        "fixes": outcomes.len(),
        "by_verdict": {
            "candidate_fix": {
                "count": candidates.len(),
                "all_arms_passed": candidates
                    .iter()
                    .filter(|o| o.arm_tally.pass == o.arms.len())
                    .count(),
                "functionality_unverified": candidates
                    .iter()
                    .filter(|o| o.labels.contains(&"functionality_unverified"))
                    .count(),
                "arms": {
                    "passed": arms_of_candidates.pass,
                    "inconclusive": arms_of_candidates.inconclusive,
                    "not_run": arms_of_candidates.not_run,
                },
            },
            "rejected": count(Verdict::Rejected),
            "inconclusive": count(Verdict::Inconclusive),
        },
        "partial": outcomes.iter().filter(|o| o.partial.is_some()).count(),
        "agents_stopped_at_round_limit": outcomes
            .iter()
            .flat_map(|o| o.agents.iter())
            .filter(|a| a.incomplete)
            .count(),
        "by_arm": arms::count_by_arm(outcomes.iter().flat_map(|o| o.arms.iter())),
    })
}

/// One line for the terminal from [`summary`].
pub fn summary_line(summary: &Value) -> String {
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let by_verdict = &summary["by_verdict"];
    let c = &by_verdict["candidate_fix"];
    let mut line = format!(
        "{} candidate (their arms: {} passed, {} inconclusive, {} not_run; {} with all arms \
         passed; {} functionality unverified), {} rejected, {} inconclusive",
        n(c, "count"),
        n(&c["arms"], "passed"),
        n(&c["arms"], "inconclusive"),
        n(&c["arms"], "not_run"),
        n(c, "all_arms_passed"),
        n(c, "functionality_unverified"),
        n(by_verdict, "rejected"),
        n(by_verdict, "inconclusive")
    );
    if n(summary, "partial") > 0 {
        line.push_str(&format!(
            " ({} of the rejected partial)",
            n(summary, "partial")
        ));
    }
    if n(summary, "agents_stopped_at_round_limit") > 0 {
        line.push_str(&format!(
            "; {} agent(s) stopped at the tool round limit",
            n(summary, "agents_stopped_at_round_limit")
        ));
    }
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
/// Add `supplied_reproductions` to a written `findings.json`: each
/// script the operator supplied and what the runner observed of it.
pub fn record_supplied_reproductions(
    dest: &Path,
    records: &[SuppliedReproductionRecord],
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let body = std::fs::read_to_string(dest).with_context(|| format!("read {}", dest.display()))?;
    let mut body: Value =
        serde_json::from_str(&body).with_context(|| format!("parse {}", dest.display()))?;
    body["supplied_reproductions"] = serde_json::to_value(records)?;
    std::fs::write(dest, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", dest.display()))?;
    Ok(())
}

pub fn record_fixes(
    dest: &Path,
    outcomes: &[FixOutcome],
    combined: &[CombinedOutcome],
) -> Result<()> {
    let body = std::fs::read_to_string(dest).with_context(|| format!("read {}", dest.display()))?;
    let mut body: Value =
        serde_json::from_str(&body).with_context(|| format!("parse {}", dest.display()))?;
    body["fixes"] = serde_json::to_value(outcomes)?;
    if !combined.is_empty() {
        body["combined_fixes"] = serde_json::to_value(combined)?;
    }
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
                "patch_source": o.patch_source,
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

/// A declared opt-out shorter than this is not read: a few characters
/// would match any script.
const OPT_OUT_MIN_LEN: usize = 8;

/// `fix.explicit_opt_outs` from `.lyrik/config.json`.
pub fn explicit_opt_outs(config: &Value) -> Vec<String> {
    config
        .get("fix")
        .and_then(|f| f.get("explicit_opt_outs"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| s.len() >= OPT_OUT_MIN_LEN)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The declared opt-out a variant's own script sets, if any. For an
/// agent's variant the files of its directory are read; for another
/// reproduction, the harness script its command names and the files
/// beside it that the script mentions by name. The match is on text:
/// the setting has to be in what runs.
pub fn opt_out_set(
    spec: &arms::VariantSpec,
    opt_outs: &[String],
    target: &Path,
    run_dir: &Path,
    rel_dir: &str,
) -> Option<String> {
    if opt_outs.is_empty() {
        return None;
    }
    const MAX: u64 = 512 * 1024;
    let read = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .filter(|m| m.is_file() && m.len() <= MAX)
            .and_then(|_| std::fs::read_to_string(p).ok())
    };
    let mut texts: Vec<String> = Vec::new();
    match spec.source {
        arms::VariantSource::Agent => {
            let script = run_dir.join(rel_dir).join(&spec.id);
            if let Some(dir) = script.parent()
                && let Ok(entries) = std::fs::read_dir(dir)
            {
                texts.extend(
                    entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| read(&e.path())),
                );
            }
        }
        arms::VariantSource::Reproduction => {
            for token in spec.command.split_whitespace() {
                if !token.starts_with(".lyrik/state/runs/") || token.contains("..") {
                    continue;
                }
                let script = target.join(token);
                let Some(text) = read(&script) else { continue };
                if let Some(dir) = script.parent()
                    && let Ok(entries) = std::fs::read_dir(dir)
                {
                    for e in entries.filter_map(|e| e.ok()) {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if e.path() != script && text.contains(&name) {
                            texts.extend(read(&e.path()));
                        }
                    }
                }
                texts.push(text);
            }
        }
    }
    opt_outs
        .iter()
        .find(|setting| texts.iter().any(|t| t.contains(setting.as_str())))
        .cloned()
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
     command: a second run with a different result makes the arm inconclusive. A command \
     may be refused at the gate; a refused command is a step not taken, and you carry on \
     with the next. You write only under the fix directory, and never into the project's \
     tree: not a source file, not a test, not a build artifact.";

/// The contract a command that shows a defect follows.
fn poc_contract() -> String {
    format!(
        "A proof of concept follows one contract. It prints `{}` on a line of its own, \
         flushed, immediately before its assertion; it exits non-zero when the defect shows \
         and zero when it does not. The line goes to stdout; stderr is not read. It prints \
         the line only once the code under test has \
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
         2. Run the commands the prompt lists as before the patch. They make the copies.\n\
         3. Write the patch as a unified diff with `a/` and `b/` prefixes to `fix.patch` in \
         the fix directory. If the prompt says a patch was supplied, it is already there: \
         do not edit it. You may check the patch with \
         `git apply --check --directory=<patched> <fix-dir>/fix.patch`, with `<patched>` the \
         patched copy the prompt names, and rewrite it until that is clean; do this before \
         the first apply command, never after.\n\
         4. Run the remaining commands from the prompt, in order. Two of them are the \
         same string twice, and the apply command appears twice: the patched copy is one \
         directory, checked with the patch in, then with it taken out, then patched \
         again. Run each where it stands in the list.\n\n\
         Your reply is one sentence saying the commands were run.\n",
        frontmatter(
            "fix",
            "Write a candidate fix for one confirmed finding and run its reproduction in a baseline and a patched copy",
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
         invariant, by a route the patch may not cover. You have a limited number of tool \
         rounds, named in the prompt: spend them on variants, not on reading.\n\n\
         {NO_VERDICT}\n\n\
         {}\n\n\
         Steps, in order:\n\n\
         1. Read the finding, the patch, and the `graph-walk` and `chain-walk` entries under \
         `step_records` in the run's `findings.json`. From the code in the `baseline` copy, \
         list every caller and path that reaches the same sink or bears on the same \
         invariant: sibling call sites, alternate entry points, callbacks, cleanup, \
         teardown and error paths, other input shapes. Each is one entry of `paths`.\n\
         2. For at least the number of paths the prompt names, each by a different route \
         from the original reproduction, from the variants the prompt says the runner has \
         already run, and from each other (another caller, another input shape, a cleanup \
         or error path), write a proof of concept. Derive each from the root cause. \
         Changing only a literal, a file name or a size is not another route unless that \
         boundary is the invariant.\n\
         3. One variant at a time, finished before the next is started. A variant is one \
         directory, `variants/<id>/` in the fix directory, holding `run.sh` (or `run.py`) \
         and `path.txt`, one line saying which path it takes. Write both, then run \
         `cd <baseline> && <interpreter> <up><fix-dir>/variants/<id>/run.sh` and then \
         `cd <patched> && <interpreter> <up><fix-dir>/variants/<id>/run.sh`, with \
         `<baseline>`, `<patched>` and `<up>` exactly as the prompt gives them and \
         `<interpreter>` `sh` for `run.sh` or `python3` for `run.py`. The variant is on \
         record from the moment its run file exists: if you stop before running it, the \
         runner runs it in both copies itself. So a variant you finished counts whatever \
         happens to the ones after it, and a half-written run file is run as it is; do \
         not leave one. The baseline copy is shared by the whole run: do not write into \
         it.\n\
         4. Last, and only if rounds remain, write `attack.json` in the fix directory: \
         `paths`, a list of `{{\"id\", \"route\", \"location\", \"description\"}}` with `route` \
         one of `caller`, `input_shape`, `cleanup`, `error_path`, `other` and `location` \
         as `file:line`, for every path you found including those you wrote nothing for. \
         It only names paths nothing was run for. No variant depends on it.\n\n\
         Do not edit the copies' source or the patch. Your reply is one sentence saying \
         how many variants you wrote.\n",
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
         file:line`. Each candidate is `{{\"title\", \"location\", \"kind\", \"command\"}}` with \
         `location` as `file:line` in the patched copy and `kind` one of `new` (a security \
         defect the patch made), `relocated` (the finding's violation moved elsewhere) or \
         `regression` (something that worked before the patch and does not after it, which \
         is not a security defect: a refused legitimate request, a cluster that no longer \
         forms). A regression is recorded under functionality, never as a relocation. A \
         candidate is your reading until a run shows it: write a proof of concept for it \
         under `relocation/<id>/` in the fix directory, under the contract above, run \
         `cd <baseline> && <interpreter> <up><script>` and then \
         `cd <patched> && <interpreter> <up><script>`, with `<baseline>`, `<patched>` and \
         `<up>` exactly as the prompt gives them and `<script>` the proof's path from the \
         project root, and record `command` as `<interpreter> <script>`, without `<up>`. Only a candidate whose proof of \
         concept shows it in the patched copy counts against the fix; one with no \
         `command`, or whose run does not show it, is recorded as a claim for a \
         maintainer and rejects nothing. Do not report a candidate you would not write a \
         proof for. If the \
         project has a fuzz harness that reaches the patched functions, give a bounded \
         command for it, fixed seed and fixed run count, under the contract above, and run \
         `cd <patched> && <command>`.\n\
         2. Functionality. Use the test command the prompt gives; if it gives none, the \
         project's own, the narrowest that exercises the patched files. Run \
         `cd <baseline> && <command>` and then `cd <patched> && <command>`. \
         If the prompt gives a coverage command, or the project has coverage tooling, run \
         `cd <patched> && <coverage command>`; its output must list each file with \
         a percentage. Then write a benign-input harness under `benign/` in the fix \
         directory: inputs the code accepted before the patch and must still accept, sent \
         through the patched functions. It prints the marker line, then each input's output \
         and observable state, with nothing that varies between runs (no times, addresses, \
         random ids or unordered listings), and exits zero. Run it as \
         `cd <baseline> && <interpreter> <up><script>` twice and \
         `cd <patched> && <interpreter> <up><script>` once, and record its `command` as \
         `<interpreter> <script>`. The baseline copy is shared by the whole run: do not \
         write into it.\n\
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

/// The text of one of [`FIX_SKILLS`] with the run's project context
/// and threat model after it, as the walks carry them. `sections` is
/// empty when the run has neither.
pub fn skill_text_with(name: &str, run_id: &str, tools: &str, sections: &str) -> String {
    let text = skill_text(name, run_id, tools);
    if sections.trim().is_empty() {
        text
    } else {
        format!("{text}\n{sections}")
    }
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

/// The commands the reproduction arm reads, in the order they run,
/// and how many of them come before the patch is written.
pub fn reproduction_commands(
    layout: &Layout,
    command: &str,
    revision: &str,
) -> (Vec<String>, usize) {
    let mut out = vec![layout.extract_baseline(revision)];
    out.extend(layout.carry_into_baseline());
    out.push(layout.extract_patched(revision));
    let before_patch = out.len();
    out.push(layout.apply());
    out.push(layout.in_copy("baseline", command));
    out.push(layout.in_copy("patched", command));
    out.push(layout.revert());
    out.push(layout.check_reverted(revision));
    // The same string as the patched run: here it sees the revision
    // again, in the same directory, rebuilt from what the patch touched.
    out.push(layout.in_copy("patched", command));
    out.push(layout.apply());
    (out, before_patch)
}

/// The commands the runner composes for one finding's arms, known
/// before any agent of the fix step runs: the reproduction's sequence,
/// the runner's own preparation, each of the finding's other confirmed
/// reproductions in both copies, and the configured test and coverage
/// commands. This is the plan the operator is shown and approves once.
/// A script an agent writes later is not in it and is asked on its own.
pub fn plan_commands(
    confirmed: &Confirmed,
    run_id: &str,
    rel_dir: &str,
    revision: &str,
    functionality: &FunctionalityConfig,
) -> Vec<String> {
    let command = confirmed.reproduction.command.trim();
    let (mut out, _) = reproduction_commands(
        &Layout::for_reproduction(run_id, rel_dir, command),
        command,
        revision,
    );
    let layout = layout_for(confirmed, run_id, rel_dir);
    out.push(layout.ensure_patched(revision));
    out.extend(layout.carry_into("baseline"));
    out.extend(layout.carry_into("patched"));
    out.push(layout.ensure_applied());
    for variant in carried_variants(confirmed, run_id) {
        out.push(layout.in_copy("baseline", &variant.command));
        out.push(layout.in_copy("patched", &variant.command));
    }
    if let Some(test) = &functionality.test_command {
        out.push(layout.in_copy("baseline", test));
        out.push(layout.in_copy("patched", test));
    }
    if let Some(coverage) = &functionality.coverage_command {
        out.push(layout.in_copy("patched", coverage));
    }
    let mut seen = BTreeSet::new();
    out.retain(|c| seen.insert(c.trim().to_string()));
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
    rounds: usize,
) -> String {
    let layout = Layout::for_reproduction(run_id, fix_dir_rel, &confirmed.reproduction.command);
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
    let (commands, before_patch) =
        reproduction_commands(&layout, &confirmed.reproduction.command, revision);
    format!(
        "/fix Write a candidate fix for this confirmed finding. Run-id: `{run_id}`. \
         Code revision: `{revision}`. Fix directory: `{}`. {invariant} {origin} {patch} \
         You have {rounds} tool rounds; the commands below take {} of them.\n\n\
         The copies are `{}` (baseline, shared by the run) and `{}` (patched). \
         Commands, in this order, each exactly as written. The first {before_patch} before \
         the patch, the rest after it:\n\n{}\n\n\
         Finding:\n```json\n{}\n```\n\n\
         Reproduction:\n```json\n{}\n```",
        layout.dir,
        commands.len(),
        layout.copy("baseline"),
        layout.copy("patched"),
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
    rounds: usize,
) -> String {
    let layout = layout_for(confirmed, run_id, fix_dir_rel);
    let carried = carried_variants(confirmed, run_id);
    let already = if carried.is_empty() {
        "The runner has run no variant of its own.".to_string()
    } else {
        format!(
            "The runner has already run these as variants, in both copies; do not repeat \
             them:\n{}",
            carried
                .iter()
                .map(|v| format!("- `{}`: {}", v.command, v.path))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    format!(
        "/fix-attack Find other routes to this patched finding. Run-id: `{run_id}`. Fix \
         directory: `{0}`. The patch is `{0}/fix.patch`. `<baseline>` is `{3}`, \
         `<patched>` is `{4}`, and `<up>` is `{5}`. Step records are in \
         `.lyrik/state/runs/{run_id}/findings.json`. \
         Write a proof of concept for at least {minimum} paths by different routes. The \
         original reproduction's command is `{1}`; a variant is not that command. You have \
         {rounds} tool rounds.\n\n{already}\n\n\
         Finding:\n```json\n{2}\n```",
        layout.dir,
        confirmed.reproduction.command,
        finding_brief(confirmed),
        layout.copy("baseline"),
        layout.copy("patched"),
        layout.up()
    )
}

/// The prompt the recheck agent receives.
pub fn build_recheck_prompt(
    confirmed: &Confirmed,
    run_id: &str,
    fix_dir_rel: &str,
    functionality: &FunctionalityConfig,
    benign_required: bool,
    rounds: usize,
) -> String {
    let layout = layout_for(confirmed, run_id, fix_dir_rel);
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
         directory: `{0}`. The patch is `{0}/fix.patch`. `<baseline>` is `{4}`, \
         `<patched>` is `{5}`, and `<up>` is `{6}`. {1} {2} {benign} You have {rounds} tool \
         rounds: run the functionality commands first, then the re-walk.\n\n\
         Finding:\n```json\n{3}\n```",
        layout.dir,
        named("test", &functionality.test_command),
        named("coverage", &functionality.coverage_command),
        finding_brief(confirmed),
        layout.copy("baseline"),
        layout.copy("patched"),
        layout.up()
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
            let layout = Layout::for_reproduction(RUN, REL, REPRO);
            let mut case = Self {
                tmp,
                observed: Vec::new(),
                confirmed,
            };
            // The patched copy runs the reproduction twice: with the
            // patch in, where the defect is gone, and with it taken
            // out, where it is back.
            let mut patched_runs = 0;
            for c in reproduction_commands(&layout, REPRO, REV).0 {
                let (ok, out) = if c == layout.in_copy("patched", REPRO) {
                    patched_runs += 1;
                    if patched_runs == 1 {
                        (true, clean())
                    } else {
                        (false, shown())
                    }
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
                ran: true,
            });
        }

        /// Two variants by different paths; the second holds or not.
        fn with_variants(mut self, second_shown_on_patched: bool) -> Self {
            let layout = Layout::for_reproduction(RUN, REL, REPRO);
            let dir = self.tmp.path().join(REL);
            for (id, path, patched_shown) in
                [("v1", "p1", false), ("v2", "p2", second_shown_on_patched)]
            {
                std::fs::create_dir_all(dir.join(format!("variants/{id}"))).unwrap();
                std::fs::write(dir.join(format!("variants/{id}/run.py")), "x").unwrap();
                std::fs::write(dir.join(format!("variants/{id}/path.txt")), path).unwrap();
                let cmd = format!("python3 {}/variants/{id}/run.py", layout.dir);
                self.add(layout.in_copy("baseline", &cmd), false, &shown());
                let out = if patched_shown { shown() } else { clean() };
                self.add(layout.in_copy("patched", &cmd), !patched_shown, &out);
            }
            std::fs::write(
                dir.join("attack.json"),
                r#"{"paths":[{"id":"p1","route":"caller","location":"src/c.rs:3"},
                             {"id":"p2","route":"error_path","location":"src/d.rs:9"},
                             {"id":"p3","route":"cleanup","location":"src/e.rs:2"}]}"#,
            )
            .unwrap();
            self
        }

        fn judge(&self) -> FixOutcome {
            self.judge_with(false, None)
        }

        /// `supplied` is the patch read at run start for this finding.
        fn judge_with(&self, target_modified: bool, supplied: Option<&str>) -> FixOutcome {
            self.judge_changed(target_modified, supplied, &InputChanges::default())
        }

        fn judge_changed(
            &self,
            target_modified: bool,
            supplied: Option<&str>,
            changes: &InputChanges,
        ) -> FixOutcome {
            judge(&JudgeInput {
                run_dir: self.tmp.path(),
                rel_dir: REL,
                run_id: RUN,
                confirmed: &self.confirmed,
                revision: REV,
                observed: &self.observed,
                target: self.tmp.path(),
                tree: &if target_modified {
                    TreeRecord::Changed
                } else {
                    TreeRecord::Unchanged
                },
                agents: &[],
                fix_model: "some-model",
                inputs: &inputs(supplied),
                changes,
            })
        }
    }

    /// Run inputs holding, at most, a patch supplied for the one finding.
    fn inputs(supplied: Option<&str>) -> FixInputs {
        FixInputs {
            config_sha256: sha256_hex(b"{}"),
            functionality: FunctionalityConfig::default(),
            patches: supplied
                .map(|text| {
                    (
                        slug("auth::src/a.rs:10"),
                        SuppliedPatch {
                            bytes: text.as_bytes().to_vec(),
                            sha256: sha256_hex(text.as_bytes()),
                        },
                    )
                })
                .into_iter()
                .collect(),
            tree: Ok("fingerprint".to_string()),
            opt_outs: Vec::new(),
            reproductions: BTreeMap::new(),
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
        // The label never stands without the tally.
        assert_eq!(
            out.label.as_deref(),
            Some("candidate fix: 3 of 5 arms passed, 0 inconclusive, 2 not_run")
        );
        assert_eq!(
            out.arm_tally,
            ArmTally {
                pass: 3,
                fail: 0,
                inconclusive: 0,
                not_run: 2
            }
        );
        // The functionality arm did not run: unverified, and labelled.
        assert!(out.labels.contains(&"functionality_unverified"));
        assert_eq!(out.inputs.config_sha256, sha256_hex(b"{}"));
        assert_eq!(out.inputs.supplied_patch_sha256, None);
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
        assert_eq!(out.patch_source, PatchSource::Generated);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["verdict"], "candidate_fix");
        assert_eq!(v["patch_source"], "generated");
        assert_eq!(v["arm_tally"]["not_run"], 2);
        assert_eq!(v["arms"][0]["basis"], "executed");
        assert_eq!(v["arms"][3]["state"], "not_run");
        assert!(v["arms"][3].get("basis").is_none());
        assert_eq!(
            v["root_cause_claim"]["evidence_state"],
            "confirmed_by_executed_poc"
        );
        assert_eq!(
            v["artifacts"]["variants"][0],
            format!("{REL}/variants/v1/run.py")
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
        // Partial: the reproduction is stopped, one other path is not.
        assert!(
            out.reasons[0].starts_with(
                "partial fix: the reproduction no longer shows the defect and 1 other path(s) \
                 still do: variants/v2/run.py"
            ),
            "{:?}",
            out.reasons
        );
        assert!(
            out.reasons[1].starts_with(
                "variant arm failed: variant variants/v2/run.py: shows the defect in the baseline \
                 and still shows it in the patched copy; the patch leaves this path open: p2"
            ),
            "{:?}",
            out.reasons
        );
        let partial = out.partial.expect("the record says partial");
        assert_eq!(partial.open_paths.len(), 1);
        assert_eq!(partial.open_paths[0].path, "p2");
        assert_eq!(out.variants[0].outcome, "held");
        assert_eq!(out.variants[1].outcome, "open");
        // A fix every variant held under is not partial.
        assert_eq!(
            Case::new(ORIGIN_PATCH).with_variants(false).judge().partial,
            None
        );
    }

    #[test]
    fn the_other_confirmed_reproductions_are_variants_fixed_before_any_agent_runs() {
        // Three agreeing reproductions of one finding, one a repeat of
        // the first command, and one the replay did not agree with.
        let mut b = body();
        let first = b["reproductions"][0].clone();
        let with = |command: &str, expected: &str, agreement: bool| {
            let mut r = first.clone();
            r["command"] = serde_json::json!(command);
            r["expected"] = serde_json::json!(expected);
            r["agreement"] = serde_json::json!(agreement);
            r
        };
        let second =
            format!("sh .lyrik/state/runs/{RUN}/staging/sink-walk/harness/second_setup.sh");
        let caller =
            format!("sh .lyrik/state/runs/{RUN}/staging/chain-walk/harness/other_caller.sh");
        let disputed = format!("sh .lyrik/state/runs/{RUN}/staging/fuzz-walk/harness/disputed.sh");
        let reproductions = b["reproductions"].as_array_mut().unwrap();
        reproductions.push(with(&second, "second setup: exits 1", true));
        reproductions.push(with(REPRO, "the same command again", true));
        reproductions.push(with(&caller, "second caller: exits 1", true));
        reproductions.push(with(&disputed, "not agreed", false));
        let c = confirmed_findings(&b).remove(0);
        assert_eq!(c.reproduction.command, REPRO);
        let carried = carried_variants(&c, RUN);
        assert_eq!(
            carried.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            [
                "reproduction:sink-walk/second_setup.sh",
                "reproduction:chain-walk/other_caller.sh"
            ]
        );
        assert_eq!(carried[0].command, second);
        assert_eq!(carried[0].path, "second setup: exits 1");
        assert!(
            carried
                .iter()
                .all(|v| v.source == arms::VariantSource::Reproduction)
        );
        // Each copy carries the harness of every walk a variant names.
        let layout = layout_for(&c, RUN, REL);
        for walk in ["sink-walk", "chain-walk"] {
            assert!(
                layout.carried.iter().any(|w| w == walk),
                "{:?}",
                layout.carried
            );
        }
        // The attack prompt tells the agent these are already run.
        let prompt = build_attack_prompt(&c, RUN, REL, 2, 60);
        assert!(
            prompt.contains(&format!("- `{second}`: second setup: exits 1")),
            "{prompt}"
        );
        assert!(prompt.contains("You have 60 tool rounds"), "{prompt}");
    }

    #[test]
    fn a_carried_reproduction_still_open_in_the_patched_copy_makes_the_fix_partial() {
        let mut case = Case::new(ORIGIN_PATCH);
        let second =
            format!("sh .lyrik/state/runs/{RUN}/staging/sink-walk/harness/second_setup.sh");
        let mut other = case.confirmed.reproduction.clone();
        other.command = second.clone();
        other.expected = "second setup: the write is accepted".into();
        case.confirmed.others.push(other);
        let layout = layout_for(&case.confirmed, RUN, REL);
        // The runner's own steps: the patch in, then the variant twice.
        case.add(layout.ensure_applied(), true, "");
        case.add(layout.in_copy("baseline", &second), false, &shown());
        case.add(layout.in_copy("patched", &second), false, &shown());
        let out = case.judge();
        assert_eq!(out.verdict, Verdict::Rejected, "{:?}", out.reasons);
        assert_eq!(
            out.arms[0].state,
            ArmState::Pass,
            "{:?}",
            out.arms[0].reasons
        );
        assert_eq!(out.arms[1].state, ArmState::Fail);
        assert_eq!(out.arms[1].basis, Some(arms::Basis::Executed));
        let partial = out.partial.expect("partial");
        assert_eq!(
            partial.open_paths[0].id,
            "reproduction:sink-walk/second_setup.sh"
        );
        assert_eq!(
            partial.open_paths[0].path,
            "second setup: the write is accepted"
        );
        assert_eq!(partial.open_paths[0].command, second);
        assert!(
            out.reasons[0].starts_with("partial fix: "),
            "{:?}",
            out.reasons
        );
        // No attack.json and no agent variant was needed for any of it.
        assert_eq!(out.artifacts.attack, None);
    }

    #[test]
    fn a_variant_under_a_declared_opt_out_is_open_by_configuration_on_the_record() {
        // The second variant still shows the defect in the patched copy,
        // and its script switches the control off.
        let case = Case::new(ORIGIN_PATCH).with_variants(true);
        let run = case.tmp.path().join(REL).join("variants/v2/run.py");
        std::fs::write(&run, "os.environ['APP_STRICT_MODE'] = 'false'\n").unwrap();
        let judged = |opt_outs: &[&str]| {
            let mut i = inputs(None);
            i.opt_outs =
                explicit_opt_outs(&serde_json::json!({"fix": {"explicit_opt_outs": opt_outs}}));
            judge(&JudgeInput {
                run_dir: case.tmp.path(),
                rel_dir: REL,
                run_id: RUN,
                confirmed: &case.confirmed,
                revision: REV,
                observed: &case.observed,
                target: case.tmp.path(),
                tree: &TreeRecord::Unchanged,
                agents: &[],
                fix_model: "some-model",
                inputs: &i,
                changes: &InputChanges::default(),
            })
        };
        // Nothing declared: the open variant rejects the fix as partial.
        let out = judged(&[]);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(out.open_by_configuration.is_empty());
        // Declared by the operator: recorded, and the arm does not fail.
        let out = judged(&["APP_STRICT_MODE'] = 'false'"]);
        assert_ne!(
            out.arms[1].state,
            ArmState::Fail,
            "{:?}",
            out.arms[1].reasons
        );
        assert_eq!(out.partial, None);
        assert_eq!(out.open_by_configuration.len(), 1);
        assert_eq!(out.open_by_configuration[0].id, "variants/v2/run.py");
        assert_eq!(
            out.open_by_configuration[0].setting,
            "APP_STRICT_MODE'] = 'false'"
        );
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["variants"][1]["outcome"], "open_by_configuration");
        // A declaration the script does not carry changes nothing, and
        // one too short to mean anything is not read.
        assert_eq!(judged(&["OTHER_SETTING=off"]).verdict, Verdict::Rejected);
        assert_eq!(judged(&["false"]).verdict, Verdict::Rejected);
    }

    #[test]
    fn the_plan_is_the_runner_composed_commands_of_one_finding_and_no_others() {
        let mut c = confirmed_findings(&body()).remove(0);
        let second =
            format!("sh .lyrik/state/runs/{RUN}/staging/sink-walk/harness/second_setup.sh");
        let mut other = c.reproduction.clone();
        other.command = second.clone();
        c.others.push(other);
        let config = FunctionalityConfig {
            test_command: Some("make check".into()),
            coverage_command: Some("make cover".into()),
        };
        let plan = plan_commands(&c, RUN, REL, REV, &config);
        let layout = layout_for(&c, RUN, REL);
        // Every command the reproduction arm reads, in the order the agent runs them.
        let (reproduction, _) =
            reproduction_commands(&Layout::for_reproduction(RUN, REL, REPRO), REPRO, REV);
        for command in &reproduction {
            assert!(plan.contains(command), "{command}");
        }
        // The runner's own steps, the carried variant in both copies, the tests.
        for command in [
            layout.ensure_patched(REV),
            layout.ensure_applied(),
            layout.in_copy("baseline", &second),
            layout.in_copy("patched", &second),
            layout.in_copy("baseline", "make check"),
            layout.in_copy("patched", "make check"),
            layout.in_copy("patched", "make cover"),
        ] {
            assert!(plan.contains(&command), "{command}");
        }
        // No command is listed twice, though the agent runs some twice.
        let mut unique = plan.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), plan.len());
        // A script an agent writes later is not in the plan, nor is
        // anything outside this finding's directory and the shared baseline.
        let agent_variant =
            layout.in_copy("patched", &format!("sh {}/variants/v1/run.sh", layout.dir));
        assert!(!plan.contains(&agent_variant));
        let other_finding = Layout::new(RUN, "staging/fix/another-finding");
        assert!(!plan.contains(&other_finding.apply()));
        for command in &plan {
            assert!(
                command.contains(&layout.dir) || command.contains(&layout.copy("baseline")),
                "{command}"
            );
        }
        // With no configured commands the plan has no test entries.
        let bare = plan_commands(&c, RUN, REL, REV, &FunctionalityConfig::default());
        assert!(!bare.iter().any(|x| x.contains("make ")));
    }

    /// Two findings of one run with the same origin: two sides of one
    /// missing check.
    fn two_members() -> (Confirmed, Confirmed) {
        let finding = |id: &str, invariant: &str| {
            serde_json::json!({"stable_id": id, "invariant": invariant,
                "location": {"file": "src/a.rs", "line_start": 10},
                "origin": {"file": "src/gate.rs", "line_start": 4, "function": "install"}})
        };
        let record = |id: &str, script: &str| -> ReproductionRecord {
            serde_json::from_value(serde_json::json!({
                "stable_id": id, "expected": format!("{script} exits 1"), "observed": "exit 1",
                "outcome": "reproduced", "code_revision": REV,
                "command": format!("sh .lyrik/state/runs/{RUN}/staging/sink-walk/harness/{script}"),
            }))
            .unwrap()
        };
        let a = Confirmed {
            stable_id: "auth::src/a.rs:10".into(),
            finding: finding("auth::src/a.rs:10", "every request is checked"),
            reproduction: record("auth::src/a.rs:10", "first_setup.sh"),
            others: vec![record("auth::src/a.rs:10", "first_other_entry.sh")],
        };
        let b = Confirmed {
            stable_id: "auth::src/b.rs:20".into(),
            finding: finding("auth::src/b.rs:20", "no credential never means access"),
            reproduction: record("auth::src/b.rs:20", "second_setup.sh"),
            others: Vec::new(),
        };
        (a, b)
    }

    const A_DIR: &str = "staging/fix/auth-src-a.rs-10";
    const B_DIR: &str = "staging/fix/auth-src-b.rs-20";
    const UNION: &str = "staging/fix/_combined-1";

    /// The log of a combined run: both patches applied, then each
    /// command in both copies. `open` is a command still shown in the
    /// combined copy; `second_applies` whether the second patch went in.
    fn combined_log(
        a: &Confirmed,
        b: &Confirmed,
        open: Option<&str>,
        second_applies: bool,
    ) -> Vec<Observed> {
        let members = [
            CombinedMember {
                confirmed: a,
                rel_dir: A_DIR,
            },
            CombinedMember {
                confirmed: b,
                rel_dir: B_DIR,
            },
        ];
        let layout = combined_layout(&members, RUN, UNION);
        let mut log: Vec<Observed> = Vec::new();
        let mut add = |command: String, success: bool, output: &str| {
            let seq = log.len();
            log.push(Observed {
                seq,
                command,
                success,
                output: output.to_string(),
                ran: true,
            });
        };
        add(
            arms::apply_member(&layout, &Layout::new(RUN, A_DIR).dir),
            true,
            "",
        );
        add(
            arms::apply_member(&layout, &Layout::new(RUN, B_DIR).dir),
            second_applies,
            "",
        );
        let commands = [
            a.reproduction.command.clone(),
            b.reproduction.command.clone(),
            a.others[0].command.clone(),
        ];
        for command in &commands {
            add(layout.in_copy("baseline", command), false, &shown());
            let still = open == Some(command.as_str());
            add(
                layout.in_copy("patched", command),
                !still,
                &if still { shown() } else { clean() },
            );
        }
        add(layout.in_copy("baseline", "make check"), true, "ok");
        add(layout.in_copy("patched", "make check"), true, "ok");
        log
    }

    fn judge_union(
        a: &Confirmed,
        b: &Confirmed,
        log: &[Observed],
        minimum: usize,
    ) -> CombinedOutcome {
        let tmp = tempdir().unwrap();
        let mut i = inputs(None);
        i.functionality.test_command = Some("make check".into());
        judge_combined(&CombinedInput {
            run_dir: tmp.path(),
            rel_dir: UNION,
            run_id: RUN,
            members: &[
                CombinedMember {
                    confirmed: a,
                    rel_dir: A_DIR,
                },
                CombinedMember {
                    confirmed: b,
                    rel_dir: B_DIR,
                },
            ],
            shared: "origin src/gate.rs:install",
            observed: log,
            target: tmp.path(),
            tree: &TreeRecord::Unchanged,
            inputs: &i,
            variant_minimum: minimum,
        })
    }

    #[test]
    fn partial_fixes_that_share_an_origin_or_an_invariant_are_grouped() {
        let (a, b) = two_members();
        let partial = |stable_id: &str, is_partial: bool| {
            let mut out = Case::new(ORIGIN_PATCH).with_variants(is_partial).judge();
            out.stable_id = stable_id.to_string();
            assert_eq!(out.partial.is_some(), is_partial);
            out
        };
        let (pa, pb) = (partial(&a.stable_id, true), partial(&b.stable_id, true));
        // The same origin.
        assert_eq!(
            combined_groups(&[(&a, &pa), (&b, &pb)]),
            [(vec![0, 1], "origin src/gate.rs:install".to_string())]
        );
        // A member whose own fix was not partial is left out, and one alone is no group.
        let whole = partial(&b.stable_id, false);
        assert!(combined_groups(&[(&a, &pa), (&b, &whole)]).is_empty());
        // Different origins and different invariants: nothing is shared.
        let mut c = b.clone();
        c.finding["origin"] = serde_json::json!({"file": "src/other.rs", "line_start": 9});
        assert!(combined_groups(&[(&a, &pa), (&c, &pb)]).is_empty());
        // Different origins, the same invariant in other spacing and case.
        c.finding["invariant"] = serde_json::json!("Every  request is\nchecked");
        assert_eq!(
            combined_groups(&[(&a, &pa), (&c, &pb)]),
            [(vec![0, 1], "the same invariant".to_string())]
        );
    }

    #[test]
    fn the_union_of_two_partial_patches_is_judged_on_its_own_runs() {
        let (a, b) = two_members();
        // Together the patches stop both reproductions and the other variant.
        let out = judge_union(&a, &b, &combined_log(&a, &b, None, true), 1);
        assert_eq!(out.verdict, Verdict::CandidateFix, "{:?}", out.reasons);
        assert_eq!(out.members, ["auth::src/a.rs:10", "auth::src/b.rs:20"]);
        assert!(out.patches_apply_together);
        assert_eq!(
            out.patches,
            [format!("{A_DIR}/fix.patch"), format!("{B_DIR}/fix.patch")]
        );
        let states: Vec<(&str, ArmState)> = out.arms.iter().map(|x| (x.arm, x.state)).collect();
        assert_eq!(
            states,
            [
                ("reproduction", ArmState::Pass),
                ("variant", ArmState::Pass),
                ("functionality", ArmState::Inconclusive)
            ]
        );
        assert_eq!(
            out.label.as_deref(),
            Some("candidate fix: 2 of 3 arms passed, 1 inconclusive, 0 not_run")
        );
        assert_eq!(out.variants.len(), 1);
        assert_eq!(out.variants[0].outcome, "held");
        // Fewer variants than the members' patches required: not a candidate.
        let out = judge_union(&a, &b, &combined_log(&a, &b, None, true), 4);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        // A variant still open with both patches in: rejected, partial, the path named.
        let other = a.others[0].command.clone();
        let out = judge_union(&a, &b, &combined_log(&a, &b, Some(&other), true), 1);
        assert_eq!(out.verdict, Verdict::Rejected);
        let partial = out.partial.expect("partial");
        assert_eq!(partial.open_paths[0].command, other);
        assert!(
            out.reasons[0].starts_with("partial fix: no member's reproduction shows the defect")
        );
        // A member's own reproduction still shown in the union: the reproduction arm fails.
        let repro_b = b.reproduction.command.clone();
        let out = judge_union(&a, &b, &combined_log(&a, &b, Some(&repro_b), true), 1);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert_eq!(out.arms[0].state, ArmState::Fail);
        assert!(
            out.arms[0].reasons[0]
                .contains("auth::src/b.rs:20 still shows the defect in the combined copy")
        );
        assert_eq!(out.partial, None);
    }

    #[test]
    fn member_patches_that_do_not_apply_together_are_recorded_as_such() {
        let (a, b) = two_members();
        let out = judge_union(&a, &b, &combined_log(&a, &b, None, false), 1);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert!(!out.patches_apply_together);
        assert!(
            out.arms.is_empty(),
            "no arm is read on a copy that is not the union"
        );
        assert_eq!(
            out.reasons,
            [
                "the member patches do not apply together: the patch of auth::src/b.rs:20 does not \
              apply on top of the ones before it"
            ]
        );
        // Nothing on the log at all: said, not guessed.
        let out = judge_union(&a, &b, &[], 1);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(
            out.reasons,
            ["the patch of auth::src/a.rs:10 was not applied to the combined copy"]
        );
    }

    #[test]
    fn the_combined_plan_is_the_runner_composed_commands_and_no_agent_script() {
        let (a, b) = two_members();
        let tmp = tempdir().unwrap();
        // The variant agent of the first member wrote a script.
        let v = tmp.path().join(A_DIR).join("variants/other_shape");
        std::fs::create_dir_all(&v).unwrap();
        std::fs::write(v.join("run.sh"), "x").unwrap();
        let members = [
            CombinedMember {
                confirmed: &a,
                rel_dir: A_DIR,
            },
            CombinedMember {
                confirmed: &b,
                rel_dir: B_DIR,
            },
        ];
        let layout = combined_layout(&members, RUN, UNION);
        let variants = combined_variants(&members, tmp.path(), RUN, &[]);
        let ids: Vec<&str> = variants.iter().map(|v| v.spec.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "reproduction:sink-walk/first_other_entry.sh",
                "auth-src-a.rs-10/variants/other_shape/run.sh"
            ]
        );
        let config = FunctionalityConfig {
            test_command: Some("make check".into()),
            coverage_command: None,
        };
        let (setup, plan) = combined_plan(&members, RUN, &layout, REV, &config, &variants);
        // Setup ends with each member patch applied, in member order.
        assert_eq!(
            &plan[setup - 2..setup],
            [
                arms::apply_member(&layout, &Layout::new(RUN, A_DIR).dir),
                arms::apply_member(&layout, &Layout::new(RUN, B_DIR).dir)
            ]
        );
        for command in [
            &a.reproduction.command,
            &b.reproduction.command,
            &a.others[0].command,
        ] {
            assert!(
                plan.contains(&layout.in_copy("baseline", command)),
                "{command}"
            );
            assert!(
                plan.contains(&layout.in_copy("patched", command)),
                "{command}"
            );
        }
        assert!(plan.contains(&layout.in_copy("patched", "make check")));
        // The agent's script is asked on its own: it is not in the plan.
        assert!(
            !plan.iter().any(|c| c.contains("variants/other_shape")),
            "{plan:?}"
        );
    }

    #[test]
    fn a_supplied_reproduction_is_read_once_hashed_and_only_a_regular_file() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join(SUPPLIED_REPRODUCTION_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(tmp.path().join(".lyrik")).unwrap();
        std::fs::write(tmp.path().join(".lyrik/config.json"), "{}").unwrap();
        std::fs::write(dir.join("auth-src-a.rs-10.sh"), "echo first\n").unwrap();
        std::fs::write(dir.join("auth-src-b.rs-5.py"), "print(1)\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "not a script").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hostname", dir.join("auth-src-c.rs-1.sh")).unwrap();
        let inputs = FixInputs::capture(tmp.path(), "{}", &serde_json::json!({}));
        let keys: Vec<&String> = inputs.reproductions.keys().collect();
        assert_eq!(keys, ["auth-src-a.rs-10", "auth-src-b.rs-5"]);
        let a = &inputs.reproductions["auth-src-a.rs-10"];
        assert_eq!((a.interpreter, a.extension), ("sh", "sh"));
        assert_eq!(a.sha256, sha256_hex(b"echo first\n"));
        assert_eq!(
            inputs.reproductions["auth-src-b.rs-5"].interpreter,
            "python3"
        );
        // The command the runner composes for it, and where it is put.
        let (rel, command) = supplied_reproduction_paths(RUN, REL, a);
        assert_eq!(rel, format!("{REL}/supplied/reproduction.sh"));
        assert_eq!(
            command,
            format!("sh .lyrik/state/runs/{RUN}/{REL}/supplied/reproduction.sh")
        );
        // Nothing changed yet; then the script is edited mid-run and
        // another appears.
        assert!(!inputs.changes(tmp.path()).any());
        std::fs::write(dir.join("auth-src-a.rs-10.sh"), "echo second\n").unwrap();
        std::fs::write(dir.join("auth-src-d.rs-2.sh"), "echo new\n").unwrap();
        let changes = inputs.changes(tmp.path());
        assert!(changes.any());
        let changed: Vec<&String> = changes.reproductions.iter().collect();
        assert_eq!(changed, ["auth-src-a.rs-10", "auth-src-d.rs-2"]);
        // What was read at run start is still what the run holds.
        assert_eq!(
            inputs.reproductions["auth-src-a.rs-10"].bytes,
            b"echo first\n"
        );
    }

    #[test]
    fn a_supplied_reproduction_is_confirmed_only_by_an_observed_run() {
        let done = |success: bool, output: &str| arms::Run::Done {
            success,
            output: output.to_string(),
            seq: 0,
        };
        // Never run, refused, or timed out: no confirmation.
        for run in [arms::Run::Never, arms::Run::Refused, arms::Run::TimedOut] {
            let (status, detail) = supplied_status(&run);
            assert_eq!(status, SuppliedStatus::Inconclusive, "{run:?}");
            assert!(detail.is_some());
        }
        // Ran and never reached its assertion: no confirmation either,
        // whatever it exited with.
        assert_eq!(
            supplied_status(&done(false, "sh: not found")).0,
            SuppliedStatus::Inconclusive
        );
        // The marker and a zero exit: the defect is not shown.
        assert_eq!(
            supplied_status(&done(true, &clean())).0,
            SuppliedStatus::NotShown
        );
        // The marker and a non-zero exit: confirmed.
        assert_eq!(
            supplied_status(&done(false, &shown())),
            (SuppliedStatus::Confirmed, None)
        );
    }

    #[test]
    fn a_confirmed_supplied_reproduction_becomes_the_reproduction_the_arms_run() {
        let b = body();
        let command = format!(
            "sh .lyrik/state/runs/{RUN}/staging/fix/auth-src-b.rs-5/supplied/reproduction.sh"
        );
        // The second finding has no reproduction the replay agreed with.
        let walk = confirmed_findings(&b);
        assert!(walk.iter().all(|c| c.stable_id != "auth::src/b.rs:5"));
        let c = confirm_with_supplied(&b, None, "auth::src/b.rs:5", &command, REV).unwrap();
        assert_eq!(c.reproduction.command, command);
        assert!(c.others.is_empty());
        assert_eq!(c.finding["title"], "u");
        // A finding the walks did confirm keeps their reproduction as a variant.
        let first = &walk[0];
        let command_a = format!("sh .lyrik/state/runs/{RUN}/{REL}/supplied/reproduction.sh");
        let c = confirm_with_supplied(&b, Some(first), &first.stable_id, &command_a, REV).unwrap();
        assert_eq!(c.reproduction.command, command_a);
        assert_eq!(c.others.len(), 1);
        assert_eq!(c.others[0].command, REPRO);
        let carried = carried_variants(&c, RUN);
        assert_eq!(carried[0].command, REPRO);
        // A stable id that names no finding confirms nothing.
        assert!(confirm_with_supplied(&b, None, "auth::src/none.rs:1", &command, REV).is_none());
    }

    #[test]
    fn a_supplied_reproduction_that_changed_during_the_run_withdraws_the_arms() {
        // The case's reproduction is the supplied script's command.
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        let script = SuppliedReproduction {
            bytes: b"x".to_vec(),
            sha256: sha256_hex(b"x"),
            interpreter: "sh",
            extension: "sh",
        };
        let (_, command) = supplied_reproduction_paths(RUN, REL, &script);
        let judged = |case: &Case, changed: bool| {
            let mut i = inputs(None);
            i.reproductions
                .insert(slug("auth::src/a.rs:10"), script.clone());
            let mut changes = InputChanges::default();
            if changed {
                changes.reproductions.insert(slug("auth::src/a.rs:10"));
            }
            judge(&JudgeInput {
                run_dir: case.tmp.path(),
                rel_dir: REL,
                run_id: RUN,
                confirmed: &case.confirmed,
                revision: REV,
                observed: &case.observed,
                target: case.tmp.path(),
                tree: &TreeRecord::Unchanged,
                agents: &[],
                fix_model: "some-model",
                inputs: &i,
                changes: &changes,
            })
        };
        // The arms ran on the walk's reproduction: a supplied script
        // for the same finding is not what they rested on.
        let out = judged(&case, true);
        assert_eq!(out.inputs.supplied_reproduction_sha256, None);
        assert_eq!(out.verdict, Verdict::CandidateFix, "{:?}", out.reasons);
        // The arms ran on the supplied script.
        case.confirmed.reproduction.command = command.clone();
        let out = judged(&case, false);
        assert_eq!(
            out.inputs.supplied_reproduction_sha256.as_deref(),
            Some(script.sha256.as_str())
        );
        let out = judged(&case, true);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert!(
            out.reasons
                .iter()
                .any(|r| r == "the reproduction supplied for this finding changed during the run"),
            "{:?}",
            out.reasons
        );
        assert!(out.arms.iter().all(|a| a.state == ArmState::Inconclusive));
    }

    #[test]
    fn an_agent_stopped_at_its_round_limit_is_on_the_arm_it_feeds_with_the_count() {
        let case = Case::new(ORIGIN_PATCH).with_variants(false);
        let agents = [
            AgentRounds {
                step: "fix".into(),
                rounds: 14,
                round_limit: 60,
                incomplete: false,
            },
            AgentRounds {
                step: "fix-attack".into(),
                rounds: 60,
                round_limit: 60,
                incomplete: true,
            },
            AgentRounds {
                step: "fix-recheck".into(),
                rounds: 60,
                round_limit: 60,
                incomplete: true,
            },
        ];
        let out = judge(&JudgeInput {
            run_dir: case.tmp.path(),
            rel_dir: REL,
            run_id: RUN,
            confirmed: &case.confirmed,
            revision: REV,
            observed: &case.observed,
            target: case.tmp.path(),
            tree: &TreeRecord::Unchanged,
            agents: &agents,
            fix_model: "some-model",
            inputs: &inputs(None),
            changes: &InputChanges::default(),
        });
        let incomplete = |arm: &str| {
            out.arms
                .iter()
                .find(|a| a.arm == arm)
                .unwrap()
                .incomplete
                .clone()
        };
        assert_eq!(incomplete("reproduction"), None);
        assert_eq!(incomplete("root_cause"), None);
        assert_eq!(
            incomplete("variant").as_deref(),
            Some(
                "the fix-attack agent was stopped at its limit of 60 tool rounds before it finished"
            )
        );
        for arm in ["relocation", "functionality"] {
            assert_eq!(
                incomplete(arm).as_deref(),
                Some(
                    "the fix-recheck agent was stopped at its limit of 60 tool rounds before it finished"
                )
            );
        }
        // What the variant agent got run before it stopped still counts.
        assert_eq!(
            out.arms[1].state,
            ArmState::Pass,
            "{:?}",
            out.arms[1].reasons
        );
        assert_eq!(out.agents, agents);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["agents"][1]["rounds"], 60);
        assert_eq!(v["agents"][1]["incomplete"], true);
        assert!(v["arms"][0].get("incomplete").is_none());
        let s = summary(std::slice::from_ref(&out));
        assert_eq!(s["agents_stopped_at_round_limit"], 2);
        assert!(
            summary_line(&s).ends_with("; 2 agent(s) stopped at the tool round limit")
                || summary_line(&s).contains("2 agent(s) stopped at the tool round limit")
        );
    }

    #[test]
    fn an_unknown_tree_state_is_on_the_record_and_is_not_a_candidate() {
        let case = Case::new(ORIGIN_PATCH).with_variants(false);
        let judged = |tree: TreeRecord| {
            judge(&JudgeInput {
                run_dir: case.tmp.path(),
                rel_dir: REL,
                run_id: RUN,
                confirmed: &case.confirmed,
                revision: REV,
                observed: &case.observed,
                target: case.tmp.path(),
                tree: &tree,
                agents: &[],
                fix_model: "some-model",
                inputs: &inputs(None),
                changes: &InputChanges::default(),
            })
        };
        let out = judged(TreeRecord::Unchanged);
        assert_eq!(out.verdict, Verdict::CandidateFix, "{:?}", out.reasons);
        assert_eq!(
            serde_json::to_value(&out).unwrap()["target_tree"]["state"],
            "unchanged"
        );
        let out = judged(TreeRecord::Unknown {
            reason: "not a git work tree".into(),
        });
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(
            out.reasons,
            ["whether the target tree changed during the run is unknown: not a git work tree"]
        );
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["target_tree"]["state"], "unknown");
        assert_eq!(v["target_tree"]["reason"], "not a git work tree");
        let out = judged(TreeRecord::Changed);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.reasons, ["the target tree changed during the fix step"]);
        // The record is read from two fingerprints.
        let (a, b) = (Ok("x".to_string()), Ok("y".to_string()));
        assert_eq!(TreeRecord::of(&a, &a), TreeRecord::Unchanged);
        assert_eq!(TreeRecord::of(&a, &b), TreeRecord::Changed);
        assert_eq!(
            TreeRecord::of(&Err("no repo".to_string()), &a),
            TreeRecord::Unknown {
                reason: "no repo".into()
            }
        );
    }

    #[test]
    fn a_symptom_patch_is_a_claim_until_a_variant_still_works() {
        // The walks place the origin elsewhere; every executed run is
        // clean. That reading alone does not reject the fix.
        let out = Case::new(SINK_PATCH).with_variants(false).judge();
        assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
        let root = arm(&out, "root_cause");
        assert_eq!(root.state, ArmState::Inconclusive);
        assert_eq!(root.basis, Some(arms::Basis::ModelJudged));
        assert!(root.model_claims[0].starts_with("symptom_patch:"));
        assert_eq!(out.verdict, Verdict::CandidateFix);
        assert!(out.labels.contains(&"symptom_patch_claimed"));
        assert!(!out.labels.contains(&"symptom_patch"));
        // The claim is on the record for a maintainer.
        let v = serde_json::to_value(&out).unwrap();
        assert!(
            v["arms"][2]["model_claims"][0]
                .as_str()
                .unwrap()
                .contains("not the origin")
        );
        // With a variant that still works on the patched code, an
        // executed run stands behind it: rejected, on both arms.
        let out = Case::new(SINK_PATCH).with_variants(true).judge();
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(out.labels.contains(&"symptom_patch"));
        assert_eq!(arm(&out, "root_cause").state, ArmState::Fail);
        assert_eq!(arm(&out, "root_cause").basis, Some(arms::Basis::Executed));
        assert!(
            out.reasons
                .iter()
                .any(|r| r.starts_with("root_cause arm failed: symptom_patch:"))
        );
    }

    #[test]
    fn a_model_judged_claim_never_rejects_a_fix_by_itself() {
        // The re-walk reports a relocated candidate with no proof.
        let case = Case::new(ORIGIN_PATCH).with_variants(false);
        std::fs::write(
            case.tmp.path().join(REL).join("recheck.json"),
            r#"{"relocation":{"scope":["decode_len at src/len.rs:2"],
                "candidates":[{"title":"the caller ignores the new error","location":"src/a.rs:9","kind":"new"}]}}"#,
        )
        .unwrap();
        let out = case.judge();
        let relocation = arm(&out, "relocation");
        assert_eq!(relocation.state, ArmState::Inconclusive);
        assert_eq!(relocation.basis, Some(arms::Basis::ModelJudged));
        assert_eq!(
            relocation.model_claims,
            ["new candidate at src/a.rs:9: the caller ignores the new error (no proof of concept)"]
        );
        assert_eq!(out.verdict, Verdict::CandidateFix);
        // No arm anywhere is failed on a model's reading.
        assert!(
            out.arms
                .iter()
                .all(|a| a.state != ArmState::Fail || a.basis == Some(arms::Basis::Executed))
        );
        // The same candidate with a proof that shows it in the patched
        // copy rejects the fix.
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        let layout = Layout::for_reproduction(RUN, REL, REPRO);
        let cmd = "sh ../relocation/c1/poc.sh";
        case.add(layout.in_copy("baseline", cmd), true, &clean());
        case.add(layout.in_copy("patched", cmd), false, &shown());
        std::fs::write(
            case.tmp.path().join(REL).join("recheck.json"),
            r#"{"relocation":{"scope":["decode_len at src/len.rs:2"],
                "candidates":[{"title":"the caller ignores the new error","location":"src/a.rs:9","kind":"new",
                               "command":"sh ../relocation/c1/poc.sh"}]}}"#,
        )
        .unwrap();
        let out = case.judge();
        assert_eq!(arm(&out, "relocation").state, ArmState::Fail);
        assert_eq!(arm(&out, "relocation").basis, Some(arms::Basis::Executed));
        assert_eq!(out.verdict, Verdict::Rejected);
    }

    #[test]
    fn a_fix_built_on_an_asserted_claim_is_labelled_so() {
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        // The baseline output no longer names the origin.
        let baseline = Layout::for_reproduction(RUN, REL, REPRO).in_copy("baseline", REPRO);
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
        // A reference fix that leaves another path open is rejected like
        // any other.
        let case = Case::new(SINK_PATCH).with_variants(true);
        let out = case.judge_with(false, Some(SINK_PATCH));
        assert_eq!(out.patch_source, PatchSource::Supplied);
        let digest = sha256_hex(SINK_PATCH.as_bytes());
        assert_eq!(out.patch.sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(
            out.inputs.supplied_patch_sha256.as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(out.verdict, Verdict::Rejected);
        // The fix directory's patch is not the one read at run start.
        let out = case.judge_with(false, Some("another patch"));
        assert!(
            out.reasons
                .contains(&"the supplied patch was changed during the fix step".to_string())
        );
    }

    /// A target with a config and one supplied patch, as a run finds it.
    fn target_with_inputs() -> (tempfile::TempDir, FixInputs) {
        let tmp = tempdir().unwrap();
        let lyrik = tmp.path().join(".lyrik");
        std::fs::create_dir_all(lyrik.join("fix-patches")).unwrap();
        let config = r#"{"mode":"defender","fix":{"test_command":"make check"}}"#;
        std::fs::write(lyrik.join("config.json"), config).unwrap();
        std::fs::write(
            lyrik.join("fix-patches/auth-src-a.rs-10.patch"),
            ORIGIN_PATCH,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(config).unwrap();
        let inputs = FixInputs::capture(tmp.path(), config, &parsed);
        (tmp, inputs)
    }

    #[test]
    fn run_inputs_are_read_once_at_run_start_with_their_digests() {
        let (tmp, inputs) = target_with_inputs();
        assert_eq!(
            inputs.functionality.test_command.as_deref(),
            Some("make check")
        );
        assert_eq!(inputs.patches.len(), 1);
        let patch = &inputs.patches["auth-src-a.rs-10"];
        assert_eq!(patch.bytes, ORIGIN_PATCH.as_bytes());
        assert_eq!(patch.sha256, sha256_hex(ORIGIN_PATCH.as_bytes()));
        assert!(!inputs.changes(tmp.path()).any());
    }

    #[test]
    fn a_config_an_agent_wrote_during_the_run_is_refused() {
        let (tmp, inputs) = target_with_inputs();
        // Mid-run, something writes a test command of its own choosing.
        std::fs::write(
            tmp.path().join(".lyrik/config.json"),
            r#"{"mode":"defender","fix":{"test_command":"true","coverage_command":"echo src/len.rs 100%"}}"#,
        )
        .unwrap();
        // The commands in force are still the ones read at run start.
        assert_eq!(
            inputs.functionality.test_command.as_deref(),
            Some("make check")
        );
        assert_eq!(inputs.functionality.coverage_command, None);
        let changes = inputs.changes(tmp.path());
        assert!(changes.config);
        assert!(changes.patches.is_empty());
        // Even a suite that ran green in both copies under the written
        // command, with the coverage it names, passes nothing.
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        let layout = Layout::for_reproduction(RUN, REL, REPRO);
        case.add(layout.in_copy("baseline", "true"), true, "(no output)");
        case.add(layout.in_copy("patched", "true"), true, "(no output)");
        case.add(
            layout.in_copy("patched", "echo src/len.rs 100%"),
            true,
            "src/len.rs 100%",
        );
        std::fs::write(
            case.tmp.path().join(REL).join("recheck.json"),
            r#"{"functionality":{"suite":{"command":"true"},"coverage":{"command":"echo src/len.rs 100%"}}}"#,
        )
        .unwrap();
        // With the inputs unchanged this is what a pass looks like.
        assert_eq!(arm(&case.judge(), "functionality").state, ArmState::Pass);
        let out = case.judge_changed(false, None, &changes);
        let functionality = arm(&out, "functionality");
        assert_eq!(functionality.state, ArmState::Inconclusive);
        assert_eq!(
            functionality.reasons[0],
            ".lyrik/config.json changed during the run"
        );
        assert!(out.labels.contains(&"functionality_unverified"));
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.label, None);
        // The other arms rested on nothing in the config and stand.
        assert_eq!(arm(&out, "variant").state, ArmState::Pass);
        // A config that went away is a change too.
        std::fs::remove_file(tmp.path().join(".lyrik/config.json")).unwrap();
        assert!(inputs.changes(tmp.path()).config);
    }

    #[test]
    fn a_patch_written_into_the_supplied_directory_during_the_run_is_refused() {
        let (tmp, inputs) = target_with_inputs();
        let dir = tmp.path().join(".lyrik/fix-patches");
        // A patch for another finding appears, and the supplied one is edited.
        std::fs::write(dir.join("auth-src-b.rs-5.patch"), SINK_PATCH).unwrap();
        std::fs::write(dir.join("auth-src-a.rs-10.patch"), SINK_PATCH).unwrap();
        // Neither is what the run holds.
        assert!(!inputs.patches.contains_key("auth-src-b.rs-5"));
        assert_eq!(
            inputs.patches["auth-src-a.rs-10"].bytes,
            ORIGIN_PATCH.as_bytes()
        );
        let changes = inputs.changes(tmp.path());
        assert!(!changes.config);
        assert_eq!(
            changes
                .patches
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["auth-src-a.rs-10", "auth-src-b.rs-5"]
        );
        // Every arm of the affected finding is withdrawn.
        let case = Case::new(ORIGIN_PATCH).with_variants(false);
        let out = case.judge_changed(false, Some(ORIGIN_PATCH), &changes);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert!(out.arms.iter().all(|a| a.state == ArmState::Inconclusive));
        assert!(out.arms.iter().all(|a| {
            a.reasons[0] == "the patch supplied for this finding changed during the run"
        }));
        // A link in the directory is not read as a patch.
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.join("auth-src-b.rs-5.patch")).unwrap();
            std::os::unix::fs::symlink("/etc/hostname", dir.join("auth-src-b.rs-5.patch")).unwrap();
            assert!(!read_supplied_patches(tmp.path()).contains_key("auth-src-b.rs-5"));
        }
    }

    #[test]
    fn no_staged_skill_of_the_fix_step_may_write_the_run_inputs() {
        // `write_file` is held to `write_paths`, which is the run's own
        // directory; neither input path is under it.
        let scope = super::super::lyrik_walks::run_write_scope(RUN);
        assert_eq!(scope, "<workspace>/.lyrik/state/runs/sample/run-001");
        for input in [
            "<workspace>/.lyrik/config.json",
            "<workspace>/.lyrik/fix-patches/x.patch",
        ] {
            assert!(!input.starts_with(&format!("{scope}/")), "{input}");
        }
        for name in FIX_SKILLS {
            let text = skill_text(name, RUN, "exec, read_file, write_file, list_files");
            let grants: Vec<&str> = text.lines().filter(|l| l.contains("write_paths")).collect();
            assert_eq!(grants.len(), 1, "{name}");
            assert!(
                grants[0].ends_with(&format!("write_paths: [\"{scope}\"]")),
                "{}",
                grants[0]
            );
        }
        let walk = super::super::lyrik_walks::wrap_with_wirken_frontmatter(
            "sink-walk",
            RUN,
            None,
            true,
            "# walk\n",
        );
        assert!(
            walk.contains(&format!("write_paths: [\"{scope}\"]")),
            "{walk}"
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
        // Two variants held where four are required: not a candidate.
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.label, None);
        assert_eq!(out.reasons, ["the variant arm did not pass"]);
        // The script is not withheld.
        assert!(case_dir_has_apply_script());
    }

    #[test]
    fn a_candidate_needs_the_reproduction_and_the_variant_arm_to_pass() {
        // Reproduction passes, no variant was attempted.
        let out = Case::new(ORIGIN_PATCH).judge();
        assert_eq!(arm(&out, "reproduction").state, ArmState::Pass);
        assert_eq!(arm(&out, "variant").state, ArmState::NotRun);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.label, None);
        assert_eq!(out.reasons, ["the variant arm did not pass"]);
        // Reproduction passes, the variants' builds broke: inconclusive.
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        for o in case
            .observed
            .iter_mut()
            .filter(|o| o.command.contains("variants/"))
        {
            o.success = false;
            o.output = "ModuleNotFoundError".into();
        }
        let out = case.judge();
        assert_eq!(arm(&out, "variant").state, ArmState::Inconclusive);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        // Variants pass, the reproduction's patched run never reached its
        // assertion.
        let mut case = Case::new(ORIGIN_PATCH).with_variants(false);
        let patched = Layout::for_reproduction(RUN, REL, REPRO).in_copy("patched", REPRO);
        for o in case.observed.iter_mut().filter(|o| o.command == patched) {
            o.output = "nothing ran".into();
        }
        let out = case.judge();
        assert_eq!(arm(&out, "variant").state, ArmState::Pass);
        assert_eq!(out.verdict, Verdict::Inconclusive);
        assert_eq!(out.reasons, ["the reproduction arm did not pass"]);
        // Both pass; functionality did not run. Still a candidate, and
        // counted as functionality unverified.
        let out = Case::new(ORIGIN_PATCH).with_variants(false).judge();
        assert_eq!(arm(&out, "functionality").state, ArmState::NotRun);
        assert_eq!(out.verdict, Verdict::CandidateFix);
        assert!(out.labels.contains(&"functionality_unverified"));
        // A failed arm is rejected whatever else passed.
        let out = Case::new(SINK_PATCH).with_variants(true).judge();
        assert_eq!(out.verdict, Verdict::Rejected);
    }

    fn case_dir_has_apply_script() -> bool {
        let case = Case::new(ORIGIN_PATCH);
        let dir = case.tmp.path().join(REL);
        write_apply_script(&dir).is_ok() && dir.join("apply.sh").is_file()
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
        record_fixes(&dest, &outcomes, &[]).unwrap();
        let body: Value = serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(body["schema_version"], "1.1");
        assert_eq!(body["fixes"][0]["stable_id"], "auth::src/a.rs:10");
        assert_eq!(body["fixes"][1]["verdict"], "rejected");
        let s = &body["fix_summary"];
        assert_eq!(s["fixes"], 3);
        // No bare candidate count: the tally and the unverified count ride with it.
        let c = &s["by_verdict"]["candidate_fix"];
        assert_eq!(c["count"], 1);
        assert_eq!(c["arms"]["passed"], 3);
        assert_eq!(c["arms"]["inconclusive"], 0);
        assert_eq!(c["arms"]["not_run"], 2);
        assert_eq!(c["all_arms_passed"], 0);
        assert_eq!(c["functionality_unverified"], 1);
        assert_eq!(s["by_verdict"]["rejected"], 1);
        assert_eq!(s["by_verdict"]["inconclusive"], 1);
        assert_eq!(s["by_arm"]["variant"]["pass"], 1);
        assert_eq!(s["by_arm"]["variant"]["fail"], 1);
        assert_eq!(s["by_arm"]["variant"]["not_run"], 1);
        assert!(
            summary_line(s).starts_with(
                "1 candidate (their arms: 3 passed, 0 inconclusive, 2 not_run; 0 with all arms \
                 passed; 1 functionality unverified), 1 rejected, 1 inconclusive (1 of the rejected \
                 partial); "
            ),
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
        assert!(
            line["reason"]
                .as_str()
                .unwrap()
                .contains("variant variants/v2/run.py")
        );
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
            ran: true,
        });
        save_observed(&dir, &Layout::for_reproduction(RUN, REL, REPRO), &observed).unwrap();
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
        let layout = Layout::for_reproduction(RUN, REL, REPRO);
        let p = build_fix_prompt(&c, RUN, REV, REL, false, 60);
        assert!(p.starts_with("/fix "), "{p}");
        assert!(p.contains("Invariant: len is bounded"), "{p}");
        assert!(p.contains("Code revision: `abc`"), "{p}");
        assert!(p.contains("\"origin\""), "{p}");
        let (commands, before_patch) = reproduction_commands(&layout, REPRO, REV);
        for command in &commands {
            assert!(p.contains(&format!("`{command}`")), "{command} in {p}");
        }
        // Baseline, the carried harness, the patched copy: then the patch.
        assert_eq!(before_patch, 3);
        assert!(p.contains("The first 3 before the patch"), "{p}");
        assert_eq!(commands.len(), 10);
        assert_eq!(
            commands[3], commands[9],
            "the patch is applied again at the end"
        );
        assert_eq!(
            commands[5], commands[8],
            "one string for the patched and reverted runs"
        );
        assert!(p.contains("Write the patch to `fix.patch`"), "{p}");
        let supplied = build_fix_prompt(&c, RUN, REV, REL, true, 60);
        assert!(
            supplied.contains("Do not write or edit a patch"),
            "{supplied}"
        );
        let a = build_attack_prompt(&c, RUN, REL, 4, 60);
        assert!(a.starts_with("/fix-attack "), "{a}");
        assert!(a.contains("at least 4 paths"), "{a}");
        assert!(a.contains(&layout.dir), "{a}");
        let config = FunctionalityConfig {
            test_command: Some("make check".into()),
            coverage_command: None,
        };
        let r = build_recheck_prompt(&c, RUN, REL, &config, true, 60);
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
        // The project context the walks were given rides after the text;
        // with none, the text is as it was.
        let with = skill_text_with(
            "fix-attack",
            RUN,
            tools,
            "## Project context\n\ntwo deployments\n",
        );
        assert!(with.starts_with(&attack_skill_text(RUN, tools)));
        assert!(with.ends_with("two deployments\n"), "{with}");
        assert_eq!(
            skill_text_with("fix", RUN, tools, " \n"),
            fix_skill_text(RUN, tools)
        );
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
                    ran: true,
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
                // The reproduction a walk left, under the marker contract,
                // written the way a walk writes one: it keeps its scratch
                // file under its own harness directory, named by its path
                // from the project root.
                let poc = |script: &str, arg: &str| {
                    format!(
                        "d=.lyrik/state/runs/r1/staging/fuzz-walk/harness\n\
                         sh {script} {arg} > \"$d/out-{script}-{arg}.txt\" || exit 2\n\
                         echo {}\nn=$(cut -d' ' -f3 \"$d/out-{script}-{arg}.txt\")\n\
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
                write(&fix.join("variants/v1/path.txt"), "p1\n");
                write(&fix.join("variants/v2/path.txt"), "p2\n");
                write(
                    &fix.join("attack.json"),
                    r#"{"paths":[
                        {"id":"p1","route":"caller","location":"b.sh:2","description":"b.sh calls decode_len"},
                        {"id":"p2","route":"input_shape","location":"a.sh:2","description":"leading zeros"},
                        {"id":"p3","route":"error_path","location":"a.sh:3","description":"not attempted"}],
                      "variants":[
                        {"id":"v1","path":"p1","poc":"variants/v1/poc.sh","command":"sh .lyrik/state/runs/r1/staging/fix/len-a.sh-2/variants/v1/poc.sh"},
                        {"id":"v2","path":"p2","poc":"variants/v2/poc.sh","command":"sh .lyrik/state/runs/r1/staging/fix/len-a.sh-2/variants/v2/poc.sh"}]}"#,
                );
                write(
                    &fix.join("benign/run.sh"),
                    &format!("echo {}\nsh a.sh 3\nsh b.sh 5\nsh a.sh 8\n", arms::REACHED),
                );
                write(
                    &fix.join("recheck.json"),
                    r#"{"relocation":{"scope":["decode_len at len.sh:1","a.sh:2","b.sh:2"],"candidates":[]},
                        "functionality":{"suite":{"command":"sh test.sh"},"benign":{"command":"sh .lyrik/state/runs/r1/staging/fix/len-a.sh-2/benign/run.sh"}},
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
                let layout = Layout::for_reproduction(RUN, REL, REPRO);
                for c in reproduction_commands(&layout, REPRO, "HEAD").0 {
                    self.exec(&c);
                }
                for v in ["v1", "v2"] {
                    let cmd = format!("sh {}/variants/{v}/poc.sh", layout.dir);
                    self.exec(&layout.in_copy("baseline", &cmd));
                    self.exec(&layout.in_copy("patched", &cmd));
                }
                for side in ["baseline", "patched"] {
                    self.exec(&layout.in_copy(side, "sh test.sh"));
                }
                let benign = format!("sh {}/benign/run.sh", layout.dir);
                self.exec(&layout.in_copy("baseline", &benign));
                self.exec(&layout.in_copy("baseline", &benign));
                self.exec(&layout.in_copy("patched", &benign));
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
                    others: Vec::new(),
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
                    tree: &TreeRecord::Unchanged,
                    agents: &[],
                    fix_model: "none: commands run by the test",
                    inputs: &inputs(None),
                    changes: &InputChanges::default(),
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

        /// A harness that names its scratch file under `.lyrik/state/`
        /// from the project root. In a copy that carries the walk's
        /// harness directory it sees the defect on the baseline. In a
        /// bare copy of the revision that path does not exist, and it
        /// never reaches its assertion.
        #[test]
        fn a_walk_style_harness_sees_the_defect_in_a_copy_that_carries_it() {
            let mut p = Project::new();
            let carried = Layout::for_reproduction(RUN, REL, REPRO);
            assert_eq!(carried.carried, ["fuzz-walk"]);
            assert!(p.exec(&carried.extract_baseline("HEAD")));
            assert!(p.exec(&carried.carry_into_baseline().unwrap()));
            // Asked for again by another finding: the copy stands as it is.
            assert!(p.exec(&carried.extract_baseline("HEAD")));
            let cmd = carried.in_copy("baseline", REPRO);
            assert!(!p.exec(&cmd), "the defect shows: non-zero exit");
            let seen = p.observed.last().unwrap().clone();
            assert!(seen.output.contains(arms::REACHED), "{}", seen.output);
            assert!(
                seen.output.contains("decode_len in len.sh gave 99"),
                "{}",
                seen.output
            );
            assert_eq!(
                arms::poc(&arms::Log(&p.observed).run(&cmd)),
                arms::Poc::Shown
            );
            // The harness wrote inside the copy, not into the target's run state.
            let scratch = "out-a.sh-99.txt";
            assert!(
                p.root()
                    .join(carried.copy("baseline"))
                    .join(".lyrik/state/runs/r1/staging/fuzz-walk/harness")
                    .join(scratch)
                    .is_file()
            );
            assert!(
                !p.root()
                    .join(".lyrik/state/runs/r1/staging/fuzz-walk/harness")
                    .join(scratch)
                    .exists()
            );
            // The same harness in a copy made without its directory.
            let mut bare = Project::new();
            let plain = Layout::new(RUN, REL);
            assert!(bare.exec(&plain.extract_baseline("HEAD")));
            let cmd = plain.in_copy("baseline", REPRO);
            bare.exec(&cmd);
            assert!(matches!(
                arms::poc(&arms::Log(&bare.observed).run(&cmd)),
                arms::Poc::Inconclusive(_)
            ));
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
            // The patch is at the origin, and no arm passes on a copy
            // that did not build.
            assert_eq!(arm(&out, "root_cause").state, ArmState::Inconclusive);
            assert_eq!(out.arm_tally.pass, 0);
        }
    }
}
