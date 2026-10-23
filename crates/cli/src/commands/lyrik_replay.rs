//! Fresh-context replay of a walk's reproductions.
//!
//! A walk that runs a command demonstrating a finding writes a
//! reproduction record under `staging/<walk>/reproductions/`. After the
//! walks return, the runner starts one agent per record with a fresh
//! context that sees the record and nothing of the walk that wrote it,
//! and that agent re-runs the command and writes a replay record under
//! `staging/<walk>/replays/` with the same ordinal. The aggregator pairs
//! the two and carries them side by side in `findings.json` under
//! `reproductions`. A replay whose outcome differs from the walk's is a
//! brocard rule 8 rejection of the finding the record names, applied by
//! `replay`, so it demotes in pentest mode and removes in defender mode
//! and is written to `rejections.jsonl` like any other.
//!
//! A replay that could not run the command, because `exec` was refused
//! or unavailable, is `blocked`: it is recorded, and it is not a
//! disagreement.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::lyrik_brocards::Rejection;

/// Brocard rule the replay applies.
pub const REPLAY_RULE: u8 = 8;

/// What the walk observed when it ran the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionOutcome {
    /// The command showed the behaviour the finding claims.
    Reproduced,
    /// The command ran and did not show it.
    NotReproduced,
}

/// One reproduction a walk recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReproductionRecord {
    /// The finding the reproduction bears on.
    pub stable_id: String,
    /// The command run through `exec`, exactly as run.
    pub command: String,
    /// The harness or input the command uses, as a path under the
    /// run's staging directory, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// What the command shows when the finding holds.
    pub expected: String,
    /// What the command showed: the output line, exit status or
    /// diagnostic, quoted.
    pub observed: String,
    pub outcome: ReproductionOutcome,
    /// The revision the command ran against.
    pub code_revision: String,
}

/// What the fresh agent observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayOutcome {
    Reproduced,
    NotReproduced,
    /// The command could not be run: `exec` refused or unavailable, or
    /// the harness missing.
    Blocked,
}

/// One replay the fresh agent recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayRecord {
    /// The command as the replay ran it. Must be the record's command.
    pub command_run: String,
    pub observed: String,
    pub outcome: ReplayOutcome,
    /// Why the replay was blocked, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A refused file and why.
#[derive(Debug, Clone, PartialEq)]
pub struct RefusedFile {
    pub file: String,
    pub reason: String,
}

/// A reproduction with its replay beside it, as `findings.json`
/// carries it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reproduction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walk: Option<String>,
    /// The reproduction file name, `repro-NNN.json`.
    pub file: String,
    #[serde(flatten)]
    pub record: ReproductionRecord,
    /// The replay, when one ran and was accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayRecord>,
    /// `true` when the replay's outcome is the walk's, `false` when it
    /// differs, absent when no replay ran or the replay was blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement: Option<bool>,
}

/// What a reader returns: the accepted records with their file names,
/// and the refused files.
pub type ReadResult<T> = (Vec<(String, T)>, Vec<RefusedFile>);

/// Read the JSON files in `dir` in name order as `T`. A missing
/// directory is an empty result.
fn read_records<T: for<'de> Deserialize<'de>>(dir: &Path) -> Result<ReadResult<T>> {
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
    for file in files {
        let path = dir.join(&file);
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        match serde_json::from_str::<T>(&body) {
            Ok(r) => accepted.push((file, r)),
            Err(e) => refused.push(RefusedFile {
                file,
                reason: format!("does not parse: {e}"),
            }),
        }
    }
    Ok((accepted, refused))
}

/// The walk's reproduction records. A record with a blank `stable_id`,
/// `command`, `observed` or `code_revision` is refused.
pub fn read_reproductions(dir: &Path) -> Result<ReadResult<ReproductionRecord>> {
    let (parsed, mut refused) = read_records::<ReproductionRecord>(dir)?;
    let mut accepted = Vec::new();
    for (file, r) in parsed {
        let blank = [
            ("stable_id", &r.stable_id),
            ("command", &r.command),
            ("observed", &r.observed),
            ("code_revision", &r.code_revision),
        ]
        .into_iter()
        .find(|(_, v)| v.trim().is_empty());
        match blank {
            Some((name, _)) => refused.push(RefusedFile {
                file,
                reason: format!("{name} is blank"),
            }),
            None => accepted.push((file, r)),
        }
    }
    refused.sort_by(|a, b| a.file.cmp(&b.file));
    Ok((accepted, refused))
}

/// The replay records a fresh agent wrote.
pub fn read_replays(dir: &Path) -> Result<ReadResult<ReplayRecord>> {
    read_records::<ReplayRecord>(dir)
}

/// The replay file name for a reproduction file: the same ordinal.
pub fn replay_file_for(repro_file: &str) -> String {
    repro_file.replacen("repro-", "replay-", 1)
}

/// Pair each reproduction with the replay of the same ordinal.
pub fn pair(
    walk: Option<&str>,
    reproductions: Vec<(String, ReproductionRecord)>,
    replays: &[(String, ReplayRecord)],
) -> Vec<Reproduction> {
    reproductions
        .into_iter()
        .map(|(file, record)| {
            let wanted = replay_file_for(&file);
            let replay = replays
                .iter()
                .find(|(f, _)| *f == wanted)
                .map(|(_, r)| r.clone());
            let agreement = replay.as_ref().and_then(|r| match r.outcome {
                ReplayOutcome::Blocked => None,
                ReplayOutcome::Reproduced => {
                    Some(record.outcome == ReproductionOutcome::Reproduced)
                }
                ReplayOutcome::NotReproduced => {
                    Some(record.outcome == ReproductionOutcome::NotReproduced)
                }
            });
            Reproduction {
                walk: walk.map(str::to_string),
                file,
                record,
                replay,
                agreement,
            }
        })
        .collect()
}

/// The rule 8 rejection a disagreement produces. `None` when the replay
/// agreed, was blocked, or did not run.
pub fn rejection_for(r: &Reproduction) -> Option<Rejection> {
    if r.agreement != Some(false) {
        return None;
    }
    let replay = r.replay.as_ref()?;
    let outcome = |o: ReplayOutcome| match o {
        ReplayOutcome::Reproduced => "reproduced",
        ReplayOutcome::NotReproduced => "not reproduced",
        ReplayOutcome::Blocked => "blocked",
    };
    let walk_outcome = match r.record.outcome {
        ReproductionOutcome::Reproduced => "reproduced",
        ReproductionOutcome::NotReproduced => "not reproduced",
    };
    Some(Rejection {
        rule: REPLAY_RULE,
        walk: r.walk.clone(),
        stable_id: Some(r.record.stable_id.clone()),
        title: None,
        location: None,
        reason: format!(
            "a fresh-context replay of `{}` found it {} where the walk recorded it {}",
            r.record.command,
            outcome(replay.outcome),
            walk_outcome
        ),
        applied_by: "replay".to_string(),
    })
}

/// The staged skill the replay agent runs under. Written by this crate,
/// not read from the walks directory: it is not a walk.
pub fn replay_skill_text(run_id: &str, tools: &str) -> String {
    format!(
        "---\nname: replay\ndescription: Re-run one recorded reproduction in a fresh context\n\
         disable-model-invocation: true\npermissions:\n  tools:\n    allow: [{tools}]\n  egress:\n    \
         mode: deny\n  filesystem:\n    read_paths: [\"<workspace>\"]\n    write_paths: \
         [\"<workspace>/.lyrik/state/runs/{run_id}\"]\n  inference:\n    allow: [\"*\"]\n---\n\n\
         # Replay\n\n\
         You are given one reproduction record and nothing else about the run that wrote \
         it. Do not look for the walk's findings, context or reasoning; the record is the \
         whole input. Your job is to run its `command` once, through `exec`, exactly as \
         written, and say what you observed.\n\n\
         Rules:\n\n\
         - Run the record's `command` and no other command. Do not repair, rewrite or \
         extend it. If it names a harness, the harness is at the record's `harness` path \
         under the run's staging directory; do not write a harness of your own.\n\
         - Compare what you observe with the record's `expected`. `reproduced` means the \
         command showed what `expected` describes; `not_reproduced` means the command ran \
         and did not.\n\
         - If `exec` is refused, unavailable, or the harness is missing, the outcome is \
         `blocked`, with `note` saying why. A blocked replay is not a disagreement.\n\
         - Write exactly one file, the replay record named in the prompt, with \
         `command_run` (the command as you ran it), `observed` (the output line, exit \
         status or diagnostic, quoted), `outcome` (`reproduced`, `not_reproduced` or \
         `blocked`) and, when blocked, `note`.\n\
         - Your reply is one sentence saying the record was written. Nothing else.\n"
    )
}

/// The prompt the replay agent receives: the record, where to write
/// the replay, and the revision.
pub fn build_replay_prompt(
    walk: &str,
    repro_file: &str,
    record: &ReproductionRecord,
    run_id: &str,
) -> String {
    let record_json = serde_json::to_string_pretty(record).unwrap_or_default();
    let replay_file = replay_file_for(repro_file);
    format!(
        "/replay Re-run this reproduction record and write the replay. Run-id: `{run_id}`. \
         Code revision: `{}`. Write the replay to \
         `.lyrik/state/runs/{run_id}/staging/{walk}/replays/{replay_file}`.\n\n\
         Record:\n```json\n{record_json}\n```",
        record.code_revision
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn repro(outcome: &str) -> String {
        format!(
            r#"{{"stable_id":"auth::src/a.rs:10","command":"cargo test -p x fuzz_a","expected":"the test fails with an assertion on length","observed":"assertion failed: len <= MAX","outcome":"{outcome}","code_revision":"abc"}}"#
        )
    }

    fn replay(outcome: &str) -> String {
        format!(
            r#"{{"command_run":"cargo test -p x fuzz_a","observed":"assertion failed: len <= MAX","outcome":"{outcome}"}}"#
        )
    }

    #[test]
    fn reproductions_are_read_in_order_and_blank_fields_are_refused() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("repro-002.json"), repro("reproduced")).unwrap();
        std::fs::write(tmp.path().join("repro-001.json"), repro("not_reproduced")).unwrap();
        std::fs::write(
            tmp.path().join("repro-003.json"),
            repro("reproduced")
                .replace(r#""command":"cargo test -p x fuzz_a""#, r#""command":" ""#),
        )
        .unwrap();
        std::fs::write(tmp.path().join("repro-004.json"), "nope").unwrap();
        let (ok, bad) = read_reproductions(tmp.path()).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].0, "repro-001.json");
        assert_eq!(ok[0].1.outcome, ReproductionOutcome::NotReproduced);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0].reason, "command is blank");
        assert!(bad[1].reason.starts_with("does not parse"));
    }

    #[test]
    fn a_missing_directory_is_empty() {
        let tmp = tempdir().unwrap();
        let (ok, bad) = read_replays(&tmp.path().join("replays")).unwrap();
        assert!(ok.is_empty() && bad.is_empty());
    }

    #[test]
    fn pairing_matches_ordinals_and_scores_agreement() {
        let repros = vec![
            (
                "repro-001.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
            (
                "repro-002.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
            (
                "repro-003.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
            (
                "repro-004.json".to_string(),
                serde_json::from_str(&repro("not_reproduced")).unwrap(),
            ),
        ];
        let replays = vec![
            (
                "replay-001.json".to_string(),
                serde_json::from_str(&replay("reproduced")).unwrap(),
            ),
            (
                "replay-002.json".to_string(),
                serde_json::from_str(&replay("not_reproduced")).unwrap(),
            ),
            (
                "replay-004.json".to_string(),
                serde_json::from_str(&replay("blocked")).unwrap(),
            ),
        ];
        let paired = pair(Some("fuzz-walk"), repros, &replays);
        let agreements: Vec<Option<bool>> = paired.iter().map(|p| p.agreement).collect();
        assert_eq!(agreements, vec![Some(true), Some(false), None, None]);
        assert!(paired[2].replay.is_none(), "no replay ran");
        assert_eq!(
            paired[3].replay.as_ref().unwrap().outcome,
            ReplayOutcome::Blocked
        );
        let v = serde_json::to_value(&paired[1]).unwrap();
        assert_eq!(v["walk"], "fuzz-walk");
        assert_eq!(v["file"], "repro-002.json");
        assert_eq!(v["stable_id"], "auth::src/a.rs:10");
        assert_eq!(v["replay"]["outcome"], "not_reproduced");
        assert_eq!(v["agreement"], false);
    }

    #[test]
    fn only_a_disagreement_is_a_rule_eight_rejection() {
        let repros = vec![
            (
                "repro-001.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
            (
                "repro-002.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
            (
                "repro-003.json".to_string(),
                serde_json::from_str(&repro("reproduced")).unwrap(),
            ),
        ];
        let replays = vec![
            (
                "replay-001.json".to_string(),
                serde_json::from_str(&replay("reproduced")).unwrap(),
            ),
            (
                "replay-002.json".to_string(),
                serde_json::from_str(&replay("not_reproduced")).unwrap(),
            ),
            (
                "replay-003.json".to_string(),
                serde_json::from_str(&replay("blocked")).unwrap(),
            ),
        ];
        let paired = pair(Some("fuzz-walk"), repros, &replays);
        assert!(rejection_for(&paired[0]).is_none());
        assert!(
            rejection_for(&paired[2]).is_none(),
            "blocked is not a disagreement"
        );
        let rej = rejection_for(&paired[1]).unwrap();
        assert_eq!(rej.rule, 8);
        assert_eq!(rej.applied_by, "replay");
        assert_eq!(rej.walk.as_deref(), Some("fuzz-walk"));
        assert_eq!(rej.stable_id.as_deref(), Some("auth::src/a.rs:10"));
        assert!(
            rej.reason
                .contains("found it not reproduced where the walk recorded it reproduced"),
            "{}",
            rej.reason
        );
    }

    #[test]
    fn the_replay_prompt_carries_only_the_record_and_the_replay_path() {
        let record: ReproductionRecord = serde_json::from_str(&repro("reproduced")).unwrap();
        let p = build_replay_prompt("fuzz-walk", "repro-007.json", &record, "sample/run-001");
        assert!(p.starts_with("/replay "), "{p}");
        assert!(
            p.contains("staging/fuzz-walk/replays/replay-007.json"),
            "{p}"
        );
        assert!(p.contains("Code revision: `abc`"), "{p}");
        assert!(p.contains(r#""command": "cargo test -p x fuzz_a""#), "{p}");
        assert!(!p.contains("finding"), "nothing of the walk's output: {p}");
    }

    #[test]
    fn the_replay_skill_declares_its_tools_and_write_scope() {
        let text = replay_skill_text("sample/run-001", "exec, read_file, write_file, list_files");
        assert!(text.starts_with("---\nname: replay\n"), "{text}");
        assert!(
            text.contains("allow: [exec, read_file, write_file, list_files]"),
            "{text}"
        );
        assert!(
            text.contains("<workspace>/.lyrik/state/runs/sample/run-001"),
            "{text}"
        );
        assert!(text.contains("`blocked`"), "{text}");
    }
}
