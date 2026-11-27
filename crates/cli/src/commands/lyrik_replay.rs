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

use super::lyrik_steps::{By, ExecutedCommands, Shown};

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

/// What a walk or a replay wrote about its own run. Carried for a
/// reader and decides nothing: the outcome beside it comes from the
/// chain.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Claimed {
    pub outcome: &'static str,
    pub observed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The replay of a reproduction, as `findings.json` carries it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Replayed {
    /// `reproduced`, `not_reproduced` or `inconclusive` from the
    /// result the chain recorded for the replay's run of the command,
    /// `blocked` when no call of it ran in the replay step.
    pub outcome: &'static str,
    /// The output the chain recorded for that run. Absent when none
    /// ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
    /// Why there is no verdict, when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Set to `walk` when the replay ran the command inside a longer
    /// line and the exit status behind `outcome` is the one the walk's
    /// run of the command by itself recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status_from: Option<&'static str>,
    /// What the replay's own record said, when it wrote one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed: Option<Claimed>,
}

/// A reproduction with its replay beside it, as `findings.json`
/// carries it. `outcome` and `observed` are read off the chain: the
/// result recorded for the walk's own `exec` of the command. What the
/// walk wrote in their place is under `claimed`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reproduction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walk: Option<String>,
    /// The reproduction file name, `repro-NNN.json`.
    pub file: String,
    pub stable_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub expected: String,
    pub code_revision: String,
    /// `reproduced`, `not_reproduced` or `inconclusive` from the
    /// result the chain recorded for the walk's run of the command,
    /// `not_run` when no call of it ran in the walk step.
    pub outcome: &'static str,
    /// The output the chain recorded for that run; empty when none
    /// ran.
    pub observed: String,
    /// Why there is no verdict, when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Set to `replay` when the walk ran the command inside a longer
    /// line, so the line's exit status was not the command's own, and
    /// the exit status behind `outcome` is the one the replay's run of
    /// the command by itself recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status_from: Option<&'static str>,
    pub claimed: Claimed,
    /// The replay, when one was dispatched for the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<Replayed>,
    /// `true` when the walk's run and the replay's both showed the
    /// finding or both showed it absent, `false` when one showed it
    /// and the other showed it absent, absent when either gave no
    /// verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement: Option<bool>,
    /// What the reproduction is evidence of. Agreed as reproduced:
    /// `observed` when the runner's trace shows the marker and cited
    /// code running, else `static_confirmed`. Disagreed: `observed`
    /// when the trace shows cited code ran and the finding still did
    /// not show, else `static_confirmed`. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<&'static str>,
    /// The runner's traced run behind `evidence`, when it made one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<super::lyrik_trace::Execution>,
}

impl Reproduction {
    /// Whether the walk's run and the replay's both showed the
    /// finding.
    pub fn agreed_reproduced(&self) -> bool {
        self.agreement == Some(true) && self.outcome == "reproduced"
    }
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

impl ReplayOutcome {
    /// The outcome as the record and the run's log spell it.
    pub fn label(self) -> &'static str {
        match self {
            ReplayOutcome::Reproduced => "reproduced",
            ReplayOutcome::NotReproduced => "not_reproduced",
            ReplayOutcome::Blocked => "blocked",
        }
    }
}

/// What a replay came to, for its `lyrik.replay.completed` row.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayStatus {
    /// `reproduced`, `not_reproduced` or `inconclusive` from the
    /// result the chain recorded for the replay's run of the command;
    /// `blocked` when no call of it ran in the replay step.
    pub status: &'static str,
    /// The output the chain recorded, when the command ran.
    pub observed: Option<String>,
    /// Why there is no verdict, or how the replay's turn failed.
    pub reason: Option<String>,
    /// What the replay's own record said, when it wrote one.
    pub claimed: Option<Claimed>,
}

/// What the replay of `repro_file`, a record whose command is
/// `command`, came to. The status is read from `executed`, the run's
/// `exec` calls as its chain has them: what the replay ran and what
/// that showed. The record the replay wrote under `replays_dir` is
/// carried as its claim and decides nothing. `turn` is how the
/// replay's turn ended.
pub fn replay_status(
    executed: &ExecutedCommands,
    command: &str,
    walk: Option<&str>,
    replays_dir: &Path,
    repro_file: &str,
    turn: &std::result::Result<(), String>,
) -> ReplayStatus {
    let (_, replay) = judge(executed, command, walk);
    let replayed = replayed(
        replay,
        std::fs::read_to_string(replays_dir.join(replay_file_for(repro_file)))
            .ok()
            .and_then(|body| serde_json::from_str::<ReplayRecord>(&body).ok())
            .as_ref(),
    );
    ReplayStatus {
        status: replayed.outcome,
        observed: replayed.observed,
        reason: match (replayed.reason, turn) {
            (Some(why), Err(failure)) => {
                Some(format!("{why}; the replay's turn failed: {failure}"))
            }
            (None, Err(failure)) => Some(format!("the replay's turn failed: {failure}")),
            (why, Ok(())) => why,
        },
        claimed: replayed.claimed,
    }
}

/// What one run of a command came to, once the walk's run and the
/// replay's are read together.
struct Verdict {
    label: &'static str,
    observed: Option<String>,
    reason: Option<String>,
    /// Whose run the exit status came from, when not this one's.
    exit_status_from: Option<&'static str>,
}

/// What the walk's run of `command` and the replay's each showed.
///
/// A command run as one of several in a line reached its assertion
/// when the marker is in the line's output, and the line's exit status
/// is another command's. Its own exit status is then taken from the
/// other run of the same command, when that run was of the command by
/// itself, and the verdict says so. With no such run there is no
/// verdict.
fn judge(executed: &ExecutedCommands, command: &str, walk: Option<&str>) -> (Verdict, Verdict) {
    let by_walk = executed.shown(command, By::Walk(walk));
    let by_replay = executed.shown(command, By::Replay);
    let read = |own: &Shown, other: &Shown, others: &'static str| {
        let lent = matches!(own, Shown::Reached { .. })
            && matches!(
                other,
                Shown::Reproduced { .. } | Shown::NotReproduced { .. }
            );
        Verdict {
            label: if lent { other.label() } else { own.label() },
            observed: own.output().map(str::to_string),
            reason: if lent {
                None
            } else {
                own.why().map(str::to_string)
            },
            exit_status_from: lent.then_some(others),
        }
    };
    (
        read(&by_walk, &by_replay, "replay"),
        read(&by_replay, &by_walk, "walk"),
    )
}

/// The replay's verdict as `findings.json` carries it, with the
/// replay's own record beside it as its claim.
fn replayed(replay: Verdict, record: Option<&ReplayRecord>) -> Replayed {
    Replayed {
        outcome: match replay.label {
            "not_run" => ReplayOutcome::Blocked.label(),
            other => other,
        },
        observed: replay.observed,
        reason: replay.reason,
        exit_status_from: replay.exit_status_from,
        claimed: record.map(|r| Claimed {
            outcome: r.outcome.label(),
            observed: r.observed.clone(),
            note: r.note.clone(),
        }),
    }
}

/// The replay file name for a reproduction file: the same ordinal.
pub fn replay_file_for(repro_file: &str) -> String {
    repro_file.replacen("repro-", "replay-", 1)
}

/// Pair each reproduction with the replay of the same ordinal, and
/// read what each run showed off `executed`. A replay is carried for
/// a record when it wrote one or ran the command.
pub fn pair(
    walk: Option<&str>,
    reproductions: Vec<(String, ReproductionRecord)>,
    replays: &[(String, ReplayRecord)],
    executed: &ExecutedCommands,
) -> Vec<Reproduction> {
    reproductions
        .into_iter()
        .map(|(file, record)| {
            let wanted = replay_file_for(&file);
            let written = replays.iter().find(|(f, _)| *f == wanted).map(|(_, r)| r);
            let (ran, replay) = judge(executed, &record.command, walk);
            let replay = replayed(replay, written);
            let replay = (written.is_some() || replay.observed.is_some()).then_some(replay);
            let agreement = replay.as_ref().and_then(|r| match (ran.label, r.outcome) {
                ("reproduced", "reproduced") | ("not_reproduced", "not_reproduced") => Some(true),
                ("reproduced", "not_reproduced") | ("not_reproduced", "reproduced") => Some(false),
                _ => None,
            });
            Reproduction {
                walk: walk.map(str::to_string),
                file,
                stable_id: record.stable_id,
                command: record.command,
                harness: record.harness,
                expected: record.expected,
                code_revision: record.code_revision,
                outcome: ran.label,
                observed: ran.observed.unwrap_or_default(),
                reason: ran.reason,
                exit_status_from: ran.exit_status_from,
                claimed: Claimed {
                    outcome: match record.outcome {
                        ReproductionOutcome::Reproduced => "reproduced",
                        ReproductionOutcome::NotReproduced => "not_reproduced",
                    },
                    observed: record.observed,
                    note: None,
                },
                replay,
                agreement,
                evidence: None,
                execution: None,
            }
        })
        .collect()
}

/// The rule 8 rejection a disagreement produces. `None` when the two
/// runs agreed or either gave no verdict.
pub fn rejection_for(r: &Reproduction) -> Option<Rejection> {
    if r.agreement != Some(false) {
        return None;
    }
    let replay = r.replay.as_ref()?;
    let spoken = |o: &str| o.replace('_', " ");
    Some(Rejection {
        rule: REPLAY_RULE,
        walk: r.walk.clone(),
        stable_id: Some(r.stable_id.clone()),
        title: None,
        location: None,
        reason: format!(
            "a fresh-context replay of `{}` showed it {} where the walk's run showed it {}",
            r.command,
            spoken(replay.outcome),
            spoken(r.outcome)
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

    /// A reproduction record for the command `sh h<n>.sh`, claiming
    /// `outcome`.
    fn record(n: u32, outcome: &str) -> (String, ReproductionRecord) {
        let mut r: serde_json::Value = serde_json::from_str(&repro(outcome)).unwrap();
        r["command"] = serde_json::json!(format!("sh h{n}.sh"));
        (
            format!("repro-{n:03}.json"),
            serde_json::from_value(r).unwrap(),
        )
    }

    /// The chain rows of one `exec` of `sh h<n>.sh`: what it printed
    /// and how it exited, or a refusal when `ran` is false.
    fn exec(n: u32, marker: bool, exit_zero: bool, ran: bool) -> Vec<wirken_audit::SessionEvent> {
        let mut result = serde_json::json!({
            "kind": "tool_result", "call_id": format!("c{n}"), "tool_name": "exec",
            "output": if marker { "LYRIK_REACHED\nshown\n" } else { "sh: 1: h.sh: not found\n" },
            "success": exit_zero,
        });
        if ran {
            result["sandbox"] = serde_json::json!({"mode": "exec_only", "runtime": "docker",
                                                   "container_id": "c", "reached": marker});
        }
        vec![
            serde_json::from_value(serde_json::json!({
                "kind": "assistant_tool_calls",
                "calls": [{"id": format!("c{n}"), "name": "exec",
                           "arguments": serde_json::json!({"command": format!("sh h{n}.sh")}).to_string()}],
            }))
            .unwrap(),
            serde_json::from_value(result).unwrap(),
        ]
    }

    /// The first model call of the replay step.
    fn replays_begin() -> wirken_audit::SessionEvent {
        serde_json::from_value(serde_json::json!({
            "kind": "llm_request", "provider": "p", "model": "m", "request_id": "r",
            "tools_hash": "aa".repeat(32), "messages_hash": "bb".repeat(32), "step": "replay",
        }))
        .unwrap()
    }

    fn replay_record(n: u32, outcome: &str) -> (String, ReplayRecord) {
        (
            format!("replay-{n:03}.json"),
            serde_json::from_str(&replay(outcome)).unwrap(),
        )
    }

    /// What a run showed is what the chain recorded for it. A record
    /// that says `reproduced` for a command that never ran, ran and
    /// exited zero, or never reached its marker, is not a
    /// reproduction; neither is a replay record that says so.
    #[test]
    fn outcomes_come_from_the_recorded_runs_and_not_from_the_records() {
        // Every record claims `reproduced`, as does every replay.
        let repros: Vec<_> = (1..=6).map(|n| record(n, "reproduced")).collect();
        let replays: Vec<_> = (1..=6).map(|n| replay_record(n, "reproduced")).collect();
        let mut rows = Vec::new();
        // The walk step. 1 and 2 showed the finding; 3 ran and exited
        // zero; 4 never reached its marker; 5 was refused; 6 was never
        // run at all.
        rows.extend(exec(1, true, false, true));
        rows.extend(exec(2, true, false, true));
        rows.extend(exec(3, true, true, true));
        rows.extend(exec(4, false, false, true));
        rows.extend(exec(5, true, false, false));
        rows.push(replays_begin());
        // The replay step. 1 showed it again; 2 exited zero; 3 exited
        // zero as the walk's did; the rest did not run.
        rows.extend(exec(1, true, false, true));
        rows.extend(exec(2, true, true, true));
        rows.extend(exec(3, true, true, true));
        let executed = ExecutedCommands::from_rows(rows);

        let paired = pair(Some("fuzz-walk"), repros, &replays, &executed);
        let outcomes: Vec<&str> = paired.iter().map(|p| p.outcome).collect();
        assert_eq!(
            outcomes,
            [
                "reproduced",
                "reproduced",
                "not_reproduced",
                "inconclusive",
                "not_run",
                "not_run"
            ]
        );
        let replayed: Vec<&str> = paired
            .iter()
            .map(|p| p.replay.as_ref().unwrap().outcome)
            .collect();
        assert_eq!(
            replayed,
            [
                "reproduced",
                "not_reproduced",
                "not_reproduced",
                "blocked",
                "blocked",
                "blocked"
            ]
        );
        let agreements: Vec<Option<bool>> = paired.iter().map(|p| p.agreement).collect();
        assert_eq!(
            agreements,
            [Some(true), Some(false), Some(true), None, None, None]
        );
        assert!(paired[0].agreed_reproduced());
        assert!(
            !paired[2].agreed_reproduced(),
            "agreed that it did not show"
        );

        // What each wrote is carried as its claim, beside what ran.
        let v = serde_json::to_value(&paired[5]).unwrap();
        assert_eq!(v["walk"], "fuzz-walk");
        assert_eq!(v["file"], "repro-006.json");
        assert_eq!(v["stable_id"], "auth::src/a.rs:10");
        assert_eq!(v["outcome"], "not_run");
        assert_eq!(v["observed"], "");
        assert_eq!(v["claimed"]["outcome"], "reproduced");
        assert_eq!(v["claimed"]["observed"], "assertion failed: len <= MAX");
        assert_eq!(v["replay"]["outcome"], "blocked");
        assert_eq!(v["replay"]["claimed"]["outcome"], "reproduced");
        assert!(v.get("agreement").is_none());
        let v = serde_json::to_value(&paired[0]).unwrap();
        assert_eq!(v["observed"], "LYRIK_REACHED\nshown\n");
        assert_eq!(v["replay"]["observed"], "LYRIK_REACHED\nshown\n");

        // With no replay record and no replay run, no replay is carried.
        let alone = pair(
            Some("fuzz-walk"),
            vec![record(1, "reproduced")],
            &[],
            &executed,
        );
        assert!(alone[0].replay.is_some(), "the replay ran, record or not");
        let unreplayed = pair(
            Some("fuzz-walk"),
            vec![record(5, "reproduced")],
            &[],
            &executed,
        );
        assert!(unreplayed[0].replay.is_none());
    }

    /// The chain rows of one `exec` of a whole shell `line` by the
    /// agent of `step`, with the output and exit of the line.
    fn exec_line(
        id: &str,
        step: &str,
        line: &str,
        output: &str,
        exit_zero: bool,
    ) -> Vec<wirken_audit::SessionEvent> {
        vec![
            serde_json::from_value(serde_json::json!({
                "kind": "assistant_tool_calls", "step": step,
                "calls": [{"id": id, "name": "exec",
                           "arguments": serde_json::json!({"command": line}).to_string()}],
            }))
            .unwrap(),
            serde_json::from_value(serde_json::json!({
                "kind": "tool_result", "call_id": id, "tool_name": "exec",
                "output": output, "success": exit_zero,
                "sandbox": {"mode": "exec_only", "runtime": "docker", "container_id": "c",
                            "reached": crate::commands::lyrik_fix_arms::tests::fixture_reached(output)},
            }))
            .unwrap(),
        ]
    }

    fn one_record(command: &str) -> Vec<(String, ReproductionRecord)> {
        let mut r: serde_json::Value = serde_json::from_str(&repro("reproduced")).unwrap();
        r["command"] = serde_json::json!(command);
        vec![(
            "repro-001.json".to_string(),
            serde_json::from_value(r).unwrap(),
        )]
    }

    /// A walk ran its harness as one command of a longer line, as a
    /// walk in a real run did, and recorded the harness command alone.
    /// The command is one of the line's simple commands, so it ran. The
    /// line's exit status is the last command's, not the harness's; the
    /// replay ran the command by itself, and its exit status is the
    /// command's own.
    #[test]
    fn a_command_run_inside_a_longer_line_is_the_command_that_ran() {
        let harness = "python3 .lyrik/state/runs/r/staging/fuzz-walk/harness/h.py";
        let mut rows = exec_line(
            "w1",
            "fuzz-walk",
            &format!("{harness}; echo \"EXIT:$?\""),
            "LYRIK_REACHED\neval executed\nEXIT:1\n",
            true,
        );
        rows.extend(exec_line(
            "r1",
            "replay",
            harness,
            "LYRIK_REACHED\neval executed\n",
            false,
        ));
        let executed = ExecutedCommands::from_rows(rows);
        let paired = pair(Some("fuzz-walk"), one_record(harness), &[], &executed);
        assert_eq!(paired[0].outcome, "reproduced", "{:?}", paired[0]);
        assert_eq!(paired[0].replay.as_ref().unwrap().outcome, "reproduced");
        assert_eq!(paired[0].agreement, Some(true));
        // It says where the walk's exit status came from.
        assert_eq!(paired[0].exit_status_from, Some("replay"));

        // The other ways a line holds the command: after `cd` and `&&`,
        // before a pipe, with its output redirected.
        for (line, own_exit) in [
            (format!("cd /workspace && {harness}"), true),
            (format!("{harness} 2>&1"), true),
            (format!("{harness} 2>&1 | head -20"), false),
            (format!("{harness} || echo failed"), false),
            (format!("echo start; {harness}"), true),
        ] {
            let mut rows = exec_line("w1", "fuzz-walk", &line, "LYRIK_REACHED\n", !own_exit);
            rows.extend(exec_line("r1", "replay", harness, "LYRIK_REACHED\n", false));
            let executed = ExecutedCommands::from_rows(rows);
            let p = &pair(Some("fuzz-walk"), one_record(harness), &[], &executed)[0];
            assert_eq!(p.outcome, "reproduced", "{line}");
            assert_eq!(p.agreement, Some(true), "{line}");
            assert_eq!(
                p.exit_status_from,
                (!own_exit).then_some("replay"),
                "{line}"
            );
        }

        // A different command in the line is not the command.
        let mut rows = exec_line(
            "w1",
            "fuzz-walk",
            "python3 other.py; echo done",
            "LYRIK_REACHED\n",
            true,
        );
        rows.extend(exec_line("r1", "replay", harness, "LYRIK_REACHED\n", false));
        let executed = ExecutedCommands::from_rows(rows);
        let p = &pair(Some("fuzz-walk"), one_record(harness), &[], &executed)[0];
        assert_eq!(p.outcome, "not_run");
        // Another walk's run of it is not this walk's.
        let mut rows = exec_line("w1", "sink-walk", harness, "LYRIK_REACHED\n", false);
        rows.extend(exec_line("r1", "replay", harness, "LYRIK_REACHED\n", false));
        let executed = ExecutedCommands::from_rows(rows);
        let p = &pair(Some("fuzz-walk"), one_record(harness), &[], &executed)[0];
        assert_eq!(p.outcome, "not_run");
        // With no run whose exit status is the command's own, there is
        // no verdict.
        let line = format!("{harness}; echo \"EXIT:$?\"");
        let mut rows = exec_line("w1", "fuzz-walk", &line, "LYRIK_REACHED\nEXIT:1\n", true);
        rows.extend(exec_line(
            "r1",
            "replay",
            &line,
            "LYRIK_REACHED\nEXIT:1\n",
            true,
        ));
        let executed = ExecutedCommands::from_rows(rows);
        let p = &pair(Some("fuzz-walk"), one_record(harness), &[], &executed)[0];
        assert_eq!(p.outcome, "inconclusive");
        assert_eq!(p.agreement, None);
    }

    #[test]
    fn only_a_disagreement_is_a_rule_eight_rejection() {
        let repros: Vec<_> = (1..=3).map(|n| record(n, "reproduced")).collect();
        let replays: Vec<_> = (1..=3).map(|n| replay_record(n, "reproduced")).collect();
        let mut rows = Vec::new();
        for n in 1..=3 {
            rows.extend(exec(n, true, false, true));
        }
        rows.push(replays_begin());
        rows.extend(exec(1, true, false, true));
        rows.extend(exec(2, true, true, true));
        let executed = ExecutedCommands::from_rows(rows);
        let paired = pair(Some("fuzz-walk"), repros, &replays, &executed);
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
                .contains("showed it not reproduced where the walk's run showed it reproduced"),
            "{}",
            rej.reason
        );
    }

    /// A replay's status is what its run showed. What it wrote is its
    /// claim, and a turn that failed is said beside the status.
    #[test]
    fn a_replays_status_is_its_recorded_run() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("replay-001.json"), replay("reproduced")).unwrap();
        let mut rows = vec![replays_begin()];
        rows.extend(exec(1, true, true, true));
        let executed = ExecutedCommands::from_rows(rows);
        let ran = replay_status(
            &executed,
            "sh h1.sh",
            None,
            tmp.path(),
            "repro-001.json",
            &Ok(()),
        );
        assert_eq!(ran.status, "not_reproduced");
        assert_eq!(ran.claimed.unwrap().outcome, "reproduced");
        let none = replay_status(
            &executed,
            "sh h2.sh",
            None,
            tmp.path(),
            "repro-002.json",
            &Err("turn: boom".to_string()),
        );
        assert_eq!(none.status, "blocked");
        assert!(none.claimed.is_none());
        assert!(
            none.reason
                .unwrap()
                .contains("the replay's turn failed: turn: boom")
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
