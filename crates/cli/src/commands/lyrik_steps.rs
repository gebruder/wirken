//! Step records for Lyrik walks.
//!
//! A walk's text is a sequence of numbered steps. Under `wirken lyrik
//! run` each step ends by writing one record under
//! `staging/<walk>/steps/step-NN.json`, and the next step starts by
//! reading that file. The record, not the model's memory of the step,
//! is what the later step works from. The runner validates the files,
//! refuses the ones that do not hold, and carries the accepted ones in
//! `findings.json` under `step_records`, outside schema 1.1.
//!
//! The chain is checked mechanically: the first record names no
//! `prior`, and every later record's `prior` is the file name of the
//! record before it. A record whose `code_revision` is not the revision
//! the run scanned is refused, so a step cannot quietly report on a
//! tree the run did not look at.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One step's record, as the walk wrote it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRecord {
    /// The step's name in the walk text, such as `target_selection`.
    pub step: String,
    /// One falsifiable sentence the step established.
    pub claim: String,
    /// The target revision the step read, as the dispatch prompt gave
    /// it.
    pub code_revision: String,
    /// The check the step ran: the command, or the read and the range.
    pub check: String,
    /// Raw evidence the check produced: quoted lines with `file:line`,
    /// or command output. Never a paraphrase.
    pub evidence: Vec<String>,
    /// What the step could not settle. Empty when nothing is open.
    pub open_questions: Vec<String>,
    /// The file name of the record the step read before starting.
    /// Absent on the first record only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<String>,
}

/// An accepted record with where it came from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AcceptedStep {
    /// The walk that wrote it. Absent in single-call mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walk: Option<String>,
    /// The staged file name, `step-NN.json`.
    pub file: String,
    #[serde(flatten)]
    pub record: StepRecord,
    /// Whether the command the record's `check` names is one the run
    /// ran: `executed` or `not_executed`. Absent when the check is a
    /// read, and when the run's chain was not there to hold it to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_status: Option<&'static str>,
}

/// One simple command of a shell line: its words, without its
/// redirections.
#[derive(Debug, Clone, PartialEq)]
struct Simple {
    words: Vec<String>,
}

/// One `exec` call of the run as its chain has it.
#[derive(Debug, Clone, PartialEq)]
struct Call {
    /// The step that made it, as its row says: a walk's name, or
    /// `replay`. Absent on a row written before rows carried it, and
    /// for the single call.
    step: Option<String>,
    /// For a row with no `step`: whether it came after the first model
    /// call of the replay step.
    after_replays_began: bool,
    /// The line's simple commands, in order.
    simple: Vec<Simple>,
    /// Whether it ran: its result says where. A refused call has no
    /// such result.
    ran: bool,
    output: String,
    /// The exit status of the line, which is that of its last simple
    /// command.
    exit_zero: bool,
    /// Whether it printed its reach value, as its row records.
    reached: bool,
}

/// The `exec` calls of a run, read off its chain. What a walk or a
/// replay did is decided from these and from nothing either wrote
/// about itself.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutedCommands(Vec<Call>);

/// Whose calls to look among.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By<'a> {
    /// The walk of this name, or the single call when there is none.
    Walk(Option<&'a str>),
    /// The replays.
    Replay,
}

/// What the chain shows a defect-showing command did, under the
/// contract a harness follows: the marker on a line of its own on
/// stdout, then a non-zero exit when the finding holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Shown {
    /// It ran, printed the marker and exited non-zero.
    Reproduced { output: String },
    /// It ran, printed the marker and exited zero.
    NotReproduced { output: String },
    /// It ran and printed the marker inside a longer line whose exit
    /// status is another command's: that it reached its assertion is
    /// on record, and how it exited is not.
    Reached { output: String },
    /// It ran and the result says neither: no marker line, or runs
    /// that disagree.
    Inconclusive { why: String, output: String },
    /// No call of it ran: none was made, or each was refused.
    NotRun { why: String },
}

impl Shown {
    pub fn label(&self) -> &'static str {
        match self {
            Shown::Reproduced { .. } => "reproduced",
            Shown::NotReproduced { .. } => "not_reproduced",
            Shown::Reached { .. } | Shown::Inconclusive { .. } => "inconclusive",
            Shown::NotRun { .. } => "not_run",
        }
    }

    /// The output the chain recorded, when the command ran.
    pub fn output(&self) -> Option<&str> {
        match self {
            Shown::Reproduced { output }
            | Shown::NotReproduced { output }
            | Shown::Reached { output }
            | Shown::Inconclusive { output, .. } => Some(output),
            Shown::NotRun { .. } => None,
        }
    }

    /// Why there is no verdict, when there is none.
    pub fn why(&self) -> Option<&str> {
        match self {
            Shown::Inconclusive { why, .. } | Shown::NotRun { why } => Some(why),
            Shown::Reached { .. } => Some(
                "it ran inside a longer line, so the line's exit status is another \
                 command's and its own is not on record",
            ),
            _ => None,
        }
    }
}

impl ExecutedCommands {
    /// From the run's rows, in order. A result is paired with the
    /// earliest unanswered `exec` call of its id.
    ///
    /// A step that writes a file drops its own earlier runs of any
    /// command that names the file. A walk writes a harness, runs it,
    /// finds it wrong and writes it again; the runs before the last
    /// write were of a file that no longer exists, and what they
    /// showed says nothing about the harness the record cites.
    pub fn from_rows(rows: impl IntoIterator<Item = wirken_audit::SessionEvent>) -> Self {
        use wirken_audit::SessionEvent;
        type Asked = (String, Option<String>, bool);
        let mut asked: std::collections::HashMap<String, std::collections::VecDeque<Asked>> =
            std::collections::HashMap::new();
        let mut calls: Vec<Call> = Vec::new();
        // Each `write_file` asked for and not yet answered: its path
        // and the step that asked.
        let mut writing: std::collections::HashMap<String, (String, Option<String>)> =
            std::collections::HashMap::new();
        let mut replays_began = false;
        for event in rows {
            match event {
                SessionEvent::LlmRequest { step, .. } => {
                    replays_began = replays_began || step.as_deref() == Some("replay");
                }
                SessionEvent::AssistantToolCalls {
                    calls: made, step, ..
                } => {
                    // A turn run by a child process has no request row;
                    // its calls name the step themselves.
                    replays_began = replays_began || step.as_deref() == Some("replay");
                    for call in made {
                        let arguments =
                            serde_json::from_str::<serde_json::Value>(&call.arguments).ok();
                        if call.name == "write_file" {
                            if let Some(path) = arguments
                                .as_ref()
                                .and_then(|a| a.get("path"))
                                .and_then(|p| p.as_str())
                            {
                                writing.insert(call.id, (path.to_string(), step.clone()));
                            }
                            continue;
                        }
                        if call.name != "exec" {
                            continue;
                        }
                        let command = arguments
                            .and_then(|a| wirken_agent::tool::extract_exec_command(&a).ok());
                        if let Some(command) = command {
                            asked.entry(call.id).or_default().push_back((
                                command,
                                step.clone(),
                                replays_began,
                            ));
                        }
                    }
                }
                SessionEvent::ToolResult {
                    call_id,
                    tool_name,
                    output,
                    success,
                    sandbox,
                    ..
                } if tool_name == "exec" => {
                    if let Some((command, step, after_replays_began)) =
                        asked.get_mut(&call_id).and_then(|q| q.pop_front())
                    {
                        calls.push(Call {
                            step,
                            after_replays_began,
                            simple: simple_commands(&command),
                            ran: sandbox.is_some(),
                            reached: sandbox.as_ref().is_some_and(|s| s.reached),
                            output,
                            exit_zero: success,
                        });
                    }
                }
                SessionEvent::ToolResult {
                    call_id,
                    tool_name,
                    success: true,
                    ..
                } if tool_name == "write_file" => {
                    if let Some((path, step)) = writing.remove(&call_id) {
                        let written = path.trim_start_matches("./");
                        calls.retain(|c| {
                            c.step != step
                                || !c.simple.iter().any(|simple| {
                                    simple
                                        .words
                                        .iter()
                                        .any(|w| w.trim_start_matches("./") == written)
                                })
                        });
                    }
                }
                _ => {}
            }
        }
        Self(calls)
    }

    /// The calls made by `by`. A row that names its step is taken at
    /// its word; one that names none is a walk's before the replays
    /// began and a replay's after.
    fn made_by<'a>(&'a self, by: By<'a>) -> impl Iterator<Item = &'a Call> {
        self.0.iter().filter(move |c| match (&c.step, by) {
            (Some(step), By::Replay) => step == "replay",
            (Some(step), By::Walk(walk)) => walk == Some(step.as_str()),
            (None, By::Replay) => c.after_replays_began,
            (None, By::Walk(_)) => !c.after_replays_began,
        })
    }

    /// Each call by `by` whose line holds `command`, with whether the
    /// line's exit status is the command's own: it is when the command
    /// ends the line.
    fn holding<'a>(&'a self, command: &str, by: By<'a>) -> Vec<(&'a Call, bool)> {
        let wanted = simple_commands(command);
        if wanted.is_empty() {
            return Vec::new();
        }
        self.made_by(by)
            .filter_map(|call| {
                let at = call
                    .simple
                    .windows(wanted.len())
                    .position(|w| w == wanted.as_slice())?;
                Some((call, at + wanted.len() == call.simple.len()))
            })
            .collect()
    }

    /// Whether `by` ran `command`: as a whole line, or as one of the
    /// simple commands of a longer one, word for word.
    pub fn ran(&self, command: &str, by: By<'_>) -> bool {
        self.holding(command, by).iter().any(|(c, _)| c.ran)
    }

    /// What `command` showed when `by` ran it, from its recorded
    /// results.
    pub fn shown(&self, command: &str, by: By<'_>) -> Shown {
        let made = self.holding(command, by);
        let ran: Vec<(&Call, bool)> = made.iter().copied().filter(|(c, _)| c.ran).collect();
        if ran.is_empty() {
            return Shown::NotRun {
                why: if made.is_empty() {
                    "no `exec` call of the command is on the chain for this step".to_string()
                } else {
                    "every `exec` call of the command was refused".to_string()
                },
            };
        }
        // A run whose exit status is the command's own says the most.
        let own: Vec<&Call> = ran
            .iter()
            .filter(|(_, own)| *own)
            .map(|(c, _)| *c)
            .collect();
        let Some(first) = own.first() else {
            let output = ran[0].0.output.clone();
            return if ran[0].0.reached {
                Shown::Reached { output }
            } else {
                Shown::Inconclusive {
                    why: no_marker(),
                    output,
                }
            };
        };
        let output = first.output.clone();
        if own.iter().any(|c| c.exit_zero != first.exit_zero) {
            return Shown::Inconclusive {
                why: "its runs exited differently".to_string(),
                output,
            };
        }
        if !first.reached {
            return Shown::Inconclusive {
                why: no_marker(),
                output,
            };
        }
        if first.exit_zero {
            Shown::NotReproduced { output }
        } else {
            Shown::Reproduced { output }
        }
    }
}

fn no_marker() -> String {
    super::lyrik_fix_arms::no_reach_line()
}

/// The simple commands of a shell line, in order: the line split on
/// `;`, `&&`, `||`, `|`, `&`, newlines and parentheses outside quotes,
/// each part taken as the words a shell would read, without its
/// redirections. `cd /w && python3 h.py 2>&1; echo "$?"` is `cd /w`,
/// `python3 h.py` and `echo $?`.
fn simple_commands(line: &str) -> Vec<Simple> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    let mut prev = ' ';
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == '\\' && q == '"' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                '\\' => {
                    cur.push(c);
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                }
                ';' | '\n' | '(' | ')' => parts.push(std::mem::take(&mut cur)),
                '|' => {
                    if chars.peek() == Some(&'|') {
                        chars.next();
                    }
                    parts.push(std::mem::take(&mut cur));
                }
                // `&&` and a lone `&` end a command; the `&` of a
                // redirection (`2>&1`, `&>file`) is part of one.
                '&' if prev != '>' && chars.peek() != Some(&'>') => {
                    if chars.peek() == Some(&'&') {
                        chars.next();
                    }
                    parts.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            },
        }
        prev = c;
    }
    parts.push(cur);
    parts
        .iter()
        .map(|part| Simple {
            words: without_redirections(
                shlex::split(part)
                    .unwrap_or_else(|| part.split_whitespace().map(str::to_string).collect()),
            ),
        })
        .filter(|s| !s.words.is_empty())
        .collect()
}

/// `words` without the redirections among them: `2>&1`, `>/dev/null`,
/// `< in`, and the target that follows a bare `>`, `>>` or `<`.
fn without_redirections(words: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(words.len());
    let mut skip_target = false;
    for w in words {
        if skip_target {
            skip_target = false;
            continue;
        }
        let op = w.trim_start_matches(|c: char| c.is_ascii_digit());
        let op = op.strip_prefix('&').unwrap_or(op);
        if op.starts_with('>') || op.starts_with('<') {
            skip_target = matches!(op, ">" | ">>" | "<");
            continue;
        }
        out.push(w);
    }
    out
}

/// Whether a record's `check` names a read and not a command: it opens
/// with `read`, with a file tool's name (`read_file`, `list_files`),
/// or with a file of the target, with or without a `:line` or
/// `:from-to` after it. Anything else names a command.
pub fn check_is_a_read(check: &str, workspace: &Path) -> bool {
    let Some(first) = check.split_whitespace().next() else {
        return false;
    };
    let first = first.trim_end_matches([';', ',', '.']);
    let word = first.trim_end_matches(':');
    if ["read", "read_file", "list_files"]
        .iter()
        .any(|w| word.eq_ignore_ascii_case(w))
    {
        return true;
    }
    let file = first.split(':').next().unwrap_or(first);
    let plain = Path::new(file)
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    plain && !file.is_empty() && workspace.join(file).is_file()
}

/// Hold each record's cited command to the commands the run ran, and
/// mark it. Returns the records marked `not_executed`.
pub fn mark_checks<'a>(
    steps: &'a mut [AcceptedStep],
    executed: &ExecutedCommands,
    workspace: &Path,
) -> Vec<&'a AcceptedStep> {
    for s in steps.iter_mut() {
        s.check_status = if check_is_a_read(&s.record.check, workspace) {
            None
        } else if executed.ran(&s.record.check, By::Walk(s.walk.as_deref())) {
            Some("executed")
        } else {
            Some("not_executed")
        };
    }
    steps
        .iter()
        .filter(|s| s.check_status == Some("not_executed"))
        .collect()
}

/// A refused file and why.
#[derive(Debug, Clone, PartialEq)]
pub struct RefusedStep {
    pub file: String,
    pub reason: String,
}

/// Read the step records in `dir`, in file-name order. Returns the
/// accepted records and the refused files. A missing directory is an
/// empty result. `expected_revision` is the run's target revision;
/// `None` when the target's git state could not be read, in which case
/// any non-blank `code_revision` is accepted.
pub fn read_walk_steps(
    dir: &Path,
    walk: Option<&str>,
    expected_revision: Option<&str>,
) -> Result<(Vec<AcceptedStep>, Vec<RefusedStep>)> {
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
    let mut previous: Option<String> = None;
    for file in files {
        let path = dir.join(&file);
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        match parse_record(&body, previous.as_deref(), expected_revision) {
            Ok(record) => accepted.push(AcceptedStep {
                walk: walk.map(str::to_string),
                file: file.clone(),
                record,
                check_status: None,
            }),
            Err(reason) => refused.push(RefusedStep {
                file: file.clone(),
                reason,
            }),
        }
        previous = Some(file);
    }
    Ok((accepted, refused))
}

/// Parse one record and check it against the file before it and the
/// run's revision. The error is the one-line reason the runner records.
fn parse_record(
    body: &str,
    previous_file: Option<&str>,
    expected_revision: Option<&str>,
) -> std::result::Result<StepRecord, String> {
    let record: StepRecord =
        serde_json::from_str(body).map_err(|e| format!("does not parse: {e}"))?;
    for (name, value) in [
        ("step", &record.step),
        ("claim", &record.claim),
        ("code_revision", &record.code_revision),
        ("check", &record.check),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} is blank"));
        }
    }
    if record.evidence.iter().all(|e| e.trim().is_empty()) {
        return Err("evidence is empty".to_string());
    }
    if let Some(expected) = expected_revision
        && record.code_revision != expected
    {
        return Err(format!(
            "code_revision {} is not the scanned revision {expected}",
            record.code_revision
        ));
    }
    match (previous_file, record.prior.as_deref()) {
        (None, None) => {}
        (None, Some(p)) => return Err(format!("first record names a prior, {p}")),
        (Some(prev), None) => return Err(format!("prior is missing; expected {prev}")),
        (Some(prev), Some(p)) if p != prev => {
            return Err(format!("prior {p} is not the record before it, {prev}"));
        }
        (Some(_), Some(_)) => {}
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn accepted(check: &str) -> AcceptedStep {
        AcceptedStep {
            walk: Some("sink-walk".into()),
            file: "step-01.json".into(),
            record: StepRecord {
                step: "s".into(),
                claim: "c".into(),
                code_revision: "unknown".into(),
                check: check.into(),
                evidence: vec!["agent.py:18: eval(expr)".into()],
                open_questions: Vec::new(),
                prior: None,
            },
            check_status: None,
        }
    }

    fn exec_rows(command: &str, ran: bool) -> Vec<wirken_audit::SessionEvent> {
        let call: wirken_audit::SessionEvent = serde_json::from_value(serde_json::json!({
            "kind": "assistant_tool_calls",
            "calls": [{
                "id": "call_0", "name": "exec",
                "arguments": serde_json::json!({"command": command}).to_string(),
            }],
        }))
        .unwrap();
        let mut result = serde_json::json!({
            "kind": "tool_result", "call_id": "call_0", "tool_name": "exec",
            "output": "", "success": ran,
        });
        if ran {
            result["sandbox"] = serde_json::json!({
                "mode": "exec_only", "runtime": "docker", "container_id": "c0",
            });
        }
        vec![call, serde_json::from_value(result).unwrap()]
    }

    /// A walk ran its harness, which crashed before its marker, wrote
    /// the harness again and ran it to its assertion. What the command
    /// showed is what the harness as last written showed: the run
    /// before the write was of a file that is gone. A write by another
    /// step, a write that was refused and a write of another file drop
    /// nothing.
    #[test]
    fn a_run_of_a_harness_before_it_was_rewritten_is_not_counted() {
        const HARNESS: &str = ".lyrik/state/runs/r/staging/sink-walk/harness/h.py";
        let row = |v: serde_json::Value| -> wirken_audit::SessionEvent {
            serde_json::from_value(v).unwrap()
        };
        let exec = |id: &str, output: &str| {
            vec![
                row(serde_json::json!({
                    "kind": "assistant_tool_calls", "step": "sink-walk",
                    "calls": [{"id": id, "name": "exec", "arguments":
                        serde_json::json!({"command": format!("python3 {HARNESS}")}).to_string()}],
                })),
                row(serde_json::json!({
                    "kind": "tool_result", "call_id": id, "tool_name": "exec",
                    "output": output, "success": false,
                    "sandbox": {"mode": "exec_only", "runtime": "docker", "container_id": "c0",
                                "reached": crate::commands::lyrik_fix_arms::tests::fixture_reached(output)},
                })),
            ]
        };
        let write = |id: &str, step: &str, path: &str, success: bool| {
            vec![
                row(serde_json::json!({
                    "kind": "assistant_tool_calls", "step": step,
                    "calls": [{"id": id, "name": "write_file", "arguments":
                        serde_json::json!({"path": path, "content": "x"}).to_string()}],
                })),
                row(serde_json::json!({
                    "kind": "tool_result", "call_id": id, "tool_name": "write_file",
                    "output": "", "success": success,
                })),
            ]
        };
        let crashed = || exec("c1", "Traceback (most recent call last):\n");
        let reached = || exec("c3", "LYRIK_REACHED\nOutput: X\n");
        let shown = |rows: Vec<Vec<wirken_audit::SessionEvent>>| {
            ExecutedCommands::from_rows(rows.into_iter().flatten())
                .shown(&format!("python3 {HARNESS}"), By::Walk(Some("sink-walk")))
                .label()
        };

        // Without a write between them the first run decides, as ever.
        assert_eq!(shown(vec![crashed(), reached()]), "inconclusive");
        // Rewritten between the runs: the first is of a file that is gone.
        assert_eq!(
            shown(vec![
                crashed(),
                write("w", "sink-walk", HARNESS, true),
                reached()
            ]),
            "reproduced"
        );
        assert_eq!(
            shown(vec![
                crashed(),
                write("w", "sink-walk", &format!("./{HARNESS}"), true),
                reached()
            ]),
            "reproduced"
        );
        // Written last and not run since: nothing is on record for it.
        assert_eq!(
            shown(vec![
                crashed(),
                reached(),
                write("w", "sink-walk", HARNESS, true)
            ]),
            "not_run"
        );
        for kept in [
            write("w", "chain-walk", HARNESS, true),
            write("w", "sink-walk", HARNESS, false),
            write("w", "sink-walk", "notes.md", true),
        ] {
            assert_eq!(shown(vec![crashed(), kept, reached()]), "inconclusive");
        }
    }

    /// A command is the same command however its words were quoted,
    /// and whatever else its line ran. A walk ran
    /// `grep -n subprocess agent.py` and cited it with the pattern in
    /// quotes; another ran its command after `cd /workspace &&`, and
    /// another before `; echo "EXIT:$?"`.
    #[test]
    fn a_cited_command_matches_what_ran_whatever_the_quoting() {
        let tmp = tempdir().unwrap();
        let mut rows = exec_rows("grep -n subprocess agent.py", true);
        rows.extend(exec_rows(
            "cd /workspace && python3 .lyrik/state/runs/r/staging/sink-walk/harness/h.py",
            true,
        ));
        rows.extend(exec_rows("grep -n \"shell=True\" agent.py", true));
        rows.extend(exec_rows(
            "python3 harness/repro.py 2>&1; echo \"EXIT:$?\"",
            true,
        ));
        rows.extend(exec_rows(
            "find . -name '*.py' | grep -v '.lyrik' | head -20",
            true,
        ));
        let executed = ExecutedCommands::from_rows(rows);
        for cited in [
            "grep -n 'subprocess' agent.py",
            "grep -n \"subprocess\" agent.py",
            "python3 .lyrik/state/runs/r/staging/sink-walk/harness/h.py",
            "grep -n shell=True agent.py",
            // One command of a longer line, and several in a row.
            "python3 harness/repro.py",
            "find . -name '*.py'",
            "grep -v .lyrik | head -20",
            "cd /workspace && python3 .lyrik/state/runs/r/staging/sink-walk/harness/h.py",
        ] {
            assert!(executed.ran(cited, By::Walk(None)), "{cited}");
        }
        // Different words are a different command.
        for cited in [
            "grep -n subprocess other.py",
            "grep -rn subprocess agent.py",
            "grep -n 'sub process' agent.py",
            "rg -n subprocess agent.py",
            // A cited line is held to every command in it: this `cd`
            // did not run.
            "cd /workspace && grep -n subprocess agent.py",
            "grep -n subprocess agent.py && cd /workspace",
            // Commands that ran, in an order they did not run in.
            "head -20 | grep -v .lyrik",
        ] {
            assert!(!executed.ran(cited, By::Walk(None)), "{cited}");
        }
        let mut steps = vec![accepted("grep -n 'subprocess' agent.py")];
        assert!(mark_checks(&mut steps, &executed, tmp.path()).is_empty());
        assert_eq!(steps[0].check_status, Some("executed"));

        // A step record is held to its own walk's commands: one only
        // another walk or a replay ran is not one it ran.
        let by = |step: &str| -> Vec<wirken_audit::SessionEvent> {
            let mut rows = exec_rows("grep -n eval agent.py", true);
            if let wirken_audit::SessionEvent::AssistantToolCalls { step: s, .. } = &mut rows[0] {
                *s = Some(step.to_string());
            }
            rows
        };
        let mut rows = by("chain-walk");
        rows.extend(by("replay"));
        let executed = ExecutedCommands::from_rows(rows);
        let mut steps = vec![accepted("grep -n eval agent.py")];
        mark_checks(&mut steps, &executed, tmp.path());
        assert_eq!(
            steps[0].check_status,
            Some("not_executed"),
            "sink-walk ran none"
        );
        steps[0].walk = Some("chain-walk".into());
        mark_checks(&mut steps, &executed, tmp.path());
        assert_eq!(steps[0].check_status, Some("executed"));
    }

    /// The checks a walk cited in a real run. It ran `sha256sum`, `pwd`
    /// and `which`; the searches it named have no `exec` row.
    #[test]
    fn a_cited_command_is_held_to_the_commands_that_ran() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("agent.py"), "x\n").unwrap();
        std::fs::write(tmp.path().join("mcp.json"), "{}\n").unwrap();
        let mut rows = exec_rows("sha256sum agent.py mcp.json", true);
        // Asked and refused: on the chain, and it did not run.
        rows.extend(exec_rows("rg -n --type py 'requests\\.get'", false));
        let executed = ExecutedCommands::from_rows(rows);

        let mut steps = vec![
            accepted("rg -n --type py 'subprocess.*shell\\s*=\\s*True'"),
            accepted("rg -n --type py 'eval\\('"),
            accepted("rg -n --type py 'requests\\.get'"),
            accepted("cat mcp.json | grep -i allow-write"),
            // Run, and cited as run but for the spacing.
            accepted("sha256sum  agent.py mcp.json"),
            // Reads, in the forms walks write them.
            accepted("read agent.py:1-20; trace analyze_data() to @tool decorator"),
            accepted("read_file src/parse.rs:10-40"),
            accepted("agent.py:18-20"),
            accepted("mcp.json"),
        ];
        let unbacked = mark_checks(&mut steps, &executed, tmp.path()).len();
        assert_eq!(unbacked, 4);
        let marks: Vec<Option<&str>> = steps.iter().map(|s| s.check_status).collect();
        assert_eq!(
            marks,
            [
                Some("not_executed"),
                Some("not_executed"),
                Some("not_executed"),
                Some("not_executed"),
                Some("executed"),
                None,
                None,
                None,
                None,
            ]
        );
        // The mark is on the record as findings.json carries it, and
        // absent from a read's.
        let carried = serde_json::to_value(&steps).unwrap();
        assert_eq!(carried[0]["check_status"], "not_executed");
        assert!(carried[5].get("check_status").is_none());
    }

    fn record(step: &str, prior: Option<&str>) -> String {
        let prior = match prior {
            Some(p) => format!(r#","prior":"{p}""#),
            None => String::new(),
        };
        format!(
            r#"{{"step":"{step}","claim":"the parser bounds the length","code_revision":"abc123","check":"read_file src/parse.rs:10-40","evidence":["src/parse.rs:12: let n = min(len, MAX);"],"open_questions":[]{prior}}}"#
        )
    }

    #[test]
    fn a_missing_directory_is_an_empty_result() {
        let tmp = tempdir().unwrap();
        let (ok, bad) =
            read_walk_steps(&tmp.path().join("steps"), Some("sink-walk"), None).unwrap();
        assert!(ok.is_empty() && bad.is_empty());
    }

    #[test]
    fn a_chained_pair_is_accepted_in_file_order() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("step-02.json"),
            record("second", Some("step-01.json")),
        )
        .unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), Some("sink-walk"), Some("abc123")).unwrap();
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].file, "step-01.json");
        assert_eq!(ok[0].record.step, "first");
        assert_eq!(ok[1].record.prior.as_deref(), Some("step-01.json"));
        assert_eq!(ok[1].walk.as_deref(), Some("sink-walk"));
    }

    #[test]
    fn the_accepted_record_serializes_flat_with_its_walk_and_file() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (ok, _) = read_walk_steps(tmp.path(), Some("sink-walk"), None).unwrap();
        let v = serde_json::to_value(&ok[0]).unwrap();
        assert_eq!(v["walk"], "sink-walk");
        assert_eq!(v["file"], "step-01.json");
        assert_eq!(v["claim"], "the parser bounds the length");
        assert!(v.get("prior").is_none(), "{v}");
    }

    #[test]
    fn a_broken_chain_is_refused_with_the_expected_file_named() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        std::fs::write(tmp.path().join("step-02.json"), record("second", None)).unwrap();
        std::fs::write(
            tmp.path().join("step-03.json"),
            record("third", Some("step-01.json")),
        )
        .unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0].file, "step-02.json");
        assert!(
            bad[0].reason.contains("expected step-01.json"),
            "{}",
            bad[0].reason
        );
        assert!(bad[1].reason.contains("step-02.json"), "{}", bad[1].reason);
    }

    #[test]
    fn a_prior_on_the_first_record_is_refused() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("step-01.json"),
            record("first", Some("step-00.json")),
        )
        .unwrap();
        let (_, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert!(
            bad[0].reason.starts_with("first record names a prior"),
            "{}",
            bad[0].reason
        );
    }

    #[test]
    fn the_wrong_revision_is_refused_and_an_unknown_run_revision_accepts_any() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("step-01.json"), record("first", None)).unwrap();
        let (_, bad) = read_walk_steps(tmp.path(), None, Some("def456")).unwrap();
        assert!(
            bad[0].reason.contains("not the scanned revision def456"),
            "{}",
            bad[0].reason
        );
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert_eq!((ok.len(), bad.len()), (1, 0));
    }

    #[test]
    fn blank_fields_empty_evidence_and_bad_json_are_refused() {
        let tmp = tempdir().unwrap();
        let blank = record("first", None).replace(
            r#""claim":"the parser bounds the length""#,
            r#""claim":"  ""#,
        );
        std::fs::write(tmp.path().join("step-01.json"), blank).unwrap();
        let empty = record("second", Some("step-01.json"))
            .replace(r#"["src/parse.rs:12: let n = min(len, MAX);"]"#, r#"[""]"#);
        std::fs::write(tmp.path().join("step-02.json"), empty).unwrap();
        std::fs::write(tmp.path().join("step-03.json"), "{not json").unwrap();
        let (ok, bad) = read_walk_steps(tmp.path(), None, None).unwrap();
        assert!(ok.is_empty());
        let reasons: Vec<&str> = bad.iter().map(|b| b.reason.as_str()).collect();
        assert_eq!(reasons[0], "claim is blank");
        assert_eq!(reasons[1], "evidence is empty");
        assert!(reasons[2].starts_with("does not parse"), "{}", reasons[2]);
    }
}
