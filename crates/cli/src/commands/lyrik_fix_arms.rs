//! The arms that check a patch: patch in, verdict out.
//!
//! Nothing here asks a model whether a patch is right. Each arm reads
//! the `exec` results the session log recorded for commands this
//! module composed, and the files the fix step's agents left under the
//! fix directory, and returns a state: `pass`, `fail`, `inconclusive`
//! or `not_run`. The patch may be Lyrik's own or one supplied to the
//! run; the arms do not know which, and a patch that matches a
//! reference fix gets nothing for it.
//!
//! A command that shows a defect follows one contract. It prints
//! [`REACHED`] on a line of its own on stdout immediately before its assertion,
//! exits non-zero when the defect shows and zero when it does not.
//! With no such line in the recorded output the harness never reached
//! its assertion (a failed build, a missing dependency, an import
//! error), and the run is `inconclusive`: neither a reproduction nor a
//! pass. A refused command is `not_run`.
//!
//! One command string per check runs unchanged in each copy of the
//! scanned revision; the copy is chosen by the `cd` this module
//! prefixes. A command that names a copy is refused, so a check cannot
//! assert on where it runs instead of on the code.
//!
//! A step that rests on a model's reading (where a walk placed the
//! origin, what a re-walk reported, which paths reach the sink) is
//! marked `model_judged`. It cannot pass an arm and it cannot fail one:
//! the arm is inconclusive and the claim is recorded on it. An arm
//! fails only on an executed run.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wirken_audit::SessionEvent;

/// The line a defect-showing command prints before its assertion.
pub const REACHED: &str = "LYRIK_REACHED";

/// The copies of the scanned revision a fix is checked in. The
/// baseline is made once per run and shared by every finding, so its
/// build is paid for once. Each finding has its own patched copy. There
/// is no third copy: the revert is checked in the patched copy, in
/// place, where the toolchain rebuilds only what the patch touched, and
/// the patch is then applied again.
///
/// A side-blind command may contain none of these words.
const SIDE_WORDS: [&str; 3] = ["baseline", "patched", "reverted"];

/// The directory under `staging/fix/` that holds the shared baseline.
pub const SHARED_DIR: &str = "_shared";

/// Variants a localized patch must survive, by different paths.
pub const VARIANT_MIN_LOCALIZED: usize = 2;
/// Variants a cross-cutting patch must survive.
pub const VARIANT_MIN_CROSS_CUTTING: usize = 4;

/// One `exec` call as the session log recorded it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observed {
    /// Position among the run's `exec` results.
    pub seq: usize,
    pub command: String,
    pub success: bool,
    pub output: String,
}

/// The `exec` calls in `events`, in order, each with the result the
/// runtime recorded for it. A call with no result row is left out.
pub fn observed_execs<'a>(events: impl IntoIterator<Item = &'a SessionEvent>) -> Vec<Observed> {
    let mut commands: BTreeMap<String, String> = BTreeMap::new();
    let mut out = Vec::new();
    for event in events {
        match event {
            SessionEvent::AssistantToolCalls { calls, .. } => {
                for call in calls.iter().filter(|c| c.name == "exec") {
                    let Ok(args) = serde_json::from_str::<Value>(&call.arguments) else {
                        continue;
                    };
                    let command = match args.get("command") {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Array(items)) => items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                        _ => continue,
                    };
                    commands.insert(call.id.clone(), command);
                }
            }
            SessionEvent::ToolResult {
                call_id,
                tool_name,
                output,
                success,
                ..
            } if tool_name == "exec" => {
                if let Some(command) = commands.get(call_id) {
                    out.push(Observed {
                        seq: out.len(),
                        command: command.clone(),
                        success: *success,
                        output: output.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// What the log holds for one command.
#[derive(Debug, Clone, PartialEq)]
pub enum Run {
    /// No call of it is on the log.
    Never,
    /// Every call of it was refused at the gate.
    Refused,
    TimedOut,
    /// It ran more than once and the exit statuses differ. The first
    /// result is not replaced by a later one.
    Disagree,
    Done {
        success: bool,
        output: String,
        seq: usize,
    },
}

/// The observed `exec` results, looked up by exact command.
pub struct Log<'a>(pub &'a [Observed]);

impl Log<'_> {
    /// Every result recorded for `command` that was not a refusal.
    pub fn runs(&self, command: &str) -> Vec<&Observed> {
        self.0
            .iter()
            .filter(|o| o.command.trim() == command.trim() && !refused(o))
            .collect()
    }

    pub fn run(&self, command: &str) -> Run {
        let asked = self.0.iter().any(|o| o.command.trim() == command.trim());
        let runs = self.runs(command);
        let Some(first) = runs.first() else {
            return if asked { Run::Refused } else { Run::Never };
        };
        if runs
            .iter()
            .any(|o| o.output.starts_with("Command timed out"))
        {
            return Run::TimedOut;
        }
        if runs.iter().any(|o| o.success != first.success) {
            return Run::Disagree;
        }
        Run::Done {
            success: first.success,
            output: first.output.clone(),
            seq: first.seq,
        }
    }
}

fn refused(o: &Observed) -> bool {
    !o.success && o.output.starts_with("Permission denied")
}

/// Whether the marker is on a line of its own on stdout. `exec` puts
/// stderr after stdout behind a `[stderr] ` prefix; that part is not
/// read, because an interpreter's error can echo the harness's own
/// source, marker included, for a harness that ran nothing.
fn has_marker(output: &str) -> bool {
    output
        .lines()
        .take_while(|l| !l.starts_with("[stderr] "))
        .any(|l| l.trim() == REACHED)
}

/// What a defect-showing command showed.
#[derive(Debug, Clone, PartialEq)]
pub enum Poc {
    Shown,
    NotShown,
    Inconclusive(String),
    NotRun(String),
}

pub fn poc(run: &Run) -> Poc {
    match run {
        Run::Never => Poc::NotRun("not run".into()),
        Run::Refused => Poc::NotRun("refused at the gate".into()),
        Run::TimedOut => Poc::Inconclusive("timed out".into()),
        Run::Disagree => Poc::Inconclusive("its runs disagree".into()),
        Run::Done {
            success, output, ..
        } => {
            if !has_marker(output) {
                Poc::Inconclusive(format!(
                    "no {REACHED} line in its output: the harness did not reach its assertion"
                ))
            } else if *success {
                Poc::NotShown
            } else {
                Poc::Shown
            }
        }
    }
}

fn seq_of(run: &Run) -> Option<usize> {
    match run {
        Run::Done { seq, .. } => Some(*seq),
        _ => None,
    }
}

/// Where a finding's fix directory is and the commands that run in it.
#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    /// The fix directory, relative to the target root, where `exec`
    /// starts.
    pub dir: String,
    run_id: String,
    /// The walks whose harness directory each copy carries, at the path
    /// it has in the target.
    pub carried: Vec<String>,
}

impl Layout {
    pub fn new(run_id: &str, rel_dir: &str) -> Self {
        Self {
            dir: format!(".lyrik/state/runs/{run_id}/{rel_dir}"),
            run_id: run_id.to_string(),
            carried: Vec::new(),
        }
    }

    /// The layout for a finding whose reproduction is `command`. A
    /// walk's harness lives under the run's staging directory, which a
    /// copy of the scanned revision does not hold, and a harness names
    /// its own files by their path from the project root. So each copy
    /// is given the harness directory of every walk the command names,
    /// at the same relative path, and the command runs in a copy
    /// exactly as it ran in the target.
    pub fn for_reproduction(run_id: &str, rel_dir: &str, command: &str) -> Self {
        Self::for_commands(run_id, rel_dir, [command])
    }

    /// The layout whose copies carry the harness directory of every
    /// walk any of `commands` names: the reproduction's and each
    /// carried variant's.
    pub fn for_commands<'a>(
        run_id: &str,
        rel_dir: &str,
        commands: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut layout = Self::new(run_id, rel_dir);
        let staging = layout.staging();
        for command in commands {
            for piece in command.split(&format!("{staging}/")).skip(1) {
                if let Some((walk, rest)) = piece.split_once('/')
                    && rest.starts_with("harness")
                    && !walk.is_empty()
                    && walk
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    && !layout.carried.iter().any(|w| w == walk)
                {
                    layout.carried.push(walk.to_string());
                }
            }
        }
        layout
    }

    fn staging(&self) -> String {
        format!(".lyrik/state/runs/{}/staging", self.run_id)
    }

    /// Where a copy is, relative to the target root.
    pub fn copy(&self, side: &str) -> String {
        if side == "baseline" {
            format!("{}/fix/{SHARED_DIR}/baseline", self.staging())
        } else {
            format!("{}/{side}", self.dir)
        }
    }

    fn carry(&self, copy: &str) -> Vec<String> {
        let s = self.staging();
        self.carried
            .iter()
            .map(|walk| {
                format!("mkdir -p {copy}/{s}/{walk} && cp -R {s}/{walk}/harness {copy}/{s}/{walk}/")
            })
            .collect()
    }

    /// Make the run's baseline copy, once. The command is the same
    /// string for every finding and does nothing when the copy is
    /// there, so what was built in it stays built.
    pub fn extract_baseline(&self, revision: &str) -> String {
        let b = self.copy("baseline");
        format!(
            "[ -e {b}.ready ] || {{ mkdir -p {b} && git archive --format=tar {revision} | tar -x \
             -C {b} && touch {b}.ready; }}"
        )
    }

    /// Put this finding's carried harness directories into the shared
    /// baseline. `None` when the reproduction names no harness.
    pub fn carry_into_baseline(&self) -> Option<String> {
        let parts = self.carry(&self.copy("baseline"));
        (!parts.is_empty()).then(|| parts.join(" && "))
    }

    /// Make this finding's patched copy, with the carried harness
    /// directories in it.
    pub fn extract_patched(&self, revision: &str) -> String {
        let p = self.copy("patched");
        let mut out =
            format!("mkdir -p {p} && git archive --format=tar {revision} | tar -x -C {p}");
        for part in self.carry(&p) {
            out.push_str(" && ");
            out.push_str(&part);
        }
        out
    }

    /// Make this finding's patched copy if it is not there. The runner
    /// runs this before its own variants, so they do not depend on the
    /// fix agent having reached its own extract step.
    pub fn ensure_patched(&self, revision: &str) -> String {
        let p = self.copy("patched");
        format!(
            "[ -d {p} ] || {{ mkdir -p {p} && git archive --format=tar {revision} | tar -x -C {p}; }}"
        )
    }

    /// Put every carried harness directory into one copy. `None` when
    /// no command names a harness.
    pub fn carry_into(&self, side: &str) -> Option<String> {
        let parts = self.carry(&self.copy(side));
        (!parts.is_empty()).then(|| parts.join(" && "))
    }

    /// Leave the patched copy with the patch in, whatever state it is
    /// in: the reverse dry run succeeds exactly when the patch is
    /// applied, and otherwise the patch is applied.
    pub fn ensure_applied(&self) -> String {
        let (p, d) = (self.copy("patched"), &self.dir);
        format!(
            "git apply -R --check --directory={p} {d}/fix.patch 2>/dev/null || git apply \
             --directory={p} {d}/fix.patch"
        )
    }

    /// The path from a copy's root back to the target root.
    pub fn up(&self) -> String {
        "../".repeat(
            self.copy("patched")
                .split('/')
                .filter(|c| !c.is_empty())
                .count(),
        )
    }

    /// `command` run from inside one copy.
    pub fn in_copy(&self, side: &str, command: &str) -> String {
        format!("cd {} && {}", self.copy(side), self.rebase(command))
    }

    /// Apply the patch to the patched copy, from the target root. A
    /// copy sits inside the target's own repository, where `git apply`
    /// run from the copy would skip every path outside it and exit zero
    /// having changed nothing; `--directory` puts the patch's paths
    /// under the copy. The same command applies the patch again after
    /// the revert check.
    pub fn apply(&self) -> String {
        format!(
            "git apply --directory={} {}/fix.patch",
            self.copy("patched"),
            self.dir
        )
    }

    /// Take the patch back out of the patched copy, in place.
    pub fn revert(&self) -> String {
        format!(
            "git apply -R --directory={} {}/fix.patch",
            self.copy("patched"),
            self.dir
        )
    }

    /// Whether every tracked file in the patched copy is as the scanned
    /// revision has it. Build output and the carried harness are not
    /// tracked and are not compared.
    pub fn check_reverted(&self, revision: &str) -> String {
        format!(
            "git --work-tree={} diff --quiet {revision} --",
            self.copy("patched")
        )
    }

    /// A command written to run from the target root, as it runs from
    /// inside a copy. A path into a harness directory the copy carries
    /// is left as it is. Any other path into the run's state is
    /// re-pointed at the target root, which a copy does not hold.
    pub fn rebase(&self, command: &str) -> String {
        const STATE: &str = ".lyrik/state/runs/";
        // Both copies sit at the same depth below the target root.
        let up = self.up();
        let carried: Vec<String> = self
            .carried
            .iter()
            .map(|w| format!("{}/staging/{w}/harness", self.run_id))
            .collect();
        let mut out = String::with_capacity(command.len());
        let mut before: Option<char> = None;
        for (i, piece) in command.split(STATE).enumerate() {
            if i > 0 {
                let in_copy = carried.iter().any(|c| piece.starts_with(c.as_str()));
                if !in_copy
                    && before.is_none_or(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '='))
                {
                    out.push_str(&up);
                }
                out.push_str(STATE);
            }
            out.push_str(piece);
            // The text before the next occurrence ends with this piece,
            // or with the marker itself when the piece is empty.
            before = piece.chars().last().or((i > 0).then_some('/'));
        }
        out
    }
}

/// One hunk of a unified diff, by its old-side range.
#[derive(Debug, Clone, PartialEq)]
pub struct Hunk {
    pub file: String,
    pub start: u32,
    pub len: u32,
    /// The enclosing-function text after the second `@@`.
    pub function: String,
}

/// What a patch touches, read from its text.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PatchShape {
    pub files: Vec<String>,
    pub hunks: Vec<Hunk>,
}

fn strip_prefix_ab(path: &str) -> &str {
    let path = path.split('\t').next().unwrap_or(path).trim();
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
}

pub fn parse_patch(text: &str) -> PatchShape {
    let mut shape = PatchShape::default();
    let mut old: Option<String> = None;
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("--- ") {
            old = Some(strip_prefix_ab(p).to_string());
        } else if let Some(p) = line.strip_prefix("+++ ") {
            let new = strip_prefix_ab(p).to_string();
            let file = match old.take() {
                Some(o) if o != "/dev/null" => o,
                _ => new,
            };
            if !shape.files.contains(&file) {
                shape.files.push(file.clone());
            }
            current = Some(file);
        } else if let Some(rest) = line.strip_prefix("@@ -")
            && let Some(file) = &current
        {
            let range = rest.split(' ').next().unwrap_or("");
            let mut parts = range.split(',');
            let start = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let len = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
            let function = rest
                .split_once(" @@")
                .map(|(_, f)| f.trim().to_string())
                .unwrap_or_default();
            shape.hunks.push(Hunk {
                file: file.clone(),
                start,
                len,
                function,
            });
        }
    }
    shape
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    /// One hunk, or hunks inside one function of one file.
    Localized,
    /// More than one file, function or path.
    CrossCutting,
}

impl PatchShape {
    pub fn locality(&self) -> Locality {
        let one_function = self.hunks.first().is_some_and(|h| !h.function.is_empty())
            && self
                .hunks
                .iter()
                .all(|h| h.function == self.hunks[0].function);
        if self.files.len() <= 1 && (self.hunks.len() <= 1 || one_function) {
            Locality::Localized
        } else {
            Locality::CrossCutting
        }
    }

    /// Whether a hunk's old-side range covers `line` of `file`.
    pub fn touches(&self, file: &str, line: u32) -> bool {
        let file = strip_prefix_ab(file).trim_start_matches("./");
        self.hunks.iter().any(|h| {
            h.file.trim_start_matches("./") == file
                && line >= h.start
                && line < h.start + h.len.max(1)
        })
    }

    pub fn test_files(&self) -> Vec<&str> {
        self.files
            .iter()
            .map(String::as_str)
            .filter(|f| is_test_path(f))
            .collect()
    }

    pub fn dependency_manifests(&self) -> Vec<&str> {
        const MANIFESTS: &[&str] = &[
            "Cargo.toml",
            "Cargo.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.mod",
            "go.sum",
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "Gemfile",
            "Gemfile.lock",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
        ];
        self.files
            .iter()
            .map(String::as_str)
            .filter(|f| MANIFESTS.contains(&f.rsplit('/').next().unwrap_or(f)))
            .collect()
    }
}

fn is_test_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.split('/')
        .any(|c| matches!(c, "test" | "tests" | "spec" | "__tests__" | "testdata"))
        || name.starts_with("test_")
        || name.contains("_test.")
        || name.contains(".test.")
        || name.contains(".spec.")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmState {
    Pass,
    Fail,
    Inconclusive,
    NotRun,
}

impl ArmState {
    pub fn as_str(self) -> &'static str {
        match self {
            ArmState::Pass => "pass",
            ArmState::Fail => "fail",
            ArmState::Inconclusive => "inconclusive",
            ArmState::NotRun => "not_run",
        }
    }
}

/// What an arm's state rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Commands that ran, read from the session log.
    Executed,
    /// A model's reading, with or without executed parts beside it.
    ModelJudged,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArmResult {
    pub arm: &'static str,
    pub state: ArmState,
    /// Absent when nothing ran and nothing was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    pub reasons: Vec<String>,
    /// What a model reported that no executed run confirmed. Kept for a
    /// maintainer to read. A claim here never fails the arm.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub model_claims: Vec<String>,
    /// Set when the agent that feeds this arm was stopped at its tool
    /// round limit before it finished: what the arm holds is what the
    /// agent got done, and it says how many rounds that was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<String>,
}

impl ArmResult {
    fn with_claims(mut self, claims: Vec<String>) -> Self {
        debug_assert!(
            claims.is_empty()
                || self.state != ArmState::Fail
                || self.basis == Some(Basis::Executed),
            "an arm fails on executed evidence, not on a claim"
        );
        self.model_claims = claims;
        self
    }

    /// The arm marked as resting on an agent that ran out of rounds.
    pub fn incomplete(mut self, why: &str) -> Self {
        self.incomplete = Some(why.to_string());
        self
    }

    /// The arm with its state withdrawn: an input it rested on changed
    /// while the run was under way.
    pub fn withheld(mut self, reason: &str) -> Self {
        self.state = ArmState::Inconclusive;
        self.reasons.insert(0, reason.to_string());
        self
    }

    fn new(arm: &'static str, state: ArmState, basis: Option<Basis>, reasons: Vec<String>) -> Self {
        debug_assert!(
            !(state == ArmState::Pass && basis != Some(Basis::Executed)),
            "an arm passes on executed evidence only"
        );
        debug_assert!(
            !(state == ArmState::Fail && basis != Some(Basis::Executed)),
            "an arm fails on executed evidence only"
        );
        Self {
            arm,
            state,
            basis,
            reasons,
            model_claims: Vec::new(),
            incomplete: None,
        }
    }
}

/// A file one of the fix step's agents wrote: `Ok(None)` when absent.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match std::fs::read_to_string(path) {
        Err(_) => Ok(None),
        Ok(body) => serde_json::from_str(&body)
            .map(Some)
            .map_err(|e| format!("{} does not parse: {e}", file_name(path))),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `attack.json`: the paths the variant agent says reach the same sink
/// or invariant. Optional. It names paths nothing was run for; which
/// variants exist and what they showed is read from the scripts and
/// the log, never from here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Attack {
    #[serde(default)]
    pub paths: Vec<AttackPath>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttackPath {
    pub id: String,
    /// `caller`, `input_shape`, `cleanup`, `error_path` or `other`.
    #[serde(default)]
    pub route: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub description: String,
}

/// A path with no variant that held, listed and never assumed safe.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UntestedPath {
    pub id: String,
    pub route: String,
    pub location: String,
    pub description: String,
    /// Why no variant counts for it.
    pub reason: String,
}

/// `recheck.json`: what the re-walk of the patched code reported, the
/// functionality commands, and the same-pattern sites.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Recheck {
    #[serde(default)]
    pub relocation: Option<Relocation>,
    #[serde(default)]
    pub functionality: Option<FunctionalityPlan>,
    #[serde(default)]
    pub class_sites: Vec<ClassSite>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Relocation {
    /// What was walked: everything reachable from the patched functions.
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    /// A bounded fuzz run over the patched functions, where a harness
    /// exists.
    #[serde(default)]
    pub fuzz: Option<Cmd>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Candidate {
    pub title: String,
    pub location: String,
    /// `new` or `relocated` for a security defect the patch introduced
    /// or moved; `regression` for behaviour that worked before the
    /// patch and does not after it, which is not a security defect and
    /// is read by the functionality arm.
    #[serde(default)]
    pub kind: String,
    /// A proof of concept for the candidate under the marker contract,
    /// as run from a copy's root. Without one the candidate is a claim.
    #[serde(default)]
    pub command: Option<String>,
}

impl Candidate {
    /// Whether the candidate is a functional regression, not a
    /// security defect.
    pub fn is_regression(&self) -> bool {
        matches!(
            self.kind.trim().to_ascii_lowercase().as_str(),
            "regression" | "functional_regression" | "functional"
        )
    }
}

/// The functional regressions the re-walk reported whose proof shows
/// in the patched copy and not in the baseline, and the ones no run
/// confirms.
fn regressions(
    log: &Log,
    layout: &Layout,
    recheck: &Result<Option<Recheck>, String>,
) -> (Vec<String>, Vec<String>) {
    let (mut shown, mut claims) = (Vec::new(), Vec::new());
    let candidates = recheck
        .as_ref()
        .ok()
        .and_then(|r| r.as_ref())
        .and_then(|r| r.relocation.as_ref())
        .map(|r| r.candidates.as_slice())
        .unwrap_or_default();
    for c in candidates.iter().filter(|c| c.is_regression()) {
        let text = format!("regression at {}: {}", c.location, c.title);
        let Some(cmd) = c.command.as_ref().filter(|cmd| !names_a_copy(cmd)) else {
            claims.push(format!("{text} (no proof of concept)"));
            continue;
        };
        let patched = poc(&log.run(&layout.in_copy("patched", cmd)));
        let baseline = poc(&log.run(&layout.in_copy("baseline", cmd)));
        if patched == Poc::Shown && baseline == Poc::NotShown {
            shown.push(format!(
                "{text}; its proof shows in the patched copy and not in the baseline"
            ));
        } else {
            claims.push(format!(
                "{text} (patched copy: {}; baseline copy: {})",
                poc_word(&patched),
                poc_word(&baseline)
            ));
        }
    }
    (shown, claims)
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cmd {
    pub command: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FunctionalityPlan {
    #[serde(default)]
    pub suite: Option<Cmd>,
    #[serde(default)]
    pub coverage: Option<Cmd>,
    #[serde(default)]
    pub benign: Option<Cmd>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClassSite {
    pub file: String,
    pub line: u32,
    /// The line at that site, quoted.
    pub quote: String,
    #[serde(default)]
    pub guarded: bool,
}

/// Where a variant came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VariantSource {
    /// Another confirmed reproduction of the same finding: another
    /// deployment, another caller. Listed by the runner before any
    /// agent ran and run by the runner.
    Reproduction,
    /// A proof of concept the variant agent wrote under `variants/`.
    Agent,
}

/// One variant the arm reads. It exists because a script exists and
/// ran, not because an agent listed it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VariantSpec {
    pub id: String,
    pub source: VariantSource,
    /// What route it takes, in the words of whoever wrote it.
    pub path: String,
    /// The command as run from the project root. In a copy it runs as
    /// [`Layout::in_copy`] makes it.
    pub command: String,
}

/// What the runs of one variant showed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VariantResult {
    pub id: String,
    pub source: VariantSource,
    pub path: String,
    pub command: String,
    /// `shown`, `not_shown`, or why neither can be said.
    pub baseline: String,
    pub patched: String,
    /// `held`: shown in the baseline, not in the patched copy. `open`:
    /// shown in both, the patch does not cover this path.
    /// `open_by_configuration`: shown in both, and its script sets a
    /// setting the operator declared an explicit opt-out of the
    /// control, so it says nothing about the patch. `introduced`:
    /// shown in the patched copy only. `not_a_variant`: not shown in
    /// the baseline. `inconclusive` otherwise.
    pub outcome: &'static str,
    /// The operator-declared opt-out the variant's script sets, on an
    /// `open_by_configuration` variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_out: Option<String>,
}

fn poc_word(p: &Poc) -> String {
    match p {
        Poc::Shown => "shown".into(),
        Poc::NotShown => "not_shown".into(),
        Poc::Inconclusive(why) | Poc::NotRun(why) => why.clone(),
    }
}

/// The agent-written variants under `fix_dir`: every `variants/<id>/`
/// holding a `run.sh` or `run.py`, and every script under `variants/`
/// the log shows run in the baseline copy. A variant is registered by
/// its script being there or having run; no list is read.
pub fn registered_variants(
    fix_dir: &Path,
    layout: &Layout,
    observed: &[Observed],
) -> Vec<VariantSpec> {
    let mut out: Vec<VariantSpec> = Vec::new();
    let describe = |id_dir: &Path, fallback: &str| {
        std::fs::read_to_string(id_dir.join("path.txt"))
            .ok()
            .and_then(|t| {
                t.lines()
                    .next()
                    .map(|l| l.trim().chars().take(240).collect::<String>())
            })
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| fallback.to_string())
    };
    let mut names: Vec<String> = std::fs::read_dir(fix_dir.join("variants"))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        let dir = fix_dir.join("variants").join(&name);
        for (file, interpreter) in [("run.sh", "sh"), ("run.py", "python3")] {
            if dir.join(file).is_file() {
                out.push(VariantSpec {
                    id: format!("variants/{name}/{file}"),
                    source: VariantSource::Agent,
                    path: describe(&dir, &name),
                    command: format!("{interpreter} {}/variants/{name}/{file}", layout.dir),
                });
                break;
            }
        }
    }
    let prefix = format!("cd {} && ", layout.copy("baseline"));
    let under = format!("{}{}/variants/", layout.up(), layout.dir);
    for o in observed {
        let Some(rest) = o.command.trim().strip_prefix(&prefix) else {
            continue;
        };
        let Some((interpreter, script)) = rest.split_once(' ') else {
            continue;
        };
        let Some(rel) = script.strip_prefix(&under) else {
            continue;
        };
        if !matches!(interpreter, "sh" | "bash" | "python3")
            || rel.split('/').any(|c| c.is_empty() || c == "..")
            || rel.contains(char::is_whitespace)
            || !fix_dir.join("variants").join(rel).is_file()
        {
            continue;
        }
        let command = format!("{interpreter} {}/variants/{rel}", layout.dir);
        if out.iter().any(|v| v.command == command) {
            continue;
        }
        let id_dir = fix_dir
            .join("variants")
            .join(rel.split('/').next().unwrap_or_default());
        out.push(VariantSpec {
            id: format!("variants/{rel}"),
            source: VariantSource::Agent,
            path: describe(&id_dir, rel),
            command,
        });
    }
    out
}

/// What the reproduction arm leaves for the arms after it.
pub struct Reproduction {
    pub arm: ArmResult,
    pub baseline: Poc,
    /// What the reproduction showed in the patched copy.
    pub patched: Poc,
    /// What the baseline run printed, when it ran.
    pub baseline_output: Option<String>,
    /// Whether the patched copy was left with the patch taken out: the
    /// revert ran and no apply followed it.
    pub left_reverted: bool,
}

fn setup(log: &Log, command: &str, what: &str, reasons: &mut Vec<String>) -> (Option<usize>, bool) {
    let run = log.run(command);
    let ran = !matches!(run, Run::Never | Run::Refused);
    match &run {
        Run::Done { success: true, .. } => {}
        Run::Done { .. } => reasons.push(format!("{what} failed")),
        Run::Never => reasons.push(format!("{what} was not run")),
        Run::Refused => reasons.push(format!("{what} was refused at the gate")),
        Run::TimedOut => reasons.push(format!("{what} timed out")),
        Run::Disagree => reasons.push(format!("{what} ran more than once with different results")),
    }
    (seq_of(&run), ran)
}

/// The successful runs of `command`, by position on the log.
fn successes(log: &Log, command: &str) -> Vec<usize> {
    log.runs(command)
        .iter()
        .filter(|o| o.success)
        .map(|o| o.seq)
        .collect()
}

fn as_run(o: &Observed) -> Run {
    if o.output.starts_with("Command timed out") {
        Run::TimedOut
    } else {
        Run::Done {
            success: o.success,
            output: o.output.clone(),
            seq: o.seq,
        }
    }
}

/// The original reproduction, in order: it shows the defect in the
/// shared baseline, does not in the patched copy, and shows it again in
/// the patched copy after the patch is taken back out and every tracked
/// file there is as the scanned revision has it. The patch is then
/// applied again. The patched copy is one directory, so which state a
/// run saw is read from where it sits on the log between the apply, the
/// revert and the second apply.
pub fn reproduction_arm(log: &Log, layout: &Layout, command: &str, revision: &str) -> Reproduction {
    let mut reasons = Vec::new();
    let mut ran_any = false;
    let mut step = |cmd: String, what: &str, reasons: &mut Vec<String>| {
        let (seq, ran) = setup(log, &cmd, what, reasons);
        ran_any |= ran;
        seq
    };
    let base_ready = step(
        layout.extract_baseline(revision),
        "extracting the baseline copy",
        &mut reasons,
    );
    if let Some(cmd) = layout.carry_into_baseline() {
        step(
            cmd,
            "carrying the harness into the baseline copy",
            &mut reasons,
        );
    }
    step(
        layout.extract_patched(revision),
        "extracting the patched copy",
        &mut reasons,
    );
    let revert = step(layout.revert(), "reverting the patch", &mut reasons);
    let checked = step(
        layout.check_reverted(revision),
        "the check that the reverted copy is the scanned revision",
        &mut reasons,
    );
    let applies = successes(log, &layout.apply());
    let asked = !log.runs(&layout.apply()).is_empty();
    ran_any |= asked;
    let applied = applies.first().copied();
    if applied.is_none() {
        reasons.push(if asked {
            "applying the patch failed".to_string()
        } else {
            "applying the patch was not run".to_string()
        });
    }
    if !(applied < revert && revert < checked) && checked.is_some() {
        reasons.push("the apply, revert and check did not run in that order".into());
    }

    let b_run = log.run(&layout.in_copy("baseline", command));
    let patched_cmd = layout.in_copy("patched", command);
    let patched_runs = log.runs(&patched_cmd);
    let refused = patched_runs.is_empty() && log.run(&patched_cmd) == Run::Refused;
    let missing = || if refused { Run::Refused } else { Run::Never };
    // The first run after the apply and before the revert saw the patch.
    let p_run = patched_runs
        .iter()
        .find(|o| applied.is_some_and(|a| o.seq > a) && revert.is_none_or(|r| o.seq < r))
        .map(|o| as_run(o))
        .unwrap_or_else(missing);
    // The first run after the revert was checked saw the revision again.
    let r_run = patched_runs
        .iter()
        .find(|o| checked.is_some_and(|c| o.seq > c))
        .map(|o| as_run(o))
        .unwrap_or_else(missing);
    let reapplied = match (seq_of(&r_run), applies.get(1)) {
        (Some(r), Some(again)) => *again > r,
        _ => false,
    };
    let (b, p, r) = (poc(&b_run), poc(&p_run), poc(&r_run));
    ran_any |= [&b, &p, &r].iter().any(|o| !matches!(o, Poc::NotRun(_)));
    if seq_of(&b_run).is_some() && seq_of(&b_run) < base_ready {
        reasons.push("the baseline copy was run before it was extracted".into());
    }
    let mut note = |side: &str, o: &Poc, want_shown: bool| match o {
        Poc::Shown if !want_shown => reasons.push(format!(
            "the reproduction still shows the defect in the {side} copy"
        )),
        Poc::NotShown if want_shown => reasons.push(format!(
            "the reproduction does not show the defect in the {side} copy"
        )),
        Poc::Inconclusive(why) | Poc::NotRun(why) => {
            reasons.push(format!("the reproduction in the {side} copy: {why}"))
        }
        _ => {}
    };
    note("baseline", &b, true);
    note("patched", &p, false);
    note("reverted", &r, true);
    if seq_of(&r_run).is_some() && !reapplied {
        reasons.push("the patch was not applied again after the revert check".into());
    }

    let state = if p == Poc::Shown && applied.is_some() {
        ArmState::Fail
    } else if reasons.is_empty() {
        ArmState::Pass
    } else if ran_any {
        ArmState::Inconclusive
    } else {
        ArmState::NotRun
    };
    let baseline_output = match b_run {
        Run::Done { output, .. } => Some(output),
        _ => None,
    };
    Reproduction {
        arm: ArmResult::new(
            "reproduction",
            state,
            ran_any.then_some(Basis::Executed),
            reasons,
        ),
        baseline: b,
        patched: p,
        baseline_output,
        left_reverted: {
            // The patch went back in through the apply or through the
            // runner's own ensure step.
            let back_in = applies
                .iter()
                .chain(successes(log, &layout.ensure_applied()).iter())
                .max()
                .copied();
            revert.is_some() && back_in < revert
        },
    }
}

fn names_a_copy(command: &str) -> bool {
    SIDE_WORDS.iter().any(|s| command.contains(s))
}

/// Whether the patch was in the patched copy when the run at `seq`
/// started: the last of the apply, the runner's ensure and the revert
/// before it put the patch in.
fn patch_in_at(log: &Log, layout: &Layout, seq: usize) -> bool {
    let last = |command: &str| {
        successes(log, command)
            .into_iter()
            .filter(|s| *s < seq)
            .max()
    };
    let put_in = last(&layout.apply()).max(last(&layout.ensure_applied()));
    put_in.is_some() && put_in > last(&layout.revert())
}

/// What `command` showed in the patched copy with the patch in.
fn patched_poc(log: &Log, layout: &Layout, command: &str) -> Poc {
    let runs = log.runs(command);
    if runs.is_empty() {
        return poc(&log.run(command));
    }
    let with_patch: Vec<&&Observed> = runs
        .iter()
        .filter(|o| patch_in_at(log, layout, o.seq))
        .collect();
    let Some(first) = with_patch.first() else {
        return Poc::Inconclusive("it ran only while the patch was out of the copy".into());
    };
    if with_patch.iter().any(|o| o.success != first.success) {
        return Poc::Inconclusive("its runs disagree".into());
    }
    poc(&as_run(first))
}

/// The variant arm: other routes to the same sink or invariant, each
/// with its own proof of concept. `specs` is every variant on record:
/// the finding's other confirmed reproductions and the scripts under
/// `variants/`. Each is read from the log alone. A variant holds when
/// it shows the defect in the baseline and not in the patched copy.
/// One that shows it in both fails the arm: the fix is partial, and
/// the path is named. `attack` is the variant agent's own list of
/// paths, when it wrote one; it adds the paths nothing was run for and
/// nothing else.
pub fn variant_arm(
    log: &Log,
    layout: &Layout,
    specs: &[VariantSpec],
    attack: Result<Option<Attack>, String>,
    reproduction_command: &str,
    minimum: usize,
    opt_out: &dyn Fn(&VariantSpec) -> Option<String>,
) -> (ArmResult, Vec<UntestedPath>, Vec<VariantResult>) {
    variant_arm_in(
        log,
        layout,
        specs,
        attack,
        &[reproduction_command],
        minimum,
        opt_out,
        &|command| patched_poc(log, layout, command),
    )
}

/// [`variant_arm`] with the reading of a patched run supplied: for one
/// finding's copy, the run that saw the patch in; for a combined copy,
/// which only ever holds the patches, the run itself. `reproductions`
/// are the commands the reproduction arm already reads.
#[allow(clippy::too_many_arguments)]
pub fn variant_arm_in(
    log: &Log,
    layout: &Layout,
    specs: &[VariantSpec],
    attack: Result<Option<Attack>, String>,
    reproductions: &[&str],
    minimum: usize,
    opt_out: &dyn Fn(&VariantSpec) -> Option<String>,
    patched_run: &dyn Fn(&str) -> Poc,
) -> (ArmResult, Vec<UntestedPath>, Vec<VariantResult>) {
    let mut reasons = Vec::new();
    let mut failed = false;
    let mut ran_any = false;
    let mut held: Vec<&VariantSpec> = Vec::new();
    let mut results = Vec::with_capacity(specs.len());
    for v in specs {
        let result = |baseline: &Poc, patched: &Poc, outcome: &'static str| VariantResult {
            id: v.id.clone(),
            source: v.source,
            path: v.path.clone(),
            command: v.command.clone(),
            baseline: poc_word(baseline),
            patched: poc_word(patched),
            outcome,
            opt_out: None,
        };
        let unread = Poc::NotRun("not read".into());
        if v.source == VariantSource::Agent && names_a_copy(&v.command.replace(&layout.dir, "")) {
            reasons.push(format!("variant {}: its command names a copy", v.id));
            results.push(result(&unread, &unread, "inconclusive"));
            continue;
        }
        if reproductions
            .iter()
            .any(|r| layout.rebase(&v.command).trim() == layout.rebase(r).trim())
        {
            reasons.push(format!("variant {}: it is the original reproduction", v.id));
            results.push(result(&unread, &unread, "inconclusive"));
            continue;
        }
        let base = poc(&log.run(&layout.in_copy("baseline", &v.command)));
        let patched = patched_run(&layout.in_copy("patched", &v.command));
        ran_any |= [&base, &patched]
            .iter()
            .any(|o| !matches!(o, Poc::NotRun(_)));
        // Shown in both copies under a setting the operator declared
        // an explicit opt-out of the control: the variant works because
        // the control is switched off, which no patch to the control
        // changes. Recorded, and neither held nor counted against the fix.
        if base == Poc::Shown
            && patched == Poc::Shown
            && let Some(setting) = opt_out(v)
        {
            reasons.push(format!(
                "variant {}: open by configuration: it sets `{setting}`, which the run's \
                 configuration declares an explicit opt-out; it does not fail the arm",
                v.id
            ));
            let mut r = result(&base, &patched, "open_by_configuration");
            r.opt_out = Some(setting);
            results.push(r);
            continue;
        }
        let outcome = match (&base, &patched) {
            (Poc::Shown, Poc::Shown) => {
                failed = true;
                reasons.push(format!(
                    "variant {}: shows the defect in the baseline and still shows it in the \
                     patched copy; the patch leaves this path open: {}",
                    v.id, v.path
                ));
                "open"
            }
            (_, Poc::Shown) => {
                failed = true;
                reasons.push(format!(
                    "variant {}: shows the defect in the patched copy and not in the baseline",
                    v.id
                ));
                "introduced"
            }
            (Poc::Shown, Poc::NotShown) => {
                held.push(v);
                "held"
            }
            (Poc::NotShown, _) => {
                reasons.push(format!(
                    "variant {}: does not show the defect in the baseline, so it is not a variant",
                    v.id
                ));
                "not_a_variant"
            }
            (Poc::Inconclusive(w) | Poc::NotRun(w), _) => {
                reasons.push(format!("variant {}: in the baseline copy: {w}", v.id));
                "inconclusive"
            }
            (Poc::Shown, Poc::Inconclusive(w) | Poc::NotRun(w)) => {
                reasons.push(format!("variant {}: in the patched copy: {w}", v.id));
                "inconclusive"
            }
        };
        results.push(result(&base, &patched, outcome));
    }
    // The agent's list of paths names what nothing was run for. A list
    // that does not parse costs the list, not the runs.
    let attack = match attack {
        Ok(a) => a.unwrap_or_default(),
        Err(e) => {
            reasons.push(format!("{e}; its list of paths is not read"));
            Attack::default()
        }
    };
    let untested: Vec<UntestedPath> = attack
        .paths
        .iter()
        .filter(|p| !held.iter().any(|v| v.path == p.id || v.id.contains(&p.id)))
        .map(|p| UntestedPath {
            id: p.id.clone(),
            route: p.route.clone(),
            location: p.location.clone(),
            description: p.description.clone(),
            reason: "no variant recorded for it held".into(),
        })
        .collect();
    let state = if failed {
        ArmState::Fail
    } else if held.len() >= minimum {
        let carried = held
            .iter()
            .filter(|v| v.source == VariantSource::Reproduction)
            .count();
        reasons.push(format!(
            "{} variant(s) held: {carried} other confirmed reproduction(s) of the finding and \
             {} written by the variant agent. That they take different paths is their \
             authors' claim; the runner does not check it",
            held.len(),
            held.len() - carried
        ));
        ArmState::Pass
    } else if specs.is_empty() {
        reasons.push(
            "no variant: the finding has no other confirmed reproduction and no script was \
             written under variants/"
                .into(),
        );
        ArmState::NotRun
    } else {
        reasons.push(format!(
            "{} variant(s) held; {minimum} are required",
            held.len()
        ));
        if ran_any {
            ArmState::Inconclusive
        } else {
            ArmState::NotRun
        }
    };
    if state == ArmState::Pass && !untested.is_empty() {
        reasons.push(format!(
            "{} listed path(s) have no variant that held; the list of paths is a model's",
            untested.len()
        ));
    }
    let basis = (ran_any || state == ArmState::Pass).then_some(Basis::Executed);
    (
        ArmResult::new("variant", state, basis, reasons),
        untested,
        results,
    )
}

/// Apply another finding's patch to this layout's patched copy: how a
/// combined copy is given each member's patch in turn.
pub fn apply_member(layout: &Layout, member_dir: &str) -> String {
    format!(
        "git apply --directory={} {member_dir}/fix.patch",
        layout.copy("patched")
    )
}

/// The reproduction arm of a combined record: every member finding's
/// own reproduction shows the defect in the baseline and does not in
/// the copy that holds all the member patches. One that still shows it
/// there fails the arm.
pub fn combined_reproduction_arm(
    log: &Log,
    layout: &Layout,
    members: &[(&str, &str)],
) -> ArmResult {
    let mut reasons = Vec::new();
    let mut failed = false;
    let mut ran_any = false;
    for (stable_id, command) in members {
        let base = poc(&log.run(&layout.in_copy("baseline", command)));
        let patched = poc(&log.run(&layout.in_copy("patched", command)));
        ran_any |= [&base, &patched]
            .iter()
            .any(|o| !matches!(o, Poc::NotRun(_)));
        match (&base, &patched) {
            (Poc::Shown, Poc::NotShown) => {}
            (_, Poc::Shown) => {
                failed = true;
                reasons.push(format!(
                    "the reproduction of {stable_id} still shows the defect in the combined copy"
                ));
            }
            (Poc::Shown, Poc::Inconclusive(w) | Poc::NotRun(w)) => reasons.push(format!(
                "the reproduction of {stable_id} in the combined copy: {w}"
            )),
            (b, _) => reasons.push(format!(
                "the reproduction of {stable_id} in the baseline copy: {}",
                poc_word(b)
            )),
        }
    }
    let state = if failed {
        ArmState::Fail
    } else if reasons.is_empty() && !members.is_empty() {
        ArmState::Pass
    } else if ran_any {
        ArmState::Inconclusive
    } else {
        ArmState::NotRun
    };
    ArmResult::new(
        "reproduction",
        state,
        ran_any.then_some(Basis::Executed),
        reasons,
    )
}

/// The functionality arm of a combined record: the configured test
/// command in the baseline and in the combined copy. It fails when the
/// command passes in the baseline and fails with the patches in. It
/// does not pass: no coverage and no benign-input run is read for a
/// union, so passing in both copies is recorded and nothing more.
pub fn combined_functionality_arm(log: &Log, layout: &Layout, test: Option<&str>) -> ArmResult {
    let Some(test) = test else {
        return ArmResult::new(
            "functionality",
            ArmState::NotRun,
            None,
            vec!["the run's configuration names no test command".into()],
        );
    };
    let base = log.run(&layout.in_copy("baseline", test));
    let patched = log.run(&layout.in_copy("patched", test));
    let ran = |r: &Run| !matches!(r, Run::Never | Run::Refused);
    let (state, reason) = match (&base, &patched) {
        (Run::Done { success: true, .. }, Run::Done { success: false, .. }) => (
            ArmState::Fail,
            "the test command passes in the baseline copy and fails in the combined copy",
        ),
        (Run::Done { success: true, .. }, Run::Done { success: true, .. }) => (
            ArmState::Inconclusive,
            "the test command passes in both copies; no coverage or benign-input run was read \
             for the union",
        ),
        (Run::Done { success: false, .. }, _) => (
            ArmState::Inconclusive,
            "the test command fails in the baseline copy, so a failure cannot be attributed \
             to the patches",
        ),
        _ if ran(&base) || ran(&patched) => (
            ArmState::Inconclusive,
            "the test command did not finish in both copies",
        ),
        _ => (ArmState::NotRun, "the test command was not run"),
    };
    ArmResult::new(
        "functionality",
        state,
        (ran(&base) || ran(&patched)).then_some(Basis::Executed),
        vec![reason.to_string()],
    )
}

/// A `{file, line_start}` site on a finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Site {
    pub file: String,
    pub line_start: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

pub fn site(finding: &Value, key: &str) -> Option<Site> {
    let v = finding.get(key)?;
    Some(Site {
        file: v.get("file")?.as_str()?.to_string(),
        line_start: u32::try_from(v.get("line_start")?.as_u64()?).ok()?,
        function: v
            .get("function")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEvidence {
    /// The baseline run of the reproduction showed the defect and its
    /// output names the origin.
    ConfirmedByExecutedPoc,
    AssertedOnly,
}

/// The root-cause claim the fix was built on, and what stands behind it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RootCauseClaim {
    /// The invariant the finding names.
    pub claim: String,
    /// Where the walks place the origin of the violation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Site>,
    pub evidence_state: ClaimEvidence,
    /// Set when the variant arm failed: a fix at this origin left
    /// another path open.
    pub suspect: bool,
}

/// The claim as the fix step was given it. It is confirmed only when
/// the runner saw the reproduction show the defect in the baseline and
/// the output of that run names the origin's file or function.
/// Anything else is asserted only.
pub fn root_cause_claim(finding: &Value, reproduction: &Reproduction) -> RootCauseClaim {
    let origin = site(finding, "origin");
    let named = origin.as_ref().is_some_and(|o| {
        reproduction.baseline_output.as_deref().is_some_and(|out| {
            out.contains(&o.file)
                || o.function
                    .as_deref()
                    .is_some_and(|f| f.len() >= 4 && out.contains(f))
        })
    });
    RootCauseClaim {
        claim: finding
            .get("invariant")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string(),
        origin,
        evidence_state: if named && reproduction.baseline == Poc::Shown {
            ClaimEvidence::ConfirmedByExecutedPoc
        } else {
            ClaimEvidence::AssertedOnly
        },
        suspect: false,
    }
}

/// The root-cause arm: the patched location against the origin. A
/// patch on the sink alone, with the origin elsewhere, is a symptom
/// patch. Where the origin lies is a walk's reading, so that alone is
/// a claim and leaves the arm inconclusive; it fails when a variant by
/// another path still shows the defect in the patched copy. The second
/// value is whether it failed as a symptom patch.
pub fn root_cause_arm(
    shape: &PatchShape,
    finding: &Value,
    claim: &RootCauseClaim,
    patched: &Poc,
    variant_failed: bool,
) -> (ArmResult, bool) {
    let judged = Some(Basis::ModelJudged);
    let Some(origin) = &claim.origin else {
        return (
            ArmResult::new(
                "root_cause",
                ArmState::Inconclusive,
                None,
                vec!["the finding records no origin to compare the patch with".into()],
            ),
            false,
        );
    };
    let sink = site(finding, "location");
    let at_origin = shape.touches(&origin.file, origin.line_start);
    let at_sink = sink
        .as_ref()
        .is_some_and(|s| shape.touches(&s.file, s.line_start));
    let at = |s: &Site| format!("{}:{}", s.file, s.line_start);
    if at_origin && !matches!(patched, Poc::Shown | Poc::NotShown) {
        // The patch is in the right place and nothing ran on it: a copy
        // that did not build shows nothing about the patched code.
        return (
            ArmResult::new(
                "root_cause",
                ArmState::Inconclusive,
                judged,
                vec![format!(
                    "the patch touches the recorded origin {}, and the reproduction never \
                     reached its assertion in the patched copy",
                    at(origin)
                )],
            ),
            false,
        );
    }
    if at_origin {
        return match claim.evidence_state {
            ClaimEvidence::ConfirmedByExecutedPoc => (
                ArmResult::new(
                    "root_cause",
                    ArmState::Pass,
                    Some(Basis::Executed),
                    Vec::new(),
                ),
                false,
            ),
            ClaimEvidence::AssertedOnly => (
                ArmResult::new(
                    "root_cause",
                    ArmState::Inconclusive,
                    judged,
                    vec![format!(
                        "the patch touches the recorded origin {}, which is asserted only",
                        at(origin)
                    )],
                ),
                false,
            ),
        };
    }
    if at_sink {
        let sink = sink.as_ref().map(at).unwrap_or_default();
        let claim_text = format!(
            "symptom_patch: the patch touches the sink {sink} and not the origin {}",
            at(origin)
        );
        // Where the origin lies is a walk's reading. It rejects the fix
        // only with an executed run behind it: a variant by another
        // path that still shows the defect in the patched copy.
        if variant_failed {
            return (
                ArmResult::new(
                    "root_cause",
                    ArmState::Fail,
                    Some(Basis::Executed),
                    vec![format!(
                        "{claim_text}; a variant by another path shows the defect in the \
                         patched copy"
                    )],
                ),
                true,
            );
        }
        return (
            ArmResult::new(
                "root_cause",
                ArmState::Inconclusive,
                judged,
                vec![
                    "the walks place the origin away from the patch; no executed run \
                     confirms it"
                        .into(),
                ],
            )
            .with_claims(vec![claim_text]),
            false,
        );
    }
    (
        ArmResult::new(
            "root_cause",
            ArmState::Inconclusive,
            judged,
            vec![format!(
                "the patch touches neither the recorded origin {} nor the sink",
                at(origin)
            )],
        ),
        false,
    )
}

/// The regression and relocation arm. It fails on an executed run: a
/// candidate from the re-walk whose proof of concept shows it in the
/// patched copy, or a bounded fuzz run that shows a defect there. A
/// candidate with no such run is a model's claim: it is recorded on
/// the arm, which is then inconclusive, and it does not reject the
/// fix. The arm passes only on a fuzz run that executed clean with no
/// candidate reported.
pub fn relocation_arm(
    log: &Log,
    layout: &Layout,
    recheck: &Result<Option<Recheck>, String>,
) -> ArmResult {
    let relocation = match recheck {
        Err(e) => {
            return ArmResult::new("relocation", ArmState::Inconclusive, None, vec![e.clone()]);
        }
        Ok(r) => r.as_ref().and_then(|r| r.relocation.as_ref()),
    };
    let Some(relocation) = relocation else {
        return ArmResult::new(
            "relocation",
            ArmState::NotRun,
            None,
            vec!["no re-walk of the patched code was recorded".into()],
        );
    };
    // A candidate is a model's claim. It fails the arm only when a
    // proof of concept for it, under the marker contract, shows the
    // defect in the patched copy. Otherwise it is kept as a claim.
    let mut reasons: Vec<String> = Vec::new();
    let mut claims: Vec<String> = Vec::new();
    let mut confirmed = false;
    // A functional regression is not this arm's: the functionality arm
    // reads it. This arm fails on a security defect the patch made or
    // moved, which is one its proof shows in the patched copy and does
    // not show in the baseline.
    for c in relocation.candidates.iter().filter(|c| !c.is_regression()) {
        let kind = if c.kind.is_empty() { "new" } else { &c.kind };
        let text = format!("{kind} candidate at {}: {}", c.location, c.title);
        let Some(cmd) = c.command.as_ref() else {
            claims.push(format!("{text} (no proof of concept)"));
            continue;
        };
        if names_a_copy(cmd) {
            claims.push(format!(
                "{text} (its proof of concept: its command names a copy)"
            ));
            continue;
        }
        let patched = poc(&log.run(&layout.in_copy("patched", cmd)));
        let baseline = poc(&log.run(&layout.in_copy("baseline", cmd)));
        match (&patched, &baseline) {
            (Poc::Shown, Poc::NotShown) => {
                confirmed = true;
                reasons.push(format!(
                    "{text}; its proof of concept shows it in the patched copy and not in \
                     the baseline"
                ));
            }
            (Poc::Shown, Poc::Shown) => claims.push(format!(
                "{text} (its proof of concept shows it in both copies: it was there before \
                 the patch, so the patch neither made nor moved it)"
            )),
            (Poc::Shown, Poc::Inconclusive(w) | Poc::NotRun(w)) => claims.push(format!(
                "{text} (its proof of concept shows it in the patched copy; in the baseline \
                 copy: {w}, so nothing shows it is new)"
            )),
            (Poc::NotShown, _) => claims.push(format!(
                "{text} (its proof of concept does not show it in the patched copy)"
            )),
            (Poc::Inconclusive(w) | Poc::NotRun(w), _) => {
                claims.push(format!("{text} (its proof of concept: {w})"))
            }
        }
    }
    let fuzz = relocation.fuzz.as_ref().map(|f| {
        if names_a_copy(&f.command) {
            Poc::Inconclusive("its command names a copy".into())
        } else {
            poc(&log.run(&layout.in_copy("patched", &f.command)))
        }
    });
    if fuzz == Some(Poc::Shown) {
        reasons.push("the bounded fuzz run shows a defect in the patched copy".into());
        confirmed = true;
    }
    if confirmed {
        return ArmResult::new("relocation", ArmState::Fail, Some(Basis::Executed), reasons)
            .with_claims(claims);
    }
    if !claims.is_empty() {
        return ArmResult::new(
            "relocation",
            ArmState::Inconclusive,
            Some(Basis::ModelJudged),
            vec![format!(
                "the re-walk reported {} candidate(s) that no executed run confirms; they \
                 are recorded as claims and do not reject the fix",
                claims.len()
            )],
        )
        .with_claims(claims);
    }
    if relocation.scope.is_empty() {
        return ArmResult::new(
            "relocation",
            ArmState::Inconclusive,
            Some(Basis::ModelJudged),
            vec!["the re-walk names no scope".into()],
        );
    }
    match fuzz {
        Some(Poc::NotShown) => ArmResult::new(
            "relocation",
            ArmState::Pass,
            Some(Basis::Executed),
            Vec::new(),
        ),
        Some(Poc::Inconclusive(w) | Poc::NotRun(w)) => ArmResult::new(
            "relocation",
            ArmState::Inconclusive,
            Some(Basis::ModelJudged),
            vec![format!(
                "the re-walk reported no candidate; the bounded fuzz run: {w}"
            )],
        ),
        _ => ArmResult::new(
            "relocation",
            ArmState::Inconclusive,
            Some(Basis::ModelJudged),
            vec!["the re-walk reported no candidate; no fuzz harness ran".into()],
        ),
    }
}

/// Whether `output` reports non-zero coverage for `file`: a line that
/// holds the file's path and a percentage above zero.
fn covered(output: &str, file: &str) -> bool {
    output.lines().filter(|l| l.contains(file)).any(|l| {
        l.split_whitespace().any(|t| {
            t.strip_suffix('%')
                .and_then(|n| n.parse::<f64>().ok())
                .is_some_and(|n| n > 0.0)
        })
    })
}

/// The commands the run's configuration names for the functionality
/// arm. They take precedence over what the recheck agent proposed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FunctionalityConfig {
    pub test_command: Option<String>,
    pub coverage_command: Option<String>,
}

/// The functionality arm. (a) The project's test suite in the baseline
/// and patched copies, with a coverage report that shows the patched
/// files exercised. (b) A benign-input harness whose output is the same
/// in both copies. A suite that newly fails, or output that differs,
/// fails the arm. Without coverage of the patched code it records
/// "functionality unverified" and does not pass.
pub fn functionality_arm(
    log: &Log,
    layout: &Layout,
    recheck: &Result<Option<Recheck>, String>,
    shape: &PatchShape,
    config: &FunctionalityConfig,
) -> ArmResult {
    let plan = match recheck {
        Err(e) if config.test_command.is_none() => {
            return ArmResult::new(
                "functionality",
                ArmState::Inconclusive,
                None,
                vec![e.clone()],
            );
        }
        Err(_) => FunctionalityPlan::default(),
        Ok(r) => r
            .as_ref()
            .and_then(|r| r.functionality.clone())
            .unwrap_or_default(),
    };
    let suite = config
        .test_command
        .clone()
        .or(plan.suite.map(|c| c.command));
    let coverage = config
        .coverage_command
        .clone()
        .or(plan.coverage.map(|c| c.command));
    let benign = plan.benign.map(|c| c.command);

    // Behaviour the re-walk showed the patch breaks: a proof that
    // shows in the patched copy and not in the baseline.
    let (regressed, regression_claims) = regressions(log, layout, recheck);
    let mut failed = !regressed.is_empty();
    let mut ran_any = failed;
    let mut reasons = regressed;
    let mut ran = |r: &Run| {
        let did = !matches!(r, Run::Never | Run::Refused);
        ran_any |= did;
        did
    };
    let why = |r: &Run| match r {
        Run::Never => "was not run",
        Run::Refused => "was refused at the gate",
        Run::TimedOut => "timed out",
        Run::Disagree => "ran more than once with different results",
        Run::Done { success: true, .. } => "passed",
        Run::Done { .. } => "failed",
    };

    // (a) The suite, then coverage of the patched files.
    let mut suite_ok = false;
    match &suite {
        None => reasons.push("no test suite command".into()),
        Some(cmd) if names_a_copy(cmd) => {
            reasons.push("the test suite command names a copy".into())
        }
        Some(cmd) => {
            let base = log.run(&layout.in_copy("baseline", cmd));
            let patched = log.run(&layout.in_copy("patched", cmd));
            ran(&base);
            ran(&patched);
            match (&base, &patched) {
                (Run::Done { success: true, .. }, Run::Done { success: true, .. }) => {
                    suite_ok = true
                }
                (Run::Done { success: true, .. }, Run::Done { success: false, .. }) => {
                    failed = true;
                    reasons.push(
                        "the test suite passes in the baseline copy and fails in the patched copy"
                            .into(),
                    );
                }
                (Run::Done { success: false, .. }, _) => reasons.push(
                    "the test suite fails in the baseline copy, so a failure cannot be \
                     attributed to the patch"
                        .into(),
                ),
                (b, p) => reasons.push(format!(
                    "the test suite {} in the baseline copy and {} in the patched copy",
                    why(b),
                    why(p)
                )),
            }
        }
    }
    let tests_touched = shape.test_files();
    if suite_ok && !tests_touched.is_empty() {
        suite_ok = false;
        reasons.push(format!(
            "the patch modifies test files ({}), so the suite does not stand for the \
             behaviour before it",
            tests_touched.join(", ")
        ));
    }
    let mut covered_all = false;
    if suite_ok {
        let sources: Vec<&String> = shape.files.iter().filter(|f| !is_test_path(f)).collect();
        match &coverage {
            None => reasons.push(
                "functionality unverified: no coverage command, so nothing shows the suite \
                 exercises the patched code"
                    .into(),
            ),
            Some(cmd) if names_a_copy(cmd) => {
                reasons.push("functionality unverified: the coverage command names a copy".into())
            }
            Some(cmd) => {
                let run = log.run(&layout.in_copy("patched", cmd));
                ran(&run);
                match &run {
                    Run::Done {
                        success: true,
                        output,
                        ..
                    } => {
                        let missing: Vec<&str> = sources
                            .iter()
                            .filter(|f| !covered(output, f))
                            .map(|f| f.as_str())
                            .collect();
                        if missing.is_empty() && !sources.is_empty() {
                            covered_all = true;
                        } else {
                            reasons.push(format!(
                                "functionality unverified: the coverage report shows no \
                                 coverage of {}",
                                if missing.is_empty() {
                                    "any patched file".to_string()
                                } else {
                                    missing.join(", ")
                                }
                            ));
                        }
                    }
                    other => reasons.push(format!(
                        "functionality unverified: the coverage command {}",
                        why(other)
                    )),
                }
            }
        }
    }

    // (b) Benign inputs: the same output in both copies.
    let mut benign_ok = false;
    match &benign {
        None => {}
        Some(cmd) if names_a_copy(cmd) => {
            reasons.push("the benign-input command names a copy".into())
        }
        Some(cmd) => {
            let base_cmd = layout.in_copy("baseline", cmd);
            let base_runs = log.runs(&base_cmd);
            let base = log.run(&base_cmd);
            let patched = log.run(&layout.in_copy("patched", cmd));
            ran(&base);
            ran(&patched);
            match (&base, &patched) {
                (
                    Run::Done {
                        success: true,
                        output: b,
                        ..
                    },
                    Run::Done {
                        success: p_ok,
                        output: p,
                        ..
                    },
                ) => {
                    if !has_marker(b) {
                        reasons.push(format!(
                            "the benign-input harness printed no {REACHED} line in the \
                             baseline copy"
                        ));
                    } else if base_runs.len() < 2 {
                        reasons.push(
                            "the benign-input harness ran once in the baseline copy; two runs \
                             are needed to rule out output that changes by itself"
                                .into(),
                        );
                    } else if base_runs.iter().any(|o| o.output != *b) {
                        reasons.push(
                            "the benign-input output differs between two runs of the baseline \
                             copy"
                                .into(),
                        );
                    } else if !p_ok {
                        failed = true;
                        reasons.push(
                            "the benign-input harness succeeds in the baseline copy and fails \
                             in the patched copy"
                                .into(),
                        );
                    } else if b != p {
                        failed = true;
                        let line = b
                            .lines()
                            .zip(p.lines())
                            .position(|(x, y)| x != y)
                            .unwrap_or_else(|| b.lines().count().min(p.lines().count()));
                        reasons.push(format!(
                            "benign-input output differs between the baseline and patched \
                             copies, first at line {}",
                            line + 1
                        ));
                    } else {
                        benign_ok = true;
                    }
                }
                (b, p) => reasons.push(format!(
                    "the benign-input harness {} in the baseline copy and {} in the patched copy",
                    why(b),
                    why(p)
                )),
            }
        }
    }
    let needs_benign = shape.locality() == Locality::CrossCutting;
    if needs_benign && !benign_ok && !failed && benign.is_none() {
        reasons.push("a cross-cutting patch requires the benign-input differential".into());
    }

    let state = if failed {
        ArmState::Fail
    } else if suite_ok && covered_all && (benign_ok || (benign.is_none() && !needs_benign)) {
        ArmState::Pass
    } else if ran_any {
        ArmState::Inconclusive
    } else {
        ArmState::NotRun
    };
    if state == ArmState::Pass {
        reasons.clear();
    }
    ArmResult::new(
        "functionality",
        state,
        ran_any.then_some(Basis::Executed),
        reasons,
    )
    .with_claims(regression_claims)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpenSite {
    pub file: String,
    pub line: u32,
}

/// Other sites with the same invariant pattern and no guard. A fix
/// closes one instance; this is what it leaves of the class.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClassOpenSites {
    pub count: usize,
    pub locations: Vec<OpenSite>,
    /// Sites whose quoted line is not in the file the site names.
    pub unverified: Vec<OpenSite>,
    /// Whether a listing was produced at all.
    pub listed: bool,
    pub basis: Basis,
}

/// The class report. A site is kept when the line it quotes is in the
/// file it names under `target`; the rest are listed as unverified.
/// That the site is unguarded is the recheck agent's reading.
pub fn class_report(recheck: &Result<Option<Recheck>, String>, target: &Path) -> ClassOpenSites {
    let sites = match recheck {
        Ok(Some(r)) => Some(&r.class_sites),
        _ => None,
    };
    let mut locations = Vec::new();
    let mut unverified = Vec::new();
    for s in sites.into_iter().flatten().filter(|s| !s.guarded) {
        let site = OpenSite {
            file: s.file.clone(),
            line: s.line,
        };
        let quoted = s.quote.trim();
        let found = !quoted.is_empty()
            && !Path::new(&s.file).is_absolute()
            && !s.file.split('/').any(|c| c == "..")
            && std::fs::read_to_string(target.join(&s.file))
                .is_ok_and(|body| body.lines().any(|l| l.contains(quoted)));
        if found {
            locations.push(site);
        } else {
            unverified.push(site);
        }
    }
    ClassOpenSites {
        count: locations.len(),
        locations,
        unverified,
        listed: sites.is_some(),
        basis: Basis::ModelJudged,
    }
}

/// How many fixes ended in each state of each arm.
pub fn count_by_arm<'a>(
    arms: impl IntoIterator<Item = &'a ArmResult>,
) -> BTreeMap<&'static str, BTreeMap<&'static str, usize>> {
    let mut out: BTreeMap<&'static str, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for a in arms {
        *out.entry(a.arm)
            .or_default()
            .entry(a.state.as_str())
            .or_default() += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const REV: &str = "abc123";
    const REPRO: &str = "python3 .lyrik/state/runs/r1/staging/fuzz-walk/harness/poc.py";

    fn layout() -> Layout {
        Layout::new("r1", "staging/fix/f1")
    }

    fn shown() -> String {
        format!("start\n{REACHED}\nAssertionError")
    }

    fn clean() -> String {
        format!("start\n{REACHED}\nok")
    }

    struct Runs(Vec<Observed>);

    impl Runs {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn add(&mut self, command: String, success: bool, output: &str) -> &mut Self {
            self.0.push(Observed {
                seq: self.0.len(),
                command,
                success,
                output: output.to_string(),
            });
            self
        }
        /// The setup and the runs of a patch that works: the baseline
        /// shows the defect, the patched copy does not, and the same
        /// copy shows it again with the patch taken out, after which
        /// the patch goes back in.
        fn good() -> Self {
            let l = layout();
            let mut r = Self::new();
            r.add(l.extract_baseline(REV), true, "(no output)");
            r.add(l.extract_patched(REV), true, "(no output)");
            r.add(l.apply(), true, "(no output)");
            r.add(l.in_copy("baseline", REPRO), false, &shown());
            r.add(l.in_copy("patched", REPRO), true, &clean());
            r.add(l.revert(), true, "(no output)");
            r.add(l.check_reverted(REV), true, "(no output)");
            r.add(l.in_copy("patched", REPRO), false, &shown());
            r.add(l.apply(), true, "(no output)");
            r
        }
        fn set(&mut self, command: &str, success: bool, output: &str) -> &mut Self {
            self.set_nth(command, 0, success, output)
        }
        /// Change the `n`th run of `command`.
        fn set_nth(&mut self, command: &str, n: usize, success: bool, output: &str) -> &mut Self {
            let o = self
                .0
                .iter_mut()
                .filter(|o| o.command == command)
                .nth(n)
                .unwrap_or_else(|| panic!("no run {n} of {command}"));
            o.success = success;
            o.output = output.to_string();
            self
        }
    }

    fn repro(r: &Runs) -> Reproduction {
        reproduction_arm(&Log(&r.0), &layout(), REPRO, REV)
    }

    #[test]
    fn exec_results_are_read_from_the_session_log_not_from_the_agent() {
        let events: Vec<SessionEvent> = serde_json::from_value(serde_json::json!([
            {"kind": "assistant_tool_calls", "calls": [
                {"id": "c1", "name": "exec", "arguments": "{\"command\":\"ls a\"}"},
                {"id": "c2", "name": "read_file", "arguments": "{\"path\":\"x\"}"},
                {"id": "c3", "name": "exec", "arguments": "{\"command\":[\"ls\",\"b\"]}"}
            ]},
            {"kind": "tool_result", "call_id": "c1", "tool_name": "exec", "output": "x", "success": true},
            {"kind": "tool_result", "call_id": "c2", "tool_name": "read_file", "output": "y", "success": true},
            {"kind": "tool_result", "call_id": "c3", "tool_name": "exec",
             "output": "Permission denied: 'exec' was not executed", "success": false}
        ]))
        .expect("session events parse");
        let seen = observed_execs(&events);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].command, "ls a");
        assert!(seen[0].success);
        assert_eq!(seen[1].command, "ls b");
        let log = Log(&seen);
        assert!(matches!(log.run("ls a"), Run::Done { success: true, .. }));
        assert_eq!(log.run("ls b"), Run::Refused);
        assert_eq!(log.run("ls c"), Run::Never);
    }

    #[test]
    fn a_run_without_the_marker_is_neither_a_reproduction_nor_a_pass() {
        let done = |success, output: &str| Run::Done {
            success,
            output: output.to_string(),
            seq: 0,
        };
        assert_eq!(poc(&done(false, &shown())), Poc::Shown);
        assert_eq!(poc(&done(true, &clean())), Poc::NotShown);
        // A failed build exits non-zero and never reaches the assertion.
        assert!(matches!(
            poc(&done(false, "error: linker `cc` not found")),
            Poc::Inconclusive(_)
        ));
        // Exit zero with no marker is not a pass either.
        assert!(matches!(poc(&done(true, "ok")), Poc::Inconclusive(_)));
        assert!(matches!(poc(&Run::TimedOut), Poc::Inconclusive(_)));
        assert!(matches!(poc(&Run::Refused), Poc::NotRun(_)));
        assert!(matches!(poc(&Run::Never), Poc::NotRun(_)));
        // The marker on stderr does not count: a traceback can echo it.
        assert!(matches!(
            poc(&done(false, &format!("[stderr] {REACHED}\nboom"))),
            Poc::Inconclusive(_)
        ));
        assert!(matches!(
            poc(&done(false, &format!("out\n[stderr] print(x)\n{REACHED}"))),
            Poc::Inconclusive(_)
        ));
    }

    /// The container path and the host path both build the recorded
    /// output with `wirken_agent::sandbox::exec_output`. Through it, a
    /// marker counts only when the command printed it on stdout.
    #[test]
    fn the_marker_is_read_from_stdout_only_as_exec_records_the_streams() {
        use wirken_agent::sandbox::exec_output;
        let run = |stdout: &str, stderr: &str, success| Run::Done {
            success,
            output: exec_output(stdout, stderr),
            seq: 0,
        };
        // On stdout, with noise on stderr after it.
        assert_eq!(
            poc(&run(
                &format!("start\n{REACHED}\n"),
                "assert failed\n",
                false
            )),
            Poc::Shown
        );
        assert_eq!(poc(&run(&format!("{REACHED}\n"), "", true)), Poc::NotShown);
        // Only on stderr: first line, and a later line of a traceback.
        for stderr in [
            format!("{REACHED}\n"),
            format!("Traceback (most recent call last):\n{REACHED}\nSyntaxError\n"),
        ] {
            for stdout in ["", "building\n", "no newline at the end"] {
                assert!(
                    matches!(poc(&run(stdout, &stderr, false)), Poc::Inconclusive(_)),
                    "{stdout:?} {stderr:?}"
                );
            }
        }
        // The streams as the log holds them.
        assert_eq!(exec_output("out\n", "err\n"), "out\n\n[stderr] err\n");
        assert_eq!(exec_output("", "err"), "[stderr] err");
        assert_eq!(exec_output("", ""), "(no output)");
        // A cut inside a multi-byte character does not panic.
        let long = "\u{00e9}".repeat(20_000);
        assert!(exec_output(&long, "").ends_with("... (truncated)"));
    }

    #[test]
    fn a_later_passing_run_does_not_replace_an_earlier_one() {
        let mut r = Runs::new();
        r.add("cmd".into(), false, &shown());
        r.add("cmd".into(), true, &clean());
        assert_eq!(Log(&r.0).run("cmd"), Run::Disagree);
    }

    #[test]
    fn commands_are_rebased_into_a_copy() {
        let l = layout();
        assert_eq!(l.dir, ".lyrik/state/runs/r1/staging/fix/f1");
        assert_eq!(
            l.in_copy("baseline", REPRO),
            "cd .lyrik/state/runs/r1/staging/fix/_shared/baseline && python3 \
             ../../../../../../../../.lyrik/state/runs/r1/staging/fuzz-walk/harness/poc.py"
        );
        // An absolute path is left as it is.
        assert_eq!(
            l.rebase("cat /w/.lyrik/state/runs/r1/x"),
            "cat /w/.lyrik/state/runs/r1/x"
        );
        assert_eq!(l.rebase("cargo test"), "cargo test");
        // A reproduction's own harness directory rides in each copy, so
        // the command, and every path the harness names from the project
        // root, is the same there as in the target.
        let carried = Layout::for_reproduction("r1", "staging/fix/f1", REPRO);
        assert_eq!(carried.carried, ["fuzz-walk"]);
        assert_eq!(
            carried.in_copy("baseline", REPRO),
            format!("cd .lyrik/state/runs/r1/staging/fix/_shared/baseline && {REPRO}")
        );
        assert_eq!(
            carried.in_copy("patched", REPRO),
            format!("cd .lyrik/state/runs/r1/staging/fix/f1/patched && {REPRO}")
        );
        // The baseline is made once: the command is the same for every
        // finding of the run and does nothing when the copy is there.
        let other = Layout::for_reproduction("r1", "staging/fix/f2", "cargo test");
        assert_eq!(carried.extract_baseline(REV), other.extract_baseline(REV));
        assert_eq!(
            carried.extract_baseline(REV),
            "[ -e .lyrik/state/runs/r1/staging/fix/_shared/baseline.ready ] || { mkdir -p \
             .lyrik/state/runs/r1/staging/fix/_shared/baseline && git archive --format=tar \
             abc123 | tar -x -C .lyrik/state/runs/r1/staging/fix/_shared/baseline && touch \
             .lyrik/state/runs/r1/staging/fix/_shared/baseline.ready; }"
        );
        assert_eq!(
            carried.carry_into_baseline().as_deref(),
            Some(
                "mkdir -p .lyrik/state/runs/r1/staging/fix/_shared/baseline/.lyrik/state/runs/r1/staging/fuzz-walk \
                 && cp -R .lyrik/state/runs/r1/staging/fuzz-walk/harness \
                 .lyrik/state/runs/r1/staging/fix/_shared/baseline/.lyrik/state/runs/r1/staging/fuzz-walk/"
            )
        );
        assert_eq!(other.carry_into_baseline(), None);
        assert_eq!(
            carried.extract_patched(REV),
            "mkdir -p .lyrik/state/runs/r1/staging/fix/f1/patched && git archive --format=tar \
             abc123 | tar -x -C .lyrik/state/runs/r1/staging/fix/f1/patched && mkdir -p \
             .lyrik/state/runs/r1/staging/fix/f1/patched/.lyrik/state/runs/r1/staging/fuzz-walk \
             && cp -R .lyrik/state/runs/r1/staging/fuzz-walk/harness \
             .lyrik/state/runs/r1/staging/fix/f1/patched/.lyrik/state/runs/r1/staging/fuzz-walk/"
        );
        // The revert is taken in the patched copy and checked against
        // the revision's tracked files; there is no third copy.
        assert_eq!(
            carried.revert(),
            "git apply -R --directory=.lyrik/state/runs/r1/staging/fix/f1/patched \
             .lyrik/state/runs/r1/staging/fix/f1/fix.patch"
        );
        assert_eq!(
            carried.check_reverted(REV),
            "git --work-tree=.lyrik/state/runs/r1/staging/fix/f1/patched diff --quiet abc123 --"
        );
        assert_eq!(carried.up(), "../".repeat(8));
        // A path into another walk's staging is still re-pointed.
        assert!(
            carried
                .rebase("cat .lyrik/state/runs/r1/staging/sink-walk/notes.txt")
                .starts_with("cat ../../")
        );
        // A command that names no harness carries nothing.
        assert!(
            Layout::for_reproduction("r1", "staging/fix/f1", "cargo test")
                .carried
                .is_empty()
        );
        // A command that starts with the path.
        assert!(
            l.rebase(".lyrik/state/runs/r1/x.sh --go")
                .starts_with("../../../../../../../../.lyrik/state/runs/r1/x.sh")
        );
    }

    #[test]
    fn the_reproduction_arm_passes_on_runs_observed_in_order() {
        let out = repro(&Runs::good());
        assert_eq!(out.arm.state, ArmState::Pass, "{:?}", out.arm.reasons);
        assert_eq!(out.arm.basis, Some(Basis::Executed));
        assert_eq!(out.baseline, Poc::Shown);
        assert_eq!(out.patched, Poc::NotShown);
        assert!(!out.left_reverted);
    }

    #[test]
    fn the_reproduction_arm_fails_when_the_patched_copy_still_shows_the_defect() {
        let l = layout();
        let mut r = Runs::good();
        r.set(&l.in_copy("patched", REPRO), false, &shown());
        let out = repro(&r);
        assert_eq!(out.arm.state, ArmState::Fail);
        assert!(
            out.arm.reasons[0].contains("still shows the defect in the patched copy"),
            "{:?}",
            out.arm.reasons
        );
    }

    #[test]
    fn the_reproduction_arm_is_inconclusive_on_a_broken_build_and_not_run_on_nothing() {
        let l = layout();
        // The baseline build broke: non-zero exit, no marker.
        let mut r = Runs::good();
        r.set(&l.in_copy("baseline", REPRO), false, "error: missing dep");
        let out = repro(&r);
        assert_eq!(out.arm.state, ArmState::Inconclusive);
        assert_ne!(out.baseline, Poc::Shown);
        // The patched copy "passing" because its build broke is not a pass.
        let mut r = Runs::good();
        r.set(&l.in_copy("patched", REPRO), true, "nothing to run");
        assert_eq!(repro(&r).arm.state, ArmState::Inconclusive);
        // A tracked file in the reverted copy is not as the revision has it.
        let mut r = Runs::good();
        r.set(&l.check_reverted(REV), false, "(no output)");
        assert_eq!(repro(&r).arm.state, ArmState::Inconclusive);
        // With the patch out, the defect does not come back: something
        // other than the patch explains the patched run.
        let mut r = Runs::good();
        r.set_nth(&l.in_copy("patched", REPRO), 1, true, &clean());
        let out = repro(&r);
        assert_eq!(out.arm.state, ArmState::Inconclusive);
        assert!(
            out.arm
                .reasons
                .contains(&"the reproduction does not show the defect in the reverted copy".into()),
            "{:?}",
            out.arm.reasons
        );
        // The patch was not put back after the revert check.
        let mut r = Runs::good();
        r.0.pop();
        let out = repro(&r);
        assert_eq!(out.arm.state, ArmState::Inconclusive);
        assert!(out.left_reverted);
        // One run in the patched copy only: nothing saw the revert.
        let mut r = Runs::good();
        r.0.remove(7);
        let out = repro(&r);
        assert_eq!(
            out.arm.state,
            ArmState::Inconclusive,
            "{:?}",
            out.arm.reasons
        );
        // Every command refused at the gate.
        let mut r = Runs::good();
        for o in &mut r.0 {
            o.success = false;
            o.output = "Permission denied: 'exec' was not executed".into();
        }
        let out = repro(&r);
        assert_eq!(out.arm.state, ArmState::NotRun);
        assert_eq!(out.arm.basis, None);
        // Nothing in the log at all.
        assert_eq!(repro(&Runs::new()).arm.state, ArmState::NotRun);
    }

    fn attack(paths: &[&str]) -> Attack {
        Attack {
            paths: paths
                .iter()
                .map(|id| AttackPath {
                    id: id.to_string(),
                    route: "caller".into(),
                    location: format!("src/{id}.rs:1"),
                    description: String::new(),
                })
                .collect(),
        }
    }

    /// An agent-written variant `variants/<id>/run.py`, whose path is `path`.
    fn agent_spec(id: &str, path: &str) -> VariantSpec {
        VariantSpec {
            id: format!("variants/{id}/run.py"),
            source: VariantSource::Agent,
            path: path.to_string(),
            command: format!("python3 {}/variants/{id}/run.py", layout().dir),
        }
    }

    /// Another confirmed reproduction of the finding, from `walk`.
    fn carried_spec(walk: &str, file: &str) -> VariantSpec {
        VariantSpec {
            id: format!("reproduction:{walk}/{file}"),
            source: VariantSource::Reproduction,
            path: format!("{file} as {walk} wrote it"),
            command: format!("sh .lyrik/state/runs/r1/staging/{walk}/harness/{file}"),
        }
    }

    /// The patch put in, then both runs of a variant.
    fn variant_runs(
        r: &mut Runs,
        l: &Layout,
        v: &VariantSpec,
        base_shown: bool,
        patched_shown: bool,
    ) {
        let out = |s: bool| if s { shown() } else { clean() };
        if r.0.iter().all(|o| o.command != l.ensure_applied()) {
            r.add(l.ensure_applied(), true, "");
        }
        r.add(
            l.in_copy("baseline", &v.command),
            !base_shown,
            &out(base_shown),
        );
        r.add(
            l.in_copy("patched", &v.command),
            !patched_shown,
            &out(patched_shown),
        );
    }

    #[test]
    fn the_variant_arm_passes_on_observed_runs_with_no_list_from_an_agent() {
        let l = layout();
        let specs = [agent_spec("v1", "p1"), agent_spec("v2", "p2")];
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], true, false);
        variant_runs(&mut r, &l, &specs[1], true, false);
        // No attack.json at all: the runs alone carry the arm.
        let (arm, untested, results) =
            variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 2, &|_| None);
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
        assert_eq!(arm.basis, Some(Basis::Executed));
        assert!(untested.is_empty());
        assert_eq!(
            results.iter().map(|v| v.outcome).collect::<Vec<_>>(),
            ["held", "held"]
        );
        // With the agent's list of paths, the one nothing ran for is listed.
        let a = attack(&["p1", "p2", "p3"]);
        let (arm, untested, _) =
            variant_arm(&Log(&r.0), &l, &specs, Ok(Some(a)), REPRO, 2, &|_| None);
        assert_eq!(arm.state, ArmState::Pass);
        assert_eq!(untested.len(), 1);
        assert_eq!(untested[0].id, "p3");
        // A list that does not parse costs the list, not the runs.
        let (arm, _, _) = variant_arm(
            &Log(&r.0),
            &l,
            &specs,
            Err("attack.json does not parse".into()),
            REPRO,
            2,
            &|_| None,
        );
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
    }

    #[test]
    fn another_confirmed_reproduction_is_a_variant_the_runner_ran() {
        let specs = [
            carried_spec("sink-walk", "internal_keyless.sh"),
            carried_spec("chain-walk", "internal_keyed.sh"),
        ];
        let l = Layout::for_commands(
            "r1",
            "staging/fix/f1",
            specs.iter().map(|v| v.command.as_str()),
        );
        assert_eq!(l.carried, ["sink-walk", "chain-walk"]);
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], true, false);
        variant_runs(&mut r, &l, &specs[1], true, false);
        // The command runs in a copy from the harness the copy carries.
        assert!(r.0.iter().any(|o| o.command
            == format!(
                "cd {} && sh .lyrik/state/runs/r1/staging/sink-walk/harness/internal_keyless.sh",
                l.copy("patched")
            )));
        let (arm, _, results) = variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 2, &|_| None);
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
        assert!(
            results
                .iter()
                .all(|v| v.source == VariantSource::Reproduction)
        );
        assert!(
            arm.reasons
                .iter()
                .any(|x| x.starts_with("2 variant(s) held: 2 other confirmed"))
        );
    }

    #[test]
    fn a_variant_shown_in_the_baseline_and_in_the_patched_copy_fails_the_arm_and_names_the_path() {
        let l = layout();
        let specs = [
            agent_spec("v1", "p1"),
            carried_spec("sink-walk", "internal_keyless.sh"),
        ];
        let l2 = Layout::for_commands(
            "r1",
            "staging/fix/f1",
            specs.iter().map(|v| v.command.as_str()),
        );
        let mut r = Runs::new();
        variant_runs(&mut r, &l2, &specs[0], true, false);
        variant_runs(&mut r, &l2, &specs[1], true, true);
        let (arm, _, results) = variant_arm(&Log(&r.0), &l2, &specs, Ok(None), REPRO, 1, &|_| None);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(arm.basis, Some(Basis::Executed));
        assert!(
            arm.reasons.iter().any(|x| x.contains(
                "reproduction:sink-walk/internal_keyless.sh: shows the defect in the baseline and \
                 still shows it in the patched copy; the patch leaves this path open: \
                 internal_keyless.sh as sink-walk wrote it"
            )),
            "{:?}",
            arm.reasons
        );
        assert_eq!(results[1].outcome, "open");
        assert_eq!(
            (results[1].baseline.as_str(), results[1].patched.as_str()),
            ("shown", "shown")
        );
        // Shown in the patched copy only: the arm fails, and it is not "open".
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], false, true);
        let (arm, _, results) =
            variant_arm(&Log(&r.0), &l, &specs[..1], Ok(None), REPRO, 1, &|_| None);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(results[0].outcome, "introduced");
    }

    #[test]
    fn a_variant_counts_only_on_runs_that_saw_the_patch() {
        let l = layout();
        let specs = [
            agent_spec("v1", "p1"),
            agent_spec("v2", "p2"),
            agent_spec("v3", "p3"),
            agent_spec("v4", "p4"),
        ];
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], true, false);
        // v2 never showed the defect in the baseline: not a variant.
        variant_runs(&mut r, &l, &specs[1], false, false);
        // v3's baseline harness broke. v4 ran in the baseline only.
        r.add(
            l.in_copy("baseline", &specs[2].command),
            false,
            "ModuleNotFoundError",
        );
        r.add(l.in_copy("baseline", &specs[3].command), false, &shown());
        let (arm, _, results) = variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 2, &|_| None);
        assert_eq!(arm.state, ArmState::Inconclusive, "{:?}", arm.reasons);
        for want in [
            "variant variants/v2/run.py: does not show the defect in the baseline, so it is not a variant",
            "variant variants/v3/run.py: in the baseline copy: no LYRIK_REACHED line",
            "variant variants/v4/run.py: in the patched copy: not run",
            "1 variant(s) held; 2 are required",
        ] {
            assert!(
                arm.reasons.iter().any(|x| x.starts_with(want)),
                "{want} in {:?}",
                arm.reasons
            );
        }
        assert_eq!(
            results.iter().map(|v| v.outcome).collect::<Vec<_>>(),
            ["held", "not_a_variant", "inconclusive", "inconclusive"]
        );
        // A patched run made while the patch was out says nothing.
        let mut r = Runs::new();
        r.add(l.apply(), true, "");
        r.add(l.revert(), true, "");
        r.add(l.in_copy("baseline", &specs[0].command), false, &shown());
        r.add(l.in_copy("patched", &specs[0].command), false, &shown());
        let (arm, _, results) =
            variant_arm(&Log(&r.0), &l, &specs[..1], Ok(None), REPRO, 1, &|_| None);
        assert_eq!(arm.state, ArmState::Inconclusive, "{:?}", arm.reasons);
        assert_eq!(
            results[0].patched,
            "it ran only while the patch was out of the copy"
        );
        // The same two runs after the runner put the patch back count.
        r.add(l.ensure_applied(), true, "");
        r.add(l.in_copy("patched", &specs[0].command), true, &clean());
        let (arm, _, _) = variant_arm(&Log(&r.0), &l, &specs[..1], Ok(None), REPRO, 1, &|_| None);
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
        // A command that names a copy, and the original reproduction again.
        let mut copy_named = agent_spec("v5", "p5");
        copy_named.command = "python3 ../patched/x.py".into();
        let mut original = agent_spec("v6", "p6");
        original.command = REPRO.into();
        let (arm, _, _) = variant_arm(
            &Log(&[]),
            &l,
            &[copy_named, original],
            Ok(None),
            REPRO,
            2,
            &|_| None,
        );
        assert_eq!(arm.state, ArmState::NotRun);
        assert!(
            arm.reasons
                .iter()
                .any(|x| x.ends_with("its command names a copy"))
        );
        assert!(
            arm.reasons
                .iter()
                .any(|x| x.ends_with("it is the original reproduction"))
        );
        // Two held variants do not meet a cross-cutting patch's four.
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], true, false);
        variant_runs(&mut r, &l, &specs[1], true, false);
        let (arm, _, _) = variant_arm(
            &Log(&r.0),
            &l,
            &specs[..2],
            Ok(None),
            REPRO,
            VARIANT_MIN_CROSS_CUTTING,
            &|_| None,
        );
        assert_eq!(arm.state, ArmState::Inconclusive);
        // No variant on record at all: not run.
        let (arm, _, results) = variant_arm(&Log(&[]), &l, &[], Ok(None), REPRO, 2, &|_| None);
        assert_eq!(arm.state, ArmState::NotRun);
        assert_eq!(arm.basis, None);
        assert!(results.is_empty());
    }

    #[test]
    fn a_variant_open_under_an_operator_declared_opt_out_does_not_fail_the_arm() {
        let l = layout();
        let specs = [
            agent_spec("v1", "p1"),
            agent_spec("opted_out", "control switched off"),
        ];
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[0], true, false);
        variant_runs(&mut r, &l, &specs[1], true, true);
        let declared = |v: &VariantSpec| {
            v.id.contains("opted_out")
                .then(|| "ENFORCE_AUTH=false".to_string())
        };
        let (arm, _, results) = variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 1, &declared);
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
        assert_eq!(results[1].outcome, "open_by_configuration");
        assert_eq!(results[1].opt_out.as_deref(), Some("ENFORCE_AUTH=false"));
        assert!(
            arm.reasons
                .iter()
                .any(|x| x.contains("open by configuration: it sets `ENFORCE_AUTH=false`"))
        );
        // It is not counted as held either: one held variant, not two.
        let (arm, _, _) = variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 2, &declared);
        assert_eq!(arm.state, ArmState::Inconclusive);
        // With nothing declared the same runs fail the arm.
        let (arm, _, results) = variant_arm(&Log(&r.0), &l, &specs, Ok(None), REPRO, 1, &|_| None);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(results[1].outcome, "open");
        // A declared opt-out does not excuse a variant the patch stopped,
        // nor one that shows only in the patched copy.
        let mut r = Runs::new();
        variant_runs(&mut r, &l, &specs[1], false, true);
        let (arm, _, results) =
            variant_arm(&Log(&r.0), &l, &specs[1..], Ok(None), REPRO, 1, &declared);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(results[0].outcome, "introduced");
    }

    #[test]
    fn a_functional_regression_fails_functionality_and_not_relocation() {
        let l = layout();
        let cmd = "sh .lyrik/state/runs/r1/staging/fix/f1/relocation/peers/poc.sh";
        let with_kind = |kind: &str| {
            recheck(
                serde_json::json!({"relocation": {"scope": ["init at src/a.rs:1"],
                "candidates": [{"title": "peers can no longer reach each other",
                    "location": "src/a.rs:9", "kind": kind, "command": cmd}]}}),
            )
        };
        // Not shown in the baseline, shown in the patched copy.
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", cmd), true, &clean());
        r.add(l.in_copy("patched", cmd), false, &shown());
        let shape = parse_patch(ORIGIN_PATCH);
        let config = FunctionalityConfig::default();
        // Declared a regression: the functionality arm fails, relocation does not.
        let reloc = relocation_arm(&Log(&r.0), &l, &with_kind("regression"));
        assert_ne!(reloc.state, ArmState::Fail, "{:?}", reloc.reasons);
        assert!(
            reloc
                .reasons
                .iter()
                .chain(reloc.model_claims.iter())
                .all(|x| !x.contains("peers"))
        );
        let func = functionality_arm(&Log(&r.0), &l, &with_kind("regression"), &shape, &config);
        assert_eq!(func.state, ArmState::Fail);
        assert_eq!(func.basis, Some(Basis::Executed));
        assert!(
            func.reasons[0]
                .starts_with("regression at src/a.rs:9: peers can no longer reach each other")
        );
        // Declared a new security defect: relocation fails, functionality does not.
        let reloc = relocation_arm(&Log(&r.0), &l, &with_kind("new"));
        assert_eq!(reloc.state, ArmState::Fail);
        assert!(reloc.reasons[0].ends_with("shows it in the patched copy and not in the baseline"));
        let func = functionality_arm(&Log(&r.0), &l, &with_kind("new"), &shape, &config);
        assert_ne!(func.state, ArmState::Fail);
        // Shown in both copies: it was there before the patch. A claim, no failure.
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", cmd), false, &shown());
        r.add(l.in_copy("patched", cmd), false, &shown());
        let reloc = relocation_arm(&Log(&r.0), &l, &with_kind("relocated"));
        assert_eq!(reloc.state, ArmState::Inconclusive);
        assert!(
            reloc.model_claims[0].contains("shows it in both copies"),
            "{:?}",
            reloc.model_claims
        );
        // Shown in the patched copy with no baseline run: nothing shows it is new.
        let mut r = Runs::new();
        r.add(l.in_copy("patched", cmd), false, &shown());
        let reloc = relocation_arm(&Log(&r.0), &l, &with_kind("new"));
        assert_eq!(reloc.state, ArmState::Inconclusive);
        assert!(
            reloc.model_claims[0].contains("nothing shows it is new"),
            "{:?}",
            reloc.model_claims
        );
        // A regression no run confirms is a claim on the functionality arm.
        let func = functionality_arm(&Log(&r.0), &l, &with_kind("regression"), &shape, &config);
        assert_ne!(func.state, ArmState::Fail);
        assert!(
            func.model_claims[0].starts_with("regression at src/a.rs:9"),
            "{:?}",
            func.model_claims
        );
    }

    #[test]
    fn a_variant_is_registered_by_its_script_not_by_a_list() {
        let l = layout();
        let tmp = tempdir().unwrap();
        let v = tmp.path().join("variants");
        std::fs::create_dir_all(v.join("other_caller")).unwrap();
        std::fs::write(v.join("other_caller/run.sh"), "x").unwrap();
        std::fs::write(
            v.join("other_caller/path.txt"),
            "the second caller, rotate.sh\nmore\n",
        )
        .unwrap();
        // Written and never run, and with no path.txt.
        std::fs::create_dir_all(v.join("unrun")).unwrap();
        std::fs::write(v.join("unrun/run.py"), "x").unwrap();
        // A script under another name that the agent ran itself.
        std::fs::create_dir_all(v.join("keyless_delete")).unwrap();
        std::fs::write(v.join("keyless_delete/internal_keyless_delete.sh"), "x").unwrap();
        // A helper that nothing ran, and a directory with no script.
        std::fs::create_dir_all(v.join("_lib")).unwrap();
        std::fs::write(v.join("_lib/common.sh"), "x").unwrap();
        let mut r = Runs::new();
        let ran = format!(
            "sh {}/variants/keyless_delete/internal_keyless_delete.sh",
            l.dir
        );
        r.add(l.in_copy("baseline", &ran), false, &shown());
        // Outside variants/, and a path that climbs out: neither is read.
        r.add(
            format!(
                "cd {} && sh {}{}/variants/../fix.patch",
                l.copy("baseline"),
                l.up(),
                l.dir
            ),
            true,
            "",
        );
        r.add(
            format!(
                "cd {} && sh {}{}/relocation/x.sh",
                l.copy("baseline"),
                l.up(),
                l.dir
            ),
            true,
            "",
        );
        let specs = registered_variants(tmp.path(), &l, &r.0);
        let ids: Vec<&str> = specs.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "variants/other_caller/run.sh",
                "variants/unrun/run.py",
                "variants/keyless_delete/internal_keyless_delete.sh"
            ]
        );
        assert_eq!(specs[0].path, "the second caller, rotate.sh");
        assert_eq!(specs[1].path, "unrun");
        assert_eq!(
            specs[1].command,
            format!("python3 {}/variants/unrun/run.py", l.dir)
        );
        assert_eq!(specs[2].command, ran);
        // The command the runner composes for a copy is the one the agent ran.
        assert_eq!(l.in_copy("baseline", &specs[2].command), r.0[0].command);
        // No variants directory: nothing registered.
        assert!(registered_variants(&tmp.path().join("none"), &l, &[]).is_empty());
    }

    const SINK_PATCH: &str = "--- a/src/parse.rs\n+++ b/src/parse.rs\n\
        @@ -40,6 +40,8 @@ fn read_field(buf: &[u8]) {\n ctx\n+guard\n ctx\n";
    const ORIGIN_PATCH: &str = "--- a/src/header.rs\n+++ b/src/header.rs\n\
        @@ -10,5 +10,7 @@ fn decode_len(b: &[u8]) {\n ctx\n+check\n ctx\n";

    fn finding() -> Value {
        serde_json::json!({
            "stable_id": "f1",
            "invariant": "len never exceeds the buffer",
            "location": {"file": "src/parse.rs", "line_start": 42},
            "origin": {"file": "src/header.rs", "line_start": 12, "function": "decode_len"}
        })
    }

    fn reproduction(baseline: Poc, output: Option<&str>) -> Reproduction {
        Reproduction {
            arm: ArmResult::new("reproduction", ArmState::Inconclusive, None, Vec::new()),
            baseline,
            patched: Poc::NotShown,
            baseline_output: output.map(str::to_string),
            left_reverted: false,
        }
    }

    #[test]
    fn a_symptom_patch_fails_only_with_an_executed_variant_behind_it() {
        let f = finding();
        let claim = root_cause_claim(&f, &reproduction(Poc::Shown, Some("panic in decode_len")));
        let shape = parse_patch(SINK_PATCH);
        // The walks' placement of the origin alone: a claim, not a failure.
        let (arm, symptom) = root_cause_arm(&shape, &f, &claim, &Poc::NotShown, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(arm.basis, Some(Basis::ModelJudged));
        assert!(!symptom);
        assert_eq!(arm.model_claims.len(), 1);
        assert!(
            arm.model_claims[0].starts_with("symptom_patch:"),
            "{:?}",
            arm.model_claims
        );
        assert!(arm.model_claims[0].contains("src/parse.rs:42"));
        assert!(arm.model_claims[0].contains("src/header.rs:12"));
        // With a variant that still works on the patched code: fails.
        let (arm, symptom) = root_cause_arm(&shape, &f, &claim, &Poc::NotShown, true);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(arm.basis, Some(Basis::Executed));
        assert!(symptom);
        assert!(
            arm.reasons[0].starts_with("symptom_patch:"),
            "{:?}",
            arm.reasons
        );
    }

    #[test]
    fn the_root_cause_arm_passes_only_on_a_claim_an_executed_run_confirms() {
        let f = finding();
        let shape = parse_patch(ORIGIN_PATCH);
        // The baseline run showed the defect and its output names the origin.
        let claim = root_cause_claim(
            &f,
            &reproduction(Poc::Shown, Some("thread panicked at src/header.rs:12")),
        );
        assert_eq!(claim.evidence_state, ClaimEvidence::ConfirmedByExecutedPoc);
        assert_eq!(claim.claim, "len never exceeds the buffer");
        let (arm, symptom) = root_cause_arm(&shape, &f, &claim, &Poc::NotShown, false);
        assert_eq!(arm.state, ArmState::Pass);
        assert!(!symptom);
        // Same patch and claim, but the patched copy did not build: the
        // reproduction never reached its assertion there.
        for patched in [
            Poc::Inconclusive("no marker".into()),
            Poc::NotRun("not run".into()),
        ] {
            let (arm, symptom) = root_cause_arm(&shape, &f, &claim, &patched, false);
            assert_eq!(arm.state, ArmState::Inconclusive);
            assert!(
                arm.reasons[0].contains("never reached its assertion in the patched copy"),
                "{:?}",
                arm.reasons
            );
            assert!(!symptom);
        }
        // Same patch, origin asserted only: a model's placement cannot pass.
        let claim = root_cause_claim(&f, &reproduction(Poc::Shown, Some("boom")));
        assert_eq!(claim.evidence_state, ClaimEvidence::AssertedOnly);
        let (arm, _) = root_cause_arm(&shape, &f, &claim, &Poc::NotShown, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(arm.basis, Some(Basis::ModelJudged));
        // Output names the origin, but the run never showed the defect.
        let claim = root_cause_claim(
            &f,
            &reproduction(Poc::Inconclusive("x".into()), Some("src/header.rs")),
        );
        assert_eq!(claim.evidence_state, ClaimEvidence::AssertedOnly);
        // No origin on the finding.
        let mut bare = f.clone();
        bare.as_object_mut().unwrap().remove("origin");
        let claim = root_cause_claim(&bare, &reproduction(Poc::Shown, Some("x")));
        let (arm, symptom) = root_cause_arm(&shape, &bare, &claim, &Poc::NotShown, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(!symptom);
        // A patch that touches neither site.
        let other = parse_patch("--- a/src/z.rs\n+++ b/src/z.rs\n@@ -1,2 +1,3 @@\n x\n+y\n");
        let claim = root_cause_claim(&f, &reproduction(Poc::Shown, Some("x")));
        let (arm, symptom) = root_cause_arm(&other, &f, &claim, &Poc::NotShown, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(!symptom);
    }

    fn recheck(json: Value) -> Result<Option<Recheck>, String> {
        Ok(Some(serde_json::from_value(json).unwrap()))
    }

    #[test]
    fn a_relocated_candidate_is_a_claim_until_an_executed_run_confirms_it() {
        let l = layout();
        let candidate = |command: Option<&str>| {
            let mut c = serde_json::json!({"title": "callback holds a raw pointer",
                "location": "src/cb.rs:14", "kind": "relocated"});
            if let Some(cmd) = command {
                c["command"] = serde_json::json!(cmd);
            }
            recheck(serde_json::json!({"relocation": {
                "scope": ["on_event at src/cb.rs:9"], "candidates": [c]
            }}))
        };
        // No proof of concept: inconclusive, the claim kept, nothing rejected.
        let arm = relocation_arm(&Log(&[]), &l, &candidate(None));
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(arm.basis, Some(Basis::ModelJudged));
        assert_eq!(
            arm.model_claims,
            [
                "relocated candidate at src/cb.rs:14: callback holds a raw pointer (no proof of concept)"
            ]
        );
        // A proof of concept that did not show it, or never reached its
        // assertion: still a claim.
        let cmd = "sh ../relocation/c1/poc.sh";
        let mut r = Runs::new();
        r.add(l.in_copy("patched", cmd), true, &clean());
        let arm = relocation_arm(&Log(&r.0), &l, &candidate(Some(cmd)));
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(arm.model_claims.len(), 1);
        let mut r = Runs::new();
        r.add(l.in_copy("patched", cmd), false, "sh: not found");
        let arm = relocation_arm(&Log(&r.0), &l, &candidate(Some(cmd)));
        assert_eq!(arm.state, ArmState::Inconclusive);
        // A proof of concept that shows it in the patched copy and not
        // in the baseline: fails.
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", cmd), true, &clean());
        r.add(l.in_copy("patched", cmd), false, &shown());
        let arm = relocation_arm(&Log(&r.0), &l, &candidate(Some(cmd)));
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(arm.basis, Some(Basis::Executed));
        assert!(arm.model_claims.is_empty());
        assert!(
            arm.reasons[0].ends_with("shows it in the patched copy and not in the baseline"),
            "{:?}",
            arm.reasons
        );
        // A claim beside a clean fuzz run does not pass the arm either.
        let both = recheck(serde_json::json!({"relocation": {
            "scope": ["f"], "fuzz": {"command": "./fuzz -runs=1000"},
            "candidates": [{"title": "t", "location": "a:1"}]
        }}));
        let mut r = Runs::new();
        r.add(l.in_copy("patched", "./fuzz -runs=1000"), true, &clean());
        assert_eq!(
            relocation_arm(&Log(&r.0), &l, &both).state,
            ArmState::Inconclusive
        );
        // A fuzz run that shows a defect in the patched copy fails on execution.
        let rc = recheck(serde_json::json!({"relocation": {
            "scope": ["f"], "fuzz": {"command": "./fuzz -runs=1000"}
        }}));
        let mut r = Runs::new();
        r.add(l.in_copy("patched", "./fuzz -runs=1000"), false, &shown());
        let arm = relocation_arm(&Log(&r.0), &l, &rc);
        assert_eq!(arm.state, ArmState::Fail);
        assert_eq!(arm.basis, Some(Basis::Executed));
    }

    #[test]
    fn a_re_walk_that_reports_nothing_is_not_a_pass_without_an_executed_run() {
        let l = layout();
        let quiet = serde_json::json!({"relocation": {"scope": ["f at src/a.rs:1"]}});
        let arm = relocation_arm(&Log(&[]), &l, &recheck(quiet));
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(arm.basis, Some(Basis::ModelJudged));
        // With a fuzz run that executed clean, it passes.
        let fuzzed = serde_json::json!({"relocation": {
            "scope": ["f at src/a.rs:1"], "fuzz": {"command": "./fuzz -runs=1000"}
        }});
        let mut r = Runs::new();
        r.add(l.in_copy("patched", "./fuzz -runs=1000"), true, &clean());
        let arm = relocation_arm(&Log(&r.0), &l, &recheck(fuzzed.clone()));
        assert_eq!(arm.state, ArmState::Pass);
        assert_eq!(arm.basis, Some(Basis::Executed));
        // The fuzz build broke: inconclusive.
        let mut r = Runs::new();
        r.add(
            l.in_copy("patched", "./fuzz -runs=1000"),
            false,
            "no such file",
        );
        assert_eq!(
            relocation_arm(&Log(&r.0), &l, &recheck(fuzzed)).state,
            ArmState::Inconclusive
        );
        // No scope, no record, a record that does not parse.
        let arm = relocation_arm(
            &Log(&[]),
            &l,
            &recheck(serde_json::json!({"relocation": {}})),
        );
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert_eq!(
            relocation_arm(&Log(&[]), &l, &Ok(None)).state,
            ArmState::NotRun
        );
        assert_eq!(
            relocation_arm(&Log(&[]), &l, &Err("recheck.json does not parse".into())).state,
            ArmState::Inconclusive
        );
    }

    const SUITE: &str = "cargo test";
    const COVER: &str = "cargo llvm-cov --summary-only";
    const BENIGN: &str = "python3 ../benign/run.py";

    fn functionality(r: &Runs, patch: &str, with_benign: bool) -> ArmResult {
        let mut plan = serde_json::json!({"functionality": {
            "suite": {"command": SUITE}, "coverage": {"command": COVER}
        }});
        if with_benign {
            plan["functionality"]["benign"] = serde_json::json!({"command": BENIGN});
        }
        functionality_arm(
            &Log(&r.0),
            &layout(),
            &recheck(plan),
            &parse_patch(patch),
            &FunctionalityConfig::default(),
        )
    }

    fn suite_runs(base_ok: bool, patched_ok: bool, coverage: &str) -> Runs {
        let l = layout();
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", SUITE), base_ok, "test result");
        r.add(l.in_copy("patched", SUITE), patched_ok, "test result");
        r.add(l.in_copy("patched", COVER), true, coverage);
        r
    }

    fn benign_runs(r: &mut Runs, base: &str, again: &str, patched: &str) {
        let l = layout();
        let out = |s: &str| format!("{REACHED}\n{s}");
        r.add(l.in_copy("baseline", BENIGN), true, &out(base));
        r.add(l.in_copy("baseline", BENIGN), true, &out(again));
        r.add(l.in_copy("patched", BENIGN), true, &out(patched));
    }

    #[test]
    fn the_functionality_arm_passes_on_a_green_suite_that_covers_the_patch() {
        let r = suite_runs(true, true, "src/header.rs  120  12  90.00%");
        let arm = functionality(&r, ORIGIN_PATCH, false);
        assert_eq!(arm.state, ArmState::Pass, "{:?}", arm.reasons);
        // With the benign differential beside it.
        let mut r = suite_runs(true, true, "src/header.rs  120  12  90.00%");
        benign_runs(&mut r, "a=1", "a=1", "a=1");
        assert_eq!(functionality(&r, ORIGIN_PATCH, true).state, ArmState::Pass);
    }

    #[test]
    fn a_suite_that_newly_fails_or_output_that_differs_blocks_the_fix() {
        let r = suite_runs(true, false, "src/header.rs 90.00%");
        let arm = functionality(&r, ORIGIN_PATCH, false);
        assert_eq!(arm.state, ArmState::Fail);
        assert!(
            arm.reasons[0].contains("fails in the patched copy"),
            "{:?}",
            arm.reasons
        );
        let mut r = suite_runs(true, true, "src/header.rs 90.00%");
        benign_runs(&mut r, "a=1\nb=2", "a=1\nb=2", "a=1\nb=3");
        let arm = functionality(&r, ORIGIN_PATCH, true);
        assert_eq!(arm.state, ArmState::Fail);
        assert!(
            arm.reasons.iter().any(|x| x.ends_with("first at line 3")),
            "{:?}",
            arm.reasons
        );
    }

    #[test]
    fn no_coverage_of_the_patched_code_is_functionality_unverified_never_a_pass() {
        // The report covers another file.
        let r = suite_runs(true, true, "src/other.rs 95.00%");
        let arm = functionality(&r, ORIGIN_PATCH, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(
            arm.reasons[0].starts_with("functionality unverified:"),
            "{:?}",
            arm.reasons
        );
        // The file is listed at zero.
        let r = suite_runs(true, true, "src/header.rs 120 120 0.00%");
        assert_eq!(
            functionality(&r, ORIGIN_PATCH, false).state,
            ArmState::Inconclusive
        );
        // No coverage command at all.
        let l = layout();
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", SUITE), true, "ok");
        r.add(l.in_copy("patched", SUITE), true, "ok");
        let arm = functionality_arm(
            &Log(&r.0),
            &l,
            &recheck(serde_json::json!({"functionality": {"suite": {"command": SUITE}}})),
            &parse_patch(ORIGIN_PATCH),
            &FunctionalityConfig::default(),
        );
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(arm.reasons[0].starts_with("functionality unverified:"));
    }

    #[test]
    fn the_functionality_arm_does_not_pass_on_gaps() {
        // The suite fails on both copies: no attribution.
        let r = suite_runs(false, false, "src/header.rs 90.00%");
        assert_eq!(
            functionality(&r, ORIGIN_PATCH, false).state,
            ArmState::Inconclusive
        );
        // The patch edits a test.
        let with_test = format!(
            "{ORIGIN_PATCH}--- a/tests/header.rs\n+++ b/tests/header.rs\n@@ -1,2 +1,2 @@\n-a\n+b\n"
        );
        let r = suite_runs(true, true, "src/header.rs 90.00%");
        let arm = functionality(&r, &with_test, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(
            arm.reasons[0].contains("modifies test files"),
            "{:?}",
            arm.reasons
        );
        // Benign output that changes between two baseline runs.
        let mut r = suite_runs(true, true, "src/header.rs 90.00%");
        benign_runs(&mut r, "t=1", "t=2", "t=1");
        assert_eq!(
            functionality(&r, ORIGIN_PATCH, true).state,
            ArmState::Inconclusive
        );
        // A cross-cutting patch with no benign differential.
        let cross = format!("{ORIGIN_PATCH}{SINK_PATCH}");
        let r = suite_runs(true, true, "src/header.rs 90.00%\nsrc/parse.rs 80.00%");
        let arm = functionality(&r, &cross, false);
        assert_eq!(arm.state, ArmState::Inconclusive);
        assert!(
            arm.reasons
                .iter()
                .any(|x| x.contains("requires the benign-input differential")),
            "{:?}",
            arm.reasons
        );
        // Nothing ran.
        let arm = functionality(&Runs::new(), ORIGIN_PATCH, false);
        assert_eq!(arm.state, ArmState::NotRun);
        // The configured command wins over the agent's.
        let l = layout();
        let mut r = Runs::new();
        r.add(l.in_copy("baseline", "make check"), true, "ok");
        r.add(l.in_copy("patched", "make check"), false, "FAIL");
        let arm = functionality_arm(
            &Log(&r.0),
            &l,
            &recheck(serde_json::json!({"functionality": {"suite": {"command": SUITE}}})),
            &parse_patch(ORIGIN_PATCH),
            &FunctionalityConfig {
                test_command: Some("make check".into()),
                coverage_command: None,
            },
        );
        assert_eq!(arm.state, ArmState::Fail);
    }

    #[test]
    fn locality_is_computed_from_the_diff() {
        let one = parse_patch(ORIGIN_PATCH);
        assert_eq!(one.locality(), Locality::Localized);
        assert_eq!(one.files, ["src/header.rs"]);
        assert!(one.touches("src/header.rs", 12));
        assert!(one.touches("b/src/header.rs", 14));
        assert!(!one.touches("src/header.rs", 15));
        assert!(!one.touches("src/parse.rs", 12));
        // Two hunks in one function of one file.
        let same = parse_patch(
            "--- a/s.c\n+++ b/s.c\n@@ -1,2 +1,3 @@ int f(void)\n x\n@@ -9,2 +10,3 @@ int f(void)\n y\n",
        );
        assert_eq!(same.locality(), Locality::Localized);
        // Two functions, then two files.
        let two = parse_patch(
            "--- a/s.c\n+++ b/s.c\n@@ -1,2 +1,3 @@ int f(void)\n x\n@@ -9,2 +10,3 @@ int g(void)\n y\n",
        );
        assert_eq!(two.locality(), Locality::CrossCutting);
        let files = parse_patch(&format!("{ORIGIN_PATCH}{SINK_PATCH}"));
        assert_eq!(files.locality(), Locality::CrossCutting);
        // A new file, a test file and a manifest.
        let new = parse_patch(
            "--- /dev/null\n+++ b/tests/new_test.rs\n@@ -0,0 +1,2 @@\n+a\n--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -3 +3,2 @@\n x\n",
        );
        assert_eq!(new.files, ["tests/new_test.rs", "Cargo.toml"]);
        assert_eq!(new.test_files(), ["tests/new_test.rs"]);
        assert_eq!(new.dependency_manifests(), ["Cargo.toml"]);
        assert!(one.test_files().is_empty());
    }

    #[test]
    fn the_class_report_lists_open_sites_whose_quote_is_in_the_file() {
        let target = tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("src")).unwrap();
        std::fs::write(
            target.path().join("src/a.rs"),
            "fn a() {\n    buf[len] = 0;\n}\n",
        )
        .unwrap();
        let rc = recheck(serde_json::json!({"class_sites": [
            {"file": "src/a.rs", "line": 2, "quote": "buf[len] = 0;"},
            {"file": "src/a.rs", "line": 9, "quote": "not in the file"},
            {"file": "src/missing.rs", "line": 1, "quote": "x"},
            {"file": "../outside.rs", "line": 1, "quote": "x"},
            {"file": "src/a.rs", "line": 1, "quote": "fn a() {", "guarded": true}
        ]}));
        let report = class_report(&rc, target.path());
        assert!(report.listed);
        assert_eq!(report.count, 1);
        assert_eq!(report.locations[0].file, "src/a.rs");
        assert_eq!(report.unverified.len(), 3);
        assert_eq!(report.basis, Basis::ModelJudged);
        // No listing is not an empty class.
        let none = class_report(&Ok(None), target.path());
        assert!(!none.listed);
        assert_eq!(none.count, 0);
    }

    #[test]
    fn fixes_are_counted_by_arm_outcome() {
        let arms = [
            ArmResult::new("variant", ArmState::Fail, Some(Basis::Executed), Vec::new()),
            ArmResult::new("variant", ArmState::Fail, Some(Basis::Executed), Vec::new()),
            ArmResult::new("variant", ArmState::NotRun, None, Vec::new()),
            ArmResult::new("relocation", ArmState::Inconclusive, None, Vec::new()),
        ];
        let counts = count_by_arm(&arms);
        assert_eq!(counts["variant"]["fail"], 2);
        assert_eq!(counts["variant"]["not_run"], 1);
        assert_eq!(counts["relocation"]["inconclusive"], 1);
    }
}
