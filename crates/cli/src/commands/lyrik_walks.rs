//! Per-walk Lyrik dispatch: parse + validate `walks: [...]` and
//! `max_concurrent_walks` from `.lyrik/config.json`, stage selected
//! walk skills under the run directory with synthesized
//! wirken-shaped frontmatter, and run one agent turn per walk.
//!
//! Concurrency lands in commit 2; this module ships the serial
//! baseline. The one-call slice (no `walks` field) keeps the
//! existing `/lyrik` dispatch path; this module is reached only
//! when the operator opts in via the config field.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Maximum concurrent walks when not specified in config. Tuned to
/// the conservative end of common provider rate limits; operators
/// running on higher tiers can raise it. Higher than the total walk
/// count is a no-op.
pub const DEFAULT_MAX_CONCURRENT_WALKS: u32 = 4;

/// Canonical list of walk skill names. Adding a walk: extend the
/// list and ship a SKILL.md for it in the walks directory
/// ([`resolve_walks_dir`]). Names are the directory name under it.
pub const KNOWN_WALKS: &[&str] = &[
    "chain-walk",
    "crypto-walk",
    "differential-walk",
    "doc-walk",
    "fuzz-walk",
    "graph-walk",
    "invariant-walk",
    "sink-walk",
];

/// Parsed `walks:` block from `.lyrik/config.json`. `walks: None`
/// is the one-call slice; callers route to the existing `/lyrik`
/// dispatch. `walks: Some([...])` opts into per-walk dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalksConfig {
    /// Selected walks for this run, in operator-supplied order.
    pub walks: Vec<String>,
    /// Maximum concurrent walks. Always populated; the parser
    /// substitutes [`DEFAULT_MAX_CONCURRENT_WALKS`] when the field
    /// is absent.
    pub max_concurrent_walks: u32,
}

/// `<data_dir>/lyrik.json`, the operator's Lyrik settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSettings {
    /// The walks directory for every target that does not set its own.
    pub walks_dir: Option<String>,
    /// Tool rounds each agent of the defender fix step gets: the model
    /// calls one of them may make before it is stopped. Absent, 60. A
    /// target's `.lyrik/config.json` does not set this.
    pub fix_tool_rounds: Option<u32>,
    /// How many continuation turns a walk gets after a reply that was
    /// cut off at the output token limit. Absent,
    /// [`WALK_CONTINUATIONS_DEFAULT`]; zero means none. A target's
    /// `.lyrik/config.json` does not set this.
    pub walk_continuations: Option<u32>,
    /// How many times a provider request that failed in transport is
    /// sent again during a walk. Absent,
    /// [`TRANSPORT_RETRIES_DEFAULT`]; zero means none.
    pub transport_retries: Option<u32>,
    /// The most a Lyrik run may spend, in USD of recorded cost. When a
    /// run's recorded cost reaches it the run stops. Absent, or zero or
    /// less, there is no ceiling.
    pub run_ceiling_usd: Option<f64>,
}

/// Times a walk's provider request that failed in transport is sent
/// again when the operator sets no count.
pub const TRANSPORT_RETRIES_DEFAULT: u32 = 2;

/// Continuation turns a truncated walk gets when the operator sets no
/// limit.
pub const WALK_CONTINUATIONS_DEFAULT: u32 = 2;

impl OperatorSettings {
    /// The ceiling on a run's recorded cost, when the operator set one.
    pub fn run_ceiling_usd(&self) -> Option<f64> {
        self.run_ceiling_usd.filter(|c| *c > 0.0)
    }

    /// Times a walk's request that failed in transport is sent again:
    /// the operator's, else the default.
    pub fn transport_retries(&self) -> u32 {
        self.transport_retries.unwrap_or(TRANSPORT_RETRIES_DEFAULT)
    }

    /// The cap on a truncated walk's continuation turns: the
    /// operator's, else the default.
    pub fn walk_continuations(&self) -> u32 {
        self.walk_continuations
            .unwrap_or(WALK_CONTINUATIONS_DEFAULT)
    }

    /// The fix step's round limit: the operator's, else the default.
    /// Zero is read as the default.
    pub fn fix_tool_rounds(&self) -> usize {
        match self.fix_tool_rounds {
            Some(n) if n > 0 => n as usize,
            _ => super::lyrik_fix::FIX_TOOL_ROUNDS_DEFAULT,
        }
    }
}

pub fn operator_settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join("lyrik.json")
}

pub fn load_operator_settings(data_dir: &Path) -> Result<OperatorSettings> {
    let path = operator_settings_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(OperatorSettings::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// The walks directory when nothing sets one: `<data_dir>/lyrik/walks`.
pub fn default_walks_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("lyrik").join("walks")
}

/// Refuse a target's `.lyrik/config.json` that sets `walks_dir`. A
/// target is input that may try to steer the run, and a directory it
/// chose would let its own text be staged as a walk; where walks come
/// from is the operator's setting alone.
pub fn refuse_target_walks_dir(config: &serde_json::Value, data_dir: &Path) -> Result<()> {
    if config.get("walks_dir").is_some() {
        anyhow::bail!(
            "config.walks_dir is not accepted: a target does not choose where walks come from. \
             Remove it from .lyrik/config.json; the operator sets `walks_dir` in {}",
            operator_settings_path(data_dir).display()
        );
    }
    Ok(())
}

/// The walks directory: where operator-installed walk skills live, one
/// `<walks_dir>/<walk-name>/SKILL.md` each. The runner reads them and
/// never writes them; a run stages its own wrapped copy.
///
/// `walks_dir` in the operator's `<data_dir>/lyrik.json`, a relative
/// path resolved against the data directory and a leading `~/` the
/// home directory, else [`default_walks_dir`]. A target's config that
/// sets `walks_dir` is refused ([`refuse_target_walks_dir`]).
pub fn resolve_walks_dir(config: &serde_json::Value, data_dir: &Path) -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    resolve_walks_dir_with_home(config, data_dir, home.as_deref())
}

fn resolve_walks_dir_with_home(
    config: &serde_json::Value,
    data_dir: &Path,
    home: Option<&Path>,
) -> Result<PathBuf> {
    refuse_target_walks_dir(config, data_dir)?;
    if let Some(raw) = load_operator_settings(data_dir)?.walks_dir {
        let path = operator_settings_path(data_dir);
        if raw.trim().is_empty() {
            anyhow::bail!("walks_dir in {} is empty", path.display());
        }
        return expand_walks_dir(&raw, data_dir, home)
            .with_context(|| format!("walks_dir in {}", path.display()));
    }
    Ok(default_walks_dir(data_dir))
}

fn expand_walks_dir(raw: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let rest = if raw == "~" {
        Some("")
    } else {
        raw.strip_prefix("~/")
    };
    if let Some(rest) = rest {
        let home = home
            .ok_or_else(|| anyhow::anyhow!("{raw} starts with ~ and no home directory is set"))?;
        return Ok(home.join(rest));
    }
    let path = Path::new(raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}

/// Parse and validate the `walks:` block.
///
/// Returns `Ok(None)` when the field is absent (one-call slice).
/// Returns `Err` for any of:
///
/// - empty `walks: []` array (likely-typo guard; the way to skip
///   Lyrik is don't run it),
/// - unknown walk name,
/// - missing `<walks_source_dir>/<walk-name>/SKILL.md`, where
///   `walks_source_dir` is the walks directory ([`resolve_walks_dir`]).
///
/// `max_concurrent_walks` defaults to
/// [`DEFAULT_MAX_CONCURRENT_WALKS`] when absent. Values of 0 are
/// rejected; values above the selected walk count are clamped (a
/// cap above the list is a no-op).
pub fn parse_walks_config(
    config: &serde_json::Value,
    walks_source_dir: &Path,
) -> Result<Option<WalksConfig>> {
    let walks_value = match config.get("walks") {
        Some(v) => v,
        None => return Ok(None),
    };

    let arr = walks_value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("config.walks must be an array of walk names"))?;

    if arr.is_empty() {
        anyhow::bail!(
            "config.walks is an empty array; remove the field to keep the one-call slice or list \
             walks like [\"sink-walk\", \"chain-walk\"]"
        );
    }

    let mut walks = Vec::with_capacity(arr.len());
    for v in arr {
        let name = v
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("config.walks entries must be strings"))?;
        if !KNOWN_WALKS.contains(&name) {
            anyhow::bail!(
                "config.walks contains unknown walk `{name}`; known walks: {known}",
                known = KNOWN_WALKS.join(", ")
            );
        }
        let skill_md = walks_source_dir.join(name).join("SKILL.md");
        if !skill_md.is_file() {
            anyhow::bail!(
                "walk `{name}` is not installed in the walks directory {}: there is no \
                 {name}/SKILL.md in it. Install the walk there, or set `walks_dir` to the \
                 directory that holds it",
                walks_source_dir.display()
            );
        }
        walks.push(name.to_string());
    }

    let max_concurrent_walks = match config.get("max_concurrent_walks") {
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("config.max_concurrent_walks must be an integer"))?;
            if n == 0 {
                anyhow::bail!(
                    "config.max_concurrent_walks must be >= 1; omit the field to use the default \
                     ({DEFAULT_MAX_CONCURRENT_WALKS})"
                );
            }
            u32::try_from(n).unwrap_or(DEFAULT_MAX_CONCURRENT_WALKS)
        }
        None => DEFAULT_MAX_CONCURRENT_WALKS,
    };

    Ok(Some(WalksConfig {
        walks,
        max_concurrent_walks,
    }))
}

/// Stage each selected walk's `SKILL.md` into the per-run staging
/// directory under a wirken-shaped frontmatter. Operators install
/// walk skills as plain SKILL.md files with `name:` and
/// `description:` frontmatter and no permissions block; the wirken Agent's SkillLoader requires a permissions
/// block, so we wrap each walk at run time rather than asking
/// operators to maintain two copies.
///
/// Returns the staged directory path. Pass it to
/// [`wirken_agent::Agent::extend_skills`] alongside the existing
/// `<data_dir>/skills/` load so the slash interceptor finds
/// `/<walk-name>` as a first-class skill.
#[cfg(test)]
pub fn stage_walk_skills(
    walks: &[String],
    walks_source_dir: &Path,
    run_dir: &Path,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
) -> Result<PathBuf> {
    stage_walk_skills_for(
        walks,
        walks_source_dir,
        run_dir,
        run_id,
        scoring,
        exec_available,
        &TargetProfile::default(),
    )
}

/// [`stage_walk_skills`] with the commands each walk is offered taken
/// from the target, as [`TargetProfile::detect`] read it.
pub fn stage_walk_skills_for(
    walks: &[String],
    walks_source_dir: &Path,
    run_dir: &Path,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
    profile: &TargetProfile,
) -> Result<PathBuf> {
    let staged = run_dir.join("walks-skills");
    std::fs::create_dir_all(&staged).with_context(|| format!("create {}", staged.display()))?;
    for name in walks {
        let src = walks_source_dir.join(name).join("SKILL.md");
        let body =
            std::fs::read_to_string(&src).with_context(|| format!("read {}", src.display()))?;
        let dest_dir = staged.join(name);
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("create {}", dest_dir.display()))?;
        let dest = dest_dir.join("SKILL.md");
        let wrapped = wrap_for_target(name, run_id, scoring, exec_available, profile, &body);
        std::fs::write(&dest, wrapped).with_context(|| format!("write {}", dest.display()))?;
        wirken_agent::bundled_skills::stage_sign_skill_dir(&dest_dir)
            .with_context(|| format!("sign staged walk skill at {}", dest_dir.display()))?;
    }
    Ok(staged)
}

/// Wrap an operator-installed walk SKILL.md body with a
/// wirken-compatible frontmatter so the Agent's SkillLoader
/// accepts it. The wrapped permissions match the staged Lyrik
/// skill's posture: read the workspace, write only under the run's
/// own directory ([`run_write_scope`]), deny network, allow any
/// inference provider. Walks do not need anything broader.
///
/// Strips an existing leading `---` frontmatter block from the
/// source (`name:` / `description:`) and writes a
/// fresh one. The original description is preserved when present
/// so the slash interceptor still surfaces a useful one-liner.
///
/// Ahead of the body goes [`run_section`], which tells the model
/// where a run's writes go. The `write_paths` above is what makes
/// that true; the section is so the walk does not spend its turn on
/// writes the gate refuses. `scoring`, the team rubric and project
/// context when the run has them, follows the run section.
#[cfg(test)]
pub fn wrap_with_wirken_frontmatter(
    walk_name: &str,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
    source: &str,
) -> String {
    wrap_for_target(
        walk_name,
        run_id,
        scoring,
        exec_available,
        &TargetProfile::default(),
        source,
    )
}

/// [`wrap_with_wirken_frontmatter`] with the run section's commands
/// taken from the target.
pub fn wrap_for_target(
    walk_name: &str,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
    profile: &TargetProfile,
    source: &str,
) -> String {
    let (orig_description, body) = strip_leading_frontmatter(source);
    let description =
        orig_description.unwrap_or_else(|| format!("Per-walk Lyrik dispatch: {walk_name}"));
    let mut section = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        run_section(walk_name, exec_available, profile),
        staging_section(walk_name),
        finding_section(),
        brocard_section(walk_name),
        step_section(walk_name),
        reproduction_section(walk_name)
    );
    if let Some(scoring) = scoring {
        section.push('\n');
        section.push_str(scoring);
    }
    let tools = run_tools(exec_available);
    let write_scope = run_write_scope(run_id);
    format!(
        "---\nname: {walk_name}\ndescription: {description}\ndisable-model-invocation: true\npermissions:\n  tools:\n    allow: [{tools}]\n  egress:\n    mode: deny\n  filesystem:\n    read_paths: [\"<workspace>\"]\n    write_paths: [\"{write_scope}\"]\n  inference:\n    allow: [\"*\"]\n---\n\n{section}\n{body}"
    )
}

/// The tools a run's staged skills grant. `exec` only when the sandbox
/// is on: with it off, an approved command (`cargo test` running the
/// target's `build.rs`, say) would run on the host with the host's
/// network.
pub fn run_tools(exec_available: bool) -> &'static str {
    if exec_available {
        "exec, read_file, write_file, list_files"
    } else {
        "read_file, write_file, list_files"
    }
}

/// The one directory a run's agents may write: the run's own
/// directory under `.lyrik/state/runs/`. The team-owned files beside
/// it (`.lyrik/rubric.md`, `.lyrik/context.md`, `.lyrik/config.json`)
/// and every earlier run's state are outside it. `run_id` is checked
/// by the runner before staging, so it carries no `..` component and
/// nothing that needs quoting.
pub fn run_write_scope(run_id: &str) -> String {
    format!("<workspace>/.lyrik/state/runs/{run_id}")
}

/// What a run reads off the target to decide which commands its walks
/// are offered: the languages at its root, its test command, and
/// whether it is a git repository. Nothing here is fixed in advance: a
/// shell project is not offered `cargo test`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TargetProfile {
    /// `rust`, `node`, `go`, `python`, `shell`, by the files at the
    /// target's root.
    pub languages: Vec<&'static str>,
    /// `fix.test_command` from the target's configuration when set,
    /// else the usual one for the first language that has one.
    pub test_command: Option<String>,
    pub git: bool,
}

impl TargetProfile {
    /// Read the target's root. `configured_test` is `fix.test_command`
    /// as the run read it at start.
    pub fn detect(target: &Path, configured_test: Option<&str>) -> Self {
        let has = |name: &str| target.join(name).exists();
        let root_has_ext = |ext: &str| {
            std::fs::read_dir(target).is_ok_and(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .any(|e| e.path().extension().is_some_and(|x| x == ext))
            })
        };
        let mut languages = Vec::new();
        if has("Cargo.toml") {
            languages.push("rust");
        }
        if has("package.json") {
            languages.push("node");
        }
        if has("go.mod") {
            languages.push("go");
        }
        if has("pyproject.toml") || has("setup.py") || has("requirements.txt") || root_has_ext("py")
        {
            languages.push("python");
        }
        if root_has_ext("sh") {
            languages.push("shell");
        }
        let usual = languages.iter().find_map(|l| match *l {
            "rust" => Some("cargo test"),
            "node" => Some("npm test"),
            "go" => Some("go test ./..."),
            "python" => Some("python3 -m pytest"),
            _ => None,
        });
        Self {
            test_command: configured_test
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or(usual)
                .map(str::to_string),
            git: has(".git"),
            languages,
        }
    }

    /// The interpreters a harness script may be run with: `sh` always,
    /// and the target's own where it is a scripting language.
    pub fn harness_interpreters(&self) -> Vec<&'static str> {
        let mut out = vec!["sh"];
        if self.languages.contains(&"python") {
            out.push("python3");
        }
        if self.languages.contains(&"node") {
            out.push("node");
        }
        out
    }
}

/// The commands a walk is expected to ask for through `exec`, derived
/// from the target, as an operator will see them. Listed in the staged
/// walk and printed before a run starts, so what will be asked is
/// known before the first prompt. Every walk may also ask to run the
/// scripts it wrote under its own harness directory; that entry is
/// [`harness_command`]. The list is not a grant: each command is still
/// put to the operator when it is about to run.
pub fn walk_commands(walk_name: &str, profile: &TargetProfile) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match walk_name {
        "fix" => {
            return super::lyrik_fix::FIX_EXEC_COMMANDS
                .iter()
                .map(|c| c.to_string())
                .collect();
        }
        "sink-walk" if profile.git => {
            out.push("git log".into());
            out.push("git blame".into());
        }
        "crypto-walk" if profile.languages.contains(&"rust") => out.push("cargo audit".into()),
        "fuzz-walk" | "invariant-walk" => out.extend(profile.test_command.clone()),
        _ => {}
    }
    out.push(harness_command(walk_name, profile));
    out
}

/// How a walk runs a script it wrote: an interpreter and a path under
/// the walk's own harness directory.
pub fn harness_command(walk_name: &str, profile: &TargetProfile) -> String {
    format!(
        "{} .lyrik/state/runs/<run-id>/staging/{walk_name}/harness/<script>",
        profile.harness_interpreters().join("|")
    )
}

/// The binaries `commands` need, by their first word, deduplicated in
/// first-seen order: `["git log", "git blame", "cargo test"]` needs
/// `git` and `cargo`.
pub fn binaries_for<S: AsRef<str>>(commands: &[S]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in commands {
        // `sh|python3 <path>` names each interpreter a harness may use.
        let first = c.as_ref().split_whitespace().next().unwrap_or_default();
        for bin in first.split('|').filter(|b| !b.is_empty()) {
            if !out.iter().any(|b| b == bin) {
                out.push(bin.to_string());
            }
        }
    }
    out
}

/// What the run says about the `exec` sandbox before the first prompt.
/// `missing` is the binaries the sandbox lacks, or `None` when it could
/// not be asked. Nothing to say when everything is there.
pub fn sandbox_banner(where_exec_runs: &str, missing: Option<&[String]>) -> Option<String> {
    match missing {
        Some([]) => None,
        Some(missing) => Some(format!(
            "  {where_exec_runs} has no {}: an approved command that needs it will fail. \
             Set `image` in sandbox.json to one that has it.",
            missing.join(" or ")
        )),
        None => Some(format!(
            "  {where_exec_runs} could not be checked for the commands below; an approved \
             command may fail there."
        )),
    }
}

/// The rules a walk runs under inside `wirken lyrik run`, placed ahead
/// of the operator's walk text. They take precedence over a location
/// the walk text names, such as a harness in the project's test tree.
fn run_section(walk_name: &str, exec_available: bool, profile: &TargetProfile) -> String {
    let exec_lines = if !exec_available {
        "- `exec` is not available in this run: the sandbox is off, so a command \
         would run on the host. A call to it is refused: record the step as skipped \
         and carry on."
            .to_string()
    } else {
        let commands = walk_commands(walk_name, profile);
        let interpreters = profile.harness_interpreters();
        format!(
            "- Commands this walk is expected to ask for through `exec`: {}. The operator \
             is asked before each one runs and may refuse any; a refused one is a step \
             skipped: record that it was skipped and carry on. The list is what is \
             expected, not a limit: a command outside it is put to the operator the same \
             way.\n\
             - You may ask to run a script you wrote under \
             `.lyrik/state/runs/<run-id>/staging/{walk_name}/harness/`, from the project \
             root, with {}: for example \
             `{} .lyrik/state/runs/<run-id>/staging/{walk_name}/harness/<name>`. This is \
             how a finding is shown to hold. Write the harness with `write_file`, ask to \
             run it, and write the reproduction record described under Reproductions; \
             the harness follows the contract given there. After this walk returns, a \
             replay runs the same command. A finding with no executed reproduction is \
             not confirmed, and a defender-mode fix is made only for a confirmed \
             finding, so do not stop at a static trace when a harness can be run.\n\
             - This turn has at most {} tool rounds. Put independent tool calls in one \
             round, and reach the harness run and its record before the rounds run out.",
            commands
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", "),
            interpreters
                .iter()
                .map(|i| format!("`{i}`"))
                .collect::<Vec<_>>()
                .join(" or "),
            interpreters[0],
            wirken_agent::runtime::MAX_TOOL_ROUNDS,
        )
    };
    format!(
        "## Under `wirken lyrik run`\n\n\
         These rules take precedence over any location named below.\n\n\
         - Everything this walk writes goes under \
         `.lyrik/state/runs/<run-id>/staging/{walk_name}/`, with the run-id from the \
         dispatch prompt. A write anywhere else is refused.\n\
         - A harness or test this walk would place in the project's test tree goes \
         under `.lyrik/state/runs/<run-id>/staging/{walk_name}/harness/` instead. \
         Promoting it into the test tree is an operator step after the run.\n\
         {exec_lines}\n"
    )
}

/// How a walk's results reach the runner: one record per finding,
/// written when the finding is established, and a short final reply.
/// The runner builds `findings.json` from the staged records and from
/// nothing in the reply, so a reply that is cut off loses only what
/// was not yet written.
fn staging_section(walk_name: &str) -> String {
    format!(
        "## Results are staged as you go\n\n\
         - Write each finding to its own `finding-NNN.json` under \
         `.lyrik/state/runs/<run-id>/staging/{walk_name}/findings/` as soon as it is \
         established, before you move on to the next area. Do not collect findings to \
         write at the end: the runner reads the staged files and nothing else, and a \
         reply that reaches the output limit keeps only what is already written.\n\
         - The final reply is a summary of a few lines: how many findings you staged, \
         what you skipped and why. Do not repeat a finding's text in it.\n\
         - If a reply of yours is cut off, the runner tells you which records it \
         kept and asks you to continue. Carry on from there; do not rewrite a record \
         that is already staged.\n\
         - To use another walk's output, read \
         `.lyrik/state/runs/<run-id>/staging/index.json` first. It lists every staged \
         record of every walk with its walk, id, title, file, line, tier and path. \
         Then read only the records you need, by the path the index gives. Do not \
         list or read another walk's directory wholesale.\n\
         - If `.lyrik/state/runs/<run-id>/staging/{walk_name}/ledger.json` exists, read \
         it before you start. It holds what earlier runs established about this \
         project. `area` has the full records for the files this run covers; `index` \
         has one line (`id`, `key`, `evidence`, `stale`) for every other record, and \
         you read one of those whole at `.lyrik/ledger/<id>.json` when you need it. A \
         record with `evidence: observed` and no `stale` mark was shown by an executed \
         run against the file as it is now: it is settled. A record with `evidence: \
         reasoned` was read from the source only: use it as a lead, and re-examine it \
         if your work depends on it. A stale record is about an older version of the \
         file and settles nothing.\n\
         - Register a claim before you work on it. Before you write a harness, run a \
         check or stage a finding for a defect, write \
         `.lyrik/state/runs/<run-id>/staging/{walk_name}/claims/claim-NNN.json` with \
         `{{\"class\": \"<class>\", \"file\": \"<file>\", \"line\": <line>}}`, the class, \
         file and line the finding would carry. In your next step read \
         `claims/claim-NNN.decision.json`; if it is not there yet, read it again. \
         `registered` means go on; the answer also carries the ledger records for \
         that file. `refused` means an earlier run already observed a defect at that \
         place, whatever class you gave it: do no work on it, write no harness and no \
         finding for it, and note the record it names in your summary. The answer \
         quotes that record's claim. Only if yours is a different defect at the same \
         place, register again as a new claim file with two more fields, \
         `\"differs_from\": \"<record id>\"` and `\"how\": \"<one sentence on how it \
         differs>\"`; that is accepted and recorded. A finding staged at a refused \
         place without that is refused again when the run's results are put together.\n"
    )
}

/// The fields the runner needs on every staged finding, whatever shape
/// the walk text gives its own. The walk's other fields ride along.
fn finding_section() -> String {
    "## Finding format\n\n\
     Each `finding-NNN.json` is one JSON object. Whatever other fields this walk's text \
     asks for, it carries these, which the runner and `findings.json` are keyed on:\n\n\
     - `framing`: a list of one or more classes, each a lower-case name such as \
     `auth`, `injection`, `memory_safety`, `unbounded_alloc`, `race_condition`. A finding \
     of any class is kept; name the class the finding is, not the nearest familiar one.\n\
     - `location`: `{\"file\", \"line_start\"}`, the file relative to the project root and \
     the 1-based line where the finding surfaces.\n\
     - `stable_id`: `<framing>::<file>:<line>`, built from the first `framing` and \
     `location`, for example `injection::src/run.sh:12`. Use this same string wherever \
     a rejection or a reproduction record names the finding.\n\
     - `id`: any non-empty string unique in this walk; the `stable_id` will do.\n\
     - `title` and `summary`: non-empty strings.\n\
     - `tier`: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.\n"
        .to_string()
}

/// Brocard rules a walk applies, in rule order. Rules 1, 2 and 6 apply
/// to every walk. Rule 3 draws on the graph and invariant walks, rule 4
/// on the crypto and sink walks, rule 5 on the doc walk. Rule 7 is
/// structural and has no walk text.
pub fn brocard_rules_for(walk_name: &str) -> Vec<u8> {
    let mut rules = vec![1, 2, 6];
    match walk_name {
        "graph-walk" | "invariant-walk" => rules.push(3),
        "crypto-walk" | "sink-walk" => rules.push(4),
        "doc-walk" => rules.push(5),
        _ => {}
    }
    rules.sort_unstable();
    rules
}

/// Source page per brocard rule, indexed by `rule - 1`. The rule text
/// is written in this repo's words; the pages are the reference.
const BROCARD_SOURCES: [&str; 8] = [
    "https://vulnbrocards.com/brocards/vb001-no-vuln-report-without-threat-model/",
    "https://vulnbrocards.com/brocards/vb002-no-exploit-from-heavens/",
    "https://vulnbrocards.com/brocards/vb003-no-vuln-outside-of-usage/",
    "https://vulnbrocards.com/brocards/vb004-no-vuln-from-standard-behavior/",
    "https://vulnbrocards.com/brocards/vb005-no-vuln-from-documented-behavior/",
    "https://vulnbrocards.com/brocards/vb006-no-cure-worse-than-disease/",
    "https://vulnbrocards.com/brocards/vb007-report-neither-necessary-nor-sufficient/",
    "docs/lyrik-brocards.md, rule 8, this repository",
];

/// One rule's walk instruction, in this repo's words.
fn brocard_instruction(rule: u8) -> &'static str {
    match rule {
        1 => {
            "Every finding carries a `threat_model` object with two non-blank strings, \
              `attacker_capability` and `harm_path`. The runner rejects a finding that \
              lacks either. If the stated model is present but incoherent, record rule 1 \
              yourself."
        }
        2 => {
            "Compare `attacker_capability` with the impact. If the stated precondition \
              already grants the impact, the finding is not an exploit: record rule 2."
        }
        3 => {
            "If the sink is reached only through callers that bound the input, record \
              rule 3. A precondition violation belongs to the caller, not the API. An \
              upstream advisory whose vulnerable surface is unreachable here is not a \
              re-finding."
        }
        4 => {
            "If the behavior is what the relevant specification permits, record rule 4. \
              An implementation stricter than its spec that fails its own strictness \
              still stands."
        }
        5 => {
            "If the project documents the behavior and its security implication, record \
              rule 5, unless the downstream usage you can read ignores that documentation. \
              In that case the finding moves to that usage."
        }
        6 => {
            "If remediating the finding costs more than the harm it prevents, record \
              rule 6 and say what the cost is. A ReDoS in a context the caller can cancel \
              locally is the reference case."
        }
        _ => "",
    }
}

/// The brocard section of a staged walk: its rules, the threat-model
/// field every finding carries, and where a rejection goes.
fn brocard_section(walk_name: &str) -> String {
    let mut out = String::from(
        "## Brocard rules\n\n\
         Every finding you emit carries a `threat_model` object: \
         `attacker_capability` and `harm_path`, both non-blank strings. \
         A finding without both is a rule 1 rejection. Every finding also carries \
         `invariant`: one sentence naming the property the code must hold that this \
         finding shows violated. A defender-mode fix targets that property, not the \
         input that showed it. Where you traced it, a finding carries `origin`: \
         `{\"file\", \"line_start\", \"function\"}`, the code where the violation starts \
         (where the bad value or state is produced), which is often not `location`, \
         where it surfaces. Give the same site for both when they are one. Leave \
         `origin` out when you have not traced it: a fix is compared against it, and a \
         guessed origin misdirects the fix.\n\n\
         A candidate that fails one of the rules below is still written as a \
         finding. Also record the rejection: write a file to \
         `staging/<walk>/rejections/rejection-NNN.json` (zero-padded ordinal) with \
         `{\"rule\": <number>, \"stable_id\": \"<the finding's stable_id>\", \
         \"reason\": \"<one sentence>\"}`. The runner grades a rejected finding \
         down in pentest mode and removes it in defender mode. A rejection file that \
         does not parse, or names a rule outside 1 to 7, is refused and recorded as \
         such.\n\n\
         Rules that apply to this walk:\n\n",
    );
    for rule in brocard_rules_for(walk_name) {
        let idx = usize::from(rule - 1);
        out.push_str(&format!(
            "- Rule {rule} (source: {}): {}\n",
            BROCARD_SOURCES[idx],
            brocard_instruction(rule)
        ));
    }
    out
}

/// The step-record rules a walk runs under. Each numbered step of the
/// walk text ends by writing a record, and the next step begins by
/// reading it. The runner checks the chain and the revision, so a
/// step cannot hand the next one a summary in place of the record.
fn step_section(walk_name: &str) -> String {
    format!(
        "## Step records\n\n\
         Each numbered step in the walk text below ends with one `write_file` call: \
         `.lyrik/state/runs/<run-id>/staging/{walk_name}/steps/step-NN.json`, with NN the \
         step's two-digit ordinal, one file per step. The file is a JSON object with \
         these fields, all required:\n\n\
         - `step`: the step's name in the walk text.\n\
         - `claim`: one falsifiable sentence the step established.\n\
         - `code_revision`: the revision the dispatch prompt names, copied exactly.\n\
         - `check`: the check the step ran: the command, or the file and line range read.\n\
         - `evidence`: a non-empty list of strings, each a quoted line with its `file:line` \
         or the output of the command. Raw, not paraphrased.\n\
         - `open_questions`: what the step could not settle; an empty list when nothing is \
         open.\n\
         - `prior`: the file name of the record read before this step began. The first \
         record has no `prior`.\n\n\
         Before a step starts, read the previous step's record with `read_file` and work \
         from its `claim`, `check` and `evidence`. Do not work from your memory of the \
         step. A record that does not parse, leaves a field blank, has no evidence, names \
         the wrong `prior`, or carries a revision the run did not scan is refused and \
         recorded as such; the walk continues, but that step left no record.\n"
    )
}

/// The reproduction rules a walk runs under. A command that demonstrates
/// a finding leaves a record the runner replays in a fresh context; the
/// replay's disagreement is brocard rule 8 against the finding.
fn reproduction_section(walk_name: &str) -> String {
    format!(
        "## Reproductions\n\n\
         When a step runs a command through `exec` to show that a finding holds, or that \
         it does not, write one record for it: \
         `.lyrik/state/runs/<run-id>/staging/{walk_name}/reproductions/repro-NNN.json`, \
         zero-padded three-digit ordinal, one file per command run. The fields, all \
         required unless noted:\n\n\
         - `stable_id`: the finding the command bears on.\n\
         - `command`: the command exactly as run.\n\
         - `harness`: the harness or input file the command uses, as a path under the \
         run's staging directory. Optional.\n\
         - `expected`: what the command shows when the finding holds.\n\
         - `observed`: what it showed: the output line, exit status or diagnostic, \
         quoted.\n\
         - `outcome`: `reproduced` or `not_reproduced`.\n\
         - `code_revision`: the revision the dispatch prompt names.\n\n\
         After this walk returns, the runner starts a separate agent for each record. It \
         sees the record and nothing else of this walk, runs the same command, and writes \
         what it observed beside yours. A replay that observes the other outcome is a \
         rule 8 rejection of the finding the record names, applied by the runner; a \
         replay that could not run the command is recorded and is not a disagreement. \
         Write the record so that a reader with only the record can run it.\n\n\
         A command that shows a finding follows one contract, so that a later fix can be \
         checked from the command's exit status and output alone. It prints `{reached}` on \
         a line of its own on stdout, flushed, immediately before its assertion, and that \
         line reaches the command's output (a test runner that hides a passing test's output \
         needs its flag to show it). It exits non-zero when the finding holds and zero when it does \
         not. It runs from the project root and keeps every file of its own (inputs, \
         markers, scratch output) under this walk's `harness/` directory, named by its \
         path from the project root, or in a temporary directory it makes. A defender-mode \
         fix runs the same command in copies of the project that carry this walk's \
         `harness/` directory at the same path and nothing else of the run's state, so a \
         harness that reads or writes elsewhere under `.lyrik/` behaves differently \
         there. A failed build or a missing dependency never reaches the line, and is read \
         as neither. A command outside the contract still gets its record and its replay; \
         a defender-mode fix for its finding cannot be checked and stays inconclusive.\n",
        reached = super::lyrik_fix_arms::REACHED
    )
}

/// Pull the `description:` line out of a leading `---` frontmatter
/// block (if any) and return the remainder as the body. Used to
/// preserve a meaningful description on the staged skill so
/// `/<walk-name>` keeps the operator-facing context that the
/// upstream walk SKILL.md carried.
fn strip_leading_frontmatter(source: &str) -> (Option<String>, &str) {
    let trimmed = source.trim_start_matches('\u{feff}');
    if !trimmed.starts_with("---") {
        return (None, trimmed);
    }
    #[allow(clippy::string_slice, reason = "the text starts with ASCII \"---\"")]
    let after_open = &trimmed[3..];
    // The frontmatter terminator is `\n---` followed by newline or end.
    let close_idx = match after_open.find("\n---") {
        Some(i) => i,
        None => return (None, trimmed),
    };
    #[allow(
        clippy::string_slice,
        reason = "close_idx is from find(\"\\n---\"), an ASCII pattern of 4 bytes"
    )]
    let block = &after_open[..close_idx];
    #[allow(
        clippy::string_slice,
        reason = "close_idx is from find(\"\\n---\"), an ASCII pattern of 4 bytes"
    )]
    let after_close = &after_open[close_idx + 4..];
    let body_start = after_close.trim_start_matches('\n');

    let mut description = None;
    for line in block.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("description:") {
            description = Some(rest.trim().to_string());
            break;
        }
    }
    (description, body_start)
}

/// Build the per-walk staging subtree under
/// `<run-dir>/staging/<walk-name>/{context,rubric,findings}/`.
/// Idempotent. The Lyrik runner aggregates walk-emitted artifacts
/// from these directories after the agent turns return.
pub fn ensure_walk_staging(run_dir: &Path, walks: &[String]) -> Result<()> {
    for w in walks {
        let walk_dir = run_dir.join("staging").join(w);
        for sub in &[
            "context",
            "rubric",
            "findings",
            "rejections",
            "steps",
            "reproductions",
            "replays",
            "claims",
        ] {
            let p = walk_dir.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("create {}", p.display()))?;
        }
    }
    Ok(())
}

/// One staged record as the index lists it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct IndexEntry {
    pub walk: String,
    /// `finding` or `rejection`.
    pub kind: &'static str,
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// The record's path, relative to the target's root.
    pub path: String,
}

/// The staged records of every walk of a run: each walk's
/// `findings/*.json` and `rejections/*.json`, in walk and file order.
/// A file that does not parse is listed with an empty title, so a
/// reader can still see it is there.
pub fn staged_index(run_dir: &Path, run_rel: &str) -> Vec<IndexEntry> {
    let staging = run_dir.join("staging");
    let mut walks: Vec<String> = std::fs::read_dir(&staging)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    walks.sort();
    let mut out = Vec::new();
    for walk in walks {
        for (kind, sub) in [("finding", "findings"), ("rejection", "rejections")] {
            let dir = staging.join(&walk).join(sub);
            let mut files: Vec<String> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| n.ends_with(".json"))
                .collect();
            files.sort();
            for name in files {
                let parsed: serde_json::Value = std::fs::read_to_string(dir.join(&name))
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(serde_json::Value::Null);
                let text = |k: &str| parsed.get(k).and_then(|v| v.as_str()).map(str::to_string);
                out.push(IndexEntry {
                    walk: walk.clone(),
                    kind,
                    id: text("stable_id")
                        .or_else(|| text("id"))
                        .unwrap_or_else(|| name.clone()),
                    title: text("title").unwrap_or_default(),
                    file: parsed
                        .pointer("/location/file")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    line: parsed
                        .pointer("/location/line_start")
                        .and_then(|v| v.as_u64()),
                    tier: text("tier"),
                    path: format!("{run_rel}/staging/{walk}/{sub}/{name}"),
                });
            }
        }
    }
    out
}

/// Write `staging/index.json` for a run. Written whole to a temporary
/// file and renamed, so a walk reading it never sees half of it.
pub fn write_staged_index(run_dir: &Path, run_rel: &str) -> Result<usize> {
    let entries = staged_index(run_dir, run_rel);
    let staging = run_dir.join("staging");
    std::fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;
    let tmp = staging.join(format!("index.json.{}.tmp", uuid::Uuid::new_v4()));
    let dest = staging.join("index.json");
    std::fs::write(&tmp, serde_json::to_string_pretty(&entries)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &dest).with_context(|| format!("write {}", dest.display()))?;
    Ok(entries.len())
}

/// The ids of the findings a walk has staged, in file order.
pub fn staged_finding_ids(run_dir: &Path, run_rel: &str, walk_name: &str) -> Vec<String> {
    staged_index(run_dir, run_rel)
        .into_iter()
        .filter(|e| e.walk == walk_name && e.kind == "finding")
        .map(|e| e.id)
        .collect()
}

/// What a walk is sent after a reply that was cut off at the output
/// limit: what the runner kept, and to carry on.
pub fn continuation_prompt(walk_name: &str, run_id: &str, kept: &[String]) -> String {
    let held = if kept.is_empty() {
        "No finding is staged yet.".to_string()
    } else {
        format!(
            "{} finding(s) are staged and kept: {}. Do not rewrite them.",
            kept.len(),
            kept.iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "Your last reply for {walk_name} was cut off at the output token limit, so \
         nothing in it reached the runner. {held} Continue the walk from where you \
         stopped. Write each further finding to \
         `.lyrik/state/runs/{run_id}/staging/{walk_name}/findings/` as its own record \
         the moment it is established, and keep what you say between tool calls \
         short. End with a summary of a few lines."
    )
}

/// How one turn of a walk ended.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnEnd {
    pub response_len: usize,
    /// Each refused call, as `tool (approval key)`.
    pub skipped: Vec<String>,
    /// The final reply's stop reason, as the audit row names it.
    pub stop_reason: Option<String>,
}

/// Why a turn did not end.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnFailure {
    pub reason: String,
    /// Set when the turn was stopped at the tool round limit: the
    /// limit it reached.
    pub tool_rounds: Option<usize>,
    /// Each call refused before the turn failed, as `tool (approval
    /// key)`.
    pub skipped: Vec<String>,
}

/// What a walk's turns came to.
#[derive(Debug, Clone, PartialEq)]
pub struct WalkTurns {
    /// The last turn's result, or why a turn failed.
    pub last: std::result::Result<TurnEnd, TurnFailure>,
    /// Refused calls across every turn.
    pub skipped: Vec<String>,
    /// One entry per reply that was cut off at the output limit: how
    /// many findings were staged, and so kept, at that point.
    pub truncations: Vec<usize>,
    /// Continuation turns sent.
    pub continuations: u32,
    /// Findings staged when the walk stopped.
    pub findings_staged: usize,
}

/// One walk's conversation, as the turn driver uses it.
pub trait WalkSession {
    /// Run one turn with `prompt` and say how it ended, or why it
    /// failed.
    fn send(
        &mut self,
        prompt: String,
    ) -> impl std::future::Future<Output = std::result::Result<TurnEnd, TurnFailure>> + Send;
}

/// Run a walk: send the first prompt and, while a reply ends at the
/// output token limit and the cap allows, send a continuation that
/// names what is staged. `session` runs one turn in the walk's own
/// conversation; `staged` returns the ids of the findings the walk has
/// staged so far, and is called after every turn, so the index a
/// continuation reads is current. A turn that fails ends the walk; what
/// it staged before failing is still counted, because the runner
/// aggregates staged records whatever the last reply was.
pub async fn drive_walk_turns(
    walk_name: &str,
    run_id: &str,
    first_prompt: String,
    cap: u32,
    session: &mut (impl WalkSession + Send),
    mut staged: impl FnMut() -> Vec<String> + Send,
) -> WalkTurns {
    let mut prompt = first_prompt;
    let mut skipped = Vec::new();
    let mut truncations = Vec::new();
    let mut continuations = 0;
    loop {
        let end = session.send(prompt).await;
        let kept = staged();
        let end = match end {
            Ok(end) => end,
            Err(failure) => {
                skipped.extend(failure.skipped.iter().cloned());
                return WalkTurns {
                    last: Err(failure),
                    skipped,
                    truncations,
                    continuations,
                    findings_staged: kept.len(),
                };
            }
        };
        skipped.extend(end.skipped.iter().cloned());
        let cut_off = end.stop_reason.as_deref() == Some("max_tokens");
        if cut_off {
            truncations.push(kept.len());
        }
        if !cut_off || continuations >= cap {
            return WalkTurns {
                last: Ok(end),
                skipped,
                truncations,
                continuations,
                findings_staged: kept.len(),
            };
        }
        continuations += 1;
        prompt = continuation_prompt(walk_name, run_id, &kept);
    }
}

/// Synthesize the per-walk dispatch prompt. The slash interceptor
/// rewrites `/<walk-name> ...` to prepend the staged walk body, so
/// the runner only needs to supply the run-id, the staging path,
/// and the workspace pointer. Walks read the rest from the staged
/// SKILL.md body.
pub fn build_walk_prompt(
    walk_name: &str,
    run_id: &str,
    code_revision: Option<&str>,
    seed_protocol_suffix: &str,
) -> String {
    let revision = match code_revision {
        Some(sha) => format!("Code revision: `{sha}`; every step record carries it."),
        None => "Code revision: unknown, the target is not a git checkout; step records \
                 carry `unknown`."
            .to_string(),
    };
    format!(
        "/{walk_name} Run {walk_name} on this workspace. Run-id: `{run_id}`. {revision} \
         Emission is staged. Findings: write each finding to \
         `.lyrik/state/runs/{run_id}/staging/{walk_name}/findings/finding-NNN.json` \
         (zero-padded ordinal; one finding per file) as soon as it is established, \
         not at the end. Your final reply is a short summary; the runner reads the \
         staged files, not the reply. Context (if produced): \
         `.lyrik/state/runs/{run_id}/staging/{walk_name}/context/<NN>-<section>.md`. \
         Rubric (if produced): `.lyrik/state/runs/{run_id}/staging/{walk_name}/rubric/<NN>-<tier>.md`. \
         Do not write `findings.json` directly; the Lyrik runner aggregates \
         per-walk staging into the canonical findings.json after every walk \
         turn returns.{seed_protocol_suffix}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn install_walk_fixture(dir: &Path, name: &str, body: &str) {
        let walk_dir = dir.join(name);
        std::fs::create_dir_all(&walk_dir).unwrap();
        std::fs::write(walk_dir.join("SKILL.md"), body).unwrap();
    }

    fn minimal_walk_body(name: &str) -> String {
        format!("---\nname: {name}\ndescription: stub for tests\n---\n\n# {name}\n\nbody.\n")
    }

    /// The fix step's round limit is the operator's: `lyrik.json` in
    /// the data directory sets it, and nothing in a target does.
    #[test]
    fn fix_tool_rounds_come_from_the_data_directory_only() {
        let data = tempfile::tempdir().unwrap();
        assert_eq!(
            load_operator_settings(data.path())
                .unwrap()
                .fix_tool_rounds(),
            super::super::lyrik_fix::FIX_TOOL_ROUNDS_DEFAULT
        );
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"fix_tool_rounds": 90}"#,
        )
        .unwrap();
        assert_eq!(
            load_operator_settings(data.path())
                .unwrap()
                .fix_tool_rounds(),
            90
        );
        // Zero is not a limit an agent can work under: the default.
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"fix_tool_rounds": 0}"#,
        )
        .unwrap();
        assert_eq!(
            load_operator_settings(data.path())
                .unwrap()
                .fix_tool_rounds(),
            super::super::lyrik_fix::FIX_TOOL_ROUNDS_DEFAULT
        );
        // A target's .lyrik/config.json is never where it is read from:
        // the loader takes the data directory and nothing else.
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join(".lyrik")).unwrap();
        std::fs::write(
            target.path().join(".lyrik/config.json"),
            r#"{"fix_tool_rounds": 500, "fix": {"tool_rounds": 500}}"#,
        )
        .unwrap();
        std::fs::remove_file(operator_settings_path(data.path())).unwrap();
        assert_eq!(
            load_operator_settings(data.path())
                .unwrap()
                .fix_tool_rounds(),
            super::super::lyrik_fix::FIX_TOOL_ROUNDS_DEFAULT
        );
    }

    /// A scripted walk: each turn stages the findings it is given and
    /// ends with the stop reason it is given. Records every prompt.
    struct Scripted {
        findings_dir: PathBuf,
        turns: Vec<(
            Vec<&'static str>,
            std::result::Result<&'static str, &'static str>,
        )>,
        prompts: Vec<String>,
    }

    impl WalkSession for Scripted {
        async fn send(&mut self, prompt: String) -> std::result::Result<TurnEnd, TurnFailure> {
            self.prompts.push(prompt);
            let (stage, end) = self.turns.remove(0);
            for name in stage {
                let id = format!("auth::src/{name}.rs:1");
                std::fs::write(
                    self.findings_dir.join(format!("finding-{name}.json")),
                    serde_json::json!({
                        "stable_id": id, "title": format!("finding {name}"), "tier": "LOW",
                        "framing": ["auth"],
                        "location": {"file": format!("src/{name}.rs"), "line_start": 1}
                    })
                    .to_string(),
                )
                .unwrap();
            }
            match end {
                Ok(stop) => Ok(TurnEnd {
                    response_len: 10,
                    skipped: vec!["exec (shell:sh)".to_string()],
                    stop_reason: Some(stop.to_string()),
                }),
                Err(why) => Err(TurnFailure {
                    reason: why.to_string(),
                    tool_rounds: (why == "round limit").then_some(20),
                    skipped: vec!["exec (shell:sh)".to_string()],
                }),
            }
        }
    }

    const RUN_REL: &str = ".lyrik/state/runs/r1";

    fn scripted(
        tmp: &Path,
        turns: Vec<(
            Vec<&'static str>,
            std::result::Result<&'static str, &'static str>,
        )>,
    ) -> (PathBuf, Scripted) {
        let run_dir = tmp.join(RUN_REL);
        ensure_walk_staging(&run_dir, &["sink-walk".to_string()]).unwrap();
        let findings_dir = run_dir.join("staging/sink-walk/findings");
        (
            run_dir,
            Scripted {
                findings_dir,
                turns,
                prompts: Vec::new(),
            },
        )
    }

    async fn drive(run_dir: &Path, session: &mut Scripted, cap: u32) -> WalkTurns {
        drive_walk_turns(
            "sink-walk",
            "r1",
            "first prompt".to_string(),
            cap,
            session,
            || {
                write_staged_index(run_dir, RUN_REL).unwrap();
                staged_finding_ids(run_dir, RUN_REL, "sink-walk")
            },
        )
        .await
    }

    /// A reply cut off at the output limit does not end the walk: what
    /// is staged is kept and counted, the walk is marked truncated, and
    /// a continuation turn names the kept records. The second turn's
    /// finding is added to the first's.
    #[tokio::test]
    async fn a_truncated_walk_keeps_what_is_staged_and_resumes() {
        let tmp = tempdir().unwrap();
        let (run_dir, mut session) = scripted(
            tmp.path(),
            vec![(vec!["a"], Ok("max_tokens")), (vec!["b"], Ok("end_turn"))],
        );
        let out = drive(&run_dir, &mut session, 2).await;
        assert_eq!(out.truncations, vec![1], "one finding was kept at the cut");
        assert_eq!(out.continuations, 1);
        assert_eq!(out.findings_staged, 2);
        assert_eq!(
            out.last.as_ref().unwrap().stop_reason.as_deref(),
            Some("end_turn")
        );
        assert_eq!(out.skipped.len(), 2, "refused calls of both turns");
        assert_eq!(session.prompts.len(), 2);
        assert_eq!(session.prompts[0], "first prompt");
        let resume = &session.prompts[1];
        assert!(
            resume.contains("cut off at the output token limit"),
            "{resume}"
        );
        assert!(
            resume.contains("1 finding(s) are staged and kept"),
            "{resume}"
        );
        assert!(resume.contains("`auth::src/a.rs:1`"), "{resume}");
        assert!(resume.contains("Do not rewrite them"), "{resume}");
        // The runner builds results from the staged records: both are
        // in the index, with the path to read each by.
        let index: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(run_dir.join("staging/index.json")).unwrap(),
        )
        .unwrap();
        let entries = index.as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["walk"], "sink-walk");
        assert_eq!(entries[0]["kind"], "finding");
        assert_eq!(entries[0]["id"], "auth::src/a.rs:1");
        assert_eq!(entries[0]["file"], "src/a.rs");
        assert_eq!(entries[0]["line"], 1);
        assert_eq!(
            entries[1]["path"],
            ".lyrik/state/runs/r1/staging/sink-walk/findings/finding-b.json"
        );
    }

    /// The operator's cap bounds the continuations. At the cap the walk
    /// stops truncated, with what it staged still counted; with a cap
    /// of zero no continuation is sent at all.
    #[tokio::test]
    async fn continuations_stop_at_the_operator_cap() {
        let tmp = tempdir().unwrap();
        let (run_dir, mut session) = scripted(
            tmp.path(),
            vec![
                (vec![], Ok("max_tokens")),
                (vec!["a"], Ok("max_tokens")),
                (vec!["b"], Ok("max_tokens")),
                (vec!["never"], Ok("end_turn")),
            ],
        );
        let out = drive(&run_dir, &mut session, 2).await;
        assert_eq!(out.continuations, 2);
        assert_eq!(out.truncations, vec![0, 1, 2]);
        assert_eq!(out.findings_staged, 2);
        assert_eq!(session.prompts.len(), 3, "the fourth turn was never sent");
        assert!(session.prompts[1].contains("No finding is staged yet"));

        let tmp = tempdir().unwrap();
        let (run_dir, mut session) = scripted(
            tmp.path(),
            vec![(vec!["a"], Ok("max_tokens")), (vec!["b"], Ok("end_turn"))],
        );
        let out = drive(&run_dir, &mut session, 0).await;
        assert_eq!(out.continuations, 0);
        assert_eq!(out.truncations, vec![1]);
        assert_eq!(out.findings_staged, 1);
        assert_eq!(session.prompts.len(), 1);
    }

    /// A turn that fails ends the walk, and what it staged before
    /// failing is still counted. A reply that ends normally gets no
    /// continuation.
    #[tokio::test]
    async fn a_failed_turn_keeps_its_staged_findings() {
        let tmp = tempdir().unwrap();
        let (run_dir, mut session) = scripted(
            tmp.path(),
            vec![
                (vec!["a"], Ok("max_tokens")),
                (vec!["b"], Err("http error")),
            ],
        );
        let out = drive(&run_dir, &mut session, 2).await;
        assert_eq!(out.last.as_ref().unwrap_err().reason, "http error");
        assert_eq!(out.last.as_ref().unwrap_err().tool_rounds, None);
        assert_eq!(out.findings_staged, 2);
        assert_eq!(out.truncations, vec![1]);

        // Stopped at the tool round limit: the count is carried, and
        // what was staged is still counted.
        let tmp = tempdir().unwrap();
        let (run_dir, mut session) =
            scripted(tmp.path(), vec![(vec!["a", "b"], Err("round limit"))]);
        let out = drive(&run_dir, &mut session, 2).await;
        assert_eq!(out.last.as_ref().unwrap_err().tool_rounds, Some(20));
        assert_eq!(out.findings_staged, 2);
        assert_eq!(out.skipped, ["exec (shell:sh)"], "refused before it failed");

        let tmp = tempdir().unwrap();
        let (run_dir, mut session) = scripted(tmp.path(), vec![(vec!["a"], Ok("end_turn"))]);
        let out = drive(&run_dir, &mut session, 2).await;
        assert!(out.truncations.is_empty());
        assert_eq!(out.continuations, 0);
        assert_eq!(session.prompts.len(), 1);
    }

    /// The cap on continuations is the operator's: `lyrik.json` in the
    /// data directory sets it, zero is a real setting, and it defaults
    /// to two.
    #[test]
    fn walk_continuations_come_from_the_data_directory() {
        let data = tempfile::tempdir().unwrap();
        let read = || {
            load_operator_settings(data.path())
                .unwrap()
                .walk_continuations()
        };
        assert_eq!(read(), WALK_CONTINUATIONS_DEFAULT);
        assert_eq!(WALK_CONTINUATIONS_DEFAULT, 2);
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"walk_continuations": 5}"#,
        )
        .unwrap();
        assert_eq!(read(), 5);
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"walk_continuations": 0}"#,
        )
        .unwrap();
        assert_eq!(read(), 0);
        // No ceiling unless the operator sets one; zero is none.
        let ceiling = || {
            load_operator_settings(data.path())
                .unwrap()
                .run_ceiling_usd()
        };
        std::fs::write(operator_settings_path(data.path()), "{}").unwrap();
        assert_eq!(ceiling(), None);
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"run_ceiling_usd": 12.5}"#,
        )
        .unwrap();
        assert_eq!(ceiling(), Some(12.5));
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"run_ceiling_usd": 0}"#,
        )
        .unwrap();
        assert_eq!(ceiling(), None);
        // Transport retries: two unless the operator says otherwise.
        let retries = || {
            load_operator_settings(data.path())
                .unwrap()
                .transport_retries()
        };
        assert_eq!(retries(), 2);
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"transport_retries": 4}"#,
        )
        .unwrap();
        assert_eq!(retries(), 4);
        std::fs::write(
            operator_settings_path(data.path()),
            r#"{"transport_retries": 0}"#,
        )
        .unwrap();
        assert_eq!(retries(), 0);
    }

    /// The staged copy of a walk tells it to write each finding as it
    /// goes, to keep the final reply short, to read another walk's
    /// output through the index, and what the ledger file means. The
    /// installed walk text is not changed: these lines are in the
    /// section the runner adds.
    #[test]
    fn the_staged_walk_is_told_to_stage_as_it_goes_and_read_the_index_first() {
        let source = minimal_walk_body("chain-walk");
        let staged = wrap_with_wirken_frontmatter("chain-walk", "r1", None, true, &source);
        for needle in [
            "as soon as it is established",
            "The final reply is a summary of a few lines",
            ".lyrik/state/runs/<run-id>/staging/index.json` first",
            "read only the records you need",
            ".lyrik/state/runs/<run-id>/staging/chain-walk/ledger.json",
            "you read one of those whole at `.lyrik/ledger/<id>.json`",
            "Register a claim before you work on it",
            "staging/chain-walk/claims/claim-NNN.json",
            "{\"class\": \"<class>\", \"file\": \"<file>\", \"line\": <line>}",
            "`refused` means an earlier run already observed a defect at that place, whatever class",
            "\"differs_from\": \"<record id>\"",
        ] {
            assert!(staged.contains(needle), "{needle}");
        }
        assert!(
            staged.ends_with("# chain-walk\n\nbody.\n"),
            "the walk's own text follows"
        );
        assert!(!source.contains("index.json"));
        let prompt = build_walk_prompt("chain-walk", "r1", None, "");
        assert!(prompt.contains("as soon as it is established"));
        assert!(prompt.contains("the runner reads the staged files, not the reply"));
    }

    #[test]
    fn parse_walks_config_returns_none_when_field_absent() {
        let cfg = serde_json::json!({"phases": {}});
        let tmp = tempdir().unwrap();
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_walks_config_rejects_empty_array() {
        let cfg = serde_json::json!({"walks": []});
        let tmp = tempdir().unwrap();
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("empty array"));
    }

    #[test]
    fn parse_walks_config_rejects_unknown_walk() {
        let cfg = serde_json::json!({"walks": ["typo-walk"]});
        let tmp = tempdir().unwrap();
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unknown walk"));
    }

    #[test]
    fn parse_walks_config_rejects_missing_skill_file() {
        let cfg = serde_json::json!({"walks": ["sink-walk"]});
        let tmp = tempdir().unwrap();
        let walks_dir = tmp.path().join("configured-walks");
        let err = parse_walks_config(&cfg, &walks_dir)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!(
                "walk `sink-walk` is not installed in the walks directory {}",
                walks_dir.display()
            )),
            "the error names the configured directory: {err}"
        );
        assert!(err.contains("sink-walk/SKILL.md"), "{err}");
        assert!(!err.contains("~/"), "no hard-coded path: {err}");
    }

    #[test]
    fn the_walks_directory_defaults_under_the_data_dir() {
        let tmp = tempdir().unwrap();
        let data = tmp.path().join("data");
        let got = resolve_walks_dir_with_home(&serde_json::json!({}), &data, None).unwrap();
        assert_eq!(got, data.join("lyrik").join("walks"));
        assert_eq!(got, default_walks_dir(&data));
    }

    #[test]
    fn the_operator_setting_overrides_the_default() {
        let tmp = tempdir().unwrap();
        let (data, home) = (tmp.path().join("data"), tmp.path().join("home"));
        std::fs::create_dir_all(&data).unwrap();
        let cfg = serde_json::json!({});
        for (setting, want) in [
            ("/srv/walks", PathBuf::from("/srv/walks")),
            ("~/walks", home.join("walks")),
            ("walks", data.join("walks")),
        ] {
            std::fs::write(
                operator_settings_path(&data),
                serde_json::json!({ "walks_dir": setting }).to_string(),
            )
            .unwrap();
            let got = resolve_walks_dir_with_home(&cfg, &data, Some(&home)).unwrap();
            assert_eq!(got, want, "{setting}");
        }

        std::fs::write(operator_settings_path(&data), r#"{"walks_dir": "~/walks"}"#).unwrap();
        assert!(resolve_walks_dir_with_home(&cfg, &data, None).is_err());
        std::fs::write(operator_settings_path(&data), r#"{"walks_dir": " "}"#).unwrap();
        assert!(resolve_walks_dir_with_home(&cfg, &data, Some(&home)).is_err());
        std::fs::write(operator_settings_path(&data), r#"{"walk_dir": "/x"}"#).unwrap();
        let err = resolve_walks_dir_with_home(&cfg, &data, Some(&home)).unwrap_err();
        assert!(format!("{err:#}").contains("lyrik.json"), "{err:#}");
    }

    #[test]
    fn a_target_config_that_sets_walks_dir_is_refused() {
        let tmp = tempdir().unwrap();
        let (data, home) = (tmp.path().join("data"), tmp.path().join("home"));
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            operator_settings_path(&data),
            r#"{"walks_dir": "/srv/walks"}"#,
        )
        .unwrap();
        for value in [
            serde_json::json!(".lyrik/walks"),
            serde_json::json!("/opt/walks"),
            serde_json::json!(""),
            serde_json::json!(null),
        ] {
            let cfg = serde_json::json!({ "walks_dir": value, "walks": ["sink-walk"] });
            let err = resolve_walks_dir_with_home(&cfg, &data, Some(&home))
                .unwrap_err()
                .to_string();
            assert!(err.contains("config.walks_dir is not accepted"), "{err}");
            assert!(
                err.contains(&operator_settings_path(&data).display().to_string()),
                "names where the operator sets it: {err}"
            );
            assert!(refuse_target_walks_dir(&cfg, &data).is_err());
        }
        assert!(refuse_target_walks_dir(&serde_json::json!({"walks": []}), &data).is_ok());
    }

    #[test]
    fn a_walk_installed_in_the_resolved_directory_is_found() {
        let tmp = tempdir().unwrap();
        let data = tmp.path().join("data");
        let walks_dir = resolve_walks_dir_with_home(&serde_json::json!({}), &data, None).unwrap();
        install_walk_fixture(&walks_dir, "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({"walks": ["sink-walk"]});
        let got = parse_walks_config(&cfg, &walks_dir).unwrap().unwrap();
        assert_eq!(got.walks, vec!["sink-walk".to_string()]);
    }

    #[test]
    fn parse_walks_config_accepts_known_installed_walk() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({"walks": ["sink-walk"]});
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap().unwrap();
        assert_eq!(parsed.walks, vec!["sink-walk"]);
        assert_eq!(parsed.max_concurrent_walks, DEFAULT_MAX_CONCURRENT_WALKS);
    }

    #[test]
    fn parse_walks_config_honors_max_concurrent_override() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({
            "walks": ["sink-walk"],
            "max_concurrent_walks": 8
        });
        let parsed = parse_walks_config(&cfg, tmp.path()).unwrap().unwrap();
        assert_eq!(parsed.max_concurrent_walks, 8);
    }

    #[test]
    fn parse_walks_config_rejects_zero_concurrency() {
        let tmp = tempdir().unwrap();
        install_walk_fixture(tmp.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        let cfg = serde_json::json!({
            "walks": ["sink-walk"],
            "max_concurrent_walks": 0
        });
        let err = parse_walks_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(">= 1"));
    }

    #[test]
    fn binaries_are_the_first_word_of_each_command_once() {
        assert_eq!(
            binaries_for(&["git log", "git blame", "cargo test"]),
            vec!["git".to_string(), "cargo".to_string()]
        );
        // A harness entry names every interpreter it may run under.
        assert_eq!(
            binaries_for(&["sh|python3 .lyrik/x/harness/<script>", "sh test.sh"]),
            vec!["sh".to_string(), "python3".to_string()]
        );
    }

    fn shell_target() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        for name in ["a.sh", "len.sh", "test.sh"] {
            std::fs::write(tmp.path().join(name), "echo x\n").unwrap();
        }
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        tmp
    }

    #[test]
    fn a_non_rust_target_is_offered_no_cargo_command() {
        let tmp = shell_target();
        let profile = TargetProfile::detect(tmp.path(), None);
        assert_eq!(profile.languages, ["shell"]);
        assert_eq!(profile.test_command, None);
        assert!(profile.git);
        for walk in KNOWN_WALKS {
            let commands = walk_commands(walk, &profile);
            assert!(
                !commands.iter().any(|c| c.contains("cargo")),
                "{walk}: {commands:?}"
            );
            let text = wrap_for_target(walk, "r1", None, true, &profile, "body\n");
            assert!(!text.contains("cargo"), "{walk}: {text}");
        }
        // The fuzz walk has only its own harness to run.
        assert_eq!(
            walk_commands("fuzz-walk", &profile),
            ["sh .lyrik/state/runs/<run-id>/staging/fuzz-walk/harness/<script>"]
        );
        // With the run's configured test command, that is what is offered.
        let configured = TargetProfile::detect(tmp.path(), Some(" sh test.sh "));
        assert_eq!(configured.test_command.as_deref(), Some("sh test.sh"));
        assert_eq!(walk_commands("fuzz-walk", &configured)[0], "sh test.sh");
        assert_eq!(
            walk_commands("invariant-walk", &configured)[0],
            "sh test.sh"
        );
        assert!(!walk_commands("graph-walk", &configured).contains(&"sh test.sh".to_string()));
    }

    #[test]
    fn the_commands_offered_follow_the_target() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();
        let rust = TargetProfile::detect(tmp.path(), None);
        assert_eq!(rust.languages, ["rust"]);
        assert!(!rust.git);
        assert_eq!(walk_commands("fuzz-walk", &rust)[0], "cargo test");
        assert_eq!(walk_commands("crypto-walk", &rust)[0], "cargo audit");
        // Not a git checkout: the sink walk is not offered git.
        assert!(
            !walk_commands("sink-walk", &rust)
                .iter()
                .any(|c| c.starts_with("git"))
        );
        // The configured command wins over the language's usual one.
        let configured = TargetProfile::detect(tmp.path(), Some("make check"));
        assert_eq!(walk_commands("fuzz-walk", &configured)[0], "make check");
        // Python and Node targets, and their interpreters for a harness.
        std::fs::remove_file(tmp.path().join("Cargo.toml")).unwrap();
        std::fs::write(tmp.path().join("pyproject.toml"), "").unwrap();
        let py = TargetProfile::detect(tmp.path(), None);
        assert_eq!(py.test_command.as_deref(), Some("python3 -m pytest"));
        assert_eq!(py.harness_interpreters(), ["sh", "python3"]);
        assert!(harness_command("graph-walk", &py).starts_with("sh|python3 "));
        // Nothing recognised: no test command, a shell harness only.
        let empty = tempdir().unwrap();
        let none = TargetProfile::detect(empty.path(), None);
        assert_eq!(none, TargetProfile::default());
        assert_eq!(walk_commands("fuzz-walk", &none).len(), 1);
    }

    #[test]
    fn every_walk_is_told_it_may_run_its_own_harness_under_the_contract() {
        let tmp = shell_target();
        let profile = TargetProfile::detect(tmp.path(), Some("sh test.sh"));
        for walk in KNOWN_WALKS {
            let text = wrap_for_target(walk, "sample/r1", None, true, &profile, "body\n");
            let harness = format!(".lyrik/state/runs/<run-id>/staging/{walk}/harness/");
            assert!(
                text.contains(&format!(
                    "You may ask to run a script you wrote under `{harness}`"
                )),
                "{walk}: {text}"
            );
            assert!(text.contains("a replay runs the same command"), "{walk}");
            assert!(
                text.contains(super::super::lyrik_fix_arms::REACHED),
                "{walk}"
            );
            assert!(text.contains("at most 20 tool rounds"), "{walk}");
            assert!(text.contains("not a limit"), "{walk}");
            // Asking is still asking: nothing is granted ahead of time,
            // and the write scope is the run directory as before.
            assert!(text.contains("The operator"), "{walk}");
            assert!(
                text.contains("write_paths: [\"<workspace>/.lyrik/state/runs/sample/r1\"]"),
                "{walk}"
            );
            assert!(text.contains("## Finding format"), "{walk}");
            assert!(text.contains("of any class is kept"), "{walk}");
        }
        // With exec unavailable no command is offered at all.
        let off = wrap_for_target("fuzz-walk", "r1", None, false, &profile, "body\n");
        assert!(off.contains("`exec` is not available in this run"), "{off}");
        assert!(!off.contains("You may ask to run a script"), "{off}");
    }

    #[test]
    fn the_banner_names_what_the_sandbox_lacks_and_is_silent_otherwise() {
        let image = "The exec sandbox image `debian:bookworm-slim`";
        let missing = vec!["git".to_string()];
        let line = sandbox_banner(image, Some(&missing)).unwrap();
        assert!(line.contains("`debian:bookworm-slim` has no git"), "{line}");
        assert!(line.contains("sandbox.json"), "{line}");
        assert_eq!(sandbox_banner(image, Some(&[])), None);
        assert!(
            sandbox_banner(image, None)
                .unwrap()
                .contains("could not be checked")
        );
    }

    #[test]
    fn the_staged_walk_lists_the_commands_it_will_ask_for() {
        let git = TargetProfile {
            git: true,
            ..Default::default()
        };
        let sink = wrap_for_target("sink-walk", "r1", None, true, &git, "body\n");
        assert!(sink.contains("`git log`, `git blame`"), "{sink}");
        let doc = wrap_for_target("doc-walk", "r1", None, true, &git, "body\n");
        assert!(
            doc.contains("`sh .lyrik/state/runs/<run-id>/staging/doc-walk/harness/<script>`"),
            "{doc}"
        );
        assert!(!doc.contains("git log"), "{doc}");
    }

    #[test]
    fn wrap_puts_step_records_after_the_brocard_rules_and_names_the_walk_path() {
        let wrapped = wrap_with_wirken_frontmatter("graph-walk", "r1", None, true, "body\n");
        let brocard = wrapped.find("## Brocard rules").unwrap();
        let steps = wrapped.find("## Step records").unwrap();
        let repros = wrapped.find("## Reproductions").unwrap();
        let body = wrapped.find("body\n").unwrap();
        assert!(
            brocard < steps && steps < repros && repros < body,
            "{wrapped}"
        );
        assert!(
            wrapped.contains("staging/graph-walk/reproductions/repro-NNN.json"),
            "{wrapped}"
        );
        assert!(
            wrapped.contains("staging/graph-walk/steps/step-NN.json"),
            "{wrapped}"
        );
        for field in [
            "`step`",
            "`claim`",
            "`code_revision`",
            "`check`",
            "`evidence`",
            "`open_questions`",
            "`prior`",
        ] {
            assert!(wrapped.contains(field), "missing {field}");
        }
    }

    #[test]
    fn wrap_puts_run_rules_ahead_of_the_walk_text() {
        let src = "---\nname: fuzz-walk\ndescription: d\n---\n\nHarnesses live in the project's test tree.\n";
        let wrapped = wrap_with_wirken_frontmatter("fuzz-walk", "r1", None, true, src);
        let rules = wrapped
            .find("## Under `wirken lyrik run`")
            .expect("run rules present");
        let walk = wrapped.find("Harnesses live").expect("walk text kept");
        assert!(rules < walk, "the rules come before the walk text");
        assert!(wrapped.contains(".lyrik/state/runs/<run-id>/staging/fuzz-walk/harness/"));
        // The gate says the same thing the text does.
        assert!(wrapped.contains("write_paths: [\"<workspace>/.lyrik/state/runs/r1\"]"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_strips_existing_block_and_preserves_description() {
        let src = "---\nname: sink-walk\ndescription: existing one\n---\n\n# Sink-Walk\n\nbody.";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", "r1", None, true, src);
        assert!(wrapped.starts_with("---\nname: sink-walk\n"));
        assert!(wrapped.contains("description: existing one"));
        assert!(wrapped.contains("# Sink-Walk"));
        assert!(wrapped.contains("permissions:"));
        assert!(wrapped.contains("write_paths: [\"<workspace>/.lyrik/state/runs/r1\"]"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_supplies_default_description_when_missing() {
        let src = "---\nname: sink-walk\n---\n\n# Sink-Walk\n";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", "r1", None, true, src);
        assert!(wrapped.contains("Per-walk Lyrik dispatch: sink-walk"));
    }

    #[test]
    fn wrap_with_wirken_frontmatter_handles_no_existing_frontmatter() {
        let src = "# Just a body\n";
        let wrapped = wrap_with_wirken_frontmatter("sink-walk", "r1", None, true, src);
        assert!(wrapped.starts_with("---\nname: sink-walk"));
        assert!(wrapped.contains("# Just a body"));
    }

    #[test]
    fn stage_walk_skills_writes_one_file_per_walk() {
        let src = tempdir().unwrap();
        install_walk_fixture(src.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        install_walk_fixture(src.path(), "chain-walk", &minimal_walk_body("chain-walk"));
        let run = tempdir().unwrap();
        let staged = stage_walk_skills(
            &["sink-walk".to_string(), "chain-walk".to_string()],
            src.path(),
            run.path(),
            "r1",
            None,
            true,
        )
        .unwrap();
        assert!(staged.join("sink-walk/SKILL.md").is_file());
        assert!(staged.join("chain-walk/SKILL.md").is_file());
        let body = std::fs::read_to_string(staged.join("sink-walk/SKILL.md")).unwrap();
        assert!(body.contains("permissions:"));
    }

    /// Each staged walk dir carries a SKILL.sig + SKILL.pub pair that
    /// verifies under the same loader gate the agent runtime applies.
    /// Catches the silent regression where stage_walk_skills stops
    /// calling stage_sign_skill_dir and walks load empty again.
    #[test]
    fn stage_walk_skills_self_signs_each_staged_dir() {
        use wirken_gateway::skill_registry::{
            VerifyResult as SkillVerifyResult, verify_skill_self_signed,
        };

        let src = tempdir().unwrap();
        install_walk_fixture(src.path(), "sink-walk", &minimal_walk_body("sink-walk"));
        install_walk_fixture(src.path(), "chain-walk", &minimal_walk_body("chain-walk"));
        let run = tempdir().unwrap();
        let staged = stage_walk_skills(
            &["sink-walk".to_string(), "chain-walk".to_string()],
            src.path(),
            run.path(),
            "r1",
            None,
            true,
        )
        .unwrap();
        for walk in ["sink-walk", "chain-walk"] {
            let walk_dir = staged.join(walk);
            assert!(
                walk_dir.join("SKILL.sig").exists(),
                "{walk}: SKILL.sig missing"
            );
            assert!(
                walk_dir.join("SKILL.pub").exists(),
                "{walk}: SKILL.pub missing"
            );
            let skill_md =
                wirken_gateway::skill_registry::read_skill_md(&walk_dir.join("SKILL.md")).unwrap();
            let result = verify_skill_self_signed(&walk_dir, &skill_md).unwrap();
            assert!(
                matches!(result, SkillVerifyResult::Valid { .. }),
                "{walk}: signature did not verify: {result:?}"
            );
        }
    }

    #[test]
    fn ensure_walk_staging_creates_subdirs_per_walk() {
        let run = tempdir().unwrap();
        ensure_walk_staging(
            run.path(),
            &["sink-walk".to_string(), "graph-walk".to_string()],
        )
        .unwrap();
        for w in ["sink-walk", "graph-walk"] {
            for sub in [
                "context",
                "rubric",
                "findings",
                "rejections",
                "steps",
                "reproductions",
                "replays",
            ] {
                assert!(
                    run.path().join("staging").join(w).join(sub).is_dir(),
                    "missing {w}/{sub}"
                );
            }
        }
    }

    #[test]
    fn build_walk_prompt_includes_walk_name_run_id_and_staging_path() {
        let p = build_walk_prompt("sink-walk", "sample/run-001", Some("abc123"), "");
        assert!(p.contains("Code revision: `abc123`"), "{p}");
        assert!(p.starts_with("/sink-walk "));
        assert!(p.contains("Run-id: `sample/run-001`"));
        assert!(p.contains("staging/sink-walk/findings/finding-NNN.json"));
    }

    #[test]
    fn build_walk_prompt_appends_seed_protocol_suffix_when_supplied() {
        let suffix = " SEEDS-MARKER";
        let p = build_walk_prompt("sink-walk", "sample/run-001", None, suffix);
        assert!(p.contains("carry `unknown`"), "{p}");
        assert!(p.ends_with(suffix));
    }

    #[test]
    fn brocard_rules_route_by_walk() {
        assert_eq!(brocard_rules_for("doc-walk"), vec![1, 2, 5, 6]);
        assert_eq!(brocard_rules_for("sink-walk"), vec![1, 2, 4, 6]);
        assert_eq!(brocard_rules_for("crypto-walk"), vec![1, 2, 4, 6]);
        assert_eq!(brocard_rules_for("graph-walk"), vec![1, 2, 3, 6]);
        assert_eq!(brocard_rules_for("invariant-walk"), vec![1, 2, 3, 6]);
        assert_eq!(brocard_rules_for("chain-walk"), vec![1, 2, 6]);
    }

    #[test]
    fn brocard_section_names_threat_model_and_routed_rules_only() {
        let doc = brocard_section("doc-walk");
        assert!(doc.contains("`threat_model`"));
        assert!(doc.contains("rejections/rejection-NNN.json"));
        assert!(doc.contains("Rule 5 (source: https://vulnbrocards.com/brocards/vb005"));
        assert!(!doc.contains("Rule 4 (source"));
        let sink = brocard_section("sink-walk");
        assert!(sink.contains("Rule 4 (source: https://vulnbrocards.com/brocards/vb004"));
        assert!(!sink.contains("Rule 5 (source"));
    }

    #[test]
    fn wrapped_walk_carries_brocard_section_before_body() {
        let wrapped = wrap_with_wirken_frontmatter(
            "sink-walk",
            "r1",
            None,
            false,
            "---\ndescription: d\n---\nBODY",
        );
        let at_section = wrapped.find("## Brocard rules").unwrap();
        let at_body = wrapped.find("BODY").unwrap();
        assert!(at_section < at_body);
    }
}
