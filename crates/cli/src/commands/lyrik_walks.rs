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
pub fn stage_walk_skills(
    walks: &[String],
    walks_source_dir: &Path,
    run_dir: &Path,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
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
        let wrapped = wrap_with_wirken_frontmatter(name, run_id, scoring, exec_available, &body);
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
pub fn wrap_with_wirken_frontmatter(
    walk_name: &str,
    run_id: &str,
    scoring: Option<&str>,
    exec_available: bool,
    source: &str,
) -> String {
    let (orig_description, body) = strip_leading_frontmatter(source);
    let description =
        orig_description.unwrap_or_else(|| format!("Per-walk Lyrik dispatch: {walk_name}"));
    let mut section = format!(
        "{}\n{}\n{}\n{}",
        run_section(walk_name, exec_available),
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

/// The commands a walk's text has it run through `exec`, as the
/// command words an operator will be asked about. Listed in the staged
/// walk and printed before a run starts, so what will be asked is
/// known before the first prompt. A walk not listed here runs none.
pub fn walk_exec_commands(walk_name: &str) -> &'static [&'static str] {
    match walk_name {
        "crypto-walk" => &["cargo audit"],
        "fuzz-walk" => &["cargo test"],
        "sink-walk" => &["git log", "git blame"],
        "fix" => super::lyrik_fix::FIX_EXEC_COMMANDS,
        _ => &[],
    }
}

/// The binaries `commands` need, by their first word, deduplicated in
/// first-seen order: `["git log", "git blame", "cargo test"]` needs
/// `git` and `cargo`.
pub fn binaries_for(commands: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in commands {
        if let Some(bin) = c.split_whitespace().next()
            && !out.iter().any(|b| b == bin)
        {
            out.push(bin.to_string());
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
fn run_section(walk_name: &str, exec_available: bool) -> String {
    let commands = walk_exec_commands(walk_name);
    let exec_line = if !exec_available {
        "- `exec` is not available in this run: the sandbox is off, so a command \
         would run on the host. A call to it is refused: record the step as skipped \
         and carry on."
            .to_string()
    } else if commands.is_empty() {
        "- This walk runs no commands through `exec`. Any command it tries is put \
         to the operator first, and a refused one is a step skipped."
            .to_string()
    } else {
        format!(
            "- Commands this walk runs through `exec`: {}. The operator is asked \
             before each one runs, and a refused one is a step skipped: record that \
             it was skipped and carry on.",
            commands
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ")
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
         {exec_line}\n"
    )
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
         input that showed it.\n\n\
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
         Write the record so that a reader with only the record can run it.\n"
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
        ] {
            let p = walk_dir.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("create {}", p.display()))?;
        }
    }
    Ok(())
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
         (zero-padded ordinal; one finding per file). Context (if produced): \
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
        let sink = wrap_with_wirken_frontmatter("sink-walk", "r1", None, true, "body\n");
        assert!(sink.contains("`git log`, `git blame`"), "{sink}");
        let doc = wrap_with_wirken_frontmatter("doc-walk", "r1", None, true, "body\n");
        assert!(doc.contains("runs no commands through `exec`"), "{doc}");
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
