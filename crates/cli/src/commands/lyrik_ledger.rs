//! The ledger: what earlier runs established about a target.
//!
//! One record per claim, kept under the target's `.lyrik/ledger/` as
//! one JSON file per record. A record says what was claimed, where,
//! at which revision, against which content of the file, whether the
//! claim was observed by an executed run or only reasoned, and which
//! run produced it. Nothing in a record names a model, a provider, a
//! walk or a harness: it is a statement about the target.
//!
//! The runner reads the ledger before a run's walks start and writes
//! it after the run's findings are final. A walk is handed the records
//! for the files it can read. A record with evidence `observed` is
//! settled while its file is unchanged: a staged finding that makes
//! the same claim again is refused with a pointer to the record. A
//! record with evidence `reasoned` is context a walk may re-examine.
//! A record whose file no longer has the content it was established
//! against is `stale`: it is kept, it is marked, and it blocks nothing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// How a claim was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// A command was run and its result is on record.
    Observed,
    /// Read from the source; nothing was run.
    Reasoned,
}

/// What kind of claim a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The defect is there.
    Finding,
    /// A proposed defect was examined and set aside.
    Rejection,
    /// A check of a patch against the defect gave a result.
    ArmResult,
}

/// One established claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Stable for a `(kind, key)` pair; also the file name.
    pub id: String,
    pub kind: Kind,
    /// `<class>::<file>:<line>`, the key a finding is known by.
    pub key: String,
    /// The claim in words.
    pub claim: String,
    /// The file the claim is about, relative to the target's root.
    pub file: String,
    /// The 1-based line the claim surfaces at.
    pub line: u64,
    /// The revision the claim was established at, when the target is
    /// a git checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// SHA-256 of the file's content when the claim was established.
    /// Absent when the file could not be read then; such a record is
    /// never treated as settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    pub evidence: Evidence,
    /// The run that produced the record.
    pub run: String,
    /// The severity tier the run gave a finding, so a later run can
    /// carry the finding with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Set when the file's content is no longer the content the claim
    /// was established against.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

impl Record {
    /// Whether the record stands in the way of the same claim being
    /// checked again: observed, and against the file as it is now.
    pub fn settled(&self) -> bool {
        self.evidence == Evidence::Observed && !self.stale && self.file_sha256.is_some()
    }
}

/// `<target>/.lyrik/ledger`.
pub fn ledger_dir(target: &Path) -> PathBuf {
    target.join(".lyrik").join("ledger")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file under the target, or `None` when it cannot be
/// read or is not inside the target.
pub fn file_sha256(target: &Path, rel: &str) -> Option<String> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    let bytes = std::fs::read(target.join(rel_path)).ok()?;
    Some(hex(&Sha256::digest(&bytes)))
}

/// The id of the record for `(kind, key)`: 16 hex characters.
pub fn record_id(kind: Kind, key: &str) -> String {
    let tag = match kind {
        Kind::Finding => "finding",
        Kind::Rejection => "rejection",
        Kind::ArmResult => "arm_result",
    };
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0]);
    h.update(key.as_bytes());
    hex(&h.finalize()[..8])
}

/// Read every record, marking as stale each one whose file no longer
/// has the content it was established against. A mark that changed is
/// written back, so the ledger on disk says what the next reader will
/// see. A file that is not a record is skipped.
pub fn load(target: &Path) -> Result<Vec<Record>> {
    let dir = ledger_dir(target);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut record) = serde_json::from_str::<Record>(&text) else {
            continue;
        };
        let stale = match &record.file_sha256 {
            Some(was) => file_sha256(target, &record.file).as_ref() != Some(was),
            None => false,
        };
        if stale != record.stale {
            record.stale = stale;
            write_record(&dir, &record)?;
        }
        out.push(record);
    }
    Ok(out)
}

fn write_record(dir: &Path, record: &Record) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", record.id));
    let tmp = dir.join(format!("{}.json.tmp", record.id));
    std::fs::write(&tmp, serde_json::to_string_pretty(record)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("write {}", path.display()))
}

/// Write `records` into the ledger. A record replaces the one with
/// its id, except that a reasoned record never replaces a settled
/// one: what a run observed is not overwritten by what a later run
/// only read. Returns how many records were written.
pub fn upsert(target: &Path, records: &[Record]) -> Result<usize> {
    let existing = load(target)?;
    let dir = ledger_dir(target);
    let mut written = 0;
    for record in records {
        let held = existing.iter().find(|e| e.id == record.id);
        if let Some(held) = held
            && held.settled()
            && record.evidence == Evidence::Reasoned
        {
            continue;
        }
        if held == Some(record) {
            continue;
        }
        write_record(&dir, record)?;
        written += 1;
    }
    Ok(written)
}

/// `(key, file, line)` of a finding-shaped object: its `stable_id`
/// when it has one, else the key built from its first `framing` and
/// its `location`.
pub fn claim_key(finding: &Value) -> Option<(String, String, u64)> {
    let location = finding.get("location")?;
    let file = location.get("file")?.as_str()?.to_string();
    let line = location.get("line_start")?.as_u64()?;
    let key = match finding.get("stable_id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            let class = finding.get("framing")?.as_array()?.first()?.as_str()?;
            format!("{class}::{file}:{line}")
        }
    };
    Some((key, file, line))
}

/// The records a finished run establishes, from its `findings.json`
/// body and its rejection records.
///
/// - A kept finding is a `finding` record: `observed` when a
///   reproduction of it ran and its replay agreed, else `reasoned`.
/// - A rejection is a `rejection` record: `observed` when the replay
///   rule (8) made it, since a command was run and showed otherwise,
///   else `reasoned`.
/// - Each arm of a fix record that passed or failed on an executed run
///   is an `arm_result` record, `observed`. An arm that did not run or
///   was inconclusive establishes nothing and writes none.
pub fn records_from_run(
    target: &Path,
    body: &Value,
    rejections: &[Value],
    run_id: &str,
) -> Vec<Record> {
    let commit = body
        .get("target_sha")
        .and_then(Value::as_str)
        .map(str::to_string);
    let empty = Vec::new();
    let reproductions = body
        .get("reproductions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let observed = |key: &str| {
        reproductions.iter().any(|r| {
            r.get("stable_id").and_then(Value::as_str) == Some(key)
                && r.get("outcome").and_then(Value::as_str) == Some("reproduced")
                && r.get("agreement").and_then(Value::as_bool) == Some(true)
        })
    };
    let record =
        |kind: Kind, key: String, claim: String, file: String, line: u64, ev: Evidence| Record {
            id: record_id(kind, &key),
            kind,
            file_sha256: file_sha256(target, &file),
            key,
            claim,
            file,
            line,
            commit: commit.clone(),
            evidence: ev,
            run: run_id.to_string(),
            tier: None,
            stale: false,
        };
    let mut out: Vec<Record> = Vec::new();
    let findings = body
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for f in findings {
        // A finding this run carried from the ledger is not something
        // this run established.
        if f.get("carried").is_some() {
            continue;
        }
        let Some((key, file, line)) = claim_key(f) else {
            continue;
        };
        let claim = f
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ev = if observed(&key) {
            Evidence::Observed
        } else {
            Evidence::Reasoned
        };
        let mut made = record(Kind::Finding, key, claim, file, line, ev);
        made.tier = f.get("tier").and_then(Value::as_str).map(str::to_string);
        out.push(made);
    }
    for r in rejections {
        let Some((key, file, line)) = claim_key(r) else {
            continue;
        };
        let title = r.get("title").and_then(Value::as_str).unwrap_or_default();
        let reason = r.get("reason").and_then(Value::as_str).unwrap_or_default();
        let ev = if r.get("rule").and_then(Value::as_u64) == Some(8) {
            Evidence::Observed
        } else {
            Evidence::Reasoned
        };
        out.push(record(
            Kind::Rejection,
            key,
            format!("set aside: {title}: {reason}"),
            file,
            line,
            ev,
        ));
    }
    let fixes = body
        .get("fixes")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for fix in fixes {
        let Some(stable_id) = fix.get("stable_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(finding) = findings
            .iter()
            .find(|f| f.get("stable_id").and_then(Value::as_str) == Some(stable_id))
        else {
            continue;
        };
        let Some((_, file, line)) = claim_key(finding) else {
            continue;
        };
        let arms = fix.get("arms").and_then(Value::as_array).unwrap_or(&empty);
        for arm in arms {
            let (Some(name), Some(state)) = (
                arm.get("arm").and_then(Value::as_str),
                arm.get("state").and_then(Value::as_str),
            ) else {
                continue;
            };
            let executed = arm.get("basis").and_then(Value::as_str) == Some("executed");
            if !executed || !matches!(state, "pass" | "fail") {
                continue;
            }
            let verb = if state == "pass" { "passed" } else { "failed" };
            out.push(record(
                Kind::ArmResult,
                format!("{stable_id}#{name}"),
                format!("a patch for this finding {verb} the {name} check"),
                file.clone(),
                line,
                Evidence::Observed,
            ));
        }
    }
    // One record per id: the first stands.
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert(r.id.clone()));
    out
}

/// Whether `path` matches `pattern`, a glob over `/`-separated
/// segments: `*` and `?` stay inside one segment, `**` spans any
/// number of them.
fn glob_matches(pattern: &str, path: &str) -> bool {
    fn segment(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => segment(&p[1..], t) || (!t.is_empty() && segment(p, &t[1..])),
            (Some(b'?'), Some(_)) => segment(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => segment(&p[1..], &t[1..]),
            _ => false,
        }
    }
    fn parts(p: &[&str], t: &[&str]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(&"**") => parts(&p[1..], t) || (!t.is_empty() && parts(p, &t[1..])),
            Some(first) => {
                !t.is_empty()
                    && segment(first.as_bytes(), t[0].as_bytes())
                    && parts(&p[1..], &t[1..])
            }
        }
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let t: Vec<&str> = path.split('/').collect();
    parts(&p, &t)
}

/// The files a run's walks work on, from `scope` in the target's
/// `.lyrik/config.json`: a path is in the area when an `include`
/// pattern matches it and no `exclude` pattern does. With no `include`
/// every file is in the area. A pattern with no `/` matches a file of
/// that name in any directory.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Area {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl Area {
    pub fn from_config(config: &Value) -> Self {
        let list = |key: &str| -> Vec<String> {
            config
                .pointer(&format!("/scope/{key}"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        Area {
            include: list("include"),
            exclude: list("exclude"),
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        let hit = |pattern: &String| {
            glob_matches(pattern, path)
                || (!pattern.contains('/') && glob_matches(&format!("**/{pattern}"), path))
        };
        (self.include.is_empty() || self.include.iter().any(hit)) && !self.exclude.iter().any(hit)
    }
}

/// What a walk is handed before it starts: in `area`, the full records
/// that are not stale for the files of its area; in `index`, one line
/// for every other record (stale ones, and those for files outside the
/// area) with its id, key, evidence and stale mark. A record in the
/// index is read whole from `.lyrik/ledger/<id>.json`.
pub fn for_walk(records: &[Record], area: &Area) -> Value {
    let full: Vec<&Record> = records
        .iter()
        .filter(|r| !r.stale && area.contains(&r.file))
        .collect();
    let index: Vec<Value> = records
        .iter()
        .filter(|r| r.stale || !area.contains(&r.file))
        .map(|r| {
            serde_json::json!({
                "id": r.id, "key": r.key, "evidence": r.evidence, "stale": r.stale,
            })
        })
        .collect();
    serde_json::json!({
        "area": full,
        "index": index,
        "read_a_record_at": ".lyrik/ledger/<id>.json",
    })
}

/// How far apart two lines may be and still be the same place. A
/// walk and an earlier run often name a defect one or two lines apart
/// (the function's first line, or the statement inside it).
pub const LINE_WINDOW: u64 = 2;

/// The settled record at a place, if there is one: observed, against
/// the file as it is now, in the same file within [`LINE_WINDOW`]
/// lines. The class a walk gave the claim is not compared: two names
/// for one defect are one defect. An arm result is about a patch and
/// settles nothing about the code.
pub fn settled_at<'a>(records: &'a [Record], file: &str, line: u64) -> Option<&'a Record> {
    records
        .iter()
        .filter(|r| r.settled() && r.kind != Kind::ArmResult && r.file == file)
        .filter(|r| r.line.abs_diff(line) <= LINE_WINDOW)
        .min_by_key(|r| r.line.abs_diff(line))
}

/// The runner's answer to a claim a walk registered.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimDecision {
    pub walk: String,
    /// The claim file's name, `claim-NNN.json`.
    pub file: String,
    pub key: String,
    /// Where the claim is: the target file and line it named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<(String, u64)>,
    /// `registered`; `refused` when the ledger already settles the
    /// place; `registered_distinct` when the walk named the settled
    /// record and said how its claim differs.
    pub decision: &'static str,
    /// The settled record at the place, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The run that record came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub established_by_run: Option<String>,
    /// The walk's sentence on how its claim differs from the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
}

/// Answer each claim under `<walk_dir>/claims/` that has no answer
/// yet. A claim is `claim-NNN.json` with `class` (or the first of
/// `framing`), `file` and `line` (or a `location`). The answer is
/// written beside it as `claim-NNN.decision.json`.
///
/// A claim at a place the ledger already settles ([`settled_at`]) is
/// `refused`, with the record and its run, whatever class it names.
/// The walk may register again with `differs_from` naming that record
/// and `how`, one sentence on how its claim differs: that is accepted
/// as `registered_distinct` and recorded. Any other claim is
/// `registered`. Every answer carries the full records for the claim's
/// file that are not stale, so registering a claim is also how a walk
/// gets the ledger for the file it is about to work on. A claim that
/// cannot be read is answered `refused` with the reason, so a walk is
/// never left waiting.
pub fn answer_claims(
    walk_dir: &Path,
    walk: &str,
    records: &[Record],
) -> Result<Vec<ClaimDecision>> {
    let dir = walk_dir.join("claims");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.ends_with(".json") && !n.ends_with(".decision.json") && !n.ends_with(".tmp"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let stem = name.trim_end_matches(".json");
        let answer_path = dir.join(format!("{stem}.decision.json"));
        if answer_path.exists() {
            continue;
        }
        let parsed: Option<Value> = std::fs::read_to_string(dir.join(&name))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let claim = parsed.as_ref().and_then(|c| {
            let class = c
                .get("class")
                .and_then(Value::as_str)
                .or_else(|| c.pointer("/framing/0").and_then(Value::as_str))?;
            let file = c
                .get("file")
                .and_then(Value::as_str)
                .or_else(|| c.pointer("/location/file").and_then(Value::as_str))?;
            let line = c
                .get("line")
                .and_then(Value::as_u64)
                .or_else(|| c.pointer("/location/line_start").and_then(Value::as_u64))?;
            Some((format!("{class}::{file}:{line}"), file.to_string(), line))
        });
        let text = |k: &str| {
            parsed
                .as_ref()
                .and_then(|c| c.get(k))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let mut decision = ClaimDecision {
            walk: walk.to_string(),
            file: name.clone(),
            key: String::new(),
            at: None,
            decision: "refused",
            record: None,
            established_by_run: None,
            how: None,
        };
        let body = match claim {
            None => serde_json::json!({
                "decision": "refused",
                "reason": "the claim needs `class`, `file` and `line`",
            }),
            Some((key, file, line)) => {
                let for_file: Vec<&Record> = records
                    .iter()
                    .filter(|r| !r.stale && r.file == file)
                    .collect();
                decision.key = key.clone();
                decision.at = Some((file.clone(), line));
                match settled_at(records, &file, line) {
                    None => {
                        decision.decision = "registered";
                        serde_json::json!({
                            "decision": "registered",
                            "key": key,
                            "records_for_file": for_file,
                        })
                    }
                    Some(held) => {
                        decision.record = Some(held.id.clone());
                        decision.established_by_run = Some(held.run.clone());
                        let names_it = text("differs_from").as_deref() == Some(held.id.as_str());
                        match (names_it, text("how")) {
                            (true, Some(how)) => {
                                decision.decision = "registered_distinct";
                                decision.how = Some(how.clone());
                                serde_json::json!({
                                    "decision": "registered_distinct",
                                    "key": key,
                                    "differs_from": held.id,
                                    "how": how,
                                    "records_for_file": for_file,
                                })
                            }
                            _ => serde_json::json!({
                                "decision": "refused",
                                "key": key,
                                "reason": "an earlier run observed a defect at this place against the \
                                           file as it is now; do not check it again and do not stage a \
                                           finding for it",
                                "record": held.id,
                                "record_key": held.key,
                                "record_claim": held.claim,
                                "record_path": format!(".lyrik/ledger/{}.json", held.id),
                                "established_by_run": held.run,
                                "if_yours_is_a_different_defect":
                                    "register again with `differs_from` set to the record id and \
                                     `how`, one sentence on how your claim differs from it",
                                "records_for_file": for_file,
                            }),
                        }
                    }
                }
            }
        };
        let tmp = dir.join(format!("{stem}.decision.json.tmp"));
        std::fs::write(&tmp, serde_json::to_string_pretty(&body)?)
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &answer_path)
            .with_context(|| format!("write {}", answer_path.display()))?;
        out.push(decision);
    }
    Ok(out)
}

/// A staged finding the runner refused because the ledger already
/// holds an observed claim at its place, against the file as it is
/// now.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Refused {
    pub walk: String,
    /// The staged file's name.
    pub file: String,
    pub key: String,
    /// The ledger record that settles it.
    pub record: String,
    /// The run that record came from.
    pub established_by_run: String,
}

/// Move each staged finding of `walk` at a place the ledger settles
/// out of `findings/` into `ledger-refused/` beside it, so it is not
/// aggregated, and return what was refused. A finding the walk
/// registered as distinct from the settled record (`distinct`, this
/// walk's `registered_distinct` answers) is left in place.
pub fn refuse_duplicates(
    walk_dir: &Path,
    walk: &str,
    records: &[Record],
    distinct: &[ClaimDecision],
) -> Result<Vec<Refused>> {
    let findings = walk_dir.join("findings");
    if !findings.is_dir() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&findings)
        .with_context(|| format!("read {}", findings.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some((key, file, line)) = claim_key(&parsed) else {
            continue;
        };
        let Some(held) = settled_at(records, &file, line) else {
            continue;
        };
        let accepted = distinct.iter().any(|d| {
            d.walk == walk
                && d.decision == "registered_distinct"
                && d.record.as_deref() == Some(held.id.as_str())
                && d.at
                    .as_ref()
                    .is_some_and(|(f, l)| *f == file && l.abs_diff(line) <= LINE_WINDOW)
        });
        if accepted {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let dest_dir = walk_dir.join("ledger-refused");
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("create {}", dest_dir.display()))?;
        std::fs::rename(&path, dest_dir.join(&name))
            .with_context(|| format!("move {}", path.display()))?;
        out.push(Refused {
            walk: walk.to_string(),
            file: name,
            key,
            record: held.id.clone(),
            established_by_run: held.run.clone(),
        });
    }
    Ok(out)
}

/// The settled finding records for the files of a run's area, as
/// findings a run's `findings.json` carries: each is marked `carried`
/// with the record, the run that established it and the revision. A
/// record at a place where this run kept a finding of its own
/// (`kept`, each a file and line) is left out, and so is every stale
/// record: a carried finding says "an earlier run showed this and the
/// file has not changed since".
pub fn carried_findings(records: &[Record], area: &Area, kept: &[(String, u64)]) -> Vec<Value> {
    records
        .iter()
        .filter(|r| r.kind == Kind::Finding && r.settled() && area.contains(&r.file))
        .filter(|r| {
            !kept
                .iter()
                .any(|(f, l)| *f == r.file && l.abs_diff(r.line) <= LINE_WINDOW)
        })
        .map(|r| {
            let class = r.key.split("::").next().unwrap_or("unclassified");
            serde_json::json!({
                "id": r.key,
                "stable_id": r.key,
                "framing": [class],
                "location": { "file": r.file, "line_start": r.line },
                "title": r.claim,
                "summary": format!(
                    "{} Carried from run {}, which observed it by an executed run; the file \
                     has not changed since, so this run did not examine it again.",
                    r.claim, r.run
                ),
                "tier": r.tier.clone().unwrap_or_else(|| "INFO".to_string()),
                "carried": {
                    "from_run": r.run,
                    "record": r.id,
                    "evidence": r.evidence,
                    "commit": r.commit,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn target_with(file: &str, content: &str) -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        tmp
    }

    fn run_body() -> Value {
        json!({
            "target_sha": "abc123",
            "findings": [
                {"stable_id": "auth::src/a.rs:10", "title": "no check before the write",
                 "framing": ["auth"], "location": {"file": "src/a.rs", "line_start": 10}},
                {"stable_id": "injection::src/a.rs:20", "title": "argument reaches a shell",
                 "framing": ["injection"], "location": {"file": "src/a.rs", "line_start": 20}}
            ],
            "reproductions": [
                {"stable_id": "auth::src/a.rs:10", "outcome": "reproduced", "agreement": true}
            ],
            "fixes": [
                {"stable_id": "auth::src/a.rs:10", "arms": [
                    {"arm": "original", "state": "pass", "basis": "executed"},
                    {"arm": "variant", "state": "inconclusive"},
                    {"arm": "relocation", "state": "not_run"}
                ]}
            ]
        })
    }

    fn rejections() -> Vec<Value> {
        vec![
            json!({"stable_id": "auth::src/a.rs:30", "title": "open handler", "reason": "the caller already holds the key",
                   "rule": 2, "location": {"file": "src/a.rs", "line_start": 30}}),
            json!({"stable_id": "auth::src/a.rs:40", "title": "missing bound", "reason": "the replay did not show it",
                   "rule": 8, "location": {"file": "src/a.rs", "line_start": 40}}),
        ]
    }

    /// A run's findings, rejections and arm results each become one
    /// record, with the evidence state the run earned.
    #[test]
    fn a_run_populates_the_ledger_from_findings_rejections_and_arm_results() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        let by_key = |k: &str| records.iter().find(|r| r.key == k).unwrap();
        assert_eq!(records.len(), 5);
        // Reproduced and replayed: observed. Read only: reasoned.
        assert_eq!(by_key("auth::src/a.rs:10").evidence, Evidence::Observed);
        assert_eq!(by_key("auth::src/a.rs:10").kind, Kind::Finding);
        assert_eq!(
            by_key("injection::src/a.rs:20").evidence,
            Evidence::Reasoned
        );
        // A judgment rejection is reasoned; a replay rejection is observed.
        assert_eq!(by_key("auth::src/a.rs:30").evidence, Evidence::Reasoned);
        assert_eq!(by_key("auth::src/a.rs:40").evidence, Evidence::Observed);
        assert_eq!(by_key("auth::src/a.rs:40").kind, Kind::Rejection);
        // Only the arm that ran and gave a result.
        let arm = by_key("auth::src/a.rs:10#original");
        assert_eq!(arm.kind, Kind::ArmResult);
        assert_eq!(arm.evidence, Evidence::Observed);
        assert!(!records.iter().any(|r| r.key.ends_with("#variant")));
        for r in &records {
            assert_eq!(r.commit.as_deref(), Some("abc123"));
            assert_eq!(r.run, "r1");
            assert_eq!(r.file, "src/a.rs");
            assert_eq!(r.file_sha256, file_sha256(tmp.path(), "src/a.rs"));
            assert_eq!(r.id, record_id(r.kind, &r.key));
        }
        assert_eq!(upsert(tmp.path(), &records).unwrap(), 5);
        assert_eq!(load(tmp.path()).unwrap().len(), 5);
        // Writing the same records again changes nothing.
        assert_eq!(upsert(tmp.path(), &records).unwrap(), 0);
    }

    /// A record is plain data about the target: its fields are the
    /// claim, where, at which revision and file content, the evidence
    /// state and the run. No field names a model, a provider, a walk
    /// or a harness.
    #[test]
    fn a_record_carries_no_model_or_harness_field() {
        let tmp = target_with("src/a.rs", "x\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        for r in &records {
            let v = serde_json::to_value(r).unwrap();
            let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            for k in &keys {
                assert!(
                    [
                        "id",
                        "kind",
                        "key",
                        "claim",
                        "file",
                        "line",
                        "commit",
                        "file_sha256",
                        "evidence",
                        "run",
                        "stale",
                        "tier"
                    ]
                    .contains(k),
                    "{k}"
                );
            }
            let text = v.to_string().to_lowercase();
            for word in ["model", "provider", "harness", "walk", "prompt", "token"] {
                assert!(!text.contains(word), "{word} in {text}");
            }
        }
        // An unknown field is not a record.
        let extra = r#"{"id":"x","kind":"finding","key":"k","claim":"c","file":"f","line":1,
                        "evidence":"observed","run":"r","model":"m"}"#;
        assert!(serde_json::from_str::<Record>(extra).is_err());
    }

    fn stage(walk_dir: &Path, name: &str, finding: &Value) {
        let dir = walk_dir.join("findings");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), finding.to_string()).unwrap();
    }

    /// A staged finding that repeats a claim the ledger holds as
    /// observed is refused, with a pointer to the record and the run
    /// it came from. One that repeats a reasoned record is kept.
    #[test]
    fn a_check_that_duplicates_an_observed_record_is_refused_with_a_pointer() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        let ledger = load(tmp.path()).unwrap();

        let walk_dir = tmp.path().join("staging/sink-walk");
        stage(
            &walk_dir,
            "finding-001.json",
            &json!({"stable_id": "auth::src/a.rs:10", "framing": ["auth"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 10}}),
        );
        stage(
            &walk_dir,
            "finding-002.json",
            &json!({"stable_id": "injection::src/a.rs:20", "framing": ["injection"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 20}}),
        );
        stage(
            &walk_dir,
            "finding-003.json",
            &json!({"framing": ["auth"], "title": "the replay-rejected one, no stable_id",
                    "location": {"file": "src/a.rs", "line_start": 40}}),
        );
        stage(
            &walk_dir,
            "finding-004.json",
            &json!({"stable_id": "auth::src/a.rs:99", "framing": ["auth"], "title": "new",
                    "location": {"file": "src/a.rs", "line_start": 99}}),
        );

        let refused = refuse_duplicates(&walk_dir, "sink-walk", &ledger, &[]).unwrap();
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert_eq!(refused[0].file, "finding-001.json");
        assert_eq!(refused[0].key, "auth::src/a.rs:10");
        assert_eq!(
            refused[0].record,
            record_id(Kind::Finding, "auth::src/a.rs:10")
        );
        assert_eq!(refused[0].established_by_run, "r1");
        // The observed rejection settles its claim too.
        assert_eq!(refused[1].file, "finding-003.json");
        assert_eq!(
            refused[1].record,
            record_id(Kind::Rejection, "auth::src/a.rs:40")
        );
        // The refused files left findings/; the reasoned and the new one stayed.
        let left: Vec<String> = std::fs::read_dir(walk_dir.join("findings"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left.len(), 2);
        assert!(left.contains(&"finding-002.json".to_string()));
        assert!(left.contains(&"finding-004.json".to_string()));
        assert!(walk_dir.join("ledger-refused/finding-001.json").is_file());
    }

    fn claim(walk_dir: &Path, name: &str, body: &Value) {
        let dir = walk_dir.join("claims");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body.to_string()).unwrap();
    }

    fn decision(walk_dir: &Path, stem: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(walk_dir.join(format!("claims/{stem}.decision.json")))
                .unwrap(),
        )
        .unwrap()
    }

    /// A walk registers a claim before it works on it. One the ledger
    /// already holds as observed is refused there and then, with the
    /// record and its run; a new one, and one the ledger only reasoned,
    /// are registered. Each answer carries the ledger for the claim's
    /// file. A claim is answered once.
    #[test]
    fn registering_a_settled_claim_is_refused_before_any_work() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        std::fs::write(tmp.path().join("src/b.rs"), "fn b() {}\n").unwrap();
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        let ledger = load(tmp.path()).unwrap();
        let walk_dir = tmp.path().join("staging/fuzz-walk");

        claim(
            &walk_dir,
            "claim-001.json",
            &json!({"class": "auth", "file": "src/a.rs", "line": 10}),
        );
        claim(
            &walk_dir,
            "claim-002.json",
            &json!({"class": "injection", "file": "src/a.rs", "line": 20}),
        );
        claim(
            &walk_dir,
            "claim-003.json",
            &json!({"framing": ["auth"], "location": {"file": "src/b.rs", "line_start": 3}}),
        );
        claim(&walk_dir, "claim-004.json", &json!({"file": "src/a.rs"}));

        let answers = answer_claims(&walk_dir, "fuzz-walk", &ledger).unwrap();
        assert_eq!(answers.len(), 4);
        assert_eq!(answers[0].decision, "refused");
        assert_eq!(answers[0].key, "auth::src/a.rs:10");
        assert_eq!(
            answers[0].record.as_deref(),
            Some(record_id(Kind::Finding, "auth::src/a.rs:10").as_str())
        );
        assert_eq!(answers[0].established_by_run.as_deref(), Some("r1"));
        assert_eq!(
            answers[1].decision, "registered",
            "a reasoned record blocks nothing"
        );
        assert_eq!(answers[2].decision, "registered");
        assert_eq!(
            answers[3].decision, "refused",
            "a claim that names no line is not registered"
        );

        let refused = decision(&walk_dir, "claim-001");
        assert_eq!(refused["decision"], "refused");
        assert_eq!(refused["established_by_run"], "r1");
        assert_eq!(
            refused["record_path"],
            format!(
                ".lyrik/ledger/{}.json",
                record_id(Kind::Finding, "auth::src/a.rs:10")
            )
        );
        // The answer is the hand-off for the claim's file: every record
        // for src/a.rs, none for another file.
        assert_eq!(refused["records_for_file"].as_array().unwrap().len(), 5);
        let registered = decision(&walk_dir, "claim-003");
        assert_eq!(registered["decision"], "registered");
        assert!(
            registered["records_for_file"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // Answered once: a second pass has nothing to do.
        assert!(
            answer_claims(&walk_dir, "fuzz-walk", &ledger)
                .unwrap()
                .is_empty()
        );
    }

    /// The class a walk gives a claim does not matter: the same place,
    /// within the line window, is the same claim. The refusal quotes
    /// the record. A walk that names the record and says how its claim
    /// differs is registered as distinct, and its finding is then left
    /// alone at aggregation; one that does not is refused there too.
    #[test]
    fn a_claim_at_a_settled_place_is_refused_whatever_class_it_names() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        let ledger = load(tmp.path()).unwrap();
        let settled = record_id(Kind::Finding, "auth::src/a.rs:10");
        let walk_dir = tmp.path().join("staging/sink-walk");

        // Another class, same line; another class, two lines off; three
        // lines off is another place.
        claim(
            &walk_dir,
            "claim-001.json",
            &json!({"class": "missing_bounds_check", "file": "src/a.rs", "line": 10}),
        );
        claim(
            &walk_dir,
            "claim-002.json",
            &json!({"class": "unbounded_alloc", "file": "src/a.rs", "line": 12}),
        );
        claim(
            &walk_dir,
            "claim-003.json",
            &json!({"class": "unbounded_alloc", "file": "src/a.rs", "line": 13}),
        );
        // Naming the record without saying how, and naming another
        // record, are not enough.
        claim(
            &walk_dir,
            "claim-004.json",
            &json!({"class": "race", "file": "src/a.rs", "line": 10, "differs_from": settled}),
        );
        claim(
            &walk_dir,
            "claim-005.json",
            &json!({"class": "race", "file": "src/a.rs", "line": 10, "differs_from": "0000000000000000", "how": "x"}),
        );
        // Naming it and saying how: accepted.
        claim(
            &walk_dir,
            "claim-006.json",
            &json!({"class": "race", "file": "src/a.rs", "line": 11,
            "differs_from": settled, "how": "The settled record is the missing check; this is two writers to the same slot."}),
        );
        let answers = answer_claims(&walk_dir, "sink-walk", &ledger).unwrap();
        let got: Vec<&str> = answers.iter().map(|a| a.decision).collect();
        assert_eq!(
            got,
            [
                "refused",
                "refused",
                "registered",
                "refused",
                "refused",
                "registered_distinct"
            ]
        );
        assert_eq!(LINE_WINDOW, 2);
        for a in &answers[..2] {
            assert_eq!(a.record.as_deref(), Some(settled.as_str()));
            assert_eq!(a.established_by_run.as_deref(), Some("r1"));
        }
        let refused = decision(&walk_dir, "claim-001");
        assert_eq!(refused["record_key"], "auth::src/a.rs:10");
        assert_eq!(refused["record_claim"], "no check before the write");
        assert!(
            refused["if_yours_is_a_different_defect"]
                .as_str()
                .unwrap()
                .contains("differs_from")
        );
        let distinct = decision(&walk_dir, "claim-006");
        assert_eq!(distinct["decision"], "registered_distinct");
        assert_eq!(distinct["differs_from"], settled);
        assert!(answers[5].how.as_deref().unwrap().contains("two writers"));

        // At aggregation: the finding registered as distinct stays; one
        // under another class with no such claim is refused.
        stage(
            &walk_dir,
            "finding-001.json",
            &json!({"stable_id": "race::src/a.rs:11", "framing": ["race"],
            "title": "two writers", "location": {"file": "src/a.rs", "line_start": 11}}),
        );
        let kept = refuse_duplicates(&walk_dir, "sink-walk", &ledger, &answers).unwrap();
        assert!(kept.is_empty(), "{kept:?}");
        let other = tmp.path().join("staging/fuzz-walk");
        stage(
            &other,
            "finding-001.json",
            &json!({"stable_id": "unbounded_alloc::src/a.rs:9", "framing": ["unbounded_alloc"],
            "title": "same defect, other name", "location": {"file": "src/a.rs", "line_start": 9}}),
        );
        let refused = refuse_duplicates(&other, "fuzz-walk", &ledger, &answers).unwrap();
        assert_eq!(
            refused.len(),
            1,
            "another walk's distinct claim does not cover this one"
        );
        assert_eq!(refused[0].record, settled);
    }

    /// A run's output carries what earlier runs observed in its scope
    /// while the file is unchanged, marked with the run that
    /// established it. Reasoned records, records outside the scope,
    /// stale records and places this run kept a finding at are not
    /// carried, and a carried finding does not become a new record.
    #[test]
    fn settled_findings_in_scope_are_carried_and_stale_ones_are_not() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        std::fs::create_dir_all(tmp.path().join("lib")).unwrap();
        std::fs::write(tmp.path().join("lib/z.rs"), "fn z() {}\n").unwrap();
        let mut body = run_body();
        body["findings"][0]["tier"] = json!("HIGH");
        body["findings"].as_array_mut().unwrap().push(json!({
            "stable_id": "auth::lib/z.rs:1", "title": "outside", "framing": ["auth"],
            "location": {"file": "lib/z.rs", "line_start": 1}
        }));
        body["reproductions"].as_array_mut().unwrap().push(json!(
            {"stable_id": "auth::lib/z.rs:1", "outcome": "reproduced", "agreement": true}
        ));
        upsert(tmp.path(), &records_from_run(tmp.path(), &body, &[], "r1")).unwrap();
        let ledger = load(tmp.path()).unwrap();
        let area = Area::from_config(&json!({"scope": {"include": ["src/**"]}}));

        let carried = carried_findings(&ledger, &area, &[]);
        assert_eq!(carried.len(), 1, "{carried:?}");
        let c = &carried[0];
        assert_eq!(c["stable_id"], "auth::src/a.rs:10");
        assert_eq!(c["framing"], json!(["auth"]));
        assert_eq!(c["location"], json!({"file": "src/a.rs", "line_start": 10}));
        assert_eq!(c["tier"], "HIGH");
        assert_eq!(c["carried"]["from_run"], "r1");
        assert_eq!(c["carried"]["evidence"], "observed");
        assert_eq!(c["carried"]["commit"], "abc123");
        assert_eq!(
            c["carried"]["record"],
            record_id(Kind::Finding, "auth::src/a.rs:10")
        );
        assert!(
            c["summary"]
                .as_str()
                .unwrap()
                .contains("Carried from run r1")
        );

        // This run kept a finding of its own there: not carried as well.
        assert!(carried_findings(&ledger, &area, &[("src/a.rs".into(), 11)]).is_empty());
        // No scope: the one outside comes too.
        assert_eq!(carried_findings(&ledger, &Area::default(), &[]).len(), 2);
        // A carried finding in a later run's output writes no record.
        let later = json!({"target_sha": "abc123", "findings": [c.clone()]});
        assert!(records_from_run(tmp.path(), &later, &[], "r2").is_empty());

        // The file changes: nothing is carried.
        std::fs::write(tmp.path().join("src/a.rs"), "fn a() { check(); }\n").unwrap();
        let ledger = load(tmp.path()).unwrap();
        assert!(carried_findings(&ledger, &area, &[]).is_empty());
    }

    /// A walk gets full records only for the files of its area, and an
    /// index line for everything else, which it can read by id.
    #[test]
    fn a_walk_is_handed_full_records_for_its_area_and_an_index_of_the_rest() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        std::fs::create_dir_all(tmp.path().join("lib")).unwrap();
        std::fs::write(tmp.path().join("lib/z.rs"), "fn z() {}\n").unwrap();
        let mut body = run_body();
        body["findings"].as_array_mut().unwrap().push(json!({
            "stable_id": "auth::lib/z.rs:1", "title": "outside the area", "framing": ["auth"],
            "location": {"file": "lib/z.rs", "line_start": 1}
        }));
        let records = records_from_run(tmp.path(), &body, &[], "r1");
        upsert(tmp.path(), &records).unwrap();
        let ledger = load(tmp.path()).unwrap();

        let area = Area::from_config(&json!({"scope": {"include": ["src/**"], "exclude": []}}));
        assert!(area.contains("src/a.rs"));
        assert!(area.contains("src/deep/er/b.rs"));
        assert!(!area.contains("lib/z.rs"));
        let handed = for_walk(&ledger, &area);
        let full: Vec<&str> = handed["area"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["key"].as_str().unwrap())
            .collect();
        assert!(full.contains(&"auth::src/a.rs:10"));
        assert!(!full.contains(&"auth::lib/z.rs:1"));
        assert!(
            handed["area"][0].get("claim").is_some(),
            "area records are whole"
        );
        let index = handed["index"].as_array().unwrap();
        assert_eq!(index.len(), 1);
        let line = index[0].as_object().unwrap();
        assert_eq!(line["key"], "auth::lib/z.rs:1");
        assert_eq!(line["evidence"], "reasoned");
        assert_eq!(line["stale"], false);
        let mut keys: Vec<&str> = line.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            ["evidence", "id", "key", "stale"],
            "an index line is compact"
        );
        // The id is the file to read the whole record from.
        let id = line["id"].as_str().unwrap();
        assert!(ledger_dir(tmp.path()).join(format!("{id}.json")).is_file());
        assert_eq!(handed["read_a_record_at"], ".lyrik/ledger/<id>.json");

        // Patterns: a bare name matches in any directory; exclude wins;
        // no include means everything.
        let sh =
            Area::from_config(&json!({"scope": {"include": ["*.sh"], "exclude": ["vendor/**"]}}));
        assert!(sh.contains("a.sh"));
        assert!(sh.contains("tools/b.sh"));
        assert!(!sh.contains("vendor/c.sh"));
        assert!(!sh.contains("a.rs"));
        assert!(Area::default().contains("anything/at/all"));
    }

    /// When the file changes, every record established against the old
    /// content is marked stale on disk and stops blocking.
    #[test]
    fn a_record_whose_file_changed_is_stale_and_blocks_nothing() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let records = records_from_run(tmp.path(), &run_body(), &rejections(), "r1");
        upsert(tmp.path(), &records).unwrap();
        assert!(load(tmp.path()).unwrap().iter().all(|r| !r.stale));

        std::fs::write(tmp.path().join("src/a.rs"), "fn a() { check(); }\n").unwrap();
        let ledger = load(tmp.path()).unwrap();
        assert!(ledger.iter().all(|r| r.stale));
        assert!(ledger.iter().all(|r| !r.settled()));
        // The mark is on disk.
        let id = record_id(Kind::Finding, "auth::src/a.rs:10");
        let on_disk: Record = serde_json::from_str(
            &std::fs::read_to_string(ledger_dir(tmp.path()).join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert!(on_disk.stale);

        let walk_dir = tmp.path().join("staging/sink-walk");
        stage(
            &walk_dir,
            "finding-001.json",
            &json!({"stable_id": "auth::src/a.rs:10", "framing": ["auth"], "title": "again",
                    "location": {"file": "src/a.rs", "line_start": 10}}),
        );
        assert!(
            refuse_duplicates(&walk_dir, "sink-walk", &ledger, &[])
                .unwrap()
                .is_empty()
        );
        let handed = for_walk(&ledger, &Area::default());
        assert!(handed["area"].as_array().unwrap().is_empty());
        let index = handed["index"].as_array().unwrap();
        assert_eq!(index.len(), 5);
        assert!(index.iter().all(|line| line["stale"] == true));
        // Registering the same claim is no longer refused either.
        claim(
            &walk_dir,
            "claim-001.json",
            &json!({"class": "auth", "file": "src/a.rs", "line": 10}),
        );
        let answers = answer_claims(&walk_dir, "sink-walk", &ledger).unwrap();
        assert_eq!(answers[0].decision, "registered");
        assert!(
            decision(&walk_dir, "claim-001")["records_for_file"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // The file put back: the records stand again.
        std::fs::write(tmp.path().join("src/a.rs"), "fn a() {}\n").unwrap();
        assert!(load(tmp.path()).unwrap().iter().all(|r| !r.stale));
    }

    /// What was observed is not overwritten by a later run that only
    /// read the code; a later observation replaces a reasoned record.
    #[test]
    fn a_reasoned_record_does_not_replace_an_observed_one() {
        let tmp = target_with("src/a.rs", "fn a() {}\n");
        let first = records_from_run(tmp.path(), &run_body(), &[], "r1");
        upsert(tmp.path(), &first).unwrap();
        let mut later = run_body();
        later["reproductions"] = json!([
            {"stable_id": "injection::src/a.rs:20", "outcome": "reproduced", "agreement": true}
        ]);
        later["fixes"] = json!([]);
        let second = records_from_run(tmp.path(), &later, &[], "r2");
        upsert(tmp.path(), &second).unwrap();
        let ledger = load(tmp.path()).unwrap();
        let by_key = |k: &str| ledger.iter().find(|r| r.key == k).unwrap();
        // r2 only read this one: r1's observation stands.
        assert_eq!(by_key("auth::src/a.rs:10").run, "r1");
        assert_eq!(by_key("auth::src/a.rs:10").evidence, Evidence::Observed);
        // r2 observed this one: it replaces r1's reasoned record.
        assert_eq!(by_key("injection::src/a.rs:20").run, "r2");
        assert_eq!(
            by_key("injection::src/a.rs:20").evidence,
            Evidence::Observed
        );
    }

    #[test]
    fn a_path_that_leaves_the_target_has_no_hash() {
        let tmp = target_with("src/a.rs", "x");
        assert!(file_sha256(tmp.path(), "src/a.rs").is_some());
        assert!(file_sha256(tmp.path(), "../outside").is_none());
        assert!(file_sha256(tmp.path(), "/etc/hostname").is_none());
        assert!(file_sha256(tmp.path(), "src/missing.rs").is_none());
    }
}
