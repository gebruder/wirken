//! Execution evidence for a reproduction: whether code of the file a
//! finding cites ran when its harness did.
//!
//! A harness prints a marker and exits non-zero when its finding
//! holds. That is true of a harness that calls the vulnerable function
//! and of one that parses the source and reports what it read, and
//! only the first observed anything. The runner tells them apart
//! itself: it runs the reproduction's `python3 <harness>` command once
//! more in the sandbox under [`TRACER`], which records each line of
//! the cited file that executes. The verdict rests on that trace,
//! which the runner made, and on nothing a model wrote.
//!
//! What the tracer cannot follow is not evidence of execution: a
//! harness in another language, a cited file that is not Python, code
//! run in a child process, a command that is more than `python3` and
//! the harness path.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A finding with an agreed reproduction whose trace shows cited code
/// ran.
pub const OBSERVED: &str = "observed";
/// A finding with an agreed reproduction and no such trace: the check
/// ran, the code it is about did not.
pub const STATIC_CONFIRMED: &str = "static_confirmed";
/// A finding with no agreed reproduction.
pub const REASONED: &str = "reasoned";

/// The tracer, run as `python3 -c <TRACER> <nonce> <cited file> <cited
/// line> <harness>`. It runs the harness as `__main__` with a trace
/// function on every thread, collects the lines of the cited file that
/// execute, and prints them after the harness's own output on a line
/// that opens with the nonce. No single quote appears in it, so it
/// passes through `sh -c` inside single quotes.
pub const TRACER: &str = r#"import ast, json, os, runpy, sys, threading
nonce, cited, line, script = sys.argv[1], os.path.realpath(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
span = None
try:
    best = None
    for n in ast.walk(ast.parse(open(cited, encoding="utf-8").read())):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            top = min([d.lineno for d in n.decorator_list] + [n.lineno])
            if top <= line <= n.end_lineno and (best is None or top >= best[0]):
                best = (top, n)
    if best:
        span = [best[1].body[0].lineno, best[1].end_lineno]
except Exception:
    pass
hit = set()
known = {}
def is_cited(name):
    r = known.get(name)
    if r is None:
        try:
            r = os.path.realpath(name) == cited
        except Exception:
            r = False
        known[name] = r
    return r
def local(frame, event, arg):
    if event == "line":
        hit.add(frame.f_lineno)
    return local
def tracer(frame, event, arg):
    if event == "call" and is_cited(frame.f_code.co_filename):
        return local
    return None
sys.argv = [script]
code = 0
threading.settrace(tracer)
sys.settrace(tracer)
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit as e:
    code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
except BaseException:
    import traceback
    traceback.print_exc()
    code = 1
finally:
    sys.settrace(None)
sys.stdout.flush()
print("\n" + nonce + " " + json.dumps({"executed": sorted(hit), "span": span, "exit": code}), flush=True)
sys.exit(code)
"#;

/// What the runner's traced run of a reproduction showed, as
/// `findings.json` carries it beside the reproduction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Execution {
    /// The file the finding cites, relative to the target's root.
    pub cited_file: String,
    /// The line the finding cites.
    pub cited_line: u64,
    /// The body of the function that holds the cited line, first line
    /// to last. Absent when the line is at module level or the file
    /// could not be parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cited_function_lines: Option<(u64, u64)>,
    /// The lines of the cited file that executed, ascending. Empty
    /// when none did or the run was not traced.
    pub executed_lines: Vec<u64>,
    /// Whether the traced run printed the marker.
    pub marker: bool,
    /// Why the run was not traced, when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untraced: Option<String>,
}

impl Execution {
    /// A reproduction that was not traced, and why.
    pub fn untraced(cited_file: &str, cited_line: u64, why: impl Into<String>) -> Self {
        Self {
            cited_file: cited_file.to_string(),
            cited_line,
            cited_function_lines: None,
            executed_lines: Vec::new(),
            marker: false,
            untraced: Some(why.into()),
        }
    }

    /// Whether a line inside the cited function's body executed, or
    /// the cited line itself when it is at module level.
    pub fn cited_lines_ran(&self) -> bool {
        match self.cited_function_lines {
            Some((from, to)) => self.executed_lines.iter().any(|l| (from..=to).contains(l)),
            None => self.executed_lines.contains(&self.cited_line),
        }
    }

    /// Whether the run showed the finding by running cited code: the
    /// marker was printed and cited lines ran.
    pub fn cited_code_ran(&self) -> bool {
        self.marker && self.cited_lines_ran()
    }

    /// [`OBSERVED`] or [`STATIC_CONFIRMED`].
    #[cfg(test)]
    pub fn evidence(&self) -> &'static str {
        if self.cited_code_ran() {
            OBSERVED
        } else {
            STATIC_CONFIRMED
        }
    }
}

/// The harness script of a command the tracer can follow: exactly
/// `python3` and one path to a `.py` file under `harness_dir`, a
/// directory relative to the target's root. `None` for anything else.
pub fn traceable_script(command: &str, harness_dir: &str) -> Option<String> {
    let mut words = command.split_whitespace();
    let (interpreter, script, rest) = (words.next()?, words.next()?, words.next());
    let plain = !script.contains(['\'', '"', '$', '`', '\\', ';', '&', '|', '<', '>'])
        && Path::new(script)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    (interpreter == "python3"
        && rest.is_none()
        && plain
        && script.ends_with(".py")
        && Path::new(script).starts_with(harness_dir))
    .then(|| script.to_string())
}

/// The command that runs `script` under the tracer.
pub fn tracer_command(nonce: &str, cited_file: &str, cited_line: u64, script: &str) -> String {
    format!("python3 -c '{TRACER}' {nonce} '{cited_file}' {cited_line} '{script}'")
}

/// Read the tracer's line out of a traced run's output.
pub fn parse_traced(output: &str, nonce: &str, cited_file: &str, cited_line: u64) -> Execution {
    #[derive(Deserialize)]
    struct Line {
        executed: Vec<u64>,
        span: Option<(u64, u64)>,
    }
    let traced = output
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(nonce))
        .and_then(|rest| serde_json::from_str::<Line>(rest.trim()).ok());
    match traced {
        Some(t) => Execution {
            cited_file: cited_file.to_string(),
            cited_line,
            cited_function_lines: t.span,
            executed_lines: t.executed,
            marker: super::lyrik_fix_arms::has_marker(output),
            untraced: None,
        },
        None => Execution::untraced(
            cited_file,
            cited_line,
            "the traced run printed no trace line",
        ),
    }
}

/// Where the runner keeps the trace of a walk's reproduction: under
/// the run directory and outside every walk's staging, so no agent of
/// the run can write it.
pub fn trace_path(run_dir: &Path, walk: &str, repro_file: &str) -> PathBuf {
    run_dir.join("traces").join(walk).join(repro_file)
}

pub fn write_trace(run_dir: &Path, walk: &str, repro_file: &str, e: &Execution) -> Result<()> {
    let path = trace_path(run_dir, walk, repro_file);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(e)?)
        .with_context(|| format!("write {}", path.display()))
}

pub fn read_trace(run_dir: &Path, walk: &str, repro_file: &str) -> Option<Execution> {
    let text = std::fs::read_to_string(trace_path(run_dir, walk, repro_file)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The file and line the staged finding `stable_id` cites, from the
/// walk's `findings/` directory, with the line moved to the text the
/// finding quotes where the file places it, as the citation check
/// will move it.
pub fn cited_location(
    findings_dir: &Path,
    stable_id: &str,
    workspace: &Path,
) -> Option<(String, u64)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(findings_dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files.into_iter().find_map(|path| {
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        if v.get("stable_id")?.as_str()? != stable_id {
            return None;
        }
        super::lyrik_citation::settle_lines(&mut v, workspace);
        Some((
            v.pointer("/location/file")?.as_str()?.to_string(),
            v.pointer("/location/line_start")?.as_u64()?,
        ))
    })
}

use anyhow::{Context, Result};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Run the tracer with the host's `python3`, as the sandbox runs
    /// it. `None` when the host has none.
    fn traced(dir: &Path, cited_line: u64, harness: &str) -> Option<Execution> {
        std::fs::write(dir.join("h.py"), harness).unwrap();
        let out = std::process::Command::new("python3")
            .current_dir(dir)
            .args([
                "-c",
                TRACER,
                "NONCE-1",
                "app.py",
                &cited_line.to_string(),
                "h.py",
            ])
            .output()
            .ok()?;
        Some(parse_traced(
            &String::from_utf8_lossy(&out.stdout),
            "NONCE-1",
            "app.py",
            cited_line,
        ))
    }

    const APP: &str = "import json\n\n\ndef analyze(expr):\n    return str(eval(expr))\n\n\ndef \
                       describe():\n    return json.dumps({})\n";

    /// The three shapes a walk's harness took in a real run, each of
    /// which parsed the source, printed the marker and exited 1, and
    /// one that calls the function.
    #[test]
    fn a_harness_earns_observed_only_when_the_cited_function_ran() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("app.py"), APP).unwrap();
        let ast_walk = "import ast, sys\ntree = ast.parse(open(\"app.py\").read())\n\
                        print(\"LYRIK_REACHED\", flush=True)\nsys.exit(1)\n";
        let text_search = "import sys\nsrc = open(\"app.py\").read()\n\
                           print(\"LYRIK_REACHED\", flush=True)\n\
                           sys.exit(1 if \"eval(\" in src else 0)\n";
        // Imports the module, so its top level runs, and never calls
        // the cited function.
        let import_only = "import os, sys\nsys.path.insert(0, os.getcwd())\nimport app\n\
                           print(\"LYRIK_REACHED\", flush=True)\nsys.exit(1)\n";
        let calls_it = "import os, sys\nsys.path.insert(0, os.getcwd())\nimport app\n\
                        print(\"LYRIK_REACHED\", flush=True)\n\
                        sys.exit(1 if app.analyze(\"1+1\") == \"2\" else 0)\n";
        let Some(first) = traced(tmp.path(), 5, ast_walk) else {
            eprintln!("skipping: no python3 on this host");
            return;
        };
        assert_eq!(first.cited_function_lines, Some((5, 5)));
        assert!(first.marker && first.executed_lines.is_empty(), "{first:?}");
        assert_eq!(first.evidence(), STATIC_CONFIRMED);
        assert_eq!(
            traced(tmp.path(), 5, text_search).unwrap().evidence(),
            STATIC_CONFIRMED
        );
        let imported = traced(tmp.path(), 5, import_only).unwrap();
        assert!(imported.executed_lines.contains(&1), "{imported:?}");
        assert_eq!(imported.evidence(), STATIC_CONFIRMED);

        let ran = traced(tmp.path(), 5, calls_it).unwrap();
        assert!(ran.executed_lines.contains(&5), "{ran:?}");
        assert_eq!(ran.evidence(), OBSERVED);
        // The `def` line names the function too: its body is what
        // must run.
        assert_eq!(
            traced(tmp.path(), 4, calls_it).unwrap().evidence(),
            OBSERVED
        );
        // Another function of the same file ran: not this finding's.
        assert_eq!(
            traced(tmp.path(), 9, calls_it).unwrap().evidence(),
            STATIC_CONFIRMED
        );
        // No marker, no reproduction, whatever ran.
        let silent = "import os, sys\nsys.path.insert(0, os.getcwd())\nimport app\n\
                      app.analyze(\"1\")\nsys.exit(1)\n";
        assert_eq!(
            traced(tmp.path(), 5, silent).unwrap().evidence(),
            STATIC_CONFIRMED
        );
    }

    #[test]
    fn only_a_plain_python3_harness_command_is_traced() {
        let dir = ".lyrik/state/runs/r1/staging/sink-walk/harness";
        let script = format!("{dir}/h.py");
        assert_eq!(
            traceable_script(&format!("python3 {script}"), dir),
            Some(script.clone())
        );
        for other in [
            format!("sh {dir}/h.sh"),
            format!("python3 {script}; echo $?"),
            format!("python3 {script} --flag"),
            format!("cd /workspace && python3 {script}"),
            format!("python3 {dir}/../../chain-walk/harness/h.py"),
            "python3 agent.py".to_string(),
            format!("python3 '{script}'"),
        ] {
            assert_eq!(traceable_script(&other, dir), None, "{other}");
        }
    }

    #[test]
    fn output_with_no_trace_line_is_untraced_and_static() {
        let e = parse_traced("LYRIK_REACHED\n", "NONCE-1", "app.py", 5);
        assert!(e.untraced.is_some());
        assert_eq!(e.evidence(), STATIC_CONFIRMED);
    }
}
