//! A finding is `observed`, and its replay `reproduced`, only when
//! code of the cited file ran. A harness that reads or parses the
//! source and prints the marker earns `static_confirmed`.
//!
//! Driven through the binary on a pseudo-terminal with a scripted
//! model: one walk stages a finding, a harness and its reproduction
//! record, and the replay runs the harness. Needs Docker and the
//! `python:3.12-slim` image, and says so when it skips.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::ScriptedModel;

fn call(calls: &[(&str, serde_json::Value)]) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": calls
            .iter()
            .map(|(name, args)| serde_json::json!({"function": {"name": name, "arguments": args}}))
            .collect::<Vec<_>>(),
    })
}

fn write(path: String, content: &str) -> (&'static str, serde_json::Value) {
    (
        "write_file",
        serde_json::json!({"path": path, "content": content}),
    )
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The same shape as the harnesses a walk wrote in a real run: parse
/// the source, print the marker, exit non-zero. Nothing of `app.py`
/// runs.
const STATIC_HARNESS: &str = r#"import ast, sys
tree = ast.parse(open("app.py").read())
uses_eval = any(
    isinstance(n, ast.Call) and getattr(n.func, "id", "") == "eval" for n in ast.walk(tree)
)
print("LYRIK_REACHED", flush=True)
print(f"analyze_uses_eval: {uses_eval}")
sys.exit(1 if uses_eval else 0)
"#;

/// Calls the cited function, so its lines run.
const EXECUTING_HARNESS: &str = r#"import os, sys
sys.path.insert(0, os.getcwd())
import app
print("LYRIK_REACHED", flush=True)
sys.exit(1 if app.analyze("1+1") == "2" else 0)
"#;

struct Outcome {
    replay: serde_json::Value,
    findings: serde_json::Value,
    ledger: Vec<serde_json::Value>,
    shown: String,
}

fn run(run: &str, harness: &str) -> Option<Outcome> {
    let image = "python:3.12-slim";
    let has_image = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !has_image {
        eprintln!("skipping: Docker or {image} is not available on this host");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(
        target.join("app.py"),
        "def analyze(expr):\n    return str(eval(expr))\n\n\ndef describe():\n    return \"ok\"\n",
    )
    .unwrap();
    let walk = data.join("lyrik/walks/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n",
    )
    .unwrap();
    std::fs::write(
        data.join("sandbox.json"),
        format!(r#"{{"image": "{image}"}}"#),
    )
    .unwrap();

    let staging = format!(".lyrik/state/runs/{run}/staging/sink-walk");
    let command = format!("python3 {staging}/harness/h.py");
    let finding = serde_json::json!({
        "id": "F001", "stable_id": "injection::app.py:2", "framing": ["injection"],
        "location": {"file": "app.py", "line_start": 2},
        "title": "eval of a caller-controlled expression",
        "summary": "analyze() passes its argument to eval.",
        "tier": "HIGH",
        "evidence": ["app.py:2:     return str(eval(expr))"],
        "threat_model": {
            "attacker_capability": "controls the expression",
            "harm_path": "runs code in the process",
        },
    });
    let repro = serde_json::json!({
        "stable_id": "injection::app.py:2",
        "command": command,
        "harness": format!("{staging}/harness/h.py"),
        "expected": "LYRIK_REACHED on stdout; exit status 1",
        "observed": "LYRIK_REACHED; exit status 1",
        "outcome": "reproduced",
        "code_revision": "unknown",
    });
    let replay = serde_json::json!({
        "command_run": command,
        "observed": "LYRIK_REACHED; exit status 1",
        "outcome": "reproduced",
    });
    let model = ScriptedModel::start(vec![
        call(&[("probe_ping", serde_json::json!({"marker": "ok"}))]),
        // The walk: a harness, the finding and the reproduction record.
        call(&[
            write(format!("{staging}/harness/h.py"), harness),
            write(
                format!("{staging}/findings/finding-001.json"),
                &finding.to_string(),
            ),
            write(
                format!("{staging}/reproductions/repro-001.json"),
                &repro.to_string(),
            ),
        ]),
        serde_json::json!({"role": "assistant", "content": "Done."}),
        // The replay: the same command, and its record.
        call(&[("exec", serde_json::json!({"command": command}))]),
        call(&[write(
            format!("{staging}/replays/replay-001.json"),
            &replay.to_string(),
        )]),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({"phases": {"framing": pin}, "walks": ["sink-walk"]}).to_string(),
    )
    .unwrap();

    let line = format!(
        "{} lyrik run --target {} --run {run}",
        shell_quote(env!("CARGO_BIN_EXE_wirken")),
        shell_quote(&target.display().to_string()),
    );
    let mut child = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", &data)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env_remove("WIRKEN_ALLOW_UNSIGNED_SKILLS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("util-linux `script`");
    child.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = target.join(format!(".lyrik/state/runs/{run}"));
    let audit = std::fs::read_to_string(run_dir.join("audit.log")).unwrap();
    let replay = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.replay.completed")
        .unwrap_or_else(|| panic!("no lyrik.replay.completed row:\n{audit}\n{shown}"))["detail"]
        .clone();
    let findings = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("findings.json"))
            .unwrap_or_else(|e| panic!("{e}\n{shown}")),
    )
    .unwrap();
    let mut ledger = Vec::new();
    for entry in std::fs::read_dir(target.join(".lyrik/ledger")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        ledger.push(serde_json::from_str(&text).unwrap());
    }
    Some(Outcome {
        replay,
        findings,
        ledger,
        shown,
    })
}

#[test]
fn a_harness_that_only_parses_the_source_is_static_confirmed() {
    let Some(o) = run("static", STATIC_HARNESS) else {
        return;
    };
    assert_eq!(
        o.replay["status"], "static_confirmed",
        "{}\n{}",
        o.replay, o.shown
    );
    let repro = &o.findings["reproductions"][0];
    assert_eq!(repro["evidence"], "static_confirmed", "{repro}");
    assert_eq!(repro["execution"]["cited_file"], "app.py", "{repro}");
    assert_eq!(
        repro["execution"]["executed_lines"],
        serde_json::json!([]),
        "{repro}"
    );
    assert_eq!(
        o.findings["findings"][0]["evidence"], "static_confirmed",
        "{}",
        o.findings
    );
    assert_eq!(o.ledger.len(), 1, "{:?}", o.ledger);
    assert_eq!(
        o.ledger[0]["evidence"], "static_confirmed",
        "{:?}",
        o.ledger
    );
}

#[test]
fn a_harness_that_runs_the_cited_function_is_observed() {
    let Some(o) = run("executed", EXECUTING_HARNESS) else {
        return;
    };
    assert_eq!(
        o.replay["status"], "reproduced",
        "{}\n{}",
        o.replay, o.shown
    );
    let repro = &o.findings["reproductions"][0];
    assert_eq!(repro["evidence"], "observed", "{repro}");
    // The cited line ran, inside `analyze`.
    assert!(
        repro["execution"]["executed_lines"]
            .as_array()
            .is_some_and(|l| l.contains(&serde_json::json!(2))),
        "{repro}"
    );
    assert_eq!(
        o.findings["findings"][0]["evidence"], "observed",
        "{}",
        o.findings
    );
    assert_eq!(o.ledger[0]["evidence"], "observed", "{:?}", o.ledger);
}
