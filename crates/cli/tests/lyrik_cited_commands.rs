//! A step record that names a command as its check is held to the
//! chain: the command is one of the run's `exec` calls that ran, or the
//! record is marked `not_executed` and counted in the funnel.
//!
//! Driven through the binary on a pseudo-terminal with a scripted
//! model, and needs Docker and the default sandbox image, since the
//! point is a command that did run beside ones that did not. The
//! commands that did not are the ones a walk cited in a real run with
//! no `exec` row behind them.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::ScriptedModel;

const RUN: &str = "cited";

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn step(n: u32, check: &str, prior: Option<&str>) -> serde_json::Value {
    let mut record = serde_json::json!({
        "step": format!("step {n}"),
        "claim": "the sink is reachable",
        "code_revision": "unknown",
        "check": check,
        "evidence": ["agent.py:18:    return str(eval(expr))"],
        "open_questions": [],
    });
    if let Some(prior) = prior {
        record["prior"] = serde_json::json!(prior);
    }
    call(
        "write_file",
        serde_json::json!({
            "path": format!(".lyrik/state/runs/{RUN}/staging/sink-walk/steps/step-{n:02}.json"),
            "content": record.to_string(),
        }),
    )
}

#[test]
fn a_cited_command_with_no_exec_row_is_marked_not_executed() {
    let docker = Command::new("docker")
        .args(["image", "inspect", "debian:bookworm-slim"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !docker {
        eprintln!("skipping: Docker or debian:bookworm-slim is not available on this host");
        return;
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
        target.join("agent.py"),
        "def analyze_data(expr):\n    return str(eval(expr))\n",
    )
    .unwrap();
    std::fs::write(
        target.join("mcp.json"),
        "{\"args\": [\"--allow-write\", \"/\"]}\n",
    )
    .unwrap();
    let walk = data.join("lyrik/walks/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n",
    )
    .unwrap();

    // One command that runs, cited exactly; then the two citations
    // with no row behind them; then a read.
    let ran = "grep -n 'eval(' agent.py";
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call("exec", serde_json::json!({"command": ran})),
        step(1, ran, None),
        step(2, "rg -n --type py 'eval\\('", Some("step-01.json")),
        step(
            3,
            "cat mcp.json | grep -i allow-write",
            Some("step-02.json"),
        ),
        step(
            4,
            "read agent.py:1-20; trace analyze_data() to @tool decorator",
            Some("step-03.json"),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        common::lyrik_config(&data, &target),
        serde_json::json!({"phases": {"framing": pin}, "walks": ["sink-walk"]}).to_string(),
    )
    .unwrap();

    let command = format!(
        "{} lyrik run --target {} --run {RUN}",
        shell_quote(env!("CARGO_BIN_EXE_wirken")),
        shell_quote(&target.display().to_string()),
    );
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
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

    let run_dir = target.join(format!(".lyrik/state/runs/{RUN}"));
    let findings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("findings.json"))
            .unwrap_or_else(|e| panic!("{e}\n{shown}")),
    )
    .unwrap();
    let marks: Vec<(String, serde_json::Value)> = findings["step_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["file"].as_str().unwrap().to_string(),
                r["check_status"].clone(),
            )
        })
        .collect();
    let mark = |file: &str, status: serde_json::Value| (file.to_string(), status);
    assert_eq!(
        marks,
        [
            mark("step-01.json", serde_json::json!("executed")),
            mark("step-02.json", serde_json::json!("not_executed")),
            mark("step-03.json", serde_json::json!("not_executed")),
            // A read is not a command: nothing to hold it to here.
            mark("step-04.json", serde_json::Value::Null),
        ],
        "{shown}"
    );
    assert_eq!(
        findings["funnel"]["walks"]["sink-walk"]["checks_not_executed"], 2,
        "{}",
        findings["funnel"]
    );

    // Each is on the run's log with the command it cited.
    let audit = std::fs::read_to_string(run_dir.join("audit.log")).unwrap();
    let cited: Vec<String> = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["event"] == "lyrik.step.check_not_executed")
        .map(|e| e["detail"]["check"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        cited,
        [
            "rg -n --type py 'eval\\('",
            "cat mcp.json | grep -i allow-write"
        ]
    );
}
