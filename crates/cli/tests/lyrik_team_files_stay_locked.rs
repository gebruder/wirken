//! A `wirken lyrik run` leaves the team's committed rubric and context
//! as it found them. The agent's writes are scoped to the run's own
//! directory, and rubric sections a run stages become a proposal there.
//!
//! Driven through the binary: a target with a committed rubric, a
//! scripted model making the calls an assessment would, in single-call
//! and walk mode.

mod common;

use std::path::Path;

use common::{ScriptedModel, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn finding() -> String {
    serde_json::json!({
        "id": "F001",
        "stable_id": "auth::src/auth.c:1",
        "framing": ["auth"],
        "location": {"file": "src/auth.c", "line_start": 1},
        "title": "stub",
        "summary": "stub",
        "tier": "LOW",
    })
    .to_string()
}

const TEAM_RUBRIC: &str = "# Team rubric\n\nHIGH: anything reaching auth.\n";
const TEAM_CONTEXT: &str = "# Team context\n";

fn write_target(target: &Path, model: &ScriptedModel, walks: Option<&[&str]>) {
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    let mut config = serde_json::json!({
        "bench_mode": true,
        "scope": {"include": ["src/**/*"], "exclude": []},
        "phases": {"framing": pin},
    });
    if let Some(walks) = walks {
        config["walks"] = serde_json::json!(walks);
    }
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join(".lyrik/config.json"), config.to_string()).unwrap();
    std::fs::write(target.join(".lyrik/rubric.md"), TEAM_RUBRIC).unwrap();
    std::fs::write(target.join(".lyrik/context.md"), TEAM_CONTEXT).unwrap();
}

/// Every `write_file` result on the chain, as (output, success).
fn write_results(data: &Path) -> Vec<(String, bool)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.output'), json_extract(payload, '$.success')
           FROM session_events
          WHERE json_extract(payload, '$.kind') = 'tool_result'
            AND json_extract(payload, '$.tool_name') = 'write_file'
          ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn run(data: &Path, home: &Path, target: &Path, run: &str) -> (bool, String) {
    let out = wirken(data)
        .env("HOME", home)
        .args(["lyrik", "run", "--target"])
        .arg(target)
        .args(["--run", run])
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn single_call_writes_to_the_committed_rubric_are_refused_and_sections_are_proposed() {
    const RUN: &str = "locked";
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    let staging = format!(".lyrik/state/runs/{RUN}/staging");
    let model = ScriptedModel::start(vec![
        // The preflight probe.
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        // Straight at the committed rubric, then at another run's state.
        call(
            "write_file",
            serde_json::json!({"path": ".lyrik/rubric.md", "content": "overwritten"}),
        ),
        call(
            "write_file",
            serde_json::json!({"path": ".lyrik/state/runs/other/findings.json", "content": "{}"}),
        ),
        // A rubric section staged the way the prompt asks.
        call(
            "write_file",
            serde_json::json!({"path": format!("{staging}/rubric/01-high.md"), "content": "PROPOSED HIGH"}),
        ),
        call(
            "write_file",
            serde_json::json!({"path": format!("{staging}/findings/finding-001.json"), "content": finding()}),
        ),
        serde_json::json!({"role": "assistant", "content": "Findings emitted to staging."}),
    ]);
    write_target(&target, &model, None);

    let (ok, report) = run(&data, &home, &target, RUN);
    assert!(ok, "{report}");

    assert_eq!(
        std::fs::read_to_string(target.join(".lyrik/rubric.md")).unwrap(),
        TEAM_RUBRIC
    );
    assert_eq!(
        std::fs::read_to_string(target.join(".lyrik/context.md")).unwrap(),
        TEAM_CONTEXT
    );
    assert!(!target.join(".lyrik/state/runs/other").exists());
    let proposed = target.join(format!(".lyrik/state/runs/{RUN}/proposed/rubric.md"));
    assert_eq!(
        std::fs::read_to_string(&proposed).unwrap(),
        "PROPOSED HIGH\n"
    );
    assert!(
        report.contains("proposed rubric.md at") && report.contains("proposed/rubric.md"),
        "{report}"
    );

    let writes = write_results(&data);
    assert_eq!(writes.len(), 4, "{writes:?}");
    assert!(
        !writes[0].1 && writes[0].0.contains(".lyrik/rubric.md"),
        "{writes:?}"
    );
    assert!(
        !writes[1].1 && writes[1].0.contains("runs/other"),
        "{writes:?}"
    );
    assert!(writes[2].1 && writes[3].1, "{writes:?}");
}

#[test]
fn a_walk_cannot_write_the_committed_context() {
    const RUN: &str = "locked-walk";
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    let walk = home.join(".claude/skills/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n\nWalk sinks.\n",
    )
    .unwrap();
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call(
            "write_file",
            serde_json::json!({"path": ".lyrik/context.md", "content": "overwritten"}),
        ),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{RUN}/staging/sink-walk/findings/finding-001.json"),
                "content": finding(),
            }),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    write_target(&target, &model, Some(&["sink-walk"]));

    let (ok, report) = run(&data, &home, &target, RUN);
    assert!(ok, "{report}");
    assert_eq!(
        std::fs::read_to_string(target.join(".lyrik/context.md")).unwrap(),
        TEAM_CONTEXT
    );
    let writes = write_results(&data);
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert!(
        !writes[0].1 && writes[0].0.contains(".lyrik/context.md"),
        "{writes:?}"
    );
    assert!(writes[1].1, "{writes:?}");
}
