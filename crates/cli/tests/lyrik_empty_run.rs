//! A `wirken lyrik run` where the assessment finds nothing writes an empty
//! `findings.json`, but only when the agent wrote the no-findings marker that
//! says which framings it checked and which files it read. A run with no
//! findings and no marker still fails, and a marker beside a finding fails.
//!
//! Driven through the binary with a scripted model.
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

fn write_target(target: &Path, model: &ScriptedModel) {
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    let config = serde_json::json!({
        "bench_mode": true,
        "scope": {"include": ["src/**/*"], "exclude": []},
        "phases": {"framing": pin},
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join(".lyrik/config.json"), config.to_string()).unwrap();
}

const RUN: &str = "clean";

fn marker(path_prefix: &str) -> serde_json::Value {
    call(
        "write_file",
        serde_json::json!({
            "path": format!("{path_prefix}/no-findings.json"),
            "content": serde_json::json!({
                "framings_checked": ["auth", "injection"],
                "files_read": ["src/auth.c"],
            })
            .to_string(),
        }),
    )
}

fn finding_write(path_prefix: &str) -> serde_json::Value {
    call(
        "write_file",
        serde_json::json!({
            "path": format!("{path_prefix}/finding-001.json"),
            "content": serde_json::json!({
                "id": "F001",
                "stable_id": "auth::src/auth.c:1",
                "framing": ["auth"],
                "location": {"file": "src/auth.c", "line_start": 1},
                "title": "stub",
                "summary": "stub",
                "tier": "LOW",
            })
            .to_string(),
        }),
    )
}

/// Run the scripted model against a fresh target and return the exit status
/// and the output.
fn run_with(script: Vec<serde_json::Value>) -> (bool, String, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap().keep();
    let (home, data, target) = (tmp.join("home"), tmp.join("data"), tmp.join("target"));
    std::fs::create_dir_all(&home).unwrap();
    let model = ScriptedModel::start(script);
    write_target(&target, &model);
    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), report, target)
}

#[test]
fn a_run_with_no_findings_and_a_marker_writes_an_empty_findings_file() {
    let (ok, report, target) = run_with(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        marker(&format!(".lyrik/state/runs/{RUN}/staging")),
        serde_json::json!({
            "role": "assistant",
            "content": "No framing applies to this target; no findings emitted.",
        }),
    ]);
    assert!(ok, "{report}");

    let body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/findings.json")))
            .expect("an empty run still writes findings.json"),
    )
    .unwrap();
    assert_eq!(body["findings"], serde_json::json!([]), "{body}");
    assert_eq!(body["rejected_candidates"], serde_json::json!([]), "{body}");
    assert!(
        report.contains("brocard rejections: none (0 findings kept)"),
        "{report}"
    );
}

#[test]
fn a_run_with_no_findings_and_no_marker_still_fails() {
    let (ok, report, _) = run_with(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        serde_json::json!({"role": "assistant", "content": "Nothing to report."}),
    ]);
    assert!(!ok, "{report}");
    assert!(
        report.contains("no no-findings marker was written"),
        "{report}"
    );
}

#[test]
fn a_marker_beside_a_finding_fails_the_run() {
    let (ok, report, _) = run_with(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        finding_write(&format!(".lyrik/state/runs/{RUN}/staging/findings")),
        marker(&format!(".lyrik/state/runs/{RUN}/staging")),
        serde_json::json!({"role": "assistant", "content": "Findings emitted to staging."}),
    ]);
    assert!(!ok, "{report}");
    assert!(report.contains("contradicts staged findings"), "{report}");
}
