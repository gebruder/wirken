//! A `wirken lyrik run` outside `bench_mode` starts only on the
//! operator's sign-off at a terminal.
//!
//! Driven through the binary with a scripted model. The approve and
//! decline cases give the run a real terminal through util-linux
//! `script`, which runs it on a pseudo-terminal fed from the test's
//! input; the no-terminal case runs with stdin closed.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use common::{ScriptedModel, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

struct Scene {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
    data: std::path::PathBuf,
    target: std::path::PathBuf,
    model: ScriptedModel,
}

fn scene(run: &str, bench_mode: bool) -> Scene {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{run}/staging/findings/finding-001.json"),
                "content": serde_json::json!({
                    "id": "F001",
                    "stable_id": "auth::src/auth.c:1",
                    "framing": ["auth"],
                    "location": {"file": "src/auth.c", "line_start": 1},
                    "title": "stub",
                    "summary": "stub",
                    "tier": "LOW",
                }).to_string(),
            }),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({"bench_mode": bench_mode, "phases": {"framing": pin}}).to_string(),
    )
    .unwrap();
    Scene {
        _tmp: tmp,
        home,
        data,
        target,
        model,
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run on a pseudo-terminal, typing `answer`. Returns (success,
/// everything the terminal showed).
fn run_on_terminal(s: &Scene, run: &str, answer: &str) -> (bool, String) {
    let command = format!(
        "{} lyrik run --target {} --run {}",
        shell_quote(env!("CARGO_BIN_EXE_wirken")),
        shell_quote(&s.target.display().to_string()),
        shell_quote(run)
    );
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .env("WIRKEN_DATA_DIR", &s.data)
        .env("HOME", &s.home)
        .env("NO_COLOR", "1")
        .env_remove("WIRKEN_ALLOW_UNSIGNED_SKILLS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("util-linux `script`");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn audit_rows(target: &Path, run: &str, event: &str) -> Vec<serde_json::Value> {
    let log = target.join(format!(".lyrik/state/runs/{run}/audit.log"));
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| r["event"] == event)
        .map(|r| r["detail"].clone())
        .collect()
}

fn chain_rows(data: &Path, kind: &str) -> Vec<serde_json::Value> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT payload FROM session_events
          WHERE json_extract(payload, '$.kind') = ?1
          ORDER BY seq",
    )
    .unwrap()
    .query_map([kind], |r| r.get::<_, String>(0))
    .unwrap()
    .map(|p| serde_json::from_str(&p.unwrap()).unwrap())
    .collect()
}

#[test]
fn a_yes_at_the_terminal_signs_the_run_off_on_the_chain() {
    const RUN: &str = "signed";
    let s = scene(RUN, false);
    let (ok, shown) = run_on_terminal(&s, RUN, "y\n");
    assert!(ok, "{shown}");
    // What was asked, before the run started.
    for part in [
        "Lyrik run signed on ",
        "  target   no git HEAD: not a git work tree",
        "  rubric   inline skills/lyrik/SKILL.md sha256 ",
        "  context  none",
        "  model    ollama scripted",
        "  walks    none, single call",
        "Sign off this run? [y/N]: ",
    ] {
        assert!(shown.contains(part), "missing {part:?} in:\n{shown}");
    }

    let rows = audit_rows(&s.target, RUN, "lyrik.phase_0.signoff");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["decision"], "operator");
    let summary_sha = rows[0]["summary_sha256"].as_str().unwrap();

    let approved = chain_rows(&s.data, "permission_approved");
    assert_eq!(approved.len(), 1, "{approved:?}");
    assert_eq!(
        approved[0]["action_key"],
        format!("lyrik:signoff:{summary_sha}")
    );
    assert_eq!(approved[0]["approved_by"], "operator");
    assert_eq!(approved[0]["scope"], "one_shot");
    assert_eq!(approved[0]["approved_via"]["kind"], "stdin");
    assert_eq!(approved[0]["agent_id"], format!("lyrik-{RUN}"));

    // And the run went ahead.
    assert!(
        s.target
            .join(format!(".lyrik/state/runs/{RUN}/findings.json"))
            .is_file()
    );
}

#[test]
fn a_no_at_the_terminal_stops_the_run_before_dispatch() {
    const RUN: &str = "declined";
    let s = scene(RUN, false);
    let (ok, shown) = run_on_terminal(&s, RUN, "n\n");
    assert!(!ok, "{shown}");
    assert!(shown.contains("run not signed off"), "{shown}");

    let rows = audit_rows(&s.target, RUN, "lyrik.phase_0.signoff");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["decision"], "declined");
    assert_eq!(rows[0]["reason"], "answered \"n\"");

    let denied = chain_rows(&s.data, "permission_denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["tool"], "lyrik");
    assert_eq!(denied[0]["denied_via"]["kind"], "stdin");
    assert_eq!(denied[0]["denial_reason"], "answered \"n\"");
    assert!(chain_rows(&s.data, "permission_approved").is_empty());

    // Nothing reached the model, not even the preflight probe.
    assert!(s.model.received().is_empty());
    assert!(
        !s.target
            .join(format!(".lyrik/state/runs/{RUN}/findings.json"))
            .exists()
    );
}

#[test]
fn without_a_terminal_a_run_outside_bench_mode_is_refused() {
    const RUN: &str = "no-terminal";
    let s = scene(RUN, false);
    let out = wirken(&s.data)
        .env("HOME", &s.home)
        .args(["lyrik", "run", "--target"])
        .arg(&s.target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{shown}");
    assert!(shown.contains("signed off at a terminal"), "{shown}");
    let rows = audit_rows(&s.target, RUN, "lyrik.phase_0.signoff");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["decision"], "pending_adapter_route");
    assert!(s.model.received().is_empty());
}

#[test]
fn bench_mode_auto_approves_without_asking() {
    const RUN: &str = "bench";
    let s = scene(RUN, true);
    let out = wirken(&s.data)
        .env("HOME", &s.home)
        .args(["lyrik", "run", "--target"])
        .arg(&s.target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("Sign off this run?"));
    let rows = audit_rows(&s.target, RUN, "lyrik.phase_0.signoff");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["decision"], "auto_bench");
    assert!(chain_rows(&s.data, "permission_approved").is_empty());
}
