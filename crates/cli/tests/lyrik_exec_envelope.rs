//! A per-walk `wirken lyrik run` signed off at a terminal runs every
//! `exec` of its walks inside one sandbox envelope and asks for none
//! of them: the target is mounted read-only, the walk's own staging
//! directory read-write, another walk's staging directory is not
//! there, and there is no network.
//!
//! The walks are told what that sandbox has before they start: an
//! interpreter the image lacks is not offered, and a shell that does
//! not expand braces is named.
//!
//! Driven through the binary on a pseudo-terminal with a scripted
//! model. The case that runs a command needs Docker and the default
//! sandbox image, and says so when it skips.

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

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

struct Scene {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
    data: std::path::PathBuf,
    target: std::path::PathBuf,
}

/// A target with two walks selected, run one at a time so the scripted
/// replies reach the walks in order.
fn scene(model: &ScriptedModel) -> Scene {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    for walk in ["sink-walk", "chain-walk"] {
        let dir = data.join("lyrik/walks").join(walk);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {walk}\ndescription: test walk\n---\n\n# {walk}\n"),
        )
        .unwrap();
    }
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({
            "phases": {"framing": pin},
            "walks": ["sink-walk", "chain-walk"],
            "max_concurrent_walks": 1,
        })
        .to_string(),
    )
    .unwrap();
    Scene {
        _tmp: tmp,
        home,
        data,
        target,
    }
}

/// Run on a pseudo-terminal, typing `answer`. Returns everything the
/// terminal showed.
fn run_on_terminal(s: &Scene, run: &str, answer: &str) -> String {
    run_on_terminal_with(s, run, answer, "")
}

/// [`run_on_terminal`] with `flags` on the command line.
fn run_on_terminal_with(s: &Scene, run: &str, answer: &str, flags: &str) -> String {
    let command = format!(
        "{} lyrik run {flags} --target {} --run {}",
        shell_quote(env!("CARGO_BIN_EXE_wirken")),
        shell_quote(&s.target.display().to_string()),
        shell_quote(run)
    );
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .env("WIRKEN_DATA_DIR", &s.data)
        .env("HOME", &s.home)
        .env("NO_COLOR", "1")
        .env("WIRKEN_ASK_APPROVAL_TIMEOUT_S", "3")
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
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
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

fn docker_has(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The summary states the envelope in one line, and no longer says
/// each command is asked again.
#[test]
fn the_summary_states_the_envelope_for_a_per_walk_run() {
    const RUN: &str = "envelope-summary";
    let model = ScriptedModel::start(vec![]);
    let s = scene(&model);
    let shown = run_on_terminal(&s, RUN, "n\n");
    let envelope = "  envelope each exec runs in the sandbox with the target read-only, the \
                    walk's own staging directory writable, other walks' staging hidden and no \
                    network; this sign-off approves every exec inside it";
    let (at, question) = (
        shown.find(envelope),
        shown.find("Sign off this run? [y/N]: "),
    );
    assert!(
        at.is_some() && at < question,
        "missing the envelope line before the question in:\n{shown}"
    );
    assert!(
        !shown.contains("Each exec command is asked again"),
        "{shown}"
    );
}

/// One sign-off, no prompt for the walk's command, and the command
/// runs inside the envelope: it cannot write the target or see the
/// other walk's staging, and it can write its own.
#[test]
fn a_signed_off_walk_runs_exec_inside_the_envelope_without_asking() {
    const RUN: &str = "envelope";
    if !docker_has("debian:bookworm-slim") {
        eprintln!("skipping: Docker or debian:bookworm-slim is not available on this host");
        return;
    }
    let staging = format!(".lyrik/state/runs/{RUN}/staging");
    // Which walk goes first is not fixed, so the command tries both
    // walks' staging: one is the caller's own.
    let command = format!(
        "(echo t > src/pwned) 2>/dev/null; echo target_write=$?; \
         n=0; v=0; for w in sink-walk chain-walk; do \
           (echo t > {staging}/$w/out) 2>/dev/null && n=$((n+1)); \
           [ -n \"$(ls {staging}/$w)\" ] && v=$((v+1)); \
         done; echo staging_writes=$n; echo staging_visible=$v"
    );
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        // The first walk: one command, then done.
        call("exec", serde_json::json!({"command": command})),
        serde_json::json!({"role": "assistant", "content": "Done."}),
        // The second.
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let s = scene(&model);
    let shown = run_on_terminal(&s, RUN, "y\n");

    // Asked once, for the run.
    assert!(shown.contains("Sign off this run? [y/N]: "), "{shown}");
    assert!(!shown.contains("approve? [y/N]"), "asked again:\n{shown}");
    assert!(
        chain_rows(&s.data, "permission_denied").is_empty(),
        "{shown}"
    );

    // The command is on the chain as approved by the sign-off.
    let approved: Vec<_> = chain_rows(&s.data, "permission_approved")
        .into_iter()
        .filter(|r| {
            !r["action_key"]
                .as_str()
                .unwrap()
                .starts_with("lyrik:signoff:")
        })
        .collect();
    assert_eq!(approved.len(), 1, "{approved:?}\n{shown}");
    assert_eq!(approved[0]["approved_by"], "lyrik-signoff", "{approved:?}");
    // Nothing was asked at the terminal for it: the surface is the
    // sign-off, named by the row that recorded it.
    let signoff = chain_rows(&s.data, "permission_approved")
        .into_iter()
        .find(|r| {
            r["action_key"]
                .as_str()
                .unwrap()
                .starts_with("lyrik:signoff:")
        })
        .expect("the sign-off row");
    assert_eq!(
        signoff["approved_via"],
        serde_json::json!({"kind": "stdin"})
    );
    assert_eq!(
        approved[0]["approved_via"],
        serde_json::json!({"kind": "grant", "grant": signoff["action_key"]}),
        "{approved:?}"
    );
    assert_eq!(approved[0]["scope"], "one_shot");
    assert_eq!(chain_rows(&s.data, "assistant_tool_calls").len(), 1);

    // And it ran inside the envelope.
    let results = chain_rows(&s.data, "tool_result");
    assert_eq!(results.len(), 1, "{results:?}");
    let output = results[0]["output"].as_str().unwrap();
    assert!(results[0]["sandbox"].is_object(), "{results:?}");
    for line in ["staging_writes=1", "staging_visible=1"] {
        assert!(output.contains(line), "missing {line} in:\n{output}");
    }
    assert!(!output.contains("target_write=0"), "{output}");
    assert!(!s.target.join("src/pwned").exists());
    let written = ["sink-walk", "chain-walk"]
        .iter()
        .filter(|w| s.target.join(&staging).join(w).join("out").is_file())
        .count();
    assert_eq!(written, 1, "one walk's staging, its own");
}

/// A Python target on an image with no `python3`: the staged walk is
/// offered `sh` only, is told `python3` is not there, and is told the
/// sandbox shell does not expand braces. The probe is on the run's log.
#[test]
fn a_walk_is_told_what_the_sandbox_lacks_before_it_starts() {
    const RUN: &str = "sandbox-facts";
    if !docker_has("debian:bookworm-slim") {
        eprintln!("skipping: Docker or debian:bookworm-slim is not available on this host");
        return;
    }
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        serde_json::json!({"role": "assistant", "content": "Done."}),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let s = scene(&model);
    std::fs::write(s.target.join("agent.py"), "print('hi')\n").unwrap();
    // The installed walk reaches for a tool of its own.
    let installed = s.data.join("lyrik/walks/sink-walk/SKILL.md");
    std::fs::write(
        &installed,
        std::fs::read_to_string(&installed).unwrap() + "\nRun `git log -p` on each sink.\n",
    )
    .unwrap();
    let shown = run_on_terminal(&s, RUN, "y\n");

    let run_dir = s.target.join(format!(".lyrik/state/runs/{RUN}"));
    for walk in ["sink-walk", "chain-walk"] {
        let text =
            std::fs::read_to_string(run_dir.join("walks-skills").join(walk).join("SKILL.md"))
                .unwrap_or_else(|e| panic!("{walk}: {e}\n{shown}"));
        let harness = format!(".lyrik/state/runs/<run-id>/staging/{walk}/harness/<script>");
        assert!(
            text.contains(&format!("`sh {harness}`")),
            "{walk} is offered sh:\n{text}"
        );
        assert!(!text.contains("python3 .lyrik"), "{walk}:\n{text}");
        assert!(
            text.contains("The sandbox has no `python3`"),
            "{walk}:\n{text}"
        );
        assert!(text.contains("does not expand braces"), "{walk}:\n{text}");
        // Told there is none, the walk is shown no command that uses it.
        let brace_example = text
            .split(['`', ' ', '\n'])
            .any(|w| w.contains('{') && w.contains(',') && w.contains('}') && !w.contains('"'));
        assert!(!brace_example, "{walk} is shown a brace expansion:\n{text}");
        // The tools a walk commonly reaches for that the image lacks,
        // each with what to use instead.
        assert!(text.contains("no `rg`: use `grep -rn`"), "{walk}:\n{text}");
        assert!(text.contains("no `jq`:"), "{walk}:\n{text}");
        for present in ["`grep`:", "`find`:", "`sha256sum`:"] {
            assert!(
                !text.contains(&format!("no {present}")),
                "{walk}: {present}\n{text}"
            );
        }
    }
    // A tool only one walk's own text names is probed for that run.
    let sink = std::fs::read_to_string(run_dir.join("walks-skills/sink-walk/SKILL.md")).unwrap();
    assert!(sink.contains("no `git`"), "{sink}");
    let audit = std::fs::read_to_string(run_dir.join("audit.log")).unwrap();
    let probed: serde_json::Value = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.sandbox.probed")
        .unwrap_or_else(|| panic!("no lyrik.sandbox.probed row:\n{audit}"));
    assert_eq!(
        probed["detail"]["missing"],
        serde_json::json!(["python3", "rg", "jq", "git"])
    );
    assert_eq!(probed["detail"]["brace_expansion"], false);
    assert_eq!(probed["detail"]["image"], "debian:bookworm-slim");
}

/// A `--bench` run has no sign-off, so nothing approves its commands:
/// at a terminal each one is asked, as before.
#[test]
fn a_bench_run_at_a_terminal_still_asks_before_each_command() {
    const RUN: &str = "bench-asks";
    if !docker_has("debian:bookworm-slim") {
        eprintln!("skipping: Docker or debian:bookworm-slim is not available on this host");
        return;
    }
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call("exec", serde_json::json!({"command": "pwd"})),
        serde_json::json!({"role": "assistant", "content": "Done."}),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let s = scene(&model);
    // Nothing typed: the prompt is left unanswered.
    let shown = run_on_terminal_with(&s, RUN, "", "--bench");
    assert!(!shown.contains("Sign off this run?"), "{shown}");
    assert!(shown.contains("approve? [y/N]"), "{shown}");
    assert!(
        chain_rows(&s.data, "permission_approved").is_empty(),
        "{shown}"
    );
    assert_eq!(chain_rows(&s.data, "permission_denied").len(), 1, "{shown}");
}

/// The file tools are held to the same envelope: a walk writes only
/// its own staging directory, and reads of another walk's staging are
/// refused except the record files the staged index lists.
///
/// Which walk goes first is not fixed, so each step names both walks'
/// paths and exactly one of the pair is the caller's own.
#[test]
fn a_walks_file_tools_stay_inside_its_own_staging() {
    const RUN: &str = "file-envelope";
    const WALKS: [&str; 2] = ["sink-walk", "chain-walk"];
    let staging = format!(".lyrik/state/runs/{RUN}/staging");
    let finding = serde_json::json!({
        "id": "F001", "stable_id": "auth::src/auth.c:1", "framing": ["auth"],
        "location": {"file": "src/auth.c", "line_start": 1},
        "title": "stub", "summary": "stub", "tier": "LOW",
    })
    .to_string();
    let write = |path: String, content: &str| {
        call(
            "write_file",
            serde_json::json!({"path": path, "content": content}),
        )
    };
    let read = |path: String| call("read_file", serde_json::json!({"path": path}));
    let list = |path: String| call("list_files", serde_json::json!({"path": path}));
    // In both walks' staging, one call each.
    let both = |f: &dyn Fn(&str) -> serde_json::Value| WALKS.map(f).to_vec();

    let mut replies = vec![call("probe_ping", serde_json::json!({"marker": "ok"}))];
    // The first walk: a finding and a harness.
    replies.extend(both(&|w| {
        write(format!("{staging}/{w}/findings/finding-001.json"), &finding)
    }));
    replies.extend(both(&|w| {
        write(format!("{staging}/{w}/harness/h.sh"), "first\n")
    }));
    replies.push(serde_json::json!({"role": "assistant", "content": "Done."}));
    // The second walk: the same writes with other content, writes to
    // the run's own files, a path that climbs out of a staging
    // directory, then reads.
    replies.extend(both(&|w| {
        write(format!("{staging}/{w}/findings/finding-001.json"), &finding)
    }));
    replies.extend(both(&|w| {
        write(format!("{staging}/{w}/harness/h.sh"), "second\n")
    }));
    replies.push(write(format!("{staging}/index.json"), "[]"));
    replies.push(write(format!(".lyrik/state/runs/{RUN}/audit.log"), ""));
    replies.push(write("src/auth.c".to_string(), "pwned"));
    replies.extend(both(&|w| {
        let other = WALKS.iter().find(|o| **o != w).unwrap();
        write(format!("{staging}/{w}/../{other}/climbed"), "x")
    }));
    replies.extend(both(&|w| read(format!("{staging}/{w}/harness/h.sh"))));
    replies.extend(both(&|w| list(format!("{staging}/{w}"))));
    replies.extend(both(&|w| {
        read(format!("{staging}/{w}/findings/finding-001.json"))
    }));
    replies.push(read("src/auth.c".to_string()));
    replies.push(serde_json::json!({"role": "assistant", "content": "Done."}));
    let model = ScriptedModel::start(replies);
    let s = scene(&model);
    let out = wirken(&s.data)
        .env("HOME", &s.home)
        .args(["lyrik", "run", "--bench", "--target"])
        .arg(&s.target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = chain_rows(&s.data, "tool_result");
    let ok: Vec<bool> = rows
        .iter()
        .map(|r| r["success"].as_bool().unwrap())
        .collect();
    assert_eq!(ok.len(), 20, "{rows:#?}");
    // Of a pair naming both walks' staging, exactly one call is the
    // caller's own and goes through.
    let one_of = |at: usize, what: &str| {
        assert_eq!(
            ok[at..at + 2].iter().filter(|b| **b).count(),
            1,
            "{what}: {rows:#?}"
        );
    };
    one_of(0, "the first walk's finding");
    one_of(2, "the first walk's harness");
    one_of(4, "the second walk's finding");
    one_of(6, "the second walk's harness");
    // The run's own files and the target: not a walk's to write.
    assert_eq!(ok[8..11], [false, false, false], "{rows:#?}");
    // A path is the file it names: climbing out of the caller's own
    // staging is refused, and into it is its own.
    one_of(11, "a path that climbs between staging directories");
    // Another walk's harness and listing are refused; its indexed
    // finding is read, as the target is.
    one_of(13, "reading a harness");
    one_of(15, "listing a staging directory");
    assert_eq!(ok[17..20], [true, true, true], "{rows:#?}");

    // Each refusal is on the chain: one of each pair of writes, the
    // three run and target writes, a climb, a harness read, a listing.
    assert_eq!(chain_rows(&s.data, "skill_permission_denied").len(), 10);
    // Neither walk overwrote the other's harness, and the target is
    // as it was.
    let mut harness: Vec<String> = WALKS
        .iter()
        .map(|w| {
            std::fs::read_to_string(s.target.join(&staging).join(w).join("harness/h.sh")).unwrap()
        })
        .collect();
    harness.sort();
    assert_eq!(harness, ["first\n", "second\n"]);
    assert_eq!(
        std::fs::read_to_string(s.target.join("src/auth.c")).unwrap(),
        "int check(void) { return 0; }\n"
    );
}
