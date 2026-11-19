//! A `wirken lyrik run` pinned to the `anthropic` provider with
//! `"auth": "plan"` makes no model call of its own. Each walk's turn is
//! run by a child process of the agent binary the operator's
//! `lyrik.json` names, which is given this run's tools over a tool
//! server and nothing else.
//!
//! Driven through the binary against `common/stub_child.py`, which
//! stands in for that agent binary: it speaks the tool protocol to the
//! run's tool server and writes the output stream a headless run
//! writes. No model is called.
mod common;

use std::path::{Path, PathBuf};

use common::wirken;

const RUN: &str = "child";
const PIN: &str = "pinned-large-9";
const SINK_PIN: &str = "pinned-small-9";

fn stub() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/stub_child.py").to_string()
}

/// The directory an agent binary reads project settings from.
fn agent_settings_dir() -> String {
    ".claude".to_string()
}

struct Run {
    ok: bool,
    report: String,
    data: PathBuf,
    target: PathBuf,
    /// One record per child the run started.
    children: Vec<serde_json::Value>,
    elapsed: std::time::Duration,
}

/// Run two walks, `sink-walk` on its own model and `chain-walk` on the
/// run pin, with the stub child doing `scenario` in every turn.
fn run(scenario: serde_json::Value, settings: serde_json::Value) -> Run {
    run_pinned(PIN, SINK_PIN, scenario, settings)
}

/// [`run`] with the run pinned to `pin` and `sink-walk` to `sink_pin`.
fn run_pinned(
    pin: &str,
    sink_pin: &str,
    scenario: serde_json::Value,
    settings: serde_json::Value,
) -> Run {
    let tmp = tempfile::tempdir().unwrap().keep();
    let (home, data, target) = (tmp.join("home"), tmp.join("data"), tmp.join("target"));
    std::fs::create_dir_all(&home).unwrap();
    for walk in ["sink-walk", "chain-walk"] {
        let dir = data.join("lyrik/walks").join(walk);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {walk}\ndescription: test walk\n---\n\n# {walk}\n\nWalk.\n"),
        )
        .unwrap();
    }
    let mut settings = settings;
    settings["plan_child_binary"] = stub().into();
    std::fs::write(data.join("lyrik.json"), settings.to_string()).unwrap();

    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    // A target that tries to configure the child: were the child
    // started here, or told to read project settings, this would be
    // its configuration.
    let agent_dir = agent_settings_dir();
    std::fs::create_dir_all(target.join(&agent_dir)).unwrap();
    std::fs::write(
        target.join(&agent_dir).join("settings.json"),
        r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "id"}]}]}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({
            "scope": {"include": ["src/**/*"], "exclude": []},
            "phases": {
                "framing": {"provider": "anthropic", "auth": "plan", "model": pin},
                "sink-walk": {"model": sink_pin},
            },
            "walks": ["sink-walk", "chain-walk"],
        })
        .to_string(),
    )
    .unwrap();

    let scenario_file = tmp.join("scenario.json");
    std::fs::write(&scenario_file, scenario.to_string()).unwrap();
    let log = tmp.join("children.jsonl");
    let started = std::time::Instant::now();
    let out = wirken(&data)
        .env("HOME", &home)
        .env("STUB_CHILD_SCENARIO", &scenario_file)
        .env("STUB_CHILD_LOG", &log)
        // What a metered key and the vault passphrase look like in the
        // environment a run is started from.
        .env("ANTHROPIC_API_KEY", "sk-test-not-a-key")
        .env("WIRKEN_VAULT_PASSPHRASE", "lyrik-plan-child-test")
        .args(["lyrik", "run", "--bench", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    let children = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        // A child ended while it was writing its record leaves a cut
        // line; that child is not counted.
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    Run {
        ok: out.status.success(),
        report: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        data,
        target,
        children,
        elapsed,
    }
}

fn bounded() -> serde_json::Value {
    serde_json::json!({"run_ceiling_model_calls": 50})
}

fn audit_rows(target: &Path, event: &str) -> Vec<serde_json::Value> {
    let audit =
        std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/audit.log"))).unwrap();
    audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["event"] == event)
        .map(|e| e["detail"].clone())
        .collect()
}

/// Every row of `kind` on the run's chain, as its JSON payload.
fn chain(data: &Path, kind: &str) -> Vec<serde_json::Value> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT payload FROM session_events
          WHERE json_extract(payload, '$.kind') = ?1 ORDER BY seq",
    )
    .unwrap()
    .query_map([kind], |r| r.get::<_, String>(0))
    .unwrap()
    .map(|p| serde_json::from_str(&p.unwrap()).unwrap())
    .collect()
}

/// A walk's turn is a child process started with this run's tools and
/// no other, outside the target, with the walk's own pinned model and
/// without the variables that would put its calls on a key. A tool it
/// calls goes through the run's gate: a read is answered, an `exec`
/// nobody can approve is refused, and both are on the chain.
#[test]
fn a_walk_runs_as_a_child_whose_tool_calls_pass_the_gate() {
    let r = run(
        serde_json::json!({"calls": [
            ["list_files", {}],
            ["exec", {"command": "git log -p -- src/auth.c"}],
        ], "reply": "Done."}),
        bounded(),
    );
    assert!(r.ok, "{}", r.report);
    assert_eq!(r.children.len(), 2, "one child per walk: {}", r.report);

    let mut models = Vec::new();
    for child in &r.children {
        let argv: Vec<&str> = child["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let after = |flag: &str| argv[argv.iter().position(|a| *a == flag).expect(flag) + 1];
        models.push(after("--model").to_string());
        assert_eq!(after("--tools"), "", "{argv:?}");
        assert_eq!(after("--setting-sources"), "", "{argv:?}");
        assert_eq!(after("--output-format"), "stream-json", "{argv:?}");
        assert!(argv.contains(&"--strict-mcp-config"), "{argv:?}");
        assert!(argv.contains(&"--no-session-persistence"), "{argv:?}");
        assert!(!argv.contains(&"--bare"), "{argv:?}");
        assert!(!argv.contains(&"--fallback-model"), "{argv:?}");

        // Outside the target, in a directory of its own.
        let cwd = Path::new(child["cwd"].as_str().unwrap());
        assert!(!cwd.starts_with(&r.target), "{}", cwd.display());
        assert!(!cwd.join(agent_settings_dir()).exists());
        // The model is told the child's directory is not where the
        // files are, by the directory's name and in the system prompt.
        assert!(cwd.ends_with("not-the-workspace"), "{}", cwd.display());
        let system_prompt = child["system_prompt"].as_str().unwrap();
        assert!(
            system_prompt.contains("is an empty scratch directory outside the workspace"),
            "{system_prompt}"
        );
        assert!(
            system_prompt.contains("Give every tool a path relative to the workspace root"),
            "{system_prompt}"
        );

        let env: Vec<&str> = child["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(!env.contains(&"ANTHROPIC_API_KEY"), "{env:?}");
        assert!(!env.contains(&"WIRKEN_VAULT_PASSPHRASE"), "{env:?}");

        // The run's tools, served to it; the walk's skill in the
        // system prompt it was handed.
        let listed: Vec<&str> = child["listed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert!(listed.contains(&"list_files"), "{listed:?}");
        assert!(listed.contains(&"exec"), "{listed:?}");
        assert!(!listed.contains(&"spawn_subagent"), "{listed:?}");
        assert_eq!(child["discover_was_refused"], true);
        assert!(
            child["prompt"].as_str().unwrap().contains("Walk."),
            "{}",
            child["prompt"]
        );

        // The read was answered; the exec was refused and said so.
        let answers = child["answers"].as_array().unwrap();
        assert_eq!(answers[0]["isError"], false, "{answers:?}");
        assert!(
            answers[0]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("src/"),
            "{answers:?}"
        );
        assert_eq!(answers[1]["isError"], true, "{answers:?}");
        assert!(
            answers[1]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Permission denied: 'exec'"),
            "{answers:?}"
        );
    }
    models.sort();
    assert_eq!(models, [PIN, SINK_PIN], "each walk on its own pin");

    // On the chain: each call the children made, its result, and the
    // refusal.
    let called: Vec<String> = chain(&r.data, "assistant_tool_calls")
        .iter()
        .map(|row| {
            format!(
                "{} {}",
                row["step"].as_str().unwrap(),
                row["calls"][0]["name"].as_str().unwrap()
            )
        })
        .collect();
    for expected in [
        "sink-walk list_files",
        "sink-walk exec",
        "chain-walk list_files",
        "chain-walk exec",
    ] {
        assert!(called.contains(&expected.to_string()), "{called:?}");
    }
    assert_eq!(chain(&r.data, "tool_result").len(), 4);
    assert_eq!(chain(&r.data, "permission_denied").len(), 2);
    // Each child's opening message is on the chain: the tools it
    // listed, every one this run's, the one tool server and its
    // status, and what it authenticates with.
    let opened = chain(&r.data, "child_opened");
    assert_eq!(opened.len(), 2, "{opened:?}");
    let mut steps = Vec::new();
    for row in &opened {
        steps.push(row["step"].as_str().unwrap().to_string());
        let tools: Vec<&str> = row["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert!(tools.contains(&"mcp__wirken__exec"), "{tools:?}");
        assert!(
            tools.iter().all(|t| t.starts_with("mcp__wirken__")),
            "{tools:?}"
        );
        assert_eq!(
            row["servers"],
            serde_json::json!([{"name": "wirken", "status": "connected"}]),
            "{row}"
        );
        assert_eq!(row["key_source"], "none", "{row}");
        assert!(row.get("refused").is_none(), "{row}");
    }
    steps.sort();
    assert_eq!(steps, ["chain-walk", "sink-walk"]);
    for completed in audit_rows(&r.target, "lyrik.walk.completed") {
        assert_eq!(completed["status"], "turn_ended", "{completed}");
        assert_eq!(
            completed["skipped"],
            serde_json::json!(["exec (shell:git)"]),
            "{completed}"
        );
    }
    // The pin on the walk's started row, as on any run.
    let mut started: Vec<(String, String)> = audit_rows(&r.target, "lyrik.walk.started")
        .iter()
        .map(|d| {
            (
                d["walk"].as_str().unwrap().to_string(),
                d["model"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    started.sort();
    assert_eq!(
        started,
        [
            ("chain-walk".to_string(), PIN.to_string()),
            ("sink-walk".to_string(), SINK_PIN.to_string()),
        ]
    );
}

/// Each model call a child made is one `llm_response` row, marked as
/// reported by the child, with the walk as its step, the model the
/// child reported, the tokens it reported and no cost. There is no
/// request row and no credential: this process sent nothing.
#[test]
fn each_reported_step_is_a_marked_row_with_step_model_and_tokens() {
    for streamless in [false, true] {
        let r = run(
            serde_json::json!({"calls": [["list_files", {}]], "reply": "Done.",
                "streamless": streamless}),
            bounded(),
        );
        assert!(r.ok, "{}", r.report);
        assert_eq!(
            chain(&r.data, "llm_request"),
            Vec::<serde_json::Value>::new()
        );

        let rows = chain(&r.data, "llm_response");
        assert_eq!(rows.len(), 4, "two steps a walk: {rows:?}");
        for (walk, model) in [("sink-walk", SINK_PIN), ("chain-walk", PIN)] {
            let of_walk: Vec<&serde_json::Value> =
                rows.iter().filter(|row| row["step"] == walk).collect();
            assert_eq!(of_walk.len(), 2, "{rows:?}");
            for row in &of_walk {
                assert_eq!(
                    row["reported"],
                    serde_json::json!({"by": "child", "model": model, "key_source": "none"}),
                    "{row}"
                );
                assert_eq!(row["cache_read_input_tokens"], 1000, "{row}");
                assert_eq!(row["cache_creation_input_tokens"], 10, "{row}");
                for absent in [
                    "credential_id",
                    "total_cost_usd_micros",
                    "input_cost_usd_micros",
                    "output_cost_usd_micros",
                ] {
                    assert!(row.get(absent).is_none(), "{absent}: {row}");
                }
            }
            // The first step called a tool, the second ended the turn.
            assert_eq!(
                (
                    &of_walk[0]["input_tokens"],
                    &of_walk[0]["output_tokens"],
                    &of_walk[0]["stop_reason"]
                ),
                (
                    &serde_json::json!(101),
                    &serde_json::json!(21),
                    &serde_json::json!("tool_use")
                ),
                "{}",
                of_walk[0]
            );
            assert_eq!(of_walk[1]["output_tokens"], 30, "{}", of_walk[1]);
            assert_eq!(of_walk[1]["stop_reason"], "end_turn", "{}", of_walk[1]);
        }
        // The run says its cost is not recorded and which ceiling held.
        // These pins have no price entry, so nothing is estimated,
        // and the run says so.
        assert!(
            r.report.contains(
                "cost: nothing billed, the run was on the plan the child process is signed in \
                 to; an estimated $0.00 at API rates over 4 model call(s), 4 of them with no \
                 price entry and not estimated"
            ),
            "{}",
            r.report
        );
        for row in &rows {
            assert!(row.get("estimated_cost_usd_micros").is_none(), "{row}");
        }
        assert!(
            r.report
                .contains("model-call ceiling 50: not reached (4 made)"),
            "{}",
            r.report
        );
    }
}

/// A child whose opening message lists a tool that is not this run's
/// is stopped there: nothing is asked of it, no tool call is served,
/// and every walk fails with the tool named.
#[test]
fn a_child_with_a_tool_that_is_not_the_runs_is_refused() {
    let r = run(
        serde_json::json!({"tools": ["Bash"], "calls": [["list_files", {}]]}),
        bounded(),
    );
    assert!(!r.ok, "{}", r.report);
    assert!(
        r.report.contains(
            "the child process has tools that are not Wirken's (Bash); the run is refused"
        ),
        "{}",
        r.report
    );
    assert_eq!(chain(&r.data, "llm_response").len(), 0);
    assert_eq!(chain(&r.data, "tool_result").len(), 0);
    // What the refused child had is on the chain, with why.
    let opened = chain(&r.data, "child_opened");
    assert_eq!(opened.len(), 2, "one a walk: {opened:?}");
    for row in &opened {
        let tools = row["tools"].as_array().unwrap();
        assert!(tools.contains(&serde_json::json!("Bash")), "{row}");
        assert!(
            row["refused"]
                .as_str()
                .unwrap()
                .contains("not Wirken's (Bash)"),
            "{row}"
        );
    }

    // So is one that says it is on an API key.
    let keyed = run(serde_json::json!({"key_source": "user"}), bounded());
    assert!(!keyed.ok, "{}", keyed.report);
    assert!(
        keyed.report.contains("authenticates with an API key"),
        "{}",
        keyed.report
    );
    assert_eq!(chain(&keyed.data, "llm_response").len(), 0);
}

/// A step answered by a model that is not the walk's pin fails the
/// walk. The step is on the chain under the model the child reported.
#[test]
fn a_step_by_another_model_fails_the_walk() {
    let r = run(
        serde_json::json!({"model": "another-model-1", "calls": [["list_files", {}]]}),
        bounded(),
    );
    assert!(!r.ok, "{}", r.report);
    for pin in [PIN, SINK_PIN] {
        assert!(
            r.report.contains(&format!(
                "the child process reported the model `another-model-1` where the pin is `{pin}`"
            )),
            "{}",
            r.report
        );
    }
    let rows = chain(&r.data, "llm_response");
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        assert_eq!(row["reported"]["model"], "another-model-1", "{row}");
    }
    // The step was stopped before its tool call was served.
    assert_eq!(chain(&r.data, "tool_result").len(), 0);
}

/// A run on this route needs a ceiling that holds without a price, and
/// reaching it ends the children: a child that would have gone on for
/// a minute is stopped when the run's model calls reach the ceiling.
#[test]
fn a_ceiling_ends_the_children() {
    let unbounded = run(serde_json::json!({}), serde_json::json!({}));
    assert!(!unbounded.ok, "{}", unbounded.report);
    assert!(
        unbounded.report.contains("`run_ceiling_model_calls`"),
        "{}",
        unbounded.report
    );
    assert_eq!(unbounded.children.len(), 0, "no child was started");

    let r = run(
        serde_json::json!({"calls": [["list_files", {}]], "hang": 60}),
        serde_json::json!({"run_ceiling_model_calls": 2}),
    );
    assert!(
        r.report
            .contains("the run reached its model-call ceiling of 2 (2 model calls recorded)"),
        "{}",
        r.report
    );
    assert!(
        r.elapsed < std::time::Duration::from_secs(40),
        "the children were not ended: {:?}\n{}",
        r.elapsed,
        r.report
    );
    assert!(
        r.report.contains("stopped at the run's model-call ceiling"),
        "{}",
        r.report
    );
    assert_eq!(chain(&r.data, "llm_response").len(), 2);
}

/// Two models the price table has, as a run on this route pins them.
const PRICED_LARGE: &str = "claude-sonnet-4-6";
const PRICED_SMALL: &str = "claude-haiku-4-5";

/// A plan call is not billed, and its row says what it would have cost
/// at API rates, in a field of its own beside the cost fields, which
/// stay absent. The run may start on a cost ceiling alone, held
/// against that estimate. The summary and `findings.json` give the
/// estimate by walk and model and say nothing was billed, and each
/// walk's completed row carries the figure corrected against the
/// child's final count, with the child's own cost figure beside it.
#[test]
fn a_plan_runs_cost_is_an_estimate_at_api_rates_by_walk_and_model() {
    let r = run_pinned(
        PRICED_LARGE,
        PRICED_SMALL,
        serde_json::json!({"calls": [["list_files", {}]], "reply": "Done."}),
        serde_json::json!({"run_ceiling_usd": 5.0}),
    );
    assert!(r.ok, "{}", r.report);

    let rows = chain(&r.data, "llm_response");
    assert_eq!(rows.len(), 4, "{rows:?}");
    let estimate_of = |walk: &str| -> u64 {
        rows.iter()
            .filter(|row| row["step"] == walk)
            .map(|row| {
                assert!(row.get("total_cost_usd_micros").is_none(), "{row}");
                row["estimated_cost_usd_micros"]
                    .as_u64()
                    .expect("an estimate")
            })
            .sum()
    };
    let (small, large) = (estimate_of("sink-walk"), estimate_of("chain-walk"));
    // The same tokens on the two models: the larger costs more.
    assert!(small > 0 && large > small, "{small} {large}");

    for said in [
        "cost: nothing billed, the run was on the plan the child process is signed in to; an \
         estimated $",
        "cost ceiling $5.00 on estimated cost: not reached",
        "estimated cost at API rates, by step and model (nothing billed):",
        &format!("  sink-walk on {PRICED_SMALL}: $"),
        &format!("  chain-walk on {PRICED_LARGE}: $"),
        "  walk sink-walk: $",
    ] {
        assert!(r.report.contains(said), "{said}\n{}", r.report);
    }

    let findings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            r.target
                .join(format!(".lyrik/state/runs/{RUN}/findings.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let cost = &findings["cost"];
    assert_eq!(cost["priced"], false, "{cost}");
    assert_eq!(cost["spend"]["usd_micros"], 0, "{cost}");
    assert_eq!(
        cost["spend"]["estimated_usd_micros"],
        small + large,
        "{cost}"
    );
    let estimate = &cost["estimate"];
    assert_eq!(estimate["billed"], false, "{estimate}");
    assert_eq!(estimate["total_usd_micros"], small + large, "{estimate}");
    let mut lines: Vec<(String, String, u64, u64)> = estimate["by_step_and_model"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["step"].as_str().unwrap().to_string(),
                l["model"].as_str().unwrap().to_string(),
                l["calls"].as_u64().unwrap(),
                l["estimated_usd_micros"].as_u64().unwrap(),
            )
        })
        .collect();
    lines.sort();
    assert_eq!(
        lines,
        [
            ("chain-walk".to_string(), PRICED_LARGE.to_string(), 2, large),
            ("sink-walk".to_string(), PRICED_SMALL.to_string(), 2, small),
        ]
    );

    // Each walk's completed row: the steps' sum, the child's final
    // count priced at the same rates, which is the corrected figure,
    // and the child's own cost figure with how far it is from ours.
    for completed in audit_rows(&r.target, "lyrik.walk.completed") {
        let walk = completed["walk"].as_str().unwrap();
        let cost = &completed["estimated_cost"];
        let steps = if walk == "sink-walk" { small } else { large };
        assert_eq!(cost["billed"], false, "{cost}");
        assert_eq!(cost["steps_estimated_usd_micros"], steps, "{cost}");
        let corrected = cost["corrected_usd_micros"].as_u64().unwrap();
        assert_eq!(cost["summary_estimated_usd_micros"], corrected, "{cost}");
        // The stub's final count differs from its steps', as a real
        // child's does where a step's output count was a placeholder.
        assert_ne!(corrected, steps, "{cost}");
        assert_eq!(
            cost["correction_usd_micros"].as_i64().unwrap(),
            corrected as i64 - steps as i64,
            "{cost}"
        );
        assert_eq!(cost["child_reported_usd_micros"], 12_300, "{cost}");
        assert_eq!(
            cost["child_reported_less_corrected_usd_micros"]
                .as_i64()
                .unwrap(),
            12_300 - corrected as i64,
            "{cost}"
        );
        let in_summary = findings["walk_summary"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["walk"] == walk)
            .unwrap();
        assert_eq!(&in_summary["estimated_cost"], cost, "{in_summary}");
    }
    let corrected_total = estimate["corrected_total_usd_micros"].as_u64().unwrap();
    let walks_corrected: u64 = estimate["walks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["corrected_usd_micros"].as_u64().unwrap())
        .sum();
    assert_eq!(corrected_total, walks_corrected, "{estimate}");
}

/// The cost ceiling stops a plan run on its estimate, and says the
/// figure is one. Where a pinned model has no price entry there is
/// nothing to hold the ceiling against, and the run does not start on
/// it alone.
#[test]
fn the_cost_ceiling_holds_a_plan_run_on_its_estimate() {
    let r = run_pinned(
        PRICED_LARGE,
        PRICED_SMALL,
        serde_json::json!({"calls": [["list_files", {}]], "hang": 60}),
        serde_json::json!({"run_ceiling_usd": 0.0001}),
    );
    assert!(
        r.report.contains("the run reached its cost ceiling of $0.00 ($0.00 estimated at API rates, nothing billed, over 2 model calls)"),
        "{}",
        r.report
    );
    assert!(
        r.elapsed < std::time::Duration::from_secs(40),
        "{:?}\n{}",
        r.elapsed,
        r.report
    );
    assert!(
        r.report
            .contains("stopped at the cost ceiling of $0.00 on estimated cost"),
        "{}",
        r.report
    );

    let unpriced = run(
        serde_json::json!({}),
        serde_json::json!({"run_ceiling_usd": 5.0}),
    );
    assert!(!unpriced.ok, "{}", unpriced.report);
    assert!(
        unpriced.report.contains(
            "anthropic pinned-large-9 has no price entry, so its calls cannot be estimated"
        ),
        "{}",
        unpriced.report
    );
    assert_eq!(unpriced.children.len(), 0);
}

/// A call's model time is the child's wait on the model: from when it
/// could next ask to the end of the reply. The child starts a tool the
/// reply names before the reply ends, and the time the tool takes is
/// not model time and does not erase it. The child's own figure is on
/// the walk's completed row beside the rows' sum, and the time ceiling
/// holds on it.
#[test]
fn model_time_is_the_wait_on_the_model_and_the_time_ceiling_holds() {
    let r = run(
        serde_json::json!({"calls": [["list_files", {}]], "think": 0.4, "reply": "Done."}),
        bounded(),
    );
    assert!(r.ok, "{}", r.report);
    let rows = chain(&r.data, "llm_response");
    assert_eq!(rows.len(), 4, "{rows:?}");
    for row in &rows {
        let ms = row["latency_ms"].as_u64().unwrap();
        assert!((350..5000).contains(&ms), "{ms} ms: {row}");
    }
    for completed in audit_rows(&r.target, "lyrik.walk.completed") {
        let cost = &completed["estimated_cost"];
        let ours = cost["model_millis"].as_u64().unwrap();
        assert!((700..10_000).contains(&ours), "{cost}");
        assert_eq!(cost["child_reported_api_millis"], 800, "{cost}");
    }

    // A second of model time, used up by the first calls: the children
    // are ended though they would have gone on for a minute.
    let stopped = run(
        serde_json::json!({"calls": [["list_files", {}]], "think": 0.7, "hang": 60}),
        serde_json::json!({"run_ceiling_model_seconds": 1}),
    );
    assert!(
        stopped
            .report
            .contains("the run reached its model-time ceiling of 1 second(s)"),
        "{}",
        stopped.report
    );
    assert!(
        stopped.elapsed < std::time::Duration::from_secs(40),
        "{:?}",
        stopped.elapsed
    );
}
