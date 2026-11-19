//! A citation is `resolved` only when the cited lines hold the text the
//! finding quotes. A quote that sits elsewhere in the file, once,
//! corrects the lines and says so; one found nowhere, or in several
//! places, is a `mismatch`; a finding that quotes nothing is `unquoted`.
//!
//! Driven through the binary with a scripted model. The target has its
//! sinks where a real sample had them (lines 22, 29, 36 and 39 to 43)
//! and the findings cite the lines a walk gave for it (26 and 32).

mod common;

use common::{ScriptedModel, wirken};

const RUN: &str = "quotes";

/// 43 lines: `eval` on 22, `requests.get` on 29, `subprocess.run` on
/// 36, `build_prompt` on 39 to 43.
fn target_source() -> String {
    let mut lines: Vec<String> = (1..=43).map(|n| format!("# line {n}")).collect();
    let mut put = |n: usize, text: &str| lines[n - 1] = text.to_string();
    put(13, "import subprocess");
    put(18, "@tool");
    put(19, "def analyze_data(expr):");
    put(22, "    return str(eval(expr))");
    put(25, "@tool");
    put(26, "def fetch_dataset(url):");
    put(29, "    return requests.get(url, timeout=10).content");
    put(32, "@tool");
    put(33, "def shell_inspect(cmd):");
    put(
        36,
        "    return subprocess.run(cmd, shell=True, capture_output=True).stdout",
    );
    put(39, "def build_prompt(user_input):");
    put(43, "    return f\"Answer the question: {user_input}\"");
    lines.join("\n") + "\n"
}

fn finding(class: &str, line: u64, extra: serde_json::Value) -> serde_json::Value {
    let mut f = serde_json::json!({
        "id": format!("{class}::agent.py:{line}"),
        "stable_id": format!("{class}::agent.py:{line}"),
        "framing": [class],
        "location": {"file": "agent.py", "line_start": line},
        "title": format!("{class} finding"),
        "summary": "A caller-controlled value reaches the sink.",
        "tier": "HIGH",
        "threat_model": {
            "attacker_capability": "controls the argument",
            "harm_path": "reaches the sink",
        },
    });
    for (k, v) in extra.as_object().unwrap() {
        if k == "quote" {
            f["location"]["quote"] = v.clone();
        } else {
            f[k] = v.clone();
        }
    }
    f
}

#[test]
fn resolved_means_the_cited_lines_hold_the_quoted_text() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    let walk = data.join("lyrik/walks/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n",
    )
    .unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("agent.py"), target_source()).unwrap();

    let staged = [
        // Cited at 26, quoted text on 29; the function it names cited
        // at 32, defined on 39.
        finding(
            "network_access",
            26,
            serde_json::json!({
                "quote": "return requests.get(url, timeout=10).content",
                "origin": {"file": "agent.py", "function": "build_prompt", "line_start": 32},
            }),
        ),
        // Cited where the quoted text is.
        finding(
            "code_injection",
            22,
            serde_json::json!({"quote": "return str(eval(expr))"}),
        ),
        // Quoted text that is nowhere in the file.
        finding(
            "shell_sink",
            30,
            serde_json::json!({"quote": "os.system(cmd)"}),
        ),
        // Quoted text on three lines, none of them the one cited.
        finding("auth", 5, serde_json::json!({"quote": "@tool"})),
        // No quote at all.
        finding("memory_safety", 40, serde_json::json!({})),
    ];
    let calls: Vec<serde_json::Value> = staged
        .iter()
        .enumerate()
        .map(|(i, f)| {
            serde_json::json!({"function": {"name": "write_file", "arguments": {
                "path": format!(
                    ".lyrik/state/runs/{RUN}/staging/sink-walk/findings/finding-{:03}.json",
                    i + 1
                ),
                "content": f.to_string(),
            }}})
        })
        .collect();
    let model = ScriptedModel::start(vec![
        serde_json::json!({"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "probe_ping", "arguments": {"marker": "ok"}}}
        ]}),
        serde_json::json!({"role": "assistant", "content": "", "tool_calls": calls}),
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
    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--bench", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/findings.json")))
            .unwrap(),
    )
    .unwrap();
    let by_class = |class: &str| -> serde_json::Value {
        body["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["framing"][0] == class)
            .unwrap_or_else(|| panic!("no {class} finding in {body}"))
            .clone()
    };

    // One match elsewhere: the lines are corrected, and it says so.
    let moved = by_class("network_access");
    assert_eq!(moved["citation_check"]["status"], "resolved", "{moved}");
    assert_eq!(moved["location"]["line_start"], 29, "{moved}");
    assert_eq!(moved["citation_check"]["corrected_from"], 26, "{moved}");
    assert_eq!(moved["origin"]["line_start"], 39, "{moved}");
    assert_eq!(
        moved["citation_check"]["origin_corrected_from"], 32,
        "{moved}"
    );

    // The quoted text is on the cited line: resolved, nothing moved.
    let exact = by_class("code_injection");
    assert_eq!(exact["citation_check"]["status"], "resolved", "{exact}");
    assert_eq!(exact["location"]["line_start"], 22, "{exact}");
    assert!(
        exact["citation_check"].get("corrected_from").is_none(),
        "{exact}"
    );

    // None, and several: a mismatch, with the lines left as cited.
    let nowhere = by_class("shell_sink");
    assert_eq!(nowhere["citation_check"]["status"], "mismatch", "{nowhere}");
    assert_eq!(nowhere["location"]["line_start"], 30, "{nowhere}");
    let several = by_class("auth");
    assert_eq!(several["citation_check"]["status"], "mismatch", "{several}");
    assert!(
        several["citation_check"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("3 lines")),
        "{several}"
    );

    // Nothing quoted: nothing to hold the lines to.
    let bare = by_class("memory_safety");
    assert_eq!(bare["citation_check"]["status"], "unquoted", "{bare}");

    // The run's tally says the same.
    let tally = &body["citation_check"];
    assert_eq!(tally["corrected"], 1, "{tally}");
    assert_eq!(tally["mismatch"], 2, "{tally}");
    assert_eq!(tally["unquoted"], 1, "{tally}");
}
