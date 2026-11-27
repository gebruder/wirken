//! A `wirken lyrik run` whose pin says `"auth": "plan"` runs on the plan
//! sign-in: it asks for no API key, and it does not start unless the
//! operator's `lyrik.json` sets a ceiling that holds for calls with no
//! recorded cost.
//!
//! Driven through the binary. Neither test reaches a model: the first is
//! refused before the vault is opened, the second at the vault, which
//! holds no sign-in.
mod common;

use std::path::Path;

use common::wirken;

const PASSPHRASE: &str = "lyrik-plan-test-passphrase";

fn write_target(data: &Path, target: &Path) {
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let config = serde_json::json!({
        "scope": {"include": ["src/**/*"], "exclude": []},
        "phases": {"framing": {"provider": "openai", "auth": "plan", "model": "gpt-plan"}},
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(common::lyrik_config(data, target), config.to_string()).unwrap();
}

/// Run the plan-pinned target with `settings` as the data directory's
/// `lyrik.json`, when given. Returns whether it succeeded, its output
/// and the data directory.
fn run(settings: Option<&str>) -> (bool, String, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap().keep();
    let (home, data, target) = (tmp.join("home"), tmp.join("data"), tmp.join("target"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    if let Some(settings) = settings {
        std::fs::write(data.join("lyrik.json"), settings).unwrap();
    }
    write_target(&data, &target);
    let out = wirken(&data)
        .env("HOME", &home)
        .env("WIRKEN_VAULT_PASSPHRASE", PASSPHRASE)
        .args(["lyrik", "run", "--bench", "--target"])
        .arg(&target)
        .args(["--run", "plan"])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), report, data)
}

#[test]
fn a_plan_run_does_not_start_without_a_ceiling_that_holds() {
    // No ceiling at all, and a cost ceiling on a model the price table
    // does not have, which has nothing to count.
    for settings in [None, Some(r#"{ "run_ceiling_usd": 20.0 }"#)] {
        let (ok, report, data) = run(settings);
        assert!(!ok, "{report}");
        assert!(
            report.contains("this run is on a plan, whose calls are not billed"),
            "{report}"
        );
        assert!(report.contains("`run_ceiling_model_seconds`"), "{report}");
        assert!(report.contains("`run_ceiling_model_calls`"), "{report}");
        assert!(
            report.contains(&data.join("lyrik.json").display().to_string()),
            "{report}"
        );
        // Refused before any credential was looked for.
        assert!(!data.join("vault.db").exists(), "{report}");
    }
}

#[test]
fn a_plan_run_asks_for_the_sign_in_and_for_no_api_key() {
    for settings in [
        r#"{ "run_ceiling_model_calls": 50 }"#,
        r#"{ "run_ceiling_model_seconds": 600 }"#,
    ] {
        let (ok, report, _) = run(Some(settings));
        assert!(!ok, "{report}");
        // The vault holds neither a sign-in nor an `openai-api-key`.
        // What the run stops on is the sign-in.
        assert!(
            report.contains("wirken credentials authorize openai-plan"),
            "{report}"
        );
        assert!(!report.contains("API key"), "{report}");
        assert!(!report.contains("openai-api-key"), "{report}");
    }
}
