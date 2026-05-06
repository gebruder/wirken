//! Regression test: workspace `.env` files cannot influence Wirken
//! runtime configuration.
//!
//! This pins the structural property that Wirken does not read
//! workspace-resident `.env` files into its process environment. With
//! no `.env` reader anywhere, no value placed in a workspace `.env`
//! can enter the gateway's env, and therefore none can reach a child
//! process spawned by the gateway through env inheritance.
//!
//! Mapped CVE/GHSA shapes from the qclawer-credited cluster against
//! OpenClaw:
//! - CVE-2026-43531: workspace `.env` env-var injection
//! - GHSA-jx3c-247h-cxwp: `.env` overrides bundled hooks root
//! - GHSA-hxvm-xjvf-93f3: `.env` overrides runtime-control env vars
//! - GHSA-55cf-xx38-4p9p: `.env` overrides connector endpoint hosts
//! - GHSA-h2vw-ph2c-jvwf: `.env` MiniMax host override
//! - GHSA-mj59-h3q9-ghfh: MCP stdio server env from workspace config
//!
//! The test has three parts. Each is independent; any one regressing
//! is enough to flag.
//!
//! 1. Dependency check. Walk `Cargo.lock` and assert no
//!    dotenv-shaped crate is present in the resolved dependency
//!    graph.
//! 2. Source check. Walk every `.rs` file under `crates/` and assert
//!    no source line reads `.env` as a config file.
//! 3. Behavioral check. Drop a `.env` at the temp cwd containing
//!    entries that would steer Wirken if read, then construct
//!    `GatewayConfig::default()` and confirm the resolved values
//!    match the documented defaults from
//!    `crates/gateway/src/config.rs:29` rather than the `.env`.

use std::io::Read;
use std::path::{Path, PathBuf};

use wirken_gateway::config::GatewayConfig;

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has two parents")
        .to_path_buf()
}

#[test]
fn no_dotenv_crate_in_resolved_dependencies() {
    let lock = workspace_root().join("Cargo.lock");
    let mut body = String::new();
    std::fs::File::open(&lock)
        .unwrap_or_else(|e| panic!("open {}: {e}", lock.display()))
        .read_to_string(&mut body)
        .expect("read Cargo.lock");

    // Cargo.lock has stanzas like:
    //   [[package]]
    //   name = "foo"
    //   version = "1.2.3"
    // A dotenv-shaped crate would surface as `name = "dotenv"`,
    // `name = "dotenvy"`, `name = "envfile"`, or similar. Match the
    // exact `name = "..."` line so a substring elsewhere doesn't
    // false-positive.
    let banned = [
        "dotenv",
        "dotenvy",
        "envfile",
        "dotenv_codegen",
        "dotenv-flow",
    ];
    for crate_name in banned {
        let needle = format!("name = \"{crate_name}\"");
        assert!(
            !body.contains(&needle),
            "Cargo.lock declares `{crate_name}` as a resolved dependency. \
             Workspace `.env` reading must not enter the dependency \
             graph; if a downstream crate pulled this in, audit the \
             chain and either drop it or document why it is safe."
        );
    }
}

#[test]
fn no_source_file_reads_dot_env() {
    let crates = workspace_root().join("crates");
    let mut offenders = Vec::new();
    walk_rust(&crates, &mut |path| {
        // Skip target dirs and this very test file (it mentions
        // `.env` strings as documentation).
        let s = path.to_string_lossy();
        if s.contains("/target/") || s.ends_with("no_workspace_dotenv.rs") {
            return;
        }
        let Ok(body) = std::fs::read_to_string(path) else {
            return;
        };
        for (idx, line) in body.lines().enumerate() {
            // Skip comment lines so docstrings that mention `.env`
            // don't false-positive.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            // Active-code mentions of dotenv-shaped readers.
            let needles = [
                "dotenv::",
                "dotenvy::",
                "dotenv!",
                "dotenvy!",
                "from_filename(\".env\")",
                "from_path(\".env\")",
                "dotenv()",
                "dotenvy()",
            ];
            for n in needles {
                if line.contains(n) {
                    offenders.push(format!("{}:{}: contains `{}`", path.display(), idx + 1, n));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "found dotenv-shaped reader(s) in source tree:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn workspace_dot_env_does_not_steer_gateway_config() {
    // Place a `.env` in a temp dir. If anything in the construction
    // path of GatewayConfig::default() were to consult workspace
    // `.env`, the resolved data_dir or related fields would shift to
    // the values planted here.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let env_path = tmp.path().join(".env");
    std::fs::write(
        &env_path,
        // Entries chosen to mirror Wirken-shaped keys an attacker
        // might plant. None of these are read.
        "WIRKEN_DATA_DIR=/tmp/attacker-controlled\n\
         WIRKEN_VAULT_PASSPHRASE=bogus\n\
         WIRKEN_SOCKET=/tmp/attacker.sock\n\
         GATEWAY_URL=http://attacker.example/config\n\
         WIRKEN_AGENT_CACHE_SIZE=999999\n\
         WIRKEN_TEAMS_PORT=80\n\
         WIRKEN_SLACK_APP_TOKEN=xapp-attacker\n\
         WIRKEN_CACHE_MODE=disabled\n",
    )
    .expect("write .env");

    // Snapshot the parent-process env keys the .env attempts to set,
    // before the GatewayConfig construction. If the construction
    // somehow loaded the file, our process env would gain entries.
    let attacker_keys = [
        "WIRKEN_DATA_DIR",
        "WIRKEN_VAULT_PASSPHRASE",
        "WIRKEN_SOCKET",
        "GATEWAY_URL",
        "WIRKEN_AGENT_CACHE_SIZE",
        "WIRKEN_TEAMS_PORT",
        "WIRKEN_SLACK_APP_TOKEN",
        "WIRKEN_CACHE_MODE",
    ];
    // For correctness of this assertion, the caller's environment
    // must not already have these set. The dependency- and source-
    // grep tests above are the structural guarantee; this is the
    // behavioral cross-check. Skip the value compare for any key
    // that the parent environment already had set, so a developer
    // running the suite with one of these legitimately exported
    // does not see a spurious failure.
    let preexisting: Vec<(&str, Option<String>)> = attacker_keys
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();

    // Run the construction in the temp cwd. `set_current_dir` is
    // process-wide, so we restore it before returning.
    let original_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(tmp.path()).expect("chdir tmp");
    let cfg = GatewayConfig::default();
    std::env::set_current_dir(&original_cwd).expect("restore cwd");

    // After construction, the parent-process env must not have
    // gained any attacker key it did not already have.
    for (key, before) in &preexisting {
        let after = std::env::var(key).ok();
        assert_eq!(
            &after, before,
            "GatewayConfig::default() loaded `{key}` from \
             workspace `.env` (process env changed). \
             Reference: crates/gateway/src/config.rs:29"
        );
    }

    // GatewayConfig::default() must produce the documented defaults
    // (config.rs:29-41), not the `.env` values. The data_dir is
    // HOME-derived (config.rs:111-120) and must not equal the
    // attacker path.
    let attacker_data_dir = Path::new("/tmp/attacker-controlled");
    assert_ne!(
        cfg.data_dir, attacker_data_dir,
        "GatewayConfig::data_dir resolved to the workspace `.env` value"
    );

    // Numeric defaults from config.rs:33-38.
    assert_eq!(cfg.session_expiry_secs, 86400);
    assert_eq!(cfg.audit_retention_days, 90);
    assert_eq!(cfg.auth_rate_limit_max, 5);
    assert_eq!(cfg.auth_rate_limit_window_secs, 60);
    assert_eq!(cfg.auth_rate_limit_lockout_secs, 600);
    assert_eq!(cfg.control_plane_rate_limit, 10);
}

fn walk_rust(dir: &Path, callback: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rust(&path, callback);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            callback(&path);
        }
    }
}
