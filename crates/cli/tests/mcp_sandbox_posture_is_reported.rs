//! `wirken mcp verify` and `wirken doctor` say which stdio MCP servers
//! the proxy will refuse for want of a sandbox block, and which run on
//! the host because their entry turns the sandbox off, before the
//! gateway is started.

use std::process::Command;

fn wirken(data_dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(args)
        .env("WIRKEN_DATA_DIR", data_dir)
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn data_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mcp.json"),
        r#"{"servers": {
            "legacy": {"command": "/usr/bin/legacy-server"},
            "hosted": {"command": "/usr/bin/hosted-server", "sandbox": "off"},
            "boxed": {"command": "/usr/bin/boxed-server", "sandbox": {"image": "img"}}
        }}"#,
    )
    .unwrap();
    dir
}

#[test]
fn mcp_verify_notes_the_refused_and_the_unsandboxed() {
    let dir = data_dir();
    let out = wirken(dir.path(), &["mcp", "verify"]);
    let line_after = |name: &str| {
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.trim_start().starts_with(name))
            .unwrap_or_else(|| panic!("{name} missing:\n{out}"));
        lines.get(i + 1).copied().unwrap_or_default().to_string()
    };
    assert!(
        line_after("legacy").contains("no sandbox block: the proxy will not start it"),
        "{out}"
    );
    assert!(
        line_after("hosted").contains("runs on the host, unsandboxed"),
        "{out}"
    );
    assert!(!line_after("boxed").contains("sandbox"), "{out}");
}

#[test]
fn doctor_fails_the_sandbox_check_for_a_server_that_will_not_start() {
    let dir = data_dir();
    let out = wirken(dir.path(), &["doctor"]);
    let check = out
        .lines()
        .skip_while(|l| !l.contains("MCP sandbox"))
        .take(2)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(check.contains("FAIL"), "{out}");
    assert!(check.contains("legacy will not start"), "{out}");
    assert!(!check.contains("boxed"), "{out}");
}
