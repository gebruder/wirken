//! `wirken credentials add` stores a value as a secret unless told it is
//! an identifier, a built-in adapter identifier gets its kind without
//! being told, and `credentials list` shows the kind.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PASSPHRASE: &str = "credentials-kind-test-passphrase";

fn wirken(data: &Path, args: &[&str], stdin: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(args)
        .env("WIRKEN_DATA_DIR", data)
        .env("WIRKEN_VAULT_PASSPHRASE", PASSPHRASE)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "wirken {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn credentials_add_stores_a_kind_and_list_shows_it() {
    let data = tempfile::tempdir().unwrap();
    let added = wirken(
        data.path(),
        &[
            "credentials",
            "add",
            "support-address",
            "--stdin",
            "--identifier",
        ],
        "help@example.org",
    );
    assert!(added.contains("stored as identifier"), "{added}");
    let added = wirken(
        data.path(),
        &["credentials", "add", "matrix-username", "--stdin"],
        "@wirken:example.org",
    );
    assert!(added.contains("stored as identifier"), "{added}");
    let added = wirken(
        data.path(),
        &["credentials", "add", "my-mcp-token", "--stdin"],
        "mcp-token-value-123",
    );
    assert!(added.contains("stored as secret"), "{added}");

    let list = wirken(data.path(), &["credentials", "list"], "");
    let kind_of = |name: &str| {
        list.lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_else(|| panic!("{name} not listed:\n{list}"))
            .to_string()
    };
    // No channel was given, so the column after the name is the kind.
    assert_eq!(kind_of("support-address"), "identifier");
    assert_eq!(kind_of("matrix-username"), "identifier");
    assert_eq!(kind_of("my-mcp-token"), "secret");
}
