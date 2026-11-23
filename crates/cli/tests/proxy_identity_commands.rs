//! `wirken proxy identity`: the operator writes grant sets and the
//! mappings that give one to a JWT, at a terminal, and each change is a
//! row on the operator lane. A subject is named on its row as the rows
//! of its calls name it: by its keyed hash.
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use common::wirken;
use wirken_audit::{OPERATOR_COMMANDS_SESSION, SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-identity-commands-passphrase";
const ISSUER: &str = "https://idp.example.com/realms/acme";

fn at_terminal(data: &Path, args: &[&str]) -> String {
    let line = std::iter::once(env!("CARGO_BIN_EXE_wirken").to_string())
        .chain(args.iter().map(|a| format!("'{a}'")))
        .collect::<Vec<_>>()
        .join(" ");
    let out = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("script, for a pseudo-terminal");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The operator's commands so far, as (command, target, detail).
fn commands(data: &Path) -> Vec<(String, String, String)> {
    let Ok(log) = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")) else {
        return Vec::new();
    };
    let handle = log.handle_for(SessionId::new(OPERATOR_COMMANDS_SESSION.to_string()));
    log.get_since(&handle, 0)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|row| match row.event {
            SessionEvent::OperatorCommand {
                command,
                target,
                detail,
                ..
            } => Some((command, target, detail)),
            _ => None,
        })
        .collect()
}

fn write_config(data: &Path, oidc: Option<serde_json::Value>) {
    let mut config = serde_json::json!({
        "upstreams": {"local": {"provider": "ollama", "base_url": "http://localhost:11434/v1"}},
    });
    if let Some(oidc) = oidc {
        config["oidc"] = oidc;
    }
    std::fs::write(data.join("proxy.json"), config.to_string()).unwrap();
}

fn oidc(record_subject: bool) -> serde_json::Value {
    serde_json::json!({
        "issuer": ISSUER, "audience": "wirken-proxy", "max_token_lifetime_secs": 900,
        "grant_claim": "groups", "record_subject": record_subject,
    })
}

#[test]
fn each_change_to_the_mapping_is_made_at_a_terminal_and_is_an_operator_row() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    write_config(data, Some(oidc(false)));

    // Not at a terminal: nothing is written and there is no row.
    let piped = wirken(data)
        .args([
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--upstream",
            "local",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!piped.status.success());
    assert!(
        String::from_utf8_lossy(&piped.stderr).contains("at a terminal"),
        "{}",
        String::from_utf8_lossy(&piped.stderr)
    );
    assert!(commands(data).is_empty());

    // An upstream proxy.json does not have.
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--upstream",
            "cloud",
        ],
    );
    assert!(said.contains("no upstream named cloud"), "{said}");
    assert!(commands(data).is_empty());

    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--upstream",
            "local",
            "--model",
            "m",
            "--ceiling-calls",
            "50",
        ],
    );
    assert!(said.contains("Wrote grant set engineers"), "{said}");
    assert!(said.contains("each subject's own"), "{said}");

    // A mapping names a grant set that exists.
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "nowhere",
            "--claim-value",
            "eng",
        ],
    );
    assert!(said.contains("no grant set named nowhere"), "{said}");

    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--claim-value",
            "eng",
        ],
    );
    assert!(
        said.contains("Mapped claim eng to grant set engineers"),
        "{said}"
    );
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--subject",
            "alice@example.com",
        ],
    );
    assert!(said.contains("Mapped subject"), "{said}");

    let rows = commands(data);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(
        rows[0],
        (
            "proxy identity grant-set set".to_string(),
            "engineers".to_string(),
            "upstreams local; models m; 50 calls a day".to_string(),
        )
    );
    assert_eq!(
        rows[1],
        (
            "proxy identity map".to_string(),
            "claim groups=eng".to_string(),
            format!("grant set engineers; issuer {ISSUER}"),
        )
    );
    // The subject is on its row as a keyed hash, and nowhere as issued.
    assert_eq!(rows[2].0, "proxy identity map");
    let hash = rows[2].1.strip_prefix("subject ").expect("a subject row");
    assert_eq!(hash.len(), 64, "{hash}");
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    for (command, target, detail) in &rows {
        assert!(!format!("{command}{target}{detail}").contains("alice"));
    }

    // The listing is the operator's own view, and shows the subject.
    let listed = wirken(data)
        .args(["proxy", "identity", "list"])
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(listed.contains(&format!("Issuer {ISSUER}")), "{listed}");
    assert!(
        listed.contains("grant set engineers  upstreams local"),
        "{listed}"
    );
    assert!(listed.contains("claim eng -> engineers"), "{listed}");
    assert!(
        listed.contains("subject alice@example.com -> engineers"),
        "{listed}"
    );

    // A grant set a mapping names stays.
    let said = at_terminal(
        data,
        &["proxy", "identity", "grant-set", "remove", "engineers"],
    );
    assert!(said.contains("2 mapping(s) name the grant set"), "{said}");

    let said = at_terminal(
        data,
        &["proxy", "identity", "unmap", "--claim-value", "eng"],
    );
    assert!(said.contains("Removed the mapping of claim eng"), "{said}");
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "unmap",
            "--subject",
            "alice@example.com",
        ],
    );
    assert!(said.contains("Removed the mapping of subject"), "{said}");
    let said = at_terminal(
        data,
        &["proxy", "identity", "unmap", "--claim-value", "eng"],
    );
    assert!(said.contains("no mapping of claim eng"), "{said}");
    let said = at_terminal(
        data,
        &["proxy", "identity", "grant-set", "remove", "engineers"],
    );
    assert!(said.contains("Removed grant set engineers"), "{said}");

    let rows = commands(data);
    let made: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        made,
        [
            "proxy identity grant-set set",
            "proxy identity map",
            "proxy identity map",
            "proxy identity unmap",
            "proxy identity unmap",
            "proxy identity grant-set remove",
        ]
    );
    // The same subject is the same hash on the row that removed it.
    assert_eq!(rows[4].1, rows[2].1);
}

/// A mapping is for the JWTs of the configured issuer, so there is
/// none to write without one; a claim value needs a claim to be a
/// value of; and with `record_subject` the subject is on its row as
/// issued.
#[test]
fn a_mapping_needs_an_issuer_and_names_the_subject_as_the_operator_set_it() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    write_config(data, None);
    at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "grant-set",
            "set",
            "engineers",
            "--upstream",
            "local",
        ],
    );
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--claim-value",
            "eng",
        ],
    );
    assert!(said.contains("proxy.json has no oidc block"), "{said}");

    let mut no_claim = oidc(true);
    no_claim.as_object_mut().unwrap().remove("grant_claim");
    write_config(data, Some(no_claim));
    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--claim-value",
            "eng",
        ],
    );
    assert!(said.contains("names no grant_claim"), "{said}");

    let said = at_terminal(
        data,
        &[
            "proxy",
            "identity",
            "map",
            "engineers",
            "--subject",
            "alice@example.com",
        ],
    );
    assert!(said.contains("Mapped subject"), "{said}");
    let rows = commands(data);
    assert_eq!(rows.last().unwrap().1, "subject alice@example.com");
}
