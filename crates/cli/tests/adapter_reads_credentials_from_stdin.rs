//! Each adapter process starts from the gateway's stdin hand-off and
//! opens no vault file.
//!
//! The binary runs with a hand-off on stdin, no vault passphrase in its
//! environment, and a data directory holding no vault. There is no
//! gateway socket, so an adapter that read every credential it needs
//! fails at the gateway connection; one missing a credential fails
//! earlier with its "No ... found" error. Either way the data directory
//! must not gain a vault file, which `CredentialStore::open` would
//! create.
#![cfg(unix)]

mod common;

use std::path::Path;

use common::{handoff, run_adapter};

const ADAPTERS: &[&str] = &[
    "telegram",
    "discord",
    "slack",
    "teams",
    "matrix",
    "whatsapp",
    "signal",
    "google-chat",
    "imessage",
];

/// Every credential `adapter` starts with, with values its
/// constructor accepts and that reach no network.
fn credentials(adapter: &str) -> Vec<(String, String)> {
    let extra: &[(&str, &str)] = match adapter {
        "slack" => &[("app-token", "xapp-test")],
        "teams" => &[("app-id", "00000000-0000-0000-0000-000000000000")],
        "matrix" => &[
            ("homeserver", "http://127.0.0.1:1"),
            ("username", "@bot:localhost"),
        ],
        "whatsapp" => &[
            ("app-secret", "app-secret"),
            ("phone-number-id", "1"),
            ("verify-token", "verify"),
        ],
        "signal" => &[
            ("endpoint", "/nonexistent/signal-cli.sock"),
            ("phone-number", "+15550000000"),
            ("allowed-senders", ""),
        ],
        "google-chat" => &[("project-number", "123456789012")],
        "imessage" => &[
            ("bluebubbles-url", "http://127.0.0.1:1"),
            ("server-password", "password"),
        ],
        _ => &[],
    };
    let mut entries = vec![
        (format!("{adapter}-token"), "token".to_string()),
        (format!("{adapter}-adapter-key"), "11".repeat(32)),
    ];
    entries.extend(
        extra
            .iter()
            .map(|(suffix, value)| (format!("{adapter}-{suffix}"), value.to_string())),
    );
    entries
}

fn assert_no_vault_files(adapter: &str, data_dir: &Path) {
    for name in ["vault.db", "vault.db-wal", "vault.db-shm", "keychain"] {
        assert!(
            !data_dir.join(name).exists(),
            "{adapter} adapter created {name} in the data directory"
        );
    }
}

#[test]
fn each_adapter_starts_from_the_handoff_and_opens_no_vault() {
    for adapter in ADAPTERS {
        let data = tempfile::tempdir().unwrap();
        let (status, stderr) = run_adapter(adapter, data.path(), &handoff(&credentials(adapter)));
        assert!(!status.success(), "{adapter}: {stderr}");
        assert!(
            stderr.contains("adapter error"),
            "{adapter} did not get past its credentials to the gateway connection: {stderr}"
        );
        assert_no_vault_files(adapter, data.path());
    }
}

#[test]
fn an_adapter_with_an_empty_handoff_does_not_fall_back_to_the_vault() {
    for adapter in ADAPTERS {
        let data = tempfile::tempdir().unwrap();
        let (status, stderr) = run_adapter(adapter, data.path(), &handoff(&[]));
        assert!(!status.success(), "{adapter}: {stderr}");
        assert!(
            stderr.contains(&format!("No token found for '{adapter}'")),
            "{adapter}: {stderr}"
        );
        assert_no_vault_files(adapter, data.path());
    }
}
