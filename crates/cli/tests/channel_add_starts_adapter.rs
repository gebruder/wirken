//! A vault populated only by `wirken channel add` starts the adapter.
//!
//! `channel add` runs non-interactively from flags into an empty data
//! directory. Every credential it wrote is then handed to the adapter
//! binary on stdin, as the gateway hands them. With no gateway socket,
//! an adapter that has every credential it needs fails at the gateway
//! connection; one missing a credential fails earlier with its
//! "No ... found" error.
#![cfg(unix)]

mod common;

use std::path::Path;

use common::{handoff, run_adapter, wirken};
use wirken_vault::{AgeFileKeychain, CredentialStore};

const PASSPHRASE: &str = "test-passphrase";

/// `wirken channel add <adapter> <flags>` and, for each name it must
/// write, the channel value `wirken setup` writes for it.
struct Case {
    adapter: &'static str,
    flags: &'static [&'static str],
    writes: &'static [(&'static str, &'static str)],
}

const CASES: &[Case] = &[
    Case {
        adapter: "teams",
        flags: &[
            "--token",
            "fake_app_password",
            "--app-id",
            "00000000-0000-0000-0000-000000000000",
        ],
        writes: &[
            ("teams-token", "teams"),
            ("teams-app-id", "teams"),
            ("teams-adapter-key", "teams"),
        ],
    },
    Case {
        adapter: "matrix",
        flags: &[
            "--token",
            "fake_password",
            "--homeserver",
            "http://127.0.0.1:1",
            "--username",
            "@wirken:localhost",
        ],
        writes: &[
            ("matrix-token", "matrix"),
            ("matrix-homeserver", "matrix"),
            ("matrix-username", "matrix"),
            ("matrix-adapter-key", "matrix"),
        ],
    },
];

/// Every entry in the vault: name, channel and value.
fn vault_contents(data: &Path) -> Vec<(String, String, String)> {
    let keychain = AgeFileKeychain::new(data.join("keychain"), PASSPHRASE.into());
    let store = CredentialStore::open(&data.join("vault.db"), &keychain).unwrap();
    store
        .list()
        .unwrap()
        .into_iter()
        .map(|meta| {
            let (secret, _) = store.peek(&meta.name).unwrap();
            (meta.name, meta.channel, secret.expose().to_string())
        })
        .collect()
}

#[test]
fn a_vault_populated_only_by_channel_add_starts_the_adapter() {
    for Case {
        adapter,
        flags,
        writes,
    } in CASES
    {
        let data = tempfile::tempdir().unwrap();
        let out = wirken(data.path())
            .env("WIRKEN_VAULT_PASSPHRASE", PASSPHRASE)
            .args(["channel", "add", adapter])
            .args(*flags)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "channel add {adapter}: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let contents = vault_contents(data.path());
        let mut written: Vec<(&str, &str)> = contents
            .iter()
            .map(|(name, channel, _)| (name.as_str(), channel.as_str()))
            .collect();
        written.sort();
        let mut expected = writes.to_vec();
        expected.sort();
        assert_eq!(written, expected, "{adapter}");

        let entries: Vec<(String, String)> = contents
            .into_iter()
            .map(|(name, _, value)| (name, value))
            .collect();
        let (status, stderr) = run_adapter(adapter, data.path(), &handoff(&entries));
        assert!(!status.success(), "{adapter}: {stderr}");
        assert!(
            stderr.contains("adapter error"),
            "{adapter} did not get past its credentials to the gateway connection: {stderr}"
        );
    }
}
