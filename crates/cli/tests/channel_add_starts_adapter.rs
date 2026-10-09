//! A vault populated only by `wirken channel add` starts the adapter,
//! for every adapter `channel add` configures from flags.
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

/// `wirken channel add <adapter> <flags>`, with `env` set, and for each
/// name it must write, the channel value `wirken setup` writes for it.
struct Case {
    adapter: &'static str,
    flags: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    writes: &'static [(&'static str, &'static str)],
    values: &'static [(&'static str, &'static str)],
}

// Low-entropy fixtures, so the secret scanner does not read them as
// real tokens. Signal is absent: `channel add signal` only prompts.
const CASES: &[Case] = &[
    Case {
        adapter: "telegram",
        flags: &["--token", "fake_token_value"],
        env: &[],
        writes: &[
            ("telegram-token", "telegram"),
            ("telegram-adapter-key", "telegram"),
        ],
        values: &[],
    },
    Case {
        adapter: "discord",
        flags: &["--token", "fake_token_value"],
        env: &[],
        writes: &[
            ("discord-token", "discord"),
            ("discord-adapter-key", "discord"),
        ],
        values: &[],
    },
    Case {
        adapter: "slack",
        flags: &["--token", "xoxb-aaaa"],
        env: &[("WIRKEN_SLACK_APP_TOKEN", "xapp-aaaa")],
        writes: &[
            ("slack-token", "slack"),
            ("slack-app-token", "slack"),
            ("slack-adapter-key", "slack"),
        ],
        values: &[],
    },
    Case {
        adapter: "teams",
        flags: &[
            "--token",
            "fake_app_password",
            "--app-id",
            "00000000-0000-0000-0000-000000000000",
        ],
        env: &[],
        writes: &[
            ("teams-token", "teams"),
            ("teams-app-id", "teams"),
            ("teams-adapter-key", "teams"),
        ],
        values: &[],
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
        env: &[],
        writes: &[
            ("matrix-token", "matrix"),
            ("matrix-homeserver", "matrix"),
            ("matrix-username", "matrix"),
            ("matrix-adapter-key", "matrix"),
        ],
        values: &[],
    },
    Case {
        adapter: "whatsapp",
        flags: &[
            "--token",
            "fake_token_value",
            "--phone-number-id",
            "123456789012345",
            "--verify-token",
            "my_verify_token",
            "--app-secret",
            "00000000000000000000000000000000",
        ],
        env: &[],
        writes: &[
            ("whatsapp-token", "whatsapp"),
            ("whatsapp-phone-number-id", "whatsapp"),
            ("whatsapp-verify-token", "whatsapp"),
            ("whatsapp-app-secret", "whatsapp"),
            ("whatsapp-adapter-key", "whatsapp"),
        ],
        values: &[],
    },
    Case {
        adapter: "google-chat",
        flags: &[
            "--token",
            "fake_token_value",
            "--project-number",
            "123456789012",
        ],
        env: &[],
        writes: &[
            ("google-chat-token", "google-chat"),
            ("google-chat-project-number", "google-chat"),
            ("google-chat-adapter-key", "google-chat"),
        ],
        values: &[],
    },
    Case {
        adapter: "imessage",
        flags: &[
            "--token",
            "fake_password",
            "--bluebubbles-url",
            "http://127.0.0.1:1",
        ],
        env: &[],
        writes: &[
            ("imessage-token", "imessage"),
            ("imessage-server-password", "imessage"),
            ("imessage-bluebubbles-url", "imessage"),
            ("imessage-adapter-key", "imessage"),
        ],
        values: &[],
    },
    // No URL and no terminal: the default URL is stored.
    Case {
        adapter: "imessage",
        flags: &["--token", "fake_password"],
        env: &[],
        writes: &[
            ("imessage-token", "imessage"),
            ("imessage-server-password", "imessage"),
            ("imessage-bluebubbles-url", "imessage"),
            ("imessage-adapter-key", "imessage"),
        ],
        values: &[("imessage-bluebubbles-url", "http://localhost:1234")],
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
        env,
        writes,
        values,
    } in CASES
    {
        let data = tempfile::tempdir().unwrap();
        let out = wirken(data.path())
            .env("WIRKEN_VAULT_PASSPHRASE", PASSPHRASE)
            .args(["channel", "add", adapter])
            .args(*flags)
            .envs(env.iter().copied())
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
        for (name, value) in *values {
            assert!(
                contents.iter().any(|(n, _, v)| n == name && v == value),
                "{adapter}: {name} is not {value}"
            );
        }

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
