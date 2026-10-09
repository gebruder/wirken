//! The credentials an adapter process starts with, handed over on stdin.
//!
//! The gateway resolves an adapter's credentials from the vault, writes
//! them to the child's stdin at spawn and closes the pipe. The adapter
//! reads stdin once and never opens the vault, so it holds neither the
//! vault passphrase nor any credential outside its own set.
//!
//! The set is decided by name, not by the vault's `channel` column:
//! `wirken credentials add` writes an empty channel when none is given,
//! so a re-added adapter credential can carry one.
//!
//! Wire format: the header line `wirken-adapter-handoff-v1\n`, then
//! zero or more entries, each a name and a value, each written as a
//! little-endian `u32` byte length followed by that many UTF-8 bytes.
//! End of input ends the hand-off.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use wirken_vault::{CredentialStore, VaultError, VaultSecret};
use zeroize::Zeroizing;

const HEADER: &[u8] = b"wirken-adapter-handoff-v1\n";

/// Upper bound on a hand-off. The largest set, WhatsApp's five
/// credentials, is well under a kilobyte.
const MAX_HANDOFF_BYTES: usize = 64 * 1024;

/// Every vault name `adapter_id`'s process starts with: its token, its
/// adapter key, and the entries its channel needs on top of those.
pub(crate) fn credential_names(adapter_id: &str) -> Vec<String> {
    let extra: &[&str] = match adapter_id {
        "slack" => &["app-token"],
        "teams" => &["app-id"],
        "matrix" => &["homeserver", "username"],
        "whatsapp" => &["app-secret", "phone-number-id", "verify-token"],
        "signal" => &["endpoint", "phone-number", "allowed-senders"],
        "google-chat" => &["project-number"],
        "imessage" => &["bluebubbles-url", "server-password"],
        _ => &[],
    };
    ["token", "adapter-key"]
        .iter()
        .chain(extra)
        .map(|suffix| format!("{adapter_id}-{suffix}"))
        .collect()
}

/// An adapter's credentials, keyed by vault name.
#[derive(Default)]
pub(crate) struct Handoff {
    credentials: BTreeMap<String, VaultSecret>,
}

impl Handoff {
    /// Resolve `adapter_id`'s set from the vault. A name the vault does
    /// not hold, or holds expired, is left out, and the adapter reports
    /// a missing required credential as it did when it read the vault
    /// itself.
    pub(crate) fn resolve(store: &CredentialStore, adapter_id: &str) -> Self {
        let mut credentials = BTreeMap::new();
        for name in credential_names(adapter_id) {
            match store.retrieve(&name) {
                Ok((secret, _)) => {
                    credentials.insert(name, secret);
                }
                Err(VaultError::NotFound(_)) => {}
                Err(e) => tracing::warn!(
                    adapter = adapter_id,
                    credential = %name,
                    error = %e,
                    "adapter credential left out of the hand-off"
                ),
            }
        }
        Self { credentials }
    }

    /// The names this hand-off carries.
    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.credentials.keys().map(String::as_str)
    }

    /// Take `name` out of the hand-off.
    pub(crate) fn take(&mut self, name: &str) -> Option<VaultSecret> {
        self.credentials.remove(name)
    }

    /// The wire form, in a buffer sized once and zeroed on drop.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let len = HEADER.len()
            + self
                .credentials
                .iter()
                .map(|(name, value)| 8 + name.len() + value.expose().len())
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(HEADER);
        for (name, value) in &self.credentials {
            push_field(&mut out, name.as_bytes());
            push_field(&mut out, value.expose().as_bytes());
        }
        out
    }

    /// Read a hand-off from `reader` until end of input. The buffer is
    /// sized once, so it is never reallocated, and is zeroed when this
    /// returns.
    pub(crate) fn read_from(reader: impl Read) -> Result<Self> {
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_HANDOFF_BYTES + 1));
        reader
            .take(MAX_HANDOFF_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .context("read the credential hand-off")?;
        if buf.len() > MAX_HANDOFF_BYTES {
            bail!("credential hand-off is larger than {MAX_HANDOFF_BYTES} bytes");
        }
        Self::decode(&buf)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(mut rest) = bytes.strip_prefix(HEADER) else {
            bail!("credential hand-off does not start with the wirken-adapter-handoff-v1 header");
        };
        let mut credentials = BTreeMap::new();
        while !rest.is_empty() {
            let name = take_field(&mut rest).context("credential hand-off name")?;
            let value = take_field(&mut rest).context("credential hand-off value")?;
            let name = std::str::from_utf8(name)
                .context("credential hand-off name is not UTF-8")?
                .to_owned();
            let Ok(value) = std::str::from_utf8(value) else {
                bail!("credential hand-off value for '{name}' is not UTF-8");
            };
            let value = VaultSecret::new(value.to_owned());
            if credentials.insert(name.clone(), value).is_some() {
                bail!("credential hand-off names '{name}' twice");
            }
        }
        Ok(Self { credentials })
    }
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    // A field over `u32::MAX` bytes would be far past `MAX_HANDOFF_BYTES`
    // and refused by the reader, so saturating here cannot pass one off
    // as a shorter field: the length no longer matches what follows.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let Some((len, tail)) = rest.split_first_chunk::<4>() else {
        bail!("truncated length");
    };
    let len = usize::try_from(u32::from_le_bytes(*len)).context("length")?;
    let Some((field, tail)) = tail.split_at_checked(len) else {
        bail!("truncated field");
    };
    *rest = tail;
    Ok(field)
}

/// Arguments and environment for an adapter child. Stdin is piped for
/// the hand-off. The vault passphrase is removed, so the child cannot
/// inherit it from the gateway's own environment.
pub(crate) fn configure_adapter_command<'a>(
    cmd: &'a mut Command,
    adapter_id: &str,
    data_dir: &Path,
    socket: &Path,
) -> &'a mut Command {
    cmd.arg("adapter")
        .arg(adapter_id)
        .env("WIRKEN_DATA_DIR", data_dir)
        .env("WIRKEN_SOCKET", socket)
        .env_remove("WIRKEN_VAULT_PASSPHRASE")
        .stdin(std::process::Stdio::piped())
        .kill_on_drop(true)
}

/// Spawn `cmd`, write `handoff` to its stdin and close the pipe. The
/// write runs on its own task; the payload is zeroed when it finishes.
pub(crate) fn spawn_with_handoff(
    cmd: &mut Command,
    handoff: Handoff,
) -> std::io::Result<tokio::process::Child> {
    // Names are not secrets; the values never reach a log.
    tracing::debug!(
        credentials = ?handoff.names().collect::<Vec<_>>(),
        "handing credentials to the adapter"
    );
    let payload = handoff.encode();
    drop(handoff);
    let mut child = cmd.spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(std::io::Error::other("adapter stdin is not piped"));
    };
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if let Err(e) = stdin.write_all(&payload).await {
            tracing::warn!(error = %e, "credential hand-off to the adapter failed");
        }
        // Dropping the handle closes the pipe, which ends the hand-off.
        drop(stdin);
    });
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_vault::AgeFileKeychain;

    /// What each adapter retrieved from the vault itself before the
    /// hand-off, read off the pre-change `adapter.rs`.
    const BEFORE: &[(&str, &[&str])] = &[
        ("telegram", &["telegram-token", "telegram-adapter-key"]),
        ("discord", &["discord-token", "discord-adapter-key"]),
        (
            "slack",
            &["slack-token", "slack-adapter-key", "slack-app-token"],
        ),
        (
            "teams",
            &["teams-token", "teams-adapter-key", "teams-app-id"],
        ),
        (
            "matrix",
            &[
                "matrix-token",
                "matrix-adapter-key",
                "matrix-homeserver",
                "matrix-username",
            ],
        ),
        (
            "whatsapp",
            &[
                "whatsapp-token",
                "whatsapp-adapter-key",
                "whatsapp-app-secret",
                "whatsapp-phone-number-id",
                "whatsapp-verify-token",
            ],
        ),
        (
            "signal",
            &[
                "signal-token",
                "signal-adapter-key",
                "signal-endpoint",
                "signal-phone-number",
                "signal-allowed-senders",
            ],
        ),
        (
            "google-chat",
            &[
                "google-chat-token",
                "google-chat-adapter-key",
                "google-chat-project-number",
            ],
        ),
        (
            "imessage",
            &[
                "imessage-token",
                "imessage-adapter-key",
                "imessage-bluebubbles-url",
                "imessage-server-password",
            ],
        ),
    ];

    fn sorted(names: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
        let mut v: Vec<String> = names.into_iter().map(Into::into).collect();
        v.sort();
        v
    }

    fn value_for(name: &str) -> String {
        format!("value-of-{name}")
    }

    /// A vault holding every adapter's credentials, a provider key, an
    /// MCP bearer token and an OAuth entry. `telegram-token` is stored
    /// with an empty channel, as `wirken credentials add` leaves it.
    fn full_vault(dir: &Path) -> CredentialStore {
        let kc = AgeFileKeychain::new(dir.join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&dir.join("vault.db"), &kc).unwrap();
        for (adapter, names) in BEFORE {
            for name in *names {
                let channel = if *name == "telegram-token" {
                    ""
                } else {
                    adapter
                };
                store
                    .store(
                        name,
                        channel,
                        &VaultSecret::new(value_for(name)),
                        None,
                        None,
                    )
                    .unwrap();
            }
        }
        for (name, channel) in [
            ("anthropic-api-key", "anthropic"),
            ("linear-token", ""),
            ("notion-oauth", "oauth"),
        ] {
            store
                .store(
                    name,
                    channel,
                    &VaultSecret::new(value_for(name)),
                    None,
                    None,
                )
                .unwrap();
        }
        store
    }

    #[test]
    fn each_adapter_is_handed_the_names_it_read_before() {
        for (adapter, names) in BEFORE {
            assert_eq!(
                sorted(credential_names(adapter)),
                sorted(names.iter().copied()),
                "{adapter}"
            );
        }
    }

    #[test]
    fn resolve_hands_each_adapter_exactly_its_own_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let store = full_vault(dir.path());
        for (adapter, names) in BEFORE {
            let mut handoff = Handoff::resolve(&store, adapter);
            assert_eq!(
                sorted(handoff.names()),
                sorted(names.iter().copied()),
                "{adapter} was handed something other than its own set"
            );
            for name in *names {
                let secret = handoff.take(name).unwrap();
                assert_eq!(secret.expose(), value_for(name));
            }
        }
    }

    #[test]
    fn resolve_leaves_out_missing_and_expired_names() {
        let dir = tempfile::tempdir().unwrap();
        let kc = AgeFileKeychain::new(dir.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&dir.path().join("vault.db"), &kc).unwrap();
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        store
            .store(
                "signal-token",
                "signal",
                &VaultSecret::new("t".into()),
                None,
                None,
            )
            .unwrap();
        store
            .store(
                "signal-phone-number",
                "signal",
                &VaultSecret::new("p".into()),
                Some(past),
                None,
            )
            .unwrap();
        let handoff = Handoff::resolve(&store, "signal");
        assert_eq!(sorted(handoff.names()), sorted(["signal-token"]));
    }

    #[test]
    fn a_handoff_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = full_vault(dir.path());
        for (adapter, names) in BEFORE {
            let encoded = Handoff::resolve(&store, adapter).encode();
            let mut decoded = Handoff::read_from(&encoded[..]).unwrap();
            assert_eq!(sorted(decoded.names()), sorted(names.iter().copied()));
            for name in *names {
                assert_eq!(decoded.take(name).unwrap().expose(), value_for(name));
            }
        }
    }

    #[test]
    fn an_empty_handoff_is_the_header_alone() {
        let encoded = Handoff::default().encode();
        assert_eq!(&encoded[..], HEADER);
        assert_eq!(Handoff::read_from(&encoded[..]).unwrap().names().count(), 0);
    }

    #[test]
    fn malformed_handoffs_are_refused() {
        let mut good = HEADER.to_vec();
        push_field(&mut good, b"telegram-token");
        push_field(&mut good, b"t");

        let no_header = good[HEADER.len()..].to_vec();
        let truncated = good[..good.len() - 1].to_vec();
        let mut twice = good.clone();
        twice.extend_from_slice(&good[HEADER.len()..]);
        let mut not_utf8 = HEADER.to_vec();
        push_field(&mut not_utf8, b"telegram-token");
        push_field(&mut not_utf8, &[0xff, 0xfe]);
        let mut oversized = HEADER.to_vec();
        oversized.resize(MAX_HANDOFF_BYTES + 1, b'x');

        for (what, bytes) in [
            ("no header", no_header),
            ("truncated", truncated),
            ("a name twice", twice),
            ("non-UTF-8 value", not_utf8),
            ("oversized", oversized),
        ] {
            assert!(
                Handoff::read_from(&bytes[..]).is_err(),
                "{what} was accepted"
            );
        }
        assert!(Handoff::read_from(&good[..]).is_ok());
    }

    /// The child environment carries no vault passphrase even when the
    /// gateway's own environment does: `sh -c env` stands in for the
    /// adapter binary, with the passphrase set on the command first the
    /// way an inherited variable would be.
    #[cfg(unix)]
    #[tokio::test]
    async fn adapter_child_environment_has_no_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        for (adapter, _) in BEFORE {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg("env")
                .env("WIRKEN_VAULT_PASSPHRASE", "inherited-passphrase")
                .stdout(std::process::Stdio::piped());
            configure_adapter_command(&mut cmd, adapter, dir.path(), &dir.path().join("gw.sock"));
            let out = cmd.output().await.unwrap();
            let env = String::from_utf8(out.stdout).unwrap();
            assert!(
                !env.contains("WIRKEN_VAULT_PASSPHRASE"),
                "{adapter} child inherited the passphrase"
            );
            assert!(env.contains("WIRKEN_DATA_DIR="), "{adapter}");
        }
    }

    /// `spawn_with_handoff` delivers the hand-off once and closes the
    /// pipe: `sh -c cat` echoes stdin and exits only at end of input.
    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_writes_the_handoff_and_closes_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let store = full_vault(dir.path());
        for (adapter, names) in BEFORE {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg("cat")
                .stdout(std::process::Stdio::piped());
            configure_adapter_command(&mut cmd, adapter, dir.path(), &dir.path().join("gw.sock"));
            let child = spawn_with_handoff(&mut cmd, Handoff::resolve(&store, adapter)).unwrap();
            let out =
                tokio::time::timeout(std::time::Duration::from_secs(20), child.wait_with_output())
                    .await
                    .expect("stdin was not closed")
                    .unwrap();
            let received = Handoff::read_from(&out.stdout[..]).unwrap();
            assert_eq!(sorted(received.names()), sorted(names.iter().copied()));
        }
    }
}
