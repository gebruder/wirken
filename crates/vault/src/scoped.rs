//! A credential store limited to a fixed set of names.
//!
//! [`CredentialStore::retrieve`] decrypts any name in the vault. A
//! process that needs only a few, such as the MCP proxy, opens a
//! [`ScopedCredentialStore`] instead: it reads and writes the names it
//! was opened with and refuses every other name, logging the refusal at
//! error with the scope and the name.

use std::collections::BTreeSet;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::error::VaultError;
use crate::keychain::Keychain;
use crate::secret::VaultSecret;
use crate::store::{CredentialMetadata, CredentialStore};

/// Reading and writing credentials by name. Implemented by the full
/// [`CredentialStore`] and by [`ScopedCredentialStore`], so code that
/// runs in both kinds of process takes either.
pub trait CredentialAccess {
    /// See [`CredentialStore::retrieve`].
    fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError>;

    /// See [`CredentialStore::peek`].
    fn peek(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError>;

    /// See [`CredentialStore::store`].
    fn store(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError>;
}

impl CredentialAccess for CredentialStore {
    fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        CredentialStore::retrieve(self, name)
    }

    fn peek(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        CredentialStore::peek(self, name)
    }

    fn store(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        CredentialStore::store(self, name, channel, secret, expires_at, rotation_due_at)
    }
}

/// A [`CredentialStore`] that reads and writes only the names it was
/// opened with.
pub struct ScopedCredentialStore {
    inner: CredentialStore,
    scope: String,
    names: BTreeSet<String>,
}

impl CredentialStore {
    /// Open the store at `db_path` limited to `names`. `scope` names the
    /// holder in refusals, e.g. `"mcp-proxy"`.
    pub fn open_scoped(
        db_path: &Path,
        keychain: &dyn Keychain,
        scope: &str,
        names: impl IntoIterator<Item = String>,
    ) -> Result<ScopedCredentialStore, VaultError> {
        Ok(Self::open(db_path, keychain)?.into_scoped(scope, names))
    }

    /// Limit an open store to `names`. The full store is consumed, so
    /// nothing else can reach it through this handle.
    pub fn into_scoped(
        self,
        scope: &str,
        names: impl IntoIterator<Item = String>,
    ) -> ScopedCredentialStore {
        ScopedCredentialStore {
            inner: self,
            scope: scope.to_string(),
            names: names.into_iter().collect(),
        }
    }
}

impl ScopedCredentialStore {
    /// The holder named in refusals.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Whether `name` is in this store's set.
    pub fn permits(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    fn check(&self, operation: &str, name: &str) -> Result<(), VaultError> {
        if self.permits(name) {
            return Ok(());
        }
        tracing::error!(
            scope = %self.scope,
            name,
            operation,
            "vault access outside the scope refused"
        );
        Err(VaultError::OutOfScope {
            scope: self.scope.clone(),
            name: name.to_string(),
        })
    }
}

impl CredentialAccess for ScopedCredentialStore {
    fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        self.check("retrieve", name)?;
        self.inner.retrieve(name)
    }

    fn peek(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        self.check("peek", name)?;
        self.inner.peek(name)
    }

    fn store(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        self.check("store", name)?;
        self.inner
            .store(name, channel, secret, expires_at, rotation_due_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgeFileKeychain;

    fn seeded(dir: &Path) -> CredentialStore {
        let kc = AgeFileKeychain::new(dir.join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&dir.join("vault.db"), &kc).unwrap();
        for (name, channel, value) in [
            ("linear-token", "", "linear"),
            ("notion-oauth", "oauth", "{\"access_token\":\"a\"}"),
            ("telegram-token", "telegram", "tg"),
            ("anthropic-api-key", "anthropic", "provider"),
        ] {
            store
                .store(name, channel, &VaultSecret::new(value.into()), None, None)
                .unwrap();
        }
        store
    }

    /// The unscoped store reads any name, whatever its channel: the
    /// property an adapter process had when it opened the vault itself.
    #[test]
    fn an_unscoped_store_retrieves_another_channels_credential() {
        let dir = tempfile::tempdir().unwrap();
        let store = seeded(dir.path());
        let (secret, meta) = CredentialStore::retrieve(&store, "telegram-token").unwrap();
        assert_eq!(secret.expose(), "tg");
        assert_eq!(meta.channel, "telegram");
        let (secret, _) = CredentialStore::retrieve(&store, "anthropic-api-key").unwrap();
        assert_eq!(secret.expose(), "provider");
    }

    #[test]
    fn a_scoped_store_reads_and_writes_its_own_names() {
        let dir = tempfile::tempdir().unwrap();
        let scoped = seeded(dir.path())
            .into_scoped("mcp-proxy", ["linear-token".into(), "notion-oauth".into()]);
        assert_eq!(
            scoped.retrieve("linear-token").unwrap().0.expose(),
            "linear"
        );
        assert!(scoped.peek("notion-oauth").is_ok());
        scoped
            .store(
                "notion-oauth",
                "oauth",
                &VaultSecret::new("{\"access_token\":\"b\"}".into()),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            scoped.retrieve("notion-oauth").unwrap().0.expose(),
            "{\"access_token\":\"b\"}"
        );
    }

    #[test]
    fn a_scoped_store_refuses_every_name_outside_its_set() {
        let dir = tempfile::tempdir().unwrap();
        let scoped = seeded(dir.path()).into_scoped("mcp-proxy", ["linear-token".into()]);
        for name in [
            "telegram-token",
            "anthropic-api-key",
            "notion-oauth",
            "absent",
        ] {
            assert!(
                matches!(
                    scoped.retrieve(name),
                    Err(VaultError::OutOfScope { ref scope, name: ref n }) if scope == "mcp-proxy" && n == name
                ),
                "retrieve {name}"
            );
            assert!(
                matches!(scoped.peek(name), Err(VaultError::OutOfScope { .. })),
                "peek {name}"
            );
            assert!(
                matches!(
                    scoped.store(name, "x", &VaultSecret::new("v".into()), None, None),
                    Err(VaultError::OutOfScope { .. })
                ),
                "store {name}"
            );
        }
        // The refused store did not overwrite the real entry.
        let store = CredentialStore::open(
            &dir.path().join("vault.db"),
            &AgeFileKeychain::new(dir.path().join("keychain"), "test-passphrase".into()),
        )
        .unwrap();
        assert_eq!(
            CredentialStore::retrieve(&store, "telegram-token")
                .unwrap()
                .0
                .expose(),
            "tg"
        );
    }

    #[test]
    fn open_scoped_limits_a_freshly_opened_store() {
        let dir = tempfile::tempdir().unwrap();
        drop(seeded(dir.path()));
        let kc = AgeFileKeychain::new(dir.path().join("keychain"), "test-passphrase".into());
        let scoped = CredentialStore::open_scoped(
            &dir.path().join("vault.db"),
            &kc,
            "mcp-proxy",
            ["linear-token".to_string()],
        )
        .unwrap();
        assert_eq!(scoped.scope(), "mcp-proxy");
        assert!(scoped.retrieve("linear-token").is_ok());
        assert!(matches!(
            scoped.retrieve("telegram-token"),
            Err(VaultError::OutOfScope { .. })
        ));
    }
}
