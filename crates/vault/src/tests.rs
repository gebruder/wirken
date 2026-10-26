use chrono::{Duration, Utc};
use tempfile::TempDir;

use crate::crypto::{decrypt, derive_key_from_passphrase, encrypt, generate_key};
use crate::keychain::{AgeFileKeychain, Keychain};
use crate::secret::VaultSecret;
use crate::store::CredentialStore;

// ---------------------------------------------------------------------------
// VaultSecret type safety tests
// ---------------------------------------------------------------------------

#[test]
fn vault_secret_does_not_impl_display() {
    // VaultSecret intentionally does not implement Display.
    // This test verifies the API contract — if someone adds Display,
    // this comment serves as a reminder that it's a security violation.
    // The compile-time guarantee is that `format!("{}", secret)` won't compile.
    let secret = VaultSecret::new("test-secret".into());
    assert_eq!(secret.expose(), "test-secret");
}

#[test]
fn vault_secret_expose_returns_correct_value() {
    let secret = VaultSecret::new("my-api-key-12345".into());
    assert_eq!(secret.expose(), "my-api-key-12345");
}

#[test]
fn vault_secret_into_inner_consumes() {
    let secret = VaultSecret::new("consumed".into());
    let inner = secret.into_inner();
    // After into_inner, secret is moved — can't use it again
    // inner is a SecretString
    use secrecy::ExposeSecret;
    assert_eq!(inner.expose_secret(), "consumed");
}

// ---------------------------------------------------------------------------
// Crypto tests
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = generate_key();
    let plaintext = VaultSecret::new("super-secret-api-key".into());

    let encrypted = encrypt("name", &plaintext, &key).unwrap();
    let decrypted = decrypt("name", &encrypted, &key).unwrap();

    assert_eq!(decrypted.expose(), "super-secret-api-key");
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    let key = generate_key();
    let plaintext = VaultSecret::new("same-input".into());

    let enc1 = encrypt("n", &plaintext, &key).unwrap();
    let enc2 = encrypt("n", &plaintext, &key).unwrap();

    // Different nonces → different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    assert_eq!(decrypt("n", &enc1, &key).unwrap().expose(), "same-input");
    assert_eq!(decrypt("n", &enc2, &key).unwrap().expose(), "same-input");
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key1 = generate_key();
    let key2 = generate_key();
    let plaintext = VaultSecret::new("secret".into());

    let encrypted = encrypt("n", &plaintext, &key1).unwrap();
    let result = decrypt("n", &encrypted, &key2);

    assert!(result.is_err());
}

#[test]
fn decrypt_truncated_ciphertext_fails() {
    let result = decrypt("n", &[0u8; 10], &generate_key());
    assert!(result.is_err());
}

#[test]
fn decrypt_empty_ciphertext_fails() {
    let result = decrypt("n", &[], &generate_key());
    assert!(result.is_err());
}

#[test]
fn encrypt_with_wrong_key_length_fails() {
    // 10 hex chars = 5 bytes, not 32
    let bad_key = VaultSecret::new("abcdef0123".into());
    let plaintext = VaultSecret::new("value".into());

    let result = encrypt("n", &plaintext, &bad_key);
    assert!(result.is_err());
}

#[test]
fn decrypt_with_mismatched_name_fails() {
    let key = generate_key();
    let plaintext = VaultSecret::new("api-key".into());
    let encrypted = encrypt("foo", &plaintext, &key).unwrap();
    let result = decrypt("bar", &encrypted, &key);
    assert!(
        result.is_err(),
        "AEAD must reject decrypt under a different name"
    );
}

#[test]
fn ciphertext_splice_across_names_fails() {
    // Encrypt under "foo", attempt to decrypt under "bar". The AEAD
    // tag binds the name; a splice that pastes "foo" ciphertext into
    // a row keyed "bar" must not yield the "foo" plaintext.
    let key = generate_key();
    let foo_secret = VaultSecret::new("foo-secret".into());
    let foo_ct = encrypt("foo", &foo_secret, &key).unwrap();
    let result = decrypt("bar", &foo_ct, &key);
    assert!(result.is_err(), "splice must be rejected");
}

#[test]
fn key_derivation_from_passphrase() {
    let salt = b"test-salt-value-1234567890123456";
    let key1 = derive_key_from_passphrase("my-passphrase", salt).unwrap();
    let key2 = derive_key_from_passphrase("my-passphrase", salt).unwrap();

    // Same passphrase + salt → same key
    assert_eq!(key1.expose(), key2.expose());
    // Key is 64 hex chars (32 bytes)
    assert_eq!(key1.expose().len(), 64);
}

#[test]
fn key_derivation_different_passphrases() {
    let salt = b"test-salt-value-1234567890123456";
    let key1 = derive_key_from_passphrase("passphrase-1", salt).unwrap();
    let key2 = derive_key_from_passphrase("passphrase-2", salt).unwrap();

    assert_ne!(key1.expose(), key2.expose());
}

#[test]
fn key_derivation_different_salts() {
    let key1 =
        derive_key_from_passphrase("same-pass", b"salt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let key2 =
        derive_key_from_passphrase("same-pass", b"salt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

    assert_ne!(key1.expose(), key2.expose());
}

// ---------------------------------------------------------------------------
// Age-file keychain tests
// ---------------------------------------------------------------------------

#[test]
fn age_keychain_store_and_retrieve() {
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());

    let key = generate_key();
    let original_value = key.expose().to_string();

    kc.store_device_key(&key).unwrap();
    let retrieved = kc.retrieve_device_key().unwrap();

    assert_eq!(retrieved.expose(), original_value);
}

#[test]
fn age_keychain_delete() {
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());

    let key = generate_key();
    kc.store_device_key(&key).unwrap();
    kc.delete_device_key().unwrap();

    let result = kc.retrieve_device_key();
    assert!(result.is_err());
}

#[test]
fn age_keychain_wrong_passphrase_fails() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("keychain");

    let kc1 = AgeFileKeychain::new(path.clone(), "correct-passphrase".into());
    let key = generate_key();
    kc1.store_device_key(&key).unwrap();

    let kc2 = AgeFileKeychain::new(path, "wrong-passphrase".into());
    let result = kc2.retrieve_device_key();
    assert!(result.is_err());
}

#[test]
fn age_keychain_store_device_key_refuses_empty_passphrase() {
    // vault-no-empty-seal: empty passphrase derives a deterministic
    // wrapping key any other process can reproduce; sealing under it
    // is no protection. The historical silent-empty-seal failure
    // mode (dialoguer Err swallowed via unwrap_or_default → "" →
    // store_device_key("")) is what this guard blocks.
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "".into());
    let key = generate_key();
    let result = kc.store_device_key(&key);
    match result {
        Err(crate::VaultError::Keychain(msg)) => {
            assert!(
                msg.contains("empty passphrase"),
                "error message must name the empty-passphrase reason; got: {msg}"
            );
        }
        other => panic!("expected Keychain(empty passphrase) error, got {other:?}"),
    }
    // Confirm the keychain files were NOT written.
    assert!(!tmp.path().join("keychain").join("device-key.age").exists());
    assert!(!tmp.path().join("keychain").join("device-key.salt").exists());
}

#[test]
fn credential_store_propagates_non_decryption_keychain_error() {
    // vault-no-empty-seal: CredentialStore::open's auto-create branch
    // narrowed to KeychainNotInitialized only. Any other backend
    // error (permission denied, IO, etc.) propagates so the operator
    // decides what to do, instead of being masked by a silent re-seal
    // under whatever passphrase is in scope.
    use crate::keychain::KeychainKind;

    struct ErroringKeychain;
    impl Keychain for ErroringKeychain {
        fn kind(&self) -> KeychainKind {
            KeychainKind::AgeFile
        }
        fn store_device_key(&self, _: &VaultSecret) -> Result<(), crate::VaultError> {
            // Auto-create branch must NOT be reached under the new
            // narrowing; if it is, the test's assertion will fail
            // because the open will return Ok(_). Returning an Err
            // here makes the regression louder.
            Err(crate::VaultError::Keychain("auto-create reached".into()))
        }
        fn retrieve_device_key(&self) -> Result<VaultSecret, crate::VaultError> {
            Err(crate::VaultError::Keychain(
                "simulated permission denied".into(),
            ))
        }
        fn delete_device_key(&self) -> Result<(), crate::VaultError> {
            unreachable!()
        }
    }

    let tmp = TempDir::new().unwrap();
    let result = CredentialStore::open(&tmp.path().join("vault.db"), &ErroringKeychain);
    match result {
        Err(crate::VaultError::Keychain(msg)) => {
            assert!(
                msg.contains("simulated permission denied"),
                "the original keychain error must propagate verbatim; got: {msg}"
            );
        }
        Ok(_) => {
            panic!("CredentialStore::open silently auto-created under a non-NotInitialized error")
        }
        Err(other) => panic!("expected the original Keychain error to propagate; got {other:?}"),
    }
}

#[test]
fn age_keychain_retrieve_returns_not_initialized_when_files_absent() {
    // vault-no-empty-seal: retrieve_device_key now distinguishes
    // "files absent" (legitimate first run) from "files exist but
    // unreadable" (permission, IO). Only the former routes to
    // CredentialStore::open's auto-create branch.
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "p".into());
    // VaultSecret intentionally does not implement Debug, so we can't
    // {:?}-print the Result; match instead and panic with the error
    // variant when present.
    match kc.retrieve_device_key() {
        Err(crate::VaultError::KeychainNotInitialized) => {}
        Err(other) => panic!("expected KeychainNotInitialized for absent files; got {other:?}"),
        Ok(_) => panic!("expected KeychainNotInitialized for absent files; got Ok(<secret>)"),
    }
}

#[test]
fn age_keychain_reports_correct_kind() {
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path(), "pass".into());
    assert_eq!(kc.kind(), crate::keychain::KeychainKind::AgeFile);
}

// ---------------------------------------------------------------------------
// Credential store tests
// ---------------------------------------------------------------------------

fn test_store(tmp: &TempDir) -> CredentialStore {
    let key = generate_key();
    CredentialStore::open_with_key(&tmp.path().join("vault.db"), key).unwrap()
}

#[test]
fn store_and_retrieve_credential() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("sk-abc123".into());
    store
        .store("openai-key", "openai", &secret, None, None)
        .unwrap();

    let (retrieved, meta) = store.retrieve("openai-key").unwrap();
    assert_eq!(retrieved.expose(), "sk-abc123");
    assert_eq!(meta.name, "openai-key");
    assert_eq!(meta.channel, "openai");
    assert!(!meta.is_expired());
}

#[test]
fn host_binding_round_trips_and_enforces() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);
    let secret = VaultSecret::new("tok".into());

    store
        .store_with_hosts(
            "tdx",
            "http",
            &secret,
            None,
            None,
            &["tenant.teamdynamix.com".to_string()],
        )
        .unwrap();
    let (_s, meta) = store.retrieve("tdx").unwrap();
    assert_eq!(
        meta.allowed_hosts,
        vec!["tenant.teamdynamix.com".to_string()]
    );
    assert!(meta.permits_host("tenant.teamdynamix.com"));
    assert!(meta.permits_host("TENANT.TeamDynamix.com")); // case-insensitive
    assert!(!meta.permits_host("attacker.example"));

    // A credential stored via the unbound `store` permits no host, so
    // `http_request` refuses it (deny by default).
    store.store("plain", "openai", &secret, None, None).unwrap();
    let (_s2, m2) = store.retrieve("plain").unwrap();
    assert!(m2.allowed_hosts.is_empty());
    assert!(!m2.permits_host("anything.example"));
}

#[test]
fn pre_migration_credential_reads_as_unbound() {
    // Adversarial: a credential row that predates the allowed_hosts
    // column. Build the old schema, insert an encrypted row, then open
    // the store (which runs the migration). The migrated row has NULL
    // allowed_hosts, so it reads back unbound and permits no host —
    // fail-closed for http_request across the upgrade.
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("vault.db");
    let key = generate_key();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE credentials (
                 name TEXT PRIMARY KEY,
                 channel TEXT NOT NULL,
                 encrypted_value BLOB NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT,
                 last_used_at TEXT,
                 rotation_due_at TEXT
             );",
        )
        .unwrap();
        let secret = VaultSecret::new("legacy-token".into());
        let enc = encrypt("legacy", &secret, &key).unwrap();
        conn.execute(
            "INSERT INTO credentials (name, channel, encrypted_value, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["legacy", "openai", enc, Utc::now().to_rfc3339()],
        )
        .unwrap();
    }
    assert!(matches!(
        CredentialStore::open_with_key(&db, VaultSecret::new(key.expose().to_string())),
        Err(crate::VaultError::NeedsMigration)
    ));
    let mut store =
        CredentialStore::open_with_key_any_format(&db, VaultSecret::new(key.expose().to_string()))
            .unwrap();
    store.migrate_to_bound(&Default::default()).unwrap();
    let store = CredentialStore::open_with_key(&db, key).unwrap();
    let (secret, meta) = store.retrieve("legacy").unwrap();
    assert_eq!(secret.expose(), "legacy-token");
    assert!(meta.binding.is_empty(), "migrated with no binding");
    assert!(!meta.permits_host("anything.example"));
}

#[test]
fn unbound_rewrite_clears_binding_and_fails_closed() {
    // Adversarial (downgrade): a pre-binding binary re-stores a
    // credential via the 7-column `store` path, leaving allowed_hosts
    // NULL. The binding is lost, but the result is deny-by-default, not
    // a usable unbound credential — a re-upgraded http_request refuses.
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);
    let secret = VaultSecret::new("t".into());
    store
        .store_with_hosts("c", "http", &secret, None, None, &["h.example".to_string()])
        .unwrap();
    assert!(store.retrieve("c").unwrap().1.permits_host("h.example"));

    store.store("c", "http", &secret, None, None).unwrap(); // old-style write
    let meta = store.retrieve("c").unwrap().1;
    assert!(meta.allowed_hosts.is_empty());
    assert!(
        !meta.permits_host("h.example"),
        "a cleared binding must fail closed, not resurrect as usable"
    );
}

#[test]
fn retrieve_updates_last_used_at() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("value".into());
    store.store("test", "chan", &secret, None, None).unwrap();

    let (_, meta1) = store.retrieve("test").unwrap();
    assert!(meta1.last_used_at.is_none()); // First retrieve sets it

    // Retrieve again — last_used_at should now be set
    let (_, meta2) = store.retrieve("test").unwrap();
    assert!(meta2.last_used_at.is_some());
}

#[test]
fn peek_does_not_update_last_used_at() {
    // Slice 3 inspection path: `wirken credentials show` and the
    // list-output scope summary call `peek` rather than `retrieve`
    // so reading the credential for display does not corrupt the
    // "when was this credential last actually used" signal.
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("value".into());
    store.store("test", "chan", &secret, None, None).unwrap();

    let (val1, meta1) = store.peek("test").unwrap();
    assert_eq!(val1.expose(), "value");
    assert!(meta1.last_used_at.is_none());

    // A subsequent peek must still see `last_used_at = None`.
    let (val2, meta2) = store.peek("test").unwrap();
    assert_eq!(val2.expose(), "value");
    assert!(meta2.last_used_at.is_none());

    // But a real retrieve DOES bump last_used_at, and a peek after
    // that reflects the retrieve.
    let _ = store.retrieve("test").unwrap();
    let (_, meta3) = store.peek("test").unwrap();
    assert!(meta3.last_used_at.is_some());
}

#[test]
fn peek_nonexistent_credential_fails() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let result = store.peek("does-not-exist");
    assert!(matches!(result, Err(crate::VaultError::NotFound(_))));
}

#[test]
fn retrieve_nonexistent_credential_fails() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let result = store.retrieve("does-not-exist");
    assert!(matches!(result, Err(crate::VaultError::NotFound(_))));
}

#[test]
fn expired_credential_returns_error() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("expired-value".into());
    let past = Utc::now() - Duration::hours(1);
    store
        .store("expired", "chan", &secret, Some(past), None)
        .unwrap();

    let result = store.retrieve("expired");
    assert!(matches!(result, Err(crate::VaultError::Expired(_))));
}

#[test]
fn rotation_due_flagged() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("value".into());
    let past = Utc::now() - Duration::hours(1);
    store
        .store("rotate-me", "chan", &secret, None, Some(past))
        .unwrap();

    let metas = store.list().unwrap();
    let meta = metas.iter().find(|m| m.name == "rotate-me").unwrap();
    assert!(meta.is_rotation_due());
}

#[test]
fn rotation_not_due_yet() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("value".into());
    let future = Utc::now() + Duration::days(90);
    store
        .store("fresh", "chan", &secret, None, Some(future))
        .unwrap();

    let metas = store.list().unwrap();
    let meta = metas.iter().find(|m| m.name == "fresh").unwrap();
    assert!(!meta.is_rotation_due());
}

#[test]
fn delete_credential() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("value".into());
    store
        .store("to-delete", "chan", &secret, None, None)
        .unwrap();

    store.delete("to-delete").unwrap();
    let result = store.retrieve("to-delete");
    assert!(matches!(result, Err(crate::VaultError::NotFound(_))));
}

#[test]
fn delete_nonexistent_fails() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let result = store.delete("nope");
    assert!(matches!(result, Err(crate::VaultError::NotFound(_))));
}

#[test]
fn delete_by_channel_clears_all_matching() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let s = VaultSecret::new("v".into());
    store
        .store("signal-token", "signal", &s, None, None)
        .unwrap();
    store
        .store("signal-adapter-key", "signal", &s, None, None)
        .unwrap();
    store
        .store("signal-endpoint", "signal", &s, None, None)
        .unwrap();
    store
        .store("openai-api-key", "openai", &s, None, None)
        .unwrap();

    let removed = store.delete_by_channel("signal").unwrap();
    assert_eq!(removed, 3);

    let remaining: Vec<String> = store.list().unwrap().into_iter().map(|m| m.name).collect();
    assert_eq!(remaining, vec!["openai-api-key".to_string()]);
}

#[test]
fn delete_by_channel_no_match_returns_zero() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let s = VaultSecret::new("v".into());
    store
        .store("openai-api-key", "openai", &s, None, None)
        .unwrap();

    let removed = store.delete_by_channel("signal").unwrap();
    assert_eq!(removed, 0);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn store_open_with_wrong_passphrase_refuses_overwrite() {
    // Regression for the setup-time bug where a second probe_keychain
    // call with an empty passphrase silently re-keyed the AgeFile
    // keychain and orphaned every row written under the first
    // passphrase. CredentialStore::open must distinguish "keychain
    // file does not exist yet" (auto-generate) from "keychain file
    // exists but unwrap failed" (hard error).
    let tmp = TempDir::new().unwrap();
    let kc_dir = tmp.path().join("kc");
    let db_path = tmp.path().join("vault.db");

    let kc1 = AgeFileKeychain::new(kc_dir.clone(), "real-passphrase".into());
    let store = CredentialStore::open(&db_path, &kc1).unwrap();
    let secret = VaultSecret::new("v".into());
    store.store("k", "chan", &secret, None, None).unwrap();
    drop(store);

    let kc2 = AgeFileKeychain::new(kc_dir.clone(), "".into());
    let result = CredentialStore::open(&db_path, &kc2);
    assert!(matches!(result, Err(crate::VaultError::Keychain(_))));

    let kc3 = AgeFileKeychain::new(kc_dir, "real-passphrase".into());
    let store3 = CredentialStore::open(&db_path, &kc3).unwrap();
    let (got, _) = store3.retrieve("k").unwrap();
    assert_eq!(got.expose(), "v");
}

#[test]
fn list_credentials() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let s1 = VaultSecret::new("v1".into());
    let s2 = VaultSecret::new("v2".into());
    let s3 = VaultSecret::new("v3".into());

    store.store("alpha", "telegram", &s1, None, None).unwrap();
    store.store("beta", "discord", &s2, None, None).unwrap();
    store.store("gamma", "slack", &s3, None, None).unwrap();

    let metas = store.list().unwrap();
    assert_eq!(metas.len(), 3);
    assert_eq!(metas[0].name, "alpha");
    assert_eq!(metas[1].name, "beta");
    assert_eq!(metas[2].name, "gamma");
}

#[test]
fn rotate_credential() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let old = VaultSecret::new("old-key".into());
    store.store("rotating", "openai", &old, None, None).unwrap();

    let new = VaultSecret::new("new-key".into());
    let future = Utc::now() + Duration::days(90);
    store.rotate("rotating", &new, Some(future)).unwrap();

    let (retrieved, meta) = store.retrieve("rotating").unwrap();
    assert_eq!(retrieved.expose(), "new-key");
    assert!(!meta.is_rotation_due());
}

#[test]
fn rotate_nonexistent_fails() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let new = VaultSecret::new("value".into());
    let result = store.rotate("nope", &new, None);
    assert!(matches!(result, Err(crate::VaultError::NotFound(_))));
}

#[test]
fn store_overwrites_existing() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let v1 = VaultSecret::new("first".into());
    let v2 = VaultSecret::new("second".into());

    store.store("key", "chan", &v1, None, None).unwrap();
    store.store("key", "chan", &v2, None, None).unwrap();

    let (retrieved, _) = store.retrieve("key").unwrap();
    assert_eq!(retrieved.expose(), "second");

    let metas = store.list().unwrap();
    assert_eq!(metas.len(), 1);
}

#[test]
fn export_encrypted_returns_bytes() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);

    let secret = VaultSecret::new("export-me".into());
    store
        .store("export-test", "chan", &secret, None, None)
        .unwrap();

    let encrypted = store.export_encrypted("export-test").unwrap();
    assert!(!encrypted.is_empty());
    // Should be at least nonce (24 bytes) + some ciphertext
    assert!(encrypted.len() > 24);
}

// ---------------------------------------------------------------------------
// Integration: keychain + store
// ---------------------------------------------------------------------------

#[test]
fn full_flow_age_keychain_to_store() {
    let tmp = TempDir::new().unwrap();

    // Set up age-file keychain
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "integration-test".into());

    // Open store with keychain (generates device key on first run)
    let store = CredentialStore::open(&tmp.path().join("vault.db"), &kc).unwrap();

    // Store a credential
    let secret = VaultSecret::new("integration-secret".into());
    store
        .store("int-test", "telegram", &secret, None, None)
        .unwrap();

    // Open store again (retrieves existing device key)
    let store2 = CredentialStore::open(&tmp.path().join("vault.db"), &kc).unwrap();
    let (retrieved, _) = store2.retrieve("int-test").unwrap();
    assert_eq!(retrieved.expose(), "integration-secret");
}

#[cfg(unix)]
#[test]
fn open_lands_0o600_on_db_and_wal_and_shm_after_first_transaction() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("vault.db");
    let store = CredentialStore::open_with_key(&db_path, generate_key()).unwrap();
    let secret = VaultSecret::new("permcheck".into());
    store.store("k", "ch", &secret, None, None).unwrap();

    for suffix in ["", "-wal", "-shm"] {
        let mut p = db_path.as_os_str().to_owned();
        p.push(suffix);
        let p = std::path::PathBuf::from(p);
        if !p.exists() {
            continue;
        }
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{}: expected 0o600, got 0o{mode:o}",
            p.display()
        );
    }
}

// ---------------------------------------------------------------------------
// vault reset tests
// ---------------------------------------------------------------------------

#[test]
fn vault_reset_removes_vault_state_and_leaves_other_files() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path();
    let db_path = data_dir.join("vault.db");
    let keychain_dir = data_dir.join("keychain");

    // Seal a device key and store one credential.
    {
        let kc = AgeFileKeychain::new(&keychain_dir, "seal-passphrase".into());
        let store = CredentialStore::open(&db_path, &kc).unwrap();
        store
            .store(
                "slack-token",
                "slack",
                &VaultSecret::new("xoxb-x".into()),
                None,
                None,
            )
            .unwrap();
    }
    // An unrelated file in the data dir must survive the reset (the audit
    // chain DB is the real thing this stands in for).
    let audit = data_dir.join("audit.db");
    std::fs::write(&audit, b"audit chain").unwrap();
    assert!(keychain_dir.is_dir());
    assert!(db_path.exists());

    let removed = crate::store::reset(data_dir, &db_path).unwrap();

    // The keychain directory and every credential DB file are gone.
    assert!(!keychain_dir.exists());
    assert!(!db_path.exists());
    assert!(removed.contains(&keychain_dir));
    assert!(removed.contains(&db_path));
    // Nothing outside the vault's own files was touched.
    assert!(audit.exists());
    assert_eq!(std::fs::read(&audit).unwrap(), b"audit chain");
    assert!(!removed.contains(&audit));
}

#[test]
fn vault_reset_then_open_creates_fresh_empty_store() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path();
    let db_path = data_dir.join("vault.db");
    let keychain_dir = data_dir.join("keychain");

    {
        let kc = AgeFileKeychain::new(&keychain_dir, "seal-passphrase".into());
        let store = CredentialStore::open(&db_path, &kc).unwrap();
        store
            .store(
                "slack-token",
                "slack",
                &VaultSecret::new("xoxb-x".into()),
                None,
                None,
            )
            .unwrap();
    }
    crate::store::reset(data_dir, &db_path).unwrap();

    // A subsequent open auto-creates via KeychainNotInitialized and the
    // store is empty. A new passphrase is fine — the old key is gone.
    let kc = AgeFileKeychain::new(&keychain_dir, "new-passphrase".into());
    let store = CredentialStore::open(&db_path, &kc).unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn vault_reset_plan_counts_rows_without_the_device_key() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path();
    let db_path = data_dir.join("vault.db");
    let keychain_dir = data_dir.join("keychain");

    {
        let kc = AgeFileKeychain::new(&keychain_dir, "seal-passphrase".into());
        let store = CredentialStore::open(&db_path, &kc).unwrap();
        store
            .store("a", "slack", &VaultSecret::new("x".into()), None, None)
            .unwrap();
        store
            .store("b", "teams", &VaultSecret::new("y".into()), None, None)
            .unwrap();
    }

    // reset_plan reports the row count from metadata alone — no keychain
    // is passed in, so no device key or decryption is involved.
    let plan = crate::store::reset_plan(data_dir, &db_path);
    assert_eq!(plan.credential_rows, Some(2));
    assert!(plan.keychain_dir.is_some());
    assert!(plan.db_files.iter().any(|p| p == &db_path));
}

/// `names` answers "what is configured" from a process that holds no
/// device key. A scheduled zirkel run uses it to tell a configured key
/// it cannot read apart from a key that was never stored.
#[test]
fn names_are_listable_without_the_device_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = tmp.path().join("vault.db");
    {
        let store = CredentialStore::open_with_key(&db, crate::crypto::generate_key()).unwrap();
        store
            .store(
                "zirkel-congress-gov-api-key",
                "zirkel",
                &VaultSecret::new("s3cret".into()),
                None,
                None,
            )
            .unwrap();
        store
            .store(
                "telegram-bot-token",
                "telegram",
                &VaultSecret::new("t0k3n".into()),
                None,
                None,
            )
            .unwrap();
    }
    // No key, no keychain: only the file.
    let names = CredentialStore::names(&db).unwrap();
    assert_eq!(
        names,
        vec![
            "telegram-bot-token".to_string(),
            "zirkel-congress-gov-api-key".to_string()
        ]
    );
    // And an absent store is an empty one, not an error.
    assert!(
        CredentialStore::names(&tmp.path().join("missing.db"))
            .unwrap()
            .is_empty()
    );
    // So is a pre-created file with no schema yet: `open` creates the
    // file before writing the table, and a command that fails between
    // the two leaves exactly this behind. Seen on a real run.
    let bare = tmp.path().join("bare.db");
    std::fs::write(&bare, b"").unwrap();
    assert!(CredentialStore::names(&bare).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Secret and identifier kinds, and what leak detection is given
// ---------------------------------------------------------------------------

/// A vault from before the `kind` column: every row has none. Opening
/// it marks the nine built-in adapter identifiers and leaves every
/// other row a secret.
#[test]
fn the_kind_migration_marks_the_builtin_identifiers_and_nothing_else() {
    use crate::kind::{BUILTIN_IDENTIFIERS, CredentialKind};
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("vault.db");
    let key = generate_key();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE credentials (
                 name TEXT PRIMARY KEY,
                 channel TEXT NOT NULL,
                 encrypted_value BLOB NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT,
                 last_used_at TEXT,
                 rotation_due_at TEXT,
                 allowed_hosts TEXT
             );",
        )
        .unwrap();
        for name in BUILTIN_IDENTIFIERS.iter().copied().chain([
            "telegram-token",
            "matrix-adapter-key",
            "my-mcp-token",
        ]) {
            let enc = encrypt(name, &VaultSecret::new("value-12345".into()), &key).unwrap();
            conn.execute(
                "INSERT INTO credentials (name, channel, encrypted_value, created_at)
                 VALUES (?1, '', ?2, ?3)",
                rusqlite::params![name, enc, Utc::now().to_rfc3339()],
            )
            .unwrap();
        }
    }
    let store = CredentialStore::open_with_key_any_format(&db, key).unwrap();
    for meta in store.list().unwrap() {
        let expected = if BUILTIN_IDENTIFIERS.contains(&meta.name.as_str()) {
            CredentialKind::Identifier
        } else {
            CredentialKind::Secret
        };
        assert_eq!(meta.kind, expected, "{}", meta.name);
    }
}

/// `store` gives a built-in identifier its kind; `store_with_kind` sets
/// one explicitly; `retrieve`, `peek` and `list` read it back, and
/// `rotate` keeps it.
#[test]
fn the_kind_is_stored_and_read_back() {
    use crate::kind::CredentialKind;
    let tmp = TempDir::new().unwrap();
    let store =
        CredentialStore::open_with_key(&tmp.path().join("vault.db"), generate_key()).unwrap();
    let v = || VaultSecret::new("value-12345".into());
    store
        .store("signal-phone-number", "signal", &v(), None, None)
        .unwrap();
    store
        .store("signal-token", "signal", &v(), None, None)
        .unwrap();
    store
        .store_with_kind(
            "support-address",
            "",
            &v(),
            None,
            None,
            &[],
            CredentialKind::Identifier,
        )
        .unwrap();

    assert_eq!(
        store.retrieve("signal-phone-number").unwrap().1.kind,
        CredentialKind::Identifier
    );
    assert_eq!(
        store.peek("signal-token").unwrap().1.kind,
        CredentialKind::Secret
    );
    store.rotate("support-address", &v(), None).unwrap();
    let kinds: Vec<_> = store
        .list()
        .unwrap()
        .into_iter()
        .map(|m| (m.name, m.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            (
                "signal-phone-number".to_string(),
                CredentialKind::Identifier
            ),
            ("signal-token".to_string(), CredentialKind::Secret),
            ("support-address".to_string(), CredentialKind::Identifier),
        ]
    );
}

/// Leak detection gets every secret's matchable parts: identifiers are
/// left out, an OAuth credential gives its tokens, a Bedrock key its
/// secret, and a value under eight bytes nothing.
#[test]
fn secrets_for_matching_skips_identifiers_splits_and_drops_short_values() {
    use crate::kind::CredentialKind;
    let tmp = TempDir::new().unwrap();
    let store =
        CredentialStore::open_with_key(&tmp.path().join("vault.db"), generate_key()).unwrap();
    let put = |name: &str, value: &str| {
        store
            .store(name, "", &VaultSecret::new(value.into()), None, None)
            .unwrap()
    };
    put("telegram-token", "123456:telegram-bot-token");
    put("matrix-username", "@wirken:example.org");
    put(
        "linear-oauth",
        r#"{"access_token":"lin-access-0001","refresh_token":"lin-refresh-0001","expires_at":1,"scope":"","provider":"linear"}"#,
    );
    put(
        "bedrock-api-key",
        "AKIAIOSFODNN7EXAMPLE:bedrock-secret-access-key",
    );
    put("short-pin", "1234");
    store
        .store_with_kind(
            "support-address",
            "",
            &VaultSecret::new("help@example.org".into()),
            None,
            None,
            &[],
            CredentialKind::Identifier,
        )
        .unwrap();

    let got: Vec<(String, Vec<String>)> = store
        .secrets_for_matching()
        .unwrap()
        .into_iter()
        .map(|s| (s.name, s.parts.iter().map(|p| p.to_string()).collect()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "bedrock-api-key".to_string(),
                vec!["bedrock-secret-access-key".to_string()]
            ),
            (
                "linear-oauth".to_string(),
                vec![
                    "lin-access-0001".to_string(),
                    "lin-refresh-0001".to_string()
                ]
            ),
            (
                "telegram-token".to_string(),
                vec!["123456:telegram-bot-token".to_string()]
            ),
        ]
    );
    // Reading them for matching is not a use.
    assert!(
        store
            .peek("telegram-token")
            .unwrap()
            .1
            .last_used_at
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// update_exclusive: compare-and-swap under the write lock
// ---------------------------------------------------------------------------

fn store_value(store: &CredentialStore, name: &str, value: &str) {
    store
        .store(name, "oauth", &VaultSecret::new(value.into()), None, None)
        .unwrap();
}

#[test]
fn update_exclusive_writes_the_replacement_decide_returns() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);
    store_value(&store, "entry", "first");
    let created = store.peek("entry").unwrap().1.created_at;

    let done = store
        .update_exclusive("entry", std::time::Duration::from_secs(1), |current| {
            assert_eq!(current.expose(), "first");
            (Some(VaultSecret::new("second".into())), 7)
        })
        .unwrap();
    assert_eq!(done.value, 7);
    assert!(done.written.unwrap());
    let (secret, meta) = store.peek("entry").unwrap();
    assert_eq!(secret.expose(), "second");
    assert_eq!(meta.created_at, created, "only the value changes");
    assert_eq!(meta.channel, "oauth");
}

#[test]
fn update_exclusive_leaves_the_entry_when_decide_returns_none() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);
    store_value(&store, "entry", "kept");
    let done = store
        .update_exclusive("entry", std::time::Duration::from_secs(1), |_| (None, ()))
        .unwrap();
    assert!(!done.written.unwrap());
    assert_eq!(store.peek("entry").unwrap().0.expose(), "kept");
    // The lock was released: an ordinary write goes through.
    store_value(&store, "entry", "after");
    assert_eq!(store.peek("entry").unwrap().0.expose(), "after");
}

#[test]
fn update_exclusive_refuses_a_missing_entry_and_releases_the_lock() {
    let tmp = TempDir::new().unwrap();
    let store = test_store(&tmp);
    let err = store
        .update_exclusive(
            "absent",
            std::time::Duration::from_secs(1),
            |_| -> (Option<VaultSecret>, ()) { panic!("decide must not run for a missing entry") },
        )
        .err()
        .expect("missing entry");
    assert!(matches!(err, crate::VaultError::NotFound(_)), "{err}");
    store_value(&store, "other", "v");
}

/// Two connections to one file stand for two processes. The second
/// waits on the first's lock and then reads what the first wrote, so a
/// caller comparing against the value it read before sees the change.
#[test]
fn a_second_connection_waits_for_the_first_and_reads_its_write() {
    let tmp = TempDir::new().unwrap();
    let key = generate_key();
    let db = tmp.path().join("vault.db");
    let first = CredentialStore::open_with_key(&db, VaultSecret::new(key.expose().into())).unwrap();
    store_value(&first, "entry", "v1");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        first
            .update_exclusive("entry", std::time::Duration::from_secs(5), |current| {
                assert_eq!(current.expose(), "v1");
                entered_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                (Some(VaultSecret::new("v2".into())), ())
            })
            .unwrap()
            .written
            .unwrap()
    });
    entered_rx.recv().unwrap();

    let second = CredentialStore::open_with_key(&db, key).unwrap();
    let seen = second
        .update_exclusive("entry", std::time::Duration::from_secs(5), |current| {
            (None, current.expose().to_string())
        })
        .unwrap();
    assert!(holder.join().unwrap());
    assert_eq!(seen.value, "v2", "the waiter reads the holder's write");
}

// ---------------------------------------------------------------------------
// Plan sign-in rows: sealed so a build that predates them cannot read
// them as a key
// ---------------------------------------------------------------------------

const PLAN_JSON: &str = r#"{"access_token":"at-plan-0001","refresh_token":"rt-plan-0001","expires_at":1,"scope":"s","provider":"openai","client_id":"oaiapp_x","subject":"u"}"#;

fn store_plan_row(store: &CredentialStore, name: &str) {
    store
        .store_with_kind(
            name,
            "oauth",
            &VaultSecret::new(PLAN_JSON.into()),
            None,
            None,
            &[],
            crate::CredentialKind::PlanSignIn,
        )
        .unwrap();
}

/// 2.3.0 reads every row through `decrypt(name, ..)` with the name
/// alone as associated data, in `retrieve`, `peek` and
/// `secrets_for_matching`, and treats an unknown kind column as a
/// secret. `decrypt` here is that function unchanged, so a plan row
/// that fails it fails every 2.3.0 read path: nothing it could send.
#[test]
fn a_plan_row_does_not_decrypt_under_its_name_alone() {
    let tmp = TempDir::new().unwrap();
    let key = generate_key();
    let store = CredentialStore::open_with_key(
        &tmp.path().join("vault.db"),
        VaultSecret::new(key.expose().into()),
    )
    .unwrap();
    store_plan_row(&store, "openai-plan");
    let sealed = store.export_encrypted("openai-plan").unwrap();
    assert!(matches!(
        decrypt("openai-plan", &sealed, &key),
        Err(crate::VaultError::Decryption(_))
    ));
    // The kind column reads as a secret to the 2.3.0 rule (anything
    // but "identifier"); the binding, not the column, is what stops it.
    let column: String = rusqlite::Connection::open(tmp.path().join("vault.db"))
        .unwrap()
        .query_row(
            "SELECT kind FROM credentials WHERE name = 'openai-plan'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(column, "plan_sign_in");

    // No row opens under its name alone: the binding is sealed in too.
    store
        .store(
            "openai-api-key",
            "openai",
            &VaultSecret::new("sk-key".into()),
            None,
            None,
        )
        .unwrap();
    let plain = store.export_encrypted("openai-api-key").unwrap();
    assert!(decrypt("openai-api-key", &plain, &key).is_err());
}

/// In this build a plan row is never handed out as a key, reads for
/// inspection and leak detection, keeps its binding through an
/// exclusive update, and cannot be rotated to a typed value.
#[test]
fn a_plan_row_is_read_only_through_peek_and_keeps_its_binding() {
    let tmp = TempDir::new().unwrap();
    let key = generate_key();
    let store = CredentialStore::open_with_key(
        &tmp.path().join("vault.db"),
        VaultSecret::new(key.expose().into()),
    )
    .unwrap();
    store_plan_row(&store, "openai-plan");

    assert!(matches!(
        store.retrieve("openai-plan"),
        Err(crate::VaultError::PlanSignIn(_))
    ));
    let (secret, meta) = store.peek("openai-plan").unwrap();
    assert_eq!(secret.expose(), PLAN_JSON);
    assert_eq!(meta.kind, crate::CredentialKind::PlanSignIn);
    assert!(meta.last_used_at.is_none());

    let matched = store.secrets_for_matching().unwrap();
    let parts: Vec<String> = matched
        .iter()
        .find(|m| m.name == "openai-plan")
        .expect("matched as a secret")
        .parts
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(parts, ["at-plan-0001", "rt-plan-0001"]);

    store
        .update_exclusive("openai-plan", std::time::Duration::from_secs(1), |_| {
            (
                Some(VaultSecret::new(PLAN_JSON.replace("0001", "0002"))),
                (),
            )
        })
        .unwrap()
        .written
        .unwrap();
    let sealed = store.export_encrypted("openai-plan").unwrap();
    assert!(decrypt("openai-plan", &sealed, &key).is_err());
    assert!(
        store
            .peek("openai-plan")
            .unwrap()
            .0
            .expose()
            .contains("0002")
    );

    assert!(matches!(
        store.rotate("openai-plan", &VaultSecret::new("typed".into()), None),
        Err(crate::VaultError::PlanSignIn(_))
    ));
    assert!(
        store
            .peek("openai-plan")
            .unwrap()
            .0
            .expose()
            .contains("0002")
    );
}

mod destination_binding {
    use super::*;
    use crate::binding::{Binding, Destination, McpServerGrant};
    use crate::{VaultError, backup_vault, restore_vault};

    fn v(s: &str) -> VaultSecret {
        VaultSecret::new(s.into())
    }

    fn mcp(name: &str, entry: &str) -> Destination {
        Destination::McpServer(McpServerGrant {
            name: name.into(),
            entry: entry.into(),
        })
    }

    #[test]
    fn a_value_goes_only_where_its_binding_allows() {
        let tmp = TempDir::new().unwrap();
        let store = test_store(&tmp);
        let mut binding = Binding::default();
        binding.grant(mcp("linear", "sha256:aa"));
        store
            .store_bound(
                "linear-token",
                "mcp",
                &v("tok-123456"),
                None,
                None,
                &binding,
                crate::CredentialKind::Secret,
            )
            .unwrap();
        assert!(
            store
                .retrieve_for("linear-token", &mcp("linear", "sha256:aa"))
                .is_ok()
        );
        for other in [
            mcp("linear", "sha256:bb"),
            mcp("evil", "sha256:aa"),
            Destination::Host("api.linear.app".into()),
            Destination::Adapter("slack".into()),
        ] {
            assert!(matches!(
                store.retrieve_for("linear-token", &other),
                Err(VaultError::NotPermitted { .. })
            ));
        }
    }

    #[test]
    fn an_edited_binding_column_does_not_decrypt() {
        let tmp = TempDir::new().unwrap();
        let key = generate_key();
        let db = tmp.path().join("vault.db");
        let store = CredentialStore::open_with_key(&db, VaultSecret::new(key.expose().to_string()))
            .unwrap();
        store
            .store_with_hosts(
                "gh",
                "",
                &v("ghp-123456"),
                None,
                None,
                &["api.github.com".into()],
            )
            .unwrap();
        store
            .store("other", "", &v("other-123456"), None, None)
            .unwrap();

        let conn = rusqlite::Connection::open(&db).unwrap();
        let widened = Binding::hosts(&["api.github.com".into(), "evil.example".into()]);
        conn.execute(
            "UPDATE credentials SET binding = ?1, allowed_hosts = ?2 WHERE name = 'gh'",
            rusqlite::params![widened.canonical(), r#"["api.github.com","evil.example"]"#],
        )
        .unwrap();
        assert!(
            store
                .retrieve_for("gh", &Destination::Host("evil.example".into()))
                .is_err()
        );
        assert!(store.peek("gh").is_err());

        // A ciphertext moved onto another row does not decrypt either.
        let (enc, binding): (Vec<u8>, String) = conn
            .query_row(
                "SELECT encrypted_value, binding FROM credentials WHERE name = 'other'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        conn.execute(
            "UPDATE credentials SET encrypted_value = ?1, binding = ?2 WHERE name = 'gh'",
            rusqlite::params![enc, binding],
        )
        .unwrap();
        assert!(store.peek("gh").is_err());
    }

    #[test]
    fn a_grant_reseals_and_rotation_and_refresh_keep_the_binding() {
        let tmp = TempDir::new().unwrap();
        let store = test_store(&tmp);
        store
            .store("key", "", &v("value-123456"), None, None)
            .unwrap();
        let wait = std::time::Duration::from_secs(1);

        let now = store
            .update_binding_exclusive("key", wait, |b| {
                let mut b = b.clone();
                b.grant(Destination::Host("api.example.com".into()));
                Some(b)
            })
            .unwrap();
        assert!(now.permits(&Destination::Host("api.example.com".into())));

        store.rotate("key", &v("value-654321"), None).unwrap();
        store
            .update_exclusive("key", wait, |_| (Some(v("value-999999")), ()))
            .unwrap()
            .written
            .unwrap();
        let (secret, meta) = store
            .retrieve_for("key", &Destination::Host("api.example.com".into()))
            .unwrap();
        assert_eq!(secret.expose(), "value-999999");
        assert_eq!(meta.binding.hosts, vec!["api.example.com".to_string()]);

        let unchanged = store
            .update_binding_exclusive("key", wait, |_| None)
            .unwrap();
        assert_eq!(unchanged, meta.binding);
    }

    #[test]
    fn an_adapters_own_credentials_are_bound_to_it() {
        let tmp = TempDir::new().unwrap();
        let store = test_store(&tmp);
        store
            .store("slack-token", "slack", &v("xoxb-123456"), None, None)
            .unwrap();
        store
            .store("openai-api-key", "openai", &v("sk-123456"), None, None)
            .unwrap();
        assert!(
            store
                .retrieve_for("slack-token", &Destination::Adapter("slack".into()))
                .is_ok()
        );
        assert!(
            store
                .retrieve_for("slack-token", &Destination::Adapter("discord".into()))
                .is_err()
        );
        assert!(store.peek("openai-api-key").unwrap().1.binding.is_empty());
    }

    /// A format 1 vault: rows sealed under their name.
    fn format_1_vault(db: &std::path::Path, key: &VaultSecret, rows: &[(&str, &str)]) {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute_batch(
            "CREATE TABLE credentials (
                 name TEXT PRIMARY KEY, channel TEXT NOT NULL,
                 encrypted_value BLOB NOT NULL, created_at TEXT NOT NULL,
                 expires_at TEXT, last_used_at TEXT, rotation_due_at TEXT,
                 allowed_hosts TEXT, kind TEXT
             );",
        )
        .unwrap();
        for (name, value) in rows {
            let enc = encrypt(name, &VaultSecret::new((*value).into()), key).unwrap();
            conn.execute(
                "INSERT INTO credentials (name, channel, encrypted_value, created_at, kind)
                 VALUES (?1, '', ?2, ?3, 'secret')",
                rusqlite::params![name, enc, Utc::now().to_rfc3339()],
            )
            .unwrap();
        }
    }

    #[test]
    fn a_migration_reseals_every_row_under_its_binding_and_verifies() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("vault.db");
        let key = generate_key();
        format_1_vault(&db, &key, &[("a", "alpha-123456"), ("b", "beta-1234567")]);
        assert_eq!(CredentialStore::format_at(&db).unwrap(), Some(1));

        let backup = tmp.path().join("vault.db.bak");
        assert_eq!(backup_vault(&db, &backup).unwrap(), 2);

        let mut store = CredentialStore::open_with_key_any_format(
            &db,
            VaultSecret::new(key.expose().to_string()),
        )
        .unwrap();
        let mut bindings = std::collections::BTreeMap::new();
        bindings.insert("a".to_string(), Binding::hosts(&["api.example.com".into()]));
        let migration = store.migrate_to_bound(&bindings).unwrap();
        assert!(matches!(
            store.migrate_to_bound(&bindings),
            Err(VaultError::AlreadyMigrated)
        ));

        let reopened =
            CredentialStore::open_with_key(&db, VaultSecret::new(key.expose().to_string()))
                .unwrap();
        assert_eq!(reopened.plaintext_digests().unwrap(), migration.digests);
        assert_eq!(CredentialStore::format_at(&db).unwrap(), Some(2));
        assert!(
            reopened
                .retrieve_for("a", &Destination::Host("api.example.com".into()))
                .is_ok()
        );
        assert!(reopened.peek("b").unwrap().1.binding.is_empty());

        // Restoring the backup puts the format 1 vault back.
        drop((store, reopened));
        restore_vault(&backup, &db).unwrap();
        assert_eq!(CredentialStore::format_at(&db).unwrap(), Some(1));
        assert_eq!(
            CredentialStore::open_with_key_any_format(&db, key)
                .unwrap()
                .count()
                .unwrap(),
            2
        );
    }

    #[test]
    fn a_migration_that_cannot_decrypt_a_row_changes_nothing() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("vault.db");
        let key = generate_key();
        format_1_vault(&db, &key, &[("a", "alpha-123456")]);
        let mut store = CredentialStore::open_with_key_any_format(&db, generate_key()).unwrap();
        assert!(store.migrate_to_bound(&Default::default()).is_err());
        assert_eq!(CredentialStore::format_at(&db).unwrap(), Some(1));
        drop(store);
        let store = CredentialStore::open_with_key_any_format(&db, key).unwrap();
        assert_eq!(store.format(), 1);
    }
}

/// A change to an entry shows in its fingerprint, read without the key:
/// a rotation in the value, a grant in the binding, a removal as a
/// missing name. Reading the entry leaves it as it was.
#[test]
fn fingerprints_change_with_a_rotation_a_grant_and_a_removal_only() {
    let tmp = TempDir::new().unwrap();
    let kc = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
    let db = tmp.path().join("vault.db");
    let store = CredentialStore::open(&db, &kc).unwrap();
    store
        .store_bound(
            "records-api",
            "",
            &VaultSecret::new("v1".into()),
            None,
            None,
            &crate::Binding::hosts(&["a.example.org".to_string()]),
            crate::default_kind("records-api"),
        )
        .unwrap();
    let first = CredentialStore::fingerprints(&db).unwrap()["records-api"];

    store.retrieve("records-api").unwrap();
    assert_eq!(
        CredentialStore::fingerprints(&db).unwrap()["records-api"],
        first,
        "a read changes nothing"
    );

    store
        .rotate("records-api", &VaultSecret::new("v2".into()), None)
        .unwrap();
    let rotated = CredentialStore::fingerprints(&db).unwrap()["records-api"];
    assert_ne!(rotated.value, first.value);
    assert_eq!(rotated.binding, first.binding);

    store
        .update_binding_exclusive("records-api", std::time::Duration::from_secs(5), |b| {
            let mut b = b.clone();
            b.grant(crate::Destination::Host("b.example.org".into()))
                .then_some(b)
        })
        .unwrap();
    let granted = CredentialStore::fingerprints(&db).unwrap()["records-api"];
    assert_ne!(granted.binding, rotated.binding);

    store.delete("records-api").unwrap();
    assert!(
        !CredentialStore::fingerprints(&db)
            .unwrap()
            .contains_key("records-api")
    );
    assert!(
        CredentialStore::fingerprints(&tmp.path().join("absent.db"))
            .unwrap()
            .is_empty()
    );
}
