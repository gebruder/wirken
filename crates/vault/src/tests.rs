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
    let store = CredentialStore::open_with_key(&db, key).unwrap();
    let (secret, meta) = store.retrieve("legacy").unwrap();
    assert_eq!(secret.expose(), "legacy-token");
    assert!(
        meta.allowed_hosts.is_empty(),
        "pre-migration row must read as unbound"
    );
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
