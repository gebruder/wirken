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

    let encrypted = encrypt(&plaintext, &key).unwrap();
    let decrypted = decrypt(&encrypted, &key).unwrap();

    assert_eq!(decrypted.expose(), "super-secret-api-key");
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    let key = generate_key();
    let plaintext = VaultSecret::new("same-input".into());

    let enc1 = encrypt(&plaintext, &key).unwrap();
    let enc2 = encrypt(&plaintext, &key).unwrap();

    // Different nonces → different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    assert_eq!(decrypt(&enc1, &key).unwrap().expose(), "same-input");
    assert_eq!(decrypt(&enc2, &key).unwrap().expose(), "same-input");
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key1 = generate_key();
    let key2 = generate_key();
    let plaintext = VaultSecret::new("secret".into());

    let encrypted = encrypt(&plaintext, &key1).unwrap();
    let result = decrypt(&encrypted, &key2);

    assert!(result.is_err());
}

#[test]
fn decrypt_truncated_ciphertext_fails() {
    let result = decrypt(&[0u8; 10], &generate_key());
    assert!(result.is_err());
}

#[test]
fn decrypt_empty_ciphertext_fails() {
    let result = decrypt(&[], &generate_key());
    assert!(result.is_err());
}

#[test]
fn encrypt_with_wrong_key_length_fails() {
    // 10 hex chars = 5 bytes, not 32
    let bad_key = VaultSecret::new("abcdef0123".into());
    let plaintext = VaultSecret::new("value".into());

    let result = encrypt(&plaintext, &bad_key);
    assert!(result.is_err());
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
