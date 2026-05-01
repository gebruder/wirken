use crate::crypto::derive_key_from_passphrase;
use crate::error::VaultError;
use crate::secret::VaultSecret;

/// The kind of keychain backend in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainKind {
    MacOs,
    Linux,
    AgeFile,
}

impl std::fmt::Display for KeychainKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainKind::MacOs => write!(f, "macOS Keychain"),
            KeychainKind::Linux => write!(f, "Linux Secret Service"),
            KeychainKind::AgeFile => write!(f, "age-encrypted file"),
        }
    }
}

/// Trait for keychain backends that store the vault's device key.
pub trait Keychain: Send + Sync {
    /// Which backend this is.
    fn kind(&self) -> KeychainKind;

    /// Store the device key in the keychain.
    fn store_device_key(&self, key: &VaultSecret) -> Result<(), VaultError>;

    /// Retrieve the device key from the keychain.
    fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError>;

    /// Delete the device key from the keychain.
    fn delete_device_key(&self) -> Result<(), VaultError>;

    /// Store an auxiliary keychain entry under `name`. Used for
    /// secrets that share the keychain's trust posture but are not
    /// the vault device key itself (e.g., the alarm-log HMAC key).
    /// `name` must be a stable, short identifier; backends may
    /// concatenate it into a larger lookup key.
    ///
    /// Default impl returns [`VaultError::Keychain`] so older
    /// backends without aux support fail-closed; the caller's
    /// fallback path engages.
    fn store_aux_key(&self, name: &str, _key: &[u8]) -> Result<(), VaultError> {
        Err(VaultError::Keychain(format!(
            "store_aux_key({name}) not implemented for {} backend",
            self.kind()
        )))
    }

    /// Retrieve an auxiliary keychain entry previously stored via
    /// [`Keychain::store_aux_key`]. Default impl returns Err.
    fn retrieve_aux_key(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        Err(VaultError::Keychain(format!(
            "retrieve_aux_key({name}) not implemented for {} backend",
            self.kind()
        )))
    }

    /// Delete an auxiliary keychain entry. Default impl returns Err.
    fn delete_aux_key(&self, name: &str) -> Result<(), VaultError> {
        Err(VaultError::Keychain(format!(
            "delete_aux_key({name}) not implemented for {} backend",
            self.kind()
        )))
    }
}

/// Load the alarm-log HMAC key from `keychain`, generating and
/// storing one if it is missing. The key is 32 random bytes hex-
/// encoded for storage; this helper unhexes the stored value back
/// into raw bytes for use with [`hmac::Mac`].
///
/// Returns `Err` only when both the retrieve and the
/// generate-then-store paths fail. The caller is expected to fall
/// back to unsigned alarm-log mode and emit a prominent warn.
pub fn load_or_create_alarm_log_key(keychain: &dyn Keychain) -> Result<Vec<u8>, VaultError> {
    const ALARM_LOG_KEY_NAME: &str = "alarm-log-hmac";
    if let Ok(bytes) = keychain.retrieve_aux_key(ALARM_LOG_KEY_NAME) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
        // Length mismatch is treated as missing; regenerate.
    }
    // On the age-file backend the wrapping key derives from the
    // operator's passphrase. If the keychain has not been unlocked
    // (no device key stored yet, or the caller passed an empty
    // passphrase before the operator was prompted), generating a
    // fresh aux key now would write `aux-<name>.age` encrypted under
    // whatever empty/wrong passphrase is currently in scope —
    // providing no integrity defense. Refuse the create path in
    // that state; the caller falls back to unsigned alarm-log mode
    // and emits a prominent warn. OS keychains (macOS / Linux) do
    // not have this problem because their wrapping is OS-managed.
    if keychain.kind() == KeychainKind::AgeFile && keychain.retrieve_device_key().is_err() {
        return Err(VaultError::Keychain(
            "age-file keychain not unlocked; will not create alarm-log aux key \
             under an empty passphrase. Open the vault first (or run `wirken \
             setup`) so the device key is reachable."
                .into(),
        ));
    }
    let mut key = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut key);
    keychain.store_aux_key(ALARM_LOG_KEY_NAME, &key)?;
    Ok(key.to_vec())
}

// ---------------------------------------------------------------------------
// macOS Keychain backend
// ---------------------------------------------------------------------------

#[cfg(feature = "keychain-macos")]
mod macos {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use std::sync::{Mutex, OnceLock};

    const SERVICE: &str = "dev.wirken.vault";
    const ACCOUNT: &str = "device-key";

    /// Process-local serialization point for macOS Keychain access.
    ///
    /// security-framework's `set_generic_password` and
    /// `get_generic_password` map to `SecItemAdd` / `SecItemUpdate` /
    /// `SecItemCopyMatching`; calls that race against each other on
    /// the same {SERVICE, ACCOUNT} slot can observe an in-flight
    /// update mid-write and leave the caller with a stale read.
    /// Holding this mutex around every keychain call serializes
    /// access from every thread inside this process.
    ///
    /// Cross-process races remain. They require an attacker running
    /// at the same UID as the gateway (otherwise the keychain
    /// permission gate refuses the call), which is already
    /// out-of-scope for the local-attacker threat model documented
    /// in [security-properties.md].
    fn lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    pub struct MacOsKeychain;

    impl Keychain for MacOsKeychain {
        fn kind(&self) -> KeychainKind {
            KeychainKind::MacOs
        }

        fn store_device_key(&self, key: &VaultSecret) -> Result<(), VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            set_generic_password(SERVICE, ACCOUNT, key.expose().as_bytes())
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain store: {e}")))?;
            Ok(())
        }

        fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            let bytes = get_generic_password(SERVICE, ACCOUNT)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain retrieve: {e}")))?;
            let s = String::from_utf8(bytes)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain decode: {e}")))?;
            Ok(VaultSecret::new(s))
        }

        fn delete_device_key(&self) -> Result<(), VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            delete_generic_password(SERVICE, ACCOUNT)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain delete: {e}")))?;
            Ok(())
        }

        fn store_aux_key(&self, name: &str, key: &[u8]) -> Result<(), VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            let account = format!("aux-{name}");
            set_generic_password(SERVICE, &account, key)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain store aux: {e}")))?;
            Ok(())
        }

        fn retrieve_aux_key(&self, name: &str) -> Result<Vec<u8>, VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            let account = format!("aux-{name}");
            get_generic_password(SERVICE, &account)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain retrieve aux: {e}")))
        }

        fn delete_aux_key(&self, name: &str) -> Result<(), VaultError> {
            let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
            let account = format!("aux-{name}");
            delete_generic_password(SERVICE, &account)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain delete aux: {e}")))?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Concurrent acquisitions of the keychain lock must serialize.
        /// We don't drive a real keychain call (those need macOS keychain
        /// access at runtime); instead we drive a counter inside the
        /// critical section and assert no overlap.
        #[test]
        #[cfg(target_os = "macos")]
        fn lock_serializes_concurrent_get_modify_put() {
            const N: usize = 16;
            let live = Arc::new(AtomicUsize::new(0));
            let max = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..N {
                let live = live.clone();
                let max = max.clone();
                handles.push(std::thread::spawn(move || {
                    let _g = lock().lock().unwrap_or_else(|p| p.into_inner());
                    let in_critical = live.fetch_add(1, Ordering::AcqRel) + 1;
                    max.fetch_max(in_critical, Ordering::AcqRel);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    live.fetch_sub(1, Ordering::AcqRel);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            assert_eq!(
                max.load(Ordering::Acquire),
                1,
                "more than one thread held the keychain lock simultaneously"
            );
        }
    }
}

#[cfg(feature = "keychain-macos")]
pub use macos::MacOsKeychain;

// ---------------------------------------------------------------------------
// Linux Secret Service backend (D-Bus → GNOME Keyring / KDE Wallet)
// ---------------------------------------------------------------------------

#[cfg(feature = "keychain-linux")]
mod linux {
    use super::*;
    use secret_service::EncryptionType;
    use secret_service::blocking::{Collection, SecretService};

    const LABEL: &str = "wirken-device-key";

    pub struct LinuxKeychain;

    impl LinuxKeychain {
        fn with_collection<F, T>(&self, f: F) -> Result<T, VaultError>
        where
            F: FnOnce(&Collection) -> Result<T, VaultError>,
        {
            let ss = SecretService::connect(EncryptionType::Dh)
                .map_err(|e| VaultError::Keychain(format!("D-Bus connect: {e}")))?;
            let collection = ss
                .get_default_collection()
                .map_err(|e| VaultError::Keychain(format!("D-Bus default collection: {e}")))?;

            // Unlock if locked
            if collection
                .is_locked()
                .map_err(|e| VaultError::Keychain(format!("D-Bus lock check: {e}")))?
            {
                collection
                    .unlock()
                    .map_err(|e| VaultError::Keychain(format!("D-Bus unlock: {e}")))?;
            }

            f(&collection)
        }
    }

    impl Keychain for LinuxKeychain {
        fn kind(&self) -> KeychainKind {
            KeychainKind::Linux
        }

        fn store_device_key(&self, key: &VaultSecret) -> Result<(), VaultError> {
            self.with_collection(|collection| {
                // Delete existing if present
                let _ = self.delete_device_key();

                let attributes = vec![("application", "wirken"), ("usage", "device-key")];
                collection
                    .create_item(
                        LABEL,
                        attributes.into_iter().collect(),
                        key.expose().as_bytes(),
                        true, // replace
                        "text/plain",
                    )
                    .map_err(|e| VaultError::Keychain(format!("D-Bus store: {e}")))?;
                Ok(())
            })
        }

        fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError> {
            self.with_collection(|collection| {
                let attributes = vec![("application", "wirken"), ("usage", "device-key")];
                let items = collection
                    .search_items(attributes.into_iter().collect())
                    .map_err(|e| VaultError::Keychain(format!("D-Bus search: {e}")))?;

                let item = items.first().ok_or_else(|| {
                    VaultError::Keychain("device key not found in Secret Service".into())
                })?;
                let secret = item
                    .get_secret()
                    .map_err(|e| VaultError::Keychain(format!("D-Bus get secret: {e}")))?;
                let s = String::from_utf8(secret)
                    .map_err(|e| VaultError::Keychain(format!("D-Bus decode: {e}")))?;
                Ok(VaultSecret::new(s))
            })
        }

        fn delete_device_key(&self) -> Result<(), VaultError> {
            self.with_collection(|collection| {
                let attributes = vec![("application", "wirken"), ("usage", "device-key")];
                let items = collection
                    .search_items(attributes.into_iter().collect())
                    .map_err(|e| VaultError::Keychain(format!("D-Bus search: {e}")))?;
                for item in items {
                    item.delete()
                        .map_err(|e| VaultError::Keychain(format!("D-Bus delete: {e}")))?;
                }
                Ok(())
            })
        }

        fn store_aux_key(&self, name: &str, key: &[u8]) -> Result<(), VaultError> {
            let usage = format!("aux-{name}");
            let label = format!("wirken-aux-{name}");
            self.with_collection(|collection| {
                // Drop any existing entry with the same usage attribute.
                let attributes_drop = vec![("application", "wirken"), ("usage", usage.as_str())];
                if let Ok(items) = collection.search_items(attributes_drop.into_iter().collect()) {
                    for item in items {
                        let _ = item.delete();
                    }
                }
                let attributes = vec![("application", "wirken"), ("usage", usage.as_str())];
                collection
                    .create_item(
                        &label,
                        attributes.into_iter().collect(),
                        key,
                        true,
                        "application/octet-stream",
                    )
                    .map_err(|e| VaultError::Keychain(format!("D-Bus store aux: {e}")))?;
                Ok(())
            })
        }

        fn retrieve_aux_key(&self, name: &str) -> Result<Vec<u8>, VaultError> {
            let usage = format!("aux-{name}");
            self.with_collection(|collection| {
                let attributes = vec![("application", "wirken"), ("usage", usage.as_str())];
                let items = collection
                    .search_items(attributes.into_iter().collect())
                    .map_err(|e| VaultError::Keychain(format!("D-Bus search aux: {e}")))?;
                let item = items.first().ok_or_else(|| {
                    VaultError::Keychain(format!("aux key {name} not found in Secret Service"))
                })?;
                item.get_secret()
                    .map_err(|e| VaultError::Keychain(format!("D-Bus get aux secret: {e}")))
            })
        }

        fn delete_aux_key(&self, name: &str) -> Result<(), VaultError> {
            let usage = format!("aux-{name}");
            self.with_collection(|collection| {
                let attributes = vec![("application", "wirken"), ("usage", usage.as_str())];
                let items = collection
                    .search_items(attributes.into_iter().collect())
                    .map_err(|e| VaultError::Keychain(format!("D-Bus search aux: {e}")))?;
                for item in items {
                    item.delete()
                        .map_err(|e| VaultError::Keychain(format!("D-Bus delete aux: {e}")))?;
                }
                Ok(())
            })
        }
    }
}

#[cfg(feature = "keychain-linux")]
pub use linux::LinuxKeychain;

// ---------------------------------------------------------------------------
// Age-encrypted file backend (always available as fallback)
// ---------------------------------------------------------------------------

mod age_file {
    use super::*;
    use crate::crypto::{decrypt, encrypt};
    use std::fs;
    use std::path::PathBuf;

    const SALT_SIZE: usize = 32;

    /// AAD bound into the device-key wrap. Pins the keychain slot to
    /// its context so a credential ciphertext cannot be substituted.
    const KEYCHAIN_AAD: &str = "wirken/keychain/device-key";

    /// Age-file keychain that stores the device key encrypted with a
    /// passphrase-derived key in a local file.
    pub struct AgeFileKeychain {
        path: PathBuf,
        passphrase: VaultSecret,
    }

    impl AgeFileKeychain {
        /// Create a new age-file keychain at the given path.
        /// The passphrase is used to derive the encryption key via Argon2id.
        pub fn new(path: impl Into<PathBuf>, passphrase: String) -> Self {
            Self {
                path: path.into(),
                passphrase: VaultSecret::new(passphrase),
            }
        }

        fn key_file_path(&self) -> PathBuf {
            self.path.join("device-key.age")
        }

        fn salt_file_path(&self) -> PathBuf {
            self.path.join("device-key.salt")
        }

        fn derive_wrapping_key(&self, salt: &[u8]) -> Result<VaultSecret, VaultError> {
            derive_key_from_passphrase(self.passphrase.expose(), salt)
        }
    }

    impl Keychain for AgeFileKeychain {
        fn kind(&self) -> KeychainKind {
            KeychainKind::AgeFile
        }

        fn store_device_key(&self, key: &VaultSecret) -> Result<(), VaultError> {
            // Ensure directory exists
            fs::create_dir_all(&self.path)?;

            // Generate a random salt
            let mut salt = [0u8; SALT_SIZE];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);

            // Derive wrapping key from passphrase + salt
            let wrapping_key = self.derive_wrapping_key(&salt)?;

            // Encrypt the device key. The AAD pins the ciphertext to
            // the keychain context — a credential blob from the main
            // store cannot decrypt into the keychain slot (and vice
            // versa) because the AEAD tag would not match.
            let encrypted = encrypt(KEYCHAIN_AAD, key, &wrapping_key)?;

            // Write salt and encrypted key
            fs::write(self.salt_file_path(), salt)?;

            // Set restrictive permissions before writing the key file
            let key_path = self.key_file_path();
            fs::write(&key_path, &encrypted)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                fs::set_permissions(self.salt_file_path(), fs::Permissions::from_mode(0o600))?;
            }

            #[cfg(not(unix))]
            {
                // No 0o600-equivalent on this platform. The vault
                // device key relies on user-profile isolation of the
                // data directory for confidentiality. Warn so the
                // operator can confirm their threat model accepts
                // that posture.
                tracing::warn!(
                    "vault device key written to {} without 0o600-equivalent ACL; \
                     relying on user profile isolation for confidentiality",
                    key_path.display()
                );
            }

            Ok(())
        }

        fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError> {
            let salt = fs::read(self.salt_file_path())
                .map_err(|e| VaultError::Keychain(format!("read salt: {e}")))?;
            let encrypted = fs::read(self.key_file_path())
                .map_err(|e| VaultError::Keychain(format!("read key file: {e}")))?;

            let wrapping_key = self.derive_wrapping_key(&salt)?;
            decrypt(KEYCHAIN_AAD, &encrypted, &wrapping_key)
        }

        fn delete_device_key(&self) -> Result<(), VaultError> {
            let _ = fs::remove_file(self.key_file_path());
            let _ = fs::remove_file(self.salt_file_path());
            Ok(())
        }

        fn store_aux_key(&self, name: &str, key: &[u8]) -> Result<(), VaultError> {
            fs::create_dir_all(&self.path)?;
            let mut salt = [0u8; SALT_SIZE];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);
            let wrapping_key = self.derive_wrapping_key(&salt)?;
            let aad = format!("wirken/keychain/aux/{name}");
            // The aux key is raw bytes; hex-encode through VaultSecret
            // for the AEAD-string interface and unhex on retrieve.
            let hex = hex_encode_bytes(key);
            let encrypted = encrypt(&aad, &VaultSecret::new(hex), &wrapping_key)?;

            let key_path = self.aux_key_file(name);
            let salt_path = self.aux_salt_file(name);
            fs::write(&salt_path, salt)?;
            fs::write(&key_path, &encrypted)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o600))?;
            }
            #[cfg(not(unix))]
            {
                tracing::warn!(
                    "aux key {name} written to {} without 0o600-equivalent ACL; \
                     relying on user profile isolation for confidentiality",
                    key_path.display()
                );
            }
            Ok(())
        }

        fn retrieve_aux_key(&self, name: &str) -> Result<Vec<u8>, VaultError> {
            let salt = fs::read(self.aux_salt_file(name))
                .map_err(|e| VaultError::Keychain(format!("read aux salt: {e}")))?;
            let encrypted = fs::read(self.aux_key_file(name))
                .map_err(|e| VaultError::Keychain(format!("read aux key file: {e}")))?;
            let wrapping_key = self.derive_wrapping_key(&salt)?;
            let aad = format!("wirken/keychain/aux/{name}");
            let secret = decrypt(&aad, &encrypted, &wrapping_key)?;
            hex_decode_bytes(secret.expose())
        }

        fn delete_aux_key(&self, name: &str) -> Result<(), VaultError> {
            let _ = fs::remove_file(self.aux_key_file(name));
            let _ = fs::remove_file(self.aux_salt_file(name));
            Ok(())
        }
    }

    impl AgeFileKeychain {
        fn aux_key_file(&self, name: &str) -> PathBuf {
            self.path.join(format!("aux-{name}.age"))
        }

        fn aux_salt_file(&self, name: &str) -> PathBuf {
            self.path.join(format!("aux-{name}.salt"))
        }
    }

    fn hex_encode_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_decode_bytes(hex: &str) -> Result<Vec<u8>, VaultError> {
        if !hex.len().is_multiple_of(2) {
            return Err(VaultError::Keychain("aux key hex has odd length".into()));
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| VaultError::Keychain(format!("aux key hex decode: {e}")))?;
            out.push(byte);
        }
        Ok(out)
    }
}

pub use age_file::AgeFileKeychain;

// ---------------------------------------------------------------------------
// Runtime keychain probe
// ---------------------------------------------------------------------------

/// Probe for a working keychain, falling back to age-file.
///
/// On macOS (with keychain-macos feature): tries macOS Keychain first.
/// On Linux (with keychain-linux feature): tries Secret Service first.
/// Always falls back to age-file if the platform keychain fails or is unavailable.
pub fn probe_keychain(
    data_dir: &std::path::Path,
    passphrase_fn: impl FnOnce() -> String,
) -> Box<dyn Keychain> {
    #[cfg(feature = "keychain-macos")]
    {
        let kc = MacOsKeychain;
        // Test if we can access the keychain
        match kc.retrieve_device_key() {
            Ok(_) => {
                tracing::info!("Using macOS Keychain");
                return Box::new(kc);
            }
            Err(_) => {
                // Try storing a test value to see if keychain is accessible
                let test = VaultSecret::new("probe".into());
                if kc.store_device_key(&test).is_ok() {
                    let _ = kc.delete_device_key();
                    tracing::info!("Using macOS Keychain");
                    return Box::new(kc);
                }
                tracing::warn!("macOS Keychain unavailable, falling back to age-file");
            }
        }
    }

    #[cfg(feature = "keychain-linux")]
    {
        let kc = LinuxKeychain;
        match kc.retrieve_device_key() {
            Ok(_) => {
                tracing::info!("Using Linux Secret Service");
                return Box::new(kc);
            }
            Err(_) => {
                let test = VaultSecret::new("probe".into());
                if kc.store_device_key(&test).is_ok() {
                    let _ = kc.delete_device_key();
                    tracing::info!("Using Linux Secret Service");
                    return Box::new(kc);
                }
                tracing::warn!("Linux Secret Service unavailable, falling back to age-file");
            }
        }
    }

    tracing::info!("Using age-encrypted file keychain");
    let passphrase = passphrase_fn();
    Box::new(AgeFileKeychain::new(data_dir.join("keychain"), passphrase))
}
