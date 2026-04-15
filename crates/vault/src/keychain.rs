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

    const SERVICE: &str = "dev.wirken.vault";
    const ACCOUNT: &str = "device-key";

    pub struct MacOsKeychain;

    impl Keychain for MacOsKeychain {
        fn kind(&self) -> KeychainKind {
            KeychainKind::MacOs
        }

        fn store_device_key(&self, key: &VaultSecret) -> Result<(), VaultError> {
            set_generic_password(SERVICE, ACCOUNT, key.expose().as_bytes())
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain store: {e}")))?;
            Ok(())
        }

        fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError> {
            let bytes = get_generic_password(SERVICE, ACCOUNT)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain retrieve: {e}")))?;
            let s = String::from_utf8(bytes)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain decode: {e}")))?;
            Ok(VaultSecret::new(s))
        }

        fn delete_device_key(&self) -> Result<(), VaultError> {
            delete_generic_password(SERVICE, ACCOUNT)
                .map_err(|e| VaultError::Keychain(format!("macOS Keychain delete: {e}")))?;
            Ok(())
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
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut salt);

            // Derive wrapping key from passphrase + salt
            let wrapping_key = self.derive_wrapping_key(&salt)?;

            // Encrypt the device key
            let encrypted = encrypt(key, &wrapping_key)?;

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

            Ok(())
        }

        fn retrieve_device_key(&self) -> Result<VaultSecret, VaultError> {
            let salt = fs::read(self.salt_file_path())
                .map_err(|e| VaultError::Keychain(format!("read salt: {e}")))?;
            let encrypted = fs::read(self.key_file_path())
                .map_err(|e| VaultError::Keychain(format!("read key file: {e}")))?;

            let wrapping_key = self.derive_wrapping_key(&salt)?;
            decrypt(&encrypted, &wrapping_key)
        }

        fn delete_device_key(&self) -> Result<(), VaultError> {
            let _ = fs::remove_file(self.key_file_path());
            let _ = fs::remove_file(self.salt_file_path());
            Ok(())
        }
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
