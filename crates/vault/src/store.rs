use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::{decrypt, encrypt, generate_key};
use crate::error::VaultError;
use crate::keychain::Keychain;
use crate::secret::VaultSecret;

/// Metadata for a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub name: String,
    pub channel: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub rotation_due_at: Option<DateTime<Utc>>,
}

impl CredentialMetadata {
    /// Check if this credential has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Check if this credential is due for rotation.
    pub fn is_rotation_due(&self) -> bool {
        self.rotation_due_at
            .map(|due| Utc::now() > due)
            .unwrap_or(false)
    }
}

/// SQLite-backed credential store with encrypted values.
pub struct CredentialStore {
    conn: Connection,
    device_key: VaultSecret,
}

impl CredentialStore {
    /// Open or create a credential store at the given path.
    /// The keychain provides the device key for encryption/decryption.
    ///
    /// On `VaultError::Decryption` from `retrieve_device_key` — an existing
    /// keychain file that won't unwrap with the supplied passphrase — this
    /// refuses to overwrite. Only `VaultError::KeychainNotInitialized` (no
    /// device key has been stored yet on this backend) routes to the
    /// auto-create branch. Every other backend error propagates so the
    /// operator decides what to do, instead of being masked by a silent
    /// re-seal.
    pub fn open(db_path: &Path, keychain: &dyn Keychain) -> Result<Self, VaultError> {
        let device_key = match keychain.retrieve_device_key() {
            Ok(key) => key,
            Err(VaultError::Decryption(_)) => {
                return Err(VaultError::Keychain(
                    "device key unwrap failed (wrong vault passphrase). \
                     Refusing to overwrite the existing keychain file."
                        .into(),
                ));
            }
            Err(VaultError::KeychainNotInitialized) => {
                let key = generate_key();
                keychain.store_device_key(&key)?;
                key
            }
            Err(other) => return Err(other),
        };

        precreate_owner_only(db_path)?;
        precreate_owner_only(&with_suffix(db_path, "-wal"))?;
        precreate_owner_only(&with_suffix(db_path, "-shm"))?;
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS credentials (
                 name TEXT PRIMARY KEY,
                 channel TEXT NOT NULL,
                 encrypted_value BLOB NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT,
                 last_used_at TEXT,
                 rotation_due_at TEXT
             );",
        )?;

        Ok(Self { conn, device_key })
    }

    /// Open a credential store with a directly provided device key.
    /// Used in tests and for FD-based credential passing.
    pub fn open_with_key(db_path: &Path, device_key: VaultSecret) -> Result<Self, VaultError> {
        precreate_owner_only(db_path)?;
        precreate_owner_only(&with_suffix(db_path, "-wal"))?;
        precreate_owner_only(&with_suffix(db_path, "-shm"))?;
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS credentials (
                 name TEXT PRIMARY KEY,
                 channel TEXT NOT NULL,
                 encrypted_value BLOB NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT,
                 last_used_at TEXT,
                 rotation_due_at TEXT
             );",
        )?;

        Ok(Self { conn, device_key })
    }

    /// Store a credential. Encrypts the secret value before writing.
    pub fn store(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        let encrypted = encrypt(name, secret, &self.device_key)?;
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT OR REPLACE INTO credentials
             (name, channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            params![
                name,
                channel,
                encrypted,
                now,
                expires_at.map(|t| t.to_rfc3339()),
                rotation_due_at.map(|t| t.to_rfc3339()),
            ],
        )?;

        Ok(())
    }

    /// Retrieve a credential by name. Returns the decrypted secret.
    /// Updates last_used_at timestamp.
    /// Returns VaultError::Expired if the credential has expired.
    pub fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at
             FROM credentials WHERE name = ?1",
        )?;

        let row = stmt
            .query_row(params![name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|_| VaultError::NotFound(name.to_string()))?;

        let (
            channel,
            encrypted,
            created_at_str,
            expires_at_str,
            last_used_at_str,
            rotation_due_at_str,
        ) = row;

        let meta = CredentialMetadata {
            name: name.to_string(),
            channel,
            created_at: parse_datetime(&created_at_str)?,
            expires_at: expires_at_str.as_deref().map(parse_datetime).transpose()?,
            last_used_at: last_used_at_str
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
            rotation_due_at: rotation_due_at_str
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
        };

        if meta.is_expired() {
            return Err(VaultError::Expired(name.to_string()));
        }

        // Update last_used_at
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE name = ?2",
            params![now, name],
        )?;

        let secret = decrypt(name, &encrypted, &self.device_key)?;
        Ok((secret, meta))
    }

    /// Inspect a credential without updating `last_used_at`. Same
    /// return shape as [`Self::retrieve`] but does not write back to
    /// the row. Used by `wirken credentials show` and `wirken
    /// credentials list`'s scope-summary augmentation, where the
    /// caller is inspecting rather than authenticating: bumping
    /// `last_used_at` on every `list` invocation would corrupt the
    /// "when was this credential last actually used" signal that
    /// operators rely on for rotation decisions.
    pub fn peek(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at
             FROM credentials WHERE name = ?1",
        )?;

        let row = stmt
            .query_row(params![name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|_| VaultError::NotFound(name.to_string()))?;

        let (
            channel,
            encrypted,
            created_at_str,
            expires_at_str,
            last_used_at_str,
            rotation_due_at_str,
        ) = row;

        let meta = CredentialMetadata {
            name: name.to_string(),
            channel,
            created_at: parse_datetime(&created_at_str)?,
            expires_at: expires_at_str.as_deref().map(parse_datetime).transpose()?,
            last_used_at: last_used_at_str
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
            rotation_due_at: rotation_due_at_str
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
        };

        if meta.is_expired() {
            return Err(VaultError::Expired(name.to_string()));
        }

        let secret = decrypt(name, &encrypted, &self.device_key)?;
        Ok((secret, meta))
    }

    /// Delete a credential by name.
    pub fn delete(&self, name: &str) -> Result<(), VaultError> {
        let changes = self
            .conn
            .execute("DELETE FROM credentials WHERE name = ?1", params![name])?;

        if changes == 0 {
            return Err(VaultError::NotFound(name.to_string()));
        }

        Ok(())
    }

    /// Delete every credential whose `channel` column matches.
    /// Returns the number of rows removed (0 if none matched).
    pub fn delete_by_channel(&self, channel: &str) -> Result<usize, VaultError> {
        let changes = self.conn.execute(
            "DELETE FROM credentials WHERE channel = ?1",
            params![channel],
        )?;
        Ok(changes)
    }

    /// List all credential metadata (without decrypting values).
    pub fn list(&self) -> Result<Vec<CredentialMetadata>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, channel, created_at, expires_at, last_used_at, rotation_due_at
             FROM credentials ORDER BY name",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (
                name,
                channel,
                created_at_str,
                expires_at_str,
                last_used_at_str,
                rotation_due_at_str,
            ) = row?;
            result.push(CredentialMetadata {
                name,
                channel,
                created_at: parse_datetime(&created_at_str).unwrap_or_else(|_| Utc::now()),
                expires_at: expires_at_str
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
                last_used_at: last_used_at_str
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
                rotation_due_at: rotation_due_at_str
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
            });
        }

        Ok(result)
    }

    /// Rotate a credential: store a new value, preserve the name and channel.
    /// Updates created_at and resets rotation_due_at.
    pub fn rotate(
        &self,
        name: &str,
        new_secret: &VaultSecret,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        // Verify credential exists
        let mut stmt = self
            .conn
            .prepare("SELECT channel FROM credentials WHERE name = ?1")?;
        let _channel: String = stmt
            .query_row(params![name], |row| row.get(0))
            .map_err(|_| VaultError::NotFound(name.to_string()))?;

        let encrypted = encrypt(name, new_secret, &self.device_key)?;
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "UPDATE credentials SET
                encrypted_value = ?1,
                created_at = ?2,
                last_used_at = NULL,
                rotation_due_at = ?3
             WHERE name = ?4",
            params![
                encrypted,
                now,
                rotation_due_at.map(|t| t.to_rfc3339()),
                name,
            ],
        )?;

        Ok(())
    }

    /// Write an encrypted credential to a file descriptor for adapter process spawning.
    /// Returns the encrypted bytes that can be written to an FD.
    pub fn export_encrypted(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT encrypted_value FROM credentials WHERE name = ?1")?;
        let encrypted: Vec<u8> = stmt
            .query_row(params![name], |row| row.get(0))
            .map_err(|_| VaultError::NotFound(name.to_string()))?;
        Ok(encrypted)
    }

    // `write_to_fd` was an unused pub fn that built a `File` from a
    // raw fd via `unsafe { File::from_raw_fd }` + `mem::forget` for
    // "spawn adapter with vault export over fd" — a path that never
    // got wired up. Removed in the 2026-04-27 audit pass: the only
    // `unsafe` block in `wirken-vault` was sitting unused, ready to
    // be lit up by a future refactor without the safety contract
    // being re-audited at any call site. The substrate it depended
    // on (`export_encrypted` above, returning bytes) stays. If an
    // fd-write path is needed later, restore the function with the
    // safety contract documented at each caller.
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, VaultError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            VaultError::Serialization(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )))
        })
}

/// Build a sibling path by appending `suffix` to `path`'s file name.
fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

/// Pre-create the SQLite file with mode 0o600 on unix so SQLite's
/// own `Connection::open` does not land a default-umask 0o644 file.
/// No-op when the path already exists; emits a warning on non-unix
/// where the chmod equivalent is unavailable.
fn precreate_owner_only(path: &Path) -> Result<(), VaultError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| VaultError::Keychain(format!("create parent: {e}")))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| VaultError::Keychain(format!("create {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        tracing::warn!(
            "creating vault database at {} without 0o600-equivalent file permissions; \
             relying on user profile isolation for confidentiality",
            path.display()
        );
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| VaultError::Keychain(format!("create {}: {e}", path.display())))?;
    }
    Ok(())
}
