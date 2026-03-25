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
    pub fn open(db_path: &Path, keychain: &dyn Keychain) -> Result<Self, VaultError> {
        let device_key = match keychain.retrieve_device_key() {
            Ok(key) => key,
            Err(_) => {
                // First run — generate and store a new device key
                let key = generate_key();
                keychain.store_device_key(&key)?;
                key
            }
        };

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
        let encrypted = encrypt(secret, &self.device_key)?;
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

        let secret = decrypt(&encrypted, &self.device_key)?;
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

        let encrypted = encrypt(new_secret, &self.device_key)?;
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

    /// Write encrypted credential bytes to a file descriptor.
    #[cfg(unix)]
    pub fn write_to_fd(&self, name: &str, fd: std::os::unix::io::RawFd) -> Result<(), VaultError> {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let encrypted = self.export_encrypted(name)?;

        // Safety: caller guarantees fd is valid and open for writing
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&encrypted)?;
        // Prevent File from closing the fd on drop — caller owns it
        std::mem::forget(file);
        Ok(())
    }
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
