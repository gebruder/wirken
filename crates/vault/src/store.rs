use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    /// Hosts this credential may be sent to by the `http_request` tool.
    /// Empty means unbound: `http_request` refuses to use it (deny by
    /// default), so a credential can only travel to hosts the operator
    /// pinned at creation, never to a host a skill's own permissions
    /// block widens to.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

impl CredentialMetadata {
    /// Check if this credential has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Whether this credential may be sent to `host`. Exact,
    /// case-insensitive host match; an unbound credential (empty
    /// `allowed_hosts`) permits nothing.
    pub fn permits_host(&self, host: &str) -> bool {
        self.allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
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
                     Refusing to overwrite the existing keychain file. \
                     Run `wirken vault reset` to start over (destroys all \
                     stored credentials)."
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
                 rotation_due_at TEXT,
                 allowed_hosts TEXT
             );",
        )?;
        migrate_allowed_hosts(&conn)?;

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
                 rotation_due_at TEXT,
                 allowed_hosts TEXT
             );",
        )?;
        migrate_allowed_hosts(&conn)?;

        Ok(Self { conn, device_key })
    }

    /// The names of every credential in the store at `db_path`, read
    /// without a device key.
    ///
    /// Names are not secrets: the schema keeps them in clear beside the
    /// encrypted value, and `list` already shows them to whoever can
    /// open the store. What this adds is the answer to "is anything
    /// configured under this name" from a process that cannot unlock
    /// the vault, such as a scheduled run with no passphrase in its
    /// environment. A run that can see a name it cannot read knows it
    /// is missing something configured, which is different from
    /// nothing having been configured, and the two must not be
    /// reported alike. An absent file is an empty store.
    pub fn names(db_path: &Path) -> Result<Vec<String>, VaultError> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        // A plain open, as the constructors use. Only SELECTs follow.
        let conn = Connection::open(db_path)?;
        // `open` pre-creates the file before the schema is written, and
        // a command can fail between the two, so a vault file with no
        // credentials table is real and means nothing was stored.
        let has_table: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'credentials'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n > 0)?;
        if !has_table {
            return Ok(Vec::new());
        }
        let mut stmt = conn.prepare("SELECT name FROM credentials ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }

    /// Store a credential with no host binding. Encrypts the secret
    /// before writing. A credential stored this way is unusable by
    /// `http_request` (deny by default); use [`Self::store_with_hosts`]
    /// to bind it to the hosts it may be sent to.
    pub fn store(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        self.store_with_hosts(name, channel, secret, expires_at, rotation_due_at, &[])
    }

    /// Store a credential, binding it to the hosts `http_request` may
    /// send it to. An empty `allowed_hosts` leaves it unbound. The
    /// binding is enforced host-side at injection time and cannot be
    /// widened by a skill's own permissions block.
    pub fn store_with_hosts(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
        allowed_hosts: &[String],
    ) -> Result<(), VaultError> {
        let encrypted = encrypt(name, secret, &self.device_key)?;
        let now = Utc::now().to_rfc3339();
        let hosts_json = if allowed_hosts.is_empty() {
            None
        } else {
            Some(serde_json::to_string(allowed_hosts)?)
        };

        self.conn.execute(
            "INSERT OR REPLACE INTO credentials
             (name, channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at, allowed_hosts)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            params![
                name,
                channel,
                encrypted,
                now,
                expires_at.map(|t| t.to_rfc3339()),
                rotation_due_at.map(|t| t.to_rfc3339()),
                hosts_json,
            ],
        )?;

        Ok(())
    }

    /// Retrieve a credential by name. Returns the decrypted secret.
    /// Updates last_used_at timestamp.
    /// Returns VaultError::Expired if the credential has expired.
    pub fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at, allowed_hosts
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
                    row.get::<_, Option<String>>(6)?,
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
            allowed_hosts_json,
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
            allowed_hosts: parse_hosts(&allowed_hosts_json)?,
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
            "SELECT channel, encrypted_value, created_at, expires_at, last_used_at, rotation_due_at, allowed_hosts
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
                    row.get::<_, Option<String>>(6)?,
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
            allowed_hosts_json,
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
            allowed_hosts: parse_hosts(&allowed_hosts_json)?,
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
            "SELECT name, channel, created_at, expires_at, last_used_at, rotation_due_at, allowed_hosts
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
                row.get::<_, Option<String>>(6)?,
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
                allowed_hosts_json,
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
                allowed_hosts: parse_hosts(&allowed_hosts_json).unwrap_or_default(),
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

/// Backfill the `allowed_hosts` column onto a `credentials` table
/// created before host-binding. New databases already carry it from
/// CREATE TABLE, so this is a no-op for them. Idempotent: it checks
/// `pragma_table_info` before the `ALTER TABLE`.
fn migrate_allowed_hosts(conn: &Connection) -> Result<(), VaultError> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name = 'allowed_hosts'",
        [],
        |r| r.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE credentials ADD COLUMN allowed_hosts TEXT;")?;
    }
    Ok(())
}

/// Parse the stored `allowed_hosts` JSON array. `NULL` / empty means an
/// unbound credential (no hosts).
fn parse_hosts(raw: &Option<String>) -> Result<Vec<String>, VaultError> {
    match raw {
        None => Ok(Vec::new()),
        Some(s) if s.is_empty() => Ok(Vec::new()),
        Some(s) => Ok(serde_json::from_str(s)?),
    }
}

/// Build a sibling path by appending `suffix` to `path`'s file name.
/// The on-disk state a [`reset`] will destroy, computed before any
/// deletion so the operator can be shown exactly what is at stake and
/// asked to confirm first. Only paths that currently exist are recorded.
pub struct ResetPlan {
    /// The keychain directory (`<data_dir>/keychain`) holding the device
    /// key, its salt, and every aux key — including the alarm-log HMAC
    /// key. `None` when it does not exist.
    pub keychain_dir: Option<PathBuf>,
    /// The credential DB SQLite files (`vault.db`, `-wal`, `-shm`) that
    /// currently exist.
    pub db_files: Vec<PathBuf>,
    /// Best-effort count of stored credential rows, or `None` when the
    /// DB is absent or unreadable. Metadata only: `COUNT(*)` never reads
    /// `encrypted_value`, so no device key or decryption is required.
    pub credential_rows: Option<i64>,
}

/// Enumerate the existing vault artifacts a `vault reset` would remove.
/// The audit chain DB is deliberately excluded.
pub fn reset_plan(data_dir: &Path, db_path: &Path) -> ResetPlan {
    let keychain_dir = {
        let d = data_dir.join("keychain");
        d.is_dir().then_some(d)
    };
    let db_files = db_file_set(db_path)
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    ResetPlan {
        keychain_dir,
        db_files,
        credential_rows: credential_row_count(db_path),
    }
}

/// Best-effort `COUNT(*)` of stored credentials for the pre-reset
/// summary. Opens the DB read-only and touches only row metadata, never
/// `encrypted_value`, so no device key is needed. `None` on any error
/// (missing DB, no `credentials` table, IO).
fn credential_row_count(db_path: &Path) -> Option<i64> {
    if !db_path.exists() {
        return None;
    }
    let conn =
        Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))
        .ok()
}

/// The three SQLite files backing the credential DB.
fn db_file_set(db_path: &Path) -> [PathBuf; 3] {
    [
        db_path.to_path_buf(),
        with_suffix(db_path, "-wal"),
        with_suffix(db_path, "-shm"),
    ]
}

/// Destroy every existing vault artifact: the keychain directory (device
/// key, salt, all aux keys including the alarm-log HMAC key) and the
/// credential DB files (`vault.db`, `-wal`, `-shm`). Returns the paths
/// actually removed. The audit chain DB is never touched. Afterwards the
/// next [`CredentialStore::open`] takes the `KeychainNotInitialized`
/// branch and creates a fresh empty store.
pub fn reset(data_dir: &Path, db_path: &Path) -> Result<Vec<PathBuf>, VaultError> {
    let mut removed = Vec::new();
    let keychain_dir = data_dir.join("keychain");
    if keychain_dir.is_dir() {
        std::fs::remove_dir_all(&keychain_dir)?;
        removed.push(keychain_dir);
    }
    for p in db_file_set(db_path) {
        if p.exists() {
            std::fs::remove_file(&p)?;
            removed.push(p);
        }
    }
    Ok(removed)
}

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
