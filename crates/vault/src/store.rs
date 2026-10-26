use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::binding::{Binding, Destination};
use crate::crypto::{decrypt_aad, encrypt_aad, generate_key};
use crate::error::VaultError;
use crate::keychain::Keychain;
use crate::kind::{
    BUILTIN_IDENTIFIERS, CredentialKind, MatchableSecret, default_kind, matchable_secret,
};
use crate::secret::VaultSecret;

/// Vault format with destination binding sealed into each row.
pub const BOUND_FORMAT: u32 = 2;

/// Metadata for a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub name: String,
    pub channel: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub rotation_due_at: Option<DateTime<Utc>>,
    /// The binding's hosts, for display.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Secret or identifier; leak detection matches only secrets.
    #[serde(default)]
    pub kind: CredentialKind,
    /// Where the value may go. Authenticated by the decryption on
    /// [`CredentialStore::retrieve`] and [`CredentialStore::peek`]; as
    /// stored, unauthenticated, on [`CredentialStore::list`].
    #[serde(default)]
    pub binding: Binding,
}

impl CredentialMetadata {
    /// Check if this credential has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Whether `http_request` may send this credential to `host`.
    pub fn permits_host(&self, host: &str) -> bool {
        self.binding.permits(&Destination::Host(host.to_string()))
    }

    /// Check if this credential is due for rotation.
    pub fn is_rotation_due(&self) -> bool {
        self.rotation_due_at
            .map(|due| Utc::now() > due)
            .unwrap_or(false)
    }
}

/// How long a statement waits on another connection's write lock
/// before failing. SQLite's own default as rusqlite sets it on open;
/// [`CredentialStore::update_exclusive`] widens it for one call and
/// puts this back.
const DEFAULT_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// What [`CredentialStore::update_exclusive`] did.
pub struct ExclusiveUpdate<T> {
    /// What `decide` returned beside its replacement.
    pub value: T,
    /// `Ok(true)` when a replacement was written, `Ok(false)` when
    /// `decide` returned none, and the error when the write or its
    /// commit failed, in which case the stored value is unchanged.
    pub written: Result<bool, VaultError>,
}

/// What [`CredentialStore::migrate_to_bound`] wrote.
#[derive(Debug)]
pub struct Migration {
    /// SHA-256 of each plaintext, by name, taken before the re-seal.
    pub digests: BTreeMap<String, [u8; 32]>,
}

/// A row as [`CredentialStore::rows_for_migration`] lists it: name,
/// channel, kind and stored hosts.
pub type MigrationRow = (String, String, CredentialKind, Vec<String>);

/// One stored row, as read.
struct Row {
    channel: String,
    encrypted: Vec<u8>,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    rotation_due_at: Option<String>,
    kind: CredentialKind,
    binding: String,
}

const ROW_COLUMNS: &str = "channel, encrypted_value, created_at, expires_at, last_used_at, \
                           rotation_due_at, kind, binding";

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        channel: row.get(0)?,
        encrypted: row.get(1)?,
        created_at: row.get(2)?,
        expires_at: row.get(3)?,
        last_used_at: row.get(4)?,
        rotation_due_at: row.get(5)?,
        kind: CredentialKind::from_column(row.get::<_, Option<String>>(6)?.as_deref()),
        binding: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
    })
}

impl Row {
    fn metadata(&self, name: &str) -> Result<CredentialMetadata, VaultError> {
        let binding = parse_binding(&self.binding)?;
        Ok(CredentialMetadata {
            name: name.to_string(),
            channel: self.channel.clone(),
            created_at: parse_datetime(&self.created_at)?,
            expires_at: self.expires_at.as_deref().map(parse_datetime).transpose()?,
            last_used_at: self
                .last_used_at
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
            rotation_due_at: self
                .rotation_due_at
                .as_deref()
                .map(parse_datetime)
                .transpose()?,
            allowed_hosts: binding.hosts.clone(),
            kind: self.kind,
            binding,
        })
    }

    fn aad(&self, name: &str) -> Vec<u8> {
        row_aad(name, self.kind, &self.binding)
    }
}

/// What [`CredentialStore::fingerprints`] reports for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFingerprint {
    /// Digest of the sealed value.
    pub value: [u8; 32],
    /// Digest of the binding column.
    pub binding: [u8; 32],
}

/// SQLite-backed credential store with encrypted values.
pub struct CredentialStore {
    conn: Connection,
    device_key: VaultSecret,
    format: u32,
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
    ///
    /// A vault from before destination binding is refused with
    /// [`VaultError::NeedsMigration`].
    pub fn open(db_path: &Path, keychain: &dyn Keychain) -> Result<Self, VaultError> {
        let store = Self::open_any_format(db_path, keychain)?;
        store.require_bound()?;
        Ok(store)
    }

    /// [`Self::open`], also accepting a vault from before destination
    /// binding. For `wirken vault migrate`.
    pub fn open_any_format(db_path: &Path, keychain: &dyn Keychain) -> Result<Self, VaultError> {
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
        Self::open_db(db_path, device_key)
    }

    /// Open a credential store with a directly provided device key.
    /// Used in tests and for FD-based credential passing.
    pub fn open_with_key(db_path: &Path, device_key: VaultSecret) -> Result<Self, VaultError> {
        let store = Self::open_db(db_path, device_key)?;
        store.require_bound()?;
        Ok(store)
    }

    /// [`Self::open_with_key`], also accepting a vault from before
    /// destination binding.
    pub fn open_with_key_any_format(
        db_path: &Path,
        device_key: VaultSecret,
    ) -> Result<Self, VaultError> {
        Self::open_db(db_path, device_key)
    }

    fn open_db(db_path: &Path, device_key: VaultSecret) -> Result<Self, VaultError> {
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
                 allowed_hosts TEXT,
                 kind TEXT,
                 binding TEXT
             );
             CREATE TABLE IF NOT EXISTS vault_meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
        )?;
        migrate_allowed_hosts(&conn)?;
        migrate_kind(&conn)?;
        migrate_binding(&conn)?;
        let format = vault_format(&conn)?;
        Ok(Self {
            conn,
            device_key,
            format,
        })
    }

    /// The vault's format: 1 before destination binding,
    /// [`BOUND_FORMAT`] after.
    pub fn format(&self) -> u32 {
        self.format
    }

    fn require_bound(&self) -> Result<(), VaultError> {
        if self.format < BOUND_FORMAT {
            return Err(VaultError::NeedsMigration);
        }
        Ok(())
    }

    /// The format of the vault at `db_path`, read without a device key.
    /// `None` when there is no vault there.
    pub fn format_at(db_path: &Path) -> Result<Option<u32>, VaultError> {
        if !db_path.exists() {
            return Ok(None);
        }
        let conn =
            Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let has_credentials: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'credentials'",
            [],
            |r| r.get(0),
        )?;
        if has_credentials == 0 {
            return Ok(None);
        }
        let has_meta: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
            [],
            |r| r.get(0),
        )?;
        if has_meta == 0 {
            return Ok(Some(1));
        }
        let format: Option<String> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'format'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(Some(format.and_then(|f| f.parse().ok()).unwrap_or(1)))
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

    /// A digest of each stored entry's sealed value and of its binding,
    /// read without the device key. A rotation, a grant or a revoke
    /// changes it; a read does not. An absent file is an empty store.
    pub fn fingerprints(db_path: &Path) -> Result<BTreeMap<String, EntryFingerprint>, VaultError> {
        let mut out = BTreeMap::new();
        if !db_path.exists() {
            return Ok(out);
        }
        // A plain open, as `names` does. Only a SELECT follows.
        let conn = Connection::open(db_path)?;
        let has_table: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'credentials'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n > 0)?;
        if !has_table {
            return Ok(out);
        }
        let mut stmt = conn.prepare("SELECT name, encrypted_value, binding FROM credentials")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        for row in rows {
            let (name, sealed, binding) = row?;
            out.insert(
                name,
                EntryFingerprint {
                    value: Sha256::digest(&sealed).into(),
                    binding: Sha256::digest(binding.unwrap_or_default().as_bytes()).into(),
                },
            );
        }
        Ok(out)
    }

    /// Store a credential. A name of the form `<adapter>-...` is bound
    /// to that adapter; anything else is stored unbound and goes nowhere
    /// until granted.
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

    /// [`Self::store`], also bound to the hosts `http_request` may send
    /// it to.
    pub fn store_with_hosts(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
        allowed_hosts: &[String],
    ) -> Result<(), VaultError> {
        self.store_with_kind(
            name,
            channel,
            secret,
            expires_at,
            rotation_due_at,
            allowed_hosts,
            default_kind(name),
        )
    }

    /// Store a credential as `kind`. [`Self::store_with_hosts`] stores
    /// it as its name's default: an identifier for the built-in adapter
    /// identifiers, a secret otherwise.
    #[allow(clippy::too_many_arguments, reason = "one column each")]
    pub fn store_with_kind(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
        allowed_hosts: &[String],
        kind: CredentialKind,
    ) -> Result<(), VaultError> {
        let mut binding = default_binding(name, channel);
        for host in allowed_hosts {
            binding.grant(Destination::Host(host.clone()));
        }
        self.store_bound(
            name,
            channel,
            secret,
            expires_at,
            rotation_due_at,
            &binding,
            kind,
        )
    }

    /// Store a credential under an explicit binding.
    #[allow(clippy::too_many_arguments, reason = "one column each")]
    pub fn store_bound(
        &self,
        name: &str,
        channel: &str,
        secret: &VaultSecret,
        expires_at: Option<DateTime<Utc>>,
        rotation_due_at: Option<DateTime<Utc>>,
        binding: &Binding,
        kind: CredentialKind,
    ) -> Result<(), VaultError> {
        self.require_bound()?;
        let binding_raw = binding.canonical();
        let encrypted = encrypt_aad(&row_aad(name, kind, &binding_raw), secret, &self.device_key)?;
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO credentials
             (name, channel, encrypted_value, created_at, expires_at, last_used_at,
              rotation_due_at, allowed_hosts, kind, binding)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9)",
            params![
                name,
                channel,
                encrypted,
                now,
                expires_at.map(|t| t.to_rfc3339()),
                rotation_due_at.map(|t| t.to_rfc3339()),
                hosts_column(binding)?,
                kind.as_str(),
                binding_raw,
            ],
        )?;
        Ok(())
    }

    fn read_row(&self, name: &str) -> Result<Row, VaultError> {
        self.conn
            .query_row(
                &format!("SELECT {ROW_COLUMNS} FROM credentials WHERE name = ?1"),
                params![name],
                row_from,
            )
            .map_err(|_| VaultError::NotFound(name.to_string()))
    }

    /// Retrieve a credential by name. Returns the decrypted secret.
    /// Updates last_used_at timestamp.
    /// Returns VaultError::Expired if the credential has expired.
    pub fn retrieve(&self, name: &str) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        let row = self.read_row(name)?;
        let meta = row.metadata(name)?;
        if meta.is_expired() {
            return Err(VaultError::Expired(name.to_string()));
        }
        // Every caller of `retrieve` uses what it gets as a key or a
        // token. A plan sign-in is neither; its token source reads it
        // through `peek`.
        if meta.kind == CredentialKind::PlanSignIn {
            return Err(VaultError::PlanSignIn(name.to_string()));
        }
        let secret = decrypt_aad(&row.aad(name), &row.encrypted, &self.device_key)?;
        self.conn.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE name = ?2",
            params![Utc::now().to_rfc3339(), name],
        )?;
        Ok((secret, meta))
    }

    /// [`Self::retrieve`] for a value about to be sent to `destination`.
    /// Refused unless the row's binding, authenticated by the
    /// decryption, permits it.
    pub fn retrieve_for(
        &self,
        name: &str,
        destination: &Destination,
    ) -> Result<(VaultSecret, CredentialMetadata), VaultError> {
        let (secret, meta) = self.retrieve(name)?;
        if !meta.binding.permits(destination) {
            return Err(VaultError::NotPermitted {
                name: name.to_string(),
                destination: destination.clone(),
            });
        }
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
        let row = self.read_row(name)?;
        let meta = row.metadata(name)?;
        if meta.is_expired() {
            return Err(VaultError::Expired(name.to_string()));
        }
        let secret = decrypt_aad(&row.aad(name), &row.encrypted, &self.device_key)?;
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

    /// List all credential metadata (without decrypting values). The
    /// binding is as stored, not authenticated.
    pub fn list(&self) -> Result<Vec<CredentialMetadata>, VaultError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT name, {ROW_COLUMNS} FROM credentials ORDER BY name"
        ))?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let rest = Row {
                channel: row.get(1)?,
                encrypted: Vec::new(),
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
                last_used_at: row.get(5)?,
                rotation_due_at: row.get(6)?,
                kind: CredentialKind::from_column(row.get::<_, Option<String>>(7)?.as_deref()),
                binding: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
            };
            Ok((name, rest))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (name, row) = row?;
            let binding = parse_binding(&row.binding).unwrap_or_default();
            result.push(CredentialMetadata {
                name,
                channel: row.channel,
                created_at: parse_datetime(&row.created_at).unwrap_or_else(|_| Utc::now()),
                expires_at: row
                    .expires_at
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
                last_used_at: row
                    .last_used_at
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
                rotation_due_at: row
                    .rotation_due_at
                    .as_deref()
                    .and_then(|s| parse_datetime(s).ok()),
                allowed_hosts: binding.hosts.clone(),
                kind: row.kind,
                binding,
            });
        }
        Ok(result)
    }

    /// Every stored secret, decrypted, as leak detection matches it:
    /// identifiers are left out, and each secret is split into the
    /// parts it can appear as ([`matchable_parts`]). A part shorter than
    /// [`MIN_MATCH_BYTES`] is dropped with a warning naming the
    /// credential. Does not touch `last_used_at`; a row that will not
    /// decrypt is skipped with a warning rather than failing the rest.
    pub fn secrets_for_matching(&self) -> Result<Vec<MatchableSecret>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, encrypted_value, kind, binding FROM credentials ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (name, encrypted, kind, binding) = row?;
            let kind = CredentialKind::from_column(kind.as_deref());
            if kind == CredentialKind::Identifier {
                continue;
            }
            let aad = row_aad(&name, kind, binding.as_deref().unwrap_or(""));
            match decrypt_aad(&aad, &encrypted, &self.device_key) {
                Ok(secret) => out.extend(matchable_secret(&name, secret.expose(), kind)),
                Err(e) => tracing::warn!(
                    credential = %name,
                    error = %e,
                    "stored credential not decrypted for leak detection"
                ),
            }
        }
        Ok(out)
    }

    /// Rotate a credential: store a new value, preserve the name,
    /// channel and binding. Updates created_at and resets
    /// rotation_due_at.
    pub fn rotate(
        &self,
        name: &str,
        new_secret: &VaultSecret,
        rotation_due_at: Option<DateTime<Utc>>,
    ) -> Result<(), VaultError> {
        let row = self.read_row(name)?;
        // A plan sign-in is replaced by signing in again, never by a
        // typed value.
        if row.kind == CredentialKind::PlanSignIn {
            return Err(VaultError::PlanSignIn(name.to_string()));
        }
        // The new value keeps the binding the old one was sealed under,
        // so the old one must open under it.
        let aad = row.aad(name);
        decrypt_aad(&aad, &row.encrypted, &self.device_key)?;
        let encrypted = encrypt_aad(&aad, new_secret, &self.device_key)?;

        self.conn.execute(
            "UPDATE credentials SET
                encrypted_value = ?1,
                created_at = ?2,
                last_used_at = NULL,
                rotation_due_at = ?3
             WHERE name = ?4",
            params![
                encrypted,
                Utc::now().to_rfc3339(),
                rotation_due_at.map(|t| t.to_rfc3339()),
                name,
            ],
        )?;

        Ok(())
    }

    /// Decide the replacement for `name` while holding the store's write
    /// lock, so no other connection, in this process or another, can
    /// change the entry between the read `decide` is given and the
    /// write it asks for.
    ///
    /// The lock is SQLite's: an `IMMEDIATE` transaction, taken before
    /// the entry is read and released after the write. A second caller
    /// waits for it up to `wait`, then reads whatever the first one
    /// wrote. That is what makes this a compare-and-swap: `decide` sees
    /// the value as it is now, compares it with the one its caller read
    /// earlier, and returns a replacement only when they still match.
    /// Readers are not blocked (the database runs in WAL mode); other
    /// writers are, for as long as `decide` takes.
    ///
    /// Only the value changes. Name, channel, dates, binding and kind
    /// stay as they were.
    pub fn update_exclusive<T>(
        &self,
        name: &str,
        wait: std::time::Duration,
        decide: impl FnOnce(&VaultSecret) -> (Option<VaultSecret>, T),
    ) -> Result<ExclusiveUpdate<T>, VaultError> {
        self.begin_immediate(wait)?;
        let (current, aad) = match self.read_for_update(name) {
            Ok((secret, row)) => (secret, row.aad(name)),
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        };
        let (replacement, value) = decide(&current);
        let written = match replacement {
            None => self
                .conn
                .execute_batch("ROLLBACK")
                .map(|()| false)
                .map_err(VaultError::from),
            Some(new_secret) => {
                let result =
                    encrypt_aad(&aad, &new_secret, &self.device_key).and_then(|encrypted| {
                        self.conn.execute(
                            "UPDATE credentials SET encrypted_value = ?1 WHERE name = ?2",
                            params![encrypted, name],
                        )?;
                        self.conn.execute_batch("COMMIT")?;
                        Ok(true)
                    });
                if result.is_err() {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
                result
            }
        };
        Ok(ExclusiveUpdate { value, written })
    }

    /// Re-seal `name` under the binding `decide` returns for its
    /// current, authenticated one, under the write lock. `decide`
    /// returning `None` changes nothing. Returns the binding now stored.
    pub fn update_binding_exclusive(
        &self,
        name: &str,
        wait: std::time::Duration,
        decide: impl FnOnce(&Binding) -> Option<Binding>,
    ) -> Result<Binding, VaultError> {
        self.require_bound()?;
        self.begin_immediate(wait)?;
        let result = (|| {
            let (secret, row) = self.read_for_update(name)?;
            let current = parse_binding(&row.binding)?;
            let Some(new) = decide(&current) else {
                return Ok((current, false));
            };
            let raw = new.canonical();
            let encrypted = encrypt_aad(&row_aad(name, row.kind, &raw), &secret, &self.device_key)?;
            self.conn.execute(
                "UPDATE credentials SET encrypted_value = ?1, binding = ?2, allowed_hosts = ?3
                 WHERE name = ?4",
                params![encrypted, raw, hosts_column(&new)?, name],
            )?;
            Ok((new, true))
        })();
        match result {
            Ok((binding, true)) => {
                if let Err(e) = self.conn.execute_batch("COMMIT") {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e.into());
                }
                Ok(binding)
            }
            Ok((binding, false)) => {
                self.conn.execute_batch("ROLLBACK")?;
                Ok(binding)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn begin_immediate(&self, wait: std::time::Duration) -> Result<(), VaultError> {
        self.conn.busy_timeout(wait)?;
        let begun = self.conn.execute_batch("BEGIN IMMEDIATE");
        self.conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
        begun?;
        Ok(())
    }

    /// The decrypted value of `name` and its row, inside the
    /// transaction the caller holds. Same refusals as [`Self::peek`]: a
    /// missing or expired entry is an error.
    fn read_for_update(&self, name: &str) -> Result<(VaultSecret, Row), VaultError> {
        let row = self.read_row(name)?;
        if let Some(exp) = row.expires_at.as_deref().map(parse_datetime).transpose()?
            && Utc::now() > exp
        {
            return Err(VaultError::Expired(name.to_string()));
        }
        let secret = decrypt_aad(&row.aad(name), &row.encrypted, &self.device_key)?;
        Ok((secret, row))
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

    /// Number of stored rows.
    pub fn count(&self) -> Result<usize, VaultError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Re-seal every row of a format 1 vault under its binding from
    /// `bindings` (empty when absent) and mark the vault
    /// [`BOUND_FORMAT`], in one transaction. Any error rolls it back and
    /// leaves the vault as it was.
    pub fn migrate_to_bound(
        &mut self,
        bindings: &BTreeMap<String, Binding>,
    ) -> Result<Migration, VaultError> {
        if self.format >= BOUND_FORMAT {
            return Err(VaultError::AlreadyMigrated);
        }
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let rows: Vec<(String, Vec<u8>, CredentialKind)> = {
            let mut stmt =
                tx.prepare("SELECT name, encrypted_value, kind FROM credentials ORDER BY name")?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    CredentialKind::from_column(row.get::<_, Option<String>>(2)?.as_deref()),
                ))
            })?
            .collect::<Result<_, _>>()?
        };
        let mut digests = BTreeMap::new();
        for (name, encrypted, kind) in rows {
            let secret = decrypt_aad(&row_aad_v1(&name, kind), &encrypted, &self.device_key)
                .map_err(|e| VaultError::Decryption(format!("{name}: {e}")))?;
            digests.insert(name.clone(), sha256(&secret));
            let binding = bindings.get(&name).cloned().unwrap_or_default();
            let raw = binding.canonical();
            let resealed = encrypt_aad(&row_aad(&name, kind, &raw), &secret, &self.device_key)?;
            tx.execute(
                "UPDATE credentials SET encrypted_value = ?1, binding = ?2, allowed_hosts = ?3
                 WHERE name = ?4",
                params![resealed, raw, hosts_column(&binding)?, name],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('format', ?1)",
            params![BOUND_FORMAT.to_string()],
        )?;
        tx.commit()?;
        self.format = BOUND_FORMAT;
        Ok(Migration { digests })
    }

    /// SHA-256 of every row's plaintext, decrypted under its binding.
    pub fn plaintext_digests(&self) -> Result<BTreeMap<String, [u8; 32]>, VaultError> {
        self.require_bound()?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT name, {ROW_COLUMNS} FROM credentials ORDER BY name"
        ))?;
        let rows: Vec<(String, Row)> = stmt
            .query_map([], |r| {
                let name: String = r.get(0)?;
                Ok((
                    name,
                    Row {
                        channel: r.get(1)?,
                        encrypted: r.get(2)?,
                        created_at: r.get(3)?,
                        expires_at: r.get(4)?,
                        last_used_at: r.get(5)?,
                        rotation_due_at: r.get(6)?,
                        kind: CredentialKind::from_column(
                            r.get::<_, Option<String>>(7)?.as_deref(),
                        ),
                        binding: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = BTreeMap::new();
        for (name, row) in rows {
            let secret = decrypt_aad(&row.aad(&name), &row.encrypted, &self.device_key)
                .map_err(|e| VaultError::Decryption(format!("{name}: {e}")))?;
            out.insert(name, sha256(&secret));
        }
        Ok(out)
    }

    /// Every row's name, channel, kind and stored hosts, without
    /// decrypting. For proposing bindings before a migration.
    pub fn rows_for_migration(&self) -> Result<Vec<MigrationRow>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, channel, kind, allowed_hosts FROM credentials ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    CredentialKind::from_column(r.get::<_, Option<String>>(2)?.as_deref()),
                    r.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(n, c, k, h)| Ok((n, c, k, parse_hosts(&h)?)))
            .collect()
    }
}

/// Copy the vault at `db_path` to `dest` with SQLite's online backup,
/// mode 0600, and return the copy's row count.
pub fn backup_vault(db_path: &Path, dest: &Path) -> Result<usize, VaultError> {
    precreate_owner_only(dest)?;
    let src = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut dst = Connection::open(dest)?;
    {
        let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
        backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
    }
    let n: i64 = dst.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Copy `backup` back over the vault at `db_path` with SQLite's online
/// backup.
pub fn restore_vault(backup: &Path, db_path: &Path) -> Result<(), VaultError> {
    let src = Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut dst = Connection::open(db_path)?;
    let restore = rusqlite::backup::Backup::new(&src, &mut dst)?;
    restore.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
    Ok(())
}

/// Channel adapter ids.
pub const ADAPTERS: [&str; 9] = [
    "telegram",
    "discord",
    "slack",
    "teams",
    "matrix",
    "whatsapp",
    "signal",
    "google-chat",
    "imessage",
];

/// The binding a new credential gets: the adapter its name starts
/// with (`<adapter>-...`), nothing otherwise. `channel` is not read.
pub fn default_binding(name: &str, _channel: &str) -> Binding {
    ADAPTERS
        .iter()
        .find(|a| {
            name.strip_prefix(**a)
                .is_some_and(|rest| rest.starts_with('-'))
        })
        .map(|a| Binding::adapter(a))
        .unwrap_or_default()
}

fn sha256(secret: &VaultSecret) -> [u8; 32] {
    Sha256::digest(secret.expose().as_bytes()).into()
}

fn parse_binding(raw: &str) -> Result<Binding, VaultError> {
    if raw.is_empty() {
        return Ok(Binding::default());
    }
    Ok(Binding::parse(raw)?)
}

fn hosts_column(binding: &Binding) -> Result<Option<String>, VaultError> {
    if binding.hosts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::to_string(&binding.hosts)?))
    }
}

/// The AEAD associated data a format 2 row is sealed under. Each field
/// is preceded by its length as a big-endian `u32`, so no field can be
/// shifted into its neighbour. `binding` is the column's bytes exactly
/// as stored.
pub(crate) fn row_aad(name: &str, kind: CredentialKind, binding: &str) -> Vec<u8> {
    let mut aad = b"wirken-vault-row".to_vec();
    aad.push(0x02);
    for field in [
        name.as_bytes(),
        kind.as_str().as_bytes(),
        binding.as_bytes(),
    ] {
        aad.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad
}

/// Format 1 associated data: the name, or for a plan sign-in its name,
/// a NUL and the kind.
pub(crate) fn row_aad_v1(name: &str, kind: CredentialKind) -> Vec<u8> {
    let mut aad = name.as_bytes().to_vec();
    if kind == CredentialKind::PlanSignIn {
        aad.push(0);
        aad.extend_from_slice(kind.as_str().as_bytes());
    }
    aad
}

/// The vault's format: as recorded, else [`BOUND_FORMAT`] for a vault
/// with no rows (recorded on the way), else 1.
fn vault_format(conn: &Connection) -> Result<u32, VaultError> {
    let recorded: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'format'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(f) = recorded {
        return Ok(f.parse().unwrap_or(1));
    }
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))?;
    if rows == 0 {
        conn.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('format', ?1)",
            params![BOUND_FORMAT.to_string()],
        )?;
        return Ok(BOUND_FORMAT);
    }
    Ok(1)
}

/// Backfill the `binding` column onto a table created before it.
fn migrate_binding(conn: &Connection) -> Result<(), VaultError> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name = 'binding'",
        [],
        |r| r.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE credentials ADD COLUMN binding TEXT;")?;
    }
    Ok(())
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

/// Backfill the `kind` column onto a `credentials` table created before
/// it, marking the built-in adapter identifiers. Every other row, with
/// no kind, is a secret. Idempotent like [`migrate_allowed_hosts`].
fn migrate_kind(conn: &Connection) -> Result<(), VaultError> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name = 'kind'",
        [],
        |r| r.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE credentials ADD COLUMN kind TEXT;")?;
        for name in BUILTIN_IDENTIFIERS {
            conn.execute(
                "UPDATE credentials SET kind = 'identifier' WHERE name = ?1",
                params![name],
            )?;
        }
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
