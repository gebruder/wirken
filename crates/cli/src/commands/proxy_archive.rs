//! The write-once archive of proxied request and response bodies.
//!
//! The chain holds a hash of each body. With `archive` set in
//! `proxy.json`, the body itself is written to an S3-compatible bucket
//! under that hash, with an Object Lock retention period, so it cannot
//! be changed or deleted until the period ends.
//!
//! The bucket never holds plaintext. Each body is encrypted here,
//! before upload, under a key of its own. That key is kept in
//! `proxy_archive_keys.db` in the data directory, wrapped under the
//! archive key the vault holds. Redacting a body destroys its key: the
//! object stays locked in the bucket and nothing can read it again.
//!
//! An object is `WKA1`, a 24-byte nonce, then the XChaCha20-Poly1305
//! ciphertext of the body. The body's kind and hash are bound in as
//! associated data, so an object moved to another key does not open.

use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use wirken_gateway::proxy::ArchiveConfig;
use wirken_vault::{CredentialStore, Destination};
use zeroize::Zeroizing;

use super::proxy_server::{BodyKind, BodySink};

/// File name of the per-body key store in the data directory.
pub const ARCHIVE_KEYS_FILE: &str = "proxy_archive_keys.db";

/// What every archived object starts with.
const MAGIC: &[u8; 4] = b"WKA1";
const NONCE_BYTES: usize = 24;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn random<const N: usize>() -> [u8; N] {
    use rand::Rng;
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// What a body is bound to: its kind and its hash.
fn aad(kind: BodyKind, sha256: &str) -> Vec<u8> {
    format!("wirken-proxy-archive/v1\0{}\0{sha256}", kind.as_str()).into_bytes()
}

/// What a body's search text is bound to. Not what the body is bound
/// to, so neither opens as the other.
fn text_aad(kind: BodyKind, sha256: &str) -> Vec<u8> {
    format!("wirken-proxy-archive-text/v1\0{}\0{sha256}", kind.as_str()).into_bytes()
}

fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = random::<NONCE_BYTES>();
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}

fn open(key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < NONCE_BYTES {
        return Err("too short to hold a nonce".into());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| "bad nonce".to_string())?;
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| e.to_string())?
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "it does not decrypt under its key".to_string())
}

/// The state of one body's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyKey {
    /// Held, wrapped under the archive key.
    Held(Vec<u8>),
    /// Destroyed by a redaction.
    Destroyed,
    /// Never held here.
    Absent,
}

/// The per-body keys, each wrapped under the archive key. A redaction
/// replaces a key with a marker that it was destroyed.
pub struct KeyStore {
    conn: Mutex<Connection>,
}

impl KeyStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA secure_delete=ON;
             CREATE TABLE IF NOT EXISTS body_keys (
                 kind TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 wrapped BLOB,
                 destroyed_at TEXT,
                 PRIMARY KEY (kind, sha256)
             );
             CREATE TABLE IF NOT EXISTS body_text (
                 kind TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 sealed BLOB NOT NULL,
                 PRIMARY KEY (kind, sha256)
             );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The search text kept for a body, encrypted under the body's own
    /// key.
    fn text(&self, kind: BodyKind, sha256: &str) -> Result<Option<Vec<u8>>, String> {
        self.conn()
            .query_row(
                "SELECT sealed FROM body_text WHERE kind = ?1 AND sha256 = ?2",
                params![kind.as_str(), sha256],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Keep `sealed` as the body's search text, unless its key is gone.
    fn put_text(&self, kind: BodyKind, sha256: &str, sealed: &[u8]) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO body_text (kind, sha256, sealed)
                 SELECT ?1, ?2, ?3 WHERE EXISTS (
                     SELECT 1 FROM body_keys
                     WHERE kind = ?1 AND sha256 = ?2 AND wrapped IS NOT NULL)",
                params![kind.as_str(), sha256, sealed],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, kind: BodyKind, sha256: &str) -> Result<BodyKey, String> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT wrapped, destroyed_at FROM body_keys WHERE kind = ?1 AND sha256 = ?2",
                params![kind.as_str(), sha256],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        Ok(match row {
            Some((Some(wrapped), None)) => BodyKey::Held(wrapped),
            Some(_) => BodyKey::Destroyed,
            None => BodyKey::Absent,
        })
    }

    /// Keep `wrapped` as the body's key, unless one is held or was
    /// destroyed.
    fn put(&self, kind: BodyKind, sha256: &str, wrapped: &[u8]) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT OR IGNORE INTO body_keys (kind, sha256, wrapped) VALUES (?1, ?2, ?3)",
                params![kind.as_str(), sha256, wrapped],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Destroy the key of every body with this hash, request or
    /// response. A hash with no key here is marked too, so a body
    /// archived later under it is not kept readable. Returns how many
    /// held keys were destroyed.
    pub fn destroy(&self, sha256: &str) -> Result<usize, String> {
        use wirken_time::TimestampExt as _;
        let now = wirken_time::Timestamp::now().to_rfc3339();
        let conn = self.conn();
        let destroyed = conn
            .execute(
                "UPDATE body_keys SET wrapped = NULL, destroyed_at = ?1
                 WHERE sha256 = ?2 AND wrapped IS NOT NULL",
                params![now, sha256],
            )
            .map_err(|e| e.to_string())?;
        // The search text was readable only under the key. It goes too.
        conn.execute("DELETE FROM body_text WHERE sha256 = ?1", params![sha256])
            .map_err(|e| e.to_string())?;
        for kind in [BodyKind::Request, BodyKind::Response] {
            conn.execute(
                "INSERT OR IGNORE INTO body_keys (kind, sha256, wrapped, destroyed_at)
                 VALUES (?1, ?2, NULL, ?3)",
                params![kind.as_str(), sha256, now],
            )
            .map_err(|e| e.to_string())?;
        }
        // The freed pages are overwritten (secure_delete), and the
        // write-ahead log is folded back so no copy of the key waits
        // in it.
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(destroyed)
    }
}

/// What reading an archived body gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The body, decrypted. Its hash is checked by the caller.
    Body(Vec<u8>),
    /// Its key was destroyed: it is in the bucket and cannot be read.
    Redacted,
    /// This data directory never held a key for it.
    NoKey,
}

/// What the bucket says of an object's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    pub mode: Option<String>,
    pub retain_until: Option<String>,
}

/// The archive: the bucket, its credentials, and the keys.
pub struct Archive {
    config: ArchiveConfig,
    endpoint: url::Url,
    http: reqwest::Client,
    access_key: String,
    secret_key: Zeroizing<String>,
    master: Zeroizing<Vec<u8>>,
    keys: KeyStore,
}

/// The host the bucket credentials are bound to: the endpoint's host,
/// with its port unless that is 443.
pub fn endpoint_host(endpoint: &str) -> Result<(url::Url, String), String> {
    let url =
        url::Url::parse(endpoint).map_err(|e| format!("archive.endpoint {endpoint:?}: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("archive.endpoint {endpoint:?} has no host"))?
        .to_ascii_lowercase();
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(format!(
            "archive.endpoint {endpoint:?} is neither https nor plain http on this host"
        ));
    }
    let bound = match url.port_or_known_default() {
        Some(443) | None => host,
        Some(port) => format!("{host}:{port}"),
    };
    Ok((url, bound))
}

impl Archive {
    /// Open the archive `config` describes. The bucket credentials are
    /// read from the vault for the endpoint's host, and refused when
    /// their entry does not allow it. The archive key is read from the
    /// vault, and made there on first use.
    pub fn open(
        config: &ArchiveConfig,
        vault: &CredentialStore,
        data_dir: &Path,
    ) -> Result<Self, String> {
        let (endpoint, host) = endpoint_host(&config.endpoint)?;
        let (credentials, _) = vault
            .retrieve_for(&config.credential, &Destination::Archive(host.clone()))
            .map_err(|e| {
                format!(
                    "the bucket credentials '{}' for {host}: {e}. Store them with `wirken \
                     credentials add {} --archive {host}`",
                    config.credential, config.credential
                )
            })?;
        let (access_key, secret_key) = credentials
            .expose()
            .split_once(':')
            .map(|(a, s)| (a.to_string(), Zeroizing::new(s.to_string())))
            .ok_or_else(|| {
                format!(
                    "the bucket credentials '{}' are not access_key_id:secret_access_key",
                    config.credential
                )
            })?;
        let master = match vault.retrieve(&config.key) {
            Ok((key, _)) => unhex(key.expose())
                .filter(|k| k.len() == 32)
                .ok_or_else(|| {
                    format!("the archive key '{}' is not 32 bytes of hex", config.key)
                })?,
            Err(wirken_vault::VaultError::NotFound(_)) => {
                let key = random::<32>();
                vault
                    .store(
                        &config.key,
                        "proxy-archive",
                        &wirken_vault::VaultSecret::new(hex(&key)),
                        None,
                        None,
                    )
                    .map_err(|e| format!("store the archive key '{}': {e}", config.key))?;
                tracing::info!(
                    "made the archive key '{}' in the vault. Bodies archived from here on \
                     cannot be read without it and {ARCHIVE_KEYS_FILE}",
                    config.key
                );
                key.to_vec()
            }
            Err(e) => return Err(format!("the archive key '{}': {e}", config.key)),
        };
        let http = reqwest::Client::builder()
            .https_only(endpoint.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| format!("archive client: {e}"))?;
        Ok(Self {
            config: config.clone(),
            endpoint,
            http,
            access_key,
            secret_key,
            master: Zeroizing::new(master),
            keys: KeyStore::open(&data_dir.join(ARCHIVE_KEYS_FILE))?,
        })
    }

    #[cfg(test)]
    fn keys(&self) -> &KeyStore {
        &self.keys
    }

    /// The object key a body is stored under.
    pub fn object_key(&self, kind: BodyKind, sha256: &str) -> String {
        format!("{}{}/{sha256}", self.config.prefix, kind.as_str())
    }

    fn object_url(&self, kind: BodyKind, sha256: &str) -> Result<url::Url, String> {
        let mut url = self.endpoint.clone();
        url.set_path(&format!(
            "/{}/{}",
            self.config.bucket,
            self.object_key(kind, sha256)
        ));
        Ok(url)
    }

    fn signed(
        &self,
        method: reqwest::Method,
        url: &url::Url,
        body: &[u8],
        extra: &[(String, String)],
    ) -> reqwest::RequestBuilder {
        let headers = wirken_agent::sigv4::sign_with_headers(
            &self.access_key,
            &self.secret_key,
            None,
            &self.config.region,
            "s3",
            method.as_str(),
            url,
            body,
            extra,
        );
        let mut request = self.http.request(method, url.clone());
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request
    }

    /// Read a body back and decrypt it.
    pub async fn get(&self, kind: BodyKind, sha256: &str) -> Result<Fetched, String> {
        let wrapped = match self.keys.get(kind, sha256)? {
            BodyKey::Held(wrapped) => wrapped,
            BodyKey::Destroyed => return Ok(Fetched::Redacted),
            BodyKey::Absent => return Ok(Fetched::NoKey),
        };
        let key = Zeroizing::new(
            open(&self.master, &aad(kind, sha256), &wrapped).map_err(|e| {
                format!("the key of {} {sha256} does not unwrap: {e}", kind.as_str())
            })?,
        );
        let url = self.object_url(kind, sha256)?;
        let response = self
            .signed(reqwest::Method::GET, &url, b"", &[])
            .send()
            .await
            .map_err(|e| format!("GET {}: {}", url.path(), e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("GET {} returned {}", url.path(), response.status()));
        }
        let object = response
            .bytes()
            .await
            .map_err(|e| format!("GET {}: {}", url.path(), e.without_url()))?;
        let sealed = object
            .strip_prefix(MAGIC.as_slice())
            .ok_or_else(|| format!("{} is not an archived body", url.path()))?;
        open(&key, &aad(kind, sha256), sealed)
            .map(Fetched::Body)
            .map_err(|e| format!("{}: {e}", url.path()))
    }

    /// The text of an archived body, for a search: read from the search
    /// text kept for it, or from the bucket the first time, when that
    /// text is made and kept. The kept text is encrypted under the
    /// body's own key, so it is as readable as the body is: `None` for
    /// a body whose key was destroyed or never held here, and for one
    /// that is not what its row says.
    pub async fn search_text(
        &self,
        kind: BodyKind,
        sha256: &str,
        shape: Option<wirken_audit::ProxyShape>,
    ) -> Result<Option<String>, String> {
        let wrapped = match self.keys.get(kind, sha256)? {
            BodyKey::Held(wrapped) => wrapped,
            BodyKey::Destroyed | BodyKey::Absent => return Ok(None),
        };
        let key = Zeroizing::new(
            open(&self.master, &aad(kind, sha256), &wrapped).map_err(|e| {
                format!("the key of {} {sha256} does not unwrap: {e}", kind.as_str())
            })?,
        );
        let bound = text_aad(kind, sha256);
        if let Some(sealed) = self.keys.text(kind, sha256)? {
            let text = open(&key, &bound, &sealed)
                .map_err(|e| format!("the search text of {} {sha256}: {e}", kind.as_str()))?;
            return Ok(Some(String::from_utf8_lossy(&text).into_owned()));
        }
        let body = match self.get(kind, sha256).await? {
            Fetched::Body(body) if hex(&Sha256::digest(&body)) == sha256 => body,
            _ => return Ok(None),
        };
        let text = wirken_audit::search::body_text(shape, &body);
        self.keys
            .put_text(kind, sha256, &seal(&key, &bound, text.as_bytes())?)?;
        Ok(Some(text))
    }

    /// Whether the body's key was destroyed.
    pub fn redacted(&self, kind: BodyKind, sha256: &str) -> bool {
        matches!(self.keys.get(kind, sha256), Ok(BodyKey::Destroyed))
    }

    /// What the bucket reports of the object's lock.
    pub async fn lock(&self, kind: BodyKind, sha256: &str) -> Result<Lock, String> {
        let url = self.object_url(kind, sha256)?;
        let response = self
            .signed(reqwest::Method::HEAD, &url, b"", &[])
            .send()
            .await
            .map_err(|e| format!("HEAD {}: {}", url.path(), e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!(
                "HEAD {} returned {}",
                url.path(),
                response.status()
            ));
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Ok(Lock {
            mode: header("x-amz-object-lock-mode"),
            retain_until: header("x-amz-object-lock-retain-until-date"),
        })
    }
}

#[async_trait::async_trait]
impl BodySink for Archive {
    /// Encrypt `body` under a new key and write it, locked, under its
    /// hash. A body this archive already holds a key for is there
    /// already. One whose key was destroyed is not written again, and
    /// the answer says no readable copy is kept.
    async fn put(&self, kind: BodyKind, sha256: &str, body: &[u8]) -> Result<bool, String> {
        match self.keys.get(kind, sha256)? {
            BodyKey::Held(_) => return Ok(true),
            BodyKey::Destroyed => return Ok(false),
            BodyKey::Absent => {}
        }
        let key = Zeroizing::new(random::<32>());
        let bound = aad(kind, sha256);
        let object = [MAGIC.as_slice(), &seal(key.as_slice(), &bound, body)?].concat();
        let retain_until = (wirken_time::now()
            + wirken_time::days(i64::from(self.config.retention_days)))
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
        let extra = [
            (
                "x-amz-checksum-sha256".to_string(),
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&object)),
            ),
            (
                "x-amz-object-lock-mode".to_string(),
                self.config.mode.header().to_string(),
            ),
            (
                "x-amz-object-lock-retain-until-date".to_string(),
                retain_until,
            ),
        ];
        let url = self.object_url(kind, sha256)?;
        let response = self
            .signed(reqwest::Method::PUT, &url, &object, &extra)
            .header("content-type", "application/octet-stream")
            .body(object)
            .send()
            .await
            .map_err(|e| format!("PUT {}: {}", url.path(), e.without_url()))?;
        if !response.status().is_success() {
            let status = response.status();
            let detail: String = response
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect();
            return Err(format!("PUT {} returned {status}: {detail}", url.path()));
        }
        // The key is kept only once the object is in the bucket.
        self.keys
            .put(kind, sha256, &seal(&self.master, &bound, key.as_slice())?)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn a_sealed_body_opens_only_under_its_key_kind_and_hash() {
        let key = random::<32>();
        let sealed = seal(&key, &aad(BodyKind::Request, HASH), b"the body").unwrap();
        assert!(!sealed.windows(8).any(|w| w == b"the body"));
        assert_eq!(
            open(&key, &aad(BodyKind::Request, HASH), &sealed).unwrap(),
            b"the body"
        );
        assert!(open(&key, &aad(BodyKind::Response, HASH), &sealed).is_err());
        assert!(open(&key, &aad(BodyKind::Request, &"0".repeat(64)), &sealed).is_err());
        assert!(open(&random::<32>(), &aad(BodyKind::Request, HASH), &sealed).is_err());
        // Two seals of one body differ: each has its own nonce.
        assert_ne!(
            sealed,
            seal(&key, &aad(BodyKind::Request, HASH), b"the body").unwrap()
        );
    }

    /// A destroyed key is gone from the store's files, a destroyed
    /// hash takes no new key, and the other kind under the same hash
    /// goes with it.
    /// The search text kept for a body is ciphertext under the body's
    /// own key: the file never holds the text, and once the key is
    /// destroyed it holds nothing of the entry either.
    #[test]
    fn a_bodys_search_text_is_sealed_under_its_key_and_goes_with_it() {
        const TEXT: &str = "the heron plan, and more words around it";
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ARCHIVE_KEYS_FILE);
        let store = KeyStore::open(&path).unwrap();
        let master = random::<32>();
        let key = random::<32>();
        let at_rest = |needle: &[u8]| {
            std::fs::read_dir(tmp.path())
                .unwrap()
                .flatten()
                .any(|file| {
                    std::fs::read(file.path())
                        .unwrap()
                        .windows(needle.len())
                        .any(|w| w == needle)
                })
        };

        // No key, no text kept.
        let sealed = seal(&key, &text_aad(BodyKind::Request, HASH), TEXT.as_bytes()).unwrap();
        store.put_text(BodyKind::Request, HASH, &sealed).unwrap();
        assert_eq!(store.text(BodyKind::Request, HASH).unwrap(), None);

        store
            .put(
                BodyKind::Request,
                HASH,
                &seal(&master, &aad(BodyKind::Request, HASH), &key).unwrap(),
            )
            .unwrap();
        store.put_text(BodyKind::Request, HASH, &sealed).unwrap();
        let kept = store.text(BodyKind::Request, HASH).unwrap().unwrap();
        assert_eq!(kept, sealed);
        // It opens under the body's key and its own binding, and under
        // nothing else.
        assert_eq!(
            open(&key, &text_aad(BodyKind::Request, HASH), &kept).unwrap(),
            TEXT.as_bytes()
        );
        assert!(open(&master, &text_aad(BodyKind::Request, HASH), &kept).is_err());
        assert!(open(&key, &aad(BodyKind::Request, HASH), &kept).is_err());
        assert!(open(&key, &text_aad(BodyKind::Response, HASH), &kept).is_err());
        // At rest: the ciphertext, and no word of the text.
        let _ = store
            .conn()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        assert!(at_rest(&sealed));
        assert!(!at_rest(b"heron"));

        assert_eq!(store.destroy(HASH).unwrap(), 1);
        assert_eq!(store.text(BodyKind::Request, HASH).unwrap(), None);
        store.put_text(BodyKind::Request, HASH, &sealed).unwrap();
        assert_eq!(store.text(BodyKind::Request, HASH).unwrap(), None);
        drop(store);
        assert!(!at_rest(&sealed), "the entry is still in the file");
        assert!(!at_rest(&sealed[NONCE_BYTES..NONCE_BYTES + 16]));
        assert!(!at_rest(b"heron"));
    }

    #[test]
    fn a_destroyed_key_is_not_in_the_store_and_cannot_be_put_back() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ARCHIVE_KEYS_FILE);
        let store = KeyStore::open(&path).unwrap();
        let wrapped = b"WRAPPED-KEY-BYTES-0123456789abcdef".to_vec();
        assert_eq!(store.get(BodyKind::Request, HASH).unwrap(), BodyKey::Absent);
        store.put(BodyKind::Request, HASH, &wrapped).unwrap();
        store.put(BodyKind::Response, HASH, &wrapped).unwrap();
        assert_eq!(
            store.get(BodyKind::Request, HASH).unwrap(),
            BodyKey::Held(wrapped.clone())
        );
        // A second put does not replace the key an object was sealed
        // under.
        store.put(BodyKind::Request, HASH, b"another").unwrap();
        assert_eq!(
            store.get(BodyKind::Request, HASH).unwrap(),
            BodyKey::Held(wrapped.clone())
        );

        assert_eq!(store.destroy(HASH).unwrap(), 2);
        for kind in [BodyKind::Request, BodyKind::Response] {
            assert_eq!(store.get(kind, HASH).unwrap(), BodyKey::Destroyed);
        }
        store.put(BodyKind::Request, HASH, &wrapped).unwrap();
        assert_eq!(
            store.get(BodyKind::Request, HASH).unwrap(),
            BodyKey::Destroyed
        );
        assert_eq!(store.destroy(HASH).unwrap(), 0);

        drop(store);
        for file in std::fs::read_dir(tmp.path()).unwrap().flatten() {
            let bytes = std::fs::read(file.path()).unwrap();
            assert!(
                !bytes
                    .windows(wrapped.len())
                    .any(|w| w == wrapped.as_slice()),
                "{} still holds the key",
                file.path().display()
            );
        }

        // A hash never archived is marked, so it is not archived
        // readable later.
        let store = KeyStore::open(&path).unwrap();
        let other = "1".repeat(64);
        assert_eq!(store.destroy(&other).unwrap(), 0);
        assert_eq!(
            store.get(BodyKind::Response, &other).unwrap(),
            BodyKey::Destroyed
        );
    }

    /// Where the tests below find an S3-compatible server with Object
    /// Lock, and the credentials for it. Without the first they pass
    /// without running, with a `skipping:` line.
    const ENDPOINT_ENV: &str = "WIRKEN_TEST_S3_ENDPOINT";
    const ACCESS_ENV: &str = "WIRKEN_TEST_S3_ACCESS_KEY";
    const SECRET_ENV: &str = "WIRKEN_TEST_S3_SECRET_KEY";
    /// Set to `1` where these tests must run: the CI job that starts
    /// a server. A missing server then fails them.
    const REQUIRE_ENV: &str = "WIRKEN_TEST_REQUIRE_S3";

    struct Live {
        archive: Archive,
        bucket: String,
        _tmp: tempfile::TempDir,
    }

    fn vault(tmp: &Path) -> CredentialStore {
        CredentialStore::open_with_key(
            &tmp.join("vault.db"),
            wirken_vault::VaultSecret::new("a".repeat(64)),
        )
        .unwrap()
    }

    fn store_credentials(vault: &CredentialStore, host: &str, value: &str) {
        let mut binding = wirken_vault::Binding::default();
        binding.grant(Destination::Archive(host.to_string()));
        vault
            .store_bound(
                "proxy-archive-credentials",
                "proxy-archive",
                &wirken_vault::VaultSecret::new(value.into()),
                None,
                None,
                &binding,
                wirken_vault::CredentialKind::Secret,
            )
            .unwrap();
    }

    fn config(endpoint: &str, bucket: &str) -> ArchiveConfig {
        serde_json::from_value(serde_json::json!({
            "endpoint": endpoint,
            "bucket": bucket,
            "prefix": "wirken/",
            "retention_days": 1,
            "credential": "proxy-archive-credentials",
        }))
        .unwrap()
    }

    /// An archive on a new bucket with Object Lock, on the server the
    /// environment names.
    async fn live() -> Option<Live> {
        let Ok(endpoint) = std::env::var(ENDPOINT_ENV) else {
            assert!(
                std::env::var(REQUIRE_ENV).as_deref() != Ok("1"),
                "{REQUIRE_ENV}=1 and {ENDPOINT_ENV} names no server"
            );
            eprintln!("skipping: {ENDPOINT_ENV} names no S3-compatible server");
            return None;
        };
        let access = std::env::var(ACCESS_ENV).expect(ACCESS_ENV);
        let secret = std::env::var(SECRET_ENV).expect(SECRET_ENV);
        let tmp = tempfile::tempdir().unwrap();
        let vault = vault(tmp.path());
        let (_, host) = endpoint_host(&endpoint).unwrap();
        store_credentials(&vault, &host, &format!("{access}:{secret}"));
        let bucket = format!("wirken-test-{}", hex(&random::<6>()));
        let archive = Archive::open(&config(&endpoint, &bucket), &vault, tmp.path()).unwrap();
        // The archive key was made in the vault on first use.
        assert!(vault.retrieve("proxy-archive-key").is_ok());

        let mut url = archive.endpoint.clone();
        url.set_path(&format!("/{bucket}"));
        let created = archive
            .signed(
                reqwest::Method::PUT,
                &url,
                b"",
                &[(
                    "x-amz-bucket-object-lock-enabled".to_string(),
                    "true".to_string(),
                )],
            )
            .send()
            .await
            .unwrap();
        assert!(
            created.status().is_success(),
            "create bucket: {} {}",
            created.status(),
            created.text().await.unwrap_or_default()
        );
        Some(Live {
            archive,
            bucket,
            _tmp: tmp,
        })
    }

    fn sha(body: &[u8]) -> String {
        hex(&Sha256::digest(body))
    }

    fn row(seq: u64, event: wirken_audit::SessionEvent) -> wirken_audit::StoredSessionEvent {
        wirken_audit::StoredSessionEvent {
            id: seq as i64,
            session_id: wirken_audit::SessionId::new("proxy-test".to_string()),
            seq,
            ts: wirken_time::now(),
            trust: wirken_audit::TrustLevel::System,
            event,
            leaf_hash: wirken_audit::HashHex(String::new()),
            prev_hash: wirken_audit::HashHex(String::new()),
            hash: wirken_audit::HashHex(String::new()),
        }
    }

    fn request_row(seq: u64, body: &[u8]) -> wirken_audit::StoredSessionEvent {
        row(
            seq,
            wirken_audit::SessionEvent::ProxyRequest {
                request_id: "r".into(),
                token_id: "t".into(),
                token_name: "n".into(),
                upstream: "u".into(),
                provider: "p".into(),
                model: "m".into(),
                shape: wirken_audit::ProxyShape::OpenaiChat,
                stream: false,
                request_sha256: wirken_audit::HashHex(sha(body)),
                request_bytes: body.len() as u64,
                credential_id: None,
                archived: true,
                identity: None,
            },
        )
    }

    /// A body written to the bucket is ciphertext there, comes back
    /// equal, sits under a lock that has not ended, cannot be deleted,
    /// and is found by the hash on its row.
    #[tokio::test]
    async fn an_archived_body_is_encrypted_locked_and_found_by_its_hash() {
        let Some(live) = live().await else {
            return;
        };
        let archive = &live.archive;
        let body = b"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"a private prompt\"}]}";
        let hash = sha(body);
        archive.put(BodyKind::Request, &hash, body).await.unwrap();
        assert_eq!(
            archive.object_key(BodyKind::Request, &hash),
            format!("wirken/request/{hash}")
        );

        // What the bucket holds, read without the archive's key.
        let url = archive.object_url(BodyKind::Request, &hash).unwrap();
        let raw = archive
            .signed(reqwest::Method::GET, &url, b"", &[])
            .send()
            .await
            .unwrap();
        assert!(raw.status().is_success());
        let version = raw
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let stored = raw.bytes().await.unwrap();
        assert!(stored.starts_with(MAGIC));
        assert!(!stored.windows(16).any(|w| w == b"a private prompt"));

        assert_eq!(
            archive.get(BodyKind::Request, &hash).await.unwrap(),
            Fetched::Body(body.to_vec())
        );
        let lock = archive.lock(BodyKind::Request, &hash).await.unwrap();
        assert_eq!(lock.mode.as_deref(), Some("COMPLIANCE"));
        assert!(
            still_locked(lock.retain_until.as_deref().unwrap()),
            "{lock:?}"
        );

        // The locked version cannot be deleted.
        let version = version.expect("a bucket with Object Lock is versioned");
        let mut delete_url = url.clone();
        delete_url.set_query(Some(&format!("versionId={version}")));
        let deleted = archive
            .signed(reqwest::Method::DELETE, &delete_url, b"", &[])
            .send()
            .await
            .unwrap();
        assert!(
            !deleted.status().is_success(),
            "a locked version was deleted: {}",
            deleted.status()
        );
        assert_eq!(
            archive.get(BodyKind::Request, &hash).await.unwrap(),
            Fetched::Body(body.to_vec())
        );

        let report = archive.check(&[request_row(1, body)]).await;
        assert_eq!(
            report,
            ArchiveReport {
                named: 1,
                matched: 1,
                redacted: 0,
                failures: vec![]
            }
        );
        eprintln!("archived to bucket {} and read back", live.bucket);
    }

    /// A row whose body is not in the bucket, and one whose object was
    /// replaced with other bytes, each fail the check and name the row.
    #[tokio::test]
    async fn a_missing_or_replaced_object_fails_the_check() {
        let Some(live) = live().await else {
            return;
        };
        let archive = &live.archive;
        let (kept, never_written) = (b"kept body".as_slice(), b"never written".as_slice());
        archive
            .put(BodyKind::Request, &sha(kept), kept)
            .await
            .unwrap();

        let missing = archive.check(&[request_row(4, never_written)]).await;
        assert_eq!(missing.matched, 0);
        assert_eq!(missing.failures.len(), 1, "{missing:?}");
        assert!(
            missing.failures[0].starts_with("seq 4 request "),
            "{missing:?}"
        );

        // Another object written over the same key: a new version that
        // does not open under the body's key.
        let url = archive.object_url(BodyKind::Request, &sha(kept)).unwrap();
        let forged = [MAGIC.as_slice(), &[7u8; 64]].concat();
        let until = (wirken_time::now() + wirken_time::days(1))
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let extra = [
            (
                "x-amz-checksum-sha256".to_string(),
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&forged)),
            ),
            (
                "x-amz-object-lock-mode".to_string(),
                "COMPLIANCE".to_string(),
            ),
            ("x-amz-object-lock-retain-until-date".to_string(), until),
        ];
        let put = archive
            .signed(reqwest::Method::PUT, &url, &forged, &extra)
            .body(forged)
            .send()
            .await
            .unwrap();
        assert!(put.status().is_success(), "{}", put.status());
        let replaced = archive.check(&[request_row(9, kept)]).await;
        assert_eq!(replaced.matched, 0);
        assert!(
            replaced.failures[0].contains("does not decrypt"),
            "{replaced:?}"
        );
    }

    /// Destroying a body's key leaves the object in the bucket, locked,
    /// and unreadable: the archive reports it redacted, and the check
    /// counts it as redacted and not as a failure.
    #[tokio::test]
    async fn a_redacted_body_stays_locked_and_cannot_be_read() {
        let Some(live) = live().await else {
            return;
        };
        let archive = &live.archive;
        let body = b"a body to be forgotten";
        let hash = sha(body);
        archive.put(BodyKind::Request, &hash, body).await.unwrap();
        assert_eq!(archive.keys().destroy(&hash).unwrap(), 1);

        assert_eq!(
            archive.get(BodyKind::Request, &hash).await.unwrap(),
            Fetched::Redacted
        );
        let lock = archive.lock(BodyKind::Request, &hash).await.unwrap();
        assert!(
            lock.mode.is_some(),
            "the object is gone or unlocked: {lock:?}"
        );
        let report = archive.check(&[request_row(1, body)]).await;
        assert_eq!((report.matched, report.redacted), (0, 1));
        assert!(report.failures.is_empty(), "{report:?}");

        // The same body sent again is not archived readable.
        archive.put(BodyKind::Request, &hash, body).await.unwrap();
        assert_eq!(
            archive.get(BodyKind::Request, &hash).await.unwrap(),
            Fetched::Redacted
        );
    }

    /// Bucket credentials stored for another host are not read for
    /// this endpoint.
    #[test]
    fn credentials_bound_to_another_host_do_not_open_the_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = vault(tmp.path());
        store_credentials(&vault, "s3.example.com", "AKIA:secret");
        let err = Archive::open(
            &config("https://other.example.net", "b"),
            &vault,
            tmp.path(),
        )
        .err()
        .unwrap();
        assert!(err.contains("other.example.net"), "{err}");
        assert!(Archive::open(&config("https://s3.example.com", "b"), &vault, tmp.path()).is_ok());
        // The archive key in the vault is 32 bytes and not in the key
        // store's file.
        let key = vault.retrieve("proxy-archive-key").unwrap().0;
        assert_eq!(key.expose().len(), 64);
    }

    /// A body whose key was destroyed is not written again, and the
    /// archive says no readable copy is kept. Nothing is sent.
    #[tokio::test]
    async fn a_redacted_body_sent_again_is_not_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = vault(tmp.path());
        store_credentials(&vault, "s3.example.com", "AKIA:secret");
        // An endpoint nothing answers at: a request to it would fail.
        let archive =
            Archive::open(&config("https://s3.example.com", "b"), &vault, tmp.path()).unwrap();
        archive.keys().destroy(HASH).unwrap();
        for kind in [BodyKind::Request, BodyKind::Response] {
            assert_eq!(archive.put(kind, HASH, b"the same body").await, Ok(false));
            assert_eq!(archive.keys().get(kind, HASH).unwrap(), BodyKey::Destroyed);
        }
    }

    #[test]
    fn bucket_credentials_are_bound_to_the_endpoint_host() {
        assert_eq!(
            endpoint_host("https://s3.eu-central-1.amazonaws.com")
                .unwrap()
                .1,
            "s3.eu-central-1.amazonaws.com"
        );
        assert_eq!(
            endpoint_host("https://S3.Example.com:9443/").unwrap().1,
            "s3.example.com:9443"
        );
        assert_eq!(
            endpoint_host("http://127.0.0.1:9000").unwrap().1,
            "127.0.0.1:9000"
        );
        assert!(endpoint_host("http://s3.example.com").is_err());
        assert!(endpoint_host("s3.example.com").is_err());
    }
}

/// One archived body a session's rows name.
pub(crate) struct Named {
    pub(crate) seq: u64,
    pub(crate) kind: BodyKind,
    pub(crate) sha256: String,
}

/// What checking a proxy session against the archive found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ArchiveReport {
    /// Bodies the rows say were archived.
    pub named: usize,
    /// Read back, decrypted, and equal to the row's hash, under a lock
    /// that has not ended.
    pub matched: usize,
    /// Unreadable because their key was destroyed; the object is there
    /// and locked.
    pub redacted: usize,
    /// Each body that is missing, altered, unlocked or unreadable for
    /// another reason, with the row it belongs to.
    pub failures: Vec<String>,
}

/// The bodies `rows` say were archived.
pub(crate) fn named(rows: &[wirken_audit::StoredSessionEvent]) -> Vec<Named> {
    use wirken_audit::SessionEvent;
    let named = |seq, kind, sha256: &wirken_audit::HashHex| Named {
        seq,
        kind,
        sha256: sha256.0.clone(),
    };
    rows.iter()
        .flat_map(|row| match &row.event {
            SessionEvent::ProxyRequest {
                request_sha256,
                archived: true,
                ..
            } => vec![named(row.seq, BodyKind::Request, request_sha256)],
            SessionEvent::ProxyResponse {
                response_sha256,
                archived: true,
                ..
            } => vec![named(row.seq, BodyKind::Response, response_sha256)],
            // The tool list an MCP session was shown, and both bodies
            // of a tool call.
            SessionEvent::ProxyToolsListed {
                tools_sha256,
                archived: true,
                ..
            } => vec![named(row.seq, BodyKind::Response, tools_sha256)],
            SessionEvent::ProxyToolCall {
                request_sha256,
                response_sha256,
                archived: true,
                ..
            } => vec![
                named(row.seq, BodyKind::Request, request_sha256),
                named(row.seq, BodyKind::Response, response_sha256),
            ],
            _ => Vec::new(),
        })
        .collect()
}

/// The hash of every body `rows` say was archived, each once, in the
/// order the rows name them.
pub fn archived_hashes(rows: &[wirken_audit::StoredSessionEvent]) -> Vec<String> {
    let mut hashes: Vec<String> = Vec::new();
    for body in named(rows) {
        if !hashes.contains(&body.sha256) {
            hashes.push(body.sha256);
        }
    }
    hashes
}

/// Whether a lock's end, as the bucket gives it, is still ahead.
fn still_locked(retain_until: &str) -> bool {
    retain_until
        .parse::<wirken_time::Timestamp>()
        .is_ok_and(|until| until > wirken_time::now())
}

impl Archive {
    /// Check every body `rows` say was archived: the object is in the
    /// bucket under the row's hash, it is under a lock that has not
    /// ended, and what it decrypts to hashes to the row's hash. A body
    /// whose key was destroyed is checked for being there and locked.
    pub async fn check(&self, rows: &[wirken_audit::StoredSessionEvent]) -> ArchiveReport {
        let mut report = ArchiveReport::default();
        for body in named(rows) {
            report.named += 1;
            let what = format!("seq {} {} {}", body.seq, body.kind.as_str(), body.sha256);
            match self.lock(body.kind, &body.sha256).await {
                Ok(Lock {
                    mode: Some(_),
                    retain_until: Some(until),
                }) if still_locked(&until) => {}
                Ok(lock) => {
                    report
                        .failures
                        .push(format!("{what}: the object is not under a lock ({lock:?})"));
                    continue;
                }
                Err(e) => {
                    report.failures.push(format!("{what}: {e}"));
                    continue;
                }
            }
            match self.get(body.kind, &body.sha256).await {
                Ok(Fetched::Body(plain)) if hex(&Sha256::digest(&plain)) == body.sha256 => {
                    report.matched += 1;
                }
                Ok(Fetched::Body(_)) => report.failures.push(format!(
                    "{what}: the archived body does not hash to the row's hash"
                )),
                Ok(Fetched::Redacted) => report.redacted += 1,
                Ok(Fetched::NoKey) => report.failures.push(format!(
                    "{what}: this data directory holds no key for it, so it cannot be read"
                )),
                Err(e) => report.failures.push(format!("{what}: {e}")),
            }
        }
        report
    }
}

impl Archive {
    /// Every body `rows` say was archived, by its hash, as far as it
    /// can be read here: decrypted and equal to the hash, made
    /// unreadable, or not available.
    pub async fn bodies(
        &self,
        rows: &[wirken_audit::StoredSessionEvent],
    ) -> std::collections::HashMap<String, wirken_audit::atif::Body> {
        use wirken_audit::atif::Body;
        let mut out = std::collections::HashMap::new();
        for body in named(rows) {
            let read = match self.get(body.kind, &body.sha256).await {
                Ok(Fetched::Body(plain)) if hex(&Sha256::digest(&plain)) == body.sha256 => {
                    Body::Plain(plain)
                }
                Ok(Fetched::Redacted) => Body::Redacted,
                Ok(Fetched::Body(_)) | Ok(Fetched::NoKey) => Body::Unavailable,
                Err(e) => {
                    tracing::warn!(
                        "archive: {} {} could not be read: {e}",
                        body.kind.as_str(),
                        body.sha256
                    );
                    Body::Unavailable
                }
            };
            out.insert(body.sha256, read);
        }
        out
    }
}

/// The bodies of a proxy session, read from the archive when one is
/// configured and `skip` is not set. Empty otherwise.
pub async fn session_bodies(
    rows: &[wirken_audit::StoredSessionEvent],
    skip: bool,
) -> anyhow::Result<std::collections::HashMap<String, wirken_audit::atif::Body>> {
    use anyhow::Context as _;
    let cfg = super::config();
    let archive_config = wirken_gateway::proxy::ProxyConfig::load(&cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .and_then(|c| c.archive);
    let Some(archive_config) = archive_config.filter(|_| !skip && !named(rows).is_empty()) else {
        return Ok(Default::default());
    };
    let passphrase = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(&cfg.data_dir, move || passphrase);
    let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    let archive = Archive::open(&archive_config, &vault, &cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("archive: {e}"))?;
    drop(vault);
    Ok(archive.bodies(rows).await)
}

/// Whether `session_id` is a lane the proxy writes.
pub fn is_proxy_session(session_id: &str) -> bool {
    !session_id.contains('/')
        && (session_id == wirken_audit::PROXY_SESSION || session_id.starts_with("proxy-"))
}

/// `wirken sessions verify` for a proxy lane: the chain, then, when an
/// archive is configured, each archived body against its row. Returns
/// the exit status: 0, 3 for a broken chain, 4 for no rows, 7 for an
/// archive failure.
pub async fn verify_session(session_id: &str, skip_archive: bool) -> anyhow::Result<i32> {
    use anyhow::Context as _;
    use wirken_audit::{SessionEvent, SessionLog as _, SessionVerifyResult};

    let cfg = super::config();
    let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
        .context("Failed to open session log")?;
    let handle = log.handle_for(wirken_audit::SessionId::new(session_id.to_string()));
    let rows = log
        .get_since(&handle, 0)
        .context("session log query failed")?;
    if rows.is_empty() {
        eprintln!("  No events for session '{session_id}'.");
        return Ok(4);
    }
    println!();
    println!("  Proxy session: {session_id}");
    let count = |pick: fn(&SessionEvent) -> bool| rows.iter().filter(|r| pick(&r.event)).count();
    println!(
        "  calls: {} forwarded, {} answered, {} refused",
        count(|e| matches!(e, SessionEvent::ProxyRequest { .. })),
        count(|e| matches!(e, SessionEvent::ProxyResponse { .. })),
        count(|e| matches!(e, SessionEvent::ProxyRefused { .. })),
    );
    let tool_calls = count(|e| matches!(e, SessionEvent::ProxyToolCall { .. }));
    let tool_refusals = count(|e| matches!(e, SessionEvent::ProxyToolRefused { .. }));
    if tool_calls + tool_refusals > 0 {
        println!("  tool calls: {tool_calls} answered, {tool_refusals} refused before the gate");
    }
    match log.verify(&handle).context("chain verification failed")? {
        SessionVerifyResult::Ok { rows_verified } => println!("  chain: OK ({rows_verified} rows)"),
        SessionVerifyResult::Empty => println!("  chain: EMPTY"),
        SessionVerifyResult::Broken { seq, .. } => {
            println!("  chain: BROKEN at seq {seq}");
            return Ok(3);
        }
    }

    let archive_config = wirken_gateway::proxy::ProxyConfig::load(&cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .and_then(|c| c.archive);
    let named_count = named(&rows).len();
    let Some(archive_config) = archive_config else {
        if named_count > 0 {
            println!(
                "  archive: not configured; {named_count} archived bodies not checked. The \
                 chain holds their hashes."
            );
        } else {
            println!("  archive: not configured");
        }
        return Ok(0);
    };
    if skip_archive {
        println!("  archive: skipped (--skip-archive); {named_count} archived bodies not checked");
        return Ok(0);
    }
    let passphrase = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(&cfg.data_dir, move || passphrase);
    let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    let archive = Archive::open(&archive_config, &vault, &cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("archive: {e}"))?;
    drop(vault);
    let report = archive.check(&rows).await;
    println!(
        "  archive: bucket {} at {}: {} named, {} match their row, {} redacted, {} failed",
        archive_config.bucket,
        archive_config.endpoint,
        report.named,
        report.matched,
        report.redacted,
        report.failures.len()
    );
    for failure in &report.failures {
        println!("    {failure}");
    }
    Ok(if report.failures.is_empty() { 0 } else { 7 })
}

#[cfg(test)]
mod mcp_rows_tests {
    use super::*;

    /// The archived bodies of an MCP session are its tool list and both
    /// bodies of each call, so `sessions verify` checks them and a
    /// session's redaction takes them.
    #[test]
    fn a_tool_list_and_both_bodies_of_a_tool_call_are_named() {
        use wirken_audit::{HashHex, SessionEvent, SessionId, SessionLog, SqliteSessionLog};
        let tmp = tempfile::tempdir().unwrap();
        let log = SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap();
        let lane = log.handle_for(SessionId::new("proxy-0a0a0a0a-work".to_string()));
        let hash = |c: &str| HashHex(c.repeat(64));
        for event in [
            SessionEvent::ProxyToolsListed {
                token_id: "0a0a0a0a".into(),
                agent_id: "default".into(),
                mcp_session: "s".into(),
                servers: vec!["files".into()],
                tools: vec!["mcp_files_read".into()],
                tools_sha256: hash("a"),
                archived: true,
                identity: None,
            },
            SessionEvent::ProxyToolCall {
                call_id: "c1".into(),
                token_id: "0a0a0a0a".into(),
                agent_id: "default".into(),
                mcp_session: "s".into(),
                tool: "mcp_files_read".into(),
                success: true,
                latency_ms: 1,
                request_sha256: hash("b"),
                request_bytes: 1,
                response_sha256: hash("c"),
                response_bytes: 1,
                archived: true,
                identity: None,
            },
            SessionEvent::ProxyToolCall {
                call_id: "c2".into(),
                token_id: "0a0a0a0a".into(),
                agent_id: "default".into(),
                mcp_session: "s".into(),
                tool: "mcp_files_read".into(),
                success: true,
                latency_ms: 1,
                request_sha256: hash("d"),
                request_bytes: 1,
                response_sha256: hash("e"),
                response_bytes: 1,
                archived: false,
                identity: None,
            },
        ] {
            log.append(&lane, wirken_audit::TrustLevel::System, event)
                .unwrap();
        }
        let rows = log.get_since(&lane, 0).unwrap();
        assert_eq!(
            archived_hashes(&rows),
            vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)]
        );
        let kinds: Vec<&str> = named(&rows).iter().map(|n| n.kind.as_str()).collect();
        assert_eq!(kinds, vec!["response", "request", "response"]);
    }
}
