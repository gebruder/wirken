//! The inference proxy's configuration and its client tokens.
//!
//! A client Wirken does not run points its model base URL at the proxy
//! listener and authenticates with a token issued here. The token
//! names which configured upstreams the client may reach and which
//! models it may ask for, and carries its own ceilings. Only a digest
//! of a token is stored: the token itself is shown once, when issued.
//!
//! `proxy.json` in the data directory turns the listener on and names
//! the upstreams. Tokens live in `proxy_tokens.db`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use wirken_time::TimestampExt as _;

use crate::budget::BudgetWindow;
use crate::error::GatewayError;

/// File name of the proxy configuration in the data directory.
pub const PROXY_CONFIG_FILE: &str = "proxy.json";
/// File name of the token store in the data directory.
pub const PROXY_TOKENS_FILE: &str = "proxy_tokens.db";

/// Where the listener binds unless `proxy.json` says otherwise.
pub const DEFAULT_BIND: &str = "127.0.0.1:18791";

/// The largest request body the listener reads, unless configured.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// How long a forwarded call may go without a byte from the provider,
/// unless configured.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// What every token starts with.
pub const TOKEN_PREFIX: &str = "wkp_";

/// `proxy.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Address the listener binds. Loopback unless
    /// `bind_beyond_loopback` is set as well.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Required for a `bind` that is not a loopback address. The
    /// listener speaks plain HTTP, so a token sent to it from another
    /// host crosses the network in the clear unless something in front
    /// of it terminates TLS.
    #[serde(default)]
    pub bind_beyond_loopback: bool,
    /// The providers calls are forwarded to, by the name tokens are
    /// issued for.
    pub upstreams: BTreeMap<String, Upstream>,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: u64,
    /// How long a forwarded call waits for the provider's next bytes
    /// before it is ended. There is no limit on its length in all.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Where full request and response bodies are written. Absent
    /// means bodies are kept nowhere: the chain holds their hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<ArchiveConfig>,
}

fn default_bind() -> String {
    DEFAULT_BIND.to_string()
}

fn default_max_body() -> u64 {
    DEFAULT_MAX_BODY_BYTES
}

fn default_idle_timeout() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

/// One provider the proxy forwards to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// A provider id, as in `provider.json`.
    pub provider: String,
    pub base_url: String,
    /// The vault entry holding the provider's key. Absent for a
    /// provider that takes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// An S3-compatible bucket with Object Lock that full bodies are
/// written to, encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveConfig {
    /// The bucket's endpoint, `https://host[:port]`. Plain HTTP is
    /// accepted for loopback only.
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// Put before every object key.
    #[serde(default)]
    pub prefix: String,
    /// How long each object is locked for.
    pub retention_days: u32,
    /// `compliance` or `governance`.
    #[serde(default)]
    pub mode: LockMode,
    /// The vault entry holding `access_key_id:secret_access_key`,
    /// granted to the endpoint's host.
    pub credential: String,
    /// The vault entry holding the key that wraps each body's own key.
    #[serde(default = "default_archive_key")]
    pub key: String,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_archive_key() -> String {
    "proxy-archive-key".to_string()
}

/// An Object Lock retention mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    /// No one can shorten or remove the lock.
    #[default]
    Compliance,
    /// A principal with the bypass permission can.
    Governance,
}

impl LockMode {
    /// The value of the `x-amz-object-lock-mode` header.
    pub fn header(self) -> &'static str {
        match self {
            Self::Compliance => "COMPLIANCE",
            Self::Governance => "GOVERNANCE",
        }
    }
}

impl ProxyConfig {
    /// Read `proxy.json` from `data_dir`. `Ok(None)` when there is
    /// none: the listener is off.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, GatewayError> {
        let path = data_dir.join(PROXY_CONFIG_FILE);
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(GatewayError::Config(format!("{}: {e}", path.display())));
            }
        };
        let config: Self = serde_json::from_str(&body)
            .map_err(|e| GatewayError::Config(format!("{}: {e}", path.display())))?;
        config.validate()?;
        Ok(Some(config))
    }

    /// The address to bind, or why the configuration cannot be served.
    pub fn bind_addr(&self) -> Result<SocketAddr, GatewayError> {
        let addr: SocketAddr = self
            .bind
            .parse()
            .map_err(|e| GatewayError::Config(format!("proxy.json: bind {:?}: {e}", self.bind)))?;
        if !addr.ip().is_loopback() && !self.bind_beyond_loopback {
            return Err(GatewayError::Config(format!(
                "proxy.json: bind {addr} is not a loopback address. The listener speaks plain \
                 HTTP; set \"bind_beyond_loopback\": true to bind it anyway"
            )));
        }
        Ok(addr)
    }

    fn validate(&self) -> Result<(), GatewayError> {
        self.bind_addr()?;
        if self.idle_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "proxy.json: idle_timeout_secs must be above zero".into(),
            ));
        }
        if self.upstreams.is_empty() {
            return Err(GatewayError::Config(
                "proxy.json: upstreams is empty: there is nowhere to forward to".into(),
            ));
        }
        for (name, upstream) in &self.upstreams {
            if !is_name(name) {
                return Err(GatewayError::Config(format!(
                    "proxy.json: upstream name {name:?} is not letters, digits, - or _"
                )));
            }
            if upstream.provider.is_empty() || upstream.base_url.is_empty() {
                return Err(GatewayError::Config(format!(
                    "proxy.json: upstream {name} needs a provider and a base_url"
                )));
            }
        }
        if let Some(archive) = &self.archive {
            if archive.retention_days == 0 {
                return Err(GatewayError::Config(
                    "proxy.json: archive.retention_days must be above zero".into(),
                ));
            }
            if archive.bucket.is_empty() || archive.endpoint.is_empty() {
                return Err(GatewayError::Config(
                    "proxy.json: archive needs an endpoint and a bucket".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Letters, digits, `-` and `_`, at least one.
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// One issued token, without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyToken {
    /// Eight hex characters, also the middle part of the token. Names
    /// the token on every row.
    pub id: String,
    pub name: String,
    /// The upstreams the token may reach, in the order they are tried.
    pub upstreams: Vec<String>,
    /// The models it may ask for. Empty allows any.
    pub models: Vec<String>,
    /// Spend ceiling over `window`.
    pub ceiling_usd_micros: Option<u64>,
    /// Call ceiling over `window`.
    pub ceiling_calls: Option<u64>,
    pub window: BudgetWindow,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl ProxyToken {
    /// Whether the token may ask for `model`.
    pub fn allows_model(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|m| m == model)
    }

    /// The ledger key the token's spend is kept under in `budget.db`.
    pub fn budget_key(&self) -> String {
        format!("proxy-token:{}", self.id)
    }
}

/// What a presented token turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenCheck {
    Valid(ProxyToken),
    Revoked(ProxyToken),
    Unknown,
}

/// What a new token is issued with.
#[derive(Debug, Clone, Default)]
pub struct TokenGrant {
    pub name: String,
    pub upstreams: Vec<String>,
    pub models: Vec<String>,
    pub ceiling_usd_micros: Option<u64>,
    pub ceiling_calls: Option<u64>,
    pub window: BudgetWindow,
}

/// The token store.
pub struct ProxyTokenStore {
    conn: Mutex<Connection>,
}

const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Compare two digests without stopping at the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn random_hex(bytes: usize) -> String {
    use rand::Rng;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn split(list: &str) -> Vec<String> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl ProxyTokenStore {
    /// Open or create the store at `db_path`.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS proxy_tokens (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 digest TEXT NOT NULL,
                 upstreams TEXT NOT NULL,
                 models TEXT NOT NULL,
                 ceiling_usd_micros INTEGER,
                 ceiling_calls INTEGER,
                 window TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 revoked_at TEXT
             );
             CREATE TABLE IF NOT EXISTS proxy_token_calls (
                 token_id TEXT NOT NULL,
                 window_start INTEGER NOT NULL,
                 calls INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (token_id, window_start)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Issue a token. Returns its record and the token itself, which
    /// is stored nowhere and cannot be shown again.
    pub fn issue(&self, grant: &TokenGrant) -> Result<(ProxyToken, String), GatewayError> {
        if !is_name(&grant.name) {
            return Err(GatewayError::Config(format!(
                "token name {:?} is not letters, digits, - or _",
                grant.name
            )));
        }
        if grant.upstreams.is_empty() {
            return Err(GatewayError::Config(
                "a token needs at least one upstream".into(),
            ));
        }
        if grant
            .upstreams
            .iter()
            .chain(&grant.models)
            .any(|s| s.is_empty() || s.contains(','))
        {
            return Err(GatewayError::Config(
                "an upstream or model name is empty or contains a comma".into(),
            ));
        }
        let id = random_hex(4);
        let token = format!("{TOKEN_PREFIX}{id}_{}", random_hex(32));
        let created_at = wirken_time::Timestamp::now().to_rfc3339();
        let window = grant.window.label();
        self.conn()
            .execute(
                "INSERT INTO proxy_tokens
                 (id, name, digest, upstreams, models, ceiling_usd_micros, ceiling_calls,
                  window, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    grant.name,
                    digest(&token),
                    grant.upstreams.join(","),
                    grant.models.join(","),
                    grant.ceiling_usd_micros.map(|v| v as i64),
                    grant.ceiling_calls.map(|v| v as i64),
                    window,
                    created_at,
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    GatewayError::Config(format!("a token named {} already exists", grant.name))
                }
                other => other.into(),
            })?;
        Ok((
            ProxyToken {
                id,
                name: grant.name.clone(),
                upstreams: grant.upstreams.clone(),
                models: grant.models.clone(),
                ceiling_usd_micros: grant.ceiling_usd_micros,
                ceiling_calls: grant.ceiling_calls,
                window: grant.window,
                created_at,
                revoked_at: None,
            },
            token,
        ))
    }

    /// Revoke the token with this id or name. Returns it, or `None`
    /// when there is no such token or it was revoked already.
    pub fn revoke(&self, id_or_name: &str) -> Result<Option<ProxyToken>, GatewayError> {
        let conn = self.conn();
        let now = wirken_time::Timestamp::now().to_rfc3339();
        let changed = conn.execute(
            "UPDATE proxy_tokens SET revoked_at = ?1
             WHERE (id = ?2 OR name = ?2) AND revoked_at IS NULL",
            params![now, id_or_name],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Self::read(&conn, "id = ?1 OR name = ?1", id_or_name).map(|t| t.map(|(t, _)| t))
    }

    /// Every token, newest first.
    pub fn list(&self) -> Result<Vec<ProxyToken>, GatewayError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, upstreams, models, ceiling_usd_micros, ceiling_calls, window,
                    created_at, revoked_at, digest
             FROM proxy_tokens ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map([], Self::row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?.0);
        }
        Ok(out)
    }

    /// What `presented` is: a token this store issued, one it issued
    /// and revoked, or neither.
    pub fn check(&self, presented: &str) -> Result<TokenCheck, GatewayError> {
        let Some(id) = presented
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|rest| rest.split_once('_'))
            .map(|(id, _)| id)
        else {
            return Ok(TokenCheck::Unknown);
        };
        let conn = self.conn();
        let Some((token, stored)) = Self::read(&conn, "id = ?1", id)? else {
            return Ok(TokenCheck::Unknown);
        };
        if !same(&stored, &digest(presented)) {
            return Ok(TokenCheck::Unknown);
        }
        Ok(if token.revoked_at.is_some() {
            TokenCheck::Revoked(token)
        } else {
            TokenCheck::Valid(token)
        })
    }

    /// How many calls the token has made in the window starting at
    /// `window_start`.
    pub fn window_calls(&self, token_id: &str, window_start: i64) -> Result<u64, GatewayError> {
        let calls: Option<i64> = self
            .conn()
            .query_row(
                "SELECT calls FROM proxy_token_calls WHERE token_id = ?1 AND window_start = ?2",
                params![token_id, window_start],
                |r| r.get(0),
            )
            .optional()?;
        Ok(calls.unwrap_or(0).max(0) as u64)
    }

    /// Count one call in the window starting at `window_start`.
    pub fn add_call(&self, token_id: &str, window_start: i64) -> Result<(), GatewayError> {
        self.conn().execute(
            "INSERT INTO proxy_token_calls (token_id, window_start, calls) VALUES (?1, ?2, 1)
             ON CONFLICT(token_id, window_start) DO UPDATE SET calls = calls + 1",
            params![token_id, window_start],
        )?;
        Ok(())
    }

    fn read(
        conn: &Connection,
        filter: &str,
        value: &str,
    ) -> Result<Option<(ProxyToken, String)>, GatewayError> {
        Ok(conn
            .query_row(
                &format!(
                    "SELECT id, name, upstreams, models, ceiling_usd_micros, ceiling_calls,
                            window, created_at, revoked_at, digest
                     FROM proxy_tokens WHERE {filter}"
                ),
                params![value],
                Self::row,
            )
            .optional()?)
    }

    fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(ProxyToken, String)> {
        let window: String = r.get(6)?;
        Ok((
            ProxyToken {
                id: r.get(0)?,
                name: r.get(1)?,
                upstreams: split(&r.get::<_, String>(2)?),
                models: split(&r.get::<_, String>(3)?),
                ceiling_usd_micros: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
                ceiling_calls: r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
                window: match window.as_str() {
                    "hour" => BudgetWindow::Hour,
                    "week" => BudgetWindow::Week,
                    _ => BudgetWindow::Day,
                },
                created_at: r.get(7)?,
                revoked_at: r.get(8)?,
            },
            r.get(9)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ProxyTokenStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = ProxyTokenStore::open(&tmp.path().join(PROXY_TOKENS_FILE)).unwrap();
        (tmp, store)
    }

    fn grant(name: &str) -> TokenGrant {
        TokenGrant {
            name: name.into(),
            upstreams: vec!["local".into(), "cloud".into()],
            models: vec!["m1".into()],
            ceiling_usd_micros: Some(5_000_000),
            ceiling_calls: Some(10),
            window: BudgetWindow::Hour,
        }
    }

    /// An issued token checks as valid with what it was issued for, a
    /// revoked one as revoked, and anything else as unknown. The store
    /// holds a digest and not the token.
    #[test]
    fn a_token_is_valid_until_revoked_and_its_value_is_not_stored() {
        let (tmp, store) = store();
        let (issued, token) = store.issue(&grant("laptop")).unwrap();
        assert!(token.starts_with(&format!("{TOKEN_PREFIX}{}_", issued.id)));
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 8 + 1 + 64);

        let TokenCheck::Valid(found) = store.check(&token).unwrap() else {
            panic!("an issued token is not valid");
        };
        assert_eq!(found, issued);
        assert_eq!(found.upstreams, ["local", "cloud"]);
        assert!(found.allows_model("m1") && !found.allows_model("m2"));
        assert_eq!(found.window, BudgetWindow::Hour);

        // Same id, another secret; no prefix; another id.
        let forged = format!("{TOKEN_PREFIX}{}_{}", issued.id, "0".repeat(64));
        for other in [forged.as_str(), "sk-something", "wkp_deadbeef_00", ""] {
            assert_eq!(store.check(other).unwrap(), TokenCheck::Unknown, "{other}");
        }

        for file in std::fs::read_dir(tmp.path()).unwrap().flatten() {
            let bytes = std::fs::read(file.path()).unwrap();
            let secret = token.rsplit('_').next().unwrap().as_bytes();
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret),
                "{} holds the token",
                file.path().display()
            );
        }

        let revoked = store.revoke("laptop").unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
        assert!(matches!(
            store.check(&token).unwrap(),
            TokenCheck::Revoked(t) if t.id == issued.id
        ));
        assert_eq!(store.revoke("laptop").unwrap(), None);
        assert_eq!(store.revoke("nobody").unwrap(), None);
    }

    #[test]
    fn a_token_with_no_model_list_allows_any_model() {
        let (_tmp, store) = store();
        let (token, _) = store
            .issue(&TokenGrant {
                models: vec![],
                ..grant("any")
            })
            .unwrap();
        assert!(token.allows_model("whatever"));
    }

    #[test]
    fn a_grant_that_names_nothing_or_repeats_a_name_is_refused() {
        let (_tmp, store) = store();
        store.issue(&grant("a")).unwrap();
        assert!(store.issue(&grant("a")).is_err());
        assert!(store.issue(&grant("bad name")).is_err());
        assert!(
            store
                .issue(&TokenGrant {
                    upstreams: vec![],
                    ..grant("b")
                })
                .is_err()
        );
        assert!(
            store
                .issue(&TokenGrant {
                    models: vec!["a,b".into()],
                    ..grant("c")
                })
                .is_err()
        );
    }

    #[test]
    fn calls_are_counted_per_window() {
        let (_tmp, store) = store();
        assert_eq!(store.window_calls("t", 100).unwrap(), 0);
        store.add_call("t", 100).unwrap();
        store.add_call("t", 100).unwrap();
        store.add_call("t", 200).unwrap();
        assert_eq!(store.window_calls("t", 100).unwrap(), 2);
        assert_eq!(store.window_calls("t", 200).unwrap(), 1);
        assert_eq!(store.window_calls("other", 100).unwrap(), 0);
    }

    fn write(dir: &Path, body: &str) {
        std::fs::write(dir.join(PROXY_CONFIG_FILE), body).unwrap();
    }

    #[test]
    fn no_file_means_the_listener_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(ProxyConfig::load(tmp.path()).unwrap(), None);
    }

    /// The listener binds loopback unless the file names another
    /// address and says so twice.
    #[test]
    fn a_bind_beyond_loopback_needs_its_own_setting() {
        let tmp = tempfile::tempdir().unwrap();
        let upstreams =
            r#""upstreams":{"local":{"provider":"ollama","base_url":"http://localhost:11434/v1"}}"#;
        write(tmp.path(), &format!("{{{upstreams}}}"));
        let config = ProxyConfig::load(tmp.path()).unwrap().unwrap();
        assert_eq!(config.bind_addr().unwrap().to_string(), DEFAULT_BIND);
        assert_eq!(config.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(config.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
        assert!(config.archive.is_none());

        write(
            tmp.path(),
            &format!(r#"{{"bind":"0.0.0.0:9000",{upstreams}}}"#),
        );
        let err = ProxyConfig::load(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("not a loopback address"), "{err}");

        write(
            tmp.path(),
            &format!(r#"{{"bind":"0.0.0.0:9000","bind_beyond_loopback":true,{upstreams}}}"#),
        );
        let config = ProxyConfig::load(tmp.path()).unwrap().unwrap();
        assert_eq!(config.bind_addr().unwrap().to_string(), "0.0.0.0:9000");
    }

    #[test]
    fn a_file_that_cannot_be_served_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        for (body, says) in [
            (r#"{"upstreams":{}}"#, "upstreams is empty"),
            (
                r#"{"idle_timeout_secs":0,"upstreams":{"a":{"provider":"ollama","base_url":"http://localhost/v1"}}}"#,
                "idle_timeout_secs",
            ),
            (
                r#"{"upstreams":{"a b":{"provider":"ollama","base_url":"http://localhost/v1"}}}"#,
                "upstream name",
            ),
            (
                r#"{"upstreams":{"a":{"provider":"","base_url":"http://localhost/v1"}}}"#,
                "needs a provider",
            ),
            (
                r#"{"upstreams":{"a":{"provider":"ollama","base_url":"http://localhost/v1"}},"extra":1}"#,
                "unknown field",
            ),
            (
                r#"{"upstreams":{"a":{"provider":"ollama","base_url":"http://localhost/v1"}},
                    "archive":{"endpoint":"https://s3.example.com","bucket":"b","retention_days":0,"credential":"c"}}"#,
                "retention_days",
            ),
        ] {
            write(tmp.path(), body);
            let err = ProxyConfig::load(tmp.path()).unwrap_err().to_string();
            assert!(err.contains(says), "{err} does not say {says}");
        }
    }

    #[test]
    fn an_archive_block_reads_with_its_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            r#"{"upstreams":{"a":{"provider":"anthropic","base_url":"https://api.anthropic.com/v1","credential":"anthropic-api-key"}},
                "archive":{"endpoint":"https://s3.example.com","bucket":"b","retention_days":30,"credential":"proxy-archive-credentials"}}"#,
        );
        let archive = ProxyConfig::load(tmp.path())
            .unwrap()
            .unwrap()
            .archive
            .unwrap();
        assert_eq!(archive.mode, LockMode::Compliance);
        assert_eq!(archive.mode.header(), "COMPLIANCE");
        assert_eq!(archive.region, "us-east-1");
        assert_eq!(archive.key, "proxy-archive-key");
        assert_eq!(archive.prefix, "");
    }
}
