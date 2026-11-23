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

/// How long the proxy remembers where a conversation stood, to
/// recognise the request that continues it: thirty days.
pub const CONVERSATION_MEMORY_SECS: i64 = 30 * 86_400;

/// What every token starts with.
pub const TOKEN_PREFIX: &str = "wkp_";

/// `proxy.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Address the listener binds. A loopback address, unless `tls` is
    /// set or `bind_beyond_loopback` is.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// The certificate and key the listener serves TLS with. Without
    /// it the listener speaks plain HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    /// Allows a `bind` that is not a loopback address with no `tls`:
    /// tokens, requests and answers then cross the network in the
    /// clear unless something in front of the listener terminates TLS.
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
    /// The identity provider whose JWTs a client may present in place
    /// of a token. Absent means only tokens issued here are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcConfig>,
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

/// The listener's TLS identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// A PEM file holding the certificate, followed by any
    /// intermediates.
    pub certificate: String,
    /// A PEM file holding the certificate's private key.
    pub private_key: String,
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

/// The identity provider whose JWTs the listener verifies. Wirken
/// issues none of them: it checks the signature against the issuer's
/// keys and the claims against what is set here, and gives the caller
/// the grant set the operator mapped it to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The issuer, exactly as it is in a JWT's `iss`: `https://...`.
    /// Plain HTTP is accepted for loopback only.
    pub issuer: String,
    /// The audience a JWT must name in its `aud`.
    pub audience: String,
    /// A file holding the issuer's keys as a JWK set, read once at
    /// start. With it the issuer is never asked for keys. Without it
    /// they are fetched from the issuer's discovery document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_file: Option<String>,
    /// The claim whose value selects a grant set: a string, or a list
    /// of strings. Without it, and for a JWT whose value selects none,
    /// the subject does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_claim: Option<String>,
    /// The longest a JWT is accepted after its `iat`, whatever its
    /// `exp` says. What a grant taken away at the identity provider
    /// outlives is at most this.
    pub max_token_lifetime_secs: u64,
    /// How far the issuer's clock may be from this host's.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,
    /// How long fetched keys are used before they are fetched again.
    #[serde(default = "default_jwks_cache")]
    pub jwks_cache_secs: u64,
    /// The signature algorithms accepted. Empty accepts each of
    /// [`crate::proxy_identity::ALGORITHMS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub algorithms: Vec<String>,
    /// Record the subject on each row as the issuer gave it. Without
    /// it a row carries a keyed hash of the subject.
    #[serde(default)]
    pub record_subject: bool,
    /// The vault entry holding the key subjects are hashed under.
    #[serde(default = "default_subject_key")]
    pub subject_key: String,
}

fn default_clock_skew() -> u64 {
    60
}

fn default_jwks_cache() -> u64 {
    3600
}

fn default_subject_key() -> String {
    "proxy-subject-key".to_string()
}

/// The most `clock_skew_secs` may be.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

impl OidcConfig {
    /// Whether `alg` is an algorithm this configuration accepts.
    pub fn accepts(&self, alg: &str) -> bool {
        crate::proxy_identity::ALGORITHMS.contains(&alg)
            && (self.algorithms.is_empty() || self.algorithms.iter().any(|a| a == alg))
    }

    /// [`Self::validate`]'s verdict, as its message.
    #[cfg(test)]
    pub(crate) fn validate_for_test(&self) -> Result<(), String> {
        self.validate().map_err(|e| e.to_string())
    }

    fn validate(&self) -> Result<(), GatewayError> {
        let bad = |why: String| Err(GatewayError::Config(format!("proxy.json: oidc: {why}")));
        let url = match reqwest::Url::parse(&self.issuer) {
            Ok(url) => url,
            Err(e) => return bad(format!("issuer {:?}: {e}", self.issuer)),
        };
        let loopback = url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" && !loopback {
            return bad(format!(
                "issuer {} is not https; plain http is accepted for loopback only",
                self.issuer
            ));
        }
        if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
            return bad(format!(
                "issuer {} carries a query, a fragment or credentials",
                self.issuer
            ));
        }
        if self.audience.is_empty() {
            return bad("audience is empty".into());
        }
        if self.max_token_lifetime_secs == 0 {
            return bad("max_token_lifetime_secs must be above zero".into());
        }
        if self.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return bad(format!("clock_skew_secs is above {MAX_CLOCK_SKEW_SECS}"));
        }
        if self.jwks_cache_secs == 0 {
            return bad("jwks_cache_secs must be above zero".into());
        }
        for alg in &self.algorithms {
            if !crate::proxy_identity::ALGORITHMS.contains(&alg.as_str()) {
                return bad(format!(
                    "algorithm {alg:?} is not accepted. A JWT is verified with a public key: \
                     one of {}",
                    crate::proxy_identity::ALGORITHMS.join(", ")
                ));
            }
        }
        if self.grant_claim.as_deref() == Some("") {
            return bad("grant_claim is empty".into());
        }
        if self.jwks_file.as_deref() == Some("") {
            return bad("jwks_file is empty".into());
        }
        if !is_name(&self.subject_key) {
            return bad(format!(
                "subject_key {:?} is not letters, digits, - or _",
                self.subject_key
            ));
        }
        Ok(())
    }
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
        if !addr.ip().is_loopback() && self.tls.is_none() && !self.bind_beyond_loopback {
            return Err(GatewayError::Config(format!(
                "proxy.json: bind {addr} is not a loopback address and there is no tls block, \
                 so tokens and conversations would cross the network in the clear. Add \
                 \"tls\" with a certificate and key, or set \"bind_beyond_loopback\": true to \
                 bind it in the clear anyway"
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
        if let Some(oidc) = &self.oidc {
            oidc.validate()?;
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
    /// The agent whose MCP servers the token may be granted, and under
    /// whose gate its tool calls run. Empty when it has no MCP grant.
    pub mcp_agent: String,
    /// The MCP servers of that agent whose tools the token may list
    /// and call.
    pub mcp_servers: Vec<String>,
    /// Who the caller is, when it presented a JWT and not a token:
    /// the record is then the grant set its mapping selected, under
    /// the id of its subject. `None` for a token issued here.
    pub identity: Option<wirken_audit::ProxyIdentity>,
}

impl ProxyToken {
    /// Whether the token may ask for `model`.
    pub fn allows_model(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|m| m == model)
    }

    /// The ledger key the token's spend is kept under in `budget.db`.
    /// A JWT's caller has its own, by subject: a ceiling of a grant
    /// set is each subject's, not shared among them.
    pub fn budget_key(&self) -> String {
        self.principal()
    }

    /// Who the caller is on a row that names a sender:
    /// `proxy-token:<id>`, or `proxy-subject:<id>` for a JWT's caller.
    pub fn principal(&self) -> String {
        match self.identity {
            None => format!("proxy-token:{}", self.id),
            Some(_) => format!("proxy-subject:{}", self.id),
        }
    }

    /// What the grants are held by, for a message: `token <name>`, or
    /// `grant set <name>` for a JWT's caller.
    pub fn held_by(&self) -> String {
        match self.identity {
            None => format!("token {}", self.name),
            Some(_) => format!("grant set {}", self.name),
        }
    }
}

/// A named set of grants a JWT's caller is given: what a token carries,
/// with no secret of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSet {
    pub name: String,
    pub upstreams: Vec<String>,
    pub models: Vec<String>,
    pub ceiling_usd_micros: Option<u64>,
    pub ceiling_calls: Option<u64>,
    pub window: BudgetWindow,
    pub mcp_agent: String,
    pub mcp_servers: Vec<String>,
    pub created_at: String,
}

impl GrantSet {
    /// The record a call is made under by the subject whose id is
    /// `id`: this grant set's grants, counted and charged to that
    /// subject.
    pub fn caller(&self, id: String, identity: wirken_audit::ProxyIdentity) -> ProxyToken {
        ProxyToken {
            id,
            name: self.name.clone(),
            upstreams: self.upstreams.clone(),
            models: self.models.clone(),
            ceiling_usd_micros: self.ceiling_usd_micros,
            ceiling_calls: self.ceiling_calls,
            window: self.window,
            created_at: self.created_at.clone(),
            revoked_at: None,
            mcp_agent: self.mcp_agent.clone(),
            mcp_servers: self.mcp_servers.clone(),
            identity: Some(identity),
        }
    }
}

/// What a mapping matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    /// A value of the configured grant claim.
    Claim,
    /// The JWT's subject.
    Subject,
}

impl MappingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Subject => "subject",
        }
    }
}

/// One line of the operator's mapping: a JWT of `issuer` whose grant
/// claim holds `value`, or whose subject is `value`, gets `grant_set`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMapping {
    pub issuer: String,
    pub kind: MappingKind,
    pub value: String,
    pub grant_set: String,
    pub created_at: String,
}

/// What the mapping gives a verified JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    One(GrantSet),
    /// No mapping matches: the caller gets nothing.
    None,
    /// Mappings match that name different grant sets, listed. The
    /// caller is refused: nothing here says which it should have.
    Several(Vec<String>),
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
    /// The agent whose MCP servers are granted. Needed with
    /// `mcp_servers`.
    pub mcp_agent: String,
    pub mcp_servers: Vec<String>,
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

const GRANT_SET_COLUMNS: &str = "SELECT name, upstreams, models, ceiling_usd_micros, \
     ceiling_calls, window, created_at, mcp_agent, mcp_servers FROM proxy_grant_sets";

fn window_of(label: &str) -> BudgetWindow {
    match label {
        "hour" => BudgetWindow::Hour,
        "week" => BudgetWindow::Week,
        _ => BudgetWindow::Day,
    }
}

/// Whether `grant` can be written as a `what` (a token, a grant set).
/// Returns the agent its MCP servers belong to, empty when it has
/// none.
fn check_grant(grant: &TokenGrant, what: &str) -> Result<String, GatewayError> {
    if !is_name(&grant.name) {
        return Err(GatewayError::Config(format!(
            "{what} name {:?} is not letters, digits, - or _",
            grant.name
        )));
    }
    if grant.upstreams.is_empty() && grant.mcp_servers.is_empty() {
        return Err(GatewayError::Config(format!(
            "a {what} needs at least one upstream or one MCP server"
        )));
    }
    if grant
        .upstreams
        .iter()
        .chain(&grant.models)
        .chain(&grant.mcp_servers)
        .any(|s| s.is_empty() || s.contains(','))
    {
        return Err(GatewayError::Config(
            "an upstream, model or MCP server name is empty or contains a comma".into(),
        ));
    }
    if !grant.mcp_servers.is_empty() && !is_name(&grant.mcp_agent) {
        return Err(GatewayError::Config(format!(
            "a {what} with MCP servers names the agent they belong to"
        )));
    }
    Ok(if grant.mcp_servers.is_empty() {
        String::new()
    } else {
        grant.mcp_agent.clone()
    })
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
             CREATE TABLE IF NOT EXISTS proxy_conversations (
                 token_id TEXT NOT NULL,
                 tail TEXT NOT NULL,
                 conversation TEXT NOT NULL,
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (token_id, tail)
             );
             CREATE TABLE IF NOT EXISTS proxy_grant_sets (
                 name TEXT PRIMARY KEY,
                 upstreams TEXT NOT NULL,
                 models TEXT NOT NULL,
                 ceiling_usd_micros INTEGER,
                 ceiling_calls INTEGER,
                 window TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 mcp_agent TEXT NOT NULL DEFAULT '',
                 mcp_servers TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS proxy_identity_mappings (
                 issuer TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 value TEXT NOT NULL,
                 grant_set TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 PRIMARY KEY (issuer, kind, value)
             );
             CREATE TABLE IF NOT EXISTS proxy_token_calls (
                 token_id TEXT NOT NULL,
                 window_start INTEGER NOT NULL,
                 calls INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (token_id, window_start)
             );",
        )?;
        // Columns a store made before tokens carried an MCP grant lacks.
        for column in ["mcp_agent", "mcp_servers"] {
            let has: bool = conn.query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('proxy_tokens') WHERE name = ?1",
                params![column],
                |r| r.get(0),
            )?;
            if !has {
                conn.execute_batch(&format!(
                    "ALTER TABLE proxy_tokens ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
                ))?;
            }
        }
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
        let mcp_agent = check_grant(grant, "token")?;
        let id = random_hex(4);
        let token = format!("{TOKEN_PREFIX}{id}_{}", random_hex(32));
        let created_at = wirken_time::Timestamp::now().to_rfc3339();
        let window = grant.window.label();
        self.conn()
            .execute(
                "INSERT INTO proxy_tokens
                 (id, name, digest, upstreams, models, ceiling_usd_micros, ceiling_calls,
                  window, created_at, mcp_agent, mcp_servers)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    mcp_agent,
                    grant.mcp_servers.join(","),
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
                mcp_agent,
                mcp_servers: grant.mcp_servers.clone(),
                identity: None,
            },
            token,
        ))
    }

    /// Write the grant set `grant` describes, in place of any of the
    /// same name. Returns it, and the one it replaced.
    pub fn set_grant_set(
        &self,
        grant: &TokenGrant,
    ) -> Result<(GrantSet, Option<GrantSet>), GatewayError> {
        let mcp_agent = check_grant(grant, "grant set")?;
        let conn = self.conn();
        let previous = Self::read_grant_set(&conn, &grant.name)?;
        let created_at = wirken_time::Timestamp::now().to_rfc3339();
        conn.execute(
            "INSERT INTO proxy_grant_sets
             (name, upstreams, models, ceiling_usd_micros, ceiling_calls, window,
              created_at, mcp_agent, mcp_servers)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(name) DO UPDATE SET
                 upstreams = ?2, models = ?3, ceiling_usd_micros = ?4, ceiling_calls = ?5,
                 window = ?6, created_at = ?7, mcp_agent = ?8, mcp_servers = ?9",
            params![
                grant.name,
                grant.upstreams.join(","),
                grant.models.join(","),
                grant.ceiling_usd_micros.map(|v| v as i64),
                grant.ceiling_calls.map(|v| v as i64),
                grant.window.label(),
                created_at,
                mcp_agent,
                grant.mcp_servers.join(","),
            ],
        )?;
        let written = Self::read_grant_set(&conn, &grant.name)?
            .ok_or_else(|| GatewayError::Config("the grant set was not written".into()))?;
        Ok((written, previous))
    }

    /// Put back the grant set `previous`, or remove `name` when there
    /// was none: what undoes a [`Self::set_grant_set`] whose row could
    /// not be recorded.
    pub fn restore_grant_set(
        &self,
        name: &str,
        previous: Option<&GrantSet>,
    ) -> Result<(), GatewayError> {
        let conn = self.conn();
        match previous {
            None => {
                conn.execute(
                    "DELETE FROM proxy_grant_sets WHERE name = ?1",
                    params![name],
                )?;
            }
            Some(p) => {
                conn.execute(
                    "UPDATE proxy_grant_sets SET
                         upstreams = ?2, models = ?3, ceiling_usd_micros = ?4,
                         ceiling_calls = ?5, window = ?6, created_at = ?7, mcp_agent = ?8,
                         mcp_servers = ?9
                     WHERE name = ?1",
                    params![
                        p.name,
                        p.upstreams.join(","),
                        p.models.join(","),
                        p.ceiling_usd_micros.map(|v| v as i64),
                        p.ceiling_calls.map(|v| v as i64),
                        p.window.label(),
                        p.created_at,
                        p.mcp_agent,
                        p.mcp_servers.join(","),
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Remove the grant set `name`. Refused while a mapping names it:
    /// a mapping to nothing would read as a grant and give none.
    /// Returns the grant set, or `None` when there is none.
    pub fn remove_grant_set(&self, name: &str) -> Result<Option<GrantSet>, GatewayError> {
        let conn = self.conn();
        let Some(set) = Self::read_grant_set(&conn, name)? else {
            return Ok(None);
        };
        let mapped: i64 = conn.query_row(
            "SELECT count(*) FROM proxy_identity_mappings WHERE grant_set = ?1",
            params![name],
            |r| r.get(0),
        )?;
        if mapped > 0 {
            return Err(GatewayError::Config(format!(
                "{mapped} mapping(s) name the grant set {name}; remove them first"
            )));
        }
        conn.execute(
            "DELETE FROM proxy_grant_sets WHERE name = ?1",
            params![name],
        )?;
        Ok(Some(set))
    }

    /// Every grant set, by name.
    pub fn grant_sets(&self) -> Result<Vec<GrantSet>, GatewayError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("{GRANT_SET_COLUMNS} ORDER BY name"))?;
        let rows = stmt.query_map([], Self::grant_set_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Map JWTs of `issuer` matching `value` to `grant_set`, in place
    /// of any mapping of the same value. Returns the grant set the
    /// value was mapped to before.
    pub fn map_identity(
        &self,
        issuer: &str,
        kind: MappingKind,
        value: &str,
        grant_set: &str,
    ) -> Result<Option<String>, GatewayError> {
        if value.is_empty() || value.len() > crate::proxy_identity::MAX_CLAIM_BYTES {
            return Err(GatewayError::Config(format!(
                "a mapped value is 1 to {} bytes",
                crate::proxy_identity::MAX_CLAIM_BYTES
            )));
        }
        let conn = self.conn();
        if Self::read_grant_set(&conn, grant_set)?.is_none() {
            return Err(GatewayError::Config(format!(
                "there is no grant set named {grant_set}"
            )));
        }
        let previous = Self::read_mapping(&conn, issuer, kind, value)?;
        conn.execute(
            "INSERT INTO proxy_identity_mappings (issuer, kind, value, grant_set, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(issuer, kind, value) DO UPDATE SET grant_set = ?4, created_at = ?5",
            params![
                issuer,
                kind.as_str(),
                value,
                grant_set,
                wirken_time::Timestamp::now().to_rfc3339()
            ],
        )?;
        Ok(previous)
    }

    /// Remove the mapping of `value`. Returns the grant set it named,
    /// or `None` when there was no such mapping.
    pub fn unmap_identity(
        &self,
        issuer: &str,
        kind: MappingKind,
        value: &str,
    ) -> Result<Option<String>, GatewayError> {
        let conn = self.conn();
        let previous = Self::read_mapping(&conn, issuer, kind, value)?;
        conn.execute(
            "DELETE FROM proxy_identity_mappings WHERE issuer = ?1 AND kind = ?2 AND value = ?3",
            params![issuer, kind.as_str(), value],
        )?;
        Ok(previous)
    }

    /// Every mapping, by issuer, kind and value.
    pub fn identity_mappings(&self) -> Result<Vec<IdentityMapping>, GatewayError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT issuer, kind, value, grant_set, created_at FROM proxy_identity_mappings
             ORDER BY issuer, kind, value",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(IdentityMapping {
                issuer: r.get(0)?,
                kind: match r.get::<_, String>(1)?.as_str() {
                    "subject" => MappingKind::Subject,
                    _ => MappingKind::Claim,
                },
                value: r.get(2)?,
                grant_set: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// The grant set the mapping gives a verified JWT of `issuer`
    /// whose grant claim holds `claim_values` and whose subject is
    /// `subject`.
    ///
    /// The claim selects. Where none of its values is mapped, the
    /// subject does. Values mapped to one grant set select it once;
    /// values mapped to different grant sets select none of them.
    pub fn select_grant_set(
        &self,
        issuer: &str,
        claim_values: &[String],
        subject: &str,
    ) -> Result<Selection, GatewayError> {
        let conn = self.conn();
        let mut names: Vec<String> = Vec::new();
        for value in claim_values {
            if let Some(name) = Self::read_mapping(&conn, issuer, MappingKind::Claim, value)?
                && !names.contains(&name)
            {
                names.push(name);
            }
        }
        if names.is_empty()
            && let Some(name) = Self::read_mapping(&conn, issuer, MappingKind::Subject, subject)?
        {
            names.push(name);
        }
        match names.as_slice() {
            [] => Ok(Selection::None),
            [name] => Ok(match Self::read_grant_set(&conn, name)? {
                Some(set) => Selection::One(set),
                // The grant set is gone from under its mapping.
                None => Selection::None,
            }),
            _ => {
                names.sort();
                Ok(Selection::Several(names))
            }
        }
    }

    fn read_mapping(
        conn: &Connection,
        issuer: &str,
        kind: MappingKind,
        value: &str,
    ) -> Result<Option<String>, GatewayError> {
        Ok(conn
            .query_row(
                "SELECT grant_set FROM proxy_identity_mappings
                 WHERE issuer = ?1 AND kind = ?2 AND value = ?3",
                params![issuer, kind.as_str(), value],
                |r| r.get(0),
            )
            .optional()?)
    }

    fn read_grant_set(conn: &Connection, name: &str) -> Result<Option<GrantSet>, GatewayError> {
        Ok(conn
            .query_row(
                &format!("{GRANT_SET_COLUMNS} WHERE name = ?1"),
                params![name],
                Self::grant_set_row,
            )
            .optional()?)
    }

    fn grant_set_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<GrantSet> {
        Ok(GrantSet {
            name: r.get(0)?,
            upstreams: split(&r.get::<_, String>(1)?),
            models: split(&r.get::<_, String>(2)?),
            ceiling_usd_micros: r.get::<_, Option<i64>>(3)?.map(|v| v.max(0) as u64),
            ceiling_calls: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
            window: window_of(&r.get::<_, String>(5)?),
            created_at: r.get(6)?,
            mcp_agent: r.get(7)?,
            mcp_servers: split(&r.get::<_, String>(8)?),
        })
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
                    created_at, revoked_at, digest, mcp_agent, mcp_servers
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

    /// The conversation a request belongs to, by the hash of each
    /// prefix of its messages (`chain`, shortest first). A request
    /// that extends one this token made before, at any point of it,
    /// continues that conversation; any other starts a new one. The
    /// request's own last hash is remembered for the requests after
    /// it. What is kept is hashes, for [`CONVERSATION_MEMORY_SECS`].
    pub fn conversation(&self, token_id: &str, chain: &[String]) -> Result<String, GatewayError> {
        let now = crate::budget::now_unix_secs();
        let conn = self.conn();
        // Hashes past their time are forgotten before this request is
        // matched against what is kept.
        conn.execute(
            "DELETE FROM proxy_conversations WHERE updated_at < ?1",
            params![now - CONVERSATION_MEMORY_SECS],
        )?;
        let mut found: Option<String> = None;
        // The longest prefix an earlier request ended on.
        for tail in chain.iter().rev() {
            found = conn
                .query_row(
                    "SELECT conversation FROM proxy_conversations
                     WHERE token_id = ?1 AND tail = ?2",
                    params![token_id, tail],
                    |r| r.get(0),
                )
                .optional()?;
            if found.is_some() {
                break;
            }
        }
        let conversation = found.unwrap_or_else(|| format!("c{}", random_hex(6)));
        if let Some(tail) = chain.last() {
            conn.execute(
                "INSERT INTO proxy_conversations (token_id, tail, conversation, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(token_id, tail) DO UPDATE SET updated_at = ?4",
                params![token_id, tail, conversation, now],
            )?;
        }
        Ok(conversation)
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
                            window, created_at, revoked_at, digest, mcp_agent, mcp_servers
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
                window: window_of(&window),
                created_at: r.get(7)?,
                revoked_at: r.get(8)?,
                mcp_agent: r.get(10)?,
                mcp_servers: split(&r.get::<_, String>(11)?),
                identity: None,
            },
            r.get(9)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hash of a request's message list is kept for thirty days. A
    /// request that extends one older than that starts a new
    /// conversation.
    #[test]
    fn a_conversation_is_remembered_for_thirty_days() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(PROXY_TOKENS_FILE);
        let store = ProxyTokenStore::open(&path).unwrap();
        let first = store.conversation("0a0a0a0a", &["h1".to_string()]).unwrap();
        let chain = ["h1".to_string(), "h2".to_string()];
        assert_eq!(store.conversation("0a0a0a0a", &chain).unwrap(), first);

        // The same history, last seen thirty-one days ago.
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE proxy_conversations SET updated_at = updated_at - ?1",
                params![CONVERSATION_MEMORY_SECS + 86_400],
            )
            .unwrap();
        let chain = ["h1".to_string(), "h2".to_string(), "h3".to_string()];
        assert_ne!(store.conversation("0a0a0a0a", &chain).unwrap(), first);
    }

    #[test]
    fn a_token_carries_its_mcp_grant_and_an_older_store_gains_the_columns() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(PROXY_TOKENS_FILE);
        // A store as it was before tokens carried an MCP grant.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE proxy_tokens (
                     id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, digest TEXT NOT NULL,
                     upstreams TEXT NOT NULL, models TEXT NOT NULL,
                     ceiling_usd_micros INTEGER, ceiling_calls INTEGER,
                     window TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
                 INSERT INTO proxy_tokens VALUES
                     ('0a0a0a0a', 'old', 'x', 'local', '', NULL, NULL, 'day', 't', NULL);",
            )
            .unwrap();
        }
        let store = ProxyTokenStore::open(&path).unwrap();
        let old = &store.list().unwrap()[0];
        assert_eq!((old.mcp_agent.as_str(), old.mcp_servers.len()), ("", 0));

        let (token, value) = store
            .issue(&TokenGrant {
                name: "tools".into(),
                mcp_agent: "default".into(),
                mcp_servers: vec!["files".into(), "notes".into()],
                ..Default::default()
            })
            .unwrap();
        assert!(token.upstreams.is_empty());
        let TokenCheck::Valid(read) = store.check(&value).unwrap() else {
            panic!("the token is valid");
        };
        assert_eq!(read.mcp_agent, "default");
        assert_eq!(read.mcp_servers, vec!["files", "notes"]);

        // Servers with no agent, and nothing at all, are refused.
        assert!(
            store
                .issue(&TokenGrant {
                    name: "no-agent".into(),
                    mcp_servers: vec!["files".into()],
                    ..Default::default()
                })
                .is_err()
        );
        assert!(
            store
                .issue(&TokenGrant {
                    name: "nothing".into(),
                    ..Default::default()
                })
                .is_err()
        );
    }

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
            ..Default::default()
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

    /// A request that extends an earlier one of the same token is the
    /// same conversation, at whichever point it picks up. An unrelated
    /// one, one with no messages, and the same messages under another
    /// token are each their own.
    #[test]
    fn a_request_that_extends_an_earlier_one_continues_its_conversation() {
        let (_tmp, store) = store();
        let chain = |tails: &[&str]| tails.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        let first = store.conversation("tok", &chain(&["h1"])).unwrap();
        assert!(first.starts_with('c') && first.len() == 13, "{first}");
        // The next turn: the first request's messages, then more.
        let second = store
            .conversation("tok", &chain(&["h1", "h2", "h3"]))
            .unwrap();
        assert_eq!(second, first);
        let third = store
            .conversation("tok", &chain(&["h1", "h2", "h3", "h4", "h5"]))
            .unwrap();
        assert_eq!(third, first);
        // A second branch from the first turn is the same conversation.
        assert_eq!(
            store.conversation("tok", &chain(&["h1", "x2"])).unwrap(),
            first
        );

        let unrelated = store.conversation("tok", &chain(&["g1", "g2"])).unwrap();
        assert_ne!(unrelated, first);
        assert_eq!(
            store
                .conversation("tok", &chain(&["g1", "g2", "g3"]))
                .unwrap(),
            unrelated
        );
        // A request that only shares a start with one, without
        // reaching where any request ended, is not a continuation.
        assert_ne!(
            store.conversation("tok", &chain(&["g1"])).unwrap(),
            unrelated
        );

        assert_ne!(store.conversation("other", &chain(&["h1"])).unwrap(), first);
        let (empty_a, empty_b) = (
            store.conversation("tok", &[]).unwrap(),
            store.conversation("tok", &[]).unwrap(),
        );
        assert_ne!(empty_a, empty_b);
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

    fn grant_to(name: &str, upstream: &str) -> TokenGrant {
        TokenGrant {
            name: name.into(),
            upstreams: vec![upstream.into()],
            ..Default::default()
        }
    }

    /// The claim selects the grant set and the subject is the
    /// fallback; a JWT no mapping matches gets nothing, and one whose
    /// values name two grant sets is given neither.
    #[test]
    fn a_mapping_selects_one_grant_set_or_none() {
        const ISSUER: &str = "https://idp.example.com";
        let tmp = tempfile::tempdir().unwrap();
        let store = ProxyTokenStore::open(&tmp.path().join(PROXY_TOKENS_FILE)).unwrap();
        store
            .set_grant_set(&grant_to("engineers", "local"))
            .unwrap();
        store.set_grant_set(&grant_to("oncall", "cloud")).unwrap();
        store
            .set_grant_set(&grant_to("alice-own", "cloud"))
            .unwrap();
        let map = |kind, value: &str, set: &str| store.map_identity(ISSUER, kind, value, set);
        assert_eq!(map(MappingKind::Claim, "eng", "engineers").unwrap(), None);
        map(MappingKind::Claim, "eng-leads", "engineers").unwrap();
        map(MappingKind::Claim, "sre", "oncall").unwrap();
        map(MappingKind::Subject, "alice", "alice-own").unwrap();

        let select = |values: &[&str], subject: &str| {
            let values: Vec<String> = values.iter().map(|v| v.to_string()).collect();
            match store.select_grant_set(ISSUER, &values, subject).unwrap() {
                Selection::One(set) => set.name,
                Selection::None => "none".into(),
                Selection::Several(names) => format!("several: {}", names.join(",")),
            }
        };
        assert_eq!(select(&["eng"], "bob"), "engineers");
        // A value with no mapping beside one with: the mapped one.
        assert_eq!(select(&["visitors", "sre"], "bob"), "oncall");
        // Two values, one grant set: no question which.
        assert_eq!(select(&["eng", "eng-leads"], "bob"), "engineers");
        // Two values, two grant sets.
        assert_eq!(select(&["eng", "sre"], "bob"), "several: engineers,oncall");
        // No value mapped: the subject, where it is mapped.
        assert_eq!(select(&["visitors"], "alice"), "alice-own");
        assert_eq!(select(&[], "alice"), "alice-own");
        assert_eq!(select(&["visitors"], "bob"), "none");
        assert_eq!(select(&[], "bob"), "none");
        // The claim selects, and the subject is not asked.
        assert_eq!(select(&["eng"], "alice"), "engineers");
        // A subject is not a claim value, nor the other way round.
        assert_eq!(select(&["alice"], "eng"), "none");
        // Another issuer's JWTs match nothing written for this one.
        let other = store
            .select_grant_set("https://other.example", &["eng".to_string()], "alice")
            .unwrap();
        assert_eq!(other, Selection::None);

        // A mapping is replaced, and says what it replaced.
        assert_eq!(
            map(MappingKind::Claim, "sre", "engineers").unwrap(),
            Some("oncall".into())
        );
        assert_eq!(select(&["eng", "sre"], "bob"), "engineers");
        assert_eq!(
            store
                .unmap_identity(ISSUER, MappingKind::Claim, "sre")
                .unwrap(),
            Some("engineers".into())
        );
        assert_eq!(
            store
                .unmap_identity(ISSUER, MappingKind::Claim, "sre")
                .unwrap(),
            None
        );
        assert_eq!(select(&["sre"], "bob"), "none");

        // A mapping names a grant set that exists, and a grant set a
        // mapping names is not removed from under it.
        assert!(map(MappingKind::Claim, "x", "nowhere").is_err());
        let err = store.remove_grant_set("engineers").unwrap_err().to_string();
        assert!(err.contains("2 mapping(s)"), "{err}");
        assert_eq!(
            store.remove_grant_set("oncall").unwrap().unwrap().name,
            "oncall"
        );
        assert_eq!(store.remove_grant_set("oncall").unwrap(), None);
        assert_eq!(store.identity_mappings().unwrap().len(), 3);
    }

    /// A grant set is what a token carries; a subject's calls under it
    /// are that subject's, by id, ledger key and sender.
    #[test]
    fn a_grant_set_is_held_per_subject() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ProxyTokenStore::open(&tmp.path().join(PROXY_TOKENS_FILE)).unwrap();
        let wanted = TokenGrant {
            name: "engineers".into(),
            upstreams: vec!["local".into()],
            models: vec!["m".into()],
            ceiling_calls: Some(5),
            mcp_agent: "default".into(),
            mcp_servers: vec!["files".into()],
            ..Default::default()
        };
        let (set, previous) = store.set_grant_set(&wanted).unwrap();
        assert!(previous.is_none());
        assert_eq!(store.grant_sets().unwrap(), vec![set.clone()]);
        // Written again, it replaces and says what it replaced.
        let (changed, previous) = store
            .set_grant_set(&TokenGrant {
                ceiling_calls: Some(9),
                ..wanted.clone()
            })
            .unwrap();
        assert_eq!(previous.as_ref(), Some(&set));
        assert_eq!(changed.ceiling_calls, Some(9));
        store
            .restore_grant_set("engineers", previous.as_ref())
            .unwrap();
        assert_eq!(store.grant_sets().unwrap()[0].ceiling_calls, Some(5));
        assert!(store.set_grant_set(&TokenGrant::default()).is_err());

        let identity = |hash: &str| wirken_audit::ProxyIdentity {
            issuer: "https://idp.example.com".into(),
            grant_set: Some("engineers".into()),
            jti: None,
            subject_hash: Some(hash.into()),
            subject: None,
        };
        let alice = set.caller("u1111111111111111".into(), identity("11"));
        let bob = set.caller("u2222222222222222".into(), identity("22"));
        assert_eq!(alice.budget_key(), "proxy-subject:u1111111111111111");
        assert_ne!(alice.budget_key(), bob.budget_key());
        assert_eq!(alice.held_by(), "grant set engineers");
        assert_eq!((alice.ceiling_calls, alice.mcp_servers.len()), (Some(5), 1));
        assert!(alice.allows_model("m") && !alice.allows_model("other"));

        let (token, _) = store.issue(&grant_to("laptop", "local")).unwrap();
        assert_eq!(token.budget_key(), format!("proxy-token:{}", token.id));
        assert_eq!(token.held_by(), "token laptop");
        assert!(token.identity.is_none());
    }

    /// The `oidc` block: off unless written, an https issuer or a
    /// loopback one, a maximum lifetime the operator states, and no
    /// algorithm that is not a public-key one.
    #[test]
    fn the_oidc_block_is_held_to_its_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let load = |oidc: serde_json::Value| {
            let mut config = serde_json::json!({
                "upstreams": {"local": {"provider": "ollama", "base_url": "http://localhost:1/v1"}},
            });
            if !oidc.is_null() {
                config["oidc"] = oidc;
            }
            write(tmp.path(), &config.to_string());
            ProxyConfig::load(tmp.path()).map(|c| c.unwrap().oidc)
        };
        assert_eq!(load(serde_json::Value::Null).unwrap(), None);

        let good = serde_json::json!({
            "issuer": "https://idp.example.com/realms/acme",
            "audience": "wirken-proxy",
            "max_token_lifetime_secs": 900,
        });
        let oidc = load(good.clone()).unwrap().unwrap();
        assert_eq!(
            (
                oidc.clock_skew_secs,
                oidc.jwks_cache_secs,
                oidc.record_subject
            ),
            (60, 3600, false)
        );
        assert_eq!(oidc.subject_key, "proxy-subject-key");
        assert!(oidc.jwks_file.is_none() && oidc.grant_claim.is_none());
        assert!(oidc.accepts("RS256") && oidc.accepts("EdDSA"));
        assert!(!oidc.accepts("HS256") && !oidc.accepts("none"));

        let with = |name: &str, value: serde_json::Value| {
            let mut oidc = good.clone();
            oidc[name] = value;
            load(oidc).map(|_| ()).map_err(|e| e.to_string())
        };
        assert!(with("issuer", "http://127.0.0.1:8080/realms/acme".into()).is_ok());
        for (name, value, why) in [
            ("issuer", "http://idp.example.com".into(), "not https"),
            ("issuer", "http://localhost.example.com".into(), "not https"),
            ("issuer", "https://idp.example.com/?a=1".into(), "query"),
            (
                "issuer",
                "https://u:p@idp.example.com".into(),
                "credentials",
            ),
            ("audience", "".into(), "audience is empty"),
            ("max_token_lifetime_secs", 0.into(), "above zero"),
            ("clock_skew_secs", 301.into(), "above 300"),
            ("jwks_cache_secs", 0.into(), "above zero"),
            (
                "algorithms",
                serde_json::json!(["RS256", "HS256"]),
                "is not accepted",
            ),
            ("grant_claim", "".into(), "grant_claim is empty"),
            ("subject_key", "a b".into(), "subject_key"),
            (
                "jwks_uri",
                "https://idp.example.com/keys".into(),
                "unknown field",
            ),
        ] {
            let err = with(name, value).unwrap_err();
            assert!(err.contains(why), "{name}: {err}");
        }
        // The maximum lifetime has no default: it is the operator's
        // statement of how long a withdrawn grant lasts.
        let mut no_lifetime = good.clone();
        no_lifetime
            .as_object_mut()
            .unwrap()
            .remove("max_token_lifetime_secs");
        let err = load(no_lifetime).unwrap_err().to_string();
        assert!(err.contains("max_token_lifetime_secs"), "{err}");
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

        // With TLS the address needs no second setting.
        write(
            tmp.path(),
            &format!(
                r#"{{"bind":"0.0.0.0:9000","tls":{{"certificate":"/c.pem","private_key":"/k.pem"}},{upstreams}}}"#
            ),
        );
        let config = ProxyConfig::load(tmp.path()).unwrap().unwrap();
        assert_eq!(config.bind_addr().unwrap().to_string(), "0.0.0.0:9000");
        assert_eq!(config.tls.unwrap().private_key, "/k.pem");
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
