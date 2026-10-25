//! Webchat credentials.
//!
//! - Session token: per gateway start, in `webchat.json` (0600), sent as a
//!   bearer by non-browser callers.
//! - Login token: one-time, in-memory, valid for [`LOGIN_TOKEN_TTL`];
//!   exchanged at `/login` for a cookie.
//! - Cookie: per login, with a public label used as the approval actor.
//!
//! Secrets are stored as SHA-256 digests and compared in constant time.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Port and session token, under the data dir.
pub const LOGIN_FILE: &str = "webchat.json";

/// Login cookie name.
pub const COOKIE: &str = "wirken_webchat";

/// Login token lifetime.
pub const LOGIN_TOKEN_TTL: Duration = Duration::from_secs(60);

/// Max outstanding login tokens.
const MAX_LOGIN_TOKENS: usize = 16;

/// Max browser sessions.
const MAX_SESSIONS: usize = 32;

type Digest32 = [u8; 32];

fn digest(secret: &str) -> Digest32 {
    Sha256::digest(secret.as_bytes()).into()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(buf.as_mut_slice());
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A logged-in browser.
    Session { label: String },
    /// A session-token bearer.
    Bearer,
}

impl Caller {
    /// Approval actor id.
    pub fn actor(&self) -> String {
        match self {
            Self::Session { label } => format!("webchat:{label}"),
            Self::Bearer => "webchat:bearer".to_string(),
        }
    }
}

struct Session {
    cookie: Digest32,
    label: String,
}

#[derive(Default)]
struct State {
    logins: VecDeque<(Digest32, Instant)>,
    sessions: VecDeque<Session>,
}

/// Credentials for one gateway start.
pub struct WebchatAuth {
    token: String,
    token_digest: Digest32,
    state: Mutex<State>,
}

impl WebchatAuth {
    pub fn generate() -> Self {
        Self::with_token(random_hex(32))
    }

    /// With a fixed session token.
    pub fn with_token(token: String) -> Self {
        Self {
            token_digest: digest(&token),
            token,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write `webchat.json` atomically at mode 0600.
    pub fn write_file(&self, data_dir: &Path, port: u16) -> std::io::Result<PathBuf> {
        let path = data_dir.join(LOGIN_FILE);
        let tmp = data_dir.join(format!(".{LOGIN_FILE}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let body = serde_json::json!({ "port": port, "token": self.token }).to_string();
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp)?;
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// Mint a one-time login token.
    pub fn mint_login(&self, now: Instant) -> String {
        let login = random_hex(32);
        let mut state = self.state();
        state
            .logins
            .retain(|(_, minted)| now.duration_since(*minted) < LOGIN_TOKEN_TTL);
        if state.logins.len() >= MAX_LOGIN_TOKENS {
            state.logins.pop_front();
        }
        state.logins.push_back((digest(&login), now));
        login
    }

    /// Redeem a login token; returns `(cookie, label)`. The token is
    /// consumed either way.
    pub fn redeem_login(&self, presented: &str, now: Instant) -> Option<(String, String)> {
        let presented = digest(presented);
        let mut state = self.state();
        let mut found = None;
        for (i, (stored, _)) in state.logins.iter().enumerate() {
            if bool::from(stored.ct_eq(&presented)) {
                found = Some(i);
            }
        }
        let (_, minted) = state.logins.remove(found?)?;
        if now.duration_since(minted) >= LOGIN_TOKEN_TTL {
            return None;
        }
        let cookie = random_hex(32);
        let label = random_hex(4);
        if state.sessions.len() >= MAX_SESSIONS {
            state.sessions.pop_front();
        }
        state.sessions.push_back(Session {
            cookie: digest(&cookie),
            label: label.clone(),
        });
        Some((cookie, label))
    }

    /// The caller named by the cookie or bearer header, if valid.
    pub fn authenticate(&self, raw_request: &str) -> Option<Caller> {
        if let Some(bearer) = bearer_token(raw_request)
            && bool::from(digest(bearer).ct_eq(&self.token_digest))
        {
            return Some(Caller::Bearer);
        }
        let presented = digest(&cookie_value(raw_request, COOKIE)?);
        let state = self.state();
        let mut label = None;
        for session in &state.sessions {
            if bool::from(session.cookie.ct_eq(&presented)) {
                label = Some(session.label.clone());
            }
        }
        label.map(|label| Caller::Session { label })
    }

    /// Whether the request carries the session token as a bearer.
    pub fn is_bearer(&self, raw_request: &str) -> bool {
        matches!(self.authenticate(raw_request), Some(Caller::Bearer))
    }
}

fn header_lines(raw: &str) -> impl Iterator<Item = &str> {
    raw.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
}

fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    header_lines(raw).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn bearer_token(raw: &str) -> Option<&str> {
    let value = header(raw, "authorization")?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

fn cookie_value(raw: &str, name: &str) -> Option<String> {
    header_lines(raw)
        .filter_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case("cookie").then_some(v)
        })
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
}

/// Read `webchat.json`.
pub fn read_file(data_dir: &Path) -> anyhow::Result<(u16, String)> {
    use anyhow::Context;
    let path = data_dir.join(LOGIN_FILE);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {}: is `wirken run` running for this data dir?",
            path.display()
        )
    })?;
    let v: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let port = v["port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .with_context(|| format!("{} has no port", path.display()))?;
    let token = v["token"]
        .as_str()
        .with_context(|| format!("{} has no token", path.display()))?
        .to_string();
    Ok((port, token))
}

/// `wirken webchat open`: mint a login token and print the login URL.
pub async fn open(browser: bool) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cfg = super::config();
    let (port, token) = read_file(&cfg.data_dir)?;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .with_context(|| format!("connect to webchat on 127.0.0.1:{port}"))?;
    let request = format!(
        "POST /api/login-tokens HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let response = String::from_utf8_lossy(&response);
    let status = response.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        bail!(
            "the gateway refused a login token (HTTP {status}); the token in {} may be from \
             an earlier start",
            cfg.data_dir.join(LOGIN_FILE).display()
        );
    }
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    let login = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["login_token"].as_str().map(str::to_string))
        .context("the gateway's answer carried no login token")?;
    let url = format!("http://127.0.0.1:{port}/login?token={login}");
    println!("{url}");
    println!(
        "Open it within {} seconds. It works once; run this again for another.",
        LOGIN_TOKEN_TTL.as_secs()
    );
    if browser && open::that(&url).is_err() {
        eprintln!("Could not open a browser; open the URL above yourself.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> WebchatAuth {
        WebchatAuth::with_token("t0ken".repeat(13))
    }

    fn get(headers: &str) -> String {
        format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:1\r\n{headers}\r\n\r\n")
    }

    #[test]
    fn a_login_token_is_redeemed_once() {
        let a = auth();
        let t0 = Instant::now();
        let login = a.mint_login(t0);
        let (cookie, label) = a.redeem_login(&login, t0).expect("first use");
        assert_eq!(cookie.len(), 64);
        assert_eq!(label.len(), 8);
        assert!(a.redeem_login(&login, t0).is_none(), "second use refused");
    }

    #[test]
    fn an_expired_login_token_is_refused_and_discarded() {
        let a = auth();
        let t0 = Instant::now();
        let login = a.mint_login(t0);
        assert!(a.redeem_login(&login, t0 + LOGIN_TOKEN_TTL).is_none());
        assert!(
            a.redeem_login(&login, t0).is_none(),
            "gone after the attempt"
        );
    }

    #[test]
    fn the_session_token_is_not_a_login_token() {
        let a = auth();
        let t0 = Instant::now();
        let _ = a.mint_login(t0);
        assert!(a.redeem_login(&"t0ken".repeat(13), t0).is_none());
    }

    #[test]
    fn a_cookie_from_a_login_authenticates_with_its_label() {
        let a = auth();
        let t0 = Instant::now();
        let (cookie, label) = a.redeem_login(&a.mint_login(t0), t0).unwrap();
        assert_eq!(
            a.authenticate(&get(&format!("Cookie: other=1; {COOKIE}={cookie}"))),
            Some(Caller::Session {
                label: label.clone()
            })
        );
        assert_eq!(
            Caller::Session {
                label: label.clone()
            }
            .actor(),
            format!("webchat:{label}")
        );
        assert_eq!(
            a.authenticate(&get(&format!("Cookie: {COOKIE}=00{cookie}"))),
            None
        );
    }

    #[test]
    fn the_bearer_is_the_session_token_only() {
        let a = auth();
        let token = "t0ken".repeat(13);
        assert_eq!(
            a.authenticate(&get(&format!("Authorization: Bearer {token}"))),
            Some(Caller::Bearer)
        );
        assert_eq!(
            a.authenticate(&get(&format!("authorization: bearer {token}"))),
            Some(Caller::Bearer)
        );
        assert_eq!(a.authenticate(&get("Authorization: Bearer wrong")), None);
        assert_eq!(
            a.authenticate(&get(&format!("Authorization: Basic {token}"))),
            None
        );
        assert_eq!(
            a.authenticate(&get(&format!("Cookie: {COOKIE}={token}"))),
            None
        );
        assert_eq!(a.authenticate(&get("")), None);
    }

    #[test]
    fn a_header_in_the_body_is_not_a_header() {
        let a = auth();
        let token = "t0ken".repeat(13);
        let raw = format!(
            "POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\nAuthorization: Bearer {token}"
        );
        assert_eq!(a.authenticate(&raw), None);
    }

    #[test]
    fn sessions_are_bounded() {
        let a = auth();
        let t0 = Instant::now();
        let (first, _) = a.redeem_login(&a.mint_login(t0), t0).unwrap();
        for _ in 0..MAX_SESSIONS {
            a.redeem_login(&a.mint_login(t0), t0).unwrap();
        }
        assert_eq!(
            a.authenticate(&get(&format!("Cookie: {COOKIE}={first}"))),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_0600_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let a = auth();
        let path = a.write_file(dir.path(), 18790).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        a.write_file(dir.path(), 18791).unwrap();
        assert_eq!(read_file(dir.path()).unwrap(), (18791, "t0ken".repeat(13)));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
