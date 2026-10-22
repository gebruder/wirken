//! Fetching release files with curl.
//!
//! Nothing here is trusted: the manifest verifies against the compiled-in
//! release keys and the artifact must match the sha256 the signed
//! manifest carries, so the transport can be any HTTPS client. curl is
//! that client, the same one `install.sh` uses. From GitHub every hop is
//! HTTPS (`--proto =https --proto-redir =https`), since a release download
//! redirects once to the asset host. A mirror is fetched as named and may
//! not redirect at all, so with a mirror set nothing is sent anywhere else.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use url::Url;

const REPO: &str = "gebruder/wirken";
const MAX_REDIRECTS: u32 = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where release files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    GitHub,
    /// A base URL laid out as `<base>/releases.json`,
    /// `<base>/releases.json.sig` and `<base>/v<version>/<artifact>`.
    Mirror(Url),
}

impl Source {
    /// The source for an update: `base_url` when given, which must be
    /// on a loopback address or be the mirror configured in
    /// `update.json`; otherwise the configured mirror; otherwise GitHub.
    pub fn choose(base_url: Option<&str>, configured_mirror: Option<&str>) -> Result<Self> {
        let configured = configured_mirror
            .map(|m| parse_base(m).with_context(|| format!("update.json mirror {m:?}")))
            .transpose()?;
        match base_url {
            Some(raw) => {
                let url = parse_base(raw)?;
                if is_loopback(&url) || configured.as_ref() == Some(&url) {
                    Ok(Source::Mirror(url))
                } else {
                    bail!(
                        "--base-url {raw} is neither on a loopback address nor the mirror \
                         configured in update.json; set it there to use a local mirror"
                    )
                }
            }
            None => Ok(configured.map_or(Source::GitHub, Source::Mirror)),
        }
    }

    pub fn manifest_url(&self) -> Url {
        self.url_for("releases.json")
    }

    pub fn signature_url(&self) -> Url {
        self.url_for("releases.json.sig")
    }

    fn url_for(&self, name: &str) -> Url {
        match self {
            Source::GitHub => Url::parse(&format!(
                "https://github.com/{REPO}/releases/latest/download/{name}"
            ))
            .expect("static url"),
            Source::Mirror(base) => base.join(name).expect("joined to a base url"),
        }
    }

    pub fn artifact_url(&self, version: &str, artifact: &str) -> Url {
        match self {
            Source::GitHub => Url::parse(&format!(
                "https://github.com/{REPO}/releases/download/v{version}/{artifact}"
            ))
            .expect("static url"),
            Source::Mirror(base) => base
                .join(&format!("v{version}/{artifact}"))
                .expect("joined to a base url"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Source::GitHub => format!("github.com/{REPO}"),
            Source::Mirror(base) => format!("mirror {base}"),
        }
    }

    /// The curl arguments that pin this source's transport: GitHub is
    /// HTTPS on every hop and follows the one redirect its downloads
    /// make; a mirror is http or https as named and may not redirect.
    fn transport_args(&self) -> Vec<String> {
        match self {
            Source::GitHub => vec![
                "--location".into(),
                "--max-redirs".into(),
                MAX_REDIRECTS.to_string(),
                "--proto".into(),
                "=https".into(),
                "--proto-redir".into(),
                "=https".into(),
            ],
            Source::Mirror(_) => vec![
                "--location".into(),
                "--max-redirs".into(),
                "0".into(),
                "--proto".into(),
                "=http,https".into(),
            ],
        }
    }
}

/// A base URL, normalised to end in `/` so names join beneath it.
fn parse_base(raw: &str) -> Result<Url> {
    let mut url = Url::parse(raw).with_context(|| format!("{raw:?} is not a URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("{raw:?} is not an http or https URL with a host");
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
        bail!("{raw:?} carries credentials or a query; give a plain base URL");
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

/// Whether a fetch shows curl's progress bar on the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Errors only, captured into the failure message.
    Silent,
    /// curl's progress bar on stderr, for a download worth watching.
    Bar,
}

/// Fetches release files from one [`Source`].
pub struct Fetcher {
    source: Source,
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

impl Fetcher {
    pub fn new(source: Source) -> Self {
        Fetcher { source }
    }

    pub fn source(&self) -> &Source {
        &self.source
    }

    /// GET `url` with curl and return at most `max_bytes` of body.
    pub async fn get(
        &self,
        url: Url,
        max_bytes: usize,
        timeout: Duration,
        progress: Progress,
    ) -> Result<Vec<u8>> {
        let scratch = scratch_path();
        tracing::debug!(
            url = %url,
            max_bytes,
            timeout_secs = timeout.as_secs(),
            "update: fetching"
        );
        let result = self
            .run_curl(&url, max_bytes, timeout, progress, &scratch)
            .await;
        let read = match &result {
            Ok(()) => {
                std::fs::read(&scratch).with_context(|| format!("read {}", scratch.display()))
            }
            Err(_) => Ok(Vec::new()),
        };
        let _ = std::fs::remove_file(&scratch);
        result?;
        let body = read?;
        if body.len() > max_bytes {
            bail!("{url} is larger than {max_bytes} bytes");
        }
        tracing::debug!(url = %url, bytes = body.len(), "update: fetched");
        Ok(body)
    }

    async fn run_curl(
        &self,
        url: &Url,
        max_bytes: usize,
        timeout: Duration,
        progress: Progress,
        scratch: &PathBuf,
    ) -> Result<()> {
        let mut cmd = tokio::process::Command::new("curl");
        cmd.args(["--fail", "--show-error"])
            .arg("--connect-timeout")
            .arg(CONNECT_TIMEOUT.as_secs().to_string())
            .arg("--max-time")
            .arg(timeout.as_secs().max(1).to_string())
            .arg("--max-filesize")
            .arg(max_bytes.to_string())
            .arg("--user-agent")
            .arg(format!(
                "wirken/{} (+https://github.com/{REPO})",
                crate::build_info::VERSION
            ))
            .args(self.source.transport_args())
            .arg("--output")
            .arg(scratch)
            .arg(url.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        match progress {
            Progress::Silent => cmd.arg("--silent").stderr(Stdio::piped()),
            Progress::Bar => cmd.arg("--progress-bar").stderr(Stdio::inherit()),
        };
        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("curl is not installed; wirken update downloads with curl")
            } else {
                anyhow::anyhow!("run curl: {e}")
            }
        })?;
        if output.status.success() {
            return Ok(());
        }
        let code = output.status.code();
        let said = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if said.is_empty() {
            match code {
                Some(c) => format!("curl exited with status {c}"),
                None => "curl was killed by a signal".to_string(),
            }
        } else {
            said
        };
        // 63 is curl's "maximum file size exceeded"; 47 its redirect limit.
        match code {
            Some(63) => bail!("{url} is larger than {max_bytes} bytes"),
            Some(47) => bail!("{url} redirected, and this source may not redirect ({detail})"),
            _ => bail!("fetch {url}: {detail}"),
        }
    }
}

/// A scratch file for one download, unique to this process and call.
fn scratch_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "wirken-update-{}-{}",
        std::process::id(),
        SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A one-file-per-path HTTP server on loopback that records every
    /// request line it receives.
    pub(crate) struct TestServer {
        pub base: String,
        pub requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// One served path: (path, status, extra headers, body).
    pub(crate) type Route = (String, u16, Vec<(String, String)>, Vec<u8>);

    /// Serve `routes`.
    pub(crate) async fn serve(routes: Vec<Route>) -> TestServer {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                loop {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&got)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push(line.clone());
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, headers, body) = routes
                    .iter()
                    .find(|(p, ..)| *p == path)
                    .map(|(_, s, h, b)| (*s, h.clone(), b.clone()))
                    .unwrap_or((404, vec![], b"not found".to_vec()));
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            }
        });
        TestServer { base, requests }
    }

    async fn get(fetcher: &Fetcher, url: &str) -> Result<Vec<u8>> {
        fetcher
            .get(
                Url::parse(url).unwrap(),
                1024,
                Duration::from_secs(5),
                Progress::Silent,
            )
            .await
    }

    #[test]
    fn a_base_url_must_be_loopback_or_the_configured_mirror() {
        assert!(matches!(
            Source::choose(Some("http://127.0.0.1:8080/wirken"), None).unwrap(),
            Source::Mirror(u) if u.as_str() == "http://127.0.0.1:8080/wirken/"
        ));
        assert!(Source::choose(Some("http://[::1]:9/"), None).is_ok());
        assert!(Source::choose(Some("http://localhost/"), None).is_ok());
        assert!(Source::choose(Some("https://mirror.lan/wirken/"), None).is_err());
        assert!(
            Source::choose(
                Some("https://mirror.lan/wirken/"),
                Some("https://mirror.lan/wirken")
            )
            .is_ok()
        );
        assert!(
            Source::choose(
                Some("https://other.lan/"),
                Some("https://mirror.lan/wirken")
            )
            .is_err()
        );
        assert!(Source::choose(Some("file:///tmp/x"), None).is_err());
        assert!(Source::choose(Some("http://user:pw@127.0.0.1/"), None).is_err());
        assert_eq!(Source::choose(None, None).unwrap(), Source::GitHub);
        assert!(matches!(
            Source::choose(None, Some("https://mirror.lan/w")).unwrap(),
            Source::Mirror(_)
        ));
    }

    #[test]
    fn github_urls_are_the_release_download_paths() {
        let s = Source::GitHub;
        assert_eq!(
            s.manifest_url().as_str(),
            "https://github.com/gebruder/wirken/releases/latest/download/releases.json"
        );
        assert_eq!(
            s.artifact_url("2.3.0", "wirken-x86_64-unknown-linux-musl")
                .as_str(),
            "https://github.com/gebruder/wirken/releases/download/v2.3.0/wirken-x86_64-unknown-linux-musl"
        );
        let m = Source::choose(Some("http://127.0.0.1:9/w"), None).unwrap();
        assert_eq!(
            m.artifact_url("2.3.0", "wirken-x").as_str(),
            "http://127.0.0.1:9/w/v2.3.0/wirken-x"
        );
    }

    #[tokio::test]
    async fn a_mirror_is_fetched_as_named_and_may_not_redirect() {
        let server = serve(vec![
            ("/releases.json".into(), 200, vec![], b"{}".to_vec()),
            (
                "/to-github".into(),
                302,
                vec![(
                    "Location".into(),
                    "https://github.com/gebruder/wirken/releases/latest/download/releases.json"
                        .into(),
                )],
                vec![],
            ),
        ])
        .await;
        let source = Source::choose(Some(&server.base), None).unwrap();
        let fetcher = Fetcher::new(source.clone());
        let body = get(&fetcher, source.manifest_url().as_str()).await.unwrap();
        assert_eq!(body, b"{}");

        let redirected = get(&fetcher, &format!("{}to-github", server.base))
            .await
            .unwrap_err();
        assert!(
            format!("{redirected:#}").contains("may not redirect"),
            "{redirected:#}"
        );

        // The redirect target was never requested: the mirror saw its
        // own two paths and nothing else left the process.
        assert_eq!(
            *server.requests.lock().unwrap(),
            vec![
                "GET /releases.json HTTP/1.1".to_string(),
                "GET /to-github HTTP/1.1".to_string()
            ]
        );
    }

    /// The GitHub source is HTTPS only, so a plain http URL is refused by
    /// curl before any request is made.
    #[tokio::test]
    async fn the_github_source_refuses_http() {
        let server = serve(vec![("/x".into(), 200, vec![], b"x".to_vec())]).await;
        let fetcher = Fetcher::new(Source::GitHub);
        let err = get(&fetcher, &format!("{}x", server.base))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("fetch http://"), "{err:#}");
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_oversize_body_is_refused() {
        let server = serve(vec![("/big".into(), 200, vec![], vec![b'x'; 4096])]).await;
        let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
        let err = get(&fetcher, &format!("{}big", server.base))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("larger than"), "{err:#}");
    }

    #[tokio::test]
    async fn an_http_error_names_the_status() {
        let server = serve(vec![]).await;
        let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
        let err = get(&fetcher, &format!("{}missing", server.base))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("404"), "{err:#}");
    }
}
