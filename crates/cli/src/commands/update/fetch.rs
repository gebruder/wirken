//! Fetching release files through Wirken's egress client.
//!
//! Every request goes through [`EgressClient::request`], which checks
//! the host against an allowlist before any connection and does not
//! follow redirects. Redirects are followed here, one hop at a time,
//! each hop checked again: for GitHub the allowlist is `github.com`
//! and the host its release downloads redirect to; for a mirror it is
//! the mirror's host alone, so with a mirror set nothing goes to
//! GitHub.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use url::Url;
use wirken_agent::egress::{EgressClient, EgressEnforcement};

const REPO: &str = "gebruder/wirken";
/// Hosts a GitHub release download touches: the release URL and the
/// asset host it redirects to.
pub const GITHUB_HOSTS: &[&str] = &["github.com", "release-assets.githubusercontent.com"];
const MAX_REDIRECTS: usize = 5;

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

    fn hosts(&self) -> Vec<String> {
        match self {
            Source::GitHub => GITHUB_HOSTS.iter().map(|h| h.to_string()).collect(),
            Source::Mirror(base) => vec![base.host_str().unwrap_or_default().to_string()],
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

    pub fn describe(&self) -> String {
        match self {
            Source::GitHub => format!("github.com/{REPO}"),
            Source::Mirror(base) => format!("mirror {base}"),
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

/// Fetches release files from one [`Source`] and nowhere else.
pub struct Fetcher {
    client: EgressClient,
    source: Source,
}

impl Fetcher {
    pub fn new(source: Source) -> Self {
        let client = EgressClient::new();
        client.set_enforcement(EgressEnforcement::Allowlist(
            source.hosts().into_iter().collect(),
        ));
        Fetcher { client, source }
    }

    pub fn source(&self) -> &Source {
        &self.source
    }

    /// GET `url`, following redirects that stay within the allowlist,
    /// and return at most `max_bytes` of body. GitHub is HTTPS only,
    /// and no redirect may move from HTTPS to HTTP.
    pub async fn get(&self, url: Url, max_bytes: usize, timeout: Duration) -> Result<Vec<u8>> {
        let mut url = url;
        for _ in 0..=MAX_REDIRECTS {
            self.check_scheme(&url)?;
            let resp = self
                .client
                .request(reqwest::Method::GET, url.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("refused {url}: {e}"))?
                .timeout(timeout)
                .send()
                .await
                .with_context(|| format!("fetch {url}"))?;
            let status = resp.status();
            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .with_context(|| format!("{url} redirected without a location"))?;
                let next = url
                    .join(location)
                    .with_context(|| format!("{url} redirected to {location:?}"))?;
                if url.scheme() == "https" && next.scheme() != "https" {
                    bail!("{url} redirected from https to {next}");
                }
                url = next;
                continue;
            }
            if !status.is_success() {
                bail!("{url}: {status}");
            }
            if resp.content_length().is_some_and(|n| n > max_bytes as u64) {
                bail!("{url} is larger than {max_bytes} bytes");
            }
            let mut body = Vec::new();
            let mut resp = resp;
            while let Some(chunk) = resp.chunk().await.with_context(|| format!("read {url}"))? {
                if body.len() + chunk.len() > max_bytes {
                    bail!("{url} is larger than {max_bytes} bytes");
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(body);
        }
        bail!(
            "more than {MAX_REDIRECTS} redirects fetching from {}",
            self.source.describe()
        )
    }

    fn check_scheme(&self, url: &Url) -> Result<()> {
        match (&self.source, url.scheme()) {
            (_, "https") => Ok(()),
            (Source::Mirror(_), "http") => Ok(()),
            _ => bail!("{url} is not https"),
        }
    }
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
    }

    /// With a mirror, the fetcher reaches the mirror and refuses
    /// GitHub outright, whether asked directly or redirected there.
    #[tokio::test]
    async fn a_mirror_sends_nothing_to_github() {
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
        let body = fetcher
            .get(source.manifest_url(), 1024, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(body, b"{}");

        let direct = fetcher
            .get(
                Url::parse(
                    "https://github.com/gebruder/wirken/releases/latest/download/releases.json",
                )
                .unwrap(),
                1024,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(format!("{direct:#}").contains("refused"), "{direct:#}");

        let redirected = fetcher
            .get(
                Url::parse(&format!("{}to-github", server.base)).unwrap(),
                1024,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            format!("{redirected:#}").contains("refused"),
            "{redirected:#}"
        );

        // Every request the mirror saw was its own path; the refused
        // ones never left the process.
        assert_eq!(
            *server.requests.lock().unwrap(),
            vec![
                "GET /releases.json HTTP/1.1".to_string(),
                "GET /to-github HTTP/1.1".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn an_oversize_body_is_refused() {
        let server = serve(vec![("/big".into(), 200, vec![], vec![b'x'; 4096])]).await;
        let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
        let err = fetcher
            .get(
                Url::parse(&format!("{}big", server.base)).unwrap(),
                1024,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("larger than"), "{err:#}");
    }
}
