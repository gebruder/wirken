//! Fetcher trait + RSS/Atom implementation.
//!
//! ## The `Fetcher` trait
//!
//! C-foundation deferred this trait deliberately — one implementation
//! couldn't tell us what the abstraction should look like. C-API
//! brings two more (Federal Register JSON, api.data.gov-keyed JSON
//! for congress.gov + govinfo.gov), and three real consumers stake
//! the shape: each takes an [`EgressClient`] and a [`SourceConfig`],
//! produces a `Vec<FetchedItem>`, lets the orchestrator dispatch by
//! the manifest's `method` field via [`FetcherRegistry`].
//!
//! Auth lives outside the trait. Source manifest entries name a
//! vault credential by string (added in piece 3); fetchers that
//! need it resolve the secret at fetch time via their own injected
//! handle. Keeps the trait clean of secret material and avoids
//! pre-committing an `Auth` enum shape before the second auth-using
//! consumer exists.
//!
//! ## RSS / Atom
//!
//! `feed-rs` parses both RSS 2.0 and Atom into a unified `Feed`
//! type. [`RssFetcher`] wraps it; the parser surface ([`parse_feed`])
//! stays module-level so tests exercise the parser without a server.
//!
//! ## Failure modes
//!
//! - HTTP-level denial (egress / rate limit) → [`FetchError::Denied`].
//! - Network error → [`FetchError::Network`].
//! - Non-success HTTP status → [`FetchError::HttpStatus`].
//! - Parse error → [`FetchError::Parse`]. Best-effort recovery is
//!   not attempted — a malformed feed gets logged and skipped at
//!   the orchestrator level.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use wirken_agent::egress::{EgressClient, HttpAccessDenied};

/// Per-source configuration the orchestrator hands to a [`Fetcher`].
/// Mirrors the on-disk `sources.toml` shape (no secrets — auth
/// material is resolved separately at fetch time by fetchers that
/// need it).
#[derive(Debug, Clone)]
pub struct SourceConfig {
    pub name: String,
    pub endpoint: String,
}

/// One pluggable fetcher. The orchestrator dispatches by the
/// manifest's `method` string via [`FetcherRegistry`]; each impl
/// produces normalised [`FetchedItem`]s through the policed
/// [`EgressClient`].
///
/// Synchronous-trait via [`async_trait::async_trait`] — fetchers do
/// I/O, so the simplification of an `async fn` in the trait is
/// load-bearing.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Primary method identifier (e.g. `"rss"`, `"json-federal-register"`).
    /// Aliases (e.g. `"atom-api"` mapping to the RSS impl) are configured
    /// at registration; this is the canonical name used in tracing.
    fn method(&self) -> &'static str;

    /// Documented per-host daily request budget for the API this
    /// fetcher calls.
    ///
    /// `None` means "use the polite Aaron-Swartz-shaped default" —
    /// today 2/day, the unauthenticated-scraping floor. It does
    /// **not** mean "no rate limit": every host always passes
    /// through [`wirken_agent::rate_limit::RateLimitedClient`]; the
    /// only question is what number gets used.
    ///
    /// Authenticated APIs return `Some(n)` matching their published
    /// quota; the orchestrator merges these into
    /// [`wirken_agent::rate_limit::RateLimitConfig::per_host_overrides`]
    /// at startup so each source's host gets its declared budget
    /// without a per-source TOML override. Encoding the opinion at
    /// the fetcher level keeps the per-API knowledge with the code
    /// that knows the API.
    fn default_rate_limit_per_day(&self) -> Option<u32> {
        None
    }

    async fn fetch(
        &self,
        http: &EgressClient,
        source: &SourceConfig,
    ) -> Result<Vec<FetchedItem>, FetchError>;
}

/// One normalized item produced by a fetcher.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FetchedItem {
    pub source_name: String,
    pub url: String,
    pub title: String,
    pub abstract_text: String,
    /// RFC 3339 string, or empty if the feed entry had no date.
    pub published_at: String,
    /// Source-specific metadata as a JSON string. Empty (or `"{}"`)
    /// for sources without extras (RSS feeds today). The Federal
    /// Register fetcher stores `{"agencies":[...],"document_number":...}`
    /// here; congress.gov / govinfo.gov add their own keys.
    /// Stored verbatim in the `source_metadata` column on
    /// `candidates`; SQLite's json1 extension can query into it
    /// without a schema migration.
    pub source_metadata: String,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP denied for {url}: {source}")]
    Denied {
        url: String,
        #[source]
        source: HttpAccessDenied,
    },
    #[error("HTTP non-success for {url}: status {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("network error for {url}: {source}")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("parse error for {url}: {message}")]
    Parse { url: String, message: String },
}

/// RSS 2.0 / Atom fetcher. Same impl handles both formats —
/// `feed-rs` discriminates the parser internally. Registered under
/// both `"rss"` and `"atom-api"` method names; arXiv's Atom API and
/// regulator RSS feeds both end up here.
pub struct RssFetcher;

#[async_trait]
impl Fetcher for RssFetcher {
    fn method(&self) -> &'static str {
        "rss"
    }

    async fn fetch(
        &self,
        http: &EgressClient,
        source: &SourceConfig,
    ) -> Result<Vec<FetchedItem>, FetchError> {
        let body = fetch_body(http, &source.endpoint).await?;
        parse_feed(&source.name, &source.endpoint, &body)
    }
}

/// HTTP-fetch raw bytes of a feed. Separated from parsing so tests
/// can exercise the parser directly without a server.
pub async fn fetch_body(http: &EgressClient, url: &str) -> Result<String, FetchError> {
    let builder = http.get(url).await.map_err(|e| FetchError::Denied {
        url: url.to_string(),
        source: e,
    })?;
    let resp = builder.send().await.map_err(|e| FetchError::Network {
        url: url.to_string(),
        source: e,
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FetchError::HttpStatus {
            url: url.to_string(),
            status: status.as_u16(),
        });
    }
    resp.text().await.map_err(|e| FetchError::Network {
        url: url.to_string(),
        source: e,
    })
}

/// Parse an RSS 2.0 or Atom feed body.
pub fn parse_feed(
    source_name: &str,
    feed_url: &str,
    body: &str,
) -> Result<Vec<FetchedItem>, FetchError> {
    let parsed = feed_rs::parser::parse(body.as_bytes()).map_err(|e| FetchError::Parse {
        url: feed_url.to_string(),
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(parsed.entries.len());
    for entry in parsed.entries {
        let url = entry
            .links
            .iter()
            .find(|l| !l.href.is_empty())
            .map(|l| l.href.clone())
            .unwrap_or_default();
        if url.is_empty() {
            // Entries without a URL aren't useful — they can't be
            // deduped or shown in a digest. Skip rather than fail.
            continue;
        }
        let title = entry
            .title
            .as_ref()
            .map(|t| t.content.trim().to_string())
            .unwrap_or_default();
        let abstract_text = entry
            .summary
            .as_ref()
            .map(|s| s.content.clone())
            .or_else(|| entry.content.as_ref().and_then(|c| c.body.clone()))
            .unwrap_or_default();
        let published_at = entry
            .published
            .or(entry.updated)
            .map(format_rfc3339)
            .unwrap_or_default();
        out.push(FetchedItem {
            source_name: source_name.to_string(),
            url,
            title,
            abstract_text,
            published_at,
            source_metadata: String::new(),
        });
    }
    Ok(out)
}

fn format_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATOM_FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>arXiv cs.CY recent</title>
  <link href="http://arxiv.org/list/cs.CY/recent"/>
  <updated>2026-04-29T00:00:00Z</updated>
  <id>http://arxiv.org/list/cs.CY/recent</id>

  <entry>
    <id>http://arxiv.org/abs/2604.00001</id>
    <title>BIPA-style enforcement in employment biometrics</title>
    <link href="http://arxiv.org/abs/2604.00001"/>
    <published>2026-04-28T12:00:00Z</published>
    <updated>2026-04-28T12:00:00Z</updated>
    <summary>This paper surveys BIPA enforcement actions and their effect on employer-collected biometric templates.</summary>
    <author><name>A. Researcher</name></author>
  </entry>

  <entry>
    <id>http://arxiv.org/abs/2604.00002</id>
    <title>Cookie banner UX patterns 2026</title>
    <link href="http://arxiv.org/abs/2604.00002"/>
    <published>2026-04-27T12:00:00Z</published>
    <updated>2026-04-27T12:00:00Z</updated>
    <summary>An empirical study of cookie banner designs.</summary>
    <author><name>B. Researcher</name></author>
  </entry>
</feed>
"#;

    const RSS2_FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>FTC Press Releases</title>
    <link>https://www.ftc.gov/news-events/news/press-releases</link>
    <description>Latest press releases.</description>
    <item>
      <title>FTC sues data broker over Section 5 unfairness</title>
      <link>https://www.ftc.gov/news-events/news/press-releases/2026/04/ftc-sues-data-broker</link>
      <pubDate>Tue, 28 Apr 2026 14:00:00 GMT</pubDate>
      <description>The Federal Trade Commission today filed suit against ExampleCorp under Section 5 of the FTC Act for unfair data broker practices.</description>
    </item>
    <item>
      <title>FTC requests comments on social media privacy</title>
      <link>https://www.ftc.gov/news-events/news/press-releases/2026/04/ftc-comments-social-privacy</link>
      <pubDate>Mon, 27 Apr 2026 09:30:00 GMT</pubDate>
      <description>The FTC announced a request for public comment on social media privacy practices.</description>
    </item>
  </channel>
</rss>
"#;

    #[test]
    fn parses_atom_feed() {
        let items = parse_feed(
            "arxiv-cs-cy",
            "https://export.arxiv.org/list/cs.CY",
            ATOM_FIXTURE,
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].title,
            "BIPA-style enforcement in employment biometrics"
        );
        assert_eq!(items[0].url, "http://arxiv.org/abs/2604.00001");
        assert!(items[0].abstract_text.contains("BIPA"));
        assert_eq!(items[0].source_name, "arxiv-cs-cy");
        assert!(!items[0].published_at.is_empty());
    }

    #[test]
    fn parses_rss2_feed() {
        let items = parse_feed("ftc-press", "https://www.ftc.gov/feed", RSS2_FIXTURE).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].title,
            "FTC sues data broker over Section 5 unfairness"
        );
        assert!(items[0].abstract_text.contains("Section 5"));
        assert_eq!(items[0].source_name, "ftc-press");
        assert!(!items[0].published_at.is_empty());
    }

    #[test]
    fn malformed_feed_returns_parse_error() {
        let err = parse_feed("x", "https://x", "not a feed at all").unwrap_err();
        assert!(matches!(err, FetchError::Parse { .. }));
    }

    #[test]
    fn entries_without_link_are_skipped() {
        let bad = r#"<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>x</title>
    <link>https://x</link>
    <description>x</description>
    <item>
      <title>has-link</title>
      <link>https://example.com/a</link>
      <description>x</description>
    </item>
    <item>
      <title>no-link</title>
      <description>x</description>
    </item>
  </channel>
</rss>"#;
        let items = parse_feed("x", "https://x", bad).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "has-link");
    }
}
