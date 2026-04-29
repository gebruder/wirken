//! GovInfo collections JSON fetcher (BILLS / CHRG).
//!
//! Targets `api.govinfo.gov/collections/BILLS/<lastModifiedStartDate>/`
//! (or any equivalent collection endpoint). The shape is consistent
//! across collections — verified in the pre-check:
//! `{"offsetMark": "...", "nextPage": "...", "count": N, "packages": [...]}`.
//!
//! ## Auth
//!
//! `X-Api-Key` via [`crate::fetcher_keyed::fetch_with_api_key`] (same
//! api.data.gov standard as Congress.gov). Key resolved from vault
//! at orchestrator startup; never reaches the agent / LLM.
//!
//! ## Rate limit
//!
//! GovInfo publishes 36,000/hour, 1,200/min, 40/sec for
//! api.data.gov keys. The fetcher declares 5,000/day — vastly under
//! all three ceilings and oversized for zirkel's daily-fire pattern.
//!
//! ## What lands in `source_metadata`
//!
//! `packageId`, `collectionCode`, `lastModified`, `dateIssued`,
//! `granulesLink`. Granules link is preserved so a follow-up fetch
//! could pull each bill's text package without re-deriving the URL.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use wirken_agent::egress::EgressClient;

use crate::fetcher::{FetchError, FetchedItem, Fetcher, SourceConfig};
use crate::fetcher_keyed::fetch_with_api_key;

pub const METHOD: &str = "json-govinfo-bills";

/// Daily rate limit declared for `api.govinfo.gov`. Way under
/// 36,000/hour and oversized for zirkel — same protection-against-
/// operator-experimentation rationale as Congress.
pub const RATE_LIMIT_PER_DAY: u32 = 5_000;

pub struct GovInfoBillsFetcher {
    api_key: SecretString,
}

impl GovInfoBillsFetcher {
    pub fn new(api_key: SecretString) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl Fetcher for GovInfoBillsFetcher {
    fn method(&self) -> &'static str {
        METHOD
    }

    fn default_rate_limit_per_day(&self) -> Option<u32> {
        Some(RATE_LIMIT_PER_DAY)
    }

    async fn fetch(
        &self,
        http: &EgressClient,
        source: &SourceConfig,
    ) -> Result<Vec<FetchedItem>, FetchError> {
        let body = fetch_with_api_key(http, &source.endpoint, self.api_key.expose_secret()).await?;
        parse_response(&source.name, &source.endpoint, &body)
    }
}

#[derive(Debug, Deserialize)]
struct CollectionsResponse {
    #[serde(default)]
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    #[serde(default)]
    #[serde(rename = "packageId")]
    package_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    #[serde(rename = "packageLink")]
    package_link: Option<String>,
    /// Human-facing detail page on govinfo.gov; some collections
    /// emit this directly, others only emit `packageLink` (the API
    /// detail URL). We prefer it when present.
    #[serde(default)]
    #[serde(rename = "detailsLink")]
    details_link: Option<String>,
    #[serde(default)]
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(default)]
    #[serde(rename = "dateIssued")]
    date_issued: Option<String>,
    #[serde(default)]
    #[serde(rename = "collectionCode")]
    collection_code: Option<String>,
    #[serde(default)]
    #[serde(rename = "granulesLink")]
    granules_link: Option<String>,
}

pub fn parse_response(
    source_name: &str,
    endpoint_url: &str,
    body: &str,
) -> Result<Vec<FetchedItem>, FetchError> {
    let parsed: CollectionsResponse =
        serde_json::from_str(body).map_err(|e| FetchError::Parse {
            url: endpoint_url.to_string(),
            message: e.to_string(),
        })?;
    let mut out = Vec::with_capacity(parsed.packages.len());
    for pkg in parsed.packages {
        // URL precedence: detailsLink (human page) > packageLink
        // (API detail) > derived from packageId. The derived URL is
        // a last resort because it depends on packageId being a
        // well-formed govinfo identifier.
        let url = pkg
            .details_link
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| pkg.package_link.clone().filter(|u| !u.is_empty()))
            .or_else(|| {
                pkg.package_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .map(|id| format!("https://www.govinfo.gov/app/details/{id}"))
            })
            .unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let title = pkg.title.as_deref().unwrap_or("").trim().to_string();
        if title.is_empty() {
            continue;
        }

        let metadata = json!({
            "packageId": pkg.package_id.clone().unwrap_or_default(),
            "collectionCode": pkg.collection_code.clone().unwrap_or_default(),
            "lastModified": pkg.last_modified.clone().unwrap_or_default(),
            "dateIssued": pkg.date_issued.clone().unwrap_or_default(),
            "granulesLink": pkg.granules_link.clone().unwrap_or_default(),
        });
        let source_metadata = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

        // Date precedence: dateIssued (when the package was
        // officially issued) > lastModified (when GovInfo last
        // updated metadata). dateIssued is YYYY-MM-DD; lastModified
        // is full RFC 3339.
        let published_at = match (pkg.date_issued.as_deref(), pkg.last_modified.as_deref()) {
            (Some(d), _) if !d.is_empty() && d.len() == 10 => format!("{d}T00:00:00Z"),
            (Some(d), _) if !d.is_empty() => d.to_string(),
            (_, Some(m)) if !m.is_empty() => m.to_string(),
            _ => String::new(),
        };

        out.push(FetchedItem {
            source_name: source_name.to_string(),
            url,
            title,
            // GovInfo collection responses don't carry an abstract
            // at the package list level — only at the granule level
            // would a per-section abstract exist. Empty here is
            // honest; the title carries the signal.
            abstract_text: String::new(),
            published_at,
            source_metadata,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic-shaped /collections/BILLS response. Field names
    /// match GovInfo's documented packages-list schema; the response
    /// in production likely carries more fields (we ignore unknowns
    /// via serde defaults).
    const FIXTURE: &str = r#"{
  "offsetMark": "*",
  "nextPage": "https://api.govinfo.gov/collections/BILLS/2026-04-01T00:00:00Z?offsetMark=AoEpMTE5LXMtNjU4&pageSize=2",
  "count": 17,
  "packages": [
    {
      "packageId": "BILLS-119hr1234ih",
      "title": "American Privacy Rights Act of 2026",
      "packageLink": "https://api.govinfo.gov/packages/BILLS-119hr1234ih/summary",
      "detailsLink": "https://www.govinfo.gov/app/details/BILLS-119hr1234ih",
      "granulesLink": "https://api.govinfo.gov/packages/BILLS-119hr1234ih/granules",
      "lastModified": "2026-04-29T18:30:00Z",
      "dateIssued": "2026-04-29",
      "collectionCode": "BILLS"
    },
    {
      "packageId": "BILLS-119s567is",
      "title": "Children's Online Safety Act",
      "packageLink": "https://api.govinfo.gov/packages/BILLS-119s567is/summary",
      "lastModified": "2026-04-28T11:15:00Z",
      "dateIssued": "2026-04-28",
      "collectionCode": "BILLS"
    }
  ]
}"#;

    #[test]
    fn parses_packages() {
        let items = parse_response(
            "govinfo-gov",
            "https://api.govinfo.gov/collections/BILLS/2026-04-01T00:00:00Z",
            FIXTURE,
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "American Privacy Rights Act of 2026");
        assert_eq!(
            items[0].url,
            "https://www.govinfo.gov/app/details/BILLS-119hr1234ih"
        );
        assert_eq!(items[0].published_at, "2026-04-29T00:00:00Z");
    }

    #[test]
    fn details_link_preferred_over_package_link() {
        let items = parse_response("g", "https://x", FIXTURE).unwrap();
        // First item has both: details should win.
        assert!(items[0].url.contains("/app/details/"));
    }

    #[test]
    fn falls_back_to_package_link_when_details_absent() {
        let items = parse_response("g", "https://x", FIXTURE).unwrap();
        // Second item has only packageLink.
        assert!(items[1].url.contains("api.govinfo.gov/packages/"));
    }

    #[test]
    fn metadata_carries_package_id_and_links() {
        let items = parse_response("g", "https://x", FIXTURE).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&items[0].source_metadata).unwrap();
        assert_eq!(meta["packageId"], "BILLS-119hr1234ih");
        assert_eq!(meta["collectionCode"], "BILLS");
        assert_eq!(
            meta["granulesLink"],
            "https://api.govinfo.gov/packages/BILLS-119hr1234ih/granules"
        );
    }

    #[test]
    fn fallback_url_from_package_id() {
        let body = r#"{"packages":[
            {"packageId":"BILLS-119hr1ih","title":"X","dateIssued":"2026-04-29"}
        ]}"#;
        let items = parse_response("g", "https://x", body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].url,
            "https://www.govinfo.gov/app/details/BILLS-119hr1ih"
        );
    }

    #[test]
    fn package_without_title_skipped() {
        let body = r#"{"packages":[
            {"packageId":"X-1","detailsLink":"https://x","dateIssued":"2026-04-29"}
        ]}"#;
        let items = parse_response("g", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn package_without_url_or_id_skipped() {
        let body = r#"{"packages":[
            {"title":"unidentifiable","dateIssued":"2026-04-29"}
        ]}"#;
        let items = parse_response("g", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn last_modified_used_when_date_issued_absent() {
        let body = r#"{"packages":[
            {"packageId":"X-1","title":"X","detailsLink":"https://x","lastModified":"2026-04-29T18:30:00Z"}
        ]}"#;
        let items = parse_response("g", "https://x", body).unwrap();
        assert_eq!(items[0].published_at, "2026-04-29T18:30:00Z");
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let err = parse_response("g", "https://x", "garbage").unwrap_err();
        assert!(matches!(err, FetchError::Parse { .. }));
    }
}
