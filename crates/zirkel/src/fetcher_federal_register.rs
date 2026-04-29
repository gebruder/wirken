//! Federal Register JSON fetcher.
//!
//! `federalregister.gov/api/v1/documents.json` returns a paginated
//! list of recent documents (rules, proposed rules, notices,
//! presidential documents). No authentication; the API endpoint is
//! public and stable. The pre-check verified the response shape
//! against `?per_page=1&order=newest` — top-level `results[]`,
//! per-item `title`, `abstract`, `publication_date`, `html_url`,
//! `agencies[]`, `document_number`, `type`, `excerpts`.
//!
//! ## Why a separate fetcher impl
//!
//! The shape is JSON, not RSS, so the parser is different. The
//! fetcher trait is what gives us one dispatch path for both.
//!
//! ## What lands in `source_metadata`
//!
//! `agencies[]` and `document_number` — both useful for downstream
//! enrichment (theme naming could surface "FTC enforcement" vs
//! "CFPB rulemaking" cleanly, and `document_number` is the canonical
//! cross-reference back to the Federal Register's own indexing).
//! The full `agencies[]` is stashed verbatim with the response's
//! original field shape (`name`, `id`, `slug`, `parent_id`, `url`)
//! so a future use that needs IDs or hierarchy isn't refetching.
//!
//! Other response fields (`type`, `excerpts`, `pdf_url`, etc.) are
//! not stashed — they aren't named requirements today and can be
//! added when a downstream use surfaces.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use wirken_agent::egress::EgressClient;

use crate::fetcher::{FetchError, FetchedItem, Fetcher, SourceConfig, fetch_body};

/// Method discriminator for [`FederalRegisterFetcher`]. Used in
/// `sources.toml`'s `method = "..."` field and in [`crate::fetcher_registry::FetcherRegistry`].
pub const METHOD: &str = "json-federal-register";

pub struct FederalRegisterFetcher;

#[async_trait]
impl Fetcher for FederalRegisterFetcher {
    fn method(&self) -> &'static str {
        METHOD
    }

    /// Federal Register's API has no published per-key limit (it's
    /// public, no key required). 1000/day is a deliberately
    /// conservative budget — well above zirkel's daily-fire usage
    /// (one request per source per cron tick) and well below
    /// anything that would draw operator attention from the
    /// federalregister.gov side.
    fn default_rate_limit_per_day(&self) -> Option<u32> {
        Some(1000)
    }

    async fn fetch(
        &self,
        http: &EgressClient,
        source: &SourceConfig,
    ) -> Result<Vec<FetchedItem>, FetchError> {
        let body = fetch_body(http, &source.endpoint).await?;
        parse_response(&source.name, &source.endpoint, &body)
    }
}

/// On-the-wire response shape (subset). Untyped JSON would do, but
/// the strongly-typed deserialise gives us field-rename safety and a
/// clear signal at parse time when the API changes.
#[derive(Debug, Deserialize)]
struct DocumentsResponse {
    #[serde(default)]
    results: Vec<Document>,
}

#[derive(Debug, Deserialize)]
struct Document {
    #[serde(default)]
    title: String,
    #[serde(default)]
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    #[serde(default)]
    publication_date: Option<String>,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    document_number: Option<String>,
    /// Raw agency objects; we pass them through to source_metadata.
    #[serde(default)]
    agencies: Vec<serde_json::Value>,
}

/// Parse the body of `documents.json` into [`FetchedItem`]s.
/// Separated so tests can exercise the parser without a server,
/// matching the RSS module's shape.
pub fn parse_response(
    source_name: &str,
    feed_url: &str,
    body: &str,
) -> Result<Vec<FetchedItem>, FetchError> {
    let parsed: DocumentsResponse = serde_json::from_str(body).map_err(|e| FetchError::Parse {
        url: feed_url.to_string(),
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(parsed.results.len());
    for doc in parsed.results {
        if doc.html_url.is_empty() {
            // Items without a URL aren't useful — they can't be
            // deduped or shown in a digest. Skip rather than fail,
            // matching the RSS parser's policy.
            continue;
        }
        // Build source_metadata. Always emit a non-empty object so
        // downstream readers don't have to special-case "no
        // metadata"; even a sparse document keeps the shape.
        let metadata = json!({
            "agencies": doc.agencies,
            "document_number": doc.document_number.clone().unwrap_or_default(),
        });
        let source_metadata = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

        // Federal Register's `publication_date` is `YYYY-MM-DD`
        // (no time component). Normalize to RFC 3339 at midnight
        // UTC so the column shape matches what RSS / Atom emit.
        let published_at = doc
            .publication_date
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|d| format!("{d}T00:00:00Z"))
            .unwrap_or_default();

        out.push(FetchedItem {
            source_name: source_name.to_string(),
            url: doc.html_url,
            title: doc.title.trim().to_string(),
            abstract_text: doc.abstract_text.unwrap_or_default(),
            published_at,
            source_metadata,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal real-shaped response from `api/v1/documents.json`.
    /// Field names taken from the verified pre-check fetch.
    const FIXTURE: &str = r#"{
  "description": "Newest Federal Register Documents",
  "count": 10000,
  "total_pages": 50,
  "next_page_url": "https://www.federalregister.gov/api/v1/documents.json?order=newest&page=2&per_page=2",
  "results": [
    {
      "title": "Notice of Proposed Rulemaking on Adtech Consent",
      "type": "Proposed Rule",
      "abstract": "The Commission proposes amendments to existing regulations governing adtech consent disclosures.",
      "document_number": "2026-08234",
      "html_url": "https://www.federalregister.gov/documents/2026/04/29/2026-08234/notice-of-proposed-rulemaking",
      "pdf_url": "https://www.federalregister.gov/documents/full_text/pdf/2026/04/29/2026-08234.pdf",
      "publication_date": "2026-04-29",
      "agencies": [
        {
          "raw_name": "FEDERAL TRADE COMMISSION",
          "name": "Federal Trade Commission",
          "id": 188,
          "url": "https://www.federalregister.gov/agencies/federal-trade-commission",
          "json_url": "https://www.federalregister.gov/api/v1/agencies/188",
          "parent_id": null,
          "slug": "federal-trade-commission"
        }
      ],
      "excerpts": "The FTC seeks comment on proposed amendments..."
    },
    {
      "title": "Final Rule on Cross-Border Data Transfers",
      "type": "Rule",
      "abstract": "Implements the framework for adequacy decisions on cross-border data transfers.",
      "document_number": "2026-08220",
      "html_url": "https://www.federalregister.gov/documents/2026/04/28/2026-08220/final-rule-on-cross-border",
      "publication_date": "2026-04-28",
      "agencies": [
        {
          "raw_name": "DEPARTMENT OF COMMERCE",
          "name": "Department of Commerce",
          "id": 67,
          "slug": "commerce-department"
        },
        {
          "raw_name": "INTERNATIONAL TRADE ADMINISTRATION",
          "name": "International Trade Administration",
          "id": 268,
          "parent_id": 67,
          "slug": "international-trade-administration"
        }
      ]
    }
  ]
}"#;

    #[test]
    fn parses_valid_response() {
        let items = parse_response(
            "federal-register",
            "https://www.federalregister.gov/api/v1/documents.json",
            FIXTURE,
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].title,
            "Notice of Proposed Rulemaking on Adtech Consent"
        );
        assert_eq!(
            items[0].url,
            "https://www.federalregister.gov/documents/2026/04/29/2026-08234/notice-of-proposed-rulemaking"
        );
        assert!(items[0].abstract_text.contains("adtech consent"));
        assert_eq!(items[0].published_at, "2026-04-29T00:00:00Z");
        assert_eq!(items[0].source_name, "federal-register");
    }

    #[test]
    fn source_metadata_includes_agencies_and_document_number() {
        let items = parse_response("fr", "https://x", FIXTURE).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&items[0].source_metadata).unwrap();
        assert_eq!(meta["document_number"], "2026-08234");
        let agencies = meta["agencies"].as_array().unwrap();
        assert_eq!(agencies.len(), 1);
        assert_eq!(agencies[0]["name"], "Federal Trade Commission");
        assert_eq!(agencies[0]["id"], 188);
        assert_eq!(agencies[0]["slug"], "federal-trade-commission");
    }

    #[test]
    fn nested_agencies_with_parent_id_preserved() {
        let items = parse_response("fr", "https://x", FIXTURE).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&items[1].source_metadata).unwrap();
        let agencies = meta["agencies"].as_array().unwrap();
        assert_eq!(agencies.len(), 2);
        // International Trade Admin lists Commerce as its parent_id.
        assert_eq!(agencies[1]["parent_id"], 67);
        assert_eq!(agencies[1]["name"], "International Trade Administration");
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let err = parse_response("x", "https://x", "not json at all").unwrap_err();
        assert!(matches!(err, FetchError::Parse { .. }));
    }

    #[test]
    fn empty_results_array_yields_no_items() {
        let body = r#"{"results":[]}"#;
        let items = parse_response("x", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn missing_html_url_skipped() {
        let body = r#"{"results":[
            {"title":"no-url","publication_date":"2026-04-29","html_url":""},
            {"title":"has-url","publication_date":"2026-04-29","html_url":"https://example.com/a"}
        ]}"#;
        let items = parse_response("x", "https://x", body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "has-url");
    }

    #[test]
    fn missing_publication_date_yields_empty_string() {
        let body = r#"{"results":[
            {"title":"undated","html_url":"https://example.com/a"}
        ]}"#;
        let items = parse_response("x", "https://x", body).unwrap();
        assert_eq!(items[0].published_at, "");
    }

    #[test]
    fn missing_agencies_yields_empty_array_in_metadata() {
        let body = r#"{"results":[
            {"title":"no-agencies","html_url":"https://example.com/a","publication_date":"2026-04-29","document_number":"X-1"}
        ]}"#;
        let items = parse_response("x", "https://x", body).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&items[0].source_metadata).unwrap();
        assert!(meta["agencies"].as_array().unwrap().is_empty());
        assert_eq!(meta["document_number"], "X-1");
    }
}
