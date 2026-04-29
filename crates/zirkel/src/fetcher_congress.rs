//! Congress.gov v3 JSON fetcher (bill endpoint).
//!
//! Targets `api.congress.gov/v3/bill` (or any equivalent v3 list
//! endpoint that returns `{"bills": [...], "pagination": {...},
//! "request": {...}}`). The operator picks the exact endpoint via
//! the `endpoint` field in `sources.toml` — the fetcher trusts the
//! operator's choice and parses the bills array shape that v3
//! returns for any bill-list query.
//!
//! ## Auth
//!
//! `X-Api-Key` via [`crate::fetcher_keyed::fetch_with_api_key`].
//! The key is resolved from the wirken vault at orchestrator startup
//! and injected at fetcher construction; it never crosses the
//! agent / LLM boundary. See piece 5's architectural doc.
//!
//! ## Rate limit
//!
//! Congress.gov publishes 5,000 requests/hour for api.data.gov keys
//! (per the README). The fetcher declares 5,000/day — well below
//! the per-hour ceiling and plenty of headroom for zirkel's daily
//! cron pattern.
//!
//! ## What lands in `source_metadata`
//!
//! `congress`, `type`, `number`, `latestAction` (its full nested
//! structure) — all useful for downstream filtering by chamber /
//! bill type / latest activity. `policyArea` is also stashed so
//! theme naming has a hand-coded grouping signal alongside the
//! embedding-based clusters.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use wirken_agent::egress::EgressClient;

use crate::fetcher::{FetchError, FetchedItem, Fetcher, SourceConfig};
use crate::fetcher_keyed::fetch_with_api_key;

pub const METHOD: &str = "json-congress-bill";

/// Daily rate limit declared for `api.congress.gov`. 5,000/day is
/// well below the published 5,000/hour ceiling and oversized for
/// zirkel's once-per-day fetch pattern; the headroom protects an
/// operator who briefly fetches multiple endpoints during setup.
pub const RATE_LIMIT_PER_DAY: u32 = 5_000;

pub struct CongressBillFetcher {
    api_key: SecretString,
}

impl CongressBillFetcher {
    pub fn new(api_key: SecretString) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl Fetcher for CongressBillFetcher {
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
struct BillsResponse {
    #[serde(default)]
    bills: Vec<Bill>,
}

#[derive(Debug, Deserialize)]
struct Bill {
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    #[serde(rename = "type")]
    bill_type: Option<String>,
    #[serde(default)]
    congress: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    #[serde(rename = "introducedDate")]
    introduced_date: Option<String>,
    #[serde(default)]
    #[serde(rename = "updateDate")]
    update_date: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    #[serde(rename = "originChamber")]
    origin_chamber: Option<String>,
    #[serde(default)]
    #[serde(rename = "latestAction")]
    latest_action: Option<serde_json::Value>,
    #[serde(default)]
    #[serde(rename = "policyArea")]
    policy_area: Option<serde_json::Value>,
}

pub fn parse_response(
    source_name: &str,
    endpoint_url: &str,
    body: &str,
) -> Result<Vec<FetchedItem>, FetchError> {
    let parsed: BillsResponse = serde_json::from_str(body).map_err(|e| FetchError::Parse {
        url: endpoint_url.to_string(),
        message: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(parsed.bills.len());
    for bill in parsed.bills {
        // The API returns a bill detail URL in `url`; if absent
        // (older response shapes), fall back to constructing the
        // human-facing congress.gov URL from the bill identity.
        let url = bill
            .url
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| build_fallback_url(&bill))
            .unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        // Title can be missing on very fresh introductions; skip
        // those rather than emit an empty-title row that the digest
        // renderer would surface as a blank line.
        let title = bill.title.as_deref().unwrap_or("").trim().to_string();
        if title.is_empty() {
            continue;
        }
        // Stash structural metadata as JSON. `latestAction` and
        // `policyArea` carry their original nested shape so future
        // filtering doesn't need a refetch.
        let metadata = json!({
            "congress": bill.congress,
            "type": bill.bill_type.clone().unwrap_or_default(),
            "number": bill.number.clone().unwrap_or_default(),
            "originChamber": bill.origin_chamber.clone().unwrap_or_default(),
            "latestAction": bill.latest_action,
            "policyArea": bill.policy_area,
        });
        let source_metadata = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

        // Date precedence: introducedDate > updateDate. Both arrive
        // as either YYYY-MM-DD or full RFC 3339 — normalise YYYY-MM-DD
        // to midnight UTC so the column shape matches RSS / Atom.
        let raw_date = bill
            .introduced_date
            .as_deref()
            .or(bill.update_date.as_deref())
            .unwrap_or("");
        let published_at = if raw_date.is_empty() {
            String::new()
        } else if raw_date.len() == 10 {
            // YYYY-MM-DD
            format!("{raw_date}T00:00:00Z")
        } else {
            raw_date.to_string()
        };

        // Abstract: synthesise from latestAction's text if available,
        // since v3 bill responses don't carry a free-text summary at
        // the list level. Better than empty for the digest renderer.
        let abstract_text = bill
            .latest_action
            .as_ref()
            .and_then(|v| v.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        out.push(FetchedItem {
            source_name: source_name.to_string(),
            url,
            title,
            abstract_text,
            published_at,
            source_metadata,
        });
    }
    Ok(out)
}

/// Build a congress.gov detail URL from `(congress, type, number)`
/// when the API response omits the `url` field. Returns `None` if
/// any component is missing.
fn build_fallback_url(bill: &Bill) -> Option<String> {
    let congress = bill.congress?;
    let bill_type = bill.bill_type.as_deref()?.to_lowercase();
    let number = bill.number.as_deref()?;
    if bill_type.is_empty() || number.is_empty() {
        return None;
    }
    Some(format!(
        "https://www.congress.gov/bill/{congress}th-congress/{bill_type}/{number}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic-shaped /v3/bill response. Field names match the
    /// v3 OpenAPI / README documentation; exact response shape from
    /// a live fetch may add fields (we ignore unknowns) but the
    /// identifying fields are stable.
    const FIXTURE: &str = r#"{
  "bills": [
    {
      "congress": 119,
      "type": "HR",
      "number": "1234",
      "title": "American Privacy Rights Act of 2026",
      "introducedDate": "2026-04-29",
      "updateDate": "2026-04-29T18:30:00Z",
      "url": "https://api.congress.gov/v3/bill/119/hr/1234?format=json",
      "originChamber": "House",
      "latestAction": {
        "actionDate": "2026-04-29",
        "text": "Referred to the Committee on Energy and Commerce."
      },
      "policyArea": {
        "name": "Commerce"
      }
    },
    {
      "congress": 119,
      "type": "S",
      "number": "567",
      "title": "Children's Online Safety Act",
      "introducedDate": "2026-04-28",
      "originChamber": "Senate",
      "latestAction": {
        "actionDate": "2026-04-28",
        "text": "Read twice and referred to the Committee on Commerce, Science, and Transportation."
      }
    }
  ],
  "pagination": {"count": 2},
  "request": {"format": "json"}
}"#;

    #[test]
    fn parses_bills() {
        let items =
            parse_response("congress-gov", "https://api.congress.gov/v3/bill", FIXTURE).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "American Privacy Rights Act of 2026");
        assert_eq!(
            items[0].url,
            "https://api.congress.gov/v3/bill/119/hr/1234?format=json"
        );
        assert_eq!(items[0].published_at, "2026-04-29T00:00:00Z");
        // Abstract synthesised from latestAction.text:
        assert!(items[0].abstract_text.contains("Energy and Commerce"));
    }

    #[test]
    fn fallback_url_constructed_when_response_omits_url() {
        let body = r#"{"bills":[
            {"congress":119,"type":"HR","number":"42","title":"X","introducedDate":"2026-04-29"}
        ]}"#;
        let items = parse_response("congress", "https://x", body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].url,
            "https://www.congress.gov/bill/119th-congress/hr/42"
        );
    }

    #[test]
    fn item_with_no_url_no_identity_skipped() {
        let body = r#"{"bills":[
            {"title":"Just a title","introducedDate":"2026-04-29"}
        ]}"#;
        let items = parse_response("congress", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn item_without_title_skipped() {
        let body = r#"{"bills":[
            {"congress":119,"type":"HR","number":"1","introducedDate":"2026-04-29"}
        ]}"#;
        let items = parse_response("congress", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn metadata_includes_full_latest_action_and_policy_area() {
        let items = parse_response("c", "https://x", FIXTURE).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&items[0].source_metadata).unwrap();
        assert_eq!(meta["congress"], 119);
        assert_eq!(meta["type"], "HR");
        assert_eq!(meta["number"], "1234");
        assert_eq!(meta["originChamber"], "House");
        assert_eq!(
            meta["latestAction"]["text"],
            "Referred to the Committee on Energy and Commerce."
        );
        assert_eq!(meta["policyArea"]["name"], "Commerce");
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let err = parse_response("c", "https://x", "garbage").unwrap_err();
        assert!(matches!(err, FetchError::Parse { .. }));
    }

    #[test]
    fn empty_bills_array_yields_no_items() {
        let body = r#"{"bills":[]}"#;
        let items = parse_response("c", "https://x", body).unwrap();
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn full_rfc3339_dates_preserved() {
        let body = r#"{"bills":[
            {"congress":119,"type":"HR","number":"1","title":"X","updateDate":"2026-04-29T18:30:00Z"}
        ]}"#;
        let items = parse_response("c", "https://x", body).unwrap();
        assert_eq!(items[0].published_at, "2026-04-29T18:30:00Z");
    }
}
