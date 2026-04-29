//! Shared transport for api.data.gov-keyed JSON fetchers.
//!
//! Both api.congress.gov and api.govinfo.gov authenticate via the
//! [api.data.gov standard](https://api.data.gov/docs/api-key/) — an
//! `X-Api-Key` header carrying the operator's key. The key lives in
//! the wirken vault; the orchestrator reads it once at startup and
//! injects it into the fetcher at construction time. From the LLM's
//! and the agent's perspective the key never exists: only the parsed
//! [`crate::fetcher::FetchedItem`]s flow downstream.
//!
//! ## Why a shared helper instead of two parallel implementations
//!
//! The two consumer fetchers (Congress, GovInfo) have different
//! response shapes; their parsers diverge cleanly. But the auth
//! injection, transport, and HTTP-level error handling are
//! identical — exactly what the trait abstraction earned by three
//! consumers said was the right shape: one auth pattern, one
//! transport, multiple parsers.
//!
//! ## Fallback to query-param auth
//!
//! api.data.gov accepts `?api_key=...` as well as the header.
//! `X-Api-Key` is preferred because it stays out of access logs
//! and out of the `Url` struct that the policed
//! [`wirken_agent::egress::EgressClient`] rate-limit-keys on. Header
//! injection is the only path supported here.

use wirken_agent::egress::EgressClient;

use crate::fetcher::FetchError;

/// HTTP-fetch raw bytes from `url`, with `X-Api-Key: <api_key>` set.
/// Mirrors [`crate::fetcher::fetch_body`]'s shape so error mapping
/// stays consistent across fetcher kinds.
pub async fn fetch_with_api_key(
    http: &EgressClient,
    url: &str,
    api_key: &str,
) -> Result<String, FetchError> {
    let builder = http.get(url).await.map_err(|e| FetchError::Denied {
        url: url.to_string(),
        source: e,
    })?;
    let resp = builder
        .header("X-Api-Key", api_key)
        .send()
        .await
        .map_err(|e| FetchError::Network {
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
