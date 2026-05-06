//! End-to-end test for the C-API slice: four fetcher kinds compose
//! cleanly through screen → write → render with a mixed source set.
//!
//! What this covers (and why):
//!
//! - Trait dispatch holds across all four real consumers — RSS,
//!   Federal Register JSON, Congress.gov keyed JSON, GovInfo keyed
//!   JSON. The trait isn't an abstraction earned by a hypothetical;
//!   it's earned by exactly these four real shapes, and this test
//!   exercises them together so the trait's right-shapeness is
//!   structural, not just per-impl.
//!
//! - The vault → fetcher constructor → `X-Api-Key` header path
//!   actually injects the key. The mock servers for the keyed
//!   fetchers reject requests without the expected header, so a
//!   succeeded run is structural proof the auth path works.
//!
//! - Source-specific metadata flows from JSON parser → FetchedItem →
//!   `candidates.source_metadata` column → `digest::load_run` →
//!   rendered text positions. The four sources produce four kinds
//!   of metadata payload; we verify each survives the pipeline.
//!
//! - The renderer numbers items consistently across a four-source
//!   run, so the operator's keep/skip reply (covered by the
//!   `e2e_digest_keepskip` test) maps back to the same candidates
//!   regardless of which fetcher kind they came from.
//!
//! What this does NOT cover:
//!
//! - LLM relevance scoring + clustering + theme naming. Those have
//!   their own e2e in `orchestrator::tests::clustering_and_theme_naming_e2e`.
//!   This test runs with `llm: None` so the focus stays on the
//!   fetcher composition, not the downstream enrichment.
//! - The push → keep/skip round-trip. `e2e_digest_keepskip` covers
//!   that on a seeded DB.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, params};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use wirken_agent::rate_limit::RateLimitConfig;
use wirken_audit::{SessionLog, SqliteSessionLog};
use wirken_zirkel::digest::{RenderOptions, load_run, render};
use wirken_zirkel::orchestrator::{OrchestratorConfig, run as orchestrator_run};

// ----- Mock-server primitives -----------------------------------------

/// Spawn a one-shot HTTP server that returns `body` with the given
/// content type. Returns the URL at which the server is listening.
async fn spawn_one_shot(body: &'static str, content_type: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/", addr);
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\n\r\n{}",
                body.len(),
                content_type,
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    url
}

/// Spawn a one-shot HTTP server that returns `body` only if the
/// request carries `X-Api-Key: <expected_key>`; otherwise responds
/// 401. This is what makes the keyed-fetcher tests structural —
/// a successful run proves the header was injected correctly.
async fn spawn_keyed_one_shot(body: &'static str, expected_key: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/", addr);
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 16384];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let header_match = req.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with(&format!("x-api-key: {expected_key}").to_ascii_lowercase())
            });
            let resp = if header_match {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                let err = "{\"error\":\"missing or wrong X-Api-Key\"}";
                format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    err.len(),
                    err
                )
            };
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    url
}

// ----- Fixtures (one per fetcher kind) ---------------------------------

const RSS_FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>FTC Press</title><link>https://www.ftc.gov</link><description>x</description>
<item>
  <title>FTC adtech privacy enforcement update</title>
  <link>https://www.ftc.gov/news/2026/04/adtech</link>
  <pubDate>Tue, 28 Apr 2026 14:00:00 GMT</pubDate>
  <description>The FTC announces new privacy enforcement against adtech firms.</description>
</item>
</channel></rss>"#;

const FR_FIXTURE: &str = r#"{
  "results": [
    {
      "title": "Notice of Proposed Rulemaking on Privacy Disclosures",
      "abstract": "The Commission proposes amendments governing privacy disclosures.",
      "document_number": "2026-08234",
      "html_url": "https://www.federalregister.gov/documents/2026/04/29/2026-08234/privacy",
      "publication_date": "2026-04-29",
      "agencies": [
        {"name": "Federal Trade Commission", "id": 188, "slug": "federal-trade-commission"}
      ]
    }
  ]
}"#;

const CONGRESS_FIXTURE: &str = r#"{
  "bills": [
    {
      "congress": 119,
      "type": "HR",
      "number": "1234",
      "title": "American Privacy Rights Act of 2026",
      "introducedDate": "2026-04-29",
      "url": "https://api.congress.gov/v3/bill/119/hr/1234?format=json",
      "originChamber": "House",
      "latestAction": {
        "actionDate": "2026-04-29",
        "text": "Referred to the Committee on Energy and Commerce."
      },
      "policyArea": {"name": "Commerce"}
    }
  ],
  "pagination": {"count": 1},
  "request": {"format": "json"}
}"#;

const GOVINFO_FIXTURE: &str = r#"{
  "offsetMark": "*",
  "count": 1,
  "packages": [
    {
      "packageId": "BILLS-119hr1234ih",
      "title": "American Privacy Rights Act package",
      "detailsLink": "https://www.govinfo.gov/app/details/BILLS-119hr1234ih",
      "granulesLink": "https://api.govinfo.gov/packages/BILLS-119hr1234ih/granules",
      "lastModified": "2026-04-29T18:30:00Z",
      "dateIssued": "2026-04-29",
      "collectionCode": "BILLS"
    }
  ]
}"#;

// ----- Preset / interests writer --------------------------------------

fn write_fixture_preset(preset_dir: &Path, storage_dir: &Path, sources_toml: &str) {
    std::fs::create_dir_all(preset_dir.join("skills/aggregator")).unwrap();
    std::fs::write(
        preset_dir.join("preset.toml"),
        r#"
[preset]
name = "test-c-api"
description = "fixture for C-API e2e"
version = "0.0.1"
skills = ["aggregator"]
"#,
    )
    .unwrap();
    let storage_yaml = storage_dir.display().to_string();
    let aggregator_md = format!(
        "---\n\
         name: aggregator\n\
         description: fixture aggregator\n\
         disable-model-invocation: true\n\
         permissions:\n\
         \x20\x20tools:\n\
         \x20\x20\x20\x20allow: [exec]\n\
         \x20\x20egress:\n\
         \x20\x20\x20\x20mode: allowlist\n\
         \x20\x20\x20\x20domains:\n\
         \x20\x20\x20\x20\x20\x20- 127.0.0.1\n\
         \x20\x20filesystem:\n\
         \x20\x20\x20\x20write_paths: [\"{storage_yaml}\"]\n\
         \x20\x20\x20\x20read_paths: [\"{storage_yaml}\"]\n\
         \x20\x20inference:\n\
         \x20\x20\x20\x20allow: [\"*\"]\n\
         ---\n\nbody\n",
    );
    std::fs::write(preset_dir.join("skills/aggregator/SKILL.md"), aggregator_md).unwrap();
    std::fs::write(preset_dir.join("sources.toml"), sources_toml).unwrap();
}

fn write_interests(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    // Single broad keyword that every fixture title contains, so
    // each source's item lands in the kept set.
    std::fs::write(path, "keywords = [\"privacy\"]\nexclusions = []\n").unwrap();
}

fn build_config(
    preset_dir: PathBuf,
    storage_dir: PathBuf,
    interests_path: PathBuf,
    log: Arc<dyn SessionLog>,
    source_api_keys: HashMap<String, String>,
) -> OrchestratorConfig {
    OrchestratorConfig {
        preset_dir,
        storage_dir,
        interests_path,
        rate_limit: RateLimitConfig::unrestricted_for_tests(),
        session_log: Some(log),
        llm: None,
        llm_api_key: None,
        ollama_embed_base: String::new(),
        embed_model: String::new(),
        source_api_keys,
        perspectives_enabled: false,
        topic: None,
        max_perspectives: 0,
        max_related_topics: 0,
        per_topic_fanout_cap: 0,
        wikipedia_api_base: None,
    }
}

// ----- The test --------------------------------------------------------

#[tokio::test]
async fn four_fetchers_compose_through_pipeline() {
    let tmp = TempDir::new().unwrap();
    let preset_dir = tmp.path().join("preset");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&storage_dir).unwrap();
    let interests_path = storage_dir.join("interests.toml");
    write_interests(&interests_path);

    // Spin up one mock server per fetcher kind. The keyed servers
    // verify the expected X-Api-Key on the request before serving.
    let rss_url = spawn_one_shot(RSS_FIXTURE, "application/xml").await;
    let fr_url = spawn_one_shot(FR_FIXTURE, "application/json").await;
    let congress_url = spawn_keyed_one_shot(CONGRESS_FIXTURE, "congress-test-key").await;
    let govinfo_url = spawn_keyed_one_shot(GOVINFO_FIXTURE, "govinfo-test-key").await;

    let sources_toml = format!(
        r#"
[[source]]
name = "ftc-press"
host = "127.0.0.1"
method = "rss"
endpoint = "{rss_url}"

[[source]]
name = "federal-register"
host = "127.0.0.1"
method = "json-federal-register"
endpoint = "{fr_url}"

[[source]]
name = "congress-gov"
host = "127.0.0.1"
method = "json-congress-bill"
endpoint = "{congress_url}"

[[source]]
name = "govinfo-gov"
host = "127.0.0.1"
method = "json-govinfo-bills"
endpoint = "{govinfo_url}"
"#
    );
    write_fixture_preset(&preset_dir, &storage_dir, &sources_toml);

    // Vault keys for the keyed sources. These are what the
    // orchestrator will inject as X-Api-Key — the mock servers
    // reject requests without them.
    let mut keys = HashMap::new();
    keys.insert("congress-gov".into(), "congress-test-key".into());
    keys.insert("govinfo-gov".into(), "govinfo-test-key".into());

    let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
    let config = build_config(
        preset_dir.clone(),
        storage_dir.clone(),
        interests_path,
        log,
        keys,
    );

    let summary = orchestrator_run(config).await.expect("run succeeds");

    // ---- Composition assertions ------------------------------------
    assert_eq!(summary.sources_attempted, 4);
    assert_eq!(
        summary.sources_succeeded, 4,
        "all four fetchers should fetch cleanly"
    );
    assert_eq!(summary.sources_failed.len(), 0);
    assert_eq!(summary.sources_unsupported.len(), 0);
    assert_eq!(summary.items_seen, 4, "one item per fixture");
    assert_eq!(
        summary.items_kept, 4,
        "every fixture title contains 'privacy', so all four match"
    );

    // ---- Per-source row + metadata assertions ----------------------
    let conn = Connection::open(storage_dir.join("aggregator.db")).unwrap();

    // RSS row: source_metadata is empty/`'{}'` (RSS has no extras).
    let (rss_title, rss_meta): (String, String) = conn
        .query_row(
            "SELECT title, source_metadata FROM candidates WHERE source_name = 'ftc-press'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(rss_title.contains("FTC adtech privacy"));
    assert_eq!(rss_meta, "{}");

    // Federal Register row: source_metadata carries agencies + document_number.
    let fr_meta: String = conn
        .query_row(
            "SELECT source_metadata FROM candidates WHERE source_name = 'federal-register'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let fr_json: serde_json::Value = serde_json::from_str(&fr_meta).unwrap();
    assert_eq!(fr_json["document_number"], "2026-08234");
    assert_eq!(fr_json["agencies"][0]["name"], "Federal Trade Commission");

    // Congress row: source_metadata carries congress, type, number, latestAction, policyArea.
    let congress_meta: String = conn
        .query_row(
            "SELECT source_metadata FROM candidates WHERE source_name = 'congress-gov'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let congress_json: serde_json::Value = serde_json::from_str(&congress_meta).unwrap();
    assert_eq!(congress_json["congress"], 119);
    assert_eq!(congress_json["type"], "HR");
    assert_eq!(congress_json["number"], "1234");
    assert_eq!(congress_json["policyArea"]["name"], "Commerce");

    // GovInfo row: source_metadata carries packageId, collectionCode, granulesLink.
    let govinfo_meta: String = conn
        .query_row(
            "SELECT source_metadata FROM candidates WHERE source_name = 'govinfo-gov'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let govinfo_json: serde_json::Value = serde_json::from_str(&govinfo_meta).unwrap();
    assert_eq!(govinfo_json["packageId"], "BILLS-119hr1234ih");
    assert_eq!(govinfo_json["collectionCode"], "BILLS");
    assert!(
        govinfo_json["granulesLink"]
            .as_str()
            .unwrap()
            .contains("/granules")
    );

    // ---- Render the run with a mixed source set ---------------------
    let (rows, themes) = load_run(&conn, &summary.run_id).unwrap();
    assert_eq!(rows.len(), 4);
    let rendered = render(&rows, &themes, &RenderOptions::default()).unwrap();

    // All four titles appear in the digest text, properly numbered.
    assert!(
        rendered
            .text
            .contains("FTC adtech privacy enforcement update"),
        "RSS title missing from digest:\n{}",
        rendered.text
    );
    assert!(
        rendered
            .text
            .contains("Notice of Proposed Rulemaking on Privacy Disclosures"),
        "Federal Register title missing from digest"
    );
    assert!(
        rendered
            .text
            .contains("American Privacy Rights Act of 2026"),
        "Congress title missing from digest"
    );
    assert!(
        rendered
            .text
            .contains("American Privacy Rights Act package"),
        "GovInfo title missing from digest"
    );

    // 1..=4 numbering across all four items.
    assert!(rendered.text.contains("1. "));
    assert!(rendered.text.contains("4. "));
    assert_eq!(rendered.ordered_candidate_ids.len(), 4);
}

/// A keyed source with no API key in `source_api_keys` records as
/// unsupported (not failed) and the run continues for the other
/// sources. This is the operator-friendly behaviour locked in piece
/// 3: missing key is visible, not silently skipped.
#[tokio::test]
async fn missing_api_key_records_unsupported_run_continues() {
    let tmp = TempDir::new().unwrap();
    let preset_dir = tmp.path().join("preset");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&storage_dir).unwrap();
    let interests_path = storage_dir.join("interests.toml");
    write_interests(&interests_path);

    let rss_url = spawn_one_shot(RSS_FIXTURE, "application/xml").await;

    let sources_toml = format!(
        r#"
[[source]]
name = "ftc-press"
host = "127.0.0.1"
method = "rss"
endpoint = "{rss_url}"

[[source]]
name = "congress-gov"
host = "127.0.0.1"
method = "json-congress-bill"
endpoint = "https://api.congress.gov/v3/bill"
"#
    );
    write_fixture_preset(&preset_dir, &storage_dir, &sources_toml);

    let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
    // No congress key.
    let config = build_config(
        preset_dir,
        storage_dir.clone(),
        interests_path,
        log,
        HashMap::new(),
    );
    let summary = orchestrator_run(config).await.expect("run succeeds");

    assert_eq!(summary.sources_attempted, 2);
    assert_eq!(summary.sources_succeeded, 1, "only RSS succeeds");
    assert_eq!(summary.sources_unsupported.len(), 1);
    assert_eq!(summary.sources_unsupported[0], "congress-gov");
    assert_eq!(summary.items_kept, 1);

    // RSS row landed in the DB; congress did not.
    let conn = Connection::open(storage_dir.join("aggregator.db")).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM candidates WHERE source_name = 'congress-gov'",
            params![],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}
