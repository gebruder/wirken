//! Zirkel orchestrator pipeline.
//!
//! Pure Rust pipeline through the policed HTTP transport. The LLM is
//! NOT in the fetch loop — that path was rejected during Scope B
//! design because subprocess HTTP (curl-via-exec) routes around
//! [`wirken_agent::egress::EgressClient`] and
//! [`wirken_agent::rate_limit::RateLimitedClient`] entirely. This
//! pipeline calls the policed client directly so egress allowlist
//! and rate-limit budget enforcement are structural.
//!
//! ## What ships in Scope B
//!
//! - Load preset via `PresetLoader`.
//! - Read aggregator skill's permission profile; construct an
//!   `EgressClient` whose enforcement matches the profile and whose
//!   inner `RateLimitedClient` carries the per-host caps.
//! - Read `sources.toml`. Pick the first source.
//! - Fetch its endpoint through the policed client.
//! - Open `SkillStore` for the aggregator under `storage_dir`.
//! - Migrate to a minimal `candidates` schema.
//! - Insert one candidate row whose body is the response text.
//!
//! Scoring, clustering, theme naming, digest push are Scope C.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;
use wirken_agent::egress::{EgressClient, EgressEnforcement, HttpAccessDenied};
use wirken_agent::preset::PresetLoader;
use wirken_agent::rate_limit::RateLimitConfig;
use wirken_agent::skill_perms::PermissionProfile;
use wirken_skill_store::{SkillStore, SkillStoreError};

const AGGREGATOR_SKILL_NAME: &str = "aggregator";

/// Caller-supplied configuration for [`run`].
pub struct OrchestratorConfig {
    /// Directory of the installed preset (e.g. `~/.wirken/presets/zirkel/`).
    pub preset_dir: PathBuf,
    /// Directory where the aggregator's SQLite store and full bodies
    /// live (e.g. `~/.wirken/zirkel/`). Must be inside the aggregator
    /// skill's `permissions.filesystem.write_paths` allow-set.
    pub storage_dir: PathBuf,
    /// Rate-limit config for the per-source HTTP transport. Production
    /// uses the schema-defaulted [`RateLimitConfig::default`]; tests
    /// can pass [`RateLimitConfig::unrestricted_for_tests`] to skip
    /// jitter.
    pub rate_limit: RateLimitConfig,
}

/// Summary of what [`run`] did.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub source_name: String,
    pub source_url: String,
    pub candidate_id: i64,
    pub bytes_fetched: usize,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("load preset: {0}")]
    LoadPreset(String),
    #[error("aggregator skill missing from preset")]
    AggregatorSkillMissing,
    #[error("read sources.toml at {path}: {source}")]
    ReadSources {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse sources.toml at {path}: {message}")]
    ParseSources { path: PathBuf, message: String },
    #[error("sources.toml is empty — nothing to fetch")]
    EmptySources,
    #[error("HTTP fetch denied for {url}: {source}")]
    HttpDenied {
        url: String,
        #[source]
        source: HttpAccessDenied,
    },
    #[error("HTTP fetch failed for {url}: {source}")]
    HttpFailed {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("HTTP non-success for {url}: status {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("skill store: {0}")]
    Store(#[from] SkillStoreError),
    #[error("write candidate row: {0}")]
    WriteCandidate(#[from] rusqlite::Error),
}

/// Schema migrations applied to the aggregator's SkillStore. Order is
/// load-bearing — never reorder or replace existing entries; append only.
const AGGREGATOR_MIGRATIONS: &[&str] = &["CREATE TABLE candidates ( \
        id           INTEGER PRIMARY KEY AUTOINCREMENT, \
        source_name  TEXT NOT NULL, \
        url          TEXT NOT NULL, \
        fetched_at   TEXT NOT NULL DEFAULT (datetime('now')), \
        body         TEXT NOT NULL \
    )"];

/// On-disk shape of `sources.toml`. Only the fields the Scope B
/// orchestrator consumes are required; later scopes will tighten
/// the schema as additional fields become load-bearing.
#[derive(Debug, Deserialize)]
struct SourcesManifest {
    #[serde(default, rename = "source")]
    sources: Vec<SourceEntry>,
}

#[derive(Debug, Deserialize)]
struct SourceEntry {
    name: String,
    endpoint: String,
}

/// Run the orchestrator once. Loads the preset, fetches the first
/// source from `sources.toml`, writes one candidate row, returns.
///
/// Caller responsibility: ensure `config.storage_dir` is within the
/// aggregator skill's `permissions.filesystem.write_paths` allow-set.
/// The store open will fail loud otherwise — preferred to silent
/// out-of-policy writes.
pub async fn run(config: OrchestratorConfig) -> Result<RunSummary, OrchestratorError> {
    let loaded = PresetLoader::load_dir(&config.preset_dir)
        .map_err(|e| OrchestratorError::LoadPreset(e.to_string()))?;
    let aggregator = loaded
        .skills
        .iter()
        .find(|s| s.name == AGGREGATOR_SKILL_NAME)
        .ok_or(OrchestratorError::AggregatorSkillMissing)?;
    let profile: PermissionProfile = aggregator.permissions.clone();

    let sources_path = config.preset_dir.join("sources.toml");
    let raw =
        std::fs::read_to_string(&sources_path).map_err(|e| OrchestratorError::ReadSources {
            path: sources_path.clone(),
            source: e,
        })?;
    let manifest: SourcesManifest =
        toml::from_str(&raw).map_err(|e| OrchestratorError::ParseSources {
            path: sources_path.clone(),
            message: e.to_string(),
        })?;
    let first = manifest
        .sources
        .into_iter()
        .next()
        .ok_or(OrchestratorError::EmptySources)?;

    let http = EgressClient::with_rate_limit(config.rate_limit.clone());
    http.set_enforcement(EgressEnforcement::from_profile(
        &wirken_agent::skill_perms::EffectiveProfile::Resolved(profile.clone()),
    ));

    let resp_text = match http.get(&first.endpoint).await {
        Ok(builder) => {
            let resp = builder
                .send()
                .await
                .map_err(|e| OrchestratorError::HttpFailed {
                    url: first.endpoint.clone(),
                    source: e,
                })?;
            let status = resp.status();
            if !status.is_success() {
                return Err(OrchestratorError::HttpStatus {
                    url: first.endpoint.clone(),
                    status: status.as_u16(),
                });
            }
            resp.text()
                .await
                .map_err(|e| OrchestratorError::HttpFailed {
                    url: first.endpoint.clone(),
                    source: e,
                })?
        }
        Err(e) => {
            return Err(OrchestratorError::HttpDenied {
                url: first.endpoint.clone(),
                source: e,
            });
        }
    };

    let mut store = SkillStore::open(AGGREGATOR_SKILL_NAME, &config.storage_dir, &profile)?;
    store.migrate(AGGREGATOR_MIGRATIONS)?;
    let bytes = resp_text.len();
    let row_id: i64;
    {
        let conn = store.conn();
        conn.execute(
            "INSERT INTO candidates (source_name, url, body) VALUES (?1, ?2, ?3)",
            rusqlite::params![first.name, first.endpoint, resp_text],
        )?;
        row_id = conn.last_insert_rowid();
    }

    Ok(RunSummary {
        source_name: first.name,
        source_url: first.endpoint,
        candidate_id: row_id,
        bytes_fetched: bytes,
    })
}

/// Test helper: write a fixture preset directory with the supplied
/// aggregator egress allow-set and source endpoint. Returns the
/// preset_dir path. The caller passes this to [`run`].
#[cfg(test)]
pub(crate) fn write_fixture_preset(
    dest: &Path,
    storage_dir: &Path,
    egress_allowlist: &[&str],
    source_url: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dest.join("skills/aggregator"))?;
    std::fs::write(
        dest.join("preset.toml"),
        r#"
[preset]
name = "test-preset"
description = "fixture for orchestrator tests"
version = "0.0.1"
skills = ["aggregator"]
"#,
    )?;
    let domains_yaml = egress_allowlist
        .iter()
        .map(|d| format!("      - {d}"))
        .collect::<Vec<_>>()
        .join("\n");
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
         \x20\x20\x20\x20domains:\n{domains_yaml}\n\
         \x20\x20filesystem:\n\
         \x20\x20\x20\x20write_paths: [\"{storage_yaml}\"]\n\
         \x20\x20\x20\x20read_paths: [\"{storage_yaml}\"]\n\
         \x20\x20inference:\n\
         \x20\x20\x20\x20allow: [\"*\"]\n\
         ---\n\nbody\n",
    );
    std::fs::write(dest.join("skills/aggregator/SKILL.md"), aggregator_md)?;
    std::fs::write(
        dest.join("sources.toml"),
        format!(
            "[[source]]\n\
             name = \"test-source\"\n\
             host = \"127.0.0.1\"\n\
             method = \"json-api\"\n\
             endpoint = \"{source_url}\"\n",
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spin up a tiny local HTTP server that accepts one connection
    /// and responds with `body`. Returns the bound URL like
    /// `http://127.0.0.1:<port>/`.
    async fn one_shot_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    /// Keystone test: orchestrator fetches one source via the policed
    /// transport, writes a candidate row to the per-skill SQLite,
    /// returns a summary. End-to-end through the layers we built.
    #[tokio::test]
    async fn fetches_one_source_and_writes_one_candidate() {
        let body = "hello from fixture source";
        let url = one_shot_server(body).await;

        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        write_fixture_preset(&preset_dir, &storage_dir, &["127.0.0.1"], &url).unwrap();

        let summary = run(OrchestratorConfig {
            preset_dir,
            storage_dir: storage_dir.clone(),
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
        })
        .await
        .unwrap();

        assert_eq!(summary.source_name, "test-source");
        assert_eq!(summary.bytes_fetched, body.len());

        // Verify the candidate row landed in SQLite.
        let db_path = storage_dir.join("aggregator.db");
        assert!(db_path.exists());
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let (saved_url, saved_body): (String, String) = conn
            .query_row(
                "SELECT url, body FROM candidates WHERE id = ?1",
                rusqlite::params![summary.candidate_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(saved_url, summary.source_url);
        assert_eq!(saved_body, body);
    }

    /// A request to a non-allowlisted host fails fast at egress
    /// without consuming rate-limit budget — the layering invariant
    /// from Phase 1 still holds when the orchestrator drives.
    #[tokio::test]
    async fn non_allowlisted_host_fails_at_egress() {
        // Server on 127.0.0.1 but the allowlist names a DIFFERENT host.
        let body = "should not be fetched";
        let url = one_shot_server(body).await;

        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        let storage_dir = tmp.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        write_fixture_preset(&preset_dir, &storage_dir, &["allowed.example.com"], &url).unwrap();

        let err = run(OrchestratorConfig {
            preset_dir,
            storage_dir: storage_dir.clone(),
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
        })
        .await
        .unwrap_err();

        match err {
            OrchestratorError::HttpDenied {
                source: HttpAccessDenied::Egress(_),
                ..
            } => {}
            other => panic!("expected HttpDenied(Egress), got {other:?}"),
        }

        // No candidate row should have been written.
        let db_path = storage_dir.join("aggregator.db");
        if db_path.exists() {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            // The schema migration may or may not have run depending on
            // ordering; if the table exists, it must be empty.
            let count: Option<i64> = conn
                .query_row("SELECT COUNT(*) FROM candidates", [], |row| row.get(0))
                .ok();
            assert_eq!(count.unwrap_or(0), 0);
        }
    }

    /// Sanity: aggregator skill missing from the preset is a typed
    /// error, not a panic. Catches future preset edits that drop the
    /// aggregator without updating the orchestrator's expectations.
    #[tokio::test]
    async fn missing_aggregator_skill_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let preset_dir = tmp.path().join("preset");
        std::fs::create_dir_all(preset_dir.join("skills/other")).unwrap();
        std::fs::write(
            preset_dir.join("preset.toml"),
            r#"
[preset]
name = "no-aggregator"
description = "missing aggregator"
version = "0.0.1"
skills = ["other"]
"#,
        )
        .unwrap();
        std::fs::write(
            preset_dir.join("skills/other/SKILL.md"),
            "---\nname: other\ndescription: x\ndisable-model-invocation: false\npermissions: {}\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(
            preset_dir.join("sources.toml"),
            "[[source]]\nname=\"x\"\nhost=\"x\"\nmethod=\"x\"\nendpoint=\"http://x\"\n",
        )
        .unwrap();

        let storage = tmp.path().join("storage");
        std::fs::create_dir_all(&storage).unwrap();

        let err = run(OrchestratorConfig {
            preset_dir,
            storage_dir: storage,
            rate_limit: RateLimitConfig::unrestricted_for_tests(),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, OrchestratorError::AggregatorSkillMissing));
    }

    // Suppress unused-import warning when skill_perms isn't otherwise used.
    #[allow(dead_code)]
    fn _force_link() -> Arc<()> {
        Arc::new(())
    }
}
