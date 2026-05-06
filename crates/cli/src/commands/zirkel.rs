//! `wirken zirkel` subcommands.
//!
//! Entry point for the Zirkel orchestrator. Both the cron-fired and
//! the manual run path call into here. The C-foundation slice loops
//! every source in `sources.toml`, dispatches RSS/Atom through the
//! policed transport, dedups against the seen table, screens with
//! the user's interests file, and writes kept items to the per-skill
//! SQLite. LLM relevance scoring, clustering, theme naming, and
//! digest push are subsequent Scope C slices.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use rusqlite::Connection;
use wirken_agent::llm::{LlmClient, LlmConfig};
use wirken_agent::rate_limit::RateLimitConfig;
use wirken_audit::{SessionLog, SqliteSessionLog};
use wirken_zirkel::binding::{
    Binding, load as load_binding_for, load_first as load_binding, record as record_binding,
    remove as remove_binding,
};
use wirken_zirkel::digest::{RenderOptions, load_run as load_digest_run, render as render_digest};
use wirken_zirkel::digest_log::record_sent;
use wirken_zirkel::embedding::DEFAULT_EMBEDDING_MODEL;
use wirken_zirkel::orchestrator::{OrchestratorConfig, run as orchestrator_run};
#[cfg(unix)]
use wirken_zirkel::push_client::{PushError, push as push_to_gateway};
use wirken_zirkel::schema::AGGREGATOR_MIGRATIONS;

/// `wirken zirkel run` — load the installed Zirkel preset, run the
/// daily fetch + screen pipeline, exit.
pub async fn run() -> Result<()> {
    let data_dir = super::data_dir()?;
    let preset_dir = data_dir.join("presets").join("zirkel");
    if !preset_dir.join("preset.toml").exists() {
        return Err(anyhow!(
            "Zirkel preset is not installed at {}; run `wirken preset install zirkel` first",
            preset_dir.display(),
        ));
    }

    // Storage lives at <data_dir>/zirkel/. Must be inside the
    // aggregator skill's filesystem.write_paths allow-set.
    let storage_dir = data_dir.join("zirkel");
    std::fs::create_dir_all(&storage_dir)?;
    let interests_path = storage_dir.join("interests.toml");
    if !interests_path.exists() {
        return Err(anyhow!(
            "interests file not found at {}. Create it with `keywords = [...]` and \
             optional `exclusions = [...]` before running.",
            interests_path.display()
        ));
    }

    // Wirken's session-log SQLite is the audit chain. Open it as a
    // thread-safe trait object so the orchestrator's HttpFetch /
    // CandidateScored / CandidateSkipped events join the same chain
    // the agent runtime writes to.
    let audit_path = data_dir.join("audit.db");
    let session_log: Arc<dyn SessionLog> = Arc::new(
        SqliteSessionLog::open(&audit_path)
            .map_err(|e| anyhow!("open audit log at {}: {e}", audit_path.display()))?,
    );

    // LLM defaults per docs/zirkel/DESIGN.md: Ollama llama3.1:8b for
    // scoring + theme naming, nomic-embed-text:v1.5 for embedding.
    // Both at the local Ollama base URL.
    let llm_cfg = LlmConfig::ollama("llama3.1:8b");
    let llm = Arc::new(LlmClient::new(llm_cfg).map_err(|e| anyhow!("construct LLM client: {e}"))?);

    // Resolve api.data.gov keys for keyed sources from the vault.
    // The orchestrator runs as the operator's UID and reads the
    // vault directly; the keys never reach the agent / LLM layer.
    // Sources without a key in the vault are recorded as
    // unsupported by the orchestrator with a clear message.
    let source_api_keys = resolve_zirkel_source_api_keys(&data_dir);

    let summary = orchestrator_run(OrchestratorConfig {
        preset_dir,
        storage_dir,
        interests_path,
        rate_limit: RateLimitConfig::default(),
        session_log: Some(session_log),
        llm: Some(llm),
        llm_api_key: None,
        ollama_embed_base: "http://127.0.0.1:11434".to_string(),
        embed_model: DEFAULT_EMBEDDING_MODEL.to_string(),
        source_api_keys,
        // Perspective expansion is opt-in. The CLI does not yet
        // surface a flag for it; until a CLI knob lands, the
        // librarian path runs identically to the pre-perspective
        // build (no expansion, no expansion_id, no audit variant).
        perspectives_enabled: false,
        topic: None,
        max_perspectives: 0,
        max_related_topics: 0,
        per_topic_fanout_cap: 0,
        wikipedia_api_base: None,
    })
    .await
    .map_err(|e| anyhow!("zirkel orchestrator: {e}"))?;

    println!("Zirkel run complete (run_id: {}):", summary.run_id);
    println!("  sources attempted:   {}", summary.sources_attempted);
    println!("  sources succeeded:   {}", summary.sources_succeeded);
    if !summary.sources_unsupported.is_empty() {
        println!(
            "  sources unsupported: {}",
            summary.sources_unsupported.join(", ")
        );
    }
    if !summary.sources_failed.is_empty() {
        println!("  sources failed:      {}", summary.sources_failed.len());
        for failure in &summary.sources_failed {
            println!("    - {}: {}", failure.source, failure.reason);
        }
    }
    println!("  items seen:          {}", summary.items_seen);
    println!("  items new:           {}", summary.items_new);
    println!("  items excluded:      {}", summary.items_excluded);
    println!("  items score 0:       {}", summary.items_score_zero);
    println!("  items kept:          {}", summary.items_kept);
    println!("  items LLM-scored:    {}", summary.items_llm_scored);
    println!("  themes named:        {}", summary.themes_named);
    if !summary.llm_score_failures.is_empty() {
        println!(
            "  LLM scoring failures: {}",
            summary.llm_score_failures.len()
        );
    }
    if !summary.theme_stage_failures.is_empty() {
        println!(
            "  theme stage failures: {}",
            summary.theme_stage_failures.len()
        );
    }
    if summary.interests_changed {
        println!("  interests changed:   yes (audit event emitted)");
    }

    // ----- Digest push (C-Signal piece 4) ----------------------------
    //
    // If the operator has bound a target via `wirken zirkel bind`,
    // render the run's candidates and push to the gateway. No
    // binding = no push (and no warning — this is the legitimate
    // headless-test-fetch path).
    //
    // Push first, record the digest second: a failed push must not
    // leave a phantom digest_log entry that the keep/skip
    // interceptor would later resolve against an unsent message.
    let cfg = super::config();
    let zirkel_db = data_dir.join("zirkel").join("aggregator.db");
    if zirkel_db.exists() {
        let conn = Connection::open(&zirkel_db)
            .map_err(|e| anyhow!("open zirkel db at {}: {e}", zirkel_db.display()))?;
        match load_binding(&conn).map_err(|e| anyhow!("load binding: {e}"))? {
            Some(binding) => {
                println!();
                #[cfg(unix)]
                push_digest_for_run(
                    &cfg.socket_dir().join("orchestrator.sock"),
                    &zirkel_db,
                    &summary.run_id,
                    &binding,
                )
                .await?;
                #[cfg(not(unix))]
                {
                    let _ = (&cfg, &zirkel_db, &summary.run_id, &binding);
                    println!(
                        "  Digest push skipped: orchestrator-push is Linux/macOS only on this platform."
                    );
                }
            }
            None => {
                println!();
                println!(
                    "  (no zirkel binding found; skipping digest push — run `wirken zirkel bind` to enable)"
                );
            }
        }
    }
    Ok(())
}

/// `wirken zirkel bind` — record (or replace, with `--force`) the
/// digest target for `agent_id`.
pub async fn bind(agent_id: &str, channel: &str, conversation: &str, force: bool) -> Result<()> {
    let conn = open_zirkel_db()?;
    let new = Binding {
        agent_id: agent_id.into(),
        channel: channel.into(),
        conversation_id: conversation.into(),
    };

    match load_binding_for(&conn, agent_id).map_err(|e| anyhow!("load binding: {e}"))? {
        Some(existing) if existing == new => {
            println!(
                "Already bound: agent '{}' → channel '{}' / conversation '{}'. No-op.",
                existing.agent_id, existing.channel, existing.conversation_id
            );
            return Ok(());
        }
        Some(existing) if !force => {
            return Err(anyhow!(
                "agent '{}' is already bound to channel '{}' / conversation '{}'. \
                 Re-run with --force to replace.",
                existing.agent_id,
                existing.channel,
                existing.conversation_id,
            ));
        }
        _ => {}
    }

    record_binding(&conn, &new).map_err(|e| anyhow!("record binding: {e}"))?;
    println!(
        "Bound: agent '{}' → channel '{}' / conversation '{}'.",
        new.agent_id, new.channel, new.conversation_id
    );

    // Live-rebind detection: the keep/skip interceptor is attached
    // to the agent at daemon startup (when `wirken run` builds its
    // factory). A bind written while the daemon is up does not
    // retroactively reach already-running agents — the interceptor
    // is part of the agent's construction, not a hot-pluggable
    // resource. Detecting the gateway socket is a best-effort
    // signal that a daemon is running on this data dir.
    let cfg = super::config();
    let gateway_socket = cfg.socket_dir().join("gateway.sock");
    if gateway_socket.exists() {
        println!();
        println!(
            "Note: `wirken run` is currently up. Restart it for the new binding to take effect — \
             the keep/skip interceptor is attached at agent startup."
        );
    }
    Ok(())
}

/// `wirken zirkel unbind` — remove the binding for `agent_id`.
pub async fn unbind(agent_id: &str) -> Result<()> {
    let conn = open_zirkel_db()?;
    let existing = load_binding_for(&conn, agent_id).map_err(|e| anyhow!("load binding: {e}"))?;
    remove_binding(&conn, agent_id).map_err(|e| anyhow!("remove binding: {e}"))?;
    match existing {
        Some(b) => println!(
            "Unbound: agent '{}' (was channel '{}' / conversation '{}').",
            b.agent_id, b.channel, b.conversation_id
        ),
        None => println!("Agent '{agent_id}' had no binding; no-op."),
    }
    Ok(())
}

/// `wirken zirkel status` — print the current binding (if any).
pub async fn status() -> Result<()> {
    let zirkel_db = super::data_dir()?.join("zirkel").join("aggregator.db");
    if !zirkel_db.exists() {
        println!(
            "No zirkel state at {} — nothing bound.",
            zirkel_db.display()
        );
        return Ok(());
    }
    let conn =
        Connection::open(&zirkel_db).map_err(|e| anyhow!("open {}: {e}", zirkel_db.display()))?;
    match wirken_zirkel::binding::list_all(&conn)
        .map_err(|e| anyhow!("list bindings: {e}"))?
        .as_slice()
    {
        [] => println!("No zirkel digest binding. Run `wirken zirkel bind` to set one."),
        rows => {
            println!("Zirkel digest bindings:");
            for b in rows {
                println!(
                    "  agent '{}' → channel '{}' / conversation '{}'",
                    b.agent_id, b.channel, b.conversation_id
                );
            }
        }
    }
    Ok(())
}

/// Open `<data_dir>/zirkel/aggregator.db`, creating the dir and
/// running migrations idempotently. The bind command may run before
/// `wirken zirkel run` has ever fired, so it can't assume the
/// migrations are in place.
fn open_zirkel_db() -> Result<Connection> {
    let data_dir = super::data_dir()?;
    let storage_dir = data_dir.join("zirkel");
    std::fs::create_dir_all(&storage_dir)
        .map_err(|e| anyhow!("create {}: {e}", storage_dir.display()))?;
    let db_path = storage_dir.join("aggregator.db");
    let mut conn =
        Connection::open(&db_path).map_err(|e| anyhow!("open {}: {e}", db_path.display()))?;
    apply_aggregator_migrations(&mut conn)
        .map_err(|e| anyhow!("apply migrations to {}: {e}", db_path.display()))?;
    Ok(conn)
}

/// `wirken zirkel auth-set --source <name>` — interactive prompt
/// for an api.data.gov key, validate against the source's API,
/// store in the wirken vault.
///
/// Validation policy: 200 → store; 401/403 → reject without
/// storing (typo caught at entry); other HTTP error or network
/// error → warn and store anyway (operator might be airgapped or
/// hitting a transient blip; storing-conditional-on-network would
/// trap them at setup).
pub async fn auth_set(source: &str) -> Result<()> {
    let validator = match source {
        "congress-gov" => SourceAuthValidator::Congress,
        "govinfo-gov" => SourceAuthValidator::GovInfo,
        other => {
            return Err(anyhow!(
                "unknown zirkel source '{other}'. Known sources: congress-gov, govinfo-gov"
            ));
        }
    };

    let key = dialoguer::Password::new()
        .with_prompt(format!("  API key for {source}"))
        .interact()
        .map_err(|e| anyhow!("read API key: {e}"))?;
    if key.is_empty() {
        return Err(anyhow!("empty key"));
    }

    println!("  Validating against {} ...", validator.host());
    match validator.try_key(&key).await {
        AuthValidation::Ok => {
            println!("  ✓ key validates against {}", validator.host());
        }
        AuthValidation::Rejected(status) => {
            return Err(anyhow!(
                "API key rejected by {}: HTTP {status}. Check the key was copied correctly. Not stored.",
                validator.host()
            ));
        }
        AuthValidation::Unreachable(reason) => {
            println!(
                "  ⚠ {} unreachable ({reason}). Key stored unverified — next \
                 `wirken zirkel run` will surface validation errors if the key is invalid.",
                validator.host()
            );
        }
    }

    let cfg = super::config();
    let keychain = wirken_vault::probe_keychain(&cfg.data_dir, || {
        dialoguer::Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .map_err(|e| anyhow!("open credential store: {e}"))?;
    let vault_key_name = format!("zirkel-{source}-api-key");
    store
        .store(
            &vault_key_name,
            "zirkel",
            &wirken_vault::VaultSecret::new(key),
            None,
            None,
        )
        .map_err(|e| anyhow!("store '{vault_key_name}': {e}"))?;

    println!("  Stored as '{vault_key_name}' in the wirken vault.");
    Ok(())
}

/// `wirken zirkel auth-list` — print the names of zirkel-bound
/// vault entries (no values). Helpful for confirming a key is
/// configured before running.
pub async fn auth_list() -> Result<()> {
    let cfg = super::config();
    if !cfg.vault_db_path().exists() {
        println!("No vault. Run `wirken zirkel auth-set --source <name>` to create one.");
        return Ok(());
    }
    let keychain = wirken_vault::probe_keychain(&cfg.data_dir, || {
        dialoguer::Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let store = wirken_vault::CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .map_err(|e| anyhow!("open credential store: {e}"))?;
    let entries = store.list().map_err(|e| anyhow!("list vault: {e}"))?;
    let zirkel: Vec<_> = entries
        .iter()
        .filter(|e| e.name.starts_with("zirkel-") && e.name.ends_with("-api-key"))
        .collect();
    if zirkel.is_empty() {
        println!(
            "No zirkel API keys stored. Configure with `wirken zirkel auth-set --source <name>`."
        );
        return Ok(());
    }
    println!("Zirkel API keys:");
    for e in zirkel {
        let source = e
            .name
            .strip_prefix("zirkel-")
            .and_then(|s| s.strip_suffix("-api-key"))
            .unwrap_or(&e.name);
        println!("  {source} (stored {})", e.created_at.format("%Y-%m-%d"));
    }
    Ok(())
}

/// Per-source validation target. Each variant knows its host (for
/// human-readable messages) and a minimal endpoint that costs one
/// request against the operator's quota.
enum SourceAuthValidator {
    Congress,
    GovInfo,
}

enum AuthValidation {
    Ok,
    /// 401 / 403 — the API definitively rejected the key.
    Rejected(u16),
    /// Anything else: network error, 5xx, timeout. Ambiguous —
    /// the key might be correct but the host is briefly unreachable.
    Unreachable(String),
}

impl SourceAuthValidator {
    fn host(&self) -> &'static str {
        match self {
            Self::Congress => "api.congress.gov",
            Self::GovInfo => "api.govinfo.gov",
        }
    }

    fn validation_url(&self) -> &'static str {
        match self {
            // Smallest valid request — limit=1 keeps the response
            // body tiny while still exercising the auth path.
            Self::Congress => "https://api.congress.gov/v3/bill?limit=1&format=json",
            Self::GovInfo => "https://api.govinfo.gov/collections?offsetMark=*&pageSize=1",
        }
    }

    async fn try_key(&self, key: &str) -> AuthValidation {
        // Direct reqwest, not the policed EgressClient — auth-set
        // is operator-side setup, not agent-side. The host is
        // well-known and the request is one-shot.
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(e) => return AuthValidation::Unreachable(format!("client build: {e}")),
        };
        let resp = client
            .get(self.validation_url())
            .header("X-Api-Key", key)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                if r.status().is_success() {
                    AuthValidation::Ok
                } else if status == 401 || status == 403 {
                    AuthValidation::Rejected(status)
                } else {
                    AuthValidation::Unreachable(format!("HTTP {status}"))
                }
            }
            Err(e) => AuthValidation::Unreachable(format!("network: {e}")),
        }
    }
}

/// Read the wirken vault and return a map of zirkel-bound source
/// names → api keys. Vault entries follow the convention
/// `zirkel-<source>-api-key`. Sources whose entry is absent or
/// whose retrieve fails simply don't end up in the map; the
/// orchestrator skips those fetcher registrations and surfaces
/// "method not registered" if sources.toml references them.
///
/// The vault open path silently returns an empty map if no vault
/// is configured — `wirken zirkel run` is allowed to fire on a
/// host with only public RSS / Federal Register sources, and
/// requiring an empty vault to exist would be a footgun.
fn resolve_zirkel_source_api_keys(
    data_dir: &std::path::Path,
) -> std::collections::HashMap<String, String> {
    use wirken_vault::{CredentialStore, probe_keychain};
    let mut out = std::collections::HashMap::new();

    let vault_db = data_dir.join("vault.db");
    if !vault_db.exists() {
        return out;
    }

    let keychain = probe_keychain(data_dir, String::new);
    let Ok(store) = CredentialStore::open(&vault_db, keychain.as_ref()) else {
        tracing::debug!("zirkel: vault.db present but could not be opened");
        return out;
    };

    // Well-known keyed sources. Adding a new keyed source means
    // adding a row here plus its fetcher registration in
    // wirken-zirkel's orchestrator.
    let sources = [
        ("congress-gov", "zirkel-congress-gov-api-key"),
        ("govinfo-gov", "zirkel-govinfo-gov-api-key"),
    ];
    for (source_name, vault_key) in sources {
        if let Ok((secret, _)) = store.retrieve(vault_key) {
            out.insert(source_name.to_string(), secret.expose().to_string());
        }
    }
    out
}

/// Idempotent migration application — same shape SkillStore uses.
/// Replicated here to avoid pulling the SkillStore + permissions
/// path into the bind command, which has nothing to do with skill
/// permissions.
fn apply_aggregator_migrations(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations ( \
            idx INTEGER PRIMARY KEY, \
            applied_at TEXT NOT NULL DEFAULT (datetime('now')) \
        )",
    )?;
    let already: std::collections::BTreeSet<i64> = {
        let mut stmt = conn.prepare("SELECT idx FROM _migrations")?;
        stmt.query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<_, _>>()?
    };
    let tx = conn.transaction()?;
    for (idx, sql) in AGGREGATOR_MIGRATIONS.iter().enumerate() {
        let idx_i64 = idx as i64;
        if already.contains(&idx_i64) {
            continue;
        }
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO _migrations (idx) VALUES (?1)",
            rusqlite::params![idx_i64],
        )?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(unix)]
async fn push_digest_for_run(
    orchestrator_socket: &std::path::Path,
    zirkel_db: &std::path::Path,
    run_id: &str,
    binding: &Binding,
) -> Result<()> {
    let mut conn = Connection::open(zirkel_db)
        .map_err(|e| anyhow!("open zirkel db at {}: {e}", zirkel_db.display()))?;
    let (rows, themes) =
        load_digest_run(&conn, run_id).map_err(|e| anyhow!("load digest rows: {e}"))?;
    if rows.is_empty() {
        println!("  Digest: no candidates this run; nothing to push.");
        return Ok(());
    }
    let opts = RenderOptions {
        date: Some(chrono::Local::now().format("%Y-%m-%d").to_string()),
        ..RenderOptions::default()
    };
    let rendered =
        render_digest(&rows, &themes, &opts).map_err(|e| anyhow!("render digest: {e}"))?;

    println!(
        "  Digest: {} item{} → channel '{}' / conversation '{}'",
        rendered.ordered_candidate_ids.len(),
        if rendered.ordered_candidate_ids.len() == 1 {
            ""
        } else {
            "s"
        },
        binding.channel,
        binding.conversation_id,
    );

    match push_to_gateway(
        orchestrator_socket,
        &binding.channel,
        &binding.conversation_id,
        &rendered.text,
    )
    .await
    {
        Ok(()) => {
            // Record only after the gateway accepted the push.
            record_sent(
                &mut conn,
                run_id,
                &binding.agent_id,
                &rendered.ordered_candidate_ids,
            )
            .map_err(|e| anyhow!("record digest: {e}"))?;
            println!("  Digest pushed.");
            Ok(())
        }
        Err(PushError::Connect { path, .. }) => {
            println!(
                "  Digest push skipped: gateway socket {} not reachable. Is `wirken run` started?",
                path
            );
            Ok(())
        }
        Err(PushError::Rejected(msg)) => {
            // The gateway is up but couldn't deliver — most often
            // the bound channel's adapter isn't connected. Surface
            // but don't fail the whole run.
            println!("  Digest push rejected by gateway: {msg}");
            Ok(())
        }
        Err(e) => Err(anyhow!("digest push failed: {e}")),
    }
}
