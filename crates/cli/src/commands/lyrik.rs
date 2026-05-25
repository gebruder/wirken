//! `wirken lyrik run` and `wirken lyrik report` subcommands.
//!
//! `run` drives the Lyrik phases against a target directory and writes
//! findings.json plus a per-stage audit log under
//! `<target>/.lyrik/state/runs/<run-id>/`.
//!
//! `report` reads findings.json and emits SARIF via
//! [`super::lyrik_sarif::build_sarif`].

use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use wirken_agent::Agent;
use wirken_agent::AgentError;
use wirken_agent::llm::LlmConfig;
use wirken_agent::recovery::RecoveryObserver;
use wirken_gateway::permissions::PermissionStore;
use wirken_vault::{CredentialStore, probe_keychain};

use super::lyrik_semgrep::{
    self, DispatchOutcome, Seed, parse_scanner_config, write_bundled_ruleset, write_seed_files,
};
use super::lyrik_walks::{
    build_walk_prompt, default_walks_source_dir, ensure_walk_staging, parse_walks_config,
    stage_walk_skills,
};

const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// `wirken lyrik run`
// ---------------------------------------------------------------------------

/// Drive Lyrik phases against the target directory.
///
/// `run_id` supports nested form `<sample>/run-<N>`; the slash becomes
/// a directory level under `.lyrik/state/runs/`.
///
/// `use_fixture`, when supplied, skips the agent-runtime skill dispatch
/// and copies the fixture findings.json into the run-state directory.
/// Required until the agent dispatch is wired (slice 7b2).
pub async fn run(target: &Path, run_id: &str, use_fixture: Option<&Path>) -> Result<()> {
    if !target.is_dir() {
        anyhow::bail!("target is not a directory: {}", target.display());
    }
    let config_path = target.join(".lyrik").join("config.json");
    if !config_path.exists() {
        anyhow::bail!(
            "missing {} (see wirken/docs/lyrik.md for the schema)",
            config_path.display()
        );
    }

    let config_body = std::fs::read_to_string(&config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let config: serde_json::Value = serde_json::from_str(&config_body)
        .with_context(|| format!("parse {}", config_path.display()))?;
    let bench_mode = config
        .get("bench_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let run_dir = target
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run_id);
    std::fs::create_dir_all(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;

    let mut audit = AuditLogger::open(&run_dir.join("audit.log"), run_id, bench_mode)?;

    audit.emit(
        "lyrik.run.started",
        serde_json::json!({
            "target": target.display().to_string(),
            "config_path": config_path.display().to_string(),
            "bench_mode": bench_mode,
            "driver_version": DRIVER_VERSION,
        }),
    )?;

    // Phase 0 sign-off. Bench mode auto-approves; production routes to
    // the configured channel adapter (not yet wired in this slice).
    if bench_mode {
        audit.emit(
            "lyrik.phase_0.signoff",
            serde_json::json!({"decision": "auto_bench"}),
        )?;
    } else {
        audit.emit(
            "lyrik.phase_0.signoff",
            serde_json::json!({"decision": "pending_adapter_route"}),
        )?;
        anyhow::bail!(
            "non-bench mode gate routing not yet wired in the runner; \
             set `bench_mode: true` in {} for now",
            config_path.display()
        );
    }

    // Skill dispatch. Default path: invoke the wirken Agent runtime
    // against the model pin in the target's .lyrik/config.json and
    // run the Lyrik skill phases end-to-end. The fixture path remains
    // for CI reproduction without spending tokens.
    let findings_dest = run_dir.join("findings.json");
    match use_fixture {
        Some(fixture) => {
            let body = std::fs::read_to_string(fixture)
                .with_context(|| format!("read fixture {}", fixture.display()))?;
            // Targeted byte-level rewrite of the top-level run_id value.
            // Round-tripping through serde_json::Value reorders keys
            // (BTreeMap shape); we want the destination byte-identical to
            // the fixture except for the run_id value, so the slice's
            // reproduction acceptance check passes.
            let rewritten = rewrite_top_level_run_id(&body, run_id)?;
            std::fs::write(&findings_dest, rewritten)
                .with_context(|| format!("write {}", findings_dest.display()))?;
            audit.emit(
                "lyrik.dispatch",
                serde_json::json!({
                    "mode": "fixture",
                    "fixture": fixture.display().to_string(),
                    "findings_path": findings_dest.display().to_string(),
                }),
            )?;
        }
        None => {
            dispatch_via_agent_runtime(target, run_id, &config, &mut audit, &findings_dest).await?;
        }
    }

    // High-severity review. Bench mode auto-approves at delivery time;
    // here the runner records the decision so consumers can distinguish
    // bench from production.
    if bench_mode {
        audit.emit(
            "lyrik.high_severity_review.signoff",
            serde_json::json!({"decision": "auto_bench"}),
        )?;
    }

    audit.emit(
        "lyrik.run.completed",
        serde_json::json!({
            "findings_path": findings_dest.display().to_string(),
            "run_state_dir": run_dir.display().to_string(),
        }),
    )?;

    println!("findings written to {}", findings_dest.display());
    println!("audit log at {}", run_dir.join("audit.log").display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent-runtime dispatch
// ---------------------------------------------------------------------------

/// Translates [`wirken_agent::recovery::RecoveryObserver`] hooks into
/// audit records on the lyrik run's audit.log. The audit handle is
/// independent of the runner's primary `AuditLogger` (a `try_clone()`
/// of the same file) so the observer can write while the dispatch
/// holds `&mut agent`.
struct LyrikRecoveryObserver {
    audit: Mutex<AuditLogger>,
}

impl RecoveryObserver for LyrikRecoveryObserver {
    fn on_rate_limited(&self, attempt: u32, retry_after_ms: u64, status: u16) {
        if let Ok(mut a) = self.audit.lock() {
            let _ = a.emit(
                "lyrik.dispatch.rate_limited",
                serde_json::json!({
                    "attempt": attempt,
                    "retry_after_ms": retry_after_ms,
                    "status": status,
                }),
            );
        }
    }
    fn on_rate_limit_exhausted(&self, attempts: u32) {
        if let Ok(mut a) = self.audit.lock() {
            let _ = a.emit(
                "lyrik.dispatch.failed",
                serde_json::json!({
                    "reason": "rate_limit_exhausted",
                    "attempts": attempts,
                }),
            );
        }
    }
    fn on_tool_validation_failed(&self, tool: &str, attempt: u32, message: &str) {
        if let Ok(mut a) = self.audit.lock() {
            let _ = a.emit(
                "lyrik.tool.validation_failed",
                serde_json::json!({
                    "tool": tool,
                    "attempt": attempt,
                    "message": message,
                }),
            );
        }
    }
    fn on_tool_validation_exhausted(&self, tool: &str, attempts: u32) {
        if let Ok(mut a) = self.audit.lock() {
            let _ = a.emit(
                "lyrik.tool.failed",
                serde_json::json!({
                    "tool": tool,
                    "attempts": attempts,
                }),
            );
        }
    }
}

/// Write a canonical empty `findings.json` to `path`. Called when
/// dispatch failed before the agent could produce real findings (today:
/// rate-limit exhaustion). Lets the bench harness count the failure
/// instead of silently losing the run.
fn write_empty_findings(path: &Path, run_id: &str) -> Result<()> {
    let body = serde_json::json!({
        "schema_version": "1.1",
        "run_id": run_id,
        "produced_at": chrono::Utc::now().to_rfc3339(),
        "findings": [],
    });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write empty findings to {}", path.display()))?;
    Ok(())
}

/// Dispatch the Lyrik skill via wirken's Agent runtime. Reads the
/// model pin from the target's `.lyrik/config.json` (preferring
/// `phases.framing`, falling back to `phases.score`/`phases.recon`),
/// builds an Agent with workspace = target, loads bundled skills
/// from `<data_dir>/skills/`, and sends the assessment prompt.
async fn dispatch_via_agent_runtime(
    target: &Path,
    run_id: &str,
    config: &serde_json::Value,
    audit: &mut AuditLogger,
    expected_findings: &Path,
) -> Result<()> {
    // Per-walk parallelism opt-in. Parsed and validated here so a
    // misconfigured walks list fails before any LLM call. The
    // one-call slice (no `walks` field in config) keeps the
    // existing single-prompt /lyrik dispatch path.
    let walks_source_dir = default_walks_source_dir();
    let walks_cfg = parse_walks_config(config, &walks_source_dir).context("parse walks config")?;

    // Opt-in pre-LLM scanner dispatch. Default off; an absent or
    // false `scanner.semgrep.enabled` field means zero behavioural
    // change. Enabled runs that find the pinned binary materialise
    // dataflow seeds the model rules on; absent binary / version
    // mismatch / parse failure degrade-and-log (the runner pin is
    // the contract, mismatched binary on PATH is unavailable).
    let run_dir = target
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run_id);
    let scanner_cfg = parse_scanner_config(config).context("parse scanner config")?;
    let seeds: Vec<Seed> = if scanner_cfg.semgrep_enabled {
        let ruleset_path =
            write_bundled_ruleset(&run_dir).context("materialise bundled semgrep ruleset")?;
        match lyrik_semgrep::dispatch_semgrep(target, &ruleset_path) {
            DispatchOutcome::Dispatched {
                version,
                ruleset_sha,
                seeds,
            } => {
                write_seed_files(&run_dir, &seeds).context("write seed files")?;
                audit.emit(
                    "lyrik.scanner.dispatched",
                    serde_json::json!({
                        "tool": "semgrep",
                        "version": version,
                        "ruleset_url": lyrik_semgrep::RULESET_URL,
                        "ruleset_sha": ruleset_sha,
                        "target": target.display().to_string(),
                        "seed_count": seeds.len(),
                    }),
                )?;
                seeds
            }
            DispatchOutcome::Unavailable { reason, detail } => {
                tracing::warn!(
                    reason = %reason,
                    "lyrik scanner unavailable; proceeding with LLM-only scanning"
                );
                audit.emit(
                    "lyrik.scanner.unavailable",
                    serde_json::json!({
                        "tool": "semgrep",
                        "reason": reason,
                        "detail": detail,
                    }),
                )?;
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let seeds_present = !seeds.is_empty();

    let pin = resolve_phase_pin(config)?;
    let mut llm_config = LlmConfig::from_provider(&pin.provider, &pin.base_url, &pin.model);
    if let Some(cw) = pin.context_window {
        llm_config.context_window = cw as usize;
    }

    let cfg = super::config();

    // Slot name the api_key was resolved from. Stamped on every
    // `LlmRequest` / `LlmResponse` for SIEM correlation. `None` for
    // ollama (no vault lookup).
    let mut api_key_credential: Option<String> = None;
    let api_key = if pin.provider != "ollama" {
        let pp = super::cached_vault_passphrase()?;
        let keychain = probe_keychain(&cfg.data_dir, move || pp);
        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("open credential store")?;
        let cred_name = format!("{}-api-key", pin.provider);
        match store.retrieve(&cred_name) {
            Ok((secret, _)) => {
                api_key_credential = Some(cred_name.clone());
                Some(secret.expose().to_string())
            }
            Err(e) => anyhow::bail!(
                "API key '{cred_name}' missing from vault: {e}; \
                 add it with `wirken credentials add {cred_name}` \
                 or change the target's .lyrik/config.json pin"
            ),
        }
    } else {
        None
    };

    // Inherit the gateway's signed audit chain. ChainHead records
    // bracket the run: the SessionStart head fires implicitly on
    // the first append by the Agent runtime; the runner emits an
    // explicit SessionEnd head after every walk turn returns. All
    // walk turns share the same session_id (the per-run agent id)
    // so they land in one signed chain.
    let audit_signer = match wirken_audit::AuditSigningKey::load_or_create(&cfg.data_dir) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "lyrik run will use an unsigned audit chain: could not load or generate \
                 the gateway audit signing key"
            );
            None
        }
    };
    let session_log_concrete: Arc<wirken_audit::SqliteSessionLog> =
        Arc::new(match audit_signer.clone() {
            Some(s) => wirken_audit::SqliteSessionLog::open_with_signer(&cfg.audit_db_path(), s)
                .context("open session log with signer")?,
            None => wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
                .context("open session log")?,
        });
    let session_log: Arc<dyn wirken_audit::SessionLog> = session_log_concrete.clone();

    let agent_id = format!("lyrik-{}", run_id.replace('/', "-"));

    // Workspace for the agent IS the target. The agent reads source
    // files from there and writes findings.json back into the target's
    // `.lyrik/state/runs/<run-id>/` per the Lyrik skill instructions.
    let mut agent = Agent::new_with_sandbox(
        agent_id.clone(),
        target.to_path_buf(),
        llm_config.clone(),
        api_key.clone(),
        api_key_credential.clone(),
        session_log.clone(),
        super::load_sandbox_config(&cfg.data_dir),
    )?;

    let perms =
        PermissionStore::open(&cfg.permissions_db_path()).context("open permission store")?;
    let perms_arc = Arc::new(Mutex::new(perms));
    agent.set_permissions(perms_arc.clone());

    let skills_dir = cfg.data_dir.join("skills");
    let skills_loaded = if skills_dir.is_dir() {
        match agent.load_skills(&skills_dir) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("load_skills({}) failed: {e}", skills_dir.display());
                0
            }
        }
    } else {
        0
    };

    // When per-walk dispatch is enabled, stage the selected walk
    // SKILLs under the run directory with synthesized wirken
    // frontmatter, then merge them into the agent's loaded skills.
    // Each walk becomes a `/<walk-name>` slash invocation with the
    // operator's installed body intact.
    let walks_staged_dir = match walks_cfg.as_ref() {
        Some(wc) => {
            ensure_walk_staging(&run_dir, &wc.walks).context("ensure per-walk staging dirs")?;
            let staged = stage_walk_skills(&wc.walks, &walks_source_dir, &run_dir)
                .context("stage walk skills")?;
            agent
                .extend_skills(&staged)
                .with_context(|| format!("extend agent skills from {}", staged.display()))?;
            Some(staged)
        }
        None => None,
    };

    audit.emit(
        "lyrik.dispatch.started",
        serde_json::json!({
            "mode": match walks_cfg.as_ref() {
                Some(_) => "per_walk",
                None => "agent_runtime",
            },
            "provider": pin.provider,
            "model": pin.model,
            "base_url": pin.base_url,
            "skills_dir": skills_dir.display().to_string(),
            "skills_loaded": skills_loaded,
            "walks_staged_dir": walks_staged_dir.as_ref().map(|p| p.display().to_string()),
            "walks": walks_cfg.as_ref().map(|c| c.walks.clone()),
            "max_concurrent_walks": walks_cfg.as_ref().map(|c| c.max_concurrent_walks),
            "workspace": target.display().to_string(),
        }),
    )?;

    // agent-runtime-error-recovery: register a recovery observer so
    // 429 retries and tool-validation failures land in the same audit
    // log as the rest of the run. The observer carries a separate
    // AuditLogger handle that appends to the same file (the file is
    // opened with append=true; concurrent writers are safe at the
    // line granularity of single `writeln!` calls).
    let observer_audit = AuditLogger {
        file: audit.file.try_clone().context("clone audit file handle")?,
        run_id: audit.run_id.clone(),
        bench_mode: audit.bench_mode,
    };
    let observer: Arc<dyn RecoveryObserver> = Arc::new(LyrikRecoveryObserver {
        audit: Mutex::new(observer_audit),
    });
    agent.set_recovery_observer(observer);

    // Dispatch. Two paths:
    //   - per_walk: one agent turn per selected walk, serial in
    //     commit 1; concurrent in commit 2. Each walk emits to its
    //     own staging/<walk-name>/ subtree, the runner aggregates
    //     across walks below.
    //   - one_call: the existing single /lyrik turn covers both
    //     framings inside one prompt. Unchanged behaviour for
    //     operators who haven't opted into walks.
    let total_response_len: usize;
    let total_denials: usize;
    let walk_outcomes: Option<Vec<WalkOutcome>>;
    match walks_cfg.as_ref() {
        Some(wc) => {
            // Build per-spawn dependencies. Each walk constructs its
            // own Agent (different LLM conversation, different tool
            // state) but shares the run-level session_id, the
            // session log, the permission store, the recovery
            // observer, and the LLM config. Sharing the session_id
            // is what makes "one session, N walk turns" land in a
            // single signed chain.
            let walk_seed_suffix = if seeds_present {
                seed_protocol_text(run_id, Some("<walk>"))
            } else {
                String::new()
            };
            let outcomes = dispatch_walks_concurrent(
                wc.walks.clone(),
                wc.max_concurrent_walks,
                agent_id.clone(),
                target.to_path_buf(),
                run_id.to_string(),
                llm_config.clone(),
                api_key.clone(),
                api_key_credential.clone(),
                session_log.clone(),
                super::load_sandbox_config(&cfg.data_dir),
                perms_arc.clone(),
                skills_dir.clone(),
                walks_staged_dir
                    .clone()
                    .expect("walks_staged_dir is Some when walks_cfg is Some"),
                walk_seed_suffix,
                audit,
            )
            .await?;
            total_response_len = outcomes.iter().map(|o| o.response_len).sum();
            total_denials = outcomes.iter().map(|o| o.denials).sum();
            walk_outcomes = Some(outcomes);
        }
        None => {
            let seed_protocol = if seeds_present {
                seed_protocol_text(run_id, None)
            } else {
                String::new()
            };
            let prompt = format!(
                "/lyrik Run a full assessment on the codebase in this workspace. \
                 Run-id: `{run_id}`. Bench mode is enabled: phase_0_signoff and \
                 high_severity_review auto-approve, do not wait for human signoff. \
                 \
                 Emission is staged. See the SKILL.md \"Staged emission\" \
                 instructions. Findings: write each finding to \
                 `.lyrik/state/runs/{run_id}/staging/findings/finding-NNN.json` \
                 (zero-padded ordinal; one finding per file; rung and deferral \
                 fields required). Phase 0 context: write each section to \
                 `.lyrik/state/runs/{run_id}/staging/context/<NN>-<section>.md`. \
                 Phase 0 rubric: write each tier to \
                 `.lyrik/state/runs/{run_id}/staging/rubric/<NN>-<tier>.md` plus \
                 `00-axes.md`. Do not write `findings.json`, `.lyrik/context.md`, \
                 or `.lyrik/rubric.md` directly. The runner aggregates the \
                 staging directories into the final files after the assessment \
                 turn returns.{seed_protocol}"
            );
            let inbound_id = format!("lyrik-run-{}", uuid::Uuid::new_v4());
            let result = match agent.process_message(&prompt, inbound_id).await {
                Ok(r) => r,
                Err(AgentError::RateLimitExhausted { attempts }) => {
                    tracing::warn!(
                        "rate limit exhausted after {attempts} attempts; \
                         writing empty findings.json"
                    );
                    write_empty_findings(expected_findings, run_id)?;
                    return Ok(());
                }
                Err(e) => {
                    return Err(
                        anyhow::Error::from(e).context("agent.process_message returned an error")
                    );
                }
            };
            total_response_len = result.response.len();
            total_denials = result.denials.len();
            walk_outcomes = None;
        }
    }

    audit.emit(
        "lyrik.dispatch.completed",
        serde_json::json!({
            "mode": match walks_cfg.as_ref() {
                Some(_) => "per_walk",
                None => "agent_runtime",
            },
            "response_len": total_response_len,
            "denials": total_denials,
        }),
    )?;

    // Staged emission aggregation. Each emission has its own
    // `staging/<kind>/` subdirectory. The runner aggregates each in
    // lexicographic order and writes to the canonical destination.
    // Missing or empty staging dirs are skipped: Phase 0 may
    // legitimately emit nothing on subsequent runs (see SKILL.md
    // skip-Phase-0 rule), and `staging/findings/` may be absent if
    // the agent wrote findings.json directly via the legacy
    // single-write path.
    let staging = run_dir.join("staging");
    aggregate_phase0_section(
        &staging.join("context"),
        &target.join(".lyrik").join("context.md"),
    )
    .context("aggregate context")?;
    aggregate_phase0_section(
        &staging.join("rubric"),
        &target.join(".lyrik").join("rubric.md"),
    )
    .context("aggregate rubric")?;
    let mut finding_sources: Vec<(Option<String>, PathBuf)> = Vec::new();
    let top_findings = staging.join("findings");
    if top_findings.is_dir() {
        finding_sources.push((None, top_findings));
    }
    if let Some(wc) = walks_cfg.as_ref() {
        for w in &wc.walks {
            let p = staging.join(w).join("findings");
            if p.is_dir() {
                finding_sources.push((Some(w.clone()), p));
            }
        }
    }
    let seed_locations: std::collections::HashSet<String> = seeds
        .iter()
        .map(|s| format!("{}:{}", s.file, s.line))
        .collect();
    let dedup_active = walks_cfg.is_some();

    // Decline + unaddressed accounting runs before aggregation so it
    // reads the as-staged finding locations and the per-walk
    // staging/<walk?>/declines/ trees while they still exist.
    // aggregate_findings_multi removes consumed staging dirs.
    process_seed_dispositions(
        &staging,
        walks_cfg.as_ref().map(|wc| wc.walks.as_slice()),
        &seeds,
        &finding_sources,
        audit,
    )
    .context("process seed dispositions")?;

    aggregate_findings_multi(
        &finding_sources,
        expected_findings,
        run_id,
        dedup_active,
        &seed_locations,
        target,
        audit,
    )
    .context("aggregate findings")?;
    // remove_dir succeeds only if empty — exactly the semantics we
    // want for cleaning up the parent staging/ once each subdir
    // aggregator has removed its own. A non-empty parent (partial
    // failure or unfamiliar staging contents) is left alone for the
    // operator to inspect.
    let _ = std::fs::remove_dir(&staging);

    // Cap the run with a SessionEnd ChainHead so the signed chain
    // ends on a signature, not an unsigned tail. Loud non-fatal:
    // failure here records an audit row and the verifier surfaces
    // the abnormal close under --require-signed.
    if audit_signer.is_some() {
        let handle = session_log.handle_for(wirken_audit::SessionId::new(agent_id.clone()));
        let session_log_close = session_log_concrete.clone();
        let close_result = tokio::task::spawn_blocking(move || {
            session_log_close.emit_chain_head(&handle, wirken_audit::ChainHeadReason::SessionEnd)
        })
        .await;
        match close_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::error!(error = %e, "lyrik shutdown could not emit SessionEnd ChainHead");
                audit.emit(
                    "lyrik.session_end.failed",
                    serde_json::json!({"error": e.to_string()}),
                )?;
            }
            Err(e) => {
                tracing::error!(error = %e, "SessionEnd emission task panicked");
                audit.emit(
                    "lyrik.session_end.failed",
                    serde_json::json!({"error": e.to_string()}),
                )?;
            }
        }
    }

    if !expected_findings.exists() {
        anyhow::bail!(
            "agent ran but findings.json was not written at {} \
             (skill emits to staging/<walk?>/findings/finding-NNN.json; the \
             runner aggregates them. Neither path produced output. \
             Total response length across turns: {})",
            expected_findings.display(),
            total_response_len
        );
    }

    // Exit-code policy for per-walk dispatch. Permission denial in
    // any walk is operator intent ("don't let this run"), routes to
    // a non-zero exit even when other walks succeeded. All walks
    // failed (transient) is also non-zero. Otherwise zero. The
    // dedup pass writes findings.json unconditionally so a
    // non-zero exit still leaves the partial artifact for review.
    if let Some(outcomes) = walk_outcomes.as_ref() {
        let any_denial = outcomes
            .iter()
            .any(|o| matches!(o.status, WalkStatus::PermissionDenial { .. }));
        let any_success = outcomes
            .iter()
            .any(|o| matches!(o.status, WalkStatus::Success));
        if any_denial {
            let denied_walks: Vec<&str> = outcomes
                .iter()
                .filter(|o| matches!(o.status, WalkStatus::PermissionDenial { .. }))
                .map(|o| o.walk_name.as_str())
                .collect();
            anyhow::bail!(
                "lyrik aborted by permission denial in {} walk(s): {}; \
                 partial findings.json was written for review",
                denied_walks.len(),
                denied_walks.join(", ")
            );
        }
        if !any_success {
            anyhow::bail!(
                "every selected walk failed (transient); see lyrik.walk.completed audit rows"
            );
        }
    }

    Ok(())
}

/// Aggregate one Phase 0 staging directory (context or rubric) into a
/// single markdown file. Empty or missing source directories are
/// no-ops — the destination is left untouched, which preserves any
/// prior `.lyrik/context.md` or `.lyrik/rubric.md` from earlier runs.
/// On success the source directory is removed.
fn aggregate_phase0_section(source: &Path, dest: &Path) -> Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
        .with_context(|| format!("read {}", source.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "md"))
        .collect();
    if entries.is_empty() {
        let _ = std::fs::remove_dir(source);
        return Ok(());
    }
    entries.sort();
    let mut out = String::new();
    for (i, p) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str("\n\n");
        }
        let body = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        out.push_str(body.trim_end());
        out.push('\n');
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(dest, out).with_context(|| format!("write {}", dest.display()))?;
    std::fs::remove_dir_all(source)
        .with_context(|| format!("remove staging dir {}", source.display()))?;
    Ok(())
}

/// Per-walk dispatch outcome. Captured per turn and rolled up into
/// the runner's overall exit decision (commit 2 wires the exit
/// logic). The shape is committed in commit 1 so commit 2's
/// `tokio::spawn` rewrite can collect outcomes from the spawn join
/// handles without changing the surface.
#[derive(Debug, Clone)]
#[allow(dead_code)] // status/response_len/denials drive commit 2's exit policy; walk_name is the dedup_sources tag.
pub(super) struct WalkOutcome {
    pub walk_name: String,
    pub status: WalkStatus,
    pub response_len: usize,
    pub denials: usize,
}

/// Outcome class. The runner collapses any
/// [`WalkStatus::PermissionDenial`] into a non-zero exit; transient
/// failures roll up under "partial success" when at least one walk
/// produced findings (commit 2 wires that policy).
#[derive(Debug, Clone)]
pub(super) enum WalkStatus {
    Success,
    TransientFailure { reason: String },
    PermissionDenial { reason: String },
}

/// Run every selected walk concurrently, gated by a Semaphore
/// with `max_concurrent` permits. Each walk constructs its own
/// Agent (separate LLM conversation, separate tool state) but
/// every Agent is built with the same `agent_id`, which means
/// every walk's events land in the same SessionLog session. The
/// chain stays unbroken across N concurrent appenders because
/// rusqlite serializes writers.
///
/// Per-walk audit rows go through the parent's AuditLogger by
/// returning the records from each spawn; the parent emits them
/// after the join. `lyrik.walk.started` / `lyrik.walk.completed`
/// shape unchanged from the serial baseline.
#[allow(clippy::too_many_arguments)]
async fn dispatch_walks_concurrent(
    walks: Vec<String>,
    max_concurrent: u32,
    agent_id: String,
    target: PathBuf,
    run_id: String,
    llm_config: LlmConfig,
    api_key: Option<String>,
    api_key_credential: Option<String>,
    session_log: Arc<dyn wirken_audit::SessionLog>,
    sandbox: wirken_agent::sandbox::SandboxConfig,
    permissions: Arc<Mutex<PermissionStore>>,
    skills_dir: PathBuf,
    walks_staged_dir: PathBuf,
    // `walk_seed_suffix`: per-walk seed/decline protocol text appended
    // to the prompt when a non-empty seed set was materialised. Empty
    // string when the scanner pass produced no seeds.
    walk_seed_suffix: String,
    audit: &mut AuditLogger,
) -> Result<Vec<WalkOutcome>> {
    use tokio::sync::Semaphore;

    let permits = std::cmp::max(1, std::cmp::min(max_concurrent, walks.len() as u32));
    let sem = Arc::new(Semaphore::new(permits as usize));

    let mut handles: Vec<(String, tokio::task::JoinHandle<WalkOutcome>)> =
        Vec::with_capacity(walks.len());
    for name in walks {
        audit.emit(
            "lyrik.walk.started",
            serde_json::json!({"walk": name, "run_id": run_id}),
        )?;

        let sem_handle = sem.clone();
        let agent_id_t = agent_id.clone();
        let target_t = target.clone();
        let run_id_t = run_id.clone();
        let llm_config_t = llm_config.clone();
        let api_key_t = api_key.clone();
        let api_key_credential_t = api_key_credential.clone();
        let session_log_t = session_log.clone();
        let sandbox_t = sandbox.clone();
        let permissions_t = permissions.clone();
        let skills_dir_t = skills_dir.clone();
        let walks_staged_dir_t = walks_staged_dir.clone();
        let walk_name = name.clone();
        // Substitute the per-spawn walk name into the seed protocol
        // template so each walk's prompt names its own declines
        // staging path. The template carries a `<walk>` sentinel the
        // dispatch site built once for the whole run.
        let walk_seed_suffix_t = walk_seed_suffix.replace("<walk>", &walk_name);

        let h = tokio::spawn(async move {
            // Permit drops on task exit (success or panic) so a
            // failed walk does not starve later walks of capacity.
            let _permit = sem_handle.acquire_owned().await.expect("semaphore closed");

            let mut local_agent = match Agent::new_with_sandbox(
                agent_id_t.clone(),
                target_t.clone(),
                llm_config_t,
                api_key_t,
                api_key_credential_t,
                session_log_t,
                sandbox_t,
            ) {
                Ok(a) => a,
                Err(e) => {
                    return WalkOutcome {
                        walk_name: walk_name.clone(),
                        status: WalkStatus::TransientFailure {
                            reason: format!("agent_construct: {e}"),
                        },
                        response_len: 0,
                        denials: 0,
                    };
                }
            };
            local_agent.set_permissions(permissions_t);

            if skills_dir_t.is_dir()
                && let Err(e) = local_agent.load_skills(&skills_dir_t)
            {
                tracing::warn!(
                    "load_skills({}) failed in walk {walk_name}: {e}",
                    skills_dir_t.display()
                );
            }
            if let Err(e) = local_agent.extend_skills(&walks_staged_dir_t) {
                return WalkOutcome {
                    walk_name: walk_name.clone(),
                    status: WalkStatus::TransientFailure {
                        reason: format!("extend_skills: {e}"),
                    },
                    response_len: 0,
                    denials: 0,
                };
            }

            let prompt = build_walk_prompt(&walk_name, &run_id_t, &walk_seed_suffix_t);
            let inbound_id = format!("lyrik-walk-{}-{}", walk_name, uuid::Uuid::new_v4());
            match local_agent.process_message(&prompt, inbound_id).await {
                Ok(r) => {
                    let denial_count = r.denials.len();
                    if denial_count > 0 {
                        WalkOutcome {
                            walk_name: walk_name.clone(),
                            status: WalkStatus::PermissionDenial {
                                reason: format!("{denial_count} denial(s)"),
                            },
                            response_len: r.response.len(),
                            denials: denial_count,
                        }
                    } else {
                        WalkOutcome {
                            walk_name: walk_name.clone(),
                            status: WalkStatus::Success,
                            response_len: r.response.len(),
                            denials: 0,
                        }
                    }
                }
                Err(AgentError::RateLimitExhausted { attempts }) => WalkOutcome {
                    walk_name: walk_name.clone(),
                    status: WalkStatus::TransientFailure {
                        reason: format!("rate_limit_exhausted after {attempts} attempts"),
                    },
                    response_len: 0,
                    denials: 0,
                },
                Err(e) => WalkOutcome {
                    walk_name: walk_name.clone(),
                    status: WalkStatus::TransientFailure {
                        reason: e.to_string(),
                    },
                    response_len: 0,
                    denials: 0,
                },
            }
        });
        handles.push((name, h));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for (name, h) in handles {
        let outcome = match h.await {
            Ok(o) => o,
            Err(join_err) => WalkOutcome {
                walk_name: name.clone(),
                status: WalkStatus::TransientFailure {
                    reason: format!("join: {join_err}"),
                },
                response_len: 0,
                denials: 0,
            },
        };
        let status_label = match &outcome.status {
            WalkStatus::Success => "success",
            WalkStatus::TransientFailure { .. } => "transient_failure",
            WalkStatus::PermissionDenial { .. } => "permission_denial",
        };
        let reason = match &outcome.status {
            WalkStatus::Success => None,
            WalkStatus::TransientFailure { reason } => Some(reason.clone()),
            WalkStatus::PermissionDenial { reason } => Some(reason.clone()),
        };
        audit.emit(
            "lyrik.walk.completed",
            serde_json::json!({
                "walk": name,
                "status": status_label,
                "reason": reason,
                "response_len": outcome.response_len,
                "denials": outcome.denials,
            }),
        )?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Aggregate findings from one or more source directories into
/// the canonical `findings.json`. Each source is a (walk_name,
/// dir) pair: `walk_name` is `None` for the top-level
/// `staging/findings/` (one-call slice), `Some(walk)` for per-walk
/// staging subdirs.
///
/// When `dedup_active` is true (per-walk path), findings sharing a
/// `(location.file, location.line_start)` key collapse to one
/// merged record: framings union, tier rises to the highest of the
/// inputs, `dedup_disagreement: true` when input tiers differ,
/// `dedup_sources: [walk_name, ...]` lists every walk that
/// contributed. When false (one-call path), every staged finding
/// is preserved verbatim.
///
/// `seed_locations` is the set of `"file:line"` keys produced by
/// the pre-LLM scanner pass. Every emitted finding is annotated
/// with `detection_source`: `static_prescreen` when its location
/// matches a seed, `model_reasoning` otherwise. Per-walk dedup
/// upgrades the pair `{static_prescreen, model_reasoning}` to
/// `both` (single-call mode has no dedup and never produces
/// `both` — documented in `docs/lyrik-json-schema.md`).
#[allow(clippy::too_many_arguments)]
fn aggregate_findings_multi(
    sources: &[(Option<String>, PathBuf)],
    dest: &Path,
    run_id: &str,
    dedup_active: bool,
    seed_locations: &std::collections::HashSet<String>,
    workspace: &Path,
    audit: &mut AuditLogger,
) -> Result<()> {
    use super::lyrik_citation;

    let mut tagged: Vec<(Option<String>, serde_json::Value)> = Vec::new();
    let mut consumed: Vec<PathBuf> = Vec::new();
    let mut literal_claim_resolved: usize = 0;
    let mut literal_claim_unresolved: usize = 0;
    let mut file_line_only_resolved: usize = 0;
    let mut file_line_only_unresolved: usize = 0;
    for (walk_name, source) in sources {
        if !source.is_dir() {
            continue;
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
            .with_context(|| format!("read {}", source.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
            .collect();
        entries.sort();
        for p in &entries {
            let body =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            let mut parsed: serde_json::Value = serde_json::from_str(&body)
                .with_context(|| format!("parse staged finding {}", p.display()))?;
            annotate_detection_source(&mut parsed, seed_locations);

            let outcome = lyrik_citation::check(&parsed, workspace);
            match (outcome.gate, outcome.status) {
                (lyrik_citation::Gate::LiteralClaim, lyrik_citation::Status::Resolved) => {
                    literal_claim_resolved += 1
                }
                (lyrik_citation::Gate::LiteralClaim, lyrik_citation::Status::Unresolved) => {
                    literal_claim_unresolved += 1
                }
                (lyrik_citation::Gate::FileLineOnly, lyrik_citation::Status::Resolved) => {
                    file_line_only_resolved += 1
                }
                (lyrik_citation::Gate::FileLineOnly, lyrik_citation::Status::Unresolved) => {
                    file_line_only_unresolved += 1
                }
            }
            audit.emit(
                "lyrik.citation.checked",
                serde_json::json!({
                    "staged_path": p.display().to_string(),
                    "finding_id": parsed.get("id").and_then(|v| v.as_str()),
                    "stable_id": parsed.get("stable_id").and_then(|v| v.as_str()),
                    "location_file": parsed
                        .get("location")
                        .and_then(|v| v.get("file"))
                        .and_then(|v| v.as_str()),
                    "location_line": parsed
                        .get("location")
                        .and_then(|v| v.get("line_start"))
                        .and_then(|v| v.as_u64()),
                    "gate": outcome.gate.as_str(),
                    "status": outcome.status.as_str(),
                    "reason": outcome.reason,
                }),
            )?;
            lyrik_citation::annotate(&mut parsed, &outcome);

            tagged.push((walk_name.clone(), parsed));
        }
        if !entries.is_empty() {
            consumed.push(source.clone());
        }
    }
    if tagged.is_empty() && consumed.is_empty() {
        return Ok(());
    }

    let findings: Vec<serde_json::Value> = if dedup_active {
        dedup_findings(tagged)
    } else {
        tagged.into_iter().map(|(_, f)| f).collect()
    };

    let body = serde_json::json!({
        "schema_version": "1.1",
        "run_id": run_id,
        "produced_at": chrono::Utc::now().to_rfc3339(),
        "citation_check": {
            "literal_claim": {
                "resolved": literal_claim_resolved,
                "unresolved": literal_claim_unresolved,
            },
            "file_line_only": {
                "resolved": file_line_only_resolved,
                "unresolved": file_line_only_unresolved,
            },
        },
        "findings": findings,
    });
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(dest, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", dest.display()))?;
    for source in consumed {
        std::fs::remove_dir_all(&source)
            .with_context(|| format!("remove staging dir {}", source.display()))?;
    }
    Ok(())
}

/// Set `detection_source` on a staged finding based on whether its
/// `(file, line_start)` matches a seed location. Does not overwrite
/// an existing value: a future producer that sets the field itself
/// stays authoritative. Findings whose location cannot be derived
/// pass through unchanged (the validator will reject them on the
/// missing-location ground).
pub(super) fn annotate_detection_source(
    finding: &mut serde_json::Value,
    seed_locations: &std::collections::HashSet<String>,
) {
    let key = location_key(finding);
    let provenance = match key {
        Some(k) if seed_locations.contains(&k) => "static_prescreen",
        Some(_) => "model_reasoning",
        None => return,
    };
    if let Some(obj) = finding.as_object_mut() {
        obj.entry("detection_source".to_string())
            .or_insert(serde_json::Value::String(provenance.to_string()));
    }
}

/// Numeric severity ordering used by the dedup tier-rises rule.
/// Higher number is more severe. Unknown tier maps to 0 so a
/// malformed input does not silently dominate well-formed peers.
fn tier_severity(tier: &str) -> u32 {
    match tier {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "INFO" => 1,
        _ => 0,
    }
}

/// Collapse findings sharing a `(location.file, location.line_start)`
/// key into one merged record per the dedup contract documented on
/// [`aggregate_findings_multi`]. Findings without a usable location
/// key (missing file or line_start) pass through unchanged so a
/// malformed input does not collide with everything else under a
/// shared default key.
pub(super) fn dedup_findings(
    tagged: Vec<(Option<String>, serde_json::Value)>,
) -> Vec<serde_json::Value> {
    use std::collections::BTreeMap;

    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<(Option<String>, serde_json::Value)>> = BTreeMap::new();
    let mut passthrough: Vec<serde_json::Value> = Vec::new();

    for (walk_name, finding) in tagged {
        let key = location_key(&finding);
        match key {
            Some(k) => {
                if !groups.contains_key(&k) {
                    order.push(k.clone());
                }
                groups.entry(k).or_default().push((walk_name, finding));
            }
            None => passthrough.push(finding),
        }
    }

    let mut out = Vec::with_capacity(order.len() + passthrough.len());
    for key in order {
        let mut group = groups.remove(&key).expect("key from order list");
        if group.len() == 1 {
            // Solo finding: still tag dedup_sources for traceability when a
            // walk_name was supplied; leave the rest of the record alone.
            let (walk_name, mut f) = group.pop().expect("len 1");
            if let Some(name) = walk_name
                && let Some(obj) = f.as_object_mut()
            {
                obj.entry("dedup_sources".to_string())
                    .or_insert(serde_json::json!([name]));
            }
            out.push(f);
            continue;
        }
        out.push(merge_finding_group(group));
    }
    out.extend(passthrough);
    out
}

/// Merge two or more findings sharing the same location. Framings
/// collapse to a sorted unique union. Tier rises to the highest of
/// the inputs; `dedup_disagreement: true` when inputs disagreed.
/// `dedup_sources` lists each contributing walk name in
/// first-seen order. The first finding's other fields (id,
/// stable_id, summary, etc.) are kept as the canonical record so
/// downstream consumers still have one stable identifier per
/// finding.
fn merge_finding_group(group: Vec<(Option<String>, serde_json::Value)>) -> serde_json::Value {
    let mut framings: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut sources: Vec<String> = Vec::new();
    let mut top_severity = 0u32;
    let mut top_tier = String::new();
    let mut tiers_disagree = false;
    let mut detection_sources: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for (walk_name, f) in &group {
        if let Some(arr) = f.get("framing").and_then(|v| v.as_array()) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    framings.insert(s.to_string());
                }
            }
        }
        if let Some(walk) = walk_name
            && !sources.contains(walk)
        {
            sources.push(walk.clone());
        }
        if let Some(t) = f.get("tier").and_then(|v| v.as_str()) {
            let sev = tier_severity(t);
            if sev > 0 && top_severity > 0 && t != top_tier {
                tiers_disagree = true;
            }
            if sev > top_severity {
                top_severity = sev;
                top_tier = t.to_string();
            }
        }
        if let Some(ds) = f.get("detection_source").and_then(|v| v.as_str()) {
            detection_sources.insert(ds.to_string());
        }
    }

    // `both` upgrade: when a static_prescreen-tagged finding
    // converges with a model_reasoning-tagged finding on the same
    // location across walks, the merged record reports `both`. This
    // is the per-walk convergence case the schema-v1.1 enum's
    // `both` variant exists for; single-call mode has no
    // aggregator and therefore never produces `both`. An existing
    // `both` on any input member also resolves to `both` so a
    // future producer that sets the field itself isn't downgraded.
    let merged_detection_source = if detection_sources.contains("both")
        || (detection_sources.contains("static_prescreen")
            && detection_sources.contains("model_reasoning"))
    {
        Some("both".to_string())
    } else if detection_sources.contains("static_prescreen") {
        Some("static_prescreen".to_string())
    } else if detection_sources.contains("model_reasoning") {
        Some("model_reasoning".to_string())
    } else {
        None
    };

    let (_, mut canonical) = group.into_iter().next().expect("group non-empty");
    if let Some(obj) = canonical.as_object_mut() {
        if !framings.is_empty() {
            obj.insert(
                "framing".to_string(),
                serde_json::Value::Array(
                    framings
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if !sources.is_empty() {
            obj.insert(
                "dedup_sources".to_string(),
                serde_json::Value::Array(
                    sources.into_iter().map(serde_json::Value::String).collect(),
                ),
            );
        }
        if !top_tier.is_empty() {
            obj.insert("tier".to_string(), serde_json::Value::String(top_tier));
        }
        obj.insert(
            "dedup_disagreement".to_string(),
            serde_json::Value::Bool(tiers_disagree),
        );
        if let Some(ds) = merged_detection_source {
            obj.insert(
                "detection_source".to_string(),
                serde_json::Value::String(ds),
            );
        }
    }
    canonical
}

fn location_key(finding: &serde_json::Value) -> Option<String> {
    let loc = finding.get("location")?;
    let file = loc.get("file").and_then(|v| v.as_str())?;
    let line = loc
        .get("line_start")
        .and_then(|v| v.as_u64())
        .or_else(|| loc.get("line").and_then(|v| v.as_u64()))?;
    Some(format!("{file}:{line}"))
}

// ---------------------------------------------------------------------------
// Scanner-seed protocol + post-turn disposition accounting
// ---------------------------------------------------------------------------

/// Per-run instruction text appended to the dispatch prompt when the
/// scanner pass materialised a non-empty seed set. `walk_name`:
/// `None` for the single-call `/lyrik` dispatch path, `Some("<walk>")`
/// for the per-walk path (the `<walk>` sentinel is substituted with
/// each spawn's name when the per-walk prompt is built).
///
/// The protocol asks the model to rule on each seed: emit a finding
/// at the seed location if the candidate is a real bug, or write a
/// decline file naming the seed_id and the reason when it isn't.
/// Anything the model neither accepts nor declines is treated as
/// `lyrik.candidate.unaddressed` by the runner (a third bucket
/// distinct from acceptance and decline) so the differential signal
/// separates "considered and rejected" from "never ruled."
pub(super) fn seed_protocol_text(run_id: &str, walk_name: Option<&str>) -> String {
    let staging_root = match walk_name {
        Some(w) => format!(".lyrik/state/runs/{run_id}/staging/{w}"),
        None => format!(".lyrik/state/runs/{run_id}/staging"),
    };
    format!(
        " \
         \
         Static-prescreen seeds: a pinned Semgrep pass produced \
         candidate locations at `.lyrik/state/runs/{run_id}/seeds/seed-NNN.json`. \
         Read every seed file. For each seed: if it names a real bug \
         under the active framings, write a finding at the seed's \
         `location` per the staging instructions above (the runner \
         annotates `detection_source` based on location match — do \
         not set it yourself). If it does NOT name a real bug, write \
         a decline file to \
         `{staging_root}/declines/decline-NNN.json` with body \
         `{{\"seed_id\": \"<seed_id>\", \"reason\": \"<one-sentence \
         rationale>\"}}` (zero-padded ordinal). A seed you do not \
         accept and do not decline lands on \
         `lyrik.candidate.unaddressed` audit rows the runner emits \
         after the turn — explicit declines are the structured \
         disposition signal."
    )
}

/// Post-turn accounting for every seed the scanner produced.
///
/// For each seed the runner classifies disposition as exactly one of:
///
/// - **accepted** — at least one staged finding's `(file,
///   line_start)` matches the seed location. Emits no audit row
///   here; the finding itself in `findings.json` is the record.
/// - **declined** — at least one decline file under
///   `<staging>/declines/` or `<staging>/<walk>/declines/` names the
///   `seed_id`. Emits `lyrik.candidate.declined` for every (walk,
///   decline-file) pair so per-walk decline rationales stay
///   distinguishable.
/// - **unaddressed** — neither matched by a finding nor referenced
///   by a decline file. Emits `lyrik.candidate.unaddressed` once
///   per seed.
///
/// Reads staging without removing it; the aggregator runs after this
/// pass and is what cleans the staging tree.
fn process_seed_dispositions(
    staging: &Path,
    walks: Option<&[String]>,
    seeds: &[Seed],
    finding_sources: &[(Option<String>, PathBuf)],
    audit: &mut AuditLogger,
) -> Result<()> {
    if seeds.is_empty() {
        return Ok(());
    }

    // Build the accepted set: every (file, line) covered by a staged
    // finding across all walks / the single-call source.
    let mut accepted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, source) in finding_sources {
        if !source.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(source)
            .with_context(|| format!("read {}", source.display()))?
            .flatten()
        {
            let p = entry.path();
            if !p.is_file() || p.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let body =
                std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(key) = location_key(&parsed) {
                accepted.insert(key);
            }
        }
    }

    // Collect decline files keyed by seed_id, tagged with the walk
    // that emitted them. `walk_name` is `None` for the single-call
    // staging/declines/ path.
    let mut decline_dirs: Vec<(Option<String>, PathBuf)> = Vec::new();
    let top = staging.join("declines");
    if top.is_dir() {
        decline_dirs.push((None, top));
    }
    if let Some(walks) = walks {
        for w in walks {
            let d = staging.join(w).join("declines");
            if d.is_dir() {
                decline_dirs.push((Some(w.clone()), d));
            }
        }
    }

    let mut declined_by_seed: std::collections::BTreeMap<
        String,
        Vec<(Option<String>, serde_json::Value)>,
    > = std::collections::BTreeMap::new();
    for (walk_name, dir) in &decline_dirs {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("read {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
            .collect();
        entries.sort();
        for p in &entries {
            let body =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        "lyrik: ignoring malformed decline file"
                    );
                    continue;
                }
            };
            let Some(seed_id) = parsed.get("seed_id").and_then(|v| v.as_str()) else {
                tracing::warn!(
                    path = %p.display(),
                    "lyrik: decline file missing `seed_id`"
                );
                continue;
            };
            declined_by_seed
                .entry(seed_id.to_string())
                .or_default()
                .push((walk_name.clone(), parsed));
        }
    }

    // Classify and emit per-seed.
    for seed in seeds {
        let seed_key = format!("{}:{}", seed.file, seed.line);
        let is_accepted = accepted.contains(&seed_key);
        let declines = declined_by_seed.get(&seed.seed_id);

        if let Some(rows) = declines {
            // Emit a decline row per (walk, decline-file) pair so
            // per-walk reasoning stays distinguishable. Acceptance
            // elsewhere does not silence a decline row: the
            // differential signal is that this walk thought the
            // seed wasn't a bug, irrespective of what other walks
            // concluded.
            for (walk_name, decline) in rows {
                audit.emit(
                    "lyrik.candidate.declined",
                    serde_json::json!({
                        "tool": "semgrep",
                        "seed_id": seed.seed_id,
                        "rule_id": seed.rule_id,
                        "location": {
                            "file": seed.file,
                            "line_start": seed.line,
                        },
                        "walk": walk_name,
                        "reason": decline.get("reason").and_then(|v| v.as_str()),
                    }),
                )?;
            }
            // If at least one walk produced a finding at this
            // location the seed is also accepted; the decline rows
            // already captured the per-walk dissent so no further
            // unaddressed/acceptance row fires.
            let _ = is_accepted;
        } else if !is_accepted {
            audit.emit(
                "lyrik.candidate.unaddressed",
                serde_json::json!({
                    "tool": "semgrep",
                    "seed_id": seed.seed_id,
                    "rule_id": seed.rule_id,
                    "location": {
                        "file": seed.file,
                        "line_start": seed.line,
                    },
                }),
            )?;
        }
    }

    // Remove decline staging dirs once accounted for so the
    // aggregator's `remove_dir(staging)` call can succeed.
    for (_, dir) in decline_dirs {
        let _ = std::fs::remove_dir_all(&dir);
    }

    Ok(())
}

/// Aggregate `staging/findings/finding-NNN.json` files into the final
/// `findings.json`. Empty or missing source directory is a no-op so a
/// directly-written findings.json (legacy path) still works. On
/// success the staging directory is removed.
#[allow(dead_code)]
fn aggregate_findings(source: &Path, dest: &Path, run_id: &str) -> Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
        .with_context(|| format!("read {}", source.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    if entries.is_empty() {
        let _ = std::fs::remove_dir(source);
        return Ok(());
    }
    entries.sort();
    let mut findings = Vec::with_capacity(entries.len());
    for p in &entries {
        let body = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parse staged finding {}", p.display()))?;
        findings.push(parsed);
    }
    let body = serde_json::json!({
        "schema_version": "1.1",
        "run_id": run_id,
        "produced_at": chrono::Utc::now().to_rfc3339(),
        "findings": findings,
    });
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(dest, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", dest.display()))?;
    std::fs::remove_dir_all(source)
        .with_context(|| format!("remove staging dir {}", source.display()))?;
    Ok(())
}

#[derive(Debug)]
struct PhasePin {
    provider: String,
    model: String,
    base_url: String,
    /// Optional per-pin context window override. When set, replaces
    /// the per-provider default from `LlmConfig::from_provider`.
    /// Lets a config pin a model with a non-default context window
    /// (e.g. an ollama model that needs a smaller window than the
    /// 32K default, or a custom OpenAI-compat endpoint with a known
    /// larger window) without touching the agent crate.
    context_window: Option<u32>,
}

fn resolve_phase_pin(config: &serde_json::Value) -> Result<PhasePin> {
    let phases = config
        .get("phases")
        .ok_or_else(|| anyhow::anyhow!("config has no `phases` block"))?;
    let pin_obj = phases
        .get("framing")
        .or_else(|| phases.get("score"))
        .or_else(|| phases.get("recon"))
        .ok_or_else(|| {
            anyhow::anyhow!("config.phases has neither framing, score, nor recon entries")
        })?;
    let provider = pin_obj
        .get("provider")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("phase pin missing `provider`"))?
        .to_string();
    let model = pin_obj
        .get("model")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("phase pin missing `model`"))?
        .to_string();
    let base_url = pin_obj
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| provider_default_base_url(&provider).map(String::from))
        .ok_or_else(|| anyhow::anyhow!("phase pin for provider `{provider}` missing `base_url`"))?;
    let context_window = pin_obj
        .get("context_window")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());
    Ok(PhasePin {
        provider,
        model,
        base_url,
        context_window,
    })
}

/// Default `base_url` per provider, used when `phases.<phase>.base_url`
/// is absent from `.lyrik/config.json`. An explicit `base_url` always
/// wins.
///
/// Bedrock is intentionally absent — the AWS SDK's endpoint resolution
/// derives the URL from the region, and Lyrik plumbs the region
/// through `LlmConfig::region` instead of `base_url`. Configs pinning
/// `bedrock` must still set `base_url` explicitly.
///
/// Privatemode's default points at the local proxy
/// (`http://localhost:8080/v1`), matching the operator-side setup
/// described in `docs/reference/privatemode.md`. Tinfoil's entry is
/// kept for `LlmConfig.base_url` only: the tinfoil dispatch arm
/// goes through the tinfoil-rs SDK and the SDK's discovery endpoint
/// picks the host at construction time, so this URL is never used
/// for routing on that path. See `docs/reference/tinfoil.md`.
pub(crate) fn provider_default_base_url(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("https://api.openai.com/v1"),
        "anthropic" => Some("https://api.anthropic.com/v1"),
        "gemini" => Some("https://generativelanguage.googleapis.com/v1"),
        "ollama" => Some("http://localhost:11434/v1"),
        "tinfoil" => Some("https://inference.tinfoil.sh/v1"),
        "privatemode" => Some("http://localhost:8080/v1"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// `wirken lyrik report`
// ---------------------------------------------------------------------------

/// Emit a Lyrik report.
///
/// Resolves findings.json from `--findings <path>` (explicit) or from
/// `--run <run-id>` under `<cwd>/.lyrik/state/runs/<run-id>/`. Exactly
/// one of the two must be supplied.
pub async fn report(
    format: &str,
    findings: Option<&Path>,
    run: Option<&str>,
    output: &Path,
) -> Result<()> {
    if format != "sarif" {
        anyhow::bail!("only --format sarif is supported (got {format:?})");
    }
    let findings_path = match (findings, run) {
        (Some(p), None) => p.to_path_buf(),
        (None, Some(run_id)) => resolve_run_dir(run_id)?.join("findings.json"),
        (Some(_), Some(_)) => anyhow::bail!("--findings and --run are mutually exclusive"),
        (None, None) => anyhow::bail!("supply either --findings <path> or --run <run-id>"),
    };
    if !findings_path.exists() {
        anyhow::bail!("findings.json missing at {}", findings_path.display());
    }

    let sarif = super::lyrik_sarif::build_sarif(&findings_path, DRIVER_VERSION)?;
    let body = serde_json::to_string_pretty(&sarif)?;

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(output, body).with_context(|| format!("write {}", output.display()))?;
    println!("wrote {}", output.display());
    Ok(())
}

fn resolve_run_dir(run: &str) -> Result<PathBuf> {
    Ok(std::env::current_dir()?
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run))
}

/// Replace the value of the first top-level `"run_id"` field in a
/// JSON document, leaving every other byte intact. Returns an error
/// if the field is missing or malformed.
fn rewrite_top_level_run_id(body: &str, new_run_id: &str) -> Result<String> {
    const KEY: &str = "\"run_id\":";
    let key_at = body
        .find(KEY)
        .ok_or_else(|| anyhow::anyhow!("fixture has no top-level run_id field"))?;
    let after_key = key_at + KEY.len();
    let q1 = body[after_key..]
        .find('"')
        .ok_or_else(|| anyhow::anyhow!("malformed run_id (no opening quote)"))?;
    let value_start = after_key + q1 + 1;
    let q2 = body[value_start..]
        .find('"')
        .ok_or_else(|| anyhow::anyhow!("malformed run_id (no closing quote)"))?;
    let value_end = value_start + q2;
    let mut out = String::with_capacity(body.len() + new_run_id.len());
    out.push_str(&body[..value_start]);
    out.push_str(new_run_id);
    out.push_str(&body[value_end..]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Audit logger
// ---------------------------------------------------------------------------

/// Per-run NDJSON audit log written to `<run-dir>/audit.log`. The
/// runner emits one record per stage. Lyrik's deployment posture
/// (the wirken-audit-chain claim) wants these records to flow into
/// the hash-chained audit subsystem too; that wiring is a follow-up
/// slice.
struct AuditLogger {
    file: std::fs::File,
    run_id: String,
    bench_mode: bool,
}

impl AuditLogger {
    fn open(path: &Path, run_id: &str, bench_mode: bool) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        Ok(Self {
            file,
            run_id: run_id.to_string(),
            bench_mode,
        })
    }

    fn emit(&mut self, event: &str, detail: serde_json::Value) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let record = serde_json::json!({
            "event": event,
            "run_id": self.run_id,
            "ts": now,
            "bench_mode": self.bench_mode,
            "driver_version": DRIVER_VERSION,
            "detail": detail,
        });
        writeln!(self.file, "{}", serde_json::to_string(&record)?)
            .with_context(|| "write audit record")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_top_level_run_id;

    #[test]
    fn rewrite_top_level_run_id_replaces_only_the_value_bytes() {
        let body = r#"{
  "run_id": "old-id",
  "produced_at": "2026-05-03T10:30:00Z"
}"#;
        let out = rewrite_top_level_run_id(body, "sample/run-001").unwrap();
        assert!(out.contains("\"run_id\": \"sample/run-001\""));
        assert!(out.contains("\"produced_at\": \"2026-05-03T10:30:00Z\""));
        // Byte-length difference is exactly len("sample/run-001") - len("old-id")
        let delta = "sample/run-001".len() as isize - "old-id".len() as isize;
        assert_eq!(out.len() as isize - body.len() as isize, delta);
    }

    #[test]
    fn rewrite_top_level_run_id_errors_when_field_absent() {
        let body = r#"{"produced_at": "2026"}"#;
        assert!(rewrite_top_level_run_id(body, "x").is_err());
    }

    use super::provider_default_base_url;

    #[test]
    fn provider_default_openai() {
        assert_eq!(
            provider_default_base_url("openai"),
            Some("https://api.openai.com/v1")
        );
    }

    #[test]
    fn provider_default_anthropic() {
        assert_eq!(
            provider_default_base_url("anthropic"),
            Some("https://api.anthropic.com/v1")
        );
    }

    #[test]
    fn provider_default_gemini() {
        assert_eq!(
            provider_default_base_url("gemini"),
            Some("https://generativelanguage.googleapis.com/v1")
        );
    }

    #[test]
    fn provider_default_ollama() {
        assert_eq!(
            provider_default_base_url("ollama"),
            Some("http://localhost:11434/v1")
        );
    }

    #[test]
    fn provider_default_tinfoil() {
        assert_eq!(
            provider_default_base_url("tinfoil"),
            Some("https://inference.tinfoil.sh/v1")
        );
    }

    #[test]
    fn provider_default_privatemode() {
        assert_eq!(
            provider_default_base_url("privatemode"),
            Some("http://localhost:8080/v1")
        );
    }

    #[test]
    fn provider_default_bedrock_returns_none() {
        // Bedrock derives its endpoint from the AWS region; no static
        // default. Configs pinning bedrock must still set base_url.
        assert_eq!(provider_default_base_url("bedrock"), None);
    }

    #[test]
    fn provider_default_unknown_returns_none() {
        assert_eq!(provider_default_base_url("not-a-provider"), None);
        assert_eq!(provider_default_base_url(""), None);
    }

    use super::resolve_phase_pin;

    #[test]
    fn resolve_phase_pin_returns_context_window_when_set() {
        let cfg = serde_json::json!({
            "phases": {
                "framing": {
                    "provider": "ollama",
                    "model": "qwen2.5:7b",
                    "context_window": 65536u64
                }
            }
        });
        let pin = resolve_phase_pin(&cfg).unwrap();
        assert_eq!(pin.context_window, Some(65_536));
        assert_eq!(pin.provider, "ollama");
        assert_eq!(pin.base_url, "http://localhost:11434/v1");
    }

    #[test]
    fn resolve_phase_pin_omits_context_window_when_absent() {
        let cfg = serde_json::json!({
            "phases": {
                "framing": {"provider": "ollama", "model": "qwen2.5:7b"}
            }
        });
        let pin = resolve_phase_pin(&cfg).unwrap();
        assert_eq!(pin.context_window, None);
    }

    #[test]
    fn resolve_phase_pin_rejects_negative_context_window() {
        let cfg = serde_json::json!({
            "phases": {
                "framing": {
                    "provider": "ollama",
                    "model": "qwen2.5:7b",
                    "context_window": -1
                }
            }
        });
        let pin = resolve_phase_pin(&cfg).unwrap();
        // u64 conversion fails for negatives; pin treats as absent.
        assert_eq!(pin.context_window, None);
    }

    use super::dedup_findings;
    use super::tier_severity;

    #[test]
    fn tier_severity_orders_canonical_tiers() {
        assert!(tier_severity("CRITICAL") > tier_severity("HIGH"));
        assert!(tier_severity("HIGH") > tier_severity("MEDIUM"));
        assert!(tier_severity("MEDIUM") > tier_severity("LOW"));
        assert!(tier_severity("LOW") > tier_severity("INFO"));
        assert_eq!(tier_severity("UNKNOWN"), 0);
    }

    fn finding(file: &str, line: u64, framing: &str, tier: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "F001",
            "stable_id": format!("{framing}::{file}:{line}"),
            "framing": [framing],
            "location": {"file": file, "line_start": line},
            "title": "stub",
            "summary": "stub",
            "tier": tier,
        })
    }

    #[test]
    fn dedup_collapses_same_location_across_walks() {
        let tagged = vec![
            (
                Some("sink-walk".into()),
                finding("src/a.rs", 10, "auth", "MEDIUM"),
            ),
            (
                Some("graph-walk".into()),
                finding("src/a.rs", 10, "injection", "HIGH"),
            ),
        ];
        let merged = dedup_findings(tagged);
        assert_eq!(merged.len(), 1);
        let m = &merged[0];
        let framings: Vec<&str> = m
            .get("framing")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert!(framings.contains(&"auth"));
        assert!(framings.contains(&"injection"));
        assert_eq!(m.get("tier").and_then(|v| v.as_str()), Some("HIGH"));
        assert_eq!(
            m.get("dedup_disagreement").and_then(|v| v.as_bool()),
            Some(true)
        );
        let sources: Vec<&str> = m
            .get("dedup_sources")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert!(sources.contains(&"sink-walk"));
        assert!(sources.contains(&"graph-walk"));
    }

    #[test]
    fn dedup_does_not_mark_disagreement_when_tiers_match() {
        let tagged = vec![
            (
                Some("sink-walk".into()),
                finding("src/a.rs", 10, "auth", "HIGH"),
            ),
            (
                Some("graph-walk".into()),
                finding("src/a.rs", 10, "injection", "HIGH"),
            ),
        ];
        let merged = dedup_findings(tagged);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0]
                .get("dedup_disagreement")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn dedup_keeps_distinct_locations_apart() {
        let tagged = vec![
            (
                Some("sink-walk".into()),
                finding("src/a.rs", 10, "auth", "HIGH"),
            ),
            (
                Some("sink-walk".into()),
                finding("src/a.rs", 11, "auth", "HIGH"),
            ),
            (
                Some("sink-walk".into()),
                finding("src/b.rs", 10, "auth", "HIGH"),
            ),
        ];
        let merged = dedup_findings(tagged);
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn dedup_solo_finding_records_dedup_sources_when_walk_known() {
        let tagged = vec![(
            Some("sink-walk".into()),
            finding("src/a.rs", 10, "auth", "HIGH"),
        )];
        let merged = dedup_findings(tagged);
        assert_eq!(merged.len(), 1);
        let s = merged[0]
            .get("dedup_sources")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].as_str(), Some("sink-walk"));
    }

    #[test]
    fn dedup_passthrough_for_finding_without_location_key() {
        let mut malformed = finding("src/a.rs", 10, "auth", "HIGH");
        malformed.as_object_mut().unwrap().remove("location");
        let tagged = vec![
            (Some("sink-walk".into()), malformed),
            (
                Some("sink-walk".into()),
                finding("src/a.rs", 10, "auth", "HIGH"),
            ),
        ];
        let merged = dedup_findings(tagged);
        // The malformed finding cannot collide on the location key,
        // so it passes through unchanged alongside the normal one.
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn dedup_higher_tier_wins() {
        for (a_tier, b_tier, expected) in [
            ("LOW", "CRITICAL", "CRITICAL"),
            ("HIGH", "MEDIUM", "HIGH"),
            ("INFO", "LOW", "LOW"),
        ] {
            let tagged = vec![
                (
                    Some("sink-walk".into()),
                    finding("src/a.rs", 10, "auth", a_tier),
                ),
                (
                    Some("graph-walk".into()),
                    finding("src/a.rs", 10, "auth", b_tier),
                ),
            ];
            let merged = dedup_findings(tagged);
            assert_eq!(
                merged[0].get("tier").and_then(|v| v.as_str()),
                Some(expected),
                "{a_tier} vs {b_tier} should resolve to {expected}"
            );
        }
    }

    use super::aggregate_findings_multi;
    use std::sync::Arc;
    use tempfile::tempdir;
    use wirken_audit::{
        AuditSigningKey, ChainHeadReason, SessionEvent, SessionId, SessionLog, SqliteSessionLog,
        TrustLevel, VerifyResult,
    };

    fn write_finding(dir: &std::path::Path, name: &str, content: &serde_json::Value) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(name),
            serde_json::to_string_pretty(content).unwrap(),
        )
        .unwrap();
    }

    /// Two walks emit findings under per-walk staging trees: one
    /// finding shared by both walks (same file:line, different
    /// framing) and one finding unique to a single walk. The
    /// aggregator collapses the shared one and keeps the unique
    /// one, producing a findings.json with two entries plus the
    /// dedup contract on the merged record.
    #[test]
    fn aggregate_findings_multi_dedups_per_walk_inputs() {
        let tmp = tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let sink_dir = staging.join("sink-walk").join("findings");
        let graph_dir = staging.join("graph-walk").join("findings");

        write_finding(
            &sink_dir,
            "finding-001.json",
            &finding("src/a.rs", 10, "auth", "MEDIUM"),
        );
        write_finding(
            &sink_dir,
            "finding-002.json",
            &finding("src/c.rs", 42, "auth", "LOW"),
        );
        write_finding(
            &graph_dir,
            "finding-001.json",
            &finding("src/a.rs", 10, "injection", "HIGH"),
        );

        let dest = tmp.path().join("findings.json");
        let sources = vec![
            (Some("sink-walk".to_string()), sink_dir),
            (Some("graph-walk".to_string()), graph_dir),
        ];
        let no_seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        let workspace = tmp.path();
        let mut audit =
            super::AuditLogger::open(&tmp.path().join("audit.log"), "sample/run-007", true)
                .unwrap();
        aggregate_findings_multi(
            &sources,
            &dest,
            "sample/run-007",
            true,
            &no_seeds,
            workspace,
            &mut audit,
        )
        .unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        let arr = body.get("findings").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr.len(), 2, "shared location collapses to one entry");
        let merged = arr
            .iter()
            .find(|f| f.pointer("/location/file").and_then(|v| v.as_str()) == Some("src/a.rs"))
            .unwrap();
        assert_eq!(merged.get("tier").and_then(|v| v.as_str()), Some("HIGH"));
        let framings: Vec<&str> = merged
            .get("framing")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert!(framings.contains(&"auth"));
        assert!(framings.contains(&"injection"));
        let sources_arr: Vec<&str> = merged
            .get("dedup_sources")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert!(sources_arr.contains(&"sink-walk"));
        assert!(sources_arr.contains(&"graph-walk"));
    }

    /// One-call aggregation with `dedup_active = false`: two
    /// findings sharing the same location stay as two entries
    /// (legacy behaviour for the operator who has not opted into
    /// per-walk dispatch).
    #[test]
    fn aggregate_findings_multi_keeps_duplicates_when_dedup_disabled() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("staging").join("findings");
        write_finding(
            &dir,
            "finding-001.json",
            &finding("src/a.rs", 10, "auth", "HIGH"),
        );
        write_finding(
            &dir,
            "finding-002.json",
            &finding("src/a.rs", 10, "injection", "HIGH"),
        );
        let dest = tmp.path().join("findings.json");
        let no_seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        let workspace = tmp.path();
        let mut audit =
            super::AuditLogger::open(&tmp.path().join("audit.log"), "sample/run-008", true)
                .unwrap();
        aggregate_findings_multi(
            &[(None, dir)],
            &dest,
            "sample/run-008",
            false,
            &no_seeds,
            workspace,
            &mut audit,
        )
        .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        let arr = body.get("findings").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr.len(), 2);
    }

    use super::annotate_detection_source;

    #[test]
    fn annotate_detection_source_marks_seed_match_as_static_prescreen() {
        let mut f = finding("src/a.rs", 10, "auth", "HIGH");
        let mut seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        seeds.insert("src/a.rs:10".to_string());
        annotate_detection_source(&mut f, &seeds);
        assert_eq!(
            f.get("detection_source").and_then(|v| v.as_str()),
            Some("static_prescreen")
        );
    }

    #[test]
    fn annotate_detection_source_marks_no_match_as_model_reasoning() {
        let mut f = finding("src/a.rs", 10, "auth", "HIGH");
        let seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        annotate_detection_source(&mut f, &seeds);
        assert_eq!(
            f.get("detection_source").and_then(|v| v.as_str()),
            Some("model_reasoning")
        );
    }

    #[test]
    fn annotate_detection_source_does_not_overwrite_existing_value() {
        let mut f = finding("src/a.rs", 10, "auth", "HIGH");
        f.as_object_mut()
            .unwrap()
            .insert("detection_source".to_string(), serde_json::json!("both"));
        let mut seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        seeds.insert("src/a.rs:10".to_string());
        annotate_detection_source(&mut f, &seeds);
        assert_eq!(
            f.get("detection_source").and_then(|v| v.as_str()),
            Some("both"),
            "annotator must not downgrade an existing value"
        );
    }

    #[test]
    fn dedup_upgrades_static_prescreen_plus_model_reasoning_to_both() {
        let mut a = finding("src/a.rs", 10, "auth", "MEDIUM");
        a.as_object_mut().unwrap().insert(
            "detection_source".to_string(),
            serde_json::json!("static_prescreen"),
        );
        let mut b = finding("src/a.rs", 10, "injection", "HIGH");
        b.as_object_mut().unwrap().insert(
            "detection_source".to_string(),
            serde_json::json!("model_reasoning"),
        );
        let merged = dedup_findings(vec![
            (Some("sink-walk".into()), a),
            (Some("graph-walk".into()), b),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].get("detection_source").and_then(|v| v.as_str()),
            Some("both"),
        );
    }

    #[test]
    fn dedup_keeps_homogeneous_static_prescreen_label_on_convergence() {
        let mut a = finding("src/a.rs", 10, "auth", "MEDIUM");
        a.as_object_mut().unwrap().insert(
            "detection_source".to_string(),
            serde_json::json!("static_prescreen"),
        );
        let mut b = finding("src/a.rs", 10, "injection", "HIGH");
        b.as_object_mut().unwrap().insert(
            "detection_source".to_string(),
            serde_json::json!("static_prescreen"),
        );
        let merged = dedup_findings(vec![
            (Some("sink-walk".into()), a),
            (Some("graph-walk".into()), b),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].get("detection_source").and_then(|v| v.as_str()),
            Some("static_prescreen"),
        );
    }

    #[test]
    fn aggregate_findings_multi_writes_schema_version_one_one() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("staging").join("findings");
        write_finding(
            &dir,
            "finding-001.json",
            &finding("src/a.rs", 10, "auth", "HIGH"),
        );
        let dest = tmp.path().join("findings.json");
        let seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        let workspace = tmp.path();
        let mut audit =
            super::AuditLogger::open(&tmp.path().join("audit.log"), "sample/run-009", true)
                .unwrap();
        aggregate_findings_multi(
            &[(None, dir)],
            &dest,
            "sample/run-009",
            false,
            &seeds,
            workspace,
            &mut audit,
        )
        .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(body["schema_version"].as_str(), Some("1.1"));
    }

    #[test]
    fn aggregate_findings_multi_annotates_seed_match_as_static_prescreen_end_to_end() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("staging").join("findings");
        write_finding(
            &dir,
            "finding-001.json",
            &finding("src/a.rs", 10, "auth", "HIGH"),
        );
        let dest = tmp.path().join("findings.json");
        let mut seeds: std::collections::HashSet<String> = std::collections::HashSet::new();
        seeds.insert("src/a.rs:10".to_string());
        let workspace = tmp.path();
        let mut audit =
            super::AuditLogger::open(&tmp.path().join("audit.log"), "sample/run-010", true)
                .unwrap();
        aggregate_findings_multi(
            &[(None, dir)],
            &dest,
            "sample/run-010",
            false,
            &seeds,
            workspace,
            &mut audit,
        )
        .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        let arr = body["findings"].as_array().unwrap();
        assert_eq!(
            arr[0].get("detection_source").and_then(|v| v.as_str()),
            Some("static_prescreen"),
        );
    }

    /// Multiple appends sharing one session_id (the shape that N
    /// concurrent walks produce against the run-level Lyrik
    /// session) verify clean against the signing key and report
    /// at least one signed chain head.
    #[test]
    fn signed_session_survives_n_walk_appends() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("audit.db");
        let signer = Arc::new(AuditSigningKey::generate());
        let log = SqliteSessionLog::open_with_signer(&db_path, signer.clone()).unwrap();
        let session_id = "lyrik-test-run".to_string();
        let handle = log.handle_for(SessionId::new(session_id.clone()));

        // Eight appends with the same session_id, simulating one
        // event per walk in a fan-out run.
        for i in 0..8 {
            log.append(
                &handle,
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: format!("walk-{i}"),
                    inbound_id: None,
                    adapter_id: None,
                    sender_id: None,
                },
            )
            .unwrap();
        }

        // Cap with an explicit SessionEnd head as the runner does
        // after dispatch returns.
        log.emit_chain_head(&handle, ChainHeadReason::SessionEnd)
            .unwrap();

        let sig = log.verify_signatures(&handle).unwrap();
        assert!(sig.first_invalid.is_none());
        assert!(
            sig.signed_heads_count >= 1,
            "expected at least one signed head, got {}",
            sig.signed_heads_count
        );
        assert_eq!(sig.signing_key_ids_seen.len(), 1);
        assert_eq!(sig.signing_key_ids_seen[0], signer.key_id_hex());

        // Open an AuditLog facade and run the full verify to
        // confirm the legacy verify shape survives signed rows.
        drop(log);
        let audit = wirken_audit::AuditLog::open_with_signer(&db_path, signer.clone()).unwrap();
        match audit.verify().unwrap() {
            VerifyResult::Ok {
                signed_heads_count,
                signing_key_ids_seen,
                ..
            } => {
                assert!(signed_heads_count >= 1);
                assert_eq!(signing_key_ids_seen.len(), 1);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }
}
