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
        "schema_version": "1.0",
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

    let pin = resolve_phase_pin(config)?;
    let mut llm_config = LlmConfig::from_provider(&pin.provider, &pin.base_url, &pin.model);
    if let Some(cw) = pin.context_window {
        llm_config.context_window = cw as usize;
    }

    let cfg = super::config();

    let api_key = if pin.provider != "ollama" {
        let pp = super::cached_vault_passphrase()?;
        let keychain = probe_keychain(&cfg.data_dir, move || pp);
        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("open credential store")?;
        let cred_name = format!("{}-api-key", pin.provider);
        match store.retrieve(&cred_name) {
            Ok((secret, _)) => Some(secret.expose().to_string()),
            Err(e) => anyhow::bail!(
                "API key '{cred_name}' missing from vault: {e}; \
                 add it with `wirken credentials add {cred_name}` \
                 or change the target's .lyrik/config.json pin"
            ),
        }
    } else {
        None
    };

    let session_log: Arc<dyn wirken_audit::SessionLog> = Arc::new(
        wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()).context("open session log")?,
    );

    // Workspace for the agent IS the target. The agent reads source
    // files from there and writes findings.json back into the target's
    // `.lyrik/state/runs/<run-id>/` per the Lyrik skill instructions.
    let mut agent = Agent::new_with_sandbox(
        format!("lyrik-{}", run_id.replace('/', "-")),
        target.to_path_buf(),
        llm_config,
        api_key,
        session_log,
        super::load_sandbox_config(&cfg.data_dir),
    )?;

    let perms =
        PermissionStore::open(&cfg.permissions_db_path()).context("open permission store")?;
    agent.set_permissions(Arc::new(Mutex::new(perms)));

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
    let run_dir_for_staging = target
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run_id);
    let walks_staged_dir = match walks_cfg.as_ref() {
        Some(wc) => {
            ensure_walk_staging(&run_dir_for_staging, &wc.walks)
                .context("ensure per-walk staging dirs")?;
            let staged = stage_walk_skills(&wc.walks, &walks_source_dir, &run_dir_for_staging)
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
    match walks_cfg.as_ref() {
        Some(wc) => {
            let outcomes = dispatch_walks_serial(&mut agent, &wc.walks, run_id, audit).await?;
            total_response_len = outcomes.iter().map(|o| o.response_len).sum();
            total_denials = outcomes.iter().map(|o| o.denials).sum();
        }
        None => {
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
                 turn returns."
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
    let run_dir = target
        .join(".lyrik")
        .join("state")
        .join("runs")
        .join(run_id);
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
    let mut finding_sources: Vec<PathBuf> = Vec::new();
    let top_findings = staging.join("findings");
    if top_findings.is_dir() {
        finding_sources.push(top_findings);
    }
    if let Some(wc) = walks_cfg.as_ref() {
        for w in &wc.walks {
            let p = staging.join(w).join("findings");
            if p.is_dir() {
                finding_sources.push(p);
            }
        }
    }
    aggregate_findings_multi(&finding_sources, expected_findings, run_id)
        .context("aggregate findings")?;
    // remove_dir succeeds only if empty — exactly the semantics we
    // want for cleaning up the parent staging/ once each subdir
    // aggregator has removed its own. A non-empty parent (partial
    // failure or unfamiliar staging contents) is left alone for the
    // operator to inspect.
    let _ = std::fs::remove_dir(&staging);

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

/// Run each selected walk one at a time, in the order the operator
/// listed them in `walks: [...]`. Records a `lyrik.walk.*` audit
/// row per turn. Always returns a per-walk outcome list, even when
/// individual walks fail. The caller decides the run's exit status
/// from the outcome set.
async fn dispatch_walks_serial(
    agent: &mut Agent,
    walks: &[String],
    run_id: &str,
    audit: &mut AuditLogger,
) -> Result<Vec<WalkOutcome>> {
    let mut outcomes = Vec::with_capacity(walks.len());
    for name in walks {
        audit.emit(
            "lyrik.walk.started",
            serde_json::json!({"walk": name, "run_id": run_id}),
        )?;
        let prompt = build_walk_prompt(name, run_id);
        let inbound_id = format!("lyrik-walk-{}-{}", name, uuid::Uuid::new_v4());
        let outcome = match agent.process_message(&prompt, inbound_id).await {
            Ok(r) => {
                let denial_count = r.denials.len();
                if denial_count > 0 {
                    // Permission-denial-during-walk is operator
                    // intent ("don't let this run"), not a transient
                    // failure. Per-walk outcome captures it; commit
                    // 2 routes any denial to a non-zero exit code.
                    WalkOutcome {
                        walk_name: name.clone(),
                        status: WalkStatus::PermissionDenial {
                            reason: format!("{denial_count} denial(s)"),
                        },
                        response_len: r.response.len(),
                        denials: denial_count,
                    }
                } else {
                    WalkOutcome {
                        walk_name: name.clone(),
                        status: WalkStatus::Success,
                        response_len: r.response.len(),
                        denials: 0,
                    }
                }
            }
            Err(AgentError::RateLimitExhausted { attempts }) => WalkOutcome {
                walk_name: name.clone(),
                status: WalkStatus::TransientFailure {
                    reason: format!("rate_limit_exhausted after {attempts} attempts"),
                },
                response_len: 0,
                denials: 0,
            },
            Err(e) => WalkOutcome {
                walk_name: name.clone(),
                status: WalkStatus::TransientFailure {
                    reason: e.to_string(),
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

/// Aggregate findings from one or more source directories into the
/// canonical `findings.json`. The single-source [`aggregate_findings`]
/// is the one-call slice; this multi-source variant covers the
/// per-walk path where each walk emits to its own
/// `staging/<walk-name>/findings/` subtree. Concatenates ordered by
/// (source-index, filename) so the merge is deterministic.
/// Dedup is commit 3.
fn aggregate_findings_multi(sources: &[PathBuf], dest: &Path, run_id: &str) -> Result<()> {
    let mut findings = Vec::new();
    let mut consumed = Vec::new();
    for source in sources {
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
            let parsed: serde_json::Value = serde_json::from_str(&body)
                .with_context(|| format!("parse staged finding {}", p.display()))?;
            findings.push(parsed);
        }
        if !entries.is_empty() {
            consumed.push(source.clone());
        }
    }
    if findings.is_empty() && consumed.is_empty() {
        return Ok(());
    }
    let body = serde_json::json!({
        "schema_version": "1.0",
        "run_id": run_id,
        "produced_at": chrono::Utc::now().to_rfc3339(),
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
        "schema_version": "1.0",
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
/// described in `docs/reference/privatemode.md`. Tinfoil points at
/// `https://inference.tinfoil.sh/v1`, matching the constructor in
/// `crates/agent/src/llm.rs`.
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
}
