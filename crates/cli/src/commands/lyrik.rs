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
use wirken_agent::llm::LlmConfig;
use wirken_gateway::permissions::PermissionStore;
use wirken_vault::{CredentialStore, probe_keychain};

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
    let pin = resolve_phase_pin(config)?;
    let llm_config = LlmConfig::from_provider(&pin.provider, &pin.base_url, &pin.model);

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

    audit.emit(
        "lyrik.dispatch.started",
        serde_json::json!({
            "mode": "agent_runtime",
            "provider": pin.provider,
            "model": pin.model,
            "base_url": pin.base_url,
            "skills_dir": skills_dir.display().to_string(),
            "skills_loaded": skills_loaded,
            "workspace": target.display().to_string(),
        }),
    )?;

    // /lyrik triggers the SlashInterceptor which prepends the skill
    // body. The remainder gives run-specific parameters the methodology
    // does not encode.
    let prompt = format!(
        "/lyrik Run a full assessment on the codebase in this workspace. \
         Run-id: `{run_id}`. Bench mode is enabled: phase_0_signoff and \
         high_severity_review auto-approve, do not wait for human signoff. \
         Write the final findings.json to \
         `.lyrik/state/runs/{run_id}/findings.json` with rung and deferral \
         fields on every finding per the report contract."
    );

    let inbound_id = format!("lyrik-run-{}", uuid::Uuid::new_v4());
    let result = agent
        .process_message(&prompt, inbound_id)
        .await
        .context("agent.process_message returned an error")?;

    audit.emit(
        "lyrik.dispatch.completed",
        serde_json::json!({
            "mode": "agent_runtime",
            "response_len": result.response.len(),
            "denials": result.denials.len(),
        }),
    )?;

    if !expected_findings.exists() {
        anyhow::bail!(
            "agent ran but findings.json was not written at {} \
             (the skill instructs the agent to write this file; check the \
             agent response: {:?})",
            expected_findings.display(),
            result.response.chars().take(500).collect::<String>()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct PhasePin {
    provider: String,
    model: String,
    base_url: String,
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
        .or_else(|| match provider.as_str() {
            "ollama" => Some("http://localhost:11434/v1".to_string()),
            "anthropic" => Some("https://api.anthropic.com/v1".to_string()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("phase pin for provider `{provider}` missing `base_url`"))?;
    Ok(PhasePin {
        provider,
        model,
        base_url,
    })
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
}
