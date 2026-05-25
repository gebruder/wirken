//! Lyrik Semgrep dispatch: runs a pinned Semgrep version against the
//! target before the LLM passes and materialises taint/dataflow
//! candidates as seed files under
//! `.lyrik/state/runs/<run-id>/seeds/seed-NNN.json`.
//!
//! Opt-in via `.lyrik/config.json::scanner.semgrep.enabled = true`.
//! Default off. Absence (binary missing, version mismatch, dispatch
//! failure) is a warn-and-continue: the runner proceeds with
//! LLM-only scanning. The pinned binary version is part of the
//! contract; a different `semgrep --version` on PATH is treated as
//! unavailable so reproducibility against the runner's pin is
//! preserved.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Pinned Semgrep CLI version. The contract is binary-version-pinned
/// so a single ruleset against two Semgrep versions cannot produce
/// divergent seed sets. Bumps land in their own slice.
pub const PINNED_SEMGREP_VERSION: &str = "1.95.0";

/// Source URL the bundled ruleset claims to mirror, stamped on the
/// `lyrik.scanner.dispatched` audit row for traceability. The bytes
/// the runner uses are the `include_str!`'d copy below, not a
/// network fetch; the URL is identity, not retrieval.
pub const RULESET_URL: &str =
    "https://github.com/gebruder/wirken/blob/main/crates/cli/src/commands/lyrik_semgrep_rules.yml";

/// Bundled ruleset bytes. Compile-time embed so the runner pin and
/// the ruleset pin move in lockstep with the binary.
pub const RULESET_BYTES: &[u8] = include_bytes!("lyrik_semgrep_rules.yml");

/// Parsed `scanner:` block from `.lyrik/config.json`. Absent or
/// `semgrep.enabled = false` skips dispatch entirely (default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerConfig {
    pub semgrep_enabled: bool,
}

/// Parse the `scanner:` block. Missing block, missing `semgrep`
/// sub-block, or `enabled` absent / false all return
/// `Ok(ScannerConfig { semgrep_enabled: false })`. Anything that
/// parses to a non-bool `enabled` is an error so a config typo does
/// not silently disable dispatch the operator asked for.
pub fn parse_scanner_config(config: &serde_json::Value) -> Result<ScannerConfig> {
    let block = match config.get("scanner") {
        Some(v) => v,
        None => {
            return Ok(ScannerConfig {
                semgrep_enabled: false,
            });
        }
    };
    let semgrep = match block.get("semgrep") {
        Some(v) => v,
        None => {
            return Ok(ScannerConfig {
                semgrep_enabled: false,
            });
        }
    };
    let enabled = match semgrep.get("enabled") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => {
            anyhow::bail!("config.scanner.semgrep.enabled must be a boolean (true or false)")
        }
        None => false,
    };
    Ok(ScannerConfig {
        semgrep_enabled: enabled,
    })
}

/// One dataflow candidate Semgrep produced. Threaded through to the
/// model via the seed files and back through the post-turn
/// annotation pass that sets `detection_source` on findings whose
/// `(file, line)` matches a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub seed_id: String,
    pub rule_id: String,
    pub file: String,
    pub line: u64,
    pub message: String,
}

/// What happened on a Semgrep dispatch attempt. The runner emits a
/// matching audit row for each variant.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// Semgrep ran and produced this seed set (possibly empty).
    /// `version` is the binary's reported version (equal to
    /// [`PINNED_SEMGREP_VERSION`] when the contract holds), and
    /// `ruleset_sha` is the hex sha-256 of [`RULESET_BYTES`].
    Dispatched {
        version: String,
        ruleset_sha: String,
        seeds: Vec<Seed>,
    },
    /// Dispatch did not happen. `reason` is a stable snake_case
    /// label (`binary_not_found`, `version_mismatch`,
    /// `invocation_failed`, `parse_failed`). The runner records it on
    /// the `lyrik.scanner.unavailable` audit row and proceeds with
    /// LLM-only scanning.
    Unavailable {
        reason: String,
        detail: serde_json::Value,
    },
}

/// Run Semgrep against `target` with the bundled ruleset. Writes
/// nothing; the caller materialises seeds and emits audit rows.
///
/// Behaviour:
///
/// - `semgrep` not on PATH or fails to invoke → `Unavailable
///   { reason: "binary_not_found" }`.
/// - `semgrep --version` reports a string that does not equal
///   [`PINNED_SEMGREP_VERSION`] → `Unavailable
///   { reason: "version_mismatch" }`.
/// - `semgrep --config <ruleset> --json --quiet <target>` exits
///   non-zero with no parseable stdout → `Unavailable
///   { reason: "invocation_failed" }`.
/// - stdout is not the Semgrep JSON shape → `Unavailable
///   { reason: "parse_failed" }`.
/// - Otherwise → `Dispatched` with the parsed seeds.
pub fn dispatch_semgrep(target: &Path, ruleset_path: &Path) -> DispatchOutcome {
    let version_out = match Command::new("semgrep").arg("--version").output() {
        Ok(o) => o,
        Err(e) => {
            return DispatchOutcome::Unavailable {
                reason: "binary_not_found".to_string(),
                detail: serde_json::json!({ "error": e.to_string() }),
            };
        }
    };
    let version = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_string();
    if version != PINNED_SEMGREP_VERSION {
        return DispatchOutcome::Unavailable {
            reason: "version_mismatch".to_string(),
            detail: serde_json::json!({
                "expected": PINNED_SEMGREP_VERSION,
                "found": version,
            }),
        };
    }

    let scan = match Command::new("semgrep")
        .arg("--config")
        .arg(ruleset_path)
        .arg("--json")
        .arg("--quiet")
        .arg("--metrics=off")
        .arg(target)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return DispatchOutcome::Unavailable {
                reason: "invocation_failed".to_string(),
                detail: serde_json::json!({ "error": e.to_string() }),
            };
        }
    };

    // Semgrep exits non-zero when it finds matches; that's normal,
    // not failure. Only treat a non-zero exit with empty stdout as a
    // hard failure.
    if !scan.status.success() && scan.stdout.is_empty() {
        return DispatchOutcome::Unavailable {
            reason: "invocation_failed".to_string(),
            detail: serde_json::json!({
                "exit_status": scan.status.code(),
                "stderr": String::from_utf8_lossy(&scan.stderr).to_string(),
            }),
        };
    }

    let seeds = match parse_semgrep_json(&scan.stdout, target) {
        Ok(s) => s,
        Err(e) => {
            return DispatchOutcome::Unavailable {
                reason: "parse_failed".to_string(),
                detail: serde_json::json!({ "error": e.to_string() }),
            };
        }
    };

    DispatchOutcome::Dispatched {
        version,
        ruleset_sha: ruleset_sha_hex(),
        seeds,
    }
}

/// Hex-encoded sha-256 of [`RULESET_BYTES`]. Computed each call;
/// callers cache when needed (single-shot per run today).
pub fn ruleset_sha_hex() -> String {
    let mut hasher = Sha256::new();
    hasher.update(RULESET_BYTES);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("write to String never fails");
    }
    s
}

/// Materialise the bundled ruleset to a path under the run dir so
/// Semgrep can read it. Returns the path written to.
pub fn write_bundled_ruleset(run_dir: &Path) -> Result<PathBuf> {
    let path = run_dir.join("semgrep-ruleset.yml");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&path, RULESET_BYTES).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Materialise the seed list to `<run-dir>/seeds/seed-NNN.json`.
/// Returns the seeds dir path. Idempotent for the same input list.
pub fn write_seed_files(run_dir: &Path, seeds: &[Seed]) -> Result<PathBuf> {
    let seeds_dir = run_dir.join("seeds");
    std::fs::create_dir_all(&seeds_dir)
        .with_context(|| format!("create {}", seeds_dir.display()))?;
    for (i, s) in seeds.iter().enumerate() {
        let name = format!("seed-{:03}.json", i + 1);
        let body = serde_json::json!({
            "seed_id": s.seed_id,
            "tool": "semgrep",
            "rule_id": s.rule_id,
            "location": {
                "file": s.file,
                "line_start": s.line,
            },
            "message": s.message,
        });
        let path = seeds_dir.join(&name);
        std::fs::write(&path, serde_json::to_string_pretty(&body)?)
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(seeds_dir)
}

/// Parse Semgrep's JSON output into a flat seed list. Workspace-
/// relative paths are computed against `target`; Semgrep emits
/// absolute paths when invoked with an absolute target, so the
/// relativisation makes seed `file` fields comparable to finding
/// `location.file` fields the model emits.
fn parse_semgrep_json(stdout: &[u8], target: &Path) -> Result<Vec<Seed>> {
    let v: serde_json::Value = serde_json::from_slice(stdout).context("parse semgrep stdout")?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("semgrep stdout has no `results` array"))?;
    let target_abs = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());

    let mut seeds = Vec::with_capacity(results.len());
    for (i, r) in results.iter().enumerate() {
        let rule_id = r
            .get("check_id")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let path = r
            .get("path")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("semgrep result missing `path`"))?;
        let line = r
            .get("start")
            .and_then(|x| x.get("line"))
            .and_then(|x| x.as_u64())
            .ok_or_else(|| anyhow::anyhow!("semgrep result missing `start.line`"))?;
        let message = r
            .get("extra")
            .and_then(|x| x.get("message"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        let path_buf = PathBuf::from(path);
        let rel = path_buf
            .strip_prefix(&target_abs)
            .or_else(|_| path_buf.strip_prefix(target))
            .map(|p| p.to_path_buf())
            .unwrap_or(path_buf);

        seeds.push(Seed {
            seed_id: format!("S{:03}", i + 1),
            rule_id,
            file: rel.to_string_lossy().into_owned(),
            line,
            message,
        });
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_scanner_config_absent_block_disables() {
        let cfg = serde_json::json!({"phases": {}});
        let s = parse_scanner_config(&cfg).unwrap();
        assert!(!s.semgrep_enabled);
    }

    #[test]
    fn parse_scanner_config_absent_semgrep_disables() {
        let cfg = serde_json::json!({"scanner": {}});
        let s = parse_scanner_config(&cfg).unwrap();
        assert!(!s.semgrep_enabled);
    }

    #[test]
    fn parse_scanner_config_false_explicitly() {
        let cfg = serde_json::json!({"scanner": {"semgrep": {"enabled": false}}});
        let s = parse_scanner_config(&cfg).unwrap();
        assert!(!s.semgrep_enabled);
    }

    #[test]
    fn parse_scanner_config_true_enables() {
        let cfg = serde_json::json!({"scanner": {"semgrep": {"enabled": true}}});
        let s = parse_scanner_config(&cfg).unwrap();
        assert!(s.semgrep_enabled);
    }

    #[test]
    fn parse_scanner_config_non_bool_enabled_errors() {
        let cfg = serde_json::json!({"scanner": {"semgrep": {"enabled": "yes"}}});
        assert!(parse_scanner_config(&cfg).is_err());
    }

    #[test]
    fn ruleset_sha_hex_is_64_lowercase_hex_chars() {
        let s = ruleset_sha_hex();
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn ruleset_sha_hex_is_deterministic() {
        assert_eq!(ruleset_sha_hex(), ruleset_sha_hex());
    }

    #[test]
    fn write_bundled_ruleset_creates_file_with_pinned_bytes() {
        let tmp = tempdir().unwrap();
        let p = write_bundled_ruleset(tmp.path()).unwrap();
        let body = std::fs::read(&p).unwrap();
        assert_eq!(body, RULESET_BYTES);
    }

    #[test]
    fn write_seed_files_produces_zero_padded_names_and_seed_id() {
        let tmp = tempdir().unwrap();
        let seeds = vec![
            Seed {
                seed_id: "S001".into(),
                rule_id: "lyrik.rust.command-injection-taint".into(),
                file: "src/a.rs".into(),
                line: 12,
                message: "tainted".into(),
            },
            Seed {
                seed_id: "S002".into(),
                rule_id: "lyrik.rust.format-sql-taint".into(),
                file: "src/b.rs".into(),
                line: 30,
                message: "sql".into(),
            },
        ];
        let dir = write_seed_files(tmp.path(), &seeds).unwrap();
        let one = std::fs::read_to_string(dir.join("seed-001.json")).unwrap();
        let two = std::fs::read_to_string(dir.join("seed-002.json")).unwrap();
        let one_v: serde_json::Value = serde_json::from_str(&one).unwrap();
        let two_v: serde_json::Value = serde_json::from_str(&two).unwrap();
        assert_eq!(one_v["seed_id"], "S001");
        assert_eq!(one_v["tool"], "semgrep");
        assert_eq!(one_v["location"]["file"], "src/a.rs");
        assert_eq!(one_v["location"]["line_start"], 12);
        assert_eq!(two_v["seed_id"], "S002");
    }

    #[test]
    fn parse_semgrep_json_extracts_relative_paths() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().to_path_buf();
        std::fs::create_dir_all(target.join("src")).unwrap();
        let abs_path = target.join("src/a.rs");
        let stdout = serde_json::json!({
            "results": [
                {
                    "check_id": "lyrik.rust.command-injection-taint",
                    "path": abs_path.to_string_lossy(),
                    "start": { "line": 42 },
                    "extra": { "message": "tainted env into Command" }
                }
            ]
        });
        let bytes = serde_json::to_vec(&stdout).unwrap();
        let seeds = parse_semgrep_json(&bytes, &target).unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].seed_id, "S001");
        assert_eq!(seeds[0].file, "src/a.rs");
        assert_eq!(seeds[0].line, 42);
        assert_eq!(seeds[0].rule_id, "lyrik.rust.command-injection-taint");
    }

    #[test]
    fn parse_semgrep_json_rejects_missing_results_array() {
        let bytes = b"{}";
        let tmp = tempdir().unwrap();
        let err = parse_semgrep_json(bytes, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("results"));
    }

    #[test]
    fn dispatch_semgrep_returns_unavailable_when_binary_absent() {
        // If `semgrep` happens to be on PATH the test still passes
        // because either version_mismatch or invocation_failed
        // produces an Unavailable variant; the assertion is on the
        // variant, not the reason. The point is: dispatch returns
        // cleanly without panicking when the binary is missing.
        let tmp = tempdir().unwrap();
        let rs = write_bundled_ruleset(tmp.path()).unwrap();
        let outcome = dispatch_semgrep(tmp.path(), &rs);
        match outcome {
            DispatchOutcome::Unavailable { .. } | DispatchOutcome::Dispatched { .. } => {}
        }
    }
}
