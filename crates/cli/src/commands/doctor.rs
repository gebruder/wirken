use anyhow::Result;

use super::config;
use wirken_audit::{AlarmLog, AlarmVerifyStatus, AuditLog, VerifyResult};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_vault::probe_keychain;

pub async fn run() -> Result<()> {
    println!();
    println!("  wirken doctor");
    println!("  ─────────────");
    println!();

    let cfg = config();
    let mut issues = 0;

    // Check data directory
    print_check("Data directory", &cfg.data_dir.display().to_string());
    if !cfg.data_dir.exists() {
        print_warn("  Data directory does not exist. Run `wirken setup`.");
        issues += 1;
    } else {
        print_ok();
    }

    // Check provider config
    let provider_path = cfg.data_dir.join("provider.json");
    print_check("AI provider", "provider.json");
    if provider_path.exists() {
        let content = std::fs::read_to_string(&provider_path).unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
        let provider = json["provider"].as_str().unwrap_or("unknown");
        let model = json["model"].as_str().unwrap_or("unknown");
        print_ok();
        println!("    {provider}/{model}");
    } else {
        print_warn("  Not configured. Run `wirken setup`.");
        issues += 1;
    }

    // Check vault
    print_check(
        "Credential vault",
        &cfg.vault_db_path().display().to_string(),
    );
    if cfg.vault_db_path().exists() {
        print_ok();
    } else {
        print_warn("  No credentials stored yet.");
    }

    // Check adapters
    print_check(
        "Adapter registry",
        &cfg.adapters_db_path().display().to_string(),
    );
    if cfg.adapters_db_path().exists() {
        match AdapterRegistry::open(&cfg.adapters_db_path()) {
            Ok(reg) => {
                let adapters = reg.list();
                print_ok();
                if adapters.is_empty() {
                    println!("    No channels configured.");
                } else {
                    for a in &adapters {
                        println!("    {} ({})", a.adapter_id, a.channel);
                    }
                }
            }
            Err(e) => {
                print_fail(&format!("  {e}"));
                issues += 1;
            }
        }
    } else {
        print_warn("  No channels configured.");
    }

    // Check audit log
    print_check("Audit log", &cfg.audit_db_path().display().to_string());
    if cfg.audit_db_path().exists() {
        match AuditLog::open(&cfg.audit_db_path()) {
            Ok(log) => match log.verify() {
                Ok(VerifyResult::Ok {
                    rows_verified,
                    signed_heads_count,
                    ..
                }) => {
                    print_ok();
                    println!(
                        "    {rows_verified} events, hash chain intact, \
                         {signed_heads_count} signed chain heads."
                    );
                }
                Ok(VerifyResult::Empty) => {
                    print_ok();
                    println!("    Empty.");
                }
                Ok(VerifyResult::Broken {
                    session_id, seq, ..
                }) => {
                    print_fail(&format!(
                        "  Hash chain broken at session {session_id} seq {seq}!"
                    ));
                    issues += 1;
                }
                Ok(VerifyResult::SignatureInvalid {
                    session_id,
                    seq,
                    signing_key_id,
                    ..
                }) => {
                    print_fail(&format!(
                        "  Chain head signature invalid at session {session_id} seq {seq} \
                         (key {signing_key_id})"
                    ));
                    issues += 1;
                }
                Ok(VerifyResult::MissingChainHead { session_id, .. }) => {
                    // Doctor runs in transition mode (no
                    // --require-signed), so this branch is reachable
                    // only when the verifier's caller asked for it.
                    print_fail(&format!("  Session {session_id} has no signed chain heads"));
                    issues += 1;
                }
                Err(e) => {
                    print_fail(&format!("  {e}"));
                    issues += 1;
                }
            },
            Err(e) => {
                print_fail(&format!("  {e}"));
                issues += 1;
            }
        }

        // Attestation chain check across all sessions.
        print_check("Attestation chain", "all sessions");
        match AuditLog::open(&cfg.audit_db_path()) {
            Ok(log) => match log.list_session_ids() {
                Ok(ids) => {
                    let session_log = log.session_log();
                    match wirken_agent::attestation::verify_recent_attestations(
                        session_log.as_ref(),
                        &ids,
                    ) {
                        Ok(wirken_agent::attestation::RecentAttestationResult::Ok {
                            sessions_checked,
                            attestations_verified,
                        }) => {
                            print_ok();
                            println!(
                                "    {sessions_checked} sessions, \
                                 {attestations_verified} attestation signatures verified."
                            );
                            println!(
                                "    Note: this verifies internal consistency only. The signer key \
                                 carried on each attestation is the agent's own identity key; an \
                                 operator-pinned trust anchor is not yet wired up."
                            );
                        }
                        Ok(other) => {
                            print_fail(&format!("  {other:?}"));
                            issues += 1;
                        }
                        Err(e) => {
                            print_fail(&format!("  {e}"));
                            issues += 1;
                        }
                    }
                }
                Err(e) => {
                    print_fail(&format!("  list session ids: {e}"));
                    issues += 1;
                }
            },
            Err(e) => {
                print_fail(&format!("  {e}"));
                issues += 1;
            }
        }
    } else {
        print_ok();
        println!("    Not created yet (starts on first event).");
    }

    // Out-of-chain alarm log. Surfaces continuous-verify integrity
    // alarms even when the in-chain audit row was tampered along
    // with the rest of the chain. Try to load the HMAC signing key
    // from the keychain; on success, doctor shows per-record verify
    // status. On failure (missing OS keychain, no passphrase
    // available), doctor reads in unsigned mode and surfaces the
    // posture.
    let alarm_log = {
        let kc = probe_keychain(&cfg.data_dir, String::new);
        match wirken_vault::load_or_create_alarm_log_key(kc.as_ref()) {
            Ok(key) => AlarmLog::with_signing_key(&cfg.data_dir, key),
            Err(_) => AlarmLog::new(&cfg.data_dir),
        }
    };
    print_check("Audit alarm log", &alarm_log.path().display().to_string());
    let signed = alarm_log.is_signed();
    match alarm_log.read_all() {
        Ok(records) if records.is_empty() => {
            print_ok();
            println!("    No alarms.");
            if !signed {
                println!(
                    "    Note: HMAC key unavailable; running in unsigned-read mode. \
                     Records will show as NoKey or Unsigned when present."
                );
            }
        }
        Ok(records) => {
            let tampered = records
                .iter()
                .filter(|v| v.status == AlarmVerifyStatus::Tampered)
                .count();
            if tampered > 0 {
                print_fail(&format!(
                    "  {} alarm(s); {tampered} TAMPERED",
                    records.len()
                ));
            } else {
                print_fail(&format!("  {} integrity alarm(s) on file", records.len()));
            }
            for v in records.iter().take(5) {
                let r = &v.record;
                let badge = match v.status {
                    AlarmVerifyStatus::Verified => "[verified]",
                    AlarmVerifyStatus::NoKey => "[no-key]",
                    AlarmVerifyStatus::Unsigned => "[unsigned]",
                    AlarmVerifyStatus::Tampered => "[TAMPERED]",
                };
                println!(
                    "    {badge} [{}] {} session={} seq={} expected={} actual={}",
                    r.timestamp,
                    r.alarm_type,
                    r.session_id.as_deref().unwrap_or("-"),
                    r.seq.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                    r.expected_hash.as_deref().unwrap_or("-"),
                    r.actual_hash.as_deref().unwrap_or("-"),
                );
            }
            if records.len() > 5 {
                println!("    ... and {} more", records.len() - 5);
            }
            if !signed {
                println!(
                    "    Note: HMAC key unavailable; integrity verdicts shown as \
                     NoKey reflect the reader's posture, not the writer's."
                );
            }
            issues += 1;
        }
        Err(e) => {
            print_fail(&format!("  {e}"));
            issues += 1;
        }
    }

    // Check sandbox runtimes
    print_check("Docker runtime", "sandbox");
    match wirken_agent::sandbox::detect_runtime().await {
        Some(rt) => {
            print_ok();
            println!("    {rt}");

            // Check gVisor
            print_check("gVisor (runsc)", "sandbox");
            if wirken_agent::sandbox::detect_gvisor().await {
                print_ok();
                println!("    Available as Docker runtime");
            } else {
                print_ok();
                println!("    Not installed (optional)");
            }
        }
        None => {
            print_ok();
            println!("    Not available (sandbox features disabled)");
        }
    }

    println!();
    if issues == 0 {
        println!("  All checks passed.");
    } else {
        println!("  {issues} issue(s) found.");
    }
    println!();

    Ok(())
}

fn print_check(name: &str, _detail: &str) {
    print!("  {name:.<30} ");
}

fn print_ok() {
    println!("OK");
}

fn print_warn(msg: &str) {
    println!("WARN");
    println!("  {msg}");
}

fn print_fail(msg: &str) {
    println!("FAIL");
    println!("  {msg}");
}
