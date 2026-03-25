use anyhow::Result;

use super::config;
use wirken_audit::{AuditLog, VerifyResult};
use wirken_gateway::adapter_registry::AdapterRegistry;

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
                Ok(VerifyResult::Ok { rows_verified }) => {
                    print_ok();
                    println!("    {rows_verified} events, hash chain intact.");
                }
                Ok(VerifyResult::Empty) => {
                    print_ok();
                    println!("    Empty.");
                }
                Ok(VerifyResult::Broken { row_id, .. }) => {
                    print_fail(&format!("  Hash chain broken at row {row_id}!"));
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
    } else {
        print_ok();
        println!("    Not created yet (starts on first event).");
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
