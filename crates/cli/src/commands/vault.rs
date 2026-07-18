use anyhow::Result;
use std::io::Write;

use super::config;

/// `wirken vault reset`: destroy the device key and every stored
/// credential so the vault can be rebuilt from scratch. This is the
/// documented way out of a forgotten passphrase, where
/// `CredentialStore::open` refuses to overwrite the keychain it cannot
/// unwrap. The operator must type `reset`; there is no `--force` bypass.
pub fn reset() -> Result<()> {
    let cfg = config();
    let db_path = cfg.vault_db_path();
    let plan = wirken_vault::reset_plan(&cfg.data_dir, &db_path);

    if plan.keychain_dir.is_none() && plan.db_files.is_empty() {
        println!(
            "  No vault state found at {}; nothing to reset.",
            cfg.data_dir.display()
        );
        return Ok(());
    }

    println!("  This will permanently destroy:");
    if let Some(dir) = &plan.keychain_dir {
        println!("    keychain directory: {}", dir.display());
        println!(
            "      the device key, its salt, and all aux keys (including the alarm-log HMAC key)"
        );
    }
    for f in &plan.db_files {
        println!("    credential db: {}", f.display());
    }
    if let Some(n) = plan.credential_rows {
        println!("    {n} stored credential row(s) will be lost");
    }
    println!();
    println!("  All stored credentials become unrecoverable. The secrets");
    println!("  themselves remain live at their providers — rotate them there.");
    println!("  The alarm-log key regenerates on next use. The audit log is");
    println!("  not touched.");
    println!();
    print!("  Type `reset` to confirm: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !reset_confirmed(&input) {
        println!("  Aborted. No changes made.");
        return Ok(());
    }

    let removed = wirken_vault::reset(&cfg.data_dir, &db_path)?;
    for p in &removed {
        println!("  removed {}", p.display());
    }
    println!("  Vault reset. The next vault open creates a fresh empty store.");
    Ok(())
}

/// The confirmation gate. Only the exact word `reset`, ignoring the
/// trailing line terminator from the prompt, proceeds; every other input
/// aborts with no deletion. Deliberately strict: surrounding whitespace
/// or any other token does not count.
fn reset_confirmed(input: &str) -> bool {
    input.trim_end_matches(['\n', '\r']) == "reset"
}

#[cfg(test)]
mod tests {
    use super::reset_confirmed;

    #[test]
    fn reset_confirmed_accepts_exact_word_with_line_terminator() {
        assert!(reset_confirmed("reset\n"));
        assert!(reset_confirmed("reset\r\n"));
        assert!(reset_confirmed("reset"));
    }

    #[test]
    fn reset_confirmed_rejects_anything_else() {
        assert!(!reset_confirmed(""));
        assert!(!reset_confirmed("\n"));
        assert!(!reset_confirmed("yes\n"));
        assert!(!reset_confirmed("Reset\n"));
        assert!(!reset_confirmed("resett\n"));
        assert!(!reset_confirmed("reset now\n"));
        // Surrounding whitespace is not the exact word.
        assert!(!reset_confirmed(" reset\n"));
        assert!(!reset_confirmed("reset \n"));
    }
}
