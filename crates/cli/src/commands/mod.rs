pub mod adapter;
pub mod agent;
pub mod agents;
pub mod audit;
pub mod channel;
pub mod credential;
pub mod cron;
pub mod doctor;
pub mod permission;
pub mod run;
pub mod service;
pub mod session;
pub mod setup;
pub mod skills;
pub mod webchat;

use std::io::Write;
use std::path::PathBuf;
use wirken_gateway::config::GatewayConfig;

/// Resolve the data directory, ensuring it exists.
pub fn data_dir() -> anyhow::Result<PathBuf> {
    let config = GatewayConfig::default();
    config.ensure_dirs()?;
    Ok(config.data_dir)
}

/// Get a GatewayConfig with default paths.
pub fn config() -> GatewayConfig {
    GatewayConfig::default()
}

/// Read a secret value (API key, token) with asterisk masking.
/// Unlike dialoguer's Password which shows nothing, this prints one
/// asterisk per character so the user can see that paste/typing worked.
pub fn read_secret(prompt: &str) -> anyhow::Result<String> {
    let term = console::Term::stderr();
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let mut input = String::new();
    loop {
        let key = term.read_key()?;
        match key {
            console::Key::Char(c) => {
                input.push(c);
                eprint!("*");
                std::io::stderr().flush()?;
            }
            console::Key::Backspace if !input.is_empty() => {
                input.pop();
                // Move cursor back, overwrite with space, move back again
                eprint!("\x08 \x08");
                std::io::stderr().flush()?;
            }
            console::Key::Enter => {
                eprintln!();
                break;
            }
            _ => {}
        }
    }
    Ok(input)
}
