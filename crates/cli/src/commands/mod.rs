pub mod adapter;
pub mod agent;
pub mod audit;
pub mod channel;
pub mod credential;
pub mod doctor;
pub mod permission;
pub mod run;
pub mod session;
pub mod setup;
pub mod webchat;

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
