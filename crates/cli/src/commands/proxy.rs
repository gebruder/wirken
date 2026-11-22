//! `wirken proxy`: the tokens clients of the inference proxy
//! authenticate with.
//!
//! Issuing and revoking a token decide who may spend the operator's
//! provider credentials, so both are done at a terminal, refuse inside
//! a Wirken `exec`, and are a signed row on the operator lane. A token
//! is shown once, when it is issued: only its digest is stored.

use anyhow::{Context, Result, bail};
use wirken_gateway::budget::BudgetWindow;
use wirken_gateway::proxy::{
    PROXY_TOKENS_FILE, ProxyConfig, ProxyToken, ProxyTokenStore, TokenGrant,
};

use super::config;

/// Refuse without a terminal. The exec marker is refused, with a row,
/// before any command here is dispatched.
fn require_terminal(command: &str) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        bail!(
            "wirken proxy {command} refuses to run inside a Wirken exec ({} is set); \
             run it yourself, from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("wirken proxy {command} is run by the operator at a terminal");
    }
    Ok(())
}

pub(crate) fn open_store(data_dir: &std::path::Path) -> Result<ProxyTokenStore> {
    ProxyTokenStore::open(&data_dir.join(PROXY_TOKENS_FILE))
        .context("Failed to open the proxy token store")
}

fn parse_window(window: &str) -> Result<BudgetWindow> {
    Ok(match window {
        "hour" => BudgetWindow::Hour,
        "day" => BudgetWindow::Day,
        "week" => BudgetWindow::Week,
        other => bail!("--window {other:?} is not hour, day or week"),
    })
}

/// What a token is allowed, as one line for a row or a listing.
fn describe(token: &ProxyToken) -> String {
    let mut parts = vec![format!("upstreams {}", token.upstreams.join(","))];
    parts.push(if token.models.is_empty() {
        "any model".to_string()
    } else {
        format!("models {}", token.models.join(","))
    });
    if let Some(micros) = token.ceiling_usd_micros {
        parts.push(format!(
            "${:.2} a {}",
            micros as f64 / 1e6,
            token.window.label()
        ));
    }
    if let Some(calls) = token.ceiling_calls {
        parts.push(format!("{calls} calls a {}", token.window.label()));
    }
    parts.join("; ")
}

/// Issue a token in `data_dir` and record it. The token is taken back
/// if its row cannot be written. Returns the record and the token.
pub(crate) fn issue_recorded(
    data_dir: &std::path::Path,
    grant: &TokenGrant,
) -> Result<(ProxyToken, String)> {
    if let Some(config) = ProxyConfig::load(data_dir).map_err(|e| anyhow::anyhow!("{e}"))? {
        for upstream in &grant.upstreams {
            if !config.upstreams.contains_key(upstream) {
                bail!(
                    "proxy.json has no upstream named {upstream}; it has {}",
                    config
                        .upstreams
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
    let store = open_store(data_dir)?;
    let (token, value) = store.issue(grant).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Err(e) = super::record_operator_command(
        "proxy token issue",
        &format!("{} ({})", token.name, token.id),
        &describe(&token),
    ) {
        let _ = store.revoke(&token.id);
        return Err(e.context("the token was not issued: its row could not be written"));
    }
    Ok((token, value))
}

/// Revoke a token in `data_dir` and record it.
pub(crate) fn revoke_recorded(
    data_dir: &std::path::Path,
    id_or_name: &str,
) -> Result<Option<ProxyToken>> {
    let store = open_store(data_dir)?;
    let Some(token) = store
        .revoke(id_or_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(None);
    };
    super::record_operator_command(
        "proxy token revoke",
        &format!("{} ({})", token.name, token.id),
        "",
    )
    .context("the token is revoked, but its row could not be written")?;
    Ok(Some(token))
}

#[allow(clippy::too_many_arguments)]
pub fn token_issue(
    name: &str,
    upstreams: &[String],
    models: &[String],
    ceiling_usd: Option<f64>,
    ceiling_calls: Option<u64>,
    window: &str,
) -> Result<()> {
    require_terminal("token issue")?;
    let ceiling_usd_micros = match ceiling_usd {
        Some(usd) if !(usd.is_finite() && usd > 0.0) => {
            bail!("--ceiling-usd must be a positive number")
        }
        Some(usd) => Some((usd * 1e6) as u64),
        None => None,
    };
    if ceiling_calls == Some(0) {
        bail!("--ceiling-calls must be above zero");
    }
    let grant = TokenGrant {
        name: name.to_string(),
        upstreams: upstreams.to_vec(),
        models: models.to_vec(),
        ceiling_usd_micros,
        ceiling_calls,
        window: parse_window(window)?,
    };
    let (token, value) = issue_recorded(&config().data_dir, &grant)?;
    println!(
        "  Issued token {} ({}): {}",
        token.name,
        token.id,
        describe(&token)
    );
    println!();
    println!("  {value}");
    println!();
    println!("  This is the only time it is shown. A client sends it as its API key.");
    Ok(())
}

pub fn token_revoke(id_or_name: &str) -> Result<()> {
    require_terminal("token revoke")?;
    match revoke_recorded(&config().data_dir, id_or_name)? {
        Some(token) => println!("  Revoked token {} ({}).", token.name, token.id),
        None => bail!("no live token has the id or name {id_or_name}"),
    }
    Ok(())
}

/// Destroy the key of the archived body with this hash in `data_dir`,
/// then record it. The object stays in the bucket for its retention
/// period and can no longer be read. Returns how many keys were
/// destroyed.
pub(crate) fn redact_recorded(
    data_dir: &std::path::Path,
    sha256: &str,
    reason: &str,
) -> Result<usize> {
    use wirken_audit::SessionLog as _;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{sha256:?} is not a SHA-256 hash: 64 hex characters, as on the row");
    }
    let sha256 = sha256.to_ascii_lowercase();
    let keys = super::proxy_archive::KeyStore::open(
        &data_dir.join(super::proxy_archive::ARCHIVE_KEYS_FILE),
    )
    .map_err(|e| anyhow::anyhow!("the archive key store: {e}"))?;
    // The key first, the row after: the row says what was done.
    let destroyed = keys
        .destroy(&sha256)
        .map_err(|e| anyhow::anyhow!("the key was not destroyed: {e}"))?;
    let log = super::open_signed_session_log(&config())?;
    let handle = log.handle_for(wirken_audit::SessionId::new(
        wirken_audit::PROXY_SESSION.to_string(),
    ));
    log.append(
        &handle,
        wirken_audit::TrustLevel::User,
        wirken_audit::SessionEvent::ProxyArchiveRedacted {
            sha256: wirken_audit::HashHex(sha256),
            operator: super::local_operator(),
            reason: reason.to_string(),
        },
    )
    .context("the key is destroyed, but its row could not be written")?;
    super::seal_operator_lane(&log, wirken_audit::PROXY_SESSION);
    Ok(destroyed)
}

pub fn archive_redact(sha256: &str, reason: &str) -> Result<()> {
    require_terminal("archive redact")?;
    let destroyed = redact_recorded(&config().data_dir, sha256, reason)?;
    if destroyed == 0 {
        println!(
            "  No key was held for {sha256}. It is marked: a body with this hash is not \
             archived readable from here on."
        );
    } else {
        println!(
            "  Destroyed {destroyed} key{} for {sha256}. The object stays in the bucket until \
             its retention ends and can no longer be read.",
            if destroyed == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

pub fn token_list() -> Result<()> {
    let tokens = open_store(&config().data_dir)?
        .list()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if tokens.is_empty() {
        println!("  No proxy tokens. Issue one with `wirken proxy token issue`.");
        return Ok(());
    }
    for token in tokens {
        let state = match &token.revoked_at {
            Some(at) => format!("revoked {at}"),
            None => format!("issued {}", token.created_at),
        };
        println!(
            "  {}  {}  {}  ({state})",
            token.id,
            token.name,
            describe(&token)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_described_by_what_it_allows() {
        let token = ProxyToken {
            id: "0a1b2c3d".into(),
            name: "laptop".into(),
            upstreams: vec!["local".into(), "cloud".into()],
            models: vec![],
            ceiling_usd_micros: Some(2_500_000),
            ceiling_calls: Some(100),
            window: BudgetWindow::Day,
            created_at: String::new(),
            revoked_at: None,
        };
        assert_eq!(
            describe(&token),
            "upstreams local,cloud; any model; $2.50 a day; 100 calls a day"
        );
    }

    #[test]
    fn a_window_is_hour_day_or_week() {
        assert_eq!(parse_window("hour").unwrap(), BudgetWindow::Hour);
        assert_eq!(parse_window("week").unwrap(), BudgetWindow::Week);
        assert!(parse_window("month").is_err());
    }
}
