//! `wirken proxy identity`: which grants a JWT of the organization's
//! identity provider is given at the proxy listener.
//!
//! A grant set is what a token carries, with no secret: upstreams,
//! models, ceilings, and the MCP servers of one agent. A mapping gives
//! a grant set to the JWTs whose grant claim holds a value, or to one
//! subject. Writing either decides who may spend the operator's
//! provider credentials, so each change is made at a terminal, refuses
//! inside a Wirken `exec`, and is a signed row on the operator lane.
//!
//! Nothing here makes an identity. A subject is whoever the issuer
//! says it is; these commands say only what that subject may do.

use anyhow::{Context, Result, bail};
use wirken_gateway::proxy::{MappingKind, OidcConfig, ProxyConfig};
use wirken_gateway::proxy_identity::subject_hash;
use wirken_vault::CredentialStore;

use super::config;
use super::proxy::{check_grant, describe_grants, grant_from_flags, open_store, require_terminal};

/// The `oidc` block of `proxy.json` in `data_dir`. A mapping is
/// written for its issuer, so there is none to write without it.
fn oidc(data_dir: &std::path::Path) -> Result<OidcConfig> {
    ProxyConfig::load(data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .and_then(|c| c.oidc)
        .context(
            "proxy.json has no oidc block. A mapping is for the JWTs of one issuer: set \
             \"oidc\" with its issuer, audience and max_token_lifetime_secs first",
        )
}

/// What a mapping matches on, from the two flags.
fn matched(claim_value: Option<&str>, subject: Option<&str>) -> Result<(MappingKind, String)> {
    match (claim_value, subject) {
        (Some(value), None) => Ok((MappingKind::Claim, value.to_string())),
        (None, Some(subject)) => Ok((MappingKind::Subject, subject.to_string())),
        _ => bail!("give one of --claim-value and --subject"),
    }
}

/// How a mapping's match is named on its row. A claim value is named
/// as it is. A subject is named as the rows of its calls name it: by
/// its keyed hash, or as issued where `record_subject` is set.
fn named(
    oidc: &OidcConfig,
    kind: MappingKind,
    value: &str,
    subject_key: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<String> {
    Ok(match kind {
        MappingKind::Claim => format!(
            "claim {}={value}",
            oidc.grant_claim.as_deref().unwrap_or_default()
        ),
        MappingKind::Subject if oidc.record_subject => format!("subject {value}"),
        MappingKind::Subject => format!(
            "subject {}",
            subject_hash(&subject_key()?, &oidc.issuer, value)
        ),
    })
}

/// The key subjects are hashed under, from the vault.
fn vault_subject_key(oidc: &OidcConfig) -> Result<Vec<u8>> {
    let cfg = config();
    let passphrase = super::cached_vault_passphrase()?;
    let keychain = wirken_vault::probe_keychain(&cfg.data_dir, move || passphrase);
    let vault = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    super::proxy_oidc::subject_key(&vault, &oidc.subject_key)
        .map(|key| key.to_vec())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Write the grant set in `data_dir` and record it. It is put back as
/// it was if its row cannot be written. Returns the line that
/// describes it and whether it replaced one.
pub(crate) fn grant_set_recorded(
    data_dir: &std::path::Path,
    grant: &wirken_gateway::proxy::TokenGrant,
) -> Result<(String, bool)> {
    check_grant(data_dir, grant)?;
    let store = open_store(data_dir)?;
    let (set, previous) = store
        .set_grant_set(grant)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let described = describe_grants(
        &set.upstreams,
        &set.models,
        &set.mcp_servers,
        &set.mcp_agent,
        set.ceiling_usd_micros,
        set.ceiling_calls,
        set.window,
    );
    if let Err(e) =
        super::record_operator_command("proxy identity grant-set set", &set.name, &described)
    {
        let _ = store.restore_grant_set(&set.name, previous.as_ref());
        return Err(e.context("the grant set was not written: its row could not be written"));
    }
    Ok((described, previous.is_some()))
}

#[allow(clippy::too_many_arguments)]
pub fn grant_set_set(
    name: &str,
    upstreams: &[String],
    models: &[String],
    ceiling_usd: Option<f64>,
    ceiling_calls: Option<u64>,
    window: &str,
    mcp_servers: &[String],
    mcp_agent: &str,
) -> Result<()> {
    require_terminal("identity grant-set set")?;
    let grant = grant_from_flags(
        "grant set",
        name,
        upstreams,
        models,
        ceiling_usd,
        ceiling_calls,
        window,
        mcp_servers,
        mcp_agent,
    )?;
    let (described, replaced) = grant_set_recorded(&config().data_dir, &grant)?;
    println!(
        "  {} grant set {name}: {described}",
        if replaced { "Replaced" } else { "Wrote" }
    );
    println!("  Its ceilings are each subject's own.");
    Ok(())
}

pub fn grant_set_remove(name: &str) -> Result<()> {
    require_terminal("identity grant-set remove")?;
    let store = open_store(&config().data_dir)?;
    let Some(set) = store
        .remove_grant_set(name)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        bail!("there is no grant set named {name}");
    };
    super::record_operator_command("proxy identity grant-set remove", &set.name, "")
        .context("the grant set is removed, but its row could not be written")?;
    println!("  Removed grant set {name}.");
    Ok(())
}

/// Map `value` to `grant_set` in `data_dir` and record it; the mapping
/// is put back as it was if its row cannot be written. Returns the
/// grant set the value was mapped to before.
pub(crate) fn map_recorded(
    data_dir: &std::path::Path,
    kind: MappingKind,
    value: &str,
    grant_set: &str,
    subject_key: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Option<String>> {
    let oidc = oidc(data_dir)?;
    if kind == MappingKind::Claim && oidc.grant_claim.is_none() {
        bail!(
            "proxy.json: oidc names no grant_claim, so no claim value selects a grant set. \
             Set \"grant_claim\", or map a --subject"
        );
    }
    let target = named(&oidc, kind, value, subject_key)?;
    let store = open_store(data_dir)?;
    let previous = store
        .map_identity(&oidc.issuer, kind, value, grant_set)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Err(e) = super::record_operator_command(
        "proxy identity map",
        &target,
        &format!("grant set {grant_set}; issuer {}", oidc.issuer),
    ) {
        let _ = match &previous {
            Some(was) => store
                .map_identity(&oidc.issuer, kind, value, was)
                .map(|_| ()),
            None => store.unmap_identity(&oidc.issuer, kind, value).map(|_| ()),
        };
        return Err(e.context("the mapping was not written: its row could not be written"));
    }
    Ok(previous)
}

/// Remove the mapping of `value` in `data_dir` and record it. Returns
/// the grant set it named, or `None` when there was no such mapping.
pub(crate) fn unmap_recorded(
    data_dir: &std::path::Path,
    kind: MappingKind,
    value: &str,
    subject_key: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Option<String>> {
    let oidc = oidc(data_dir)?;
    let target = named(&oidc, kind, value, subject_key)?;
    let store = open_store(data_dir)?;
    let Some(was) = store
        .unmap_identity(&oidc.issuer, kind, value)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(None);
    };
    super::record_operator_command(
        "proxy identity unmap",
        &target,
        &format!("grant set {was}; issuer {}", oidc.issuer),
    )
    .context("the mapping is removed, but its row could not be written")?;
    Ok(Some(was))
}

pub fn map(grant_set: &str, claim_value: Option<&str>, subject: Option<&str>) -> Result<()> {
    require_terminal("identity map")?;
    let (kind, value) = matched(claim_value, subject)?;
    let data_dir = config().data_dir.clone();
    let key = || vault_subject_key(&oidc(&data_dir)?);
    let previous = map_recorded(&data_dir, kind, &value, grant_set, key)?;
    match previous {
        Some(was) if was != grant_set => {
            println!(
                "  Mapped {} {value} to grant set {grant_set}, in place of {was}.",
                kind.as_str()
            )
        }
        _ => println!(
            "  Mapped {} {value} to grant set {grant_set}.",
            kind.as_str()
        ),
    }
    Ok(())
}

pub fn unmap(claim_value: Option<&str>, subject: Option<&str>) -> Result<()> {
    require_terminal("identity unmap")?;
    let (kind, value) = matched(claim_value, subject)?;
    let data_dir = config().data_dir.clone();
    let key = || vault_subject_key(&oidc(&data_dir)?);
    match unmap_recorded(&data_dir, kind, &value, key)? {
        Some(was) => println!(
            "  Removed the mapping of {} {value} to grant set {was}.",
            kind.as_str()
        ),
        None => bail!("no mapping of {} {value}", kind.as_str()),
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let data_dir = &config().data_dir;
    let store = open_store(data_dir)?;
    let sets = store.grant_sets().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mappings = store
        .identity_mappings()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    match ProxyConfig::load(data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .and_then(|c| c.oidc)
    {
        Some(oidc) => println!(
            "  Issuer {} (audience {}, grant claim {})",
            oidc.issuer,
            oidc.audience,
            oidc.grant_claim.as_deref().unwrap_or("none: subjects only")
        ),
        None => println!("  proxy.json has no oidc block: no JWT is accepted."),
    }
    if sets.is_empty() {
        println!("  No grant sets. Write one with `wirken proxy identity grant-set set`.");
    }
    for set in &sets {
        println!(
            "  grant set {}  {}",
            set.name,
            describe_grants(
                &set.upstreams,
                &set.models,
                &set.mcp_servers,
                &set.mcp_agent,
                set.ceiling_usd_micros,
                set.ceiling_calls,
                set.window,
            )
        );
    }
    for mapping in &mappings {
        println!(
            "  {} {} -> {}  (issuer {})",
            mapping.kind.as_str(),
            mapping.value,
            mapping.grant_set,
            mapping.issuer
        );
    }
    Ok(())
}
