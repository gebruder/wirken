use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use wirken_agent::skill::SkillLoader;
use wirken_gateway::skill_registry::{self, SkillIndex, VerifyResult, generate_signing_keypair};

use super::config;

const DEFAULT_INDEX_URL: &str =
    "https://raw.githubusercontent.com/gebruder/wirken-skills/main/index.json";

pub async fn search(query: &str) -> Result<()> {
    let index = fetch_index().await?;
    let results = index.search(query);

    if results.is_empty() {
        println!("  No skills found matching '{query}'.");
        return Ok(());
    }

    println!(
        "  {:20}  {:40}  {:8}  AUTHOR",
        "NAME", "DESCRIPTION", "VERSION"
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(20),
        "─".repeat(40),
        "─".repeat(8),
        "─".repeat(16)
    );

    for entry in &results {
        let signed = if entry.signature.is_some() {
            " [signed]"
        } else {
            ""
        };
        println!(
            "  {:20}  {:40}  {:8}  {}{}",
            entry.name,
            truncate(&entry.description, 40),
            entry.version,
            entry.author,
            signed,
        );
    }
    println!();
    println!(
        "  {} skills found. Install with: wirken skills install <name>",
        results.len()
    );
    Ok(())
}

/// Install gate: signature verification against the registry's
/// expected key (see `verify_skill_with_expected_key_and_delegation`
/// below) plus the `WIRKEN_ALLOW_UNSIGNED_SKILLS` env-var bypass.
/// `wirken skills install` is an operator-typed CLI command; it does
/// NOT route through the runtime permission-tier system. Tier 1/2/3
/// exists to gate model-driven actions against operator policy, and
/// adding a tier prompt for something the operator just typed would
/// be a UX papercut rather than a security control.
pub async fn install(name: &str) -> Result<()> {
    let cfg = config();
    let index = fetch_index().await?;

    let entry = index
        .find(name)
        .ok_or_else(|| anyhow::anyhow!("Skill '{name}' not found in registry"))?;

    println!(
        "  Installing '{}' v{} by {}...",
        entry.name, entry.version, entry.author
    );

    // Download SKILL.md
    let http = reqwest::Client::new();
    let resp = http
        .get(&entry.url)
        .send()
        .await
        .context("Failed to download skill")?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed: HTTP {}", resp.status());
    }

    let content = resp.text().await.context("Failed to read skill content")?;

    // Install to skills directory
    let skills_dir = cfg.data_dir.join("skills");
    let skill_dir = skills_dir.join(&entry.name);
    std::fs::create_dir_all(&skill_dir)?;

    let skill_path = skill_dir.join("SKILL.md");
    std::fs::write(&skill_path, &content)?;

    // Verify signature against the registry's expected key (not a bundled SKILL.pub).
    // This prevents an attacker from signing a tampered skill with their own key.
    // When the binary carries a bundled registry root key, the entry's
    // `signer_key` must be delegated by that root via the
    // `signer_key_delegation` field; otherwise the install is refused.
    if let (Some(sig_hex), Some(key_hex)) = (&entry.signature, &entry.signer_key) {
        let delegation = entry.signer_key_delegation.as_deref();
        let result = wirken_gateway::skill_registry::verify_skill_with_expected_key_and_delegation(
            &skill_dir,
            sig_hex,
            key_hex,
            delegation,
            wirken_gateway::skill_registry::bundled_registry_pubkey().as_ref(),
        )?;
        match result {
            VerifyResult::Valid { signer } => {
                // Write sig/pub files for future local verification
                std::fs::write(skill_dir.join("SKILL.sig"), sig_hex)?;
                std::fs::write(skill_dir.join("SKILL.pub"), key_hex)?;
                // The index's delegation of the signer key goes beside
                // them, so the skill also loads under a configured
                // registry root (strict mode), which checks SKILL.deleg.
                // An entry without one leaves no stale file from an
                // earlier install.
                let deleg_path = skill_dir.join("SKILL.deleg");
                match delegation {
                    Some(deleg_hex) => std::fs::write(&deleg_path, deleg_hex.trim())?,
                    None => match std::fs::remove_file(&deleg_path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    },
                }
                #[allow(
                    clippy::string_slice,
                    reason = "signer is key hex the ASCII-checked decoder accepted as 32 bytes: 64 ASCII chars"
                )]
                let short = &signer[..16];
                println!("  Signature valid (signer: {short}...)");
            }
            VerifyResult::Invalid => {
                // Remove the skill — signature didn't verify
                std::fs::remove_dir_all(&skill_dir)?;
                anyhow::bail!(
                    "Signature verification failed! Skill not installed. \
                     If the registry index lacks a `signer_key_delegation` \
                     field this build expects (registry root anchor enabled), \
                     the index needs to be re-signed by the upstream registry."
                );
            }
            VerifyResult::Unsigned => {}
        }
    } else if wirken_gateway::org::parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_SKILLS") {
        tracing::warn!(
            "WIRKEN_ALLOW_UNSIGNED_SKILLS=1: installing '{}' without a registry-anchored \
             signer key; the bundle's provenance is unverified",
            entry.name
        );
        println!("  Warning: skill is unsigned (WIRKEN_ALLOW_UNSIGNED_SKILLS=1).");
    } else {
        std::fs::remove_dir_all(&skill_dir)?;
        anyhow::bail!(
            "Skill '{}' has no signer_key in the registry index; refusing to install. \
             Set WIRKEN_ALLOW_UNSIGNED_SKILLS=1 to opt in.",
            entry.name
        );
    }

    println!("  Installed to {}", skill_dir.display());
    Ok(())
}

pub async fn list() -> Result<()> {
    let cfg = config();
    let skills_dir = cfg.data_dir.join("skills");

    let skills = SkillLoader::load_dir(&skills_dir).unwrap_or_default();

    if skills.is_empty() {
        println!("  No skills installed.");
        println!(
            "  `wirken setup` installs the bundled skills; sign your own with `wirken skills sign <dir>`."
        );
        return Ok(());
    }

    println!(
        "  {:20}  {:40}  {:8}  SIGNED",
        "NAME", "DESCRIPTION", "AVAILABLE"
    );
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(20),
        "─".repeat(40),
        "─".repeat(8),
        "─".repeat(8)
    );

    for skill in &skills {
        let available = if skill.available { "yes" } else { "no" };
        let skill_dir = skill.path.parent().unwrap_or(&skills_dir);
        let signed = match skill_registry::verify_skill_self_signed(skill_dir) {
            Ok(VerifyResult::Valid { .. }) => "self-signed",
            Ok(VerifyResult::Invalid) => "INVALID",
            _ => "no",
        };
        println!(
            "  {:20}  {:40}  {:8}  {}",
            skill.name,
            truncate(&skill.description, 40),
            available,
            signed,
        );
    }
    println!();
    println!("  {} skills installed.", skills.len());
    Ok(())
}

/// Install an operator-set registry root public key, opting this
/// install into strict identity anchoring. The matching private key
/// never ships and signs delegations offline.
pub async fn trust_root(pubkey_hex: &str) -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs().ok();
    skill_registry::save_registry_root(&cfg.data_dir, pubkey_hex)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = skill_registry::registry_root_path(&cfg.data_dir);
    println!("  Registry root installed: {}", path.display());
    println!("  Skill loading now requires delegation by this root (strict mode);");
    println!("  self-signed-only bundles will no longer load.");
    println!();
    println!("  Re-sign bundled and local skills as delegates of this root, using");
    println!("  the root private key in your offline signing environment:");
    println!("    wirken skills sign --root-key <offline-root-seed> <dir>");
    Ok(())
}

/// Read an offline root's Ed25519 private seed: 64 hex characters.
fn read_root_seed(path: &str) -> Result<SigningKey> {
    let root_hex = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("read root key {path}"))?,
    );
    let root_bytes = zeroize::Zeroizing::new(skill_registry::hex_decode_public(root_hex.trim())?);
    let arr: [u8; 32] = root_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("root key must be a 32-byte Ed25519 seed (64 hex chars)"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// `wirken skills sign-index`: delegate every registry index entry's
/// signer key under the offline registry root, reading each entry's
/// SKILL.md from a local checkout of the registry. Prints the signed
/// index to stdout and touches nothing else.
pub fn sign_index(
    index_path: &str,
    root_key: &str,
    skills_dir: &str,
    url_prefix: &str,
) -> Result<()> {
    let body =
        std::fs::read_to_string(index_path).with_context(|| format!("read index {index_path}"))?;
    let mut index: SkillIndex =
        serde_json::from_str(&body).with_context(|| format!("parse index {index_path}"))?;
    let root = read_root_seed(root_key)?;
    let checkout = std::path::Path::new(skills_dir);

    skill_registry::sign_index(&mut index, &root, |entry| {
        let rel = entry.url.strip_prefix(url_prefix).ok_or_else(|| {
            wirken_gateway::error::GatewayError::Config(format!(
                "'{}' url {} does not start with {url_prefix}",
                entry.name, entry.url
            ))
        })?;
        let rel = std::path::Path::new(rel);
        if !rel
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            return Err(wirken_gateway::error::GatewayError::Config(format!(
                "'{}' url path {} leaves the checkout",
                entry.name,
                rel.display()
            )));
        }
        let path = checkout.join(rel);
        std::fs::read(&path).map_err(|e| {
            wirken_gateway::error::GatewayError::Config(format!(
                "'{}' read {}: {e}",
                entry.name,
                path.display()
            ))
        })
    })?;

    println!("{}", serde_json::to_string_pretty(&index)?);
    eprintln!(
        "  Signed {} entries under registry root {}",
        index.skills.len(),
        skill_registry::hex_encode_public(&root.verifying_key().to_bytes())
    );
    Ok(())
}

pub async fn sign(dir: &str, root_key: Option<&str>) -> Result<()> {
    let skill_dir = std::path::Path::new(dir);
    if !skill_dir.join("SKILL.md").exists() {
        anyhow::bail!("No SKILL.md found in '{dir}'");
    }

    // Check for existing signing key or generate new one
    let cfg = config();
    let key_path = cfg.data_dir.join("signing-key.hex");

    let signing_key = if key_path.exists() {
        let hex = std::fs::read_to_string(&key_path)?;
        let bytes = skill_registry::hex_decode_public(hex.trim())?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        SigningKey::from_bytes(&arr)
    } else {
        let (secret_hex, public_hex) = generate_signing_keypair();
        std::fs::create_dir_all(&cfg.data_dir)?;
        std::fs::write(&key_path, &secret_hex)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        #[cfg(not(unix))]
        {
            // No 0o600-equivalent on this platform. The skill signing
            // key relies on user-profile isolation for confidentiality.
            tracing::warn!(
                "skill signing key written to {} without 0o600-equivalent ACL; \
                 relying on user profile isolation for confidentiality",
                key_path.display()
            );
        }

        println!("  Generated new signing keypair.");
        println!("  Public key: {public_hex}");
        println!("  Secret key saved to {}", key_path.display());
        println!();

        let bytes = skill_registry::hex_decode_public(&secret_hex)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        SigningKey::from_bytes(&arr)
    };

    let pub_hex = skill_registry::hex_encode_public(&signing_key.verifying_key().to_bytes());

    // Delegated sign: the operator supplies the offline root private
    // seed; we bind the signer key to that root by writing SKILL.deleg.
    // Used only for installs that opted into a registry root. Without
    // `--root-key`, self-signing is unchanged (the floor).
    if let Some(root_path) = root_key {
        let root_signing = read_root_seed(root_path)?;
        skill_registry::delegate_sign_skill(skill_dir, &signing_key, &root_signing)?;
        let root_pub = skill_registry::hex_encode_public(&root_signing.verifying_key().to_bytes());
        println!("  Signed (delegated): {}/SKILL.md", dir);
        println!("  Signer public key: {pub_hex}");
        println!("  Delegated by root: {root_pub}");
        println!("  Wrote SKILL.sig, SKILL.pub, SKILL.deleg");
        return Ok(());
    }

    let sig = skill_registry::sign_skill(skill_dir, &signing_key)?;
    println!("  Signed: {}/SKILL.md", dir);
    #[allow(
        clippy::string_slice,
        reason = "the signature is hex this binary just encoded: 128 ASCII chars"
    )]
    let (head, tail) = (&sig[..16], &sig[sig.len() - 16..]);
    println!("  Signature: {head}...{tail}");
    println!("  Public key: {pub_hex}");
    Ok(())
}

/// Outcome of `wirken skills verify` after applying the strict-mode
/// gate to a `VerifyResult`. The CLI maps `Fail` to `exit(1)`; tests
/// exercise the matrix via this enum without spawning a process.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    Ok,
    Fail,
}

pub(crate) fn decide_verify_outcome(result: &VerifyResult, strict: bool) -> VerifyOutcome {
    match result {
        VerifyResult::Valid { .. } => {
            // Self-signed only proves internal consistency. Without a
            // registry-anchored expected key the signer is whoever
            // generated the bundle, not necessarily a trusted
            // publisher. Default mode warns; --strict refuses.
            if strict {
                VerifyOutcome::Fail
            } else {
                VerifyOutcome::Ok
            }
        }
        VerifyResult::Invalid => VerifyOutcome::Fail,
        VerifyResult::Unsigned => {
            if strict {
                VerifyOutcome::Fail
            } else {
                VerifyOutcome::Ok
            }
        }
    }
}

pub async fn verify(dir: &str, strict: bool) -> Result<()> {
    let skill_dir = std::path::Path::new(dir);
    let result = skill_registry::verify_skill_self_signed(skill_dir)?;
    let outcome = decide_verify_outcome(&result, strict);

    match &result {
        VerifyResult::Valid { signer } => {
            println!("  Signature: SELF-SIGNED (bundle key matches bundle signature)");
            println!("  Signer: {signer}");
            if outcome == VerifyOutcome::Fail {
                println!(
                    "  --strict: refusing self-signed bundle. A bundle is anchored when its \
                     signer is delegated by a registry root (`wirken skills sign --root-key`) \
                     and the loading host trusts that root (`wirken skills trust-root`)."
                );
            } else {
                tracing::warn!(
                    "verify: self-signed bundle at {} accepted; pass --strict to fail \
                     on bundles without registry-anchored trust",
                    skill_dir.display()
                );
                println!(
                    "  Note: this only checks the bundle is internally consistent. To tie the \
                     signer to a publisher, trust that publisher's registry root with \
                     `wirken skills trust-root` and load bundles it delegated, or re-run \
                     with --strict."
                );
            }
        }
        VerifyResult::Invalid => {
            println!("  Signature: INVALID");
            println!("  The skill content has been modified after signing.");
        }
        VerifyResult::Unsigned => {
            println!("  Not signed.");
            if outcome == VerifyOutcome::Fail {
                println!("  --strict: refusing unsigned bundle.");
            } else {
                tracing::warn!(
                    "verify: unsigned bundle at {} accepted; pass --strict to fail \
                     on bundles without a signature",
                    skill_dir.display()
                );
            }
        }
    }

    if outcome == VerifyOutcome::Fail {
        std::process::exit(1);
    }
    Ok(())
}

/// What `search` and `install` report when the index is not there. At
/// the default URL that is the state today: no public index is published.
fn missing_index_message(url: &str) -> String {
    if url == DEFAULT_INDEX_URL {
        format!(
            "No skill index at {url} (HTTP 404): no public skill index is published yet, \
             so there is nothing to search or install. Set WIRKEN_SKILLS_INDEX to read \
             another index."
        )
    } else {
        format!("No skill index at {url} (HTTP 404, set by WIRKEN_SKILLS_INDEX).")
    }
}

async fn fetch_index() -> Result<SkillIndex> {
    let url = std::env::var("WIRKEN_SKILLS_INDEX").unwrap_or_else(|_| DEFAULT_INDEX_URL.into());

    let http = reqwest::Client::new();
    let resp = http
        .get(&url)
        .send()
        .await
        .context(format!("Failed to fetch skill index from {url}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("{}", missing_index_message(&url));
    }
    if !resp.status().is_success() {
        anyhow::bail!("Skill index at {url} answered HTTP {}", resp.status());
    }

    resp.json::<SkillIndex>()
        .await
        .context("Failed to parse skill index")
}

#[allow(
    clippy::string_slice,
    reason = "cut is walked back to a char boundary before slicing"
)]
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max.saturating_sub(3);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &s[..cut])
}

/// Migrate operator-installed skill frontmatter to the current shape.
///
/// Two transformations, both narrowly scoped:
/// 1. `metadata.openclaw` -> `metadata.wirken`. Pure rename. Triggered
///    only when `metadata.openclaw` is present and `metadata.wirken`
///    is not. If both are present the operator already partially
///    migrated; we leave it alone.
/// 2. Append a top-level `permissions:` block when missing. Stub is
///    deny-everything (empty allow lists, allowlist-mode egress with
///    empty domain set). Migrated skills load but cannot use tools,
///    egress, or filesystem until the operator edits the stub. The
///    teaching moment is in the file the operator opens next.
///
/// Each rewritten file is copied to
/// `SKILL.md.pre-migrate-<UTC-iso8601>` first; the rewrite is a
/// `serde_yaml` round-trip so YAML comments in the original
/// frontmatter are not preserved (rare in practice).
///
/// `dry_run = true` reports what would change and writes nothing.
pub async fn migrate(path: Option<&str>, dry_run: bool) -> Result<()> {
    use std::path::PathBuf;
    let dir: PathBuf = match path {
        Some(p) => PathBuf::from(p),
        None => config().data_dir.join("skills"),
    };
    if !dir.is_dir() {
        anyhow::bail!("not a directory: {}", dir.display());
    }
    println!("  Scanning {}", dir.display());

    let mut total = 0usize;
    let mut changed = 0usize;
    let mut skipped = 0usize;
    let mut errored = 0usize;

    let entries = std::fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errored += 1;
                println!("  ! dir entry: {e}");
                continue;
            }
        };
        let skill_dir = entry.path();
        if !skill_dir.is_dir() {
            continue;
        }
        let skill_file = skill_dir.join("SKILL.md");
        if !skill_file.exists() {
            continue;
        }
        total += 1;

        let name = skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?");

        match migrate_one(&skill_file, dry_run) {
            Ok(MigrationOutcome::NoChange) => {
                skipped += 1;
                println!("  - {name}: no change");
            }
            Ok(MigrationOutcome::WouldChange(changes)) => {
                changed += 1;
                println!("  ~ {name} (dry-run): {}", changes.join(", "));
            }
            Ok(MigrationOutcome::Changed { changes, backup }) => {
                changed += 1;
                println!(
                    "  + {name}: {} (backup: {})",
                    changes.join(", "),
                    backup.display()
                );
            }
            Err(e) => {
                errored += 1;
                println!("  ! {name}: {e}");
            }
        }
    }

    println!();
    if dry_run {
        println!(
            "  Dry-run: {total} skill(s) inspected, {changed} would change, {skipped} already current, {errored} errored."
        );
        println!("  Run without --dry-run to apply.");
    } else {
        println!(
            "  {total} skill(s) inspected, {changed} migrated, {skipped} already current, {errored} errored."
        );
    }
    if errored > 0 {
        anyhow::bail!("{errored} skill(s) errored during migration");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum MigrationOutcome {
    /// Nothing to do.
    NoChange,
    /// Dry-run reported a list of changes that would apply.
    WouldChange(Vec<&'static str>),
    /// Applied; backup at `backup`.
    Changed {
        changes: Vec<&'static str>,
        backup: std::path::PathBuf,
    },
}

fn migrate_one(skill_file: &std::path::Path, dry_run: bool) -> Result<MigrationOutcome> {
    let content = std::fs::read_to_string(skill_file)
        .with_context(|| format!("read {}", skill_file.display()))?;

    let (yaml_str, body, leading_separator) = split_frontmatter(&content)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml_str)
        .with_context(|| format!("parse YAML in {}", skill_file.display()))?;

    let changes = apply_migrations(&mut value);
    if changes.is_empty() {
        return Ok(MigrationOutcome::NoChange);
    }
    if dry_run {
        return Ok(MigrationOutcome::WouldChange(changes));
    }

    let backup = skill_file.with_file_name(format!(
        "{}.pre-migrate-{}",
        skill_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("SKILL.md"),
        chrono::Utc::now().format("%Y-%m-%dT%H%M%SZ")
    ));
    std::fs::copy(skill_file, &backup)
        .with_context(|| format!("backup to {}", backup.display()))?;

    let new_yaml = serde_yaml::to_string(&value).context("serialize migrated frontmatter")?;
    let mut new_content = String::new();
    if leading_separator {
        new_content.push_str("---\n");
    }
    new_content.push_str(&new_yaml);
    new_content.push_str("---\n\n");
    new_content.push_str(&body);
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    std::fs::write(skill_file, new_content)
        .with_context(|| format!("write {}", skill_file.display()))?;

    Ok(MigrationOutcome::Changed { changes, backup })
}

/// Split a SKILL.md into (yaml, body, had_leading_separator). Mirrors
/// the parser in `wirken_agent::skill::parse_frontmatter`: opening
/// `---` is optional; if present, the next `---` closes the
/// frontmatter and the rest is body. Files without an opening `---`
/// are treated as body-only.
fn split_frontmatter(content: &str) -> Result<(&str, String, bool)> {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        anyhow::bail!("no frontmatter to migrate (file has no leading `---`)");
    }
    #[allow(
        clippy::string_slice,
        reason = "the text starts with ASCII \"---\" and the end offset is from find(\"---\")"
    )]
    let rest = &trimmed[3..];
    let end = rest
        .find("---")
        .ok_or_else(|| anyhow::anyhow!("unclosed frontmatter (no closing `---`)"))?;
    #[allow(
        clippy::string_slice,
        reason = "the text starts with ASCII \"---\" and the end offset is from find(\"---\")"
    )]
    let yaml = rest[..end].trim_matches('\n');
    #[allow(
        clippy::string_slice,
        reason = "the text starts with ASCII \"---\" and the end offset is from find(\"---\")"
    )]
    let body = rest[end + 3..].trim_start_matches('\n').to_string();
    Ok((yaml, body, true))
}

/// Apply the two known migrations to a parsed YAML mapping. Returns
/// the list of change tags applied. Pure: no I/O. Tested directly.
fn apply_migrations(value: &mut serde_yaml::Value) -> Vec<&'static str> {
    let mut changes: Vec<&'static str> = Vec::new();

    // (1) metadata.openclaw -> metadata.wirken
    if let Some(metadata) = value.get_mut("metadata").and_then(|v| v.as_mapping_mut()) {
        let openclaw_key = serde_yaml::Value::String("openclaw".to_string());
        let wirken_key = serde_yaml::Value::String("wirken".to_string());
        if metadata.contains_key(&openclaw_key)
            && !metadata.contains_key(&wirken_key)
            && let Some(v) = metadata.remove(&openclaw_key)
        {
            metadata.insert(wirken_key, v);
            changes.push("openclaw->wirken");
        }
    }

    // (2) Append empty `permissions:` block when absent.
    let permissions_key = serde_yaml::Value::String("permissions".to_string());
    let needs_permissions = match value.as_mapping() {
        Some(m) => !m.contains_key(permissions_key.clone()),
        None => false,
    };
    if needs_permissions && let Some(map) = value.as_mapping_mut() {
        map.insert(permissions_key, empty_permissions_stub());
        changes.push("permissions stub added");
    }

    changes
}

/// The deny-everything permissions stub inserted on migration. Loads
/// cleanly through `resolve_block` (every list is empty, allowlist
/// mode is the strictest egress posture). Migrated skills load but
/// can do nothing until the operator edits.
fn empty_permissions_stub() -> serde_yaml::Value {
    serde_yaml::from_str::<serde_yaml::Value>(
        "tools:\n  allow: []\negress:\n  mode: allowlist\n  domains: []\nfilesystem:\n  write_paths: []\n  read_paths: []\ninference:\n  allow: []\n",
    )
    .expect("static permissions stub parses as YAML")
}

#[cfg(test)]
mod missing_index_tests {
    use super::{DEFAULT_INDEX_URL, missing_index_message};

    #[test]
    fn the_default_index_reports_that_none_is_published() {
        let msg = missing_index_message(DEFAULT_INDEX_URL);
        assert!(msg.contains(DEFAULT_INDEX_URL), "{msg}");
        assert!(
            msg.contains("no public skill index is published yet"),
            "{msg}"
        );
    }

    #[test]
    fn another_index_is_named_without_the_publication_claim() {
        let msg = missing_index_message("http://127.0.0.1:1/index.json");
        assert!(msg.contains("http://127.0.0.1:1/index.json"), "{msg}");
        assert!(!msg.contains("published"), "{msg}");
    }
}

#[cfg(test)]
mod verify_outcome_tests {
    use super::{VerifyOutcome, VerifyResult, decide_verify_outcome};

    fn valid() -> VerifyResult {
        VerifyResult::Valid {
            signer: "ab".repeat(32),
        }
    }

    #[test]
    fn valid_non_strict_passes() {
        assert_eq!(decide_verify_outcome(&valid(), false), VerifyOutcome::Ok);
    }

    #[test]
    fn valid_strict_fails() {
        assert_eq!(decide_verify_outcome(&valid(), true), VerifyOutcome::Fail);
    }

    #[test]
    fn invalid_non_strict_fails() {
        assert_eq!(
            decide_verify_outcome(&VerifyResult::Invalid, false),
            VerifyOutcome::Fail
        );
    }

    #[test]
    fn invalid_strict_fails() {
        assert_eq!(
            decide_verify_outcome(&VerifyResult::Invalid, true),
            VerifyOutcome::Fail
        );
    }

    #[test]
    fn unsigned_non_strict_passes() {
        assert_eq!(
            decide_verify_outcome(&VerifyResult::Unsigned, false),
            VerifyOutcome::Ok
        );
    }

    #[test]
    fn unsigned_strict_fails() {
        assert_eq!(
            decide_verify_outcome(&VerifyResult::Unsigned, true),
            VerifyOutcome::Fail
        );
    }
}

#[cfg(test)]
mod migrate_tests {
    use super::{apply_migrations, split_frontmatter};
    use serde_yaml::Value;

    fn parse(s: &str) -> Value {
        serde_yaml::from_str(s).unwrap()
    }

    #[test]
    fn openclaw_renames_when_wirken_absent() {
        let mut v = parse(
            "name: x\nmetadata:\n  openclaw:\n    requires:\n      bins:\n      - docker\npermissions:\n  tools: { allow: [] }\n",
        );
        let changes = apply_migrations(&mut v);
        assert_eq!(changes, vec!["openclaw->wirken"]);
        let metadata = v.get("metadata").unwrap().as_mapping().unwrap();
        assert!(metadata.contains_key(Value::String("wirken".into())));
        assert!(!metadata.contains_key(Value::String("openclaw".into())));
    }

    #[test]
    fn openclaw_preserved_when_wirken_already_present() {
        let mut v = parse(
            "name: x\nmetadata:\n  wirken:\n    requires:\n      bins:\n      - docker\n  openclaw:\n    requires:\n      bins:\n      - legacy\npermissions:\n  tools: { allow: [] }\n",
        );
        let changes = apply_migrations(&mut v);
        assert!(
            changes.is_empty(),
            "should not touch when both keys present"
        );
        let metadata = v.get("metadata").unwrap().as_mapping().unwrap();
        assert!(metadata.contains_key(Value::String("openclaw".into())));
        assert!(metadata.contains_key(Value::String("wirken".into())));
    }

    #[test]
    fn missing_permissions_block_gets_stub() {
        let mut v = parse("name: x\ndescription: y\n");
        let changes = apply_migrations(&mut v);
        assert_eq!(changes, vec!["permissions stub added"]);
        let permissions = v.get("permissions").unwrap();
        let map = permissions.as_mapping().unwrap();
        assert!(map.contains_key(Value::String("tools".into())));
        assert!(map.contains_key(Value::String("egress".into())));
        assert!(map.contains_key(Value::String("filesystem".into())));
        assert!(map.contains_key(Value::String("inference".into())));
        let egress = permissions.get("egress").unwrap();
        assert_eq!(
            egress.get("mode").unwrap(),
            &Value::String("allowlist".into())
        );
    }

    #[test]
    fn both_migrations_apply_in_one_pass() {
        let mut v =
            parse("name: x\nmetadata:\n  openclaw:\n    requires:\n      bins:\n      - docker\n");
        let changes = apply_migrations(&mut v);
        assert_eq!(changes, vec!["openclaw->wirken", "permissions stub added"]);
        let metadata = v.get("metadata").unwrap().as_mapping().unwrap();
        assert!(metadata.contains_key(Value::String("wirken".into())));
        assert!(v.get("permissions").is_some());
    }

    #[test]
    fn already_current_skill_no_changes() {
        let mut v = parse(
            "name: x\nmetadata:\n  wirken:\n    requires:\n      bins: []\npermissions:\n  tools: { allow: [] }\n",
        );
        let changes = apply_migrations(&mut v);
        assert!(
            changes.is_empty(),
            "no-change when already current, got {changes:?}"
        );
    }

    #[test]
    fn split_frontmatter_extracts_yaml_and_body() {
        let content = "---\nname: x\n---\n\nbody line one\n";
        let (yaml, body, had_sep) = split_frontmatter(content).unwrap();
        assert_eq!(yaml, "name: x");
        assert_eq!(body, "body line one\n");
        assert!(had_sep);
    }

    #[test]
    fn split_frontmatter_rejects_no_leading_separator() {
        let content = "name: x\n---\nbody\n";
        let err = split_frontmatter(content).unwrap_err();
        assert!(err.to_string().contains("no frontmatter"));
    }

    #[test]
    fn split_frontmatter_rejects_unclosed() {
        let content = "---\nname: x\nbody body body\n";
        let err = split_frontmatter(content).unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }
}
