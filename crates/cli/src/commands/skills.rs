use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use wirken_agent::skill::SkillLoader;
use wirken_gateway::skill_registry::{
    self, SkillIndex, VerifyResult, generate_signing_keypair, verify_skill_with_expected_key,
};

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
    if let (Some(sig_hex), Some(key_hex)) = (&entry.signature, &entry.signer_key) {
        match verify_skill_with_expected_key(&skill_dir, sig_hex, key_hex)? {
            VerifyResult::Valid { signer } => {
                // Write sig/pub files for future local verification
                std::fs::write(skill_dir.join("SKILL.sig"), sig_hex)?;
                std::fs::write(skill_dir.join("SKILL.pub"), key_hex)?;
                println!("  Signature valid (signer: {}...)", &signer[..16]);
            }
            VerifyResult::Invalid => {
                // Remove the skill — signature didn't verify
                std::fs::remove_dir_all(&skill_dir)?;
                anyhow::bail!("Signature verification failed! Skill not installed.");
            }
            VerifyResult::Unsigned => {}
        }
    } else if matches!(
        std::env::var("WIRKEN_ALLOW_UNSIGNED_SKILLS").as_deref(),
        Ok("1")
    ) {
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
        println!("  Search with: wirken skills search <query>");
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

pub async fn sign(dir: &str) -> Result<()> {
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

    let sig = skill_registry::sign_skill(skill_dir, &signing_key)?;
    let pub_hex = skill_registry::hex_encode_public(&signing_key.verifying_key().to_bytes());

    println!("  Signed: {}/SKILL.md", dir);
    println!("  Signature: {}...{}", &sig[..16], &sig[sig.len() - 16..]);
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
                    "  --strict: refusing self-signed bundle. Install via \
                     `wirken skills install <name>` so the registry index pins \
                     the expected signer key."
                );
            } else {
                tracing::warn!(
                    "verify: self-signed bundle at {} accepted; pass --strict to fail \
                     on bundles without registry-anchored trust",
                    skill_dir.display()
                );
                println!(
                    "  Note: this only checks the bundle is internally consistent. To check \
                     the signer key matches a trusted publisher, use \
                     `wirken skills install <name>` against the registry, which pins the \
                     expected key from the registry index entry, or re-run with --strict."
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

async fn fetch_index() -> Result<SkillIndex> {
    let url = std::env::var("WIRKEN_SKILLS_INDEX").unwrap_or_else(|_| DEFAULT_INDEX_URL.into());

    let http = reqwest::Client::new();
    let resp = http
        .get(&url)
        .send()
        .await
        .context(format!("Failed to fetch skill index from {url}"))?;

    if !resp.status().is_success() {
        // Return empty index if registry is unavailable
        tracing::warn!(
            "Skill index unavailable (HTTP {}), using empty index",
            resp.status()
        );
        return Ok(SkillIndex { skills: vec![] });
    }

    resp.json::<SkillIndex>()
        .await
        .context("Failed to parse skill index")
}

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
