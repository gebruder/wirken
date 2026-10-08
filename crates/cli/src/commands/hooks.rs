//! `wirken hooks` subcommands.
//!
//! Three operations: register a hook's Ed25519 pubkey and type with
//! the gateway; list registered hooks; unregister one. Mirrors the
//! adapter registration UX: hook processes run externally, hold
//! their own keypair, and connect inbound on
//! `<data_dir>/sockets/gateway-hooks.sock`. The gateway looks the
//! presented pubkey up in the table this command writes to.

use anyhow::Result;
use wirken_gateway::hook_registry::HookRegistry;
use wirken_ipc::HookType;

use super::config;

fn open_registry() -> Result<HookRegistry> {
    let cfg = config();
    let path = cfg.data_dir.join("hooks.db");
    HookRegistry::open(&path)
        .map_err(|e| anyhow::anyhow!("open hook registry at {}: {e}", path.display()))
}

fn parse_hook_type(s: &str) -> Result<HookType> {
    match s {
        "observe" => Ok(HookType::Observe),
        "veto" => Ok(HookType::Veto),
        "egress" => Ok(HookType::Egress),
        other => {
            anyhow::bail!("unknown hook type {other:?}; expected `observe`, `veto`, or `egress`")
        }
    }
}

fn parse_pubkey_hex(hex: &str) -> Result<[u8; 32]> {
    let cleaned = hex.trim();
    if cleaned.len() != 64 {
        anyhow::bail!(
            "public key must be 64 hex chars (32 bytes); got {} chars",
            cleaned.len()
        );
    }
    let bytes =
        wirken_audit::hex::decode(cleaned).map_err(|e| anyhow::anyhow!("public key hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))
}

pub fn register(hook_id: &str, pubkey_hex: &str, hook_type: &str) -> Result<()> {
    let pk = parse_pubkey_hex(pubkey_hex)?;
    let ty = parse_hook_type(hook_type)?;
    let registry = open_registry()?;
    registry
        .register(hook_id, &pk, ty)
        .map_err(|e| anyhow::anyhow!("register hook {hook_id}: {e}"))?;
    println!("Registered hook {hook_id} ({}).", ty.as_wire());
    Ok(())
}

pub fn list() -> Result<()> {
    let registry = open_registry()?;
    let mut entries = registry.list();
    if entries.is_empty() {
        println!("No hooks registered.");
        return Ok(());
    }
    entries.sort_by(|a, b| a.hook_id.cmp(&b.hook_id));
    println!("{:<24} {:<10} PUBKEY", "HOOK_ID", "TYPE");
    for e in entries {
        let pk_hex: String = e.public_key.iter().map(|b| format!("{b:02x}")).collect();
        println!("{:<24} {:<10} {}", e.hook_id, e.hook_type.as_wire(), pk_hex);
    }
    Ok(())
}

pub fn unregister(hook_id: &str) -> Result<()> {
    let registry = open_registry()?;
    registry
        .unregister(hook_id)
        .map_err(|e| anyhow::anyhow!("unregister hook {hook_id}: {e}"))?;
    println!("Unregistered hook {hook_id}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pubkey_hex_round_trips_32_bytes() {
        let bytes = [0xAB; 32];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_pubkey_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn parse_pubkey_hex_rejects_wrong_length() {
        assert!(parse_pubkey_hex("deadbeef").is_err());
    }

    #[test]
    fn parse_pubkey_hex_rejects_non_ascii() {
        // 64 bytes, the expected length, with every two-byte slice
        // splitting a character.
        let bad = format!("a{}a", "\u{e9}".repeat(31));
        assert_eq!(bad.len(), 64);
        let err = parse_pubkey_hex(&bad).unwrap_err();
        assert!(
            format!("{err:#}").contains("non-ASCII hex string"),
            "{err:#}"
        );
    }

    #[test]
    fn parse_pubkey_hex_rejects_non_hex() {
        let bad = "zz".repeat(32);
        assert!(parse_pubkey_hex(&bad).is_err());
    }

    #[test]
    fn parse_hook_type_accepts_known_labels() {
        assert_eq!(parse_hook_type("observe").unwrap(), HookType::Observe);
        assert_eq!(parse_hook_type("veto").unwrap(), HookType::Veto);
        assert_eq!(parse_hook_type("egress").unwrap(), HookType::Egress);
    }

    #[test]
    fn parse_hook_type_rejects_unknown() {
        assert!(parse_hook_type("mutate").is_err());
    }
}
