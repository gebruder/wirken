//! End-to-end coverage for signed Wasm skills: the signature covers the
//! `skill.wasm` bytes, the module compiles and runs under the WASI p1
//! sandbox, and what it writes to stdout and stderr reaches the caller.
//!
//! The fixtures are WAT compiled at test time rather than a checked-in
//! `.wasm`, so the bytes under signature are readable in this file.

use ed25519_dalek::SigningKey;
use wirken_gateway::skill_registry::{VerifyResult, sign_skill, verify_skill_self_signed};

use crate::wasm_sandbox::load_wasm_skills;

/// Echoes stdin to stdout, then exits cleanly.
const ECHO_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 200))
    (i32.store (i32.const 4) (i32.const 100))
    (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 16) (i32.const 200))
    (i32.store (i32.const 20) (i32.load (i32.const 8)))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
  )
)
"#;

/// Writes to stderr, then traps.
const TRAP_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 200) "BOOM-ON-STDERR")
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 200))
    (i32.store (i32.const 4) (i32.const 14))
    (drop (call $fd_write (i32.const 2) (i32.const 0) (i32.const 1) (i32.const 8)))
    (unreachable)
  )
)
"#;

/// Build `<tmp>/<name>/` holding a compiled `skill.wasm` and a SKILL.md,
/// sign it with a throwaway key, and return the temp root.
fn signed_skill(name: &str, wat: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join(name);
    std::fs::create_dir_all(&dir).expect("create skill dir");

    let wasm = wat::parse_str(wat).expect("compile WAT fixture");
    std::fs::write(dir.join("skill.wasm"), &wasm).expect("write skill.wasm");
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: wasm sandbox fixture\n---\n\nFixture.\n"),
    )
    .expect("write SKILL.md");

    // Ephemeral: generated per run, never written anywhere but this dir.
    let key = SigningKey::from_bytes(&rand_seed());
    sign_skill(&dir, &key).expect("sign_skill");
    (tmp, dir)
}

fn rand_seed() -> [u8; 32] {
    // Any distinct-per-run value works; the key is thrown away with the dir.
    let mut seed = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&now);
    seed
}

#[test]
fn signature_covers_the_wasm_bytes() {
    let (_tmp, dir) = signed_skill("echo-skill", ECHO_WAT);

    match verify_skill_self_signed(&dir).expect("verify") {
        VerifyResult::Valid { .. } => {}
        other => panic!("freshly signed bundle did not verify: {other:?}"),
    }

    // Swapping the wasm after signing must invalidate the bundle, which is
    // the property that makes signing a Wasm skill mean anything.
    std::fs::write(dir.join("skill.wasm"), b"\0asm\x01\0\0\0").expect("tamper");
    assert_eq!(
        verify_skill_self_signed(&dir).expect("verify after tamper"),
        VerifyResult::Invalid,
        "tampering with skill.wasm left the signature valid"
    );
}

#[test]
fn stdout_reaches_the_caller() {
    let (tmp, _dir) = signed_skill("echo-skill", ECHO_WAT);

    let skills = load_wasm_skills(tmp.path());
    assert_eq!(skills.len(), 1, "expected one loaded wasm skill");

    let args = r#"{"probe":"round-trip"}"#;
    let result = skills[0].execute(args).expect("execute");

    assert!(result.success, "module trapped unexpectedly: {result:?}");
    assert!(
        !result.output.is_empty() && result.output != "(no output)",
        "stdout was dropped instead of returned: {result:?}"
    );
    assert!(
        result.output.contains("round-trip"),
        "stdout did not carry the module's write: {result:?}"
    );
}

#[test]
fn stderr_is_reported_when_the_module_traps() {
    let (tmp, _dir) = signed_skill("trap-skill", TRAP_WAT);

    let skills = load_wasm_skills(tmp.path());
    assert_eq!(skills.len(), 1, "expected one loaded wasm skill");

    let result = skills[0].execute("{}").expect("execute");

    assert!(
        !result.success,
        "trapping module reported success: {result:?}"
    );
    assert!(
        result.output.contains("BOOM-ON-STDERR"),
        "stderr was discarded on the trap path: {result:?}"
    );
}
