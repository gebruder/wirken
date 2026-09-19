//! The exec classifier on arbitrary command text.
//!
//! `exec` is the tool a hostile model reaches for, and the whole of
//! what stops it is a string classification: `tool_to_action` decides
//! the action, `resolve_exec_pattern` resolves a path-bearing first
//! token, and `canonical_exec_prefix` reduces it for the allowlist
//! lookup. `tests/hostile/corpus.jsonl` pins the shapes anyone thought
//! of. This pins the two rules underneath them against shapes nobody
//! did.
//!
//! Two invariants, both stated by the code under test:
//!
//! 1. A command containing any `SHELL_METACHARS` byte resolves to the
//!    pipeline sentinel, so it is Tier 3 and cannot be pre-approved.
//! 2. A command whose canonical lead token is not on
//!    `TIER2_ALLOWLIST` is Tier 3.
//!
//! A crash here is a finding about the classifier. Do not relax an
//! assertion to make a case pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wirken_agent::tool::tool_to_action;
use wirken_gateway::permissions::{Action, PermissionTier, TIER2_ALLOWLIST, canonical_exec_prefix};

/// The bytes that force the sentinel. Kept in step with
/// `SHELL_METACHARS` in `crates/agent/src/tool.rs`, which is private;
/// a divergence fails every metacharacter case at once, which is the
/// right noise level for a change to that list.
const SHELL_METACHARS: &[&str] = &["|", ";", "&", "$(", "`", ">", "<", "\n"];

/// The pattern the classifier substitutes for a command carrying any
/// of the above.
const PIPELINE_SENTINEL: &str = ":pipeline:";

/// Exercise one `exec` payload and check both rules.
fn check(args: serde_json::Value, joined: &str) {
    let Some(action) = tool_to_action("exec", &args) else {
        panic!("exec must always classify, got None for {args}");
    };
    let Action::ShellExec { pattern } = &action else {
        panic!("exec must classify as ShellExec, got {action} for {args}");
    };

    // Rule 1: any metacharacter forces the sentinel.
    if SHELL_METACHARS.iter().any(|m| joined.contains(m)) {
        assert_eq!(
            pattern, PIPELINE_SENTINEL,
            "a command carrying a shell metacharacter must resolve to the \
             pipeline sentinel; command {joined:?} resolved to {pattern:?}"
        );
    }

    // Rule 2: anything not canonically on the Tier 2 allowlist prompts.
    let canonical = canonical_exec_prefix(pattern);
    let tier = action.tier();
    if TIER2_ALLOWLIST.contains(&canonical.as_str()) {
        assert_eq!(
            tier,
            PermissionTier::Tier2,
            "an allowlisted canonical verb {canonical:?} must be Tier 2; command {joined:?}"
        );
    } else {
        assert_eq!(
            tier,
            PermissionTier::Tier3,
            "canonical verb {canonical:?} is not on TIER2_ALLOWLIST and must be \
             Tier 3; command {joined:?}"
        );
    }

    // The sentinel is never storable, whichever way it arrived.
    if pattern == PIPELINE_SENTINEL {
        assert_eq!(
            tier,
            PermissionTier::Tier3,
            "the pipeline sentinel must be Tier 3; command {joined:?}"
        );
        assert!(
            !wirken_gateway::permissions::is_storable_approval_key(&action.approval_key()),
            "the pipeline sentinel must not be a storable approval key; command {joined:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Invalid UTF-8 cannot reach the classifier: tool arguments arrive
    // as JSON, which is text. Lossy conversion keeps every byte
    // pattern reachable as some string rather than discarding the
    // input.
    let text = String::from_utf8_lossy(data).into_owned();

    // String form, as the model most often emits it.
    check(serde_json::json!({ "command": text.clone() }), &text);

    // Array form. Split on NUL so one fuzz input drives both shapes
    // and the argv case gets multi-element vectors without a second
    // structured decoder. The classifier joins with a space, so that
    // is what the invariants are checked against.
    let argv: Vec<String> = text.split('\0').map(str::to_string).collect();
    let joined = argv.join(" ");
    check(serde_json::json!({ "command": argv }), &joined);
});
