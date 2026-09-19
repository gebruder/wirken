//! Replay of `tests/hostile/corpus.jsonl`, the hostile-call regression
//! corpus, through the two functions that decide what a tool call is
//! allowed to do: `tool_to_action`, which classifies the call, and
//! `PermissionStore::check`, which answers on the classification.
//!
//! The corpus is the demo in `scripts/demo/` generalised. That script
//! plays four hostile moves against a live gateway and is a
//! demonstration; this is the same moves plus every variant of them
//! that the classifier has a rule for, replayed with no network, no
//! LLM and no sandbox, on a scratch data dir.
//!
//! Each line names its own expected outcome:
//!
//! - `tier1` allowed with no prompt. It does not mean unguarded: for
//!   `http_request` and the file tools the real refusal is a hard one
//!   from a different layer, and the line says which.
//! - `tier2` prompts once and the grant can be remembered.
//! - `tier3` prompts on every use and no grant can be stored.
//! - `sentinel` the exec command carried a shell metacharacter and was
//!   forced to the pipeline sentinel, a pattern on no allowlist.
//! - `refused` the classifier places the name nowhere, so the runtime's
//!   default-deny (`UnknownTool`, Tier 3) is what runs.
//!
//! A mismatch is a finding about the gate, not a stale expectation.
//! The rule for this file is that a line is changed only when the
//! classification it asserts was wrong to begin with, and never to
//! make a failing run pass.
//!
//! Unix only: the fixture tree needs symlinks, and the symlink cases
//! are the point of the path-prefixed lines.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;
use wirken_agent::tool::{ToolConfig, ToolRegistry, tool_to_action};
use wirken_gateway::permissions::{
    Action, ApprovalScope, PermissionCheck, PermissionStore, PermissionTier,
};

const CORPUS: &str = include_str!("../../../tests/hostile/corpus.jsonl");

/// Path as a reader should type it, for failure output. `include_str!`
/// resolves the real one at compile time.
const CORPUS_PATH: &str = "tests/hostile/corpus.jsonl";

/// The pattern `tool_to_action` substitutes for any command carrying a
/// shell metacharacter. The constant itself is private to the agent
/// crate; this is its observable form, pinned here on purpose. If the
/// two ever diverge, every `sentinel` line fails at once, which is the
/// right noise level for a change to the one pattern that is supposed
/// to match no verb.
const PIPELINE_SENTINEL: &str = ":pipeline:";

/// Placeholder in a corpus command, replaced with the fixture tree this
/// run built. Lets the path-prefixed lines assert symlink resolution
/// without depending on what happens to be installed on the host.
const FIXTURE_TOKEN: &str = "{{fixtures}}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Tier1,
    Tier2,
    Tier3,
    Sentinel,
    Refused,
}

impl Outcome {
    fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "tier1" => Self::Tier1,
            "tier2" => Self::Tier2,
            "tier3" => Self::Tier3,
            "sentinel" => Self::Sentinel,
            "refused" => Self::Refused,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
            Self::Sentinel => "sentinel",
            Self::Refused => "refused",
        }
    }

    /// The tier the gate answers with. `sentinel` and `refused` are
    /// Tier 3 with a reason attached, not tiers of their own.
    fn tier(self) -> PermissionTier {
        match self {
            Self::Tier1 => PermissionTier::Tier1,
            Self::Tier2 => PermissionTier::Tier2,
            Self::Tier3 | Self::Sentinel | Self::Refused => PermissionTier::Tier3,
        }
    }
}

/// Classify one call exactly as the runtime tier gate does, including
/// its fallback: `tool_to_action` returning `None` becomes
/// `UnknownTool`, which is Tier 3 and default-denied. Returns the
/// outcome and the action the gate would go on to check.
fn classify(tool: &str, args: &Value) -> (Outcome, Action) {
    match tool_to_action(tool, args) {
        None => (
            Outcome::Refused,
            Action::UnknownTool {
                tool: tool.to_string(),
            },
        ),
        Some(action) => {
            let outcome = match &action {
                Action::ShellExec { pattern } if pattern == PIPELINE_SENTINEL => Outcome::Sentinel,
                _ => match action.tier() {
                    PermissionTier::Tier1 => Outcome::Tier1,
                    PermissionTier::Tier2 => Outcome::Tier2,
                    PermissionTier::Tier3 => Outcome::Tier3,
                },
            };
            (outcome, action)
        }
    }
}

/// Fixture tree for the path-prefixed exec lines:
///
/// - `plain/ls`     a real file whose name is an allowlisted verb
/// - `launder/ls`   a symlink named `ls` whose target is named `curl`
/// - `broken/ls`    a symlink named `ls` pointing at nothing
///
/// Built per run so the outcomes do not depend on what the host has in
/// `/usr/bin`, which is what made these cases untestable as literals.
fn build_fixtures(root: &Path) -> PathBuf {
    let fixtures = root.join("fixtures");
    for sub in ["plain", "launder", "broken", "target"] {
        std::fs::create_dir_all(fixtures.join(sub)).unwrap();
    }
    std::fs::write(fixtures.join("plain").join("ls"), b"#!/bin/sh\n").unwrap();
    std::fs::write(fixtures.join("target").join("curl"), b"#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink(
        fixtures.join("target").join("curl"),
        fixtures.join("launder").join("ls"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        fixtures.join("target").join("gone"),
        fixtures.join("broken").join("ls"),
    )
    .unwrap();
    fixtures
}

/// Replace [`FIXTURE_TOKEN`] anywhere in the arguments. Done on the
/// serialised form so it reaches both `command` shapes, the string and
/// the array. The path is escaped as a JSON string body first, so a
/// scratch path containing a quote or a backslash cannot break the
/// re-parse.
fn substitute(args: &Value, fixtures: &Path) -> Value {
    let raw = args.to_string();
    if !raw.contains(FIXTURE_TOKEN) {
        return args.clone();
    }
    let quoted = serde_json::to_string(&fixtures.to_string_lossy().into_owned()).unwrap();
    let body = &quoted[1..quoted.len() - 1];
    serde_json::from_str(&raw.replace(FIXTURE_TOKEN, body))
        .expect("fixture substitution must leave valid JSON")
}

fn field<'a>(entry: &'a Value, name: &str, lineno: usize) -> &'a Value {
    entry
        .get(name)
        .unwrap_or_else(|| panic!("{CORPUS_PATH}:{lineno}: missing field '{name}'"))
}

fn text(entry: &Value, name: &str, lineno: usize) -> String {
    field(entry, name, lineno)
        .as_str()
        .unwrap_or_else(|| panic!("{CORPUS_PATH}:{lineno}: field '{name}' must be a string"))
        .to_string()
}

/// One corpus line, ready to replay.
struct Entry {
    lineno: usize,
    id: String,
    tool: String,
    args: Value,
    expect: Outcome,
    key: String,
    why: String,
}

fn parse_corpus(fixtures: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for (idx, raw) in CORPUS.lines().enumerate() {
        let lineno = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("{CORPUS_PATH}:{lineno}: not valid JSON: {e}"));
        let id = text(&entry, "id", lineno);
        assert!(
            ids.insert(id.clone()),
            "{CORPUS_PATH}:{lineno}: duplicate id '{id}'. Ids name a case in a \
             failure message, so two lines sharing one make the message ambiguous."
        );
        let expect_raw = text(&entry, "expect", lineno);
        let expect = Outcome::parse(&expect_raw).unwrap_or_else(|| {
            panic!(
                "{CORPUS_PATH}:{lineno}: unknown expect '{expect_raw}'. \
                 One of: tier1, tier2, tier3, sentinel, refused."
            )
        });
        let args = field(&entry, "args", lineno).clone();
        assert!(
            args.is_object(),
            "{CORPUS_PATH}:{lineno}: 'args' must be an object"
        );
        let why = text(&entry, "why", lineno);
        assert!(
            !why.trim().is_empty(),
            "{CORPUS_PATH}:{lineno}: 'why' carries the reasoning a reader needs \
             when this line fails, so it may not be empty."
        );
        entries.push(Entry {
            lineno,
            id,
            tool: text(&entry, "tool", lineno),
            args: substitute(&args, fixtures),
            expect,
            key: text(&entry, "key", lineno),
            why,
        });
    }
    assert!(
        !entries.is_empty(),
        "{CORPUS_PATH} is empty. An empty corpus passes every assertion \
         below and proves nothing."
    );
    entries
}

/// Failure report: the call, both outcomes, and the line's own
/// reasoning. Printed instead of a bare assert so a mismatch can be
/// read without opening the corpus.
fn report(entry: &Entry, observed: Outcome, action: &Action, detail: &str) -> String {
    format!(
        "\n{CORPUS_PATH}:{lineno}  id={id}\n  \
         call      {tool} {args}\n  \
         expected  {expected}\n  \
         observed  {observed} (action {action}, key {key})\n  \
         why       {why}\n  \
         {detail}\n\n\
         This is a finding about the gate, not a stale expectation. \
         Do not edit the line to make it pass unless the classification \
         it asserts was wrong when it was written.\n",
        lineno = entry.lineno,
        id = entry.id,
        tool = if entry.tool.is_empty() {
            "\"\"".to_string()
        } else {
            entry.tool.clone()
        },
        args = entry.args,
        expected = entry.expect.as_str(),
        observed = observed.as_str(),
        action = action,
        key = action.approval_key(),
        why = entry.why,
    )
}

/// Replay every line. Fails on the first mismatch.
#[test]
fn hostile_corpus_replays_to_its_expected_outcome() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let store = PermissionStore::open(&scratch.path().join("permissions.db")).unwrap();

    for entry in parse_corpus(&fixtures) {
        let (observed, action) = classify(&entry.tool, &entry.args);

        if observed != entry.expect {
            panic!(
                "{}",
                report(&entry, observed, &action, "classification mismatch")
            );
        }
        if action.approval_key() != entry.key {
            panic!(
                "{}",
                report(
                    &entry,
                    observed,
                    &action,
                    &format!("approval key mismatch: corpus says {}", entry.key),
                )
            );
        }
        if observed == Outcome::Sentinel
            && !matches!(&action, Action::ShellExec { pattern } if pattern == PIPELINE_SENTINEL)
        {
            panic!(
                "{}",
                report(
                    &entry,
                    observed,
                    &action,
                    "expected the pipeline sentinel, got another shell pattern"
                )
            );
        }

        // Each line gets its own agent and session, so a grant written
        // for one never answers for the next: several lines share an
        // approval key on purpose (`shell:ls` three times) and sharing
        // an agent would let the first approval satisfy the rest.
        let agent_id = format!("corpus-agent-{}", entry.lineno);
        let session_id = format!("corpus-session-{}", entry.lineno);

        let first = store
            .check(&action, &session_id, Some(&agent_id))
            .unwrap_or_else(|e| panic!("{}", report(&entry, observed, &action, &format!("{e}"))));
        let expected_first = match entry.expect {
            Outcome::Tier1 => PermissionCheck::Allowed,
            other => PermissionCheck::NeedsApproval {
                tier: other.tier(),
                lapsed_at: None,
            },
        };
        if first != expected_first {
            panic!(
                "{}",
                report(
                    &entry,
                    observed,
                    &action,
                    &format!("check said {first:?}, expected {expected_first:?}")
                )
            );
        }

        if entry.expect == Outcome::Tier2 {
            // The whole of Tier 2: a grant can be written and the next
            // call is answered from it.
            store
                .approve(&action, &agent_id, "corpus")
                .unwrap_or_else(|e| {
                    panic!(
                        "{}",
                        report(
                            &entry,
                            observed,
                            &action,
                            &format!("a Tier 2 key must be storable, got {e}")
                        )
                    )
                });
            let after = store.check(&action, &session_id, Some(&agent_id)).unwrap();
            if after != PermissionCheck::Allowed {
                panic!(
                    "{}",
                    report(
                        &entry,
                        observed,
                        &action,
                        &format!("a stored grant must answer the next call, got {after:?}")
                    )
                );
            }
        } else {
            // Everything else: neither store will take a grant, so the
            // prompt cannot be silenced for the rest of a session. This
            // is the half of "Tier 3 always prompts" that lives on the
            // write side, asserted here for every hostile line rather
            // than for one representative key.
            for scope in [
                ApprovalScope::Persisted,
                ApprovalScope::Session {
                    session_id: session_id.clone(),
                },
            ] {
                let written = store.approve_with_scope(&action, &agent_id, "corpus", scope.clone());
                if written.is_ok() {
                    panic!(
                        "{}",
                        report(
                            &entry,
                            observed,
                            &action,
                            &format!("{scope:?} grant was accepted for a non-Tier-2 key")
                        )
                    );
                }
            }
            let after = store.check(&action, &session_id, Some(&agent_id)).unwrap();
            if after != expected_first {
                panic!(
                    "{}",
                    report(
                        &entry,
                        observed,
                        &action,
                        &format!("verdict changed after refused grants: {after:?}")
                    )
                );
            }
        }
    }
}

/// How a given [`Action`] variant is expected to be reached.
enum Coverage {
    /// Some corpus line must produce it.
    FromCorpus,
    /// No tool call can produce it, with the reason why.
    NotFromAToolCall(&'static str),
}

/// The tripwire. Every `Action` variant is accounted for here, and the
/// match is exhaustive, so adding a variant stops this file compiling
/// until someone decides which of the two it is. Choosing
/// `FromCorpus` then fails the coverage test until a corpus line
/// actually produces it.
fn coverage(action: &Action) -> Coverage {
    match action {
        Action::WorkspaceFileAccess
        | Action::WebSearch
        | Action::HttpRequest
        | Action::ShellExec { .. }
        | Action::NetworkRequest { .. }
        | Action::McpToolCall { .. }
        | Action::UnknownTool { .. }
        | Action::CrossChannelMemoryRead { .. }
        | Action::ImportedChatRead { .. }
        | Action::ImportedChatSearch { .. } => Coverage::FromCorpus,

        Action::ChannelConverse => {
            Coverage::NotFromAToolCall("the agent's channel reply is the normal response path")
        }
        Action::ExternalFileAccess { .. } => {
            Coverage::NotFromAToolCall("no built-in tool reaches outside the workspace")
        }
        Action::CrossConversationMessage => {
            Coverage::NotFromAToolCall("cross-conversation messaging is not an agent tool")
        }
        Action::DestructiveFileOp => {
            Coverage::NotFromAToolCall("workspace writes are Tier 1 and cap-std confined")
        }
        Action::CredentialAccess => {
            Coverage::NotFromAToolCall("credentials are mediated by the vault and the MCP proxy")
        }
        Action::CronCreate => Coverage::NotFromAToolCall("cron is created through the CLI"),
        Action::WasmSkillCall { .. } => Coverage::NotFromAToolCall(
            "the runtime builds it for a known Wasm skill; the classifier returns None, \
             which the corpus covers as refused",
        ),
    }
}

/// One value per `Action` variant. Kept beside [`coverage`], whose
/// match the compiler checks; the count below is what catches a
/// variant added there but forgotten here.
fn all_variants() -> Vec<Action> {
    let s = || "x".to_string();
    vec![
        Action::WorkspaceFileAccess,
        Action::ChannelConverse,
        Action::WebSearch,
        Action::HttpRequest,
        Action::ShellExec { pattern: s() },
        Action::ExternalFileAccess { path: s() },
        Action::CrossConversationMessage,
        Action::DestructiveFileOp,
        Action::NetworkRequest { domain: s() },
        Action::CredentialAccess,
        Action::CronCreate,
        Action::McpToolCall { tool: s() },
        Action::UnknownTool { tool: s() },
        Action::WasmSkillCall { skill: s() },
        Action::CrossChannelMemoryRead { from_channel: s() },
        Action::ImportedChatRead { source_id: s() },
        Action::ImportedChatSearch {
            source_id: Some(s()),
        },
    ]
}

/// Pinned so `all_variants` cannot fall behind the enum. Raise it in
/// the same edit that adds the variant.
const ACTION_VARIANTS: usize = 17;

/// Every gateable action and every built-in tool has corpus lines.
///
/// This is what makes the corpus a tripwire rather than a snapshot: a
/// new `Action` variant or a new entry in `ToolRegistry` fails here
/// until lines exist for it.
#[test]
fn every_gateable_action_and_built_in_tool_has_corpus_lines() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let entries = parse_corpus(&fixtures);

    let variants = all_variants();
    assert_eq!(
        variants.len(),
        ACTION_VARIANTS,
        "all_variants() lists {} of {ACTION_VARIANTS} Action variants. The \
         match in coverage() is exhaustive and will have told you which one \
         is new; add it here and raise ACTION_VARIANTS.",
        variants.len()
    );
    let labels: BTreeSet<String> = variants.iter().map(|a| a.to_string()).collect();
    assert_eq!(
        labels.len(),
        variants.len(),
        "two Action variants share a Display label, so coverage cannot \
         distinguish them"
    );

    let mut produced: BTreeSet<String> = BTreeSet::new();
    let mut tools: BTreeSet<String> = BTreeSet::new();
    for entry in &entries {
        let (_, action) = classify(&entry.tool, &entry.args);
        produced.insert(action.to_string());
        tools.insert(entry.tool.clone());
    }

    for variant in &variants {
        match coverage(variant) {
            Coverage::FromCorpus => assert!(
                produced.contains(&variant.to_string()),
                "no line in {CORPUS_PATH} produces the '{variant}' action, which \
                 coverage() says a tool call reaches. Add lines for it, or record \
                 in coverage() why no tool call can produce it."
            ),
            // The other direction, and the reason it is worth
            // asserting: a variant declared unreachable that a corpus
            // line now produces means the declaration went stale, and
            // an action nobody expected to be tool-reachable became
            // tool-reachable without anyone revisiting its tier.
            Coverage::NotFromAToolCall(reason) => assert!(
                !produced.contains(&variant.to_string()),
                "a line in {CORPUS_PATH} produces '{variant}', which coverage() \
                 records as not reachable from a tool call ({reason}). Either the \
                 line is wrong or that record is now stale."
            ),
        }
    }

    // Every built-in the LLM is offered. `definitions()` is the list
    // the model actually sees, so a tool added there without corpus
    // lines is a gateable call nobody replayed.
    let registry = ToolRegistry::new(scratch.path().join("workspace"), ToolConfig::default())
        .expect("tool registry");
    for def in registry.definitions() {
        assert!(
            tools.contains(&def.name),
            "built-in tool '{}' has no line in {CORPUS_PATH}. Every gateable \
             call needs at least one, including the ones that are Tier 1: a \
             Tier 1 line records which layer refuses instead of the gate.",
            def.name
        );
    }
}
