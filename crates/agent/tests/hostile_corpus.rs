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
//! A line with `inbound` instead of `tool` is replayed through
//! `InboundGate::check` against its `allow` entries and expects
//! `dropped` or `admitted`.
//!
//! An `http_request` line may also carry `permissions`, a skill
//! `permissions:` block as JSON, and `gate`, what the skill-profile
//! gates the runtime runs after the tier gate answer under that
//! block: `allowed`, or `refused:<axis>` with the axis of the
//! `skill_permission_denied` row (`tools`, `http_method`,
//! `http_post_path`, `credentials`, `egress`). Those gates are the
//! layer the `tier1` lines above point at, replayed in the runtime's
//! order, and every refusal they produce is checked to name the host
//! and the method.
//!
//! A line may carry one more field naming a control behind the gate,
//! with the answer that control has to give for the line's call. Each
//! is replayed by its own test below:
//!
//! - `resolves_to`, on an `http_request` line with `permissions`: the
//!   addresses the host's name resolves to. `gate` is then answered by
//!   `EgressClient::request` under a resolver that gives those
//!   addresses, so a name that clears the allow-set and resolves
//!   outside global unicast replays to `refused:egress`.
//! - `card`: approval-card styles. The arguments line of the card, read
//!   the way that channel displays it, has to be the arguments.
//! - `ask`: `asked`, or `refused:arguments_too_long` for a call the
//!   approval card could not show whole.
//! - `container`: what the exec container is given under the named
//!   egress mode: its network, the resolver and search domain its
//!   `resolv.conf` is written with, and whether a seccomp profile is
//!   named.
//! - `egress_ask`: a request the egress proxy puts to the operator, and
//!   the line the approval shows for it.
//! - `seccomp_refuses`: syscalls the exec seccomp profile must refuse.
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
use wirken_adapter_core::approval_card::{ApprovalCard, CardStyle, one_line, shown_whole};
use wirken_agent::approval_gate::{ApprovalGate, ApprovalOutcome};
use wirken_agent::egress::{
    EgressClient, EgressDenyReason, EgressEnforcement, HostResolver, HttpAccessDenied,
};
use wirken_agent::error::PermissionDenialContext;
use wirken_agent::http_tool;
use wirken_agent::sandbox::{EgressDecision, SandboxConfig, build_host_config};
use wirken_agent::sandbox_egress::{
    ObservedSensitivity, SandboxEgressAttribution, SandboxEgressContext, SandboxEgressPolicy,
};
use wirken_agent::skill_perms::{
    EffectiveProfile, GateDecision, PermissionsBlock, PhasedEffective, resolve_block,
};
use wirken_agent::tool::{ReadSensitivity, ToolConfig, ToolRegistry, tool_to_action};
use wirken_gateway::permissions::{
    Action, ApprovalScope, PermissionCheck, PermissionStore, PermissionTier,
};
use wirken_gateway::sender_registry::{InboundGate, SenderRegistry, Verdict};
use wirken_sandbox::egress::{EgressDecider, RequestKind, RequestSeen};

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

/// What the skill-profile gates should answer for an `http_request`
/// line, when the line says.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GateExpect {
    Allowed,
    Refused(String),
}

impl GateExpect {
    fn parse(raw: &str) -> Option<Self> {
        if raw == "allowed" {
            return Some(Self::Allowed);
        }
        let axis = raw.strip_prefix("refused:")?;
        matches!(
            axis,
            "tools" | "http_method" | "http_post_path" | "credentials" | "egress"
        )
        .then(|| Self::Refused(axis.to_string()))
    }
}

impl std::fmt::Display for GateExpect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => f.write_str("allowed"),
            Self::Refused(axis) => write!(f, "refused:{axis}"),
        }
    }
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
    /// The skill `permissions:` block and the gate answer under it,
    /// for an `http_request` line that carries them.
    gate: Option<(PermissionsBlock, GateExpect)>,
    /// The line as written, for the fields one test reads.
    raw: Value,
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
        // Replayed by `hostile_inbound_lines_replay_to_their_expected_outcome`.
        if entry.get("inbound").is_some() {
            continue;
        }
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
        let tool = text(&entry, "tool", lineno);
        let gate = entry.get("gate").map(|g| {
            let raw = g
                .as_str()
                .unwrap_or_else(|| panic!("{CORPUS_PATH}:{lineno}: 'gate' must be a string"));
            let expect = GateExpect::parse(raw).unwrap_or_else(|| {
                panic!(
                    "{CORPUS_PATH}:{lineno}: unknown gate '{raw}'. 'allowed', or \
                     'refused:' and one of tools, http_method, http_post_path, \
                     credentials, egress."
                )
            });
            assert_eq!(
                tool, "http_request",
                "{CORPUS_PATH}:{lineno}: 'gate' replays the http_request gates and \
                 is only meaningful on an http_request line"
            );
            let block: PermissionsBlock =
                serde_json::from_value(field(&entry, "permissions", lineno).clone())
                    .unwrap_or_else(|e| {
                        panic!("{CORPUS_PATH}:{lineno}: 'permissions' is not a skill block: {e}")
                    });
            (block, expect)
        });
        assert!(
            gate.is_some() || entry.get("permissions").is_none(),
            "{CORPUS_PATH}:{lineno}: 'permissions' without 'gate' replays nothing"
        );
        entries.push(Entry {
            lineno,
            id,
            tool,
            args: substitute(&args, fixtures),
            expect,
            key: text(&entry, "key", lineno),
            why,
            gate,
            raw: entry.clone(),
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

/// One inbound line: a message and the allowlist it meets.
struct InboundEntry {
    lineno: usize,
    id: String,
    channel: String,
    sender_id: String,
    conversation_id: String,
    /// `(channel, id, group)`.
    allow: Vec<(String, String, bool)>,
    admitted: bool,
    why: String,
}

fn parse_inbound() -> Vec<InboundEntry> {
    let mut entries = Vec::new();
    for (idx, raw) in CORPUS.lines().enumerate() {
        let lineno = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("{CORPUS_PATH}:{lineno}: not valid JSON: {e}"));
        let Some(inbound) = entry.get("inbound") else {
            continue;
        };
        let admitted = match text(&entry, "expect", lineno).as_str() {
            "dropped" => false,
            "admitted" => true,
            other => panic!(
                "{CORPUS_PATH}:{lineno}: unknown inbound expect '{other}'. \
                 One of: dropped, admitted."
            ),
        };
        let allow = field(&entry, "allow", lineno)
            .as_array()
            .unwrap_or_else(|| panic!("{CORPUS_PATH}:{lineno}: 'allow' must be an array"))
            .iter()
            .map(|a| {
                (
                    text(a, "channel", lineno),
                    text(a, "id", lineno),
                    field(a, "group", lineno)
                        .as_bool()
                        .unwrap_or_else(|| panic!("{CORPUS_PATH}:{lineno}: 'group' is a bool")),
                )
            })
            .collect();
        let why = text(&entry, "why", lineno);
        assert!(
            !why.trim().is_empty(),
            "{CORPUS_PATH}:{lineno}: 'why' may not be empty."
        );
        entries.push(InboundEntry {
            lineno,
            id: text(&entry, "id", lineno),
            channel: text(inbound, "channel", lineno),
            sender_id: text(inbound, "sender_id", lineno),
            conversation_id: text(inbound, "conversation_id", lineno),
            allow,
            admitted,
            why,
        });
    }
    entries
}

/// Replay every inbound line, each against a fresh allowlist.
#[test]
fn hostile_inbound_lines_replay_to_their_expected_outcome() {
    let entries = parse_inbound();
    assert!(
        entries.iter().any(|e| !e.admitted),
        "{CORPUS_PATH} has no inbound line expected to be dropped"
    );
    for entry in entries {
        let scratch = tempfile::tempdir().unwrap();
        let registry = SenderRegistry::open(&scratch.path().join("senders.db")).unwrap();
        for (channel, id, group) in &entry.allow {
            registry.add(channel, id, *group, "").unwrap();
        }
        let gate = InboundGate::new(registry, Default::default());
        let verdict = gate.check(&entry.channel, &entry.sender_id, &entry.conversation_id);
        let admitted = matches!(verdict, Verdict::Admitted(_));
        assert_eq!(
            admitted,
            entry.admitted,
            "\n{CORPUS_PATH}:{lineno}  id={id}\n  \
             message   {channel} sender={sender} conversation={conversation}\n  \
             allow     {allow:?}\n  \
             expected  {expected}\n  \
             observed  {verdict:?}\n  \
             why       {why}\n\n\
             This is a finding about the gate, not a stale expectation.\n",
            lineno = entry.lineno,
            id = entry.id,
            channel = entry.channel,
            sender = entry.sender_id,
            conversation = entry.conversation_id,
            allow = entry.allow,
            expected = if entry.admitted {
                "admitted"
            } else {
                "dropped"
            },
            why = entry.why,
        );
    }
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
        let session_id = format!("{agent_id}/test/{}", entry.lineno);

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
                .approve(&action, &agent_id, "test", "corpus")
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
                let written =
                    store.approve_with_scope(&action, &agent_id, "test", "corpus", scope.clone());
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

/// Replay one `http_request` line through the skill-profile gates
/// in the runtime's order: `tools.allow`, then the `http_request`
/// gate (method, POST endpoint, credential), then the egress
/// allow-set. The answer is what the tool call would get with the
/// line's block as the agent's whole effective profile.
/// A resolver that answers every name with the line's `resolves_to`.
struct Resolves(Vec<std::net::IpAddr>);

#[async_trait::async_trait]
impl HostResolver for Resolves {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(self
            .0
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, port))
            .collect())
    }
}

fn replay_gate(block: PermissionsBlock, args: &Value, resolves_to: Option<&Value>) -> GateExpect {
    let profile = resolve_block(block, Path::new("/skill"), None, None)
        .expect("corpus permissions block resolves");
    let effective = EffectiveProfile::Resolved(profile);
    let perms = PhasedEffective::from_base(effective.clone());
    if perms.gate_tool("http_request") != GateDecision::Allow {
        return GateExpect::Refused("tools".into());
    }
    if let Some(refusal) = http_tool::gate(&perms, &args.to_string()) {
        // The property the row and the tool result carry: a refusal
        // names the host and the method it was refused on.
        let host = refusal
            .host
            .clone()
            .expect("every corpus http_request line has a host");
        assert!(
            refusal.message.contains(&format!("'{host}'"))
                && refusal.message.contains(&refusal.method),
            "a refusal names the host and the method: {refusal:?}"
        );
        return GateExpect::Refused(refusal.axis.to_string());
    }
    let client = EgressClient::new();
    client.set_enforcement(EgressEnforcement::from_profile(&effective));
    let url = args["url"].as_str().unwrap_or_default();
    if !client.request_would_pass(url) {
        return GateExpect::Refused("egress".into());
    }
    // The name cleared the allow-set. Where the line says what the name
    // resolves to, the request is built the way the tool builds it, so
    // the address check answers too.
    let Some(resolves_to) = resolves_to else {
        return GateExpect::Allowed;
    };
    let addresses = resolves_to
        .as_array()
        .expect("'resolves_to' is an array of addresses")
        .iter()
        .map(|a| {
            a.as_str()
                .and_then(|s| s.parse().ok())
                .expect("'resolves_to' holds IP addresses")
        })
        .collect();
    let client = client.with_resolver(std::sync::Arc::new(Resolves(addresses)));
    let built = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(client.request(reqwest::Method::GET, url));
    match built {
        Ok(_) => GateExpect::Allowed,
        Err(HttpAccessDenied::Egress(denied)) => {
            // The refusal names the host and the address it was
            // refused on.
            let EgressDenyReason::NonGlobalAddress { address } = &denied.reason else {
                panic!("a listed name is refused on its address: {denied:?}");
            };
            let shown = denied.to_string();
            assert!(
                shown.contains(&denied.host) && shown.contains(&address.to_string()),
                "a refusal names the host and the address: {shown}"
            );
            GateExpect::Refused("egress".into())
        }
        Err(other) => panic!("unexpected refusal for {url}: {other}"),
    }
}

/// Replay every `http_request` line that carries a block through the
/// gates behind the tier gate. The corpus has to reach every refusal
/// axis and an allow, or a gate that refused everything would pass.
#[test]
fn http_request_lines_replay_through_the_skill_gates() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in parse_corpus(&fixtures) {
        let Some((block, expect)) = entry.gate else {
            continue;
        };
        let observed = replay_gate(block, &entry.args, entry.raw.get("resolves_to"));
        assert_eq!(
            observed,
            expect,
            "\n{CORPUS_PATH}:{lineno}  id={id}\n  \
             call      http_request {args}\n  \
             expected  {expect}\n  \
             observed  {observed}\n  \
             why       {why}\n\n\
             This is a finding about the gate, not a stale expectation.\n",
            lineno = entry.lineno,
            id = entry.id,
            args = entry.args,
            why = entry.why,
        );
        seen.insert(observed.to_string());
    }
    for required in [
        "allowed",
        "refused:http_method",
        "refused:http_post_path",
        "refused:credentials",
        "refused:egress",
    ] {
        assert!(
            seen.contains(required),
            "no http_request line in {CORPUS_PATH} replays to '{required}'; \
             the gate's {required} arm is unpinned"
        );
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
        Action::CrossChannelMemoryRead { from_channel: s() },
        Action::ImportedChatRead { source_id: s() },
        Action::ImportedChatSearch {
            source_id: Some(s()),
        },
    ]
}

/// Pinned so `all_variants` cannot fall behind the enum. Raise it in
/// the same edit that adds the variant.
const ACTION_VARIANTS: usize = 16;

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

/// The arguments line of a card in `style`, as that channel displays
/// it: the text after the label, with the style's own markup undone.
fn displayed_arguments(card: &ApprovalCard, style: &str) -> String {
    let (style, label) = match style {
        "discord" => (CardStyle::Discord, "**arguments:** "),
        "telegram" => (CardStyle::TelegramHtml, "<b>arguments:</b> "),
        "plain" => (CardStyle::Plain, "arguments: "),
        other => panic!("unknown card style '{other}'. One of: discord, telegram, plain."),
    };
    let text = card.render(style);
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix(label))
        .unwrap_or_else(|| panic!("the card has an arguments line: {text}"));
    match style {
        CardStyle::Plain => line.to_string(),
        // The value is escaped inside `<code>`.
        CardStyle::TelegramHtml => line
            .strip_prefix("<code>")
            .and_then(|l| l.strip_suffix("</code>"))
            .expect("arguments are a code element")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
        // A code span shows its content as written and cannot hold a
        // backtick. Outside one, a backslash and the punctuation
        // character after it display as that character, and an
        // unescaped punctuation character would be read as markup.
        CardStyle::Discord => match line.strip_prefix('`').and_then(|l| l.strip_suffix('`')) {
            Some(inner) => {
                assert!(!inner.contains('`'), "a code span cannot hold a backtick");
                inner.to_string()
            }
            None => {
                let mut shown = String::new();
                let mut chars = line.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        shown.push(chars.next().expect("an escape is a pair"));
                    } else {
                        assert!(
                            !c.is_ascii_punctuation(),
                            "'{c}' is unescaped and would be read as markup: {line}"
                        );
                        shown.push(c);
                    }
                }
                shown
            }
        },
        _ => unreachable!("styles are matched above"),
    }
}

/// Every line with `card`: on each style named, the card shows the
/// arguments the model sent, character for character.
#[test]
fn approval_cards_show_the_arguments_as_sent() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let mut replayed = 0;
    for entry in parse_corpus(&fixtures) {
        let Some(styles) = entry.raw.get("card") else {
            continue;
        };
        let arguments = entry.args.to_string();
        let card = ApprovalCard {
            agent: "default".into(),
            tool_name: entry.tool.clone(),
            tier: "tier3".into(),
            action_key: entry.key.clone(),
            arguments: Some(arguments.clone()),
            ..ApprovalCard::default()
        };
        for style in styles.as_array().expect("'card' is an array of styles") {
            let style = style.as_str().expect("a card style is a string");
            assert_eq!(
                displayed_arguments(&card, style),
                one_line(&arguments),
                "\n{CORPUS_PATH}:{}  id={}\n  the {style} card does not show the \
                 arguments as sent\n  why       {}\n",
                entry.lineno,
                entry.id,
                entry.why,
            );
            replayed += 1;
        }
    }
    assert!(replayed > 0, "no line in {CORPUS_PATH} carries 'card'");
}

/// Every line with `ask`: whether the call can be put to an operator
/// at all. The runtime refuses, before any surface renders it, a call
/// whose arguments the card would cut.
#[test]
fn a_call_the_card_cannot_show_whole_is_not_asked() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let mut seen = BTreeSet::new();
    for entry in parse_corpus(&fixtures) {
        let Some(expect) = entry.raw.get("ask").and_then(|a| a.as_str()) else {
            continue;
        };
        let observed = if shown_whole(&entry.args.to_string()) {
            "asked"
        } else {
            "refused:arguments_too_long"
        };
        assert_eq!(
            observed, expect,
            "\n{CORPUS_PATH}:{}  id={}\n  why       {}\n",
            entry.lineno, entry.id, entry.why,
        );
        seen.insert(observed);
    }
    assert!(
        seen.contains("refused:arguments_too_long"),
        "no line in {CORPUS_PATH} replays to a refused ask"
    );
}

/// Every line with `container`: what the exec container is given under
/// the named egress mode.
#[test]
fn exec_containers_are_given_what_the_line_says() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let mut replayed = 0;
    for entry in parse_corpus(&fixtures) {
        let Some(container) = entry.raw.get("container") else {
            continue;
        };
        let want = |name: &str| {
            container
                .get(name)
                .unwrap_or_else(|| panic!("{CORPUS_PATH}:{}: container.{name}", entry.lineno))
        };
        let decision = match want("egress").as_str() {
            Some("none") => EgressDecision::Denied,
            Some("proxied") => EgressDecision::Proxied("wirken-egress-corpus"),
            other => panic!("unknown container.egress {other:?}. One of: none, proxied."),
        };
        let host = build_host_config(&SandboxConfig::default(), "/workspace", decision);
        let at = format!("{CORPUS_PATH}:{}  id={}", entry.lineno, entry.id);
        if decision == EgressDecision::Denied {
            assert_eq!(
                host.network_mode.as_deref(),
                want("network").as_str(),
                "{at}"
            );
        }
        assert_eq!(
            host.dns.as_deref(),
            Some(&[want("nameserver").as_str().unwrap().to_string()][..]),
            "{at}: the resolver written to resolv.conf"
        );
        assert_eq!(
            host.dns_search.as_deref(),
            Some(&[want("search").as_str().unwrap().to_string()][..]),
            "{at}: the search list written to resolv.conf"
        );
        assert_eq!(
            wirken_sandbox::seccomp::is_set(&host),
            want("seccomp").as_bool().unwrap(),
            "{at}: whether a seccomp profile is named"
        );
        replayed += 1;
    }
    assert!(replayed > 0, "no line in {CORPUS_PATH} carries 'container'");
}

/// Every line with `seccomp_refuses`: the exec profile allows none of
/// the named syscalls on any rule that does not test its arguments.
#[test]
fn the_exec_seccomp_profile_refuses_what_the_line_names() {
    let profile: Value = serde_json::from_str(wirken_sandbox::seccomp::PROFILE).unwrap();
    assert_eq!(profile["defaultAction"], "SCMP_ACT_ERRNO");
    let allowed: BTreeSet<&str> = profile["syscalls"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule["action"] == "SCMP_ACT_ALLOW")
        .flat_map(|rule| rule["names"].as_array().unwrap())
        .map(|name| name.as_str().unwrap())
        .collect();
    assert!(allowed.contains("read"), "the profile is an allowlist");
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let mut replayed = 0;
    for entry in parse_corpus(&fixtures) {
        let Some(names) = entry.raw.get("seccomp_refuses") else {
            continue;
        };
        for name in names.as_array().expect("'seccomp_refuses' is an array") {
            let name = name.as_str().expect("a syscall name");
            assert!(
                !allowed.contains(name),
                "\n{CORPUS_PATH}:{}  id={}\n  the exec seccomp profile allows '{name}'\n  \
                 why       {}\n",
                entry.lineno,
                entry.id,
                entry.why,
            );
            replayed += 1;
        }
    }
    assert!(
        replayed > 0,
        "no line in {CORPUS_PATH} carries 'seccomp_refuses'"
    );
}

/// Records what the egress proxy asks an operator, and approves.
#[derive(Default)]
struct Asked(std::sync::Mutex<Vec<Option<String>>>);

#[async_trait::async_trait]
impl ApprovalGate for Asked {
    async fn request_approval(&self, ctx: &PermissionDenialContext) -> ApprovalOutcome {
        self.0.lock().unwrap().push(ctx.arguments.clone());
        ApprovalOutcome::Approved { actor: None }
    }

    fn source(&self) -> wirken_audit::ApprovalSource {
        wirken_audit::ApprovalSource::Stdin
    }
}

/// Every line with `egress_ask`: a request that clears the channel's
/// allowlist, from a session that has read exec output, is put to the
/// operator, and what the operator is shown is the line's `shown`.
#[test]
fn an_egress_ask_shows_the_request() {
    let scratch = tempfile::tempdir().unwrap();
    let fixtures = build_fixtures(scratch.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut replayed = 0;
    for entry in parse_corpus(&fixtures) {
        let Some(ask) = entry.raw.get("egress_ask") else {
            continue;
        };
        let string = |name: &str| ask[name].as_str().expect("egress_ask field").to_string();
        let domains: Vec<String> = ask["domains"]
            .as_array()
            .expect("egress_ask.domains")
            .iter()
            .map(|d| d.as_str().unwrap().to_string())
            .collect();
        let gate = std::sync::Arc::new(Asked::default());
        let observed: ObservedSensitivity = Default::default();
        observed
            .write()
            .unwrap()
            .insert(ReadSensitivity::ExecOutput);
        let ctx = SandboxEgressContext {
            policy: SandboxEgressPolicy::from_config("allowlist", &domains),
            attribution: SandboxEgressAttribution {
                agent_id: "default".into(),
                ..Default::default()
            },
            audit: None,
            observed,
            approval: Some(gate.clone()),
        };
        let port = u16::try_from(ask["port"].as_u64().expect("egress_ask.port")).unwrap();
        let kind = if port == 443 {
            RequestKind::Connect
        } else {
            RequestKind::Plain
        };
        let (method, path, host) = (string("method"), string("path"), string("host"));
        let verdict = runtime.block_on(ctx.decide(
            &host,
            port,
            kind,
            RequestSeen {
                method: &method,
                path: &path,
            },
        ));
        let at = format!("{CORPUS_PATH}:{}  id={}", entry.lineno, entry.id);
        assert!(verdict.escalated, "{at}: the operator is asked");
        assert_eq!(
            gate.0.lock().unwrap().as_slice(),
            [Some(string("shown"))],
            "{at}: what the approval shows for the request"
        );
        replayed += 1;
    }
    assert!(
        replayed > 0,
        "no line in {CORPUS_PATH} carries 'egress_ask'"
    );
}
