#!/usr/bin/env python3
"""Checks on the text of Rust source, run in CI rather than as tests.

A check that passes or fails on the text of a `.rs` file is a lint. It
breaks on a rename that changed nothing and passes on a rewrite that
broke everything, so it has no business in a test binary where it reads
as behavioural coverage. These used to be `#[test]`s. They are the same
checks; what changed is that they no longer claim to be tests.

Standard library only, like the other scripts CI runs. Exits 1 on the
first failing check with the file, the line and what to do about it.

    python3 scripts/source_lints.py
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAILURES = []


def fail(path, line, message):
    where = f"{path.relative_to(ROOT)}:{line}" if line else path.relative_to(ROOT)
    FAILURES.append(f"{where}: {message}")


def rust_files(under):
    for p in sorted((ROOT / under).rglob("*.rs")):
        if "/target/" not in str(p):
            yield p


def no_test_reads_rust_source():
    """`include_str!` of a `.rs` path.

    A test that reads a source file passes or fails on its text. The
    behavioural form is to call the function and assert on what it
    returns; where the property is really about source shape, it
    belongs in this file.

    `include_str!` of a `.pub`, `.sig`, `.deleg`, `.md` or `.json` is
    data the binary ships or a fixture, and is not what this is about.
    """
    for path in rust_files("crates"):
        for n, line in enumerate(path.read_text().split("\n"), 1):
            if re.search(r'include_str!\s*\(\s*"[^"]*\.rs"', line):
                fail(
                    path,
                    n,
                    "include_str! of a .rs path. A test must not read Rust source; "
                    "call the function and assert on what it returns, or move the "
                    "check here.",
                )


def no_model_name_is_stored_in_the_config_paths():
    """No vendor model id is hardcoded where a model gets stored.

    `mod.rs` is not one of these paths: its listers filter what a
    provider returned, so a vendor prefix there is a test over the
    provider's own answer rather than a name this repo offers anyone.
    """
    vendors = ("claude", "gpt", "gemini", "llama", "mistral")
    for name in ("agents.rs", "setup.rs"):
        path = ROOT / "crates/cli/src/commands" / name
        for n, line in enumerate(path.read_text().split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("///"):
                continue
            for literal in re.findall(r'"([^"]*)"', line):
                low = literal.lower()
                for vendor in vendors:
                    # A versioned id, not prose: the vendor name
                    # followed by a separator and a digit.
                    if re.match(rf"^{vendor}[-._]?\d", low) or re.match(
                        rf"^{vendor}-\d", low
                    ):
                        fail(
                            path,
                            n,
                            f"{literal!r} is a versioned model id. A stored default "
                            "names a model this repo does not choose; take it from "
                            "the provider or from the operator.",
                        )


def every_keychain_probe_reads_the_passphrase_from_an_approved_supplier():
    """A keychain probe takes its passphrase from something that
    reads `WIRKEN_VAULT_PASSPHRASE`.

    A probe that prompts without reading it cannot run headless, and
    its failure text names a variable the command ignored. A probe that
    supplies a constant seals or degrades silently. A raw `env::var` is
    not on the list: it reads the exported value and misses one an
    earlier prompt in this process cached.
    """
    probe = "probe_" + "keychain("
    suppliers = (
        "cached_vault_" + "passphrase()",
        "prompt_vault_" + "passphrase(",
        "vault_passphrase_" + "source()",
    )
    # (file, probes it may hold outside a supplier, why)
    allowances = {
        "commands/doctor.rs": (
            1,
            "a diagnostic must neither prompt nor depend on the environment; "
            "it reports the posture it lands in",
        ),
        "commands/run.rs": (
            1,
            "resolve_channel_overrides takes run's per-boot passphrase as a "
            "parameter; its supplier is prompt_vault_passphrase at the call site",
        ),
    }
    root = ROOT / "crates/cli/src"
    seen_files = 0
    seen_probes = 0
    for path in sorted(root.rglob("*.rs")):
        seen_files += 1
        rel = str(path.relative_to(root))
        lines = path.read_text().split("\n")
        offenders = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("use ") or probe not in line:
                continue
            seen_probes += 1
            window = "\n".join(lines[max(0, i - 4) : i + 5])
            if not any(s in window for s in suppliers):
                offenders.append(i + 1)
        expected, why = allowances.get(rel, (0, None))
        if len(offenders) != expected:
            if why:
                fail(
                    path,
                    None,
                    f"the allowance ({why}) no longer matches what the file holds: "
                    f"expected {expected} probes outside a supplier, found "
                    f"{len(offenders)} at lines {offenders}",
                )
            else:
                fail(
                    path,
                    offenders[0],
                    "a keychain probe takes its passphrase from something that does "
                    "not read WIRKEN_VAULT_PASSPHRASE. Take it from "
                    "cached_vault_passphrase, or from prompt_vault_passphrase inside "
                    "run, or name an allowance in this script with its reason.",
                )
    if seen_files < 10 or seen_probes < 25:
        FAILURES.append(
            f"the walker saw too little to be trusted: {seen_files} files, "
            f"{seen_probes} probes"
        )


def webchat_routes_keep_their_guards():
    """Four properties of the webchat routes.

    Checks on source text: where a guard sits inside a route, not
    what the route answers.
    """
    path = ROOT / "crates/cli/src/commands/webchat.rs"
    src = path.read_text()

    def arm(start_marker, end_marker, label):
        try:
            after = src.split(start_marker, 1)[1]
            return after.split(end_marker, 1)[0]
        except IndexError:
            fail(path, None, f"could not find the {label} route")
            return ""

    verify = arm(
        "async fn route_verify(",
        "/// Verify the audit chain",
        "verify",
    )
    if verify:
        if "api_preflight(req.raw, shared.port, true)" not in verify:
            fail(path, None, "the verify route must require an Origin")
        if "shared.verify_limit.check()" not in verify:
            fail(path, None, "the verify route must be rate limited")
        if "VerifyClaim::claim(&shared.verify_running)" not in verify:
            fail(path, None, "the verify route must take a single-flight claim")
        if "verify_running.store(" in verify:
            fail(
                path,
                None,
                "the verify latch is released by the claim going out of scope, not "
                "by a statement the next early return can skip",
            )
        if "verify_chain_off_runtime(" not in verify:
            fail(path, None, "the verify must run off the async runtime")

    off_runtime = arm(
        "async fn verify_chain_off_runtime(",
        "\n}\n",
        "off-runtime verify",
    )
    if off_runtime and "spawn_blocking" not in off_runtime:
        fail(
            path,
            None,
            "verify_chain_off_runtime is the route's only path to AuditLog::verify; "
            "the scan runs on the blocking pool or it holds the runtime",
        )

    chat = arm(
        "async fn route_chat(",
        "/// Stream one accepted turn",
        "chat",
    )
    if chat:
        scan = chat.find("inbound_scan::scan_catching_panics")
        inbound = chat.find('"message.inbound",')
        flagged = chat.find('"message.threat_flagged",')
        if scan < 0:
            fail(path, None, "the chat route must scan through the shared helper")
        elif "detector.scan(" in chat:
            fail(
                path,
                None,
                "the detector is reached through inbound_scan, not called directly: "
                "a direct call is uncaught, and an uncaught panic unwinds past the "
                "inbound write",
            )
        if scan >= 0 and inbound >= 0 and not scan < inbound:
            fail(
                path,
                None,
                "the inbound row is written after the scan so it carries the verdict",
            )
        if scan >= 0 and flagged >= 0 and not scan < flagged:
            fail(path, None, "the threat row follows the scan that produced it")
        if "shared.open_turns.try_open(&conversation)" not in chat:
            fail(path, None, "the chat route must claim the conversation's turn")
        if "conversation_key(json[\"conversation\"].as_str())" not in chat:
            fail(path, None, "the chat route must take its conversation from the request")
        if "json_unavailable(" not in chat:
            fail(
                path,
                None,
                "a halted audit writer must answer 503, which is the state the page "
                "raises its banner from",
            )
        if "json_conflict(" not in chat:
            fail(
                path,
                None,
                "a send into an open turn must be refused through json_conflict; "
                "what that builder returns is asserted in the test binary",
            )
        # The open-turn refusal names the age, so the page can say how
        # long, and goes out before anything is spent on the turn.
        for needle, why in (
            (
                '"age_seconds": shared.open_turns.open_age(&conversation)',
                "the refusal must carry the open turn's age",
            ),
            ("json_conflict(&body)", "the refusal must go through the 409 builder"),
        ):
            if needle not in chat:
                fail(path, None, why)
        claim = chat.find("shared.open_turns.try_open(&conversation)")
        if claim < 0 or inbound < 0 or not claim < inbound:
            fail(
                path,
                None,
                "the turn claim comes first: refused before the inbound row is written",
            )

    turn = arm(
        "async fn run_turn(",
        "/// `POST /api/verify`",
        "chat stream",
    )
    if turn and r'data: {\"type\":\"done\"}\n\n' not in turn:
        fail(
            path,
            None,
            "the chat stream must emit a done event before the socket closes; "
            "its absence is what the page reads as a cut-off stream",
        )

    decision = arm(
        "async fn route_decision(",
        "let resolve = shared.pending_approvals.resolve(&request_id, decision);",
        "approval decision",
    )
    if decision:
        for needle, why in (
            (
                "approval_belongs_to_webchat(&shared.pending_approvals, &request_id) "
                "== Some(false)",
                "the decision route must consult the channel guard before resolving",
            ),
            (
                'conversation_key(json["conversation"].as_str())',
                "the decision must name the conversation it came from",
            ),
            (
                "approval_belongs_to_conversation(&shared.pending_approvals, "
                "&request_id, &viewing)",
                "the decision must be checked against that conversation",
            ),
            (
                "json_forbidden(DECISION_WRONG_CONVERSATION)",
                "a decision for another conversation must be refused",
            ),
        ):
            if needle not in decision:
                fail(path, None, why)

    if "let session_id = SessionId::new(viewing);" not in src:
        fail(path, None, "the decision ack must go to the conversation being viewed")

    # The About panel's two routes are the only ones that serve
    # capabilities and credentials, and both preflight.
    for fn_marker, next_marker, label in (
        ("async fn route_capabilities(", "/// `GET /api/credentials`", "GET /api/capabilities"),
        ("fn route_credentials(", "/// `GET /api/status`", "GET /api/credentials"),
    ):
        an_arm = arm(fn_marker, next_marker, label)
        if an_arm and "api_preflight(req.raw, shared.port, false)" not in an_arm:
            fail(path, None, f"the {label} route must preflight")

    approvals = arm(
        "fn route_approvals(",
        "/// `GET /api/capabilities`",
        "approvals",
    )
    if approvals:
        for needle, why in (
            ('query_param(req.first_line, "c")', "the listing must read the conversation"),
            ("conversation_key(Some(c))", "and normalise it the same way"),
            (
                "approvals_snapshot_for(&shared.pending_approvals, conversation.as_deref())",
                "and scope the snapshot to it",
            ),
        ):
            if needle not in approvals:
                fail(path, None, why)

    if "conversation_rows(&cfg, rows, &shared.open_turns)" not in src:
        fail(
            path,
            None,
            "the conversation list route must serve the rows conversation_rows builds",
        )


CHECKS = (
    no_test_reads_rust_source,
    no_model_name_is_stored_in_the_config_paths,
    every_keychain_probe_reads_the_passphrase_from_an_approved_supplier,
    webchat_routes_keep_their_guards,
)


if __name__ == "__main__":
    for check in CHECKS:
        check()
    if FAILURES:
        print("source lints failed:\n", file=sys.stderr)
        for f in FAILURES:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print(f"source lints: {len(CHECKS)} checks, no findings")
