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


CHECKS = (
    no_test_reads_rust_source,
    no_model_name_is_stored_in_the_config_paths,
    every_keychain_probe_reads_the_passphrase_from_an_approved_supplier,
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
