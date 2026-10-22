#!/usr/bin/env python3
"""Require a `### Security` heading when a release closes an advisory.

`releases.json` flags a release as carrying security fixes from one
signal: a `### Security` heading in its CHANGELOG section
(build-releases-json.py). A dependency bump that closes an advisory
without that heading ships a manifest telling every installed binary
there is nothing security-related to install. This check closes that
gap from the tool side.

It runs `cargo deny check advisories` at the previous tag and at HEAD.
The advisory ids reported at the tag and not now are the ones this
release closes. When that set is not empty, the release's CHANGELOG
section must carry `### Security`: `## [Unreleased]` before the version
bump, the new version's section after it, whichever is the first section
with an entry. A heading with no closed advisory is allowed; a fix in
this repository's own code counts too.

    scripts/check-security-heading.py [<previous-tag>]

With no argument the previous tag is `git describe --tags --abbrev=0
HEAD^`, as check-names.sh takes it. Exit 1 when the heading is missing,
2 when cargo-deny or git could not answer. Standard library only; needs
git and cargo-deny on the path.
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DENY = ["cargo", "deny", "-f", "json", "--all-features", "check", "advisories"]


def advisory_ids(tree):
    """The advisory ids cargo-deny reports for the tree at `tree`."""
    run = subprocess.run(DENY, cwd=tree, capture_output=True, text=True)
    ids = set()
    for line in (run.stdout + run.stderr).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            diag = json.loads(line)
        except json.JSONDecodeError:
            continue
        advisory = (diag.get("fields") or {}).get("advisory") or {}
        if "id" in advisory:
            ids.add(advisory["id"])
    # cargo-deny exits 1 both when it reports advisories and when it could
    # not run at all; no reported id with a failure is the second case.
    if run.returncode != 0 and not ids:
        tail = (run.stderr or run.stdout).strip().splitlines()[-5:]
        sys.exit("cargo deny could not check %s:\n  %s" % (tree, "\n  ".join(tail)))
    return ids


def previous_tag():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0", "HEAD^"], cwd=ROOT, text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        sys.exit("no previous tag reachable from HEAD^: %s" % e)


def release_section(text):
    """The first `## [...]` section with an entry, as (name, body)."""
    sections = []
    name, body = None, []
    for line in text.splitlines():
        m = re.match(r"^## \[([^\]]+)\]", line)
        if m:
            if name is not None:
                sections.append((name, "\n".join(body)))
            name, body = m.group(1), []
        elif name is not None:
            body.append(line)
    if name is not None:
        sections.append((name, "\n".join(body)))
    for n, b in sections:
        if any(l.startswith("- ") for l in b.splitlines()):
            return n, b
    return None, ""


def has_security(body):
    """The same rule build-releases-json.py applies."""
    return any(line.strip() == "### Security" for line in body.splitlines())


def closed_since(prev):
    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp) / "prev"
        add = subprocess.run(
            ["git", "worktree", "add", "--detach", str(tree), prev],
            cwd=ROOT, capture_output=True, text=True,
        )
        if add.returncode != 0:
            sys.exit("git worktree add %s: %s" % (prev, add.stderr.strip()))
        try:
            before = advisory_ids(tree)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(tree)],
                cwd=ROOT, capture_output=True,
            )
    now = advisory_ids(ROOT)
    return sorted(before - now)


def main():
    prev = sys.argv[1] if len(sys.argv) > 1 else previous_tag()
    closed = closed_since(prev)
    name, body = release_section((ROOT / "CHANGELOG.md").read_text())
    if not closed:
        print("check-security-heading: no advisory reported at %s is closed now; no heading required" % prev)
        return 0
    ids = ", ".join(closed)
    if has_security(body):
        print("check-security-heading: %s closed since %s; `### Security` present in [%s]" % (ids, prev, name))
        return 0
    print(
        "check-security-heading: %s reported at %s and not now, but the [%s] section of "
        "CHANGELOG.md has no `### Security` heading. Add one naming them, so releases.json "
        "flags this release." % (ids, prev, name),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
