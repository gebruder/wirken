#!/usr/bin/env python3
"""Build releases.json, the cumulative release manifest, for review.

`wirken update` reads one file to learn what releases exist: which is
newest, which carried security fixes, and the sha256 of every
artifact. This script writes that file from two sources the
maintainer already has, for the maintainer to read before signing it:

- The git tags, for each version's `issued_at`: the tag's time in UTC.
  The release being cut must be tagged; an older version with no tag
  keeps the `issued_at` the previous manifest gave it, or failing that
  its CHANGELOG date at midnight UTC, and is named on stderr.
- CHANGELOG.md, for whether each version has a `### Security` section,
  and a one-line summary (the first sentence of its first bullet; edit
  it if it reads badly).
- Each release's published checksums.sha256, for the artifacts. The
  release being cut reads its checksums from a local file (the draft's,
  downloaded in the release runbook); older releases come from
  --previous, the last published releases.json, or failing that are
  fetched from GitHub.

A version in CHANGELOG.md with no published checksums is left out and
named on stderr. A release with no CHANGELOG section is not listed:
there is nothing to say whether it carried security fixes.

    scripts/build-releases-json.py --current v2.3.0 \\
        --checksums checksums.sha256 --previous previous/releases.json \\
        > releases.json

Then sign it with scripts/sign-release.sh, which signs it under the
`wirken-release-manifest` namespace. See docs/release-process.md.

Standard library only.
"""

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent

REPO = "gebruder/wirken"
HEADING = re.compile(r"^## \[(\d+\.\d+\.\d+)\] [-\u2014] (\d{4}-\d{2}-\d{2})\s*$")
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  (wirken-[A-Za-z0-9_.-]+)$")
MAX_SUMMARY = 200


def version_key(v):
    return tuple(int(p) for p in v.split("."))


def changelog_sections(text):
    """{version: (date, body)} for every released version."""
    sections = {}
    current = None
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            current = m.group(1)
            sections[current] = [m.group(2), []]
            continue
        if line.startswith("## "):
            current = None
            continue
        if current:
            sections[current][1].append(line)
    return {v: (date, "\n".join(body)) for v, (date, body) in sections.items()}


def to_utc(iso):
    """An ISO 8601 time with an offset, as the manifest writes it in UTC."""
    t = datetime.datetime.fromisoformat(iso.strip())
    if t.tzinfo is None:
        raise ValueError(f"{iso!r} carries no UTC offset")
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tag_time(version):
    """The UTC time of tag v<version>: the tagger's time for an annotated
    tag, the commit's for a lightweight one. None when the tag is absent."""
    for field in ("taggerdate", "creatordate"):
        out = subprocess.run(
            ["git", "for-each-ref", f"refs/tags/v{version}", f"--format=%({field}:iso-strict)"],
            cwd=ROOT, capture_output=True, text=True,
        ).stdout.strip()
        if out:
            return to_utc(out)
    return None


def has_security(body):
    return any(line.strip() == "### Security" for line in body.splitlines())


def summary(body):
    """The first sentence of the section's first bullet, as plain text."""
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("- "):
            continue
        text = [line[2:].strip()]
        for cont in lines[i + 1 :]:
            if not cont.startswith("  ") or not cont.strip():
                break
            text.append(cont.strip())
        flat = " ".join(text)
        flat = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", flat)
        flat = flat.replace("**", "").replace("`", "")
        sentence = re.split(r"(?<=[.!?])\s", flat, maxsplit=1)[0]
        if len(sentence) > MAX_SUMMARY:
            sentence = sentence[: MAX_SUMMARY - 3].rstrip() + "..."
        return sentence
    return ""


def parse_checksums(text, source):
    artifacts = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = SHA256_LINE.match(line.strip())
        if not m:
            sys.exit(f"{source}: not a checksums.sha256 line: {line!r}")
        artifacts[m.group(2)] = m.group(1)
    if not artifacts:
        sys.exit(f"{source}: no artifacts")
    return artifacts


def fetch_checksums(version):
    url = f"https://github.com/{REPO}/releases/download/v{version}/checksums.sha256"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return parse_checksums(resp.read().decode(), url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--current", required=True, help="tag being released, e.g. v2.3.0")
    ap.add_argument("--checksums", required=True, help="that release's checksums.sha256")
    ap.add_argument("--previous", help="the last published releases.json, to reuse its artifacts")
    ap.add_argument("--changelog", default=str(pathlib.Path(__file__).resolve().parent.parent / "CHANGELOG.md"))
    ap.add_argument("--offline", action="store_true", help="never fetch; leave out versions not in --previous")
    args = ap.parse_args()

    current = args.current.removeprefix("v")
    sections = changelog_sections(pathlib.Path(args.changelog).read_text())
    if current not in sections:
        sys.exit(f"{args.changelog} has no `## [{current}] - <date>` section")

    previous = {}
    if args.previous:
        for entry in json.loads(pathlib.Path(args.previous).read_text())["releases"]:
            previous[entry["version"]] = entry

    if tag_time(current) is None:
        sys.exit(f"no tag v{current}; tag the release first, its time is the entry's issued_at")

    releases = []
    for version in sorted(sections, key=version_key, reverse=True):
        if version_key(version) > version_key(current):
            sys.exit(f"CHANGELOG has {version}, newer than the release being cut, {current}")
        date, body = sections[version]
        if version == current:
            artifacts = parse_checksums(pathlib.Path(args.checksums).read_text(), args.checksums)
        elif version in previous:
            artifacts = previous[version]["artifacts"]
        elif args.offline:
            print(f"left out {version}: not in --previous", file=sys.stderr)
            continue
        else:
            artifacts = fetch_checksums(version)
            if artifacts is None:
                print(f"left out {version}: no published checksums.sha256", file=sys.stderr)
                continue
        issued_at = tag_time(version)
        if issued_at is None:
            if version in previous:
                issued_at = previous[version]["issued_at"]
                print(f"{version}: no tag; issued_at kept from --previous", file=sys.stderr)
            else:
                issued_at = f"{date}T00:00:00Z"
                print(f"{version}: no tag; issued_at is its CHANGELOG date at midnight UTC", file=sys.stderr)
        releases.append(
            {
                "version": version,
                "issued_at": issued_at,
                "security": has_security(body),
                "summary": summary(body),
                "artifacts": dict(sorted(artifacts.items())),
            }
        )

    manifest = {
        "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "releases": releases,
    }
    json.dump(manifest, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
