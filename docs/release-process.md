# Release process

Maintainer runbook. Follow top to bottom. The crypto reference and the
end-user verification snippet are in [signing.md](signing.md#release-signing).

> **Audience.** Maintainers who hold the offline release signing key.
> Contributors and users consume published releases.

## Prerequisites

- `gh` authenticated with write access to `gebruder/wirken`.
- The offline Ed25519 signing key stored outside the repo tree. Examples below
  assume `~/.ssh/wirken-release-signing`.
- OpenSSH 8.1+, `cargo`, `rustfmt`, `clippy`, `cargo-sweep`.
- `REPO` pointing at your checkout:

```bash
export REPO=~/code/wirken
gh auth status
ssh-keygen -lf "$REPO"/KEYS   # must match the fingerprint in SECURITY.md
```

## Version scheme

Semver on `X.Y.Z`, currently in the `1.x` series. Patch for bug fixes and
docs; minor for features, new adapters and breaking config changes. Every
workspace crate shares `workspace.package.version`; the git tag is
`v<version>`.

## Sequence

Replace `1.22.0` with the target version throughout.

### 1. Clean main, run pre-flight

Reclaim build-cache space first. The pre-flight compiles the whole workspace
twice over and a shared target directory only grows, since cargo never removes
artifacts a build no longer references. `--installed` removes artifacts from
toolchains that are no longer installed, which is the large reclaim after any
`rustup update`:

```bash
cargo sweep --installed --dry-run   # inspect, then drop --dry-run
cargo sweep --time 7                # optional, on top
```

```bash
git checkout main && git pull --ff-only && git status   # clean
cargo fmt --check
cargo clippy --workspace -- -D warnings
shellcheck install.sh
[ "$(sha256sum install.sh | awk '{print $1}')" = "$(grep -o '[0-9a-f]\{64\}' README.md | head -1)" ] \
    && echo "install.sh SHA matches README pin" \
    || { echo "install.sh SHA drift"; exit 1; }
cargo test --workspace
cargo deny check
./scripts/test-install.sh
gh api repos/gebruder/wirken/dependabot/alerts \
    --jq '.[] | select(.state == "open") | {num: .number, sev: .security_advisory.severity, pkg: .dependency.package.name, ghsa: .security_advisory.ghsa_id}'
gh api repos/gebruder/wirken/code-scanning/alerts \
    --jq '.[] | select(.state == "open") | {num: .number, sev: .rule.security_severity_level, rule: .rule.id, tool: .tool.name, path: .most_recent_instance.location.path}'
if secrets=$(gh api repos/gebruder/wirken/secret-scanning/alerts \
        --jq '.[] | select(.state == "open") | {num: .number, type: .secret_type_display_name}' 2>&1); then
    echo "${secrets:-no open secret-scanning alerts}"
else
    echo "UNVERIFIED: secret scanning not enabled, or this account cannot read it."
    echo "  Check with: gh api repos/gebruder/wirken --jq .permissions"
    echo "  Do not record this as clean."
fi
gh pr list --label dependencies --state open
```

The secret-scanning branch is spelled out because the API answers `404` both
when the feature is off and when the caller lacks permission to read it, so a
swallowed error is indistinguishable from a clean surface. On this repo it is
the permission case: the release account has push and triage, not admin. An
unverified surface is recorded as unverified, never as clean.

The `shellcheck` and SHA checks exist because a locally modified `install.sh`
that has not been pushed is not caught by the `installer-pin` CI workflow
until push, and a release tagged before push ships with a mismatched pin.
`cargo fmt`, `clippy` and `deny` are redundant with CI and serve as a local
fast-fail.

The security-surface queries and the dependency-PR list are non-empty by
default. Read every open row on every surface, and for each either fold the
fix into this release or defer it explicitly in the CHANGELOG. Patch and
non-0.x-minor dependabot bumps fold cleanly; 0.x-minor and major bumps take a
soak cycle.

**What gates a tag.** Three surfaces, not interchangeable:

- **Code-scanning findings (CodeQL).** A critical or high finding blocks until
  fixed or dismissed per the policy below.
- **Dependabot advisories.** Any open alert blocks.
- **`cargo deny check advisories`**, with `unsound` and `yanked` enforced.
  `deny.toml` sets `unsound = "all"`, `yanked = "deny"` and
  `[graph] all-features = true`; do not relax any of the three to get a green
  run. An advisory ignored there needs a written reason in the `ignore` entry
  naming the reachable path and what would make it revisitable.

**Scorecard findings are reviewed and recorded, not gating.** They score
repository posture (branch protection, review requirements, pinned actions),
not defects in the code or its dependencies. The one exception is
`VulnerabilitiesID`, whose body lists OSV ids: treat that list as a
cross-check against `cargo deny check advisories`, not as its own gate. The
two disagreeing is itself the finding. Scorecard reads `Cargo.lock` directly
and so reports advisories against crates that are locked but in no shipped
build graph; cargo-deny reads the build graph. When Scorecard names an id
cargo-deny does not, establish which is right before deciding anything. Both
failure directions have happened.

**Per-alert dismissal policy (code scanning).** Dismiss individually, never in
bulk and never by rule. Before dismissing, record for each alert: `file:line`,
what the flagged value actually is, what it is used for, and a verdict of
*not a secret* (domain string, test vector, public constant) or *real
finding*. A real finding is fixed in its own commit, not dismissed. Use the
narrowest reason GitHub offers and put the evidence in the dismissal comment,
including what makes the site test-only. A dismissal with no reason recorded
is indistinguishable later from one nobody read.

Do not suppress a rule repository-wide to clear test-path noise. CodeQL's
config cannot scope a single rule to a path: `query-filters` selects on query
metadata with no path dimension and `paths-ignore` selects on path with no
rule dimension, so the first would drop the rule from production `src` and the
second would drop every rule from the test paths. Per-alert dismissal is the
mechanism, and it persists while the fingerprint does.

### 2. Bump the workspace version

```toml
[workspace.package]
version = "1.22.0"
```

```bash
cargo update -w
```

Scan published docs for prose hardcoded to the previous series; skip for patch
bumps, and replace `1.21` with the prior minor:

```bash
git grep -nE "1\.21\.[0-9x]+|1\.21 " -- README.md SECURITY.md docs/ \
    | grep -vE 'docs/release-process\.md|docs/signing\.md|CHANGELOG\.md' \
    || true
```

Common offenders: the `SECURITY.md` supported-versions table, and the
`README.md` status section and gateway banner example. Stage edits alongside
the bump.

### 3. Commit, push, wait for green

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to 1.22.0"
git push
gh run watch -R gebruder/wirken
```

### 4. Tag

```bash
git tag -a v1.22.0 -m "v1.22.0"
git push origin v1.22.0
```

### 5. Watch the release build

Produces five binaries and `checksums.sha256`, and creates a **draft**
release.

```bash
gh run watch -R gebruder/wirken
```

This is the only job that compiles the whole workspace for Windows, and it
runs on a tag, so a Windows-only break would otherwise become visible only
after the version is public. The Windows Smoke `cargo check --workspace` step
converts that into a branch-time failure; it looks redundant with this job
precisely because it is the same compile moved earlier, and removing it puts
the first signal back on the tag.

### 6-9. Download, sign, self-verify, upload

Work in a scratch directory outside the repo tree; `sign-release.sh` refuses
to run if the private key is inside it.

```bash
mkdir -p /tmp/wirken-release && cd /tmp/wirken-release
gh release download v1.22.0 -R gebruder/wirken --pattern checksums.sha256
cat checksums.sha256   # five lines, one per binary

WIRKEN_SIGNING_KEY=~/.ssh/wirken-release-signing "$REPO"/scripts/sign-release.sh v1.22.0

ssh-keygen -Y verify -f "$REPO"/KEYS -I releases@gebruder.ottenheimer.app \
    -n file -s checksums.sha256.sig < checksums.sha256

gh release upload v1.22.0 checksums.sha256.sig -R gebruder/wirken
```

The verify must print
`Good "file" signature for releases@gebruder.ottenheimer.app`. If it fails, do
not upload; see [Recovery](#recovery-during-a-release).

### 10. Confirm assets

```bash
gh release view v1.22.0 -R gebruder/wirken
```

Five binaries, `checksums.sha256`, `checksums.sha256.sig`, and
`wirken.intoto.jsonl`. The provenance attaches on its own once the build
matrix completes and needs no maintainer action; it is generated by the
`provenance` job and is not signed with the offline key. If it is missing that
job failed, the draft is still publishable from the binaries plus signed
checksums, and the provenance can be regenerated by re-running the job.

### 11. Publish

The draft body opens with a "draft until signed" placeholder followed by the
generated notes. Strip the placeholder and flip to published in one call:

```bash
gh release view v1.22.0 -R gebruder/wirken --json body --jq .body \
    | sed '1,/^See `docs\/signing.md` for the full procedure\.$/d' \
    | sed '/./,$!d' > notes.md
head -1 notes.md   # must be "## What's Changed", or the compare link if no PRs
gh release edit v1.22.0 -R gebruder/wirken --draft=false --notes-file notes.md
```

### 12. Smoke test

Fresh shell, scratch install dir so your local binary survives:

```bash
WIRKEN_INSTALL_DIR=/tmp/wirken-smoke \
    sh -c 'curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh'
/tmp/wirken-smoke/wirken --version
```

The installer output must contain both
`Signature verified: releases@gebruder.ottenheimer.app` and
`Checksum verified: ...`. If either is missing the release is broken.

**Housekeeping.** Re-read `README.md` for any count or version that shifted.
If `crates/audit/src/session_log.rs` changed since the previous release, sync
the `wirken-siem` repo's compatibility table and field index in the same
sitting. Clean up `/tmp/wirken-release` and `/tmp/wirken-smoke`.

## Recovery during a release

**CI failed on the tag push.** The tag exists but no draft was created.

```bash
git tag -d v1.22.0
git push --delete origin v1.22.0
# fix on main, then restart from the tag step
```

**Signature verification failed.** The key you signed with does not match the
one pinned in the repo. Check `WIRKEN_SIGNING_KEY`. Do not upload an
unverified signature.

**Wrong signature uploaded.**

```bash
gh release delete-asset v1.22.0 checksums.sha256.sig -R gebruder/wirken --yes
gh release upload v1.22.0 checksums.sha256.sig -R gebruder/wirken
```

**A bad release is already published.** Do not delete it; users may have
downloaded. Publish a patch with the fix, then edit the bad release body to
prepend `**Broken, use vX.Y.Z.**`. If it is actively harmful (wrong binary,
leaked credential), delete the binaries and signature but leave the page with
an explanatory note, so the installer fails cleanly rather than silently
installing stale content.

## Key rotation

Three steps with a hard dependency order.

**1. Generate offline.** Record the fingerprint and issue date. Store the
private key outside the repo tree and do not overwrite the old one until step
3 publishes.

```bash
ssh-keygen -t ed25519 -C releases@gebruder.ottenheimer.app -f wirken-release-signing-NEW
ssh-keygen -lf wirken-release-signing-NEW.pub
```

**2. Swap the trust anchor in one commit.** Every file pinning the public key
updates together: `KEYS` gains the new key as active and marks the old with
`# Retired YYYY-MM-DD`, keeping it for verifying pre-rotation releases;
`install.sh` replaces `ALLOWED_SIGNERS` and its header fingerprint;
`README.md` bumps the pinned `install.sh` SHA-256; `SECURITY.md` updates the
active fingerprint and issue date.

**3. Tag and cut the next release with the new key immediately.**

**Ordering trap.** Between merging step 2 and publishing step 3, the installer
on `main` trusts the new key but the latest release is still signed with the
old one, so `curl | sh` exits 5 during that window. Merge the rotation commit
and tag the release in the same sitting. Users with a pinned older
`install.sh` are unaffected.

## Key loss or compromise

Same shape as rotation, with the differences below. Severity depends on
whether the old private key was lost (nobody has it) or compromised (someone
might).

Users with an already-installed binary are unaffected: the binary has no trust
path to the release key, and signature verification runs only at install time.
Users with a pinned older `install.sh` keep working against existing releases
as long as those signatures verify under the old public key. New installs from
`main` break until a new signed release is cut, and that is the only
user-visible cost.

1. **Generate a new key offline.**
2. **Swap the anchor in one commit**, with two differences from rotation. If
   **compromised**, remove the old key from `KEYS` entirely rather than
   retiring it, because any binary signed by it must no longer be treated as
   trustworthy, and edit each existing release to prepend
   `**Revoked, key compromised. Upgrade to vX.Y.Z.**`. If **only lost**, keep
   the old key with `# Retired YYYY-MM-DD, private key lost, no further
   signatures will be produced`, so old releases stay verifiable.
3. **Tag and publish a new signed release immediately.** On a compromise, bump
   a patch with no code changes purely to restore the trust path.
4. **If compromised, publish an advisory**: which fingerprint is revoked,
   which releases are affected, which version to upgrade to. Rotate any other
   credentials that shared storage with the compromised key.

There is no global revocation mechanism for `ssh-keygen` signatures. Trust
anchor swap plus a new signed release is the whole fix.
