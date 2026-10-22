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

Semver on `X.Y.Z`, currently in the `2.x` series. Patch for bug fixes and
docs; minor for features and new adapters; major for a change to the CLI, the
on-disk audit format or configuration that requires operator action, and never
for a crate API change alone. Every workspace crate shares
`workspace.package.version`; the git tag is `v<version>`.

The stability surface is the CLI outside `wirken lyrik` and the on-disk audit
format. `wirken lyrik` is outside it: its subcommands, flags, run output, and
the fields `findings.json` carries outside schema 1.1. A change there never
forces more than a minor bump. The findings schema is versioned on its own,
by tag (`schema-v1.1`), not by Wirken release; see
[lyrik.md](lyrik.md#findings-schema-11).

## Sequence

Replace `X.Y.Z` with the target version throughout, and `P.Q` with the
previous minor series.

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
scripts/check-names.sh
scripts/check-security-heading.py   # previous tag by default; or name it
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

The secret-scanning branch is spelled out because the API answers `404` in
three cases: the feature is off, the caller is not an admin of the
repository, or the caller is an admin whose token lacks the scope to read the
alerts. A swallowed error is indistinguishable from a clean surface. Tell the
three apart:

```bash
gh api repos/gebruder/wirken \
    --jq '{admin: .permissions.admin, secret_scanning: .security_and_analysis.secret_scanning.status}'
gh api -i repos/gebruder/wirken/secret-scanning/alerts 2>&1 \
    | grep -iE '^(x-oauth-scopes|x-accepted-oauth-scopes|x-accepted-github-permissions):'
```

`admin: false` is the permission case; on this repo the release account has
push and triage, not admin. `security_and_analysis` is returned only to an
admin: `secret_scanning: "disabled"` means the feature is off. An admin with
`"enabled"` and a `404` holds a token without the scope: the second command
shows the scopes the token has (`X-OAuth-Scopes`, a classic token) against
what the endpoint accepts (`X-Accepted-OAuth-Scopes`, or
`X-Accepted-GitHub-Permissions` for a fine-grained token). For a classic
token that is `repo` or `security_events` (`gh auth refresh -s
security_events`); for a fine-grained one, "Secret scanning alerts: read". An
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

A soak cycle is the operator's end-to-end run on main that exercises the
bumped crate's path, done before the tag. It is a run, not a wait: a feed
parser bump soaks on a real `wirken zirkel run` fetch. Where the crate has no
path an operator can run, the in-tree end-to-end tests that exercise it are
its soak, and the CHANGELOG entry for the bump names them.

**The release workflow enforces part of the gate.** Its first job, `gate`,
runs on the tag push before any build: `scripts/check-names.sh`,
`cargo deny check`, and open CodeQL alerts (any critical or high fails),
read with the workflow token's `security-events: read`. Every build job needs
it, so a failing gate builds nothing and creates no draft release. If the
token cannot read code scanning, the job prints it as `UNVERIFIED` and fails.
Dependabot alerts are not in the job: the workflow token cannot be granted
them, so they are checked only by the manual pre-flight above, run with the
maintainer's account. The pre-flight is also the local fast-fail, so a tag is
not pushed into a gate that will refuse it. To run the gate alone on a branch, without
the build matrix and without creating a release:

```bash
gh workflow run release.yml -R gebruder/wirken --ref <branch> -f gate_only=true
```

**What gates a tag.** `scripts/check-names.sh` and
`scripts/check-security-heading.py` passing, and three surfaces, not
interchangeable:

- **Code-scanning findings (CodeQL).** A critical or high finding blocks until
  fixed or dismissed per the policy below.
- **Dependabot advisories.** Any open alert blocks.
- **`cargo deny check advisories`**, with `unsound` and `yanked` enforced.
  `deny.toml` sets `unsound = "all"`, `yanked = "deny"` and
  `[graph] all-features = true`; do not relax any of the three to get a green
  run. An advisory ignored there needs a written reason in the `ignore` entry
  naming the reachable path and what would make it revisitable.

**`scripts/check-security-heading.py`** runs `cargo deny check advisories`
at the previous tag and at HEAD, and takes the advisory ids reported there
and not now: the advisories this release closes. When that set is not empty,
the release's CHANGELOG section (`## [Unreleased]` before the bump, the new
version's section after it) must carry a `### Security` heading, or the
check fails naming the ids. `build-releases-json.py` sets `security` in
`releases.json` from that heading alone, so a dependency bump that closes an
advisory without the heading ships a manifest that tells every installed
binary there is nothing security-related to install. A `### Security` heading
with no closed advisory is allowed: a fix in this repo's own code counts.

**`scripts/check-names.sh`** fails on an AI-tool name in any tracked file or
path, and on a co-author trailer naming the tool or its vendor, or a
"generated with" line, in any commit since the last tag. A file may carry a
model identifier only when `scripts/check-names.allow` lists its exact path
with a reason; that list is for functional identifiers in code and tests, and
a documentation path in it fails. The `Names` workflow runs the same check on
every push.

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

### 2. Bump the version

Five files change together in the release commit:

- `Cargo.toml`: the workspace version.

  ```toml
  [workspace.package]
  version = "X.Y.Z"
  ```

- `Cargo.lock` and `fuzz/Cargo.lock`: the workspace crates' versions, and
  nothing else.

  ```bash
  cargo update -w
  cargo update -w --manifest-path fuzz/Cargo.toml
  ```

- `README.md`: the gateway banner example, `wirken vX.Y.Z`.
- `CHANGELOG.md`: the entries under `## [Unreleased]` move under a new
  `## [X.Y.Z] - YYYY-MM-DD` heading, dated in UTC (`date -u +%F`), and
  `## [Unreleased]` stays, empty. The manifest takes each release's
  `issued_at` from its tag's time in UTC, not from this heading, so the two
  agree only when the heading is a UTC date.

Scan published docs for prose hardcoded to the previous series; skip for patch
bumps:

```bash
git grep -nE "P\.Q\.[0-9x]+|P\.Q " -- README.md SECURITY.md docs/ \
    | grep -vE 'docs/release-process\.md|docs/signing\.md|CHANGELOG\.md' \
    || true
```

Common offenders: the `SECURITY.md` supported-versions table, and the
`README.md` status section. Stage edits alongside the bump.

### 3. Commit, push, wait for green

```bash
git add Cargo.toml Cargo.lock fuzz/Cargo.lock README.md CHANGELOG.md
git commit -m "Release X.Y.Z"
git push origin main
gh run watch -R gebruder/wirken
```

### 4. Tag

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
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

### 6-9. Download, build the manifest, sign, self-verify, upload

Work in a scratch directory outside the repo tree; `sign-release.sh` refuses
to run if the private key is inside it.

```bash
mkdir -p /tmp/wirken-release && cd /tmp/wirken-release
gh release download vX.Y.Z -R gebruder/wirken --pattern checksums.sha256
cat checksums.sha256   # five lines, one per binary

# The last published manifest, whose entries are reused. Absent before
# the first release that carries one; the script then fetches each
# older release's checksums.sha256 instead.
gh release download -R gebruder/wirken --pattern releases.json --dir previous \
    || echo "no published releases.json yet"
PREV=; [ -f previous/releases.json ] && PREV="--previous previous/releases.json"
"$REPO"/scripts/build-releases-json.py --current vX.Y.Z \
    --checksums checksums.sha256 $PREV > releases.json

WIRKEN_SIGNING_KEY=~/.ssh/wirken-release-signing "$REPO"/scripts/sign-release.sh vX.Y.Z

ssh-keygen -Y verify -f "$REPO"/KEYS -I releases@gebruder.ottenheimer.app \
    -n file -s checksums.sha256.sig < checksums.sha256
ssh-keygen -Y verify -f "$REPO"/KEYS -I releases@gebruder.ottenheimer.app \
    -n wirken-release-manifest -s releases.json.sig < releases.json

gh release upload vX.Y.Z checksums.sha256.sig releases.json releases.json.sig \
    -R gebruder/wirken
```

Read `releases.json` before signing it, because `wirken update --check` tells
operators what it says. Check that the new entry's artifacts are the five lines
of `checksums.sha256`, that `security` is true exactly for the versions whose
CHANGELOG section has a `### Security` heading, and that each `summary` reads
well; edit a summary by hand if it does not. Versions the script left out are
named on stderr. Its top-level `issued_at` is the time it ran: every published
manifest must carry a later one than the last, because an install refuses a
manifest older than the newest it has verified.

Both verifies must print `Good "file" signature` and
`Good "wirken-release-manifest" signature` for
`releases@gebruder.ottenheimer.app`. If either fails, do not upload; see
[Recovery](#recovery-during-a-release).

### 10. Confirm assets

```bash
gh release view vX.Y.Z -R gebruder/wirken
```

Five binaries, `checksums.sha256`, `checksums.sha256.sig`, `releases.json`,
`releases.json.sig`, and `wirken.intoto.jsonl`. The provenance attaches on its own once the build
matrix completes and needs no maintainer action; it is generated by the
`provenance` job and is not signed with the offline key. If it is missing that
job failed, the draft is still publishable from the binaries plus signed
checksums, and the provenance can be regenerated by re-running the job.

### 11. Publish

The draft body is the generated notes and nothing else, so publishing is a
flip of the draft flag. Check the body first: it must say nothing about being
a draft, because whatever it says is what the published release says.

```bash
gh release view vX.Y.Z -R gebruder/wirken --json body --jq .body | grep -i draft \
    && echo "body mentions draft; read it before publishing"
gh release edit vX.Y.Z -R gebruder/wirken --draft=false
```

### 12. Smoke test

A real `wirken update` from the previous release to this one, on Linux, as
an operator would run it. Fresh shell, scratch install and data dirs so
your local binary and data survive. `P.Q.R` is the release this one
replaces.

```bash
mkdir -p /tmp/wirken-smoke && cd /tmp/wirken-smoke
curl -fsSL --proto =https --proto-redir =https -o wirken \
    https://github.com/gebruder/wirken/releases/download/vP.Q.R/wirken-x86_64-unknown-linux-musl
chmod +x wirken
./wirken --version                                             # P.Q.R
export WIRKEN_DATA_DIR=/tmp/wirken-smoke/data
./wirken update --check                                        # latest X.Y.Z
./wirken update                                                # type X.Y.Z
./wirken --version                                             # X.Y.Z
./wirken update --check                                        # Up to date.
./wirken update --rollback                                     # type rollback
./wirken --version                                             # P.Q.R
```

`update --check` from the previous binary must verify the published
`releases.json` against the key compiled into it, name `X.Y.Z` as latest,
and say `Security fixes in: X.Y.Z` exactly when this release's CHANGELOG
section has a `### Security` heading. `update` must show the download's
progress bar, then `sha256 matches; installing`, then `Installed wirken
X.Y.Z at ... checked against releases.json signed by <fingerprint>`, where
the fingerprint is the release key's. A refused signature, a fetch error, or
a sha256 mismatch means the manifest step (6-9) or the build is broken for
every installed binary. The rollback must restore `P.Q.R` byte for byte.

This replaces the old `install.sh` smoke test: `install.sh` is exercised by
`scripts/test-install.sh` in the pre-flight, and the update path is the one
only a published release can exercise.

**Housekeeping.** Re-read `README.md` for any count or version that shifted.
If `crates/audit/src/session_log.rs` changed since the previous release, sync
the `wirken-siem` repo's compatibility table and field index in the same
sitting. Clean up `/tmp/wirken-release` and `/tmp/wirken-smoke`, and unset
`WIRKEN_DATA_DIR`.

## Recovery during a release

**CI failed on the tag push.** The tag exists but no draft was created.

```bash
git tag -d vX.Y.Z
git push --delete origin vX.Y.Z
# fix on main, then restart from the tag step
```

**Signature verification failed.** The key you signed with does not match the
one pinned in the repo. Check `WIRKEN_SIGNING_KEY`. Do not upload an
unverified signature.

**Wrong signature uploaded.**

```bash
gh release delete-asset vX.Y.Z checksums.sha256.sig -R gebruder/wirken --yes
gh release upload vX.Y.Z checksums.sha256.sig -R gebruder/wirken
```

**A bad release is already published.** Do not delete it; users may have
downloaded. Publish a patch with the fix, then edit the bad release body to
prepend `**Broken, use vX.Y.Z.**`. If it is actively harmful (wrong binary,
leaked credential), delete the binaries and signature but leave the page with
an explanatory note, so the installer fails cleanly rather than silently
installing stale content.

## Key rotation

Since 2.3.0 every binary pins the release keys `wirken update` trusts:
`RELEASE_KEYS` in `crates/gateway/src/release_keys.rs`, with no runtime
override. An installed binary accepts a `releases.json` signed only by a key
in its own list. A rotation therefore ships the new key inside a release
signed with the old one first, and only then moves signing.

**1. Generate offline.** Record the fingerprint and issue date. Store the
private key outside the repo tree and do not overwrite the old one.

```bash
ssh-keygen -t ed25519 -C releases@gebruder.ottenheimer.app -f wirken-release-signing-NEW
ssh-keygen -lf wirken-release-signing-NEW.pub
```

**2. Ship a bridge release that pins both keys, signed with the old key.**
Every file pinning the public key gains the new key beside the old one, in
one commit:

- `crates/gateway/src/release_keys.rs`: `RELEASE_KEYS` lists both keys. Its
  tests hold the list equal to the keys in `KEYS` and in `install.sh`'s
  `ALLOWED_SIGNERS` and check the published fingerprint, so they change with
  it.
- `KEYS`: the new key beside the active one.
- `install.sh`: `ALLOWED_SIGNERS` and its header fingerprint list both keys;
  `README.md` bumps the pinned `install.sh` SHA-256.
- `SECURITY.md`: the new fingerprint and its issue date.

Cut and publish that release with the old key. A binary that updates to it
trusts both keys; `install.sh` on `main` accepts both, so `curl | sh` keeps
working throughout.

**3. Move signing to the new key in a later release.** Sign the next release
with the new key. In the same release, retire the old key: `KEYS` marks it
`# Retired YYYY-MM-DD` and keeps it for verifying earlier releases. Because
the `release_keys` tests hold `RELEASE_KEYS`, `KEYS` and `ALLOWED_SIGNERS` to
the same keys, a retired key stays in all three or leaves all three in one
commit.

**Ordering trap.** A release signed with the new key before the bridge
release is out cannot be checked by any installed binary: `wirken update`
refuses its manifest as signed by a key that is not pinned, and those
binaries cannot update. Their operators reinstall with `install.sh`. Publish
the bridge release, and give operators time to take it, before signing with
the new key.

## Key loss or compromise

Severity depends on whether the old private key was lost (nobody has it) or
compromised (someone might). In both cases there is no bridge release: one
cannot be signed with a lost key and must not be trusted from a compromised
one.

**`wirken update` stops working for installed binaries until they reinstall.**
Each installed binary pins only the old key, so it refuses every manifest
signed with the new one. Operators reinstall with `install.sh`, which installs
a binary that pins the new key; after that `wirken update` works again. On a
compromise, also tell operators not to run `wirken update` on a binary that
pins the compromised key: a manifest signed with that key verifies there.
Installed binaries otherwise keep running. Users with a pinned older
`install.sh` keep working against existing releases as long as those
signatures verify under the old public key. New installs from `main` break
until a new signed release is cut.

1. **Generate a new key offline.**
2. **Swap the anchor in one commit.** Every file pinning the public key gains
   the new key: `RELEASE_KEYS` in `crates/gateway/src/release_keys.rs` and its
   tests, `KEYS`, `install.sh`'s `ALLOWED_SIGNERS` and header fingerprint, the
   `README.md` pin of `install.sh`, and `SECURITY.md`. The `release_keys`
   tests hold `RELEASE_KEYS`, `KEYS` and `ALLOWED_SIGNERS` to the same keys,
   so the old key leaves all three or stays in all three. If
   **compromised**, remove it from all three rather than retiring it, because
   any binary or manifest signed by it must no longer be treated as
   trustworthy, and edit each existing release to prepend
   `**Revoked, key compromised. Upgrade to vX.Y.Z.**`. If **only lost**, keep
   it in all three, marked in `KEYS` with `# Retired YYYY-MM-DD, private key
   lost, no further signatures will be produced`: nobody can sign with it, and
   old releases stay verifiable.
3. **Tag and publish a new signed release immediately.** On a compromise, bump
   a patch with no code changes purely to restore the trust path. Its notes
   tell operators to reinstall with `install.sh`, since `wirken update` cannot
   reach it from a binary that pins only the old key.
4. **If compromised, publish an advisory**: which fingerprint is revoked,
   which releases are affected, which version to reinstall, and not to run
   `wirken update` on a binary that pins the revoked key. Rotate any other
   credentials that shared storage with the compromised key.

There is no global revocation mechanism for `ssh-keygen` signatures. Trust
anchor swap plus a new signed release, and a reinstall of every installed
binary, is the whole fix.
