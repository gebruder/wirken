# Release process

Step-by-step maintainer runbook. Follow top to bottom. Signing crypto
details live in [release-signing.md](release-signing.md).

> **Audience.** This document is for maintainers who hold the offline
> release signing key. Contributors and users do not run these steps;
> they consume published releases. To verify a release you downloaded,
> see the manual verification snippet in
> [release-signing.md](release-signing.md#verify-a-release-manually).

## Prerequisites (one-time)

- `gh` authenticated to github.com with write access to `gebruder/wirken`.
- Offline Ed25519 signing key stored outside the repo tree. Examples in
  this document assume `~/.ssh/wirken-release-signing`; substitute your
  actual path.
- OpenSSH 8.1+ (`ssh-keygen -Y` support).
- `cargo`, `rustfmt`, `clippy`.
- `cargo-sweep` (`cargo install cargo-sweep`), for the reclaim step below.
- `REPO` environment variable pointing at your local `wirken` checkout:
  ```bash
  export REPO=~/code/wirken   # wherever you cloned it
  ```
  Commands below reference `"$REPO"/scripts/sign-release.sh` and
  `"$REPO"/KEYS`.

Sanity check:

```bash
gh auth status
ssh-keygen -lf "$REPO"/KEYS   # must match the fingerprint in SECURITY.md
```

## Version scheme

Semver on `X.Y.Z`, currently in the `1.x` series:

- Bump `Z` (patch) for bug fixes and docs.
- Bump `Y` (minor) for features, new adapters, breaking config changes.

Every workspace crate shares `workspace.package.version` in the root
`Cargo.toml`. The git tag is `v<version>`.

## Release sequence

Run top to bottom. Replace `0.7.4` with the target version.

1. **Clean main, run pre-flight.** All must pass; fix on a branch and
   merge before tagging.

   Reclaim build-cache space first. The pre-flight below compiles the
   whole workspace twice over (`clippy --all-targets`, then `test`),
   and a target directory shared across projects only grows: cargo
   never removes artifacts a build no longer references.

   ```bash
   cargo sweep --installed --dry-run   # inspect, then drop --dry-run
   cargo sweep --time 7                # optional, on top of the above
   ```

   `--installed` removes artifacts built by toolchains that are no
   longer installed, which is the large reclaim after any `rustup
   update` and typically dwarfs `--time`. Run it whenever the
   toolchain has moved since the last release.

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
   gh api repos/gebruder/wirken/secret-scanning/alerts \
       --jq '.[] | select(.state == "open") | {num: .number, type: .secret_type_display_name}' 2>/dev/null || true
   gh pr list --label dependencies --state open
   ```

   The `shellcheck` and SHA checks exist because a locally modified
   `install.sh` that has not been pushed will not be caught by the
   `installer-pin` CI workflow until push, and a release tagged before
   push will ship with a mismatched pin. `cargo fmt`, `cargo clippy`,
   and `cargo deny check` are redundant with CI but serve as a local
   fast-fail.

   The security-surface queries and the dependency-PR list are
   non-empty by default. Read every open row on every surface. For
   each, fold the fix into this release or defer it explicitly in
   the CHANGELOG. Patch and non-0.x-minor dependabot bumps fold
   cleanly; 0.x-minor and major bumps take a soak cycle. Do not tag
   while a critical or high-severity advisory is open on any surface.

2. **Bump the workspace version.** Edit `Cargo.toml`:
   ```toml
   [workspace.package]
   version = "0.7.4"
   ```
   Regenerate the lockfile:
   ```bash
   cargo update -w
   ```
   Scan published docs for prose hardcoded to the previous series. Skip
   for patch bumps. Replace `0.6` with the prior minor.
   ```bash
   git grep -nE "0\.6\.[0-9x]+|0\.6 " -- README.md SECURITY.md docs/ \
       | grep -vE 'docs/release-process\.md|docs/release-signing\.md|CHANGELOG\.md' \
       || true
   ```
   Eyeball the hits and fix any prose still hardcoded to the prior
   series. Common offenders: `SECURITY.md` supported-versions table,
   `README.md` status section and gateway banner example. Stage edits
   alongside the bump.

3. **Commit and push the bump. Wait for CI green on main.**
   ```bash
   git add Cargo.toml Cargo.lock
   git commit -m "chore: bump version to 0.7.4"
   git push
   gh run watch -R gebruder/wirken   # wait for main CI
   ```

4. **Annotated tag, push.** CI triggers on the `v*` tag.
   ```bash
   git tag -a v0.7.4 -m "v0.7.4"
   git push origin v0.7.4
   ```

5. **Watch the release build.** Produces five binaries, `checksums.sha256`,
   and creates a **draft** release.
   ```bash
   gh run watch -R gebruder/wirken
   ```

   This job is the only one that compiles the whole workspace for
   Windows, and it runs on a tag, so a Windows-only break used to
   become visible only after the version was public. The Windows Smoke
   `cargo check --workspace` step exists to convert that into a
   branch-time failure; it looks redundant with this job precisely
   because it is the same compile moved earlier, and removing it puts
   the first signal back on the tag.

6. **Download `checksums.sha256` from the draft.** Work in a scratch
   directory outside the repo tree (`scripts/sign-release.sh` refuses to
   run if the private key is inside the tree).
   ```bash
   mkdir -p /tmp/wirken-release && cd /tmp/wirken-release
   gh release download v0.7.4 -R gebruder/wirken --pattern checksums.sha256
   cat checksums.sha256   # sanity: five lines, one per binary
   ```

7. **Sign.** You will be prompted for the passphrase.
   ```bash
   WIRKEN_SIGNING_KEY=~/.ssh/wirken-release-signing \
       "$REPO"/scripts/sign-release.sh v0.7.4
   ```

8. **Self-verify before upload.** Must print `Good "file" signature for
   releases@gebruder.ottenheimer.app`. If it fails, do not upload. See
   [Recovery](#recovery-during-a-release).
   ```bash
   ssh-keygen -Y verify \
       -f "$REPO"/KEYS \
       -I releases@gebruder.ottenheimer.app \
       -n file \
       -s checksums.sha256.sig \
       < checksums.sha256
   ```

9. **Upload the signature to the draft.**
   ```bash
   gh release upload v0.7.4 checksums.sha256.sig -R gebruder/wirken
   ```

10. **Confirm all assets are attached.** You should see the five
    binaries, `checksums.sha256`, `checksums.sha256.sig`, and
    `wirken.intoto.jsonl` (the SLSA provenance; generated automatically
    by the `provenance` workflow job, not signed with the offline key).
    ```bash
    gh release view v0.7.4 -R gebruder/wirken
    ```
    The provenance attaches on its own once the build matrix completes;
    no maintainer action is needed for it. If it is missing, the
    `provenance` job failed — the draft is still publishable from the
    binaries + signed checksums, and the provenance can be regenerated
    by re-running that job. See [release-signing.md](release-signing.md#build-provenance-slsa).

11. **Publish.** Flip from draft to published.
    ```bash
    gh release edit v0.7.4 -R gebruder/wirken --draft=false
    ```

12. **Smoke test.** On a fresh shell, with a scratch install dir so you
    do not overwrite your local binary.
    ```bash
    WIRKEN_INSTALL_DIR=/tmp/wirken-smoke \
        sh -c 'curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh'
    /tmp/wirken-smoke/wirken --version
    ```
    The installer output must contain both
    `Signature verified: releases@gebruder.ottenheimer.app` and
    `Checksum verified: ...`. If either is missing the release is
    broken. Go to [Recovery](#recovery-during-a-release).

Post-release housekeeping: update the README Status section counts if
any shifted (adapters, providers, skills, tests). If
`crates/audit/src/session_log.rs` changed since the previous release,
sync the `wirken-siem` repo's compatibility table and field index in
the same sitting. Clean up `/tmp/wirken-release` and
`/tmp/wirken-smoke`.

## Recovery during a release

**CI failed on the tag push.** The tag exists on GitHub but no draft
was created.
```bash
git tag -d v0.7.4
git push --delete origin v0.7.4
# fix on main, then restart from step 4
```

**Signature verification failed in step 8.** The key you signed with
does not match the key pinned in the repo. Check `WIRKEN_SIGNING_KEY`
points at the right file. Do not upload an unverified signature.

**You uploaded the wrong signature.**
```bash
gh release delete-asset v0.7.4 checksums.sha256.sig -R gebruder/wirken --yes
gh release upload v0.7.4 checksums.sha256.sig -R gebruder/wirken
```

**You already published a bad release.** Do not delete it; users may
have already downloaded. Publish a patch (`v0.7.5`) with the fix, then
edit the bad release body to prepend `**Broken — use v0.7.5.**`. If
the bad release is actively harmful (wrong binary, leaked credential),
delete the binaries and signature from the release but leave the page
with an explanatory note so the installer fails cleanly rather than
silently installing stale content.

## Key rotation

Three-step dependency. Do not reorder.

1. **Generate the new key offline.** Record the fingerprint and issue
   date.
   ```bash
   ssh-keygen -t ed25519 -C releases@gebruder.ottenheimer.app \
       -f wirken-release-signing-NEW
   ssh-keygen -lf wirken-release-signing-NEW.pub
   ```
   Store the private key outside the repo tree. Do not overwrite the
   old private key until step 3 publishes.

2. **In one commit on main, swap the trust anchor.** Every file that
   pins the public key updates together:
   - `KEYS`: add the new key as the active entry; mark the old key
     with a `# Retired YYYY-MM-DD` comment (keep it in the file for
     verifying pre-rotation releases).
   - `install.sh`: replace `ALLOWED_SIGNERS` with the new public key
     line. Update the `# Current active key` header fingerprint.
   - `README.md`: bump the pinned install.sh SHA-256 (the value is
     whatever `sha256sum install.sh` prints after the edit).
   - `SECURITY.md`: update the active fingerprint and issue date.

   Merge the commit.

3. **Immediately tag and cut the next release with the new key.** Run
   [the release sequence](#release-sequence) from step 4 onward using
   the new private key for signing.

**Ordering trap.** Between merging step 2 and publishing step 3, the
installer on `main` trusts the new key but the latest release is still
signed with the old key. `curl | sh` from the install URL exits 5
during that window. Keep the window as short as possible: merge the
rotation commit and tag the release in the same sitting, not days
apart. Users with a pinned older `install.sh` are unaffected.

## Key loss or compromise recovery

Same shape as rotation, but with the caveats below. Severity depends
on whether the old private key was lost (no one has it) or compromised
(someone else might).

**Users with an already-installed binary are unaffected.** The binary
they run has no trust path to the release key. Signature verification
only runs at install time.

**Users with a pinned older `install.sh` keep working** against
existing releases as long as those releases' signatures still verify
under the old public key. The old public key stays in their pinned
`install.sh` either way.

**New installs from `main` break until you cut a new signed release.**
That is the only user-visible cost. Worst case is a few hours to a few
days of broken `curl | sh`, not catastrophic.

Procedure:

1. **Generate a new key offline.** Same command as rotation step 1.

2. **Swap the trust anchor in one commit.** Same edits as rotation
   step 2 with two differences:
   - **If compromised (not just lost):** remove the old key from `KEYS`
     entirely instead of retiring it. Any binary signed by the
     compromised key must no longer be treated as trustworthy.
     Explicitly yank the old releases: edit each existing release to
     prepend `**Revoked — key compromised. Upgrade to vX.Y.Z.**`.
   - **If only lost:** keep the old key in `KEYS` with
     `# Retired YYYY-MM-DD — private key lost, no further signatures
     will be produced`. Old releases stay verifiable.

3. **Tag and publish a new signed release immediately.** If the loss
   is an emergency (compromise), bump a patch version with no code
   changes just to get a release signed under the new key out to
   `main`-following users. The release's only purpose is to restore
   the trust path.

4. **If compromised, publish an advisory.** Post to
   `security@gebruder.ottenheimer.app` and a GitHub security advisory:
   which key fingerprint is revoked, which releases are affected, and
   which version to upgrade to. Rotate any other credentials that
   shared the same storage as the compromised private key.

No recovery option short of this: there is no global revocation
mechanism for ssh-keygen signatures. Trust anchor swap + new signed
release is the whole fix.
