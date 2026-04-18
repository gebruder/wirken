# Release process

Step-by-step runbook for cutting a Wirken release. Follow top to bottom.
Signing mechanics live in [release-signing.md](release-signing.md); this
document covers the surrounding workflow.

## Prerequisites (one-time setup)

- `gh` CLI authenticated to github.com with access to `gebruder/wirken`.
- Offline Ed25519 signing key at `~/.ssh/wirken-release-signing` (or
  wherever, kept outside the repo tree).
- `ssh-keygen` (OpenSSH 8.1 or newer).
- `cargo`, `rustfmt`, `clippy`.

Verify:

```bash
gh auth status
ssh-keygen -Y verify -f KEYS -I releases@gebruder.ottenheimer.app \
    -n file -s /dev/null < /dev/null 2>&1 | head -1
```

The second command will fail (no signature to verify), but it confirms
`KEYS` parses and `ssh-keygen` is present.

## Decide the version

Semver. `0.X.Y`:

- Bump `Y` for bug fixes and docs.
- Bump `X` for new features, new adapters, breaking config changes.
- `1.0` when the type-level channel separation is threaded through the
  production message path.

Every workspace crate shares one version via `workspace.package.version`
in the root `Cargo.toml`. The git tag is `v<version>` (e.g. `v0.7.4`).

## Pre-flight checks on main

From a clean checkout of `main`:

```bash
git checkout main
git pull --ff-only
git status   # must be clean

cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
./scripts/test-install.sh
```

All four must pass. If any fail, fix on a branch, merge, and restart
from this step.

## Bump the version

Edit `Cargo.toml`:

```toml
[workspace.package]
version = "0.7.4"
```

Regenerate the lockfile:

```bash
cargo update -w
```

Commit:

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to 0.7.4"
git push
```

CI should stay green on main before tagging. Wait for it.

## Tag and push

Annotated tag, version prefixed with `v`:

```bash
git tag -a v0.7.4 -m "v0.7.4"
git push origin v0.7.4
```

This triggers `.github/workflows/release.yml`. The workflow:

1. Builds `wirken-x86_64-unknown-linux-musl`, `wirken-aarch64-unknown-linux-musl`,
   `wirken-x86_64-apple-darwin`, `wirken-aarch64-apple-darwin`.
2. Computes `checksums.sha256` over all four binaries.
3. Creates a **draft** release with the binaries and `checksums.sha256`
   attached. The release body tells you exactly what to do next.

Watch the run:

```bash
gh run watch -R gebruder/wirken
```

If the build fails, see [Recovery](#recovery).

## Sign checksums.sha256

Once the draft exists, download the checksums to a scratch directory
outside the repo (`scripts/sign-release.sh` refuses to run if the
private key is inside the repo tree, and keeping signing work out of
the tree is cleaner):

```bash
mkdir -p /tmp/wirken-release && cd /tmp/wirken-release
gh release download v0.7.4 -R gebruder/wirken --pattern checksums.sha256
cat checksums.sha256   # sanity-check: four lines, one per binary
```

Sign:

```bash
WIRKEN_SIGNING_KEY=~/.ssh/wirken-release-signing \
    ~/code/wirken/scripts/sign-release.sh v0.7.4
```

You will be prompted for the key passphrase. Output:

```
Wrote checksums.sha256.sig
```

Self-verify before uploading:

```bash
ssh-keygen -Y verify \
    -f ~/code/wirken/KEYS \
    -I releases@gebruder.ottenheimer.app \
    -n file \
    -s checksums.sha256.sig \
    < checksums.sha256
```

Expected: `Good "file" signature for releases@gebruder.ottenheimer.app`.

If that fails, do not upload. See [Recovery](#recovery).

## Upload signature and publish

Upload the signature to the draft:

```bash
gh release upload v0.7.4 checksums.sha256.sig -R gebruder/wirken
```

Confirm all expected assets are attached:

```bash
gh release view v0.7.4 -R gebruder/wirken
```

You should see:

- `wirken-x86_64-unknown-linux-musl`
- `wirken-aarch64-unknown-linux-musl`
- `wirken-x86_64-apple-darwin`
- `wirken-aarch64-apple-darwin`
- `checksums.sha256`
- `checksums.sha256.sig`

Publish (flip from draft to published):

```bash
gh release edit v0.7.4 -R gebruder/wirken --draft=false
```

## Smoke-test the published release

On a clean shell, with a scratch `WIRKEN_INSTALL_DIR` so you do not
overwrite your local binary:

```bash
WIRKEN_INSTALL_DIR=/tmp/wirken-smoke \
    sh -c 'curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh'
/tmp/wirken-smoke/wirken --version
```

Expected lines in the installer output:

```
Signature verified: releases@gebruder.ottenheimer.app
Checksum verified: ...
Installed to /tmp/wirken-smoke/wirken
```

If either verification line is missing, the release is broken even if
the binary ran. Go to [Recovery](#recovery).

Clean up:

```bash
rm -rf /tmp/wirken-smoke /tmp/wirken-release
```

## Post-release

- Update `README.md` Status section counts if the numbers shifted
  (adapters, providers, skills, test count).
- If this release adds a new channel adapter, update `docs/channels.md`
  and the README opening paragraph.
- Close milestone / issues tagged for this version.

## Recovery

**CI failed on the tag push.** The tag exists on GitHub but no draft
release was created. Fix the build, then delete and retag:

```bash
git tag -d v0.7.4
git push --delete origin v0.7.4
# fix, commit, push main
git tag -a v0.7.4 -m "v0.7.4"
git push origin v0.7.4
```

**You signed but verification failed against `KEYS`.** The signing key
you used does not match the key pinned in the repo. Check
`WIRKEN_SIGNING_KEY` points at the right file and re-run signing. Do
not publish an unverified signature.

**You uploaded the wrong signature.** Delete the asset and re-upload:

```bash
gh release delete-asset v0.7.4 checksums.sha256.sig -R gebruder/wirken --yes
gh release upload v0.7.4 checksums.sha256.sig -R gebruder/wirken
```

**You already published a bad release.** Do not delete it; users may
already have downloaded it. Instead:

1. Publish a patch version (`v0.7.5`) with the fix.
2. On the bad release, edit the body to add a `**Broken — use
   v0.7.5.**` notice at the top.
3. If the bad release is actively harmful (wrong binary, corrupt
   signature, credential leak), delete the binaries and signature from
   the release but leave the release page with an explanatory note, so
   users hitting the installer see a clean failure rather than a silent
   broken install.

**Private key compromise suspected.** Follow the key rotation
procedure in [release-signing.md](release-signing.md#rotate-the-key),
then re-sign and publish the next release with the new key. Alert via
`security@gebruder.ottenheimer.app`.
