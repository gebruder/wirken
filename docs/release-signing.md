# Release signing

Every Wirken release is signed with an offline Ed25519 SSH key. The
installer fetches `checksums.sha256.sig` alongside `checksums.sha256` and
verifies both with `ssh-keygen -Y verify` before touching the binary.

Verification needs only OpenSSH 8.1 or newer, which ships with every
supported Linux distribution and macOS release. No new user-side
dependency.

## Trust anchor

The public half of the signing key is pinned in two places:

- `KEYS` at the repository root, for manual verification.
- `install.sh`, embedded as an `ALLOWED_SIGNERS` shell variable. The
  installer never fetches the key over the network.

`SECURITY.md` records the fingerprint and cross-references this document.

## Generate the offline key

Do this on an air-gapped machine, or at minimum on a machine that never
uploads the private key anywhere.

```
ssh-keygen -t ed25519 -C releases@gebruder.ottenheimer.app -f wirken-release-signing
```

Record the fingerprint. This value goes into `KEYS` and `SECURITY.md`:

```
ssh-keygen -lf wirken-release-signing.pub
```

Paste the single-line contents of `wirken-release-signing.pub` into the
placeholder slot in `KEYS` and into the `ALLOWED_SIGNERS` variable in
`install.sh`. Do not commit `wirken-release-signing` (the private key).
Store it encrypted (YubiKey, hardware token, or an offline volume).

Update `SECURITY.md` with the fingerprint and issue date.

## Sign a release

```
WIRKEN_SIGNING_KEY=/secure/path/to/wirken-release-signing \
    scripts/sign-release.sh vX.Y.Z
```

`sign-release.sh` reads the local `checksums.sha256` (produced by the
release workflow and downloaded from the draft release) and writes
`checksums.sha256.sig` next to it. Upload the signature to the draft
release before publishing.

Under the hood it runs:

```
ssh-keygen -Y sign \
    -n file \
    -f "$WIRKEN_SIGNING_KEY" \
    checksums.sha256
```

CI never holds the private key. The release workflow builds artifacts,
computes checksums, and uploads everything to a draft release. Signing
happens on the maintainer's machine. The signature is attached to the
draft, and the draft is then published.

## Verify a release

```
curl -fsSLO https://github.com/gebruder/wirken/releases/download/vX.Y.Z/checksums.sha256
curl -fsSLO https://github.com/gebruder/wirken/releases/download/vX.Y.Z/checksums.sha256.sig
curl -fsSLO https://raw.githubusercontent.com/gebruder/wirken/main/KEYS

ssh-keygen -Y verify \
    -f KEYS \
    -I releases@gebruder.ottenheimer.app \
    -n file \
    -s checksums.sha256.sig \
    < checksums.sha256
```

`Good "file" signature for releases@gebruder.ottenheimer.app` means the
checksums file was signed by the current release key.

## Rotate the key

Rotation happens on schedule (annually) and on any suspected compromise.

1. Generate a new key on the offline machine.
2. Append the new public key to `KEYS` with a fresh issue date.
3. Leave the old key in `KEYS` for a deprecation window so pre-rotation
   releases still verify. Add a `# Retired YYYY-MM-DD` comment.
4. Update `ALLOWED_SIGNERS` in `install.sh` to the new key. The installer
   only trusts one active key at a time.
5. Update the active fingerprint in `SECURITY.md`.
6. Sign the next release with the new key.
7. Destroy or archive the retired private key.

Do not reuse the retired `releases@gebruder.ottenheimer.app` identity for
other purposes.

## What the signature covers

The signature is over `checksums.sha256`. The installer:

1. Verifies the `ssh-keygen -Y` signature on `checksums.sha256`.
2. Computes the SHA-256 of the downloaded binary.
3. Matches it against the line for that binary in the signed checksums.

Both steps must pass. A forged binary without a matching checksum fails
step 2. A forged checksums file without the private key fails step 1.

## Escape hatch

The installer respects `WIRKEN_ALLOW_UNVERIFIED=1` for disaster recovery,
for example when the signing key has been rotated out and the old
checksums file is being replayed. The variable warns on stderr, proceeds,
and is never the default. Never recommend it in end-user docs.
