# Release signing

> To cut a release, follow [release-process.md](release-process.md).
> This document is the crypto reference and the paste-ready manual
> verification snippet.

Every Wirken release is signed with an offline Ed25519 SSH key. The
installer fetches `checksums.sha256.sig` alongside `checksums.sha256`
and verifies both with `ssh-keygen -Y verify` before touching the
binary. Verification needs only OpenSSH 8.1+, which ships on every
supported platform. No new user-side dependency.

## Trust anchor

The public half of the release signing key is pinned in two places:

- `KEYS` at the repository root (OpenSSH allowed_signers format).
- `install.sh`, embedded as the `ALLOWED_SIGNERS` shell variable. The
  installer never fetches the key over the network.

`SECURITY.md` records the active fingerprint and cross-references this
document.

## What the signature covers

The signature is over `checksums.sha256`. The installer does two things:

1. Verifies the `ssh-keygen -Y` signature on `checksums.sha256` against
   the embedded `ALLOWED_SIGNERS`.
2. Computes the SHA-256 of the downloaded binary and matches it against
   the line for that binary in the signed checksums file.

Both must pass. A forged binary without a matching checksum fails
step 2. A forged `checksums.sha256` without the private key fails
step 1.

## Verify a release manually

Paste-ready. Does not trust `install.sh` or the current `main`. Pins
`KEYS` to a specific commit, so even a compromised `main` cannot shift
the trust anchor under you.

```bash
TAG=v0.7.4                                    # release to verify
BINARY=wirken-x86_64-unknown-linux-musl       # your platform
PINNED_COMMIT=<40-char-sha-of-an-audited-commit>

mkdir /tmp/wirken-verify && cd /tmp/wirken-verify

curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/$BINARY"
curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/checksums.sha256"
curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/checksums.sha256.sig"
curl -fsSL  "https://raw.githubusercontent.com/gebruder/wirken/$PINNED_COMMIT/KEYS" -o KEYS

# 1. Signature over checksums.sha256 must verify against pinned KEYS.
ssh-keygen -Y verify \
    -f KEYS \
    -I releases@gebruder.ottenheimer.app \
    -n file \
    -s checksums.sha256.sig \
    < checksums.sha256

# 2. Binary's SHA-256 must match the signed line.
grep " $BINARY\$" checksums.sha256 | sha256sum -c -
```

Expected output:

```
Good "file" signature for releases@gebruder.ottenheimer.app with ED25519 key SHA256:tzlfNHy4G1KIsmAR+cM3MGwVndheh2ak/usA6rw7SuE
wirken-x86_64-unknown-linux-musl: OK
```

Set `PINNED_COMMIT` to a commit you personally audited, the commit you
originally installed from, or the commit referenced in a SECURITY
advisory. Pulling `KEYS` from `main` is fine for casual verification;
pinning is for the threat model where `main` itself might be suspect.

Cross-check the fingerprint in the first line of output against the
one recorded in [SECURITY.md](../SECURITY.md) and in the `KEYS`
comments at the pinned commit. They must match.

## Escape hatch

The installer respects `WIRKEN_ALLOW_UNVERIFIED=1` for disaster
recovery only. It warns on stderr and proceeds. Never default it on.
Never recommend it in end-user docs.
