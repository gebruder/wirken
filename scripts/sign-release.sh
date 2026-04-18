#!/bin/sh
# Sign a Wirken release's checksums.sha256 with the offline Ed25519 key.
#
# Usage:
#   WIRKEN_SIGNING_KEY=/secure/path/wirken-release-signing \
#       scripts/sign-release.sh vX.Y.Z
#
# Input:
#   - ./checksums.sha256 in the current directory (downloaded from the
#     draft release produced by the release workflow).
#   - WIRKEN_SIGNING_KEY env var pointing at the private key file.
#
# Output:
#   - ./checksums.sha256.sig next to the input. Upload to the release.
#
# Never commits the private key.

set -eu

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version-tag>" >&2
    exit 1
fi

VERSION="$1"

case "$VERSION" in
    v*) ;;
    *)
        echo "Error: version tag must start with 'v' (got: $VERSION)" >&2
        exit 1
        ;;
esac

if [ -z "${WIRKEN_SIGNING_KEY:-}" ]; then
    echo "Error: WIRKEN_SIGNING_KEY is not set." >&2
    echo "Point it at the offline private key, for example:" >&2
    echo "  WIRKEN_SIGNING_KEY=/secure/path/wirken-release-signing $0 $VERSION" >&2
    exit 1
fi

if [ ! -f "$WIRKEN_SIGNING_KEY" ]; then
    echo "Error: WIRKEN_SIGNING_KEY=${WIRKEN_SIGNING_KEY} does not exist." >&2
    exit 1
fi

# Guardrail: refuse to run if the private key is anywhere inside the
# working tree. This is a cheap check that catches the obvious mistake
# of dropping the key into the repo.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
KEY_ABS=$(cd "$(dirname "$WIRKEN_SIGNING_KEY")" && pwd)/$(basename "$WIRKEN_SIGNING_KEY")
case "$KEY_ABS" in
    "$REPO_ROOT"/*)
        echo "Error: private key is inside the repo tree (${KEY_ABS})." >&2
        echo "Move it to a location outside the working tree before signing." >&2
        exit 1
        ;;
esac

if [ ! -f checksums.sha256 ]; then
    echo "Error: ./checksums.sha256 not found." >&2
    echo "Download it from the draft release for ${VERSION} into the current directory." >&2
    exit 1
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "Error: ssh-keygen not found. OpenSSH 8.1+ is required." >&2
    exit 1
fi

echo "Signing checksums.sha256 for ${VERSION}"
ssh-keygen -Y sign \
    -n file \
    -f "$WIRKEN_SIGNING_KEY" \
    checksums.sha256

if [ ! -f checksums.sha256.sig ]; then
    echo "Error: ssh-keygen did not produce checksums.sha256.sig" >&2
    exit 1
fi

echo "Wrote checksums.sha256.sig"
echo "Next: upload checksums.sha256.sig to the draft release for ${VERSION}, then publish."
