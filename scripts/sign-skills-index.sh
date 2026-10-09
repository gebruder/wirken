#!/bin/sh
# Sign the wirken-skills registry index under the offline registry root.
#
# Usage:
#   scripts/sign-skills-index.sh --root-key <registry-root seed> \
#       <index.json> <wirken-skills checkout>
#
# Input:
#   - --root-key: path to the registry root's Ed25519 private seed, 64 hex
#     characters, the same file `wirken skills sign --root-key` reads. The
#     project root's public half is skills/REGISTRY-ROOT.pub.
#   - <index.json>: the registry index, entries already signed by their
#     authors (`wirken skills sign`).
#   - <wirken-skills checkout>: a local checkout of the registry, so each
#     entry's SKILL.md is read without a network.
#   - WIRKEN_BIN (optional): the wirken binary to run; default `wirken`.
#
# For every entry this checks the entry's signature against the SKILL.md
# in the checkout, writes signer_key_delegation (the root's signature
# over the entry's signer_key) and adds sha256 where the entry has none.
# Any entry that fails the check refuses the whole index. The root's
# public key is printed to stderr, to compare with REGISTRY-ROOT.pub.
#
# Output:
#   - <index>.signed.json next to the input. Publish it as the index.
#
# Reads the root seed; never copies or commits it.

set -eu

if [ $# -ne 4 ] || [ "$1" != "--root-key" ]; then
    echo "Usage: $0 --root-key <registry-root seed> <index.json> <wirken-skills checkout>" >&2
    exit 1
fi

ROOT_KEY="$2"
INDEX="$3"
CHECKOUT="$4"

if [ ! -f "$ROOT_KEY" ]; then
    echo "Error: root seed $ROOT_KEY not found." >&2
    exit 1
fi

if [ ! -f "$INDEX" ]; then
    echo "Error: $INDEX not found." >&2
    exit 1
fi

if [ ! -d "$CHECKOUT" ]; then
    echo "Error: $CHECKOUT is not a directory." >&2
    exit 1
fi

OUT="${INDEX%.json}.signed.json"
TMP="$OUT.tmp"

if ! "${WIRKEN_BIN:-wirken}" skills sign-index \
    --root-key "$ROOT_KEY" \
    --skills-dir "$CHECKOUT" \
    "$INDEX" > "$TMP"; then
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$OUT"
echo "Wrote $OUT" >&2
