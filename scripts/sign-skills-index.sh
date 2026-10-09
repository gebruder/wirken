#!/bin/sh
# Sign the wirken-skills registry index under the offline registry root.
#
# Usage:
#   WIRKEN_REGISTRY_ROOT_KEY=/secure/path/registry-root.seed \
#       scripts/sign-skills-index.sh <index.json> <wirken-skills checkout>
#
# Input:
#   - <index.json>: the registry index, entries already signed by their
#     authors (`wirken skills sign`).
#   - <wirken-skills checkout>: a local checkout of the registry, so each
#     entry's SKILL.md is read without a network.
#   - WIRKEN_REGISTRY_ROOT_KEY: path to the root's Ed25519 private seed,
#     64 hex characters, whose public half is
#     crates/gateway/src/wirken-registry-pubkey.pub.
#   - WIRKEN_BIN (optional): the wirken binary to run; default `wirken`.
#
# For every entry this checks the entry's signature against the SKILL.md
# in the checkout, writes signer_key_delegation (the root's signature
# over the entry's signer_key) and adds sha256 where the entry has none.
# Any entry that fails the check refuses the whole index.
#
# Output:
#   - <index>.signed.json next to the input. Publish it as the index.
#
# Reads the root seed; never copies or commits it.

set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <index.json> <wirken-skills checkout>" >&2
    exit 1
fi

INDEX="$1"
CHECKOUT="$2"

if [ -z "${WIRKEN_REGISTRY_ROOT_KEY:-}" ]; then
    echo "Error: WIRKEN_REGISTRY_ROOT_KEY is not set." >&2
    echo "Point it at the offline registry root seed, for example:" >&2
    echo "  WIRKEN_REGISTRY_ROOT_KEY=/secure/path/registry-root.seed $0 $INDEX $CHECKOUT" >&2
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
    --root-key "$WIRKEN_REGISTRY_ROOT_KEY" \
    --skills-dir "$CHECKOUT" \
    "$INDEX" > "$TMP"; then
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$OUT"
echo "Wrote $OUT" >&2
