#!/bin/sh
# shellcheck disable=SC2034,SC2030,SC2031
# Acceptance tests for install.sh exit codes.
#
# Sources install.sh with WIRKEN_INSTALLER_SOURCE_ONLY=1 so the verification
# functions can be called directly without running the full installer.
# SC2034 is disabled because the subshells assign variables that are read
# from inside install.sh's sourced functions, which shellcheck cannot follow.
# SC2030/SC2031 are disabled because each test is intentionally scoped to
# its own subshell; variable mutations do not leak to subsequent tests.

set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT" || exit 1

# Subshells below assign variables that are read from inside install.sh's
# sourced functions. shellcheck does not follow the dynamic reference so
# we silence the unused-variable warning for the whole file.
# shellcheck disable=SC2034

FAILED=0

check() {
    name="$1"
    expected="$2"
    actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "PASS: $name (exit $actual)"
    else
        echo "FAIL: $name (expected $expected, got $actual)"
        FAILED=$((FAILED + 1))
    fi
}

# ---------------------------------------------------------------------------
# Exit 3: binary not listed in checksums.sha256
# ---------------------------------------------------------------------------
tmp=$(mktemp -d)
(
    WIRKEN_INSTALLER_SOURCE_ONLY=1
    export WIRKEN_INSTALLER_SOURCE_ONLY
    # shellcheck disable=SC1091
    . ./install.sh
    TMPDIR="$tmp"
    CHECKSUM_FILE="$tmp/checksums.sha256"
    TMPFILE="$tmp/wirken"
    BINARY_NAME="wirken-x86_64-unknown-linux-musl"
    CHECKSUM_URL="file:///dev/null"
    echo "0000000000000000000000000000000000000000000000000000000000000000  wirken-some-other-arch" > "$CHECKSUM_FILE"
    echo "dummy" > "$TMPFILE"
    verify_checksum
)
check "missing binary in checksums -> exit 3" 3 $?
rm -rf "$tmp"

# ---------------------------------------------------------------------------
# Exit 2: checksums URL cannot be fetched
# ---------------------------------------------------------------------------
tmp=$(mktemp -d)
(
    WIRKEN_INSTALLER_SOURCE_ONLY=1
    export WIRKEN_INSTALLER_SOURCE_ONLY
    # shellcheck disable=SC1091
    . ./install.sh
    TMPDIR="$tmp"
    CHECKSUM_FILE="$tmp/missing-checksums"
    TMPFILE="$tmp/wirken"
    BINARY_NAME="wirken-x86_64-unknown-linux-musl"
    # 127.0.0.1:1 is reserved TCPMUX and unroutable in practice; curl -f returns
    # non-zero. The file does not exist, so verify_checksum will try to fetch.
    CHECKSUM_URL="http://127.0.0.1:1/blocked"
    echo "dummy" > "$TMPFILE"
    verify_checksum
)
check "blocked checksums URL -> exit 2" 2 $?
rm -rf "$tmp"

# ---------------------------------------------------------------------------
# Exit 5: signature file cannot be fetched
# ---------------------------------------------------------------------------
tmp=$(mktemp -d)
(
    WIRKEN_INSTALLER_SOURCE_ONLY=1
    export WIRKEN_INSTALLER_SOURCE_ONLY
    # shellcheck disable=SC1091
    . ./install.sh
    TMPDIR="$tmp"
    CHECKSUM_FILE="$tmp/checksums.sha256"
    SIG_FILE="$tmp/checksums.sha256.sig"
    SIGNERS_FILE="$tmp/allowed_signers"
    TMPFILE="$tmp/wirken"
    BINARY_NAME="wirken-x86_64-unknown-linux-musl"
    CHECKSUM_URL="http://127.0.0.1:1/blocked"
    SIG_URL="http://127.0.0.1:1/blocked"
    echo "dummy" > "$TMPFILE"
    verify_signature
)
check "blocked signature URL -> exit 5" 5 $?
rm -rf "$tmp"

# ---------------------------------------------------------------------------
# Escape hatch: WIRKEN_ALLOW_UNVERIFIED=1 turns a hard fail into a warning.
# ---------------------------------------------------------------------------
tmp=$(mktemp -d)
(
    WIRKEN_INSTALLER_SOURCE_ONLY=1
    WIRKEN_ALLOW_UNVERIFIED=1
    export WIRKEN_INSTALLER_SOURCE_ONLY WIRKEN_ALLOW_UNVERIFIED
    # shellcheck disable=SC1091
    . ./install.sh
    TMPDIR="$tmp"
    CHECKSUM_FILE="$tmp/checksums.sha256"
    TMPFILE="$tmp/wirken"
    BINARY_NAME="wirken-x86_64-unknown-linux-musl"
    CHECKSUM_URL="file:///dev/null"
    echo "0000  wirken-other" > "$CHECKSUM_FILE"
    echo "dummy" > "$TMPFILE"
    verify_checksum
) >/dev/null 2>&1
check "escape hatch masks exit 3" 0 $?
rm -rf "$tmp"

# ---------------------------------------------------------------------------
# verify() reports the binary the installer just wrote to INSTALL_DIR, not
# whatever wirken resolves to on PATH. An older wirken on PATH would
# otherwise make a successful install look like a no-op.
# ---------------------------------------------------------------------------
install_dir=$(mktemp -d)
path_dir=$(mktemp -d)

# Older wirken on PATH.
cat > "$path_dir/wirken" <<'STUB'
#!/bin/sh
echo "wirken 0.0.1-stub"
STUB
chmod +x "$path_dir/wirken"

# Freshly installed wirken in INSTALL_DIR. verify() should report this one.
cat > "$install_dir/wirken" <<'STUB'
#!/bin/sh
echo "wirken 0.7.4-installed"
STUB
chmod +x "$install_dir/wirken"

output=$(
    WIRKEN_INSTALLER_SOURCE_ONLY=1
    PATH="$path_dir:$PATH"
    export WIRKEN_INSTALLER_SOURCE_ONLY PATH
    # shellcheck disable=SC1091
    . ./install.sh
    INSTALL_DIR="$install_dir"
    verify 2>&1
)

if echo "$output" | grep -q "0.7.4-installed" \
        && ! echo "$output" | grep -q "0.0.1-stub"; then
    echo "PASS: verify() reports installed binary, not PATH wirken"
elif echo "$output" | grep -q "0.0.1-stub"; then
    echo "FAIL: verify() reported PATH wirken (0.0.1-stub) instead of installed"
    FAILED=$((FAILED + 1))
else
    echo "FAIL: verify() output matched neither expected version:"
    printf '  %s\n' "$output"
    FAILED=$((FAILED + 1))
fi
rm -rf "$install_dir" "$path_dir"

if [ "$FAILED" -gt 0 ]; then
    echo "$FAILED test(s) failed."
    exit 1
fi
echo "All install.sh exit-code tests passed."
