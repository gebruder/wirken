#!/bin/sh
# Wirken installer
# Usage: curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh
#
# Exit codes:
#   1  generic failure (unsupported OS/arch, download failure, etc.)
#   2  could not fetch checksums.sha256
#   3  target binary not listed in checksums.sha256
#   4  neither sha256sum nor shasum is installed
#   5  signature missing, invalid, or ssh-keygen unavailable
#
# Escape hatch:
#   WIRKEN_ALLOW_UNVERIFIED=1  proceed despite checksum or signature failure.
#                              Warns once. Use only for disaster recovery.
#
# Never binds services to 0.0.0.0. Wirken binds local endpoints to 127.0.0.1.

set -eu

REPO="gebruder/wirken"
INSTALL_DIR="${WIRKEN_INSTALL_DIR:-$HOME/.local/bin}"

# --------------------------------------------------------------------------
# Allowed signers for ssh-keygen -Y verify. The public key is embedded in
# this script so verification does not depend on a network fetch of KEYS.
# REPLACE: paste the public key line from KEYS after offline key generation.
# --------------------------------------------------------------------------
ALLOWED_SIGNERS='releases@gebruder.ottenheimer.app ssh-ed25519 REPLACE_ME_WITH_PUBLIC_KEY'
SIGNER_IDENTITY="releases@gebruder.ottenheimer.app"

UNVERIFIED_WARNED=0

main() {
    detect_platform
    get_latest_version
    download_binary
    install_binary
    verify
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS_NAME="unknown-linux-musl" ;;
        Darwin) OS_NAME="apple-darwin" ;;
        *)
            echo "Error: unsupported OS: $OS" >&2
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH_NAME="x86_64" ;;
        aarch64|arm64)  ARCH_NAME="aarch64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac

    TARGET="${ARCH_NAME}-${OS_NAME}"
    echo "Platform: ${OS} ${ARCH} -> ${TARGET}"
}

get_latest_version() {
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$VERSION" ]; then
        echo "Error: could not determine latest version" >&2
        exit 1
    fi

    echo "Version: ${VERSION}"
}

# Handle a verification failure. Honors the WIRKEN_ALLOW_UNVERIFIED escape
# hatch. Exits with $1 unless the escape hatch is set, in which case it
# warns once and returns 0.
verification_failure() {
    code="$1"
    message="$2"

    if [ "${WIRKEN_ALLOW_UNVERIFIED:-0}" = "1" ]; then
        if [ "$UNVERIFIED_WARNED" -eq 0 ]; then
            echo "WARNING: WIRKEN_ALLOW_UNVERIFIED=1 set. Proceeding without verification." >&2
            echo "WARNING: You are running an unverified binary. Do not do this in production." >&2
            UNVERIFIED_WARNED=1
        fi
        echo "WARNING: ${message}" >&2
        return 0
    fi

    echo "Error: ${message}" >&2
    echo "Hint: set WIRKEN_ALLOW_UNVERIFIED=1 to override (not recommended)." >&2
    rm -rf "${TMPDIR:-/nonexistent}"
    exit "$code"
}

download_binary() {
    BINARY_NAME="wirken-${TARGET}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.sha256"
    SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.sha256.sig"

    TMPDIR=$(mktemp -d)
    TMPFILE="${TMPDIR}/wirken"
    CHECKSUM_FILE="${TMPDIR}/checksums.sha256"
    SIG_FILE="${TMPDIR}/checksums.sha256.sig"
    SIGNERS_FILE="${TMPDIR}/allowed_signers"

    echo "Downloading ${URL}"
    curl -fsSL -o "$TMPFILE" "$URL"

    verify_signature
    verify_checksum

    chmod +x "$TMPFILE"
}

# Fetch checksums.sha256.sig and verify with ssh-keygen -Y against the
# embedded allowed_signers entry. Exit 5 on failure unless the escape
# hatch is set.
verify_signature() {
    # Fetch signature first; an unavailable sig is a hard failure.
    if ! curl -fsSL -o "$SIG_FILE" "$SIG_URL"; then
        verification_failure 5 "could not fetch signature file ${SIG_URL}"
        return 0
    fi

    # We also need checksums.sha256 to verify the signature over.
    if ! curl -fsSL -o "$CHECKSUM_FILE" "$CHECKSUM_URL"; then
        verification_failure 2 "could not fetch ${CHECKSUM_URL}"
        return 0
    fi

    if ! command -v ssh-keygen >/dev/null 2>&1; then
        verification_failure 5 "ssh-keygen not found; install OpenSSH 8.1+ to verify release signatures"
        return 0
    fi

    # Reject the placeholder public key rather than silently accepting.
    case "$ALLOWED_SIGNERS" in
        *REPLACE_ME_WITH_PUBLIC_KEY*)
            verification_failure 5 "installer has placeholder signing key; cannot verify"
            return 0
            ;;
    esac

    printf '%s\n' "$ALLOWED_SIGNERS" > "$SIGNERS_FILE"

    if ! ssh-keygen -Y verify \
            -f "$SIGNERS_FILE" \
            -I "$SIGNER_IDENTITY" \
            -n file \
            -s "$SIG_FILE" \
            < "$CHECKSUM_FILE" >/dev/null 2>&1; then
        verification_failure 5 "signature on checksums.sha256 did not verify against release signing key"
        return 0
    fi

    echo "Signature verified: ${SIGNER_IDENTITY}"
}

# Verify the binary's SHA-256 against the signed checksums file. All
# failure paths are hard errors unless the escape hatch is set.
verify_checksum() {
    # Re-fetch only if verify_signature did not already.
    if [ ! -s "$CHECKSUM_FILE" ]; then
        if ! curl -fsSL -o "$CHECKSUM_FILE" "$CHECKSUM_URL"; then
            verification_failure 2 "could not fetch ${CHECKSUM_URL}"
            return 0
        fi
    fi

    EXPECTED=$(grep " ${BINARY_NAME}\$" "$CHECKSUM_FILE" | awk '{print $1}')
    if [ -z "$EXPECTED" ]; then
        verification_failure 3 "${BINARY_NAME} not listed in checksums.sha256"
        return 0
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMPFILE" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMPFILE" | awk '{print $1}')
    else
        verification_failure 4 "neither sha256sum nor shasum found; install coreutils or perl-shasum"
        return 0
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        verification_failure 1 "checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
        return 0
    fi

    echo "Checksum verified: ${EXPECTED}"
}

install_binary() {
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true

    EXISTING="${INSTALL_DIR}/wirken"
    if [ -x "$EXISTING" ]; then
        CURRENT=$("$EXISTING" --version 2>/dev/null | awk '{print $NF}')
        TAG_VERSION=$(echo "$VERSION" | sed 's/^v//')
        if [ "$CURRENT" = "$TAG_VERSION" ]; then
            echo "wirken ${CURRENT} is already installed."
            rm -rf "$TMPDIR"
            return
        fi
        echo "Upgrading wirken ${CURRENT} -> ${TAG_VERSION}"
    fi

    if [ ! -w "$INSTALL_DIR" ]; then
        echo "Error: ${INSTALL_DIR} is not writable." >&2
        echo "Set WIRKEN_INSTALL_DIR to a writable directory, or make ${INSTALL_DIR} writable." >&2
        rm -rf "$TMPDIR"
        exit 1
    fi

    mv "$TMPFILE" "${INSTALL_DIR}/wirken"
    echo "Installed to ${INSTALL_DIR}/wirken"

    rm -rf "$TMPDIR"

    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo ""
            echo "Add to your PATH:"
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            ;;
    esac
}

verify() {
    if command -v wirken >/dev/null 2>&1; then
        echo ""
        wirken --version
        echo ""
        echo "Run 'wirken setup' to get started."
    elif [ -x "${INSTALL_DIR}/wirken" ]; then
        echo ""
        "${INSTALL_DIR}/wirken" --version
        echo ""
        echo "Run 'wirken setup' to get started."
    fi
}

# Test seam: sourcing this script with WIRKEN_INSTALLER_SOURCE_ONLY=1
# defines all functions but does not run main. Used by scripts/test-install.sh.
if [ "${WIRKEN_INSTALLER_SOURCE_ONLY:-0}" != "1" ]; then
    main
fi
