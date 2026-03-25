#!/bin/sh
# Wirken installer
# Usage: curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh

set -e

REPO="gebruder/wirken"
INSTALL_DIR="${WIRKEN_INSTALL_DIR:-$HOME/.local/bin}"

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

download_binary() {
    BINARY_NAME="wirken-${TARGET}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
    TMPDIR=$(mktemp -d)
    TMPFILE="${TMPDIR}/wirken"

    echo "Downloading ${URL}"
    curl -fsSL -o "$TMPFILE" "$URL"
    chmod +x "$TMPFILE"
}

install_binary() {
    # Try user directory first
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMPFILE" "${INSTALL_DIR}/wirken"
        echo "Installed to ${INSTALL_DIR}/wirken"
    else
        # Fall back to /usr/local/bin with sudo
        echo "Cannot write to ${INSTALL_DIR}, trying /usr/local/bin with sudo"
        INSTALL_DIR="/usr/local/bin"
        sudo mv "$TMPFILE" "${INSTALL_DIR}/wirken"
        echo "Installed to ${INSTALL_DIR}/wirken"
    fi

    rm -rf "$TMPDIR"

    # Check if install dir is in PATH
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

main
