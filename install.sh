#!/usr/bin/env bash
#
# cleanscan installer
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash
#
# Options (environment variables):
#   CLEANASCAN_VERSION   tag to install, e.g. v1.0.0 (default: latest)
#   INSTALL_DIR          where to install (default: /usr/local/bin or ~/.local/bin)
#   BIN_DIR              alias for INSTALL_DIR

set -euo pipefail

REPO="nexuslibs/cleanscan"
BINARY="cleanscan"
VERSION="${CLEANASCAN_VERSION:-latest}"

err()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl is required but not found"
command -v tar  >/dev/null 2>&1 || err "tar is required but not found"

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_KIND=linux ;;
  Darwin) OS_KIND=darwin ;;
  *) err "unsupported OS: $OS (only Linux and macOS are supported)" ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_KIND=x86_64 ;;
  aarch64|arm64) ARCH_KIND=aarch64 ;;
  *) err "unsupported architecture: $ARCH (only x86_64 and aarch64 are supported)" ;;
esac

if [ "$OS_KIND" = "darwin" ]; then
  TARGET="${ARCH_KIND}-apple-darwin"
else
  TARGET="${ARCH_KIND}-unknown-linux-musl"
fi

# ---------------------------------------------------------------------------
# Resolve download URLs
# ---------------------------------------------------------------------------
ASSET="cleanscan-${TARGET}.tar.gz"
ASSET_SHA="${ASSET}.sha256"

if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TARBALL_URL="${BASE_URL}/${ASSET}"
SHA_URL="${BASE_URL}/${ASSET_SHA}"

# ---------------------------------------------------------------------------
# Choose install directory
# ---------------------------------------------------------------------------
if [ -n "${INSTALL_DIR:-}" ]; then
  : # use as-is
elif [ -n "${BIN_DIR:-}" ]; then
  INSTALL_DIR="$BIN_DIR"
elif [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
elif [ -n "${HOME:-}" ] && [ -w "${HOME}/.local/bin" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
elif [ -n "${HOME:-}" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
else
  err "no writable install directory found (set INSTALL_DIR)"
fi

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "Downloading ${ASSET} (${VERSION})"
curl -fSL "$TARBALL_URL" -o "$TMP/$ASSET" \
  || err "download failed: $TARBALL_URL
       (is there a release built for target '$TARGET'?)"

# ---------------------------------------------------------------------------
# Verify checksum (best-effort)
# ---------------------------------------------------------------------------
if curl -fSL "$SHA_URL" -o "$TMP/$ASSET_SHA" 2>/dev/null; then
  EXPECTED="$(cat "$TMP/$ASSET_SHA" | tr -d '[:space:]')"
  ACTUAL=""
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)"
  fi
  if [ -n "$ACTUAL" ]; then
    if [ "$ACTUAL" = "$EXPECTED" ]; then
      info "Checksum verified"
    else
      err "checksum mismatch for $ASSET
       expected: $EXPECTED
       actual:   $ACTUAL"
    fi
  else
    info "No sha256 tool available; skipping verification"
  fi
else
  info "No checksum file published; skipping verification"
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
tar -xzf "$TMP/$ASSET" -C "$TMP"
install -m 0755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"

info "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
"$INSTALL_DIR/$BINARY" --version 2>/dev/null || true

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo
    echo "note: $INSTALL_DIR is not on your PATH."
    echo "      Add it with: export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac
