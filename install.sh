#!/usr/bin/env bash
#
# cleanscan installer
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash
#
# Options (environment variables):
#   CLEANSCAN_VERSION     tag to install, e.g. v1.0.0 (default: latest)
#   CLEANASCAN_VERSION    deprecated alias for CLEANSCAN_VERSION
#   INSTALL_DIR          where to install (default: $PREFIX/bin in Termux,
#                         otherwise /usr/local/bin or ~/.local/bin)
#   BIN_DIR              alias for INSTALL_DIR

set -euo pipefail

REPO="nexuslibs/cleanscan"
BINARY="cleanscan"
VERSION="${CLEANSCAN_VERSION:-${CLEANASCAN_VERSION:-latest}}"

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
OS="${CLEANSCAN_TEST_OS:-$(uname -s)}"
ARCH="${CLEANSCAN_TEST_ARCH:-$(uname -m)}"

IS_TERMUX=0
if [ -n "${CLEANSCAN_TEST_TERMUX:-}" ]; then
  IS_TERMUX=1
elif [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == */com.termux/* ]]; then
  IS_TERMUX=1
fi

case "$OS" in
  Linux)  OS_KIND=linux ;;
  Darwin) OS_KIND=darwin ;;
  *) err "unsupported OS: $OS (only Linux, macOS, and Termux are supported)" ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_KIND=x86_64 ;;
  aarch64|arm64) ARCH_KIND=aarch64 ;;
  armv7l|armv7)  ARCH_KIND=armv7 ;;
  i686|i386|x86) ARCH_KIND=i686 ;;
  *) err "unsupported architecture: $ARCH (supported: x86_64, aarch64, armv7, i686)" ;;
esac

if [ "$IS_TERMUX" -eq 1 ]; then
  [ "$OS_KIND" = "linux" ] || err "Termux must run on Linux"
  case "$ARCH_KIND" in
    armv7) TARGET="armv7-unknown-linux-musleabihf" ;;
    i686) TARGET="i686-unknown-linux-musl" ;;
    *) TARGET="${ARCH_KIND}-unknown-linux-musl" ;;
  esac
elif [ "$OS_KIND" = "darwin" ]; then
  case "$ARCH_KIND" in
    x86_64|aarch64) TARGET="${ARCH_KIND}-apple-darwin" ;;
    *) err "unsupported macOS architecture: $ARCH" ;;
  esac
else
  case "$ARCH_KIND" in
    armv7) TARGET="armv7-unknown-linux-musleabihf" ;;
    *) TARGET="${ARCH_KIND}-unknown-linux-musl" ;;
  esac
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
elif [ "$IS_TERMUX" -eq 1 ]; then
  PREFIX_VALUE="${CLEANSCAN_TEST_PREFIX:-${PREFIX:-}}"
  [ -n "$PREFIX_VALUE" ] || err "Termux prefix is unavailable; set PREFIX or INSTALL_DIR"
  INSTALL_DIR="$PREFIX_VALUE/bin"
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

mkdir -p "$INSTALL_DIR"

if [ "${CLEANSCAN_INSTALLER_DRY_RUN:-0}" = "1" ]; then
  printf 'target=%s\ninstall_dir=%s\n' "$TARGET" "$INSTALL_DIR"
  exit 0
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
# Verify checksum (fail-closed)
# ---------------------------------------------------------------------------
EXPECTED="$(curl -fSL "$SHA_URL" 2>/dev/null | tr -d '[:space:]')" \
  || err "checksum download failed: $SHA_URL"

if [ -z "$EXPECTED" ] || ! printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  err "invalid checksum format from $SHA_URL (expected 64-character hex)"
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)"
else
  err "no sha256 tool (sha256sum/shasum) available to verify $ASSET"
fi

if [ "$ACTUAL" = "$EXPECTED" ]; then
  info "Checksum verified"
else
  err "checksum mismatch for $ASSET
       expected: $EXPECTED
       actual:   $ACTUAL"
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
