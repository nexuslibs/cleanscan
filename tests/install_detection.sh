#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/install.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

run_detection() {
  local os="$1"
  local arch="$2"
  local expected_target="$3"
  local expected_dir="$4"
  shift 4

  local output
  output="$({
    env "$@" \
      CLEANSCAN_TEST_OS="$os" \
      CLEANSCAN_TEST_ARCH="$arch" \
      CLEANSCAN_INSTALLER_DRY_RUN=1 \
      INSTALL_DIR="$expected_dir" \
      bash "$INSTALLER"
  })"

  grep -qx "target=$expected_target" <<<"$output"
  grep -qx "install_dir=$expected_dir" <<<"$output"
}

run_detection Linux x86_64 x86_64-unknown-linux-musl "$TEST_ROOT/linux-x86"
run_detection Linux aarch64 aarch64-unknown-linux-musl "$TEST_ROOT/linux-arm64"
run_detection Darwin x86_64 x86_64-apple-darwin "$TEST_ROOT/macos-x86"

TERMUX_PREFIX="$TEST_ROOT/termux/usr"
run_detection Linux aarch64 aarch64-unknown-linux-musl "$TERMUX_PREFIX/bin" \
  CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX="$TERMUX_PREFIX" INSTALL_DIR=
run_detection Linux armv7l armv7-unknown-linux-musleabihf "$TERMUX_PREFIX/bin" \
  CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX="$TERMUX_PREFIX" INSTALL_DIR=
run_detection Linux x86_64 x86_64-unknown-linux-musl "$TERMUX_PREFIX/bin" \
  CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX="$TERMUX_PREFIX" INSTALL_DIR=
run_detection Linux i686 i686-unknown-linux-musl "$TERMUX_PREFIX/bin" \
  CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX="$TERMUX_PREFIX" INSTALL_DIR=

termux_output="$({
  env CLEANSCAN_TEST_OS=Linux CLEANSCAN_TEST_ARCH=aarch64 \
    CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX="$TERMUX_PREFIX" \
    INSTALL_DIR= CLEANSCAN_INSTALLER_DRY_RUN=1 bash "$INSTALLER"
})"
grep -qx "target=aarch64-unknown-linux-musl" <<<"$termux_output"
grep -qx "install_dir=$TERMUX_PREFIX/bin" <<<"$termux_output"

if env CLEANSCAN_TEST_OS=Linux CLEANSCAN_TEST_ARCH=mips \
  CLEANSCAN_INSTALLER_DRY_RUN=1 INSTALL_DIR="$TEST_ROOT/unsupported" \
  bash "$INSTALLER" >/dev/null 2>&1; then
  echo "unsupported architecture was accepted" >&2
  exit 1
fi

if env CLEANSCAN_TEST_OS=Linux CLEANSCAN_TEST_ARCH=aarch64 \
  CLEANSCAN_TEST_TERMUX=1 CLEANSCAN_TEST_PREFIX= \
  CLEANSCAN_INSTALLER_DRY_RUN=1 bash "$INSTALLER" >/dev/null 2>&1; then
  echo "Termux without PREFIX was accepted" >&2
  exit 1
fi

echo "installer platform detection tests passed"
