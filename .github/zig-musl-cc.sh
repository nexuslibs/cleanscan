#!/usr/bin/env bash
set -euo pipefail

: "${ZIG_MUSL_TARGET:?ZIG_MUSL_TARGET must be set (e.g. aarch64-linux-musl)}"

target="${ZIG_MUSL_TARGET/unknown-}"
case "$target" in
  armv7-*) target="arm-linux-musleabihf" ;;
  i686-*) target="x86-linux-musl" ;;
esac

mode="cc"
case "$(basename "$0")" in
  *cxx* | *++*) mode="c++" ;;
esac

args=()
for a in "$@"; do
  case "$a" in
    --target=*) : ;;
    *) args+=("$a") ;;
  esac
done

exec zig "$mode" -target "$target" -fno-sanitize=all "${args[@]}"
