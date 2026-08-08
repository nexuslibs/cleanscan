#!/usr/bin/env bash
set -euo pipefail

: "${ZIG_MUSL_TARGET:?ZIG_MUSL_TARGET must be set (e.g. aarch64-linux-musl)}"

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

exec zig "$mode" -target "$ZIG_MUSL_TARGET" -fno-sanitize=all "${args[@]}"
