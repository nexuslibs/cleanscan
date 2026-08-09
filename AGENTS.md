# AGENTS.md

Single Rust **binary** crate (`cargo test --lib` fails — there is no library target). Entrypoint is `src/main.rs`; the real work lives in `scanner.rs` (probe engine + warmup), `colo.rs` (embedded colo→country data), `config.rs`, `speed.rs`, and `src/tui/` (ratatui interface).

## Developer commands

Run in this order (mirrors CI, which fails the build on any step):

```bash
cargo fmt --all -- --check      # must be clean
cargo clippy --locked --all-targets -- -D warnings   # warnings are errors
cargo build --locked
cargo test --locked
```

- `--locked` is used everywhere in CI — keep `Cargo.lock` committed and up to date.
- Clippy uses `-D warnings`; unused fields/vars break the build, not just lint.
- Run one test: `cargo test <test_name>` (substring match). `cargo test --lib` does **not** work in this bin crate.

## Optional `syn` feature

- `--discover syn` (masscan-style raw SYN sweep) is compiled only with
  `--features syn`, which adds the `pcap` and `libc` dependencies. It is
  **not** in `default`, so Android/Termux builds stay free of libpcap.
- CI covers it: `ci.yml` installs `libpcap-dev` and runs syn-featured clippy +
  tests; `release.yml` statically builds libpcap 1.10.5 with the zig wrapper
  for the `linux-musl` targets (`LIBPCAP_LIBDIR`) and enables `--features syn`
  for the Linux and macOS release binaries. Android targets deliberately stay
  without the feature (no libpcap for Android).
- Local verification: `cargo clippy --features syn --locked --all-targets -- -D warnings`
  and `cargo test --features syn` (host builds need libpcap headers:
  `libpcap-dev` on Debian/Ubuntu, `brew install libpcap` on macOS). At runtime
  the engine needs root (`euid 0`); its loopback end-to-end test skips itself
  when not root.
- SYN sweeps are IPv4-only and Ethernet-only and need a reachable IPv4 default
  gateway; the TUI wizard deliberately keeps the `syn` driver unreachable
  (CLI-only).

## Branch and commit enforcement

- `.github/workflows/conventional-commits.yml` validates PR titles, not branch
  names. Branch names therefore have no workflow-enforced prefix or pattern.
- PR titles must match the workflow's Conventional Commit pattern:
  `type(scope): description`. Allowed types are `build`, `chore`, `ci`, `docs`,
  `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`; scope and
  the `!` breaking-change marker are optional. Scope characters are limited to
  letters, numbers, `.`, `_`, `/`, and `-`.
- Commit messages should use the same format so Release Please can classify
  releases correctly. Examples: `feat(tui): add ASCII rendering`,
  `fix(scanner): handle timeout`, `docs: clarify release workflow`, and
  `feat!: change the export schema`.
- Breaking changes may also use a `BREAKING CHANGE:` footer. The subject must
  be imperative, concise, and non-empty; free-form messages such as `update
  stuff` are invalid.

## Embedded data

`src/colo_db.json` (Cloudflare `colo` code → country) is compiled in via `include_str!` in `colo.rs`. Editing it needs only a rebuild — there is no runtime asset path. Verify entries against the live Cloudflare colo list; the lookup is case-insensitive and unknown codes resolve to `None` (never error).

## Release process

Releases are automated by Release Please and driven by **Conventional Commits**. PR titles / squash commits must use prefixes: `fix:` (patch), `feat:` (minor; note: below `1.0.0` `feat` bumps the minor), `feat!:` or `BREAKING CHANGE:` (major), `docs:`/`chore:` (no release). Merging the auto-opened version PR publishes the release; no custom secret required.

## Android (Termux) builds

`*-linux-android` targets are built with the NDK (installed via Android Studio at `~/Library/Android/sdk/ndk/<version>`; CI installs `28.2.13676358` via `sdkmanager`). The `<triple>24-clang` wrappers serve as both CC and linker, plus `-Wl,-z,max-page-size=16384` for Android 15+ 16K-page devices. Termux installs (install.sh, updater.rs) prefer `*-linux-android` assets; the musl static-PIE builds serve non-Termux Linux. Android binaries link against Bionic and cannot run on non-Android hosts — verify them structurally (INTERP `/system/bin/linker64`, DYN, 16K LOAD alignment).

## Conventions worth knowing

- Country filtering (`--country`) is a Unicode-aware substring match using `to_lowercase()` on both sides (e.g. `Côte d'Ivoire` matches); do not switch it back to `to_ascii_lowercase()`.
- The first probe establishes the TCP+TLS connection: with warmup on, a discarded warmup probe captures `cold_ms`; if warmup fails, the first *successful* measured probe is discarded as `cold_ms` so connection setup stays out of steady-state latency.
