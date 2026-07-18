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

## Embedded data

`src/colo_db.json` (Cloudflare `colo` code → country) is compiled in via `include_str!` in `colo.rs`. Editing it needs only a rebuild — there is no runtime asset path. Verify entries against the live Cloudflare colo list; the lookup is case-insensitive and unknown codes resolve to `None` (never error).

## Release process

Releases are automated by Release Please and driven by **Conventional Commits**. PR titles / squash commits must use prefixes: `fix:` (patch), `feat:` (minor; note: below `1.0.0` `feat` bumps the minor), `feat!:` or `BREAKING CHANGE:` (major), `docs:`/`chore:` (no release). Merging the auto-opened version PR publishes the release; no custom secret required.

## Conventions worth knowing

- Country filtering (`--country`) is a Unicode-aware substring match using `to_lowercase()` on both sides (e.g. `Côte d'Ivoire` matches); do not switch it back to `to_ascii_lowercase()`.
- The first probe establishes the TCP+TLS connection: with warmup on, a discarded warmup probe captures `cold_ms`; if warmup fails, the first *successful* measured probe is discarded as `cold_ms` so connection setup stays out of steady-state latency.
