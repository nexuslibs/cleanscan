# cleanscan

A Cloudflare IP scanner / latency prober written in Rust. It samples random IPs
from CIDR ranges (or a file of IPs/CIDRs), probes each one over HTTPS while
resolving the target hostname directly to that IP, and ranks the fastest,
most reliable addresses by latency.

It is a rewrite of tools like `cfscan` / `CloudflareScanner`, useful for finding
the best Cloudflare edge IPs to reach a given origin host.

## Features

- **TUI by default** — a live, interactive terminal dashboard with a progress
  gauge and a results table that updates as each IP is probed.
- **CLI mode** — drop-in tab-separated table output for piping / scripting via
  the `--cli` flag.
- Custom DNS resolution per IP, HTTP/2 adaptive windows, configurable
  concurrency, probes, and timeouts.
- Persistent TUI settings, including selected CIDR ranges and scan parameters.

## Build

Install the Rust toolchain first, then run:

```sh
cargo build --release
```

> If your environment cannot reach the crates.io git index, force the sparse
> protocol: `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo build`.

## Install

Download a prebuilt binary from a GitHub release. Linux artifacts are
statically linked musl binaries; macOS artifacts are native binaries for Intel
and Apple Silicon.

Once a release has been published, install the latest version with:

```sh
bash -c 'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'
```

The script detects your OS/architecture, downloads the matching tarball,
verifies its SHA256 checksum (and aborts on download failure, missing tooling,
or mismatch), and installs `cleanscan` to `/usr/local/bin`
(falls back to `~/.local/bin` if that is not writable). It prints a note if the
install directory is not already on your `PATH`.

Options (environment variables):

```sh
# Install a specific version
CLEANSCAN_VERSION=v1.0.0 bash -c 'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'

# Install to a custom directory
INSTALL_DIR=/opt/bin bash -c 'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'
```

## Releases and versioning

Releases are automated through GitHub Actions. Use Conventional Commit
prefixes in pull request titles and squash commits:

- `fix:` creates a patch release.
- `feat:` creates a minor release.
- `feat!:` or a `BREAKING CHANGE:` footer creates a major release.
- `docs:` and `chore:` changes do not create a release.

While the project is below `1.0.0`, a feature release advances the minor
version. Release Please opens a version PR that updates the Cargo version and
changelog. Once CI passes and you merge the release PR, GitHub then builds
Linux musl and macOS binaries for both supported architectures, verifies their
checksums, and publishes the release only after every artifact is ready.
Review and merge the release PR when it is ready. The merge starts the release
build automatically, and no custom GitHub secret is required.

The installer continues to support the latest release and pinned versions via
`CLEANSCAN_VERSION=vX.Y.Z`.

## Usage

```sh
# TUI mode (default)
cleanscan --cidr 188.114.96.0/20 --cidr 104.16.0.0/13

# Provide a file of IPs / CIDRs (one per line; blank lines and lines beginning with # are ignored)
cleanscan --ips ips.txt

# Pipe-friendly tab-separated output
cleanscan --cli --cidr 188.114.96.0/20 --top 20
```

### TUI controls

When `cleanscan` is run with no `--cidr` / `--ips`, it opens a CIDR
selection screen first. Built-in Cloudflare ranges are listed and pre-selected;
toggle the ones you want and press `Enter` to start. When targets are supplied
on the command line, the scan starts directly with those targets.

**Selection screen**

| Key            | Action                                  |
|----------------|-----------------------------------------|
| `↑` / `↓` (`k`/`j`) | Move the cursor through the CIDR list |
| `space`        | Toggle selection of the highlighted CIDR |
| `A`            | Select **all** CIDRs                    |
| `D`            | Deselect **all** CIDRs                  |
| `a`            | Add a custom CIDR via the inline text field |
| `c`            | Open the **settings** screen to tweak scan parameters |
| `Enter`        | Start the scan with the selected CIDRs  |
| `q`            | Quit                                    |

While typing a custom CIDR (`a`), `char` appends, `Backspace` deletes,
`Enter` confirms, and `Esc` cancels.

**Settings screen**

Reached from the selection screen with `c`. Scan parameters can be edited here.
Navigation mirrors the selection screen:

| Key            | Action                                  |
|----------------|-----------------------------------------|
| `↑` / `↓` (`k`/`j`) | Move the cursor through the parameters |
| `Enter`        | Edit the highlighted parameter          |
| `char`         | While editing, append to the value      |
| `Backspace`    | While editing, delete a character       |
| `Enter`        | While editing, confirm the new value    |
| `Esc`          | While editing, cancel; otherwise return to the selection screen |
| `b`            | Return to the selection screen          |
| `q`            | Quit                                    |

The following parameters are editable, with the same meaning as their CLI
counterparts: `Host` (`--host`), `Path` (`--path`), `Sample per CIDR`
(`--sample-per-cidr`), `Probes` (`--probes`), `Concurrency` (`--concurrency`),
`Timeout (ms)` (`--timeout-ms`), `Connect timeout (ms)` (`--connect-timeout-ms`),
and `Top results` (`--top`).
Target-source flags such as `--cidr` and `--ips` are selected before launching
the TUI and are not edited in this screen.

**Scanning screen**

| Key       | Action                          |
|-----------|---------------------------------|
| `q`       | Quit                            |
| `p` / `␣` | Pause / resume the scan         |
| `s`       | Save results to a `.tsv` file (after the scan finishes) |

### CLI options

| Flag                   | Default          | Description                                      |
|------------------------|------------------|--------------------------------------------------|
| `--cli`                | off              | Use tab-separated CLI output instead of the TUI  |
| `--host`               | `app.iplat.ir`   | Hostname for HTTPS / SNI / Host header           |
| `--path`               | `/cdn-cgi/trace` | Path to probe                                    |
| `--ips`                | —                | File with one IP or CIDR per line                |
| `--cidr`               | —                | CIDR block to sample (repeatable)                |
| `--sample-per-cidr`    | `100`            | Random IPs sampled from each CIDR                |
| `--probes`             | `8`              | Repeated probes per IP                           |
| `--concurrency`        | `120`            | Max concurrent HTTP probes                       |
| `--timeout-ms`         | `2500`           | Request timeout (ms)                             |
| `--connect-timeout-ms` | `1000`           | Connect timeout (ms)                             |
| `--top`                | `50`             | Number of top results to display                 |

## Output

Only IPs with at least one successful probe are shown. Probes are scheduled one
at a time per IP: successful IPs receive priority for their remaining probes,
unexplored IPs are preferred over IPs that have failed, and original order is
used as a deterministic tie-breaker. CLI results are ranked by failure count
(ascending), then `p95`, `max`, and `avg` latency (all ascending). Each row reports `ok`/`fail` counts and `avg`,
`p50`, `p90`, `p95`, and `max` latency in seconds, followed by individual
successful probe samples in the `samples` column. Only the top `N` rows are
printed, where `N` is controlled by `--top`.

The TUI displays the same latency statistics. Its save action writes the top
successful results to a timestamped
`cleanscan_<timestamp>.tsv` file in the current directory.

CIDR ranges are sampled randomly, so overlapping samples may produce fewer
unique targets than `sample-per-cidr` suggests. Each probe is an HTTPS request
to the configured host and path, using the candidate IP for the connection
while retaining the hostname for TLS SNI and the Host header.

## Configuration

The TUI saves settings automatically so the next run can reuse the previous
host, path, scan parameters, custom CIDRs, and selected ranges. The file is
stored at the platform-specific user configuration directory under
`cleanscan/config.json`. Command-line options override saved settings for that
run.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

MIT
