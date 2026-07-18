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
- Selective upload/download throughput tests for successful latency targets.
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

When `cleanscan` is run with no `--cidr` / `--ips`, it opens a guided setup
wizard (Ranges → Settings → Review). Its top bar shows the step progress, and
across every screen the panel that currently holds keyboard focus is drawn with
a highlighted (accent-colored) border so it is always clear where input goes.
Built-in Cloudflare ranges are listed and pre-selected; toggle the ones you want
and press `Enter` to advance. When targets are supplied on the command line, the
scan starts directly with those targets.

**Selection screen**

| Key            | Action                                  |
|----------------|-----------------------------------------|
| `Tab` / `Shift+Tab` | Move focus between controls |
| `↑` / `↓` (or `k` / `j`) | Move through the focused list |
| `Space` | Toggle the focused CIDR |
| `a` | Add a custom CIDR range |
| `A` | Select all ranges |
| `N` / `n` / `d` | Deselect all ranges |
| `Enter` | Activate or edit the focused control |
| `Esc` | Cancel or go back |
| `/` | Open the command palette |
| `?` | Open contextual help (close with `?`, `Esc`, or `q`) |
| `q` | Quit |

While the custom CIDR field is focused, typed characters append, `Backspace`
deletes, `Enter` confirms, and `Esc` cancels.

**Settings screen**

After advancing from the selection screen, scan parameters can be edited here.
Navigation mirrors the selection screen:

| Key            | Action                                  |
|----------------|-----------------------------------------|
| `Tab` / `Shift+Tab` | Move focus between controls |
| `↑` / `↓` | Move through the parameters |
| `j` / `k` | Move through the parameters |
| `Enter`        | Edit or activate the highlighted parameter |
| `char`         | While editing, append to the value      |
| `Backspace`    | While editing, delete a character       |
| `Enter`        | While editing, confirm the new value    |
| `Esc`          | While editing, cancel; otherwise return to the selection screen |
| `q`            | Quit                                    |

The following parameters are editable, with the same meaning as their CLI
counterparts: `Host` (`--host`), `Path` (`--path`), `Sample per CIDR`
(`--sample-per-cidr`), `Probes` (`--probes`), `Concurrency` (`--concurrency`),
`Timeout (ms)` (`--timeout-ms`), `Connect timeout (ms)` (`--connect-timeout-ms`),
and `Top results` (`--top`). Speed-test settings are also editable: download
path, upload path, payload size in MB, repetition count, and speed timeout (ms).
Target-source flags such as `--cidr` and `--ips` are selected before launching
the TUI and are not edited in this screen.

**Scanning screen**

| Key       | Action                          |
|-----------|---------------------------------|
| `q`       | Quit                            |
| `p`       | Pause / resume the scan         |
| `e`       | Export results to a `.tsv` file (after the scan finishes) |
| `t`       | Select successful IPs for speed testing (after the scan finishes) |
| `Enter`   | Open full details for the selected IP |
| `↑` / `↓` | Select a result IP |
| `c`       | Copy the selected IP to the clipboard |
| `f`       | Include failed targets for diagnosis |
| `r`       | Re-run the identical sampled target set |
| `n`       | Generate a new sample with the same settings |
| `m`       | Export runs for comparison |
| `/`       | Open the command palette |
| `?`       | Open contextual help (close with `?`, `Esc`, or `q`) |

In the command palette, type `colo:FRA` (or any datacenter code) to narrow the
results table to IPs in that Cloudflare colo; `colo:` with no code clears the
filter. Type `country:Germany` (substring match) to narrow results to a country;
`country:` with no code clears it. The `Colo` and `Country` columns are shown by
default and can be toggled like any other result column.

**Speed-test screen**

After latency scanning completes, press `t` to select speed-test targets. The
screen lists every scanned IP with its `READY`, `DEGRADED`, or `FAILED` status,
average latency, p95 latency, and negotiated protocol. Failed targets remain
visible for diagnosis but cannot be selected for a bandwidth test. The default
order is fastest average latency first; click a column header to sort, or press
`s` to reverse the current order.

Press `/` to search by IP, status, or protocol. `Enter` accepts the search and
`Esc` clears it before leaving search mode. `Tab` moves focus through each
control individually (the target list, the three direction buttons,
select-all/clear, and start/back), and `Enter` activates whichever control is
focused. The currently chosen direction is always shown as a filled button so
selection and focus never look alike. Shortcuts: `Space` toggles the
highlighted eligible IP, `a` / `x` select-all / clear, and `d` / `u` / `b` set
the download / upload / both direction. Results report throughput in Mbps for
each direction. Press `c` to copy the selected IP and `Esc` to return to the
latency dashboard.

### CLI options

| Flag                   | Default          | Description                                      |
|------------------------|------------------|--------------------------------------------------|
| `--cli`                | off              | Use tab-separated CLI output instead of the TUI  |
| `--host`               | required         | Hostname for HTTPS / SNI / Host header (no built-in default) |
| `--path`               | `/cdn-cgi/trace` | Path to probe                                    |
| `--ips`                | —                | File with one IP or CIDR per line                |
| `--cidr`               | —                | CIDR block to sample (repeatable)                |
| `--sample-per-cidr`    | `100`            | Random IPs sampled from each CIDR                |
| `--probes`             | `8`              | Repeated probes per IP                           |
| `--concurrency`        | `120`            | Max concurrent HTTP probes                       |
| `--timeout-ms`         | `2500`           | Request timeout (ms)                             |
| `--connect-timeout-ms` | `1000`           | Connect timeout (ms)                             |
| `--top`                | `50`             | Number of top results to display                 |
| `--seed`               | random           | Reproducible CIDR sampling seed                 |
| `--targets-file`       | —                | Exact target list for a reproducible run        |
| `--format`             | `tsv`            | CLI output format: `tsv`, `json`, or `ndjson`   |
| `--output`             | stdout           | Write CLI output to a file                     |
| `--min-success-rate`   | —                | Minimum per-target success rate threshold       |
| `--max-p95-ms`         | —                | Maximum per-target p95 latency threshold        |
| `--fail-if-no-healthy-target` | off         | Fail if no target meets thresholds              |
| `--colo`                | —                | Only report IPs in the given Cloudflare datacenter (e.g. `FRA`) |
| `--country`             | —                | Only report IPs in the given country (substring match, e.g. `Germany`) |
| `--no-warmup`           | off              | Skip the connection-establishment warmup probe (measure raw RTT) |

## Output

All sampled IPs are shown, including targets with no successful probes. Probes are scheduled one
at a time per IP: successful IPs receive priority for their remaining probes,
unexplored IPs are preferred over IPs that have failed, and original order is
used as a deterministic tie-breaker. CLI results are ranked by success rate
(descending), then `p95` and average latency (ascending). Each row reports `ok`/`fail` counts and `avg`,
`p50`, `p90`, `p95`, and `max` latency in seconds, followed by individual
successful probe samples in the `samples` column. The `colo` column shows the
Cloudflare datacenter code parsed from `/cdn-cgi/trace` (when probing that
path), and `connect_ms` reports the one-off TCP + TLS connection-establishment
time captured by the warmup probe. Only the top `N` rows are printed, where `N`
is controlled by `--top`.

Completed scans show a decision summary with READY, DEGRADED, and FAILED
counts, a recommended target, backups, success rate, p95 latency, and
confidence. The selected-IP details modal supports `1`–`5` / `Tab` tabs for
overview, failure diagnostics, latency distribution, speed context, and
latency map.

The Review screen shows the random seed and exact deduplicated target count.
Press `s` for a new sample or `c` to save the exact targets to
`cleanscan_targets_<seed>.txt`.

The TUI displays the same latency statistics. Its save action writes the top
successful results to a timestamped
`cleanscan_<timestamp>.tsv` file in the current directory.

CIDR ranges are sampled randomly, so overlapping samples may produce fewer
unique targets than `sample-per-cidr` suggests. Each probe is an HTTPS request
to the configured host and path, using the candidate IP for the connection
while retaining the hostname for TLS SNI and the Host header. Before the
counted latency probes, cleanscan sends one discarded warmup probe per IP so
the TCP + TLS connection is established; the reported `avg`/`p50`/`p90`/`p95`/`max`
latencies reflect steady-state RTT rather than connection-setup cost, and the
one-off connect time is reported separately as `connect_ms`. Pass `--no-warmup`
to measure raw RTT including the handshake. Results are ranked by success rate
first, then p95 and average latency; failures include categorized diagnostics
in the details view and machine-readable output.

Speed tests use the same direct-IP connection behavior. The default endpoints
are `/speed-test/100mb.bin` for downloads and `/speed-test/upload` for uploads;
the download endpoint should serve at least the configured payload size, and
the upload endpoint should consume the complete POST body before responding.

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
