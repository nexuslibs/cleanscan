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
- Cloudflare HTTPS port selection across 443, 2053, 2083, 2087, 2096, and 8443.
- Selective upload/download throughput tests for successful latency targets.
- Persistent TUI settings, including selected CIDR ranges and scan parameters.
- Current public IP, ASN, and ISP name in the running dashboard header when
  network metadata is available.

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

### Termux (Android terminal)

cleanscan runs in [Termux](https://termux.dev/) using the static Linux/musl
release artifacts. Install Termux from [F-Droid](https://f-droid.org/en/packages/com.termux/)
rather than the discontinued Play Store build. Then install the required tools:

```sh
pkg update
pkg install curl tar
```

Install the latest cleanscan release directly into Termux's `$PREFIX/bin`:

```sh
curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash
```

To install a specific release:

```sh
CLEANSCAN_VERSION=v0.16.0 bash -c \
  'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'
```

Verify the installation and run a small smoke test:

```sh
cleanscan --version
cleanscan --cli --host example.com \
  --cidr 188.114.96.0/20 --sample-per-cidr 1
```

The installer selects an artifact for ARM64, ARMv7, x86_64, or x86 Termux
devices and verifies its SHA256 checksum before installing. It does not require
root access. On Android, use `termux-setup-storage` only if you want to read or
write files under shared storage; scans and exports work from the Termux home
directory without that permission.

The TUI uses the same keyboard controls as desktop terminals. The `c` clipboard
action depends on Termux clipboard integration and may not work on every setup;
use the exported TSV or target manifest files if clipboard access is unavailable.
For long scans, keep Termux in the foreground or use `termux-wake-lock` from the
`termux-api` package to reduce interruptions when the device sleeps.

Termux support is delivered through static Linux binaries. This release does
not include an Android APK or a separate Termux package-manager formula.

If installation reports an unsupported architecture, check `uname -m` and use a
device supported by the published release artifacts. The installer also requires
Termux's `$PREFIX` to be available; do not run it from an Android shell outside
Termux.

## Usage

```sh
# TUI mode (default)
cleanscan --cidr 188.114.96.0/20 --cidr 104.16.0.0/13

# Provide a file of IPs / CIDRs (one per line; blank lines and lines beginning with # are ignored)
cleanscan --ips ips.txt

# Pipe-friendly tab-separated output
cleanscan --cli --cidr 188.114.96.0/20 --top 20

# Check transport survivability for the top 10 healthy candidates
cleanscan --cli --host example.com --cidr 188.114.96.0/20 \
  --proxy-url 'vless://UUID@example.com:443?type=ws&security=tls&sni=example.com&host=example.com&path=%2Fws'

# Probe several required application paths.
cleanscan --cli --host example.com \
  --check edge=/cdn-cgi/trace \
  --check app=/healthz \
  --cidr 188.114.96.0/20
```

### TUI environment options

For terminals that do not support Unicode box-drawing or braille glyphs, use
ASCII rendering:

```sh
CLEANSCAN_ASCII=1 cleanscan --cidr 188.114.96.0/20
```

Set `CLEANSCAN_REDUCED_MOTION=1` to disable modal slide transitions while
keeping status updates and progress feedback enabled.

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
counterparts: `Host` (`--host`), `Path` (`--path`), `HTTPS ports` (`--port`, repeatable), `Sample per CIDR`
(`--sample-per-cidr`), `Probes` (`--probes`), `Concurrency` (`--concurrency`),
`Timeout (ms)` (`--timeout-ms`), `Connect timeout (ms)` (`--connect-timeout-ms`),
`Top results` (`--top`), `Stability weight` (`--stability-weight`, default `1.0`),
and `Loss weight` (`--loss-weight`, default `1.0`). Validation settings are also editable:
expected statuses, required body markers, required headers, and redirect behavior.
Comma-separated values are used for repeatable marker/header fields. Speed-test settings are also editable: download
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
| `--port`               | `443`            | Cloudflare HTTPS port to probe; repeatable (`443`, `2053`, `2083`, `2087`, `2096`, or `8443`) |
| `--check NAME=PATH`    | —                | Additional required health check; repeatable     |
| `--expect-status`      | any 2xx          | Expected HTTP status code (repeatable)           |
| `--require-body`       | —                | Required literal response-body marker (repeatable) |
| `--require-header`     | —                | Required exact response header as `name=value` (repeatable) |
| `--follow-redirects`   | off              | Follow redirects during validation               |
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
| `--proxy-url`          | —                | Parse VLESS/Trojan transport settings and check top candidates |
| `--protocol-check-top` | `10`             | Number of healthy candidates to transport-check |
| `--min-success-rate`   | —                | Minimum per-target success rate threshold       |
| `--max-p95-ms`         | —                | Maximum per-target p95 latency threshold        |
| `--fail-if-no-healthy-target` | off         | Fail if no target meets thresholds              |
| `--colo`                | —                | Only report IPs in the given Cloudflare datacenter (e.g. `FRA`) |
| `--country`             | —                | Only report IPs in the given country (substring match, e.g. `Germany`) |
| `--no-warmup`           | off              | Skip the warmup probe; the first measured probe includes connection setup, while later probes may reuse the connection |
| `--stability-weight`    | `1.0`            | Weight of latency jitter in the recommendation score (higher penalizes variable-latency IPs) |
| `--loss-weight`         | `1.0`            | Weight of packet loss in the recommendation score (higher penalizes lossy IPs) |
| `--watch`               | —                | Repeat scans every N seconds using the same exact target list |
| `--manifest`            | —                | Atomically write a primary/backup JSON manifest   |
| `--manifest-backups`    | `3`              | Number of backup targets in the manifest         |
| `--manifest-min-confidence` | `UNKNOWN`    | Minimum confidence required for manifest targets |
| `--alert-p95-increase-ms` | —              | Watch alert threshold for recommended p95 regression |
| `--alert-packet-loss-increase` | —        | Watch alert threshold for recommended packet-loss regression |
| `--fail-on-alert`       | off              | Exit watch mode when an alert is emitted         |
| `--watch-promote-after` | `2`             | Healthy cycles required before promotion         |
| `--watch-demote-after` | `2`              | Unhealthy cycles required before demotion        |
| `--watch-switch-margin` | `0.10`           | Minimum relative score improvement before switch |
| `--watch-cooldown-cycles` | `2`            | Minimum cycles between recommendation changes    |
| `--watch-state`         | config directory | Restart-safe watch state path                    |
| `--watch-new-sample`    | off              | Discard persisted watch targets and resample     |

## Output

At startup, cleanscan performs a best-effort lookup of the current public IP,
origin ASN, and ISP name through `ipwho.is`. The TUI shows these values in its dashboard and
speed-test headers; CLI mode prints them to stderr so tabular stdout remains
pipe-friendly. If the lookup is unavailable, the scan continues and displays
`—`/`unknown` instead.

All sampled IPs are shown, including targets with no successful probes. Probes are scheduled one
at a time per IP: successful IPs receive priority for their remaining probes,
unexplored IPs are preferred over IPs that have failed, and original order is
used as a deterministic tie-breaker. CLI results are ranked by recommendation score (descending), then success
rate, `p95`, jitter, packet loss, and average latency as deterministic tie-breakers. Each row reports `ok`/`fail` counts and `avg`,
`p50`, `p90`, `p95`, and `max` latency in seconds, the `jitter` spread in seconds
(`p95 − p50`, a stability signal robust to single outliers), the `loss` count
and `pkt_loss` percentage (probes dropped with no response — timeouts and
connect/TLS failures, distinct from application-level HTTP errors), followed by
individual successful probe samples in the `samples` column. The `colo` column
shows the Cloudflare datacenter code parsed from `/cdn-cgi/trace` (when probing
that path), and `cold_ms` reports the one-off TCP + TLS connection-establishment
time captured by the warmup probe. Only the top `N` rows are printed, where `N`
is controlled by `--top`.

Completed scans show a decision summary with READY, DEGRADED, and FAILED
counts, a recommended target, backups, success rate, p95 latency, and
confidence. The selected-IP details modal supports `1`–`5` / `Tab` tabs for
overview, failure diagnostics, latency distribution, speed context, and
latency map.

When validation options are configured, a probe is counted as successful only
when its status, required headers, and required body markers all match. A
validation failure remains in the result diagnostics, contributes to the
completed/failed counts, lowers the success rate, and does not contribute a
successful latency sample. In watch mode, structured `alert`
events are emitted for health loss, recommendation changes, configured p95 or
packet-loss regressions, and colo changes. `--manifest` writes the current
healthy primary and backup pool only after a completed scan; the JSON file is
updated atomically and contains the validation policy and target metrics.

The Review screen shows the random seed and exact deduplicated target count.
Press `s` for a new sample or `c` to save the exact targets to
`cleanscan_targets_<seed>.txt`.

The TUI displays the same latency statistics. Its save action writes the top
successful results to a timestamped
`cleanscan_<timestamp>.tsv` file in the current directory.

CIDR ranges are sampled randomly, so overlapping samples may produce fewer
unique targets than `sample-per-cidr` suggests. Each probe is an HTTPS request
to the configured host and path, using the candidate IP for the connection
while retaining the hostname for TLS SNI and the Host header. Selected ports
are probed independently; results remain one row per IP and use the best
healthy port as the summary while preserving per-port details in structured
output. Before the counted latency probes, cleanscan sends one discarded warmup
probe per IP and port so
the TCP + TLS connection is established; the reported `avg`/`p50`/`p90`/`p95`/`max`
latencies reflect steady-state RTT rather than connection-setup cost, and the
one-off cold-request latency is reported separately as `cold_ms`. Pass
`--no-warmup`, and the first measured probe includes connection setup while later
probes may reuse the connection. Results are ranked by recommendation score
descending, then success rate, p95, jitter, packet loss, and average latency; failures include categorized diagnostics
in the details view and machine-readable output. The recommendation `score`
(and therefore the TUI's default order and the CLI's top results) blends
reliability with latency, jitter, and packet loss, so a slightly slower but
steadier, loss-free IP outranks a fast-but-jittery or lossy one.

With multiple checks, each path is probed against the same IP, but each check
uses its own HTTP client and warmup request. Required checks gate manifest
eligibility, and the displayed reliability and latency summary is the worst
required check, so thresholds cannot hide a slow or unreliable required path.
The aggregate score remains the weighted mean of all check scores, while the
serialized `checks` entries retain each check's full statistics.

When two-phase sampling is enabled, `two_phase_focus_cidrs` controls the
maximum number of eligible CIDRs used for the focus pass. Its default value of
`0` means all eligible CIDRs; it is independent of `top`, which only limits
displayed results. A discarded cold-probe success contributes to reliability
but never to steady-state latency statistics. Recommendation latency uses p95
with a capped max-tail contribution, preventing one extreme outlier from
dominating the ranking.

Watch mode freezes its exact sampled target list on the first cycle and reuses
it after restart when the source and health profile are unchanged. Use
`--watch-new-sample` to intentionally replace it.

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

When `--proxy-url` is supplied in CLI mode, cleanscan parses only the
transport-safe parts of a VLESS/Trojan share URL: destination port, TLS/SNI,
network type, and WebSocket host/path. It then checks the top healthy latency
candidates for TCP connectivity, TLS negotiation, a short long-lived TLS idle
hold, and WebSocket endpoint reachability when applicable. This is a transport
survivability check, not a VLESS/Trojan authentication or full-tunnel test; no
Xray process is started and UUIDs/passwords are not printed.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

MIT
