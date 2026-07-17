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

## Build

```sh
cargo build --release
```

> If your environment cannot reach the crates.io git index, force the sparse
> protocol: `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo build`.

## Install

Download a prebuilt static binary (Linux x86_64 / aarch64, macOS) from the
latest GitHub release:

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
CLEANASCAN_VERSION=v1.0.0 bash -c 'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'

# Install to a custom directory
INSTALL_DIR=/opt/bin bash -c 'curl -sSfL https://raw.githubusercontent.com/nexuslibs/cleanscan/main/install.sh | bash'
```

## Usage

```sh
# TUI mode (default)
cleanscan --cidr 188.114.96.0/20 --cidr 104.16.0.0/13

# Provide a file of IPs / CIDRs (one per line, # comments allowed)
cleanscan --ips ips.txt

# Pipe-friendly tab-separated output
cleanscan --cli --cidr 188.114.96.0/20 --top 20
```

### TUI controls

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

Results are ranked by: failure count (ascending), then `p95`, `max`, and `avg`
latency (all ascending). Each row reports `ok`/`fail` counts and `avg`, `p50`,
`p90`, `p95`, and `max` latency in seconds.

## License

MIT
