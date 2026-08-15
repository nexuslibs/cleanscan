mod adaptive;
mod colo;
mod config;
mod discovery;
mod iface;
mod proxy;
mod scanner;
mod speed;
#[cfg(feature = "syn")]
mod syn;
mod system_info;
mod tui;
mod updater;
mod watch;

use clap::{Parser, Subcommand};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use config::{validate_ports, AppConfig, DiscoveryDriver, HealthCheck};
use futures::StreamExt;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Cloudflare IP scanner / latency prober")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Use CLI output mode (tab-separated) instead of TUI
    #[arg(long)]
    pub cli: bool,

    /// Skip the best-effort public IP and network metadata lookup.
    #[arg(long)]
    pub no_network_info: bool,

    /// Hostname used for HTTPS/SNI/Host header
    #[arg(long)]
    pub host: Option<String>,

    /// Path to test
    #[arg(long)]
    pub path: Option<String>,

    /// Cloudflare HTTPS port to probe. Repeatable; defaults to 443.
    #[arg(long = "port")]
    pub ports: Vec<u16>,

    /// Additional health check in NAME=PATH form. Global validation flags apply.
    #[arg(long = "check")]
    pub checks: Vec<String>,

    /// Mark the named --check as optional (required=false). Repeatable.
    #[arg(long = "check-optional")]
    pub check_optional: Vec<String>,

    /// Set the weight of the named --check in NAME=WEIGHT form. Repeatable.
    #[arg(long = "check-weight")]
    pub check_weights: Vec<String>,

    /// Expected HTTP status code. Repeat to allow multiple statuses; empty means any 2xx.
    #[arg(long = "expect-status")]
    pub expected_statuses: Vec<u16>,

    /// Literal substring required in the response body. Repeatable.
    #[arg(long = "require-body")]
    pub required_body_markers: Vec<String>,

    /// Exact required response header in name=value form. Repeatable.
    #[arg(long = "require-header")]
    pub required_headers: Vec<String>,

    /// Follow redirects instead of treating them as validation failures.
    #[arg(long)]
    pub follow_redirects: bool,

    /// Optional file containing candidate IPs and/or CIDRs, one per line
    #[arg(long)]
    pub ips: Option<String>,

    /// File containing the exact target list for a reproducible run
    #[arg(long)]
    pub targets_file: Option<String>,

    /// CIDR to sample. Can be repeated
    #[arg(long)]
    pub cidr: Vec<String>,

    /// Number of random IPs to sample from each CIDR
    #[arg(long)]
    pub sample_per_cidr: Option<usize>,

    /// Discovery driver for the target set: sampling (random per-CIDR sample),
    /// connect (full-range TCP connect sweep for reachable ports), or syn
    /// (raw SYN sweep; requires root and a build with the `syn` feature).
    #[arg(long, value_parser = ["sampling", "connect", "syn"])]
    pub discover: Option<String>,

    /// Network interface for probes, discovery, and speed tests (e.g. en0);
    /// defaults to auto (OS route selection). For `--discover syn` this also
    /// selects the capture device.
    #[arg(long)]
    pub interface: Option<String>,

    /// Xray-style TLS fragment JSON applied to --proxy-url protocol checks and
    /// the TUI fragment tester (e.g. '{"packets":"tlshello","length":"100-200","interval":"10-20"}')
    #[arg(long = "tls-fragment")]
    pub tls_fragment: Option<String>,

    /// List network interfaces with their IP addresses, then exit.
    #[arg(long)]
    pub list_interfaces: bool,

    /// Pacing for the raw SYN sweep (`--discover syn`) in packets per second.
    #[arg(long)]
    pub rate: Option<u32>,

    /// Extra retransmit passes per window for the raw SYN sweep (`--discover syn`).
    #[arg(long)]
    pub syn_retrans: Option<u32>,

    /// Number of repeated probes per IP
    #[arg(long)]
    pub probes: Option<usize>,

    /// Max concurrent HTTP probes
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Request timeout in milliseconds
    #[arg(long)]
    pub timeout_ms: Option<u64>,

    /// Connect timeout in milliseconds
    #[arg(long)]
    pub connect_timeout_ms: Option<u64>,

    /// Print only top N results
    #[arg(long)]
    pub top: Option<usize>,

    /// Reproducible sampling seed
    #[arg(long)]
    pub seed: Option<u64>,

    /// Output format in CLI mode
    #[arg(long, default_value = "tsv", value_parser = ["tsv", "json", "ndjson"])]
    pub format: String,

    /// Write CLI results to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// VLESS/Trojan share URL whose transport settings should be checked
    #[arg(long)]
    pub proxy_url: Option<String>,

    /// Number of healthy latency candidates to transport-check
    #[arg(long, default_value_t = 10)]
    pub protocol_check_top: usize,

    /// Minimum per-target probe success rate required for a healthy run
    #[arg(long)]
    pub min_success_rate: Option<f64>,

    /// Maximum recommended p95 latency in milliseconds
    #[arg(long)]
    pub max_p95_ms: Option<f64>,

    /// Exit with an error when no target meets the configured thresholds
    #[arg(long)]
    pub fail_if_no_healthy_target: bool,

    /// Only report IPs in the given Cloudflare datacenter (e.g. FRA)
    #[arg(long)]
    pub colo: Option<String>,

    /// Only report IPs in the given country (substring match, e.g. "Germany")
    #[arg(long)]
    pub country: Option<String>,

    /// Skip the connection-establishment warmup probe (first counted probe includes connection time)
    #[arg(long)]
    pub no_warmup: bool,

    /// Weight applied to latency jitter when ranking results (higher penalizes variable-latency IPs)
    #[arg(long)]
    pub stability_weight: Option<f64>,

    /// Weight applied to packet loss when ranking results (higher penalizes lossy IPs)
    #[arg(long)]
    pub loss_weight: Option<f64>,

    /// Disable fail-fast early stopping: probe every target for the full
    /// `--probes` count even when it is clearly dead or clearly worse.
    #[arg(long)]
    pub no_early_stop: bool,

    /// Consecutive dropped probes after which a target is declared dead.
    #[arg(long)]
    pub early_stop_loss_streak: Option<usize>,

    /// Minimum measured probes before any early-stop rule may fire.
    #[arg(long)]
    pub early_stop_min_samples: Option<usize>,

    /// Success rate below which a target is abandoned once enough probes ran.
    #[arg(long)]
    pub early_stop_success_floor: Option<f64>,

    /// Disable pruning of targets that cannot beat the current top-N.
    #[arg(long)]
    pub no_early_stop_prune: bool,

    /// Tolerance for a target being worse than the worst top-N candidate before pruning.
    #[arg(long)]
    pub early_stop_prune_margin: Option<f64>,

    /// Run a sparse discovery pass first, then focus probing on the CIDRs that
    /// produced the best Cloudflare colos (two-phase, colo-aware sampling).
    #[arg(long)]
    pub two_phase: bool,

    /// Fraction of `sample_per_cidr` used for the discovery pass with `--two-phase`.
    #[arg(long)]
    pub discover_fraction: Option<f64>,

    /// Enable confidence-aware adaptive probing.
    #[arg(long)]
    pub adaptive_probing: bool,

    /// Minimum measured probes per target in adaptive mode.
    #[arg(long)]
    pub min_probes: Option<usize>,

    /// Maximum measured probes per target in adaptive mode.
    #[arg(long)]
    pub max_probes: Option<usize>,

    /// Enable adaptive worker concurrency.
    #[arg(long)]
    pub adaptive_concurrency: bool,

    /// Minimum workers in adaptive concurrency mode.
    #[arg(long)]
    pub min_concurrency: Option<usize>,

    /// Maximum workers in adaptive concurrency mode.
    #[arg(long)]
    pub max_concurrency: Option<usize>,

    /// Confidence level for adaptive intervals (0.90, 0.95, or 0.99).
    #[arg(long, value_parser = ["0.90", "0.95", "0.99"])]
    pub confidence: Option<String>,

    /// Repeat scans every N seconds using the same exact target list.
    #[arg(long)]
    pub watch: Option<u64>,

    /// Write the ranked healthy primary/backup manifest atomically after each scan.
    #[arg(long)]
    pub manifest: Option<String>,

    /// Number of backup targets to include in the manifest.
    #[arg(long, default_value_t = 3)]
    pub manifest_backups: usize,

    /// Minimum confidence label required for manifest targets (UNKNOWN, LOW, MEDIUM, HIGH).
    #[arg(long, default_value = "UNKNOWN", value_parser = ["UNKNOWN", "LOW", "MEDIUM", "HIGH"])]
    pub manifest_min_confidence: String,

    /// Alert when recommended p95 rises by at least this many milliseconds between watch cycles.
    #[arg(long)]
    pub alert_p95_increase_ms: Option<f64>,

    /// Alert when recommended packet loss rises by at least this fraction between watch cycles.
    #[arg(long)]
    pub alert_packet_loss_increase: Option<f64>,

    /// Exit watch mode when an alert is emitted.
    #[arg(long)]
    pub fail_on_alert: bool,

    /// Require this many consecutive healthy cycles before promotion.
    #[arg(long, default_value_t = 2)]
    pub watch_promote_after: u32,

    /// Require this many consecutive unhealthy cycles before demotion.
    #[arg(long, default_value_t = 2)]
    pub watch_demote_after: u32,

    /// Minimum score improvement required before switching a healthy primary.
    #[arg(long, default_value_t = 0.10)]
    pub watch_switch_margin: f64,

    /// Minimum cycles between recommendation changes.
    #[arg(long, default_value_t = 2)]
    pub watch_cooldown_cycles: u64,

    /// Persisted watch state path. Defaults to the cleanscan config directory.
    #[arg(long)]
    pub watch_state: Option<String>,

    /// Discard persisted watch targets and start a fresh random sample.
    #[arg(long)]
    pub watch_new_sample: bool,

    /// Disable the best-effort release check performed on normal runs.
    #[arg(long)]
    pub no_update_check: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Check for and install the latest compatible release.
    Update {
        /// Check for an update without installing it.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    if let Some(Command::Update { check }) = args.command.clone() {
        return updater::run_explicit(check);
    }
    if args.list_interfaces {
        for entry in iface::list_interfaces()? {
            let addresses = entry
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let vpn = if iface::is_vpn_interface(&entry.name) {
                "\tVPN"
            } else {
                ""
            };
            println!("{}\t{addresses}{vpn}", entry.name);
        }
        return Ok(());
    }
    let mut update_receiver =
        if args.no_update_check || std::env::var_os("CLEANSCAN_NO_UPDATE_CHECK").is_some() {
            None
        } else {
            Some(updater::start_background_check())
        };
    let mut config = config::load_config();

    if let Some(host) = args.host {
        config.host = host;
    }
    let explicit_path = args.path.is_some();
    if explicit_path && (!args.checks.is_empty() || !config.health_checks.is_empty()) {
        anyhow::bail!(
            "--check/health checks cannot be combined with --path; put the primary path in --check"
        );
    }
    if let Some(path) = args.path {
        config.path = path;
    }
    if !args.ports.is_empty() {
        config.ports = validate_ports(&args.ports).map_err(anyhow::Error::msg)?;
    } else {
        config.ports = validate_ports(&config.ports).unwrap_or_else(|_| vec![443]);
    }
    if !args.checks.is_empty() {
        config.health_checks = args
            .checks
            .iter()
            .map(|value| parse_health_check(value))
            .collect::<Result<Vec<_>>>()?;
    }
    for name in &args.check_optional {
        let check = config
            .health_checks
            .iter_mut()
            .find(|check| check.name == *name)
            .ok_or_else(|| anyhow::anyhow!("--check-optional {name:?} does not match a --check"))?;
        check.required = false;
    }
    for expression in &args.check_weights {
        let (name, weight) = expression.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--check-weight must use NAME=WEIGHT form, got {expression:?}")
        })?;
        let weight = weight
            .trim()
            .parse::<f64>()
            .map_err(|_| anyhow::anyhow!("--check-weight for {name:?} must be a number"))?;
        if !weight.is_finite() || weight < 0.0 {
            anyhow::bail!("--check-weight for {name:?} must be non-negative");
        }
        let check = config
            .health_checks
            .iter_mut()
            .find(|check| check.name == name)
            .ok_or_else(|| anyhow::anyhow!("--check-weight {name:?} does not match a --check"))?;
        check.weight = weight;
    }
    if !args.expected_statuses.is_empty() {
        config.expected_statuses = args.expected_statuses.clone();
    }
    if !args.required_body_markers.is_empty() {
        config.required_body_markers = args.required_body_markers.clone();
    }
    if !args.required_headers.is_empty() {
        config.required_headers = args.required_headers.clone();
    }
    if args.follow_redirects {
        config.follow_redirects = true;
    }
    if let Some(sample_per_cidr) = args.sample_per_cidr {
        config.sample_per_cidr = sample_per_cidr;
    }
    if let Some(driver) = args.discover.as_deref() {
        config.discovery_driver = driver.parse().map_err(anyhow::Error::msg)?;
    }
    config.interface = crate::iface::normalize_interface(args.interface.clone());
    if let Some(raw) = args.tls_fragment.as_deref() {
        config.tls_fragment = if raw.trim().is_empty() {
            None
        } else {
            Some(crate::proxy::FragmentSpec::parse_json(raw).map_err(|e| {
                anyhow::anyhow!(
                    "--tls-fragment: {e}; expected an xray fragment object like \
                     {{\"packets\":\"tlshello\",\"length\":\"100-200\",\"interval\":\"10-20\"}}"
                )
            })?)
        };
        if args.cli && config.tls_fragment.is_some() && args.proxy_url.is_none() {
            eprintln!(
                "warning: --tls-fragment is only applied to --proxy-url protocol checks; \
                 without a proxy URL, fragmentation will not be applied"
            );
        }
    }
    if let Some(rate) = args.rate {
        if rate == 0 || rate > 1_000_000 {
            anyhow::bail!("--rate must be between 1 and 1000000");
        }
        config.syn_rate = rate;
    }
    if let Some(retrans) = args.syn_retrans {
        if retrans > 10 {
            anyhow::bail!("--syn-retrans must be between 0 and 10");
        }
        config.syn_retransmits = retrans;
    }
    if let Some(probes) = args.probes {
        config.probes = probes;
    }
    if let Some(concurrency) = args.concurrency {
        config.concurrency = concurrency;
    }
    if let Some(timeout_ms) = args.timeout_ms {
        config.timeout_ms = timeout_ms;
    }
    if let Some(connect_timeout_ms) = args.connect_timeout_ms {
        config.connect_timeout_ms = connect_timeout_ms;
    }
    if let Some(top) = args.top {
        config.top = top;
    }
    if let Some(seed) = args.seed {
        config.seed = seed;
    }
    if args.no_warmup {
        config.warmup = false;
    }
    if let Some(weight) = args.stability_weight {
        config.stability_weight = weight;
    }
    if let Some(weight) = args.loss_weight {
        config.loss_weight = weight;
    }
    if args.no_early_stop {
        config.early_stop = false;
    }
    if let Some(streak) = args.early_stop_loss_streak {
        config.early_stop_loss_streak = streak;
    }
    if let Some(min) = args.early_stop_min_samples {
        config.early_stop_min_samples = min;
    }
    if let Some(floor) = args.early_stop_success_floor {
        config.early_stop_success_floor = floor;
    }
    if args.no_early_stop_prune {
        config.early_stop_prune = false;
    }
    if let Some(margin) = args.early_stop_prune_margin {
        config.early_stop_prune_margin = margin;
    }
    if args.two_phase {
        config.two_phase = true;
    }
    if let Some(fraction) = args.discover_fraction {
        if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            anyhow::bail!("--discover-fraction must be a finite value between 0.0 and 1.0");
        }
        config.discover_fraction = fraction;
    }
    if args.adaptive_probing {
        config.adaptive_probing = true;
    }
    if let Some(min) = args.min_probes {
        config.min_probes = min;
    }
    if let Some(max) = args.max_probes {
        config.max_probes = max;
    }
    if args.min_concurrency == Some(0) || args.max_concurrency == Some(0) {
        anyhow::bail!(
            "adaptive concurrency bounds are invalid: max must be >= min and both must be non-zero"
        );
    }
    if args.adaptive_concurrency {
        config.adaptive_concurrency = true;
    }
    if let Some(min) = args.min_concurrency {
        config.min_concurrency = min;
    }
    if let Some(max) = args.max_concurrency {
        config.max_concurrency = max;
    }
    if let Some(confidence) = args.confidence.as_deref() {
        config.confidence = confidence.parse()?;
    }

    if !config.stability_weight.is_finite() || config.stability_weight < 0.0 {
        anyhow::bail!("--stability-weight must be a finite, non-negative value");
    }
    let mut check_names = std::collections::BTreeSet::new();
    for check in &config.health_checks {
        if check.name.trim().is_empty()
            || check.path.trim().is_empty()
            || !check.path.starts_with('/')
        {
            anyhow::bail!("health checks require a non-empty name and absolute path");
        }
        if !check_names.insert(check.name.to_ascii_lowercase()) {
            anyhow::bail!("duplicate health check name: {}", check.name);
        }
        if !check.weight.is_finite() || check.weight < 0.0 {
            anyhow::bail!("health check weights must be finite and non-negative");
        }
    }
    if !config.loss_weight.is_finite() || config.loss_weight < 0.0 {
        anyhow::bail!("--loss-weight must be a finite, non-negative value");
    }
    if !(0.0..=1.0).contains(&config.confidence)
        || !config.confidence.is_finite()
        || !matches!(config.confidence, 0.90 | 0.95 | 0.99)
    {
        anyhow::bail!("--confidence must be exactly 0.90, 0.95, or 0.99");
    }
    if config.min_probes == 0 || config.max_probes < config.min_probes {
        anyhow::bail!(
            "adaptive probe bounds are invalid: max must be >= min and both must be non-zero"
        );
    }
    normalize_config(&mut config);
    if config.max_concurrency < config.min_concurrency {
        anyhow::bail!(
            "adaptive concurrency bounds are invalid: max must be >= min and both must be non-zero"
        );
    }
    if args.watch.is_some() && config.two_phase {
        anyhow::bail!("--watch cannot be combined with --two-phase");
    }
    if config.discovery_driver == DiscoveryDriver::Syn && args.discover.is_some() {
        #[cfg(not(feature = "syn"))]
        anyhow::bail!(
            "--discover syn requires a build with the `syn` cargo feature: `cargo build --features syn`"
        );
        #[cfg(feature = "syn")]
        if !syn::is_root() {
            anyhow::bail!(
                "--discover syn requires root privileges (raw sockets); run as root or with sudo"
            );
        }
    }
    if config.discovery_driver != DiscoveryDriver::Syn
        && (args.rate.is_some() || args.syn_retrans.is_some())
    {
        anyhow::bail!("--rate and --syn-retrans require --discover syn");
    }
    if let Some(name) = config.interface.as_deref() {
        if let Err(error) = iface::validate_interface(name) {
            if args.interface.is_some() {
                return Err(error);
            }
            eprintln!(
                "warning: {error}; reverting to auto routing (remove `interface` from config.json to silence this)"
            );
            config.interface = None;
        }
    }
    if config.discovery_driver != DiscoveryDriver::Sampling && config.two_phase {
        anyhow::bail!("--discover cannot be combined with --two-phase");
    }
    if args.cli && args.watch.is_some() && args.format != "ndjson" {
        anyhow::bail!("--watch requires --cli --format ndjson");
    }
    if args.watch == Some(0) {
        anyhow::bail!("--watch must be at least 1 second");
    }
    if !args.cli && (args.format != "tsv" || args.output.is_some()) {
        anyhow::bail!("--format and --output require --cli");
    }
    if let Some(value) = args.alert_p95_increase_ms {
        if !value.is_finite() || value < 0.0 {
            anyhow::bail!("--alert-p95-increase-ms must be finite and non-negative");
        }
    }
    if let Some(value) = args.alert_packet_loss_increase {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            anyhow::bail!("--alert-packet-loss-increase must be between 0 and 1");
        }
    }
    if config
        .expected_statuses
        .iter()
        .any(|status| !(100..=599).contains(status))
    {
        anyhow::bail!("--expect-status values must be between 100 and 599");
    }
    if config
        .required_headers
        .iter()
        .any(|value| !value.contains('='))
    {
        anyhow::bail!("required headers must use name=value form");
    }

    if let Some(min) = args.min_success_rate {
        if !min.is_finite() || !(0.0..=1.0).contains(&min) {
            anyhow::bail!("--min-success-rate must be a finite value between 0.0 and 1.0");
        }
    }
    if let Some(max) = args.max_p95_ms {
        if !max.is_finite() || max < 0.0 {
            anyhow::bail!("--max-p95-ms must be a finite, non-negative value");
        }
    }
    if !args.watch_switch_margin.is_finite() || args.watch_switch_margin < 0.0 {
        anyhow::bail!("--watch-switch-margin must be finite and non-negative");
    }
    if args.watch_promote_after == 0 || args.watch_demote_after == 0 {
        anyhow::bail!("watch promotion and demotion thresholds must be non-zero");
    }

    if args.targets_file.is_some() && (args.ips.is_some() || !args.cidr.is_empty()) {
        anyhow::bail!("--targets-file cannot be combined with --ips or --cidr");
    }
    if config.discovery_driver != DiscoveryDriver::Sampling && args.targets_file.is_some() {
        anyhow::bail!("--discover cannot be combined with --targets-file");
    }
    if !args.cli && args.targets_file.is_some() {
        anyhow::bail!("--targets-file requires --cli");
    }
    if config.host.is_empty()
        && (args.cli || args.ips.is_some() || args.targets_file.is_some() || !args.cidr.is_empty())
    {
        anyhow::bail!(
            "no host configured — pass --host <domain> or set a host in the TUI settings"
        );
    }

    let system_network = system_info::lookup_sync(!args.no_network_info);

    let update_notice = if args.cli {
        update_receiver.take().map(|receiver| {
            std::thread::spawn(move || {
                if let Ok(notice) = receiver.recv() {
                    eprintln!("{notice}");
                }
            })
        })
    } else {
        None
    };

    let watch_policy = watch::WatchPolicy {
        promote_after: args.watch_promote_after,
        demote_after: args.watch_demote_after,
        switch_margin: args.watch_switch_margin,
        cooldown_cycles: args.watch_cooldown_cycles,
    };

    if args.cli {
        eprintln!(
            "System network: ip={} asn={} isp={}",
            system_network.public_ip_display(),
            system_network.asn_display(),
            system_network.isp_display()
        );
        let result = cli_mode(
            config,
            args.cidr,
            args.ips,
            args.targets_file,
            &args.format,
            args.output.as_deref(),
            args.proxy_url.as_deref(),
            args.protocol_check_top,
            args.min_success_rate,
            args.max_p95_ms,
            args.fail_if_no_healthy_target,
            args.seed,
            args.colo,
            args.country,
            args.watch,
            args.manifest,
            args.manifest_backups,
            args.manifest_min_confidence,
            args.alert_p95_increase_ms,
            args.alert_packet_loss_increase,
            args.fail_on_alert,
            watch_policy,
            args.watch_state.as_deref(),
            args.watch_new_sample,
        );
        if let Some(handle) = update_notice {
            let _ = handle.join();
        }
        result
    } else {
        tui::run_tui(
            config,
            args.cidr,
            args.ips,
            args.seed,
            args.watch,
            args.manifest,
            args.min_success_rate,
            args.max_p95_ms,
            args.manifest_min_confidence,
            args.manifest_backups,
            watch_policy,
            args.watch_state.as_deref(),
            args.watch_new_sample,
            update_receiver,
            system_network,
        )
    }
}

fn normalize_config(config: &mut AppConfig) {
    if config.sample_per_cidr == 0 {
        config.sample_per_cidr = 1;
    }
    if config.concurrency == 0 {
        config.concurrency = 1;
    }
    if config.min_concurrency == 0 {
        config.min_concurrency = 1;
    }
    config
        .runtime_min_concurrency
        .store(config.min_concurrency, std::sync::atomic::Ordering::Relaxed);
    if config.max_concurrency == 0 {
        config.max_concurrency = 1;
    }
    if config.probes == 0 {
        config.probes = 1;
    }
}

fn parse_health_check(value: &str) -> Result<HealthCheck> {
    let (name, path) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--check must use NAME=PATH form"))?;
    let name = name.trim();
    let path = path.trim();
    if name.is_empty() || path.is_empty() || !path.starts_with('/') {
        anyhow::bail!("--check must use a non-empty NAME and an absolute PATH");
    }
    Ok(HealthCheck {
        name: name.to_string(),
        path: path.to_string(),
        required: true,
        weight: 1.0,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HealthThresholds {
    min_success_rate: Option<f64>,
    max_p95_ms: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Manifest {
    schema_version: u32,
    generated_at_unix: u64,
    host: String,
    path: String,
    ports: Vec<u16>,
    seed: u64,
    targets: Vec<String>,
    validation: ManifestValidation,
    thresholds: HealthThresholdsOutput,
    primary: Option<scanner::ProbeResult>,
    backups: Vec<scanner::ProbeResult>,
    failure: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManifestValidation {
    expected_statuses: Vec<u16>,
    required_body_markers: Vec<String>,
    required_headers: Vec<String>,
    follow_redirects: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HealthThresholdsOutput {
    min_success_rate: Option<f64>,
    max_p95_ms: Option<f64>,
    min_confidence: String,
}

fn confidence_rank(value: &str) -> u8 {
    match value {
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Multi-port and multi-check scans forward per-port/per-check rows and then
/// the merged aggregate per IP; keep only the latest (merged) row per IP while
/// preserving relative order.
fn dedup_results(mut results: Vec<scanner::ProbeResult>) -> Vec<scanner::ProbeResult> {
    let mut seen = std::collections::HashSet::new();
    results.reverse();
    results.retain(|result| seen.insert(result.ip.clone()));
    results.reverse();
    results
}

fn healthy_result(
    result: &scanner::ProbeResult,
    thresholds: HealthThresholds,
    min_confidence: &str,
) -> bool {
    let required_checks = result
        .checks
        .iter()
        .filter(|check| check.required)
        .collect::<Vec<_>>();
    let success_rate_ok = if required_checks.is_empty() {
        thresholds
            .min_success_rate
            .is_none_or(|min| result.success_rate >= min)
    } else {
        required_checks.iter().all(|check| {
            thresholds
                .min_success_rate
                .is_none_or(|min| check.success_rate >= min)
        })
    };
    let p95_ok = if required_checks.is_empty() {
        thresholds
            .max_p95_ms
            .is_none_or(|max| result.p95 * 1000.0 <= max)
    } else {
        required_checks.iter().all(|check| {
            thresholds
                .max_p95_ms
                .is_none_or(|max| check.p95 * 1000.0 <= max)
        })
    };
    result.ok > 0
        && result.health_ok
        && success_rate_ok
        && p95_ok
        && confidence_rank(scanner::result_confidence(result)) >= confidence_rank(min_confidence)
}

pub(crate) fn build_manifest(
    config: &AppConfig,
    targets: Vec<String>,
    results: &[scanner::ProbeResult],
    thresholds: HealthThresholds,
    min_confidence: &str,
    backup_count: usize,
) -> Manifest {
    let mut healthy: Vec<scanner::ProbeResult> = results
        .iter()
        .filter(|result| healthy_result(result, thresholds, min_confidence))
        .cloned()
        .collect();
    healthy.sort_by(crate::tui::App::natural_cmp);
    let primary = healthy.first().cloned();
    let backups = healthy.into_iter().skip(1).take(backup_count).collect();
    Manifest {
        schema_version: 1,
        generated_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        host: config.host.clone(),
        path: config.path.clone(),
        ports: config.ports.clone(),
        seed: config.seed,
        targets,
        validation: ManifestValidation {
            expected_statuses: config.expected_statuses.clone(),
            required_body_markers: config.required_body_markers.clone(),
            required_headers: config.required_headers.clone(),
            follow_redirects: config.follow_redirects,
        },
        thresholds: HealthThresholdsOutput {
            min_success_rate: thresholds.min_success_rate,
            max_p95_ms: thresholds.max_p95_ms,
            min_confidence: min_confidence.to_string(),
        },
        failure: primary
            .is_none()
            .then(|| "no target met manifest health thresholds".to_string()),
        primary,
        backups,
    }
}

pub(crate) fn write_manifest(path: &str, manifest: &Manifest) -> Result<()> {
    let content = serde_json::to_vec_pretty(manifest)?;
    let target = std::path::Path::new(path);
    let parent = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("manifest.json");
    let temp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        use std::io::Write;
        file.write_all(&content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, target)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Whether `--colo`/`--country` filtering can read the `colo=` field the
/// probe body must expose. The default `/cdn-cgi/trace` path provides it;
/// other paths usually do not, so the filtered output would silently be empty.
fn colo_filter_may_be_empty(path: &str, colo: &Option<String>, country: &Option<String>) -> bool {
    (colo.is_some() || country.is_some()) && !path.contains("cdn-cgi/trace")
}

fn warn_if_colo_filter_uninformative(path: &str, colo: &Option<String>, country: &Option<String>) {
    if colo_filter_may_be_empty(path, colo, country) {
        eprintln!(
            "warning: --colo/--country filters rely on the `colo=` field in the probe body; \
             the configured path {path:?} usually does not expose it, so the filtered output \
             may be empty"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn cli_mode(
    config: AppConfig,
    cidr: Vec<String>,
    ips: Option<String>,
    targets_file: Option<String>,
    format: &str,
    output: Option<&str>,
    proxy_url: Option<&str>,
    protocol_check_top: usize,
    min_success_rate: Option<f64>,
    max_p95_ms: Option<f64>,
    fail_if_no_healthy_target: bool,
    seed: Option<u64>,
    colo: Option<String>,
    country: Option<String>,
    watch: Option<u64>,
    manifest_path: Option<String>,
    manifest_backups: usize,
    manifest_min_confidence: String,
    alert_p95_increase_ms: Option<f64>,
    alert_packet_loss_increase: Option<f64>,
    fail_on_alert: bool,
    watch_policy: watch::WatchPolicy,
    watch_state_path: Option<&str>,
    watch_new_sample: bool,
) -> Result<()> {
    let has_explicit_targets = ips.is_some() || targets_file.is_some();
    let ips_identity = ips.as_deref().and_then(|path| std::fs::read(path).ok());
    let targets_file_identity = targets_file
        .as_deref()
        .and_then(|path| std::fs::read(path).ok());
    let effective_seed = seed
        .or_else(|| (config.seed != 0).then_some(config.seed))
        .unwrap_or_else(rand::random);
    let source_identity = (
        cidr.clone(),
        ips_identity,
        targets_file_identity,
        config.sample_per_cidr,
        config.discovery_driver,
        effective_seed,
    );
    let source_fingerprint = watch::fingerprint(&source_identity);

    let use_discovery = config.discovery_driver != DiscoveryDriver::Sampling;
    let use_two_phase = config.two_phase && !has_explicit_targets && !use_discovery;
    if use_two_phase && !config.health_checks.is_empty() {
        anyhow::bail!("--two-phase cannot be combined with configured health checks");
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let config_arc = Arc::new(config.clone());
    let selected_cidrs: Vec<String> = if !cidr.is_empty() {
        cidr.clone()
    } else {
        config.selected_cidrs.clone()
    };
    // The sweep enumerates CIDRs fully; when only an --ips file is given,
    // nothing else may be pulled in, and without any explicit source the
    // configured CIDR selection is the sweep range.
    let sweep_cidrs: Vec<String> = if !cidr.is_empty() {
        cidr.clone()
    } else if ips.is_some() {
        Vec::new()
    } else {
        config.selected_cidrs.clone()
    };
    let rt = tokio::runtime::Runtime::new()?;

    let targets = if use_discovery {
        let sources = discovery::parse_target_sources(ips.as_deref(), &sweep_cidrs)?;
        let total_addresses = discovery::enumerated_address_count(&sources);
        match config.discovery_driver {
            DiscoveryDriver::Connect => eprintln!(
                "Connect discovery: {} candidate addresses × {} ports, concurrency={}",
                total_addresses,
                config.ports.len().max(1),
                config.concurrency
            ),
            DiscoveryDriver::Syn => eprintln!(
                "SYN discovery: {} candidate addresses × {} ports, rate={} pps, retransmits={}{}",
                total_addresses,
                config.ports.len().max(1),
                config.syn_rate,
                config.syn_retransmits,
                config
                    .interface
                    .as_deref()
                    .map(|interface| format!(", interface={interface}"))
                    .unwrap_or_default()
            ),
            DiscoveryDriver::Sampling => unreachable!("discovery branch reached in sampling mode"),
        }
        let driver_label = match config.discovery_driver {
            DiscoveryDriver::Connect => "connect",
            DiscoveryDriver::Syn => "syn",
            DiscoveryDriver::Sampling => unreachable!("discovery branch reached in sampling mode"),
        };
        let discovered = rt.block_on(scanner::run_discovery(
            sweep_cidrs,
            ips.clone(),
            config_arc.clone(),
            None,
            Arc::new(AtomicBool::new(false)),
        ))?;
        if discovered.is_empty() {
            anyhow::bail!("{driver_label} discovery found no reachable targets");
        }
        eprintln!(
            "Discovery sweep complete: {} reachable target(s)",
            discovered.len()
        );
        discovered
    } else if let Some(path) = targets_file {
        scanner::load_ip_manifest(&path)?
    } else {
        scanner::collect_targets_with_optional_seed(&config, &cidr, &ips, Some(effective_seed))?
    };
    if let Some(interval) = watch {
        return cli_watch(
            config,
            targets,
            interval,
            min_success_rate,
            max_p95_ms,
            fail_if_no_healthy_target,
            colo,
            country,
            manifest_path,
            manifest_backups,
            manifest_min_confidence,
            alert_p95_increase_ms,
            alert_packet_loss_increase,
            fail_on_alert,
            watch_policy,
            watch_state_path,
            watch_new_sample,
            source_fingerprint,
        );
    }
    let mut manifest_targets = targets.clone();
    let total = targets.len();

    if !use_two_phase {
        eprintln!(
            "Testing {} targets × {} probes × {} ports ({:?}), concurrency={}",
            total,
            config.probes,
            config.ports.len(),
            config.ports,
            config.concurrency
        );
    }

    if use_two_phase {
        manifest_targets = rt.block_on(scanner::run_scan_two_phase(
            selected_cidrs,
            config_arc,
            colo.clone(),
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ))?;
    } else {
        rt.block_on(scanner::run_profile_scan(
            targets,
            config_arc,
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ));
    }

    // Keep fully failed targets in machine-readable output so callers can
    // inspect their categorized diagnostics and distinguish them from targets
    // that were never sampled.
    let mut results: Vec<scanner::ProbeResult> = dedup_results(rx.iter().collect());

    warn_if_colo_filter_uninformative(&config.path, &colo, &country);
    if let Some(colo) = &colo {
        let want = colo.to_ascii_uppercase();
        results.retain(|r| {
            r.colo
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case(&want))
        });
    }

    if let Some(country) = &country {
        let want = country.to_lowercase();
        results.retain(|r| {
            r.country
                .as_deref()
                .is_some_and(|c| c.to_lowercase().contains(&want))
        });
    }

    results.sort_by(crate::tui::App::natural_cmp);

    if let Some(raw_proxy_url) = proxy_url {
        let transport = proxy::parse_share_url(raw_proxy_url)?;
        if config.tls_fragment.is_some() && !transport.tls {
            eprintln!(
                "warning: --tls-fragment requires a TLS transport; fragmentation is disabled for this proxy URL"
            );
        }
        let interface =
            config
                .interface
                .as_deref()
                .and_then(|name| match iface::interface_addrs(name) {
                    Ok(addrs) => Some(addrs),
                    Err(error) => {
                        eprintln!("warning: {error}; proxy checks will use auto routing");
                        None
                    }
                });
        let checks = results
            .iter()
            .filter(|result| result.ok > 0)
            .take(protocol_check_top)
            .map(|result| {
                proxy::check_candidate_fragmented(
                    &transport,
                    &result.ip,
                    config.timeout_ms,
                    interface,
                    config.tls_fragment.as_ref(),
                )
            })
            .collect::<Vec<_>>();
        let checks = rt.block_on(
            futures::stream::iter(checks)
                .buffer_unordered(config.concurrency.max(1))
                .collect::<Vec<_>>(),
        );
        eprintln!(
            "protocol transport: {} {}:{} via {} (top {}){}",
            transport.protocol,
            transport.address,
            transport.port,
            transport.network,
            protocol_check_top,
            if transport.tls {
                match &config.tls_fragment {
                    Some(spec) => format!(", fragment {}", spec.xray_json()),
                    None => String::new(),
                }
            } else {
                String::new()
            }
        );
        for check in checks {
            eprintln!(
                "protocol_check\tip={}\ttcp={}\ttls={}\tlong_tls={}\tws_reached={}\tws_accepted={}\thttp={}\tcolo={}\telapsed_ms={:.1}\terror={}",
                check.ip,
                check.tcp_ok,
                check.tls_ok,
                check.long_tls_ok,
                check.websocket_reached
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                check.websocket_accepted
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                check.http_ok
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                check.colo.as_deref().unwrap_or("-"),
                check.elapsed_ms,
                check.error.unwrap_or_default()
            );
        }
    }
    let healthy = results.iter().any(|result| {
        healthy_result(
            result,
            HealthThresholds {
                min_success_rate,
                max_p95_ms,
            },
            &manifest_min_confidence,
        )
    });
    let health_error = fail_if_no_healthy_target && !healthy;

    let rows = results.iter().take(config.top).collect::<Vec<_>>();
    if results.len() > config.top {
        eprintln!(
            "warning: {} results truncated to --top {}; pass --top to show more",
            results.len(),
            config.top
        );
    }
    let rendered = match format {
        "json" => serde_json::to_string_pretty(&rows)?,
        "ndjson" => rows
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n"),
        _ => {
            let mut text = String::from("rank\tip\tport\tcolo\tcountry\tprotocol\tok\tfail\tsuccess_rate\tconfidence\tavg\tp50\tp90\tp95\tmax\tjitter\tloss\tpkt_loss\tcold_ms\tmin_score\tmax_score\tsamples\tfailures\tdiagnostics\n");
            for (i, r) in rows.iter().enumerate() {
                let samples = r
                    .samples
                    .iter()
                    .map(|x| format!("{:.3}", x))
                    .collect::<Vec<_>>()
                    .join(",");
                let diagnostics = r
                    .diagnostics
                    .iter()
                    .map(|diagnostic| format!("{:?}:{}", diagnostic.category, diagnostic.message))
                    .collect::<Vec<_>>()
                    .join(",");

                text.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{:.1}\t{}\t{:.5}\t{:.5}\t{}\t{}\t{}\n",
                    i + 1,
                    r.ip,
                    r.port,
                    r.colo.clone().unwrap_or_default(),
                    r.country.clone().unwrap_or_default(),
                    r.protocol,
                    r.ok,
                    r.fail,
                    r.success_rate,
                    scanner::result_confidence(r),
                    r.avg,
                    r.p50,
                    r.p90,
                    r.p95,
                    r.max,
                    r.jitter,
                    r.loss,
                    r.packet_loss * 100.0,
                    r.cold_ms.map(|ms| format!("{:.1}", ms)).unwrap_or_default(),
                    r.min_score,
                    r.max_score,
                    samples,
                    r.failures.join(","),
                    diagnostics
                ));
            }
            text
        }
    };
    if let Some(path) = output {
        std::fs::write(path, rendered)?;
    } else {
        println!("{rendered}");
    }

    if let Some(path) = manifest_path {
        let manifest = build_manifest(
            &config,
            manifest_targets,
            &results,
            HealthThresholds {
                min_success_rate,
                max_p95_ms,
            },
            &manifest_min_confidence,
            manifest_backups,
        );
        write_manifest(&path, &manifest)?;
    }

    if health_error {
        anyhow::bail!("no target met the configured health thresholds");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cli_watch(
    config: AppConfig,
    targets: Vec<String>,
    interval: u64,
    min_success_rate: Option<f64>,
    max_p95_ms: Option<f64>,
    fail_if_no_healthy_target: bool,
    colo: Option<String>,
    country: Option<String>,
    manifest_path: Option<String>,
    manifest_backups: usize,
    manifest_min_confidence: String,
    alert_p95_increase_ms: Option<f64>,
    alert_packet_loss_increase: Option<f64>,
    fail_on_alert: bool,
    watch_policy: watch::WatchPolicy,
    watch_state_path: Option<&str>,
    watch_new_sample: bool,
    source_fingerprint: u64,
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let profile_fingerprint = watch::fingerprint(&(
        config.host.clone(),
        config.path.clone(),
        config.expected_statuses.clone(),
        config.required_body_markers.clone(),
        config.required_headers.clone(),
        config.follow_redirects,
        config.health_checks.clone(),
    ));
    let state_path = watch_state_path
        .map(std::path::PathBuf::from)
        .or_else(|| watch::default_state_path(&config.host, source_fingerprint))
        .ok_or_else(|| anyhow::anyhow!("cannot determine watch state path"))?;
    let state = if !watch_new_sample {
        watch::load(&state_path)
            .filter(|saved| saved.compatible(source_fingerprint, profile_fingerprint))
    } else {
        None
    };
    let (targets, mut watch_state) = if let Some(saved) = state {
        (saved.targets.clone(), saved)
    } else {
        let fresh =
            watch::WatchState::new(source_fingerprint, profile_fingerprint, targets.clone());
        watch::save(&state_path, &fresh)
            .map_err(|error| anyhow::anyhow!("failed to persist watch targets: {error}"))?;
        (fresh.targets.clone(), fresh)
    };
    let mut cycle = watch_state.cycle;
    let thresholds = HealthThresholds {
        min_success_rate,
        max_p95_ms,
    };
    let mut previous_healthy: Option<bool> = None;
    let mut previous_manifest: Option<Manifest> = None;
    loop {
        cycle += 1;
        println!(
            "{}",
            serde_json::json!({"event":"cycle_started", "cycle":cycle, "targets":targets.len()})
        );
        let (tx, rx) = std::sync::mpsc::channel();
        runtime.block_on(scanner::run_profile_scan(
            targets.clone(),
            Arc::new(config.clone()),
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ));
        let mut results: Vec<scanner::ProbeResult> = dedup_results(rx.iter().collect());
        warn_if_colo_filter_uninformative(&config.path, &colo, &country);
        if let Some(want) = &colo {
            results.retain(|r| {
                r.colo
                    .as_deref()
                    .is_some_and(|c| c.eq_ignore_ascii_case(want))
            });
        }
        if let Some(want) = &country {
            let want = want.to_lowercase();
            results.retain(|r| {
                r.country
                    .as_deref()
                    .is_some_and(|c| c.to_lowercase().contains(&want))
            });
        }
        results.sort_by(crate::tui::App::natural_cmp);
        let transition = watch_state.advance(&results, watch_policy, |result| {
            healthy_result(result, thresholds, &manifest_min_confidence)
        });
        let mut manifest_results = results.clone();
        if let Some(stable) = transition.stable_primary.as_deref() {
            manifest_results.sort_by(|a, b| {
                (a.ip != stable)
                    .cmp(&(b.ip != stable))
                    .then_with(|| crate::tui::App::natural_cmp(a, b))
            });
        }
        let manifest = build_manifest(
            &config,
            targets.clone(),
            &manifest_results,
            thresholds,
            &manifest_min_confidence,
            manifest_backups,
        );
        let mut manifest = manifest;
        if let Some(stable) = transition.stable_primary.as_deref() {
            manifest.primary = manifest_results
                .iter()
                .find(|r| r.ip == stable && healthy_result(r, thresholds, &manifest_min_confidence))
                .cloned();
            manifest.backups = manifest_results
                .iter()
                .filter(|r| {
                    r.ip != stable && healthy_result(r, thresholds, &manifest_min_confidence)
                })
                .take(manifest_backups)
                .cloned()
                .collect();
            manifest.failure = manifest
                .primary
                .is_none()
                .then(|| "stable primary is no longer available".to_string());
        } else {
            manifest.primary = None;
            manifest.backups = manifest_results
                .iter()
                .filter(|r| healthy_result(r, thresholds, &manifest_min_confidence))
                .take(manifest_backups)
                .cloned()
                .collect();
            manifest.failure = Some("no stable target met the watch policy".to_string());
        }
        if let Some(path) = &manifest_path {
            write_manifest(path, &manifest)?;
            println!(
                "{}",
                serde_json::json!({"event":"manifest_written", "cycle":cycle, "path":path, "primary":manifest.primary.as_ref().map(|r| &r.ip)})
            );
        }
        let healthy = manifest.primary.is_some();
        let recommendation = transition.stable_primary.clone();
        if let Some(before) = &previous_manifest {
            let before_ips = std::iter::once(before.primary.as_ref().map(|r| r.ip.clone()))
                .chain(before.backups.iter().map(|r| Some(r.ip.clone())))
                .collect::<Vec<_>>();
            let current_ips = std::iter::once(manifest.primary.as_ref().map(|r| r.ip.clone()))
                .chain(manifest.backups.iter().map(|r| Some(r.ip.clone())))
                .collect::<Vec<_>>();
            if before_ips != current_ips {
                println!(
                    "{}",
                    serde_json::json!({"event":"manifest_changed", "cycle":cycle, "primary":recommendation})
                );
            }
        }
        println!(
            "{}",
            serde_json::json!({"event":"cycle_completed", "cycle":cycle, "healthy":healthy, "recommendation":recommendation, "results":results})
        );
        let mut alerts = Vec::new();
        if cycle > 1 && transition.changed {
            let before_ip = previous_manifest
                .as_ref()
                .and_then(|manifest| manifest.primary.as_ref())
                .map(|result| result.ip.clone());
            alerts.push(serde_json::json!({"kind":"recommendation_changed", "from":before_ip, "to":recommendation}));
        }
        if let Some(current) = manifest.primary.as_ref() {
            let baseline = previous_manifest.as_ref().and_then(|manifest| {
                manifest
                    .primary
                    .iter()
                    .chain(manifest.backups.iter())
                    .find(|result| result.ip == current.ip)
            });
            if let Some(before) = baseline {
                if let Some(threshold) = alert_p95_increase_ms {
                    let delta = (current.p95 - before.p95) * 1000.0;
                    if delta >= threshold {
                        alerts.push(serde_json::json!({"kind":"p95_regression", "ip":current.ip, "increase_ms":delta, "threshold_ms":threshold}));
                    }
                }
                if let Some(threshold) = alert_packet_loss_increase {
                    let delta = current.packet_loss - before.packet_loss;
                    if delta >= threshold {
                        alerts.push(serde_json::json!({"kind":"packet_loss_regression", "ip":current.ip, "increase":delta, "threshold":threshold}));
                    }
                }
                if before.colo != current.colo {
                    alerts.push(serde_json::json!({"kind":"colo_changed", "ip":current.ip, "from":before.colo, "to":current.colo}));
                }
            }
        }
        if cycle > 1 && !healthy && previous_healthy != Some(false) {
            alerts.push(serde_json::json!({"kind":"no_healthy_target"}));
        }
        for alert in &alerts {
            println!(
                "{}",
                serde_json::json!({"event":"alert", "cycle":cycle, "alert":alert})
            );
        }
        if cycle > 1 && previous_healthy != Some(healthy) {
            println!(
                "{}",
                serde_json::json!({"event":"target_health_changed", "cycle":cycle, "healthy":healthy})
            );
        }
        let record = serde_json::json!({"schema_version":1, "cycle":cycle, "host":config.host, "path":config.path, "targets":targets, "healthy":healthy, "recommendation":recommendation, "alerts":alerts.clone(), "manifest":manifest, "results":results});
        if let Err(error) = config::append_history(&record) {
            eprintln!("history write failed: {error}");
        }
        watch::save(&state_path, &watch_state)
            .map_err(|error| anyhow::anyhow!("failed to persist watch state: {error}"))?;
        previous_healthy = Some(healthy);
        previous_manifest = Some(manifest);
        let actionable_alert = alerts.iter().any(|alert| {
            alert
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind != "recommendation_changed")
        });
        if (fail_if_no_healthy_target && !healthy) || (fail_on_alert && actionable_alert) {
            println!(
                "{}",
                serde_json::json!({"event":"health_failure", "cycle":cycle, "alerts":alerts})
            );
            return Err(anyhow::anyhow!("watch alert policy triggered"));
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_manifest, colo_filter_may_be_empty, dedup_results, healthy_result, normalize_config,
        write_manifest, Args, Command, HealthThresholds,
    };
    use crate::config::AppConfig;
    use crate::scanner;
    use clap::Parser;

    #[test]
    fn update_subcommands_parse_without_scan_arguments() {
        let args = Args::try_parse_from(["cleanscan", "update", "--check"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Command::Update { check: true })
        ));
    }

    #[test]
    fn update_check_opt_out_flag_parses() {
        let args = Args::try_parse_from(["cleanscan", "--no-update-check"]).unwrap();
        assert!(args.no_update_check);
    }

    #[test]
    fn zero_numeric_values_are_normalized() {
        let mut config = AppConfig {
            sample_per_cidr: 0,
            probes: 0,
            concurrency: 0,
            ..AppConfig::default()
        };
        normalize_config(&mut config);
        assert_eq!(config.sample_per_cidr, 1);
        assert_eq!(config.probes, 1);
        assert_eq!(config.concurrency, 1);
        assert_eq!(config.two_phase_focus_cidrs, 0);
    }

    #[test]
    fn required_check_thresholds_are_all_enforced() {
        let mut result = scanner::ProbeResult {
            ip: "192.0.2.1".to_string(),
            port: 443,
            protocol: "h2".to_string(),
            ok: 8,
            fail: 0,
            completed: 8,
            avg: 0.01,
            p50: 0.01,
            p90: 0.01,
            p95: 0.01,
            max: 0.01,
            jitter: 0.0,
            stddev: 0.0,
            loss: 0,
            packet_loss: 0.0,
            samples: vec![0.01; 8],
            failures: Vec::new(),
            diagnostics: Vec::new(),
            success_rate: 1.0,
            score: 1.0,
            colo: None,
            country: None,
            cold_ms: None,
            stopped_early: false,
            min_score: 1.0,
            max_score: 1.0,
            success_rate_lower: 1.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: vec![
                scanner::CheckResult {
                    name: "primary".to_string(),
                    path: "/health".to_string(),
                    required: true,
                    weight: 1.0,
                    score: 1.0,
                    healthy: true,
                    ok: 8,
                    fail: 0,
                    completed: 8,
                    success_rate: 1.0,
                    avg: 0.01,
                    p50: 0.01,
                    p90: 0.01,
                    p95: 0.01,
                    max: 0.01,
                    jitter: 0.0,
                    stddev: 0.0,
                    packet_loss: 0.0,
                    cold_ms: None,
                    colo: None,
                },
                scanner::CheckResult {
                    name: "secondary".to_string(),
                    path: "/ready".to_string(),
                    required: true,
                    weight: 1.0,
                    score: 1.0,
                    healthy: true,
                    ok: 8,
                    fail: 0,
                    completed: 8,
                    success_rate: 1.0,
                    avg: 0.20,
                    p50: 0.20,
                    p90: 0.20,
                    p95: 0.20,
                    max: 0.20,
                    jitter: 0.0,
                    stddev: 0.0,
                    packet_loss: 0.0,
                    cold_ms: None,
                    colo: None,
                },
            ],
            health_ok: true,
            port_results: Vec::new(),
        };

        assert!(!healthy_result(
            &result,
            HealthThresholds {
                min_success_rate: Some(1.0),
                max_p95_ms: Some(100.0),
            },
            "UNKNOWN"
        ));

        result.checks[1].p95 = 0.05;
        assert!(healthy_result(
            &result,
            HealthThresholds {
                min_success_rate: Some(1.0),
                max_p95_ms: Some(100.0),
            },
            "UNKNOWN"
        ));

        for check in &mut result.checks {
            check.required = false;
        }
        result.success_rate = 0.0;
        result.p95 = 0.20;
        assert!(!healthy_result(
            &result,
            HealthThresholds {
                min_success_rate: Some(1.0),
                max_p95_ms: Some(100.0),
            },
            "UNKNOWN"
        ));
    }

    #[test]
    fn dedup_results_keeps_latest_row_per_ip_in_order() {
        fn row(ip: &str, port: u16) -> scanner::ProbeResult {
            scanner::ProbeResult {
                ip: ip.to_string(),
                port,
                ..unchecked_default_result()
            }
        }
        fn unchecked_default_result() -> scanner::ProbeResult {
            scanner::ProbeResult {
                ip: String::new(),
                port: 0,
                protocol: String::new(),
                ok: 0,
                fail: 0,
                completed: 0,
                avg: 0.0,
                p50: 0.0,
                p90: 0.0,
                p95: 0.0,
                max: 0.0,
                jitter: 0.0,
                stddev: 0.0,
                loss: 0,
                packet_loss: 0.0,
                samples: Vec::new(),
                failures: Vec::new(),
                diagnostics: Vec::new(),
                success_rate: 0.0,
                score: 0.0,
                colo: None,
                country: None,
                cold_ms: None,
                stopped_early: false,
                min_score: 0.0,
                max_score: 0.0,
                success_rate_lower: 0.0,
                success_rate_upper: 0.0,
                score_confidence: 0.95,
                decision: "competitive".to_string(),
                checks: Vec::new(),
                health_ok: false,
                port_results: Vec::new(),
            }
        }

        let input = vec![
            row("10.0.0.1", 443),
            row("10.0.0.2", 443),
            row("10.0.0.1", 8443),
            row("10.0.0.1", 2053),
            row("10.0.0.3", 443),
            row("10.0.0.1", 2053),
        ];
        let deduped = dedup_results(input);
        let ips: Vec<&str> = deduped.iter().map(|r| r.ip.as_str()).collect();
        assert_eq!(ips, ["10.0.0.2", "10.0.0.3", "10.0.0.1"]);
        assert_eq!(deduped[2].port, 2053);
    }

    #[test]
    fn colo_filters_only_warn_when_path_cannot_expose_colo() {
        let colo = Some("FRA".to_string());
        let country = None;
        assert!(!colo_filter_may_be_empty("/cdn-cgi/trace", &colo, &country));
        assert!(!colo_filter_may_be_empty("/cdn-cgi/trace", &None, &None));
        assert!(colo_filter_may_be_empty("/health", &colo, &country));
        assert!(!colo_filter_may_be_empty(
            "/cdn-cgi/trace",
            &None,
            &Some("x".to_string())
        ));
        assert!(!colo_filter_may_be_empty("/health", &None, &None));
    }

    #[test]
    fn empty_scan_produces_explainable_manifest() {
        let config = AppConfig::default();
        let manifest = build_manifest(
            &config,
            vec!["192.0.2.1".to_string()],
            &[],
            HealthThresholds {
                min_success_rate: Some(1.0),
                max_p95_ms: Some(100.0),
            },
            "HIGH",
            3,
        );
        assert!(manifest.primary.is_none());
        assert_eq!(manifest.backups.len(), 0);
        assert!(manifest.failure.is_some());
        assert_eq!(manifest.thresholds.min_confidence, "HIGH");
    }

    #[test]
    fn manifest_write_replaces_target_with_valid_json() {
        let path = std::env::temp_dir().join(format!(
            "cleanscan-manifest-test-{}.json",
            std::process::id()
        ));
        let manifest = build_manifest(
            &AppConfig::default(),
            Vec::new(),
            &[],
            HealthThresholds {
                min_success_rate: None,
                max_p95_ms: None,
            },
            "UNKNOWN",
            3,
        );
        write_manifest(path.to_str().unwrap(), &manifest).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["primary"].is_null());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn country_filter_is_unicode_aware() {
        let results = vec![scanner::ProbeResult {
            ip: "198.41.0.4".to_string(),
            port: 443,
            protocol: "h2".to_string(),
            ok: 1,
            fail: 0,
            completed: 1,
            avg: 0.0,
            p50: 0.0,
            p90: 0.0,
            p95: 0.0,
            max: 0.0,
            jitter: 0.0,
            stddev: 0.0,
            loss: 0,
            packet_loss: 0.0,
            samples: vec![0.0],
            failures: Vec::new(),
            diagnostics: Vec::new(),
            success_rate: 1.0,
            score: 1.0,
            colo: Some("ABJ".to_string()),
            country: Some("Côte d'Ivoire".to_string()),
            cold_ms: None,
            stopped_early: false,
            min_score: 1.0,
            max_score: 1.0,
            success_rate_lower: 1.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: Vec::new(),
            health_ok: true,
            port_results: Vec::new(),
        }];
        let mut filtered = results.clone();
        filtered.retain(|r| {
            r.country
                .as_deref()
                .is_some_and(|c| c.to_lowercase().contains(&"CÔTE".to_lowercase()))
        });
        assert_eq!(filtered.len(), 1);
    }
}
