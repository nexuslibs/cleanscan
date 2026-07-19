mod colo;
mod config;
mod scanner;
mod speed;
mod tui;

use clap::Parser;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use config::AppConfig;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Cloudflare IP scanner / latency prober")]
pub struct Args {
    /// Use CLI output mode (tab-separated) instead of TUI
    #[arg(long)]
    pub cli: bool,

    /// Hostname used for HTTPS/SNI/Host header
    #[arg(long)]
    pub host: Option<String>,

    /// Path to test
    #[arg(long)]
    pub path: Option<String>,

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

    /// Score margin a target must beat the worst top-N candidate by to keep probing.
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
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = config::load_config();

    if let Some(host) = args.host {
        config.host = host;
    }
    if let Some(path) = args.path {
        config.path = path;
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
    if let Some(confidence) = args.confidence.as_deref() {
        config.confidence = confidence.parse()?;
    }

    if !config.stability_weight.is_finite() || config.stability_weight < 0.0 {
        anyhow::bail!("--stability-weight must be a finite, non-negative value");
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
    if args.watch.is_some() && config.two_phase {
        anyhow::bail!("--watch cannot be combined with --two-phase");
    }
    if args.cli && args.watch.is_some() && args.format != "ndjson" {
        anyhow::bail!("--watch requires --cli --format ndjson");
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

    normalize_config(&mut config);

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

    if args.targets_file.is_some() && (args.ips.is_some() || !args.cidr.is_empty()) {
        anyhow::bail!("--targets-file cannot be combined with --ips or --cidr");
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

    if args.cli {
        cli_mode(
            config,
            args.cidr,
            args.ips,
            args.targets_file,
            &args.format,
            args.output.as_deref(),
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
        )
    } else {
        tui::run_tui(
            config,
            args.cidr,
            args.ips,
            args.seed,
            args.watch,
            args.manifest,
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
    if config.probes == 0 {
        config.probes = 1;
    }
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

fn healthy_result(
    result: &scanner::ProbeResult,
    thresholds: HealthThresholds,
    min_confidence: &str,
) -> bool {
    result.ok > 0
        && thresholds
            .min_success_rate
            .is_none_or(|min| result.success_rate >= min)
        && thresholds
            .max_p95_ms
            .is_none_or(|max| result.p95 * 1000.0 <= max)
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

#[allow(clippy::too_many_arguments)]
fn cli_mode(
    config: AppConfig,
    cidr: Vec<String>,
    ips: Option<String>,
    targets_file: Option<String>,
    format: &str,
    output: Option<&str>,
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
) -> Result<()> {
    let has_explicit_targets = ips.is_some() || targets_file.is_some();
    let targets = if let Some(path) = targets_file {
        scanner::load_ip_manifest(&path)?
    } else {
        scanner::collect_targets_with_optional_seed(&config, &cidr, &ips, seed)?
    };
    let manifest_targets = targets.clone();
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
        );
    }
    let total = targets.len();
    let use_two_phase = config.two_phase && !has_explicit_targets;

    if !use_two_phase {
        eprintln!(
            "Testing {} targets × {} probes, concurrency={}",
            total, config.probes, config.concurrency
        );
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let config_arc = Arc::new(config.clone());

    let selected_cidrs: Vec<String> = if !cidr.is_empty() {
        cidr.clone()
    } else {
        config.selected_cidrs.clone()
    };

    let rt = tokio::runtime::Runtime::new()?;
    if use_two_phase {
        rt.block_on(scanner::run_scan_two_phase(
            selected_cidrs,
            config_arc,
            colo.clone(),
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ))?;
    } else {
        rt.block_on(scanner::run_scan(
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
    let mut results: Vec<scanner::ProbeResult> = rx.iter().collect();

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
    let rendered = match format {
        "json" => serde_json::to_string_pretty(&rows)?,
        "ndjson" => rows
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n"),
        _ => {
            let mut text = String::from("rank\tip\tcolo\tcountry\tprotocol\tok\tfail\tsuccess_rate\tconfidence\tavg\tp50\tp90\tp95\tmax\tjitter\tloss\tpkt_loss\tcold_ms\tmin_score\tmax_score\tsamples\tfailures\tdiagnostics\n");
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
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{:.1}\t{}\t{:.5}\t{:.5}\t{}\t{}\t{}\n",
                    i + 1,
                    r.ip,
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
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let mut cycle = 0u64;
    let thresholds = HealthThresholds {
        min_success_rate,
        max_p95_ms,
    };
    let mut previous: Option<scanner::ProbeResult> = None;
    let mut previous_healthy: Option<bool> = None;
    let mut previous_manifest: Option<Manifest> = None;
    loop {
        cycle += 1;
        println!(
            "{}",
            serde_json::json!({"event":"cycle_started", "cycle":cycle, "targets":targets.len()})
        );
        let (tx, rx) = std::sync::mpsc::channel();
        runtime.block_on(scanner::run_scan(
            targets.clone(),
            Arc::new(config.clone()),
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ));
        let mut results: Vec<scanner::ProbeResult> = rx.iter().collect();
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
        let manifest = build_manifest(
            &config,
            targets.clone(),
            &results,
            thresholds,
            &manifest_min_confidence,
            manifest_backups,
        );
        if let Some(path) = &manifest_path {
            write_manifest(path, &manifest)?;
            println!(
                "{}",
                serde_json::json!({"event":"manifest_written", "cycle":cycle, "path":path, "primary":manifest.primary.as_ref().map(|r| &r.ip)})
            );
        }
        let healthy = manifest.primary.is_some();
        let recommendation = manifest.primary.as_ref().map(|r| r.ip.clone());
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
        if cycle > 1 {
            let before_ip = previous.as_ref().map(|result| result.ip.clone());
            if before_ip != recommendation {
                alerts.push(serde_json::json!({"kind":"recommendation_changed", "from":before_ip, "to":recommendation}));
            }
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
        previous = manifest.primary.clone();
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
    use super::{build_manifest, normalize_config, write_manifest, HealthThresholds};
    use crate::config::AppConfig;
    use crate::scanner;

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
