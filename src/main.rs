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

    if !config.stability_weight.is_finite() || config.stability_weight < 0.0 {
        anyhow::bail!("--stability-weight must be a finite, non-negative value");
    }
    if !config.loss_weight.is_finite() || config.loss_weight < 0.0 {
        anyhow::bail!("--loss-weight must be a finite, non-negative value");
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
        )
    } else {
        tui::run_tui(config, args.cidr, args.ips, args.seed)
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
) -> Result<()> {
    let targets = if let Some(path) = targets_file {
        scanner::load_ip_manifest(&path)?
    } else {
        scanner::collect_targets_with_optional_seed(&config, &cidr, &ips, seed)?
    };
    let total = targets.len();

    eprintln!(
        "Testing {} targets × {} probes, concurrency={}",
        total, config.probes, config.concurrency
    );

    let (tx, rx) = std::sync::mpsc::channel();
    let config_arc = Arc::new(config.clone());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(scanner::run_scan(
        targets,
        config_arc,
        tx,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ));

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
        result.ok > 0
            && min_success_rate.is_none_or(|min| result.success_rate >= min)
            && max_p95_ms.is_none_or(|max| result.p95 * 1000.0 <= max)
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
            let mut text = String::from("rank\tip\tcolo\tcountry\tprotocol\tok\tfail\tsuccess_rate\tconfidence\tavg\tp50\tp90\tp95\tmax\tjitter\tloss\tpkt_loss\tcold_ms\tsamples\tfailures\n");
            for (i, r) in rows.iter().enumerate() {
                let samples = r
                    .samples
                    .iter()
                    .map(|x| format!("{:.3}", x))
                    .collect::<Vec<_>>()
                    .join(",");

                text.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{:.1}\t{}\t{}\t{}\n",
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
                    samples,
                    r.failures.join(",")
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

    if health_error {
        anyhow::bail!("no target met the configured health thresholds");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_config;
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
            success_rate: 1.0,
            score: 1.0,
            colo: Some("ABJ".to_string()),
            country: Some("Côte d'Ivoire".to_string()),
            cold_ms: None,
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
