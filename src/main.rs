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

    normalize_config(&mut config);

    if config.host.is_empty() && (args.cli || args.ips.is_some() || !args.cidr.is_empty()) {
        anyhow::bail!(
            "no host configured — pass --host <domain> or set a host in the TUI settings"
        );
    }

    if args.cli {
        cli_mode(config, args.cidr, args.ips)
    } else {
        tui::run_tui(config, args.cidr, args.ips)
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

fn cli_mode(config: AppConfig, cidr: Vec<String>, ips: Option<String>) -> Result<()> {
    let targets = scanner::collect_targets(&config, &cidr, &ips)?;
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

    let mut results: Vec<scanner::ProbeResult> = rx.iter().filter(|r| r.ok > 0).collect();

    results.sort_by(|a, b| {
        a.fail
            .cmp(&b.fail)
            .then_with(|| a.p95.partial_cmp(&b.p95).unwrap())
            .then_with(|| a.max.partial_cmp(&b.max).unwrap())
            .then_with(|| a.avg.partial_cmp(&b.avg).unwrap())
    });

    println!("rank\tip\tok\tfail\tavg\tp50\tp90\tp95\tmax\tsamples");

    for (i, r) in results.iter().take(config.top).enumerate() {
        let samples = r
            .samples
            .iter()
            .map(|x| format!("{:.3}", x))
            .collect::<Vec<_>>()
            .join(",");

        println!(
            "{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}",
            i + 1,
            r.ip,
            r.ok,
            r.fail,
            r.avg,
            r.p50,
            r.p90,
            r.p95,
            r.max,
            samples
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_config;
    use crate::config::AppConfig;

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
}
