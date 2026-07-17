mod scanner;
mod tui;

use clap::Parser;
use std::sync::Arc;

use anyhow::Result;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Cloudflare IP scanner / latency prober")]
pub struct Args {
    /// Use CLI output mode (tab-separated) instead of TUI
    #[arg(long)]
    pub cli: bool,

    /// Hostname used for HTTPS/SNI/Host header
    #[arg(long, default_value = "app.iplat.ir")]
    pub host: String,

    /// Path to test
    #[arg(long, default_value = "/cdn-cgi/trace")]
    pub path: String,

    /// Optional file containing candidate IPs and/or CIDRs, one per line
    #[arg(long)]
    pub ips: Option<String>,

    /// CIDR to sample. Can be repeated
    #[arg(long)]
    pub cidr: Vec<String>,

    /// Number of random IPs to sample from each CIDR
    #[arg(long, default_value_t = 100)]
    pub sample_per_cidr: usize,

    /// Number of repeated probes per IP
    #[arg(long, default_value_t = 8)]
    pub probes: usize,

    /// Max concurrent HTTP probes
    #[arg(long, default_value_t = 120)]
    pub concurrency: usize,

    /// Request timeout in milliseconds
    #[arg(long, default_value_t = 2500)]
    pub timeout_ms: u64,

    /// Connect timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    pub connect_timeout_ms: u64,

    /// Print only top N results
    #[arg(long, default_value_t = 50)]
    pub top: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.cli {
        cli_mode(args)
    } else {
        tui::run_tui(args)
    }
}

fn cli_mode(args: Args) -> Result<()> {
    let targets = scanner::collect_targets(&args)?;
    let total = targets.len();

    eprintln!(
        "Testing {} targets × {} probes, concurrency={}",
        total, args.probes, args.concurrency
    );

    let (tx, rx) = std::sync::mpsc::channel();
    let args_arc = Arc::new(args.clone());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(scanner::run_scan(targets, args_arc, tx));

    let mut results: Vec<scanner::ProbeResult> = rx.iter().collect();

    results.sort_by(|a, b| {
        a.fail
            .cmp(&b.fail)
            .then_with(|| a.p95.partial_cmp(&b.p95).unwrap())
            .then_with(|| a.max.partial_cmp(&b.max).unwrap())
            .then_with(|| a.avg.partial_cmp(&b.avg).unwrap())
    });

    println!("rank\tip\tok\tfail\tavg\tp50\tp90\tp95\tmax\tsamples");

    for (i, r) in results.iter().take(args.top).enumerate() {
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
