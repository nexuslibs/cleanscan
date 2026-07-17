use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use rand::Rng;
use reqwest::Client;
use tokio::sync::Semaphore;

use crate::Args;

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub ip: String,
    pub ok: usize,
    pub fail: usize,
    pub avg: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    pub samples: Vec<f64>,
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn random_ip_from_net(net: IpNet) -> Option<IpAddr> {
    let mut rng = rand::thread_rng();

    match net {
        IpNet::V4(v4) => {
            let network = u32::from(v4.network());
            let broadcast = u32::from(v4.broadcast());
            let prefix = v4.prefix_len();
            let host_bits = 32u32.saturating_sub(prefix as u32);
            let size: u32 = if host_bits >= 32 {
                u32::MAX
            } else {
                1u32 << host_bits
            };

            let (start, end) = if size <= 2 {
                (network, broadcast)
            } else {
                (network + 1, broadcast - 1)
            };

            if start > end {
                return None;
            }

            let n = rng.gen_range(start..=end);
            Some(IpAddr::V4(Ipv4Addr::from(n)))
        }
        IpNet::V6(v6) => {
            let network = u128::from(v6.network());
            let prefix = v6.prefix_len();
            let host_bits = 128u32.saturating_sub(prefix as u32);

            let size: u128 = if host_bits >= 128 {
                u128::MAX
            } else {
                1u128 << host_bits
            };

            let offset = if size <= 2 {
                rng.gen_range(0..size)
            } else {
                rng.gen_range(1..(size - 1))
            };

            Some(IpAddr::V6(Ipv6Addr::from(network.saturating_add(offset))))
        }
    }
}

fn add_ip_or_cidr(s: &str, out: &mut BTreeSet<String>, sample_per_cidr: usize) -> Result<()> {
    let s = s.trim();

    if s.is_empty() || s.starts_with('#') {
        return Ok(());
    }

    if let Ok(ip) = IpAddr::from_str(s) {
        out.insert(ip.to_string());
        return Ok(());
    }

    let net = IpNet::from_str(s).map_err(|_| anyhow!("invalid IP/CIDR: {}", s))?;

    for _ in 0..sample_per_cidr {
        if let Some(ip) = random_ip_from_net(net) {
            out.insert(ip.to_string());
        }
    }

    Ok(())
}

pub fn collect_targets(args: &Args) -> Result<Vec<String>> {
    let mut targets = BTreeSet::new();

    if let Some(path) = &args.ips {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            add_ip_or_cidr(line, &mut targets, args.sample_per_cidr)?;
        }
    }

    for cidr in &args.cidr {
        add_ip_or_cidr(cidr, &mut targets, args.sample_per_cidr)?;
    }

    if targets.is_empty() {
        return Err(anyhow!(
            "no targets. Use --ips /path/to/file or --cidr 188.114.96.0/20"
        ));
    }

    Ok(targets.into_iter().collect())
}

fn client_for_ip(host: &str, ip: &str, args: &Args) -> Result<Client> {
    let ip_addr = IpAddr::from_str(ip)?;
    let socket = SocketAddr::new(ip_addr, 443);

    let client = reqwest::Client::builder()
        .http2_adaptive_window(true)
        .pool_max_idle_per_host(0)
        .resolve_to_addrs(host, &[socket])
        .connect_timeout(Duration::from_millis(args.connect_timeout_ms))
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()?;

    Ok(client)
}

async fn probe_once(client: &Client, url: &str) -> Option<f64> {
    let start = Instant::now();

    let resp = client.get(url).header("accept", "*/*").send().await.ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let _ = resp.bytes().await.ok()?;

    Some(start.elapsed().as_secs_f64())
}

async fn test_ip(
    ip: String,
    args: Arc<Args>,
    sem: Arc<Semaphore>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) -> ProbeResult {
    let url = format!("https://{}{}", args.host, args.path);
    let client = match client_for_ip(&args.host, &ip, &args) {
        Ok(c) => c,
        Err(_) => {
            return ProbeResult {
                ip,
                ok: 0,
                fail: args.probes,
                avg: 0.0,
                p50: 0.0,
                p90: 0.0,
                p95: 0.0,
                max: 0.0,
                samples: Vec::new(),
            };
        }
    };

    let mut futs = FuturesUnordered::new();

    for _ in 0..args.probes {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        while paused.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let permit = sem.clone().acquire_owned().await.unwrap();
        let c = client.clone();
        let u = url.clone();

        futs.push(tokio::spawn(async move {
            let _permit = permit;
            probe_once(&c, &u).await
        }));
    }

    let mut samples = Vec::new();
    let mut fail = 0usize;

    while let Some(joined) = futs.next().await {
        match joined {
            Ok(Some(v)) => samples.push(v),
            _ => fail += 1,
        }
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let ok = samples.len();
    let avg = if ok > 0 {
        samples.iter().sum::<f64>() / ok as f64
    } else {
        0.0
    };

    ProbeResult {
        ip,
        ok,
        fail,
        avg,
        p50: percentile(&samples, 0.50),
        p90: percentile(&samples, 0.90),
        p95: percentile(&samples, 0.95),
        max: samples.last().copied().unwrap_or(0.0),
        samples,
    }
}

/// Run the full scan over `targets`, sending each result through `tx`.
/// `cancel` stops scheduling new probes/targets, and `paused` halts probe
/// scheduling until cleared.
pub async fn run_scan(
    targets: Vec<String>,
    args: Arc<Args>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks = FuturesUnordered::new();

    for ip in targets {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let tx = tx.clone();
        let args = args.clone();
        let sem = sem.clone();
        let cancel = cancel.clone();
        let paused = paused.clone();
        tasks.push(tokio::spawn(async move {
            let result = test_ip(ip, args, sem, cancel, paused).await;
            let _ = tx.send(result);
        }));
    }

    while tasks.next().await.is_some() {}
}
