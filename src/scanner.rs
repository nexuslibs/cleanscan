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

use crate::config::AppConfig;

/// Built-in list of common Cloudflare edge CIDR ranges offered for selection
/// in the TUI when no targets are supplied on the command line.
pub const DEFAULT_CLOUDFLARE_CIDRS: &[&str] = &[
    "188.114.96.0/20",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "162.158.0.0/15",
    "198.41.128.0/17",
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.192.0/23",
];

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

pub fn collect_targets(
    config: &AppConfig,
    cli_cidrs: &[String],
    cli_ips: &Option<String>,
) -> Result<Vec<String>> {
    let mut targets = BTreeSet::new();

    if let Some(path) = cli_ips {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            add_ip_or_cidr(line, &mut targets, config.sample_per_cidr)?;
        }
    }

    for cidr in cli_cidrs {
        add_ip_or_cidr(cidr, &mut targets, config.sample_per_cidr)?;
    }

    if targets.is_empty() {
        return Err(anyhow!(
            "no targets. Use --ips /path/to/file or --cidr 188.114.96.0/20"
        ));
    }

    Ok(targets.into_iter().collect())
}

/// Validate a single CIDR/IP string without sampling any targets. Returns the
/// parsed network on success. Used by the TUI to validate custom CIDR input.
pub fn cidr_valid(s: &str) -> Result<IpNet> {
    let trimmed = s.trim();
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).map_err(|_| anyhow!("invalid IP/CIDR: {}", s));
    }
    IpNet::from_str(trimmed).map_err(|_| anyhow!("invalid IP/CIDR: {}", s))
}

/// Build a target set from an explicit list of CIDR strings (used by the TUI
/// CIDR selection screen). Each CIDR is sampled as in `collect_targets`.
pub fn collect_from_cidrs(cidrs: &[String], sample_per_cidr: usize) -> Result<Vec<String>> {
    let mut targets = BTreeSet::new();

    for cidr in cidrs {
        add_ip_or_cidr(cidr, &mut targets, sample_per_cidr)?;
    }

    if targets.is_empty() {
        return Err(anyhow!("no targets. Select at least one CIDR to scan."));
    }

    Ok(targets.into_iter().collect())
}

fn client_for_ip(host: &str, ip: &str, args: &AppConfig) -> Result<Client> {
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

struct TargetState {
    ip: String,
    url: String,
    client: Option<Client>,
    samples: Vec<f64>,
    fail: usize,
    scheduled: usize,
    completed: usize,
    in_flight: bool,
}

impl TargetState {
    fn new(ip: String, args: &AppConfig, probe_count: usize) -> Self {
        let url = format!("https://{}{}", args.host, args.path);
        let client = client_for_ip(&args.host, &ip, args).ok();
        let (fail, scheduled, completed) = if client.is_some() {
            (0, 0, 0)
        } else {
            (probe_count, probe_count, probe_count)
        };

        Self {
            ip,
            url,
            client,
            samples: Vec::new(),
            fail,
            scheduled,
            completed,
            in_flight: false,
        }
    }

    fn has_remaining_probe(&self, probe_count: usize) -> bool {
        self.scheduled < probe_count && !self.in_flight
    }

    fn result(&mut self) -> ProbeResult {
        self.samples
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let ok = self.samples.len();
        let avg = if ok > 0 {
            self.samples.iter().sum::<f64>() / ok as f64
        } else {
            0.0
        };

        ProbeResult {
            ip: self.ip.clone(),
            ok,
            fail: self.fail,
            avg,
            p50: percentile(&self.samples, 0.50),
            p90: percentile(&self.samples, 0.90),
            p95: percentile(&self.samples, 0.95),
            max: self.samples.last().copied().unwrap_or(0.0),
            samples: self.samples.clone(),
        }
    }
}

fn select_next_target(states: &[TargetState], probe_count: usize) -> Option<usize> {
    let mut candidates: Vec<usize> = states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.has_remaining_probe(probe_count))
        .map(|(index, _)| index)
        .collect();

    candidates.sort_by(|&a, &b| {
        let left = &states[a];
        let right = &states[b];
        let left_success = left.samples.len();
        let right_success = right.samples.len();

        let left_tier = if left_success > 0 {
            0
        } else if left.completed == 0 {
            1
        } else {
            2
        };
        let right_tier = if right_success > 0 {
            0
        } else if right.completed == 0 {
            1
        } else {
            2
        };

        left_tier
            .cmp(&right_tier)
            .then_with(|| {
                let left_rate = if left.completed == 0 {
                    0.0
                } else {
                    left_success as f64 / left.completed as f64
                };
                let right_rate = if right.completed == 0 {
                    0.0
                } else {
                    right_success as f64 / right.completed as f64
                };
                right_rate
                    .partial_cmp(&left_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| right_success.cmp(&left_success))
            .then_with(|| {
                let left_avg = if left_success == 0 {
                    f64::INFINITY
                } else {
                    left.samples.iter().sum::<f64>() / left_success as f64
                };
                let right_avg = if right_success == 0 {
                    f64::INFINITY
                } else {
                    right.samples.iter().sum::<f64>() / right_success as f64
                };
                left_avg
                    .partial_cmp(&right_avg)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then(a.cmp(&b))
    });

    candidates.into_iter().next()
}

/// Run the full scan over `targets`, sending each result through `tx`.
/// `cancel` stops scheduling new probes/targets, and `paused` halts probe
/// scheduling until cleared.
pub async fn run_scan(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));

    let probe_count = args.probes.max(1);
    let workers = args.concurrency.max(1);
    let mut states: Vec<TargetState> = targets
        .into_iter()
        .map(|ip| TargetState::new(ip, &args, probe_count))
        .collect();
    let mut futs = FuturesUnordered::new();

    for state in &mut states {
        if state.completed == probe_count {
            let _ = tx.send(state.result());
        }
    }

    let mut cancellation = Box::pin(async {
        while !cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });

    loop {
        while !cancel.load(Ordering::Relaxed) && futs.len() < workers {
            while paused.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let Some(index) = select_next_target(&states, probe_count) else {
                break;
            };
            let state = &mut states[index];
            let client = state
                .client
                .as_ref()
                .expect("targets without clients are completed during initialization")
                .clone();
            let url = state.url.clone();
            state.scheduled += 1;
            state.in_flight = true;
            let sem = sem.clone();
            let cancel = cancel.clone();

            futs.push(tokio::spawn(async move {
                let permit = tokio::select! {
                    biased;
                    permit = sem.acquire_owned() => permit.ok(),
                    _ = async {
                        while !cancel.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    } => None,
                };
                let sample = match permit {
                    Some(_permit) => probe_once(&client, &url).await,
                    None => None,
                };
                (index, sample)
            }));
        }

        if futs.is_empty() {
            break;
        }

        tokio::select! {
            biased;
            _ = &mut cancellation => {
                for task in futs.iter_mut() {
                    task.abort();
                }
                while futs.next().await.is_some() {}
                break;
            }
            joined = futs.next() => {
                let Some(Ok((index, sample))) = joined else { continue };
                let state = &mut states[index];
                state.in_flight = false;
                state.completed += 1;
                if let Some(value) = sample {
                    state.samples.push(value);
                } else {
                    state.fail += 1;
                }
                if state.completed == probe_count {
                    let _ = tx.send(state.result());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cidr_valid, select_next_target, TargetState};

    fn state(
        ip: &str,
        completed: usize,
        scheduled: usize,
        samples: &[f64],
        fail: usize,
    ) -> TargetState {
        TargetState {
            ip: ip.to_string(),
            url: String::new(),
            client: None,
            samples: samples.to_vec(),
            fail,
            scheduled,
            completed,
            in_flight: false,
        }
    }

    #[test]
    fn cidr_valid_accepts_bare_ipv4_and_ipv6() {
        assert_eq!(cidr_valid(" 192.0.2.1 ").unwrap().prefix_len(), 32);
        assert_eq!(cidr_valid("2001:db8::1").unwrap().prefix_len(), 128);
        assert!(cidr_valid("192.0.2.0/24").is_ok());
        assert!(cidr_valid("not-an-ip").is_err());
    }

    #[test]
    fn successful_ip_is_prioritized_for_remaining_probes() {
        let states = vec![
            state("192.0.2.1", 1, 1, &[0.1], 0),
            state("192.0.2.2", 0, 0, &[], 0),
        ];

        assert_eq!(select_next_target(&states, 3), Some(0));
    }

    #[test]
    fn unexplored_ip_precedes_failed_ip() {
        let states = vec![
            state("192.0.2.1", 1, 1, &[], 1),
            state("192.0.2.2", 0, 0, &[], 0),
        ];

        assert_eq!(select_next_target(&states, 3), Some(1));
    }

    #[test]
    fn higher_success_rate_wins_within_successful_ips() {
        let states = vec![
            state("192.0.2.1", 2, 2, &[0.1], 1),
            state("192.0.2.2", 1, 1, &[0.2], 0),
        ];

        assert_eq!(select_next_target(&states, 3), Some(1));
    }

    #[test]
    fn in_flight_ip_is_not_selected_again() {
        let mut in_flight = state("192.0.2.1", 0, 1, &[], 0);
        in_flight.in_flight = true;
        let states = vec![in_flight, state("192.0.2.2", 0, 0, &[], 0)];

        assert_eq!(select_next_target(&states, 3), Some(1));
    }
}
