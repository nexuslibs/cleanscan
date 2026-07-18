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
use rand::{rngs::StdRng, Rng, SeedableRng};
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    pub ip: String,
    pub protocol: String,
    pub ok: usize,
    pub fail: usize,
    pub avg: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    pub samples: Vec<f64>,
    pub failures: Vec<String>,
    pub success_rate: f64,
    pub score: f64,
    /// Cloudflare datacenter code (e.g. "FRA") parsed from `/cdn-cgi/trace`,
    /// or `None` when the probed path does not expose it.
    pub colo: Option<String>,
    /// Round-trip time of the connection-establishment (TCP + TLS) warmup
    /// probe, captured separately from steady-state latency. `None` when the
    /// warmup failed or warmup is disabled.
    pub connect_ms: Option<f64>,
}

pub fn result_status(result: &ProbeResult) -> &'static str {
    if result.ok == 0 {
        "FAILED"
    } else if result.success_rate >= 0.95 {
        "READY"
    } else {
        "DEGRADED"
    }
}

pub fn result_confidence(result: &ProbeResult) -> &'static str {
    match result.ok + result.fail {
        0..=2 => "UNKNOWN",
        3..=7 => "LOW",
        8..=19 => "MEDIUM",
        _ => "HIGH",
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn random_ip_from_net(net: IpNet, rng: &mut impl Rng) -> Option<IpAddr> {
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

fn add_ip_or_cidr(
    s: &str,
    out: &mut BTreeSet<String>,
    sample_per_cidr: usize,
    rng: &mut impl Rng,
) -> Result<()> {
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
        if let Some(ip) = random_ip_from_net(net, rng) {
            out.insert(ip.to_string());
        }
    }

    Ok(())
}

pub fn collect_targets_with_optional_seed(
    config: &AppConfig,
    cli_cidrs: &[String],
    cli_ips: &Option<String>,
    explicit_seed: Option<u64>,
) -> Result<Vec<String>> {
    let seed = explicit_seed.unwrap_or_else(|| {
        if config.seed == 0 {
            rand::random()
        } else {
            config.seed
        }
    });
    collect_targets_with_seed(config, cli_cidrs, cli_ips, seed)
}

/// Load an exact manifest containing one IP address per line.
pub fn load_ip_manifest(path: &str) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    let mut targets = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let ip = IpAddr::from_str(line)
            .map_err(|_| anyhow!("invalid IP in targets manifest: {}", line))?;
        targets.push(ip.to_string());
    }
    if targets.is_empty() {
        return Err(anyhow!("targets manifest contains no IP addresses"));
    }
    Ok(targets)
}

pub fn collect_targets_with_seed(
    config: &AppConfig,
    cli_cidrs: &[String],
    cli_ips: &Option<String>,
    seed: u64,
) -> Result<Vec<String>> {
    let mut targets = BTreeSet::new();
    let mut rng = StdRng::seed_from_u64(seed);

    if let Some(path) = cli_ips {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            add_ip_or_cidr(line, &mut targets, config.sample_per_cidr, &mut rng)?;
        }
    }

    for cidr in cli_cidrs {
        add_ip_or_cidr(cidr, &mut targets, config.sample_per_cidr, &mut rng)?;
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
pub fn collect_from_cidrs_with_seed(
    cidrs: &[String],
    sample_per_cidr: usize,
    seed: u64,
) -> Result<Vec<String>> {
    let mut targets = BTreeSet::new();
    let mut rng = StdRng::seed_from_u64(seed);

    for cidr in cidrs {
        add_ip_or_cidr(cidr, &mut targets, sample_per_cidr, &mut rng)?;
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
        .resolve_to_addrs(host, &[socket])
        .connect_timeout(Duration::from_millis(args.connect_timeout_ms))
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()?;

    Ok(client)
}

async fn probe_once(client: &Client, url: &str) -> Result<(f64, String, Option<String>), String> {
    let start = Instant::now();

    let resp = client
        .get(url)
        .header("accept", "*/*")
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "request timeout".to_string()
            } else if error.is_connect() {
                "connect/TLS failure".to_string()
            } else {
                "request failure".to_string()
            }
        })?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let protocol = match resp.version() {
        reqwest::Version::HTTP_09 => "http/0.9",
        reqwest::Version::HTTP_10 => "http/1.0",
        reqwest::Version::HTTP_11 => "http/1.1",
        reqwest::Version::HTTP_2 => "h2",
        reqwest::Version::HTTP_3 => "h3",
        _ => "unknown",
    };

    // Read the full body so keep-alive connections can be reused, and to
    // extract the Cloudflare datacenter code from `/cdn-cgi/trace`.
    let body = resp
        .text()
        .await
        .map_err(|_| "body read failure".to_string())?;
    let colo = parse_colo(&body);

    Ok((start.elapsed().as_secs_f64(), protocol.to_string(), colo))
}

/// Extract the Cloudflare `colo=` code from a `/cdn-cgi/trace` response body.
/// The body is `key=value` lines; the field is absent for other paths.
fn parse_colo(body: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("colo=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_ascii_uppercase());
            }
        }
    }
    None
}

struct TargetState {
    ip: String,
    url: String,
    client: Option<Client>,
    samples: Vec<f64>,
    protocols: Vec<String>,
    fail: usize,
    scheduled: usize,
    completed: usize,
    in_flight: bool,
    failures: Vec<String>,
    /// Cloudflare datacenter code captured from the first successful probe.
    colo: Option<String>,
    /// Connection-establishment (TCP + TLS) round-trip time from the warmup
    /// probe, captured separately from steady-state latency.
    connect_ms: Option<f64>,
    /// Whether the warmup probe has been dispatched and completed.
    warmup_done: bool,
    /// Whether a warmup probe is currently in flight.
    warmup_in_flight: bool,
}

impl TargetState {
    fn new(ip: String, args: &AppConfig, probe_count: usize) -> Self {
        let url = format!("https://{}{}", args.host, args.path);
        let client = client_for_ip(&args.host, &ip, args).ok();
        let client_ok = client.is_some();
        let (fail, scheduled, completed) = if client_ok {
            (0, 0, 0)
        } else {
            (probe_count, probe_count, probe_count)
        };

        Self {
            ip,
            url,
            client,
            samples: Vec::new(),
            protocols: Vec::new(),
            fail,
            scheduled,
            completed,
            in_flight: false,
            failures: if client_ok {
                Vec::new()
            } else {
                vec!["invalid target/client setup".to_string(); probe_count]
            },
            colo: None,
            connect_ms: None,
            warmup_done: !args.warmup,
            warmup_in_flight: false,
        }
    }

    fn has_remaining_probe(&self, probe_count: usize) -> bool {
        self.warmup_done && self.scheduled < probe_count && !self.in_flight
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
            protocol: summarize_protocols(&self.protocols),
            ok,
            fail: self.fail,
            avg,
            p50: percentile(&self.samples, 0.50),
            p90: percentile(&self.samples, 0.90),
            p95: percentile(&self.samples, 0.95),
            max: self.samples.last().copied().unwrap_or(0.0),
            samples: self.samples.clone(),
            failures: self.failures.clone(),
            success_rate: if ok + self.fail > 0 {
                ok as f64 / (ok + self.fail) as f64
            } else {
                0.0
            },
            score: if ok > 0 {
                (ok as f64 / (ok + self.fail).max(1) as f64)
                    / self.samples.last().copied().unwrap_or(1.0).max(0.001)
            } else {
                0.0
            },
            colo: self.colo.clone(),
            connect_ms: self.connect_ms.map(|seconds| seconds * 1000.0),
        }
    }
}

fn summarize_protocols(protocols: &[String]) -> String {
    let Some(first) = protocols.first() else {
        return "—".to_string();
    };

    if protocols.iter().all(|protocol| protocol == first) {
        first.clone()
    } else {
        "mixed".to_string()
    }
}

fn select_next_target(states: &[TargetState], probe_count: usize) -> Option<usize> {
    states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.has_remaining_probe(probe_count))
        .min_by(|(left_index, left), (right_index, right)| {
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
                .then(left_index.cmp(right_index))
        })
        .map(|(index, _)| index)
}

/// Outcome of a single scheduled probe: a discarded connection-warmup probe
/// or a counted steady-state latency probe.
enum ProbeOutcome {
    Warmup {
        index: usize,
        sample: Result<(f64, String, Option<String>), String>,
    },
    Measured {
        index: usize,
        sample: Result<(f64, String, Option<String>), String>,
    },
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

            // Dispatch any pending warmup probes first so the TCP+TLS
            // connection is established before steady-state probes run.
            if args.warmup {
                while futs.len() < workers {
                    let warmup_index = states
                        .iter()
                        .position(|s| !s.warmup_done && !s.warmup_in_flight && !s.in_flight);
                    let Some(index) = warmup_index else { break };
                    let state = &mut states[index];
                    let client = state
                        .client
                        .as_ref()
                        .expect("targets without clients are completed during initialization")
                        .clone();
                    let url = state.url.clone();
                    state.warmup_in_flight = true;
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
                            None => Err("cancelled".to_string()),
                        };
                        ProbeOutcome::Warmup { index, sample }
                    }));
                }
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
                    None => Err("cancelled".to_string()),
                };
                ProbeOutcome::Measured { index, sample }
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
                let Some(Ok(outcome)) = joined else { continue };
                match outcome {
                    ProbeOutcome::Warmup { index, sample } => {
                        let state = &mut states[index];
                        state.warmup_in_flight = false;
                        state.warmup_done = true;
                        if let Ok((value, _protocol, colo)) = sample {
                            state.connect_ms = Some(value);
                            if state.colo.is_none() {
                                state.colo = colo;
                            }
                        }
                    }
                    ProbeOutcome::Measured { index, sample } => {
                        let state = &mut states[index];
                        state.in_flight = false;
                        state.completed += 1;
                        match sample {
                            Ok((value, protocol, colo)) => {
                                state.samples.push(value);
                                state.protocols.push(protocol);
                                if state.colo.is_none() {
                                    state.colo = colo;
                                }
                            }
                            Err(reason) => {
                                state.fail += 1;
                                state.failures.push(reason);
                            }
                        }
                        if state.completed == probe_count {
                            let _ = tx.send(state.result());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cidr_valid, collect_from_cidrs_with_seed, parse_colo, result_confidence, result_status,
        select_next_target, TargetState,
    };
    use crate::config::AppConfig;

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
            protocols: Vec::new(),
            fail,
            scheduled,
            completed,
            in_flight: false,
            failures: Vec::new(),
            colo: None,
            connect_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
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

    #[test]
    fn seeded_sampling_is_reproducible_and_deduplicated() {
        let first = collect_from_cidrs_with_seed(
            &["192.0.2.0/24".to_string(), "192.0.2.0/24".to_string()],
            20,
            42,
        )
        .unwrap();
        let second = collect_from_cidrs_with_seed(
            &["192.0.2.0/24".to_string(), "192.0.2.0/24".to_string()],
            20,
            42,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(first.len() <= 40);
    }

    #[test]
    fn result_status_and_confidence_reflect_reliability() {
        let mut state = state("192.0.2.1", 20, 20, &[0.1; 20], 0);
        let result = state.result();
        assert_eq!(result_status(&result), "READY");
        assert_eq!(result_confidence(&result), "HIGH");
        assert_eq!(result.success_rate, 1.0);
    }

    #[test]
    fn parse_colo_extracts_datacenter_code() {
        let body = "fl=abc\nh=example.com\nip=1.2.3.4\ncolo=fra\nts=123\n";
        assert_eq!(parse_colo(body), Some("FRA".to_string()));
        assert_eq!(parse_colo("no colo here"), None);
        assert_eq!(parse_colo("colo=\n"), None);
    }

    #[test]
    fn warmup_done_reflects_config() {
        let enabled = AppConfig {
            warmup: true,
            ..Default::default()
        };
        let disabled = AppConfig {
            warmup: false,
            ..Default::default()
        };

        let with_warmup = TargetState::new("192.0.2.1".to_string(), &enabled, 4);
        let without_warmup = TargetState::new("192.0.2.1".to_string(), &disabled, 4);

        assert!(!with_warmup.warmup_done);
        assert!(without_warmup.warmup_done);
    }

    #[test]
    fn warmup_excluded_from_latency_stats() {
        let mut state = TargetState {
            ip: "192.0.2.1".to_string(),
            url: String::new(),
            client: None,
            samples: vec![0.2, 0.3, 0.25],
            protocols: vec!["h2".to_string(); 3],
            fail: 0,
            scheduled: 3,
            completed: 3,
            in_flight: false,
            failures: Vec::new(),
            colo: Some("FRA".to_string()),
            connect_ms: Some(0.05),
            warmup_done: true,
            warmup_in_flight: false,
        };
        let result = state.result();
        // Steady-state only: connect_ms is separate and samples exclude the warmup.
        assert_eq!(result.connect_ms, Some(50.0));
        assert_eq!(result.colo, Some("FRA".to_string()));
        assert_eq!(result.avg, (0.2 + 0.3 + 0.25) / 3.0);
    }
}
