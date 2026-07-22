use std::{
    collections::{BTreeMap, BTreeSet},
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

use crate::adaptive::{AdaptivePolicy, ObservationKind, ProbeObservation};
use crate::config::{AppConfig, HealthCheck};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ScanPhase {
    Starting,
    WarmingUp,
    Probing,
    Finalizing,
    Discovery,
    Focus,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub probes_started: usize,
    pub probes_completed: usize,
    pub active_probes: usize,
    pub targets_completed: usize,
    pub latest_target: Option<String>,
    #[serde(default)]
    pub current_workers: Option<usize>,
    #[serde(default)]
    pub adaptive_reason: Option<String>,
}

fn send_progress(
    progress: Option<&std::sync::mpsc::Sender<ScanProgress>>,
    phase: ScanPhase,
    probes_started: usize,
    probes_completed: usize,
    active_probes: usize,
    targets_completed: usize,
    latest_target: Option<String>,
) {
    if let Some(tx) = progress {
        let _ = tx.send(ScanProgress {
            phase,
            probes_started,
            probes_completed,
            active_probes,
            targets_completed,
            latest_target,
            current_workers: None,
            adaptive_reason: None,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn send_progress_with_workers(
    progress: Option<&std::sync::mpsc::Sender<ScanProgress>>,
    phase: ScanPhase,
    probes_started: usize,
    probes_completed: usize,
    active_probes: usize,
    targets_completed: usize,
    latest_target: Option<String>,
    current_workers: usize,
    adaptive_reason: Option<&str>,
) {
    if let Some(tx) = progress {
        let _ = tx.send(ScanProgress {
            phase,
            probes_started,
            probes_completed,
            active_probes,
            targets_completed,
            latest_target,
            current_workers: Some(current_workers),
            adaptive_reason: adaptive_reason.map(str::to_string),
        });
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    pub name: String,
    pub path: String,
    pub required: bool,
    pub weight: f64,
    pub score: f64,
    pub healthy: bool,
    pub ok: usize,
    pub fail: usize,
    pub completed: usize,
    pub success_rate: f64,
    pub avg: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    pub jitter: f64,
    pub stddev: f64,
    pub packet_loss: f64,
    pub cold_ms: Option<f64>,
    pub colo: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    ClientSetup,
    Connect,
    Tls,
    Timeout,
    HttpStatus,
    Redirect,
    ValidationBody,
    ValidationHeader,
    BodyRead,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticPhase {
    ClientConstruction,
    ConnectionTls,
    ResponseHeaders,
    ResponseBody,
    Cancellation,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeDiagnostic {
    pub category: DiagnosticCategory,
    pub phase: DiagnosticPhase,
    pub message: String,
    pub status: Option<u16>,
    pub location: Option<String>,
    pub elapsed_ms: Option<f64>,
}

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
    pub port: u16,
    pub protocol: String,
    pub ok: usize,
    pub fail: usize,
    /// Number of completed measured requests used as the denominator for
    /// success rate and packet loss.
    pub completed: usize,
    pub avg: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    /// Tail spread of steady-state latency: `p95 - p50` (seconds). Robust to a
    /// single outlier and a better stability signal than variance alone.
    pub jitter: f64,
    /// Sample standard deviation of successful probe latencies (seconds).
    pub stddev: f64,
    /// Number of probes that were dropped (no response): timeouts and
    /// connect/TLS failures. Distinct from application-level errors such as a
    /// non-2xx status or a body read failure.
    pub loss: usize,
    /// Fraction of attempted probes that were dropped, in `0..=1`.
    pub packet_loss: f64,
    pub samples: Vec<f64>,
    pub failures: Vec<String>,
    pub diagnostics: Vec<ProbeDiagnostic>,
    pub success_rate: f64,
    pub score: f64,
    /// Cloudflare datacenter code (e.g. "FRA") parsed from `/cdn-cgi/trace`,
    /// or `None` when the probed path does not expose it.
    pub colo: Option<String>,
    /// Country derived from `colo` via the embedded Cloudflare datacenter
    /// mapping, or `None` when the code is unknown or no colo was captured.
    pub country: Option<String>,
    /// Round-trip time of the cold (first) request, which establishes the TCP +
    /// TLS connection, captured separately from steady-state latency. `None`
    /// when the warmup/first request failed or warmup is disabled.
    pub cold_ms: Option<f64>,
    /// Whether this target was emitted before exhausting its configured probe
    /// budget because an early-stop rule determined it could be abandoned.
    pub stopped_early: bool,
    pub min_score: f64,
    pub max_score: f64,
    pub success_rate_lower: f64,
    pub success_rate_upper: f64,
    pub score_confidence: f64,
    pub decision: String,
    pub checks: Vec<CheckResult>,
    pub health_ok: bool,
    #[serde(default)]
    pub port_results: Vec<PortResult>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub ok: usize,
    pub fail: usize,
    pub completed: usize,
    pub avg: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    pub jitter: f64,
    pub stddev: f64,
    pub loss: usize,
    pub packet_loss: f64,
    pub samples: Vec<f64>,
    pub failures: Vec<String>,
    pub diagnostics: Vec<ProbeDiagnostic>,
    pub success_rate: f64,
    pub score: f64,
    pub colo: Option<String>,
    pub country: Option<String>,
    pub cold_ms: Option<f64>,
    pub stopped_early: bool,
    pub min_score: f64,
    pub max_score: f64,
    pub success_rate_lower: f64,
    pub success_rate_upper: f64,
    pub score_confidence: f64,
    pub decision: String,
    pub checks: Vec<CheckResult>,
    pub health_ok: bool,
}

fn port_result(result: &ProbeResult) -> PortResult {
    PortResult {
        port: result.port,
        protocol: result.protocol.clone(),
        ok: result.ok,
        fail: result.fail,
        completed: result.completed,
        avg: result.avg,
        p50: result.p50,
        p90: result.p90,
        p95: result.p95,
        max: result.max,
        jitter: result.jitter,
        stddev: result.stddev,
        loss: result.loss,
        packet_loss: result.packet_loss,
        samples: result.samples.clone(),
        failures: result.failures.clone(),
        diagnostics: result.diagnostics.clone(),
        success_rate: result.success_rate,
        score: result.score,
        colo: result.colo.clone(),
        country: result.country.clone(),
        cold_ms: result.cold_ms,
        stopped_early: result.stopped_early,
        min_score: result.min_score,
        max_score: result.max_score,
        success_rate_lower: result.success_rate_lower,
        success_rate_upper: result.success_rate_upper,
        score_confidence: result.score_confidence,
        decision: result.decision.clone(),
        checks: result.checks.clone(),
        health_ok: result.health_ok,
    }
}

pub fn effective_health_checks(config: &AppConfig) -> Vec<HealthCheck> {
    if config.health_checks.is_empty() {
        vec![HealthCheck {
            name: "primary".to_string(),
            path: config.path.clone(),
            required: true,
            weight: 1.0,
        }]
    } else {
        config.health_checks.clone()
    }
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
    match result.completed {
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

/// Recommendation score blending reliability, latency, jitter, and packet loss.
/// A fast but jittery/lossy target is penalized so a slightly slower, steadier
/// one can outrank it. Mirrors the scoring in `TargetState::result` but takes
/// the raw inputs so it can be used for in-scan decisions without building a
/// full `ProbeResult`.
fn score_from_samples(
    samples: &[f64],
    cold_ms: Option<f64>,
    ok: usize,
    completed: usize,
    loss: usize,
    stability_weight: f64,
    loss_weight: f64,
) -> f64 {
    if ok == 0 {
        return 0.0;
    }
    let fallback = if samples.is_empty() {
        cold_ms.map(|seconds| vec![seconds]).unwrap_or_default()
    } else {
        Vec::new()
    };
    let scoring_samples = if samples.is_empty() {
        fallback.as_slice()
    } else {
        samples
    };
    if scoring_samples.is_empty() {
        return 0.0;
    }
    let mut sorted = scoring_samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let max = sorted.last().copied().unwrap_or(0.0);
    let jitter = (p95 - p50).max(0.0);
    let total = completed.max(1);
    let reliability = ok as f64 / total as f64;
    let tail = (max - p95).max(0.0).min(p95.max(0.001));
    let latency_penalty = p95.max(0.001) + 0.25 * tail;
    let loss_penalty = loss as f64 / total as f64;
    reliability / (latency_penalty + stability_weight * jitter + loss_weight * loss_penalty)
}

fn wilson_interval(successes: usize, total: usize, confidence: f64) -> (f64, f64) {
    if total == 0 {
        return (0.0, 1.0);
    }
    let z = match confidence {
        c if c >= 0.99 => 2.576,
        c if c >= 0.95 => 1.96,
        _ => 1.645,
    };
    let n = total as f64;
    let p = successes as f64 / n;
    let denom = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denom;
    let spread = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denom;
    ((centre - spread).max(0.0), (centre + spread).min(1.0))
}

fn bootstrap_score_interval(state: &TargetState, confidence: f64) -> (f64, f64) {
    if state.samples.is_empty() {
        return (0.0, 0.0);
    }
    let iterations = 256usize;
    let mut seed = 0xcbf29ce484222325u64;
    for byte in state.ip.as_bytes() {
        seed = (seed ^ *byte as u64).wrapping_mul(0x100000001b3);
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let mut scores = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let sample: Vec<f64> = (0..state.samples.len())
            .map(|_| state.samples[rng.gen_range(0..state.samples.len())])
            .collect();
        scores.push(score_from_samples(
            &sample,
            None,
            state.ok,
            state.completed,
            state.loss,
            state.stability_weight,
            state.loss_weight,
        ));
    }
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let alpha = (1.0 - confidence) / 2.0;
    (percentile(&scores, alpha), percentile(&scores, 1.0 - alpha))
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

/// Return the number of addresses represented by an IP or CIDR, saturating
/// when the mathematical count cannot fit in `u128` (IPv6 `/0`).
pub fn cidr_address_count(s: &str) -> Option<u128> {
    let net = cidr_valid(s).ok()?;
    let host_bits = match net {
        IpNet::V4(net) => 32u32.saturating_sub(net.prefix_len() as u32),
        IpNet::V6(net) => 128u32.saturating_sub(net.prefix_len() as u32),
    };
    Some(if host_bits == 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    })
}

/// The deterministic workload contribution of one selected range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrWorkload {
    pub capacity: u128,
    pub estimated_ips: u128,
}

/// The single source of truth for CIDR review and selection summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrWorkloadSummary {
    pub ranges: Vec<CidrWorkload>,
    pub total_ips: u128,
    pub total_probes: u128,
}

pub fn workload_for_cidrs(
    cidrs: &[String],
    samples_per_cidr: usize,
    probes_per_ip: usize,
    selected_ports: usize,
) -> CidrWorkloadSummary {
    let mut ranges = Vec::with_capacity(cidrs.len());
    let mut total_ips = 0u128;
    for cidr in cidrs {
        if let Some(capacity) = cidr_address_count(cidr) {
            let estimated_ips = capacity.min(samples_per_cidr as u128);
            ranges.push(CidrWorkload {
                capacity,
                estimated_ips,
            });
            total_ips = total_ips.saturating_add(estimated_ips);
        }
    }
    let total_probes = total_ips
        .saturating_mul(probes_per_ip as u128)
        .saturating_mul(selected_ports.max(1) as u128);
    CidrWorkloadSummary {
        ranges,
        total_ips,
        total_probes,
    }
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

pub(crate) fn resolve_host_for_ip(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.split_once(']').map(|(name, _)| name))
        .or_else(|| {
            if host.parse::<IpAddr>().is_ok() {
                return None;
            }
            host.rsplit_once(':').and_then(|(name, port)| {
                if port.parse::<u16>().is_ok() {
                    Some(name)
                } else {
                    None
                }
            })
        })
        .unwrap_or(host)
}

pub(crate) fn https_authority(host: &str, port: u16) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(name, _)| name))
        .unwrap_or_else(|| resolve_host_for_ip(host));
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn client_for_ip(host: &str, ip: &str, args: &AppConfig, port: u16) -> Result<Client> {
    let ip_addr = IpAddr::from_str(ip)?;
    let socket = SocketAddr::new(ip_addr, port);

    let client = reqwest::Client::builder()
        .http2_adaptive_window(true)
        .no_proxy()
        .resolve_to_addrs(resolve_host_for_ip(host), &[socket])
        .redirect(if args.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .connect_timeout(Duration::from_millis(args.connect_timeout_ms))
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()?;

    Ok(client)
}

async fn probe_once(
    client: &Client,
    url: &str,
    args: &AppConfig,
) -> Result<(f64, String, Option<String>), ProbeDiagnostic> {
    let start = Instant::now();

    let resp = client
        .get(url)
        .header("accept", "*/*")
        .send()
        .await
        .map_err(|error| {
            let category = if error.is_timeout() {
                DiagnosticCategory::Timeout
            } else if error.is_connect()
                && error
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("certificate")
            {
                DiagnosticCategory::Tls
            } else if error.is_connect() {
                DiagnosticCategory::Connect
            } else {
                DiagnosticCategory::Unknown
            };
            ProbeDiagnostic {
                category,
                phase: if error.is_connect() {
                    DiagnosticPhase::ConnectionTls
                } else {
                    DiagnosticPhase::ResponseHeaders
                },
                message: error.to_string(),
                status: None,
                location: None,
                elapsed_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            }
        })?;

    let protocol = match resp.version() {
        reqwest::Version::HTTP_09 => "http/0.9",
        reqwest::Version::HTTP_10 => "http/1.0",
        reqwest::Version::HTTP_11 => "http/1.1",
        reqwest::Version::HTTP_2 => "h2",
        reqwest::Version::HTTP_3 => "h3",
        _ => "unknown",
    };

    // Capture latency immediately after headers are received, before reading body.
    let latency = start.elapsed().as_secs_f64();

    // Read the full body so keep-alive connections can be reused, and to
    // extract the Cloudflare datacenter code from `/cdn-cgi/trace`.
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let headers = resp.headers().clone();
    let body = resp.text().await.map_err(|error| ProbeDiagnostic {
        category: DiagnosticCategory::BodyRead,
        phase: DiagnosticPhase::ResponseBody,
        message: error.to_string(),
        status: None,
        location: None,
        elapsed_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
    })?;

    if let Some(diagnostic) = validate_response(status, &headers, &body, location.as_deref(), args)
    {
        return Err(ProbeDiagnostic {
            elapsed_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            ..diagnostic
        });
    }
    let colo = parse_colo(&body);

    Ok((latency, protocol.to_string(), colo))
}

fn validate_response(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    location: Option<&str>,
    args: &AppConfig,
) -> Option<ProbeDiagnostic> {
    let status_ok = if args.expected_statuses.is_empty() {
        (200..300).contains(&status)
    } else {
        args.expected_statuses.contains(&status)
    };
    if !status_ok {
        return Some(ProbeDiagnostic {
            category: if location.is_some() {
                DiagnosticCategory::Redirect
            } else {
                DiagnosticCategory::HttpStatus
            },
            phase: DiagnosticPhase::ResponseBody,
            message: format!("HTTP {}", status),
            status: Some(status),
            location: location.map(str::to_string),
            elapsed_ms: None,
        });
    }
    for marker in &args.required_body_markers {
        if !body.contains(marker) {
            return Some(ProbeDiagnostic {
                category: DiagnosticCategory::ValidationBody,
                phase: DiagnosticPhase::ResponseBody,
                message: format!("required body marker missing: {marker}"),
                status: Some(status),
                location: location.map(str::to_string),
                elapsed_ms: None,
            });
        }
    }
    for expression in &args.required_headers {
        let (name, expected) = match crate::config::parse_required_header(expression) {
            Ok(value) => value,
            Err(error) => {
                return Some(ProbeDiagnostic {
                    category: DiagnosticCategory::ValidationHeader,
                    phase: DiagnosticPhase::ResponseHeaders,
                    message: format!("invalid required header expression: {error}"),
                    status: Some(status),
                    location: location.map(str::to_string),
                    elapsed_ms: None,
                });
            }
        };
        if headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            != Some(expected.as_str())
        {
            return Some(ProbeDiagnostic {
                category: DiagnosticCategory::ValidationHeader,
                phase: DiagnosticPhase::ResponseHeaders,
                message: format!("required header mismatch: {name}"),
                status: Some(status),
                location: location.map(str::to_string),
                elapsed_ms: None,
            });
        }
    }
    None
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

/// Whether a probe failure reason indicates a dropped probe (no usable
/// response) rather than an application-level error. Timeouts and
/// connect/TLS failures reflect packet loss; non-2xx status and body read
/// failures mean the server *did* respond.
fn is_loss_reason(reason: &ProbeDiagnostic) -> bool {
    matches!(
        reason.category,
        DiagnosticCategory::Timeout
            | DiagnosticCategory::Connect
            | DiagnosticCategory::Tls
            | DiagnosticCategory::Cancelled
    )
}

struct TargetState {
    ip: String,
    port: u16,
    url: String,
    client: Option<Client>,
    samples: Vec<f64>,
    protocols: Vec<String>,
    ok: usize,
    fail: usize,
    loss: usize,
    scheduled: usize,
    completed: usize,
    in_flight: bool,
    failures: Vec<String>,
    diagnostics: Vec<ProbeDiagnostic>,
    /// Cloudflare datacenter code captured from the first successful probe.
    colo: Option<String>,
    /// Cold-request (TCP + TLS connection-establishment) round-trip time from
    /// the warmup probe, captured separately from steady-state latency.
    cold_ms: Option<f64>,
    /// Whether the warmup probe has been dispatched and completed.
    warmup_done: bool,
    /// Whether a warmup probe is currently in flight.
    warmup_in_flight: bool,
    /// When the warmup probe failed, the first successful measured probe must
    /// be discarded so its connection-setup cost is excluded from steady-state
    /// latency and instead recorded as `cold_ms`.
    warmup_discard_first: bool,
    stability_weight: f64,
    loss_weight: f64,
    confidence: f64,
    /// Number of consecutive dropped probes (timeouts / connect failures).
    /// Reset on any successful probe; drives the early-stop loss-streak rule.
    loss_streak: usize,
    /// Whether this target was stopped before exhausting its probe budget.
    stopped_early: bool,
    bootstrap_interval: Option<(f64, f64)>,
}

impl TargetState {
    fn new(ip: String, args: &AppConfig, probe_count: usize, port: u16) -> Self {
        let url = format!("https://{}{}", https_authority(&args.host, port), args.path);
        let client = client_for_ip(&args.host, &ip, args, port).ok();
        let client_ok = client.is_some();
        let (fail, loss, scheduled, completed) = if client_ok {
            (0, 0, 0, 0)
        } else {
            (probe_count, 0, probe_count, probe_count)
        };

        Self {
            ip,
            port,
            url,
            client,
            samples: Vec::new(),
            protocols: Vec::new(),
            ok: 0,
            fail,
            loss,
            scheduled,
            completed,
            in_flight: false,
            failures: if client_ok {
                Vec::new()
            } else {
                vec!["invalid target/client setup".to_string(); probe_count]
            },
            diagnostics: if client_ok {
                Vec::new()
            } else {
                vec![
                    ProbeDiagnostic {
                        category: DiagnosticCategory::ClientSetup,
                        phase: DiagnosticPhase::ClientConstruction,
                        message: "invalid target/client setup".to_string(),
                        status: None,
                        location: None,
                        elapsed_ms: None
                    };
                    probe_count
                ]
            },
            colo: None,
            cold_ms: None,
            warmup_done: !args.warmup || !client_ok,
            warmup_in_flight: false,
            warmup_discard_first: false,
            stability_weight: args.stability_weight,
            loss_weight: args.loss_weight,
            confidence: args.confidence,
            loss_streak: 0,
            stopped_early: false,
            bootstrap_interval: None,
        }
    }

    fn has_remaining_probe(&self, probe_count: usize) -> bool {
        self.warmup_done && self.scheduled < probe_count && !self.in_flight && !self.stopped_early
    }

    /// Current best recommendation score from the samples gathered so far,
    /// used by the early-stop prune rule to compare against the leaderboard.
    fn current_score(&self) -> f64 {
        score_from_samples(
            &self.samples,
            self.cold_ms,
            self.ok,
            self.completed,
            self.loss,
            self.stability_weight,
            self.loss_weight,
        )
    }

    fn score_lower_bound(&mut self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.cached_bootstrap_interval().0
    }

    fn prune_score(&mut self, adaptive: bool) -> f64 {
        if adaptive {
            self.score_lower_bound()
        } else {
            self.current_score()
        }
    }

    fn cached_bootstrap_interval(&mut self) -> (f64, f64) {
        if let Some(interval) = self.bootstrap_interval {
            return interval;
        }
        let interval = bootstrap_score_interval(self, self.confidence);
        self.bootstrap_interval = Some(interval);
        interval
    }

    #[allow(dead_code)]
    fn result(&mut self) -> ProbeResult {
        self.result_with_mode(false)
    }

    fn result_with_mode(&mut self, adaptive: bool) -> ProbeResult {
        self.samples
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sample_count = self.samples.len();
        let avg = if sample_count > 0 {
            self.samples.iter().sum::<f64>() / sample_count as f64
        } else {
            0.0
        };

        let p50 = percentile(&self.samples, 0.50);
        let p90 = percentile(&self.samples, 0.90);
        let p95 = percentile(&self.samples, 0.95);
        let max = self.samples.last().copied().unwrap_or(0.0);
        let jitter = if sample_count > 0 {
            (p95 - p50).max(0.0)
        } else {
            0.0
        };
        let stddev = if sample_count > 1 {
            let variance = self.samples.iter().map(|s| (s - avg).powi(2)).sum::<f64>()
                / (sample_count - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        let total = self.completed.max(1);
        let success_rate = self.ok as f64 / total as f64;
        let packet_loss = self.loss as f64 / total as f64;
        let point_score = score_from_samples(
            &self.samples,
            self.cold_ms,
            self.ok,
            self.completed,
            self.loss,
            self.stability_weight,
            self.loss_weight,
        );
        let (success_rate_lower, success_rate_upper) =
            wilson_interval(self.ok, self.completed, self.confidence);
        let (min_score, max_score) = self.cached_bootstrap_interval();
        let score = if adaptive { min_score } else { point_score };

        ProbeResult {
            ip: self.ip.clone(),
            port: self.port,
            protocol: summarize_protocols(&self.protocols),
            ok: self.ok,
            fail: self.fail,
            completed: self.completed,
            avg,
            p50,
            p90,
            p95,
            max,
            jitter,
            stddev,
            loss: self.loss,
            packet_loss,
            samples: self.samples.clone(),
            failures: self.failures.clone(),
            diagnostics: self.diagnostics.clone(),
            success_rate,
            score,
            colo: self.colo.clone(),
            country: self
                .colo
                .as_ref()
                .and_then(|code| crate::colo::lookup_country(code).map(str::to_string)),
            cold_ms: self.cold_ms.map(|seconds| seconds * 1000.0),
            stopped_early: self.stopped_early,
            min_score,
            max_score,
            success_rate_lower,
            success_rate_upper,
            score_confidence: self.confidence,
            decision: if self.ok == 0 {
                "discarded"
            } else if self.completed < 3 {
                "insufficient_data"
            } else {
                "competitive"
            }
            .to_string(),
            checks: Vec::new(),
            health_ok: self.ok > 0,
            port_results: Vec::new(),
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

fn select_next_target_adaptive(
    states: &mut [TargetState],
    probe_count: usize,
    min_probes: usize,
) -> Option<usize> {
    let candidates: Vec<usize> = states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.has_remaining_probe(probe_count))
        .map(|(index, _)| index)
        .collect();
    let bootstrap_intervals: Vec<(usize, (f64, f64))> = candidates
        .iter()
        .map(|&index| (index, states[index].cached_bootstrap_interval()))
        .collect();
    states
        .iter()
        .enumerate()
        .filter(|(index, _)| candidates.binary_search(index).is_ok())
        .min_by(|(left_index, left), (right_index, right)| {
            let left_min = left.completed < min_probes;
            let right_min = right.completed < min_probes;
            right_min
                .cmp(&left_min)
                .then_with(|| {
                    let (_, (left_min, left_max)) = bootstrap_intervals
                        .binary_search_by_key(left_index, |(index, _)| *index)
                        .map(|position| bootstrap_intervals[position])
                        .unwrap_or((*left_index, (0.0, 0.0)));
                    let (_, (right_min, right_max)) = bootstrap_intervals
                        .binary_search_by_key(right_index, |(index, _)| *index)
                        .map(|position| bootstrap_intervals[position])
                        .unwrap_or((*right_index, (0.0, 0.0)));
                    let lw = left_max - left_min;
                    let rw = right_max - right_min;
                    rw.partial_cmp(&lw).unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    right
                        .current_score()
                        .partial_cmp(&left.current_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
        .map(|(index, _)| index)
}

fn adaptive_should_stop(index: usize, states: &mut [TargetState], cfg: &AppConfig) -> bool {
    if states[index].completed < cfg.min_probes || states[index].samples.is_empty() {
        return false;
    }
    let own = states[index].cached_bootstrap_interval();
    (0..states.len()).any(|other_index| {
        if other_index == index
            || states[other_index].completed < cfg.min_probes
            || states[other_index].samples.is_empty()
        {
            return false;
        }
        states[other_index].cached_bootstrap_interval().0 > own.1
    })
}

/// Decide whether a target should stop being probed before its full probe
/// budget is exhausted. Returns `true` when any early-stop rule applies:
///  * loss streak: `early_stop_loss_streak` consecutive dropped probes;
///  * low success: success rate below `early_stop_success_floor`;
///  * prune: at least `top` READY candidates exist and this target's current
///    best score remains worse than the worst of them after applying the
///    configured margin tolerance.
///
/// `best` is the running leaderboard of `(score, p95)` for completed targets,
/// capped at `top` entries (see `record_best`).
fn should_stop_early(
    state: &mut TargetState,
    cfg: &AppConfig,
    best: &[(f64, f64)],
    adaptive: bool,
) -> bool {
    if !cfg.early_stop {
        return false;
    }

    if state.completed >= cfg.early_stop_min_samples
        && state.loss_streak >= cfg.early_stop_loss_streak
    {
        return true;
    }

    if state.completed >= cfg.early_stop_min_samples {
        let rate = state.ok as f64 / state.completed.max(1) as f64;
        if rate < cfg.early_stop_success_floor {
            return true;
        }
    }

    if cfg.early_stop_prune
        && best.len() >= cfg.top
        && state.samples.len() >= cfg.early_stop_min_samples
    {
        let current = state.prune_score(adaptive);
        let worst_top = best[best.len() - 1].0;
        // The margin is slack: tolerate a target being somewhat worse before
        // pruning it. This is equivalent to current * (1 + margin) < worst.
        if current < worst_top / (1.0 + cfg.early_stop_prune_margin) {
            return true;
        }
    }

    false
}

/// Insert a completed result into the running top-`top` leaderboard, sorted by
/// score descending. Targets with no successful samples are ignored.
fn record_best(best: &mut Vec<(f64, f64)>, result: &ProbeResult, top: usize) {
    if result.ok == 0 {
        return;
    }
    best.push((result.score, result.p95));
    best.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    if best.len() > top {
        best.truncate(top);
    }
}

/// Outcome of a single scheduled probe: a discarded connection-warmup probe
/// or a counted steady-state latency probe.
enum ProbeOutcome {
    Warmup {
        index: usize,
        sample: Result<(f64, String, Option<String>), ProbeDiagnostic>,
    },
    Measured {
        index: usize,
        sample: Result<(f64, String, Option<String>), ProbeDiagnostic>,
    },
}

fn remaining_measured_work(states: &[TargetState], probe_count: usize) -> usize {
    states
        .iter()
        .filter(|state| state.warmup_done && !state.stopped_early)
        .map(|state| probe_count.saturating_sub(state.scheduled))
        .fold(0usize, usize::saturating_add)
}

/// Keep the semaphore's idle permits consistent with the scheduler's current
/// worker target. A downscale never interrupts a probe that already acquired
/// a permit; those probes drain naturally, while excess idle permits are
/// removed so newly scheduled work cannot exceed the target.
fn reconcile_worker_permits(sem: &Semaphore, workers: usize, active_futures: usize) {
    let desired_available = workers.saturating_sub(active_futures);
    let available = sem.available_permits();
    if available > desired_available {
        sem.forget_permits(available - desired_available);
    } else if available < desired_available {
        sem.add_permits(desired_available - available);
    }
}

fn adaptive_progress_reason(
    decision: &crate::adaptive::Decision,
    applied: crate::adaptive::ApplyResult,
) -> String {
    if applied.resized {
        decision.reason.clone()
    } else if !matches!(decision.action, crate::adaptive::Action::NoChange) {
        format!("{}; awaiting hysteresis", decision.reason)
    } else {
        decision.reason.clone()
    }
}

/// Run the full scan over `targets`, sending each result through `tx`.
/// `cancel` stops scheduling new probes/targets, and `paused` halts probe
/// scheduling until cleared.
#[allow(clippy::too_many_arguments)]
async fn run_scan_port(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    port: u16,
    include_port_details: bool,
    progress_offsets: (usize, usize, usize),
    progress_phase: Option<ScanPhase>,
) -> (usize, usize, usize) {
    let probe_count = if args.adaptive_probing {
        args.max_probes.max(args.min_probes).max(1)
    } else {
        args.probes.max(1)
    };
    let initial_workers = if args.adaptive_concurrency {
        args.concurrency
            .max(1)
            .clamp(args.min_concurrency.max(1), args.max_concurrency.max(1))
    } else {
        args.concurrency.max(1)
    };
    let sem = Arc::new(Semaphore::new(initial_workers));
    let mut workers = initial_workers;
    let mut controller = args.adaptive_concurrency.then(|| {
        AdaptivePolicy::new(
            initial_workers,
            args.min_concurrency.max(1),
            args.max_concurrency.max(args.min_concurrency).max(1),
        )
    });
    let mut adaptive_reason: Option<String> = None;
    let mut states: Vec<TargetState> = targets
        .into_iter()
        .map(|ip| TargetState::new(ip, &args, probe_count, port))
        .collect();
    let mut futs = FuturesUnordered::new();
    let (mut probes_started, mut probes_completed, mut targets_completed) = progress_offsets;

    let warming_phase = progress_phase.unwrap_or(if args.warmup {
        ScanPhase::WarmingUp
    } else {
        ScanPhase::Probing
    });
    let probing_phase = progress_phase.unwrap_or(ScanPhase::Probing);
    send_progress_with_workers(
        progress.as_ref(),
        warming_phase,
        probes_started,
        probes_completed,
        futs.len(),
        targets_completed,
        None,
        workers,
        adaptive_reason.as_deref(),
    );

    for state in &mut states {
        if state.completed == probe_count {
            let mut result = state.result_with_mode(args.adaptive_probing);
            if include_port_details {
                result.port_results = vec![port_result(&result)];
            }
            let _ = tx.send(result);
            if include_port_details {
                targets_completed += 1;
            }
        }
    }

    // Running leaderboard of the best READY results so far, used by the
    // early-stop prune rule. Capped at `top` entries.
    let mut best: Vec<(f64, f64)> = Vec::new();

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
                    let probe_args = args.clone();
                    state.warmup_in_flight = true;
                    probes_started += 1;
                    send_progress_with_workers(
                        progress.as_ref(),
                        warming_phase,
                        probes_started,
                        probes_completed,
                        futs.len() + 1,
                        targets_completed,
                        Some(state.ip.clone()),
                        workers,
                        adaptive_reason.as_deref(),
                    );
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
                            Some(_permit) => probe_once(&client, &url, &probe_args).await,
                            None => Err(ProbeDiagnostic {
                                category: DiagnosticCategory::Cancelled,
                                phase: DiagnosticPhase::Cancellation,
                                message: "cancelled".to_string(),
                                status: None,
                                location: None,
                                elapsed_ms: None,
                            }),
                        };
                        ProbeOutcome::Warmup { index, sample }
                    }));
                }
            }

            let next = if args.adaptive_probing {
                select_next_target_adaptive(&mut states, probe_count, args.min_probes)
            } else {
                select_next_target(&states, probe_count)
            };
            let Some(index) = next else {
                break;
            };
            let state = &mut states[index];
            let client = state
                .client
                .as_ref()
                .expect("targets without clients are completed during initialization")
                .clone();
            let url = state.url.clone();
            let probe_args = args.clone();
            state.scheduled += 1;
            state.in_flight = true;
            probes_started += 1;
            send_progress_with_workers(
                progress.as_ref(),
                probing_phase,
                probes_started,
                probes_completed,
                futs.len() + 1,
                targets_completed,
                Some(state.ip.clone()),
                workers,
                adaptive_reason.as_deref(),
            );
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
                    Some(_permit) => probe_once(&client, &url, &probe_args).await,
                    None => Err(ProbeDiagnostic {
                        category: DiagnosticCategory::Cancelled,
                        phase: DiagnosticPhase::Cancellation,
                        message: "cancelled".to_string(),
                        status: None,
                        location: None,
                        elapsed_ms: None,
                    }),
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
                        probes_completed += 1;
                        let state = &mut states[index];
                        state.warmup_in_flight = false;
                        match sample {
                            Ok((value, _protocol, colo)) => {
                                state.warmup_done = true;
                                state.cold_ms = Some(value);
                                if state.colo.is_none() {
                                    state.colo = colo;
                                }
                            }
                            Err(diagnostic) => {
                                // The warmup could not establish the connection,
                                // so it is not ready for steady-state timing. End
                                // the warmup phase but flag the first successful
                                // measured probe to be discarded as the cold
                                // request, keeping its setup cost out of latency.
                                state.warmup_done = true;
                                state.warmup_discard_first = true;
                                state.diagnostics.push(diagnostic.clone());
                                state.failures.push(diagnostic.message);
                            }
                        }
                    }
                    ProbeOutcome::Measured { index, sample } => {
                        let state = &mut states[index];
                        state.in_flight = false;
                        probes_completed += 1;
                        state.completed += 1;
                        let fallback_cold = sample.is_ok() && state.warmup_discard_first;
                        let adaptive_now = controller.as_ref().map(|_| Instant::now());
                        if let Some(controller) = controller.as_mut() {
                            let now = adaptive_now.expect("adaptive timestamp exists");
                            let observation = match &sample {
                                Ok((value, _, _)) => ProbeObservation {
                                    kind: ObservationKind::Success,
                                    latency: (!fallback_cold).then_some(*value),
                                    at: now,
                                },
                                Err(diagnostic) => ProbeObservation {
                                    kind: match diagnostic.category {
                                        DiagnosticCategory::Timeout => ObservationKind::Timeout,
                                        DiagnosticCategory::Connect | DiagnosticCategory::Tls => {
                                            ObservationKind::ConnectionFailure
                                        }
                                        DiagnosticCategory::Cancelled => ObservationKind::Cancelled,
                                        DiagnosticCategory::HttpStatus
                                        | DiagnosticCategory::Redirect
                                        | DiagnosticCategory::ValidationBody
                                        | DiagnosticCategory::ValidationHeader
                                        | DiagnosticCategory::BodyRead
                                        | DiagnosticCategory::ClientSetup
                                        | DiagnosticCategory::Unknown => ObservationKind::OtherFailure,
                                    },
                                    latency: None,
                                    at: now,
                                },
                            };
                            controller.record(observation);
                        }
                        match sample {
                            Ok((value, protocol, colo)) => {
                                state.ok += 1;
                                state.loss_streak = 0;
                                state.bootstrap_interval = None;
                                if state.warmup_discard_first {
                                    // This first successful measured probe paid
                                    // the connection-setup cost; record it as the
                                    // cold request and exclude it from latency.
                                    state.warmup_discard_first = false;
                                    state.cold_ms = Some(value);
                                    if state.colo.is_none() {
                                        state.colo = colo;
                                    }
                                } else {
                                    state.samples.push(value);
                                    state.protocols.push(protocol);
                                    if state.colo.is_none() {
                                        state.colo = colo;
                                    }
                                }
                            }
                            Err(diagnostic) => {
                                state.bootstrap_interval = None;
                                state.fail += 1;
                                if is_loss_reason(&diagnostic) {
                                    state.loss += 1;
                                    state.loss_streak += 1;
                                }
                                state.failures.push(diagnostic.message.clone());
                                state.diagnostics.push(diagnostic);
                            }
                        }
                        let adaptive_min_reached = !args.adaptive_probing || state.completed >= args.min_probes;
                        let legacy_stop = adaptive_min_reached
                            && should_stop_early(state, &args, &best, args.adaptive_probing);
                        let completed = state.completed;
                        let _ = state;
                        let adaptive_stop =
                            args.adaptive_probing && adaptive_should_stop(index, &mut states, &args);
                        let mut completed_target = None;
                        if adaptive_stop || legacy_stop {
                            // Target is dead or cannot beat the current
                            // leaderboard; stop probing it and emit a partial
                            // result now rather than spending the full budget.
                            let state = &mut states[index];
                            state.stopped_early = true;
                            let mut result = state.result_with_mode(args.adaptive_probing);
                            if include_port_details {
                                result.port_results = vec![port_result(&result)];
                            }
                            record_best(&mut best, &result, args.top);
                            let _ = tx.send(result);
                            if include_port_details {
                                targets_completed += 1;
                                completed_target = Some(state.ip.clone());
                            }
                        } else if completed == probe_count {
                            let state = &mut states[index];
                            let mut result = state.result_with_mode(args.adaptive_probing);
                            if include_port_details {
                                result.port_results = vec![port_result(&result)];
                            }
                            record_best(&mut best, &result, args.top);
                            let _ = tx.send(result);
                            if include_port_details {
                                targets_completed += 1;
                                completed_target = Some(state.ip.clone());
                            }
                        }
                        if let Some(controller) = controller.as_mut() {
                            let now = adaptive_now.expect("adaptive timestamp exists");
                            let remaining_work = remaining_measured_work(&states, probe_count);
                            let decision = controller.evaluate(now, remaining_work);
                            let applied = controller.apply(&decision, now);
                            if applied.resized {
                                workers = applied.workers;
                            }
                            adaptive_reason = Some(adaptive_progress_reason(&decision, applied));
                        }
                        reconcile_worker_permits(&sem, workers, futs.len());
                        send_progress_with_workers(
                            progress.as_ref(),
                            probing_phase,
                            probes_started,
                            probes_completed,
                            futs.len(),
                            targets_completed,
                            completed_target,
                            workers,
                            adaptive_reason.as_deref(),
                        );
                    }
                }
            }
        }
    }
    (probes_started, probes_completed, targets_completed)
}

pub async fn run_scan_with_progress(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) {
    run_scan_with_progress_from_offsets(
        targets,
        args,
        tx,
        cancel,
        paused,
        progress,
        (0, 0, 0),
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_scan_with_progress_from_offsets(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
    mut progress_offsets: (usize, usize, usize),
    progress_phase: Option<ScanPhase>,
) -> (usize, usize, usize) {
    let ports = if args.ports.is_empty() {
        vec![443]
    } else {
        args.ports.clone()
    };
    if ports.len() == 1 {
        return run_scan_port(
            targets,
            args,
            tx,
            progress,
            cancel,
            paused,
            ports[0],
            true,
            progress_offsets,
            progress_phase,
        )
        .await;
    }

    let mut by_ip: BTreeMap<String, Vec<ProbeResult>> = BTreeMap::new();
    'ports: for port in ports {
        if cancel.load(Ordering::Relaxed) {
            break 'ports;
        }
        let mut port_args = (*args).clone();
        port_args.ports = vec![port];
        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let (probes_started, probes_completed, _) = run_scan_port(
            targets.clone(),
            Arc::new(port_args),
            port_tx,
            progress.clone(),
            cancel.clone(),
            paused.clone(),
            port,
            false,
            progress_offsets,
            progress_phase,
        )
        .await;
        progress_offsets.0 = probes_started;
        progress_offsets.1 = probes_completed;
        for result in port_rx {
            let _ = tx.send(result.clone());
            by_ip.entry(result.ip.clone()).or_default().push(result);
        }
    }
    let mut merged_targets = 0;
    for results in by_ip.values() {
        if merge_port_results(results).is_some() {
            merged_targets += 1;
        }
    }
    progress_offsets.2 += merged_targets;
    send_progress(
        progress.as_ref(),
        progress_phase.unwrap_or(ScanPhase::Finalizing),
        progress_offsets.0,
        progress_offsets.1,
        0,
        progress_offsets.2,
        None,
    );
    for (_, results) in by_ip {
        if let Some(result) = merge_port_results(&results) {
            let _ = tx.send(result);
        }
    }
    progress_offsets
}

fn merge_port_results(results: &[ProbeResult]) -> Option<ProbeResult> {
    let best = results
        .iter()
        .filter(|result| result.health_ok)
        .max_by(|left, right| {
            left.score
                .partial_cmp(&right.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .p95
                        .partial_cmp(&left.p95)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
        .or_else(|| {
            results.iter().max_by(|left, right| {
                left.score
                    .partial_cmp(&right.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        right
                            .success_rate
                            .partial_cmp(&left.success_rate)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            })
        })?;
    let mut merged = best.clone();
    merged.port_results = results.iter().map(port_result).collect();
    merged.health_ok = results.iter().any(|result| result.health_ok);
    Some(merged)
}

/// Run every configured health check and merge the per-path results into one
/// target result. Checks share the same target set and validation policy, but
/// currently use independent clients and warmup requests; top-level latency
/// fields use the required check with the worst p95 as the summary, while
/// reliability and score fields are based on required checks. Optional checks
/// remain available in the per-check details but do not affect recommendation
/// scoring or required-health accounting.
pub async fn run_profile_scan(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    run_profile_scan_with_progress_from_offsets(targets, args, tx, cancel, paused, None, (0, 0, 0))
        .await;
}

async fn run_profile_scan_with_progress_from_offsets(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
    mut progress_offsets: (usize, usize, usize),
) -> (usize, usize, usize) {
    let checks = effective_health_checks(&args);
    if args.health_checks.is_empty() {
        return run_scan_with_progress_from_offsets(
            targets,
            args,
            tx,
            cancel,
            paused,
            progress,
            progress_offsets,
            None,
        )
        .await;
    }

    let expected_checks = checks.clone();
    let mut all_by_ip: BTreeMap<String, Vec<ProbeResult>> = BTreeMap::new();
    let ports = if args.ports.is_empty() {
        vec![443]
    } else {
        args.ports.clone()
    };
    'ports: for port in ports {
        let mut stop_after_port = false;
        let mut by_ip: BTreeMap<String, Vec<(HealthCheck, ProbeResult)>> = BTreeMap::new();
        for check in &checks {
            if cancel.load(Ordering::Relaxed) {
                stop_after_port = true;
                break;
            }
            let mut check_args = (*args).clone();
            check_args.path = check.path.clone();
            check_args.health_checks.clear();
            check_args.ports = vec![port];
            let (check_tx, check_rx) = std::sync::mpsc::channel();
            progress_offsets = run_scan_port(
                targets.clone(),
                Arc::new(check_args),
                check_tx,
                progress.clone(),
                cancel.clone(),
                paused.clone(),
                port,
                false,
                progress_offsets,
                None,
            )
            .await;
            for result in check_rx {
                let _ = tx.send(result.clone());
                by_ip
                    .entry(result.ip.clone())
                    .or_default()
                    .push((check.clone(), result));
            }
            if cancel.load(Ordering::Relaxed) {
                stop_after_port = true;
                break;
            }
        }
        for (ip, entries) in by_ip {
            if let Some(merged) = merge_profile_results(&entries, &expected_checks) {
                all_by_ip.entry(ip).or_default().push(merged);
            }
        }
        if stop_after_port {
            break 'ports;
        }
    }
    progress_offsets.2 += all_by_ip.len();
    for (_, results) in all_by_ip {
        if let Some(result) = merge_port_results(&results) {
            let _ = tx.send(result);
        }
    }
    send_progress(
        progress.as_ref(),
        ScanPhase::Finalizing,
        progress_offsets.0,
        progress_offsets.1,
        0,
        progress_offsets.2,
        None,
    );
    progress_offsets
}

pub async fn run_profile_scan_with_progress(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) {
    run_profile_scan_with_progress_from_offsets(
        targets,
        args,
        tx,
        cancel,
        paused,
        progress,
        (0, 0, 0),
    )
    .await;
}

fn merge_profile_results(
    entries: &[(HealthCheck, ProbeResult)],
    expected_checks: &[HealthCheck],
) -> Option<ProbeResult> {
    let (_, mut merged) = entries.first().cloned()?;
    let summary = entries
        .iter()
        .filter(|(check, _)| check.required)
        .map(|(_, result)| result)
        .max_by(|left, right| {
            left.p95
                .partial_cmp(&right.p95)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .success_rate
                        .partial_cmp(&left.success_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
        .unwrap_or(&entries[0].1);
    let aggregate_entries: Vec<&ProbeResult> = entries
        .iter()
        .filter(|(check, _)| check.required)
        .map(|(_, result)| result)
        .collect();
    let aggregate_entries = if aggregate_entries.is_empty() {
        entries.iter().map(|(_, result)| result).collect()
    } else {
        aggregate_entries
    };
    let ok = aggregate_entries.iter().map(|result| result.ok).sum();
    let fail = aggregate_entries.iter().map(|result| result.fail).sum();
    let completed = aggregate_entries
        .iter()
        .map(|result| result.completed)
        .sum();
    let loss = aggregate_entries.iter().map(|result| result.loss).sum();
    let success_rate = if completed > 0 {
        ok as f64 / completed as f64
    } else {
        0.0
    };
    let packet_loss = if completed > 0 {
        loss as f64 / completed as f64
    } else {
        0.0
    };
    let (success_rate_lower, success_rate_upper) =
        wilson_interval(ok, completed, summary.score_confidence);
    let score_entries: Vec<&(HealthCheck, ProbeResult)> =
        entries.iter().filter(|(check, _)| check.required).collect();
    let score_entries = if score_entries.is_empty() {
        entries.iter().collect()
    } else {
        score_entries
    };
    let total_weight: f64 = score_entries
        .iter()
        .map(|(check, _)| check.weight.max(0.0))
        .sum();
    let weighted_score = score_entries
        .iter()
        .map(|(check, result)| check.weight.max(0.0) * result.score)
        .sum::<f64>();
    let weighted_min_score = score_entries
        .iter()
        .map(|(check, result)| check.weight.max(0.0) * result.min_score)
        .sum::<f64>();
    let weighted_max_score = score_entries
        .iter()
        .map(|(check, result)| check.weight.max(0.0) * result.max_score)
        .sum::<f64>();
    let normalize = |value: f64| {
        if total_weight > 0.0 {
            value / total_weight
        } else {
            0.0
        }
    };
    let required_ok = expected_checks
        .iter()
        .filter(|check| check.required)
        .all(|check| {
            entries
                .iter()
                .any(|(entry, result)| entry.name == check.name && result.ok > 0)
        });
    let aggregate_healthy = entries.iter().any(|(_, result)| result.ok > 0);

    merged.protocol = summary.protocol.clone();
    merged.ok = ok;
    merged.fail = fail;
    merged.completed = completed;
    merged.avg = summary.avg;
    merged.p50 = summary.p50;
    merged.p90 = summary.p90;
    merged.p95 = summary.p95;
    merged.max = summary.max;
    merged.jitter = summary.jitter;
    merged.stddev = summary.stddev;
    merged.loss = loss;
    merged.packet_loss = packet_loss;
    merged.samples = summary.samples.clone();
    merged.failures = entries
        .iter()
        .flat_map(|(_, result)| result.failures.iter().cloned())
        .collect();
    merged.diagnostics = entries
        .iter()
        .flat_map(|(_, result)| result.diagnostics.iter().cloned())
        .collect();
    merged.colo = summary.colo.clone();
    merged.country = summary.country.clone();
    merged.cold_ms = summary.cold_ms;
    merged.success_rate = success_rate;
    merged.min_score = normalize(weighted_min_score);
    merged.max_score = normalize(weighted_max_score);
    merged.success_rate_lower = success_rate_lower;
    merged.success_rate_upper = success_rate_upper;
    merged.score_confidence = summary.score_confidence;
    merged.score = normalize(weighted_score);
    merged.health_ok = required_ok && aggregate_healthy;
    merged.checks = entries
        .iter()
        .map(|(check, result)| CheckResult {
            name: check.name.clone(),
            path: check.path.clone(),
            required: check.required,
            weight: check.weight,
            score: result.score,
            healthy: result.ok > 0,
            ok: result.ok,
            fail: result.fail,
            completed: result.completed,
            success_rate: result.success_rate,
            avg: result.avg,
            p50: result.p50,
            p90: result.p90,
            p95: result.p95,
            max: result.max,
            jitter: result.jitter,
            stddev: result.stddev,
            packet_loss: result.packet_loss,
            cold_ms: result.cold_ms,
            colo: result.colo.clone(),
        })
        .collect();
    merged.decision = if !required_ok {
        "required_check_failed".to_string()
    } else if !aggregate_healthy {
        "discarded".to_string()
    } else {
        "competitive".to_string()
    };
    Some(merged)
}

/// Select which CIDRs to focus the second phase on, given the discovery-pass
/// results. When `prefer_colo` is set, focus the CIDRs that produced that colo;
/// otherwise focus the CIDRs whose best discovery score ranks within `limit`.
fn select_focus_cidrs(
    phase1: &[ProbeResult],
    selected_cidrs: &[String],
    prefer_colo: Option<&str>,
    top: usize,
) -> Vec<String> {
    let nets: Vec<(IpNet, String)> = selected_cidrs
        .iter()
        .filter_map(|c| IpNet::from_str(c).ok().map(|n| (n, c.clone())))
        .collect();

    if let Some(want) = prefer_colo {
        let want = want.to_ascii_uppercase();
        let mut focus = Vec::new();
        for r in phase1 {
            if r.ok == 0 {
                continue;
            }
            let Some(colo) = r.colo.as_deref() else {
                continue;
            };
            if !colo.eq_ignore_ascii_case(&want) {
                continue;
            }
            if let Ok(ip) = IpAddr::from_str(&r.ip) {
                if let Some((_, cidr)) = nets.iter().find(|(n, _)| n.contains(&ip)) {
                    if !focus.contains(cidr) {
                        focus.push(cidr.clone());
                    }
                }
            }
        }
        return focus;
    }

    let mut best: BTreeMap<String, f64> = BTreeMap::new();
    for r in phase1 {
        if r.ok == 0 {
            continue;
        }
        if let Ok(ip) = IpAddr::from_str(&r.ip) {
            if let Some((_, cidr)) = nets.iter().find(|(n, _)| n.contains(&ip)) {
                let entry = best.entry(cidr.clone()).or_insert(0.0);
                if r.score > *entry {
                    *entry = r.score;
                }
            }
        }
    }
    let mut ranked: Vec<(f64, String)> = best.into_iter().map(|(c, s)| (s, c)).collect();
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().take(top).map(|(_, c)| c).collect()
}

/// Run a two-phase, colo-aware scan. With `two_phase` disabled, or when no
/// CIDRs are supplied, this delegates to `run_scan` over the full target set.
/// Otherwise it runs a sparse discovery pass, then allocates the remaining
/// probe budget to CIDRs that produced the best Cloudflare colos.
pub async fn run_scan_two_phase(
    selected_cidrs: Vec<String>,
    config: Arc<AppConfig>,
    prefer_colo: Option<String>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) -> Result<Vec<String>> {
    run_scan_two_phase_with_progress(
        selected_cidrs,
        config,
        prefer_colo,
        tx,
        cancel,
        paused,
        None,
    )
    .await
}

pub async fn run_scan_two_phase_with_progress(
    selected_cidrs: Vec<String>,
    config: Arc<AppConfig>,
    prefer_colo: Option<String>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) -> Result<Vec<String>> {
    if !config.two_phase || selected_cidrs.is_empty() {
        let targets = collect_from_cidrs_with_seed(
            &selected_cidrs,
            config.sample_per_cidr,
            if config.seed == 0 {
                rand::random()
            } else {
                config.seed
            },
        )?;
        let actual = targets.clone();
        run_scan_with_progress(targets, config, tx, cancel, paused, progress).await;
        return Ok(actual);
    }

    let discover_per = (config.sample_per_cidr as f64 * config.discover_fraction)
        .max(1.0)
        .round() as usize;
    let focus_per = config.sample_per_cidr.saturating_sub(discover_per).max(1);
    let base_seed = if config.seed == 0 {
        rand::random()
    } else {
        config.seed
    };

    // Discovery pass.
    send_progress(progress.as_ref(), ScanPhase::Discovery, 0, 0, 0, 0, None);
    let (p1_tx, p1_rx) = std::sync::mpsc::channel();
    let targets1 = collect_from_cidrs_with_seed(&selected_cidrs, discover_per, base_seed)?;
    let mut actual_targets: BTreeSet<String> = targets1.iter().cloned().collect();
    let progress_offsets = run_scan_with_progress_from_offsets(
        targets1,
        config.clone(),
        p1_tx,
        cancel.clone(),
        paused.clone(),
        progress.clone(),
        (0, 0, 0),
        Some(ScanPhase::Discovery),
    )
    .await;
    let phase1: Vec<ProbeResult> = p1_rx.iter().collect();
    for result in &phase1 {
        let _ = tx.send(result.clone());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(actual_targets.into_iter().collect());
    }

    let focus_limit = if config.two_phase_focus_cidrs == 0 {
        selected_cidrs.len()
    } else {
        config.two_phase_focus_cidrs
    };
    let focus = select_focus_cidrs(
        &phase1,
        &selected_cidrs,
        prefer_colo.as_deref(),
        focus_limit,
    );
    let focus_set: BTreeSet<String> = focus.iter().cloned().collect();

    // Focus pass: oversample the CIDRs that produced good colos; keep a light
    // top-up on the rest. A different seed avoids re-probing identical IPs.
    let focus_seed = base_seed
        .wrapping_mul(2)
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut targets2: BTreeSet<String> = BTreeSet::new();
    let mut rng = StdRng::seed_from_u64(focus_seed);
    for cidr in &selected_cidrs {
        let net = match IpNet::from_str(cidr) {
            Ok(net) => net,
            Err(_) => continue,
        };
        let per = if focus_set.contains(cidr) {
            focus_per
        } else {
            discover_per
        };
        for _ in 0..per {
            if let Some(ip) = random_ip_from_net(net, &mut rng) {
                targets2.insert(ip.to_string());
            }
        }
    }

    if !targets2.is_empty() {
        actual_targets.extend(targets2.iter().cloned());
        send_progress(progress.as_ref(), ScanPhase::Focus, 0, 0, 0, 0, None);
        run_scan_with_progress_from_offsets(
            targets2.into_iter().collect(),
            config,
            tx,
            cancel,
            paused,
            progress,
            progress_offsets,
            Some(ScanPhase::Focus),
        )
        .await;
    }
    Ok(actual_targets.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::{
        adaptive_progress_reason, bootstrap_score_interval, cidr_valid,
        collect_from_cidrs_with_seed, https_authority, merge_port_results, merge_profile_results,
        parse_colo, reconcile_worker_permits, record_best, remaining_measured_work,
        resolve_host_for_ip, result_confidence, result_status, score_from_samples,
        select_focus_cidrs, select_next_target, should_stop_early, validate_response,
        wilson_interval, DiagnosticCategory, ProbeResult, TargetState,
    };
    use crate::adaptive::{Action, ApplyResult, Decision, SignalDirection};
    use crate::config::{AppConfig, HealthCheck};
    use tokio::sync::Semaphore;

    fn state(
        ip: &str,
        completed: usize,
        scheduled: usize,
        samples: &[f64],
        fail: usize,
    ) -> TargetState {
        TargetState {
            ip: ip.to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: samples.to_vec(),
            protocols: Vec::new(),
            ok: samples.len(),
            fail,
            loss: 0,
            scheduled,
            completed,
            in_flight: false,
            failures: Vec::new(),
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
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
    fn cidr_address_count_handles_ipv4_ipv6_and_saturation() {
        assert_eq!(super::cidr_address_count("192.0.2.1"), Some(1));
        assert_eq!(super::cidr_address_count("192.0.2.0/31"), Some(2));
        assert_eq!(super::cidr_address_count("192.0.2.0/24"), Some(256));
        assert_eq!(super::cidr_address_count("2001:db8::1"), Some(1));
        assert_eq!(super::cidr_address_count("2001:db8::/120"), Some(256));
        assert_eq!(super::cidr_address_count("::/0"), Some(u128::MAX));
        assert_eq!(super::cidr_address_count("invalid"), None);
    }

    #[test]
    fn estimated_targets_cap_each_cidr_by_capacity() {
        let cidrs = vec![
            "192.0.2.1/32".to_string(),
            "192.0.2.0/24".to_string(),
            "2001:db8::/126".to_string(),
        ];
        assert_eq!(super::workload_for_cidrs(&cidrs, 4096, 1, 1).total_ips, 261);
    }

    #[test]
    fn workload_summary_caps_each_range_and_saturates_probe_math() {
        let cidrs = vec![
            "192.0.2.1/32".to_string(),
            "192.0.2.0/24".to_string(),
            "188.114.96.0/20".to_string(),
            "2001:db8::1/128".to_string(),
            "2001:db8::/64".to_string(),
        ];
        let summary = super::workload_for_cidrs(&cidrs, 4096, 3, 2);
        assert_eq!(summary.total_ips, 1 + 256 + 4096 + 1 + 4096);
        assert_eq!(summary.total_probes, summary.total_ips * 6);
        assert_eq!(summary.ranges[0].capacity, 1);
        assert_eq!(summary.ranges[1].capacity, 256);
        assert_eq!(summary.ranges[2].capacity, 4096);
        assert_eq!(summary.ranges[4].estimated_ips, 4096);

        let saturated = super::workload_for_cidrs(
            &["::/0".to_string(), "::/0".to_string()],
            usize::MAX,
            usize::MAX,
            usize::MAX,
        );
        assert_eq!(saturated.total_ips, (usize::MAX as u128).saturating_mul(2));
        assert_eq!(saturated.total_probes, u128::MAX);
    }

    #[test]
    fn resolve_host_for_ip_strips_ports_without_breaking_ipv6() {
        assert_eq!(resolve_host_for_ip("example.test:443"), "example.test");
        assert_eq!(resolve_host_for_ip("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(resolve_host_for_ip("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn adaptive_progress_reason_distinguishes_pending_resize() {
        let decision = Decision {
            action: Action::ScaleDown(1),
            signal: SignalDirection::Down,
            reason: "failure pressure is sustained".to_string(),
        };
        assert_eq!(
            adaptive_progress_reason(
                &decision,
                ApplyResult {
                    resized: false,
                    workers: 3,
                }
            ),
            "failure pressure is sustained; awaiting hysteresis"
        );
        assert_eq!(
            adaptive_progress_reason(
                &decision,
                ApplyResult {
                    resized: true,
                    workers: 2,
                }
            ),
            "failure pressure is sustained"
        );
    }

    #[test]
    fn worker_permits_follow_target_without_reclaiming_active_probes() {
        let sem = Semaphore::new(4);
        let first = sem.try_acquire().expect("first permit");
        let second = sem.try_acquire().expect("second permit");

        reconcile_worker_permits(&sem, 2, 2);
        assert_eq!(sem.available_permits(), 0);

        drop(first);
        reconcile_worker_permits(&sem, 2, 1);
        assert_eq!(sem.available_permits(), 1);

        reconcile_worker_permits(&sem, 4, 1);
        assert_eq!(sem.available_permits(), 3);
        drop(second);
    }

    #[test]
    fn https_authority_formats_supported_ports_and_ipv6() {
        assert_eq!(https_authority("example.test", 2053), "example.test:2053");
        assert_eq!(
            https_authority("example.test:443", 8443),
            "example.test:8443"
        );
        assert_eq!(https_authority("[2001:db8::1]", 2087), "[2001:db8::1]:2087");
        assert_eq!(https_authority("2001:db8::1", 2096), "[2001:db8::1]:2096");
    }

    #[test]
    fn validation_accepts_default_2xx_and_required_content() {
        let config = AppConfig {
            required_body_markers: vec!["colo=FRA".to_string()],
            required_headers: vec![" content-type = text/plain ".to_string()],
            ..AppConfig::default()
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        assert!(validate_response(200, &headers, "colo=FRA", None, &config).is_none());
    }

    #[test]
    fn validation_reports_status_body_and_header_failures() {
        let config = AppConfig {
            expected_statuses: vec![204],
            ..AppConfig::default()
        };
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(
            validate_response(200, &headers, "", None, &config)
                .unwrap()
                .category,
            DiagnosticCategory::HttpStatus
        );

        let config = AppConfig {
            required_body_markers: vec!["healthy".to_string()],
            ..AppConfig::default()
        };
        assert_eq!(
            validate_response(200, &headers, "not-ready", None, &config)
                .unwrap()
                .category,
            DiagnosticCategory::ValidationBody
        );

        let config = AppConfig {
            required_headers: vec!["x-health=ok".to_string()],
            ..AppConfig::default()
        };
        assert_eq!(
            validate_response(200, &headers, "", None, &config)
                .unwrap()
                .category,
            DiagnosticCategory::ValidationHeader
        );
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
    fn remaining_work_excludes_pending_warmups_and_stopped_targets() {
        let mut pending_warmup = state("192.0.2.1", 0, 0, &[], 0);
        pending_warmup.warmup_done = false;
        let ready = state("192.0.2.2", 1, 1, &[0.1], 0);
        let mut stopped = state("192.0.2.3", 0, 0, &[], 0);
        stopped.stopped_early = true;
        assert_eq!(
            remaining_measured_work(&[pending_warmup, ready, stopped], 3),
            2
        );
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
    fn wilson_interval_is_wider_for_small_samples() {
        let small = wilson_interval(3, 3, 0.95);
        let large = wilson_interval(30, 30, 0.95);
        assert!(small.0 < large.0);
        assert!(small.1 - small.0 > large.1 - large.0);
    }

    #[test]
    fn bootstrap_interval_is_deterministic_for_an_ip() {
        let state = state("192.0.2.77", 4, 4, &[0.010, 0.011, 0.012, 0.013], 0);
        assert_eq!(
            bootstrap_score_interval(&state, 0.95),
            bootstrap_score_interval(&state, 0.95)
        );
    }

    #[test]
    fn cached_bootstrap_interval_refreshes_after_probe_state_changes() {
        let mut state = state("192.0.2.77", 4, 4, &[0.010, 0.011, 0.012, 0.013], 0);
        let first = state.cached_bootstrap_interval();
        state.samples.push(1.0);
        state.ok += 1;
        state.completed += 1;
        state.bootstrap_interval = None;
        let refreshed = state.cached_bootstrap_interval();

        assert_ne!(first, refreshed);
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

        let with_warmup = TargetState::new("192.0.2.1".to_string(), &enabled, 4, 443);
        let without_warmup = TargetState::new("192.0.2.1".to_string(), &disabled, 4, 443);

        assert!(!with_warmup.warmup_done);
        assert!(without_warmup.warmup_done);
    }

    #[test]
    fn failed_client_setup_is_excluded_from_warmup() {
        let enabled = AppConfig {
            warmup: true,
            ..Default::default()
        };
        // An unresolvable/invalid IP makes client construction fail, so the
        // target is completed during initialization and must not be selected
        // for a warmup probe (which would panic on the missing client).
        let failed = TargetState::new("not-an-ip".to_string(), &enabled, 4, 443);
        assert!(failed.warmup_done);
        assert_eq!(failed.completed, 4);
        assert_eq!(failed.fail, 4);
    }

    #[test]
    fn warmup_excluded_from_latency_stats() {
        let mut state = TargetState {
            ip: "192.0.2.1".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.2, 0.3, 0.25],
            protocols: vec!["h2".to_string(); 3],
            ok: 3,
            fail: 0,
            loss: 0,
            scheduled: 3,
            completed: 3,
            in_flight: false,
            failures: Vec::new(),
            diagnostics: Vec::new(),
            colo: Some("FRA".to_string()),
            cold_ms: Some(0.05),
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        };
        let result = state.result();
        // Steady-state only: cold_ms is separate and samples exclude the warmup.
        assert_eq!(result.cold_ms, Some(50.0));
        assert_eq!(result.colo, Some("FRA".to_string()));
        assert_eq!(result.avg, (0.2 + 0.3 + 0.25) / 3.0);
        // jitter = p95 - p50; with sorted [0.2, 0.25, 0.3] that is 0.30 - 0.25 = 0.05.
        assert!((result.jitter - 0.05).abs() < f64::EPSILON);
        assert!((result.packet_loss - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn discarded_cold_success_counts_toward_reliability_not_latency() {
        let mut state = state("192.0.2.1", 1, 1, &[], 0);
        state.ok = 1;
        state.cold_ms = Some(0.250);

        let result = state.result();

        assert_eq!(result.ok, 1);
        assert_eq!(result.completed, 1);
        assert_eq!(result.success_rate, 1.0);
        assert_eq!(result_status(&result), "READY");
        assert!(result.health_ok);
        assert!(result.samples.is_empty());
        assert_eq!(result.avg, 0.0);
        assert_eq!(result.cold_ms, Some(250.0));
    }

    #[test]
    fn jitter_stddev_and_packet_loss_are_computed() {
        let mut state = TargetState {
            ip: "192.0.2.1".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.20, 0.30],
            protocols: vec!["h2".to_string(); 3],
            ok: 3,
            fail: 1,
            loss: 1,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: vec!["request timeout".to_string()],
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        };
        let result = state.result();
        // sorted samples [0.10, 0.20, 0.30]: p50 = 0.20, p95 = 0.30.
        assert_eq!(result.p50, 0.20);
        assert_eq!(result.p95, 0.30);
        assert!((result.jitter - 0.10).abs() < f64::EPSILON);
        let mean = 0.20;
        let expected_stddev =
            ((0.10f64 - mean).powi(2) + (0.20f64 - mean).powi(2) + (0.30f64 - mean).powi(2)) / 2.0;
        assert!((result.stddev - expected_stddev.sqrt()).abs() < 1e-9);
        // 1 lost probe out of 4 attempted => 0.25 packet loss.
        assert!((result.packet_loss - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn score_penalizes_jitter_and_loss() {
        // Equal p95/max values with different p50 values isolate jitter.
        let steady = TargetState {
            ip: "192.0.2.1".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.30, 0.30],
            protocols: vec!["h2".to_string(); 4],
            ok: 4,
            fail: 0,
            loss: 0,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: Vec::new(),
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 0.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        let jittery = TargetState {
            ip: "192.0.2.2".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.10, 0.30, 0.30],
            protocols: vec!["h2".to_string(); 4],
            ok: 4,
            fail: 0,
            loss: 0,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: Vec::new(),
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 0.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        assert_eq!(steady.p95, jittery.p95);
        assert_eq!(steady.max, jittery.max);
        assert!(steady.jitter < jittery.jitter);
        assert!(steady.score > jittery.score);

        // Equal reliability with different failure classification isolates
        // packet loss; disabling jitter must not disable the loss penalty.
        let reliable = TargetState {
            ip: "192.0.2.3".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.20],
            protocols: vec!["h2".to_string(); 3],
            ok: 3,
            fail: 1,
            loss: 0,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: vec!["HTTP status 500".to_string()],
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 0.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        let lossy = TargetState {
            ip: "192.0.2.4".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.20],
            protocols: vec!["h2".to_string(); 3],
            ok: 3,
            fail: 1,
            loss: 1,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: vec!["request timeout".to_string()],
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 0.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        assert_eq!(reliable.success_rate, lossy.success_rate);
        assert!(reliable.packet_loss < lossy.packet_loss);
        assert!(reliable.score > lossy.score);
    }

    #[test]
    fn score_limits_the_influence_of_a_single_extreme_tail() {
        let ordinary = score_from_samples(&[0.10; 20], None, 20, 20, 0, 1.0, 0.0);
        let mut samples = vec![0.10; 19];
        samples.push(10.0);
        let extreme = score_from_samples(&samples, None, 20, 20, 0, 1.0, 0.0);

        assert!(extreme > ordinary / 3.0);
    }

    #[test]
    fn cold_fallback_prevents_empty_sample_score_inflation() {
        let fallback = score_from_samples(&[], Some(0.10), 1, 1, 0, 1.0, 0.0);
        let ordinary = score_from_samples(&[0.10], None, 1, 1, 0, 1.0, 0.0);

        assert_eq!(fallback, ordinary);
        assert!(fallback < 100.0);
    }

    #[test]
    fn cold_fallback_is_used_for_result_score_but_not_latency_samples() {
        let mut state = state("192.0.2.8", 1, 1, &[], 0);
        state.ok = 1;
        state.cold_ms = Some(0.10);

        let result = state.result();

        assert_eq!(result.samples, Vec::<f64>::new());
        assert_eq!(result.avg, 0.0);
        assert_eq!(result.p95, 0.0);
        assert!(result.score < 100.0);
    }

    fn early_stop_config() -> AppConfig {
        AppConfig {
            early_stop: true,
            early_stop_loss_streak: 5,
            early_stop_min_samples: 3,
            early_stop_success_floor: 0.5,
            early_stop_prune: true,
            early_stop_prune_margin: 0.2,
            ..Default::default()
        }
    }

    #[test]
    fn score_from_samples_matches_result_score() {
        // The shared scoring helper must agree with the full ProbeResult score.
        let mut state = TargetState {
            ip: "192.0.2.1".to_string(),
            port: 443,
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.20, 0.30],
            protocols: vec!["h2".to_string(); 3],
            ok: 3,
            fail: 1,
            loss: 1,
            scheduled: 4,
            completed: 4,
            in_flight: false,
            failures: vec!["request timeout".to_string()],
            diagnostics: Vec::new(),
            colo: None,
            cold_ms: None,
            warmup_done: true,
            warmup_in_flight: false,
            warmup_discard_first: false,
            bootstrap_interval: None,
            stability_weight: 1.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        };
        let cfg = early_stop_config();
        let expected = state.result().score;
        assert!((state.current_score() - expected).abs() < 1e-12);
        let _ = cfg;
    }

    #[test]
    fn early_stop_fires_on_loss_streak_after_min_samples() {
        // Isolate the loss-streak rule by disabling the low-success-rate rule.
        let mut cfg = early_stop_config();
        cfg.early_stop_success_floor = 0.0;
        let mut s = state("192.0.2.1", 0, 0, &[], 0);
        // Four losses, below the 5-streak threshold but at min_samples: rate is 0.
        for _ in 0..4 {
            s.completed += 1;
            s.loss_streak += 1;
        }
        assert!(!should_stop_early(&mut s, &cfg, &[], false));
        // Fifth consecutive loss crosses the streak threshold.
        s.completed += 1;
        s.loss_streak += 1;
        assert!(should_stop_early(&mut s, &cfg, &[], false));
    }

    #[test]
    fn early_stop_fires_on_low_success_rate() {
        let cfg = early_stop_config();
        let mut s = state("192.0.2.1", 3, 3, &[0.1], 2);
        // 1 success out of 3 completed => 0.33 < 0.5 floor.
        assert!(should_stop_early(&mut s, &cfg, &[], false));
    }

    #[test]
    fn early_stop_does_not_fire_before_min_samples() {
        let cfg = early_stop_config();
        let mut s = state("192.0.2.1", 1, 1, &[], 1);
        // A single failure must not abort a target prematurely.
        assert!(!should_stop_early(&mut s, &cfg, &[], false));
    }

    #[test]
    fn early_stop_prunes_clearly_worse_targets() {
        let cfg = early_stop_config();
        // Leaderboard already full of strong candidates (score ~ high).
        let best: Vec<(f64, f64)> = vec![(10.0, 0.05); cfg.top];
        let mut worse = state("192.0.2.9", 4, 4, &[0.9, 0.9, 0.9, 0.9], 0);
        // 0.9s latency => far below the leaderboard's score; should be pruned.
        assert!(should_stop_early(&mut worse, &cfg, &best, false));
    }

    #[test]
    fn early_stop_prune_margin_is_tolerance_slack() {
        let cfg = early_stop_config();
        let best: Vec<(f64, f64)> = vec![(10.0, 0.05); cfg.top];

        let mut within_tolerance = state("192.0.2.10", 3, 3, &[0.117647; 3], 0);
        assert!(!should_stop_early(
            &mut within_tolerance,
            &cfg,
            &best,
            false
        ));

        let mut beyond_tolerance = state("192.0.2.11", 3, 3, &[0.125; 3], 0);
        assert!(should_stop_early(&mut beyond_tolerance, &cfg, &best, false));
    }

    #[test]
    fn early_stop_disabled_by_config() {
        let mut cfg = early_stop_config();
        cfg.early_stop = false;
        let mut s = state("192.0.2.1", 6, 6, &[], 6);
        s.loss_streak = 6;
        assert!(!should_stop_early(&mut s, &cfg, &[], false));
    }

    #[test]
    fn early_stopped_result_uses_actual_measurements_and_serializes_marker() {
        let mut s = state("192.0.2.1", 3, 3, &[0.1], 2);
        s.loss = 2;
        s.loss_streak = 2;
        s.failures = vec!["request timeout".to_string(); 2];
        s.stopped_early = true;

        let result = s.result();
        assert_eq!(result.completed, 3);
        assert_eq!(result.ok, 1);
        assert_eq!(result.fail, 2);
        assert!((result.success_rate - (1.0 / 3.0)).abs() < f64::EPSILON);
        assert!((result.packet_loss - (2.0 / 3.0)).abs() < f64::EPSILON);
        assert!(result.stopped_early);
        assert!(!s.has_remaining_probe(8));

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["stopped_early"], true);
    }

    #[test]
    fn record_best_keeps_top_scores_sorted() {
        let mut best: Vec<(f64, f64)> = Vec::new();
        let make = |score: f64| ProbeResult {
            ip: String::new(),
            port: 443,
            protocol: String::new(),
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
            samples: vec![0.1],
            failures: Vec::new(),
            diagnostics: Vec::new(),
            success_rate: 1.0,
            score,
            colo: None,
            country: None,
            cold_ms: None,
            stopped_early: false,
            min_score: score,
            max_score: score,
            success_rate_lower: 1.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: Vec::new(),
            health_ok: true,
            port_results: Vec::new(),
        };
        for s in [1.0, 5.0, 3.0, 9.0, 2.0] {
            record_best(&mut best, &make(s), 3);
        }
        assert_eq!(best.len(), 3);
        assert_eq!(best[0].0, 9.0);
        assert_eq!(best[1].0, 5.0);
        assert_eq!(best[2].0, 3.0);
    }

    fn focus_result(ip: &str, colo: Option<&str>, score: f64, ok: usize) -> ProbeResult {
        ProbeResult {
            ip: ip.to_string(),
            port: 443,
            protocol: String::new(),
            ok,
            fail: 0,
            completed: ok,
            avg: 0.0,
            p50: 0.0,
            p90: 0.0,
            p95: 0.0,
            max: 0.0,
            jitter: 0.0,
            stddev: 0.0,
            loss: 0,
            packet_loss: 0.0,
            samples: vec![0.1; ok],
            failures: Vec::new(),
            diagnostics: Vec::new(),
            success_rate: 1.0,
            score,
            colo: colo.map(|c| c.to_string()),
            country: None,
            cold_ms: None,
            stopped_early: false,
            min_score: score,
            max_score: score,
            success_rate_lower: 1.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: Vec::new(),
            health_ok: true,
            port_results: Vec::new(),
        }
    }

    #[test]
    fn port_merge_chooses_best_healthy_port_and_keeps_details() {
        let mut failed = focus_result("192.0.2.1", None, 100.0, 0);
        failed.port = 443;
        failed.health_ok = false;
        let mut healthy = focus_result("192.0.2.1", None, 2.0, 1);
        healthy.port = 2053;
        let merged = merge_port_results(&[failed, healthy]).unwrap();
        assert_eq!(merged.port, 2053);
        assert!(merged.health_ok);
        assert_eq!(merged.port_results.len(), 2);
        assert_eq!(merged.port_results[0].port, 443);
    }

    #[test]
    fn select_focus_cidrs_prefers_named_colo() {
        let cidrs = vec!["192.0.2.0/24".to_string(), "198.51.100.0/24".to_string()];
        let phase1 = vec![
            focus_result("192.0.2.5", Some("FRA"), 9.0, 4),
            focus_result("198.51.100.5", Some("AMS"), 8.0, 4),
        ];
        let focus = select_focus_cidrs(&phase1, &cidrs, Some("FRA"), 50);
        assert_eq!(focus, vec!["192.0.2.0/24".to_string()]);
    }

    #[test]
    fn select_focus_cidrs_ranks_by_score() {
        let cidrs = vec!["192.0.2.0/24".to_string(), "198.51.100.0/24".to_string()];
        let phase1 = vec![
            focus_result("192.0.2.5", Some("FRA"), 9.0, 4),
            focus_result("198.51.100.5", Some("AMS"), 8.0, 4),
        ];
        // top=1 keeps only the highest-scoring CIDR.
        let focus = select_focus_cidrs(&phase1, &cidrs, None, 1);
        assert_eq!(focus, vec!["192.0.2.0/24".to_string()]);
        // top=2 keeps both.
        let focus2 = select_focus_cidrs(&phase1, &cidrs, None, 2);
        assert_eq!(focus2.len(), 2);
    }

    #[test]
    fn select_focus_cidrs_ignores_failed_targets() {
        let cidrs = vec!["192.0.2.0/24".to_string(), "198.51.100.0/24".to_string()];
        let phase1 = vec![
            focus_result("192.0.2.5", Some("FRA"), 9.0, 0),
            focus_result("198.51.100.5", Some("AMS"), 8.0, 4),
        ];
        let focus = select_focus_cidrs(&phase1, &cidrs, None, 1);
        assert_eq!(focus, vec!["198.51.100.0/24".to_string()]);
    }

    #[test]
    fn profile_merge_aggregates_required_check_counts() {
        let mut passing = focus_result("192.0.2.1", Some("FRA"), 8.0, 2);
        passing.failures = vec!["optional detail".to_string()];
        let mut failing = focus_result("192.0.2.1", Some("AMS"), 2.0, 0);
        failing.fail = 2;
        failing.completed = 2;
        failing.success_rate = 0.0;
        failing.samples.clear();
        failing.failures = vec!["required failure".to_string()];
        let checks = vec![
            HealthCheck {
                name: "primary".to_string(),
                path: "/".to_string(),
                required: true,
                weight: 1.0,
            },
            HealthCheck {
                name: "fallback".to_string(),
                path: "/health".to_string(),
                required: true,
                weight: 1.0,
            },
        ];
        let merged = merge_profile_results(
            &[(checks[0].clone(), passing), (checks[1].clone(), failing)],
            &checks,
        )
        .unwrap();
        assert_eq!(merged.ok, 2);
        assert_eq!(merged.fail, 2);
        assert_eq!(merged.completed, 4);
        assert_eq!(merged.success_rate, 0.5);
        assert_eq!(merged.failures.len(), 2);
        assert_eq!(merged.checks.len(), 2);
        assert!(!merged.health_ok);
    }

    #[test]
    fn profile_merge_optional_checks_do_not_dilute_recommendation_score() {
        let required = focus_result("192.0.2.1", Some("FRA"), 5.0, 2);
        let optional = focus_result("192.0.2.1", Some("AMS"), 100.0, 2);
        let checks = vec![
            HealthCheck {
                name: "primary".to_string(),
                path: "/".to_string(),
                required: true,
                weight: 1.0,
            },
            HealthCheck {
                name: "optional".to_string(),
                path: "/ready".to_string(),
                required: false,
                weight: 100.0,
            },
        ];
        let merged = merge_profile_results(
            &[(checks[0].clone(), required), (checks[1].clone(), optional)],
            &checks,
        )
        .unwrap();
        assert_eq!(merged.score, 5.0);
        assert_eq!(merged.min_score, 5.0);
        assert_eq!(merged.max_score, 5.0);
    }

    #[test]
    fn profile_merge_falls_back_to_all_checks_without_required_checks() {
        let optional = focus_result("192.0.2.1", Some("AMS"), 7.0, 2);
        let checks = vec![HealthCheck {
            name: "optional".to_string(),
            path: "/ready".to_string(),
            required: false,
            weight: 1.0,
        }];
        let merged = merge_profile_results(&[(checks[0].clone(), optional)], &checks).unwrap();
        assert_eq!(merged.score, 7.0);
    }
}
