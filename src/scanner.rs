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

use crate::config::{AppConfig, HealthCheck};

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
    pub avg: f64,
    pub p95: f64,
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
    completed: usize,
    loss: usize,
    stability_weight: f64,
    loss_weight: f64,
) -> f64 {
    let ok = samples.len();
    if ok == 0 {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let max = sorted.last().copied().unwrap_or(0.0);
    let jitter = (p95 - p50).max(0.0);
    let total = completed.max(1);
    let reliability = ok as f64 / total as f64;
    let latency_penalty = max.max(0.001);
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
        .no_proxy()
        .resolve_to_addrs(host, &[socket])
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
        let Some((name, expected)) = expression.split_once('=') else {
            return Some(ProbeDiagnostic {
                category: DiagnosticCategory::ValidationHeader,
                phase: DiagnosticPhase::ResponseHeaders,
                message: format!("invalid required header expression: {expression}"),
                status: Some(status),
                location: location.map(str::to_string),
                elapsed_ms: None,
            });
        };
        let name = name.trim();
        let expected = expected.trim();
        if headers.get(name).and_then(|value| value.to_str().ok()) != Some(expected) {
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
    url: String,
    client: Option<Client>,
    samples: Vec<f64>,
    protocols: Vec<String>,
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
}

impl TargetState {
    fn new(ip: String, args: &AppConfig, probe_count: usize) -> Self {
        let url = format!("https://{}{}", args.host, args.path);
        let client = client_for_ip(&args.host, &ip, args).ok();
        let client_ok = client.is_some();
        let (fail, loss, scheduled, completed) = if client_ok {
            (0, 0, 0, 0)
        } else {
            (probe_count, 0, probe_count, probe_count)
        };

        Self {
            ip,
            url,
            client,
            samples: Vec::new(),
            protocols: Vec::new(),
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
            self.completed,
            self.loss,
            self.stability_weight,
            self.loss_weight,
        )
    }

    #[allow(dead_code)]
    fn result(&mut self) -> ProbeResult {
        self.result_with_mode(false)
    }

    fn result_with_mode(&mut self, adaptive: bool) -> ProbeResult {
        self.samples
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let ok = self.samples.len();
        let avg = if ok > 0 {
            self.samples.iter().sum::<f64>() / ok as f64
        } else {
            0.0
        };

        let p50 = percentile(&self.samples, 0.50);
        let p90 = percentile(&self.samples, 0.90);
        let p95 = percentile(&self.samples, 0.95);
        let max = self.samples.last().copied().unwrap_or(0.0);
        let jitter = if ok > 0 { (p95 - p50).max(0.0) } else { 0.0 };
        let stddev = if ok > 1 {
            let variance =
                self.samples.iter().map(|s| (s - avg).powi(2)).sum::<f64>() / (ok - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        let total = self.completed.max(1);
        let success_rate = ok as f64 / total as f64;
        let packet_loss = self.loss as f64 / total as f64;
        let point_score = score_from_samples(
            &self.samples,
            self.completed,
            self.loss,
            self.stability_weight,
            self.loss_weight,
        );
        let (success_rate_lower, success_rate_upper) =
            wilson_interval(ok, self.completed, self.confidence);
        let (min_score, max_score) = bootstrap_score_interval(self, self.confidence);
        let score = if adaptive { min_score } else { point_score };

        ProbeResult {
            ip: self.ip.clone(),
            protocol: summarize_protocols(&self.protocols),
            ok,
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
            decision: if ok == 0 {
                "discarded"
            } else if self.completed < 3 {
                "insufficient_data"
            } else {
                "competitive"
            }
            .to_string(),
            checks: Vec::new(),
            health_ok: ok > 0,
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
    states: &[TargetState],
    probe_count: usize,
    min_probes: usize,
) -> Option<usize> {
    let bootstrap_intervals: Vec<(f64, f64)> = states
        .iter()
        .map(|state| bootstrap_score_interval(state, state.confidence))
        .collect();
    states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.has_remaining_probe(probe_count))
        .min_by(|(left_index, left), (right_index, right)| {
            let left_min = left.completed < min_probes;
            let right_min = right.completed < min_probes;
            right_min
                .cmp(&left_min)
                .then_with(|| {
                    let (left_min, left_max) = bootstrap_intervals[*left_index];
                    let (right_min, right_max) = bootstrap_intervals[*right_index];
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

fn adaptive_should_stop(index: usize, states: &[TargetState], cfg: &AppConfig) -> bool {
    let state = &states[index];
    if state.completed < cfg.min_probes || state.samples.is_empty() {
        return false;
    }
    let bootstrap_intervals: Vec<(f64, f64)> = states
        .iter()
        .map(|state| bootstrap_score_interval(state, cfg.confidence))
        .collect();
    let own = bootstrap_intervals[index];
    states.iter().enumerate().any(|(other_index, other)| {
        other_index != index && other.completed >= cfg.min_probes && !other.samples.is_empty() && {
            let other_bounds = bootstrap_intervals[other_index];
            other_bounds.0 > own.1
        }
    })
}

/// Decide whether a target should stop being probed before its full probe
/// budget is exhausted. Returns `true` when any early-stop rule applies:
///  * loss streak: `early_stop_loss_streak` consecutive dropped probes;
///  * low success: success rate below `early_stop_success_floor`;
///  * prune: at least `top` READY candidates exist and this target's current
///    best score cannot beat the worst of them by `early_stop_prune_margin`.
///
/// `best` is the running leaderboard of `(score, p95)` for completed targets,
/// capped at `top` entries (see `record_best`).
fn should_stop_early(state: &TargetState, cfg: &AppConfig, best: &[(f64, f64)]) -> bool {
    if !cfg.early_stop {
        return false;
    }

    if state.completed >= cfg.early_stop_min_samples
        && state.loss_streak >= cfg.early_stop_loss_streak
    {
        return true;
    }

    if state.completed >= cfg.early_stop_min_samples {
        let rate = state.samples.len() as f64 / state.completed.max(1) as f64;
        if rate < cfg.early_stop_success_floor {
            return true;
        }
    }

    if cfg.early_stop_prune
        && best.len() >= cfg.top
        && state.samples.len() >= cfg.early_stop_min_samples
    {
        let current = state.current_score();
        let worst_top = best[best.len() - 1].0;
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

    let probe_count = if args.adaptive_probing {
        args.max_probes.max(args.min_probes).max(1)
    } else {
        args.probes.max(1)
    };
    let workers = args.concurrency.max(1);
    let mut states: Vec<TargetState> = targets
        .into_iter()
        .map(|ip| TargetState::new(ip, &args, probe_count))
        .collect();
    let mut futs = FuturesUnordered::new();

    for state in &mut states {
        if state.completed == probe_count {
            let _ = tx.send(state.result_with_mode(args.adaptive_probing));
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
                select_next_target_adaptive(&states, probe_count, args.min_probes)
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
                        state.completed += 1;
                        match sample {
                            Ok((value, protocol, colo)) => {
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
                                    state.loss_streak = 0;
                                    state.samples.push(value);
                                    state.protocols.push(protocol);
                                    if state.colo.is_none() {
                                        state.colo = colo;
                                    }
                                }
                            }
                            Err(diagnostic) => {
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
                        let legacy_stop = adaptive_min_reached && should_stop_early(state, &args, &best);
                        let completed = state.completed;
                        let _ = state;
                        let adaptive_stop = args.adaptive_probing && adaptive_should_stop(index, &states, &args);
                        if adaptive_stop || legacy_stop {
                            // Target is dead or cannot beat the current
                            // leaderboard; stop probing it and emit a partial
                            // result now rather than spending the full budget.
                            let state = &mut states[index];
                            state.stopped_early = true;
                            let result = state.result_with_mode(args.adaptive_probing);
                            record_best(&mut best, &result, args.top);
                            let _ = tx.send(result);
                        } else if completed == probe_count {
                            let state = &mut states[index];
                            let result = state.result_with_mode(args.adaptive_probing);
                            record_best(&mut best, &result, args.top);
                            let _ = tx.send(result);
                        }
                    }
                }
            }
        }
    }
}

/// Run every configured health check and merge the per-path results into one
/// target result. Checks share the same target set and validation policy, but
/// currently use independent clients and warmup requests; the first check
/// remains the compatibility/primary result.
pub async fn run_profile_scan(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    tx: std::sync::mpsc::Sender<ProbeResult>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    let checks = effective_health_checks(&args);
    if checks.len() <= 1 {
        run_scan(targets, args, tx, cancel, paused).await;
        return;
    }

    let mut by_ip: BTreeMap<String, Vec<(HealthCheck, ProbeResult)>> = BTreeMap::new();
    for check in checks {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut check_args = (*args).clone();
        check_args.path = check.path.clone();
        check_args.health_checks.clear();
        let (check_tx, check_rx) = std::sync::mpsc::channel();
        run_scan(
            targets.clone(),
            Arc::new(check_args),
            check_tx,
            cancel.clone(),
            paused.clone(),
        )
        .await;
        for result in check_rx {
            by_ip
                .entry(result.ip.clone())
                .or_default()
                .push((check.clone(), result));
        }
    }

    for (_, entries) in by_ip {
        let Some((_, mut merged)) = entries.first().cloned() else {
            continue;
        };
        let total_weight: f64 = entries.iter().map(|(check, _)| check.weight.max(0.0)).sum();
        let weighted_score = entries
            .iter()
            .map(|(check, result)| check.weight.max(0.0) * result.score)
            .sum::<f64>();
        let required_ok = entries
            .iter()
            .filter(|(check, _)| check.required)
            .all(|(_, result)| result.ok > 0);
        merged.score = if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        };
        merged.health_ok = required_ok;
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
                avg: result.avg,
                p95: result.p95,
                colo: result.colo.clone(),
            })
            .collect();
        let aggregate_healthy = entries.iter().any(|(_, result)| result.ok > 0);
        merged.decision = if !required_ok {
            "required_check_failed".to_string()
        } else if !aggregate_healthy {
            "discarded".to_string()
        } else {
            "competitive".to_string()
        };
        let _ = tx.send(merged);
    }
}

/// Select which CIDRs to focus the second phase on, given the discovery-pass
/// results. When `prefer_colo` is set, focus the CIDRs that produced that colo;
/// otherwise focus the CIDRs whose best discovery score ranks in the top `top`.
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
) -> Result<()> {
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
        run_scan(targets, config, tx, cancel, paused).await;
        return Ok(());
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
    let (p1_tx, p1_rx) = std::sync::mpsc::channel();
    let targets1 = collect_from_cidrs_with_seed(&selected_cidrs, discover_per, base_seed)?;
    run_scan(
        targets1,
        config.clone(),
        p1_tx,
        cancel.clone(),
        paused.clone(),
    )
    .await;
    let phase1: Vec<ProbeResult> = p1_rx.iter().collect();
    for result in &phase1 {
        let _ = tx.send(result.clone());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }

    let focus = select_focus_cidrs(&phase1, &selected_cidrs, prefer_colo.as_deref(), config.top);
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
        run_scan(targets2.into_iter().collect(), config, tx, cancel, paused).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_score_interval, cidr_valid, collect_from_cidrs_with_seed, parse_colo,
        record_best, result_confidence, result_status, select_focus_cidrs, select_next_target,
        should_stop_early, validate_response, wilson_interval, DiagnosticCategory, ProbeResult,
        TargetState,
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
    fn failed_client_setup_is_excluded_from_warmup() {
        let enabled = AppConfig {
            warmup: true,
            ..Default::default()
        };
        // An unresolvable/invalid IP makes client construction fail, so the
        // target is completed during initialization and must not be selected
        // for a warmup probe (which would panic on the missing client).
        let failed = TargetState::new("not-an-ip".to_string(), &enabled, 4);
        assert!(failed.warmup_done);
        assert_eq!(failed.completed, 4);
        assert_eq!(failed.fail, 4);
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
    fn jitter_stddev_and_packet_loss_are_computed() {
        let mut state = TargetState {
            ip: "192.0.2.1".to_string(),
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.20, 0.30],
            protocols: vec!["h2".to_string(); 3],
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
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.30, 0.30],
            protocols: vec!["h2".to_string(); 4],
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
            stability_weight: 1.0,
            loss_weight: 0.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        let jittery = TargetState {
            ip: "192.0.2.2".to_string(),
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.10, 0.30, 0.30],
            protocols: vec!["h2".to_string(); 4],
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
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.20],
            protocols: vec!["h2".to_string(); 3],
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
            stability_weight: 0.0,
            loss_weight: 1.0,
            confidence: 0.95,
            loss_streak: 0,
            stopped_early: false,
        }
        .result();
        let lossy = TargetState {
            ip: "192.0.2.4".to_string(),
            url: String::new(),
            client: None,
            samples: vec![0.20, 0.20, 0.20],
            protocols: vec!["h2".to_string(); 3],
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
            url: String::new(),
            client: None,
            samples: vec![0.10, 0.20, 0.30],
            protocols: vec!["h2".to_string(); 3],
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
        assert!(!should_stop_early(&s, &cfg, &[]));
        // Fifth consecutive loss crosses the streak threshold.
        s.completed += 1;
        s.loss_streak += 1;
        assert!(should_stop_early(&s, &cfg, &[]));
    }

    #[test]
    fn early_stop_fires_on_low_success_rate() {
        let cfg = early_stop_config();
        let s = state("192.0.2.1", 3, 3, &[0.1], 2);
        // 1 success out of 3 completed => 0.33 < 0.5 floor.
        assert!(should_stop_early(&s, &cfg, &[]));
    }

    #[test]
    fn early_stop_does_not_fire_before_min_samples() {
        let cfg = early_stop_config();
        let s = state("192.0.2.1", 1, 1, &[], 1);
        // A single failure must not abort a target prematurely.
        assert!(!should_stop_early(&s, &cfg, &[]));
    }

    #[test]
    fn early_stop_prunes_clearly_worse_targets() {
        let cfg = early_stop_config();
        // Leaderboard already full of strong candidates (score ~ high).
        let best: Vec<(f64, f64)> = vec![(10.0, 0.05); cfg.top];
        let worse = state("192.0.2.9", 4, 4, &[0.9, 0.9, 0.9, 0.9], 0);
        // 0.9s latency => far below the leaderboard's score; should be pruned.
        assert!(should_stop_early(&worse, &cfg, &best));
    }

    #[test]
    fn early_stop_disabled_by_config() {
        let mut cfg = early_stop_config();
        cfg.early_stop = false;
        let mut s = state("192.0.2.1", 6, 6, &[], 6);
        s.loss_streak = 6;
        assert!(!should_stop_early(&s, &cfg, &[]));
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
        }
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
}
