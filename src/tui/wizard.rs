use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::collections::HashSet;

use crate::config::{
    validate_ports, AppConfig, DiscoveryDriver, HealthCheck, CLOUDFLARE_HTTPS_PORTS,
};
use crate::tui::theme;
use crate::tui::{widgets, App, ButtonAction, ButtonKind, WizardStep};
use tui_slider::{Slider, SliderState};

/// Identifies an editable scan parameter on the settings step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    Host,
    Path,
    Ports,
    ExpectedStatuses,
    RequiredBodyMarkers,
    RequiredHeaders,
    FollowRedirects,
    HealthChecks,
    Warmup,
    Interface,
    TlsFragment,
    DownloadPath,
    UploadPath,
    SpeedPayloadMb,
    SpeedRepetitions,
    SpeedTimeoutMs,
    SamplePerCidr,
    Probes,
    Concurrency,
    TimeoutMs,
    ConnectTimeoutMs,
    Top,
    StabilityWeight,
    LossWeight,
    EarlyStop,
    EarlyStopLossStreak,
    EarlyStopMinSamples,
    EarlyStopPrune,
    EarlyStopPruneMargin,
    TwoPhase,
    DiscoveryDriver,
    DiscoverFraction,
    AdaptiveProbing,
    MinProbes,
    MaxProbes,
    AdaptiveConcurrency,
    MinConcurrency,
    MaxConcurrency,
    Confidence,
}

// Keep this high enough to sample a substantial fraction of a /15 while
// retaining a finite guard against accidental unbounded target generation.
const MAX_SAMPLE_PER_CIDR: usize = 1_000_000;
const MAX_PROBES: usize = 1_000;
const MAX_CONCURRENCY: usize = 10_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
const MAX_CONNECT_TIMEOUT_MS: u64 = 600_000;
const MAX_TOP: usize = 10_000;
const MAX_EARLY_STOP_LOSS_STREAK: usize = 1_000;
const MAX_EARLY_STOP_MIN_SAMPLES: usize = 1_000;
const MAX_SPEED_PAYLOAD_MB: u64 = 1_024;
const MAX_SPEED_REPETITIONS: usize = 100;
const MAX_SPEED_TIMEOUT_MS: u64 = 3_600_000;

impl SettingField {
    /// Values the adaptive score intervals accept. `main` rejects any other
    /// value, so the wizard must never persist anything outside this set.
    const CONFIDENCE_LEVELS: [f64; 3] = [0.90, 0.95, 0.99];

    /// All settings fields in display order, grouped by concern. Group
    /// boundaries are described by [`SettingField::GROUPS`].
    pub const ALL: [SettingField; 39] = [
        // Target
        SettingField::Host,
        SettingField::Path,
        SettingField::Ports,
        SettingField::ExpectedStatuses,
        SettingField::RequiredBodyMarkers,
        SettingField::RequiredHeaders,
        SettingField::FollowRedirects,
        SettingField::HealthChecks,
        SettingField::Warmup,
        // Network
        SettingField::Interface,
        SettingField::TlsFragment,
        // Latency scan
        SettingField::SamplePerCidr,
        SettingField::Probes,
        SettingField::Concurrency,
        SettingField::TimeoutMs,
        SettingField::ConnectTimeoutMs,
        SettingField::Top,
        // Ranking quality
        SettingField::StabilityWeight,
        SettingField::LossWeight,
        // Adaptive scan
        SettingField::EarlyStop,
        SettingField::EarlyStopLossStreak,
        SettingField::EarlyStopMinSamples,
        SettingField::EarlyStopPrune,
        SettingField::EarlyStopPruneMargin,
        SettingField::TwoPhase,
        SettingField::DiscoveryDriver,
        SettingField::DiscoverFraction,
        SettingField::AdaptiveProbing,
        SettingField::MinProbes,
        SettingField::MaxProbes,
        SettingField::AdaptiveConcurrency,
        SettingField::MinConcurrency,
        SettingField::MaxConcurrency,
        SettingField::Confidence,
        // Speed test
        SettingField::DownloadPath,
        SettingField::UploadPath,
        SettingField::SpeedPayloadMb,
        SettingField::SpeedRepetitions,
        SettingField::SpeedTimeoutMs,
    ];

    /// Section headers and the number of consecutive fields in each, in the
    /// same order as [`SettingField::ALL`].
    pub const GROUPS: [(&'static str, usize); 7] = [
        ("Target", 3),
        ("Validation", 6),
        ("Network", 2),
        ("Latency scan", 6),
        ("Ranking quality", 2),
        ("Adaptive scan", 15),
        ("Speed test", 5),
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SettingField::Host => "Host",
            SettingField::Path => "Path",
            SettingField::Ports => "HTTPS ports",
            SettingField::ExpectedStatuses => "Expected statuses",
            SettingField::RequiredBodyMarkers => "Required body markers",
            SettingField::RequiredHeaders => "Required headers",
            SettingField::FollowRedirects => "Follow redirects",
            SettingField::HealthChecks => "Health checks",
            SettingField::Warmup => "Warmup probe",
            SettingField::Interface => "Network interface",
            SettingField::TlsFragment => "TLS fragment (xray)",
            SettingField::DownloadPath => "Download path",
            SettingField::UploadPath => "Upload path",
            SettingField::SpeedPayloadMb => "Speed payload (MB)",
            SettingField::SpeedRepetitions => "Speed repetitions",
            SettingField::SpeedTimeoutMs => "Speed timeout (ms)",
            SettingField::SamplePerCidr => "Sample per CIDR",
            SettingField::Probes => "Probes",
            SettingField::Concurrency => "Starting workers",
            SettingField::TimeoutMs => "Timeout (ms)",
            SettingField::ConnectTimeoutMs => "Connect timeout (ms)",
            SettingField::Top => "Top results",
            SettingField::StabilityWeight => "Stability weight",
            SettingField::LossWeight => "Loss weight",
            SettingField::EarlyStop => "Early stop",
            SettingField::EarlyStopLossStreak => "Stop loss streak",
            SettingField::EarlyStopMinSamples => "Stop min samples",
            SettingField::EarlyStopPrune => "Prune to top-N",
            SettingField::EarlyStopPruneMargin => "Prune margin",
            SettingField::TwoPhase => "Two-phase scan",
            SettingField::DiscoveryDriver => "Discovery driver",
            SettingField::DiscoverFraction => "Discover fraction",
            SettingField::AdaptiveProbing => "Adaptive probing",
            SettingField::MinProbes => "Minimum probes",
            SettingField::MaxProbes => "Maximum probes",
            SettingField::AdaptiveConcurrency => "Adaptive concurrency",
            SettingField::MinConcurrency => "Minimum concurrency",
            SettingField::MaxConcurrency => "Maximum concurrency",
            SettingField::Confidence => "Confidence",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SettingField::Host => "The hostname used in SNI and the Host header for HTTP probes (e.g. app.iplat.ir). Cleanscan resolves this host to the tested edge IPs directly.",
            SettingField::Path => "The HTTP request path to probe (e.g. /cdn-cgi/trace). Typically points to a lightweight text file or endpoint to minimize bandwidth usage.",
            SettingField::Ports => "Cloudflare HTTPS ports to probe. Enter edit mode, then use ↑/↓ to choose a port, Space to toggle it, A to select all, and N to clear all. At least one port is required.",
            SettingField::ExpectedStatuses => "Comma-separated HTTP statuses accepted by the endpoint. Empty means any 2xx response.",
            SettingField::RequiredBodyMarkers => "Comma-separated literal substrings that must occur in the response body.",
            SettingField::RequiredHeaders => "Comma-separated exact header checks in name=value form.",
            SettingField::FollowRedirects => "Follow redirects during validation. Off preserves the default strict behavior.",
            SettingField::HealthChecks => "Optional checks encoded as name|path|required|weight;... . Leave empty to use the primary path.",
            SettingField::Warmup => "Send a discarded connection-establishment request before measured latency probes.",
            SettingField::Interface => "Network interface used for probes, discovery sweeps, and speed tests. Auto (default) lets the OS route every connection; picking an interface (e.g. en0, wlan0, tun0) binds outbound connections to that interface's address so all test traffic leaves through the chosen link (on Linux the interface must have its own route to the targets, as VPN tunnels do). Useful on hosts with multiple uplinks or VPNs. The CLI equivalent is --interface <name>; `--list-interfaces` prints the available ones.",
            SettingField::TlsFragment => "Xray-style TLS ClientHello fragmentation (xray `freedom` fragment settings) applied to protocol checks (`--proxy-url`) and the TLS fragment tester. Paste a full xray fragment object, e.g. {\"packets\":\"tlshello\",\"length\":\"100-200\",\"interval\":\"10-20\"}; empty disables fragmentation. tlshello splits only the ClientHello into random-length fragments re-wrapped as TLS records; with interval 0 they are combined into a single packet. Find the value that defeats your ISP's DPI with the tester (g on the results screen), then paste it here and in your xray config.",
            SettingField::DownloadPath => "Static file endpoint used for download speed tests.",
            SettingField::UploadPath => "POST endpoint used for upload speed tests; it should consume and discard the request body.",
            SettingField::SpeedPayloadMb => "Payload size used for each upload/download repetition. Larger payloads reduce short-test noise but use more bandwidth.",
            SettingField::SpeedRepetitions => "Number of upload/download repetitions per selected IP; reported speeds are averaged.",
            SettingField::SpeedTimeoutMs => "Maximum total time for one upload/download transfer, separate from the normal latency probe timeout.",
            SettingField::SamplePerCidr => "Number of random IPs sampled from each selected CIDR. Higher values increase coverage across the edge network, but increase total targets.",
            SettingField::Probes => "Number of requests sent to each IP to probe latency. More probes filter out transient noise and establish a highly accurate latency percentile.",
            SettingField::Concurrency => "Initial number of simultaneous request workers. With adaptive concurrency enabled, the scanner adjusts this at runtime within the configured minimum and maximum bounds.",
            SettingField::TimeoutMs => "Max time (in ms) allowed for an HTTP request to finish. Probes exceeding this threshold are treated as errors/failures.",
            SettingField::ConnectTimeoutMs => "Max time (in ms) to establish a TCP socket connection. Lower values skip dead, blacklisted, or blocked IPs more rapidly.",
            SettingField::Top => "Number of fastest, zero-fail IP addresses to show in the final dashboard results table and export to files.",
            SettingField::StabilityWeight => "Weight of latency jitter in the recommendation score. Higher values rank a variable-latency (jittery) IP lower relative to a steadier one with similar average latency.",
            SettingField::LossWeight => "Weight of packet loss in the recommendation score. Higher values rank a lossy IP lower even when its success rate still looks usable.",
            SettingField::EarlyStop => "Stop probing a target before its full probe budget once it is clearly dead (consecutive dropped probes) or clearly worse than the current top candidates. Saves wall-clock time on dead/timeout IPs.",
            SettingField::EarlyStopLossStreak => "Number of consecutive dropped probes (timeouts / connect failures) after which a target is declared dead and stopped. Only applies once enough probes have completed.",
            SettingField::EarlyStopMinSamples => "Minimum number of measured probes before any early-stop rule may fire, so a single first-timeout does not abort an otherwise-good target.",
            SettingField::EarlyStopPrune => "Once at least 'Top results' READY candidates exist, stop probing targets whose current score remains worse than the current top-N boundary after applying the margin tolerance.",
            SettingField::EarlyStopPruneMargin => "How much worse (as a fraction) a target may be than the worst current top-N candidate before the prune rule stops probing it.",
            SettingField::TwoPhase => "Run a sparse discovery pass first, then spend the rest of the probe budget focusing on the CIDRs that produced the best Cloudflare colos. Finds good edges faster and densifies there. Not available with the connect or syn discovery driver.",
            SettingField::DiscoveryDriver => "How the target set is produced before probing: `sampling` picks random IPs from each selected CIDR; `connect` sweeps every address in the selected ranges with plain TCP connects and only addresses with a reachable probe port become targets (masscan-style discovery without raw sockets); `syn` does the same with a raw SYN sweep (root, IPv4/Ethernet, and a build with the `syn` feature). Selecting connect or syn disables two-phase scanning.",
            SettingField::DiscoverFraction => "Fraction of sample_per_cidr used for the discovery pass when two-phase scanning is enabled; the remainder is spent on the focused CIDRs.",
            SettingField::AdaptiveProbing => "Allocate probes adaptively using confidence intervals instead of probing every target equally.",
            SettingField::MinProbes => "Minimum measured probes before adaptive stopping can occur.",
            SettingField::MaxProbes => "Maximum measured probes per target in adaptive mode.",
            SettingField::AdaptiveConcurrency => "Adjust worker concurrency from recent timeout, failure, and latency signals; fixed concurrency remains the default.",
            SettingField::MinConcurrency => "Lower worker bound used by adaptive concurrency.",
            SettingField::MaxConcurrency => "Upper worker bound used by adaptive concurrency.",
            SettingField::Confidence => "Confidence level used by adaptive score intervals. Must be exactly 0.90, 0.95, or 0.99.",
        }
    }

    /// Current value of this field as an editable string.
    pub fn value_string(&self, args: &AppConfig) -> String {
        match self {
            SettingField::Host => args.host.clone(),
            SettingField::Path => args.path.clone(),
            SettingField::Ports => args
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            SettingField::ExpectedStatuses => args
                .expected_statuses
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            SettingField::RequiredBodyMarkers => args.required_body_markers.join(","),
            SettingField::RequiredHeaders => args.required_headers.join(","),
            SettingField::FollowRedirects => {
                if args.follow_redirects {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::HealthChecks => args
                .health_checks
                .iter()
                .map(|check| {
                    format!(
                        "{}|{}|{}|{}",
                        check.name,
                        check.path,
                        if check.required { "true" } else { "false" },
                        check.weight
                    )
                })
                .collect::<Vec<_>>()
                .join(";"),
            SettingField::Warmup => {
                if args.warmup {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::Interface => args.interface.clone().unwrap_or_else(|| "Auto".to_string()),
            SettingField::TlsFragment => match &args.tls_fragment {
                Some(spec) => spec.xray_json(),
                None => "Off".to_string(),
            },
            SettingField::DownloadPath => args.download_path.clone(),
            SettingField::UploadPath => args.upload_path.clone(),
            SettingField::SpeedPayloadMb => (args.speed_payload_bytes / (1024 * 1024)).to_string(),
            SettingField::SpeedRepetitions => args.speed_repetitions.to_string(),
            SettingField::SpeedTimeoutMs => args.speed_timeout_ms.to_string(),
            SettingField::SamplePerCidr => args.sample_per_cidr.to_string(),
            SettingField::Probes => args.probes.to_string(),
            SettingField::Concurrency => args.concurrency.to_string(),
            SettingField::TimeoutMs => args.timeout_ms.to_string(),
            SettingField::ConnectTimeoutMs => args.connect_timeout_ms.to_string(),
            SettingField::Top => args.top.to_string(),
            SettingField::StabilityWeight => args.stability_weight.to_string(),
            SettingField::LossWeight => args.loss_weight.to_string(),
            SettingField::EarlyStop => {
                if args.early_stop {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::EarlyStopLossStreak => args.early_stop_loss_streak.to_string(),
            SettingField::EarlyStopMinSamples => args.early_stop_min_samples.to_string(),
            SettingField::EarlyStopPrune => {
                if args.early_stop_prune {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::EarlyStopPruneMargin => args.early_stop_prune_margin.to_string(),
            SettingField::TwoPhase => {
                if args.two_phase {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::DiscoveryDriver => match args.discovery_driver {
                DiscoveryDriver::Sampling => "Sampling".to_string(),
                DiscoveryDriver::Connect => "Connect".to_string(),
                DiscoveryDriver::Syn => "Syn".to_string(),
            },
            SettingField::DiscoverFraction => args.discover_fraction.to_string(),
            SettingField::AdaptiveProbing => {
                if args.adaptive_probing {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::MinProbes => args.min_probes.to_string(),
            SettingField::MaxProbes => args.max_probes.to_string(),
            SettingField::AdaptiveConcurrency => {
                if args.adaptive_concurrency {
                    "On".to_string()
                } else {
                    "Off".to_string()
                }
            }
            SettingField::MinConcurrency => args.min_concurrency.to_string(),
            SettingField::MaxConcurrency => args.max_concurrency.to_string(),
            SettingField::Confidence => args.confidence.to_string(),
        }
    }

    fn is_numeric(&self) -> bool {
        !matches!(
            self,
            SettingField::Host
                | SettingField::Path
                | SettingField::Ports
                | SettingField::ExpectedStatuses
                | SettingField::RequiredBodyMarkers
                | SettingField::RequiredHeaders
                | SettingField::FollowRedirects
                | SettingField::HealthChecks
                | SettingField::DownloadPath
                | SettingField::UploadPath
                | SettingField::EarlyStop
                | SettingField::EarlyStopPrune
                | SettingField::TwoPhase
                | SettingField::DiscoveryDriver
                | SettingField::Warmup
                | SettingField::AdaptiveProbing
                | SettingField::AdaptiveConcurrency
                | SettingField::Interface
                | SettingField::TlsFragment
        )
    }

    /// Step size used when nudging a numeric field with up/down arrows.
    fn step(&self) -> i64 {
        match self {
            SettingField::TimeoutMs | SettingField::ConnectTimeoutMs => 100,
            SettingField::SamplePerCidr => 10,
            SettingField::SpeedPayloadMb => 10,
            SettingField::SpeedTimeoutMs => 1_000,
            SettingField::Confidence => 5,
            _ => 1,
        }
    }

    fn is_fractional(&self) -> bool {
        matches!(
            self,
            SettingField::StabilityWeight
                | SettingField::LossWeight
                | SettingField::EarlyStopPruneMargin
                | SettingField::DiscoverFraction
                | SettingField::Confidence
        )
    }

    fn fractional_step(&self) -> f64 {
        match self {
            SettingField::StabilityWeight | SettingField::LossWeight => 0.1,
            SettingField::EarlyStopPruneMargin | SettingField::DiscoverFraction => 0.05,
            _ => unreachable!("fractional_step called for an integer field"),
        }
    }

    fn nudged_fractional_value(&self, value: f64, direction: i64) -> f64 {
        if matches!(self, SettingField::Confidence) {
            let current = Self::CONFIDENCE_LEVELS
                .iter()
                .copied()
                .min_by(|a, b| (a - value).abs().total_cmp(&(b - value).abs()))
                .unwrap_or(0.95);
            let index = Self::CONFIDENCE_LEVELS
                .iter()
                .position(|level| (*level - current).abs() < 1e-9)
                .unwrap_or(1) as i64;
            let next = index + direction;
            if next >= 0 && next < Self::CONFIDENCE_LEVELS.len() as i64 {
                Self::CONFIDENCE_LEVELS[next as usize]
            } else {
                current
            }
        } else {
            let upper = if matches!(self, SettingField::DiscoverFraction) {
                1.0
            } else {
                f64::MAX
            };
            (value + direction as f64 * self.fractional_step()).clamp(0.0, upper)
        }
    }

    fn nudged_text(&self, value: &str, direction: i64) -> Option<String> {
        if self.is_fractional() {
            let value = value.parse::<f64>().ok()?;
            let value = self.nudged_fractional_value(value, direction);
            Some(format!("{value:.2}"))
        } else {
            value
                .parse::<i64>()
                .ok()
                .map(|value| self.nudged_value(value, direction).to_string())
        }
    }

    fn max_value(&self) -> i64 {
        match self {
            SettingField::SamplePerCidr => MAX_SAMPLE_PER_CIDR as i64,
            SettingField::Probes => MAX_PROBES as i64,
            SettingField::Concurrency => MAX_CONCURRENCY as i64,
            SettingField::TimeoutMs => MAX_TIMEOUT_MS as i64,
            SettingField::ConnectTimeoutMs => MAX_CONNECT_TIMEOUT_MS as i64,
            SettingField::Top => MAX_TOP as i64,
            SettingField::SpeedPayloadMb => MAX_SPEED_PAYLOAD_MB as i64,
            SettingField::SpeedRepetitions => MAX_SPEED_REPETITIONS as i64,
            SettingField::SpeedTimeoutMs => MAX_SPEED_TIMEOUT_MS as i64,
            SettingField::EarlyStopLossStreak => MAX_EARLY_STOP_LOSS_STREAK as i64,
            SettingField::EarlyStopMinSamples => MAX_EARLY_STOP_MIN_SAMPLES as i64,
            SettingField::EarlyStopPruneMargin => i64::MAX,
            SettingField::DiscoverFraction => i64::MAX,
            SettingField::MinProbes | SettingField::MaxProbes => MAX_PROBES as i64,
            SettingField::MinConcurrency | SettingField::MaxConcurrency => MAX_CONCURRENCY as i64,
            SettingField::Host
            | SettingField::Path
            | SettingField::Ports
            | SettingField::ExpectedStatuses
            | SettingField::RequiredBodyMarkers
            | SettingField::RequiredHeaders
            | SettingField::FollowRedirects
            | SettingField::HealthChecks
            | SettingField::DownloadPath
            | SettingField::UploadPath
            | SettingField::EarlyStop
            | SettingField::EarlyStopPrune
            | SettingField::TwoPhase
            | SettingField::DiscoveryDriver
            | SettingField::Warmup
            | SettingField::Interface
            | SettingField::TlsFragment
            | SettingField::AdaptiveProbing
            | SettingField::AdaptiveConcurrency
            | SettingField::StabilityWeight
            | SettingField::LossWeight
            | SettingField::Confidence => i64::MAX,
        }
    }

    /// Return the value after one up/down adjustment, clamped to the field's
    /// valid range.
    fn nudged_value(&self, value: i64, direction: i64) -> i64 {
        value
            .saturating_add(direction.saturating_mul(self.step()))
            .clamp(1, self.max_value())
    }

    /// Parse `raw` and apply it to `args`. Returns an error message on failure.
    pub fn apply(&self, raw: &str, args: &mut AppConfig) -> Result<(), String> {
        let raw = raw.trim();
        match self {
            SettingField::Host => {
                if raw.is_empty() || raw.contains("://") || raw.contains('/') || raw.contains('\\')
                {
                    return Err(
                        "host must be a non-empty authority without a scheme or path".to_string(),
                    );
                }
                args.host = raw.to_string();
            }
            SettingField::Path => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("path must be non-empty and begin with /".to_string());
                }
                args.path = raw.to_string();
            }
            SettingField::Ports => {
                let ports = if raw.is_empty() {
                    Vec::new()
                } else {
                    raw.split(',')
                        .map(|value| {
                            value
                                .trim()
                                .parse::<u16>()
                                .map_err(|_| "ports must be comma-separated numbers".to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?
                };
                args.ports = validate_ports(&ports)?;
            }
            SettingField::ExpectedStatuses => {
                if raw.is_empty() {
                    args.expected_statuses.clear();
                } else {
                    let statuses = raw
                        .split(',')
                        .map(|value| {
                            value
                                .trim()
                                .parse::<u16>()
                                .map_err(|_| "invalid status".to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if statuses.iter().any(|status| !(100..=599).contains(status)) {
                        return Err("statuses must be between 100 and 599".to_string());
                    }
                    args.expected_statuses = statuses;
                }
            }
            SettingField::RequiredBodyMarkers => {
                args.required_body_markers = if raw.is_empty() {
                    Vec::new()
                } else {
                    raw.split(',')
                        .map(|value| value.trim().to_string())
                        .collect()
                };
            }
            SettingField::RequiredHeaders => {
                let headers = if raw.is_empty() {
                    Vec::new()
                } else {
                    raw.split(',')
                        .map(|value| value.trim().to_string())
                        .collect()
                };
                for value in &headers {
                    crate::config::parse_required_header(value)?;
                }
                args.required_headers = headers;
            }
            SettingField::FollowRedirects => {
                args.follow_redirects = match raw.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::HealthChecks => {
                if raw.is_empty() {
                    args.health_checks.clear();
                } else {
                    let mut checks = Vec::new();
                    let mut names = HashSet::new();
                    for encoded in raw.split(';') {
                        let fields: Vec<&str> = encoded.split('|').collect();
                        if fields.len() != 4
                            || fields[0].trim().is_empty()
                            || !fields[1].trim().starts_with('/')
                        {
                            return Err(
                                "checks must use name|/path|required|weight format".to_string()
                            );
                        }
                        let name = fields[0].trim().to_string();
                        if !names.insert(name.clone()) {
                            return Err(format!("duplicate health check name: {name}"));
                        }
                        let required = match fields[2].trim().to_lowercase().as_str() {
                            "true" | "on" | "yes" | "1" => true,
                            "false" | "off" | "no" | "0" => false,
                            _ => return Err("check required must be true or false".to_string()),
                        };
                        let weight = fields[3]
                            .trim()
                            .parse::<f64>()
                            .map_err(|_| "check weight must be a number".to_string())?;
                        if !weight.is_finite() || weight < 0.0 {
                            return Err("check weight must be non-negative".to_string());
                        }
                        checks.push(HealthCheck {
                            name,
                            path: fields[1].trim().to_string(),
                            required,
                            weight,
                        });
                    }
                    args.health_checks = checks;
                }
            }
            SettingField::Warmup => {
                args.warmup = match raw.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::Interface => {
                match crate::iface::normalize_interface(Some(raw.to_string())) {
                    Some(name) => {
                        crate::iface::validate_interface(&name)
                            .map_err(|error| error.to_string())?;
                        args.interface = Some(name);
                    }
                    None => args.interface = None,
                }
            }
            SettingField::TlsFragment => {
                if raw.is_empty() {
                    args.tls_fragment = None;
                } else {
                    args.tls_fragment = Some(crate::proxy::FragmentSpec::parse_json(raw)?);
                }
            }
            SettingField::DownloadPath => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("download path must be non-empty and begin with /".to_string());
                }
                args.download_path = raw.to_string();
            }
            SettingField::UploadPath => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("upload path must be non-empty and begin with /".to_string());
                }
                args.upload_path = raw.to_string();
            }
            SettingField::SpeedPayloadMb => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_PAYLOAD_MB).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_PAYLOAD_MB}"));
                }
                args.speed_payload_bytes = v * 1024 * 1024;
            }
            SettingField::SpeedRepetitions => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_REPETITIONS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_REPETITIONS}"));
                }
                args.speed_repetitions = v;
            }
            SettingField::SpeedTimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_TIMEOUT_MS}"));
                }
                args.speed_timeout_ms = v;
            }
            SettingField::SamplePerCidr => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SAMPLE_PER_CIDR).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SAMPLE_PER_CIDR}"));
                }
                args.sample_per_cidr = v;
            }
            SettingField::Probes => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_PROBES).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_PROBES}"));
                }
                args.probes = v;
            }
            SettingField::Concurrency => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONCURRENCY).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONCURRENCY}"));
                }
                args.concurrency = v;
            }
            SettingField::TimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_TIMEOUT_MS}"));
                }
                args.timeout_ms = v;
            }
            SettingField::ConnectTimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONNECT_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONNECT_TIMEOUT_MS}"));
                }
                args.connect_timeout_ms = v;
            }
            SettingField::Top => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_TOP).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_TOP}"));
                }
                args.top = v;
            }
            SettingField::StabilityWeight => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !v.is_finite() || v < 0.0 {
                    return Err("must be a non-negative number".to_string());
                }
                args.stability_weight = v;
            }
            SettingField::LossWeight => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !v.is_finite() || v < 0.0 {
                    return Err("must be a non-negative number".to_string());
                }
                args.loss_weight = v;
            }
            SettingField::EarlyStop => {
                let lowered = raw.to_lowercase();
                args.early_stop = match lowered.as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::EarlyStopLossStreak => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_EARLY_STOP_LOSS_STREAK).contains(&v) {
                    return Err(format!(
                        "must be between 1 and {MAX_EARLY_STOP_LOSS_STREAK}"
                    ));
                }
                args.early_stop_loss_streak = v;
            }
            SettingField::EarlyStopMinSamples => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_EARLY_STOP_MIN_SAMPLES).contains(&v) {
                    return Err(format!(
                        "must be between 1 and {MAX_EARLY_STOP_MIN_SAMPLES}"
                    ));
                }
                args.early_stop_min_samples = v;
            }
            SettingField::EarlyStopPrune => {
                let lowered = raw.to_lowercase();
                args.early_stop_prune = match lowered.as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::EarlyStopPruneMargin => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !v.is_finite() || v < 0.0 {
                    return Err("must be a non-negative number".to_string());
                }
                args.early_stop_prune_margin = v;
            }
            SettingField::TwoPhase => {
                let lowered = raw.to_lowercase();
                args.two_phase = match lowered.as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
                if args.two_phase && args.discovery_driver != DiscoveryDriver::Sampling {
                    args.discovery_driver = DiscoveryDriver::Sampling;
                }
            }
            SettingField::DiscoveryDriver => {
                let lowered = raw.trim().to_ascii_lowercase();
                match lowered.as_str() {
                    "sampling" | "random" => args.discovery_driver = DiscoveryDriver::Sampling,
                    "connect" | "sweep" => {
                        args.discovery_driver = DiscoveryDriver::Connect;
                        // Connect discovery and the two-phase sampling pass are
                        // alternative target-selection strategies.
                        args.two_phase = false;
                    }
                    "syn" => {
                        #[cfg(feature = "syn")]
                        {
                            args.discovery_driver = DiscoveryDriver::Syn;
                            args.two_phase = false;
                        }
                        #[cfg(not(feature = "syn"))]
                        {
                            return Err(
                                "syn requires a build with the `syn` cargo feature; use sampling or connect"
                                    .to_string(),
                            );
                        }
                    }
                    _ => return Err("enter sampling, connect, or syn".to_string()),
                }
            }
            SettingField::DiscoverFraction => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                    return Err("must be a number between 0 and 1".to_string());
                }
                args.discover_fraction = v;
            }
            SettingField::AdaptiveProbing => {
                args.adaptive_probing = match raw.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::MinProbes => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_PROBES).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_PROBES}"));
                }
                args.min_probes = v;
            }
            SettingField::MaxProbes => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_PROBES).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_PROBES}"));
                }
                args.max_probes = v;
            }
            SettingField::AdaptiveConcurrency => {
                args.adaptive_concurrency = match raw.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => return Err("enter on or off".to_string()),
                };
            }
            SettingField::MinConcurrency => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONCURRENCY).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONCURRENCY}"));
                }
                args.min_concurrency = v;
                args.runtime_min_concurrency
                    .store(v, std::sync::atomic::Ordering::Relaxed);
            }
            SettingField::MaxConcurrency => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONCURRENCY).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONCURRENCY}"));
                }
                args.max_concurrency = v;
            }
            SettingField::Confidence => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                let level = Self::CONFIDENCE_LEVELS
                    .iter()
                    .copied()
                    .find(|level| (level - v).abs() < 1e-9)
                    .ok_or_else(|| "must be exactly 0.90, 0.95, or 0.99".to_string())?;
                args.confidence = level;
            }
        }
        Ok(())
    }

    /// Ranking-quality tuning remains advanced; adaptive scan controls are
    /// intentionally visible because they change core scan behavior.
    pub fn is_advanced(self) -> bool {
        matches!(
            self,
            SettingField::StabilityWeight | SettingField::LossWeight
        )
    }

    pub fn is_toggle(self) -> bool {
        matches!(
            self,
            SettingField::Warmup
                | SettingField::EarlyStop
                | SettingField::EarlyStopPrune
                | SettingField::TwoPhase
                | SettingField::DiscoveryDriver
                | SettingField::AdaptiveProbing
                | SettingField::AdaptiveConcurrency
        )
    }

    pub fn toggle(self, args: &mut AppConfig) {
        match self {
            SettingField::Warmup => args.warmup = !args.warmup,
            SettingField::EarlyStop => args.early_stop = !args.early_stop,
            SettingField::EarlyStopPrune => args.early_stop_prune = !args.early_stop_prune,
            SettingField::TwoPhase => {
                args.two_phase = !args.two_phase;
                if args.two_phase && args.discovery_driver != DiscoveryDriver::Sampling {
                    args.discovery_driver = DiscoveryDriver::Sampling;
                }
            }
            SettingField::DiscoveryDriver => {
                args.discovery_driver = match args.discovery_driver {
                    DiscoveryDriver::Sampling => DiscoveryDriver::Connect,
                    #[cfg(feature = "syn")]
                    DiscoveryDriver::Connect => DiscoveryDriver::Syn,
                    _ => DiscoveryDriver::Sampling,
                };
                // Connect and SYN discovery replace the two-phase sampling
                // pass as target-selection strategies.
                if args.discovery_driver != DiscoveryDriver::Sampling {
                    args.two_phase = false;
                }
            }
            SettingField::AdaptiveProbing => args.adaptive_probing = !args.adaptive_probing,
            SettingField::AdaptiveConcurrency => {
                args.adaptive_concurrency = !args.adaptive_concurrency
            }
            _ => {}
        }
    }
}

/// Render the active wizard step plus the shared top bar and footer.
pub fn render(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    render_step_bar(app, frame, chunks[0]);

    match app.wizard_step {
        WizardStep::Ranges => render_ranges(app, frame, chunks[1]),
        WizardStep::Settings => render_settings(app, frame, chunks[1]),
        WizardStep::Review => render_review(app, frame, chunks[1]),
    }

    render_footer(app, frame, chunks[2]);
    render_hint(app, frame, chunks[3]);
}

fn render_step_bar(app: &App, frame: &mut Frame, area: Rect) {
    widgets::stepper_header(
        frame,
        area,
        &["Ranges", "Settings", "Review"],
        app.wizard_step as usize,
    );
}

fn format_ip_count(count: u128) -> String {
    let digits = count.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted
}

fn ip_label(count: u128) -> String {
    format!(
        "{} {}",
        format_ip_count(count),
        if count == 1 { "IP" } else { "IPs" }
    )
}

fn worker_summary(app: &App) -> String {
    if app.config.adaptive_concurrency {
        format!(
            "{} start; {}–{} adaptive",
            app.config.concurrency, app.config.min_concurrency, app.config.max_concurrency
        )
    } else {
        format!("{} fixed", app.config.concurrency)
    }
}

/// How the selected ranges become targets, as shown on the ranges step.
fn scan_mode_label(app: &App) -> String {
    match app.config.discovery_driver {
        DiscoveryDriver::Sampling => format!(
            "sample {} IPs per CIDR",
            format_ip_count(app.config.sample_per_cidr as u128)
        ),
        DiscoveryDriver::Connect => "full-range sweep (TCP connect)".to_string(),
        DiscoveryDriver::Syn => "full-range sweep (raw SYN)".to_string(),
    }
}

fn selected_cidrs_and_workload(app: &App) -> (Vec<String>, crate::scanner::CidrWorkloadSummary) {
    let selected_cidrs: Vec<String> = app
        .cidr_candidates
        .iter()
        .filter(|entry| entry.selected)
        .map(|entry| entry.cidr.clone())
        .collect();
    let workload = crate::scanner::workload_for_cidrs(
        &selected_cidrs,
        app.config.sample_per_cidr,
        app.config.probes,
        app.config.ports.len(),
    );
    (selected_cidrs, workload)
}

fn render_ranges(app: &mut App, frame: &mut Frame, area: Rect) {
    // On tall terminals, lead with a compact brand banner.
    let body = if area.height >= 16 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(area);
        let banner = Paragraph::new(vec![
            Line::from(Span::styled(
                "C L E A N S C A N",
                theme::header_style().add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "Cloudflare edge latency & speed scanner",
                theme::hint_style(),
            )),
        ])
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(banner, split[0]);
        split[1]
    } else {
        area
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(body);

    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[0]);

    let list_block = widgets::panel_block(
        "Cloudflare CIDR ranges (space toggle, A all, N none, s sweep)",
        true,
    );
    let inner = list_block.inner(main_layout[0]);
    frame.render_widget(list_block, main_layout[0]);
    app.ranges_inner = Some(inner);

    let visible = inner.height as usize;
    let total = app.cidr_candidates.len();
    let max_scroll = total.saturating_sub(visible);
    // Keep the cursor visible within the viewport.
    if app.cursor < app.ranges_scroll {
        app.ranges_scroll = app.cursor;
    } else if visible > 0 && app.cursor >= app.ranges_scroll + visible {
        app.ranges_scroll = app.cursor + 1 - visible;
    }
    app.ranges_scroll = app.ranges_scroll.min(max_scroll);

    for (i, idx) in (app.ranges_scroll..).enumerate().take(visible) {
        if idx >= total {
            break;
        }
        let e = &app.cidr_candidates[idx];
        let y = inner.y + i as u16;
        if idx == app.cursor || e.selected {
            frame.render_widget(
                Paragraph::new("").style(theme::row_selected_style()),
                Rect {
                    x: inner.x,
                    y,
                    width: inner.width,
                    height: 1,
                },
            );
        }
        // Cursor marker gutter (mirrors the list highlight symbol).
        if idx == app.cursor {
            frame.render_widget(
                Paragraph::new(format!("{} ", widgets::focus_marker()))
                    .style(theme::row_selected_style()),
                Rect {
                    x: inner.x,
                    y,
                    width: 2,
                    height: 1,
                },
            );
        }
        let selected_row = idx == app.cursor || e.selected;
        let label_style = if selected_row {
            theme::row_selected_style()
        } else {
            theme::hint_style()
        };
        let count = crate::scanner::cidr_address_count(&e.cidr)
            .map(|count| format!("({})", ip_label(count)))
            .unwrap_or_else(|| "(invalid)".to_string());
        let checkbox = format!(
            "{} ",
            if e.selected {
                widgets::checkbox_checked_symbol()
            } else {
                widgets::checkbox_unchecked_symbol()
            }
        );
        let primary = format!("{checkbox}{}", e.cidr);
        let row_width = inner.width.saturating_sub(2) as usize;
        let metadata_width = count.chars().count();
        let primary_width = primary.chars().count();
        let right_aligned = row_width >= primary_width + metadata_width + 3;
        let inline = !right_aligned && row_width >= primary_width + metadata_width + 2;
        let row = if right_aligned {
            Line::from(vec![
                Span::styled(primary, label_style),
                Span::raw(" ".repeat(row_width - primary_width - metadata_width)),
                Span::styled(count, theme::row_metadata_style(selected_row)),
            ])
        } else if inline {
            Line::from(vec![
                Span::styled(format!("{primary}  "), label_style),
                Span::styled(count, theme::row_metadata_style(selected_row)),
            ])
        } else {
            // Keep the checkbox and complete CIDR visible even at the
            // smallest useful width; metadata yields rather than truncating
            // the identity of the selectable item.
            Line::from(Span::styled(primary, label_style))
        };
        frame.render_widget(
            Paragraph::new(row),
            Rect {
                x: inner.x + 2,
                y,
                width: inner.width.saturating_sub(2),
                height: 1,
            },
        );
    }

    // Maintain the ListState bookkeeping for external consumers and tests.
    app.ranges_list_state = app
        .ranges_list_state
        .with_offset(app.ranges_scroll)
        .with_selected((!app.cidr_candidates.is_empty()).then_some(app.cursor));
    app.ranges_scroll = app.ranges_list_state.offset();

    // Right Side Info Panel
    let selected_count = app.cidr_candidates.iter().filter(|e| e.selected).count();
    let (selected_cidrs, workload) = selected_cidrs_and_workload(app);
    let sweep = matches!(
        app.config.discovery_driver,
        DiscoveryDriver::Connect | DiscoveryDriver::Syn
    );
    let (total_ips, total_probes) = if sweep {
        // The full-range sweep probes every candidate address against every
        // selected port, so the sampling-based workload is not applicable.
        let candidates = crate::discovery::parse_target_sources(None, &selected_cidrs)
            .map(|sources| crate::discovery::enumerated_address_count(&sources))
            .unwrap_or(0);
        (
            candidates,
            candidates.saturating_mul(app.config.ports.len().max(1) as u128),
        )
    } else {
        (workload.total_ips, workload.total_probes)
    };

    let info_text = vec![
        Line::from(vec![Span::styled(" RANGE SUMMARY ", theme::header_style())]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Selected Ranges: ", theme::title_style()),
            Span::raw(format!(
                "{} / {}",
                selected_count,
                app.cidr_candidates.len()
            )),
        ]),
        Line::from(vec![
            Span::styled("Scan mode  : ", theme::title_style()),
            Span::raw(scan_mode_label(app)),
        ]),
        Line::from(vec![
            Span::styled(
                if sweep {
                    "Sweep candidates : "
                } else {
                    "Total target IPs: "
                },
                theme::title_style(),
            ),
            Span::raw(format_ip_count(total_ips)),
        ]),
        Line::from(vec![
            Span::styled(
                if sweep {
                    "Max sweep probes: "
                } else {
                    "Total HTTP Probes: "
                },
                theme::title_style(),
            ),
            Span::raw(format_ip_count(total_probes)),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Quick Actions: ", theme::subtitle_style())),
        Line::from(vec![
            Span::styled("  A  ", theme::highlight_style()),
            Span::raw("Select all CIDRs"),
        ]),
        Line::from(vec![
            Span::styled("  N  ", theme::highlight_style()),
            Span::raw("Deselect all CIDRs"),
        ]),
        Line::from(vec![
            Span::styled("  a  ", theme::highlight_style()),
            Span::raw("Add a custom CIDR range"),
        ]),
        Line::from(vec![
            Span::styled("  s  ", theme::highlight_style()),
            Span::raw("Toggle full-range sweep"),
        ]),
    ];

    let info_block = widgets::panel_block("Selected Metrics", false);
    let info_para = Paragraph::new(info_text).block(info_block);
    frame.render_widget(info_para, main_layout[1]);

    // Input line at bottom
    let input_line = if app.custom_input_mode {
        let (before, after) = app
            .input_buffer
            .split_at(app.edit_caret.min(app.input_buffer.len()));
        format!("> {}{}_{}", before, after, "")
    } else {
        "  press 'a' to add a custom CIDR range  ".to_string()
    };
    let title = " Add CIDR ";
    let input =
        Paragraph::new(input_line).block(widgets::panel_block(title, app.custom_input_mode));
    frame.render_widget(input, chunks[1]);
}

fn render_settings(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Preset bar
            Constraint::Min(1),    // Main parameters
        ])
        .split(area);

    // Preset Bar
    // Detect matching preset
    let mut current_preset = "Custom";
    if app.config.sample_per_cidr == 100
        && app.config.probes == 8
        && app.config.concurrency == 120
        && app.config.timeout_ms == 2500
        && app.config.connect_timeout_ms == 1000
        && app.config.top == 50
    {
        current_preset = "Default [1]";
    } else if app.config.sample_per_cidr == 50
        && app.config.probes == 4
        && app.config.concurrency == 200
        && app.config.timeout_ms == 1500
        && app.config.connect_timeout_ms == 500
        && app.config.top == 25
    {
        current_preset = "Fast Scan [2]";
    } else if app.config.sample_per_cidr == 200
        && app.config.probes == 15
        && app.config.concurrency == 80
        && app.config.timeout_ms == 3500
        && app.config.connect_timeout_ms == 1500
        && app.config.top == 100
    {
        current_preset = "Thorough Scan [3]";
    }

    let preset_spans = vec![
        Span::styled(" Quick Presets: ", theme::subtitle_style()),
        Span::styled(
            " [1] Default ",
            if current_preset.contains("Default") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled(
            " [2] Fast Scan ",
            if current_preset.contains("Fast") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled(
            " [3] Thorough Scan ",
            if current_preset.contains("Thorough") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled("  Current: ", theme::hint_style()),
        Span::styled(current_preset, theme::title_style()),
    ];

    let preset_block = widgets::panel_block("Preset Configurations", false);
    let preset_para = Paragraph::new(Line::from(preset_spans)).block(preset_block);
    frame.render_widget(preset_para, chunks[0]);

    // Settings columns layout
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    let block = widgets::panel_block("Scan parameters (Space toggle, Enter edit)", true);
    let inner = block.inner(main_layout[0]);
    app.settings_inner = Some(inner);

    // Build the field list with section subheaders, tracking which display row
    // maps to which field index (headers map to `None`) for mouse hit-testing.
    let mut lines: Vec<Line> = Vec::new();
    let mut row_map: Vec<Option<usize>> = Vec::new();
    let mut ports_row_map: Vec<Option<usize>> = Vec::new();
    let mut interface_row_map: Vec<Option<usize>> = Vec::new();
    let ports_field_index = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Ports)
        .expect("ports setting field must exist");
    let interface_field_index = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Interface)
        .expect("interface setting field must exist");
    let editing_ports = matches!(
        app.edit_field,
        Some(i) if i == ports_field_index
    );
    let editing_interface = matches!(
        app.edit_field,
        Some(i) if i == interface_field_index
    );
    let interface_rows: Vec<(String, bool)> =
        std::iter::once(("Auto (default)".to_string(), app.config.interface.is_none()))
            .chain(app.interface_list.iter().map(|entry| {
                let addresses = entry
                    .addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let selected = matches!(&app.config.interface, Some(name) if *name == entry.name);
                (format!("{}  {}", entry.name, addresses), selected)
            }))
            .collect();
    let mut field_idx = 0usize;
    for (header, count) in SettingField::GROUPS {
        let group_start = field_idx;
        let group_is_advanced = SettingField::ALL[group_start].is_advanced();
        if group_is_advanced && !app.show_advanced_settings {
            lines.push(Line::from(Span::styled(
                " ADVANCED SETTINGS  (press x to show)",
                theme::hint_style().add_modifier(Modifier::BOLD),
            )));
            row_map.push(None);
            ports_row_map.push(None);
            interface_row_map.push(None);
            field_idx += count;
            continue;
        }
        lines.push(Line::from(Span::styled(
            format!(" {} ", header.to_uppercase()),
            theme::subtitle_style().add_modifier(Modifier::BOLD),
        )));
        row_map.push(None);
        ports_row_map.push(None);
        interface_row_map.push(None);
        for _ in 0..count {
            let i = field_idx;
            let f = SettingField::ALL[i];
            if editing_ports && i == ports_field_index {
                // One row per port keeps the full list visible and tappable
                // even on narrow (phone) terminals, where the inline form
                // overflowed the panel and hid the later ports.
                for (index, port) in CLOUDFLARE_HTTPS_PORTS.iter().enumerate() {
                    let selected = app
                        .edit_buffer
                        .split(',')
                        .filter_map(|v| v.trim().parse::<u16>().ok())
                        .any(|value| value == *port);
                    let cursor_here = index == app.port_cursor;
                    let style = if cursor_here {
                        theme::row_selected_style()
                    } else {
                        Style::default().fg(theme::palette().subtitle)
                    };
                    let row = format!(
                        "{}{}{}",
                        if cursor_here {
                            widgets::focus_marker()
                        } else {
                            " "
                        },
                        port,
                        if selected {
                            widgets::checked_marker()
                        } else {
                            widgets::unchecked_marker()
                        }
                    );
                    lines.push(Line::from(format!("  {row}")).style(style));
                    row_map.push(Some(i));
                    ports_row_map.push(Some(index));
                    interface_row_map.push(None);
                }
                field_idx += 1;
                continue;
            }
            if editing_interface && i == interface_field_index {
                // One row per selectable interface (Auto first), with the
                // interface's addresses alongside the name.
                for (index, (label, selected)) in interface_rows.iter().enumerate() {
                    let cursor_here = index == app.interface_cursor;
                    let style = if cursor_here {
                        theme::row_selected_style()
                    } else {
                        Style::default().fg(theme::palette().subtitle)
                    };
                    let row = format!(
                        "{}{}{}",
                        if cursor_here {
                            widgets::focus_marker()
                        } else {
                            " "
                        },
                        if *selected {
                            widgets::checked_marker()
                        } else {
                            widgets::unchecked_marker()
                        },
                        label
                    );
                    lines.push(Line::from(format!("  {row}")).style(style));
                    row_map.push(Some(i));
                    ports_row_map.push(None);
                    interface_row_map.push(Some(index));
                }
                field_idx += 1;
                continue;
            }
            let style = if i == app.cursor {
                theme::row_selected_style()
            } else {
                Style::default().fg(theme::palette().subtitle)
            };
            let value = if app.edit_field == Some(i) {
                let (before, after) = app
                    .edit_buffer
                    .split_at(app.edit_caret.min(app.edit_buffer.len()));
                format!("{}{}_", before, after)
            } else if f.is_toggle() {
                format!(
                    "{} {}",
                    if f.value_string(&app.config) == "On" {
                        widgets::checkbox_checked_symbol()
                    } else {
                        widgets::checkbox_unchecked_symbol()
                    },
                    if f.value_string(&app.config) == "On" {
                        "Enabled"
                    } else {
                        "Disabled"
                    }
                )
            } else {
                f.value_string(&app.config)
            };
            let label = format!("{:20}", f.label());
            lines.push(Line::from(format!("{} = {}", label, value)).style(style));
            row_map.push(Some(i));
            ports_row_map.push(None);
            interface_row_map.push(None);
            field_idx += 1;
        }
    }

    let items = lines.into_iter().map(ListItem::new).collect::<Vec<_>>();
    let selected_row = if editing_ports || editing_interface {
        // While editing one of the list fields, the list highlight follows
        // the focused row so the List widget keeps it inside the viewport as
        // the cursor moves and the row map slices stay aligned with the
        // scroll.
        row_map
            .iter()
            .position(|field| *field == Some(app.cursor))
            .map(|row| {
                row + if editing_ports {
                    app.port_cursor
                } else {
                    app.interface_cursor
                }
            })
    } else {
        row_map.iter().position(|field| *field == Some(app.cursor))
    };
    app.settings_list_state = app
        .settings_list_state
        .with_offset(app.settings_scroll)
        .with_selected(selected_row);
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(theme::row_selected_style())
            .highlight_symbol(if editing_ports || editing_interface {
                ""
            } else {
                widgets::focus_marker()
            }),
        main_layout[0],
        &mut app.settings_list_state,
    );
    app.settings_scroll = app.settings_list_state.offset();
    let start = app.settings_scroll.min(row_map.len());
    let end = (start + inner.height as usize).min(row_map.len());
    app.settings_row_map = row_map[start..end].to_vec();
    app.ports_row_map = ports_row_map[start..end].to_vec();
    app.interface_row_map = interface_row_map[start..end].to_vec();

    // Right Side Description Panel
    let current_field = SettingField::ALL[app.cursor.min(SettingField::ALL.len() - 1)];
    let desc_text = vec![
        Line::from(vec![Span::styled(
            format!(" {} ", current_field.label().to_uppercase()),
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(Span::styled("Description:", theme::title_style())),
        Line::from(""),
    ];

    let mut desc_para_lines = desc_text;
    desc_para_lines.push(Line::from(current_field.description()));
    desc_para_lines.push(Line::from(""));
    desc_para_lines.push(Line::from(Span::styled(
        "Keyboard Shortcut:",
        theme::subtitle_style(),
    )));
    desc_para_lines.push(Line::from("  Press Enter to edit directly."));
    if current_field.is_numeric() {
        desc_para_lines.push(Line::from(
            "  Press Enter to edit; then use ↑/↓ to adjust the numeric value.",
        ));
        desc_para_lines.push(Line::from("  Use j/k to move between fields."));
    }

    let (_, workload) = selected_cidrs_and_workload(app);
    desc_para_lines.insert(
        1,
        Line::from(Span::styled(
            format!(
                "Estimated workload: {} targets{}{} probes",
                format_ip_count(workload.total_ips),
                widgets::workload_separator(),
                format_ip_count(workload.total_probes)
            ),
            theme::subtitle_style(),
        )),
    );

    let desc_block = widgets::subtle_panel_block("Field Context");
    let desc_inner = desc_block.inner(main_layout[1]);
    frame.render_widget(desc_block, main_layout[1]);

    // Numerically editable fields get a live slider visualizing the value.
    if current_field.is_numeric() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(desc_inner);
        frame.render_widget(
            Paragraph::new(desc_para_lines).wrap(Wrap { trim: true }),
            chunks[0],
        );

        let value = current_field
            .value_string(&app.config)
            .parse::<f64>()
            .unwrap_or(1.0);
        let (min, max) = numeric_slider_bounds(current_field);
        let state = SliderState::new(value.clamp(min, max), min, max);
        let slider = Slider::from_state(&state)
            .show_value(true)
            .show_handle(true)
            .filled_color(theme::palette().accent)
            .empty_color(theme::palette().border)
            .handle_color(theme::palette().highlight);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {} ", current_field.label().to_uppercase()),
                theme::panel_title_style(),
            ))),
            Rect {
                x: chunks[1].x,
                y: chunks[1].y,
                width: chunks[1].width,
                height: 1,
            },
        );
        frame.render_widget(
            slider,
            Rect {
                x: chunks[1].x,
                y: chunks[1].y + 1,
                width: chunks[1].width,
                height: 1,
            },
        );
    } else {
        frame.render_widget(
            Paragraph::new(desc_para_lines).wrap(Wrap { trim: true }),
            desc_inner,
        );
    }
}

fn numeric_slider_bounds(field: SettingField) -> (f64, f64) {
    match field {
        SettingField::StabilityWeight | SettingField::LossWeight => (0.0, 10.0),
        SettingField::EarlyStopPruneMargin
        | SettingField::DiscoverFraction
        | SettingField::Confidence => (0.0, 1.0),
        _ => (1.0, (field.max_value().min(1_000_000)) as f64),
    }
}

fn render_review(app: &mut App, frame: &mut Frame, area: Rect) {
    let (selected, workload) = selected_cidrs_and_workload(app);
    let sweep_mode = review_sweep_mode(app.config.discovery_driver);

    let selected_count = selected.len();
    let preview_ready = !app.preview_targets.is_empty();
    // A generated preview is deduplicated by the scanner and is therefore
    // authoritative for the actual target workload. Before generation, the
    // deterministic per-CIDR cap is the stable upper-bound estimate. In
    // sweep mode (connect or syn) the sweep enumerates every address in the
    // selected ranges instead of sampling.
    let (total_ips, total_probes) = review_totals(
        &selected,
        preview_ready,
        app.preview_targets.len(),
        &app.config,
        workload.total_ips,
    );
    let (readiness_text, readiness_warn) =
        review_readiness(sweep_mode, preview_ready, app.config.concurrency, total_ips);

    // Ideal scan duration estimate
    let ideal_seconds =
        ideal_scan_seconds(total_probes, app.config.concurrency, app.config.timeout_ms);
    let est_duration_str = if ideal_seconds < 60.0 {
        format!("{:.1}s", ideal_seconds)
    } else {
        format!(
            "{:02}:{:02}",
            (ideal_seconds / 60.0) as u64,
            (ideal_seconds % 60.0) as u64
        )
    };

    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mut summary_left = vec![
        Line::from(vec![Span::styled(
            " TARGET SPECIFICATION ",
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Hostname  : ", theme::title_style()),
            Span::raw(app.config.host.clone()),
        ]),
        Line::from(vec![
            Span::styled("Probe Path: ", theme::title_style()),
            Span::raw(app.config.path.clone()),
        ]),
        Line::from(vec![
            Span::styled("CIDR count: ", theme::title_style()),
            Span::raw(format!("{} selected", selected_count)),
        ]),
        Line::from(""),
    ];
    summary_left.extend(selected.iter().take(8).map(|c| {
        let capacity = crate::scanner::cidr_address_count(c)
            .map(ip_label)
            .unwrap_or_else(|| "invalid".to_string());
        let estimated = crate::scanner::workload_for_cidrs(
            std::slice::from_ref(c),
            app.config.sample_per_cidr,
            1,
            1,
        )
        .total_ips;
        Line::from(format!(
            "  {}  capacity: {capacity}; estimated targets: {}",
            c,
            ip_label(estimated)
        ))
    }));
    summary_left.push(Line::from(if selected_count > 8 {
        format!("  ... and {} more", selected_count - 8)
    } else {
        "".to_string()
    }));

    let summary_right = vec![
        Line::from(vec![Span::styled(
            " SCANNING PARAMETERS ",
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Sampling limit: ", theme::title_style()),
            Span::raw(format_ip_count(app.config.sample_per_cidr as u128)),
        ]),
        Line::from(vec![
            Span::styled("Driver      : ", theme::title_style()),
            Span::raw(match app.config.discovery_driver {
                DiscoveryDriver::Sampling => "sampling (random per-CIDR)".to_string(),
                DiscoveryDriver::Connect => "connect sweep (full range)".to_string(),
                DiscoveryDriver::Syn => "syn (raw SYN sweep)".to_string(),
            }),
        ]),
        Line::from(vec![
            Span::styled("Interface   : ", theme::title_style()),
            Span::raw(match &app.config.interface {
                None => "auto".to_string(),
                Some(name) => {
                    let suffix = app.review_interface_suffix.get_or_insert_with(|| {
                        crate::iface::interface_addrs(name)
                            .ok()
                            .and_then(|addrs| addrs.pick(true))
                            .map(|ip| format!(" ({ip})"))
                            .unwrap_or_default()
                    });
                    format!("{name}{suffix}")
                }
            }),
        ]),
        Line::from(vec![
            Span::styled("Fragment    : ", theme::title_style()),
            Span::raw(match &app.config.tls_fragment {
                Some(spec) => spec.xray_json(),
                None => "off".to_string(),
            }),
        ]),
        Line::from(vec![
            Span::styled("Probes/IP   : ", theme::title_style()),
            Span::raw(format_ip_count(app.config.probes as u128)),
        ]),
        Line::from(vec![
            Span::styled("Workers     : ", theme::title_style()),
            Span::raw(worker_summary(app)),
        ]),
        Line::from(vec![
            Span::styled("Timeout     : ", theme::title_style()),
            Span::raw(format!(
                "{}ms (connect: {}ms)",
                app.config.timeout_ms, app.config.connect_timeout_ms
            )),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "ESTIMATES & WORKLOAD",
            theme::subtitle_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                if preview_ready {
                    "Exact target IPs: "
                } else {
                    "Estimated target IPs: "
                },
                theme::title_style(),
            ),
            Span::raw(format_ip_count(total_ips)),
        ]),
        Line::from(vec![
            Span::styled("Total Probes: ", theme::title_style()),
            Span::raw(format_ip_count(total_probes)),
        ]),
        Line::from(vec![
            Span::styled("Early Stop  : ", theme::title_style()),
            Span::raw(if app.config.early_stop {
                "enabled (upper bound)"
            } else {
                "disabled"
            }),
        ]),
        Line::from(vec![
            Span::styled("Est Duration: ", theme::title_style()),
            Span::raw(format!("~{}", est_duration_str)),
        ]),
        Line::from(vec![
            Span::styled("Seed        : ", theme::title_style()),
            Span::raw(app.scan_seed.to_string()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            readiness_text,
            if readiness_warn {
                theme::warn_style()
            } else {
                theme::good_style()
            },
        )),
    ];

    let block_left = widgets::panel_block("Target configuration", false);
    let para_left = Paragraph::new(summary_left).block(block_left);
    frame.render_widget(para_left, main_layout[0]);

    let block_right = widgets::panel_block("Scope & Workload", false);
    let para_right = Paragraph::new(summary_right).block(block_right);
    frame.render_widget(para_right, main_layout[1]);
}

/// Whether the driver sweeps every candidate address in the selected ranges
/// (connect or syn) instead of sampling a per-CIDR subset.
fn review_sweep_mode(driver: DiscoveryDriver) -> bool {
    matches!(driver, DiscoveryDriver::Connect | DiscoveryDriver::Syn)
}

/// Candidate and probe totals shown on the review screen. Sweep drivers
/// enumerate the full selected ranges; sampled drivers use the generated
/// preview when available and the deterministic per-CIDR cap otherwise.
fn review_totals(
    selected: &[String],
    preview_ready: bool,
    preview_len: usize,
    config: &AppConfig,
    sampled_total: u128,
) -> (u128, u128) {
    let total_ips = if review_sweep_mode(config.discovery_driver) {
        crate::discovery::enumerated_address_count(
            &crate::discovery::parse_target_sources(None, selected).unwrap_or_default(),
        )
    } else if preview_ready {
        preview_len as u128
    } else {
        sampled_total
    };
    let total_probes = if review_sweep_mode(config.discovery_driver) {
        total_ips.saturating_mul(config.ports.len().max(1) as u128)
    } else {
        total_ips
            .saturating_mul(config.probes as u128)
            .saturating_mul(config.ports.len().max(1) as u128)
    };
    (total_ips, total_probes)
}

/// Readiness line for the review screen and whether it warns. Sweep drivers
/// report the sweep-ready status even when the target set is large, but still
/// warn on very high concurrency or huge ranges.
fn review_readiness(
    sweep_mode: bool,
    preview_ready: bool,
    concurrency: usize,
    total_ips: u128,
) -> (&'static str, bool) {
    if sweep_mode {
        (
            "Ready: sweep will find reachable ports, then probe them",
            concurrency > 500 || total_ips > 10_000,
        )
    } else if !preview_ready {
        ("Unavailable: target preview could not be generated", true)
    } else if concurrency > 500 {
        (
            "Warning: very high concurrency may trigger rate limits",
            true,
        )
    } else if total_ips > 10_000 {
        (
            "Warning: large target set; this scan may take significant time",
            true,
        )
    } else {
        ("Ready: sampled targets are stable for this review", false)
    }
}

fn ideal_scan_seconds(total_probes: u128, concurrency: usize, timeout_ms: u64) -> f64 {
    (total_probes as f64 / concurrency.max(1) as f64) * (timeout_ms as f64 / 2000.0)
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(16),
            Constraint::Min(0),
            Constraint::Length(16),
        ])
        .split(area);

    let left_action = match app.wizard_step {
        WizardStep::Ranges => ButtonAction::Quit,
        _ => ButtonAction::Back,
    };
    let left_label = match app.wizard_step {
        WizardStep::Ranges if app.return_to_results => "Results (Esc)",
        WizardStep::Ranges => "Quit (q)",
        _ => "Back (Esc)",
    };
    app.button_ex(
        frame,
        chunks[0],
        left_label,
        left_action,
        ButtonKind::Secondary,
        app.focus_index == 1,
    );

    let right_action = match app.wizard_step {
        WizardStep::Review => ButtonAction::Start,
        _ => ButtonAction::Next,
    };
    let right_label = match app.wizard_step {
        WizardStep::Review => "Start scan",
        _ => "Next",
    };
    let right_focused = app.focus_index == 2;
    let right_kind = if right_focused {
        ButtonKind::Primary
    } else {
        ButtonKind::Secondary
    };
    app.button_ex(
        frame,
        chunks[2],
        right_label,
        right_action,
        right_kind,
        right_focused,
    );
}

fn render_hint(app: &App, frame: &mut Frame, area: Rect) {
    let hints: &[widgets::KeyHint] = match app.wizard_step {
        WizardStep::Ranges => {
            if app.custom_input_mode {
                &[
                    ("type", "CIDR"),
                    (widgets::enter_key(), "confirm"),
                    ("Esc", "cancel"),
                ]
            } else {
                &[
                    ("Tab", "focus"),
                    ("Space", "toggle"),
                    ("s", "sweep"),
                    (widgets::enter_key(), "next"),
                    ("/", "commands"),
                    ("?", "help"),
                ]
            }
        }
        WizardStep::Settings => {
            if app.edit_field.is_some() {
                &[
                    ("type", "value"),
                    ("←/→", "move"),
                    ("↑/↓", "step"),
                    (widgets::enter_key(), "confirm"),
                    ("Esc", "cancel"),
                ]
            } else {
                &[
                    ("Tab", "focus"),
                    ("Space", "toggle"),
                    (widgets::enter_key(), "toggle/edit/next"),
                    ("↑/↓", "move"),
                    ("x", "advanced"),
                    ("/", "commands"),
                    ("?", "help"),
                ]
            }
        }
        WizardStep::Review => &[
            ("Tab", "focus"),
            (widgets::enter_key(), "start"),
            ("s", "new sample"),
            ("c", "save targets"),
            ("Esc", "back"),
            ("/", "commands"),
            ("?", "help"),
        ],
    };
    widgets::status_bar(frame, area, hints, app.visible_message());
}

/// Handle a key while on the wizard. Delegates to the active step's editor.
pub fn handle_wizard_key(app: &mut App, code: KeyCode) {
    match app.wizard_step {
        WizardStep::Ranges => handle_ranges_key(app, code),
        WizardStep::Settings => handle_settings_key(app, code),
        WizardStep::Review => handle_review_key(app, code),
    }
}

fn handle_ranges_key(app: &mut App, code: KeyCode) {
    if app.custom_input_mode {
        match code {
            KeyCode::Enter => {
                let s = app.input_buffer.trim().to_string();
                if s.is_empty() {
                    app.custom_input_mode = false;
                    app.input_buffer.clear();
                    app.edit_caret = 0;
                    return;
                }
                match crate::scanner::cidr_valid(&s) {
                    Ok(_) => {
                        if let Some((idx, entry)) = app
                            .cidr_candidates
                            .iter_mut()
                            .enumerate()
                            .find(|(_, entry)| entry.cidr == s)
                        {
                            entry.selected = true;
                            app.cursor = idx;
                            app.toast_warn(format!("CIDR {s} already exists; selected it"));
                        } else {
                            app.cidr_candidates.push(crate::tui::CidrEntry {
                                cidr: s.clone(),
                                selected: true,
                            });
                            app.cursor = app.cidr_candidates.len() - 1;
                            app.toast_success(format!("Added {s}"));
                        }
                        app.invalidate_preview();
                        app.input_buffer.clear();
                        app.edit_caret = 0;
                        app.custom_input_mode = false;
                        app.save_config();
                    }
                    Err(e) => app.toast_error(format!("Invalid CIDR '{s}': {e}")),
                }
            }
            KeyCode::Esc => {
                app.custom_input_mode = false;
                app.input_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace if app.edit_caret > 0 => {
                let previous = previous_char_boundary(&app.input_buffer, app.edit_caret);
                app.input_buffer.drain(previous..app.edit_caret);
                app.edit_caret = previous;
            }
            KeyCode::Delete if app.edit_caret < app.input_buffer.len() => {
                let next = next_char_boundary(&app.input_buffer, app.edit_caret);
                app.input_buffer.drain(app.edit_caret..next);
            }
            KeyCode::Left if app.edit_caret > 0 => {
                app.edit_caret = previous_char_boundary(&app.input_buffer, app.edit_caret);
            }
            KeyCode::Right if app.edit_caret < app.input_buffer.len() => {
                app.edit_caret = next_char_boundary(&app.input_buffer, app.edit_caret);
            }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.input_buffer.len(),
            KeyCode::Char(c) => {
                app.input_buffer.insert(app.edit_caret, c);
                app.edit_caret += c.len_utf8();
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Up | KeyCode::Char('k') if app.cursor > 0 => {
            app.cursor -= 1;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let last = app.cidr_candidates.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(e) = app.cidr_candidates.get_mut(app.cursor) {
                e.selected = !e.selected;
                app.invalidate_preview();
                app.save_config();
            }
        }
        KeyCode::Char('a') => {
            app.custom_input_mode = true;
            app.input_buffer.clear();
            app.edit_caret = 0;
        }
        KeyCode::Char('A') => {
            for e in app.cidr_candidates.iter_mut() {
                e.selected = true;
            }
            app.invalidate_preview();
            app.save_config();
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            let selected: Vec<String> = app
                .cidr_candidates
                .iter()
                .filter(|e| e.selected)
                .map(|e| e.cidr.clone())
                .collect();
            if app.config.discovery_driver == DiscoveryDriver::Sampling {
                // Sweep and the two-phase sampling pass are alternative
                // target-selection strategies; remember the two-phase
                // preference so switching back to sampling restores it.
                app.two_phase_before_sweep = app.config.two_phase;
                app.config.discovery_driver = DiscoveryDriver::Connect;
                app.config.two_phase = false;
                let total = crate::discovery::parse_target_sources(None, &selected)
                    .map(|sources| crate::discovery::enumerated_address_count(&sources))
                    .unwrap_or(0);
                if total > 10_000 {
                    app.toast_warn(format!(
                        "Full-range sweep: {} addresses will be scanned; large ranges take significant time",
                        format_ip_count(total)
                    ));
                } else {
                    app.toast_info(format!(
                        "Full-range sweep enabled: {} addresses will be scanned; reachable ports become targets",
                        format_ip_count(total)
                    ));
                }
            } else {
                app.config.discovery_driver = DiscoveryDriver::Sampling;
                app.config.two_phase = app.two_phase_before_sweep;
                app.toast_info(format!(
                    "Sampling mode restored: {} random IPs per CIDR",
                    app.config.sample_per_cidr
                ));
            }
            app.invalidate_preview();
            app.save_config();
        }
        KeyCode::Char('N') | KeyCode::Char('n') | KeyCode::Char('d') | KeyCode::Char('D') => {
            for e in app.cidr_candidates.iter_mut() {
                e.selected = false;
            }
            app.invalidate_preview();
            app.save_config();
        }
        KeyCode::Char('c') => {
            app.wizard_step = WizardStep::Settings;
            app.cursor = 0;
        }
        KeyCode::Right if (app.wizard_step as usize) < 2 => {
            app.wizard_step = WizardStep::Settings;
            app.cursor = 0;
        }
        KeyCode::Enter => match app.focus_index {
            1 if app.return_to_results => app.return_to_results(),
            1 => app.should_quit = true,
            _ => {
                app.wizard_step = WizardStep::Settings;
                app.cursor = 0;
            }
        },
        KeyCode::Esc if app.return_to_results => app.return_to_results(),
        _ => {}
    }
}

fn handle_settings_key(app: &mut App, code: KeyCode) {
    if app.edit_field.is_some() {
        let i = app.edit_field.expect("edit_field checked above");
        let field = SettingField::ALL[i];
        if field == SettingField::Ports {
            match code {
                KeyCode::Enter => {
                    app.commit_edit();
                }
                KeyCode::Esc => {
                    app.edit_field = None;
                    app.edit_buffer.clear();
                }
                KeyCode::Up if app.port_cursor > 0 => app.port_cursor -= 1,
                KeyCode::Down if app.port_cursor + 1 < CLOUDFLARE_HTTPS_PORTS.len() => {
                    app.port_cursor += 1
                }
                KeyCode::Char(' ') => toggle_port_buffer(app),
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    app.edit_buffer = CLOUDFLARE_HTTPS_PORTS
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                }
                KeyCode::Char('n') | KeyCode::Char('N') => app.edit_buffer.clear(),
                _ => {}
            }
            return;
        }
        if field == SettingField::Interface {
            match code {
                KeyCode::Enter => {
                    app.commit_edit();
                }
                KeyCode::Esc => {
                    app.edit_field = None;
                    app.edit_buffer.clear();
                    app.edit_caret = 0;
                }
                KeyCode::Up if app.interface_cursor > 0 => {
                    app.interface_cursor -= 1;
                }
                KeyCode::Down if app.interface_cursor + 1 < app.interface_list.len() + 1 => {
                    app.interface_cursor += 1;
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Enter => {
                app.commit_edit();
            }
            KeyCode::Esc => {
                app.edit_field = None;
                app.edit_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace if app.edit_caret > 0 => {
                let previous = previous_char_boundary(&app.edit_buffer, app.edit_caret);
                app.edit_buffer.drain(previous..app.edit_caret);
                app.edit_caret = previous;
            }
            KeyCode::Delete if app.edit_caret < app.edit_buffer.len() => {
                let next = next_char_boundary(&app.edit_buffer, app.edit_caret);
                app.edit_buffer.drain(app.edit_caret..next);
            }
            KeyCode::Left if app.edit_caret > 0 => {
                app.edit_caret = previous_char_boundary(&app.edit_buffer, app.edit_caret);
            }
            KeyCode::Right if app.edit_caret < app.edit_buffer.len() => {
                app.edit_caret = next_char_boundary(&app.edit_buffer, app.edit_caret);
            }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.edit_buffer.len(),
            KeyCode::Up | KeyCode::Down if field.is_numeric() => {
                let delta = if code == KeyCode::Up { 1 } else { -1 };
                if let Some(value) = field.nudged_text(&app.edit_buffer, delta) {
                    app.edit_buffer = value;
                    app.edit_caret = app.edit_buffer.len();
                }
            }
            KeyCode::Char(c) => {
                app.edit_buffer.insert(app.edit_caret, c);
                app.edit_caret += c.len_utf8();
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('x') => {
            app.show_advanced_settings = !app.show_advanced_settings;
            if !app.show_advanced_settings && SettingField::ALL[app.cursor].is_advanced() {
                app.cursor = 0;
            }
            app.settings_scroll = 0;
        }
        KeyCode::Char(' ') if SettingField::ALL[app.cursor].is_toggle() => {
            SettingField::ALL[app.cursor].toggle(&mut app.config);
            app.invalidate_preview();
            app.save_config();
        }
        KeyCode::Char('k') if app.cursor > 0 => {
            app.cursor = previous_visible_setting(app.cursor, app.show_advanced_settings);
        }
        KeyCode::Char('j') => {
            app.cursor = next_visible_setting(app.cursor, app.show_advanced_settings);
        }
        KeyCode::Up if app.cursor > 0 => {
            app.cursor = previous_visible_setting(app.cursor, app.show_advanced_settings);
        }
        KeyCode::Down => {
            app.cursor = next_visible_setting(app.cursor, app.show_advanced_settings);
        }
        KeyCode::Right if (app.wizard_step as usize) < 2 => {
            app.wizard_step = WizardStep::Review;
            app.cursor = 0;
        }
        KeyCode::Left | KeyCode::Esc => {
            app.wizard_step = WizardStep::Ranges;
            app.cursor = 0;
        }
        KeyCode::Enter => match app.focus_index {
            1 => {
                app.wizard_step = WizardStep::Ranges;
                app.cursor = 0;
            }
            2 => {
                app.wizard_step = WizardStep::Review;
                app.cursor = 0;
            }
            _ if SettingField::ALL[app.cursor].is_toggle() => {
                SettingField::ALL[app.cursor].toggle(&mut app.config);
                app.invalidate_preview();
                app.save_config();
            }
            _ => app.start_edit(app.cursor),
        },
        KeyCode::Char('1') => {
            app.config.sample_per_cidr = 100;
            app.config.probes = 8;
            app.config.concurrency = 120;
            app.config.timeout_ms = 2500;
            app.config.connect_timeout_ms = 1000;
            app.config.top = 50;
            app.config.early_stop = true;
            app.config.early_stop_loss_streak = 5;
            app.config.early_stop_min_samples = 3;
            app.config.early_stop_prune = true;
            app.config.early_stop_prune_margin = 0.2;
            app.config.two_phase = false;
            app.config.discover_fraction = 0.25;
            app.invalidate_preview();
            app.toast_success("Preset Applied: Default");
            app.save_config();
        }
        KeyCode::Char('2') => {
            app.config.sample_per_cidr = 50;
            app.config.probes = 4;
            app.config.concurrency = 200;
            app.config.timeout_ms = 1500;
            app.config.connect_timeout_ms = 500;
            app.config.top = 25;
            app.config.early_stop = true;
            app.config.early_stop_loss_streak = 4;
            app.config.early_stop_min_samples = 2;
            app.config.early_stop_prune = true;
            app.config.early_stop_prune_margin = 0.2;
            app.config.two_phase = true;
            app.config.discovery_driver = DiscoveryDriver::Sampling;
            app.config.discover_fraction = 0.25;
            app.invalidate_preview();
            app.toast_success("Preset Applied: Fast Scan");
            app.save_config();
        }
        KeyCode::Char('3') => {
            app.config.sample_per_cidr = 200;
            app.config.probes = 15;
            app.config.concurrency = 80;
            app.config.timeout_ms = 3500;
            app.config.connect_timeout_ms = 1500;
            app.config.top = 100;
            app.config.early_stop = true;
            app.config.early_stop_loss_streak = 8;
            app.config.early_stop_min_samples = 5;
            app.config.early_stop_prune = true;
            app.config.early_stop_prune_margin = 0.1;
            app.config.two_phase = false;
            app.config.discover_fraction = 0.25;
            app.invalidate_preview();
            app.toast_success("Preset Applied: Thorough Scan");
            app.save_config();
        }
        _ => {}
    }
    app.ensure_settings_visible();
}

pub(super) fn toggle_port_buffer(app: &mut App) {
    let port = CLOUDFLARE_HTTPS_PORTS[app.port_cursor];
    let mut ports = app
        .edit_buffer
        .split(',')
        .filter_map(|value| value.trim().parse::<u16>().ok())
        .collect::<Vec<_>>();
    if let Some(index) = ports.iter().position(|value| *value == port) {
        ports.remove(index);
    } else {
        ports.push(port);
    }
    ports.sort_unstable();
    app.edit_buffer = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
}

fn handle_review_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('s') => {
            app.regenerate_preview();
        }
        KeyCode::Char('c') => app.save_target_manifest(),
        KeyCode::Enter => match app.focus_index {
            1 => {
                app.wizard_step = WizardStep::Settings;
                app.cursor = 0;
            }
            2 => app.pending_start = true,
            _ => app.pending_start = true,
        },
        KeyCode::Left | KeyCode::Esc => {
            app.wizard_step = WizardStep::Settings;
            app.cursor = 0;
        }
        _ => {}
    }
}

impl App {
    /// Apply and save the currently edited settings field.
    ///
    /// Returns `true` when the draft was valid and the edit mode was closed.
    /// Invalid drafts remain active so the user can correct them.
    pub fn commit_edit(&mut self) -> bool {
        let Some(i) = self.edit_field else {
            return true;
        };
        let field = SettingField::ALL[i];
        if field == SettingField::Interface {
            self.commit_interface_selection();
            return true;
        }
        let mut updated_config = self.config.clone();
        match field.apply(&self.edit_buffer, &mut updated_config) {
            Ok(()) => {
                if matches!(field, SettingField::MinProbes | SettingField::MaxProbes)
                    && updated_config.min_probes > updated_config.max_probes
                {
                    self.toast_error("Minimum probes cannot exceed maximum probes");
                    return false;
                }
                if matches!(
                    field,
                    SettingField::MinConcurrency | SettingField::MaxConcurrency
                ) && updated_config.min_concurrency > updated_config.max_concurrency
                {
                    self.toast_error("Minimum concurrency cannot exceed maximum concurrency");
                    return false;
                }
                self.config = updated_config;
                self.edit_field = None;
                self.edit_buffer.clear();
                self.edit_caret = 0;
                self.invalidate_preview();
                self.save_config();
                true
            }
            Err(e) => {
                self.toast_error(format!("Invalid {}: {}", field.label(), e));
                false
            }
        }
    }

    /// Keep the selected settings field inside the last rendered viewport.
    pub fn ensure_settings_visible(&mut self) {
        let Some(inner) = self.settings_inner else {
            return;
        };
        let visible = inner.height as usize;
        if visible == 0 {
            return;
        }
        let row = settings_display_row(self.cursor);
        if row < self.settings_scroll {
            self.settings_scroll = row;
        } else if row >= self.settings_scroll + visible {
            self.settings_scroll = row + 1 - visible;
        }
    }

    /// Begin editing the setting at `idx` (used by keyboard Enter and mouse click).
    pub fn start_edit(&mut self, idx: usize) {
        if idx < SettingField::ALL.len() {
            let field = SettingField::ALL[idx];
            self.edit_field = Some(idx);
            self.edit_buffer = field.value_string(&self.config);
            self.edit_caret = self.edit_buffer.len();
            if field == SettingField::Ports {
                self.port_cursor = 0;
            }
            if field == SettingField::Interface {
                self.interface_list = crate::iface::list_interfaces().unwrap_or_default();
                self.interface_cursor = match &self.config.interface {
                    None => 0,
                    Some(name) => self
                        .interface_list
                        .iter()
                        .position(|entry| entry.name == *name)
                        .map(|index| index + 1)
                        .unwrap_or(0),
                };
            }
        }
    }

    /// Commit the currently highlighted interface row: row 0 clears the
    /// pin (auto), any other row pins that interface.
    pub fn commit_interface_selection(&mut self) {
        let selection = if self.interface_cursor == 0 {
            None
        } else {
            self.interface_list
                .get(self.interface_cursor - 1)
                .map(|entry| entry.name.clone())
        };
        self.config.interface = selection;
        self.review_interface_suffix = None;
        self.edit_field = None;
        self.edit_buffer.clear();
        self.edit_caret = 0;
        self.invalidate_preview();
        self.save_config();
    }
}

fn settings_display_row(field_idx: usize) -> usize {
    let mut row = 0;
    let mut first_field = 0;
    for (_, count) in SettingField::GROUPS {
        row += 1;
        if field_idx < first_field + count {
            return row + field_idx - first_field;
        }
        row += count;
        first_field += count;
    }
    row.saturating_sub(1)
}

fn previous_visible_setting(index: usize, show_advanced: bool) -> usize {
    (0..index)
        .rev()
        .find(|candidate| show_advanced || !SettingField::ALL[*candidate].is_advanced())
        .unwrap_or(index)
}

fn next_visible_setting(index: usize, show_advanced: bool) -> usize {
    ((index + 1)..SettingField::ALL.len())
        .find(|candidate| show_advanced || !SettingField::ALL[*candidate].is_advanced())
        .unwrap_or(index)
}

fn previous_char_boundary(s: &str, index: usize) -> usize {
    s[..index]
        .char_indices()
        .next_back()
        .map(|(position, _)| position)
        .unwrap_or(0)
}

fn next_char_boundary(s: &str, index: usize) -> usize {
    s[index..]
        .chars()
        .next()
        .map(|c| index + c.len_utf8())
        .unwrap_or(index)
}

#[cfg(test)]
mod tests {
    use super::{
        handle_ranges_key, handle_settings_key, ideal_scan_seconds, next_char_boundary,
        numeric_slider_bounds, previous_char_boundary, review_readiness, review_totals,
        selected_cidrs_and_workload, SettingField,
    };
    use crate::config::{AppConfig, DiscoveryDriver};
    use crate::tui::{App, CidrEntry};
    use std::sync::{atomic::AtomicBool, Arc};

    fn settings_app() -> App {
        App::new(
            AppConfig::default(),
            false,
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn field_position(field: SettingField) -> usize {
        SettingField::ALL
            .iter()
            .position(|candidate| *candidate == field)
            .unwrap()
    }

    #[test]
    fn advanced_settings_are_collapsed_but_navigation_stays_on_visible_fields() {
        let mut app = settings_app();
        app.cursor = field_position(SettingField::Top); // last regular latency field
        handle_settings_key(&mut app, crossterm::event::KeyCode::Down);
        assert_eq!(app.cursor, field_position(SettingField::EarlyStop)); // adaptive controls remain visible

        handle_settings_key(&mut app, crossterm::event::KeyCode::Char('x'));
        app.cursor = field_position(SettingField::StabilityWeight);
        handle_settings_key(&mut app, crossterm::event::KeyCode::Down);
        assert_eq!(app.cursor, field_position(SettingField::LossWeight));

        handle_settings_key(&mut app, crossterm::event::KeyCode::Char('x'));
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn interface_field_applies_auto_default_and_validates_names() {
        let mut config = AppConfig::default();
        assert_eq!(config.interface, None);
        for raw in ["auto", "Auto", "default", ""] {
            SettingField::Interface.apply(raw, &mut config).unwrap();
            assert_eq!(
                config.interface, None,
                "raw input {raw:?} should clear the pin"
            );
        }
        let name = crate::iface::list_interfaces()
            .unwrap()
            .first()
            .map(|entry| entry.name.clone())
            .expect("every platform has at least one interface");
        SettingField::Interface.apply(&name, &mut config).unwrap();
        assert_eq!(config.interface.as_deref(), Some(name.as_str()));
        assert!(SettingField::Interface
            .apply("definitely-not-an-interface", &mut config)
            .is_err());
        assert_eq!(config.interface.as_deref(), Some(name.as_str()));
    }

    #[test]
    fn interface_picker_navigates_and_commits() {
        let mut app = settings_app();
        app.wizard_step = crate::tui::WizardStep::Settings;
        let index = field_position(SettingField::Interface);
        app.start_edit(index);
        assert_eq!(app.edit_field, Some(index));
        assert_eq!(app.interface_cursor, 0);
        assert!(
            !app.interface_list.is_empty(),
            "expected at least a loopback interface"
        );

        // Down clamps to the last row (interfaces after the Auto row).
        for _ in 0..app.interface_list.len() + 5 {
            handle_settings_key(&mut app, crossterm::event::KeyCode::Down);
        }
        assert_eq!(app.interface_cursor, app.interface_list.len());

        handle_settings_key(&mut app, crossterm::event::KeyCode::Enter);
        assert_eq!(app.edit_field, None);
        assert_eq!(
            app.config.interface.as_deref(),
            app.interface_list.last().map(|entry| entry.name.as_str())
        );

        // Reopening the picker highlights the pinned interface; walking back
        // to Auto and committing clears the pin.
        app.start_edit(index);
        assert_eq!(app.interface_cursor, app.interface_list.len());
        while app.interface_cursor > 0 {
            handle_settings_key(&mut app, crossterm::event::KeyCode::Up);
        }
        handle_settings_key(&mut app, crossterm::event::KeyCode::Enter);
        assert_eq!(app.config.interface, None);
    }

    #[test]
    fn interface_edit_cancels_without_changes() {
        let mut app = settings_app();
        app.wizard_step = crate::tui::WizardStep::Settings;
        app.start_edit(field_position(SettingField::Interface));
        handle_settings_key(&mut app, crossterm::event::KeyCode::Down);
        handle_settings_key(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.edit_field, None);
        assert_eq!(app.config.interface, None);
    }

    #[test]
    fn adaptive_controls_toggle_without_text_editing() {
        let mut app = settings_app();
        app.config.adaptive_concurrency = false;
        app.cursor = SettingField::ALL
            .iter()
            .position(|field| *field == SettingField::AdaptiveConcurrency)
            .unwrap();

        handle_settings_key(&mut app, crossterm::event::KeyCode::Char(' '));
        assert!(app.config.adaptive_concurrency);
        handle_settings_key(&mut app, crossterm::event::KeyCode::Enter);
        assert!(!app.config.adaptive_concurrency);
        assert!(app.edit_field.is_none());
    }

    #[test]
    fn host_and_path_validation_match_url_construction() {
        let mut config = AppConfig::default();
        assert!(SettingField::Host
            .apply("example.test:443", &mut config)
            .is_ok());
        assert!(SettingField::Host
            .apply("https://example.test", &mut config)
            .is_err());
        assert!(SettingField::Host
            .apply("example.test/path", &mut config)
            .is_err());
        assert!(SettingField::Path.apply("/trace", &mut config).is_ok());
        assert!(SettingField::Path.apply("trace", &mut config).is_err());
    }

    #[test]
    fn ports_setting_accepts_supported_values_and_rejects_empty() {
        let mut config = AppConfig::default();
        SettingField::Ports
            .apply("8443,443,443", &mut config)
            .unwrap();
        assert_eq!(config.ports, vec![443, 8443]);
        assert!(SettingField::Ports.apply("", &mut config).is_err());
        assert!(SettingField::Ports.apply("22", &mut config).is_err());
    }

    #[test]
    fn advanced_scan_settings_and_health_checks_are_editable() {
        let mut config = AppConfig::default();
        SettingField::HealthChecks
            .apply(
                "primary|/health|true|2;optional|/ready|false|0.5",
                &mut config,
            )
            .unwrap();
        assert_eq!(config.health_checks.len(), 2);
        assert_eq!(config.health_checks[0].path, "/health");
        assert!(!config.health_checks[1].required);
        assert_eq!(config.health_checks[1].weight, 0.5);

        SettingField::Warmup.apply("off", &mut config).unwrap();
        SettingField::AdaptiveProbing
            .apply("on", &mut config)
            .unwrap();
        SettingField::MinProbes.apply("4", &mut config).unwrap();
        SettingField::MaxProbes.apply("20", &mut config).unwrap();
        SettingField::Confidence.apply("0.99", &mut config).unwrap();
        assert!(!config.warmup);
        assert!(config.adaptive_probing);
        assert_eq!(config.min_probes, 4);
        assert_eq!(config.max_probes, 20);
        assert_eq!(config.confidence, 0.99);
    }

    #[test]
    fn health_checks_reject_duplicate_names() {
        let mut config = AppConfig::default();
        let error = SettingField::HealthChecks
            .apply(
                "primary|/health|true|1; primary |/ready|false|1",
                &mut config,
            )
            .unwrap_err();
        assert_eq!(error, "duplicate health check name: primary");
        assert!(config.health_checks.is_empty());
    }

    #[test]
    fn confidence_slider_uses_fractional_bounds() {
        assert_eq!(numeric_slider_bounds(SettingField::Confidence), (0.0, 1.0));
    }

    #[test]
    fn confidence_nudge_and_apply_stay_within_supported_levels() {
        assert_eq!(
            SettingField::Confidence.nudged_fractional_value(0.95, -1),
            0.90
        );
        assert_eq!(
            SettingField::Confidence.nudged_fractional_value(0.90, -1),
            0.90
        );
        assert_eq!(
            SettingField::Confidence.nudged_fractional_value(0.95, 1),
            0.99
        );
        assert_eq!(
            SettingField::Confidence.nudged_fractional_value(0.99, 1),
            0.99
        );
        assert_eq!(
            SettingField::Confidence.nudged_text("0.90", 1),
            Some("0.95".to_string())
        );
        let mut config = AppConfig::default();
        assert!(SettingField::Confidence.apply("0.90", &mut config).is_ok());
        assert!(SettingField::Confidence.apply("0.95", &mut config).is_ok());
        assert!(SettingField::Confidence.apply("0.99", &mut config).is_ok());
        assert!(SettingField::Confidence.apply("0.85", &mut config).is_err());
        assert!(SettingField::Confidence.apply("1.00", &mut config).is_err());
        assert!(SettingField::Confidence.apply("0.01", &mut config).is_err());
    }

    #[test]
    fn required_headers_reject_empty_parts_and_accept_equals_in_values() {
        let mut config = AppConfig::default();
        assert!(SettingField::RequiredHeaders
            .apply("x-token=a=b", &mut config)
            .is_ok());
        assert!(SettingField::RequiredHeaders
            .apply("=value", &mut config)
            .is_err());
        assert!(SettingField::RequiredHeaders
            .apply("name=", &mut config)
            .is_err());
        assert!(SettingField::RequiredHeaders
            .apply("bad header=value", &mut config)
            .is_err());
    }

    #[test]
    fn discovery_driver_cycles_between_sampling_and_connect() {
        let mut config = AppConfig::default();
        assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);
        SettingField::DiscoveryDriver.toggle(&mut config);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Connect);
        #[cfg(not(feature = "syn"))]
        {
            SettingField::DiscoveryDriver.toggle(&mut config);
            assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);
        }
    }

    #[cfg(feature = "syn")]
    #[test]
    fn discovery_driver_cycles_through_syn_when_built_with_feature() {
        let mut config = AppConfig::default();
        SettingField::DiscoveryDriver.toggle(&mut config);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Connect);
        SettingField::DiscoveryDriver.toggle(&mut config);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Syn);
        assert!(!config.two_phase);
        SettingField::DiscoveryDriver.toggle(&mut config);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);
    }

    #[test]
    fn discovery_driver_and_two_phase_are_mutually_exclusive() {
        let mut config = AppConfig {
            two_phase: true,
            ..AppConfig::default()
        };
        SettingField::DiscoveryDriver.toggle(&mut config);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Connect);
        assert!(!config.two_phase);

        let mut config = AppConfig {
            discovery_driver: DiscoveryDriver::Connect,
            ..AppConfig::default()
        };
        SettingField::TwoPhase.toggle(&mut config);
        assert!(config.two_phase);
        assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);
    }

    #[test]
    fn ranges_sweep_key_toggles_between_sampling_and_connect() {
        let mut app = settings_app();
        app.cidr_candidates = vec![CidrEntry {
            cidr: "10.0.0.0/24".to_string(),
            selected: true,
        }];
        assert_eq!(app.config.discovery_driver, DiscoveryDriver::Sampling);

        app.config.two_phase = true;
        handle_ranges_key(&mut app, crossterm::event::KeyCode::Char('s'));
        assert_eq!(
            app.config.discovery_driver,
            DiscoveryDriver::Connect,
            "s enables the full-range connect sweep"
        );
        assert!(
            !app.config.two_phase,
            "sweep and the two-phase sampling pass are exclusive"
        );

        handle_ranges_key(&mut app, crossterm::event::KeyCode::Char('S'));
        assert_eq!(
            app.config.discovery_driver,
            DiscoveryDriver::Sampling,
            "s restores sampling mode"
        );
        assert!(
            app.config.two_phase,
            "s restores the two-phase setting saved before the sweep"
        );
    }

    #[test]
    fn discovery_driver_edit_accepts_names_and_rejects_syn() {
        let mut config = AppConfig::default();
        assert!(SettingField::DiscoveryDriver
            .apply("connect", &mut config)
            .is_ok());
        assert_eq!(config.discovery_driver, DiscoveryDriver::Connect);
        assert!(!config.two_phase);

        assert!(SettingField::DiscoveryDriver
            .apply("sampling", &mut config)
            .is_ok());
        assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);

        #[cfg(feature = "syn")]
        {
            assert!(SettingField::DiscoveryDriver
                .apply("syn", &mut config)
                .is_ok());
            assert_eq!(config.discovery_driver, DiscoveryDriver::Syn);
            assert!(!config.two_phase);
        }
        #[cfg(not(feature = "syn"))]
        {
            assert!(SettingField::DiscoveryDriver
                .apply("syn", &mut config)
                .is_err());
            assert_eq!(config.discovery_driver, DiscoveryDriver::Sampling);
        }

        assert!(SettingField::DiscoveryDriver
            .apply("bogus", &mut config)
            .is_err());
    }

    #[test]
    fn syn_review_counts_full_range_and_reports_sweep_ready() {
        let mut app = settings_app();
        app.config.discovery_driver = DiscoveryDriver::Syn;
        app.cidr_candidates = vec![CidrEntry {
            cidr: "10.0.0.0/24".to_string(),
            selected: true,
        }];
        let (selected, workload) = selected_cidrs_and_workload(&app);
        let (ips, probes) = review_totals(&selected, false, 0, &app.config, workload.total_ips);
        assert_eq!(
            ips, 254,
            "syn enumerates the full range, not the sample cap"
        );
        assert_eq!(probes, ips * app.config.ports.len().max(1) as u128);
        let (text, warn) = review_readiness(true, false, app.config.concurrency, ips);
        assert_eq!(
            text,
            "Ready: sweep will find reachable ports, then probe them"
        );
        assert!(!warn);

        let (text, warn) = review_readiness(true, false, app.config.concurrency, 65_534);
        assert_eq!(
            text,
            "Ready: sweep will find reachable ports, then probe them"
        );
        assert!(warn, "huge sweep ranges still warn");
    }

    #[test]
    fn sampled_review_keeps_capped_estimates_and_sampling_readiness() {
        let mut app = settings_app();
        app.cidr_candidates = vec![CidrEntry {
            cidr: "10.0.0.0/16".to_string(),
            selected: true,
        }];
        let (selected, workload) = selected_cidrs_and_workload(&app);
        assert_eq!(workload.total_ips, 100, "sampling caps at sample_per_cidr");
        let (ips, probes) = review_totals(&selected, false, 0, &app.config, workload.total_ips);
        assert_eq!(ips, 100, "sampled drivers must not count the full range");
        assert_eq!(
            probes,
            ips * app.config.probes as u128 * app.config.ports.len().max(1) as u128
        );
        let (text, warn) = review_readiness(false, true, app.config.concurrency, ips);
        assert_eq!(text, "Ready: sampled targets are stable for this review");
        assert!(!warn);
    }

    #[test]
    fn zero_concurrency_uses_one_worker_for_eta() {
        assert_eq!(ideal_scan_seconds(100, 0, 2_000), 100.0);
    }

    #[test]
    fn expected_statuses_require_http_status_range() {
        let mut config = AppConfig::default();
        assert!(SettingField::ExpectedStatuses
            .apply("100,200,599", &mut config)
            .is_ok());
        assert!(SettingField::ExpectedStatuses
            .apply("99", &mut config)
            .is_err());
        assert!(SettingField::ExpectedStatuses
            .apply("600", &mut config)
            .is_err());
    }

    #[test]
    fn editor_boundaries_are_utf8_safe() {
        let value = "a🙂b";
        assert_eq!(previous_char_boundary(value, value.len()), 5);
        assert_eq!(previous_char_boundary(value, 5), 1);
        assert_eq!(next_char_boundary(value, 1), 5);
        assert_eq!(next_char_boundary(value, 5), value.len());
    }

    #[test]
    fn numeric_nudge_uses_field_specific_steps() {
        assert_eq!(SettingField::Probes.nudged_value(8, 1), 9);
        assert_eq!(SettingField::SamplePerCidr.nudged_value(100, 1), 110);
        assert_eq!(SettingField::TimeoutMs.nudged_value(2500, -1), 2400);
    }

    #[test]
    fn numeric_nudge_clamps_to_valid_bounds() {
        assert_eq!(SettingField::Probes.nudged_value(1, -1), 1);
        assert_eq!(SettingField::Probes.nudged_value(1000, 1), 1000);
        assert_eq!(SettingField::Top.nudged_value(10_000, 1), 10_000);
    }

    #[test]
    fn arrows_traverse_numeric_settings_when_not_editing() {
        let mut app = settings_app();
        app.wizard_step = crate::tui::WizardStep::Settings;
        app.cursor = 1;

        handle_settings_key(&mut app, crossterm::event::KeyCode::Down);
        assert_eq!(app.cursor, 2);
        assert_eq!(app.config.sample_per_cidr, 100);

        handle_settings_key(&mut app, crossterm::event::KeyCode::Up);
        assert_eq!(app.cursor, 1);
        assert_eq!(app.config.sample_per_cidr, 100);
    }

    #[test]
    fn arrows_step_numeric_draft_while_editing() {
        let mut app = settings_app();
        app.wizard_step = crate::tui::WizardStep::Settings;
        let sample_index = SettingField::ALL
            .iter()
            .position(|field| *field == SettingField::SamplePerCidr)
            .unwrap();
        app.start_edit(sample_index);
        app.edit_buffer = "100".to_string();
        app.edit_caret = app.edit_buffer.len();

        handle_settings_key(&mut app, crossterm::event::KeyCode::Up);

        assert_eq!(app.edit_field, Some(sample_index));
        assert_eq!(app.edit_buffer, "110");
        assert_eq!(app.config.sample_per_cidr, 100);
    }

    #[test]
    fn invalid_edit_remains_active_when_committing() {
        let mut app = settings_app();
        app.start_edit(1);
        app.edit_buffer = "invalid/path".to_string();

        assert!(!app.commit_edit());
        assert_eq!(app.edit_field, Some(1));
        assert_eq!(app.config.path, "/cdn-cgi/trace");
    }

    #[test]
    fn sample_per_cidr_accepts_large_explicit_workloads() {
        let mut app = settings_app();
        let sample_index = SettingField::ALL
            .iter()
            .position(|field| *field == SettingField::SamplePerCidr)
            .unwrap();
        app.start_edit(sample_index);
        app.edit_buffer = "1000000".to_string();

        assert!(app.commit_edit());
        assert_eq!(app.config.sample_per_cidr, 1_000_000);
    }

    #[test]
    fn fractional_fields_nudge_without_integer_clamping() {
        assert_eq!(
            SettingField::StabilityWeight.nudged_text("1.0", -1),
            Some("0.90".to_string())
        );
        assert_eq!(
            SettingField::DiscoverFraction.nudged_text("0.25", -1),
            Some("0.20".to_string())
        );
        assert_eq!(
            SettingField::DiscoverFraction.nudged_text("0.0", -1),
            Some("0.00".to_string())
        );
        assert_eq!(
            SettingField::DiscoverFraction.nudged_text("1.0", 1),
            Some("1.00".to_string())
        );
    }

    #[test]
    fn ip_capacity_labels_use_trusted_compact_grammar() {
        assert_eq!(super::ip_label(1), "1 IP");
        assert_eq!(super::ip_label(256), "256 IPs");
        assert_eq!(super::ip_label(4_096), "4,096 IPs");
        assert_eq!(
            super::format_ip_count(u128::MAX),
            "340,282,366,920,938,463,463,374,607,431,768,211,455"
        );
    }
}
