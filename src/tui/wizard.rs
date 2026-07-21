use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::collections::HashSet;

use crate::config::{AppConfig, HealthCheck};
use crate::tui::theme;
use crate::tui::{widgets, App, ButtonAction, ButtonKind, WizardStep};
use tui_checkbox::Checkbox;
use tui_slider::{Slider, SliderState};

/// Identifies an editable scan parameter on the settings step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    Host,
    Path,
    ExpectedStatuses,
    RequiredBodyMarkers,
    RequiredHeaders,
    FollowRedirects,
    HealthChecks,
    Warmup,
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
    DiscoverFraction,
    AdaptiveProbing,
    MinProbes,
    MaxProbes,
    Confidence,
}

const MAX_SAMPLE_PER_CIDR: usize = 10_000;
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
    /// All settings fields in display order, grouped by concern. Group
    /// boundaries are described by [`SettingField::GROUPS`].
    pub const ALL: [SettingField; 32] = [
        // Target
        SettingField::Host,
        SettingField::Path,
        SettingField::ExpectedStatuses,
        SettingField::RequiredBodyMarkers,
        SettingField::RequiredHeaders,
        SettingField::FollowRedirects,
        SettingField::HealthChecks,
        SettingField::Warmup,
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
        SettingField::DiscoverFraction,
        SettingField::AdaptiveProbing,
        SettingField::MinProbes,
        SettingField::MaxProbes,
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
    pub const GROUPS: [(&'static str, usize); 6] = [
        ("Target", 2),
        ("Validation", 6),
        ("Latency scan", 6),
        ("Ranking quality", 2),
        ("Adaptive scan", 11),
        ("Speed test", 5),
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SettingField::Host => "Host",
            SettingField::Path => "Path",
            SettingField::ExpectedStatuses => "Expected statuses",
            SettingField::RequiredBodyMarkers => "Required body markers",
            SettingField::RequiredHeaders => "Required headers",
            SettingField::FollowRedirects => "Follow redirects",
            SettingField::HealthChecks => "Health checks",
            SettingField::Warmup => "Warmup probe",
            SettingField::DownloadPath => "Download path",
            SettingField::UploadPath => "Upload path",
            SettingField::SpeedPayloadMb => "Speed payload (MB)",
            SettingField::SpeedRepetitions => "Speed repetitions",
            SettingField::SpeedTimeoutMs => "Speed timeout (ms)",
            SettingField::SamplePerCidr => "Sample per CIDR",
            SettingField::Probes => "Probes",
            SettingField::Concurrency => "Concurrency",
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
            SettingField::DiscoverFraction => "Discover fraction",
            SettingField::AdaptiveProbing => "Adaptive probing",
            SettingField::MinProbes => "Minimum probes",
            SettingField::MaxProbes => "Maximum probes",
            SettingField::Confidence => "Confidence",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SettingField::Host => "The hostname used in SNI and the Host header for HTTP probes (e.g. app.iplat.ir). Cleanscan resolves this host to the tested edge IPs directly.",
            SettingField::Path => "The HTTP request path to probe (e.g. /cdn-cgi/trace). Typically points to a lightweight text file or endpoint to minimize bandwidth usage.",
            SettingField::ExpectedStatuses => "Comma-separated HTTP statuses accepted by the endpoint. Empty means any 2xx response.",
            SettingField::RequiredBodyMarkers => "Comma-separated literal substrings that must occur in the response body.",
            SettingField::RequiredHeaders => "Comma-separated exact header checks in name=value form.",
            SettingField::FollowRedirects => "Follow redirects during validation. Off preserves the default strict behavior.",
            SettingField::HealthChecks => "Optional checks encoded as name|path|required|weight;... . Leave empty to use the primary path.",
            SettingField::Warmup => "Send a discarded connection-establishment request before measured latency probes.",
            SettingField::DownloadPath => "Static file endpoint used for download speed tests.",
            SettingField::UploadPath => "POST endpoint used for upload speed tests; it should consume and discard the request body.",
            SettingField::SpeedPayloadMb => "Payload size used for each upload/download repetition. Larger payloads reduce short-test noise but use more bandwidth.",
            SettingField::SpeedRepetitions => "Number of upload/download repetitions per selected IP; reported speeds are averaged.",
            SettingField::SpeedTimeoutMs => "Maximum total time for one upload/download transfer, separate from the normal latency probe timeout.",
            SettingField::SamplePerCidr => "Number of random IPs sampled from each selected CIDR. Higher values increase coverage across the edge network, but increase total targets.",
            SettingField::Probes => "Number of requests sent to each IP to probe latency. More probes filter out transient noise and establish a highly accurate latency percentile.",
            SettingField::Concurrency => "Maximum number of simultaneous request workers. Higher concurrency speeds up scanning but may trigger rate limiting or CPU bottlenecks.",
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
            SettingField::TwoPhase => "Run a sparse discovery pass first, then spend the rest of the probe budget focusing on the CIDRs that produced the best Cloudflare colos. Finds good edges faster and densifies there.",
            SettingField::DiscoverFraction => "Fraction of sample_per_cidr used for the discovery pass when two-phase scanning is enabled; the remainder is spent on the focused CIDRs.",
            SettingField::AdaptiveProbing => "Allocate probes adaptively using confidence intervals instead of probing every target equally.",
            SettingField::MinProbes => "Minimum measured probes before adaptive stopping can occur.",
            SettingField::MaxProbes => "Maximum measured probes per target in adaptive mode.",
            SettingField::Confidence => "Confidence level used by adaptive score intervals, from 0 to 1.",
        }
    }

    /// Current value of this field as an editable string.
    pub fn value_string(&self, args: &AppConfig) -> String {
        match self {
            SettingField::Host => args.host.clone(),
            SettingField::Path => args.path.clone(),
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
            SettingField::Confidence => args.confidence.to_string(),
        }
    }

    fn is_numeric(&self) -> bool {
        !matches!(
            self,
            SettingField::Host
                | SettingField::Path
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
                | SettingField::Warmup
                | SettingField::AdaptiveProbing
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
            SettingField::Confidence => 0.05,
            _ => unreachable!("fractional_step called for an integer field"),
        }
    }

    fn nudged_fractional_value(&self, value: f64, direction: i64) -> f64 {
        let lower = if matches!(self, SettingField::Confidence) {
            0.01
        } else {
            0.0
        };
        let upper = if matches!(
            self,
            SettingField::DiscoverFraction | SettingField::Confidence
        ) {
            1.0
        } else {
            f64::MAX
        };
        (value + direction as f64 * self.fractional_step()).clamp(lower, upper)
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
            SettingField::Host
            | SettingField::Path
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
            | SettingField::Warmup
            | SettingField::AdaptiveProbing
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
            SettingField::Confidence => {
                let v = raw
                    .parse::<f64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !v.is_finite() || !(0.0..=1.0).contains(&v) || v == 0.0 {
                    return Err("must be a number between 0 and 1".to_string());
                }
                args.confidence = v;
            }
        }
        Ok(())
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

    let list_block =
        widgets::panel_block("Cloudflare CIDR ranges (space toggle, A all, N none)", true);
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
                Paragraph::new("› ").style(theme::row_selected_style()),
                Rect {
                    x: inner.x,
                    y,
                    width: 2,
                    height: 1,
                },
            );
        }
        let checkbox = Checkbox::new(e.cidr.clone(), e.selected)
            .checked_symbol("[✓]")
            .unchecked_symbol("[ ]")
            .style(if idx == app.cursor || e.selected {
                theme::row_selected_style()
            } else {
                theme::hint_style()
            })
            .label_style(if idx == app.cursor || e.selected {
                theme::row_selected_style()
            } else {
                theme::hint_style()
            })
            .checkbox_style(if e.selected {
                Style::default()
                    .fg(theme::palette().success)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::palette().subtitle)
            });
        frame.render_widget(
            checkbox,
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
    let total_ips = selected_count.saturating_mul(app.config.sample_per_cidr);
    let total_requests = total_ips.saturating_mul(app.config.probes);

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
            Span::styled("Sample per CIDR: ", theme::title_style()),
            Span::raw(app.config.sample_per_cidr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total target IPs: ", theme::title_style()),
            Span::raw(total_ips.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total HTTP Probes: ", theme::title_style()),
            Span::raw(total_requests.to_string()),
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

    let block = widgets::panel_block("Scan parameters (Enter edit, ↑/↓ step numeric)", true);
    let inner = block.inner(main_layout[0]);
    app.settings_inner = Some(inner);

    // Build the field list with section subheaders, tracking which display row
    // maps to which field index (headers map to `None`) for mouse hit-testing.
    let mut lines: Vec<Line> = Vec::new();
    let mut row_map: Vec<Option<usize>> = Vec::new();
    let mut field_idx = 0usize;
    for (header, count) in SettingField::GROUPS {
        lines.push(Line::from(Span::styled(
            format!(" {} ", header.to_uppercase()),
            theme::subtitle_style().add_modifier(Modifier::BOLD),
        )));
        row_map.push(None);
        for _ in 0..count {
            let i = field_idx;
            let f = SettingField::ALL[i];
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
            } else {
                f.value_string(&app.config)
            };
            let label = format!("{:20}", f.label());
            lines.push(Line::from(format!("{} = {}", label, value)).style(style));
            row_map.push(Some(i));
            field_idx += 1;
        }
    }

    let items = lines.into_iter().map(ListItem::new).collect::<Vec<_>>();
    let selected_row = row_map.iter().position(|field| *field == Some(app.cursor));
    app.settings_list_state = app
        .settings_list_state
        .with_offset(app.settings_scroll)
        .with_selected(selected_row);
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(theme::row_selected_style())
            .highlight_symbol("› "),
        main_layout[0],
        &mut app.settings_list_state,
    );
    app.settings_scroll = app.settings_list_state.offset();
    let start = app.settings_scroll.min(row_map.len());
    let end = (start + inner.height as usize).min(row_map.len());
    app.settings_row_map = row_map[start..end].to_vec();

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

    let desc_block = widgets::panel_block("Field Context", false);
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
    let selected: Vec<String> = app
        .cidr_candidates
        .iter()
        .filter(|e| e.selected)
        .map(|e| e.cidr.clone())
        .collect();

    let selected_count = selected.len();
    let preview_ready = !app.preview_targets.is_empty();
    let total_ips = if app.preview_targets.is_empty() {
        selected_count.saturating_mul(app.config.sample_per_cidr)
    } else {
        app.preview_targets.len()
    };
    let total_probes = total_ips.saturating_mul(app.config.probes);

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
    summary_left.extend(
        selected
            .iter()
            .take(8)
            .map(|c| Line::from(format!("  • {c}"))),
    );
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
            Span::styled("Samples/CIDR: ", theme::title_style()),
            Span::raw(app.config.sample_per_cidr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Probes/IP   : ", theme::title_style()),
            Span::raw(app.config.probes.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Concurrency : ", theme::title_style()),
            Span::raw(app.config.concurrency.to_string()),
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
            Span::styled("Total IPs   : ", theme::title_style()),
            Span::raw(total_ips.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total Probes: ", theme::title_style()),
            Span::raw(total_probes.to_string()),
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
            if !preview_ready {
                "Unavailable: target preview could not be generated"
            } else if app.config.concurrency > 500 {
                "Warning: very high concurrency may trigger rate limits"
            } else if total_ips > 10_000 {
                "Warning: large target set; this scan may take significant time"
            } else {
                "Ready: sampled targets are stable for this review"
            },
            if !preview_ready || app.config.concurrency > 500 || total_ips > 10_000 {
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

fn ideal_scan_seconds(total_probes: usize, concurrency: usize, timeout_ms: u64) -> f64 {
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
                &[("type", "CIDR"), ("↵", "confirm"), ("Esc", "cancel")]
            } else {
                &[
                    ("Tab", "focus"),
                    ("Space", "toggle"),
                    ("↵", "next"),
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
                    ("↵", "confirm"),
                    ("Esc", "cancel"),
                ]
            } else {
                &[
                    ("Tab", "focus"),
                    ("↵", "edit/next"),
                    ("↑/↓", "move"),
                    ("/", "commands"),
                    ("?", "help"),
                ]
            }
        }
        WizardStep::Review => &[
            ("Tab", "focus"),
            ("↵", "start"),
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
            1 => app.should_quit = true,
            _ => {
                app.wizard_step = WizardStep::Settings;
                app.cursor = 0;
            }
        },
        _ => {}
    }
}

fn handle_settings_key(app: &mut App, code: KeyCode) {
    if app.edit_field.is_some() {
        let i = app.edit_field.expect("edit_field checked above");
        let field = SettingField::ALL[i];
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
        KeyCode::Char('k') if app.cursor > 0 => {
            app.cursor -= 1;
        }
        KeyCode::Char('j') => {
            let last = SettingField::ALL.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Up if app.cursor > 0 => {
            app.cursor -= 1;
        }
        KeyCode::Down => {
            let last = SettingField::ALL.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
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

fn handle_review_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('s') => app.regenerate_preview(),
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
        let mut updated_config = self.config.clone();
        match field.apply(&self.edit_buffer, &mut updated_config) {
            Ok(()) => {
                if matches!(field, SettingField::MinProbes | SettingField::MaxProbes)
                    && updated_config.min_probes > updated_config.max_probes
                {
                    self.toast_error("Minimum probes cannot exceed maximum probes");
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
        }
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
        handle_settings_key, ideal_scan_seconds, next_char_boundary, numeric_slider_bounds,
        previous_char_boundary, SettingField,
    };
    use crate::config::AppConfig;
    use crate::tui::App;
    use std::sync::{atomic::AtomicBool, Arc};

    fn settings_app() -> App {
        App::new(
            AppConfig::default(),
            false,
            Arc::new(AtomicBool::new(false)),
        )
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
    fn confidence_nudge_never_reaches_uncommittable_zero() {
        assert_eq!(
            SettingField::Confidence.nudged_fractional_value(0.05, -1),
            0.01
        );
        let mut config = AppConfig::default();
        assert!(SettingField::Confidence.apply("0.01", &mut config).is_ok());
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
}
