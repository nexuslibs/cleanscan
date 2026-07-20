use anyhow::Result;
use reqwest::header::HeaderName;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs, io::Write};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HealthCheck {
    pub name: String,
    pub path: String,
    #[serde(default = "default_health_check_required")]
    pub required: bool,
    #[serde(default = "default_health_check_weight")]
    pub weight: f64,
}

fn default_health_check_required() -> bool {
    true
}
fn default_health_check_weight() -> f64 {
    1.0
}

/// Parse and validate a required response-header expression.
///
/// The first `=` separates the header name from its expected value; additional
/// equals signs belong to the value (for example, a base64 token).
pub fn parse_required_header(expression: &str) -> Result<(String, String), String> {
    let Some((name, expected)) = expression.split_once('=') else {
        return Err("headers must use name=value form".to_string());
    };
    let name = name.trim();
    let expected = expected.trim();
    if name.is_empty() {
        return Err("header name must not be empty".to_string());
    }
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("invalid header name: {name}"))?;
    if expected.is_empty() {
        return Err("header value must not be empty".to_string());
    }
    Ok((name.to_string(), expected.to_string()))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub health_checks: Vec<HealthCheck>,
    /// Expected HTTP statuses. An empty list accepts any 2xx response.
    #[serde(default)]
    pub expected_statuses: Vec<u16>,
    /// Required literal substrings that must occur in the response body.
    #[serde(default)]
    pub required_body_markers: Vec<String>,
    /// Required exact header expressions in `name=value` form.
    #[serde(default)]
    pub required_headers: Vec<String>,
    /// Follow redirects during validation. Disabled by default for compatibility.
    #[serde(default)]
    pub follow_redirects: bool,
    pub sample_per_cidr: usize,
    pub probes: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub top: usize,
    #[serde(default)]
    pub seed: u64,
    #[serde(default = "default_download_path")]
    pub download_path: String,
    #[serde(default = "default_upload_path")]
    pub upload_path: String,
    #[serde(default = "default_speed_payload_bytes")]
    pub speed_payload_bytes: u64,
    #[serde(default = "default_speed_repetitions")]
    pub speed_repetitions: usize,
    #[serde(default = "default_speed_timeout_ms")]
    pub speed_timeout_ms: u64,
    /// Send a discarded connection-establishment probe before the counted
    /// latency probes so measured latency reflects steady-state RTT rather
    /// than TCP + TLS handshake cost.
    #[serde(default = "default_warmup")]
    pub warmup: bool,
    /// Weight applied to jitter in the recommendation score. Higher values make
    /// a jittery (variable-latency) IP rank lower relative to a steadier one.
    #[serde(default = "default_stability_weight")]
    pub stability_weight: f64,
    /// Weight applied to packet loss in the recommendation score. Higher values
    /// make a lossy IP rank lower even when its success rate still looks usable.
    #[serde(default = "default_loss_weight")]
    pub loss_weight: f64,
    /// Stop probing a target early once it is clearly dead or clearly worse
    /// than the current top candidates, instead of always running the full
    /// `--probes` budget against every target.
    #[serde(default = "default_early_stop")]
    pub early_stop: bool,
    /// Number of consecutive dropped probes (timeouts / connect failures) after
    /// which a target is declared dead and stopped early. Only applies once at
    /// least `early_stop_min_samples` measured probes have completed.
    #[serde(default = "default_early_stop_loss_streak")]
    pub early_stop_loss_streak: usize,
    /// Minimum number of measured probes before any early-stop rule may fire,
    /// so a single first-timeout does not abort an otherwise-good target.
    #[serde(default = "default_early_stop_min_samples")]
    pub early_stop_min_samples: usize,
    /// Success rate below which a target is abandoned early once enough probes
    /// have completed. A target unlikely to ever reach READY is skipped.
    #[serde(default = "default_early_stop_success_floor")]
    pub early_stop_success_floor: f64,
    /// Once at least `top` READY candidates exist, stop probing targets whose
    /// current best score remains worse than the worst candidate after the
    /// configured margin tolerance is applied.
    #[serde(default = "default_early_stop_prune")]
    pub early_stop_prune: bool,
    /// How much worse (as a fraction) a target may be than the current worst
    /// top-N candidate before it is pruned.
    #[serde(default = "default_early_stop_prune_margin")]
    pub early_stop_prune_margin: f64,
    /// Run a sparse discovery pass first, then focus the remaining probe budget
    /// on CIDRs that produced the best Cloudflare colos (two-phase sampling).
    #[serde(default = "default_two_phase")]
    pub two_phase: bool,
    /// Fraction of `sample_per_cidr` used for the discovery pass when
    /// `two_phase` is enabled (the remainder is spent focusing on good colos).
    #[serde(default = "default_discover_fraction")]
    pub discover_fraction: f64,
    /// Maximum number of CIDRs selected for the two-phase focus pass. Zero
    /// means all eligible CIDRs; this is independent of the display limit.
    #[serde(default)]
    pub two_phase_focus_cidrs: usize,
    #[serde(default)]
    pub adaptive_probing: bool,
    #[serde(default = "default_min_probes")]
    pub min_probes: usize,
    #[serde(default = "default_max_probes")]
    pub max_probes: usize,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    pub custom_cidrs: Vec<String>,
    #[serde(default)]
    pub selected_cidrs: Vec<String>,
    #[serde(skip)]
    pub selected_cidrs_persisted: bool,
}

fn default_download_path() -> String {
    "/speed-test/100mb.bin".to_string()
}

fn default_upload_path() -> String {
    "/speed-test/upload".to_string()
}

fn default_speed_payload_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_speed_repetitions() -> usize {
    1
}

fn default_speed_timeout_ms() -> u64 {
    120_000
}

fn default_warmup() -> bool {
    true
}

fn default_stability_weight() -> f64 {
    1.0
}

fn default_loss_weight() -> f64 {
    1.0
}

fn default_early_stop() -> bool {
    true
}

fn default_early_stop_loss_streak() -> usize {
    5
}

fn default_early_stop_min_samples() -> usize {
    3
}

fn default_early_stop_success_floor() -> f64 {
    0.5
}

fn default_early_stop_prune() -> bool {
    true
}

fn default_early_stop_prune_margin() -> f64 {
    0.2
}

fn default_two_phase() -> bool {
    false
}

fn default_discover_fraction() -> f64 {
    0.25
}

fn default_min_probes() -> usize {
    3
}
fn default_max_probes() -> usize {
    40
}
fn default_confidence() -> f64 {
    0.95
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: "/cdn-cgi/trace".to_string(),
            health_checks: Vec::new(),
            expected_statuses: Vec::new(),
            required_body_markers: Vec::new(),
            required_headers: Vec::new(),
            follow_redirects: false,
            sample_per_cidr: 100,
            probes: 8,
            concurrency: 120,
            timeout_ms: 2500,
            connect_timeout_ms: 1000,
            top: 50,
            seed: 0,
            download_path: default_download_path(),
            upload_path: default_upload_path(),
            speed_payload_bytes: default_speed_payload_bytes(),
            speed_repetitions: default_speed_repetitions(),
            speed_timeout_ms: default_speed_timeout_ms(),
            warmup: default_warmup(),
            stability_weight: default_stability_weight(),
            loss_weight: default_loss_weight(),
            early_stop: default_early_stop(),
            early_stop_loss_streak: default_early_stop_loss_streak(),
            early_stop_min_samples: default_early_stop_min_samples(),
            early_stop_success_floor: default_early_stop_success_floor(),
            early_stop_prune: default_early_stop_prune(),
            early_stop_prune_margin: default_early_stop_prune_margin(),
            two_phase: default_two_phase(),
            discover_fraction: default_discover_fraction(),
            two_phase_focus_cidrs: 0,
            adaptive_probing: false,
            min_probes: default_min_probes(),
            max_probes: default_max_probes(),
            confidence: default_confidence(),
            custom_cidrs: Vec::new(),
            selected_cidrs: crate::scanner::DEFAULT_CLOUDFLARE_CIDRS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            selected_cidrs_persisted: false,
        }
    }
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|mut p| {
        p.push("cleanscan");
        p.push("config.json");
        p
    })
}

pub fn append_history(record: &serde_json::Value) -> Result<()> {
    let mut path = config_path().unwrap_or_else(|| PathBuf::from("."));
    path.pop();
    path.push("history");
    fs::create_dir_all(&path)?;
    path.push(format!("runs-{}.jsonl", chrono_like_date()));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, record)?;
    writeln!(file)?;
    Ok(())
}

fn chrono_like_date() -> String {
    // Keep the history filename dependency-free and lexically sortable.
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    format!("day-{days}")
}

pub fn load_config() -> AppConfig {
    if let Some(path) = config_path() {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Some(config) = parse_config(&content) {
                    return config;
                }
            }
        }
    }
    AppConfig::default()
}

fn parse_config(content: &str) -> Option<AppConfig> {
    let mut config = serde_json::from_str::<AppConfig>(content).ok()?;
    config.selected_cidrs_persisted = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|value| value.get("selected_cidrs").cloned())
        .is_some();
    Some(config)
}

pub fn save_config(config: &AppConfig) -> Result<()> {
    if let Some(path) = config_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(config)?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.json");
        let mut temp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
        let mut suffix = 0u64;
        let mut temp = loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break file,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    suffix += 1;
                    temp_path =
                        parent.join(format!(".{file_name}.tmp-{}-{suffix}", std::process::id()));
                }
                Err(e) => return Err(e.into()),
            }
        };

        let result = (|| -> Result<()> {
            temp.write_all(content.as_bytes())?;
            temp.sync_all()?;
            drop(temp);
            fs::rename(&temp_path, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_config, parse_required_header, AppConfig};

    #[test]
    fn required_header_parser_validates_names_and_values() {
        assert_eq!(
            parse_required_header(" content-type = text/plain ").unwrap(),
            ("content-type".to_string(), "text/plain".to_string())
        );
        assert_eq!(
            parse_required_header("x-token=a=b=c").unwrap(),
            ("x-token".to_string(), "a=b=c".to_string())
        );
        assert!(parse_required_header("=value").is_err());
        assert!(parse_required_header("name=").is_err());
        assert!(parse_required_header("=").is_err());
        assert!(parse_required_header("bad header=value").is_err());
    }

    #[test]
    fn selected_cidrs_distinguishes_missing_from_explicit_empty() {
        let missing: AppConfig = parse_config(
            r#"{"host":"example.test","path":"/","sample_per_cidr":1,"probes":1,"concurrency":1,"timeout_ms":1,"connect_timeout_ms":1,"top":1,"custom_cidrs":[]}"#,
        )
        .unwrap();
        assert!(missing.selected_cidrs.is_empty());
        assert!(!missing.selected_cidrs_persisted);

        let explicit: AppConfig = parse_config(
            r#"{"host":"example.test","path":"/","sample_per_cidr":1,"probes":1,"concurrency":1,"timeout_ms":1,"connect_timeout_ms":1,"top":1,"custom_cidrs":[],"selected_cidrs":[]}"#,
        )
        .unwrap();
        assert!(explicit.selected_cidrs.is_empty());
        assert!(explicit.selected_cidrs_persisted);
    }
}
