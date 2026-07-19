use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs, io::Write};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub path: String,
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
    /// current best score cannot beat the worst of that set by the margin.
    #[serde(default = "default_early_stop_prune")]
    pub early_stop_prune: bool,
    /// How much better (as a fraction) a target's score must be versus the
    /// current worst top-N candidate to keep probing it under the prune rule.
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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: "/cdn-cgi/trace".to_string(),
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
    use super::{parse_config, AppConfig};

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
