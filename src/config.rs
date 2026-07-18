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
    #[serde(default = "default_download_path")]
    pub download_path: String,
    #[serde(default = "default_upload_path")]
    pub upload_path: String,
    #[serde(default = "default_speed_payload_bytes")]
    pub speed_payload_bytes: u64,
    #[serde(default = "default_speed_repetitions")]
    pub speed_repetitions: usize,
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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: "app.iplat.ir".to_string(),
            path: "/cdn-cgi/trace".to_string(),
            sample_per_cidr: 100,
            probes: 8,
            concurrency: 120,
            timeout_ms: 2500,
            connect_timeout_ms: 1000,
            top: 50,
            download_path: default_download_path(),
            upload_path: default_upload_path(),
            speed_payload_bytes: default_speed_payload_bytes(),
            speed_repetitions: default_speed_repetitions(),
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
