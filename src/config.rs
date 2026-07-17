use std::fs;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use anyhow::Result;

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
    pub custom_cidrs: Vec<String>,
    pub selected_cidrs: Vec<String>,
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
            custom_cidrs: Vec::new(),
            selected_cidrs: crate::scanner::DEFAULT_CLOUDFLARE_CIDRS
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
                if let Ok(config) = serde_json::from_str::<AppConfig>(&content) {
                    return config;
                }
            }
        }
    }
    AppConfig::default()
}

pub fn save_config(config: &AppConfig) -> Result<()> {
    if let Some(path) = config_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let content = serde_json::to_string_pretty(config)?;
        fs::write(path, content)?;
    }
    Ok(())
}
