use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use futures::stream;
use reqwest::{Client, StatusCode};
use tokio::{sync::Semaphore, task::JoinSet};

use crate::config::AppConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedDirection {
    Download,
    Upload,
    Both,
}

impl SpeedDirection {
    pub fn includes_download(self) -> bool {
        matches!(self, Self::Download | Self::Both)
    }

    pub fn includes_upload(self) -> bool {
        matches!(self, Self::Upload | Self::Both)
    }
}

#[derive(Debug, Clone)]
pub struct SpeedMeasurement {
    pub bytes: u64,
    pub seconds: f64,
    pub bytes_per_second: f64,
}

#[derive(Debug, Clone)]
pub struct SpeedResult {
    pub ip: String,
    pub download: Option<SpeedMeasurement>,
    pub upload: Option<SpeedMeasurement>,
    pub error: Option<String>,
}

fn client_for_ip(host: &str, ip: &str, args: &AppConfig) -> Result<Client> {
    let ip_addr = IpAddr::from_str(ip)?;
    let socket = SocketAddr::new(ip_addr, 443);
    let resolve_host = host
        .strip_prefix('[')
        .and_then(|host| host.split_once(']').map(|(name, _)| name))
        .or_else(|| {
            host.rsplit_once(':').and_then(|(name, port)| {
                if port.parse::<u16>().is_ok() {
                    Some(name)
                } else {
                    None
                }
            })
        })
        .unwrap_or(host);
    Ok(reqwest::Client::builder()
        .http2_adaptive_window(true)
        .pool_max_idle_per_host(0)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(resolve_host, &[socket])
        .connect_timeout(Duration::from_millis(args.connect_timeout_ms))
        .timeout(Duration::from_millis(args.speed_timeout_ms))
        .build()?)
}

async fn download_once(
    client: &Client,
    url: &str,
    expected_bytes: u64,
) -> Result<SpeedMeasurement> {
    let start = Instant::now();
    let response = client.get(url).header("accept", "*/*").send().await?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!("download returned HTTP {}", response.status()));
    }

    let mut response = response;
    let mut bytes = 0u64;
    while let Some(chunk) = response.chunk().await? {
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes >= expected_bytes {
            break;
        }
    }
    if bytes < expected_bytes {
        return Err(anyhow!(
            "download ended after {} of {} bytes",
            bytes,
            expected_bytes
        ));
    }
    let seconds = start.elapsed().as_secs_f64().max(f64::EPSILON);
    Ok(SpeedMeasurement {
        bytes: expected_bytes,
        seconds,
        bytes_per_second: expected_bytes as f64 / seconds,
    })
}

async fn upload_once(client: &Client, url: &str, payload_bytes: u64) -> Result<SpeedMeasurement> {
    const CHUNK_SIZE: usize = 64 * 1024;
    let chunks = (payload_bytes as usize).div_ceil(CHUNK_SIZE);
    let stream = stream::iter((0..chunks).map(move |index| {
        let remaining = payload_bytes.saturating_sub(index as u64 * CHUNK_SIZE as u64);
        let size = remaining.min(CHUNK_SIZE as u64) as usize;
        Ok::<Vec<u8>, std::io::Error>(vec![0u8; size])
    }));

    let start = Instant::now();
    let response = client
        .post(url)
        .header("content-type", "application/octet-stream")
        .header("content-length", payload_bytes)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("upload returned HTTP {}", response.status()));
    }

    let seconds = start.elapsed().as_secs_f64().max(f64::EPSILON);
    Ok(SpeedMeasurement {
        bytes: payload_bytes,
        seconds,
        bytes_per_second: payload_bytes as f64 / seconds,
    })
}

fn average_measurements(values: Vec<SpeedMeasurement>) -> Option<SpeedMeasurement> {
    if values.is_empty() {
        return None;
    }
    let bytes = values.iter().map(|v| v.bytes).sum::<u64>() / values.len() as u64;
    let seconds = values.iter().map(|v| v.seconds).sum::<f64>() / values.len() as f64;
    let bytes_per_second =
        values.iter().map(|v| v.bytes_per_second).sum::<f64>() / values.len() as f64;
    Some(SpeedMeasurement {
        bytes,
        seconds,
        bytes_per_second,
    })
}

async fn test_target(ip: String, args: Arc<AppConfig>, direction: SpeedDirection) -> SpeedResult {
    let client = match client_for_ip(&args.host, &ip, &args) {
        Ok(client) => client,
        Err(error) => {
            return SpeedResult {
                ip,
                download: None,
                upload: None,
                error: Some(error.to_string()),
            }
        }
    };
    let download_url = format!("https://{}{}", args.host, args.download_path);
    let upload_url = format!("https://{}{}", args.host, args.upload_path);
    let repetitions = args.speed_repetitions.max(1);
    let mut downloads = Vec::new();
    let mut uploads = Vec::new();
    let mut errors = Vec::new();

    for _ in 0..repetitions {
        if direction.includes_download() {
            match download_once(&client, &download_url, args.speed_payload_bytes).await {
                Ok(value) => downloads.push(value),
                Err(error) => errors.push(format!("download: {error}")),
            }
        }
        if direction.includes_upload() {
            match upload_once(&client, &upload_url, args.speed_payload_bytes).await {
                Ok(value) => uploads.push(value),
                Err(error) => errors.push(format!("upload: {error}")),
            }
        }
    }

    SpeedResult {
        ip,
        download: average_measurements(downloads),
        upload: average_measurements(uploads),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

pub async fn run_speed_scan(
    targets: Vec<String>,
    args: Arc<AppConfig>,
    direction: SpeedDirection,
    tx: std::sync::mpsc::Sender<SpeedResult>,
    cancel: Arc<AtomicBool>,
) {
    let concurrency = args.concurrency.clamp(1, 4);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();
    let mut cancellation = Box::pin(async {
        while !cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });

    for ip in targets {
        while tasks.len() >= concurrency {
            tokio::select! {
                biased;
                _ = &mut cancellation => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return;
                }
                result = tasks.join_next() => {
                    if let Some(Ok(result)) = result {
                        let _ = tx.send(result);
                    }
                }
            }
        }
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let permit = semaphore.clone().acquire_owned().await;
        let Ok(permit) = permit else { break };
        let args = args.clone();
        tasks.spawn(async move {
            let _permit = permit;
            test_target(ip, args, direction).await
        });
    }

    loop {
        tokio::select! {
            biased;
            _ = &mut cancellation => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return;
            }
            result = tasks.join_next() => {
                let Some(result) = result else { break };
                if let Ok(result) = result {
                    let _ = tx.send(result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{average_measurements, SpeedMeasurement};

    #[test]
    fn averages_repeated_measurements() {
        let result = average_measurements(vec![
            SpeedMeasurement {
                bytes: 100,
                seconds: 1.0,
                bytes_per_second: 100.0,
            },
            SpeedMeasurement {
                bytes: 100,
                seconds: 2.0,
                bytes_per_second: 50.0,
            },
        ])
        .unwrap();
        assert_eq!(result.bytes, 100);
        assert_eq!(result.seconds, 1.5);
        assert_eq!(result.bytes_per_second, 75.0);
    }
}
