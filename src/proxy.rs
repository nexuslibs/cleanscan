use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use rustls::{pki_types::ServerName, ClientConfig};
use rustls_platform_verifier::ConfigVerifierExt;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyTransport {
    pub protocol: String,
    pub network: String,
    pub address: String,
    pub port: u16,
    pub sni: String,
    pub host: Option<String>,
    pub path: Option<String>,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SurvivabilityResult {
    pub ip: String,
    pub port: u16,
    pub network: String,
    pub tcp_ok: bool,
    pub tls_ok: bool,
    pub long_tls_ok: bool,
    pub websocket_reached: Option<bool>,
    pub websocket_accepted: Option<bool>,
    pub elapsed_ms: f64,
    pub error: Option<String>,
}

pub fn parse_share_url(raw: &str) -> Result<ProxyTransport> {
    let url = Url::parse(raw.trim()).map_err(|e| anyhow!("invalid proxy URL: {e}"))?;
    let protocol = match url.scheme() {
        "vless" | "trojan" => url.scheme().to_string(),
        other => return Err(anyhow!("unsupported proxy URL scheme: {other}")),
    };
    let address = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy URL has no address"))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let query = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let network = query
        .get("type")
        .map_or("tcp", |v| v.as_ref())
        .to_ascii_lowercase();
    let tls = query
        .get("security")
        .map_or(protocol == "trojan", |v| v != "none");
    if network == "ws" && !tls {
        return Err(anyhow!(
            "non-TLS WebSocket proxy transports are unsupported"
        ));
    }
    let sni = query
        .get("sni")
        .map_or_else(|| address.clone(), |v| v.to_string());
    let host = query
        .get("host")
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty());
    let path = query
        .get("path")
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty());
    Ok(ProxyTransport {
        protocol,
        network,
        address,
        port,
        sni,
        host,
        path,
        tls,
    })
}

fn tls_config() -> Result<TlsConnector> {
    static CONNECTOR: OnceLock<std::result::Result<TlsConnector, String>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            ClientConfig::with_platform_verifier()
                .map(|config| TlsConnector::from(Arc::new(config)))
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(|error| anyhow!(error))
}

async fn tls_connect(stream: TcpStream, sni: &str) -> Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(sni.to_string()).map_err(|_| anyhow!("invalid TLS SNI"))?;
    Ok(tls_config()?.connect(name, stream).await?)
}

pub async fn check_candidate(
    transport: &ProxyTransport,
    ip: &str,
    timeout_ms: u64,
) -> SurvivabilityResult {
    let started = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms.max(500));
    let addr = match ip.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, transport.port),
        Err(e) => return failed(ip, transport, started, format!("invalid candidate IP: {e}")),
    };
    let stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return failed(ip, transport, started, format!("TCP connect: {e}")),
        Err(_) => return failed(ip, transport, started, "TCP connect timed out".into()),
    };
    let mut result = SurvivabilityResult {
        ip: ip.into(),
        port: transport.port,
        network: transport.network.clone(),
        tcp_ok: true,
        tls_ok: !transport.tls,
        long_tls_ok: false,
        websocket_reached: None,
        websocket_accepted: None,
        elapsed_ms: 0.0,
        error: None,
    };
    if transport.tls {
        match timeout(timeout_duration, tls_connect(stream, &transport.sni)).await {
            Ok(Ok(mut tls)) => {
                result.tls_ok = true;
                result.long_tls_ok = idle_hold(&mut tls, timeout_duration).await;
                if transport.network == "ws" {
                    let (reached, accepted) =
                        websocket_probe(&mut tls, transport, timeout_duration).await;
                    result.websocket_reached = Some(reached);
                    result.websocket_accepted = Some(accepted);
                }
            }
            Ok(Err(e)) => result.error = Some(format!("TLS handshake: {e}")),
            Err(_) => result.error = Some("TLS handshake timed out".into()),
        }
    }
    result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    if transport.tls && result.error.is_none() && !result.long_tls_ok {
        result.error = Some("long-lived TLS connection did not survive idle hold".into());
    }
    result
}

async fn idle_hold(stream: &mut TlsStream<TcpStream>, duration: Duration) -> bool {
    let mut byte = [0u8; 1];
    match timeout(duration.min(Duration::from_secs(2)), stream.read(&mut byte)).await {
        Err(_) => true,
        Ok(Ok(0)) | Ok(Err(_)) => false,
        Ok(Ok(_)) => true,
    }
}

async fn websocket_probe(
    stream: &mut TlsStream<TcpStream>,
    transport: &ProxyTransport,
    duration: Duration,
) -> (bool, bool) {
    let host = transport.host.as_deref().unwrap_or(&transport.sni);
    let path = transport.path.as_deref().unwrap_or("/");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: Y2xlYW5zY2Fu\r\nSec-WebSocket-Version: 13\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return (false, false);
    }
    let mut response = [0u8; 1024];
    let Ok(Ok(size)) = timeout(duration, stream.read(&mut response)).await else {
        return (false, false);
    };
    if size == 0 {
        return (false, false);
    }
    let text = String::from_utf8_lossy(&response[..size]);
    let reached = text.starts_with("HTTP/");
    (
        reached,
        reached
            && text
                .lines()
                .next()
                .is_some_and(|line| line.contains(" 101 ")),
    )
}

fn failed(
    ip: &str,
    transport: &ProxyTransport,
    started: Instant,
    error: String,
) -> SurvivabilityResult {
    SurvivabilityResult {
        ip: ip.into(),
        port: transport.port,
        network: transport.network.clone(),
        tcp_ok: false,
        tls_ok: false,
        long_tls_ok: false,
        websocket_reached: None,
        websocket_accepted: None,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_share_url;

    #[test]
    fn parses_vless_websocket_transport_without_exposing_credentials() {
        let config = parse_share_url(
            "vless://secret@example.com:2053?type=ws&security=tls&sni=edge.example&host=cdn.example&path=%2Fws",
        )
        .unwrap();
        assert_eq!(config.protocol, "vless");
        assert_eq!(config.port, 2053);
        assert_eq!(config.sni, "edge.example");
        assert_eq!(config.host.as_deref(), Some("cdn.example"));
        assert_eq!(config.path.as_deref(), Some("/ws"));
        assert!(!serde_json::to_string(&config).unwrap().contains("secret"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_share_url("ss://example.com").is_err());
    }
}
