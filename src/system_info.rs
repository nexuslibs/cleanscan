use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Default)]
pub struct SystemNetworkInfo {
    pub public_ip: Option<String>,
    pub asn: Option<String>,
    pub isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: bool,
    ip: Option<String>,
    connection: Option<IpWhoConnection>,
}

#[derive(Debug, Deserialize)]
struct IpWhoConnection {
    asn: Option<u64>,
    isp: Option<String>,
    org: Option<String>,
}

pub fn lookup_sync() -> SystemNetworkInfo {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return SystemNetworkInfo::default();
    };
    runtime.block_on(lookup())
}

async fn lookup() -> SystemNetworkInfo {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(_) => return SystemNetworkInfo::default(),
    };

    let Ok(response) = client.get("https://ipwho.is/").send().await else {
        return SystemNetworkInfo::default();
    };
    let Ok(data) = response.json::<IpWhoResponse>().await else {
        return SystemNetworkInfo::default();
    };
    if !data.success {
        return SystemNetworkInfo::default();
    }
    let Some(connection) = data.connection else {
        return SystemNetworkInfo {
            public_ip: data.ip,
            ..SystemNetworkInfo::default()
        };
    };
    SystemNetworkInfo {
        public_ip: data.ip,
        asn: connection.asn.map(|asn| format!("AS{asn}")),
        isp: connection.isp.or(connection.org),
    }
}

impl SystemNetworkInfo {
    pub fn public_ip_display(&self) -> &str {
        self.public_ip.as_deref().unwrap_or("—")
    }

    pub fn asn_display(&self) -> &str {
        self.asn.as_deref().unwrap_or("—")
    }

    pub fn isp_display(&self) -> &str {
        self.isp.as_deref().unwrap_or("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::SystemNetworkInfo;

    #[test]
    fn missing_metadata_has_safe_display_values() {
        let info = SystemNetworkInfo::default();
        assert_eq!(info.public_ip_display(), "—");
        assert_eq!(info.asn_display(), "—");
        assert_eq!(info.isp_display(), "unknown");
    }
}
