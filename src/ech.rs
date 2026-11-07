//! ECH (Encrypted Client Hello) config fetch + parse for the proxy/TLS-check
//! path. The ECH config for Cloudflare is fetched from the `cloudflare-ech.com`
//! HTTPS DNS record over DNS-over-HTTPS, parsed into the raw
//! `EchConfigList` bytes rustls expects, and cached for the process lifetime.
//!
//! Fail-closed: when `--ech` is on and no config can be obtained (fetch
//! failure, missing `ech` parameter, or a build without an HPKE-capable
//! provider), callers must refuse cleartext SNI instead of falling back.
//!
//! Live ECH handshakes additionally need an HPKE provider (aws-lc-rs), so
//! `with_ech` construction is behind the opt-in `ech` cargo feature; the
//! default build stays ring-only. Fetch/parse/cache work in every build.

use std::net::{IpAddr, SocketAddr};

/// DoH endpoint serving the Cloudflare ECH config (queried by name so the
/// request itself is a normal TLS connection to Cloudflare's DNS).
pub const ECH_DOH_URL: &str =
    "https://cloudflare-dns.com/dns-query?name=cloudflare-ech.com&type=HTTPS";

type EchCache = std::sync::Mutex<Option<(Vec<u8>, std::time::Instant)>>;
/// In-process cache: fetched once, then reused while the DNS TTL says it is
/// still valid; refreshed after expiry.
static ECH_CACHE: std::sync::OnceLock<EchCache> = std::sync::OnceLock::new();

/// Base64 (standard alphabet, padding required on input) decode for the
/// `ech=` parameter bytes. Hand-rolled so no new dependency is needed.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    /// 6-bit value of a single base64 alphabet byte, erroring on invalid input.
    fn value_of(byte: u8) -> Result<u32, String> {
        match byte {
            b'A'..=b'Z' => Ok((byte - b'A') as u32),
            b'a'..=b'z' => Ok((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((byte - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte {byte:?}")),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let padding = chunk.iter().filter(|&&b| b == b'=').count();
        if padding > 2 {
            return Err("base64 padding exceeds 2".to_string());
        }
        let mut acc = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            if i >= 4 - padding {
                if byte != b'=' {
                    return Err("base64 padding must be trailing".to_string());
                }
                acc <<= 6;
            } else {
                acc = (acc << 6) | value_of(byte)?;
            }
        }
        out.push((acc >> 16) as u8);
        if padding < 2 {
            out.push((acc >> 8) as u8);
        }
        if padding < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

/// Extract the raw `EchConfigList` bytes from a DNS-over-HTTPS JSON response
/// (dns-json format) for the `cloudflare-ech.com` HTTPS record. Bytes only;
/// use [`parse_ech_config_list_with_ttl`] to also get the answer TTL.
#[allow(dead_code)]
pub fn parse_ech_config_list(json: &str) -> Result<Vec<u8>, String> {
    parse_ech_config_list_with_ttl(json).map(|(bytes, _)| bytes)
}

/// Extract the raw `EchConfigList` bytes plus the DNS TTL (seconds) of the
/// HTTPS answer, so the cache knows when to refresh.
pub fn parse_ech_config_list_with_ttl(json: &str) -> Result<(Vec<u8>, Option<u64>), String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid DoH JSON: {e}"))?;
    let answers = value
        .get("Answer")
        .and_then(|a| a.as_array())
        .ok_or_else(|| "DoH response has no Answer array".to_string())?;
    for answer in answers {
        // Type 65 = HTTPS record.
        if answer.get("type").and_then(|t| t.as_u64()) != Some(65) {
            continue;
        }
        // Only records carrying an `ech=` parameter count; the TTL that
        // bounds the cache comes from the same answer.
        let ttl = answer.get("TTL").and_then(|t| t.as_u64());
        let Some(data) = answer.get("data").and_then(|d| d.as_str()) else {
            continue;
        };
        // Presentation format: `priority target key=value ...`; the ech value
        // may be quoted and ends at whitespace or the closing quote.
        for token in data.split_whitespace() {
            let Some(value) = token
                .strip_prefix("ech=")
                .or_else(|| token.strip_prefix("\"ech="))
            else {
                continue;
            };
            let value = value.trim_end_matches('"');
            if value.is_empty() {
                continue;
            }
            return base64_decode(value)
                .map(|bytes| (bytes, ttl))
                .map_err(|e| format!("invalid ech= parameter: {e}"));
        }
    }
    Err("no ech parameter in any HTTPS record".to_string())
}

/// Fetch (once, then cached) the raw `EchConfigList` bytes for Cloudflare.
/// Returns `None` on any failure — callers in ECH mode must treat that as
/// a hard error (fail-closed), never as "fall back to cleartext".
pub async fn ech_config_list(interface: Option<crate::iface::InterfaceAddrs>) -> Option<Vec<u8>> {
    let cache = ECH_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Some((cached, expires)) = cache.lock().ok().and_then(|guard| guard.clone()) {
        if std::time::Instant::now() < expires {
            return Some(cached);
        }
    }
    let (fetched, ttl_secs) = fetch_ech_config_list(interface).await?;
    // Refresh-after-expiry fallback TTL when the answer carries none.
    let ttl = std::time::Duration::from_secs(ttl_secs.unwrap_or(300));
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((fetched.clone(), std::time::Instant::now() + ttl));
    }
    Some(fetched)
}

/// Pick the pinned-interface local address to bind the DoH request to,
/// matching the address family of the first resolved DoH address. `None`
/// (no pin, or no family match) lets the OS route.
fn doh_local_addr(
    interface: Option<crate::iface::InterfaceAddrs>,
    resolved: &[SocketAddr],
) -> Option<IpAddr> {
    let addrs = interface?;
    let first = resolved.first()?;
    addrs.pick(first.is_ipv4())
}

/// Uncached DoH fetch of the Cloudflare ECH config list; `None` on any
/// transport, HTTP, or parse failure so callers stay fail-closed.
/// Follows the same interface pin as the ECH-enabled checks (`--interface`)
/// via `local_address` (SO_MARK is not applicable here: reqwest has no
/// connector hook for it, the same limitation as the scanner probes).
async fn fetch_ech_config_list(
    interface: Option<crate::iface::InterfaceAddrs>,
) -> Option<(Vec<u8>, Option<u64>)> {
    let mut builder = reqwest::ClientBuilder::new()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5));
    // Resolve first so the pin uses the DoH host's address family.
    if interface.is_some() {
        if let Ok(resolved) = tokio::net::lookup_host(("cloudflare-dns.com", 443)).await {
            let resolved: Vec<SocketAddr> = resolved.collect();
            if let Some(local) = doh_local_addr(interface, &resolved) {
                builder = builder.local_address(local);
            }
        }
    }
    let client = crate::proxy::apply_rustls_backend(builder, crate::proxy::TlsFingerprint::Default)
        .build()
        .ok()?;
    let response = client
        .get(ECH_DOH_URL)
        .header("accept", "application/dns-json")
        .send()
        .await
        .ok()?;
    let text = response.text().await.ok()?;
    parse_ech_config_list_with_ttl(&text).ok()
}

/// Whether this build can actually perform ECH handshakes (an HPKE-capable
/// provider is compiled in). Without it, `--ech` must fail closed with an
/// explanatory error instead of silently sending cleartext SNI.
pub fn ech_handshake_supported() -> bool {
    cfg!(feature = "ech")
}

/// Fail-closed guard for ECH mode: when `ech` is requested, returns the
/// config list or an error message explaining why cleartext is refused.
/// When `ech` is off, always `Ok(None)`. `interface` pins ECH discovery
/// to the same egress as the checks being guarded.
pub async fn require_ech_config(
    ech: bool,
    interface: Option<crate::iface::InterfaceAddrs>,
) -> Result<Option<Vec<u8>>, String> {
    if !ech {
        return Ok(None);
    }
    if !ech_handshake_supported() {
        return Err(
            "ECH requested but this build has no HPKE provider (needs --features ech); refusing cleartext SNI"
                .to_string(),
        );
    }
    match ech_config_list(interface).await {
        Some(list) => Ok(Some(list)),
        None => Err("ECH config fetch failed; refusing cleartext SNI".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{doh_local_addr, parse_ech_config_list};
    use crate::iface::InterfaceAddrs;
    use std::net::{IpAddr, SocketAddr};

    const SAMPLE: &str = r#"{
        "Status": 0,
        "Answer": [
            {"name": "cloudflare-ech.com.", "type": 65, "TTL": 300,
             "data": "1 . alpn=\"h2,h3\" ech=RUNIQ09ORklHTElTVEJZVEVT ipv4hint=1.1.1.1"}
        ]
    }"#;

    #[test]
    fn parses_ech_list_from_doh_https_record() {
        let bytes = parse_ech_config_list(SAMPLE).unwrap();
        assert_eq!(&bytes[..], b"ECHCONFIGLISTBYTES");
    }

    #[test]
    fn rejects_missing_answer_missing_ech_and_garbage() {
        assert!(parse_ech_config_list(r#"{"Status":0}"#).is_err());
        assert!(parse_ech_config_list(r#"{"Answer":[]}"#).is_err());
        assert!(
            parse_ech_config_list(r#"{"Answer":[{"type":65,"data":"1 . alpn=\"h2\""}]}"#).is_err()
        );
        assert!(parse_ech_config_list("not json").is_err());
        assert!(parse_ech_config_list("").is_err());
    }

    #[test]
    fn doh_pin_matches_first_resolved_family() {
        let v4: SocketAddr = "104.16.0.1:443".parse().unwrap();
        let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let pinned = InterfaceAddrs {
            ipv4: Some("192.168.1.5".parse().unwrap()),
            ipv6: Some("fd00::5".parse().unwrap()),
        };
        assert_eq!(
            doh_local_addr(Some(pinned), &[v4]),
            Some("192.168.1.5".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            doh_local_addr(Some(pinned), &[v6]),
            Some("fd00::5".parse::<IpAddr>().unwrap())
        );
        // v6-only resolution with a v4-only pin: no pin (OS routes).
        let v4_only = InterfaceAddrs {
            ipv4: Some("192.168.1.5".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(doh_local_addr(Some(v4_only), &[v6]), None);
        assert_eq!(doh_local_addr(None, &[v4]), None);
        assert_eq!(doh_local_addr(Some(pinned), &[]), None);
    }

    #[test]
    fn extracts_ech_param_from_quoted_and_padded_forms() {
        let quoted = r#"{"Answer":[{"type":65,"data":"1 . \"ech=RUNJ\""}]}"#;
        assert_eq!(parse_ech_config_list(quoted).unwrap(), b"ECI");
        let second =
            r#"{"Answer":[{"type":1,"data":"1.1.1.1"},{"type":65,"data":"1 . ech=RUNJIQ=="}]}"#;
        assert_eq!(parse_ech_config_list(second).unwrap(), b"ECI!");
    }
}
