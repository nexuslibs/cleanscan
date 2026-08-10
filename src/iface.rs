//! Network interface enumeration and address resolution.
//!
//! Probes normally let the OS pick the route ("auto"). When the user pins an
//! interface, outbound connections are bound to an address owned by that
//! interface so the whole test — discovery sweeps, HTTP probes, and speed
//! tests — leaves through the chosen link.

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A network interface with every address currently assigned to it.
#[derive(Debug, Clone, Default)]
pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

/// The usable IPv4 and IPv6 addresses of a pinned interface, resolved once.
/// Each family prefers an off-link-capable address (not loopback, not
/// link-local), falling back to the first address of the family.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceAddrs {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl InterfaceAddrs {
    /// Address of the requested family, if the pinned interface has one.
    pub fn pick(&self, want_ipv4: bool) -> Option<IpAddr> {
        if want_ipv4 {
            self.ipv4.map(IpAddr::V4)
        } else {
            self.ipv6.map(IpAddr::V6)
        }
    }
}

/// List all network interfaces, grouped by name and sorted by name.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mut grouped: Vec<InterfaceInfo> = Vec::new();
    for entry in if_addrs::get_if_addrs()? {
        let index = grouped
            .iter()
            .position(|group| group.name == entry.name)
            .unwrap_or_else(|| {
                grouped.push(InterfaceInfo {
                    name: entry.name.clone(),
                    addresses: Vec::new(),
                });
                grouped.len() - 1
            });
        grouped[index].addresses.push(entry.addr.ip());
    }
    grouped.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(grouped)
}

/// Resolve the addresses of a named interface. Errors when the interface does
/// not exist, listing the available ones so the message is actionable.
pub fn interface_addrs(name: &str) -> Result<InterfaceAddrs> {
    let interfaces = list_interfaces()?;
    let entry = interfaces
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| {
            anyhow!(
                "interface {name:?} not found; available: {}",
                interfaces
                    .iter()
                    .map(|entry| entry.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let (ipv4, ipv6) = preferred_addresses(&entry.addresses);
    Ok(InterfaceAddrs { ipv4, ipv6 })
}

/// Pick the best address of each family for off-link traffic. Loopback and
/// link-local addresses cannot reach remote hosts, so any other address of
/// the family wins; fall back to the first address of the family.
fn preferred_addresses(addresses: &[IpAddr]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for addr in addresses {
        match addr {
            IpAddr::V4(ip) if ipv4.is_none() && is_off_link_capable(addr) => ipv4 = Some(*ip),
            IpAddr::V6(ip) if ipv6.is_none() && is_off_link_capable(addr) => ipv6 = Some(*ip),
            _ => {}
        }
    }
    for addr in addresses {
        match addr {
            IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(*ip),
            IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(*ip),
            _ => {}
        }
    }
    (ipv4, ipv6)
}

fn is_off_link_capable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unicast_link_local(),
    }
}

/// Normalize a user-supplied interface value: empty, `auto`, or `default`
/// mean "let the OS route" (`None`); anything else is a pinned interface
/// name. Keeps the CLI (`--interface auto`) and the TUI editor in sync.
pub fn normalize_interface(name: Option<String>) -> Option<String> {
    let trimmed = name.as_deref().map(str::trim).unwrap_or("");
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("auto")
        || trimmed.eq_ignore_ascii_case("default")
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Error when the pinned interface lacks an address of a family used by any
/// target, so the user learns up front instead of through per-probe errors.
pub fn validate_target_families<'a>(
    name: &str,
    addrs: &InterfaceAddrs,
    targets: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut ipv4_used = false;
    let mut ipv6_used = false;
    for target in targets {
        match target.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => ipv4_used = true,
            Ok(IpAddr::V6(_)) => ipv6_used = true,
            Err(_) => {}
        }
    }
    if ipv4_used && addrs.ipv4.is_none() {
        return Err(anyhow!(
            "interface {name:?} has no IPv4 address; IPv4 targets cannot be routed through it"
        ));
    }
    if ipv6_used && addrs.ipv6.is_none() {
        return Err(anyhow!(
            "interface {name:?} has no IPv6 address; IPv6 targets cannot be routed through it"
        ));
    }
    Ok(())
}

/// Validate that `name` is a currently existing interface. The error lists the
/// available interfaces so callers (CLI validation, the TUI picker) can show
/// an actionable message.
pub fn validate_interface(name: &str) -> Result<()> {
    let interfaces = list_interfaces()?;
    if interfaces.iter().any(|entry| entry.name == name) {
        Ok(())
    } else {
        Err(anyhow!(
            "interface {name:?} not found; available: {}",
            interfaces
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Connect to `addr`, optionally binding the local address of the pinned
/// interface first so the connection egresses through that interface.
pub async fn bind_connect(
    addr: SocketAddr,
    interface: Option<InterfaceAddrs>,
) -> std::io::Result<tokio::net::TcpStream> {
    let Some(local) = interface.and_then(|addrs| addrs.pick(addr.is_ipv4())) else {
        return tokio::net::TcpStream::connect(addr).await;
    };
    let socket = if local.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.bind(SocketAddr::new(local, 0))?;
    socket.connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_name() -> String {
        list_interfaces()
            .unwrap()
            .into_iter()
            .find(|entry| entry.addresses.iter().any(IpAddr::is_loopback))
            .map(|entry| entry.name)
            .expect("every platform has a loopback interface")
    }

    #[test]
    fn list_interfaces_includes_loopback_with_addresses() {
        let interfaces = list_interfaces().unwrap();
        assert!(
            interfaces
                .iter()
                .any(|entry| entry.addresses.iter().any(|addr| addr.is_loopback())),
            "expected a loopback interface among {interfaces:?}"
        );
        assert!(
            interfaces
                .iter()
                .any(|entry| entry.addresses.iter().any(|addr| addr.is_ipv4())),
            "expected at least one IPv4 address among {interfaces:?}"
        );
    }

    #[test]
    fn interface_addrs_resolves_families_and_require_errors_on_missing_family() {
        let name = loopback_name();
        let addrs = interface_addrs(&name).unwrap();
        assert!(addrs.ipv4.is_some(), "loopback should have 127.0.0.1");
        assert!(addrs.pick(true).unwrap().is_ipv4());
        assert!(addrs.pick(false).is_none() || addrs.pick(false).unwrap().is_ipv6());
    }

    #[test]
    fn preferred_addresses_skip_loopback_and_link_local() {
        let fe80: IpAddr = "fe80::1".parse().unwrap();
        let global: IpAddr = "2606:4700::1".parse().unwrap();
        let link_local_v4: IpAddr = "169.254.1.1".parse().unwrap();
        let usable_v4: IpAddr = "192.168.1.5".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();

        let (ipv4, ipv6) = preferred_addresses(&[fe80, global]);
        assert_eq!(ipv4, None);
        assert_eq!(ipv6.map(IpAddr::V6), Some(global));

        let (ipv4, ipv6) = preferred_addresses(&[link_local_v4, usable_v4]);
        assert_eq!(ipv4.map(IpAddr::V4), Some(usable_v4));
        assert_eq!(ipv6, None);

        let (ipv4, ipv6) = preferred_addresses(&[fe80]);
        assert_eq!(ipv4, None);
        assert_eq!(
            ipv6.map(IpAddr::V6),
            Some(fe80),
            "link-local must still win when it is the only address of the family"
        );

        let (ipv4, ipv6) = preferred_addresses(&[loopback]);
        assert_eq!(ipv4.map(IpAddr::V4), Some(loopback));
        assert_eq!(ipv6, None);

        let (ipv4, ipv6) = preferred_addresses(&[]);
        assert_eq!((ipv4, ipv6), (None, None));
    }

    #[test]
    fn normalize_interface_maps_auto_default_and_empty_to_none() {
        assert_eq!(normalize_interface(None), None);
        assert_eq!(normalize_interface(Some(String::new())), None);
        assert_eq!(normalize_interface(Some("  ".to_string())), None);
        for name in ["auto", "Auto", "AUTO", "default", "Default"] {
            assert_eq!(
                normalize_interface(Some(name.to_string())),
                None,
                "{name} should mean auto routing"
            );
        }
        assert_eq!(
            normalize_interface(Some("en0".to_string())),
            Some("en0".to_string())
        );
        assert_eq!(
            normalize_interface(Some(" utun6 ".to_string())),
            Some("utun6".to_string())
        );
    }

    #[test]
    fn validate_target_families_reports_missing_family_only_when_used() {
        let ipv4 = "127.0.0.1".parse().unwrap();
        let addrs = InterfaceAddrs {
            ipv4: Some(ipv4),
            ipv6: None,
        };
        assert!(validate_target_families("lo0", &addrs, ["127.0.0.1"]).is_ok());
        assert!(validate_target_families("lo0", &addrs, []).is_ok());
        let error = validate_target_families("lo0", &addrs, ["2001:db8::1"]).unwrap_err();
        assert!(error.to_string().contains("no IPv6 address"));
        assert!(validate_target_families("lo0", &addrs, ["192.0.2.1", "2001:db8::1"]).is_err());
        assert!(validate_target_families("lo0", &addrs, ["not-an-ip"]).is_ok());
        let addrs = InterfaceAddrs {
            ipv4: None,
            ipv6: Some("::1".parse().unwrap()),
        };
        let error = validate_target_families("lo0", &addrs, ["192.0.2.1"]).unwrap_err();
        assert!(error.to_string().contains("no IPv4 address"));
    }

    #[test]
    fn validate_interface_rejects_unknown_names_with_available_list() {
        assert!(validate_interface(&loopback_name()).is_ok());
        let error = validate_interface("definitely-not-an-interface").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("not found"));
        assert!(message.contains(&loopback_name()));
    }
}
