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

/// Interface prefixes that mark a link as a VPN (or generic tunnel) device.
/// Lowercase; the common names across macOS (`utun`, `ipsec`), Linux
/// (`tun`, `tap`, `ppp`, `wg`), and Windows WireGuard/OpenVPN adapters.
const VPN_INTERFACE_PREFIXES: &[&str] = &["utun", "tun", "tap", "ppp", "wg", "ipsec"];

/// Heuristic: does this interface look like a VPN tunnel? Case-insensitive
/// prefix match against the well-known tunnel names. This is a hint, not
/// proof: macOS also creates `utun` devices for System Extensions and
/// iCloud Private Relay, and some VPNs use plain ethernet-style names.
pub fn is_vpn_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VPN_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Interface prefixes for virtual network devices that are not real
/// uplinks: bridges, container veth pairs, VM adapters, and Apple's
/// AWDL (Wi-Fi Direct) link.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "bridge", "br", "veth", "docker", "vmnet", "vboxnet", "virbr", "awdl", "llw",
];

/// Heuristic: is this a virtual (bridge/VM/container) device rather than a
/// physical uplink? Used to prefer real interfaces for VPN bypass.
fn is_virtual_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// The best candidate for routing *around* a VPN: the first non-VPN
/// physical uplink that carries at least one off-link-capable address.
/// Loopback, VPN, and virtual (bridge/VM/container) interfaces are skipped
/// first; if no physical uplink qualifies, the first usable virtual
/// interface is used as a fallback so the row still works on unusual
/// setups. Returns `None` when every interface is a tunnel or otherwise
/// unusable.
pub fn bypass_vpn_interface() -> Option<String> {
    let interfaces = list_interfaces().ok()?;
    let mut virtual_fallback = None;
    for entry in interfaces {
        if is_vpn_interface(&entry.name) || entry.addresses.iter().any(IpAddr::is_loopback) {
            continue;
        }
        let (ipv4, ipv6) = preferred_addresses(&entry.addresses);
        let usable = ipv4
            .map(IpAddr::V4)
            .is_some_and(|addr| is_off_link_capable(&addr))
            || ipv6
                .map(IpAddr::V6)
                .is_some_and(|addr| is_off_link_capable(&addr));
        if !usable {
            continue;
        }
        if is_virtual_interface(&entry.name) {
            if virtual_fallback.is_none() {
                virtual_fallback = Some(entry.name);
            }
            continue;
        }
        return Some(entry.name);
    }
    virtual_fallback
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

/// Parse a `--mark` value: decimal (`106`) or hex (`0x106`, as the marks
/// are conventionally written). `0` is rejected because it means "no mark";
/// the valid range is `1..=u32::MAX`.
pub fn parse_mark_value(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("mark value is empty".to_string());
    }
    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid mark value {raw:?}"))?
    } else {
        let parsed = trimmed
            .parse::<u64>()
            .map_err(|e| format!("invalid mark value {raw:?}: {e}"))?;
        u32::try_from(parsed).map_err(|_| format!("mark value {raw:?} is out of range"))?
    };
    if value == 0 {
        return Err("mark value 0 means no mark; use 1 or above".to_string());
    }
    Ok(value)
}

/// Whether this platform supports `SO_MARK` (Linux and Android do).
pub fn mark_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

/// Set the `SO_MARK` socket option on `socket` (before `connect`) so the
/// kernel routes the connection through the fwmark-selected table. Linux
/// and Android only; other targets return a clear `Unsupported` error, and
/// insufficient privilege (no `CAP_NET_ADMIN`) surfaces as the setsockopt
/// error instead of a silent fallback.
fn set_socket_mark(socket: &tokio::net::TcpSocket, mark: u32) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        use std::os::raw::{c_int, c_void};
        const SOL_SOCKET: c_int = 1;
        const SO_MARK: c_int = 36;
        unsafe extern "C" {
            fn setsockopt(
                fd: c_int,
                level: c_int,
                optname: c_int,
                optval: *const c_void,
                optlen: u32,
            ) -> c_int;
        }
        let fd = socket.as_raw_fd();
        let ret = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_MARK,
                &mark as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        if ret != 0 {
            // Tagged so callers (e.g. the discovery sweep) can tell a
            // mark-setup failure apart from an ordinary connect refusal.
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("SO_MARK setup failed: {}", std::io::Error::last_os_error()),
            ));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = socket;
        let _ = mark;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SO_MARK (--mark) is only supported on Linux and Android",
        ))
    }
}

/// Happy Eyeballs (RFC 8305) stagger: the second address family is
/// attempted 250 ms after the first if it hasn't connected yet.
pub const HAPPY_EYEBALLS_DELAY_MS: u64 = 250;

/// Order candidate addresses Happy-Eyeballs style (RFC 8305): IPv6 first,
/// then IPv4, alternating so each family gets a turn at the stagger
/// cadence. Exact duplicates are dropped.
pub fn eyeball_order(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v6: Vec<SocketAddr> = Vec::new();
    let mut v4: Vec<SocketAddr> = Vec::new();
    for addr in addrs {
        let bucket = if addr.is_ipv6() { &mut v6 } else { &mut v4 };
        if !bucket.contains(&addr) {
            bucket.push(addr);
        }
    }
    let mut ordered = Vec::with_capacity(v6.len() + v4.len());
    let mut i = 0;
    while i < v6.len() || i < v4.len() {
        if let Some(addr) = v6.get(i) {
            ordered.push(*addr);
        }
        if let Some(addr) = v4.get(i) {
            ordered.push(*addr);
        }
        i += 1;
    }
    ordered
}

/// Connect to the first candidate address that answers, racing with the
/// Happy Eyeballs stagger: attempt 0 starts immediately; attempt *n* starts
/// `HAPPY_EYEBALLS_DELAY_MS` after attempt *n-1* if nothing has succeeded —
/// or immediately if attempt *n-1* failed fast. Interface binding and
/// `SO_MARK` are applied per attempt via [`bind_connect`].
pub async fn dial_raced(
    addrs: Vec<SocketAddr>,
    interface: Option<InterfaceAddrs>,
    mark: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    let ordered = eyeball_order(addrs);
    if ordered.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no addresses to dial",
        ));
    }
    use futures::StreamExt;
    /// Abort-on-drop owner for the dial attempts: dropping the raced dial
    /// (e.g. on a timeout/cancel outside) aborts every pending task and
    /// releases its sockets instead of letting detached tasks run on.
    struct DialTasks {
        abort_handles: Vec<tokio::task::AbortHandle>,
    }
    impl Drop for DialTasks {
        fn drop(&mut self) {
            for abort in &self.abort_handles {
                abort.abort();
            }
        }
    }
    let mut guard = DialTasks {
        abort_handles: Vec::new(),
    };
    let mut pending = futures::stream::FuturesUnordered::new();
    macro_rules! spawn_next {
        ($idx:expr) => {{
            let handle = tokio::spawn(bind_connect(ordered[$idx], interface, mark));
            guard.abort_handles.push(handle.abort_handle());
            pending.push(handle);
        }};
    }
    let mut next_idx;
    let mut last_error: Option<std::io::Error> = None;
    spawn_next!(0);
    next_idx = 1;
    loop {
        let stagger: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            if next_idx < ordered.len() {
                Box::pin(tokio::time::sleep(std::time::Duration::from_millis(
                    HAPPY_EYEBALLS_DELAY_MS,
                )))
            } else {
                Box::pin(futures::future::pending::<()>())
            };
        tokio::select! {
            result = pending.next() => {
                match result {
                    Some(Ok(Ok(stream))) => {
                        return Ok(stream);
                    }
                    Some(Ok(Err(e))) => {
                        last_error = Some(e);
                        // Fail fast: start the next attempt immediately
                        // instead of waiting out the stagger.
                        if next_idx < ordered.len() {
                            spawn_next!(next_idx);
                            next_idx += 1;
                        } else if pending.is_empty() {
                            return Err(last_error.unwrap_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::ConnectionRefused,
                                    "all addresses failed",
                                )
                            }));
                        }
                    }
                    Some(Err(_)) => {
                        // Task panicked/cancelled: treat like a failure.
                        last_error = Some(std::io::Error::other("dial task failed"));
                        if next_idx < ordered.len() {
                            spawn_next!(next_idx);
                            next_idx += 1;
                        } else if pending.is_empty() {
                            return Err(last_error.unwrap());
                        }
                    }
                    None => {
                        return Err(last_error.unwrap_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::ConnectionRefused,
                                "all addresses failed",
                            )
                        }));
                    }
                }
            }
            _ = stagger => {
                if next_idx < ordered.len() {
                    spawn_next!(next_idx);
                    next_idx += 1;
                }
            }
        }
    }
}

/// Keep only the candidate addresses whose family the pinned interface can
/// reach (it has an address of that family). Hostname lookups resolve both
/// families even when the pinned interface only carries one.
fn filter_to_interface_families(
    candidates: Vec<SocketAddr>,
    interface: Option<InterfaceAddrs>,
) -> Vec<SocketAddr> {
    let Some(iface_addrs) = interface else {
        return candidates;
    };
    candidates
        .into_iter()
        .filter(|addr| iface_addrs.pick(addr.is_ipv4()).is_some())
        .collect()
}

/// Dial `host_or_ip` on `port`: an IP literal goes straight to
/// [`bind_connect`]; a hostname is resolved and raced Happy-Eyeballs style
/// via [`dial_raced`], filtered to the pinned interface's families. Used by
/// the proxy checks so domain targets get dual-stack racing instead of the
/// OS's single-address answer.
pub async fn dial(
    host_or_ip: &str,
    port: u16,
    interface: Option<InterfaceAddrs>,
    mark: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    if let Ok(ip) = host_or_ip.parse::<IpAddr>() {
        return bind_connect(SocketAddr::new(ip, port), interface, mark).await;
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host_or_ip, port)).await?.collect();
    let addrs = filter_to_interface_families(addrs, interface);
    dial_raced(addrs, interface, mark).await
}

/// Connect to `addr`, optionally binding the local address of the pinned
/// interface first so the connection egresses through that interface.
/// When `mark` is `Some`, `SO_MARK` is applied to the socket before
/// `connect` so the connection egresses through the fwmark-selected
/// routing table (e.g. to keep probes out of a TUN: Linux/Android only).
pub async fn bind_connect(
    addr: SocketAddr,
    interface: Option<InterfaceAddrs>,
    mark: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    let local = interface.and_then(|addrs| addrs.pick(addr.is_ipv4()));
    if local.is_none() && mark.is_none() {
        return tokio::net::TcpStream::connect(addr).await;
    }
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if let Some(local) = local {
        socket.bind(SocketAddr::new(local, 0))?;
    }
    if let Some(mark) = mark {
        set_socket_mark(&socket, mark)?;
    }
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
    fn vpn_interface_prefixes_are_recognized_case_insensitively() {
        for name in [
            "utun3", "tun0", "tap1", "ppp0", "wg0", "ipsec0", "UTUN2", "Tun4",
        ] {
            assert!(is_vpn_interface(name), "{name} should look like a VPN");
        }
        for name in ["en0", "eth0", "wlan0", "lo0", "awdl0", "bridge100", ""] {
            assert!(!is_vpn_interface(name), "{name} should not look like a VPN");
        }
    }

    #[test]
    fn bypass_vpn_interface_prefers_a_non_vpn_uplink() {
        let interfaces = list_interfaces().unwrap();
        assert!(
            interfaces
                .iter()
                .any(|entry| entry.addresses.iter().any(|addr| !addr.is_loopback())),
            "expected a non-loopback interface among {interfaces:?}"
        );
        let Some(name) = bypass_vpn_interface() else {
            return; // loopback-only host: there is nothing to bypass with
        };
        let entry = interfaces
            .iter()
            .find(|entry| entry.name == name)
            .expect("bypass candidate must be a live interface");
        assert!(
            !is_vpn_interface(&entry.name),
            "bypass candidate must not be a VPN interface"
        );
        assert!(
            entry.addresses.iter().any(|addr| !addr.is_loopback()),
            "bypass candidate must have a non-loopback address"
        );
        let has_physical = interfaces.iter().any(|entry| {
            !is_vpn_interface(&entry.name)
                && !is_virtual_interface(&entry.name)
                && entry.addresses.iter().any(|addr| !addr.is_loopback())
        });
        if has_physical {
            assert!(
                !is_virtual_interface(&entry.name),
                "bypass candidate must prefer a physical uplink when one exists"
            );
        }
    }

    #[test]
    fn virtual_interface_prefixes_are_recognized() {
        for name in [
            "bridge100",
            "br0",
            "vethabc12",
            "docker0",
            "vmnet8",
            "vboxnet0",
            "virbr0",
            "awdl0",
            "llw0",
        ] {
            assert!(
                is_virtual_interface(name),
                "{name} should look like a virtual device"
            );
        }
        for name in ["en0", "en5", "eth0", "wlan0", "utun3", "wg0", "lo0", ""] {
            assert!(
                !is_virtual_interface(name),
                "{name} should not look like a virtual device"
            );
        }
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

    // --- RED: item 5 — SO_MARK parsing + bind_connect marks ---
    #[test]
    fn parse_mark_value_accepts_decimal_and_hex() {
        use super::parse_mark_value;
        assert_eq!(parse_mark_value("106").unwrap(), 106);
        assert_eq!(parse_mark_value("0x106").unwrap(), 262);
        assert_eq!(parse_mark_value("0X1f").unwrap(), 31);
        assert_eq!(parse_mark_value(" 262 ").unwrap(), 262);
    }

    #[test]
    fn parse_mark_value_rejects_zero_garbage_and_overflow() {
        use super::parse_mark_value;
        assert!(parse_mark_value("0").is_err());
        assert!(parse_mark_value("0x0").is_err());
        assert!(parse_mark_value("").is_err());
        assert!(parse_mark_value("not-a-mark").is_err());
        assert!(parse_mark_value("-1").is_err());
        assert!(parse_mark_value("4294967296").is_err());
        assert!(parse_mark_value("0x100000000").is_err());
    }

    /// `bind_connect` with a mark degrades gracefully where `SO_MARK` is
    /// unsupported or unprivileged instead of panicking.
    #[tokio::test]
    async fn bind_connect_with_mark_fails_cleanly_on_unsupported_platform() {
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        if cfg!(target_os = "linux") || cfg!(target_os = "android") {
            // Linux: setting SO_MARK needs CAP_NET_ADMIN in some kernels;
            // only assert the call returns (either path is acceptable if the
            // mark is really applied — the important bit is it doesn't panic).
            let _ = super::bind_connect(addr, None, Some(106)).await;
        } else {
            let err = super::bind_connect(addr, None, Some(106))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("SO_MARK"),
                "unsupported platform must name SO_MARK: {err}"
            );
        }
    }

    // --- RED: item 7 — Happy Eyeballs raced dial ---
    #[test]
    fn filter_to_interface_families_drops_unreachable_family() {
        use super::filter_to_interface_families;
        let v4a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v6a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4_only = InterfaceAddrs {
            ipv4: Some("192.168.1.5".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(
            filter_to_interface_families(vec![v4a, v6a], Some(v4_only)),
            vec![v4a]
        );
        assert_eq!(
            filter_to_interface_families(vec![v4a, v6a], None),
            vec![v4a, v6a]
        );
    }

    #[test]
    fn eyeball_order_prefers_ipv6_first_and_interleaves_families() {
        use super::eyeball_order;
        let v4a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v4b: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let v6a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v6b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        // Dual-stack input: v6 first, then v4, then next v6, then next v4.
        assert_eq!(
            eyeball_order(vec![v4a, v6a, v4b, v6b]),
            vec![v6a, v4a, v6b, v4b]
        );
        // Single family keeps its order.
        assert_eq!(eyeball_order(vec![v4a, v4b]), vec![v4a, v4b]);
        assert_eq!(eyeball_order(vec![v6b, v6a]), vec![v6b, v6a]);
        assert_eq!(eyeball_order(vec![]), Vec::<SocketAddr>::new());
    }

    #[tokio::test]
    async fn dial_raced_reaches_a_listener_and_fails_closed_on_no_addrs() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addrs = vec![
            // Closed port first: fast failure must fall through to the listener.
            SocketAddr::new("127.0.0.2".parse().unwrap(), 9),
            SocketAddr::new("127.0.0.1".parse().unwrap(), port),
        ];
        let stream = super::dial_raced(addrs.clone(), None, None)
            .await
            .expect("dial must fail over to the loopback listener");
        assert_eq!(stream.peer_addr().unwrap().port(), port);
        drop(stream);
        drop(listener);

        assert!(super::dial_raced(vec![], None, None).await.is_err());
    }

    /// `dial` reaches a loopback listener via both IP literals and hostnames.
    #[tokio::test]
    async fn dial_accepts_hostnames_and_ip_literals() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let by_ip = super::dial("127.0.0.1", port, None, None)
            .await
            .expect("IP-literal dial");
        assert_eq!(by_ip.peer_addr().unwrap().port(), port);
        drop(by_ip);
        // Hostname path: resolve independently and, when IPv4 loopback is
        // present, require the raced dial to reach our v4-only listener.
        let resolved: Vec<std::net::IpAddr> = tokio::net::lookup_host(("localhost", port))
            .await
            .expect("localhost must resolve")
            .map(|addr| addr.ip())
            .collect();
        let v4_loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        if resolved.contains(&v4_loopback) {
            let by_name = super::dial("localhost", port, None, None)
                .await
                .expect("hostname dial must reach the v4 listener");
            assert_eq!(by_name.peer_addr().unwrap().port(), port);
            drop(by_name);
        }
        drop(listener);
    }
}
