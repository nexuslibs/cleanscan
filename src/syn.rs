//! Raw SYN discovery driver (masscan-style sweep).
//!
//! Sends Ethernet/IPv4/TCP SYN frames directly to the wire through libpcap
//! and watches for SYN-ACK replies: candidate addresses that answer with a
//! SYN-ACK on any probe port become targets for the probe engine, mirroring
//! what the kernel-backed [`connect_sweep`] reports. Pacing, windowed
//! ephemeral-port allocation and retransmission mimic masscan's model.
//!
//! Compiled only with the `syn` cargo feature. Requires root (raw sockets),
//! an Ethernet-capable interface with a reachable IPv4 default gateway, and
//! IPv4-only sources.
//!
//! [`connect_sweep`]: crate::discovery::connect_sweep

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use pcap::{Active, Capture, Device, Error, Linktype};
use rand::Rng;

use crate::discovery::{
    enumerated_address_count, send_progress, AddressEnumerator, ProgressSender, SourceEntry,
};

/// Tuning knobs for one SYN sweep.
#[derive(Debug, Clone)]
pub struct SynSweepParams {
    /// Pacing in packets per second sent to the wire.
    pub rate_pps: u32,
    /// Extra passes over each window after the first (retransmissions).
    pub retransmits: u32,
    /// How long to keep listening for replies after each pass.
    pub reply_wait_ms: u64,
    /// Interface to send on; `None` picks a default device with an IPv4 address.
    pub interface: Option<String>,
}

/// Whether the current process can open raw packet sockets (effective uid 0).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

const ETH_IPV4: u16 = 0x0800;
const ETH_ARP: u16 = 0x0806;
const ETH_VLAN: u16 = 0x8100;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const IP_TCP: u8 = 6;
const IP_TTL: u8 = 64;
const TCP_SYN: u8 = 0x02;
const TCP_WINDOW: u16 = 64240;
/// Largest window of concurrently outstanding SYN pairs. Every pair owns a
/// private ephemeral source port, so a window is bounded by the port space.
const WINDOW_PAIRS: usize = 16_384;
const SNAP_LEN: usize = 256;
const CAPTURE_BUFFER: usize = 4 * 1024 * 1024;
const MAX_RATE_PPS: u32 = 1_000_000;
const MAX_RETRANSMITS: u32 = 10;
const _: () = assert!(WINDOW_PAIRS <= 65536 - 1024);

/// Local link information needed to craft and filter frames.
#[derive(Debug, Clone, Copy)]
struct LinkInfo {
    ip: Ipv4Addr,
    mac: [u8; 6],
    gateway_mac: [u8; 6],
}

#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    ip: Ipv4Addr,
    mac: [u8; 6],
}

fn pcap_err(error: pcap::Error) -> anyhow::Error {
    anyhow!("pcap: {error}")
}

fn interface_ipv4(device: &Device) -> Option<Ipv4Addr> {
    device
        .addresses
        .iter()
        .find_map(|address| match address.addr {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
}

fn default_ipv4_device(devices: &[Device]) -> Option<&Device> {
    devices
        .iter()
        .find(|d| interface_ipv4(d).is_some() && !d.name.starts_with("lo"))
        .or_else(|| devices.iter().find(|d| interface_ipv4(d).is_some()))
}

fn select_device(interface: Option<&str>) -> Result<(Device, InterfaceInfo)> {
    let devices = Device::list().map_err(pcap_err)?;
    let device = if let Some(name) = interface {
        devices
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| {
                anyhow!(
                    "interface {name:?} not found; available: {}",
                    devices
                        .iter()
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
            .clone()
    } else if let Some(device) = Device::lookup().map_err(pcap_err)? {
        if device.name != "any" {
            device
        } else {
            default_ipv4_device(&devices)
                .ok_or_else(|| anyhow!("no usable network interface found"))?
                .clone()
        }
    } else {
        default_ipv4_device(&devices)
            .ok_or_else(|| anyhow!("no usable network interface found"))?
            .clone()
    };
    let ip = interface_ipv4(&device)
        .ok_or_else(|| anyhow!("interface {} has no IPv4 address", device.name))?;
    let name = device.name.clone();
    // Loopback links carry no meaningful Ethernet address; the kernel ignores
    // the header on them, so zeros are safe and the MAC lookup is skipped.
    let mac = if ip.is_loopback() {
        [0u8; 6]
    } else {
        interface_mac(&name)?
    };
    Ok((device, InterfaceInfo { name, ip, mac }))
}

#[cfg(target_os = "linux")]
fn interface_mac(name: &str) -> Result<[u8; 6]> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        bail!(
            "cannot open control socket: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.as_bytes().len() >= ifr.ifr_name.len() {
        unsafe { libc::close(fd) };
        bail!("interface name {name:?} is too long");
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = *src as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::Ioctl, &mut ifr) };
    unsafe { libc::close(fd) };
    if rc != 0 {
        bail!(
            "cannot read MAC of {name:?}: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut mac = [0u8; 6];
    for (dst, src) in mac
        .iter_mut()
        .zip(unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data })
    {
        *dst = src as u8;
    }
    Ok(mac)
}

#[cfg(target_os = "macos")]
fn interface_mac(name: &str) -> Result<[u8; 6]> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            bail!("getifaddrs failed: {}", std::io::Error::last_os_error());
        }
        let mut found: Option<[u8; 6]> = None;
        let mut current = ifap;
        while !current.is_null() {
            let ifa = &*current;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family == libc::AF_LINK as u8 {
                let ifa_name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                if ifa_name == name {
                    let sdl = ifa.ifa_addr as *const libc::sockaddr_dl;
                    let alen = (*sdl).sdl_alen as usize;
                    if alen == 6 {
                        let base = (ifa.ifa_addr as *const u8)
                            .add(std::mem::size_of::<libc::sockaddr_dl>());
                        let data =
                            std::slice::from_raw_parts(base, (*sdl).sdl_nlen as usize + alen);
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&data[(*sdl).sdl_nlen as usize..][..6]);
                        found = Some(mac);
                    }
                    break;
                }
            }
            current = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found.ok_or_else(|| anyhow!("cannot read MAC of {name:?}"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn interface_mac(_name: &str) -> Result<[u8; 6]> {
    bail!("SYN discovery is not supported on this platform yet")
}

#[cfg(target_os = "linux")]
fn default_gateway_ipv4() -> Result<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    parse_linux_route(&table)
        .ok_or_else(|| anyhow!("no IPv4 default route found in /proc/net/route"))
}

/// Parse the default gateway out of a `/proc/net/route` table. Addresses are
/// stored little-endian, so the hex field is byte-swapped on decode.
#[cfg(any(test, target_os = "linux"))]
fn parse_linux_route(table: &str) -> Option<Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let _iface = fields.next()?;
        let dest = fields.next()?;
        let gateway = fields.next()?;
        let flags = fields.next()?;
        if dest != "00000000" || flags.parse::<u16>().ok()? & 0x1 == 0 {
            return None;
        }
        Some(Ipv4Addr::from(
            u32::from_str_radix(gateway, 16).ok()?.to_le_bytes(),
        ))
    })
}

#[cfg(target_os = "macos")]
fn default_gateway_ipv4() -> Result<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        bail!(
            "`route -n get default` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_macos_route(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("no IPv4 default route found via `route -n get default`"))
}

/// Parse `gateway: 192.168.1.1` out of `route -n get default` output.
#[cfg(any(test, target_os = "macos"))]
fn parse_macos_route(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("gateway:")?;
        rest.trim().parse().ok()
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_gateway_ipv4() -> Result<Ipv4Addr> {
    bail!("SYN discovery is not supported on this platform yet")
}

/// Build an Ethernet/ARP request frame asking for `target_ip`'s link address.
fn build_arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETH_ARP.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&ETH_IPV4.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    frame[22..28].copy_from_slice(&src_mac);
    frame[28..32].copy_from_slice(&src_ip.octets());
    frame[38..42].copy_from_slice(&target_ip.octets());
    frame
}

/// Parse an Ethernet/ARP reply into the sender's IP and MAC.
fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if frame.len() < 42 || u16::from_be_bytes([frame[12], frame[13]]) != ETH_ARP {
        return None;
    }
    if u16::from_be_bytes([frame[20], frame[21]]) != ARP_REPLY {
        return None;
    }
    let sender_mac = [
        frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
    ];
    let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    Some((sender_ip, sender_mac))
}

/// Resolve the gateway's link address with an ARP request on `capture`.
fn arp_resolve(
    capture: &mut Capture<Active>,
    info: &InterfaceInfo,
    gateway: Ipv4Addr,
) -> Result<[u8; 6]> {
    capture
        .sendpacket(&build_arp_request(info.mac, info.ip, gateway)[..])
        .map_err(pcap_err)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((sender_ip, sender_mac)) = parse_arp_reply(packet.data) {
                    if sender_ip == gateway {
                        return Ok(sender_mac);
                    }
                }
            }
            Err(Error::TimeoutExpired) => {}
            Err(error) => return Err(pcap_err(error)),
        }
    }
    bail!("ARP reply from {gateway} not received; check the interface and gateway")
}

/// Open the capture on the selected interface, resolve the gateway link
/// address, and validate the link layer.
fn prepare_capture(interface: Option<&str>) -> Result<(Capture<Active>, LinkInfo)> {
    let (device, info) = select_device(interface)?;
    let mut capture = Capture::from_device(device)
        .map_err(pcap_err)?
        .snaplen(SNAP_LEN as i32)
        .promisc(true)
        .timeout(20)
        .immediate_mode(true)
        .buffer_size(CAPTURE_BUFFER as i32)
        .open()
        .map_err(pcap_err)?;
    if capture.get_datalink() != Linktype::ETHERNET {
        bail!(
            "interface {} has an unsupported link layer ({:?}); only Ethernet links are supported",
            info.name,
            capture.get_datalink()
        );
    }
    let gateway_mac = if info.ip.is_loopback() {
        [0u8; 6]
    } else {
        arp_resolve(&mut capture, &info, default_gateway_ipv4()?)?
    };
    Ok((
        capture,
        LinkInfo {
            ip: info.ip,
            mac: info.mac,
            gateway_mac,
        },
    ))
}

/// RFC 1071 one's-complement Internet checksum.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut pairs = data.chunks_exact(2);
    for pair in pairs.by_ref() {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(byte) = pairs.remainder().first() {
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum over the IPv4 pseudo-header plus the TCP segment.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IP_TCP);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    ip_checksum(&pseudo)
}

/// Build an Ethernet/IPv4/TCP SYN frame with correct checksums, padded to the
/// 60-byte Ethernet minimum (padding is not part of the IP length).
#[allow(clippy::too_many_arguments)]
fn build_syn_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ip_id: u16,
) -> [u8; 60] {
    let mut frame = [0u8; 60];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETH_IPV4.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40u16.to_be_bytes());
    frame[18..20].copy_from_slice(&ip_id.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[22] = IP_TTL;
    frame[23] = IP_TCP;
    frame[26..30].copy_from_slice(&src_ip.octets());
    frame[30..34].copy_from_slice(&dst_ip.octets());
    let ip_checksum_value = ip_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum_value.to_be_bytes());
    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = TCP_SYN;
    frame[48..50].copy_from_slice(&TCP_WINDOW.to_be_bytes());
    let tcp_checksum_value = tcp_checksum(src_ip, dst_ip, &frame[34..54]);
    frame[50..52].copy_from_slice(&tcp_checksum_value.to_be_bytes());
    frame
}

/// Parse an Ethernet frame into a possible SYN-ACK reply: the responder IP,
/// the frame's destination IP, and the destination (ephemeral) port. Returns
/// `None` for anything that is not an IPv4 TCP SYN-ACK (VLAN tags accepted).
fn parse_syn_ack(frame: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16)> {
    let mut eth = 0usize;
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == ETH_VLAN {
        if frame.len() < 18 {
            return None;
        }
        eth = 4;
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
    }
    if ethertype != ETH_IPV4 {
        return None;
    }
    let ip = 14 + eth;
    if frame.len() < ip + 20 || frame[ip + 9] != IP_TCP {
        return None;
    }
    let tcp = ip + ((frame[ip] & 0x0f) as usize) * 4;
    if frame.len() < tcp + 20 || frame[tcp + 13] & 0x12 != 0x12 {
        return None;
    }
    let src = Ipv4Addr::new(
        frame[ip + 12],
        frame[ip + 13],
        frame[ip + 14],
        frame[ip + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip + 16],
        frame[ip + 17],
        frame[ip + 18],
        frame[ip + 19],
    );
    let dst_port = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    Some((src, dst, dst_port))
}

/// Drain captured replies until `duration` elapses or the scan is cancelled.
fn drain_replies(
    capture: &mut Capture<Active>,
    our_ip: Ipv4Addr,
    window_base: u16,
    window_pairs: u16,
    open: &mut BTreeSet<String>,
    duration: Duration,
    cancel: &AtomicBool,
) -> Result<()> {
    let deadline = Instant::now() + duration;
    let top = window_base as u32 + window_pairs as u32;
    while Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((responder, dst_ip, dst_port)) = parse_syn_ack(packet.data) {
                    if dst_ip == our_ip && (window_base as u32..top).contains(&(dst_port as u32)) {
                        open.insert(responder.to_string());
                    }
                }
            }
            Err(Error::TimeoutExpired) => {}
            Err(error) => return Err(pcap_err(error)),
        }
    }
    Ok(())
}

/// Sleep for the pacing interval, slicing it so cancellation stays responsive.
fn sleep_paced(pacing: Duration, cancel: &AtomicBool) {
    let mut remaining = pacing;
    while !remaining.is_zero() && !cancel.load(Ordering::Relaxed) {
        let step = remaining.min(Duration::from_millis(5));
        std::thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
}

/// Sweep every unique candidate address with raw SYN frames and collect the
/// addresses that answer with a SYN-ACK on any probe port, deduplicated and
/// sorted. Blocking; callers should run this on a dedicated thread. Every
/// window of in-flight pairs uses a private ephemeral port range, is
/// retransmitted `retransmits` extra times, and replies are drained for
/// `reply_wait_ms` after each pass.
pub fn syn_sweep(
    sources: &[SourceEntry],
    ports: &[u16],
    params: SynSweepParams,
    cancel: Arc<AtomicBool>,
    progress: Option<ProgressSender>,
) -> Result<Vec<String>> {
    if ports.is_empty() {
        bail!("SYN discovery requires at least one probe port");
    }
    if ports.len() > WINDOW_PAIRS {
        bail!("too many probe ports for a SYN sweep");
    }
    if sources.iter().any(|entry| {
        matches!(
            entry,
            SourceEntry::Ip(IpAddr::V6(_)) | SourceEntry::Net(IpNet::V6(_))
        )
    }) {
        bail!("SYN discovery supports IPv4 only; remove the IPv6 sources");
    }
    if !is_root() {
        bail!("SYN discovery requires root privileges (raw sockets)");
    }
    let total = enumerated_address_count(sources);
    if total == 0 {
        return Ok(Vec::new());
    }
    let (mut capture, link) = prepare_capture(params.interface.as_deref())?;
    let rate = params.rate_pps.clamp(1, MAX_RATE_PPS) as u64;
    let pacing = Duration::from_secs(1) / rate as u32;
    let reply_wait = Duration::from_millis(params.reply_wait_ms.max(100));
    let retransmits = params.retransmits.min(MAX_RETRANSMITS);
    let window_ips = (WINDOW_PAIRS / ports.len()).max(1);
    let mut rng = rand::thread_rng();
    let mut open: BTreeSet<String> = BTreeSet::new();
    let mut attempted: u64 = 0;

    send_progress(
        progress.as_ref(),
        0,
        total,
        Some(&format!("syn sweep started: {total} candidate address(es)")),
    );

    let mut enumerator = AddressEnumerator::new(sources);
    while !cancel.load(Ordering::Relaxed) {
        let window: Vec<Ipv4Addr> = (0..window_ips)
            .filter_map(|_| match enumerator.next() {
                Some(IpAddr::V4(ip)) => Some(ip),
                Some(IpAddr::V6(_)) | None => None,
            })
            .collect();
        if window.is_empty() {
            break;
        }
        let pairs_total = window.len() * ports.len();
        let base: u16 = rng.gen_range(1024..=(65536 - pairs_total) as u16);
        let pairs: Vec<(Ipv4Addr, u16, u16, u32)> = window
            .iter()
            .enumerate()
            .flat_map(|(index, ip)| {
                let seq = rng.gen::<u32>();
                ports.iter().enumerate().map(move |(port_index, port)| {
                    (
                        *ip,
                        *port,
                        base + (index * ports.len() + port_index) as u16,
                        seq,
                    )
                })
            })
            .collect();
        let port_top = base as u32 + pairs_total as u32 - 1;
        let _ = capture
            .filter(
                &format!(
                    "tcp and dst host {} and dst portrange {base}-{port_top}",
                    link.ip
                ),
                true,
            )
            .map_err(pcap_err);
        let mut ip_id = rng.gen::<u16>();
        for _pass in 0..=retransmits {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            for (ip, port, sport, seq) in &pairs {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let frame = build_syn_frame(
                    link.mac,
                    link.gateway_mac,
                    link.ip,
                    *ip,
                    *sport,
                    *port,
                    *seq,
                    ip_id,
                );
                capture.sendpacket(&frame[..]).map_err(pcap_err)?;
                ip_id = ip_id.wrapping_add(1);
                sleep_paced(pacing, &cancel);
            }
            drain_replies(
                &mut capture,
                link.ip,
                base,
                pairs_total as u16,
                &mut open,
                reply_wait,
                &cancel,
            )?;
        }
        attempted = attempted.saturating_add(window.len() as u64);
        send_progress(progress.as_ref(), attempted, total, None);
    }

    send_progress(
        progress.as_ref(),
        attempted,
        total,
        Some(&format!(
            "syn sweep complete: {} reachable address(es)",
            open.len()
        )),
    );
    Ok(open.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanPhase;

    #[test]
    fn ip_checksum_matches_rfc1071_example() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ip_checksum(&header), 0xb861);
    }

    #[test]
    fn syn_frame_fields_and_checksums_are_valid() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip: Ipv4Addr = "192.168.1.5".parse().unwrap();
        let dst_ip: Ipv4Addr = "104.16.1.1".parse().unwrap();
        let frame = build_syn_frame(src_mac, dst_mac, src_ip, dst_ip, 40000, 443, 12345, 7);
        assert_eq!(&frame[0..6], &dst_mac);
        assert_eq!(&frame[6..12], &src_mac);
        assert_eq!(&frame[12..14], &ETH_IPV4.to_be_bytes());
        assert_eq!(frame[14], 0x45);
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 40);
        assert_eq!(u16::from_be_bytes([frame[18], frame[19]]), 7);
        assert_eq!(frame[22], IP_TTL);
        assert_eq!(frame[23], IP_TCP);
        assert_eq!(&frame[26..30], &src_ip.octets());
        assert_eq!(&frame[30..34], &dst_ip.octets());
        assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 40000);
        assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 443);
        assert_eq!(
            u32::from_be_bytes([frame[38], frame[39], frame[40], frame[41]]),
            12345
        );
        assert_eq!(frame[47], TCP_SYN);
        assert_eq!(u16::from_be_bytes([frame[48], frame[49]]), TCP_WINDOW);
        // A correct header re-sums to zero with its own checksum included.
        assert_eq!(ip_checksum(&frame[14..34]), 0);
        assert_eq!(tcp_checksum(src_ip, dst_ip, &frame[34..54]), 0);
        // Ethernet padding beyond the IP length is zeroed.
        assert!(frame[54..60].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn syn_ack_parsing_accepts_replies_only() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip: Ipv4Addr = "192.168.1.5".parse().unwrap();
        let dst_ip: Ipv4Addr = "104.16.1.1".parse().unwrap();
        let mut frame = build_syn_frame(src_mac, dst_mac, src_ip, dst_ip, 443, 40000, 0, 7);
        // A plain SYN (our own transmission) must not count.
        assert!(parse_syn_ack(&frame).is_none());
        // Turn it into a genuine reply: addresses and ports swap direction.
        frame.swap(26, 30);
        frame.swap(27, 31);
        frame.swap(28, 32);
        frame.swap(29, 33);
        frame.swap(34, 36);
        frame.swap(35, 37);
        frame[47] = 0x12; // SYN-ACK
        let (responder, dst_ip_seen, dst_port) = parse_syn_ack(&frame).unwrap();
        assert_eq!(responder, dst_ip);
        assert_eq!(dst_ip_seen, src_ip);
        assert_eq!(dst_port, 443);
        frame[47] = 0x04; // RST is a closed-port signal, not a reachable target
        assert!(parse_syn_ack(&frame).is_none());
    }

    #[test]
    fn syn_ack_parsing_accepts_vlan_tags() {
        let mut frame = build_syn_frame(
            [1, 2, 3, 4, 5, 6],
            [6, 5, 4, 3, 2, 1],
            "192.168.1.5".parse().unwrap(),
            "104.16.1.1".parse().unwrap(),
            443,
            40000,
            0,
            7,
        );
        frame[47] = 0x12;
        let mut vlan = Vec::with_capacity(frame.len() + 4);
        vlan.extend_from_slice(&frame[0..12]);
        vlan.extend_from_slice(&ETH_VLAN.to_be_bytes());
        vlan.extend_from_slice(&[0x00, 0x01]);
        vlan.extend_from_slice(&frame[12..]);
        assert!(parse_syn_ack(&vlan).is_some());
    }

    #[test]
    fn arp_request_and_reply_roundtrip() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let src_ip: Ipv4Addr = "192.168.1.5".parse().unwrap();
        let gateway: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let request = build_arp_request(src_mac, src_ip, gateway);
        assert_eq!(request.len(), 42);
        assert_eq!(&request[0..6], &[0xff; 6]);
        assert_eq!(&request[6..12], &src_mac);
        assert_eq!(&request[12..14], &ETH_ARP.to_be_bytes());
        assert_eq!(u16::from_be_bytes([request[20], request[21]]), ARP_REQUEST);
        assert_eq!(&request[22..28], &src_mac);
        assert_eq!(&request[28..32], &src_ip.octets());
        assert_eq!(&request[38..42], &gateway.octets());

        let mut reply = [0u8; 42];
        reply[12..14].copy_from_slice(&ETH_ARP.to_be_bytes());
        reply[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        reply[22..28].copy_from_slice(&[0xaa; 6]);
        reply[28..32].copy_from_slice(&gateway.octets());
        let (sender_ip, sender_mac) = parse_arp_reply(&reply).unwrap();
        assert_eq!(sender_ip, gateway);
        assert_eq!(sender_mac, [0xaa; 6]);
        assert!(parse_arp_reply(&[0u8; 42]).is_none());
    }

    #[test]
    fn linux_route_table_yields_default_gateway() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                     eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_linux_route(table),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(parse_linux_route("Iface\tDestination\n"), None);
    }

    #[test]
    fn macos_route_output_yields_default_gateway() {
        let output = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.254\n";
        assert_eq!(
            parse_macos_route(output),
            Some("192.168.1.254".parse().unwrap())
        );
        assert_eq!(parse_macos_route("no gateway"), None);
    }

    #[test]
    fn syn_sweep_rejects_ipv6_sources() {
        let result = syn_sweep(
            &[SourceEntry::Net("fd00::/126".parse().unwrap())],
            &[443],
            SynSweepParams {
                rate_pps: 100,
                retransmits: 0,
                reply_wait_ms: 100,
                interface: None,
            },
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("IPv4 only"), "{error}");
    }

    #[test]
    fn syn_sweep_finds_loopback_listener_when_root() {
        if !is_root() {
            eprintln!("skipping: raw SYN sweep test requires root");
            return;
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let interface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        let open = syn_sweep(
            &[SourceEntry::Ip("127.0.0.1".parse().unwrap())],
            &[port],
            SynSweepParams {
                rate_pps: 1_000,
                retransmits: 1,
                reply_wait_ms: 500,
                interface: Some(interface.to_string()),
            },
            Arc::new(AtomicBool::new(false)),
            Some(tx),
        )
        .unwrap();
        assert_eq!(open, vec!["127.0.0.1".to_string()]);
        let events: Vec<_> = rx.try_iter().collect();
        assert!(events.iter().any(|p| p.phase == ScanPhase::Discovery));
        assert!(events.iter().any(|p| {
            p.event
                .as_ref()
                .is_some_and(|e| e.message.contains("complete"))
        }));
    }
}
