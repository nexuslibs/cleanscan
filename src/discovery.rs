//! Target discovery: sweep candidate address ranges for reachable ports before
//! the expensive HTTP(S) probe engine runs. A connect sweep is a plain TCP
//! connect (SYN/SYN-ACK handshake completed by the kernel) against each
//! candidate address; it needs no raw sockets or privileges. A raw SYN sweep
//! behind the same discovery-driver surface is provided by [`crate::syn`]
//! (compiled with the `syn` cargo feature).

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::stream::StreamExt;
use ipnet::{IpAddrRange, IpNet};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::scanner::{ProbeFailureCounts, ScanEvent, ScanEventKind, ScanPhase, ScanProgress};

pub type ProgressSender = std::sync::mpsc::SyncSender<ScanProgress>;

/// One target source: a single address or a network to enumerate fully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEntry {
    Ip(IpAddr),
    Net(IpNet),
}

/// Parse an IP/CIDR manifest file and/or a list of CIDR strings into the
/// ordered source list. File lines and CIDR strings accept one IP or CIDR per
/// line; blank lines and `#` comments are skipped.
pub fn parse_target_sources(ips_file: Option<&str>, cidrs: &[String]) -> Result<Vec<SourceEntry>> {
    let mut sources = Vec::new();
    if let Some(path) = ips_file {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            sources.push(parse_source(line)?);
        }
    }
    for cidr in cidrs {
        let trimmed = cidr.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        sources.push(parse_source(trimmed)?);
    }
    if sources.is_empty() {
        return Err(anyhow!(
            "no discovery sources: pass --ips /path/to/file or --cidr <range>"
        ));
    }
    Ok(sources)
}

fn parse_source(s: &str) -> Result<SourceEntry> {
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(SourceEntry::Ip(ip));
    }
    let net = IpNet::from_str(s).map_err(|_| anyhow!("invalid IP/CIDR: {s}"))?;
    Ok(SourceEntry::Net(net))
}

/// Number of addresses `hosts()` yields for a net, computed arithmetically so
/// huge IPv6 ranges cannot hang an iteration.
fn net_host_count(net: &IpNet) -> u128 {
    let host_bits = match net {
        IpNet::V4(net) => 32u32.saturating_sub(net.prefix_len() as u32),
        IpNet::V6(net) => 128u32.saturating_sub(net.prefix_len() as u32),
    };
    let size = if host_bits >= 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    };
    // `hosts()` excludes network and broadcast for IPv4 prefixes below /31.
    if matches!(net, IpNet::V4(net) if net.prefix_len() < 31) {
        size.saturating_sub(2)
    } else {
        size
    }
}

/// Upper bound of addresses covered by the sources (before deduplication).
pub fn enumerated_address_count(sources: &[SourceEntry]) -> u128 {
    sources
        .iter()
        .map(|entry| match entry {
            SourceEntry::Ip(_) => 1,
            SourceEntry::Net(net) => net_host_count(net),
        })
        .sum()
}

/// Whether `addr` is inside the range `hosts()` actually yields for `net`.
/// For IPv4 prefixes below /31 the network and broadcast addresses are never
/// yielded, so prefix containment alone would over-report coverage and make a
/// later overlapping net skip hosts the earlier net never enumerated.
fn net_hosts_contains(net: &IpNet, addr: &IpAddr) -> bool {
    if !net.contains(addr) {
        return false;
    }
    match net {
        IpNet::V4(net) if net.prefix_len() < 31 => {
            *addr != IpAddr::V4(net.network()) && *addr != IpAddr::V4(net.broadcast())
        }
        _ => true,
    }
}

/// Lazily yields every unique candidate address exactly once, in source order.
/// An address is skipped when an earlier source already covered it: a single
/// IP inside an earlier network, or an overlap between networks. Memory use is
/// bounded by the source list, so whole ranges can be walked without
/// materializing them.
pub struct AddressEnumerator<'a> {
    sources: &'a [SourceEntry],
    index: usize,
    prior_ips: Vec<IpAddr>,
    prior_nets: Vec<IpNet>,
    current: Option<IpAddrRange>,
    pending: Option<IpAddr>,
}

impl<'a> AddressEnumerator<'a> {
    pub fn new(sources: &'a [SourceEntry]) -> Self {
        Self {
            sources,
            index: 0,
            prior_ips: Vec::new(),
            prior_nets: Vec::new(),
            current: None,
            pending: None,
        }
    }

    fn already_covered(&self, addr: &IpAddr) -> bool {
        self.prior_ips.contains(addr)
            || self
                .prior_nets
                .iter()
                .any(|net| net_hosts_contains(net, addr))
    }
}

impl Iterator for AddressEnumerator<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        loop {
            if let Some(ip) = self.pending.take() {
                if !self.already_covered(&ip) {
                    self.prior_ips.push(ip);
                    return Some(ip);
                }
            }
            if let Some(range) = self.current.as_mut() {
                for addr in range.by_ref() {
                    let covered = self.prior_ips.contains(&addr)
                        || self
                            .prior_nets
                            .iter()
                            .any(|net| net_hosts_contains(net, &addr));
                    if !covered {
                        return Some(addr);
                    }
                }
                // The range is exhausted: its net is now fully walked, so it
                // becomes a "prior" net that later sources deduplicate
                // against. It was never checked against itself.
                self.current = None;
                if let SourceEntry::Net(net) = &self.sources[self.index - 1] {
                    self.prior_nets.push(*net);
                }
            }
            if self.index >= self.sources.len() {
                return None;
            }
            match &self.sources[self.index] {
                SourceEntry::Ip(ip) => self.pending = Some(*ip),
                SourceEntry::Net(net) => self.current = Some(net.hosts()),
            }
            self.index += 1;
        }
    }
}

#[cfg(test)]
pub fn collect_candidates(sources: &[SourceEntry]) -> Vec<IpAddr> {
    AddressEnumerator::new(sources).collect()
}

pub(crate) fn send_progress(
    tx: Option<&ProgressSender>,
    attempted: u64,
    total: u128,
    event: Option<&str>,
) {
    if let Some(tx) = tx {
        let _ = tx.try_send(ScanProgress {
            phase: ScanPhase::Discovery,
            probes_started: attempted as usize,
            probes_completed: attempted as usize,
            active_probes: 0,
            targets_completed: attempted as usize,
            latest_target: None,
            current_workers: None,
            adaptive_reason: None,
            targets_total: Some(total.min(usize::MAX as u128) as usize),
            failure_counts: ProbeFailureCounts::default(),
            event: event.map(|message| ScanEvent {
                kind: ScanEventKind::TargetQueued,
                target: None,
                message: message.to_string(),
                diagnostic_category: None,
                probe_succeeded: None,
            }),
        });
    }
}

/// Sweep every unique candidate address with plain TCP connects against the
/// given ports. An address is "reachable" when any port accepts the
/// connection; reachable addresses are returned deduplicated and sorted.
/// `concurrency` bounds in-flight connects; `cancel` stops the walk between
/// addresses (in-flight connects are allowed to drain).
#[allow(clippy::too_many_arguments)]
pub async fn connect_sweep(
    sources: &[SourceEntry],
    ports: &[u16],
    connect_timeout_ms: u64,
    concurrency: usize,
    cancel: Arc<AtomicBool>,
    progress: Option<ProgressSender>,
) -> Vec<String> {
    let total = enumerated_address_count(sources);
    let connect_timeout = Duration::from_millis(connect_timeout_ms.max(1));
    let mut open: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut attempted: u64 = 0;

    send_progress(
        progress.as_ref(),
        0,
        total,
        Some(&format!(
            "connect sweep started: {total} candidate address(es)"
        )),
    );

    let mut stream = futures::stream::iter(AddressEnumerator::new(sources))
        .take_while(|_| {
            let cancelled = cancel.load(Ordering::Relaxed);
            futures::future::ready(!cancelled)
        })
        .map(|addr| {
            let cancel = cancel.clone();
            async move {
                let mut reachable = false;
                if !cancel.load(Ordering::Relaxed) {
                    for port in ports {
                        if timeout(
                            connect_timeout,
                            TcpStream::connect(SocketAddr::new(addr, *port)),
                        )
                        .await
                        .is_ok()
                        {
                            reachable = true;
                            break;
                        }
                    }
                }
                (addr, reachable)
            }
        })
        .buffer_unordered(concurrency.max(1));

    while let Some((addr, reachable)) = stream.next().await {
        attempted = attempted.saturating_add(1);
        if reachable {
            open.insert(addr.to_string());
        }
        if attempted.is_multiple_of(1024) {
            send_progress(progress.as_ref(), attempted, total, None);
        }
    }

    send_progress(
        progress.as_ref(),
        attempted,
        total,
        Some(&format!(
            "discovery sweep complete: {} reachable address(es)",
            open.len()
        )),
    );
    open.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(s: &str) -> SourceEntry {
        parse_source(s).unwrap()
    }

    #[test]
    fn sources_parse_files_and_cidr_lists() {
        let path = std::env::temp_dir().join(format!("cleanscan-src-{}.txt", std::process::id()));
        std::fs::write(&path, "192.0.2.1\n# comment\n\n10.0.0.0/30\n").unwrap();
        let sources = parse_target_sources(
            Some(path.to_str().unwrap()),
            &["203.0.113.0/24".to_string()],
        )
        .unwrap();
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0], SourceEntry::Ip("192.0.2.1".parse().unwrap()));
        assert!(matches!(sources[1], SourceEntry::Net(_)));
        assert!(matches!(sources[2], SourceEntry::Net(_)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn empty_sources_error() {
        assert!(parse_target_sources(None, &["# nothing".to_string()]).is_err());
        assert!(parse_target_sources(None, &["not-an-ip".to_string()]).is_err());
    }

    #[test]
    fn host_counts_match_hosts_iteration() {
        for cidr in ["10.0.0.0/24", "10.0.0.0/30", "10.0.0.0/31", "10.0.0.1/32"] {
            let net = IpNet::from_str(cidr).unwrap();
            assert_eq!(net_host_count(&net) as usize, net.hosts().count(), "{cidr}");
        }
        let v6 = IpNet::from_str("fd00::/126").unwrap();
        assert_eq!(net_host_count(&v6), 4);
        // A full IPv6 /0 must not hang: the count is computed, not iterated.
        let v6_0 = IpNet::from_str("::/0").unwrap();
        assert_eq!(net_host_count(&v6_0), u128::MAX);
    }

    #[test]
    fn candidates_deduplicate_overlaps_and_ips() {
        let sources = vec![
            entry("10.0.0.5"),
            entry("10.0.0.0/30"),
            entry("10.0.0.0/24"),
            entry("10.0.0.9"),
            entry("10.0.1.0/24"),
        ];
        let candidates = collect_candidates(&sources);
        let as_strings: Vec<String> = candidates.iter().map(|ip| ip.to_string()).collect();
        assert_eq!(&as_strings[0..3], &["10.0.0.5", "10.0.0.1", "10.0.0.2"]);
        // Earlier sources win: the /24 sweeps .3 (the /30's broadcast, which
        // the /30 never yields but is a valid host of the /24) and .9; the
        // explicit IP sources and the /30's hosts are then skipped as already
        // covered. Every unique address is yielded exactly once.
        assert_eq!(candidates.len(), 1 + 2 + 251 + 254);
        for wanted in ["10.0.0.3", "10.0.0.5", "10.0.0.9", "10.0.1.1"] {
            let count = as_strings.iter().filter(|ip| ip.as_str() == wanted).count();
            assert_eq!(count, 1, "{wanted} must be yielded exactly once");
        }
        let unique: std::collections::BTreeSet<&String> = as_strings.iter().collect();
        assert_eq!(unique.len(), candidates.len());
    }

    #[tokio::test]
    async fn connect_sweep_finds_reachable_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Linux treats all of 127.0.0.0/8 as loopback, so a socket bound to
        // 127.0.0.1 also accepts connections addressed to 127.0.0.2 there.
        // A TEST-NET address (RFC 5737) is never local, so the unreachable
        // probe is deterministic on every platform.
        let sources = vec![entry("127.0.0.1"), entry("192.0.2.1")];
        let open = connect_sweep(
            &sources,
            &[port],
            300,
            4,
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .await;
        assert_eq!(open, vec!["127.0.0.1".to_string()]);
    }

    #[tokio::test]
    async fn connect_sweep_respects_cancellation() {
        let sources = vec![entry("192.0.2.0/24")];
        let cancel = Arc::new(AtomicBool::new(true));
        let open = connect_sweep(&sources, &[443], 100, 4, cancel, None).await;
        assert!(open.is_empty());
    }
}
