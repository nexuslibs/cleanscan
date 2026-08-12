use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSlice},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rustls::{pki_types::ServerName, ClientConfig};
#[cfg(not(target_os = "android"))]
use rustls_platform_verifier::ConfigVerifierExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
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
    /// Xray-style fragment spec applied for this check (`None` = off).
    #[serde(default)]
    pub fragment: Option<String>,
    /// Whether a plain HTTP GET over the TLS connection returned 2xx.
    #[serde(default)]
    pub http_ok: Option<bool>,
    /// Cloudflare datacenter code parsed from a `/cdn-cgi/trace` body.
    #[serde(default)]
    pub colo: Option<String>,
    pub elapsed_ms: f64,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Xray-style TLS fragmentation (port of XTLS/Xray-core `freedom.FragmentWriter`).
// The config model, JSON shape, random-length splitting, TLS record re-wrapping,
// and single-packet combine behavior all mirror xray's freedom outbound.
// ---------------------------------------------------------------------------

/// Xray-compatible integer range: JSON accepts `"100-200"`, `"5"`, or a plain
/// number; `from`/`to` are normalized to `from <= to` (xray's `ensureOrder`).
/// `""` parses as `(0, 0)` like xray's `ParseRangeString`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Int32Range {
    pub from: i32,
    pub to: i32,
}

impl Int32Range {
    pub const fn new(from: i32, to: i32) -> Self {
        if from <= to {
            Self { from, to }
        } else {
            Self { from: to, to: from }
        }
    }

    /// Parse a range string exactly like xray's `ParseRangeString`: a plain
    /// number, `""` (zero), or `"a-b"` (negatives supported).
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Ok(value) = s.parse::<i64>() {
            return Ok(Self::new(value as i32, value as i32));
        }
        if s.is_empty() {
            return Ok(Self::new(0, 0));
        }
        let (left, right) = if let Some(rest) = s.strip_prefix('-') {
            // "-114-514" or "-1919--810": split at the second dash.
            let Some(second) = rest.find('-') else {
                return Err(format!("invalid range string: {s:?}"));
            };
            (&s[..second + 1], &s[second + 2..])
        } else {
            let Some((left, right)) = s.split_once('-') else {
                return Err(format!("invalid range string: {s:?}"));
            };
            (left, right)
        };
        let left = left
            .parse::<i64>()
            .map_err(|_| format!("invalid range string: {s:?}"))?;
        let right = right
            .parse::<i64>()
            .map_err(|_| format!("invalid range string: {s:?}"))?;
        Ok(Self::new(left as i32, right as i32))
    }
}

impl std::fmt::Display for Int32Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.from == self.to {
            write!(f, "{}", self.from)
        } else {
            write!(f, "{}-{}", self.from, self.to)
        }
    }
}

impl Serialize for Int32Range {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RangeVisitor;
        impl<'de> serde::de::Visitor<'de> for RangeVisitor {
            type Value = Int32Range;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an integer range like \"100-200\", \"5\", or 5")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Int32Range::parse(value).map_err(E::custom)
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Int32Range::new(value as i32, value as i32))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Int32Range::new(value as i32, value as i32))
            }
        }
        deserializer.deserialize_any(RangeVisitor)
    }
}

/// Which writes are fragmented, mirroring xray's `fragment.packets`:
/// `"tlshello"` (first TLS ClientHello only), `""` (every TCP write), or a
/// write-count range such as `"1-3"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPackets {
    TlsHello,
    TcpAll,
    TcpRange { from: u32, to: u32 },
}

impl FragmentPackets {
    fn parse(s: &str) -> Result<Self, String> {
        let lowered = s.to_ascii_lowercase();
        match lowered.as_str() {
            "tlshello" => Ok(Self::TlsHello),
            "" => Ok(Self::TcpAll),
            _ => {
                let range = Int32Range::parse(&lowered)
                    .map_err(|_| format!("invalid packets value: {s:?}"))?;
                Ok(Self::TcpRange {
                    from: range.from.max(0) as u32,
                    to: range.to.max(0) as u32,
                })
            }
        }
    }
}

impl Serialize for FragmentPackets {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::TlsHello => serializer.serialize_str("tlshello"),
            Self::TcpAll => serializer.serialize_str(""),
            Self::TcpRange { from, to } => serializer.serialize_str(&format!("{from}-{to}")),
        }
    }
}

impl<'de> Deserialize<'de> for FragmentPackets {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Xray `freedom` outbound fragment settings, JSON-compatible with xray:
/// `{"packets":"tlshello","length":"100-200","interval":"10-20","maxSplit":"2"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentSpec {
    pub packets: FragmentPackets,
    pub length: Int32Range,
    pub interval: Int32Range,
    pub max_split: Option<Int32Range>,
}

impl FragmentSpec {
    /// Validate like xray's `freedom.go Build()`: length min must be > 0,
    /// interval must be present (0 allowed), packet ranges must not start at 0.
    pub fn validate(&self) -> Result<(), String> {
        if self.length.from <= 0 {
            return Err("length min must be greater than 0".to_string());
        }
        if self.interval.from < 0 || self.interval.to < 0 {
            return Err("interval must not be negative".to_string());
        }
        if let FragmentPackets::TcpRange { from, .. } = self.packets {
            if from == 0 {
                return Err("packets range cannot start at 0".to_string());
            }
        }
        Ok(())
    }

    /// Parse an xray fragment JSON block (the `fragment` object from a freedom
    /// outbound) and validate it.
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let spec: FragmentSpec =
            serde_json::from_str(raw).map_err(|error| format!("invalid fragment JSON: {error}"))?;
        spec.validate()?;
        Ok(spec)
    }

    /// Serialize to the exact xray JSON shape (for clipboard / CLI output).
    pub fn xray_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl Serialize for FragmentSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FragmentSpec", 4)?;
        state.serialize_field("packets", &self.packets)?;
        state.serialize_field("length", &self.length)?;
        state.serialize_field("interval", &self.interval)?;
        if let Some(max_split) = &self.max_split {
            state.serialize_field("maxSplit", max_split)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for FragmentSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            packets: FragmentPackets,
            length: Int32Range,
            interval: Int32Range,
            #[serde(rename = "maxSplit", default)]
            max_split: Option<Int32Range>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let spec = FragmentSpec {
            packets: raw.packets,
            length: raw.length,
            interval: raw.interval,
            max_split: raw.max_split,
        };
        spec.validate().map_err(serde::de::Error::custom)?;
        Ok(spec)
    }
}

/// Curated xray-style fragment profiles offered by the TUI tester. Each entry
/// is `(label, spec)`; the first entry (`None`) is the unfragmented control.
pub const TLS_FRAGMENT_PRESETS: &[(&str, Option<FragmentSpec>)] = &[
    ("Off (control)", None),
    (
        "1-1",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(1, 1),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "2-2",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(2, 2),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "4-4",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(4, 4),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "8-8",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(8, 8),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "16-16",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(16, 16),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "32-32",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(32, 32),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "64-64",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(64, 64),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "128-128",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(128, 128),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "256-256",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(256, 256),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "1-3 classic",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(1, 3),
            interval: Int32Range::new(0, 0),
            max_split: None,
        }),
    ),
    (
        "10-20 / 10-20ms (xray default)",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(10, 20),
            interval: Int32Range::new(10, 20),
            max_split: None,
        }),
    ),
    (
        "100-200 / 10-20ms",
        Some(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(100, 200),
            interval: Int32Range::new(10, 20),
            max_split: None,
        }),
    ),
];

/// xray `crypto.RandBetween`: `[min, max)` with equal values returning `min`
/// and reversed bounds swapped. Deterministic given the rng (for tests).
fn rand_between(rng: &mut impl Rng, from: u64, to: u64) -> u64 {
    if from == to {
        return from;
    }
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    from + rng.gen_range(0..to - from)
}

/// One queued fragment write: `delay_ms` is applied *before* the write so the
/// sleep lands between the previous fragment and this one (xray sleeps after
/// each fragment, including the last, before the tail).
struct FragmentItem {
    bytes: Vec<u8>,
    delay_ms: u64,
}

/// `AsyncWrite` wrapper that fragments outgoing writes exactly like xray's
/// `freedom.FragmentWriter`: `tlshello` splits the first TLS handshake record
/// into random-length fragments re-wrapped as complete TLS records (with an
/// optional per-fragment delay, or a single combined write when interval is
/// 0); `tcp` splits writes into random-length chunks.
pub struct FragmentWriter<S, R> {
    inner: S,
    spec: FragmentSpec,
    rng: R,
    /// Number of logical writes seen (xray's `f.count`).
    count: u64,
    queue: VecDeque<FragmentItem>,
    /// A delayed item popped from the queue, held while its sleep runs.
    pending: Option<FragmentItem>,
    current: Option<(Vec<u8>, usize)>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Set once `poll_write` returned `Ready` for the current logical write,
    /// so the next call can be recognized as a new write rather than a poll
    /// retry of the same buffer.
    flushed: bool,
    /// Trailing inter-fragment delay carried from a fragmented write into the
    /// first fragment of the next write (xray sleeps after the final chunk).
    carry_delay: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> FragmentWriter<S, R> {
    pub fn new(inner: S, spec: FragmentSpec, rng: R) -> Self {
        Self {
            inner,
            spec,
            rng,
            count: 0,
            queue: VecDeque::new(),
            pending: None,
            current: None,
            sleep: None,
            flushed: true,
            carry_delay: 0,
        }
    }

    /// Recover the wrapped inner stream (used by tests to inspect writes).
    #[cfg(test)]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Split `buf` into queue items for one logical write, mirroring xray's
    /// `FragmentWriter.Write`.
    fn push_items(&mut self, buf: &[u8]) {
        self.count += 1;
        if self.spec.packets == FragmentPackets::TlsHello
            && self.count == 1
            && buf.len() > 5
            && buf[0] == 22
        {
            let record_len = 5 + (((buf[3] as usize) << 8) | buf[4] as usize);
            if buf.len() >= record_len {
                self.push_tlshello(buf, record_len);
                self.apply_carry();
                return;
            }
        }
        let in_range = match self.spec.packets {
            FragmentPackets::TlsHello | FragmentPackets::TcpAll => true,
            FragmentPackets::TcpRange { from, to } => {
                self.count >= u64::from(from) && self.count <= u64::from(to)
            }
        };
        if self.spec.packets != FragmentPackets::TlsHello && in_range {
            self.push_tcp(buf);
        } else {
            self.queue.push_back(FragmentItem {
                bytes: buf.to_vec(),
                delay_ms: 0,
            });
        }
        self.apply_carry();
    }

    fn apply_carry(&mut self) {
        if self.carry_delay > 0 {
            if let Some(first) = self.queue.front_mut() {
                first.delay_ms = first.delay_ms.saturating_add(self.carry_delay);
            }
            self.carry_delay = 0;
        }
    }

    /// xray `tlshello` path: split the first TLS record's payload into
    /// random-length fragments, each re-wrapped in a complete TLS record
    /// (original content type/version, fresh 2-byte length). Interval 0
    /// concatenates all fragment records into a single write ("single TLS
    /// hello fragmenting", xray PR #3660); otherwise each fragment is its own
    /// write with a random delay between them, then the record tail.
    fn push_tlshello(&mut self, buf: &[u8], record_len: usize) {
        let data = &buf[5..record_len];
        let length = self.spec.length;
        let interval = self.spec.interval;
        let max_split = match self.spec.max_split {
            Some(range) => rand_between(
                &mut self.rng,
                range.from.max(0) as u64,
                range.to.max(0) as u64,
            ),
            None => 0,
        };
        let combine = interval.to.max(0) == 0;
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        let mut pending_delay = 0u64;
        let mut combined: Vec<u8> = Vec::new();
        loop {
            let length_min = length.from.max(1) as u64;
            let length_max = length.to.max(1) as u64;
            let mut to =
                from.saturating_add(rand_between(&mut self.rng, length_min, length_max) as usize);
            split_num += 1;
            if to > data.len() || (max_split > 0 && split_num >= max_split) {
                to = data.len();
            }
            let l = to - from;
            let mut fragment = Vec::with_capacity(5 + l);
            fragment.extend_from_slice(&buf[..3]);
            fragment.push((l >> 8) as u8);
            fragment.push(l as u8);
            fragment.extend_from_slice(&data[from..to]);
            from = to;
            if combine {
                combined.extend_from_slice(&fragment);
            } else {
                let delay = rand_between(
                    &mut self.rng,
                    interval.from.max(0) as u64,
                    interval.to.max(0) as u64,
                );
                self.queue.push_back(FragmentItem {
                    bytes: fragment,
                    delay_ms: pending_delay,
                });
                pending_delay = delay;
            }
            if from == data.len() {
                if !combine && buf.len() > record_len {
                    self.queue.push_back(FragmentItem {
                        bytes: buf[record_len..].to_vec(),
                        delay_ms: pending_delay,
                    });
                }
                break;
            }
        }
        if combine {
            if !combined.is_empty() {
                self.queue.push_back(FragmentItem {
                    bytes: combined,
                    delay_ms: 0,
                });
            }
            if buf.len() > record_len {
                self.queue.push_back(FragmentItem {
                    bytes: buf[record_len..].to_vec(),
                    delay_ms: 0,
                });
            }
        }
    }

    /// xray `tcp` path: split the write into random-length chunks with delays
    /// between them, capped by `maxSplit`.
    fn push_tcp(&mut self, buf: &[u8]) {
        let length = self.spec.length;
        let interval = self.spec.interval;
        let max_split = match self.spec.max_split {
            Some(range) => rand_between(
                &mut self.rng,
                range.from.max(0) as u64,
                range.to.max(0) as u64,
            ),
            None => 0,
        };
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        let mut pending_delay = 0u64;
        while from < buf.len() {
            let length_min = length.from.max(1) as u64;
            let length_max = length.to.max(1) as u64;
            let mut to =
                from.saturating_add(rand_between(&mut self.rng, length_min, length_max) as usize);
            split_num += 1;
            if to > buf.len() || (max_split > 0 && split_num >= max_split) {
                to = buf.len();
            }
            let chunk = buf[from..to].to_vec();
            from = to;
            let delay = rand_between(
                &mut self.rng,
                interval.from.max(0) as u64,
                interval.to.max(0) as u64,
            );
            self.queue.push_back(FragmentItem {
                bytes: chunk,
                delay_ms: pending_delay,
            });
            pending_delay = delay;
        }
        self.carry_delay = pending_delay;
    }
}

/// Result of draining the fragment queue without blocking on the caller's buf.
enum DrainOutcome {
    Drained,
    Pending,
    Error(io::Error),
}

/// Write queued fragments (and the armed inter-fragment sleep) to the inner
/// stream until nothing is left, the sleep is pending, or the inner stream
/// blocks. The incoming `buf` is not touched: poll retries pass the same
/// logical write, whose bytes are already in the queue.
fn drain_queue<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin>(
    this: &mut FragmentWriter<S, R>,
    cx: &mut Context<'_>,
) -> DrainOutcome {
    loop {
        if let Some(sleep) = this.sleep.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return DrainOutcome::Pending;
            }
            this.sleep = None;
        }
        if let Some(item) = this.pending.take() {
            this.current = Some((item.bytes, 0));
            continue;
        }
        if let Some((bytes, written)) = this.current.as_mut() {
            while *written < bytes.len() {
                let slice = &bytes[*written..];
                match Pin::new(&mut this.inner).poll_write(cx, slice) {
                    Poll::Ready(Ok(0)) => {
                        return DrainOutcome::Error(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "fragment writer: zero-length write",
                        ))
                    }
                    Poll::Ready(Ok(n)) => *written += n,
                    Poll::Pending => return DrainOutcome::Pending,
                    Poll::Ready(Err(error)) => return DrainOutcome::Error(error),
                }
            }
            this.current = None;
            continue;
        }
        if let Some(item) = this.queue.pop_front() {
            if item.delay_ms > 0 {
                this.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                    item.delay_ms,
                ))));
                this.pending = Some(item);
            } else {
                this.current = Some((item.bytes, 0));
            }
            continue;
        }
        return DrainOutcome::Drained;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncWrite for FragmentWriter<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Finish any fragments of the current logical write first. While they
        // are pending, `buf` is a poll retry of the same slice whose bytes are
        // already enqueued, so it must not be re-enqueued.
        match drain_queue(this, cx) {
            DrainOutcome::Pending => return Poll::Pending,
            DrainOutcome::Error(error) => return Poll::Ready(Err(error)),
            DrainOutcome::Drained => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.flushed {
            // The previous logical write was fully flushed, so this is a new
            // write: fragment it and flush those fragments too.
            this.flushed = false;
            this.push_items(buf);
            match drain_queue(this, cx) {
                DrainOutcome::Pending => return Poll::Pending,
                DrainOutcome::Error(error) => return Poll::Ready(Err(error)),
                DrainOutcome::Drained => {}
            }
        }
        this.flushed = true;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let buf = bufs
            .iter()
            .flat_map(|slice| slice.iter())
            .copied()
            .collect::<Vec<_>>();
        self.poll_write(cx, &buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncRead for FragmentWriter<S, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
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

pub(crate) fn client_config() -> Result<ClientConfig, rustls::Error> {
    #[cfg(target_os = "android")]
    {
        let mut roots = rustls::RootCertStore::empty();
        for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            roots.add(der.clone())?;
        }
        Ok(ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth())
    }
    #[cfg(not(target_os = "android"))]
    {
        ClientConfig::with_platform_verifier()
    }
}

pub(crate) fn apply_rustls_backend(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    #[cfg(target_os = "android")]
    {
        builder
            .tls_backend_preconfigured(client_config().expect("failed to build Android TLS config"))
    }
    #[cfg(not(target_os = "android"))]
    {
        builder
    }
}

fn tls_config() -> Result<TlsConnector> {
    static CONNECTOR: OnceLock<std::result::Result<TlsConnector, String>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            client_config()
                .map(|config| TlsConnector::from(Arc::new(config)))
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(|error| anyhow!(error))
}

/// Trait-object bound for the connection stream (a bare `TcpStream` or a
/// `FragmentWriter` wrapped around one), so both TLS paths share one type.
trait BoxedIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BoxedIo for T {}

type BoxedStream = Box<dyn BoxedIo>;

/// Probe one candidate IP with an optional xray-style fragment spec. With a
/// spec, the TCP stream is wrapped in a [`FragmentWriter`] before the TLS
/// handshake; for TCP transports a plain HTTP GET probe runs after the
/// handshake so a result means the connection works end to end, not just that
/// TLS completed.
pub async fn check_candidate_fragmented(
    transport: &ProxyTransport,
    ip: &str,
    timeout_ms: u64,
    interface: Option<crate::iface::InterfaceAddrs>,
    fragment: Option<&FragmentSpec>,
) -> SurvivabilityResult {
    let started = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms.max(500));
    let addr = match ip.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, transport.port),
        Err(e) => {
            return failed(
                ip,
                transport,
                fragment,
                started,
                format!("invalid candidate IP: {e}"),
            )
        }
    };
    let stream = match timeout(
        timeout_duration,
        crate::iface::bind_connect(addr, interface),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return failed(
                ip,
                transport,
                fragment,
                started,
                format!("TCP connect: {e}"),
            )
        }
        Err(_) => {
            return failed(
                ip,
                transport,
                fragment,
                started,
                "TCP connect timed out".into(),
            )
        }
    };
    let _ = stream.set_nodelay(true);
    let mut result = SurvivabilityResult {
        ip: ip.into(),
        port: transport.port,
        network: transport.network.clone(),
        tcp_ok: true,
        tls_ok: !transport.tls,
        long_tls_ok: false,
        websocket_reached: None,
        websocket_accepted: None,
        fragment: if transport.tls {
            fragment.map(FragmentSpec::xray_json)
        } else {
            None
        },
        http_ok: None,
        colo: None,
        elapsed_ms: 0.0,
        error: None,
    };
    if transport.tls {
        let handshake = async {
            let name = ServerName::try_from(transport.sni.to_string())
                .map_err(|_| anyhow!("invalid TLS SNI"))?;
            let stream: BoxedStream = match fragment {
                Some(spec) => Box::new(FragmentWriter::new(
                    stream,
                    spec.clone(),
                    StdRng::from_entropy(),
                )),
                None => Box::new(stream),
            };
            Ok::<_, anyhow::Error>(tls_config()?.connect(name, stream).await?)
        };
        match timeout(timeout_duration, handshake).await {
            Ok(Ok(mut tls)) => {
                result.tls_ok = true;
                result.long_tls_ok = idle_hold(&mut tls, timeout_duration).await;
                if transport.network == "ws" {
                    let (reached, accepted) =
                        websocket_probe(&mut tls, transport, timeout_duration).await;
                    result.websocket_reached = Some(reached);
                    result.websocket_accepted = Some(accepted);
                } else {
                    let (reached, colo) = http_probe(&mut tls, transport, timeout_duration).await;
                    result.http_ok = Some(reached);
                    result.colo = colo;
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

/// Plain HTTP/1.1 GET over an established TLS connection. Returns whether a
/// 2xx response arrived and the Cloudflare colo parsed from the body.
async fn http_probe<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
    transport: &ProxyTransport,
    duration: Duration,
) -> (bool, Option<String>) {
    let host = transport.host.as_deref().unwrap_or(&transport.sni);
    let path = transport.path.as_deref().unwrap_or("/");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: cleanscan/0.1\r\nAccept: */*\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return (false, None);
    }
    let mut response = vec![0u8; 16_384];
    let Ok(Ok(size)) = timeout(duration, stream.read(&mut response)).await else {
        return (false, None);
    };
    if size == 0 {
        return (false, None);
    }
    let text = String::from_utf8_lossy(&response[..size]);
    let status_ok = text.starts_with("HTTP/1.1 2")
        || text.starts_with("HTTP/1.0 2")
        || text.starts_with("HTTP/2 2");
    (status_ok, crate::scanner::parse_colo(&text))
}

async fn idle_hold<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
    duration: Duration,
) -> bool {
    let mut byte = [0u8; 1];
    match timeout(duration.min(Duration::from_secs(2)), stream.read(&mut byte)).await {
        Err(_) => true,
        Ok(Ok(0)) | Ok(Err(_)) => false,
        Ok(Ok(_)) => true,
    }
}

async fn websocket_probe<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
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
    fragment: Option<&FragmentSpec>,
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
        fragment: if transport.tls {
            fragment.map(FragmentSpec::xray_json)
        } else {
            None
        },
        http_ok: None,
        colo: None,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_share_url, rand_between, FragmentPackets, FragmentSpec, FragmentWriter, Int32Range,
        TLS_FRAGMENT_PRESETS,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn int32_range_parses_like_xray() {
        assert_eq!(Int32Range::parse("5").unwrap(), Int32Range::new(5, 5));
        assert_eq!(Int32Range::parse("").unwrap(), Int32Range::new(0, 0));
        assert_eq!(Int32Range::parse("1-2").unwrap(), Int32Range::new(1, 2));
        assert_eq!(
            Int32Range::parse("114-514").unwrap(),
            Int32Range::new(114, 514)
        );
        assert_eq!(
            Int32Range::parse("-114-514").unwrap(),
            Int32Range::new(-114, 514)
        );
        assert_eq!(
            Int32Range::parse("-1919--810").unwrap(),
            Int32Range::new(-1919, -810)
        );
        // Reversed bounds are exchanged like xray's ensureOrder.
        assert_eq!(
            Int32Range::parse("200-100").unwrap(),
            Int32Range::new(100, 200)
        );
        assert!(Int32Range::parse("abc").is_err());
        assert!(Int32Range::parse("1-2-3").is_err());
    }

    #[test]
    fn int32_range_json_matches_xray() {
        assert_eq!(
            serde_json::to_string(&Int32Range::new(5, 5)).unwrap(),
            "\"5\""
        );
        assert_eq!(
            serde_json::to_string(&Int32Range::new(10, 20)).unwrap(),
            "\"10-20\""
        );
        assert_eq!(
            serde_json::from_str::<Int32Range>("\"10-20\"").unwrap(),
            Int32Range::new(10, 20)
        );
        assert_eq!(
            serde_json::from_str::<Int32Range>("7").unwrap(),
            Int32Range::new(7, 7)
        );
        assert!(serde_json::from_str::<Int32Range>("\"abc\"").is_err());
    }

    #[test]
    fn fragment_spec_json_round_trips_like_xray() {
        let raw = r#"{"packets":"tlshello","length":"100-200","interval":"10-20"}"#;
        let spec = FragmentSpec::parse_json(raw).unwrap();
        assert_eq!(spec.packets, FragmentPackets::TlsHello);
        assert_eq!(spec.length, Int32Range::new(100, 200));
        assert_eq!(spec.interval, Int32Range::new(10, 20));
        assert_eq!(spec.max_split, None);
        // Serialization skips maxSplit and keeps xray's string ranges.
        assert_eq!(spec.xray_json(), raw);

        let with_split = FragmentSpec::parse_json(
            r#"{"packets":"","length":"10","interval":"0","maxSplit":"2"}"#,
        )
        .unwrap();
        assert_eq!(with_split.packets, FragmentPackets::TcpAll);
        assert_eq!(
            with_split.xray_json(),
            r#"{"packets":"","length":"10","interval":"0","maxSplit":"2"}"#
        );

        let ranged =
            FragmentSpec::parse_json(r#"{"packets":"1-3","length":"8-16","interval":"5"}"#)
                .unwrap();
        assert_eq!(ranged.packets, FragmentPackets::TcpRange { from: 1, to: 3 });
        assert_eq!(
            ranged.xray_json(),
            r#"{"packets":"1-3","length":"8-16","interval":"5"}"#
        );
    }

    #[test]
    fn fragment_spec_validation_mirrors_freedom_build() {
        assert!(FragmentSpec::parse_json(
            r#"{"packets":"tlshello","length":"0-10","interval":"0"}"#
        )
        .is_err());
        assert!(FragmentSpec::parse_json(
            r#"{"packets":"tlshello","length":"10-20","interval":"-1"}"#
        )
        .is_err());
        assert!(
            FragmentSpec::parse_json(r#"{"packets":"0-3","length":"10-20","interval":"0"}"#)
                .is_err()
        );
        assert!(FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"10-20"}"#).is_err());
        assert!(FragmentSpec::parse_json(r#"not json"#).is_err());
    }

    #[test]
    fn rand_between_matches_xray_semantics() {
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(rand_between(&mut rng, 5, 5), 5);
        assert_eq!(rand_between(&mut rng, 0, 0), 0);
        for _ in 0..100 {
            let value = rand_between(&mut rng, 10, 20);
            assert!((10..20).contains(&value));
            let swapped = rand_between(&mut rng, 20, 10);
            assert!((10..20).contains(&swapped));
        }
    }

    #[test]
    fn presets_are_valid_xray_specs() {
        assert_eq!(TLS_FRAGMENT_PRESETS[0].0, "Off (control)");
        assert!(TLS_FRAGMENT_PRESETS[0].1.is_none());
        for (label, spec) in &TLS_FRAGMENT_PRESETS[1..] {
            let spec = spec.as_ref().unwrap();
            spec.validate().unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(spec.packets, FragmentPackets::TlsHello);
            assert!(spec.length.from > 0);
        }
    }

    /// Write a fake TLS handshake record through a `FragmentWriter` and
    /// return the exact bytes the other end of a duplex receives.
    async fn write_through(spec: FragmentSpec, payload: &[u8]) -> Vec<u8> {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut writer = FragmentWriter::new(client, spec, StdRng::seed_from_u64(42));
        writer.write_all(payload).await.unwrap();
        drop(writer);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        received
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, payload.len() as u8];
        record.extend_from_slice(payload);
        record
    }

    fn frag_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, payload.len() as u8];
        record.extend_from_slice(payload);
        record
    }

    #[tokio::test]
    async fn tlshello_combine_mode_rewraps_each_fragment_as_a_tls_record() {
        // length 1-1, interval 0: every ClientHello byte becomes its own TLS
        // record, all concatenated into a single write (xray PR #3660 mode).
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"1-1","interval":"0"}"#)
                .unwrap();
        let received = write_through(spec, &tls_record(b"hello")).await;
        let mut expected = Vec::new();
        for byte in b"hello" {
            expected.extend_from_slice(&frag_record(&[*byte]));
        }
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tlshello_splits_into_fixed_chunks_and_writes_tail() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"3-3","interval":"0"}"#)
                .unwrap();
        let mut record = tls_record(b"hello");
        record.extend_from_slice(b"tail");
        let received = write_through(spec, &record).await;
        let mut expected = frag_record(b"hel");
        expected.extend_from_slice(&frag_record(b"lo"));
        expected.extend_from_slice(b"tail");
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tlshello_max_split_caps_fragment_count() {
        let spec = FragmentSpec::parse_json(
            r#"{"packets":"tlshello","length":"1-1","interval":"0","maxSplit":"2"}"#,
        )
        .unwrap();
        let received = write_through(spec, &tls_record(b"hello")).await;
        let mut expected = frag_record(b"h");
        expected.extend_from_slice(&frag_record(b"ello"));
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tlshello_interval_mode_keeps_records_separate_with_delays() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"2-2","interval":"1-1"}"#)
                .unwrap();
        let received = write_through(spec, &tls_record(b"hello")).await;
        let mut expected = frag_record(b"he");
        expected.extend_from_slice(&frag_record(b"ll"));
        expected.extend_from_slice(&frag_record(b"o"));
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tlshello_leaves_non_handshake_first_writes_untouched() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"1-1","interval":"0"}"#)
                .unwrap();
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let received = write_through(spec, payload).await;
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn tlshello_only_fragments_the_first_write() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"1-1","interval":"0"}"#)
                .unwrap();
        let (client, mut server) = tokio::io::duplex(4096);
        let mut writer = FragmentWriter::new(client, spec, StdRng::seed_from_u64(42));
        writer.write_all(&tls_record(b"hello")).await.unwrap();
        // Second write passes through completely unfragmented.
        writer.write_all(b"plain").await.unwrap();
        drop(writer);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        let mut expected = Vec::new();
        for byte in b"hello" {
            expected.extend_from_slice(&frag_record(&[*byte]));
        }
        expected.extend_from_slice(b"plain");
        assert_eq!(received, expected);
    }

    /// Records the exact slices the inner writer receives, so split boundaries
    /// are observable without real TCP segmentation.
    struct SliceRecorder {
        slices: Vec<Vec<u8>>,
    }

    impl tokio::io::AsyncWrite for SliceRecorder {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.get_mut().slices.push(buf.to_vec());
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncRead for SliceRecorder {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn tcp_mode_emits_one_inner_write_per_chunk() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"","length":"2-2","interval":"0"}"#).unwrap();
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = FragmentWriter::new(recorder, spec, StdRng::seed_from_u64(42));
        writer.write_all(b"abcdef").await.unwrap();
        let recorder = writer.into_inner();
        assert_eq!(
            recorder.slices,
            vec![b"ab".to_vec(), b"cd".to_vec(), b"ef".to_vec()]
        );
    }

    #[tokio::test]
    async fn combine_mode_emits_a_single_inner_write() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"2-2","interval":"0"}"#)
                .unwrap();
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = FragmentWriter::new(recorder, spec, StdRng::seed_from_u64(42));
        writer.write_all(&tls_record(b"hello")).await.unwrap();
        let recorder = writer.into_inner();
        // Interval 0: all fragment records concatenated into one write.
        assert_eq!(recorder.slices.len(), 1);
        let mut expected = frag_record(b"he");
        expected.extend_from_slice(&frag_record(b"ll"));
        expected.extend_from_slice(&frag_record(b"o"));
        assert_eq!(recorder.slices[0], expected);
    }

    #[tokio::test]
    async fn interval_mode_emits_one_inner_write_per_fragment() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"2-2","interval":"1-1"}"#)
                .unwrap();
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = FragmentWriter::new(recorder, spec, StdRng::seed_from_u64(42));
        writer.write_all(&tls_record(b"hello")).await.unwrap();
        let recorder = writer.into_inner();
        assert_eq!(
            recorder.slices,
            vec![frag_record(b"he"), frag_record(b"ll"), frag_record(b"o"),]
        );
    }
}
