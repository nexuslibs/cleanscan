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

/// One stage of a v2rayNG-style multi-stage stream fragment, JSON shape:
/// `{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],
/// "delays":["0"],"maxSplit":"0"}}`.
///
/// Port of xray-core `transport/internet/finalmask/fragment` semantics:
/// - `packets` picks which writes this stage splits (`tlshello` = first TLS
///   ClientHello record only, `""` = every write, `"1-1"` = write count range);
/// - `lengths` / `delays` are per-segment patterns whose **last entry repeats**
///   (xray's `lengthForSegment` clamping), each entry a range like `"5"` or
///   `"8-16"`;
/// - a `tlshello` stage re-wraps payload chunks as complete TLS records; when
///   `delays` is a single zero entry the whole hello is merged into one write;
/// - `max_split` caps the segment count (the capped segment takes the rest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentStage {
    pub packets: FragmentPackets,
    pub lengths: &'static [Int32Range],
    pub delays: &'static [Int32Range],
    pub max_split: Option<Int32Range>,
}

/// A TLS-fragmentation profile: a single xray `freedom` fragment
/// ([`FragmentSpec`]) or a multi-stage v2rayNG-style stream fragment config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentProfile {
    Xray(FragmentSpec),
    V2rayNg { stages: &'static [FragmentStage] },
}

impl FragmentProfile {
    /// Serialize to the exact JSON pasted into xray / v2rayNG: the freedom
    /// fragment object for [`FragmentProfile::Xray`], the `{"tcp":[...]}`
    /// stream-fragment config for [`FragmentProfile::V2rayNg`].
    pub fn xray_json(&self) -> String {
        match self {
            FragmentProfile::Xray(spec) => spec.xray_json(),
            FragmentProfile::V2rayNg { stages } => {
                let items = stages
                    .iter()
                    .map(|stage| {
                        format!(
                            "{{\"type\":\"fragment\",\"settings\":{{\"packets\":{},\"lengths\":{},\"delays\":{},\"maxSplit\":{}}}}}",
                            serde_json::to_string(&stage.packets).unwrap_or_default(),
                            serde_json::to_string(
                                &stage
                                    .lengths
                                    .iter()
                                    .map(Int32Range::to_string)
                                    .collect::<Vec<_>>()
                            )
                            .unwrap_or_default(),
                            serde_json::to_string(
                                &stage
                                    .delays
                                    .iter()
                                    .map(Int32Range::to_string)
                                    .collect::<Vec<_>>()
                            )
                            .unwrap_or_default(),
                            serde_json::to_string(
                                &stage
                                    .max_split
                                    .map(|r| r.to_string())
                                    .unwrap_or_else(|| "0".to_string())
                            )
                            .unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{\"tcp\":[{items}]}}")
            }
        }
    }
}

/// The well-known two-stage Cloudflare fragment: split the ClientHello into
/// 5/94/1-byte TLS records (delay 0 → one merged write), then re-split the
/// first write into 109/1-byte chunks with 1 ms pauses (max 355 segments).
pub const DOUBLE_FRAGMENT_STAGES: &[FragmentStage] = &[
    FragmentStage {
        packets: FragmentPackets::TlsHello,
        lengths: &[
            Int32Range::new(5, 5),
            Int32Range::new(94, 94),
            Int32Range::new(1, 1),
        ],
        delays: &[Int32Range::new(0, 0)],
        max_split: Some(Int32Range::new(0, 0)),
    },
    FragmentStage {
        packets: FragmentPackets::TcpRange { from: 1, to: 1 },
        lengths: &[Int32Range::new(109, 109), Int32Range::new(1, 1)],
        delays: &[Int32Range::new(1, 1)],
        max_split: Some(Int32Range::new(355, 355)),
    },
];

/// Curated fragment profiles offered by the TUI tester. Each entry is
/// `(label, profile)`; the first entry (`None`) is the unfragmented control.
pub const TLS_FRAGMENT_PRESETS: &[(&str, Option<FragmentProfile>)] = &[
    ("Off (control)", None),
    (
        "1-1",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(1, 1),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "2-2",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(2, 2),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "4-4",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(4, 4),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "8-8",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(8, 8),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "16-16",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(16, 16),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "32-32",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(32, 32),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "64-64",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(64, 64),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "128-128",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(128, 128),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "256-256",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(256, 256),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "1-3 classic",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(1, 3),
            interval: Int32Range::new(0, 0),
            max_split: None,
        })),
    ),
    (
        "10-20 / 10-20ms (xray default)",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(10, 20),
            interval: Int32Range::new(10, 20),
            max_split: None,
        })),
    ),
    (
        "100-200 / 10-20ms",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(100, 200),
            interval: Int32Range::new(10, 20),
            max_split: None,
        })),
    ),
    (
        "5/94/1 + 109/1 (double)",
        Some(FragmentProfile::V2rayNg {
            stages: DOUBLE_FRAGMENT_STAGES,
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
    /// Length of the logical write whose fragments are currently enqueued;
    /// poll retries must pass the same buffer.
    write_len: usize,
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
            write_len: 0,
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
        // Save any delay carried from the previous write's final fragment and
        // clear the slot before enqueuing: push_tcp stores the current write's
        // own trailing delay there for the next write.
        let carried = std::mem::take(&mut self.carry_delay);
        self.write_len = buf.len();
        self.count += 1;
        if self.spec.packets == FragmentPackets::TlsHello
            && self.count == 1
            && buf.len() > 5
            && buf[0] == 22
        {
            let record_len = 5 + (((buf[3] as usize) << 8) | buf[4] as usize);
            if buf.len() >= record_len {
                self.push_tlshello(buf, record_len);
                self.apply_carry(carried);
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
        self.apply_carry(carried);
    }

    /// Apply a delay carried from the previous write's final fragment to the
    /// first item of the write just enqueued, so the trailing sleep of a
    /// fragmented write lands between writes instead of inside the write that
    /// produced it.
    fn apply_carry(&mut self, carry_delay: u64) {
        if carry_delay > 0 {
            if let Some(first) = self.queue.front_mut() {
                first.delay_ms = first.delay_ms.saturating_add(carry_delay);
            }
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
        if !this.flushed && buf.len() != this.write_len {
            // A poll retry must carry the same logical write: the previous
            // buffer's bytes are already enqueued, so accepting a different
            // buffer here would silently drop it.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fragment writer: poll retry passed a buffer of a different \
                 length than the write being drained",
            )));
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

/// Clamp a per-segment pattern lookup to the last entry, mirroring xray's
/// `lengthForSegment` / `delayForSegment` (`(min, max)` in ms or bytes).
fn clamped_range(list: &[Int32Range], index: u64) -> (u64, u64) {
    let Some(range) = list.last() else {
        return (1, 1);
    };
    let range = if index as usize >= list.len() {
        range
    } else {
        &list[index as usize]
    };
    (range.from.max(0) as u64, range.to.max(0) as u64)
}

/// Whether a write at `count` (1-based, per-stage) matches a stage's
/// `packets` gate, mirroring xray's `fragmentConn.Write` dispatch.
fn stage_matches(stage: &FragmentStage, data: &[u8], count: u64) -> bool {
    match stage.packets {
        FragmentPackets::TlsHello => {
            count == 1
                && data.len() > 5
                && data[0] == 22
                && data.len() >= 5 + (((data[3] as usize) << 8) | data[4] as usize)
        }
        FragmentPackets::TcpAll => true,
        FragmentPackets::TcpRange { from, to } => {
            count >= u64::from(from) && count <= u64::from(to)
        }
    }
}

/// Split `data` into `(bytes, delay_ms)` segments per one stage, plus the
/// trailing delay carried after the final segment (xray sleeps after every
/// segment, including the last). The `tlshello` path re-wraps payload chunks
/// as TLS records and merges them into a single write when `delays` is one
/// zero entry, exactly like xray's `mergeTlsHelloSegments`.
fn split_stage(
    rng: &mut impl Rng,
    stage: &FragmentStage,
    data: &[u8],
) -> (Vec<(Vec<u8>, u64)>, u64) {
    let max_split = match stage.max_split {
        Some(range) => rand_between(rng, range.from.max(0) as u64, range.to.max(0) as u64),
        None => 0,
    };
    if stage.packets == FragmentPackets::TlsHello {
        let record_len = 5 + (((data[3] as usize) << 8) | data[4] as usize);
        let payload = &data[5..record_len];
        let merge = stage.delays.len() == 1 && stage.delays[0].to.max(0) == 0;
        let mut segments: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut merged: Vec<u8> = Vec::new();
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        let mut pending_delay = 0u64;
        while from < payload.len() {
            let (length_min, length_max) = clamped_range(stage.lengths, split_num);
            let mut to = from.saturating_add(rand_between(rng, length_min, length_max) as usize);
            if to > payload.len() || (max_split > 0 && split_num + 1 >= max_split) {
                to = payload.len();
            }
            let len = to - from;
            let mut fragment = Vec::with_capacity(5 + len);
            fragment.extend_from_slice(&data[..3]);
            fragment.push((len >> 8) as u8);
            fragment.push(len as u8);
            fragment.extend_from_slice(&payload[from..to]);
            from = to;
            if merge {
                merged.extend_from_slice(&fragment);
            } else {
                segments.push((fragment, pending_delay));
                let (delay_min, delay_max) = clamped_range(stage.delays, split_num);
                pending_delay = rand_between(rng, delay_min, delay_max);
            }
            split_num += 1;
        }
        if payload.is_empty() {
            if merge {
                merged.extend_from_slice(&data[..5]);
            } else {
                segments.push((data[..5].to_vec(), pending_delay));
            }
        }
        if merge {
            let mut out = Vec::new();
            if !merged.is_empty() {
                out.push((merged, 0));
            }
            if data.len() > record_len {
                out.push((data[record_len..].to_vec(), 0));
            }
            (out, 0)
        } else {
            (segments, pending_delay)
        }
    } else {
        let mut segments: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        let mut pending_delay = 0u64;
        while from < data.len() {
            let (length_min, length_max) = clamped_range(stage.lengths, split_num);
            let mut to = from.saturating_add(rand_between(rng, length_min, length_max) as usize);
            if to > data.len() || (max_split > 0 && split_num + 1 >= max_split) {
                to = data.len();
            }
            segments.push((data[from..to].to_vec(), pending_delay));
            from = to;
            let (delay_min, delay_max) = clamped_range(stage.delays, split_num);
            pending_delay = rand_between(rng, delay_min, delay_max);
            split_num += 1;
        }
        (segments, pending_delay)
    }
}

/// Multi-stage stream fragmentation, a port of xray-core
/// `transport/internet/finalmask/fragment.fragmentConn`: stages run in order,
/// each seeing the writes emitted by the previous stage with its own write
/// counter, so a second stage with `packets: "1-1"` re-splits the first write
/// of the stream below it (e.g. the merged TLS-hello burst).
pub struct FinalMaskWriter<S, R> {
    inner: S,
    stages: &'static [FragmentStage],
    rng: R,
    counts: Vec<u64>,
    carries: Vec<u64>,
    queue: VecDeque<FragmentItem>,
    pending: Option<FragmentItem>,
    current: Option<(Vec<u8>, usize)>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    flushed: bool,
    write_len: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> FinalMaskWriter<S, R> {
    pub fn new(inner: S, stages: &'static [FragmentStage], rng: R) -> Self {
        Self {
            inner,
            stages,
            rng,
            counts: vec![0; stages.len()],
            carries: vec![0; stages.len()],
            queue: VecDeque::new(),
            pending: None,
            current: None,
            sleep: None,
            flushed: true,
            write_len: 0,
        }
    }

    /// Transform one logical write through every stage into the final
    /// `(bytes, delay_ms)` queue items. Each stage sees the writes the
    /// previous stage emitted (its own counter), and a stage's trailing delay
    /// lands before the next item it processes, exactly like chained
    /// `fragmentConn.Write` calls on the wire.
    fn push_write(&mut self, buf: &[u8]) {
        self.write_len = buf.len();
        let mut items: Vec<(Vec<u8>, u64)> = vec![(buf.to_vec(), 0)];
        for (stage_index, stage) in self.stages.iter().enumerate() {
            let mut carry = self.carries[stage_index];
            let mut out: Vec<(Vec<u8>, u64)> = Vec::new();
            for (data, delay) in items {
                self.counts[stage_index] += 1;
                if stage_matches(stage, &data, self.counts[stage_index]) {
                    let (segments, trailing) = split_stage(&mut self.rng, stage, &data);
                    let mut first = true;
                    for (bytes, segment_delay) in segments {
                        if first {
                            out.push((
                                bytes,
                                delay.saturating_add(carry).saturating_add(segment_delay),
                            ));
                            first = false;
                        } else {
                            out.push((bytes, segment_delay));
                        }
                    }
                    carry = trailing;
                } else {
                    out.push((data, delay.saturating_add(carry)));
                    carry = 0;
                }
            }
            self.carries[stage_index] = carry;
            items = out;
        }
        for (bytes, delay_ms) in items {
            self.queue.push_back(FragmentItem { bytes, delay_ms });
        }
    }
}

/// Write queued multi-stage fragments (and the armed inter-fragment sleep) to
/// the inner stream until nothing is left, the sleep is pending, or the inner
/// stream blocks. The incoming `buf` is not touched: poll retries pass the
/// same logical write, whose bytes are already in the queue.
fn drain_stage_queue<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin>(
    this: &mut FinalMaskWriter<S, R>,
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
                            "finalmask writer: zero-length write",
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

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncWrite for FinalMaskWriter<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match drain_stage_queue(this, cx) {
            DrainOutcome::Pending => return Poll::Pending,
            DrainOutcome::Error(error) => return Poll::Ready(Err(error)),
            DrainOutcome::Drained => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.flushed && buf.len() != this.write_len {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finalmask writer: poll retry passed a buffer of a different \
                 length than the write being drained",
            )));
        }
        if this.flushed {
            this.flushed = false;
            this.push_write(buf);
            match drain_stage_queue(this, cx) {
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

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncRead for FinalMaskWriter<S, R> {
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
    check_candidate_fragmented_profile(
        transport,
        ip,
        timeout_ms,
        interface,
        fragment.cloned().map(FragmentProfile::Xray).as_ref(),
    )
    .await
}

/// Probe one candidate IP with an optional fragment profile: a single xray
/// freedom fragment or a multi-stage v2rayNG-style stream config.
pub async fn check_candidate_fragmented_profile(
    transport: &ProxyTransport,
    ip: &str,
    timeout_ms: u64,
    interface: Option<crate::iface::InterfaceAddrs>,
    fragment: Option<&FragmentProfile>,
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
            fragment.map(FragmentProfile::xray_json)
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
                Some(FragmentProfile::Xray(spec)) => Box::new(FragmentWriter::new(
                    stream,
                    spec.clone(),
                    StdRng::from_entropy(),
                )),
                Some(FragmentProfile::V2rayNg { stages }) => {
                    Box::new(FinalMaskWriter::new(stream, stages, StdRng::from_entropy()))
                }
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
    // Read incrementally: the colo line can arrive in a later segment than
    // the status line (slow or fragmented links), so keep reading until the
    // peer closes, the deadline expires, or the colo is found.
    let mut response = Vec::new();
    let mut buffer = [0u8; 16_384];
    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(size)) => {
                response.extend_from_slice(&buffer[..size]);
                if crate::scanner::parse_colo(&String::from_utf8_lossy(&response)).is_some() {
                    break;
                }
            }
            Ok(Err(_)) => return (false, None),
            Err(_) => break,
        }
    }
    if response.is_empty() {
        return (false, None);
    }
    let text = String::from_utf8_lossy(&response);
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
    fragment: Option<&FragmentProfile>,
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
            fragment.map(FragmentProfile::xray_json)
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
        parse_share_url, rand_between, split_stage, FinalMaskWriter, FragmentPackets,
        FragmentProfile, FragmentSpec, FragmentWriter, Int32Range, DOUBLE_FRAGMENT_STAGES,
        TLS_FRAGMENT_PRESETS,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::io;
    use std::time::{Duration, Instant};
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
    fn presets_are_valid_fragment_profiles() {
        assert_eq!(TLS_FRAGMENT_PRESETS[0].0, "Off (control)");
        assert!(TLS_FRAGMENT_PRESETS[0].1.is_none());
        for (label, profile) in &TLS_FRAGMENT_PRESETS[1..] {
            match profile.as_ref().unwrap() {
                FragmentProfile::Xray(spec) => {
                    spec.validate().unwrap_or_else(|e| panic!("{label}: {e}"));
                    assert_eq!(spec.packets, FragmentPackets::TlsHello);
                    assert!(spec.length.from > 0);
                }
                FragmentProfile::V2rayNg { stages } => {
                    assert!(!stages.is_empty(), "{label} must have at least one stage");
                    for stage in *stages {
                        assert!(!stage.lengths.is_empty());
                        assert!(!stage.delays.is_empty());
                        assert!(stage.lengths.last().unwrap().from > 0);
                    }
                }
            }
        }
    }

    #[test]
    fn double_fragment_profile_serializes_to_v2rayng_json() {
        let json = FragmentProfile::V2rayNg {
            stages: DOUBLE_FRAGMENT_STAGES,
        }
        .xray_json();
        let actual: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["109","1"],"delays":["1"],"maxSplit":"355"}}]}"#,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn double_fragment_stage_splitting_matches_xray_semantics() {
        let mut rng = StdRng::seed_from_u64(7);
        let payload: Vec<u8> = (0..178u8).collect();
        let record = tls_record(&payload);

        // Stage 1 (tlshello 5/94/1, delays ["0"]): payload chunks 5, 94, then
        // 1-byte tails (last entry repeats), re-wrapped as TLS records and
        // merged into one write (xray `mergeTlsHelloSegments`).
        let (items, trailing) = split_stage(&mut rng, &DOUBLE_FRAGMENT_STAGES[0], &record);
        assert_eq!(trailing, 0);
        assert_eq!(items.len(), 1, "hello must merge into a single write");
        assert_eq!(items[0].1, 0);
        let merged = &items[0].0;
        assert_eq!(merged.len(), 5 * 81 + 178, "81 TLS records");
        assert_eq!(merged[4] as usize, 5, "first record payload is 5 bytes");
        assert_eq!(merged[14] as usize, 94, "second record payload is 94 bytes");
        assert_eq!(merged[113] as usize, 1, "third record payload is 1 byte");

        // Stage 2 (packets 1-1, lengths 109/1, delay 1 ms, maxSplit 355):
        // the merged write is split 109 + 1×353 + remainder, one segment per
        // 1 ms pause.
        let (chunks, trailing) = split_stage(&mut rng, &DOUBLE_FRAGMENT_STAGES[1], merged);
        assert_eq!(trailing, 1, "delay pattern repeats after the final segment");
        assert_eq!(chunks.len(), 355, "maxSplit caps the segment count");
        assert_eq!(chunks[0].0.len(), 109);
        assert_eq!(chunks[0].1, 0);
        assert_eq!(chunks[1].0.len(), 1);
        assert_eq!(chunks[1].1, 1);
        assert_eq!(
            chunks[354].0.len(),
            583 - 109 - 353,
            "capped segment takes the rest"
        );
        let reassembled: Vec<u8> = chunks
            .iter()
            .flat_map(|(bytes, _)| bytes.iter().copied())
            .collect();
        assert_eq!(reassembled, *merged);
    }

    #[test]
    fn tlshello_zero_length_record_survives_fragmentation() {
        let mut rng = StdRng::seed_from_u64(7);
        // A zero-length TLS record (header only) must still be emitted as a
        // valid five-byte record instead of producing an empty segment list.
        let empty = tls_record(&[]);
        let (items, trailing) = split_stage(&mut rng, &DOUBLE_FRAGMENT_STAGES[0], &empty);
        assert_eq!(trailing, 0);
        assert_eq!(items.len(), 1, "empty record must still produce one write");
        assert_eq!(
            items[0].0, empty,
            "five-byte header must pass through untouched"
        );

        // Trailing data after the empty record is preserved in merge mode.
        let mut data = empty.clone();
        data.extend_from_slice(&tls_record(b"tail"));
        let (items, trailing) = split_stage(&mut rng, &DOUBLE_FRAGMENT_STAGES[0], &data);
        assert_eq!(trailing, 0);
        let out: Vec<u8> = items.iter().flat_map(|(b, _)| b.iter().copied()).collect();
        assert_eq!(out, data, "empty record header and tail must both survive");
    }

    #[tokio::test]
    async fn finalmask_writer_merges_hello_then_splits_first_write() {
        let payload: Vec<u8> = (0..11u8).collect();
        let (client, mut server) = tokio::io::duplex(4096);
        let mut writer =
            FinalMaskWriter::new(client, DOUBLE_FRAGMENT_STAGES, StdRng::seed_from_u64(42));
        writer.write_all(&tls_record(&payload)).await.unwrap();
        drop(writer);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        let mut expected = tls_record(&payload[..5]);
        expected.extend_from_slice(&tls_record(&payload[5..]));
        assert_eq!(received, expected);
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
            expected.extend_from_slice(&tls_record(&[*byte]));
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
        let mut expected = tls_record(b"hel");
        expected.extend_from_slice(&tls_record(b"lo"));
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
        let mut expected = tls_record(b"h");
        expected.extend_from_slice(&tls_record(b"ello"));
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn tlshello_interval_mode_keeps_records_separate_with_delays() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"tlshello","length":"2-2","interval":"1-1"}"#)
                .unwrap();
        let received = write_through(spec, &tls_record(b"hello")).await;
        let mut expected = tls_record(b"he");
        expected.extend_from_slice(&tls_record(b"ll"));
        expected.extend_from_slice(&tls_record(b"o"));
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
            expected.extend_from_slice(&tls_record(&[*byte]));
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
        let mut expected = tls_record(b"he");
        expected.extend_from_slice(&tls_record(b"ll"));
        expected.extend_from_slice(&tls_record(b"o"));
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
            vec![tls_record(b"he"), tls_record(b"ll"), tls_record(b"o"),]
        );
    }

    #[tokio::test]
    async fn tcp_mode_carries_trailing_delay_between_writes() {
        let spec =
            FragmentSpec::parse_json(r#"{"packets":"","length":"2-2","interval":"5-5"}"#).unwrap();
        let (client, mut server) = tokio::io::duplex(4096);
        let mut writer = FragmentWriter::new(client, spec, StdRng::seed_from_u64(42));
        let reader = tokio::spawn(async move {
            let mut chunks = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match server.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => chunks.push((Instant::now(), buf[..n].to_vec())),
                }
            }
            chunks
        });
        writer.write_all(b"abcdef").await.unwrap();
        writer.write_all(b"ghij").await.unwrap();
        drop(writer);
        let chunks = reader.await.unwrap();
        let bytes = chunks
            .iter()
            .map(|(_, chunk)| chunk.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            bytes,
            vec![
                b"ab".to_vec(),
                b"cd".to_vec(),
                b"ef".to_vec(),
                b"gh".to_vec(),
                b"ij".to_vec(),
            ]
        );
        // The first write's trailing 5ms delay must land between the writes
        // (ef -> gh), not on the first write's own first fragment.
        let gap = chunks[3].0.duration_since(chunks[2].0);
        assert!(
            gap >= Duration::from_millis(4),
            "delay between writes was {gap:?}"
        );
    }
}
