use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
use rustls::{pki_types::ServerName, ClientConfig};
#[cfg(not(target_os = "android"))]
use rustls_platform_verifier::BuilderVerifierExt;
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
    /// When true, the first `tlshello` fragment ends at the midpoint of the
    /// SNI hostname (Aether-style targeted split) instead of a random
    /// length. Not an xray field — serialized only when true as
    /// `"sni_split":true`.
    pub sni_split: bool,
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
    /// Serialize as the xray `fragment` object, emitting the optional
    /// `maxSplit` and `sni_split` fields only when present/enabled.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FragmentSpec", 5)?;
        state.serialize_field("packets", &self.packets)?;
        state.serialize_field("length", &self.length)?;
        state.serialize_field("interval", &self.interval)?;
        if let Some(max_split) = &self.max_split {
            state.serialize_field("maxSplit", max_split)?;
        }
        if self.sni_split {
            state.serialize_field("sni_split", &self.sni_split)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for FragmentSpec {
    /// Deserialize via a raw intermediate so validation runs on the
    /// assembled spec and invalid ranges fail as serde errors.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            packets: FragmentPackets,
            length: Int32Range,
            interval: Int32Range,
            #[serde(rename = "maxSplit", default)]
            max_split: Option<Int32Range>,
            #[serde(default, alias = "sniSplit")]
            sni_split: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        let spec = FragmentSpec {
            packets: raw.packets,
            length: raw.length,
            interval: raw.interval,
            max_split: raw.max_split,
            sni_split: raw.sni_split,
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

/// Aether-style raw TCP-chunking config (port of `aether/src/fragment.rs`
/// `FragmentConfig`): splits the raw TCP byte stream into small
/// `poll_write` chunks with inter-chunk delays. Not TLS-record
/// re-wrapping and not IP fragmentation — the TLS stream itself is
/// unchanged, only wire segmentation changes. First-write-only: the
/// first write (ClientHello) is chunked; after `poll_read` everything
/// goes whole. `size` is bounded to `1..=4096`, `delay` to `0..=1000`
/// like Aether's `AetherRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AetherFragmentConfig {
    pub size: Int32Range,
    pub delay: Int32Range,
    pub sni_split: bool,
}

impl AetherFragmentConfig {
    pub const fn default_aether() -> Self {
        Self {
            size: Int32Range::new(8, 16),
            delay: Int32Range::new(2, 10),
            sni_split: false,
        }
    }

    /// Check Aether bounds (`size` in `1..=4096`, `delay` in `0..=1000`),
    /// matching the upstream `AetherRange` limits.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=4096).contains(&self.size.from) || !(1..=4096).contains(&self.size.to) {
            return Err("aether size must be within 1-4096".to_string());
        }
        if !(0..=1000).contains(&self.delay.from) || !(0..=1000).contains(&self.delay.to) {
            return Err("aether delay must be within 0-1000".to_string());
        }
        Ok(())
    }

    /// Parse the `{"aether":{...}}` wrapper and delegate to [`Self::from_value`]
    /// for the inner object.
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("invalid fragment JSON: {e}"))?;
        let inner = value
            .get("aether")
            .ok_or_else(|| "invalid fragment JSON: missing \"aether\"".to_string())?;
        Self::from_value(inner)
    }

    /// Build from an already-parsed `aether` JSON object, accepting string or
    /// numeric `size`/`delay` entries and an optional `sni_split` flag, then
    /// validate the assembled config.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, String> {
        let obj = value
            .as_object()
            .ok_or_else(|| "invalid fragment JSON: aether must be an object".to_string())?;
        let size_raw = obj
            .get("size")
            .map(|v| {
                if let Some(s) = v.as_str() {
                    Ok::<String, String>(s.to_string())
                } else if let Some(n) = v.as_i64() {
                    Ok(n.to_string())
                } else {
                    Err("invalid aether size".to_string())
                }
            })
            .transpose()?
            .ok_or_else(|| "invalid aether JSON: missing size".to_string())?;
        let delay_raw = obj
            .get("delay")
            .map(|v| {
                if let Some(s) = v.as_str() {
                    Ok::<String, String>(s.to_string())
                } else if let Some(n) = v.as_i64() {
                    Ok(n.to_string())
                } else {
                    Err("invalid aether delay".to_string())
                }
            })
            .transpose()?
            .ok_or_else(|| "invalid aether JSON: missing delay".to_string())?;
        let size = Int32Range::parse(size_raw.trim())
            .map_err(|_| format!("invalid aether size: {size_raw:?}"))?;
        let delay = Int32Range::parse(delay_raw.trim())
            .map_err(|_| format!("invalid aether delay: {delay_raw:?}"))?;
        let sni_split = obj
            .get("sni_split")
            .or_else(|| obj.get("sniSplit"))
            .map(|v| {
                v.as_bool()
                    .ok_or_else(|| "invalid aether sni_split".to_string())
            })
            .transpose()?
            .unwrap_or(false);
        let cfg = Self {
            size,
            delay,
            sni_split,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn xray_json(&self) -> String {
        format!(
            "{{\"aether\":{{\"size\":{},\"delay\":{},\"sni_split\":{}}}}}",
            serde_json::to_string(&self.size.to_string()).unwrap_or_default(),
            serde_json::to_string(&self.delay.to_string()).unwrap_or_default(),
            self.sni_split,
        )
    }
}

/// A TLS-fragmentation profile: a single xray `freedom` fragment
/// ([`FragmentSpec`]), a multi-stage v2rayNG-style stream fragment config,
/// or an Aether-style raw TCP chunking config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentProfile {
    Xray(FragmentSpec),
    V2rayNg { stages: &'static [FragmentStage] },
    Aether(AetherFragmentConfig),
}

impl FragmentProfile {
    /// Serialize to the exact JSON pasted into xray / v2rayNG: the freedom
    /// fragment object for [`FragmentProfile::Xray`], the `{"tcp":[...]}`
    /// stream-fragment config for [`FragmentProfile::V2rayNg`], or the
    /// `{"aether":{...}}` chunking config for [`FragmentProfile::Aether`].
    pub fn xray_json(&self) -> String {
        match self {
            FragmentProfile::Xray(spec) => spec.xray_json(),
            FragmentProfile::Aether(cfg) => cfg.xray_json(),
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

    /// Parse a pasted custom JSON block in any supported shape, mirroring
    /// PattNG's `FinalMaskField` (any spacing / key order): freedom
    /// `{"packets":...}`, finalmask `{"tcp":[...]}`, or
    /// `{"aether":{...}}`. Whitespace-insensitive via `serde_json`.
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("custom fragment JSON is empty".to_string());
        }
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid fragment JSON: {e}"))?;
        let obj = value
            .as_object()
            .ok_or_else(|| "invalid fragment JSON: expected an object".to_string())?;
        if obj.contains_key("aether") {
            return Ok(FragmentProfile::Aether(AetherFragmentConfig::parse_json(
                trimmed,
            )?));
        }
        if obj.contains_key("tcp") {
            let tcp = obj
                .get("tcp")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "invalid finalmask JSON: tcp must be an array".to_string())?;
            if tcp.is_empty() {
                return Err("invalid finalmask JSON: tcp must not be empty".to_string());
            }
            let mut owned: Vec<FragmentStage> = Vec::new();
            for (idx, item) in tcp.iter().enumerate() {
                let settings = item.get("settings").ok_or_else(|| {
                    format!("invalid finalmask JSON: stage {idx} missing settings")
                })?;
                let settings_obj = settings.as_object().ok_or_else(|| {
                    format!("invalid finalmask JSON: stage {idx} settings must be an object")
                })?;
                let packets_raw = settings_obj
                    .get("packets")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        format!("invalid finalmask JSON: stage {idx} missing packets")
                    })?;
                let packets = FragmentPackets::parse(packets_raw)
                    .map_err(|e| format!("invalid finalmask JSON: stage {idx} {e}"))?;
                let lengths = parse_int32_range_array(settings_obj, "lengths", idx)?;
                let delays = parse_int32_range_array(settings_obj, "delays", idx)?;
                let max_split = match settings_obj.get("maxSplit") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let s = if let Some(s) = v.as_str() {
                            s.to_string()
                        } else if let Some(n) = v.as_i64() {
                            n.to_string()
                        } else {
                            return Err(format!(
                                "invalid finalmask JSON: stage {idx} bad maxSplit"
                            ));
                        };
                        Some(Int32Range::parse(s.trim()).map_err(|_| {
                            format!("invalid finalmask JSON: stage {idx} bad maxSplit")
                        })?)
                    }
                };
                if lengths.is_empty() || delays.is_empty() {
                    return Err(format!(
                        "invalid finalmask JSON: stage {idx} lengths/delays must not be empty"
                    ));
                }
                // A stage whose repeating (last) length entry can only
                // produce zero while maxSplit can be unlimited never
                // advances the split cursor — an infinite no-progress loop.
                // `rand_between` excludes the upper bound, so an upper of 0
                // or 1 with a clamped lower of 0 is zero-only. maxSplit is
                // potentially unlimited whenever its lower bound clamps to
                // 0 (it can draw 0). Finite caps force the tail to the end,
                // and zero-length prefixes with a progressing tail (e.g.
                // PattNG [0,104,1]) are fine.
                let unlimited = match &max_split {
                    None => true,
                    Some(range) => range.from.max(0) == 0,
                };
                if unlimited {
                    if let Some(last) = lengths.last() {
                        if last.from.max(0) == 0 && last.to <= 1 {
                            return Err(format!(
                                "invalid finalmask JSON: stage {idx} has zero length with unlimited maxSplit (splits would make no progress)"
                            ));
                        }
                    }
                }
                let lengths_leaked: &'static [Int32Range] = Box::leak(lengths.into_boxed_slice());
                let delays_leaked: &'static [Int32Range] = Box::leak(delays.into_boxed_slice());
                owned.push(FragmentStage {
                    packets,
                    lengths: lengths_leaked,
                    delays: delays_leaked,
                    max_split,
                });
            }
            let stages_leaked: &'static [FragmentStage] = Box::leak(owned.into_boxed_slice());
            return Ok(FragmentProfile::V2rayNg {
                stages: stages_leaked,
            });
        }
        Ok(FragmentProfile::Xray(FragmentSpec::parse_json(trimmed)?))
    }

    /// Validate only when used (PattNG `AetherFmt.normalize`): when
    /// `active` is false, any raw text — even invalid or empty — resolves
    /// to `None` without error so an unused custom field never blocks a
    /// run. When active, raw is parsed via [`FragmentProfile::parse_json`].
    pub fn parse_custom_when_active(active: bool, raw: &str) -> Result<Option<Self>, String> {
        if !active {
            return Ok(None);
        }
        Ok(Some(FragmentProfile::parse_json(raw)?))
    }
}

/// Parse a finalmask stage's `lengths`/`delays` array of range strings (or
/// numbers) into [`Int32Range`]s, tagging errors with the stage index.
fn parse_int32_range_array(
    settings: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    idx: usize,
) -> Result<Vec<Int32Range>, String> {
    let arr = settings
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("invalid finalmask JSON: stage {idx} missing {key}"))?;
    arr.iter()
        .map(|v| {
            let s = if let Some(s) = v.as_str() {
                s.to_string()
            } else if let Some(n) = v.as_i64() {
                n.to_string()
            } else {
                return Err(format!("invalid finalmask JSON: stage {idx} bad {key}"));
            };
            Int32Range::parse(s.trim())
                .map_err(|_| format!("invalid finalmask JSON: stage {idx} bad {key}"))
        })
        .collect()
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

/// The recipe circulating for filtered networks (`tlshello-0-len` from
/// patterniha/PattNG, GPL-3.0 — see the project's third-party notices; the
/// same values appear on Telegram and ship as the default Anti-DPI recipe of
/// the SenPaiScanner project): split the ClientHello into a zero-length TLS
/// record, a 104-byte record, then 1-byte records (delays all 0 → merged into
/// a single write), then re-cut that write into a 114-byte piece plus 1-byte
/// slivers with 1 ms pauses (max 11 segments).
///
/// Note: the zero-length record is only tolerated by Cloudflare-style edges;
/// strict TLS stacks RST it. Unlike stock xray (`LengthMin` >= 1), the
/// staged writer can express it because a `0` length simply emits a
/// header-only record.
pub const PATTNG_STAGES: &[FragmentStage] = &[
    FragmentStage {
        packets: FragmentPackets::TlsHello,
        lengths: &[
            Int32Range::new(0, 0),
            Int32Range::new(104, 104),
            Int32Range::new(1, 1),
        ],
        delays: &[Int32Range::new(0, 0)],
        max_split: Some(Int32Range::new(0, 0)),
    },
    FragmentStage {
        packets: FragmentPackets::TcpRange { from: 1, to: 1 },
        lengths: &[Int32Range::new(114, 114), Int32Range::new(1, 1)],
        delays: &[Int32Range::new(1, 1)],
        max_split: Some(Int32Range::new(11, 11)),
    },
];

/// PattNG's second finalMask preset (`tlshello (6-98-1-0-0-114-1-1-11)` in
/// `final_mask_preset_values`): same shape as [`PATTNG_STAGES`] but a 6-byte
/// first record instead of a zero-length record, then 98/1-byte records.
/// Unlike the zero-length variant, this one is tolerated by strict TLS
/// stacks, so it covers edges that RST header-only records.
pub const PATTNG_6_98_STAGES: &[FragmentStage] = &[
    FragmentStage {
        packets: FragmentPackets::TlsHello,
        lengths: &[
            Int32Range::new(6, 6),
            Int32Range::new(98, 98),
            Int32Range::new(1, 1),
        ],
        delays: &[Int32Range::new(0, 0)],
        max_split: Some(Int32Range::new(0, 0)),
    },
    FragmentStage {
        packets: FragmentPackets::TcpRange { from: 1, to: 1 },
        lengths: &[Int32Range::new(114, 114), Int32Range::new(1, 1)],
        delays: &[Int32Range::new(1, 1)],
        max_split: Some(Int32Range::new(11, 11)),
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
            sni_split: false,
        })),
    ),
    (
        "2-2",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(2, 2),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "4-4",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(4, 4),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "8-8",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(8, 8),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "16-16",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(16, 16),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "32-32",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(32, 32),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "64-64",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(64, 64),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "128-128",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(128, 128),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "256-256",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(256, 256),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "1-3 classic",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(1, 3),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "10-20 / 10-20ms (xray default)",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(10, 20),
            interval: Int32Range::new(10, 20),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "100-200 / 10-20ms",
        Some(FragmentProfile::Xray(FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(100, 200),
            interval: Int32Range::new(10, 20),
            max_split: None,
            sni_split: false,
        })),
    ),
    (
        "5/94/1 + 109/1 (double)",
        Some(FragmentProfile::V2rayNg {
            stages: DOUBLE_FRAGMENT_STAGES,
        }),
    ),
    (
        "0/104/1 + 114/1 (PattNG)",
        Some(FragmentProfile::V2rayNg {
            stages: PATTNG_STAGES,
        }),
    ),
    (
        "6/98/1 + 114/1 (PattNG)",
        Some(FragmentProfile::V2rayNg {
            stages: PATTNG_6_98_STAGES,
        }),
    ),
    (
        "aether 8-16/2-10",
        Some(FragmentProfile::Aether(
            AetherFragmentConfig::default_aether(),
        )),
    ),
    (
        "aether sni-split",
        Some(FragmentProfile::Aether(AetherFragmentConfig {
            sni_split: true,
            ..AetherFragmentConfig::default_aether()
        })),
    ),
];

/// xray `crypto.RandBetween`: `[min, max)` with equal values returning `min`
/// and reversed bounds swapped. Deterministic given the rng (for tests).
fn rand_between(rng: &mut impl Rng, from: u64, to: u64) -> u64 {
    if from == to {
        return from;
    }
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    from + rng.random_range(0..to - from)
}

/// Locate the SNI hostname inside a TLS record buffer (`buf` includes the
/// 5-byte record header). Returns `(start, end)` absolute offsets into
/// `buf`, or `None` for non-ClientHello / truncated input (never panics).
/// Hand-rolled walker mirroring Aether's `sni_host_range`: version(2) +
/// random(32) fixed layout, then variable session-id / cipher-suites /
/// compression, then extension walk to kind `0x0000` (server_name).
fn sni_host_range(buf: &[u8]) -> Option<(usize, usize)> {
    let get = |i: usize| buf.get(i).copied();
    let be16 = |i: usize| -> Option<usize> {
        Some((get(i)? as usize) << 8 | get(i.checked_add(1)?)? as usize)
    };
    if buf.len() <= 5 || get(0)? != 22 || get(5)? != 0x01 {
        return None;
    }
    // 5 record + 1 handshake type + 3 handshake length + 2 version + 32 random = 43.
    let mut at = 43usize;
    let session_len = get(at)? as usize;
    at = at.checked_add(1)?.checked_add(session_len)?;
    let cipher_len = be16(at)?;
    at = at.checked_add(2)?.checked_add(cipher_len)?;
    let comp_len = get(at)? as usize;
    at = at.checked_add(1)?.checked_add(comp_len)?;
    let _ext_total = be16(at)?;
    at = at.checked_add(2)?;
    while at.checked_add(4)? <= buf.len() {
        let kind = be16(at)?;
        let len = be16(at.checked_add(2)?)?;
        let body = at.checked_add(4)?;
        let end = body.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        if kind == 0x0000 {
            // server_name: list_len(2) + name_type(1) + host_len(2) + host
            if len < 5 {
                return None;
            }
            if get(body.checked_add(2)?)? != 0 {
                return None;
            }
            let host_len = be16(body.checked_add(3)?)?;
            let host_off = body.checked_add(5)?;
            let host_end = host_off.checked_add(host_len)?;
            if host_len == 0 || host_end > end {
                return None;
            }
            return Some((host_off, host_end));
        }
        at = end;
    }
    None
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
        // SNI-targeted first chunk (Aether-style): when `sni_split` is on,
        // the first fragment ends at the midpoint of the SNI hostname
        // instead of a random length, so no single record holds the whole
        // hostname. Computed once in payload coordinates (record header
        // stripped); falls back to random lengths when absent/truncated.
        let sni_mid_payload = if self.spec.sni_split {
            sni_host_range(&buf[..record_len]).map(|(hs, he)| {
                let mid_abs = hs + (he - hs) / 2;
                mid_abs.saturating_sub(5)
            })
        } else {
            None
        };
        loop {
            let length_min = length.from.max(1) as u64;
            let length_max = length.to.max(1) as u64;
            let mut to =
                from.saturating_add(rand_between(&mut self.rng, length_min, length_max) as usize);
            if split_num == 0 {
                if let Some(mid) = sni_mid_payload {
                    if mid > from && mid < data.len() {
                        to = mid;
                    }
                }
            }
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
            // Delayed mode: trailing bytes after the first record must not
            // be discarded; forward them after the split fragments with the
            // configured delay carried from the last split segment.
            if data.len() > record_len {
                segments.push((data[record_len..].to_vec(), pending_delay));
            }
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

/// Aether-style raw TCP chunking (port of `aether/src/fragment.rs`
/// `FragmentingStream`): splits the first write burst into small raw
/// chunks with inter-chunk delays, no TLS-record re-wrapping. The raw
/// stream itself is unchanged — only wire segmentation changes — so a
/// DPI that parses multi-record hellos but triggers on one-packet SNI
/// is still evaded. First-write-only: `poll_read` disables
/// fragmentation so post-handshake writes go whole. `sni_split`
/// targets the first chunk at the SNI hostname midpoint.
pub struct AetherFragmentWriter<S, R> {
    inner: S,
    cfg: AetherFragmentConfig,
    rng: R,
    fragmenting: bool,
    first_write: bool,
    queue: VecDeque<FragmentItem>,
    pending: Option<FragmentItem>,
    current: Option<(Vec<u8>, usize)>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    flushed: bool,
    write_len: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AetherFragmentWriter<S, R> {
    pub fn new(inner: S, cfg: AetherFragmentConfig, rng: R) -> Self {
        Self {
            inner,
            cfg,
            rng,
            fragmenting: true,
            first_write: true,
            queue: VecDeque::new(),
            pending: None,
            current: None,
            sleep: None,
            flushed: true,
            write_len: 0,
        }
    }

    #[cfg(test)]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Enqueue one logical write as raw chunks: whole when fragmentation is
    /// off or this is not the first write, otherwise size/delay-randomized
    /// chunks with an optional SNI-midpoint first cut when `sni_split` is on.
    fn push_items(&mut self, buf: &[u8]) {
        self.write_len = buf.len();
        if !self.fragmenting || !self.first_write || buf.is_empty() {
            self.queue.push_back(FragmentItem {
                bytes: buf.to_vec(),
                delay_ms: 0,
            });
            return;
        }
        let size_min = self.cfg.size.from.max(1) as u64;
        let size_max = self.cfg.size.to.max(1) as u64;
        let sni_mid = if self.cfg.sni_split {
            sni_host_range(buf).map(|(hs, he)| hs + (he - hs) / 2)
        } else {
            None
        };
        let mut from = 0usize;
        let mut pending_delay = 0u64;
        let mut first = true;
        while from < buf.len() {
            let mut to = if first {
                if let Some(mid) = sni_mid {
                    if mid > from && mid < buf.len() {
                        mid
                    } else {
                        from.saturating_add(rand_between(&mut self.rng, size_min, size_max) as usize)
                    }
                } else {
                    from.saturating_add(rand_between(&mut self.rng, size_min, size_max) as usize)
                }
            } else {
                from.saturating_add(rand_between(&mut self.rng, size_min, size_max) as usize)
            };
            if to > buf.len() {
                to = buf.len();
            }
            if to == from {
                to = buf.len();
            }
            let chunk = buf[from..to].to_vec();
            from = to;
            let delay = rand_between(
                &mut self.rng,
                self.cfg.delay.from.max(0) as u64,
                self.cfg.delay.to.max(0) as u64,
            );
            self.queue.push_back(FragmentItem {
                bytes: chunk,
                delay_ms: pending_delay,
            });
            pending_delay = delay;
            first = false;
        }
    }
}

/// Drive the queued Aether chunks (and their inter-chunk sleeps) to the
/// inner stream until drained, pending, or errored; the caller's `buf` is
/// untouched so poll retries can replay the same buffer safely.
fn drain_aether_queue<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin>(
    this: &mut AetherFragmentWriter<S, R>,
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
                            "aether writer: zero-length write",
                        ))
                    }
                    Poll::Ready(Ok(n)) => *written += n,
                    Poll::Pending => return DrainOutcome::Pending,
                    Poll::Ready(Err(e)) => return DrainOutcome::Error(e),
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

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncWrite for AetherFragmentWriter<S, R> {
    /// Accept the buffer, chunk it on the first write via `push_items`, and
    /// drain the queue; the whole buffer is reported written once queued.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match drain_aether_queue(this, cx) {
            DrainOutcome::Pending => return Poll::Pending,
            DrainOutcome::Error(e) => return Poll::Ready(Err(e)),
            DrainOutcome::Drained => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.flushed && buf.len() != this.write_len {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aether writer: poll retry passed a buffer of a different length than the write being drained",
            )));
        }
        if this.flushed {
            this.flushed = false;
            this.push_items(buf);
            this.first_write = false;
            match drain_aether_queue(this, cx) {
                DrainOutcome::Pending => return Poll::Pending,
                DrainOutcome::Error(e) => return Poll::Ready(Err(e)),
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

impl<S: AsyncRead + AsyncWrite + Unpin, R: Rng + Unpin> AsyncRead for AetherFragmentWriter<S, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.fragmenting = false;
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

/// TLS ClientHello fingerprint preset. `Default` keeps the rustls defaults;
/// `Chrome` re-orders ALPN, cipher suites, and key-exchange groups to match
/// Chrome's ClientHello (best-effort: GREASE and extension order are
/// rustls-fixed and not emulated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsFingerprint {
    #[default]
    Default,
    Chrome,
}

impl std::str::FromStr for TlsFingerprint {
    type Err = String;

    /// Parse `"default"`/`"chrome"` (plus empty/auto/off aliases for default);
    /// anything else is an error listing the accepted names.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "default" | "off" | "auto" => Ok(TlsFingerprint::Default),
            "chrome" => Ok(TlsFingerprint::Chrome),
            other => Err(format!(
                "unknown TLS fingerprint {other:?}; expected \"default\" or \"chrome\""
            )),
        }
    }
}

impl std::fmt::Display for TlsFingerprint {
    /// Render as the CLI name (`default` or `chrome`) for output and round-tripping.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TlsFingerprint::Default => "default",
            TlsFingerprint::Chrome => "chrome",
        })
    }
}

/// Chrome-like ring crypto provider: TLS 1.3 ciphers start with
/// `TLS_AES_128_GCM_SHA256` (rustls defaults to AES-256 first), TLS 1.2
/// ciphers follow Chrome's `C02B/C02F/C02C/C030/CCA8/CCA9` order, and key
/// exchange is `X25519, P-256, P-384`. Other provider fields (signatures,
/// RNG, key provider) are the ring defaults.
pub(crate) fn chrome_provider() -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::ring::{cipher_suite as cs, kx_group as kx};
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    provider.kx_groups = vec![kx::X25519, kx::SECP256R1, kx::SECP384R1];
    Arc::new(provider)
}

/// Build the rustls `ClientConfig` for a fingerprint and optional ECH list,
/// using the Chrome provider/ALPN for `Chrome`, webpki roots on Android, and
/// the platform verifier elsewhere; ECH goes through `client_config_ech`
/// when the `ech` feature is compiled in.
/// Reuse the parsed webpki root store across Android `ClientConfig`s so
/// repeated client builds don't re-parse the full trust bundle each time.
/// Sessions stay per-config (each builder call creates its own `ClientConfig`
/// with its own resumption store); the store itself is refreshed on a short
/// TTL so OS trust-store changes are still picked up.
#[cfg(target_os = "android")]
fn shared_android_roots() -> Result<rustls::RootCertStore, rustls::Error> {
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<(Option<rustls::RootCertStore>, Instant)>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((None, Instant::now())));
    {
        let guard = cache.lock().expect("root cache mutex poisoned");
        if let Some(roots) = &guard.0 {
            if guard.1.elapsed() < std::time::Duration::from_secs(60) {
                return Ok(roots.clone());
            }
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        roots.add(der.clone())?;
    }
    let mut guard = cache.lock().expect("root cache mutex poisoned");
    *guard = (Some(roots.clone()), Instant::now());
    Ok(roots)
}

pub(crate) fn client_config(
    fingerprint: TlsFingerprint,
    ech_list: Option<&[u8]>,
    http11_only: bool,
) -> Result<ClientConfig, rustls::Error> {
    #[cfg(feature = "ech")]
    if let Some(list) = ech_list {
        return client_config_ech(fingerprint, list, http11_only);
    }
    #[cfg(not(feature = "ech"))]
    let _ = ech_list;
    #[cfg(target_os = "android")]
    let mut config = match fingerprint {
        TlsFingerprint::Chrome => {
            let roots = shared_android_roots()?;
            ClientConfig::builder_with_provider(chrome_provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        TlsFingerprint::Default => {
            let roots = shared_android_roots()?;
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    #[cfg(not(target_os = "android"))]
    let mut config = match fingerprint {
        TlsFingerprint::Chrome => ClientConfig::builder_with_provider(chrome_provider())
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth(),
        TlsFingerprint::Default => {
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_platform_verifier()?
                .with_no_client_auth()
        }
    };
    if fingerprint == TlsFingerprint::Chrome {
        config.alpn_protocols = if http11_only {
            vec![b"http/1.1".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
    }
    Ok(config)
}

/// ECH-capable config (only built with the `ech` feature, which brings the
/// aws-lc-rs HPKE provider). The ECH config list was already fetched +
/// validated by [`crate::ech::require_ech_config`]; this only binds it to a
/// `ClientConfig` with `with_ech`. Fail-closed: callers must have refused
/// cleartext already when no list was available.
#[cfg(feature = "ech")]
fn client_config_ech(
    fingerprint: TlsFingerprint,
    list: &[u8],
    http11_only: bool,
) -> Result<ClientConfig, rustls::Error> {
    use rustls::pki_types::EchConfigListBytes;
    let ech_config = rustls::client::EchConfig::new(
        EchConfigListBytes::from(list.to_vec()),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )?;
    let mut config = match fingerprint {
        TlsFingerprint::Chrome => {
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            // Reuse the Chrome ordering, sourced from the ring provider:
            // keep aws-lc-rs crypto, re-apply Chrome suite/KX order.
            let chrome = chrome_provider();
            provider.cipher_suites = chrome.cipher_suites.clone();
            provider.kx_groups = chrome.kx_groups.clone();
            #[cfg(target_os = "android")]
            {
                let roots = shared_android_roots()?;
                ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_ech(rustls::client::EchMode::Enable(ech_config))?
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            #[cfg(not(target_os = "android"))]
            {
                ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_ech(rustls::client::EchMode::Enable(ech_config))?
                    .with_platform_verifier()?
                    .with_no_client_auth()
            }
        }
        TlsFingerprint::Default => {
            #[cfg(target_os = "android")]
            {
                let roots = shared_android_roots()?;
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_ech(rustls::client::EchMode::Enable(ech_config))?
                .with_root_certificates(roots)
                .with_no_client_auth()
            }
            #[cfg(not(target_os = "android"))]
            {
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_ech(rustls::client::EchMode::Enable(ech_config))?
                .with_platform_verifier()?
                .with_no_client_auth()
            }
        }
    };
    if fingerprint == TlsFingerprint::Chrome {
        config.alpn_protocols = if http11_only {
            vec![b"http/1.1".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
    }
    Ok(config)
}

/// Install the fingerprint-aware TLS config onto a reqwest builder; only
/// `Chrome` (and non-Android `Default` stays on reqwest's default) needs an
/// explicit preconfigured backend.
pub(crate) fn apply_rustls_backend(
    builder: reqwest::ClientBuilder,
    fingerprint: TlsFingerprint,
) -> reqwest::ClientBuilder {
    match fingerprint {
        // Chrome needs an explicit backend: reqwest's default rustls config
        // would otherwise keep the stock provider and ALPN.
        TlsFingerprint::Chrome => builder.tls_backend_preconfigured(
            client_config(fingerprint, None, false).expect("failed to build Chrome TLS config"),
        ),
        TlsFingerprint::Default => {
            #[cfg(target_os = "android")]
            {
                builder.tls_backend_preconfigured(
                    client_config(fingerprint, None, false)
                        .expect("failed to build Android TLS config"),
                )
            }
            #[cfg(not(target_os = "android"))]
            {
                builder
            }
        }
    }
}

/// Cached `TlsConnector` for a fingerprint/ECH pair so repeated probes reuse
/// one connector (and its connection pool semantics) instead of rebuilding.
/// `http11_only` forces `http/1.1` ALPN for callers that speak plain
/// HTTP/1.1 after the handshake (the manual fragment/proxy probes), never
/// `h2` — a negotiated h2 would break their raw request.
fn tls_config(
    fingerprint: TlsFingerprint,
    ech_list: Option<&[u8]>,
    http11_only: bool,
) -> Result<TlsConnector> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    type ConnectorCache =
        HashMap<(TlsFingerprint, Vec<u8>, bool), std::result::Result<TlsConnector, String>>;
    static CONNECTORS: OnceLock<Mutex<ConnectorCache>> = OnceLock::new();
    let cache = CONNECTORS.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (
        fingerprint,
        ech_list.map(|list| list.to_vec()).unwrap_or_default(),
        http11_only,
    );
    let cached = {
        let guard = cache.lock().expect("TLS connector cache mutex poisoned");
        guard.get(&key).cloned()
    };
    let connector = match cached {
        Some(built) => built,
        None => {
            let built = client_config(fingerprint, ech_list, http11_only)
                .map(|config| TlsConnector::from(Arc::new(config)))
                .map_err(|error| error.to_string());
            let mut guard = cache.lock().expect("TLS connector cache mutex poisoned");
            guard.entry(key).or_insert_with(|| built.clone()).clone()
        }
    };
    connector.map_err(|error| anyhow!(error))
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
#[allow(clippy::too_many_arguments)]
pub async fn check_candidate_fragmented(
    transport: &ProxyTransport,
    ip: &str,
    timeout_ms: u64,
    interface: Option<crate::iface::InterfaceAddrs>,
    mark: Option<u32>,
    fingerprint: TlsFingerprint,
    ech: bool,
    fragment: Option<&FragmentSpec>,
) -> SurvivabilityResult {
    check_candidate_fragmented_profile(
        transport,
        ip,
        timeout_ms,
        interface,
        mark,
        fingerprint,
        ech,
        fragment.cloned().map(FragmentProfile::Xray).as_ref(),
    )
    .await
}

/// Probe one candidate IP with an optional fragment profile: a single xray
/// freedom fragment or a multi-stage v2rayNG-style stream config.
#[allow(clippy::too_many_arguments)]
pub async fn check_candidate_fragmented_profile(
    transport: &ProxyTransport,
    ip: &str,
    timeout_ms: u64,
    interface: Option<crate::iface::InterfaceAddrs>,
    mark: Option<u32>,
    fingerprint: TlsFingerprint,
    ech: bool,
    fragment: Option<&FragmentProfile>,
) -> SurvivabilityResult {
    let started = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms.max(500));
    // IP literals dial directly; a hostname is resolved and raced Happy
    // Eyeballs style (IPv6 first, 250 ms stagger) via `iface::dial`.
    let stream = match timeout(
        timeout_duration,
        crate::iface::dial(ip, transport.port, interface, mark),
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
        // ECH is fail-closed: no config (or no HPKE build) refuses the
        // connection with an explanatory error instead of cleartext SNI —
        // but the TCP connect already succeeded, so keep that result.
        let ech_list = match crate::ech::require_ech_config(ech, interface).await {
            Ok(list) => list,
            Err(e) => {
                result.error = Some(e);
                result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                return result;
            }
        };
        let handshake = async {
            let name = ServerName::try_from(transport.sni.to_string())
                .map_err(|_| anyhow!("invalid TLS SNI"))?;
            let stream: BoxedStream = match fragment {
                Some(FragmentProfile::Xray(spec)) => Box::new(FragmentWriter::new(
                    stream,
                    spec.clone(),
                    StdRng::try_from_rng(&mut rand::rngs::SysRng)
                        .expect("failed to seed StdRng from OS randomness"),
                )),
                Some(FragmentProfile::V2rayNg { stages }) => Box::new(FinalMaskWriter::new(
                    stream,
                    stages,
                    StdRng::try_from_rng(&mut rand::rngs::SysRng)
                        .expect("failed to seed StdRng from OS randomness"),
                )),
                Some(FragmentProfile::Aether(cfg)) => Box::new(AetherFragmentWriter::new(
                    stream,
                    *cfg,
                    StdRng::try_from_rng(&mut rand::rngs::SysRng)
                        .expect("failed to seed StdRng from OS randomness"),
                )),
                None => Box::new(stream),
            };
            Ok::<_, anyhow::Error>(
                tls_config(fingerprint, ech_list.as_deref(), true)?
                    .connect(name, stream)
                    .await?,
            )
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
/// 2xx response arrived and the Cloudflare colo parsed from the response.
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
    // Read incrementally: the body `colo=` line can arrive in a later
    // segment than the header CF-Ray (slow or fragmented links), and it is
    // authoritative. Remember the header colo as a fallback but keep reading
    // until the body colo appears or the response ends.
    let mut response = Vec::new();
    let mut header_colo: Option<String> = None;
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
                let text = String::from_utf8_lossy(&response);
                if crate::scanner::parse_colo(&text).is_some() {
                    break;
                }
                if header_colo.is_none() {
                    if let Some(header) = crate::scanner::parse_cf_ray_colo(&text) {
                        header_colo = Some(header);
                    }
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
    let colo = crate::scanner::parse_colo(&text).or(header_colo);
    (status_ok, colo)
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
        parse_share_url, rand_between, split_stage, AetherFragmentConfig, AetherFragmentWriter,
        FinalMaskWriter, FragmentPackets, FragmentProfile, FragmentSpec, FragmentStage,
        FragmentWriter, Int32Range, DOUBLE_FRAGMENT_STAGES, PATTNG_6_98_STAGES, PATTNG_STAGES,
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

    /// Every curated TLS-fragment preset parses and validates.
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
                FragmentProfile::Aether(cfg) => {
                    cfg.validate().unwrap_or_else(|e| panic!("{label}: {e}"));
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
    fn pattng_profile_serializes_to_senpai_json() {
        let json = FragmentProfile::V2rayNg {
            stages: PATTNG_STAGES,
        }
        .xray_json();
        let actual: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}"#,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    /// PattNG stage one emits the zero-length + 104-byte + 1-byte records.
    #[test]
    fn pattng_recipe_stage_one_emits_zero_length_record() {
        let mut rng = StdRng::seed_from_u64(7);
        let payload: Vec<u8> = (0..178u8).collect();
        let record = tls_record(&payload);

        // Stage 1 (tlshello 0/104/1, delays ["0"]): a zero-length TLS record,
        // a 104-byte record, then one 1-byte record per remaining byte — all
        // merged into a single write (delays all zero).
        let (items, trailing) = split_stage(&mut rng, &PATTNG_STAGES[0], &record);
        assert_eq!(trailing, 0);
        assert_eq!(items.len(), 1, "hello must merge into a single write");
        assert_eq!(items[0].1, 0);

        let merged = &items[0].0;
        assert_eq!(&merged[..5], &[0x16, 0x03, 0x01, 0x00, 0x00]);
        assert_eq!(merged[9], 104, "second record carries 104 payload bytes");

        // Walk the record stream: 0, 104, then 1-byte chunks, payload identical.
        let mut lengths = Vec::new();
        let mut reassembled = Vec::new();
        let mut offset = 0usize;
        while offset < merged.len() {
            let len = ((merged[offset + 3] as usize) << 8) | merged[offset + 4] as usize;
            lengths.push(len);
            reassembled.extend_from_slice(&merged[offset + 5..offset + 5 + len]);
            offset += 5 + len;
        }
        assert_eq!(offset, merged.len());
        assert_eq!(lengths[0], 0);
        assert_eq!(lengths[1], 104);
        assert!(lengths[2..].iter().all(|len| *len == 1));
        assert_eq!(reassembled, payload);
    }

    /// PattNG stage two re-cuts the merged write and terminates correctly.
    #[test]
    fn pattng_recipe_stage_two_cuts_merged_write_and_terminates() {
        let mut rng = StdRng::seed_from_u64(7);
        let payload: Vec<u8> = (0..178u8).collect();
        let record = tls_record(&payload);
        let (items, _) = split_stage(&mut rng, &PATTNG_STAGES[0], &record);
        let merged = items[0].0.clone();

        // Stage 2 (packets 1-1, lengths 114/1, delay 1 ms, maxSplit 11): the
        // merged burst leaves as 114 + 9×1-byte reads, the 11th taking the rest.
        let (chunks, trailing) = split_stage(&mut rng, &PATTNG_STAGES[1], &merged);
        assert_eq!(trailing, 1, "delay pattern repeats after the final segment");
        assert_eq!(chunks.len(), 11, "maxSplit caps the segment count");
        assert_eq!(chunks[0].0.len(), 114);
        assert_eq!(chunks[0].1, 0);
        assert!(
            chunks[1..10]
                .iter()
                .all(|(bytes, delay)| bytes.len() == 1 && *delay == 1),
            "slivers carry the 1 ms pause"
        );
        assert_eq!(chunks[10].0.len(), merged.len() - 114 - 9);
        assert_eq!(chunks[10].1, 1);
        let reassembled: Vec<u8> = chunks
            .iter()
            .flat_map(|(bytes, _)| bytes.iter().copied())
            .collect();
        assert_eq!(reassembled, merged);
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

    #[test]
    fn delayed_tlshello_stage_preserves_trailing_records() {
        // A delayed (delays: ["1"]) tlshello stage must forward bytes after
        // the first record instead of discarding them.
        let lengths: &'static [Int32Range] = Box::leak([Int32Range::new(100, 100)].into());
        let delays: &'static [Int32Range] = Box::leak([Int32Range::new(1, 1)].into());
        let stage = FragmentStage {
            packets: FragmentPackets::TlsHello,
            lengths,
            delays,
            max_split: Some(Int32Range::new(10, 10)),
        };
        let mut data = tls_record(b"hello");
        data.extend_from_slice(b"TRAILING!");
        let (segments, _trailing) = split_stage(&mut StdRng::seed_from_u64(7), &stage, &data);
        let received: Vec<u8> = segments
            .iter()
            .flat_map(|(bytes, _)| bytes.iter())
            .copied()
            .collect();
        assert!(
            received.windows(9).any(|w| w == b"TRAILING!"),
            "trailing bytes must be forwarded in delayed tlshello splits: {received:?}"
        );
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

    // --- RED: item 3 — PattNG 6/98/1 preset ---
    #[test]
    fn pattng_6_98_profile_serializes_to_json() {
        let json = FragmentProfile::V2rayNg {
            stages: PATTNG_6_98_STAGES,
        }
        .xray_json();
        let actual: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["6","98","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}"#,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn pattng_6_98_preset_appears_in_tls_presets() {
        assert!(
            TLS_FRAGMENT_PRESETS
                .iter()
                .any(|(label, _)| label.contains("6/98/1")),
            "6/98/1 preset must be listed"
        );
    }

    // --- RED: item 1 — SNI host range + sni_split on Xray tlshello writer ---
    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        // Handshake payload (after 5-byte TLS record header).
        let mut payload = Vec::new();
        payload.push(0x01); // handshake type ClientHello
        let ext_body_start = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2; // version+random+session_len+cipher_len+suites+comp_len+comp+ext_len
                                                             // We compute handshake length after building extensions.
        let host = sni.as_bytes();
        let ext_len = 2 + 1 + 2 + host.len();
        let ext_total = 2 + 2 + ext_len;
        let handshake_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_total;
        payload.extend_from_slice(&(handshake_len as u32).to_be_bytes()[1..]); // 3-byte length
        payload.extend_from_slice(&[0x03, 0x03]); // version
        payload.extend_from_slice(&[0u8; 32]); // random
        payload.push(0); // session_id len
        payload.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        payload.extend_from_slice(&[0x01, 0x00]); // compression
        payload.extend_from_slice(&(ext_total as u16).to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x00]); // ext kind server_name
        payload.extend_from_slice(&(ext_len as u16).to_be_bytes());
        // list length excludes its own 2-byte prefix: type(1) + len(2) + host.
        payload.extend_from_slice(&((ext_len - 2) as u16).to_be_bytes()); // list len
        payload.push(0); // name type
        payload.extend_from_slice(&(host.len() as u16).to_be_bytes());
        payload.extend_from_slice(host);
        let _ = ext_body_start;
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(&payload);
        record
    }

    #[test]
    fn sni_host_range_finds_host_inside_client_hello() {
        let hello = client_hello_with_sni("example.com");
        let (start, end) = super::sni_host_range(&hello).expect("SNI must be found");
        assert_eq!(&hello[start..end], b"example.com");
        assert_eq!(end - start, 11);
        assert!(super::sni_host_range(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(super::sni_host_range(&hello[..10]).is_none());
    }

    /// With `sni_split` the first fragment cuts inside the SNI hostname.
    #[tokio::test]
    async fn tlshello_sni_split_first_fragment_ends_inside_sni() {
        let spec = FragmentSpec {
            packets: FragmentPackets::TlsHello,
            length: Int32Range::new(200, 200),
            interval: Int32Range::new(0, 0),
            max_split: None,
            sni_split: true,
        };
        let hello = client_hello_with_sni("example.com");
        let (hs, he) = super::sni_host_range(&hello).unwrap();
        let midpoint_payload = (hs + (he - hs) / 2) - 5; // payload coords (minus record header)
        let recorded = write_through(spec, &hello).await;
        // Walk re-wrapped records; first record payload length must be midpoint.
        let first_len = ((recorded[3] as usize) << 8) | recorded[4] as usize;
        assert_eq!(
            first_len, midpoint_payload,
            "first fragment must end at SNI midpoint"
        );
        assert!(first_len > 0 && first_len < hello.len() - 5);
    }

    // --- RED: item 2 — Aether raw TCP chunking profile ---
    #[test]
    fn aether_config_validates_bounds_like_aether_range() {
        let ok = AetherFragmentConfig {
            size: Int32Range::new(8, 16),
            delay: Int32Range::new(2, 10),
            sni_split: false,
        };
        assert!(ok.validate().is_ok());
        assert!(AetherFragmentConfig {
            size: Int32Range::new(0, 16),
            ..ok
        }
        .validate()
        .is_err());
        assert!(AetherFragmentConfig {
            size: Int32Range::new(8, 4097),
            ..ok
        }
        .validate()
        .is_err());
        assert!(AetherFragmentConfig {
            delay: Int32Range::new(0, 1001),
            ..ok
        }
        .validate()
        .is_err());
        assert_eq!(
            AetherFragmentConfig::default_aether().xray_json(),
            r#"{"aether":{"size":"8-16","delay":"2-10","sni_split":false}}"#
        );
    }

    /// The Aether chunking profile is listed among the TLS presets.
    #[test]
    fn aether_profile_appears_in_tls_presets() {
        assert!(
            TLS_FRAGMENT_PRESETS
                .iter()
                .any(|(label, profile)| label.contains("aether")
                    && matches!(profile, Some(FragmentProfile::Aether(_)))),
            "aether preset must be listed"
        );
    }

    #[tokio::test]
    async fn aether_writer_chunks_raw_bytes_not_tls_records() {
        let cfg = AetherFragmentConfig {
            size: Int32Range::new(8, 8),
            delay: Int32Range::new(0, 0),
            sni_split: false,
        };
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = AetherFragmentWriter::new(recorder, cfg, StdRng::seed_from_u64(42));
        writer.write_all(b"abcdefghijklmnopqrst").await.unwrap();
        let recorder = writer.into_inner();
        assert_eq!(
            recorder.slices,
            vec![b"abcdefgh".to_vec(), b"ijklmnop".to_vec(), b"qrst".to_vec()]
        );
    }

    #[tokio::test]
    async fn aether_writer_fragments_only_first_write() {
        let cfg = AetherFragmentConfig {
            size: Int32Range::new(4, 4),
            delay: Int32Range::new(0, 0),
            sni_split: false,
        };
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = AetherFragmentWriter::new(recorder, cfg, StdRng::seed_from_u64(42));
        writer.write_all(b"abcdefgh").await.unwrap();
        writer.write_all(b"ijklmnop").await.unwrap();
        let recorder = writer.into_inner();
        assert_eq!(
            recorder.slices,
            vec![b"abcd".to_vec(), b"efgh".to_vec(), b"ijklmnop".to_vec()]
        );
    }

    #[tokio::test]
    async fn aether_writer_sni_split_first_chunk_at_midpoint() {
        let cfg = AetherFragmentConfig {
            size: Int32Range::new(200, 200),
            delay: Int32Range::new(0, 0),
            sni_split: true,
        };
        let hello = client_hello_with_sni("example.com");
        let (hs, he) = super::sni_host_range(&hello).unwrap();
        let midpoint = hs + (he - hs) / 2;
        let recorder = SliceRecorder { slices: Vec::new() };
        let mut writer = AetherFragmentWriter::new(recorder, cfg, StdRng::seed_from_u64(42));
        writer.write_all(&hello).await.unwrap();
        let recorder = writer.into_inner();
        assert_eq!(recorder.slices[0].len(), midpoint);
        assert_eq!(&recorder.slices[0][..], &hello[..midpoint]);
    }

    // --- RED: item 4 — paste-in custom JSON (validate only when used) ---
    #[test]
    fn fragment_profile_parse_json_accepts_freedom_finalmask_and_aether() {
        let freedom = FragmentProfile::parse_json(
            r#"{"packets":"tlshello","length":"100-200","interval":"10-20"}"#,
        )
        .unwrap();
        assert!(matches!(freedom, FragmentProfile::Xray(_)));
        let finalmask = FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}}]}"#,
        )
        .unwrap();
        assert!(matches!(finalmask, FragmentProfile::V2rayNg { .. }));
        let aether = FragmentProfile::parse_json(
            r#"{"aether":{"size":"8-16","delay":"2-10","sni_split":false}}"#,
        )
        .unwrap();
        assert!(matches!(aether, FragmentProfile::Aether(_)));
        assert!(FragmentProfile::parse_json("not json").is_err());
        assert!(FragmentProfile::parse_json(r#"{"packets":"tlshello"}"#).is_err());
    }

    #[test]
    fn fragment_profile_parse_when_inactive_ignores_invalid_json() {
        // Validate only when used: disabled custom JSON must not error.
        assert!(FragmentProfile::parse_custom_when_active(false, "not json")
            .unwrap()
            .is_none());
        assert!(FragmentProfile::parse_custom_when_active(false, "")
            .unwrap()
            .is_none());
        assert!(FragmentProfile::parse_custom_when_active(true, "not json").is_err());
        assert!(FragmentProfile::parse_custom_when_active(
            true,
            r#"{"packets":"tlshello","length":"10-20","interval":"0"}"#
        )
        .unwrap()
        .is_some());
    }

    // --- Review: finalmask zero-length stage with unlimited maxSplit ---
    #[test]
    fn finalmask_rejects_zero_length_stage_with_unlimited_maxsplit() {
        // Zero-length-only stage with maxSplit "0" (unlimited): every split
        // is 0 bytes, `from` never advances — an infinite no-progress loop.
        let zero = FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0"],"delays":["0"],"maxSplit":"0"}}]}"#,
        );
        assert!(
            zero.is_err(),
            "zero-length stage with unlimited maxSplit must be rejected: {zero:?}"
        );
        // maxSplit absent is also unlimited.
        let zero_no_cap = FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"","lengths":["0"],"delays":["0"]}}]}"#,
        );
        assert!(zero_no_cap.is_err());
        // Repeating last entry zero after a nonzero prefix is also stuck.
        let stuck_tail = FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["104","0"],"delays":["0"],"maxSplit":"0"}}]}"#,
        );
        assert!(stuck_tail.is_err());
        // Finite cap forces the tail to the end: safe and must parse.
        let finite = FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0"],"delays":["0"],"maxSplit":"3"}}]}"#,
        );
        assert!(finite.is_ok(), "finite maxSplit must be preserved");
        // Zero-length prefix with a progressing tail (PattNG shape) and the
        // double-fragment shape must keep parsing.
        assert!(FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}}]}"#
        )
        .is_ok());
        assert!(FragmentProfile::parse_json(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],"delays":["0"],"maxSplit":"0"}}]}"#
        )
        .is_ok());
    }

    // --- RED: item 6 — Chrome-like TLS ClientHello fingerprint ---
    #[test]
    fn chrome_provider_starts_with_aes128_and_orders_kx_groups_chrome_like() {
        use rustls::crypto::ring::{cipher_suite as cs, kx_group as kx};
        let provider = super::chrome_provider();
        assert_eq!(provider.cipher_suites.len(), 9);
        assert_eq!(
            provider.cipher_suites[0],
            cs::TLS13_AES_128_GCM_SHA256,
            "Chrome negotiates AES-128-GCM first (0x1301)"
        );
        assert_eq!(provider.cipher_suites[1], cs::TLS13_AES_256_GCM_SHA384);
        assert_eq!(
            provider.cipher_suites[2],
            cs::TLS13_CHACHA20_POLY1305_SHA256
        );
        // TLS 1.2 order: ECDHE-ECDSA-AES128, ECDHE-RSA-AES128,
        // ECDHE-ECDSA-AES256, ECDHE-RSA-AES256, ECDHE-ECDSA-CHACHA,
        // ECDHE-RSA-CHACHA.
        assert_eq!(
            provider.cipher_suites[3],
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(
            provider.cipher_suites[4],
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(
            provider.cipher_suites[5],
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            vec![
                rustls::crypto::ring::kx_group::X25519.name(),
                rustls::crypto::ring::kx_group::SECP256R1.name(),
                rustls::crypto::ring::kx_group::SECP384R1.name(),
            ]
        );
        let _ = kx::X25519;
    }

    #[test]
    fn chrome_client_config_sets_h2_http1_alpn_and_builds() {
        let config = super::client_config(super::TlsFingerprint::Chrome, None, false).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn default_client_config_has_no_alpn() {
        let config = super::client_config(super::TlsFingerprint::Default, None, false).unwrap();
        assert!(config.alpn_protocols.is_empty());
    }
}
