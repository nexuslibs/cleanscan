//! System capability tiers for concurrency ceilings, derived from the Aether
//! `sysprofile.rs` idea: low-end devices (few CPUs, little RAM) get small
//! effective concurrency so full-subnet sweeps don't OOM, capable hosts keep
//! the configured default. Detection is RAM + CPU only; all thresholds are
//! pure functions for deterministic unit tests.

/// Concurrency tier of the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrencyTier {
    Low,
    Medium,
    High,
}

impl ConcurrencyTier {
    /// Ceiling applied to the requested concurrency. `usize::MAX` means
    /// "no ceiling" (the user's value stands).
    pub fn cap(&self) -> usize {
        match self {
            ConcurrencyTier::Low => 4,
            ConcurrencyTier::Medium => 10,
            ConcurrencyTier::High => usize::MAX,
        }
    }
}

/// Effective concurrency for a requested value under a tier.
pub fn effective_concurrency(requested: usize, tier: ConcurrencyTier) -> usize {
    requested.max(1).min(tier.cap())
}

/// Default concurrency when the user did not choose one explicitly:
/// the configured default (120) clamped by the host tier, so low-end
/// devices default to 4/10 instead of 120.
pub fn default_concurrency(tier: ConcurrencyTier) -> usize {
    effective_concurrency(DEFAULT_CONCURRENCY, tier)
}

pub const DEFAULT_CONCURRENCY: usize = 120;

/// Pure tier classification from CPU count and total RAM in megabytes.
pub fn tier_for(cpus: usize, ram_mb: u64) -> ConcurrencyTier {
    if cpus <= 2 || ram_mb < 1_024 {
        ConcurrencyTier::Low
    } else if cpus <= 4 || ram_mb < 4_096 {
        ConcurrencyTier::Medium
    } else {
        ConcurrencyTier::High
    }
}

/// Parse the total memory (MiB) from Linux `/proc/meminfo` text, or `None`
/// when absent/unparseable (e.g. non-Linux platforms).
pub fn parse_meminfo_total_mb(text: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb / 1_024);
        }
    }
    None
}

/// Detect the current host's tier: CPU count from
/// `available_parallelism`, RAM from `/proc/meminfo` (Linux/Android) where
/// available, otherwise CPU-only.
pub fn detect_tier() -> ConcurrencyTier {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let ram_mb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| parse_meminfo_total_mb(&text))
        .unwrap_or(u64::MAX);
    tier_for(cpus, ram_mb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_are_low_4_medium_10_high_unbounded() {
        assert_eq!(ConcurrencyTier::Low.cap(), 4);
        assert_eq!(ConcurrencyTier::Medium.cap(), 10);
        assert_eq!(ConcurrencyTier::High.cap(), usize::MAX);
    }

    #[test]
    fn effective_concurrency_clamps_to_tier() {
        assert_eq!(effective_concurrency(120, ConcurrencyTier::Low), 4);
        assert_eq!(effective_concurrency(120, ConcurrencyTier::Medium), 10);
        assert_eq!(effective_concurrency(120, ConcurrencyTier::High), 120);
        assert_eq!(effective_concurrency(6, ConcurrencyTier::Medium), 6);
        assert_eq!(effective_concurrency(0, ConcurrencyTier::High), 1);
    }

    #[test]
    fn default_concurrency_uses_tier_ceiling() {
        assert_eq!(default_concurrency(ConcurrencyTier::Low), 4);
        assert_eq!(default_concurrency(ConcurrencyTier::Medium), 10);
        assert_eq!(default_concurrency(ConcurrencyTier::High), 120);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(tier_for(1, 8192), ConcurrencyTier::Low);
        assert_eq!(tier_for(2, 8192), ConcurrencyTier::Low);
        assert_eq!(tier_for(8, 512), ConcurrencyTier::Low);
        assert_eq!(tier_for(8, 2048), ConcurrencyTier::Medium);
        assert_eq!(tier_for(3, 8192), ConcurrencyTier::Medium);
        assert_eq!(tier_for(8, 8192), ConcurrencyTier::High);
        assert_eq!(tier_for(16, 16384), ConcurrencyTier::High);
    }

    #[test]
    fn meminfo_parses_mem_total_kb_to_mb() {
        let text = "MemTotal:       16384000 kB\nMemFree:         1024 kB\n";
        assert_eq!(parse_meminfo_total_mb(text), Some(16_000));
        assert_eq!(parse_meminfo_total_mb("unrelated\ntext\n"), None);
        assert_eq!(parse_meminfo_total_mb("MemTotal: garbage kB\n"), None);
        assert_eq!(parse_meminfo_total_mb(""), None);
    }

    #[test]
    fn detect_tier_returns_a_valid_tier() {
        let tier = detect_tier();
        assert!(matches!(
            tier,
            ConcurrencyTier::Low | ConcurrencyTier::Medium | ConcurrencyTier::High
        ));
    }
}
