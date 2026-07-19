use crate::scanner::ProbeResult;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchPolicy {
    pub promote_after: u32,
    pub demote_after: u32,
    pub switch_margin: f64,
    pub cooldown_cycles: u64,
}

impl Default for WatchPolicy {
    fn default() -> Self {
        Self {
            promote_after: 2,
            demote_after: 2,
            switch_margin: 0.10,
            cooldown_cycles: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchState {
    pub schema_version: u32,
    pub source_fingerprint: u64,
    pub profile_fingerprint: u64,
    pub targets: Vec<String>,
    pub cycle: u64,
    pub stable_primary: Option<String>,
    pub candidate: Option<String>,
    pub candidate_streak: u32,
    pub unhealthy_streak: u32,
    pub last_switch_cycle: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchTransition {
    pub observed_primary: Option<String>,
    pub stable_primary: Option<String>,
    pub changed: bool,
    pub healthy: bool,
    pub reason: String,
}

impl WatchState {
    pub fn new(source_fingerprint: u64, profile_fingerprint: u64, targets: Vec<String>) -> Self {
        Self {
            schema_version: 1,
            source_fingerprint,
            profile_fingerprint,
            targets,
            cycle: 0,
            stable_primary: None,
            candidate: None,
            candidate_streak: 0,
            unhealthy_streak: 0,
            last_switch_cycle: None,
        }
    }

    pub fn compatible(&self, source_fingerprint: u64, profile_fingerprint: u64) -> bool {
        self.schema_version == 1
            && self.source_fingerprint == source_fingerprint
            && self.profile_fingerprint == profile_fingerprint
            && !self.targets.is_empty()
    }

    pub fn advance(
        &mut self,
        results: &[ProbeResult],
        policy: WatchPolicy,
        healthy: impl Fn(&ProbeResult) -> bool,
    ) -> WatchTransition {
        self.cycle = self.cycle.saturating_add(1);
        let mut ranked: Vec<&ProbeResult> = results.iter().filter(|r| healthy(r)).collect();
        ranked.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.ip.cmp(&b.ip))
        });
        let observed = ranked.first().map(|r| r.ip.clone());
        let stable_result = self
            .stable_primary
            .as_deref()
            .and_then(|ip| ranked.iter().find(|r| r.ip == ip).copied());
        let healthy_stable = stable_result.is_some();
        let previous = self.stable_primary.clone();

        if let Some(observed_ip) = observed.as_deref() {
            if self.candidate.as_deref() == Some(observed_ip) {
                self.candidate_streak = self.candidate_streak.saturating_add(1);
            } else {
                self.candidate = Some(observed_ip.to_string());
                self.candidate_streak = 1;
            }
        } else {
            self.candidate = None;
            self.candidate_streak = 0;
        }

        if healthy_stable {
            self.unhealthy_streak = 0;
            let margin_ok = stable_result.is_none_or(|stable| {
                observed
                    .as_deref()
                    .and_then(|ip| ranked.iter().find(|r| r.ip == ip))
                    .is_some_and(|candidate| {
                        candidate.ip == self.stable_primary.as_deref().unwrap_or_default()
                            || candidate.score >= stable.score * (1.0 + policy.switch_margin)
                    })
            });
            let cooldown_ok = self
                .last_switch_cycle
                .is_none_or(|last| self.cycle.saturating_sub(last) >= policy.cooldown_cycles);
            if observed.as_deref() != self.stable_primary.as_deref()
                && margin_ok
                && cooldown_ok
                && self.candidate_streak >= policy.promote_after.max(1)
            {
                self.stable_primary = observed.clone();
                self.last_switch_cycle = Some(self.cycle);
            }
        } else if self.stable_primary.is_some() {
            self.unhealthy_streak = self.unhealthy_streak.saturating_add(1);
            if self.unhealthy_streak >= policy.demote_after.max(1) {
                self.stable_primary = None;
                self.last_switch_cycle = Some(self.cycle);
                self.unhealthy_streak = 0;
            }
        } else if self.candidate_streak >= policy.promote_after.max(1) {
            let cooldown_ok = self
                .last_switch_cycle
                .is_none_or(|last| self.cycle.saturating_sub(last) >= policy.cooldown_cycles);
            if cooldown_ok {
                self.stable_primary = observed.clone();
                self.last_switch_cycle = Some(self.cycle);
            }
        }

        let changed = previous != self.stable_primary;
        let reason = if changed {
            if self.stable_primary.is_some() {
                "stable recommendation promoted".to_string()
            } else {
                "stable recommendation demoted".to_string()
            }
        } else if !healthy_stable && previous.is_some() {
            format!(
                "primary unhealthy ({}/{})",
                self.unhealthy_streak, policy.demote_after
            )
        } else if observed != self.stable_primary {
            format!(
                "candidate pending ({}/{})",
                self.candidate_streak, policy.promote_after
            )
        } else {
            "stable recommendation retained".to_string()
        };

        WatchTransition {
            observed_primary: observed,
            stable_primary: self.stable_primary.clone(),
            changed,
            healthy: self.stable_primary.is_some() || !ranked.is_empty(),
            reason,
        }
    }
}

pub fn fingerprint<T: Serialize>(value: &T) -> u64 {
    let Ok(bytes) = serde_json::to_vec(value) else {
        return 0;
    };
    let mut hasher = DefaultHasher::new();
    hasher.write(&bytes);
    hasher.finish()
}

pub fn default_state_path(host: &str, source_fingerprint: u64) -> Option<PathBuf> {
    dirs::config_dir().map(|mut path| {
        path.push("cleanscan");
        path.push(format!(
            "watch-{source_fingerprint:016x}-{:016x}.json",
            fingerprint(&host)
        ));
        path
    })
}

pub fn load(path: &std::path::Path) -> Option<WatchState> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            eprintln!("failed to read watch state {}: {error}", path.display());
            return None;
        }
    };
    match serde_json::from_str(&content) {
        Ok(state) => Some(state),
        Err(error) => {
            eprintln!("failed to parse watch state {}: {error}", path.display());
            None
        }
    }
}

pub fn save(path: &std::path::Path, state: &WatchState) -> std::io::Result<()> {
    let content = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temp, content)?;
    std::fs::rename(temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(ip: &str, score: f64) -> ProbeResult {
        ProbeResult {
            ip: ip.to_string(),
            protocol: "h2".to_string(),
            ok: 1,
            fail: 0,
            completed: 1,
            avg: 0.01,
            p50: 0.01,
            p90: 0.01,
            p95: 0.01,
            max: 0.01,
            jitter: 0.0,
            stddev: 0.0,
            loss: 0,
            packet_loss: 0.0,
            samples: vec![0.01],
            failures: vec![],
            diagnostics: vec![],
            success_rate: 1.0,
            score,
            colo: None,
            country: None,
            cold_ms: None,
            stopped_early: false,
            min_score: score,
            max_score: score,
            success_rate_lower: 0.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: Vec::new(),
            health_ok: true,
        }
    }

    #[test]
    fn promotion_requires_a_streak() {
        let mut state = WatchState::new(1, 2, vec!["1.1.1.1".into()]);
        let policy = WatchPolicy::default();
        assert!(
            !state
                .advance(&[result("1.1.1.1", 1.0)], policy, |r| r.ok > 0)
                .changed
        );
        assert!(
            state
                .advance(&[result("1.1.1.1", 1.0)], policy, |r| r.ok > 0)
                .changed
        );
        assert_eq!(state.stable_primary.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn target_fingerprint_is_not_used_as_selection_identity() {
        let state = WatchState::new(42, 7, vec!["1.1.1.1".into()]);
        assert!(state.compatible(42, 7));
        assert!(!state.compatible(43, 7));
    }
}
