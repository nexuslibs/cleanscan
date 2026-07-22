//! Networking-free adaptive concurrency policy.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Tuning values for the adaptive controller. These are intentionally kept
/// out of user configuration until production measurements justify exposing
/// them as compatibility-sensitive settings.
#[derive(Debug, Clone, Copy)]
pub struct TuningParams {
    /// How long an observation remains relevant to the rolling metrics.
    pub window: Duration,
    /// Maximum observations retained, even during a burst.
    pub window_capacity: usize,
    /// Minimum endpoint-relevant outcomes before policy decisions are allowed.
    pub min_samples: usize,
    /// Successful latency samples needed to establish the persistent baseline.
    pub baseline_samples: usize,
    /// Minimum time between actual resizes.
    pub cooldown: Duration,
    /// Minimum time after a downscale before an upscale may occur.
    pub scale_down_dwell: Duration,
    /// Healthy decision epochs needed after a downscale before recovery.
    pub recovery_streak: usize,
    /// Consecutive matching signal epochs needed for a resize.
    pub hysteresis_streak: usize,
    /// Workers added by one scale-up decision.
    pub scale_up_step: usize,
    /// Workers removed by one scale-down decision.
    pub scale_down_step: usize,
    /// Timeout fraction that indicates overload.
    pub timeout_rate_threshold: f64,
    /// Non-timeout failure fraction that indicates overload.
    pub error_rate_threshold: f64,
    /// p90 multiplier that indicates latency degradation.
    pub latency_degradation_ratio: f64,
    /// Minimum degraded successful latency samples required before downscaling.
    pub latency_degradation_min_samples: usize,
    /// p90 multiplier still considered healthy for scale-up.
    pub healthy_latency_ratio: f64,
    /// Minimum relative throughput improvement required to justify another
    /// scale-up after the previous resize. A value of `0.02` means that a
    /// later worker increase must improve throughput by more than two percent.
    pub throughput_improvement_threshold: f64,
    /// Remaining measured attempts required per desired worker.
    pub remaining_work_per_worker: usize,
    /// Minimum success fraction considered stable.
    pub stable_success_rate: f64,
}

impl Default for TuningParams {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(15),
            window_capacity: 256,
            min_samples: 12,
            baseline_samples: 8,
            cooldown: Duration::from_secs(2),
            scale_down_dwell: Duration::from_secs(5),
            recovery_streak: 3,
            hysteresis_streak: 2,
            scale_up_step: 1,
            scale_down_step: 1,
            timeout_rate_threshold: 0.25,
            error_rate_threshold: 0.35,
            latency_degradation_ratio: 1.5,
            latency_degradation_min_samples: 2,
            healthy_latency_ratio: 1.2,
            throughput_improvement_threshold: 0.02,
            remaining_work_per_worker: 4,
            stable_success_rate: 0.90,
        }
    }
}

impl TuningParams {
    /// Keep policy construction safe even when callers build tuning values
    /// directly instead of using the defaults. The controller must never be
    /// disabled accidentally by a zero capacity/streak/step or an invalid
    /// threshold.
    fn normalized(self) -> Self {
        let defaults = Self::default();
        Self {
            window: if self.window.is_zero() {
                defaults.window
            } else {
                self.window
            },
            window_capacity: self.window_capacity.max(1),
            min_samples: self.min_samples.max(1),
            baseline_samples: self.baseline_samples.max(1),
            cooldown: self.cooldown,
            scale_down_dwell: self.scale_down_dwell,
            recovery_streak: self.recovery_streak.max(1),
            hysteresis_streak: self.hysteresis_streak.max(1),
            scale_up_step: self.scale_up_step.max(1),
            scale_down_step: self.scale_down_step.max(1),
            timeout_rate_threshold: if self.timeout_rate_threshold.is_finite() {
                self.timeout_rate_threshold.clamp(0.0, 1.0)
            } else {
                defaults.timeout_rate_threshold
            },
            error_rate_threshold: if self.error_rate_threshold.is_finite() {
                self.error_rate_threshold.clamp(0.0, 1.0)
            } else {
                defaults.error_rate_threshold
            },
            latency_degradation_ratio: if self.latency_degradation_ratio.is_finite() {
                self.latency_degradation_ratio.max(1.0)
            } else {
                defaults.latency_degradation_ratio
            },
            latency_degradation_min_samples: self.latency_degradation_min_samples.max(1),
            healthy_latency_ratio: if self.healthy_latency_ratio.is_finite() {
                self.healthy_latency_ratio.max(1.0)
            } else {
                defaults.healthy_latency_ratio
            },
            throughput_improvement_threshold: if self.throughput_improvement_threshold.is_finite() {
                self.throughput_improvement_threshold.clamp(0.0, 1.0)
            } else {
                defaults.throughput_improvement_threshold
            },
            remaining_work_per_worker: self.remaining_work_per_worker.max(1),
            stable_success_rate: if self.stable_success_rate.is_finite() {
                self.stable_success_rate.clamp(0.0, 1.0)
            } else {
                defaults.stable_success_rate
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKind {
    Success,
    Timeout,
    ConnectionFailure,
    OtherFailure,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeObservation {
    pub kind: ObservationKind,
    /// Steady-state latency only. Warmup probes never create observations;
    /// the failed-warmup fallback may record success with no latency.
    pub latency: Option<f64>,
    pub at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    NoChange,
    ScaleUp(usize),
    ScaleDown(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalDirection {
    None,
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub signal: SignalDirection,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyResult {
    pub resized: bool,
    pub workers: usize,
}

#[derive(Debug, Clone, Copy)]
struct WindowObservation {
    observation: ProbeObservation,
}

#[derive(Debug, Clone)]
struct MetricsWindow {
    observations: VecDeque<WindowObservation>,
    params: TuningParams,
}

impl MetricsWindow {
    fn new(params: TuningParams) -> Self {
        Self {
            observations: VecDeque::with_capacity(params.window_capacity),
            params,
        }
    }

    fn evict(&mut self, now: Instant) {
        while self.observations.front().is_some_and(|entry| {
            now.checked_duration_since(entry.observation.at)
                .is_some_and(|age| age > self.params.window)
        }) {
            self.observations.pop_front();
        }
    }

    fn record(&mut self, observation: ProbeObservation) {
        self.evict(observation.at);
        self.observations
            .push_back(WindowObservation { observation });
        while self.observations.len() > self.params.window_capacity {
            self.observations.pop_front();
        }
    }
}

/// Stateful adaptive worker policy. It has no networking or async runtime
/// dependencies and is deterministic when driven with explicit Instants.
#[derive(Debug, Clone)]
pub struct AdaptivePolicy {
    workers: usize,
    min_workers: usize,
    max_workers: usize,
    params: TuningParams,
    window: MetricsWindow,
    baseline: Option<f64>,
    baseline_samples: usize,
    baseline_latency_samples: Vec<f64>,
    last_resize: Option<Instant>,
    last_scale_down: Option<Instant>,
    scale_up_reference: Option<(Instant, f64)>,
    scale_up_blocked: bool,
    up_streak: usize,
    down_streak: usize,
    healthy_streak: usize,
}

impl AdaptivePolicy {
    pub fn new(workers: usize, min_workers: usize, max_workers: usize) -> Self {
        Self::with_params(workers, min_workers, max_workers, TuningParams::default())
    }

    pub fn with_params(
        workers: usize,
        min_workers: usize,
        max_workers: usize,
        params: TuningParams,
    ) -> Self {
        let params = params.normalized();
        let min_workers = min_workers.max(1);
        let max_workers = max_workers.max(min_workers);
        let workers = workers.clamp(min_workers, max_workers);
        Self {
            workers,
            min_workers,
            max_workers,
            params,
            window: MetricsWindow::new(params),
            baseline: None,
            baseline_samples: 0,
            baseline_latency_samples: Vec::with_capacity(params.baseline_samples),
            last_resize: None,
            last_scale_down: None,
            scale_up_reference: None,
            scale_up_blocked: false,
            up_streak: 0,
            down_streak: 0,
            healthy_streak: 0,
        }
    }

    /// Update the live lower bound without resetting adaptive history.
    pub fn set_min_workers(&mut self, requested: usize) -> ApplyResult {
        self.min_workers = requested.max(1).min(self.max_workers);
        if self.workers < self.min_workers {
            self.workers = self.min_workers;
            ApplyResult {
                resized: true,
                workers: self.workers,
            }
        } else {
            ApplyResult {
                resized: false,
                workers: self.workers,
            }
        }
    }

    pub fn record(&mut self, observation: ProbeObservation) {
        self.window.record(observation);
        if self.baseline.is_none()
            && observation.kind == ObservationKind::Success
            && observation
                .latency
                .is_some_and(|latency| latency.is_finite())
        {
            self.baseline_latency_samples
                .push(observation.latency.expect("latency checked above").max(0.0));
            self.baseline_samples = self.baseline_samples.saturating_add(1);
            if self.baseline_samples >= self.params.baseline_samples {
                self.baseline = Some(percentile(&self.baseline_latency_samples, 0.90));
            }
        }
    }

    fn observations_at(&self, now: Instant) -> Vec<ProbeObservation> {
        self.window
            .observations
            .iter()
            .filter_map(|entry| {
                now.checked_duration_since(entry.observation.at)
                    .is_some_and(|age| age <= self.params.window)
                    .then_some(entry.observation)
            })
            .collect()
    }

    /// Number of endpoint-relevant outcomes currently in the rolling window.
    pub fn completed_count(&self, now: Instant) -> usize {
        self.observations_at(now)
            .into_iter()
            .filter(|observation| !matches!(observation.kind, ObservationKind::Cancelled))
            .count()
    }

    /// Number of successful measured outcomes currently in the window.
    pub fn success_count(&self, now: Instant) -> usize {
        self.observations_at(now)
            .into_iter()
            .filter(|observation| observation.kind == ObservationKind::Success)
            .count()
    }

    /// Number of timeout outcomes currently in the window.
    pub fn timeout_count(&self, now: Instant) -> usize {
        self.observations_at(now)
            .into_iter()
            .filter(|observation| observation.kind == ObservationKind::Timeout)
            .count()
    }

    /// Current p90 over valid successful steady-state latencies.
    pub fn latency_p90(&self, now: Instant) -> Option<f64> {
        let latencies: Vec<f64> = self
            .observations_at(now)
            .into_iter()
            .filter(|observation| observation.kind == ObservationKind::Success)
            .filter_map(|observation| observation.latency)
            .filter(|latency| latency.is_finite())
            .collect();
        (!latencies.is_empty()).then(|| percentile(&latencies, 0.90))
    }

    /// Estimate throughput over a completed interval in the rolling window.
    /// At least two distinct completion timestamps are required; treating a
    /// burst of same-timestamp synthetic events as an infinite rate makes the
    /// plateau detector permanently over-optimistic.
    fn throughput_per_second(&self, now: Instant) -> Option<f64> {
        let observations: Vec<_> = self
            .observations_at(now)
            .into_iter()
            .filter(|observation| observation.kind != ObservationKind::Cancelled)
            .collect();
        let first = observations.first()?.at;
        let last = observations.last()?.at;
        let elapsed = elapsed_since(last, first).as_secs_f64();
        (elapsed > 0.0).then_some(observations.len() as f64 / elapsed)
    }

    /// Throughput since a resize. This intentionally excludes all
    /// pre-resize observations from the numerator and denominator so a slow
    /// or fast period before the resize cannot make the new worker count look
    /// equivalent to the old one.
    fn throughput_since(&self, now: Instant, anchor: Instant) -> Option<f64> {
        let samples = self.observations_since(now, anchor);
        if samples == 0 {
            return None;
        }
        let elapsed = elapsed_since(now, anchor).as_secs_f64();
        (elapsed > 0.0).then_some(samples as f64 / elapsed)
    }

    fn observations_since(&self, now: Instant, anchor: Instant) -> usize {
        self.observations_at(now)
            .into_iter()
            .filter(|observation| {
                observation.at > anchor && observation.kind != ObservationKind::Cancelled
            })
            .count()
    }

    pub fn evaluate(&self, now: Instant, remaining_work: usize) -> Decision {
        if self.min_workers == self.max_workers {
            return self.no_change(SignalDirection::None, "worker bounds are fixed");
        }

        let observations = self.observations_at(now);
        if observations.is_empty() {
            return self.no_change(SignalDirection::None, "no recent observations");
        }

        let completed = self.completed_count(now);
        if completed == 0 {
            return self.no_change(SignalDirection::None, "no endpoint outcomes in window");
        }
        if completed < self.params.min_samples {
            return self.no_change(SignalDirection::None, "warming up / insufficient samples");
        }

        let timeouts = self.timeout_count(now);
        let successes = self.success_count(now);
        let completed_rate = completed as f64;
        let timeout_rate = timeouts as f64 / completed_rate;

        // A failed target is not evidence that concurrency is too high. Only
        // downscale on timeout pressure when successful traffic is present;
        // all-failure windows commonly represent dead or blocked IPs.
        if successes > 0 && timeout_rate > self.params.timeout_rate_threshold {
            return self.scale_down(
                now,
                "timeout pressure exceeds adaptive threshold",
                "timeout pressure is sustained",
            );
        }

        let latencies: Vec<f64> = observations
            .iter()
            .filter(|observation| observation.kind == ObservationKind::Success)
            .filter_map(|observation| observation.latency)
            .filter(|latency| latency.is_finite())
            .collect();
        let p90 = (!latencies.is_empty()).then(|| percentile(&latencies, 0.90));
        debug_assert_eq!(p90, self.latency_p90(now));
        if let (Some(baseline), Some(current)) = (self.baseline, p90) {
            let degradation_limit = baseline * self.params.latency_degradation_ratio;
            let degraded_samples = latencies
                .iter()
                .filter(|latency| **latency > degradation_limit)
                .count();
            if current > degradation_limit
                && degraded_samples >= self.params.latency_degradation_min_samples
            {
                return self.scale_down(
                    now,
                    "latency degradation exceeds adaptive threshold",
                    "latency degradation is sustained",
                );
            }
        }

        let Some(baseline) = self.baseline else {
            return self.no_change(SignalDirection::None, "latency baseline is not established");
        };
        let Some(current) = p90 else {
            return self.no_change(
                SignalDirection::None,
                "successful latency samples are unavailable",
            );
        };
        let success_rate = successes as f64 / completed_rate;
        let healthy_latency = current <= baseline * self.params.healthy_latency_ratio;
        let desired_workers = self.workers.saturating_add(1);
        let enough_work =
            remaining_work >= desired_workers.saturating_mul(self.params.remaining_work_per_worker);
        let dwell_elapsed = self
            .last_scale_down
            .is_none_or(|anchor| elapsed_since(now, anchor) >= self.params.scale_down_dwell);
        let cooldown_elapsed = self
            .last_resize
            .is_none_or(|anchor| elapsed_since(now, anchor) >= self.params.cooldown);
        let healthy = success_rate >= self.params.stable_success_rate && healthy_latency;
        if healthy {
            if self.workers < self.max_workers && enough_work && dwell_elapsed && cooldown_elapsed {
                let action = if self.healthy_streak.saturating_add(1) >= self.params.recovery_streak
                {
                    Action::ScaleUp(self.params.scale_up_step)
                } else {
                    Action::NoChange
                };
                return Decision {
                    action,
                    signal: SignalDirection::Up,
                    reason: if action == Action::NoChange {
                        "healthy conditions do not yet justify scale-up".to_string()
                    } else {
                        "healthy conditions support gradual scale-up".to_string()
                    },
                };
            }

            let reason = if !enough_work {
                "healthy conditions do not yet justify scale-up: insufficient remaining work"
            } else if !dwell_elapsed {
                "healthy conditions do not yet justify scale-up: recovery dwell active"
            } else if !cooldown_elapsed {
                "healthy conditions do not yet justify scale-up: cooldown active"
            } else {
                "healthy conditions do not yet justify scale-up"
            };
            return self.no_change(SignalDirection::None, reason);
        }

        self.no_change(
            SignalDirection::None,
            "conditions are not stable enough to scale",
        )
    }

    pub fn apply(&mut self, decision: &Decision, now: Instant) -> ApplyResult {
        match decision.signal {
            SignalDirection::Up => {
                self.up_streak = self.up_streak.saturating_add(1);
                self.down_streak = 0;
                self.healthy_streak = self.healthy_streak.saturating_add(1);
            }
            SignalDirection::Down if matches!(decision.action, Action::ScaleDown(_)) => {
                self.down_streak = self.down_streak.saturating_add(1);
                self.up_streak = 0;
                self.healthy_streak = 0;
            }
            SignalDirection::Down => {
                // A cooldown- or bound-blocked decision is not a hysteresis
                // epoch. Requiring fresh pressure after the gate prevents a
                // long cooldown from preloading the downscale streak.
                self.down_streak = 0;
                self.up_streak = 0;
                self.healthy_streak = 0;
            }
            SignalDirection::None => {
                self.up_streak = 0;
                self.down_streak = 0;
                self.healthy_streak = 0;
            }
        }

        let should_resize = match (decision.signal, decision.action) {
            (SignalDirection::Up, Action::ScaleUp(step)) => {
                let wants_scale_up = if self.scale_up_blocked {
                    false
                } else if let Some((anchor, reference)) = self.scale_up_reference {
                    let enough_post_resize_samples =
                        self.observations_since(now, anchor) >= self.params.min_samples;
                    let throughput = self.throughput_since(now, anchor);
                    if enough_post_resize_samples
                        && throughput.is_some_and(|current| {
                            current
                                <= reference * (1.0 + self.params.throughput_improvement_threshold)
                        })
                    {
                        // The latest increase did not improve throughput. Keep
                        // this worker count as the stable point and do not keep
                        // ramping into a flat or slower region.
                        self.scale_up_blocked = true;
                        false
                    } else {
                        self.up_streak >= self.params.hysteresis_streak
                    }
                } else {
                    self.up_streak >= self.params.hysteresis_streak
                };
                wants_scale_up && self.workers < self.max_workers && step > 0
            }
            (SignalDirection::Down, Action::ScaleDown(step)) => {
                self.down_streak >= self.params.hysteresis_streak
                    && self.workers > self.min_workers
                    && step > 0
            }
            _ => false,
        };
        if !should_resize {
            return ApplyResult {
                resized: false,
                workers: self.workers,
            };
        }

        let (new_workers, downscaled) = match decision.action {
            Action::ScaleUp(step) => (
                self.workers.saturating_add(step).min(self.max_workers),
                false,
            ),
            Action::ScaleDown(step) => (
                self.workers.saturating_sub(step).max(self.min_workers),
                true,
            ),
            Action::NoChange => (self.workers, false),
        };
        if new_workers == self.workers {
            return ApplyResult {
                resized: false,
                workers: self.workers,
            };
        }
        self.workers = new_workers;
        self.last_resize = Some(now);
        if downscaled {
            self.last_scale_down = Some(now);
            self.scale_up_reference = None;
            self.scale_up_blocked = false;
            self.healthy_streak = 0;
        } else {
            // Capture the pre-resize rate. The next comparison uses only
            // completions after `now`, rather than a rolling window that
            // straddles the resize.
            self.scale_up_reference = self
                .throughput_per_second(now)
                .map(|throughput| (now, throughput));
            // Without a measurable pre-resize interval there is no evidence
            // that another increase is beneficial. Stop at this stable point
            // instead of ramping blindly on a burst of same-timestamp events.
            if self.scale_up_reference.is_none() {
                self.scale_up_blocked = true;
            }
        }
        self.up_streak = 0;
        self.down_streak = 0;
        ApplyResult {
            resized: true,
            workers: self.workers,
        }
    }

    fn scale_down(&self, now: Instant, available: &str, sustained: &str) -> Decision {
        let cooldown = self
            .last_resize
            .is_some_and(|anchor| elapsed_since(now, anchor) < self.params.cooldown);
        Decision {
            action: if self.workers > self.min_workers && !cooldown {
                Action::ScaleDown(self.params.scale_down_step)
            } else {
                Action::NoChange
            },
            signal: SignalDirection::Down,
            reason: if cooldown {
                available.to_string()
            } else {
                sustained.to_string()
            },
        }
    }

    fn no_change(&self, signal: SignalDirection, reason: &str) -> Decision {
        Decision {
            action: Action::NoChange,
            signal,
            reason: reason.to_string(),
        }
    }
}

fn elapsed_since(now: Instant, then: Instant) -> Duration {
    now.checked_duration_since(then).unwrap_or_default()
}

fn percentile(values: &[f64], pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    sorted[index.min(sorted.len().saturating_sub(1))]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> TuningParams {
        TuningParams {
            min_samples: 4,
            baseline_samples: 2,
            recovery_streak: 1,
            hysteresis_streak: 2,
            ..TuningParams::default()
        }
    }

    fn success(at: Instant, latency: Option<f64>) -> ProbeObservation {
        ProbeObservation {
            kind: ObservationKind::Success,
            latency,
            at,
        }
    }

    #[test]
    fn baseline_and_hysteresis_are_deterministic() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        for i in 0..4 {
            controller.record(success(start + Duration::from_millis(i), Some(10.0)));
        }
        let decision = controller.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(decision.signal, SignalDirection::Up);
        assert_eq!(decision.action, Action::ScaleUp(1));
        assert!(
            !controller
                .apply(&decision, start + Duration::from_secs(1))
                .resized
        );
        let decision = controller.evaluate(start + Duration::from_secs(1), 100);
        assert!(
            controller
                .apply(&decision, start + Duration::from_secs(1))
                .resized
        );
        assert_eq!(controller.workers, 3);
    }

    #[test]
    fn cancelled_is_excluded_from_pressure_rates() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        for i in 0..4 {
            controller.record(ProbeObservation {
                kind: ObservationKind::Cancelled,
                latency: None,
                at: start + Duration::from_millis(i),
            });
        }
        let decision = controller.evaluate(start + Duration::from_secs(1), 10);
        assert_eq!(decision.action, Action::NoChange);
        assert_eq!(decision.signal, SignalDirection::None);
    }

    #[test]
    fn stale_observations_are_evicted() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        controller.record(success(start, Some(10.0)));
        let decision = controller.evaluate(start + Duration::from_secs(16), 10);
        assert_eq!(decision.reason, "no recent observations");
    }

    #[test]
    fn aggregates_and_baseline_survive_window_eviction() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        controller.record(success(start, Some(10.0)));
        controller.record(success(start + Duration::from_millis(1), Some(11.0)));
        controller.record(ProbeObservation {
            kind: ObservationKind::Timeout,
            latency: None,
            at: start + Duration::from_millis(2),
        });
        assert_eq!(
            controller.completed_count(start + Duration::from_secs(1)),
            3
        );
        assert_eq!(controller.success_count(start + Duration::from_secs(1)), 2);
        assert_eq!(controller.timeout_count(start + Duration::from_secs(1)), 1);
        assert_eq!(
            controller.latency_p90(start + Duration::from_secs(1)),
            Some(11.0)
        );

        let later = start + Duration::from_secs(16);
        assert_eq!(controller.completed_count(later), 0);
        assert_eq!(controller.baseline, Some(11.0));
        assert_eq!(controller.baseline_samples, 2);
    }

    #[test]
    fn evaluate_is_read_only() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        for i in 0..4 {
            controller.record(success(start + Duration::from_millis(i), Some(10.0)));
        }
        let before = controller.clone();
        let first = controller.evaluate(start + Duration::from_secs(1), 100);
        let second = controller.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(first, second);
        assert_eq!(controller.workers, before.workers);
        assert_eq!(controller.up_streak, before.up_streak);
        assert_eq!(controller.down_streak, before.down_streak);
        assert_eq!(controller.last_resize, before.last_resize);
    }

    #[test]
    fn direct_tuning_values_are_normalized() {
        let controller = AdaptivePolicy::with_params(
            0,
            0,
            0,
            TuningParams {
                window_capacity: 0,
                min_samples: 0,
                baseline_samples: 0,
                hysteresis_streak: 0,
                scale_up_step: 0,
                scale_down_step: 0,
                remaining_work_per_worker: 0,
                timeout_rate_threshold: f64::NAN,
                latency_degradation_ratio: 0.0,
                ..TuningParams::default()
            },
        );
        assert_eq!(controller.min_workers, 1);
        assert_eq!(controller.max_workers, 1);
        assert_eq!(controller.params.window_capacity, 1);
        assert_eq!(controller.params.min_samples, 1);
        assert_eq!(controller.params.baseline_samples, 1);
        assert_eq!(controller.params.hysteresis_streak, 1);
        assert_eq!(controller.params.scale_up_step, 1);
        assert_eq!(controller.params.scale_down_step, 1);
        assert_eq!(controller.params.remaining_work_per_worker, 1);
        assert!(controller.params.timeout_rate_threshold.is_finite());
        assert_eq!(controller.params.latency_degradation_ratio, 1.0);
    }

    #[test]
    fn single_latency_outlier_does_not_downscale_small_window() {
        let start = Instant::now();
        let mut controller = AdaptivePolicy::with_params(2, 1, 4, params());
        for (i, latency) in [10.0, 10.0, 10.0, 100.0].into_iter().enumerate() {
            controller.record(success(
                start + Duration::from_millis(i as u64),
                Some(latency),
            ));
        }
        let decision = controller.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(decision.action, Action::NoChange);
        assert_eq!(decision.signal, SignalDirection::None);
    }

    #[test]
    fn timeout_pressure_requires_successful_traffic() {
        let start = Instant::now();
        let mut timeouts = AdaptivePolicy::with_params(3, 1, 4, params());
        for i in 0..2 {
            timeouts.record(success(start + Duration::from_millis(i), Some(10.0)));
        }
        for i in 2..4 {
            timeouts.record(ProbeObservation {
                kind: ObservationKind::Timeout,
                latency: None,
                at: start + Duration::from_millis(i),
            });
        }
        let timeout_decision = timeouts.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(timeout_decision.signal, SignalDirection::Down);
        assert_eq!(timeout_decision.action, Action::ScaleDown(1));

        let mut errors = AdaptivePolicy::with_params(3, 1, 4, params());
        for i in 0..4 {
            errors.record(ProbeObservation {
                kind: ObservationKind::OtherFailure,
                latency: None,
                at: start + Duration::from_millis(i),
            });
        }
        let error_decision = errors.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(error_decision.signal, SignalDirection::None);
        assert_eq!(error_decision.action, Action::NoChange);
    }

    #[test]
    fn sustained_latency_degradation_produces_down_signal() {
        let start = Instant::now();
        let mut policy = AdaptivePolicy::with_params(3, 1, 4, params());
        policy.record(success(start, Some(10.0)));
        policy.record(success(start + Duration::from_millis(1), Some(10.0)));
        policy.record(success(start + Duration::from_millis(2), Some(20.0)));
        policy.record(success(start + Duration::from_millis(3), Some(20.0)));
        let decision = policy.evaluate(start + Duration::from_secs(1), 100);
        assert_eq!(decision.signal, SignalDirection::Down);
        assert_eq!(decision.action, Action::ScaleDown(1));
    }

    #[test]
    fn cooldown_does_not_preload_down_hysteresis() {
        let start = Instant::now();
        let mut tuning = params();
        tuning.cooldown = Duration::from_secs(10);
        let mut controller = AdaptivePolicy::with_params(3, 1, 4, tuning);
        for i in 0..4 {
            controller.record(success(start + Duration::from_millis(i), Some(10.0)));
        }
        let healthy = controller.evaluate(start + Duration::from_secs(1), 100);
        controller.apply(&healthy, start + Duration::from_secs(1));
        let healthy = controller.evaluate(start + Duration::from_secs(1), 100);
        assert!(
            controller
                .apply(&healthy, start + Duration::from_secs(1))
                .resized
        );

        for i in 4..8 {
            controller.record(ProbeObservation {
                kind: ObservationKind::Timeout,
                latency: None,
                at: start + Duration::from_millis(i),
            });
        }
        let blocked = controller.evaluate(start + Duration::from_secs(2), 100);
        assert_eq!(blocked.action, Action::NoChange);
        assert_eq!(blocked.signal, SignalDirection::Down);
        controller.apply(&blocked, start + Duration::from_secs(2));

        let first_after_cooldown = controller.evaluate(start + Duration::from_secs(12), 100);
        assert_eq!(first_after_cooldown.action, Action::ScaleDown(1));
        assert!(
            !controller
                .apply(&first_after_cooldown, start + Duration::from_secs(12))
                .resized
        );
        let second_after_cooldown = controller.evaluate(start + Duration::from_secs(12), 100);
        assert!(
            controller
                .apply(&second_after_cooldown, start + Duration::from_secs(12))
                .resized
        );
    }

    #[test]
    fn blocked_healthy_epochs_do_not_preload_scale_up_hysteresis() {
        let start = Instant::now();
        let mut tuning = params();
        tuning.window = Duration::from_secs(1);
        tuning.scale_down_dwell = Duration::from_secs(10);
        tuning.cooldown = Duration::ZERO;
        let mut controller = AdaptivePolicy::with_params(3, 1, 4, tuning);

        for i in 0..2 {
            controller.record(success(start + Duration::from_millis(i), Some(10.0)));
        }
        for i in 2..4 {
            controller.record(ProbeObservation {
                kind: ObservationKind::Timeout,
                latency: None,
                at: start + Duration::from_millis(i),
            });
        }
        let down = controller.evaluate(start + Duration::from_millis(500), 100);
        controller.apply(&down, start + Duration::from_millis(500));
        let down = controller.evaluate(start + Duration::from_millis(500), 100);
        assert!(
            controller
                .apply(&down, start + Duration::from_millis(500))
                .resized
        );

        for i in 0..4 {
            controller.record(success(
                start + Duration::from_secs(2) + Duration::from_millis(i),
                Some(10.0),
            ));
        }
        let blocked = controller.evaluate(start + Duration::from_secs(3), 100);
        assert_eq!(blocked.signal, SignalDirection::None);
        assert!(blocked.reason.contains("recovery dwell"));
        controller.apply(&blocked, start + Duration::from_secs(3));

        for i in 0..4 {
            controller.record(success(
                start + Duration::from_secs(12) + Duration::from_millis(i),
                Some(10.0),
            ));
        }
        let first_eligible = controller.evaluate(start + Duration::from_secs(13), 100);
        assert_eq!(first_eligible.action, Action::ScaleUp(1));
        assert!(
            !controller
                .apply(&first_eligible, start + Duration::from_secs(13))
                .resized
        );
    }

    fn scale_once(policy: &mut AdaptivePolicy, at: Instant) {
        let decision = policy.evaluate(at, 100);
        assert_eq!(decision.action, Action::ScaleUp(1));
        assert!(policy.apply(&decision, at).resized);
    }

    #[test]
    fn throughput_plateau_uses_only_post_resize_observations() {
        let start = Instant::now();
        let mut tuning = params();
        tuning.recovery_streak = 1;
        tuning.hysteresis_streak = 1;
        tuning.cooldown = Duration::ZERO;
        let mut policy = AdaptivePolicy::with_params(5, 1, 7, tuning);

        // Establish a measurable pre-resize rate of roughly five completions
        // per second, then move from 5 to 6 workers.
        for millis in [0, 200, 400, 600] {
            policy.record(success(start + Duration::from_millis(millis), Some(10.0)));
        }
        scale_once(&mut policy, start + Duration::from_secs(1));

        // This is flat/slower than the pre-resize rate. A rolling calculation
        // over all observations could hide that fact by mixing both epochs.
        for millis in [1200, 1400, 1600, 1800] {
            policy.record(success(start + Duration::from_millis(millis), Some(10.0)));
        }
        let decision = policy.evaluate(start + Duration::from_secs(2), 100);
        assert_eq!(decision.action, Action::ScaleUp(1));
        assert!(
            !policy
                .apply(&decision, start + Duration::from_secs(2))
                .resized
        );
        assert_eq!(policy.workers, 6);

        // Once blocked, a healthy window must not keep increasing concurrency.
        let decision = policy.evaluate(start + Duration::from_secs(2), 100);
        assert!(
            !policy
                .apply(&decision, start + Duration::from_secs(2))
                .resized
        );
        assert_eq!(policy.workers, 6);
    }

    #[test]
    fn throughput_improvement_allows_the_next_worker() {
        let start = Instant::now();
        let mut tuning = params();
        tuning.recovery_streak = 1;
        tuning.hysteresis_streak = 1;
        tuning.cooldown = Duration::ZERO;
        let mut policy = AdaptivePolicy::with_params(5, 1, 7, tuning);
        for millis in [0, 200, 400, 600] {
            policy.record(success(start + Duration::from_millis(millis), Some(10.0)));
        }
        scale_once(&mut policy, start + Duration::from_secs(1));

        // A genuinely faster post-resize epoch is allowed to advance to 7.
        for millis in [1100, 1200, 1300, 1400] {
            policy.record(success(start + Duration::from_millis(millis), Some(10.0)));
        }
        let decision = policy.evaluate(start + Duration::from_millis(1500), 100);
        assert_eq!(decision.action, Action::ScaleUp(1));
        assert!(
            policy
                .apply(&decision, start + Duration::from_millis(1500))
                .resized
        );
        assert_eq!(policy.workers, 7);
    }

    #[test]
    fn cancelled_observations_do_not_inflate_throughput() {
        let start = Instant::now();
        let mut policy = AdaptivePolicy::with_params(5, 1, 6, params());
        for millis in [0, 200, 400, 600] {
            policy.record(success(start + Duration::from_millis(millis), Some(10.0)));
        }
        policy.record(ProbeObservation {
            kind: ObservationKind::Cancelled,
            latency: None,
            at: start + Duration::from_millis(800),
        });

        // Four real completions over 600ms is the rate; the cancelled task is
        // not a completed probe and must not make this look like five.
        let rate = policy.throughput_per_second(start + Duration::from_secs(1));
        assert_eq!(rate, Some(4.0 / 0.6));
    }
}
