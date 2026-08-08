//! The TUI event loop: `run_tui` spawns the scanner, investigator, and
//! speed-test workers, drains their telemetry channels, and drives the
//! render/input cycle. The watch-cycle and manifest helpers used only by the
//! loop live here too.

use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};

use crossterm::event::{self, EnableMouseCapture, Event, KeyEventKind};

use crate::config::AppConfig;
use crate::scanner::{ProbeResult, ScanControl, ScanProgress};
use crate::speed::{SpeedDirection, SpeedResult};

use super::state::{
    FocusTarget, InvestigationState, RunKind, RunRecord, ScanLifecycle, Screen, WizardStep,
};
use super::{App, RestoreGuard};

pub(super) fn build_current_manifest(app: &App) -> crate::Manifest {
    crate::build_manifest(
        &app.config,
        app.last_targets.clone(),
        &app.results,
        app.manifest_thresholds,
        &app.manifest_min_confidence,
        app.manifest_backups,
    )
}

fn queue_manifest_write(
    path: &str,
    manifest: crate::Manifest,
    result_tx: &std::sync::mpsc::Sender<Result<(), String>>,
) {
    let path = path.to_string();
    let result_tx = result_tx.clone();
    std::thread::spawn(move || {
        let result = crate::write_manifest(&path, &manifest).map_err(|error| error.to_string());
        let _ = result_tx.send(result);
    });
}

fn watch_profile_fingerprint(config: &AppConfig) -> u64 {
    crate::watch::fingerprint(&(
        config.host.clone(),
        config.path.clone(),
        config.ports.clone(),
        config.expected_statuses.clone(),
        config.required_body_markers.clone(),
        config.required_headers.clone(),
        config.follow_redirects,
        config.health_checks.clone(),
    ))
}

fn prepare_watch_targets(
    app: &mut App,
    mut targets: Vec<String>,
    source_fingerprint: u64,
) -> Vec<String> {
    if app.watch_interval.is_none() {
        return targets;
    }
    let profile_fingerprint = watch_profile_fingerprint(&app.config);
    if let Some(state) = &app.watch_state {
        if state.compatible(source_fingerprint, profile_fingerprint) {
            return targets;
        }
        app.watch_state = None;
        app.watch_state_path = None;
    }
    let path = app
        .watch_state_path
        .clone()
        .map(std::path::PathBuf::from)
        .or_else(|| crate::watch::default_state_path(&app.config.host, source_fingerprint));
    let Some(path) = path else {
        app.toast_warn("Unable to determine watch state path; continuing without persistence");
        return targets;
    };
    app.watch_state_path = Some(path.to_string_lossy().into_owned());
    if !app.watch_new_sample {
        if let Some(saved) = crate::watch::load(&path)
            .filter(|saved| saved.compatible(source_fingerprint, profile_fingerprint))
        {
            targets = saved.targets.clone();
            app.watch_state = Some(saved);
            return targets;
        }
    }
    let state =
        crate::watch::WatchState::new(source_fingerprint, profile_fingerprint, targets.clone());
    if let Err(error) = crate::watch::save(&path, &state) {
        app.toast_warn(format!("Watch state write failed: {error}"));
    }
    app.watch_state = Some(state);
    targets
}

/// Run the full TUI loop.
#[allow(clippy::too_many_arguments)]
pub fn run_tui(
    config: AppConfig,
    cli_cidr: Vec<String>,
    cli_ips: Option<String>,
    explicit_seed: Option<u64>,
    watch_interval: Option<u64>,
    manifest_path: Option<String>,
    min_success_rate: Option<f64>,
    max_p95_ms: Option<f64>,
    manifest_min_confidence: String,
    manifest_backups: usize,
    watch_policy: crate::watch::WatchPolicy,
    watch_state_path: Option<&str>,
    watch_new_sample: bool,
    mut update_receiver: Option<crate::updater::UpdateReceiver>,
    system_network: crate::system_info::SystemNetworkInfo,
) -> anyhow::Result<()> {
    let has_cli_targets = cli_ips.is_some() || !cli_cidr.is_empty();

    let mut config = config;
    config.seed = explicit_seed.unwrap_or_else(|| {
        if config.seed == 0 {
            rand::random()
        } else {
            config.seed
        }
    });
    let config_arc = Arc::new(config);
    let (tx, rx) = std::sync::mpsc::channel::<ProbeResult>();
    // Progress is telemetry, not work completion. Bound it so a fast scanner
    // cannot grow an unbounded queue or starve rendering/input handling.
    let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel::<ScanProgress>(128);
    let (speed_tx, speed_rx) = std::sync::mpsc::channel::<SpeedResult>();
    let (manifest_tx, manifest_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (control_tx, control_rx) = std::sync::mpsc::channel::<ScanControl>();
    let (investigation_tx, investigation_rx) = std::sync::mpsc::channel::<ProbeResult>();
    let (investigation_progress_tx, investigation_progress_rx) =
        std::sync::mpsc::sync_channel::<ScanProgress>(64);
    let progress_sender = progress_tx.clone();
    let paused = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));

    let mut terminal = ratatui::init();
    // Enable mouse interaction for the whole session.
    let _ = crossterm::execute!(io::stdout(), EnableMouseCapture);
    let _guard = RestoreGuard;
    let mut app = App::new((*config_arc).clone(), has_cli_targets, paused.clone());
    app.system_network = system_network;
    app.set_cancel_token(cancel.clone());
    app.set_scan_control(control_tx);
    app.watch_interval = watch_interval.map(|seconds| Duration::from_secs(seconds.max(1)));
    app.manifest_path = manifest_path;
    app.manifest_thresholds = crate::HealthThresholds {
        min_success_rate,
        max_p95_ms,
    };
    app.manifest_min_confidence = manifest_min_confidence;
    app.manifest_backups = manifest_backups;
    app.watch_policy = watch_policy;
    app.watch_state_path = watch_state_path.map(str::to_string);
    app.watch_new_sample = watch_new_sample;
    if has_cli_targets {
        app.set_explicit_target_source(cli_cidr.clone(), cli_ips.clone());
    }

    let spawn_scanner = |targets: Vec<String>,
                         selected_cidrs: Vec<String>,
                         scan_config: Arc<AppConfig>|
     -> std::thread::JoinHandle<Result<Vec<String>, String>> {
        let scanner_config = scan_config;
        let scanner_paused = paused.clone();
        let scanner_cancel = cancel.clone();
        let scanner_tx = tx.clone();
        let scanner_progress = progress_sender.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return Err(format!("failed to create tokio runtime: {e}"));
                }
            };
            if scanner_config.two_phase
                && !selected_cidrs.is_empty()
                && scanner_config.health_checks.is_empty()
            {
                rt.block_on(crate::scanner::run_scan_two_phase_with_progress(
                    selected_cidrs,
                    scanner_config,
                    None,
                    scanner_tx,
                    scanner_cancel,
                    scanner_paused,
                    Some(scanner_progress.clone()),
                ))
                .map_err(|e| e.to_string())
            } else {
                rt.block_on(crate::scanner::run_profile_scan_with_progress(
                    targets.clone(),
                    scanner_config,
                    scanner_tx,
                    scanner_cancel,
                    scanner_paused,
                    Some(scanner_progress.clone()),
                ));
                Ok(targets)
            }
        })
    };

    let spawn_speed = |targets: Vec<(String, u16)>,
                       scan_config: Arc<AppConfig>,
                       direction: SpeedDirection|
     -> std::thread::JoinHandle<Result<(), String>> {
        let speed_config = scan_config;
        let speed_cancel = cancel.clone();
        let speed_sender = speed_tx.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("failed to create tokio runtime: {e}"))?;
            rt.block_on(crate::speed::run_speed_scan(
                targets,
                speed_config,
                direction,
                speed_sender,
                speed_cancel,
            ));
            Ok(())
        })
    };

    let mut scanner: Option<std::thread::JoinHandle<Result<Vec<String>, String>>> = None;
    let mut investigator: Option<std::thread::JoinHandle<Result<(), String>>> = None;
    let mut speed_runner: Option<std::thread::JoinHandle<Result<(), String>>> = None;

    // CLI-provided targets start scanning immediately (legacy behavior).
    if has_cli_targets {
        if app.config.host.is_empty() {
            app.toast_warn("Set a Host before starting the scan");
        } else {
            let targets = crate::scanner::collect_targets_with_seed(
                &config_arc,
                &cli_cidr,
                &cli_ips,
                app.scan_seed,
            )?;
            let source_fingerprint = crate::watch::fingerprint(&(
                cli_cidr.clone(),
                cli_ips.clone(),
                config_arc.sample_per_cidr,
                explicit_seed,
                app.scan_seed,
            ));
            app.watch_source_fingerprint = Some(source_fingerprint);
            let targets = prepare_watch_targets(&mut app, targets, source_fingerprint);
            let total = targets.len();
            app.set_scan_targets(targets.clone());
            if config_arc.two_phase && !config_arc.health_checks.is_empty() {
                app.toast_warn(
                    "Two-phase scanning is unavailable with health checks; using profile scan",
                );
            }
            let two_phase_cidrs: Vec<String> = if cli_ips.is_some() {
                Vec::new()
            } else if !cli_cidr.is_empty() {
                cli_cidr.clone()
            } else {
                config_arc.selected_cidrs.clone()
            };
            scanner = Some(spawn_scanner(targets, two_phase_cidrs, config_arc.clone()));
            app.begin_scan(total);
        }
    }

    type SpawnScanner<'a> = dyn Fn(
            Vec<String>,
            Vec<String>,
            Arc<AppConfig>,
        ) -> std::thread::JoinHandle<Result<Vec<String>, String>>
        + 'a;

    // Launch a scan from the wizard's (possibly edited) configuration.
    let start_wizard_scan =
        |app: &mut App,
         scanner: &mut Option<std::thread::JoinHandle<Result<Vec<String>, String>>>,
         spawn_scanner: &SpawnScanner<'_>| {
            let exact_targets = app.rescan_targets.take();
            let use_exact_targets = exact_targets.is_some();
            let cidrs: Vec<String> = app
                .cidr_candidates
                .iter()
                .filter(|e| e.selected)
                .map(|e| e.cidr.clone())
                .collect();
            if exact_targets.is_none() && cidrs.is_empty() {
                app.toast_warn("Select at least one CIDR (space) before starting");
                return;
            }
            if app.config.host.is_empty() {
                app.toast_warn("Set a Host before starting the scan");
                return;
            }
            if app.preview_pending {
                app.toast_info("Target preview is still generating");
                return;
            }
            let targets = if let Some(targets) = exact_targets {
                Ok(targets)
            } else if app.preview_targets.is_empty() {
                crate::scanner::collect_from_cidrs_with_seed(
                    &cidrs,
                    app.config.sample_per_cidr,
                    app.scan_seed,
                )
            } else {
                Ok(app.preview_targets.clone())
            };
            match targets {
                Ok(targets) => {
                    if app.config.two_phase && !app.config.health_checks.is_empty() {
                        app.toast_warn(
                        "Two-phase scanning is unavailable with health checks; using profile scan",
                    );
                    }
                    let computed_source_fingerprint = crate::watch::fingerprint(&(
                        cidrs.clone(),
                        app.config.sample_per_cidr,
                        explicit_seed,
                        app.scan_seed,
                    ));
                    let source_fingerprint = if use_exact_targets {
                        app.watch_source_fingerprint
                            .unwrap_or(computed_source_fingerprint)
                    } else {
                        computed_source_fingerprint
                    };
                    app.watch_source_fingerprint = Some(source_fingerprint);
                    let targets = prepare_watch_targets(app, targets, source_fingerprint);
                    let total = targets.len();
                    let scan_config = Arc::new(app.config.clone());
                    app.set_scan_targets(targets.clone());
                    let scan_cidrs = if use_exact_targets {
                        Vec::new()
                    } else {
                        cidrs.clone()
                    };
                    *scanner = Some(spawn_scanner(targets, scan_cidrs, scan_config));
                    app.begin_scan(total);
                }
                Err(e) => app.toast_error(format!("Error: {e}")),
            }
        };

    let mut run = || -> anyhow::Result<()> {
        loop {
            while let Ok(control) = control_rx.try_recv() {
                app.apply_runtime_control(control, &cancel, &paused);
            }
            while let Ok(result) = manifest_rx.try_recv() {
                if let Err(error) = result {
                    app.toast_warn(format!("Manifest write failed: {error}"));
                }
            }
            while let Ok(r) = rx.try_recv() {
                app.add_result(r);
            }
            for _ in 0..256 {
                match progress_rx.try_recv() {
                    Ok(progress) => app.apply_scan_progress(progress),
                    Err(_) => break,
                }
            }
            while let Ok(r) = speed_rx.try_recv() {
                app.speed_results.push(r);
            }
            while let Ok(result) = investigation_rx.try_recv() {
                if let Some(investigation) = app.investigation.as_mut() {
                    investigation.results.push(result);
                }
            }
            for _ in 0..64 {
                match investigation_progress_rx.try_recv() {
                    Ok(progress) => {
                        if let (Some(event), Some(investigation)) =
                            (progress.event, app.investigation.as_mut())
                        {
                            investigation.apply_event(event);
                        }
                    }
                    Err(_) => break,
                }
            }

            if app.pending_isolation.is_some()
                && app.investigation.is_none()
                && app.scan_progress.active_probes == 0
            {
                let ip = app
                    .pending_isolation
                    .take()
                    .expect("pending isolation checked");
                let config = Arc::new(app.config.clone());
                let result_tx = investigation_tx.clone();
                let progress_tx = investigation_progress_tx.clone();
                let investigation_id = app.next_run_id;
                app.next_run_id = app.next_run_id.saturating_add(1);
                let state =
                    InvestigationState::new(investigation_id, ip.clone(), app.current_run_id);
                let investigation_cancel = state.cancel.clone();
                app.investigation = Some(state);
                app.toast_info(format!("Running isolated investigation for {ip}"));
                investigator = Some(std::thread::spawn(move || {
                    let runtime = tokio::runtime::Runtime::new()
                        .map_err(|error| format!("failed to create runtime: {error}"))?;
                    runtime.block_on(crate::scanner::run_profile_scan_with_progress(
                        vec![ip],
                        config,
                        result_tx,
                        investigation_cancel,
                        Arc::new(AtomicBool::new(false)),
                        Some(progress_tx),
                    ));
                    Ok(())
                }));
            }

            if investigator
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
            {
                while let Ok(result) = investigation_rx.try_recv() {
                    if let Some(investigation) = app.investigation.as_mut() {
                        investigation.results.push(result);
                    }
                }
                let outcome = investigator
                    .take()
                    .expect("finished investigator exists")
                    .join();
                let Some(investigation) = app.investigation.take() else {
                    continue;
                };
                let cancelled = investigation.cancel.load(Ordering::Relaxed);
                let lifecycle = match &outcome {
                    Ok(Ok(())) if cancelled => ScanLifecycle::Cancelled,
                    Ok(Ok(())) => ScanLifecycle::Completed,
                    Ok(Err(_)) | Err(_) => ScanLifecycle::Failed,
                };
                let record = RunRecord {
                    id: investigation.id,
                    source_run_id: Some(investigation.source_run_id),
                    kind: RunKind::Investigation,
                    targets: vec![investigation.target],
                    results: investigation.results,
                    elapsed: investigation.started_at.elapsed(),
                    lifecycle,
                };
                app.run_history.push_front(record);
                app.evict_run_history();
                match outcome {
                    Ok(Ok(())) if cancelled => {
                        app.toast_warn("Isolated investigation stopped; partial results kept")
                    }
                    Ok(Ok(())) => app
                        .toast_success("Isolated investigation complete; main scan remains paused"),
                    Ok(Err(error)) => {
                        app.toast_error(format!("Isolated investigation failed: {error}"))
                    }
                    Err(_) => app.toast_error("Isolated investigation worker panicked"),
                }
                if app.quit_after_cancel {
                    app.should_quit = true;
                } else if app.edit_after_stop && app.scan_complete {
                    app.edit_after_stop = false;
                    app.enter_customization();
                }
            }

            if !app.scan_complete && scanner.as_ref().is_some_and(|s| s.is_finished()) {
                while let Ok(r) = rx.try_recv() {
                    app.add_result(r);
                }
                for _ in 0..256 {
                    match progress_rx.try_recv() {
                        Ok(progress) => app.apply_scan_progress(progress),
                        Err(_) => break,
                    }
                }
                if let Some(handle) = scanner.take() {
                    match handle.join() {
                        Ok(Ok(actual_targets)) => {
                            app.last_targets = actual_targets.clone();
                            if let Some(state) = app.watch_state.as_mut() {
                                state.targets = actual_targets;
                            }
                            app.scan_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Completed);
                        }
                        Ok(Err(e)) => {
                            app.scan_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Failed);
                            app.scan_error = Some(e.to_string());
                            app.toast_error(format!("Scan failed: {e}"));
                        }
                        Err(_) => {
                            app.scan_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Failed);
                            app.scan_error = Some("Scan worker panicked".to_string());
                            app.toast_error("Scan worker panicked");
                        }
                    }
                    if app.scan_lifecycle == ScanLifecycle::Cancelled {
                        if app.quit_after_cancel {
                            app.should_quit = true;
                        } else if app.edit_after_stop && app.investigation.is_none() {
                            app.edit_after_stop = false;
                            app.enter_customization();
                            app.toast_info(
                                "Partial results preserved; edit settings and start a new run",
                            );
                        } else {
                            app.toast_warn("Scan stopped; completed results were preserved");
                        }
                    }
                    if app.watch_interval.is_some()
                        && app.scan_complete
                        && app.scan_lifecycle != ScanLifecycle::Cancelled
                    {
                        if !app.last_targets.is_empty() {
                            app.watch_cycle = app.watch_cycle.saturating_add(1);
                        }
                        if app.watch_state.is_none() {
                            let source_fingerprint = crate::watch::fingerprint(&app.last_targets);
                            let profile_fingerprint = watch_profile_fingerprint(&app.config);
                            app.watch_state = Some(crate::watch::WatchState::new(
                                source_fingerprint,
                                profile_fingerprint,
                                app.last_targets.clone(),
                            ));
                        }
                        let watch_thresholds = app.manifest_thresholds;
                        let watch_min_confidence = app.manifest_min_confidence.clone();
                        let transition = app
                            .watch_state
                            .as_mut()
                            .expect("watch state initialized")
                            .advance(&app.results, app.watch_policy, |result| {
                                crate::healthy_result(
                                    result,
                                    watch_thresholds,
                                    &watch_min_confidence,
                                )
                            });
                        let mut manifest_results = app.results.clone();
                        if let Some(stable) = transition.stable_primary.as_deref() {
                            manifest_results.sort_by(|a, b| {
                                (a.ip != stable)
                                    .cmp(&(b.ip != stable))
                                    .then_with(|| App::natural_cmp(a, b))
                            });
                        } else {
                            manifest_results.sort_by(App::natural_cmp);
                        }
                        let mut manifest = build_current_manifest(&app);
                        if let Some(stable) = transition.stable_primary.as_deref() {
                            manifest.primary = manifest_results
                                .iter()
                                .find(|result| {
                                    result.ip == stable
                                        && crate::healthy_result(
                                            result,
                                            app.manifest_thresholds,
                                            &app.manifest_min_confidence,
                                        )
                                })
                                .cloned();
                            manifest.backups = manifest_results
                                .iter()
                                .filter(|result| {
                                    result.ip != stable
                                        && crate::healthy_result(
                                            result,
                                            app.manifest_thresholds,
                                            &app.manifest_min_confidence,
                                        )
                                })
                                .take(app.manifest_backups)
                                .cloned()
                                .collect();
                            manifest.failure = manifest
                                .primary
                                .is_none()
                                .then(|| "stable primary is no longer available".to_string());
                        } else {
                            manifest.primary = None;
                            manifest.backups = manifest_results
                                .iter()
                                .filter(|result| {
                                    crate::healthy_result(
                                        result,
                                        app.manifest_thresholds,
                                        &app.manifest_min_confidence,
                                    )
                                })
                                .take(app.manifest_backups)
                                .cloned()
                                .collect();
                            manifest.failure =
                                Some("no stable target met the watch policy".to_string());
                        }
                        if let Some(path) = &app.manifest_path {
                            queue_manifest_write(path, manifest.clone(), &manifest_tx);
                        }
                        let healthy = manifest.primary.is_some();
                        let recommendation = transition.stable_primary.clone();
                        let mut alerts = Vec::new();
                        if transition.changed {
                            alerts.push("recommended target changed".to_string());
                        }
                        if !healthy && app.last_watch_healthy != Some(false) {
                            alerts.push("no healthy target".to_string());
                        }
                        if let Some(path) = &app.watch_state_path {
                            if let Some(state) = &app.watch_state {
                                if let Err(error) =
                                    crate::watch::save(std::path::Path::new(path), state)
                                {
                                    app.toast_warn(format!("Watch state write failed: {error}"));
                                }
                            }
                        }
                        app.alert_message = (!alerts.is_empty()).then(|| alerts.join("; "));
                        if let Some(message) = &app.alert_message {
                            app.toast_warn(format!("Watch alert: {message}"));
                        }
                        let record = serde_json::json!({
                            "schema_version": 1,
                            "cycle": app.watch_cycle,
                            "host": app.config.host,
                            "path": app.config.path,
                            "targets": app.last_targets,
                            "healthy": healthy,
                            "recommendation": recommendation,
                            "alerts": alerts,
                            "manifest": manifest,
                            "results": app.results,
                        });
                        if let Err(error) = crate::config::append_history(&record) {
                            app.toast_warn(format!("History write failed: {error}"));
                        }
                        app.last_watch_healthy = Some(healthy);
                    }
                    if app.watch_interval.is_none()
                        && app.scan_lifecycle != ScanLifecycle::Cancelled
                    {
                        if let Some(path) = &app.manifest_path {
                            queue_manifest_write(path, build_current_manifest(&app), &manifest_tx);
                        }
                    }
                    if app.scan_lifecycle != ScanLifecycle::Cancelled {
                        if let Some(interval) = app.watch_interval {
                            if !app.last_targets.is_empty() {
                                app.watch_due = Some(Instant::now() + interval);
                                app.toast_info(format!(
                                    "Watch cycle {} complete; next scan in {}s",
                                    app.watch_cycle,
                                    interval.as_secs()
                                ));
                            }
                        }
                    }
                }
            }

            if app.watch_relaunch_ready(Instant::now(), paused.load(Ordering::Relaxed)) {
                app.results.clear();
                app.results_revision = app.results_revision.wrapping_add(1);
                app.sorted_cache.borrow_mut().take();
                app.scan_complete = false;
                app.watch_due = None;
                app.rescan_targets = Some(app.last_targets.clone());
                app.pending_start = true;
            }

            if app.screen == Screen::SpeedTesting
                && speed_runner.as_ref().is_some_and(|s| s.is_finished())
            {
                while let Ok(r) = speed_rx.try_recv() {
                    app.speed_results.push(r);
                }
                if let Some(handle) = speed_runner.take() {
                    match handle.join() {
                        Ok(Ok(())) => {
                            app.speed_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Completed);
                            app.speed_result_cursor = 0;
                            app.scroll = 0;
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                            if app.scan_lifecycle == ScanLifecycle::Cancelled {
                                app.should_quit = true;
                            }
                        }
                        Ok(Err(e)) => {
                            app.speed_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Failed);
                            app.toast_error(format!("Speed test failed: {e}"));
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                            if app.scan_lifecycle == ScanLifecycle::Cancelled {
                                app.should_quit = true;
                            }
                        }
                        Err(_) => {
                            app.speed_complete = true;
                            app.scan_lifecycle =
                                app.resolve_terminal_lifecycle(ScanLifecycle::Failed);
                            app.toast_error("Speed test worker panicked");
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                            if app.scan_lifecycle == ScanLifecycle::Cancelled {
                                app.should_quit = true;
                            }
                        }
                    }
                }
            }

            if let Some(receiver) = update_receiver.as_ref() {
                if let Ok(notice) = receiver.try_recv() {
                    // Keep update availability visible until acknowledged by
                    // another message; the background check may finish after
                    // the user has already entered the wizard.
                    app.toast_warn(notice);
                    update_receiver = None;
                }
            }
            app.poll_preview();
            app.tick_message();
            app.tick = app.tick.wrapping_add(1);

            // Sample probe throughput roughly once per second for the sparkline.
            if app.screen == Screen::Scanning
                && !app.scan_complete
                && app.last_tp_instant.elapsed() >= Duration::from_millis(1000)
            {
                let now_count = app.scan_progress.probes_completed;
                let delta = now_count.saturating_sub(app.last_tp_count) as u64;
                app.throughput.push(delta);
                if app.throughput.len() > 240 {
                    app.throughput.remove(0);
                }
                app.last_tp_count = now_count;
                app.last_tp_instant = Instant::now();
                let now = Instant::now();
                app.probe_rate_history
                    .push((now, app.scan_progress.probes_completed));
                app.probe_rate_history.retain(|(at, _)| {
                    now.checked_duration_since(*at)
                        .is_some_and(|age| age <= Duration::from_secs(15))
                });
            }

            if app.screen == Screen::Wizard
                && app.wizard_step == WizardStep::Review
                && app.preview_targets.is_empty()
            {
                app.refresh_preview();
            }
            terminal.draw(|f| app.render(f))?;

            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        app.handle_key(key.code, key.modifiers);
                    }
                    Event::Mouse(m) => app.handle_mouse(m),
                    _ => {}
                }
            }

            if app.should_quit {
                break;
            }

            if app.pending_start && app.investigation.is_none() && app.pending_isolation.is_none() {
                app.pending_start = false;
                start_wizard_scan(&mut app, &mut scanner, &spawn_scanner);
            }

            if app.pending_speed_start
                && app.screen == Screen::SpeedSelect
                && speed_runner.is_none()
            {
                app.pending_speed_start = false;
                let targets: Vec<(String, u16)> = app
                    .speed_targets
                    .iter()
                    .filter(|ip| app.speed_selected.contains(*ip))
                    .filter_map(|ip| {
                        app.results
                            .iter()
                            .find(|result| result.ip == *ip)
                            .map(|result| (ip.clone(), result.port))
                    })
                    .collect();
                app.speed_results.clear();
                app.speed_complete = false;
                app.scan_lifecycle = ScanLifecycle::Running;
                app.speed_start_time = Instant::now();
                app.screen = Screen::SpeedTesting;
                speed_runner = Some(spawn_speed(
                    targets,
                    Arc::new(app.config.clone()),
                    app.speed_direction,
                ));
            }
        }
        Ok(())
    };

    let result = run();

    cancel.store(true, Ordering::Relaxed);
    if let Some(investigation) = &app.investigation {
        investigation.cancel.store(true, Ordering::Relaxed);
    }
    if let Some(s) = scanner {
        let _ = s.join();
    }
    if let Some(s) = speed_runner {
        let _ = s.join();
    }
    if let Some(worker) = investigator {
        let _ = worker.join();
    }
    result
}
