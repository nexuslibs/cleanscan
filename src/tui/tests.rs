use super::run::build_current_manifest;
use super::wizard::SettingField;
use super::{
    export_tsv_line, ranked_export_results, Action, App, FocusTarget, InvestigationState, RunKind,
    RunRecord, ScanDashboardView, ScanLifecycle, Screen, TargetFilter, TargetSort, TargetStage,
    WizardStep,
};
use crate::config::AppConfig;
use crate::scanner::{
    DiagnosticCategory, DiagnosticPhase, ProbeDiagnostic, ProbeFailureCounts, ProbeResult,
    ScanControl, ScanEvent, ScanEventKind, ScanPhase, ScanProgress,
};
use crate::watch::{WatchPolicy, WatchState};
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{backend::TestBackend, Terminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn result(ip: &str, fail: usize, p95: f64) -> ProbeResult {
    ProbeResult {
        ip: ip.to_string(),
        port: 443,
        protocol: "h2".to_string(),
        ok: 1,
        fail,
        completed: 1 + fail,
        avg: p95,
        p50: p95,
        p90: p95,
        p95,
        max: p95,
        jitter: 0.0,
        stddev: 0.0,
        loss: 0,
        packet_loss: 0.0,
        samples: vec![p95],
        failures: Vec::new(),
        diagnostics: Vec::new(),
        success_rate: 1.0 / (1 + fail) as f64,
        score: 1.0 / p95.max(0.001),
        colo: None,
        country: None,
        cold_ms: None,
        stopped_early: false,
        min_score: 0.0,
        max_score: 0.0,
        success_rate_lower: 0.0,
        success_rate_upper: 1.0,
        score_confidence: 0.95,
        decision: "competitive".to_string(),
        checks: Vec::new(),
        health_ok: true,
        port_results: Vec::new(),
    }
}

fn draw(app: &mut App, w: u16, h: u16) {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.render(f)).unwrap();
    // Advance real time between draws so overlay animations (which advance on
    // wall-clock deltas) progress deterministically, matching ~60fps timing.
    std::thread::sleep(std::time::Duration::from_millis(16));
}

fn rendered(app: &mut App, w: u16, h: u16) -> String {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn export_ranks_successes_and_applies_top_limit() {
    let results = vec![
        result("failed", 1, 0.5),
        result("slow", 0, 0.2),
        result("fast", 0, 0.1),
    ];
    let ranked = ranked_export_results(&results, 1);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].ip, "fast");
    assert_eq!(ranked[0].fail, 0);
}

#[test]
fn export_excludes_ips_with_no_successful_probes() {
    let mut failed = result("failed", 1, 0.001);
    failed.ok = 0;
    failed.health_ok = false;
    failed.samples.clear();

    let results = [failed, result("ok", 1, 0.1)];
    let ranked = ranked_export_results(&results, 50);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].ip, "ok");
}

#[test]
fn export_tsv_includes_location_columns() {
    let mut edge = result("192.0.2.1", 0, 0.02);
    edge.colo = Some("FRA".to_string());
    edge.country = Some("Germany".to_string());
    assert_eq!(
            export_tsv_line(1, &edge),
            "1\t192.0.2.1\t443\tFRA\tGermany\th2\t1\t0\t0.020\t0.020\t0.020\t0.020\t0.020\t0.000\t0.000%"
        );
}

#[test]
fn scanning_focus_map_keeps_stop_and_quit_reachable() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let (control_tx, control_rx) = std::sync::mpsc::channel();
    app.set_scan_control(control_tx);
    app.begin_scan(1);
    assert_eq!(app.focus_count(), 4);
    app.focus_index = 2;
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        control_rx.try_recv().unwrap(),
        ScanControl::StopAndKeepResults
    );

    app.handle_key(KeyCode::Char('q'), KeyModifiers::NONE);
    assert!(app.confirm_quit);
    app.confirm_quit = false;
    app.scan_complete = true;
    assert_eq!(app.focus_count(), 5);
    app.focus_index = 4;
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.should_quit);
}

#[test]
fn escape_cancels_active_scan_and_quits_completed_dashboard() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.confirm_quit);

    app.confirm_quit = false;
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Completed;
    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.should_quit);
}

#[test]
fn f_opens_diagnostics_for_the_first_failed_target() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(2);
    let mut failed = result("192.0.2.2", 2, 0.2);
    failed.ok = 0;
    failed.failures = vec!["request timeout".to_string()];
    app.results = vec![result("192.0.2.1", 0, 0.1), failed];

    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);

    assert!(app.show_failures);
    assert!(app.show_result_details);
    assert_eq!(app.detail_tab, 1);
    assert_eq!(app.result_cursor, 1);
}

#[test]
fn f_opens_a_failed_target_outside_the_normal_top_limit() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(2);
    app.config.top = 1;
    let mut first = result("192.0.2.1", 1, 0.01);
    first.ok = 0;
    first.failures = vec!["first failure".to_string()];
    let mut second = result("192.0.2.2", 1, 0.02);
    second.ok = 0;
    second.failures = vec!["actual cause".to_string()];
    app.results = vec![first, second];

    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);

    assert!(app.show_result_details);
    assert_eq!(app.detail_tab, 1);
    assert_eq!(app.sorted_results()[app.result_cursor].ip, "192.0.2.1");
}

#[test]
fn diagnostics_are_rendered_when_only_structured_diagnostics_exist() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    let mut failed = result("192.0.2.9", 1, 0.02);
    failed.ok = 0;
    failed.failures.clear();
    failed.diagnostics.push(ProbeDiagnostic {
        category: DiagnosticCategory::Timeout,
        phase: DiagnosticPhase::ResponseHeaders,
        message: "request timed out while reading response headers".to_string(),
        status: None,
        location: None,
        elapsed_ms: Some(1_000.0),
    });
    app.results = vec![failed];
    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    terminal.draw(|frame| app.render(frame)).unwrap();
    let rendered = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("request timed out"));
}

#[test]
fn escape_closes_details_before_quitting_completed_results() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Completed;
    app.show_result_details = true;

    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);

    assert!(!app.show_result_details);
    assert!(!app.should_quit);
}

#[test]
fn worker_failure_remains_available_from_f() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Failed;
    app.scan_error = Some("connection scheduler failed".to_string());

    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);

    assert!(app.show_result_details);
    assert_eq!(app.detail_tab, 1);
}

#[test]
fn completed_results_can_customize_and_return_without_rerunning() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    app.scan_complete = true;
    app.last_targets = vec!["192.0.2.1".to_string()];
    app.results = vec![result("192.0.2.1", 0, 0.02)];
    app.handle_key(KeyCode::Char('w'), KeyModifiers::NONE);
    assert_eq!(app.screen, Screen::Wizard);
    assert_eq!(app.wizard_step, WizardStep::Settings);
    assert!(app.return_to_results);
    assert_eq!(app.last_targets, vec!["192.0.2.1"]);
    assert_eq!(app.results.len(), 1);

    app.wizard_step = WizardStep::Ranges;
    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.screen, Screen::Scanning);
    assert!(!app.return_to_results);
    assert!(app.scan_complete);
    assert_eq!(app.results.len(), 1);
}

#[test]
fn completed_results_command_palette_is_contextual() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(1);
    app.scan_complete = true;
    app.open_command_palette();
    let actions = app.filtered_actions();
    assert!(actions.contains(&Action::CustomizeScan));
    assert!(actions.contains(&Action::ConfigureColumns));
    assert!(actions.contains(&Action::ToggleFailures));
    assert!(!actions.contains(&Action::Next));
    assert!(!actions.contains(&Action::Start));
}

#[test]
fn watch_fingerprint_changes_when_scan_seed_changes() {
    let cidrs = vec!["192.0.2.0/24".to_string()];
    let first = crate::watch::fingerprint(&(cidrs.clone(), 20usize, None::<u64>, 11u64));
    let second = crate::watch::fingerprint(&(cidrs, 20usize, None::<u64>, 12u64));
    assert_ne!(first, second);
}

#[test]
fn dashboard_sorting_tolerates_nan_latency() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut edge = result("192.0.2.1", 0, 0.02);
    edge.avg = f64::NAN;
    edge.p50 = f64::NAN;
    app.begin_scan(1);
    app.add_result(edge);
    draw(&mut app, 120, 36);
}

#[test]
fn watch_state_persists_and_covers_promotion_loss_recovery_and_identity() {
    let path =
        std::env::temp_dir().join(format!("cleanscan-tui-watch-{}.json", std::process::id()));
    let mut state = WatchState::new(11, 22, vec!["192.0.2.1".to_string()]);
    let policy = WatchPolicy::default();
    assert!(
        !state
            .advance(&[result("192.0.2.1", 0, 0.02)], policy, |r| r.health_ok)
            .changed
    );
    crate::watch::save(&path, &state).unwrap();
    let mut state = crate::watch::load(&path).unwrap();
    assert!(state.compatible(11, 22));
    assert!(!state.compatible(12, 22));
    assert!(
        state
            .advance(&[result("192.0.2.1", 0, 0.02)], policy, |r| r.health_ok)
            .changed
    );
    assert!(!state.advance(&[], policy, |r| r.health_ok).changed);
    assert!(state.advance(&[], policy, |r| r.health_ok).changed);
    assert!(state
        .advance(&[result("192.0.2.1", 0, 0.02)], policy, |r| r.health_ok)
        .stable_primary
        .is_none());
    assert!(state
        .advance(&[result("192.0.2.1", 0, 0.02)], policy, |r| r.health_ok)
        .stable_primary
        .is_some());
    let _ = std::fs::remove_file(path);
}

#[test]
fn current_manifest_keeps_only_healthy_primary_and_backups() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.last_targets = vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()];
    app.results = vec![result("192.0.2.1", 0, 0.02), result("192.0.2.2", 1, 0.03)];
    let manifest = build_current_manifest(&app);
    assert_eq!(
        manifest.primary.as_ref().map(|r| r.ip.as_str()),
        Some("192.0.2.1")
    );
    assert_eq!(manifest.backups.len(), 1);
}

#[test]
fn dashboard_renders_without_panicking() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(500);
    for i in 0..40 {
        app.add_result(result(
            &format!("10.0.0.{i}"),
            i % 5,
            0.05 + i as f64 * 0.01,
        ));
    }
    app.throughput = vec![1, 3, 2, 5, 8, 4, 6, 2];
    // Render at a comfortable size and a smaller one to exercise layouts.
    draw(&mut app, 140, 40);
    draw(&mut app, 90, 30);
    draw(&mut app, 60, 20);
    draw(&mut app, 40, 9);
    // Completed state and overlays should also render cleanly.
    app.scan_complete = true;
    app.show_help = true;
    draw(&mut app, 120, 36);
    app.show_help = false;
    app.confirm_quit = true;
    draw(&mut app, 120, 36);
}

#[test]
fn confirming_quit_requests_immediate_cancellation() {
    let cancel = Arc::new(AtomicBool::new(false));
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.set_cancel_token(cancel.clone());
    app.begin_scan(10);
    app.confirm_quit = true;
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.scan_lifecycle, ScanLifecycle::Cancelling);
    assert!(cancel.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!app.should_quit);
}

#[test]
fn cancelling_quit_dialog_keeps_scan_running() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(10);
    app.confirm_quit = true;
    app.handle_key(KeyCode::Char('n'), KeyModifiers::NONE);
    assert_eq!(app.scan_lifecycle, ScanLifecycle::Running);
    assert!(!app.confirm_quit);
}

#[test]
fn rerun_confirmation_is_reversible_and_preserves_results() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.screen = Screen::Scanning;
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Completed;
    app.results.push(result("192.0.2.1", 0, 0.02));
    app.handle_key(KeyCode::Char('r'), KeyModifiers::NONE);
    assert!(app.confirm_scan_action.is_some());
    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.confirm_scan_action.is_none());
    assert_eq!(app.results.len(), 1);
}

#[test]
fn warning_and_error_toasts_do_not_expire_automatically() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.toast_error("export failed");
    app.message_time = Some(Instant::now() - Duration::from_secs(5));
    assert!(app.visible_message().is_some());
    app.toast_warn("configuration warning");
    app.message_time = Some(Instant::now() - Duration::from_secs(5));
    app.tick_message();
    assert!(app.visible_message().is_some());
}

#[test]
fn detail_tabs_and_visualizations_render_including_empty_samples() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(3);
    app.show_failures = true;
    let mut sampled = result("10.0.0.1", 0, 0.05);
    sampled.samples = vec![0.04, 0.06, 0.05, 0.08];
    app.add_result(sampled);
    let mut empty = result("10.0.0.2", 2, 0.2);
    empty.ok = 0;
    empty.health_ok = false;
    empty.samples.clear();
    app.add_result(empty);
    app.scan_complete = true;
    app.show_result_details = true;

    // Warm-up draw so the overlay animation has advanced past its first
    // (zero-delta) frame; otherwise tab 0's body would never render.
    draw(&mut app, 120, 40);
    for tab in 0..5 {
        app.detail_tab = tab;
        draw(&mut app, 120, 40);
    }
    app.result_cursor = 1;
    app.detail_tab = 2;
    draw(&mut app, 120, 40);
}

#[test]
fn list_widgets_track_selection_and_scroll_for_wizard_and_overlays() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.cursor = app.cidr_candidates.len().saturating_sub(1);
    draw(&mut app, 120, 36);
    assert_eq!(app.ranges_list_state.selected(), Some(app.cursor));
    assert!(app.ranges_list_state.offset() <= app.cursor);

    app.wizard_step = WizardStep::Settings;
    app.cursor = 0;
    draw(&mut app, 120, 36);
    assert_eq!(app.settings_list_state.selected(), Some(1));

    app.open_command_palette();
    draw(&mut app, 120, 36);
    assert_eq!(app.command_list_state.selected(), Some(0));

    app.show_command_palette = false;
    app.show_column_picker = true;
    app.column_picker_cursor = 11;
    draw(&mut app, 120, 36);
    assert_eq!(app.column_picker_list_state.selected(), Some(11));
}

#[test]
fn wizard_ranges_render_distinct_checkbox_states() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.cursor = 2;
    app.cidr_candidates[0].selected = true;
    app.cidr_candidates[1].selected = false;

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("[✓]") || rendered.contains("[x]"));
    assert!(rendered.contains("[ ]"));
    assert!(rendered.contains("(4,096 IPs)"));

    assert!(terminal.backend().buffer().content().iter().any(|cell| {
        (cell.symbol() == "✓" || cell.symbol() == "x")
            && cell.modifier.contains(ratatui::style::Modifier::BOLD)
    }));
}

#[test]
fn all_screens_render_without_panicking() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    for screen in [
        Screen::Wizard,
        Screen::SpeedSelect,
        Screen::SpeedTesting,
        Screen::SpeedResults,
    ] {
        app.screen = screen;
        draw(&mut app, 120, 36);
    }
}

#[test]
fn focus_cycles_and_tracks_semantic_targets() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(app.focus_target, FocusTarget::List);
    app.focus_next(false);
    assert_eq!(app.focus_target, FocusTarget::Button);
    app.focus_next(true);
    assert_eq!(app.focus_target, FocusTarget::List);
}

#[test]
fn command_palette_filters_and_dispatches_actions() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.open_command_palette();
    app.command_query = "help".to_string();
    assert_eq!(app.filtered_actions(), vec![Action::OpenHelp]);
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(!app.show_command_palette);
    assert!(app.show_help);
}

#[test]
fn command_palette_does_not_offer_speed_test_while_testing() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.screen = Screen::SpeedTesting;
    app.open_command_palette();

    assert!(!app.filtered_actions().contains(&Action::SpeedTest));
    app.activate_action(Action::SpeedTest);
    assert_eq!(app.screen, Screen::SpeedTesting);
}

#[test]
fn wizard_review_enter_uses_the_focused_control() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Review;
    assert_eq!(app.focus_count(), 3);

    app.focus_index = 1;
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.wizard_step, WizardStep::Settings);

    app.wizard_step = WizardStep::Review;
    app.focus_index = 2;
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.pending_start);
}

#[test]
fn compact_dashboard_and_detail_draw_without_panicking() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(10);
    app.add_result(result("192.0.2.1", 0, 0.04));
    app.show_result_details = true;
    draw(&mut app, 80, 24);
    assert!(app.buttons.iter().all(|(button, _)| button.height == 3));
    draw(&mut app, 79, 23);
}

#[test]
fn scan_dashboard_keeps_footer_buttons_below_results() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(10);
    app.add_result(result("192.0.2.1", 0, 0.04));
    draw(&mut app, 168, 13);

    let table_bottom = app.table_inner.expect("scan table rendered").bottom();
    assert!(app
        .buttons
        .iter()
        .all(|(button, _)| button.y >= table_bottom));
}

#[test]
fn scan_progress_resets_and_updates_without_creating_results() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(500);
    app.apply_scan_progress(ScanProgress {
        phase: ScanPhase::WarmingUp,
        probes_started: 12,
        probes_completed: 4,
        active_probes: 8,
        targets_completed: 0,
        latest_target: Some("192.0.2.1".to_string()),
        current_workers: None,
        adaptive_reason: None,
        targets_total: Some(500),
        failure_counts: ProbeFailureCounts::default(),
        event: None,
    });
    assert!(app.results.is_empty());
    assert!(app.scan_started_ips.contains("192.0.2.1"));
    assert_eq!(app.total_targets, 500);
    assert_eq!(app.scan_progress.probes_completed, 4);
    assert_eq!(app.scan_progress.active_probes, 8);

    app.apply_scan_progress(ScanProgress {
        phase: ScanPhase::Probing,
        probes_started: 13,
        probes_completed: 5,
        active_probes: 1,
        targets_completed: 1,
        latest_target: None,
        current_workers: Some(2),
        adaptive_reason: Some("steady".to_string()),
        targets_total: None,
        failure_counts: ProbeFailureCounts::default(),
        event: None,
    });
    assert_eq!(app.scan_progress.targets_total, Some(500));

    app.begin_scan(3);
    assert!(app.scan_started_ips.is_empty());
    assert_eq!(app.scan_progress.phase, ScanPhase::Starting);
    assert_eq!(app.scan_progress.probes_started, 0);
    assert_eq!(app.scan_progress.targets_completed, 0);
}

#[test]
fn structured_events_drive_live_target_activity_and_stay_bounded() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.set_scan_targets(vec!["192.0.2.7".to_string()]);
    app.begin_scan(1);
    let progress = |event| ScanProgress {
        phase: ScanPhase::Probing,
        probes_started: 1,
        probes_completed: 1,
        active_probes: 0,
        targets_completed: 0,
        latest_target: Some("192.0.2.7".to_string()),
        current_workers: Some(1),
        adaptive_reason: None,
        targets_total: Some(1),
        failure_counts: ProbeFailureCounts::default(),
        event: Some(event),
    };
    app.apply_scan_progress(progress(ScanEvent {
        kind: ScanEventKind::ProbeStarted,
        target: Some("192.0.2.7".to_string()),
        message: "probe started".to_string(),
        diagnostic_category: None,
        probe_succeeded: None,
    }));
    app.apply_scan_progress(progress(ScanEvent {
        kind: ScanEventKind::ProbeCompleted,
        target: Some("192.0.2.7".to_string()),
        message: "request timeout".to_string(),
        diagnostic_category: Some(DiagnosticCategory::Timeout),
        probe_succeeded: Some(false),
    }));
    let target = app.target_activity.get("192.0.2.7").unwrap();
    assert_eq!(target.stage, TargetStage::Probing);
    assert_eq!(target.probes_started, 1);
    assert_eq!(target.probes_completed, 1);
    assert_eq!(target.failures, 1);
    assert!(app.last_completion_at.is_some());
    app.apply_scan_progress(progress(ScanEvent {
        kind: ScanEventKind::TargetFinalized,
        target: Some("192.0.2.7".to_string()),
        message: "target finalized".to_string(),
        diagnostic_category: Some(DiagnosticCategory::Timeout),
        probe_succeeded: Some(false),
    }));
    let target = app.target_activity.get("192.0.2.7").unwrap();
    assert_eq!(target.stage, TargetStage::Finalized);
    assert_eq!(target.probes_completed, 1);
    assert_eq!(target.failures, 1);

    for index in 0..1_005 {
        app.apply_scan_event(ScanEvent {
            kind: ScanEventKind::WorkerChanged,
            target: None,
            message: format!("worker event {index}"),
            diagnostic_category: None,
            probe_succeeded: None,
        });
    }
    assert_eq!(app.scan_events.len(), 1_000);
    assert_eq!(
        app.scan_events.front().unwrap().event.message,
        "worker event 1004"
    );
}

#[test]
fn scan_views_render_at_wide_compact_and_micro_sizes() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.set_scan_targets(vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()]);
    app.begin_scan(2);
    app.add_result(result("192.0.2.1", 0, 0.02));
    app.dashboard_view = ScanDashboardView::Results;
    let wide = rendered(&mut app, 200, 40);
    assert!(wide.contains("Results"));
    assert!(wide.contains("Stop + keep"));
    assert!(wide.contains("Quit"));

    app.dashboard_view = ScanDashboardView::LiveTargets;
    let compact = rendered(&mut app, 120, 28);
    assert!(compact.contains("Live targets"));
    assert!(compact.contains("filter all"));
    assert!(compact.contains("sort attention"));
    assert!(compact.contains("Stop + keep"));
    assert!(compact.contains("Quit"));

    let micro_targets = rendered(&mut app, 60, 20);
    for label in ["Sel", "IP", "Stage", "Age"] {
        assert!(micro_targets.contains(label), "missing {label}");
    }
    assert!(micro_targets.contains("stop"));
    assert!(micro_targets.contains("quit"));

    app.dashboard_view = ScanDashboardView::RunLog;
    let micro_runs = rendered(&mut app, 60, 20);
    for label in ["Run", "Kind", "State", "Results", "Elapsed"] {
        assert!(micro_runs.contains(label), "missing {label}");
    }
    assert!(!micro_runs.contains("Run details & deltas"));
}

#[test]
fn isolate_and_targeted_rerun_use_selected_target_without_overwriting_results() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let (control_tx, control_rx) = std::sync::mpsc::channel();
    app.set_scan_control(control_tx);
    app.set_scan_targets(vec!["192.0.2.1".to_string()]);
    app.begin_scan(1);
    app.add_result(result("192.0.2.1", 0, 0.02));
    app.handle_key(KeyCode::Char(' '), KeyModifiers::NONE);
    app.handle_key(KeyCode::Char('i'), KeyModifiers::NONE);
    assert_eq!(
        control_rx.try_recv().unwrap(),
        ScanControl::IsolateTarget("192.0.2.1".to_string())
    );
    assert_eq!(app.results.len(), 1);

    app.scan_complete = true;
    app.handle_key(KeyCode::Char('R'), KeyModifiers::NONE);
    assert_eq!(app.rescan_targets, Some(vec!["192.0.2.1".to_string()]));
    assert_eq!(app.pending_run_kind, RunKind::Targeted);
    assert_eq!(app.pending_source_run_id, Some(app.current_run_id));
    assert!(app.pending_start);
    assert_eq!(app.results.len(), 1);
}

#[test]
fn investigation_telemetry_is_separate_and_stop_cancels_every_job() {
    let paused = Arc::new(AtomicBool::new(false));
    let primary_cancel = Arc::new(AtomicBool::new(false));
    let mut app = App::new(AppConfig::default(), false, paused.clone());
    app.set_scan_targets(vec!["192.0.2.7".to_string()]);
    app.begin_scan(1);
    app.apply_scan_event(ScanEvent {
        kind: ScanEventKind::ProbeStarted,
        target: Some("192.0.2.7".to_string()),
        message: "primary probe".to_string(),
        diagnostic_category: None,
        probe_succeeded: None,
    });
    let primary_activity = app.target_activity.get("192.0.2.7").unwrap().clone();
    let primary_events = app.scan_events.len();

    let mut investigation = InvestigationState::new(2, "192.0.2.7".to_string(), 1);
    investigation.apply_event(ScanEvent {
        kind: ScanEventKind::ProbeCompleted,
        target: Some("192.0.2.7".to_string()),
        message: "isolated timeout".to_string(),
        diagnostic_category: Some(DiagnosticCategory::Timeout),
        probe_succeeded: Some(false),
    });
    let investigation_cancel = investigation.cancel.clone();
    app.investigation = Some(investigation);
    app.pending_isolation = Some("198.51.100.9".to_string());

    assert_eq!(
        app.target_activity
            .get("192.0.2.7")
            .unwrap()
            .probes_completed,
        primary_activity.probes_completed
    );
    assert_eq!(app.scan_events.len(), primary_events);
    assert_eq!(app.investigation.as_ref().unwrap().events.len(), 1);
    assert_eq!(app.investigation.as_ref().unwrap().activity.failures, 1);

    app.apply_runtime_control(ScanControl::StopAndKeepResults, &primary_cancel, &paused);
    assert!(primary_cancel.load(Ordering::Relaxed));
    assert!(investigation_cancel.load(Ordering::Relaxed));
    assert!(app.pending_isolation.is_none());
    assert_eq!(app.scan_lifecycle, ScanLifecycle::Cancelling);
}

#[test]
fn resume_clears_pending_isolation_but_never_interrupts_a_running_investigation() {
    let paused = Arc::new(AtomicBool::new(true));
    let primary_cancel = Arc::new(AtomicBool::new(false));
    let mut app = App::new(AppConfig::default(), false, paused.clone());
    app.set_scan_targets(vec!["192.0.2.7".to_string()]);
    app.begin_scan(1);
    app.pending_isolation = Some("192.0.2.7".to_string());
    app.scan_lifecycle = ScanLifecycle::Paused;

    app.apply_runtime_control(ScanControl::ResumeScheduling, &primary_cancel, &paused);
    assert!(app.pending_isolation.is_none());
    assert!(!paused.load(Ordering::Relaxed));
    assert_eq!(app.scan_lifecycle, ScanLifecycle::Running);

    let investigation = InvestigationState::new(2, "192.0.2.7".to_string(), 1);
    let investigation_cancel = investigation.cancel.clone();
    app.investigation = Some(investigation);
    paused.store(true, Ordering::Relaxed);
    app.apply_runtime_control(ScanControl::ResumeScheduling, &primary_cancel, &paused);
    assert!(paused.load(Ordering::Relaxed));
    assert!(!investigation_cancel.load(Ordering::Relaxed));
}

#[test]
fn completed_run_isolation_holds_watch_scheduling_until_explicit_resume() {
    let paused = Arc::new(AtomicBool::new(false));
    let primary_cancel = Arc::new(AtomicBool::new(false));
    let mut app = App::new(AppConfig::default(), false, paused.clone());
    app.set_scan_targets(vec!["192.0.2.7".to_string()]);
    app.begin_scan(1);
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Completed;
    app.apply_runtime_control(
        ScanControl::IsolateTarget("192.0.2.7".to_string()),
        &primary_cancel,
        &paused,
    );
    assert!(paused.load(Ordering::Relaxed));
    assert_eq!(app.scan_lifecycle, ScanLifecycle::Completed);
    assert_eq!(app.pending_isolation.as_deref(), Some("192.0.2.7"));
    let controls = rendered(&mut app, 120, 28);
    assert!(controls.contains("Resume"));
    assert!(controls.contains("Stop"));

    app.apply_runtime_control(ScanControl::ResumeScheduling, &primary_cancel, &paused);
    assert!(!paused.load(Ordering::Relaxed));
    assert!(app.pending_isolation.is_none());
}

#[test]
fn watch_relaunch_requires_explicitly_resumed_idle_coordinator() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let now = Instant::now();
    app.watch_due = Some(now);
    assert!(app.watch_relaunch_ready(now, false));
    assert!(!app.watch_relaunch_ready(now, true));

    app.pending_isolation = Some("192.0.2.1".to_string());
    assert!(!app.watch_relaunch_ready(now, false));
    app.pending_isolation = None;
    app.investigation = Some(InvestigationState::new(2, "192.0.2.1".to_string(), 1));
    assert!(!app.watch_relaunch_ready(now, false));
}

#[test]
fn live_targets_attention_filter_sort_search_and_navigation_are_independent() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let targets = (1..=30)
        .map(|index| format!("192.0.2.{index}"))
        .collect::<Vec<_>>();
    app.set_scan_targets(targets);
    app.begin_scan(30);
    let now = Instant::now();
    {
        let active = app.target_activity.get_mut("192.0.2.20").unwrap();
        active.stage = TargetStage::Probing;
        active.first_activity = Some(now - Duration::from_secs(30));
    }
    {
        let active = app.target_activity.get_mut("192.0.2.10").unwrap();
        active.stage = TargetStage::WarmingUp;
        active.first_activity = Some(now - Duration::from_secs(60));
    }
    {
        let failed = app.target_activity.get_mut("192.0.2.3").unwrap();
        failed.stage = TargetStage::Finalized;
        failed.failures = 1;
    }
    {
        let done = app.target_activity.get_mut("192.0.2.4").unwrap();
        done.stage = TargetStage::Finalized;
    }
    assert_eq!(app.visible_target_ips()[0], "192.0.2.10");
    assert_eq!(app.visible_target_ips()[1], "192.0.2.20");

    app.dashboard_view = ScanDashboardView::LiveTargets;
    app.handle_key(KeyCode::PageDown, KeyModifiers::NONE);
    assert_eq!(app.target_cursor, 10);
    assert_eq!(app.result_cursor, 0);
    app.handle_key(KeyCode::End, KeyModifiers::NONE);
    assert_eq!(app.target_cursor, 29);
    app.handle_key(KeyCode::Home, KeyModifiers::NONE);
    assert_eq!(app.target_cursor, 0);

    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);
    assert_eq!(app.target_filter, TargetFilter::Active);
    assert_eq!(app.visible_target_ips().len(), 2);
    app.handle_key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert_eq!(app.target_sort, TargetSort::ActivityAge);
    app.handle_key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert_eq!(app.target_sort, TargetSort::Stage);
    app.handle_key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert_eq!(app.target_sort, TargetSort::Ip);
    app.handle_key(KeyCode::Char('s'), KeyModifiers::NONE);
    assert_eq!(app.target_sort, TargetSort::Attention);

    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);
    assert_eq!(app.target_filter, TargetFilter::Problems);
    assert_eq!(app.visible_target_ips(), vec!["192.0.2.3"]);
    app.selected_targets.insert("192.0.2.4".to_string());
    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);
    assert_eq!(app.target_filter, TargetFilter::Selected);
    assert_eq!(app.visible_target_ips(), vec!["192.0.2.4"]);
    app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);
    assert_eq!(app.target_filter, TargetFilter::All);

    app.open_command_palette();
    app.command_query = "target:.20".to_string();
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.dashboard_view, ScanDashboardView::LiveTargets);
    assert_eq!(app.target_query, ".20");
    assert_eq!(app.visible_target_ips(), vec!["192.0.2.20"]);
}

#[test]
fn mouse_target_selection_uses_the_rendered_scroll_origin() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.set_scan_targets((1..=40).map(|index| format!("192.0.2.{index}")).collect());
    app.begin_scan(40);
    app.dashboard_view = ScanDashboardView::LiveTargets;
    app.target_cursor = 30;
    draw(&mut app, 120, 20);
    let inner = app.table_inner.unwrap();
    let rendered_start = app.target_render_start;
    assert!(rendered_start > 0);
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: inner.x + 2,
        row: inner.y + 3,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.target_cursor, rendered_start + 2);
}

#[test]
fn mouse_results_and_run_log_selection_follow_each_view_scroll() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(40);
    for index in 1..=40 {
        app.add_result(result(
            &format!("192.0.2.{index}"),
            0,
            index as f64 / 1000.0,
        ));
    }
    app.result_cursor = 30;
    draw(&mut app, 120, 20);
    let result_inner = app.table_inner.unwrap();
    let result_start = app.scroll;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: result_inner.x + 2,
        row: result_inner.y + 2,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.result_cursor, result_start + 1);

    for id in 2..=30 {
        app.run_history.push_back(RunRecord {
            id,
            source_run_id: None,
            kind: RunKind::Full,
            targets: Vec::new(),
            results: Vec::new(),
            elapsed: Duration::from_secs(id),
            lifecycle: ScanLifecycle::Completed,
        });
    }
    app.dashboard_view = ScanDashboardView::RunLog;
    app.run_cursor = 20;
    draw(&mut app, 120, 20);
    let run_inner = app.table_inner.unwrap();
    let run_start = app.run_render_start;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: run_inner.x + 2,
        row: run_inner.y + 3,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.run_cursor, run_start + 2);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: run_inner.x + 2,
        row: run_inner.y + 3,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.run_cursor, run_start + 3);
}

#[test]
fn run_comparison_uses_only_linked_provenance_and_displays_every_delta() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.set_scan_targets(vec!["192.0.2.1".to_string()]);
    app.begin_scan(1);
    let mut source = result("192.0.2.1", 0, 0.020);
    source.avg = 0.010;
    source.packet_loss = 0.10;
    source.success_rate = 0.80;
    source.colo = Some("FRA".to_string());
    source.diagnostics.push(ProbeDiagnostic {
        category: DiagnosticCategory::Timeout,
        phase: DiagnosticPhase::ResponseHeaders,
        message: "source timeout".to_string(),
        status: None,
        location: None,
        elapsed_ms: Some(20.0),
    });
    app.results = vec![source];
    let mut rerun = result("192.0.2.1", 1, 0.030);
    rerun.avg = 0.015;
    rerun.packet_loss = 0.20;
    rerun.success_rate = 0.60;
    rerun.colo = Some("AMS".to_string());
    app.run_history.push_front(RunRecord {
        id: 2,
        source_run_id: Some(app.current_run_id),
        kind: RunKind::Targeted,
        targets: vec!["192.0.2.1".to_string()],
        results: vec![rerun],
        elapsed: Duration::from_secs(2),
        lifecycle: ScanLifecycle::Completed,
    });
    app.dashboard_view = ScanDashboardView::RunLog;
    app.run_cursor = 1;
    let output = rendered(&mut app, 160, 40);
    assert!(output.contains("Compared with source run #1"));
    assert!(output.contains("avg +5.0ms"));
    assert!(output.contains("p95 +10.0ms"));
    assert!(output.contains("loss +10.0pp"));
    assert!(output.contains("success -20.0pp"));
    assert!(output.contains("colo FRA→AMS"));
    assert!(output.contains("diagnostics -1"));

    app.run_history[0].source_run_id = Some(2);
    let self_output = rendered(&mut app, 160, 40);
    assert!(self_output.contains("No source run is linked."));
    app.run_history[0].source_run_id = Some(999);
    let evicted_output = rendered(&mut app, 160, 40);
    assert!(evicted_output.contains("Source run #999 is no longer retained."));
}

#[test]
fn history_eviction_preserves_linked_sources_when_an_unlinked_run_can_be_removed() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    for id in (1..=11).rev() {
        app.run_history.push_back(RunRecord {
            id,
            source_run_id: (id == 11).then_some(1),
            kind: RunKind::Full,
            targets: vec![format!("192.0.2.{id}")],
            results: Vec::new(),
            elapsed: Duration::from_secs(1),
            lifecycle: ScanLifecycle::Completed,
        });
    }
    app.evict_run_history();
    assert_eq!(app.run_history.len(), 10);
    assert!(app.run_history.iter().any(|run| run.id == 1));
    assert!(!app.run_history.iter().any(|run| run.id == 2));
}

#[test]
fn run_log_navigation_does_not_move_results_or_live_targets() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.screen = Screen::Scanning;
    app.result_cursor = 3;
    app.target_cursor = 4;
    for id in 1..=20 {
        app.run_history.push_back(RunRecord {
            id,
            source_run_id: None,
            kind: RunKind::Full,
            targets: Vec::new(),
            results: Vec::new(),
            elapsed: Duration::from_secs(id),
            lifecycle: ScanLifecycle::Completed,
        });
    }
    app.dashboard_view = ScanDashboardView::RunLog;
    app.handle_key(KeyCode::PageDown, KeyModifiers::NONE);
    assert_eq!(app.run_cursor, 10);
    assert_eq!(app.result_cursor, 3);
    assert_eq!(app.target_cursor, 4);
    app.handle_key(KeyCode::End, KeyModifiers::NONE);
    assert_eq!(app.run_cursor, 20);
    app.handle_key(KeyCode::Home, KeyModifiers::NONE);
    assert_eq!(app.run_cursor, 0);
}

#[test]
fn quit_and_edit_actions_stop_completed_scan_investigations() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let (control_tx, control_rx) = std::sync::mpsc::channel();
    app.set_scan_control(control_tx);
    app.begin_scan(1);
    app.scan_complete = true;
    app.scan_lifecycle = ScanLifecycle::Completed;
    app.investigation = Some(InvestigationState::new(
        2,
        "192.0.2.1".to_string(),
        app.current_run_id,
    ));

    app.activate_action(Action::CustomizeScan);
    assert!(app.edit_after_stop);
    assert_eq!(
        control_rx.try_recv().unwrap(),
        ScanControl::StopAndKeepResults
    );

    app.activate_button(super::ButtonAction::Quit);
    assert!(app.confirm_quit);
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.quit_after_cancel);
    assert!(app
        .investigation
        .as_ref()
        .unwrap()
        .cancel
        .load(Ordering::Relaxed));
}

#[test]
fn session_run_history_keeps_only_ten_runs() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    for index in 0..12 {
        app.set_scan_targets(vec![format!("192.0.2.{index}")]);
        app.begin_scan(1);
        app.add_result(result(&format!("192.0.2.{index}"), 0, 0.02));
        app.scan_complete = true;
        app.scan_lifecycle = ScanLifecycle::Completed;
    }
    app.set_scan_targets(vec!["198.51.100.1".to_string()]);
    app.begin_scan(1);
    assert_eq!(app.run_history.len(), 10);
    assert!(app
        .run_history
        .iter()
        .all(|run| !run.targets.contains(&"192.0.2.0".to_string())));
}

#[test]
fn live_worker_override_changes_in_steps_and_clears_for_new_scan() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(10);
    app.scan_progress.current_workers = Some(5);

    app.adjust_runtime_worker_override(1);
    assert_eq!(
        app.config.runtime_worker_override.load(Ordering::Relaxed),
        6
    );
    app.adjust_runtime_worker_override(-8);
    assert_eq!(
        app.config.runtime_worker_override.load(Ordering::Relaxed),
        1
    );

    app.begin_scan(10);
    assert_eq!(
        app.config.runtime_worker_override.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn micro_dashboard_keeps_scrolling_and_details_available() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.begin_scan(12);
    for index in 0..12 {
        app.add_result(result(&format!("192.0.2.{}", index + 1), 0, 0.04));
    }
    app.result_cursor = 11;
    app.show_result_details = true;
    draw(&mut app, 40, 12);
    std::thread::sleep(Duration::from_millis(160));
    draw(&mut app, 40, 12);
    assert!(app.scroll > 0);
    assert!(app.result_details_overlay.inner_area().is_some());
}

#[test]
fn help_scroll_is_keyboard_accessible() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.show_help = true;
    app.handle_key(KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(app.help_scroll, 1);
    app.handle_key(KeyCode::PageDown, KeyModifiers::NONE);
    assert_eq!(app.help_scroll, 9);
    app.handle_key(KeyCode::Home, KeyModifiers::NONE);
    assert_eq!(app.help_scroll, 0);
}

#[test]
fn speed_select_exposes_one_focus_per_control() {
    use crate::speed::SpeedDirection;
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.open_speed_selection();
    assert_eq!(app.screen, Screen::SpeedSelect);
    // List + 3 directions + select-all/clear + start + back.
    assert_eq!(app.focus_count(), 8);

    app.focus_index = 1;
    app.speed_select_activate_focused();
    assert_eq!(app.speed_direction, SpeedDirection::Download);

    app.focus_index = 2;
    app.speed_select_activate_focused();
    assert_eq!(app.speed_direction, SpeedDirection::Upload);

    app.focus_index = 3;
    app.speed_select_activate_focused();
    assert_eq!(app.speed_direction, SpeedDirection::Both);

    // Back button focus returns to the scanning dashboard.
    app.focus_index = 7;
    app.speed_select_activate_focused();
    assert_eq!(app.screen, Screen::Scanning);
}

#[test]
fn speed_selection_shows_failed_targets_but_select_all_excludes_them() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut failed = result("192.0.2.2", 1, 0.2);
    failed.ok = 0;
    failed.health_ok = false;
    failed.samples.clear();
    app.results = vec![failed, result("192.0.2.1", 0, 0.03)];
    app.open_speed_selection();

    let visible = app.speed_visible_indices();
    assert_eq!(visible.len(), 2);
    assert_eq!(App::speed_status(&app.results[visible[0]]), "READY");
    app.speed_cursor = 1;
    app.handle_speed_select_key(KeyCode::Char(' '));
    assert!(app.speed_selected.is_empty());
    app.focus_index = 4;
    app.speed_select_activate_focused();
    assert_eq!(
        app.speed_selected,
        ["192.0.2.1".to_string()].into_iter().collect()
    );
}

#[test]
fn speed_selection_filters_by_ip_status_and_protocol() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut failed = result("192.0.2.2", 1, 0.2);
    failed.ok = 0;
    failed.health_ok = false;
    failed.protocol = "h3".to_string();
    app.results = vec![result("192.0.2.1", 0, 0.03), failed];
    app.open_speed_selection();

    app.speed_query = "192.0.2.2".to_string();
    assert_eq!(app.speed_visible_indices().len(), 1);
    app.speed_query = "failed".to_string();
    assert_eq!(app.speed_visible_indices().len(), 1);
    app.speed_query = "h3".to_string();
    assert_eq!(app.speed_visible_indices().len(), 1);
}

#[test]
fn speed_selection_sorts_latency_then_protocol_then_ip() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut a = result("192.0.2.3", 0, 0.05);
    a.protocol = "h3".to_string();
    let mut b = result("192.0.2.1", 0, 0.05);
    b.protocol = "h2".to_string();
    let c = result("192.0.2.2", 0, 0.01);
    app.results = vec![a, b, c];
    app.open_speed_selection();

    let ips = |app: &App| {
        app.speed_visible_indices()
            .into_iter()
            .map(|index| app.results[index].ip.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ips(&app), vec!["192.0.2.2", "192.0.2.1", "192.0.2.3"]);
    app.speed_sort_asc = false;
    assert_eq!(ips(&app), vec!["192.0.2.3", "192.0.2.1", "192.0.2.2"]);
}

#[test]
fn speed_selection_keeps_selection_when_filtering_and_sorting() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.results = vec![result("192.0.2.1", 0, 0.03), result("192.0.2.2", 0, 0.01)];
    app.open_speed_selection();
    app.speed_selected.insert("192.0.2.1".to_string());
    app.speed_query = "192.0.2.2".to_string();
    app.speed_sort_asc = false;
    assert!(app.speed_selected.contains("192.0.2.1"));
    app.speed_query.clear();
    assert!(app.speed_selected.contains("192.0.2.1"));
}

#[test]
fn location_filter_matches_colo_case_insensitively() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut a = result("10.0.0.1", 0, 0.1);
    a.colo = Some("Fra".to_string());
    let mut b = result("10.0.0.2", 0, 0.1);
    b.colo = Some("gru".to_string());
    app.results = vec![a, b];
    app.colo_filter = Some("fra".to_string());
    let ips: Vec<_> = app.sorted_results().iter().map(|r| r.ip.clone()).collect();
    assert_eq!(ips, vec!["10.0.0.1"]);
}

#[test]
fn location_filter_matches_unicode_country_substring() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut a = result("10.0.0.1", 0, 0.1);
    a.country = Some("Côte d'Ivoire".to_string());
    let mut b = result("10.0.0.2", 0, 0.1);
    b.country = Some("France".to_string());
    app.results = vec![a, b];
    // "CÔTE" (uppercase circumflex) must match "Côte d'Ivoire" case-insensitively.
    app.country_filter = Some("CÔTE".to_string());
    let ips: Vec<_> = app.sorted_results().iter().map(|r| r.ip.clone()).collect();
    assert_eq!(ips, vec!["10.0.0.1"]);
}

#[test]
fn location_sort_by_colo_and_country() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    let mut a = result("10.0.0.1", 0, 0.1);
    a.colo = Some("gru".to_string());
    a.country = Some("Brazil".to_string());
    let mut b = result("10.0.0.2", 0, 0.1);
    b.colo = Some("fra".to_string());
    b.country = Some("Germany".to_string());
    app.results = vec![a, b];
    app.sort_asc = true;

    app.sort_col = 10; // by colo
    let mut ips: Vec<_> = app.sorted_results().iter().map(|r| r.ip.clone()).collect();
    assert_eq!(ips, vec!["10.0.0.2", "10.0.0.1"]); // fra < gru

    app.sort_col = 11; // by country
    ips = app.sorted_results().iter().map(|r| r.ip.clone()).collect();
    assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2"]); // Brazil < Germany
}

#[test]
fn help_overlay_closes_only_on_dedicated_keys() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.show_help = true;
    // Navigation keys are consumed but leave help open.
    app.handle_key(KeyCode::Down, KeyModifiers::NONE);
    assert!(app.show_help);
    app.handle_key(KeyCode::Char('x'), KeyModifiers::NONE);
    assert!(app.show_help);
    // Esc dismisses it.
    app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
    assert!(!app.show_help);
}

#[test]
fn ports_editor_renders_one_row_per_port_on_narrow_terminals() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Settings;
    let ports_idx = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Ports)
        .unwrap();
    app.start_edit(ports_idx);

    let output = rendered(&mut app, 40, 30);
    // Every port must be on screen: the inline single-line form overflowed
    // this width and clipped everything past the first few ports.
    for port in [443u16, 2053, 2083, 2087, 2096, 8443] {
        assert!(
            output.contains(&port.to_string()),
            "port {port} not rendered at 40 columns"
        );
    }
    // The row map exposes exactly one row per port for mouse hit-testing.
    let mapped: Vec<usize> = app.ports_row_map.iter().flatten().copied().collect();
    assert_eq!(mapped, vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn mouse_tap_toggles_the_clicked_port_while_editing() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Settings;
    let ports_idx = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Ports)
        .unwrap();
    app.start_edit(ports_idx);
    assert_eq!(app.edit_buffer, "443");

    draw(&mut app, 120, 36);
    let inner = app.settings_inner.unwrap();
    let row = app
        .ports_row_map
        .iter()
        .position(|p| *p == Some(1))
        .unwrap();

    let tap = |app: &mut App, row: usize| {
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: inner.x + 2,
            row: inner.y + row as u16,
            modifiers: KeyModifiers::NONE,
        });
    };

    tap(&mut app, row);
    assert_eq!(app.edit_field, Some(ports_idx));
    assert_eq!(app.port_cursor, 1);
    assert!(
        app.edit_buffer.split(',').any(|value| value == "2053"),
        "tap should have selected port 2053"
    );

    tap(&mut app, row);
    assert!(
        !app.edit_buffer.split(',').any(|value| value == "2053"),
        "second tap should have deselected port 2053"
    );
}

#[test]
fn interface_editor_renders_auto_row_and_interface_addresses() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Settings;
    let interface_idx = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Interface)
        .unwrap();
    app.start_edit(interface_idx);
    let interfaces = app.interface_list.clone();
    assert!(
        !interfaces.is_empty(),
        "expected at least a loopback interface"
    );

    let output = rendered(&mut app, 160, 40);
    assert!(
        output.contains("Auto (default)"),
        "the Auto row must always be listed"
    );
    // The row map exposes one row per selectable entry (Auto first) for
    // mouse hit-testing, but only for rows in the viewport. On hosts with
    // many interfaces the map is a leading window of the picker list, not
    // the whole list, so only assert that property.
    let mapped: Vec<usize> = app.interface_row_map.iter().flatten().copied().collect();
    assert!(
        mapped.iter().enumerate().all(|(index, row)| *row == index),
        "mapped rows must be the leading window of the picker list"
    );
    for (index, entry) in interfaces.iter().enumerate() {
        if !mapped.contains(&(index + 1)) {
            continue;
        }
        assert!(
            output.contains(&entry.name),
            "interface {} not rendered",
            entry.name
        );
        for addr in &entry.addresses {
            assert!(
                output.contains(&addr.to_string()),
                "address {} of {} not rendered",
                addr,
                entry.name
            );
        }
    }
}

#[test]
fn mouse_tap_commits_the_clicked_interface_while_editing() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Settings;
    let interface_idx = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Interface)
        .unwrap();
    app.start_edit(interface_idx);
    assert_eq!(app.interface_cursor, 0);

    draw(&mut app, 120, 36);
    let inner = app.settings_inner.unwrap();
    let row = app
        .interface_row_map
        .iter()
        .position(|entry| *entry == Some(1))
        .unwrap();

    let tap = |app: &mut App, row: usize| {
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: inner.x + 2,
            row: inner.y + row as u16,
            modifiers: KeyModifiers::NONE,
        });
    };

    let expected = app.interface_list.first().map(|entry| entry.name.clone());
    tap(&mut app, row);
    assert_eq!(app.edit_field, None, "tap should commit the selection");
    assert_eq!(app.config.interface, expected);
}

#[test]
fn ports_editor_keeps_row_maps_aligned() {
    let mut app = App::new(
        AppConfig::default(),
        false,
        Arc::new(AtomicBool::new(false)),
    );
    app.wizard_step = WizardStep::Settings;
    let ports_idx = SettingField::ALL
        .iter()
        .position(|field| *field == SettingField::Ports)
        .unwrap();
    app.start_edit(ports_idx);

    // Tall terminal: the visible slice covers every row, so the row maps
    // must all stay as long as the rendered list.
    draw(&mut app, 120, 80);

    assert_eq!(
        app.settings_row_map.len(),
        app.interface_row_map.len(),
        "interface row map must track the rendered rows while ports are edited"
    );
    assert_eq!(
        app.settings_row_map.len(),
        app.ports_row_map.len(),
        "ports row map must track the rendered rows while ports are edited"
    );
}
