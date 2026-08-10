mod clipboard;
pub mod dashboard;
pub mod help;
mod run;
pub mod speed;
mod state;
#[cfg(test)]
mod tests;
pub mod theme;
pub mod widgets;
pub mod wizard;

pub use run::run_tui;
use state::{apply_event_to_activity, PendingScanAction, SortedCache};
pub use state::{
    Action, ButtonAction, CidrEntry, FocusTarget, InvestigationState, RunKind, RunRecord,
    ScanDashboardView, ScanLifecycle, ScanProgressState, Screen, TargetActivity, TargetFilter,
    TargetSort, TargetStage, TimedScanEvent, WizardStep,
};

pub use widgets::{ButtonKind, ToastKind};

use std::{
    cell::RefCell,
    cmp::Ordering as CmpOrdering,
    collections::{BTreeMap, HashSet, VecDeque},
    fs,
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    symbols::border::ROUNDED,
    text::{Line, Span},
    widgets::{Block, Borders, ListState, Paragraph},
    Frame,
};

use crate::config::AppConfig;
use crate::scanner::{
    ProbeFailureCounts, ProbeResult, ScanControl, ScanEvent, ScanEventKind, ScanProgress,
};
use crate::speed::{SpeedDirection, SpeedResult};
use crate::tui::wizard::SettingField;
use tui_overlay::{Anchor, Backdrop, Easing, Overlay, OverlayState, Slide};

/// Default animation configuration shared by every modal overlay.
fn modal_state() -> OverlayState {
    let duration = if reduced_motion() {
        Duration::ZERO
    } else {
        Duration::from_millis(140)
    };
    OverlayState::new()
        .with_duration(duration)
        .with_easing(Easing::EaseOut)
}

/// Terminal applications do not receive a platform reduced-motion signal, so
/// provide an explicit opt-in that works in SSH and CI environments too.
/// `CLEANSCAN_REDUCED_MOTION=1` disables modal sliding while retaining all
/// state and status feedback.
fn reduced_motion() -> bool {
    std::env::var("CLEANSCAN_REDUCED_MOTION")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Build a centered, dimmed, sliding modal overlay with a themed title block.
pub(crate) fn modal_overlay(
    title: &'static str,
    percent_w: u16,
    percent_h: u16,
) -> Overlay<'static> {
    let overlay = Overlay::new()
        .anchor(Anchor::Center)
        .width(Constraint::Percentage(percent_w))
        .height(Constraint::Percentage(percent_h))
        .backdrop(Backdrop::new(theme::palette().sel_bg))
        .block(widgets::panel_block(title, true));
    if reduced_motion() {
        overlay
    } else {
        overlay.slide(Slide::Top)
    }
}

/// Central application state shared across all screens.
pub struct App {
    /// Editable scan parameters; drive the scan when launched from the wizard.
    pub config: AppConfig,
    pub system_network: crate::system_info::SystemNetworkInfo,
    pub screen: Screen,
    pub wizard_step: WizardStep,
    pub cidr_candidates: Vec<CidrEntry>,
    pub cursor: usize,
    pub port_cursor: usize,
    /// Row cursor while the network-interface picker is being edited.
    pub interface_cursor: usize,
    /// Live interface list shown by the network-interface picker.
    pub interface_list: Vec<crate::iface::InterfaceInfo>,
    /// Cached `(ip)` suffix for the review screen's interface row; computed
    /// once per interface change instead of on every rendered frame.
    pub review_interface_suffix: Option<String>,
    /// When true, the user is typing a custom CIDR in the ranges step.
    pub custom_input_mode: bool,
    pub input_buffer: String,
    /// Index of the settings field currently being edited, if any.
    pub edit_field: Option<usize>,
    pub edit_buffer: String,
    pub edit_caret: usize,
    pub results: Vec<ProbeResult>,
    results_revision: u64,
    sorted_cache: RefCell<Option<SortedCache>>,
    pub total_targets: usize,
    pub scan_started_ips: HashSet<String>,
    /// Unique IPs with at least one emitted result in the current scan.
    pub scan_result_ips: HashSet<String>,
    /// Unique IPs with at least one successful emitted result.
    pub scan_succeeded_ips: HashSet<String>,
    pub scan_progress: ScanProgressState,
    pub dashboard_view: ScanDashboardView,
    pub target_activity: BTreeMap<String, TargetActivity>,
    pub target_cursor: usize,
    pub target_scroll: usize,
    pub target_render_start: usize,
    pub target_filter: TargetFilter,
    pub target_sort: TargetSort,
    pub target_query: String,
    pub selected_targets: HashSet<String>,
    pub scan_events: VecDeque<TimedScanEvent>,
    pub last_completion_at: Option<Instant>,
    pub run_history: VecDeque<RunRecord>,
    pub run_cursor: usize,
    pub run_scroll: usize,
    pub run_render_start: usize,
    pub current_run_id: u64,
    pub current_source_run_id: Option<u64>,
    pub next_run_id: u64,
    pub active_run_kind: RunKind,
    pub pending_run_kind: RunKind,
    pub pending_source_run_id: Option<u64>,
    pub active_targets: Vec<String>,
    pub pending_isolation: Option<String>,
    pub investigation: Option<InvestigationState>,
    pub scan_control: Option<std::sync::mpsc::Sender<ScanControl>>,
    /// Exact sampled targets shown in the review screen and used for the run.
    pub preview_targets: Vec<String>,
    preview_rx: Option<std::sync::mpsc::Receiver<Result<Vec<String>, String>>>,
    preview_pending: bool,
    preview_failed: bool,
    pub last_targets: Vec<String>,
    pub scan_seed: u64,
    pub scan_complete: bool,
    pub scan_lifecycle: ScanLifecycle,
    /// Persistent error from the scan worker, retained for diagnosis after
    /// the worker exits instead of being shown only as a transient toast.
    pub scan_error: Option<String>,
    pub should_quit: bool,
    pub paused: Arc<AtomicBool>,
    pub cancel: Option<Arc<AtomicBool>>,
    pub quit_after_cancel: bool,
    pub edit_after_stop: bool,
    pub message: Option<String>,
    pub message_kind: ToastKind,
    pub message_time: Option<Instant>,
    /// Scroll offset into the results table.
    pub scroll: usize,
    pub result_cursor: usize,
    /// Scroll offset into the wizard CIDR list.
    pub ranges_scroll: usize,
    pub ranges_list_state: ListState,
    /// Scroll offset into the wizard settings list.
    pub settings_scroll: usize,
    pub settings_list_state: ListState,
    /// Whether expert ranking/adaptive scan settings are visible.
    pub show_advanced_settings: bool,
    /// Currently sorted column index in the results table (natural order = 0).
    pub sort_col: usize,
    pub sort_asc: bool,
    pub show_failures: bool,
    pub colo_filter: Option<String>,
    pub country_filter: Option<String>,
    pub result_column_visibility: [bool; 14],
    pub column_picker_cursor: usize,
    pub start_time: Instant,
    /// Help overlay visibility.
    pub show_help: bool,
    /// Vertical scroll offset for contextual help on short terminals.
    pub help_scroll: usize,
    /// Animation frame counter, advanced once per event-loop iteration.
    pub tick: u64,
    /// Last known mouse position, used for button hover styling.
    pub hover_pos: Option<(u16, u16)>,
    /// Rolling per-second probe throughput samples (for the sparkline).
    pub throughput: Vec<u64>,
    /// Timestamp of the last throughput sample.
    pub last_tp_instant: Instant,
    /// Result count at the last throughput sample.
    pub last_tp_count: usize,
    /// Probe-completion snapshots used for the rolling dashboard rate.
    pub probe_rate_history: Vec<(Instant, usize)>,
    // --- mouse hit-testing regions (recomputed every render) ---
    pub buttons: Vec<(Rect, ButtonAction)>,
    pub ranges_inner: Option<Rect>,
    pub settings_inner: Option<Rect>,
    /// Maps each rendered settings row to a field index (`None` for headers).
    pub settings_row_map: Vec<Option<usize>>,
    /// Maps each rendered settings row to a Cloudflare HTTPS port index while
    /// the ports field is being edited (`None` otherwise), for mouse hit-testing.
    pub ports_row_map: Vec<Option<usize>>,
    /// Maps each rendered settings row to a network-interface row index while
    /// the interface field is being edited (`None` otherwise), for mouse hit-testing.
    pub interface_row_map: Vec<Option<usize>>,
    pub table_inner: Option<Rect>,
    pub table_header: Option<Rect>,
    pub table_col_bounds: Vec<(u16, u16)>,
    pub table_col_indices: Vec<usize>,
    pub dashboard_tabs: Vec<(Rect, ScanDashboardView)>,
    /// Speed-select list inner rect + first visible index, for mouse hit-testing.
    pub speed_list_inner: Option<Rect>,
    pub speed_list_start: usize,
    pub speed_table_header: Option<Rect>,
    pub speed_table_col_bounds: Vec<(u16, u16)>,
    /// Set when a quit was requested while a scan is running; a second 'q'
    /// confirms the exit. Any other key clears it.
    pub confirm_quit: bool,
    /// Set when the wizard's Start action fires; the run loop performs the spawn.
    pub pending_start: bool,
    pub rescan_targets: Option<Vec<String>>,
    pub speed_targets: Vec<String>,
    pub speed_selected: std::collections::HashSet<String>,
    pub speed_cursor: usize,
    pub speed_query: String,
    pub speed_search_mode: bool,
    pub speed_sort_col: usize,
    pub speed_sort_asc: bool,
    pub speed_direction: SpeedDirection,
    pub speed_results: Vec<SpeedResult>,
    pub speed_result_cursor: usize,
    pub speed_complete: bool,
    pub speed_start_time: Instant,
    pub pending_speed_start: bool,
    pub confirm_speed_start: bool,
    confirm_scan_action: Option<PendingScanAction>,
    /// Active semantic focus target and its position in the current screen's
    /// focus map. Focus is intentionally independent from list cursors.
    pub focus_target: FocusTarget,
    pub focus_index: usize,
    /// Searchable command palette state.
    pub show_command_palette: bool,
    pub show_column_picker: bool,
    pub command_query: String,
    pub command_cursor: usize,
    pub command_list_state: ListState,
    pub column_picker_list_state: ListState,
    /// Full statistics drawer for the currently selected latency result.
    pub show_result_details: bool,
    pub detail_tab: usize,
    pub watch_interval: Option<Duration>,
    /// Source identity used to keep watch promotion/demotion state stable
    /// when a cycle is relaunched through the exact-target rescan path.
    pub watch_source_fingerprint: Option<u64>,
    pub watch_cycle: u64,
    pub watch_due: Option<Instant>,
    pub manifest_path: Option<String>,
    pub manifest_thresholds: crate::HealthThresholds,
    pub manifest_min_confidence: String,
    pub manifest_backups: usize,
    pub last_watch_healthy: Option<bool>,
    pub alert_message: Option<String>,
    pub watch_state: Option<crate::watch::WatchState>,
    pub watch_policy: crate::watch::WatchPolicy,
    pub watch_state_path: Option<String>,
    pub watch_new_sample: bool,
    /// True when the wizard was opened from completed results and should
    /// return there instead of quitting when the user backs out.
    pub return_to_results: bool,
    /// Animation lifecycle state for each modal layer, driven by `render`.
    pub help_overlay: OverlayState,
    pub quit_overlay: OverlayState,
    pub speed_confirm_overlay: OverlayState,
    pub command_palette_overlay: OverlayState,
    pub column_picker_overlay: OverlayState,
    pub result_details_overlay: OverlayState,
    pub scan_action_overlay: OverlayState,
    /// Last frame timestamp used to derive per-frame animation deltas.
    anim_clock: Option<Instant>,
    explicit_target_source: Option<(Vec<String>, Option<String>)>,
}

impl App {
    fn resolve_terminal_lifecycle(&self, outcome: ScanLifecycle) -> ScanLifecycle {
        if self.scan_lifecycle == ScanLifecycle::Cancelling {
            ScanLifecycle::Cancelled
        } else {
            outcome
        }
    }

    /// Elapsed time since the previous frame, used to advance overlay animations.
    /// Called once per `render` so every modal ticks by the same delta.
    fn anim_elapsed(&mut self) -> Duration {
        let now = Instant::now();
        let elapsed = match self.anim_clock {
            Some(prev) => now.saturating_duration_since(prev),
            None => Duration::ZERO,
        };
        self.anim_clock = Some(now);
        elapsed
    }

    /// Number of focusable regions on the current screen. Keeping this map
    /// small and predictable makes Tab useful even when a screen is compact.
    pub fn focus_count(&self) -> usize {
        match self.screen {
            Screen::Wizard => match self.wizard_step {
                WizardStep::Ranges => 3,
                WizardStep::Settings => 3,
                WizardStep::Review => 3,
            },
            Screen::Scanning => {
                if self.scan_complete && self.scan_lifecycle != ScanLifecycle::Cancelling {
                    5
                } else {
                    4
                }
            }
            Screen::SpeedSelect => 8,
            Screen::SpeedTesting => 1,
            Screen::SpeedResults => 3,
        }
    }

    pub fn focus_next(&mut self, reverse: bool) {
        let count = self.focus_count().max(1);
        if reverse {
            self.focus_index = if self.focus_index == 0 {
                count - 1
            } else {
                self.focus_index - 1
            };
        } else {
            self.focus_index = (self.focus_index + 1) % count;
        }
        self.focus_target = self.focus_target_for(self.focus_index);
    }

    pub fn focus_target_for(&self, index: usize) -> FocusTarget {
        if self.confirm_quit || self.show_command_palette || self.show_result_details {
            return FocusTarget::Dialog;
        }
        match self.screen {
            Screen::Wizard => match (self.wizard_step, index) {
                (WizardStep::Ranges, 0) => FocusTarget::List,
                (WizardStep::Settings, 0) => FocusTarget::Field,
                (WizardStep::Review, 0) => FocusTarget::Panel,
                _ => FocusTarget::Button,
            },
            Screen::Scanning if index == 0 => FocusTarget::Table,
            Screen::SpeedSelect if index == 0 => FocusTarget::List,
            Screen::SpeedResults if index == 0 => FocusTarget::Table,
            Screen::SpeedTesting => FocusTarget::Panel,
            _ => FocusTarget::Button,
        }
    }

    fn filtered_actions(&self) -> Vec<Action> {
        let query = self.command_query.to_ascii_lowercase();
        Action::ALL
            .iter()
            .copied()
            .filter(|action| {
                *action != Action::OpenCommandPalette
                    && self.action_available(*action)
                    && (query.is_empty()
                        || action.label().to_ascii_lowercase().contains(&query)
                        || action.description().to_ascii_lowercase().contains(&query))
            })
            .collect()
    }

    fn action_available(&self, action: Action) -> bool {
        match self.screen {
            Screen::Wizard => {
                (action == Action::Back
                    && (self.wizard_step as usize > 0 || self.return_to_results))
                    || (action == Action::Next && (self.wizard_step as usize) < 2)
                    || (action == Action::Start && self.wizard_step == WizardStep::Review)
                    || matches!(action, Action::Quit | Action::OpenHelp)
            }
            Screen::Scanning
                if self.scan_complete && self.scan_lifecycle != ScanLifecycle::Cancelling =>
            {
                matches!(
                    action,
                    Action::Quit
                        | Action::Export
                        | Action::SpeedTest
                        | Action::CopyIp
                        | Action::OpenDetails
                        | Action::OpenHelp
                        | Action::OpenCommandPalette
                        | Action::ConfigureColumns
                        | Action::ToggleFailures
                        | Action::RepeatTargets
                        | Action::NewSample
                        | Action::ExportComparison
                        | Action::CustomizeScan
                        | Action::CycleScanView
                        | Action::RerunSelected
                        | Action::IsolateTarget
                ) || ((self.investigation.is_some() || self.pending_isolation.is_some())
                    && matches!(action, Action::PauseResume | Action::StopKeepResults))
            }
            Screen::Scanning => matches!(
                action,
                Action::Quit
                    | Action::PauseResume
                    | Action::CopyIp
                    | Action::OpenDetails
                    | Action::OpenHelp
                    | Action::OpenCommandPalette
                    | Action::ToggleFailures
                    | Action::CycleScanView
                    | Action::IsolateTarget
                    | Action::StopKeepResults
                    | Action::CustomizeScan
            ),
            Screen::SpeedSelect => matches!(
                action,
                Action::Quit
                    | Action::Back
                    | Action::Start
                    | Action::SelectAll
                    | Action::ClearSelection
                    | Action::Download
                    | Action::Upload
                    | Action::Both
                    | Action::OpenHelp
                    | Action::OpenCommandPalette
            ),
            Screen::SpeedTesting => matches!(action, Action::Quit | Action::OpenHelp),
            Screen::SpeedResults => matches!(
                action,
                Action::Quit
                    | Action::CopyIp
                    | Action::Back
                    | Action::OpenHelp
                    | Action::OpenCommandPalette
            ),
        }
    }

    fn selected_action(&self) -> Option<Action> {
        self.filtered_actions().get(self.command_cursor).copied()
    }

    fn open_command_palette(&mut self) {
        self.show_command_palette = true;
        self.command_query.clear();
        self.command_cursor = 0;
    }

    fn close_command_palette(&mut self) {
        self.show_command_palette = false;
        self.command_query.clear();
        self.command_cursor = 0;
    }

    pub fn new(config: AppConfig, has_cli_targets: bool, paused: Arc<AtomicBool>) -> Self {
        let scan_seed = config.seed;
        let mut cidr_candidates = Vec::new();

        let default_set: std::collections::HashSet<String> =
            crate::scanner::DEFAULT_CLOUDFLARE_CIDRS
                .iter()
                .map(|s| s.to_string())
                .collect();

        // Populate candidates from defaults
        for c in crate::scanner::DEFAULT_CLOUDFLARE_CIDRS {
            let selected =
                !config.selected_cidrs_persisted || config.selected_cidrs.contains(&c.to_string());
            cidr_candidates.push(CidrEntry {
                cidr: c.to_string(),
                selected,
            });
        }

        // Add custom ones from config
        for c in &config.custom_cidrs {
            if !default_set.contains(c) {
                let selected = config.selected_cidrs.contains(c);
                cidr_candidates.push(CidrEntry {
                    cidr: c.clone(),
                    selected,
                });
            }
        }

        Self {
            config,
            system_network: crate::system_info::SystemNetworkInfo::default(),
            screen: if has_cli_targets {
                Screen::Scanning
            } else {
                Screen::Wizard
            },
            wizard_step: WizardStep::Ranges,
            cidr_candidates,
            cursor: 0,
            port_cursor: 0,
            interface_cursor: 0,
            interface_list: Vec::new(),
            review_interface_suffix: None,
            custom_input_mode: false,
            input_buffer: String::new(),
            edit_field: None,
            edit_buffer: String::new(),
            edit_caret: 0,
            results: Vec::new(),
            results_revision: 0,
            sorted_cache: RefCell::new(None),
            total_targets: 0,
            scan_started_ips: HashSet::new(),
            scan_result_ips: HashSet::new(),
            scan_succeeded_ips: HashSet::new(),
            scan_progress: ScanProgressState::default(),
            dashboard_view: ScanDashboardView::Results,
            target_activity: BTreeMap::new(),
            target_cursor: 0,
            target_scroll: 0,
            target_render_start: 0,
            target_filter: TargetFilter::All,
            target_sort: TargetSort::Attention,
            target_query: String::new(),
            selected_targets: HashSet::new(),
            scan_events: VecDeque::new(),
            last_completion_at: None,
            run_history: VecDeque::new(),
            run_cursor: 0,
            run_scroll: 0,
            run_render_start: 0,
            current_run_id: 0,
            current_source_run_id: None,
            next_run_id: 1,
            active_run_kind: RunKind::Full,
            pending_run_kind: RunKind::Full,
            pending_source_run_id: None,
            active_targets: Vec::new(),
            pending_isolation: None,
            investigation: None,
            scan_control: None,
            preview_targets: Vec::new(),
            preview_rx: None,
            preview_pending: false,
            preview_failed: false,
            last_targets: Vec::new(),
            scan_seed,
            scan_complete: false,
            scan_lifecycle: ScanLifecycle::Running,
            scan_error: None,
            should_quit: false,
            paused,
            cancel: None,
            quit_after_cancel: false,
            edit_after_stop: false,
            message: None,
            message_kind: ToastKind::Info,
            message_time: None,
            scroll: 0,
            result_cursor: 0,
            ranges_scroll: 0,
            ranges_list_state: ListState::default(),
            settings_scroll: 0,
            settings_list_state: ListState::default(),
            show_advanced_settings: false,
            sort_col: 0,
            sort_asc: true,
            show_failures: false,
            colo_filter: None,
            country_filter: None,
            result_column_visibility: [true; 14],
            column_picker_cursor: 0,
            start_time: Instant::now(),
            show_help: false,
            help_scroll: 0,
            tick: 0,
            hover_pos: None,
            throughput: Vec::new(),
            last_tp_instant: Instant::now(),
            last_tp_count: 0,
            probe_rate_history: Vec::new(),
            buttons: Vec::new(),
            ranges_inner: None,
            settings_inner: None,
            settings_row_map: Vec::new(),
            ports_row_map: Vec::new(),
            interface_row_map: Vec::new(),
            table_inner: None,
            table_header: None,
            table_col_bounds: Vec::new(),
            table_col_indices: Vec::new(),
            dashboard_tabs: Vec::new(),
            speed_list_inner: None,
            speed_list_start: 0,
            speed_table_header: None,
            speed_table_col_bounds: Vec::new(),
            confirm_quit: false,
            pending_start: false,
            rescan_targets: None,
            speed_targets: Vec::new(),
            speed_selected: std::collections::HashSet::new(),
            speed_cursor: 0,
            speed_query: String::new(),
            speed_search_mode: false,
            speed_sort_col: 2,
            speed_sort_asc: true,
            speed_direction: SpeedDirection::Both,
            speed_results: Vec::new(),
            speed_result_cursor: 0,
            speed_complete: false,
            speed_start_time: Instant::now(),
            pending_speed_start: false,
            confirm_speed_start: false,
            confirm_scan_action: None,
            focus_target: FocusTarget::List,
            focus_index: 0,
            show_command_palette: false,
            show_column_picker: false,
            command_query: String::new(),
            command_cursor: 0,
            command_list_state: ListState::default(),
            column_picker_list_state: ListState::default(),
            show_result_details: false,
            detail_tab: 0,
            watch_interval: None,
            watch_source_fingerprint: None,
            watch_cycle: 0,
            watch_due: None,
            manifest_path: None,
            manifest_thresholds: crate::HealthThresholds {
                min_success_rate: None,
                max_p95_ms: None,
            },
            manifest_min_confidence: "UNKNOWN".to_string(),
            manifest_backups: 3,
            last_watch_healthy: None,
            alert_message: None,
            watch_state: None,
            watch_policy: crate::watch::WatchPolicy::default(),
            watch_state_path: None,
            watch_new_sample: false,
            return_to_results: false,
            help_overlay: modal_state(),
            quit_overlay: modal_state(),
            speed_confirm_overlay: modal_state(),
            command_palette_overlay: modal_state(),
            column_picker_overlay: modal_state(),
            result_details_overlay: modal_state(),
            scan_action_overlay: modal_state(),
            anim_clock: None,
            explicit_target_source: None,
        }
    }

    pub fn visible_result_columns(&self) -> Vec<usize> {
        self.result_column_visibility
            .iter()
            .enumerate()
            .filter_map(|(index, visible)| visible.then_some(index))
            .collect()
    }

    pub fn column_visible(&self, column: usize) -> bool {
        self.result_column_visibility
            .get(column)
            .copied()
            .unwrap_or(false)
    }

    fn toggle_column(&mut self) {
        let column = self.column_picker_cursor;
        if self.result_column_visibility[column] && self.visible_result_columns().len() == 1 {
            self.toast_warn("At least one result column must remain visible");
            return;
        }
        self.result_column_visibility[column] = !self.result_column_visibility[column];
        if !self.column_visible(self.sort_col) {
            self.sort_col = 0;
            self.sort_asc = true;
        }
    }

    pub fn save_config(&mut self) {
        let default_set: std::collections::HashSet<String> =
            crate::scanner::DEFAULT_CLOUDFLARE_CIDRS
                .iter()
                .map(|s| s.to_string())
                .collect();

        let mut custom_cidrs = Vec::new();
        for candidate in &self.cidr_candidates {
            if !default_set.contains(&candidate.cidr) {
                custom_cidrs.push(candidate.cidr.clone());
            }
        }

        let selected_cidrs: Vec<String> = self
            .cidr_candidates
            .iter()
            .filter(|e| e.selected)
            .map(|e| e.cidr.clone())
            .collect();

        let mut current_config = self.config.clone();
        current_config.custom_cidrs = custom_cidrs;
        current_config.selected_cidrs = selected_cidrs;

        if let Err(e) = crate::config::save_config(&current_config) {
            self.toast_error(format!("Config save failed: {e}"));
        }
    }

    /// Switch to the scanning dashboard once targets are known. Resets per-scan state.
    pub fn begin_scan(&mut self, total: usize) {
        self.archive_current_run();
        self.active_run_kind = self.pending_run_kind;
        self.current_source_run_id = self.pending_source_run_id;
        self.pending_run_kind = RunKind::Full;
        self.pending_source_run_id = None;
        self.current_run_id = self.next_run_id;
        self.next_run_id = self.next_run_id.saturating_add(1);
        self.screen = Screen::Scanning;
        self.return_to_results = false;
        self.focus_index = 0;
        self.focus_target = FocusTarget::Table;
        self.show_result_details = false;
        self.detail_tab = 0;
        self.total_targets = total;
        self.scan_started_ips.clear();
        self.config
            .runtime_worker_override
            .store(0, Ordering::Relaxed);
        self.scan_result_ips.clear();
        self.scan_succeeded_ips.clear();
        self.scan_progress = ScanProgressState::default();
        self.dashboard_view = ScanDashboardView::Results;
        self.target_activity = self
            .last_targets
            .iter()
            .cloned()
            .map(|ip| (ip.clone(), TargetActivity::queued(ip)))
            .collect();
        self.active_targets = self.last_targets.clone();
        self.target_cursor = 0;
        self.target_scroll = 0;
        self.target_render_start = 0;
        self.target_filter = TargetFilter::All;
        self.target_sort = TargetSort::Attention;
        self.target_query.clear();
        self.selected_targets.clear();
        self.scan_events.clear();
        self.last_completion_at = None;
        self.pending_isolation = None;
        self.investigation = None;
        self.scan_complete = false;
        self.scan_lifecycle = ScanLifecycle::Running;
        self.scan_error = None;
        self.quit_after_cancel = false;
        self.edit_after_stop = false;
        self.results.clear();
        self.results_revision = self.results_revision.wrapping_add(1);
        self.sorted_cache.borrow_mut().take();
        self.scroll = 0;
        self.result_cursor = 0;
        self.sort_col = 0;
        self.sort_asc = true;
        self.show_failures = false;
        self.message = None;
        self.message_time = None;
        self.start_time = Instant::now();
        self.throughput.clear();
        self.last_tp_instant = Instant::now();
        self.last_tp_count = 0;
        self.probe_rate_history.clear();
    }

    fn archive_current_run(&mut self) {
        if self.active_targets.is_empty() || (self.results.is_empty() && !self.scan_complete) {
            return;
        }
        let record = RunRecord {
            id: self.current_run_id,
            source_run_id: self.current_source_run_id,
            kind: self.active_run_kind,
            targets: self.active_targets.clone(),
            results: self.results.clone(),
            elapsed: self.start_time.elapsed(),
            lifecycle: self.scan_lifecycle,
        };
        self.run_history.push_front(record);
        self.evict_run_history();
        self.run_cursor = 0;
        self.run_scroll = 0;
        self.run_render_start = 0;
    }

    fn evict_run_history(&mut self) {
        while self.run_history.len() > 10 {
            let mut linked_sources = self
                .run_history
                .iter()
                .filter_map(|run| run.source_run_id)
                .collect::<HashSet<_>>();
            linked_sources.extend(self.pending_source_run_id);
            linked_sources.extend(self.current_source_run_id);
            // Index zero is the run just archived. Prefer evicting the oldest
            // unreferenced prior run; if every prior run is linked, evict the
            // oldest one and let its dependants report source unavailable.
            let removable = (1..self.run_history.len())
                .rev()
                .find(|index| !linked_sources.contains(&self.run_history[*index].id))
                .unwrap_or_else(|| self.run_history.len() - 1);
            self.run_history.remove(removable);
        }
    }

    pub fn set_scan_control(&mut self, tx: std::sync::mpsc::Sender<ScanControl>) {
        self.scan_control = Some(tx);
    }

    fn apply_runtime_control(
        &mut self,
        control: ScanControl,
        primary_cancel: &Arc<AtomicBool>,
        scheduler_paused: &Arc<AtomicBool>,
    ) {
        match control {
            ScanControl::PauseScheduling => {
                scheduler_paused.store(true, Ordering::Relaxed);
                self.scan_lifecycle = ScanLifecycle::Paused;
                self.toast_info("Scheduling paused; active probes are draining");
            }
            ScanControl::ResumeScheduling => {
                if self.investigation.is_some() {
                    self.toast_warn("Wait for or stop the isolated investigation before resuming");
                } else {
                    if self.pending_isolation.take().is_some() {
                        self.toast_info("Pending isolated investigation cancelled");
                    }
                    scheduler_paused.store(false, Ordering::Relaxed);
                    if !self.scan_complete {
                        self.scan_lifecycle = ScanLifecycle::Running;
                    }
                    self.toast_info("Probe scheduling resumed");
                }
            }
            ScanControl::SetWorkers(workers) => {
                self.config
                    .runtime_worker_override
                    .store(workers.max(1), Ordering::Relaxed);
            }
            ScanControl::AutomaticWorkers => {
                self.config
                    .runtime_worker_override
                    .store(0, Ordering::Relaxed);
            }
            ScanControl::IsolateTarget(ip) => {
                if self.investigation.is_some() || self.pending_isolation.is_some() {
                    self.toast_warn("An isolated investigation is already pending");
                } else {
                    scheduler_paused.store(true, Ordering::Relaxed);
                    if !self.scan_complete {
                        self.scan_lifecycle = ScanLifecycle::Paused;
                    }
                    self.pending_isolation = Some(ip.clone());
                    self.toast_info(format!("Draining active probes before isolating {ip}"));
                }
            }
            ScanControl::StopAndKeepResults => {
                self.quit_after_cancel = false;
                self.pending_isolation = None;
                if let Some(investigation) = &self.investigation {
                    investigation.cancel.store(true, Ordering::Relaxed);
                }
                if !self.scan_complete {
                    primary_cancel.store(true, Ordering::Relaxed);
                    self.scan_lifecycle = ScanLifecycle::Cancelling;
                }
                self.toast_info("Stopping active work; completed results will be kept");
            }
        }
    }

    pub fn set_cancel_token(&mut self, cancel: Arc<AtomicBool>) {
        self.cancel = Some(cancel);
    }

    fn request_cancel(&mut self) {
        let primary_running = matches!(
            self.scan_lifecycle,
            ScanLifecycle::Running | ScanLifecycle::Paused
        );
        let investigation_running = self.investigation.is_some();
        if primary_running || investigation_running || self.pending_isolation.is_some() {
            if let Some(cancel) = &self.cancel {
                if primary_running {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
            if let Some(investigation) = &self.investigation {
                investigation.cancel.store(true, Ordering::Relaxed);
            }
            self.pending_isolation = None;
            self.quit_after_cancel = true;
            if primary_running {
                self.scan_lifecycle = ScanLifecycle::Cancelling;
            }
            self.toast_info("Cancelling active scan work…");
        } else {
            self.should_quit = true;
        }
    }

    pub fn set_scan_targets(&mut self, targets: Vec<String>) {
        self.last_targets = targets.clone();
        self.preview_targets = targets;
        self.preview_failed = false;
    }

    pub fn invalidate_preview(&mut self) {
        self.preview_targets.clear();
        self.preview_failed = false;
    }

    pub fn refresh_preview(&mut self) {
        if self.preview_pending || self.preview_failed {
            return;
        }
        let seed = self.scan_seed;
        let config = self.config.clone();
        let source = self.explicit_target_source.clone();
        let cidrs: Vec<String> = self
            .cidr_candidates
            .iter()
            .filter(|entry| entry.selected)
            .map(|entry| entry.cidr.clone())
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = if let Some((explicit_cidrs, ips)) = source {
                crate::scanner::collect_targets_with_seed(&config, &explicit_cidrs, &ips, seed)
            } else {
                crate::scanner::collect_from_cidrs_with_seed(&cidrs, config.sample_per_cidr, seed)
            }
            .map_err(|error| error.to_string());
            let _ = tx.send(result);
        });
        self.preview_rx = Some(rx);
        self.preview_pending = true;
        self.toast_info("Generating target preview…");
    }

    fn poll_preview(&mut self) {
        let Some(rx) = self.preview_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else { return };
        self.preview_rx = None;
        self.preview_pending = false;
        match result {
            Ok(targets) => {
                self.preview_targets = targets;
                self.preview_failed = false;
                self.toast_success(format!("Generated {} targets", self.preview_targets.len()));
            }
            Err(error) => {
                self.preview_failed = true;
                self.toast_error(format!("Preview failed: {error}"));
            }
        }
    }

    fn collect_preview(&self, seed: u64) -> anyhow::Result<Vec<String>> {
        if let Some((cidrs, ips)) = &self.explicit_target_source {
            crate::scanner::collect_targets_with_seed(&self.config, cidrs, ips, seed)
        } else {
            let cidrs: Vec<String> = self
                .cidr_candidates
                .iter()
                .filter(|entry| entry.selected)
                .map(|entry| entry.cidr.clone())
                .collect();
            crate::scanner::collect_from_cidrs_with_seed(&cidrs, self.config.sample_per_cidr, seed)
        }
    }

    pub fn regenerate_preview(&mut self) -> bool {
        self.preview_failed = false;
        let seed = rand::random();
        match self.collect_preview(seed) {
            Ok(targets) => {
                self.scan_seed = seed;
                self.config.seed = seed;
                self.preview_targets = targets;
                self.preview_failed = false;
                self.toast_success(format!("Generated {} targets", self.preview_targets.len()));
                true
            }
            Err(error) => {
                self.preview_failed = true;
                self.toast_error(format!("Preview failed: {error}"));
                false
            }
        }
    }

    pub fn set_explicit_target_source(&mut self, cidrs: Vec<String>, ips: Option<String>) {
        self.explicit_target_source = Some((cidrs, ips));
        self.preview_failed = false;
    }

    fn regenerate_explicit_preview(&mut self) -> bool {
        if self.explicit_target_source.is_none() {
            return false;
        }
        self.preview_failed = false;
        let seed = rand::random();
        match self.collect_preview(seed) {
            Ok(targets) => {
                self.scan_seed = seed;
                self.config.seed = seed;
                self.preview_targets = targets;
                self.preview_failed = false;
                self.toast_success(format!("Generated {} targets", self.preview_targets.len()));
                true
            }
            Err(error) => {
                self.preview_failed = true;
                self.toast_error(format!("Preview failed: {error}"));
                false
            }
        }
    }

    pub fn save_target_manifest(&mut self) {
        if self.preview_targets.is_empty() {
            self.toast_warn("No sampled targets available");
            return;
        }
        let base = format!("cleanscan_targets_{}.txt", self.scan_seed);
        let content = self.preview_targets.join("\n") + "\n";
        let mut selected = base.clone();
        let mut suffix = 1;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&selected)
            {
                Ok(mut file) => match file.write_all(content.as_bytes()) {
                    Ok(()) => {
                        self.toast_success(format!("Targets saved to {selected}"));
                        break;
                    }
                    Err(error) => {
                        self.toast_error(format!("Target save failed: {error}"));
                        break;
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    selected = format!("cleanscan_targets_{}_{}.txt", self.scan_seed, suffix);
                    suffix += 1;
                }
                Err(error) => {
                    self.toast_error(format!("Target save failed: {error}"));
                    break;
                }
            }
        }
    }

    pub fn add_result(&mut self, result: ProbeResult) {
        self.scan_started_ips.insert(result.ip.clone());
        self.scan_result_ips.insert(result.ip.clone());
        if result.ok > 0 {
            self.scan_succeeded_ips.insert(result.ip.clone());
        }
        let now = Instant::now();
        let activity = self
            .target_activity
            .entry(result.ip.clone())
            .or_insert_with(|| TargetActivity::queued(result.ip.clone()));
        activity.stage = TargetStage::Finalized;
        activity.probes_completed = activity.probes_completed.max(result.completed);
        activity.probes_started = activity.probes_started.max(activity.probes_completed);
        activity.failures = result.fail;
        activity.last_activity = Some(now);
        activity.last_outcome = crate::scanner::result_status(&result).to_string();
        self.last_completion_at = Some(now);
        // Multi-port and multi-check scans forward per-port/per-check rows and
        // then the merged aggregate; keep only the latest (merged) row per IP.
        if let Some(existing) = self.results.iter_mut().find(|r| r.ip == result.ip) {
            *existing = result;
        } else {
            self.results.push(result);
        }
        self.results_revision = self.results_revision.wrapping_add(1);
        self.sorted_cache.borrow_mut().take();
    }

    pub fn apply_scan_progress(&mut self, progress: ScanProgress) {
        if let Some(ip) = &progress.latest_target {
            self.scan_started_ips.insert(ip.clone());
        }
        if progress.current_workers != self.scan_progress.current_workers
            || (progress.adaptive_reason.is_some()
                && progress.adaptive_reason != self.scan_progress.adaptive_reason)
        {
            let workers = progress
                .current_workers
                .unwrap_or(self.config.concurrency.max(1));
            self.apply_scan_event(ScanEvent {
                kind: ScanEventKind::WorkerChanged,
                target: None,
                message: progress
                    .adaptive_reason
                    .clone()
                    .unwrap_or_else(|| format!("scheduler using {workers} workers")),
                diagnostic_category: None,
                probe_succeeded: None,
            });
        }
        if let Some(event) = progress.event.clone() {
            self.apply_scan_event(event);
        }
        self.scan_progress = ScanProgressState {
            phase: progress.phase,
            probes_started: self
                .scan_progress
                .probes_started
                .max(progress.probes_started),
            probes_completed: self
                .scan_progress
                .probes_completed
                .max(progress.probes_completed),
            active_probes: progress.active_probes,
            targets_completed: self
                .scan_progress
                .targets_completed
                .max(progress.targets_completed),
            latest_target: progress.latest_target,
            current_workers: progress
                .current_workers
                .or(self.scan_progress.current_workers),
            adaptive_reason: progress
                .adaptive_reason
                .or(self.scan_progress.adaptive_reason.clone()),
            targets_total: progress.targets_total.or(self.scan_progress.targets_total),
            failure_counts: ProbeFailureCounts {
                request_timeout: self
                    .scan_progress
                    .failure_counts
                    .request_timeout
                    .max(progress.failure_counts.request_timeout),
                connect_timeout: self
                    .scan_progress
                    .failure_counts
                    .connect_timeout
                    .max(progress.failure_counts.connect_timeout),
                connection_tls: self
                    .scan_progress
                    .failure_counts
                    .connection_tls
                    .max(progress.failure_counts.connection_tls),
                general_errors: self
                    .scan_progress
                    .failure_counts
                    .general_errors
                    .max(progress.failure_counts.general_errors),
            },
        };
    }

    fn apply_scan_event(&mut self, event: ScanEvent) {
        let now = Instant::now();
        if let Some(ip) = &event.target {
            let activity = self
                .target_activity
                .entry(ip.clone())
                .or_insert_with(|| TargetActivity::queued(ip.clone()));
            if apply_event_to_activity(activity, &event, now) {
                self.last_completion_at = Some(now);
            }
        }
        self.scan_events.push_front(TimedScanEvent {
            elapsed: self.start_time.elapsed(),
            event,
        });
        self.scan_events.truncate(1_000);
    }

    fn copy_selected_ip(&mut self) {
        let ip = match self.screen {
            Screen::Scanning => self
                .sorted_results()
                .into_iter()
                .take(self.config.top)
                .nth(self.result_cursor)
                .map(|result| result.ip.clone()),
            Screen::SpeedResults => self
                .speed_results
                .get(self.speed_result_cursor)
                .map(|result| result.ip.clone()),
            _ => None,
        };
        let Some(ip) = ip else {
            self.toast_warn("No IP selected");
            return;
        };
        match clipboard::copy(&ip) {
            Ok(destination) => self.toast_success(format!("Copied {ip} to {destination}")),
            Err(error) => self.toast_error(format!("Copy failed: {error}")),
        }
    }

    /// Show a transient toast with an explicit severity.
    pub fn toast_kind(&mut self, msg: impl Into<String>, kind: ToastKind) {
        self.message = Some(msg.into());
        self.message_kind = kind;
        self.message_time = Some(Instant::now());
    }

    pub fn toast_success(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Success);
    }

    pub fn toast_info(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Info);
    }

    pub fn toast_warn(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Warn);
    }

    pub fn toast_error(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Error);
    }

    /// Whether the current toast should still be visible (auto-fade after 4s).
    pub fn visible_message(&self) -> Option<(&str, ToastKind)> {
        match (self.message.as_deref(), self.message_time) {
            (Some(m), Some(t))
                if (self.message_kind == ToastKind::Warn
                    || self.message_kind == ToastKind::Error
                    || t.elapsed() < Duration::from_secs(4)) =>
            {
                Some((m, self.message_kind))
            }
            (Some(m), None) => Some((m, self.message_kind)),
            _ => None,
        }
    }

    /// Clear stale toast.
    pub fn tick_message(&mut self) {
        if let (Some(_), Some(t)) = (self.message.as_deref(), self.message_time) {
            if self.message_kind != ToastKind::Warn
                && self.message_kind != ToastKind::Error
                && t.elapsed() >= Duration::from_secs(4)
            {
                self.message = None;
                self.message_time = None;
            }
        }
    }

    /// Natural ranking used as the default results order.
    pub fn natural_cmp(a: &ProbeResult, b: &ProbeResult) -> std::cmp::Ordering {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.success_rate
                    .partial_cmp(&a.success_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.p95
                    .partial_cmp(&b.p95)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.jitter
                    .partial_cmp(&b.jitter)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.packet_loss
                    .partial_cmp(&b.packet_loss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.max
                    .partial_cmp(&b.max)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.avg
                    .partial_cmp(&b.avg)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Results sorted for display according to the active sort column.
    pub fn sorted_results(&self) -> Vec<&ProbeResult> {
        let key = (
            self.results_revision,
            self.sort_col,
            self.sort_asc,
            self.show_failures,
            self.colo_filter.clone(),
            self.country_filter.clone(),
        );
        let indices = if self
            .sorted_cache
            .borrow()
            .as_ref()
            .is_some_and(|cache| cache.key == key)
        {
            self.sorted_cache
                .borrow()
                .as_ref()
                .expect("cache checked above")
                .indices
                .clone()
        } else {
            let mut indices: Vec<usize> = self
                .results
                .iter()
                .enumerate()
                .filter(|(_, r)| self.show_failures || r.ok > 0)
                .filter(|(_, r)| match &self.colo_filter {
                    Some(want) => r
                        .colo
                        .as_deref()
                        .is_some_and(|c| c.eq_ignore_ascii_case(want)),
                    None => true,
                })
                .filter(|(_, r)| match &self.country_filter {
                    Some(want) => r
                        .country
                        .as_deref()
                        .is_some_and(|c| c.to_lowercase().contains(&want.to_lowercase())),
                    None => true,
                })
                .map(|(index, _)| index)
                .collect();
            indices.sort_by(|&left, &right| {
                let a = &self.results[left];
                let b = &self.results[right];
                if self.sort_col == 0 {
                    let ord = Self::natural_cmp(a, b);
                    if self.sort_asc {
                        ord
                    } else {
                        ord.reverse()
                    }
                } else {
                    let ord = match self.sort_col {
                        1 => a.ip.cmp(&b.ip),
                        2 => a.protocol.cmp(&b.protocol),
                        3 => a.ok.cmp(&b.ok),
                        4 => a.fail.cmp(&b.fail),
                        5 => a.avg.partial_cmp(&b.avg).unwrap_or(CmpOrdering::Equal),
                        6 => a.p50.partial_cmp(&b.p50).unwrap_or(CmpOrdering::Equal),
                        7 => a.p90.partial_cmp(&b.p90).unwrap_or(CmpOrdering::Equal),
                        8 => a.p95.partial_cmp(&b.p95).unwrap_or(CmpOrdering::Equal),
                        9 => a.max.partial_cmp(&b.max).unwrap_or(CmpOrdering::Equal),
                        10 => a.colo.cmp(&b.colo),
                        11 => a.country.cmp(&b.country),
                        12 => a
                            .jitter
                            .partial_cmp(&b.jitter)
                            .unwrap_or(CmpOrdering::Equal),
                        13 => a
                            .packet_loss
                            .partial_cmp(&b.packet_loss)
                            .unwrap_or(CmpOrdering::Equal),
                        _ => CmpOrdering::Equal,
                    };
                    if self.sort_asc {
                        ord
                    } else {
                        ord.reverse()
                    }
                }
            });
            self.sorted_cache.replace(Some(SortedCache {
                key,
                indices: indices.clone(),
            }));
            indices
        };
        indices
            .into_iter()
            .map(|index| &self.results[index])
            .collect()
    }

    // --- shared rendering helpers (also record mouse hit regions) ---

    /// Render an action button and record its rect for mouse hit-testing.
    pub fn button(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        action: ButtonAction,
        focused: bool,
    ) {
        self.button_ex(frame, area, label, action, ButtonKind::Secondary, focused);
    }

    /// Render an action button with an explicit visual weight. Focus or mouse
    /// hover both render the button in its "active" style.
    pub fn button_ex(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        action: ButtonAction,
        kind: ButtonKind,
        focused: bool,
    ) {
        let hovered = self.hover_pos.is_some_and(|p| point_in(area, p));
        let style = widgets::button_style(kind, focused || hovered);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(ROUNDED)
            .style(style);
        let para = Paragraph::new(format!(" {label} "))
            .alignment(ratatui::layout::Alignment::Center)
            .block(block);
        frame.render_widget(para, area);
        self.buttons.push((area, action));
    }

    fn save_to_file(&self) -> Result<String, io::Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let base = format!("cleanscan_{ts}");
        let mut suffix = 0usize;
        let (filename, mut f) = loop {
            let candidate = if suffix == 0 {
                format!("{base}.tsv")
            } else {
                format!("{base}_{suffix}.tsv")
            };
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => break (candidate, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => suffix += 1,
                Err(e) => return Err(e),
            }
        };
        writeln!(
            f,
            "rank\tip\tport\tcolo\tcountry\tprotocol\tok\tfail\tavg\tp50\tp90\tp95\tmax\tjitter\tpacket_loss"
        )?;
        for (i, r) in ranked_export_results(&self.results, self.config.top)
            .into_iter()
            .enumerate()
        {
            writeln!(f, "{}", export_tsv_line(i + 1, r))?;
        }
        Ok(filename)
    }

    fn save_comparison_to_file(&self) -> Result<String, io::Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let base = format!("cleanscan_comparison_{ts}");
        let mut suffix = 0usize;
        let (filename, mut file) = loop {
            let candidate = if suffix == 0 {
                format!("{base}.json")
            } else {
                format!("{base}_{suffix}.json")
            };
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => break (candidate, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => suffix += 1,
                Err(e) => return Err(e),
            }
        };

        let snapshot = serde_json::json!({
            "seed": self.scan_seed,
            "targets": self.last_targets,
            "results": self.results,
        });
        let content = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        file.write_all(&content)?;
        file.write_all(b"\n")?;
        Ok(filename)
    }

    pub fn export_comparison(&mut self) {
        if !self.scan_complete {
            self.toast_warn("Scan still running — wait for it to finish before exporting");
            return;
        }
        match self.save_comparison_to_file() {
            Ok(name) => self.toast_success(format!("Comparison saved to {name}")),
            Err(e) => self.toast_error(format!("Comparison export failed: {e}")),
        }
    }

    /// Save results to a TSV file (only meaningful when the scan is done).
    pub fn save(&mut self) {
        if !self.scan_complete {
            self.toast_warn("Scan still running — wait for it to finish before saving");
            return;
        }
        match self.save_to_file() {
            Ok(name) => self.toast_success(format!("Results saved to {name}")),
            Err(e) => self.toast_error(format!("Save failed: {e}")),
        }
    }
}

fn ranked_export_results(results: &[ProbeResult], top: usize) -> Vec<&ProbeResult> {
    let mut ranked: Vec<&ProbeResult> = results.iter().filter(|r| r.ok > 0).collect();
    ranked.sort_by(|a, b| App::natural_cmp(a, b));
    ranked.truncate(top);
    ranked
}

fn export_tsv_line(rank: usize, result: &ProbeResult) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}%",
        rank,
        result.ip,
        result.port,
        result.colo.as_deref().unwrap_or(""),
        result.country.as_deref().unwrap_or(""),
        result.protocol,
        result.ok,
        result.fail,
        result.avg,
        result.p50,
        result.p90,
        result.p95,
        result.max,
        result.jitter,
        result.packet_loss * 100.0,
    )
}

impl App {
    /// Top-level key dispatch.
    fn handle_key(&mut self, code: KeyCode, _mods: KeyModifiers) {
        if self.scan_lifecycle == ScanLifecycle::Cancelling {
            return;
        }
        if self.screen == Screen::Wizard && (self.edit_field.is_some() || self.custom_input_mode) {
            wizard::handle_wizard_key(self, code);
            return;
        }

        // The quit-confirm modal captures all input until dismissed.
        if self.confirm_quit {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.confirm_quit = false;
                    self.request_cancel();
                }
                _ => self.confirm_quit = false,
            }
            return;
        }

        if self.confirm_scan_action.is_some() {
            match code {
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let action = self.confirm_scan_action.take();
                    match action {
                        Some(PendingScanAction::RepeatTargets) => self.repeat_targets_now(),
                        Some(PendingScanAction::NewSample) => self.generate_new_sample_now(),
                        None => {}
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.confirm_scan_action = None;
                }
                _ => {}
            }
            return;
        }

        if self.confirm_speed_start {
            match code {
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.confirm_speed_start = false;
                    self.pending_speed_start = true;
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.confirm_speed_start = false;
                }
                _ => {}
            }
            return;
        }

        if self.show_column_picker {
            match code {
                KeyCode::Esc | KeyCode::Char('q') => self.show_column_picker = false,
                KeyCode::Up => {
                    self.column_picker_cursor = self.column_picker_cursor.saturating_sub(1)
                }
                KeyCode::Down => {
                    self.column_picker_cursor = (self.column_picker_cursor + 1)
                        .min(dashboard::RESULT_COLUMNS.len().saturating_sub(1))
                }
                KeyCode::Char(' ') | KeyCode::Enter => self.toggle_column(),
                _ => {}
            }
            return;
        }

        if self.show_command_palette {
            match code {
                KeyCode::Esc => self.close_command_palette(),
                KeyCode::Up => {
                    self.command_cursor = self.command_cursor.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.command_cursor = (self.command_cursor + 1)
                        .min(self.filtered_actions().len().saturating_sub(1));
                }
                KeyCode::Enter => {
                    let query = self.command_query.trim();
                    if let Some(code) = query.strip_prefix("colo:") {
                        let code = code.trim();
                        self.colo_filter = if code.is_empty() {
                            None
                        } else {
                            Some(code.to_ascii_uppercase())
                        };
                        self.close_command_palette();
                        match &self.colo_filter {
                            Some(c) => self.toast_info(format!("Filtering by colo {c}")),
                            None => self.toast_info("Colo filter cleared"),
                        }
                        return;
                    }
                    if let Some(code) = query.strip_prefix("country:") {
                        let code = code.trim();
                        self.country_filter = if code.is_empty() {
                            None
                        } else {
                            Some(code.to_string())
                        };
                        self.close_command_palette();
                        match &self.country_filter {
                            Some(c) => self.toast_info(format!("Filtering by country {c}")),
                            None => self.toast_info("Country filter cleared"),
                        }
                        return;
                    }
                    if let Some(value) = query.strip_prefix("target:") {
                        self.target_query = value.trim().to_string();
                        self.dashboard_view = ScanDashboardView::LiveTargets;
                        self.target_cursor = 0;
                        self.target_scroll = 0;
                        self.close_command_palette();
                        if self.target_query.is_empty() {
                            self.toast_info("Live target search cleared");
                        } else {
                            self.toast_info(format!("Live target search: {}", self.target_query));
                        }
                        return;
                    }
                    if let Some(action) = self.selected_action() {
                        self.close_command_palette();
                        self.activate_action(action);
                    } else {
                        self.toast_warn("No matching command");
                    }
                }
                KeyCode::Backspace => {
                    self.command_query.pop();
                    self.command_cursor = 0;
                }
                KeyCode::Char(c) => {
                    self.command_query.push(c);
                    self.command_cursor = 0;
                }
                _ => {}
            }
            return;
        }

        if self.show_result_details {
            match code {
                KeyCode::Esc | KeyCode::Char('q') => self.show_result_details = false,
                KeyCode::Tab => self.detail_tab = (self.detail_tab + 1) % 5,
                KeyCode::Char('1') => self.detail_tab = 0,
                KeyCode::Char('2') => self.detail_tab = 1,
                KeyCode::Char('3') => self.detail_tab = 2,
                KeyCode::Char('4') => self.detail_tab = 3,
                KeyCode::Char('5') => self.detail_tab = 4,
                KeyCode::Char('c') => self.activate_action(Action::CopyIp),
                KeyCode::Char('e') => self.activate_action(Action::Export),
                KeyCode::Char('t') if self.scan_complete => {
                    self.show_result_details = false;
                    self.activate_action(Action::SpeedTest);
                }
                _ => {}
            }
            return;
        }

        if self.screen == Screen::SpeedSelect && self.speed_search_mode {
            self.handle_speed_select_key(code);
            return;
        }

        // The help overlay stays open until explicitly dismissed with `?`,
        // `Esc`, or `q`, so incidental navigation keys don't close it. All keys
        // are consumed while it is visible.
        if self.show_help {
            if matches!(
                code,
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q')
            ) {
                self.show_help = false;
                self.help_scroll = 0;
            } else {
                match code {
                    KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                    KeyCode::Down => self.help_scroll = self.help_scroll.saturating_add(1),
                    KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(8),
                    KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(8),
                    KeyCode::Home => self.help_scroll = 0,
                    _ => {}
                }
            }
            return;
        }

        // Global keys work on every screen.
        match code {
            KeyCode::Esc if self.screen == Screen::SpeedTesting => {
                self.request_cancel();
                return;
            }
            KeyCode::Esc if self.screen == Screen::Scanning => {
                if self.scan_complete
                    && self.investigation.is_none()
                    && self.pending_isolation.is_none()
                {
                    self.show_help = false;
                    self.should_quit = true;
                } else {
                    self.confirm_quit = true;
                }
                return;
            }
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                self.help_scroll = 0;
                return;
            }
            KeyCode::Char('/') if self.screen == Screen::SpeedSelect => {
                self.speed_search_mode = true;
                return;
            }
            KeyCode::Char('/') => {
                self.open_command_palette();
                return;
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if self.screen == Screen::Scanning
                    && (!self.scan_complete
                        || self.investigation.is_some()
                        || self.pending_isolation.is_some())
                {
                    self.confirm_quit = true;
                } else if self.screen == Screen::SpeedTesting {
                    self.request_cancel();
                } else if self.screen == Screen::Wizard && self.return_to_results {
                    self.return_to_results();
                } else {
                    self.should_quit = true;
                }
                return;
            }
            _ => {}
        }

        match code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus_next(code == KeyCode::BackTab);
                return;
            }
            KeyCode::Char(' ') if self.screen == Screen::Scanning => {
                self.toggle_selected_target();
                return;
            }
            KeyCode::Enter if self.screen == Screen::Scanning => {
                match self.focus_index {
                    0 if self.dashboard_view == ScanDashboardView::Results => {
                        self.show_result_details = true
                    }
                    0 if self.dashboard_view == ScanDashboardView::LiveTargets => {
                        self.toggle_selected_target()
                    }
                    1 if self.scan_complete
                        && (self.investigation.is_some() || self.pending_isolation.is_some()) =>
                    {
                        self.activate_action(Action::PauseResume)
                    }
                    1 if self.scan_complete => self.activate_action(Action::Export),
                    1 => self.activate_action(Action::PauseResume),
                    2 if self.scan_complete
                        && (self.investigation.is_some() || self.pending_isolation.is_some()) =>
                    {
                        self.activate_action(Action::StopKeepResults)
                    }
                    2 if self.scan_complete => self.activate_action(Action::SpeedTest),
                    2 => self.activate_action(Action::StopKeepResults),
                    3 if self.scan_complete => self.activate_action(Action::CustomizeScan),
                    3 => self.activate_action(Action::Quit),
                    4 if self.scan_complete => self.activate_action(Action::Quit),
                    _ => {}
                }
                return;
            }
            _ => {}
        }

        match self.screen {
            Screen::Wizard => wizard::handle_wizard_key(self, code),
            Screen::Scanning => self.handle_scan_key(code),
            Screen::SpeedSelect => self.handle_speed_select_key(code),
            Screen::SpeedTesting => {}
            Screen::SpeedResults => self.handle_speed_results_key(code),
        }
    }

    fn activate_action(&mut self, action: Action) {
        if action == Action::SpeedTest && self.screen == Screen::SpeedTesting {
            return;
        }
        match action {
            Action::Back => self.activate_button(ButtonAction::Back),
            Action::Next => self.activate_button(ButtonAction::Next),
            Action::Start => {
                if self.screen == Screen::SpeedSelect {
                    self.activate_button(ButtonAction::SpeedStart);
                } else if self.screen == Screen::Wizard
                    && self.wizard_step == WizardStep::Review
                    && !self.pending_start
                {
                    self.activate_button(ButtonAction::Start);
                }
            }
            Action::Quit => self.activate_button(ButtonAction::Quit),
            Action::Export => self.save(),
            Action::PauseResume => self.activate_button(ButtonAction::PauseResume),
            Action::SpeedTest => self.activate_button(ButtonAction::SpeedTest),
            Action::CopyIp => self.copy_selected_ip(),
            Action::OpenDetails => {
                if self.scan_lifecycle != ScanLifecycle::Cancelling {
                    self.show_result_details = true;
                }
            }
            Action::CloseDetails => self.show_result_details = false,
            Action::OpenHelp => {
                self.show_help = true;
                self.help_scroll = 0;
            }
            Action::OpenCommandPalette => self.open_command_palette(),
            Action::ConfigureColumns => {
                if self.screen == Screen::Scanning {
                    self.show_column_picker = true;
                    self.column_picker_cursor = self
                        .column_picker_cursor
                        .min(dashboard::RESULT_COLUMNS.len().saturating_sub(1));
                }
            }
            Action::Confirm => {
                if self.confirm_quit {
                    self.confirm_quit = false;
                    self.request_cancel();
                }
            }
            Action::Cancel => {
                self.confirm_quit = false;
                self.confirm_scan_action = None;
                self.show_result_details = false;
            }
            Action::SelectAll => self.activate_button(ButtonAction::SpeedAll),
            Action::ClearSelection => self.activate_button(ButtonAction::SpeedClear),
            Action::Download => self.activate_button(ButtonAction::SpeedDirDownload),
            Action::Upload => self.activate_button(ButtonAction::SpeedDirUpload),
            Action::Both => self.activate_button(ButtonAction::SpeedDirBoth),
            Action::ToggleFailures => {
                if self.screen == Screen::Scanning {
                    self.toggle_failure_filter();
                }
            }
            Action::RepeatTargets => {
                if self.screen == Screen::Scanning && self.scan_complete {
                    self.repeat_targets();
                }
            }
            Action::NewSample => {
                if self.screen == Screen::Scanning && self.scan_complete {
                    self.generate_new_sample();
                }
            }
            Action::ExportComparison => {
                if self.screen == Screen::Scanning && self.scan_complete {
                    self.export_comparison();
                }
            }
            Action::CustomizeScan => {
                if self.screen == Screen::Scanning {
                    if self.scan_complete
                        && self.investigation.is_none()
                        && self.pending_isolation.is_none()
                    {
                        self.enter_customization();
                    } else {
                        self.edit_after_stop = true;
                        self.send_scan_control(ScanControl::StopAndKeepResults);
                        self.toast_info(
                            "Stopping safely; scan settings will open when active work ends",
                        );
                    }
                }
            }
            Action::CycleScanView => self.cycle_scan_view(),
            Action::IsolateTarget => self.isolate_selected_target(),
            Action::RerunSelected => self.rerun_selected_targets(),
            Action::StopKeepResults => self.send_scan_control(ScanControl::StopAndKeepResults),
        }
    }

    /// Draw the current screen. Resets mouse hit regions first, then delegates
    /// to the active screen renderer (and the help overlay if open).
    pub fn render(&mut self, frame: &mut Frame) {
        self.buttons.clear();
        self.ranges_inner = None;
        self.settings_inner = None;
        self.settings_row_map.clear();
        self.ports_row_map.clear();
        self.table_inner = None;
        self.table_header = None;
        self.table_col_bounds.clear();
        self.table_col_indices.clear();
        self.dashboard_tabs.clear();
        self.speed_list_inner = None;
        self.speed_table_header = None;
        self.speed_table_col_bounds.clear();

        let elapsed = self.anim_elapsed();
        match self.screen {
            Screen::Wizard => wizard::render(self, frame, frame.area()),
            Screen::Scanning => dashboard::render(self, frame, frame.area(), elapsed),
            Screen::SpeedSelect | Screen::SpeedTesting | Screen::SpeedResults => {
                speed::render(self, frame, frame.area())
            }
        }

        // Modal layers are always "rendered" so the overlay state machine can
        // play its open/close animation; each overlay is a no-op while closed.
        help::overlay(self, frame, frame.area(), elapsed);
        self.render_quit_confirm(frame, frame.area(), elapsed);
        self.render_scan_action_confirm(frame, frame.area(), elapsed);
        self.render_speed_confirm(frame, frame.area(), elapsed);
        self.render_command_palette(frame, frame.area(), elapsed);
        self.render_column_picker(frame, frame.area(), elapsed);
    }

    fn render_scan_action_confirm(&mut self, frame: &mut Frame, area: Rect, elapsed: Duration) {
        let overlay = modal_overlay(" Confirm scan action ", 54, 30);
        if self.confirm_scan_action.is_some() {
            self.scan_action_overlay.open();
        } else {
            self.scan_action_overlay.close();
        }
        self.scan_action_overlay.tick(elapsed);
        frame.render_stateful_widget(overlay, area, &mut self.scan_action_overlay);
        let Some(inner) = self.scan_action_overlay.inner_area() else {
            return;
        };
        let message = match self.confirm_scan_action {
            Some(PendingScanAction::RepeatTargets) => {
                "Repeat the identical target set? Current results will be replaced."
            }
            Some(PendingScanAction::NewSample) => {
                "Generate a new sample? Current results will be replaced."
            }
            None => return,
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(message),
                Line::from("Enter / y to continue • Esc / n to cancel"),
            ])
            .alignment(ratatui::layout::Alignment::Center),
            inner,
        );
    }

    fn render_column_picker(&mut self, frame: &mut Frame, area: Rect, elapsed: Duration) {
        let overlay = modal_overlay(" Result columns ", 56, 46);
        if self.show_column_picker {
            self.column_picker_overlay.open();
        } else {
            self.column_picker_overlay.close();
        }
        self.column_picker_overlay.tick(elapsed);
        frame.render_stateful_widget(overlay, area, &mut self.column_picker_overlay);
        let Some(inner) = self.column_picker_overlay.inner_area() else {
            return;
        };
        let items = dashboard::RESULT_COLUMNS
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let marker = if self.column_visible(index) {
                    "[x]"
                } else {
                    "[ ]"
                };
                let style = if index == self.column_picker_cursor {
                    theme::row_selected_style()
                } else {
                    ratatui::style::Style::default()
                };
                ratatui::widgets::ListItem::new(
                    Line::from(format!(" {marker} {name:<8}")).style(style),
                )
            })
            .collect::<Vec<_>>();
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(2)])
            .split(inner);
        self.column_picker_list_state = self
            .column_picker_list_state
            .with_offset(0)
            .with_selected(Some(self.column_picker_cursor));
        frame.render_stateful_widget(
            ratatui::widgets::List::new(items)
                .highlight_style(theme::row_selected_style())
                .highlight_symbol(widgets::focus_marker()),
            body[0],
            &mut self.column_picker_list_state,
        );
        frame.render_widget(
            Paragraph::new("↑/↓ move • Space toggle • Esc close").style(theme::hint_style()),
            body[1],
        );
    }

    fn render_command_palette(&mut self, frame: &mut Frame, area: Rect, elapsed: Duration) {
        let overlay = modal_overlay(" Command palette ", 72, 70);
        if self.show_command_palette {
            self.command_palette_overlay.open();
        } else {
            self.command_palette_overlay.close();
        }
        self.command_palette_overlay.tick(elapsed);
        frame.render_stateful_widget(overlay, area, &mut self.command_palette_overlay);
        let Some(inner) = self.command_palette_overlay.inner_area() else {
            return;
        };
        let actions = self.filtered_actions();
        let visible = inner.height.saturating_sub(3).saturating_div(2) as usize;
        self.command_cursor = self.command_cursor.min(actions.len().saturating_sub(1));
        let start = self
            .command_cursor
            .saturating_sub(visible.saturating_sub(1));
        let items = actions
            .iter()
            .enumerate()
            .map(|(i, action)| {
                let style = if i == self.command_cursor {
                    theme::row_selected_style()
                } else {
                    ratatui::style::Style::default()
                };
                ratatui::widgets::ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!(" {:<24}", action.label()), style),
                        Span::styled(
                            format!(" {:<6}", action.shortcut()),
                            theme::highlight_style(),
                        ),
                    ])
                    .style(style),
                    Line::from(format!("   {}", action.description())).style(theme::hint_style()),
                ])
            })
            .collect::<Vec<_>>();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(inner);
        frame.render_widget(
            Paragraph::new(format!(" /{}", self.command_query)).style(theme::title_style()),
            chunks[0],
        );
        if actions.is_empty() {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from("No matching commands"),
                    Line::from("Try: country:germany  or  colo:FRA"),
                ])
                .style(theme::hint_style()),
                chunks[1],
            );
            frame.render_widget(
                Paragraph::new("Type to search • Esc close").style(theme::hint_style()),
                chunks[2],
            );
            return;
        }
        self.command_list_state = self.command_list_state.with_offset(start).with_selected(
            actions
                .get(self.command_cursor)
                .map(|_| self.command_cursor),
        );
        frame.render_stateful_widget(
            ratatui::widgets::List::new(items)
                .highlight_style(theme::row_selected_style())
                .highlight_symbol(widgets::focus_marker()),
            chunks[1],
            &mut self.command_list_state,
        );
        frame.render_widget(
            Paragraph::new("↑/↓ navigate • Enter run • Esc close").style(theme::hint_style()),
            chunks[2],
        );
    }

    fn render_speed_confirm(&mut self, frame: &mut Frame, area: Rect, elapsed: Duration) {
        let overlay = modal_overlay(" Start bandwidth test? ", 58, 32);
        if self.confirm_speed_start {
            self.speed_confirm_overlay.open();
        } else {
            self.speed_confirm_overlay.close();
        }
        self.speed_confirm_overlay.tick(elapsed);
        frame.render_stateful_widget(overlay, area, &mut self.speed_confirm_overlay);
        let Some(inner) = self.speed_confirm_overlay.inner_area() else {
            return;
        };
        let directions = match self.speed_direction {
            SpeedDirection::Download | SpeedDirection::Upload => 1,
            SpeedDirection::Both => 2,
        } as u64;
        let estimated_bytes = self.speed_selected.len() as u64
            * self.config.speed_payload_bytes
            * directions
            * self.config.speed_repetitions as u64;
        let lines = vec![
            Line::from(Span::styled(
                format!("{} IPs selected", self.speed_selected.len()),
                theme::title_style(),
            )),
            Line::from(format!(
                "Estimated minimum transfer: {:.2} GB",
                estimated_bytes as f64 / 1_000_000_000.0
            )),
            Line::from("This may transfer significant data."),
            Line::from("Enter / y to continue • Esc / n to cancel"),
        ];
        frame.render_widget(
            Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center),
            inner,
        );
    }

    /// Modal shown when the user tries to quit mid-scan.
    fn render_quit_confirm(&mut self, frame: &mut Frame, area: Rect, elapsed: Duration) {
        use ratatui::layout::Alignment;
        use ratatui::text::{Line, Span};
        use ratatui::widgets::Paragraph;

        let overlay = modal_overlay(" Quit cleanscan? ", 46, 30);
        if self.confirm_quit {
            self.quit_overlay.open();
        } else {
            self.quit_overlay.close();
        }
        self.quit_overlay.tick(elapsed);
        frame.render_stateful_widget(overlay, area, &mut self.quit_overlay);
        let Some(inner) = self.quit_overlay.inner_area() else {
            return;
        };

        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(1),
                Constraint::Length(3),
            ])
            .split(inner);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Scan work is still active.",
                theme::title_style(),
            )),
            Line::from(Span::styled(
                "Use x to stop and keep completed results; quitting exits the app.",
                theme::hint_style(),
            )),
        ];
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), body[0]);

        let buttons = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(28),
                Constraint::Percentage(4),
                Constraint::Percentage(28),
                Constraint::Percentage(20),
            ])
            .split(body[2]);
        self.button(
            frame,
            buttons[1],
            "Stay (n)",
            ButtonAction::CancelQuit,
            false,
        );
        self.button_ex(
            frame,
            buttons[3],
            "Quit (y)",
            ButtonAction::ConfirmQuit,
            ButtonKind::Primary,
            true,
        );
    }

    fn handle_scan_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('o') => self.activate_action(Action::CycleScanView),
            KeyCode::Char(' ') => self.toggle_selected_target(),
            KeyCode::Char('i') => self.activate_action(Action::IsolateTarget),
            KeyCode::Char('R') if self.scan_complete => self.activate_action(Action::RerunSelected),
            KeyCode::Char('x')
                if !self.scan_complete
                    || self.investigation.is_some()
                    || self.pending_isolation.is_some() =>
            {
                self.activate_action(Action::StopKeepResults)
            }
            KeyCode::Char(',') => self.adjust_runtime_worker_override(-1),
            KeyCode::Char('.') => self.adjust_runtime_worker_override(1),
            KeyCode::Char('[') => self.adjust_runtime_worker_override(-8),
            KeyCode::Char(']') => self.adjust_runtime_worker_override(8),
            KeyCode::Char('0') => self.clear_runtime_worker_override(),
            KeyCode::Char('r') if self.scan_complete => self.activate_action(Action::RepeatTargets),
            KeyCode::Char('n') if self.scan_complete => self.activate_action(Action::NewSample),
            KeyCode::Char('m') if self.scan_complete => {
                self.activate_action(Action::ExportComparison)
            }
            KeyCode::Char('f') if self.dashboard_view == ScanDashboardView::LiveTargets => {
                self.cycle_target_filter()
            }
            KeyCode::Char('s') if self.dashboard_view == ScanDashboardView::LiveTargets => {
                self.cycle_target_sort()
            }
            KeyCode::Char('f') => self.activate_action(Action::ToggleFailures),
            KeyCode::Char('v') => self.activate_action(Action::ConfigureColumns),
            KeyCode::Char('w') => self.activate_action(Action::CustomizeScan),
            KeyCode::Char('p') => self.activate_action(Action::PauseResume),
            KeyCode::Char('e') => self.activate_action(Action::Export),
            KeyCode::Char('t') if self.scan_complete => self.activate_action(Action::SpeedTest),
            KeyCode::Char('c') => self.activate_action(Action::CopyIp),
            KeyCode::Up => self.move_scan_cursor(-1),
            KeyCode::Down => {
                self.move_scan_cursor(1);
            }
            KeyCode::PageUp => self.move_scan_cursor(-10),
            KeyCode::PageDown => self.move_scan_cursor(10),
            KeyCode::Home => self.scan_cursor_home(),
            KeyCode::End => self.scan_cursor_end(),
            _ => {}
        }
    }

    fn cycle_scan_view(&mut self) {
        let current = ScanDashboardView::ALL
            .iter()
            .position(|view| *view == self.dashboard_view)
            .unwrap_or(0);
        self.dashboard_view = ScanDashboardView::ALL[(current + 1) % ScanDashboardView::ALL.len()];
        self.scroll = 0;
        self.toast_info(format!("{} view", self.dashboard_view.label()));
    }

    pub fn visible_target_ips(&self) -> Vec<String> {
        let query = self.target_query.to_lowercase();
        let mut targets = self
            .target_activity
            .values()
            .filter(|target| match self.target_filter {
                TargetFilter::All => true,
                TargetFilter::Active => {
                    matches!(target.stage, TargetStage::WarmingUp | TargetStage::Probing)
                }
                TargetFilter::Problems => target.failures > 0,
                TargetFilter::Selected => self.selected_targets.contains(&target.ip),
            })
            .filter(|target| {
                query.is_empty()
                    || target.ip.to_lowercase().contains(&query)
                    || target.last_outcome.to_lowercase().contains(&query)
                    || target.stage.label().to_lowercase().contains(&query)
            })
            .collect::<Vec<_>>();
        let attention_rank = |target: &TargetActivity| match target.stage {
            TargetStage::WarmingUp | TargetStage::Probing => 0,
            TargetStage::Finalized if target.failures > 0 => 1,
            TargetStage::Queued => 2,
            TargetStage::Finalized => 3,
        };
        let stage_rank = |target: &TargetActivity| match target.stage {
            TargetStage::WarmingUp => 0,
            TargetStage::Probing => 1,
            TargetStage::Queued => 2,
            TargetStage::Finalized => 3,
        };
        targets.sort_by(|left, right| {
            let order = match self.target_sort {
                TargetSort::Attention => attention_rank(left)
                    .cmp(&attention_rank(right))
                    .then_with(|| left.first_activity.cmp(&right.first_activity)),
                TargetSort::ActivityAge => left
                    .first_activity
                    .is_none()
                    .cmp(&right.first_activity.is_none())
                    .then_with(|| left.first_activity.cmp(&right.first_activity)),
                TargetSort::Stage => stage_rank(left).cmp(&stage_rank(right)),
                TargetSort::Ip => CmpOrdering::Equal,
            };
            order.then_with(|| left.ip.cmp(&right.ip))
        });
        targets
            .into_iter()
            .map(|target| target.ip.clone())
            .collect()
    }

    pub fn run_log_len(&self) -> usize {
        1 + usize::from(self.investigation.is_some()) + self.run_history.len()
    }

    fn watch_relaunch_ready(&self, now: Instant, scheduler_paused: bool) -> bool {
        self.watch_due.is_some_and(|due| now >= due)
            && self.pending_isolation.is_none()
            && self.investigation.is_none()
            && !scheduler_paused
    }

    fn cycle_target_filter(&mut self) {
        let current = TargetFilter::ALL
            .iter()
            .position(|filter| *filter == self.target_filter)
            .unwrap_or(0);
        self.target_filter = TargetFilter::ALL[(current + 1) % TargetFilter::ALL.len()];
        self.target_cursor = 0;
        self.target_scroll = 0;
        self.toast_info(format!(
            "Live targets filter: {}",
            self.target_filter.label()
        ));
    }

    fn cycle_target_sort(&mut self) {
        let current = TargetSort::ALL
            .iter()
            .position(|sort| *sort == self.target_sort)
            .unwrap_or(0);
        self.target_sort = TargetSort::ALL[(current + 1) % TargetSort::ALL.len()];
        self.target_cursor = 0;
        self.target_scroll = 0;
        self.toast_info(format!("Live targets sort: {}", self.target_sort.label()));
    }

    fn move_scan_cursor(&mut self, delta: i32) {
        match self.dashboard_view {
            ScanDashboardView::Results => {
                let max = self
                    .sorted_results()
                    .len()
                    .min(self.config.top)
                    .saturating_sub(1);
                self.result_cursor = if delta < 0 {
                    self.result_cursor
                        .saturating_sub(delta.unsigned_abs() as usize)
                } else {
                    (self.result_cursor + delta as usize).min(max)
                };
                self.scroll = self.scroll.min(self.result_cursor);
            }
            ScanDashboardView::LiveTargets => {
                let max = self.visible_target_ips().len().saturating_sub(1);
                self.target_cursor = if delta < 0 {
                    self.target_cursor
                        .saturating_sub(delta.unsigned_abs() as usize)
                } else {
                    (self.target_cursor + delta as usize).min(max)
                };
            }
            ScanDashboardView::RunLog => {
                let max = self.run_log_len().saturating_sub(1);
                self.run_cursor = if delta < 0 {
                    self.run_cursor
                        .saturating_sub(delta.unsigned_abs() as usize)
                } else {
                    (self.run_cursor + delta as usize).min(max)
                };
            }
        }
    }

    fn scan_cursor_home(&mut self) {
        match self.dashboard_view {
            ScanDashboardView::Results => {
                self.result_cursor = 0;
                self.scroll = 0;
            }
            ScanDashboardView::LiveTargets => {
                self.target_cursor = 0;
                self.target_scroll = 0;
            }
            ScanDashboardView::RunLog => {
                self.run_cursor = 0;
                self.run_scroll = 0;
            }
        }
    }

    fn scan_cursor_end(&mut self) {
        match self.dashboard_view {
            ScanDashboardView::Results => {
                self.result_cursor = self
                    .sorted_results()
                    .len()
                    .min(self.config.top)
                    .saturating_sub(1);
                self.scroll = self.result_cursor;
            }
            ScanDashboardView::LiveTargets => {
                self.target_cursor = self.visible_target_ips().len().saturating_sub(1);
                self.target_scroll = self.target_cursor;
            }
            ScanDashboardView::RunLog => {
                self.run_cursor = self.run_log_len().saturating_sub(1);
                self.run_scroll = self.run_cursor;
            }
        }
    }

    fn selected_scan_target(&self) -> Option<String> {
        match self.dashboard_view {
            ScanDashboardView::Results => self
                .sorted_results()
                .get(self.result_cursor)
                .map(|result| result.ip.clone()),
            ScanDashboardView::LiveTargets => {
                self.visible_target_ips().get(self.target_cursor).cloned()
            }
            ScanDashboardView::RunLog => None,
        }
    }

    fn toggle_selected_target(&mut self) {
        let Some(ip) = self.selected_scan_target() else {
            self.toast_warn("Select a target first");
            return;
        };
        if !self.selected_targets.insert(ip.clone()) {
            self.selected_targets.remove(&ip);
        }
        self.toast_info(format!(
            "{} target(s) selected",
            self.selected_targets.len()
        ));
    }

    fn send_scan_control(&mut self, control: ScanControl) {
        let Some(tx) = &self.scan_control else {
            self.toast_warn("Scan controls are unavailable");
            return;
        };
        if tx.send(control).is_err() {
            self.toast_warn("Scanner control channel closed");
        }
    }

    fn isolate_selected_target(&mut self) {
        let Some(ip) = self.selected_scan_target() else {
            self.toast_warn("Select a live target to isolate");
            return;
        };
        self.send_scan_control(ScanControl::IsolateTarget(ip));
    }

    fn rerun_selected_targets(&mut self) {
        if self.investigation.is_some() || self.pending_isolation.is_some() {
            self.toast_warn("Stop or finish the isolated investigation before starting a rerun");
            return;
        }
        if self.selected_targets.is_empty() {
            if let Some(ip) = self.selected_scan_target() {
                self.selected_targets.insert(ip);
            }
        }
        if self.selected_targets.is_empty() {
            self.toast_warn("Select one or more targets first");
            return;
        }
        let mut targets = self.selected_targets.iter().cloned().collect::<Vec<_>>();
        targets.sort();
        self.pending_run_kind = RunKind::Targeted;
        self.pending_source_run_id = Some(self.current_run_id);
        self.rescan_targets = Some(targets);
        self.pending_start = true;
    }

    fn adjust_runtime_worker_override(&mut self, delta: i32) {
        let current = self
            .config
            .runtime_worker_override
            .load(Ordering::Relaxed)
            .max(1);
        let current_workers = self
            .scan_progress
            .current_workers
            .unwrap_or(self.config.concurrency)
            .max(1);
        let current = if self.config.runtime_worker_override.load(Ordering::Relaxed) == 0 {
            current_workers
        } else {
            current
        };
        let next = if delta.is_negative() {
            current.saturating_sub(delta.unsigned_abs() as usize).max(1)
        } else {
            current
                .saturating_add(delta as usize)
                .min(self.config.max_concurrency.max(1))
        };
        self.config
            .runtime_worker_override
            .store(next, Ordering::Relaxed);
        if let Some(tx) = &self.scan_control {
            let _ = tx.send(ScanControl::SetWorkers(next));
        }
        self.toast_info(format!("Manual workers: {next} (0 = automatic)"));
    }

    fn clear_runtime_worker_override(&mut self) {
        self.config
            .runtime_worker_override
            .store(0, Ordering::Relaxed);
        if let Some(tx) = &self.scan_control {
            let _ = tx.send(ScanControl::AutomaticWorkers);
        }
        self.toast_info("Worker count returned to automatic control");
    }

    fn toggle_failure_filter(&mut self) {
        self.show_failures = !self.show_failures;
        self.result_cursor = 0;
        self.scroll = 0;
        if self.show_failures {
            let first_failure = self
                .sorted_results()
                .iter()
                .position(|result| result.fail > 0);
            if let Some(index) = first_failure {
                self.result_cursor = index;
                self.show_result_details = true;
                self.detail_tab = 1;
            } else if self.scan_error.is_some() {
                self.show_result_details = true;
                self.detail_tab = 1;
            }
        }
        self.toast_kind(
            if self.show_failures {
                "Showing failures — opening the first cause"
            } else {
                "Showing successful targets"
            },
            ToastKind::Info,
        );
    }

    fn repeat_targets(&mut self) {
        if self.investigation.is_some() || self.pending_isolation.is_some() {
            self.toast_warn("Stop or finish the isolated investigation before repeating the scan");
            return;
        }
        self.confirm_scan_action = Some(PendingScanAction::RepeatTargets);
    }

    fn repeat_targets_now(&mut self) {
        if self.last_targets.is_empty() {
            self.toast_warn("No previous target manifest available");
        } else {
            self.pending_run_kind = RunKind::Full;
            self.pending_source_run_id = Some(self.current_run_id);
            self.rescan_targets = Some(self.last_targets.clone());
            self.pending_start = true;
            self.toast_info("Re-running the identical target set");
        }
    }

    fn generate_new_sample(&mut self) {
        if self.investigation.is_some() || self.pending_isolation.is_some() {
            self.toast_warn(
                "Stop or finish the isolated investigation before generating a new sample",
            );
            return;
        }
        self.confirm_scan_action = Some(PendingScanAction::NewSample);
    }

    fn generate_new_sample_now(&mut self) {
        self.pending_run_kind = RunKind::Full;
        self.pending_source_run_id = Some(self.current_run_id);
        let generated = if self.explicit_target_source.is_some() {
            self.regenerate_explicit_preview()
        } else {
            self.regenerate_preview()
        };
        if generated {
            self.watch_source_fingerprint = None;
            self.rescan_targets = Some(self.preview_targets.clone());
            self.pending_start = true;
        }
    }

    fn enter_customization(&mut self) {
        self.screen = Screen::Wizard;
        self.wizard_step = WizardStep::Settings;
        self.return_to_results = true;
        self.edit_field = None;
        self.edit_buffer.clear();
        self.cursor = 0;
        self.focus_index = 0;
        self.focus_target = FocusTarget::Field;
        self.toast_info("Customize scan parameters; results are preserved until Start");
    }

    fn return_to_results(&mut self) {
        self.screen = Screen::Scanning;
        self.return_to_results = false;
        self.focus_index = 0;
        self.focus_target = FocusTarget::Table;
        self.toast_info("Returned to previous scan results");
    }

    fn open_speed_selection(&mut self) {
        self.speed_targets = self
            .results
            .iter()
            .map(|result| result.ip.clone())
            .collect();
        self.speed_selected.clear();
        self.speed_cursor = 0;
        self.speed_query.clear();
        self.speed_search_mode = false;
        self.speed_sort_col = 2;
        self.speed_sort_asc = true;
        self.speed_direction = SpeedDirection::Both;
        self.speed_results.clear();
        self.speed_complete = false;
        self.confirm_speed_start = false;
        self.focus_index = 0;
        self.focus_target = FocusTarget::List;
        self.screen = Screen::SpeedSelect;
    }

    fn speed_status(result: &ProbeResult) -> &'static str {
        crate::scanner::result_status(result)
    }

    fn speed_optional_latency_cmp(a: Option<f64>, b: Option<f64>) -> std::cmp::Ordering {
        match (a, b) {
            (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    }

    fn speed_visible_indices(&self) -> Vec<usize> {
        let query = self.speed_query.to_ascii_lowercase();
        let speed_targets: HashSet<&str> = self.speed_targets.iter().map(String::as_str).collect();
        let mut indices: Vec<usize> = self
            .results
            .iter()
            .enumerate()
            .filter(|(_, result)| speed_targets.contains(result.ip.as_str()))
            .filter(|(_, result)| {
                query.is_empty()
                    || result.ip.to_ascii_lowercase().contains(&query)
                    || result.protocol.to_ascii_lowercase().contains(&query)
                    || Self::speed_status(result)
                        .to_ascii_lowercase()
                        .contains(&query)
            })
            .map(|(index, _)| index)
            .collect();

        indices.sort_by(|left, right| {
            let a = &self.results[*left];
            let b = &self.results[*right];
            let ordering = match self.speed_sort_col {
                0 => a.ip.cmp(&b.ip),
                1 => Self::speed_status(a).cmp(Self::speed_status(b)),
                2 => Self::speed_optional_latency_cmp(
                    (a.ok > 0).then_some(a.avg),
                    (b.ok > 0).then_some(b.avg),
                ),
                3 => Self::speed_optional_latency_cmp(
                    (a.ok > 0).then_some(a.p95),
                    (b.ok > 0).then_some(b.p95),
                ),
                4 => a.protocol.cmp(&b.protocol),
                _ => std::cmp::Ordering::Equal,
            };
            let ordering = ordering
                .then_with(|| a.protocol.cmp(&b.protocol))
                .then_with(|| a.ip.cmp(&b.ip));
            if self.speed_sort_asc {
                ordering
            } else {
                ordering.reverse()
            }
        });
        indices
    }

    fn handle_speed_select_key(&mut self, code: KeyCode) {
        if self.speed_search_mode {
            match code {
                KeyCode::Esc => {
                    if self.speed_query.is_empty() {
                        self.speed_search_mode = false;
                    } else {
                        self.speed_query.clear();
                        self.speed_cursor = 0;
                        self.scroll = 0;
                    }
                }
                KeyCode::Backspace => {
                    self.speed_query.pop();
                    self.speed_cursor = 0;
                    self.scroll = 0;
                }
                KeyCode::Enter => self.speed_search_mode = false,
                KeyCode::Char(c) => {
                    self.speed_query.push(c);
                    self.speed_cursor = 0;
                    self.scroll = 0;
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('/') => {
                self.speed_search_mode = true;
            }
            KeyCode::Char(' ') => {
                if let Some(index) = self.speed_visible_indices().get(self.speed_cursor).copied() {
                    let result = &self.results[index];
                    if result.ok > 0 {
                        let ip = result.ip.clone();
                        if !self.speed_selected.insert(ip.clone()) {
                            self.speed_selected.remove(&ip);
                        }
                    }
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.speed_selected = self
                    .results
                    .iter()
                    .filter(|result| result.ok > 0)
                    .map(|result| result.ip.clone())
                    .collect();
            }
            KeyCode::Char('x') | KeyCode::Char('X') | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.speed_selected.clear()
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.speed_direction = SpeedDirection::Download
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                self.speed_direction = SpeedDirection::Upload
            }
            KeyCode::Char('b') | KeyCode::Char('B') => self.speed_direction = SpeedDirection::Both,
            KeyCode::Up if self.speed_cursor > 0 => self.speed_cursor -= 1,
            KeyCode::Down if self.speed_cursor + 1 < self.speed_visible_indices().len() => {
                self.speed_cursor += 1
            }
            KeyCode::PageUp => self.speed_cursor = self.speed_cursor.saturating_sub(10),
            KeyCode::PageDown => {
                self.speed_cursor = (self.speed_cursor + 10)
                    .min(self.speed_visible_indices().len().saturating_sub(1))
            }
            KeyCode::Char('s') => self.speed_sort_asc = !self.speed_sort_asc,
            KeyCode::Char('<') => {
                self.speed_sort_col = self.speed_sort_col.saturating_sub(1);
                self.speed_cursor = 0;
            }
            KeyCode::Char('>') => {
                self.speed_sort_col = (self.speed_sort_col + 1).min(4);
                self.speed_cursor = 0;
            }
            KeyCode::Enter => self.speed_select_activate_focused(),
            KeyCode::Esc => self.screen = Screen::Scanning,
            _ => {}
        }
    }

    /// Activate whichever speed-select control currently holds keyboard focus.
    /// The list (index 0) and the Start button both begin the test; direction
    /// and selection buttons apply their respective action.
    fn speed_select_activate_focused(&mut self) {
        match self.focus_index {
            1 => self.speed_direction = SpeedDirection::Download,
            2 => self.speed_direction = SpeedDirection::Upload,
            3 => self.speed_direction = SpeedDirection::Both,
            4 => {
                self.speed_selected = self
                    .results
                    .iter()
                    .filter(|result| result.ok > 0)
                    .map(|result| result.ip.clone())
                    .collect()
            }
            5 => self.speed_selected.clear(),
            7 => self.screen = Screen::Scanning,
            _ => {
                if self.speed_selected.is_empty() {
                    self.toast_warn("Select at least one successful IP");
                } else {
                    self.confirm_speed_start = true;
                }
            }
        }
    }

    fn handle_speed_results_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => {
                self.screen = Screen::Scanning;
            }
            KeyCode::Char('c') | KeyCode::Char('C') => self.copy_selected_ip(),
            KeyCode::Up => {
                self.speed_result_cursor = self.speed_result_cursor.saturating_sub(1);
                self.scroll = self.scroll.min(self.speed_result_cursor);
            }
            KeyCode::Down => {
                let max = self.speed_results.len().saturating_sub(1);
                self.speed_result_cursor = (self.speed_result_cursor + 1).min(max);
                self.scroll = self.scroll.max(self.speed_result_cursor);
            }
            KeyCode::PageUp => {
                self.speed_result_cursor = self.speed_result_cursor.saturating_sub(10);
                self.scroll = self.scroll.min(self.speed_result_cursor);
            }
            KeyCode::PageDown => {
                let max = self.speed_results.len().saturating_sub(1);
                self.speed_result_cursor = (self.speed_result_cursor + 10).min(max);
                self.scroll = self.scroll.max(self.speed_result_cursor);
            }
            KeyCode::Home => {
                self.speed_result_cursor = 0;
                self.scroll = 0;
            }
            KeyCode::End => {
                self.speed_result_cursor = self.speed_results.len().saturating_sub(1);
                self.scroll = self.speed_result_cursor;
            }
            _ => {}
        }
    }

    fn handle_mouse(&mut self, m: crossterm::event::MouseEvent) {
        use crossterm::event::{MouseButton, MouseEventKind};
        if self.scan_lifecycle == ScanLifecycle::Cancelling {
            return;
        }
        // Track the pointer so buttons can render a hover state.
        self.hover_pos = Some((m.column, m.row));

        // While the quit-confirm overlay is lifecycle-active (opening, open,
        // or closing), all input is captured. Buttons are only activatable
        // once the overlay has fully opened, so clicks during the open/close
        // animation neither fall through to the dashboard nor dismiss the
        // modal prematurely.
        if self.quit_overlay.inner_area().is_some() {
            if let MouseEventKind::Down(MouseButton::Left) = m.kind {
                let p = (m.column, m.row);
                if self.quit_overlay.is_open() {
                    for (rect, action) in self.buttons.clone() {
                        if point_in(rect, p) {
                            self.activate_button(action);
                            break;
                        }
                    }
                }
            }
            return;
        }

        // Other overlays consume all mouse input so clicks cannot activate
        // controls rendered underneath them, including during their close
        // animation (when the visibility flag has already been cleared).
        if self.speed_confirm_overlay.inner_area().is_some()
            || self.scan_action_overlay.inner_area().is_some()
            || self.command_palette_overlay.inner_area().is_some()
            || self.column_picker_overlay.inner_area().is_some()
            || self.result_details_overlay.inner_area().is_some()
        {
            return;
        }

        if self.show_help || self.custom_input_mode {
            return;
        }
        match m.kind {
            MouseEventKind::ScrollUp => {
                if self.screen == Screen::Scanning {
                    self.move_scan_cursor(-1);
                } else if self.screen == Screen::SpeedResults {
                    if self.speed_result_cursor > 0 {
                        self.speed_result_cursor -= 1;
                        self.scroll = self.scroll.min(self.speed_result_cursor);
                    }
                } else if self.screen == Screen::SpeedSelect {
                    self.speed_cursor = self.speed_cursor.saturating_sub(1);
                } else if self.wizard_step == WizardStep::Ranges && !self.custom_input_mode {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                    }
                } else if self.wizard_step == WizardStep::Settings
                    && self.edit_field.is_none()
                    && self.cursor > 0
                {
                    self.cursor -= 1;
                }
            }
            MouseEventKind::ScrollDown => {
                if self.screen == Screen::Scanning {
                    self.move_scan_cursor(1);
                } else if self.screen == Screen::SpeedResults {
                    let max = self.speed_results.len().saturating_sub(1);
                    self.speed_result_cursor = (self.speed_result_cursor + 1).min(max);
                    self.scroll = self.scroll.max(self.speed_result_cursor);
                } else if self.screen == Screen::SpeedSelect {
                    let last = self.speed_visible_indices().len().saturating_sub(1);
                    self.speed_cursor = (self.speed_cursor + 1).min(last);
                } else if self.wizard_step == WizardStep::Ranges && !self.custom_input_mode {
                    let last = self.cidr_candidates.len().saturating_sub(1);
                    if self.cursor < last {
                        self.cursor += 1;
                    }
                } else if self.wizard_step == WizardStep::Settings && self.edit_field.is_none() {
                    let last = SettingField::ALL.len().saturating_sub(1);
                    if self.cursor < last {
                        self.cursor += 1;
                    }
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let p = (m.column, m.row);
                // Buttons take priority.
                for (rect, action) in self.buttons.clone() {
                    if point_in(rect, p) {
                        if self.edit_field.is_some() && !self.commit_edit() {
                            return;
                        }
                        self.activate_button(action);
                        return;
                    }
                }
                if self.screen == Screen::Wizard {
                    if self.wizard_step == WizardStep::Ranges {
                        if let Some(inner) = self.ranges_inner {
                            if point_in(inner, p) {
                                let idx = self.ranges_scroll + (m.row - inner.y) as usize;
                                if idx < self.cidr_candidates.len() {
                                    self.cursor = idx;
                                    if !self.custom_input_mode {
                                        self.cidr_candidates[idx].selected =
                                            !self.cidr_candidates[idx].selected;
                                        self.invalidate_preview();
                                        self.save_config();
                                    }
                                }
                            }
                        }
                    } else if self.wizard_step == WizardStep::Settings {
                        if let Some(inner) = self.settings_inner {
                            if point_in(inner, p) {
                                let row = (m.row - inner.y) as usize;
                                // While editing the ports field, taps toggle
                                // individual ports instead of committing the
                                // whole edit. Other rows keep the normal
                                // commit-and-activate behavior.
                                if self
                                    .edit_field
                                    .map(|i| SettingField::ALL[i] == SettingField::Interface)
                                    .unwrap_or(false)
                                {
                                    if let Some(Some(row_idx)) =
                                        self.interface_row_map.get(row).copied()
                                    {
                                        self.interface_cursor = row_idx;
                                        self.commit_interface_selection();
                                        return;
                                    }
                                }
                                if self
                                    .edit_field
                                    .map(|i| SettingField::ALL[i] == SettingField::Ports)
                                    .unwrap_or(false)
                                {
                                    if let Some(Some(port_idx)) =
                                        self.ports_row_map.get(row).copied()
                                    {
                                        self.port_cursor = port_idx;
                                        wizard::toggle_port_buffer(self);
                                        return;
                                    }
                                }
                                if let Some(Some(idx)) = self.settings_row_map.get(row).copied() {
                                    if self.edit_field.is_some() && !self.commit_edit() {
                                        return;
                                    }
                                    self.cursor = idx;
                                    let field = SettingField::ALL[idx];
                                    if field.is_toggle() {
                                        field.toggle(&mut self.config);
                                        self.invalidate_preview();
                                        self.save_config();
                                    } else {
                                        self.start_edit(idx);
                                    }
                                }
                            }
                        }
                    }
                } else if self.screen == Screen::Scanning {
                    if let Some((_, view)) = self
                        .dashboard_tabs
                        .iter()
                        .find(|(rect, _)| point_in(*rect, p))
                    {
                        self.dashboard_view = *view;
                        return;
                    }
                    if let Some(header) = self.table_header {
                        if point_in(header, p) {
                            if let Some(col) = col_at(&self.table_col_bounds, m.column) {
                                if col == self.sort_col {
                                    self.sort_asc = !self.sort_asc;
                                } else {
                                    self.sort_col =
                                        self.table_col_indices.get(col).copied().unwrap_or(0);
                                    self.sort_asc = true;
                                }
                            }
                        }
                    }
                    if let Some(inner) = self.table_inner {
                        if p.1 > inner.y && point_in(inner, p) {
                            let row = self.scroll + (p.1 - inner.y - 1) as usize;
                            match self.dashboard_view {
                                ScanDashboardView::Results => {
                                    let max = self
                                        .sorted_results()
                                        .len()
                                        .min(self.config.top)
                                        .saturating_sub(1);
                                    self.result_cursor = row.min(max);
                                }
                                ScanDashboardView::LiveTargets => {
                                    self.target_cursor = (self.target_render_start
                                        + (p.1 - inner.y - 1) as usize)
                                        .min(self.visible_target_ips().len().saturating_sub(1));
                                }
                                ScanDashboardView::RunLog => {
                                    self.run_cursor = (self.run_render_start
                                        + (p.1 - inner.y - 1) as usize)
                                        .min(self.run_log_len().saturating_sub(1));
                                }
                            }
                        }
                    }
                } else if self.screen == Screen::SpeedSelect {
                    if let Some(header) = self.speed_table_header {
                        if point_in(header, p) {
                            if let Some(column) = col_at(&self.speed_table_col_bounds, m.column) {
                                let Some(sort_col) = (match column {
                                    1 => Some(0),
                                    2 => Some(1),
                                    3 => Some(2),
                                    4 => Some(3),
                                    5 => Some(4),
                                    _ => None,
                                }) else {
                                    return;
                                };
                                if sort_col == self.speed_sort_col {
                                    self.speed_sort_asc = !self.speed_sort_asc;
                                } else {
                                    self.speed_sort_col = sort_col;
                                    self.speed_sort_asc = true;
                                }
                                self.speed_cursor = 0;
                                self.scroll = 0;
                            }
                            return;
                        }
                    }
                    if let Some(inner) = self.speed_list_inner {
                        if point_in(inner, p) {
                            let row = self.speed_list_start + (m.row - inner.y) as usize;
                            if let Some(index) = self.speed_visible_indices().get(row).copied() {
                                let result = &self.results[index];
                                self.speed_cursor = row;
                                if result.ok > 0 {
                                    let ip = result.ip.clone();
                                    if !self.speed_selected.insert(ip.clone()) {
                                        self.speed_selected.remove(&ip);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        if self.wizard_step == WizardStep::Settings {
            self.ensure_settings_visible();
        }
    }

    fn activate_button(&mut self, action: ButtonAction) {
        match action {
            ButtonAction::Back => {
                if self.wizard_step as usize > 0 {
                    self.wizard_step = match self.wizard_step {
                        WizardStep::Ranges => WizardStep::Ranges,
                        WizardStep::Settings => WizardStep::Ranges,
                        WizardStep::Review => WizardStep::Settings,
                    };
                    self.cursor = 0;
                } else if self.return_to_results {
                    self.return_to_results();
                }
            }
            ButtonAction::Next => {
                if (self.wizard_step as usize) < 2 {
                    self.wizard_step = match self.wizard_step {
                        WizardStep::Ranges => WizardStep::Settings,
                        WizardStep::Settings => WizardStep::Review,
                        WizardStep::Review => WizardStep::Review,
                    };
                    self.cursor = 0;
                }
            }
            ButtonAction::Start => {
                if self.screen == Screen::Wizard && self.wizard_step == WizardStep::Review {
                    // Re-run start via the spawn closure is not accessible here;
                    // instead set a flag handled by the run loop.
                    self.pending_run_kind = RunKind::Full;
                    self.pending_source_run_id = None;
                    self.pending_start = true;
                }
            }
            ButtonAction::Quit => {
                if self.screen == Screen::Scanning
                    && (!self.scan_complete
                        || self.investigation.is_some()
                        || self.pending_isolation.is_some())
                {
                    self.confirm_quit = true;
                } else if self.screen == Screen::Wizard && self.return_to_results {
                    self.return_to_results();
                } else {
                    self.should_quit = true;
                }
            }
            ButtonAction::Save => self.save(),
            ButtonAction::PauseResume => {
                if self.paused.load(Ordering::Relaxed) {
                    self.send_scan_control(ScanControl::ResumeScheduling);
                } else {
                    self.send_scan_control(ScanControl::PauseScheduling);
                }
            }
            ButtonAction::WorkerDown => self.adjust_runtime_worker_override(-1),
            ButtonAction::WorkerUp => self.adjust_runtime_worker_override(1),
            ButtonAction::WorkerAuto => self.clear_runtime_worker_override(),
            ButtonAction::StopKeepResults => {
                self.send_scan_control(ScanControl::StopAndKeepResults)
            }
            ButtonAction::SpeedTest => self.open_speed_selection(),
            ButtonAction::CustomizeScan => {
                if self.screen == Screen::Scanning && self.scan_complete {
                    self.enter_customization();
                }
            }
            ButtonAction::ConfirmQuit => {
                self.confirm_quit = false;
                self.request_cancel();
            }
            ButtonAction::CancelQuit => self.confirm_quit = false,
            ButtonAction::SpeedAll => {
                self.speed_selected = self
                    .results
                    .iter()
                    .filter(|result| result.ok > 0)
                    .map(|result| result.ip.clone())
                    .collect();
            }
            ButtonAction::SpeedClear => self.speed_selected.clear(),
            ButtonAction::SpeedDirDownload => self.speed_direction = SpeedDirection::Download,
            ButtonAction::SpeedDirUpload => self.speed_direction = SpeedDirection::Upload,
            ButtonAction::SpeedDirBoth => self.speed_direction = SpeedDirection::Both,
            ButtonAction::SpeedStart => {
                if self.speed_selected.is_empty() {
                    self.toast_warn("Select at least one successful IP");
                } else {
                    self.confirm_speed_start = true;
                }
            }
            ButtonAction::SpeedBack => self.screen = Screen::Scanning,
        }
    }
}

fn point_in(r: Rect, p: (u16, u16)) -> bool {
    p.0 >= r.x && p.0 < r.x + r.width && p.1 >= r.y && p.1 < r.y + r.height
}

fn col_at(bounds: &[(u16, u16)], x: u16) -> Option<usize> {
    bounds.iter().position(|(x0, x1)| x >= *x0 && x < *x1)
}

/// Restores the terminal when dropped, guaranteeing cleanup on every exit path.
/// yeah
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
        ratatui::restore();
    }
}
