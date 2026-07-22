mod clipboard;
pub mod dashboard;
pub mod help;
pub mod speed;
pub mod theme;
pub mod widgets;
pub mod wizard;

pub use widgets::{ButtonKind, ToastKind};

use std::{
    cell::RefCell,
    cmp::Ordering as CmpOrdering,
    collections::HashSet,
    fs,
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::event::{self, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    symbols::border::ROUNDED,
    text::{Line, Span},
    widgets::{Block, Borders, ListState, Paragraph},
    Frame,
};

use crate::config::AppConfig;
use crate::scanner::{ProbeFailureCounts, ProbeResult, ScanPhase, ScanProgress};
use crate::speed::{SpeedDirection, SpeedResult};
use crate::tui::wizard::SettingField;
use tui_overlay::{Anchor, Backdrop, Easing, Overlay, OverlayState, Slide};

/// Which top-level screen the TUI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Guided setup wizard (steps 1-3).
    Wizard,
    /// Live scanning dashboard.
    Scanning,
    SpeedSelect,
    SpeedTesting,
    SpeedResults,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanLifecycle {
    Running,
    Paused,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct ScanProgressState {
    pub phase: ScanPhase,
    pub probes_started: usize,
    pub probes_completed: usize,
    pub active_probes: usize,
    pub targets_completed: usize,
    pub latest_target: Option<String>,
    pub current_workers: Option<usize>,
    pub adaptive_reason: Option<String>,
    pub targets_total: Option<usize>,
    pub failure_counts: ProbeFailureCounts,
}

impl Default for ScanProgressState {
    fn default() -> Self {
        Self {
            phase: ScanPhase::Starting,
            probes_started: 0,
            probes_completed: 0,
            active_probes: 0,
            targets_completed: 0,
            latest_target: None,
            current_workers: None,
            adaptive_reason: None,
            targets_total: None,
            failure_counts: ProbeFailureCounts::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingScanAction {
    RepeatTargets,
    NewSample,
}

/// Step within the guided wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Ranges = 0,
    Settings = 1,
    Review = 2,
}

/// Semantic focus target shared by every screen. The concrete index is kept in
/// `focus_index`, while this enum gives the UI a stable vocabulary for focus
/// styling, help, and future screen-specific focus maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusTarget {
    Panel,
    List,
    Table,
    Button,
    Field,
    Dialog,
}

/// User-facing commands. The command palette, contextual help, keyboard
/// aliases, and visible buttons all resolve to this same registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Back,
    Next,
    Start,
    Quit,
    Export,
    PauseResume,
    SpeedTest,
    CopyIp,
    OpenDetails,
    CloseDetails,
    OpenHelp,
    OpenCommandPalette,
    Confirm,
    Cancel,
    SelectAll,
    ClearSelection,
    Download,
    Upload,
    Both,
    ConfigureColumns,
    ToggleFailures,
    RepeatTargets,
    NewSample,
    ExportComparison,
    CustomizeScan,
}

impl Action {
    pub const ALL: [Action; 25] = [
        Action::Back,
        Action::Next,
        Action::Start,
        Action::Quit,
        Action::Export,
        Action::PauseResume,
        Action::SpeedTest,
        Action::CopyIp,
        Action::OpenDetails,
        Action::CloseDetails,
        Action::OpenHelp,
        Action::OpenCommandPalette,
        Action::Confirm,
        Action::Cancel,
        Action::SelectAll,
        Action::ClearSelection,
        Action::Download,
        Action::Upload,
        Action::Both,
        Action::ConfigureColumns,
        Action::ToggleFailures,
        Action::RepeatTargets,
        Action::NewSample,
        Action::ExportComparison,
        Action::CustomizeScan,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Back => "Back",
            Action::Next => "Next",
            Action::Start => "Start scan",
            Action::Quit => "Quit",
            Action::Export => "Export results",
            Action::PauseResume => "Pause / resume",
            Action::SpeedTest => "Run speed test",
            Action::CopyIp => "Copy selected IP",
            Action::OpenDetails => "Open selected details",
            Action::CloseDetails => "Close details",
            Action::OpenHelp => "Open help",
            Action::OpenCommandPalette => "Open command palette",
            Action::Confirm => "Confirm",
            Action::Cancel => "Cancel",
            Action::SelectAll => "Select all",
            Action::ClearSelection => "Clear selection",
            Action::Download => "Download only",
            Action::Upload => "Upload only",
            Action::Both => "Download + upload",
            Action::ConfigureColumns => "Configure result columns",
            Action::ToggleFailures => "Show failures",
            Action::RepeatTargets => "Repeat current targets",
            Action::NewSample => "Generate new sample",
            Action::ExportComparison => "Export comparison",
            Action::CustomizeScan => "Customize scan",
        }
    }

    pub fn shortcut(self) -> &'static str {
        match self {
            Action::Quit => "q",
            Action::Export => "e",
            Action::PauseResume => "p",
            Action::SpeedTest => "t",
            Action::CopyIp => "c",
            Action::OpenHelp => "?",
            Action::OpenCommandPalette => "/",
            Action::Confirm => "Enter",
            Action::Cancel => "Esc",
            Action::ConfigureColumns => "v",
            Action::ToggleFailures => "f",
            Action::RepeatTargets => "r",
            Action::NewSample => "n",
            Action::ExportComparison => "m",
            Action::CustomizeScan => "w",
            _ => "",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Action::OpenDetails => "Show complete latency statistics for the selected result",
            Action::Export => "Write the ranked results to a TSV file",
            Action::SpeedTest => "Choose successful IPs for bandwidth testing",
            Action::PauseResume => "Pause or resume the active scan",
            Action::CopyIp => "Copy the selected IP address to the clipboard",
            Action::ConfigureColumns => "Show or hide columns in the results table",
            Action::ToggleFailures => "Toggle between successful targets and all targets",
            Action::RepeatTargets => "Run the identical sampled target set again",
            Action::NewSample => "Generate a new target sample with the same settings",
            Action::ExportComparison => "Export the current run for comparison",
            Action::CustomizeScan => "Return to scan parameters without discarding results",
            _ => self.label(),
        }
    }
}

/// Identifies an action button drawn on screen, used for mouse hit-testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonAction {
    Back,
    Next,
    Start,
    Quit,
    Save,
    PauseResume,
    SpeedTest,
    ConfirmQuit,
    CancelQuit,
    SpeedAll,
    SpeedClear,
    SpeedDirDownload,
    SpeedDirUpload,
    SpeedDirBoth,
    SpeedStart,
    SpeedBack,
    CustomizeScan,
}

/// A selectable CIDR candidate in the wizard's ranges step.
pub struct CidrEntry {
    pub cidr: String,
    pub selected: bool,
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
    pub table_inner: Option<Rect>,
    pub table_header: Option<Rect>,
    pub table_col_bounds: Vec<(u16, u16)>,
    pub table_col_indices: Vec<usize>,
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

#[derive(Clone)]
struct SortedCache {
    key: (u64, usize, bool, bool, Option<String>, Option<String>),
    indices: Vec<usize>,
}

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
                    3
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
                )
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
            table_inner: None,
            table_header: None,
            table_col_bounds: Vec::new(),
            table_col_indices: Vec::new(),
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
        self.scan_complete = false;
        self.scan_lifecycle = ScanLifecycle::Running;
        self.scan_error = None;
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

    pub fn set_cancel_token(&mut self, cancel: Arc<AtomicBool>) {
        self.cancel = Some(cancel);
    }

    fn request_cancel(&mut self) {
        if matches!(
            self.scan_lifecycle,
            ScanLifecycle::Running | ScanLifecycle::Paused
        ) {
            if let Some(cancel) = &self.cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            self.scan_lifecycle = ScanLifecycle::Cancelling;
            self.toast_info("Cancelling… waiting for active work to stop");
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
        self.results.push(result);
        self.results_revision = self.results_revision.wrapping_add(1);
        self.sorted_cache.borrow_mut().take();
    }

    pub fn apply_scan_progress(&mut self, progress: ScanProgress) {
        if let Some(ip) = &progress.latest_target {
            self.scan_started_ips.insert(ip.clone());
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

fn build_current_manifest(app: &App) -> crate::Manifest {
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
                        app.should_quit = true;
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

            if app.watch_due.is_some_and(|due| Instant::now() >= due) {
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

            if app.pending_start {
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
    if let Some(s) = scanner {
        let _ = s.join();
    }
    if let Some(s) = speed_runner {
        let _ = s.join();
    }
    result
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
                if self.scan_complete {
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
                if self.screen == Screen::Scanning && !self.scan_complete {
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
                self.activate_action(Action::PauseResume);
                return;
            }
            KeyCode::Enter if self.screen == Screen::Scanning => {
                match self.focus_index {
                    0 => self.show_result_details = true,
                    1 if self.scan_complete => self.activate_action(Action::Export),
                    1 => self.activate_action(Action::PauseResume),
                    2 if self.scan_complete => self.activate_action(Action::SpeedTest),
                    2 => self.activate_action(Action::Quit),
                    3 if self.scan_complete => self.activate_action(Action::CustomizeScan),
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
                if self.screen == Screen::Scanning && self.scan_complete {
                    self.enter_customization();
                }
            }
        }
    }

    /// Draw the current screen. Resets mouse hit regions first, then delegates
    /// to the active screen renderer (and the help overlay if open).
    pub fn render(&mut self, frame: &mut Frame) {
        self.buttons.clear();
        self.ranges_inner = None;
        self.settings_inner = None;
        self.settings_row_map.clear();
        self.table_inner = None;
        self.table_header = None;
        self.table_col_bounds.clear();
        self.table_col_indices.clear();
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
                "A scan is still running.",
                theme::title_style(),
            )),
            Line::from(Span::styled(
                "Quitting now will discard in-progress results.",
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
            KeyCode::Char('f') => self.activate_action(Action::ToggleFailures),
            KeyCode::Char('v') => self.activate_action(Action::ConfigureColumns),
            KeyCode::Char('w') if self.scan_complete => self.activate_action(Action::CustomizeScan),
            KeyCode::Char('p') => self.activate_action(Action::PauseResume),
            KeyCode::Char('e') => self.activate_action(Action::Export),
            KeyCode::Char('t') if self.scan_complete => self.activate_action(Action::SpeedTest),
            KeyCode::Char('c') => self.activate_action(Action::CopyIp),
            KeyCode::Up => {
                self.result_cursor = self.result_cursor.saturating_sub(1);
                self.scroll = self.scroll.min(self.result_cursor);
            }
            KeyCode::Down => {
                let max = self
                    .sorted_results()
                    .len()
                    .min(self.config.top)
                    .saturating_sub(1);
                self.result_cursor = (self.result_cursor + 1).min(max);
                self.scroll = self.scroll.max(self.result_cursor);
            }
            KeyCode::PageUp => {
                self.result_cursor = self.result_cursor.saturating_sub(10);
                self.scroll = self.scroll.min(self.result_cursor);
            }
            KeyCode::PageDown => {
                let max = self
                    .sorted_results()
                    .len()
                    .min(self.config.top)
                    .saturating_sub(1);
                self.result_cursor = (self.result_cursor + 10).min(max);
                self.scroll = self.scroll.max(self.result_cursor);
            }
            KeyCode::Home => {
                self.result_cursor = 0;
                self.scroll = 0;
            }
            KeyCode::End => {
                let max = self
                    .sorted_results()
                    .len()
                    .min(self.config.top)
                    .saturating_sub(1);
                self.result_cursor = max;
                self.scroll = max;
            }
            _ => {}
        }
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
        self.toast_info(format!("Manual workers: {next} (0 = automatic)"));
    }

    fn clear_runtime_worker_override(&mut self) {
        self.config
            .runtime_worker_override
            .store(0, Ordering::Relaxed);
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
        self.confirm_scan_action = Some(PendingScanAction::RepeatTargets);
    }

    fn repeat_targets_now(&mut self) {
        if self.last_targets.is_empty() {
            self.toast_warn("No previous target manifest available");
        } else {
            self.rescan_targets = Some(self.last_targets.clone());
            self.pending_start = true;
            self.toast_info("Re-running the identical target set");
        }
    }

    fn generate_new_sample(&mut self) {
        self.confirm_scan_action = Some(PendingScanAction::NewSample);
    }

    fn generate_new_sample_now(&mut self) {
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
                    if self.result_cursor > 0 {
                        self.result_cursor -= 1;
                        self.scroll = self.scroll.min(self.result_cursor);
                    }
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
                    let max = self
                        .sorted_results()
                        .len()
                        .min(self.config.top)
                        .saturating_sub(1);
                    self.result_cursor = (self.result_cursor + 1).min(max);
                    self.scroll = self.scroll.max(self.result_cursor);
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
                            let max = self
                                .sorted_results()
                                .len()
                                .min(self.config.top)
                                .saturating_sub(1);
                            self.result_cursor = row.min(max);
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
                    self.pending_start = true;
                }
            }
            ButtonAction::Quit => {
                if self.screen == Screen::Scanning && !self.scan_complete {
                    self.confirm_quit = true;
                } else if self.screen == Screen::Wizard && self.return_to_results {
                    self.return_to_results();
                } else {
                    self.should_quit = true;
                }
            }
            ButtonAction::Save => self.save(),
            ButtonAction::PauseResume => {
                let next = !self.paused.load(Ordering::Relaxed);
                self.paused.store(next, Ordering::Relaxed);
                self.scan_lifecycle = if next {
                    ScanLifecycle::Paused
                } else {
                    ScanLifecycle::Running
                };
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
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
        ratatui::restore();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_current_manifest, export_tsv_line, ranked_export_results, Action, App, FocusTarget,
        ProbeResult, ScanLifecycle, Screen, WizardStep,
    };
    use crate::config::AppConfig;
    use crate::scanner::{
        DiagnosticCategory, DiagnosticPhase, ProbeDiagnostic, ProbeFailureCounts, ScanPhase,
        ScanProgress,
    };
    use crate::watch::{WatchPolicy, WatchState};
    use crossterm::event::{KeyCode, KeyModifiers};
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
    fn scanning_focus_map_keeps_quit_reachable() {
        let mut app = App::new(
            AppConfig::default(),
            false,
            Arc::new(AtomicBool::new(false)),
        );
        app.begin_scan(1);
        assert_eq!(app.focus_count(), 3);
        app.focus_index = 2;
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
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
        });
        assert_eq!(app.scan_progress.targets_total, Some(500));

        app.begin_scan(3);
        assert!(app.scan_started_ips.is_empty());
        assert_eq!(app.scan_progress.phase, ScanPhase::Starting);
        assert_eq!(app.scan_progress.probes_started, 0);
        assert_eq!(app.scan_progress.targets_completed, 0);
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
}
