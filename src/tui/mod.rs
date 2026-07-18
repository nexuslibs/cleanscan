mod clipboard;
pub mod dashboard;
pub mod help;
pub mod speed;
pub mod theme;
pub mod widgets;
pub mod wizard;

pub use widgets::{ButtonKind, ToastKind};

use std::{
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
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::config::AppConfig;
use crate::scanner::ProbeResult;
use crate::speed::{SpeedDirection, SpeedResult};
use crate::tui::wizard::SettingField;

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
}

impl Action {
    pub const ALL: [Action; 19] = [
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
    pub screen: Screen,
    pub wizard_step: WizardStep,
    pub cidr_candidates: Vec<CidrEntry>,
    pub cursor: usize,
    /// When true, the user is typing a custom CIDR in the ranges step.
    pub custom_input_mode: bool,
    pub input_buffer: String,
    /// Index of the settings field currently being edited, if any.
    pub edit_field: Option<usize>,
    pub edit_buffer: String,
    pub edit_caret: usize,
    pub results: Vec<ProbeResult>,
    pub total_targets: usize,
    pub scan_complete: bool,
    pub should_quit: bool,
    pub paused: Arc<AtomicBool>,
    pub message: Option<String>,
    pub message_kind: ToastKind,
    pub message_time: Option<Instant>,
    /// Scroll offset into the results table.
    pub scroll: usize,
    pub result_cursor: usize,
    /// Scroll offset into the wizard CIDR list.
    pub ranges_scroll: usize,
    /// Scroll offset into the wizard settings list.
    pub settings_scroll: usize,
    /// Currently sorted column index in the results table (natural order = 0).
    pub sort_col: usize,
    pub sort_asc: bool,
    pub start_time: Instant,
    /// Help overlay visibility.
    pub show_help: bool,
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
    // --- mouse hit-testing regions (recomputed every render) ---
    pub buttons: Vec<(Rect, ButtonAction)>,
    pub ranges_inner: Option<Rect>,
    pub settings_inner: Option<Rect>,
    /// Maps each rendered settings row to a field index (`None` for headers).
    pub settings_row_map: Vec<Option<usize>>,
    pub table_inner: Option<Rect>,
    pub table_header: Option<Rect>,
    pub table_col_bounds: Vec<(u16, u16)>,
    /// Speed-select list inner rect + first visible index, for mouse hit-testing.
    pub speed_list_inner: Option<Rect>,
    pub speed_list_start: usize,
    /// Set when a quit was requested while a scan is running; a second 'q'
    /// confirms the exit. Any other key clears it.
    pub confirm_quit: bool,
    /// Set when the wizard's Start action fires; the run loop performs the spawn.
    pub pending_start: bool,
    pub speed_targets: Vec<String>,
    pub speed_selected: std::collections::HashSet<String>,
    pub speed_cursor: usize,
    pub speed_direction: SpeedDirection,
    pub speed_results: Vec<SpeedResult>,
    pub speed_result_cursor: usize,
    pub speed_complete: bool,
    pub speed_start_time: Instant,
    pub pending_speed_start: bool,
    pub confirm_speed_start: bool,
    /// Active semantic focus target and its position in the current screen's
    /// focus map. Focus is intentionally independent from list cursors.
    pub focus_target: FocusTarget,
    pub focus_index: usize,
    /// Searchable command palette state.
    pub show_command_palette: bool,
    pub command_query: String,
    pub command_cursor: usize,
    /// Full statistics drawer for the currently selected latency result.
    pub show_result_details: bool,
}

impl App {
    /// Number of focusable regions on the current screen. Keeping this map
    /// small and predictable makes Tab useful even when a screen is compact.
    pub fn focus_count(&self) -> usize {
        match self.screen {
            Screen::Wizard => match self.wizard_step {
                WizardStep::Ranges => 3,
                WizardStep::Settings => 3,
                WizardStep::Review => 2,
            },
            Screen::Scanning => {
                if self.scan_complete {
                    5
                } else {
                    3
                }
            }
            Screen::SpeedSelect => 5,
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
                (self.screen != Screen::SpeedTesting || *action != Action::SpeedTest)
                    && (query.is_empty()
                        || action.label().to_ascii_lowercase().contains(&query)
                        || action.description().to_ascii_lowercase().contains(&query))
            })
            .collect()
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
            screen: if has_cli_targets {
                Screen::Scanning
            } else {
                Screen::Wizard
            },
            wizard_step: WizardStep::Ranges,
            cidr_candidates,
            cursor: 0,
            custom_input_mode: false,
            input_buffer: String::new(),
            edit_field: None,
            edit_buffer: String::new(),
            edit_caret: 0,
            results: Vec::new(),
            total_targets: 0,
            scan_complete: false,
            should_quit: false,
            paused,
            message: None,
            message_kind: ToastKind::Info,
            message_time: None,
            scroll: 0,
            result_cursor: 0,
            ranges_scroll: 0,
            settings_scroll: 0,
            sort_col: 0,
            sort_asc: true,
            start_time: Instant::now(),
            show_help: false,
            tick: 0,
            hover_pos: None,
            throughput: Vec::new(),
            last_tp_instant: Instant::now(),
            last_tp_count: 0,
            buttons: Vec::new(),
            ranges_inner: None,
            settings_inner: None,
            settings_row_map: Vec::new(),
            table_inner: None,
            table_header: None,
            table_col_bounds: Vec::new(),
            speed_list_inner: None,
            speed_list_start: 0,
            confirm_quit: false,
            pending_start: false,
            speed_targets: Vec::new(),
            speed_selected: std::collections::HashSet::new(),
            speed_cursor: 0,
            speed_direction: SpeedDirection::Both,
            speed_results: Vec::new(),
            speed_result_cursor: 0,
            speed_complete: false,
            speed_start_time: Instant::now(),
            pending_speed_start: false,
            confirm_speed_start: false,
            focus_target: FocusTarget::List,
            focus_index: 0,
            show_command_palette: false,
            command_query: String::new(),
            command_cursor: 0,
            show_result_details: false,
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
        self.focus_index = 0;
        self.focus_target = FocusTarget::Table;
        self.show_result_details = false;
        self.total_targets = total;
        self.scan_complete = false;
        self.results.clear();
        self.scroll = 0;
        self.result_cursor = 0;
        self.sort_col = 0;
        self.sort_asc = true;
        self.message = None;
        self.message_time = None;
        self.start_time = Instant::now();
        self.throughput.clear();
        self.last_tp_instant = Instant::now();
        self.last_tp_count = 0;
    }

    pub fn add_result(&mut self, result: ProbeResult) {
        self.results.push(result);
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

    pub fn toast_warn(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Warn);
    }

    pub fn toast_error(&mut self, msg: impl Into<String>) {
        self.toast_kind(msg, ToastKind::Error);
    }

    /// Whether the current toast should still be visible (auto-fade after 4s).
    pub fn visible_message(&self) -> Option<(&str, ToastKind)> {
        match (self.message.as_deref(), self.message_time) {
            (Some(m), Some(t)) if t.elapsed() < Duration::from_secs(4) => {
                Some((m, self.message_kind))
            }
            (Some(m), None) => Some((m, self.message_kind)),
            _ => None,
        }
    }

    /// Clear stale toast.
    pub fn tick_message(&mut self) {
        if let (Some(_), Some(t)) = (self.message.as_deref(), self.message_time) {
            if t.elapsed() >= Duration::from_secs(4) {
                self.message = None;
                self.message_time = None;
            }
        }
    }

    /// Natural ranking used as the default results order.
    pub fn natural_cmp(a: &ProbeResult, b: &ProbeResult) -> std::cmp::Ordering {
        a.fail
            .cmp(&b.fail)
            .then_with(|| {
                a.p95
                    .partial_cmp(&b.p95)
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
        let mut v: Vec<&ProbeResult> = self.results.iter().filter(|r| r.ok > 0).collect();
        if self.sort_col == 0 {
            v.sort_by(|a, b| {
                let ord = Self::natural_cmp(a, b);
                if self.sort_asc {
                    ord
                } else {
                    ord.reverse()
                }
            });
            return v;
        }
        let cmp = |a: &&ProbeResult, b: &&ProbeResult| -> std::cmp::Ordering {
            let (a, b) = (*a, *b);
            let ord = match self.sort_col {
                1 => a.ip.cmp(&b.ip),
                2 => a.ok.cmp(&b.ok),
                3 => a.fail.cmp(&b.fail),
                4 => a
                    .avg
                    .partial_cmp(&b.avg)
                    .unwrap_or(std::cmp::Ordering::Equal),
                5 => a
                    .p50
                    .partial_cmp(&b.p50)
                    .unwrap_or(std::cmp::Ordering::Equal),
                6 => a
                    .p90
                    .partial_cmp(&b.p90)
                    .unwrap_or(std::cmp::Ordering::Equal),
                7 => a
                    .p95
                    .partial_cmp(&b.p95)
                    .unwrap_or(std::cmp::Ordering::Equal),
                8 => a
                    .max
                    .partial_cmp(&b.max)
                    .unwrap_or(std::cmp::Ordering::Equal),
                _ => std::cmp::Ordering::Equal,
            };
            if self.sort_asc {
                ord
            } else {
                ord.reverse()
            }
        };
        v.sort_by(cmp);
        v
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
        writeln!(f, "rank\tip\tok\tfail\tavg\tp50\tp90\tp95\tmax")?;
        for (i, r) in ranked_export_results(&self.results, self.config.top)
            .into_iter()
            .enumerate()
        {
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}",
                i + 1,
                r.ip,
                r.ok,
                r.fail,
                r.avg,
                r.p50,
                r.p90,
                r.p95,
                r.max
            )?;
        }
        Ok(filename)
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

/// Center a rectangle of the given percentage size within `area`.
pub fn centered(area: Rect, percent_w: u16, percent_h: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_h) / 2),
            Constraint::Percentage(percent_h),
            Constraint::Percentage((100 - percent_h) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_w) / 2),
            Constraint::Percentage(percent_w),
            Constraint::Percentage((100 - percent_w) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}

/// Run the full TUI loop.
pub fn run_tui(
    config: AppConfig,
    cli_cidr: Vec<String>,
    cli_ips: Option<String>,
) -> anyhow::Result<()> {
    let has_cli_targets = cli_ips.is_some() || !cli_cidr.is_empty();

    let config_arc = Arc::new(config);
    let (tx, rx) = std::sync::mpsc::channel::<ProbeResult>();
    let (speed_tx, speed_rx) = std::sync::mpsc::channel::<SpeedResult>();
    let paused = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));

    let mut terminal = ratatui::init();
    // Enable mouse interaction for the whole session.
    let _ = crossterm::execute!(io::stdout(), EnableMouseCapture);
    let _guard = RestoreGuard;
    let mut app = App::new((*config_arc).clone(), has_cli_targets, paused.clone());

    let spawn_scanner = |targets: Vec<String>,
                         scan_config: Arc<AppConfig>|
     -> std::thread::JoinHandle<Result<(), String>> {
        let scanner_config = scan_config;
        let scanner_paused = paused.clone();
        let scanner_cancel = cancel.clone();
        let scanner_tx = tx.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return Err(format!("failed to create tokio runtime: {e}"));
                }
            };
            rt.block_on(crate::scanner::run_scan(
                targets,
                scanner_config,
                scanner_tx,
                scanner_cancel,
                scanner_paused,
            ));
            Ok(())
        })
    };

    let spawn_speed = |targets: Vec<String>,
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

    let mut scanner: Option<std::thread::JoinHandle<Result<(), String>>> = None;
    let mut speed_runner: Option<std::thread::JoinHandle<Result<(), String>>> = None;

    // CLI-provided targets start scanning immediately (legacy behavior).
    if has_cli_targets {
        if app.config.host.is_empty() {
            app.toast_warn("Set a Host before starting the scan");
        } else {
            let targets = crate::scanner::collect_targets(&config_arc, &cli_cidr, &cli_ips)?;
            let total = targets.len();
            scanner = Some(spawn_scanner(targets, config_arc.clone()));
            app.begin_scan(total);
        }
    }

    // Launch a scan from the wizard's (possibly edited) configuration.
    let start_wizard_scan =
        |app: &mut App,
         scanner: &mut Option<std::thread::JoinHandle<Result<(), String>>>,
         spawn_scanner: &dyn Fn(
            Vec<String>,
            Arc<AppConfig>,
        ) -> std::thread::JoinHandle<Result<(), String>>| {
            let cidrs: Vec<String> = app
                .cidr_candidates
                .iter()
                .filter(|e| e.selected)
                .map(|e| e.cidr.clone())
                .collect();
            if cidrs.is_empty() {
                app.toast_warn("Select at least one CIDR (space) before starting");
                return;
            }
            if app.config.host.is_empty() {
                app.toast_warn("Set a Host before starting the scan");
                return;
            }
            match crate::scanner::collect_from_cidrs(&cidrs, app.config.sample_per_cidr) {
                Ok(targets) => {
                    let total = targets.len();
                    let scan_config = Arc::new(AppConfig {
                        host: app.config.host.clone(),
                        path: app.config.path.clone(),
                        custom_cidrs: app.config.custom_cidrs.clone(),
                        selected_cidrs: app.config.selected_cidrs.clone(),
                        selected_cidrs_persisted: app.config.selected_cidrs_persisted,
                        sample_per_cidr: app.config.sample_per_cidr,
                        probes: app.config.probes,
                        concurrency: app.config.concurrency,
                        timeout_ms: app.config.timeout_ms,
                        connect_timeout_ms: app.config.connect_timeout_ms,
                        top: app.config.top,
                        download_path: app.config.download_path.clone(),
                        upload_path: app.config.upload_path.clone(),
                        speed_payload_bytes: app.config.speed_payload_bytes,
                        speed_repetitions: app.config.speed_repetitions,
                        speed_timeout_ms: app.config.speed_timeout_ms,
                    });
                    *scanner = Some(spawn_scanner(targets, scan_config));
                    app.begin_scan(total);
                }
                Err(e) => app.toast_error(format!("Error: {e}")),
            }
        };

    let mut run = || -> anyhow::Result<()> {
        loop {
            while let Ok(r) = rx.try_recv() {
                app.add_result(r);
            }
            while let Ok(r) = speed_rx.try_recv() {
                app.speed_results.push(r);
            }

            if !app.scan_complete && scanner.as_ref().is_some_and(|s| s.is_finished()) {
                while let Ok(r) = rx.try_recv() {
                    app.add_result(r);
                }
                if let Some(handle) = scanner.take() {
                    match handle.join() {
                        Ok(Ok(())) => app.scan_complete = true,
                        Ok(Err(e)) => {
                            app.scan_complete = true;
                            app.toast_error(format!("Scan failed: {e}"));
                        }
                        Err(_) => {
                            app.scan_complete = true;
                            app.toast_error("Scan worker panicked");
                        }
                    }
                }
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
                            app.speed_result_cursor = 0;
                            app.scroll = 0;
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                        }
                        Ok(Err(e)) => {
                            app.speed_complete = true;
                            app.toast_error(format!("Speed test failed: {e}"));
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                        }
                        Err(_) => {
                            app.speed_complete = true;
                            app.toast_error("Speed test worker panicked");
                            app.focus_index = 0;
                            app.focus_target = FocusTarget::Table;
                            app.screen = Screen::SpeedResults;
                        }
                    }
                }
            }

            app.tick_message();
            app.tick = app.tick.wrapping_add(1);

            // Sample probe throughput roughly once per second for the sparkline.
            if app.screen == Screen::Scanning
                && !app.scan_complete
                && app.last_tp_instant.elapsed() >= Duration::from_millis(1000)
            {
                let now_count = app.results.len();
                let delta = now_count.saturating_sub(app.last_tp_count) as u64;
                app.throughput.push(delta);
                if app.throughput.len() > 240 {
                    app.throughput.remove(0);
                }
                app.last_tp_count = now_count;
                app.last_tp_instant = Instant::now();
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
                let targets: Vec<String> = app
                    .speed_targets
                    .iter()
                    .filter(|ip| app.speed_selected.contains(*ip))
                    .cloned()
                    .collect();
                app.speed_results.clear();
                app.speed_complete = false;
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
        if self.screen == Screen::Wizard && (self.edit_field.is_some() || self.custom_input_mode) {
            wizard::handle_wizard_key(self, code);
            return;
        }

        // The quit-confirm modal captures all input until dismissed.
        if self.confirm_quit {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => self.should_quit = true,
                _ => self.confirm_quit = false,
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
                    if let Some(action) = self.selected_action() {
                        self.close_command_palette();
                        self.activate_action(action);
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

        // The help overlay consumes every key, including its toggle and quit
        // keys, so dismissing it cannot mutate the underlying application.
        if self.show_help {
            self.show_help = false;
            return;
        }

        // Global keys work on every screen.
        match code {
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                return;
            }
            KeyCode::Char('/') => {
                self.open_command_palette();
                return;
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if self.screen == Screen::Scanning && !self.scan_complete {
                    self.confirm_quit = true;
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
                if self.focus_target == FocusTarget::Table {
                    self.show_result_details = true;
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
            Action::Start => self.activate_button(if self.screen == Screen::SpeedSelect {
                ButtonAction::SpeedStart
            } else {
                ButtonAction::Start
            }),
            Action::Quit => self.activate_button(ButtonAction::Quit),
            Action::Export => self.save(),
            Action::PauseResume => self.activate_button(ButtonAction::PauseResume),
            Action::SpeedTest => self.activate_button(ButtonAction::SpeedTest),
            Action::CopyIp => self.copy_selected_ip(),
            Action::OpenDetails => self.show_result_details = true,
            Action::CloseDetails => self.show_result_details = false,
            Action::OpenHelp => self.show_help = true,
            Action::OpenCommandPalette => self.open_command_palette(),
            Action::Confirm => {
                if self.confirm_quit {
                    self.should_quit = true;
                }
            }
            Action::Cancel => {
                self.confirm_quit = false;
                self.show_result_details = false;
            }
            Action::SelectAll => self.activate_button(ButtonAction::SpeedAll),
            Action::ClearSelection => self.activate_button(ButtonAction::SpeedClear),
            Action::Download => self.activate_button(ButtonAction::SpeedDirDownload),
            Action::Upload => self.activate_button(ButtonAction::SpeedDirUpload),
            Action::Both => self.activate_button(ButtonAction::SpeedDirBoth),
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
        self.speed_list_inner = None;

        match self.screen {
            Screen::Wizard => wizard::render(self, frame, frame.area()),
            Screen::Scanning => dashboard::render(self, frame, frame.area()),
            Screen::SpeedSelect | Screen::SpeedTesting | Screen::SpeedResults => {
                speed::render(self, frame, frame.area())
            }
        }

        if self.show_help {
            help::overlay(self, frame, frame.area());
        }

        if self.confirm_quit {
            self.render_quit_confirm(frame, frame.area());
        }

        if self.confirm_speed_start {
            self.render_speed_confirm(frame, frame.area());
        }

        if self.show_command_palette {
            self.render_command_palette(frame, frame.area());
        }
    }

    fn render_command_palette(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered(area, 72, 70);
        let inner = widgets::modal(frame, area, popup, " Command palette ");
        let actions = self.filtered_actions();
        let visible = inner.height.saturating_sub(3) as usize;
        self.command_cursor = self.command_cursor.min(actions.len().saturating_sub(1));
        let start = self
            .command_cursor
            .saturating_sub(visible.saturating_sub(1));
        let list = actions
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, action)| {
                let style = if i == self.command_cursor {
                    theme::row_selected_style()
                } else {
                    ratatui::style::Style::default()
                };
                Line::from(vec![
                    Span::styled(format!(" {:<24}", action.label()), style),
                    Span::styled(
                        format!(" {:<6}", action.shortcut()),
                        theme::highlight_style(),
                    ),
                    Span::styled(action.description(), theme::hint_style()),
                ])
                .style(style)
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
        frame.render_widget(Paragraph::new(list), chunks[1]);
        frame.render_widget(
            Paragraph::new("↑/↓ navigate • Enter run • Esc close").style(theme::hint_style()),
            chunks[2],
        );
    }

    fn render_speed_confirm(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered(area, 58, 32);
        let inner = widgets::modal(frame, area, popup, " Start bandwidth test? ");
        let lines = vec![
            Line::from(Span::styled(
                format!("{} IPs selected", self.speed_selected.len()),
                theme::title_style(),
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
    fn render_quit_confirm(&mut self, frame: &mut Frame, area: Rect) {
        use ratatui::layout::Alignment;
        use ratatui::text::{Line, Span};
        use ratatui::widgets::Paragraph;

        let popup = centered(area, 46, 30);
        let inner = widgets::modal(frame, area, popup, " Quit cleanscan? ");

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

    fn open_speed_selection(&mut self) {
        self.speed_targets = self
            .results
            .iter()
            .filter(|result| result.ok > 0)
            .map(|result| result.ip.clone())
            .collect();
        self.speed_targets.sort();
        self.speed_selected.clear();
        self.speed_cursor = 0;
        self.speed_direction = SpeedDirection::Both;
        self.speed_results.clear();
        self.speed_complete = false;
        self.confirm_speed_start = false;
        self.focus_index = 0;
        self.focus_target = FocusTarget::List;
        self.screen = Screen::SpeedSelect;
    }

    fn handle_speed_select_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char(' ') => {
                if let Some(ip) = self.speed_targets.get(self.speed_cursor).cloned() {
                    if !self.speed_selected.insert(ip.clone()) {
                        self.speed_selected.remove(&ip);
                    }
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.speed_selected = self.speed_targets.iter().cloned().collect();
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
            KeyCode::Down if self.speed_cursor + 1 < self.speed_targets.len() => {
                self.speed_cursor += 1
            }
            KeyCode::PageUp => self.speed_cursor = self.speed_cursor.saturating_sub(10),
            KeyCode::PageDown => {
                self.speed_cursor =
                    (self.speed_cursor + 10).min(self.speed_targets.len().saturating_sub(1))
            }
            KeyCode::Enter => {
                if self.speed_selected.is_empty() {
                    self.toast_warn("Select at least one successful IP");
                } else {
                    self.confirm_speed_start = true;
                }
            }
            KeyCode::Esc => self.screen = Screen::Scanning,
            _ => {}
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
        // Track the pointer so buttons can render a hover state.
        self.hover_pos = Some((m.column, m.row));

        // While the quit-confirm modal is up, only its buttons are live.
        if self.confirm_quit {
            if let MouseEventKind::Down(MouseButton::Left) = m.kind {
                let p = (m.column, m.row);
                for (rect, action) in self.buttons.clone() {
                    if point_in(rect, p) {
                        self.activate_button(action);
                        break;
                    }
                }
            }
            return;
        }

        // Other overlays consume all mouse input so clicks cannot activate
        // controls rendered underneath them.
        if self.confirm_speed_start || self.show_command_palette || self.show_result_details {
            return;
        }

        if self.show_help || self.edit_field.is_some() || self.custom_input_mode {
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
                    let last = self.speed_targets.len().saturating_sub(1);
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
                for (rect, action) in &self.buttons {
                    if point_in(*rect, p) {
                        self.activate_button(*action);
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
                                        self.save_config();
                                    }
                                }
                            }
                        }
                    } else if self.wizard_step == WizardStep::Settings {
                        if let Some(inner) = self.settings_inner {
                            if point_in(inner, p) && self.edit_field.is_none() {
                                let row = (m.row - inner.y) as usize;
                                if let Some(Some(idx)) = self.settings_row_map.get(row).copied() {
                                    self.cursor = idx;
                                    self.start_edit(idx);
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
                                    self.sort_col = col;
                                    self.sort_asc = true;
                                }
                            }
                        }
                    }
                } else if self.screen == Screen::SpeedSelect {
                    if let Some(inner) = self.speed_list_inner {
                        if point_in(inner, p) {
                            let idx = self.speed_list_start + (m.row - inner.y) as usize;
                            if let Some(ip) = self.speed_targets.get(idx).cloned() {
                                self.speed_cursor = idx;
                                if !self.speed_selected.insert(ip.clone()) {
                                    self.speed_selected.remove(&ip);
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
                if self.wizard_step == WizardStep::Review {
                    // Re-run start via the spawn closure is not accessible here;
                    // instead set a flag handled by the run loop.
                    self.pending_start = true;
                }
            }
            ButtonAction::Quit => {
                if self.screen == Screen::Scanning && !self.scan_complete {
                    self.confirm_quit = true;
                } else {
                    self.should_quit = true;
                }
            }
            ButtonAction::Save => self.save(),
            ButtonAction::PauseResume => {
                let next = !self.paused.load(Ordering::Relaxed);
                self.paused.store(next, Ordering::Relaxed);
            }
            ButtonAction::SpeedTest => self.open_speed_selection(),
            ButtonAction::ConfirmQuit => self.should_quit = true,
            ButtonAction::CancelQuit => self.confirm_quit = false,
            ButtonAction::SpeedAll => {
                self.speed_selected = self.speed_targets.iter().cloned().collect();
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
    use super::{ranked_export_results, Action, App, FocusTarget, ProbeResult, Screen};
    use crate::config::AppConfig;
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    fn result(ip: &str, fail: usize, p95: f64) -> ProbeResult {
        ProbeResult {
            ip: ip.to_string(),
            ok: 1,
            fail,
            avg: p95,
            p50: p95,
            p90: p95,
            p95,
            max: p95,
            samples: vec![p95],
        }
    }

    fn draw(app: &mut App, w: u16, h: u16) {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| app.render(f)).unwrap();
    }

    #[test]
    fn export_ranks_successes_and_applies_top_limit() {
        let results = vec![
            result("failed", 1, 0.001),
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
        failed.samples.clear();

        let results = [failed, result("ok", 1, 0.1)];
        let ranked = ranked_export_results(&results, 50);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].ip, "ok");
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
        // Completed state and overlays should also render cleanly.
        app.scan_complete = true;
        app.show_help = true;
        draw(&mut app, 120, 36);
        app.show_help = false;
        app.confirm_quit = true;
        draw(&mut app, 120, 36);
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
        draw(&mut app, 79, 23);
    }
}
