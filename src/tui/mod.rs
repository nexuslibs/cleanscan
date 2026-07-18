pub mod dashboard;
pub mod help;
pub mod theme;
pub mod wizard;

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
    style::{Color, Style},
    symbols::border::ROUNDED,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::config::AppConfig;
use crate::scanner::ProbeResult;
use crate::tui::wizard::SettingField;

/// Which top-level screen the TUI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Guided setup wizard (steps 1-3).
    Wizard,
    /// Live scanning dashboard.
    Scanning,
}

/// Step within the guided wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Ranges = 0,
    Settings = 1,
    Review = 2,
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
    pub message_time: Option<Instant>,
    /// Scroll offset into the results table.
    pub scroll: usize,
    /// Scroll offset into the wizard CIDR list.
    pub ranges_scroll: usize,
    /// Currently sorted column index in the results table (natural order = 0).
    pub sort_col: usize,
    pub sort_asc: bool,
    pub start_time: Instant,
    /// Help overlay visibility.
    pub show_help: bool,
    // --- mouse hit-testing regions (recomputed every render) ---
    pub buttons: Vec<(Rect, ButtonAction)>,
    pub ranges_inner: Option<Rect>,
    pub settings_inner: Option<Rect>,
    pub table_inner: Option<Rect>,
    pub table_header: Option<Rect>,
    pub table_col_bounds: Vec<(u16, u16)>,
    /// Set when a quit was requested while a scan is running; a second 'q'
    /// confirms the exit. Any other key clears it.
    pub confirm_quit: bool,
    /// Set when the wizard's Start action fires; the run loop performs the spawn.
    pub pending_start: bool,
}

impl App {
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
            message_time: None,
            scroll: 0,
            ranges_scroll: 0,
            sort_col: 0,
            sort_asc: true,
            start_time: Instant::now(),
            show_help: false,
            buttons: Vec::new(),
            ranges_inner: None,
            settings_inner: None,
            table_inner: None,
            table_header: None,
            table_col_bounds: Vec::new(),
            confirm_quit: false,
            pending_start: false,
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
            self.toast(format!("Config save failed: {e}"));
        }
    }

    /// Switch to the scanning dashboard once targets are known. Resets per-scan state.
    pub fn begin_scan(&mut self, total: usize) {
        self.screen = Screen::Scanning;
        self.total_targets = total;
        self.scan_complete = false;
        self.results.clear();
        self.scroll = 0;
        self.sort_col = 0;
        self.sort_asc = true;
        self.message = None;
        self.message_time = None;
        self.start_time = Instant::now();
    }

    pub fn add_result(&mut self, result: ProbeResult) {
        self.results.push(result);
    }

    /// Show a transient status/toast message.
    pub fn toast(&mut self, msg: impl Into<String>) {
        self.message = Some(msg.into());
        self.message_time = Some(Instant::now());
    }

    /// Whether the current toast should still be visible (auto-fade after 4s).
    pub fn visible_message(&self) -> Option<&str> {
        match (self.message.as_deref(), self.message_time) {
            (Some(m), Some(t)) if t.elapsed() < Duration::from_secs(4) => Some(m),
            (Some(m), None) => Some(m),
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
        let mut v: Vec<&ProbeResult> = self.results.iter().collect();
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
        let style = if focused {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(ratatui::style::Modifier::BOLD)
        } else {
            theme::header_style()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(ROUNDED)
            .style(style);
        let para = Paragraph::new(format!(" {label} ")).block(block);
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
            self.toast("Scan still running — wait for it to finish before saving");
            return;
        }
        match self.save_to_file() {
            Ok(name) => self.toast(format!("Results saved to {name}")),
            Err(e) => self.toast(format!("Save failed: {e}")),
        }
    }
}

fn ranked_export_results(results: &[ProbeResult], top: usize) -> Vec<&ProbeResult> {
    let mut ranked: Vec<&ProbeResult> = results.iter().filter(|r| r.fail == 0).collect();
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

    let mut scanner: Option<std::thread::JoinHandle<Result<(), String>>> = None;

    // CLI-provided targets start scanning immediately (legacy behavior).
    if has_cli_targets {
        let targets = crate::scanner::collect_targets(&config_arc, &cli_cidr, &cli_ips)?;
        let total = targets.len();
        scanner = Some(spawn_scanner(targets, config_arc.clone()));
        app.begin_scan(total);
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
                app.toast("Select at least one CIDR (space) before starting");
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
                    });
                    *scanner = Some(spawn_scanner(targets, scan_config));
                    app.begin_scan(total);
                }
                Err(e) => app.toast(format!("Error: {e}")),
            }
        };

    let mut run = || -> anyhow::Result<()> {
        loop {
            while let Ok(r) = rx.try_recv() {
                app.add_result(r);
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
                            app.toast(format!("Scan failed: {e}"));
                        }
                        Err(_) => {
                            app.scan_complete = true;
                            app.toast("Scan worker panicked");
                        }
                    }
                }
            }

            app.tick_message();

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
        }
        Ok(())
    };

    let result = run();

    cancel.store(true, Ordering::Relaxed);
    if let Some(s) = scanner {
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

        // Global keys work on every screen.
        match code {
            KeyCode::Char('?') => {
                self.confirm_quit = false;
                self.show_help = !self.show_help;
                return;
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if self.screen == Screen::Scanning && !self.scan_complete {
                    if self.confirm_quit {
                        self.should_quit = true;
                    } else {
                        self.confirm_quit = true;
                        self.toast("Scan running — press q again to quit");
                    }
                    return;
                }
                self.should_quit = true;
                return;
            }
            _ => {}
        }

        if self.show_help {
            // Any key closes the help overlay.
            self.show_help = false;
            self.confirm_quit = false;
            return;
        }

        // Any key other than 'q' clears a pending quit confirmation.
        if !matches!(code, KeyCode::Char('q') | KeyCode::Char('Q')) {
            self.confirm_quit = false;
        }

        match self.screen {
            Screen::Wizard => wizard::handle_wizard_key(self, code),
            Screen::Scanning => self.handle_scan_key(code),
        }
    }

    /// Draw the current screen. Resets mouse hit regions first, then delegates
    /// to the active screen renderer (and the help overlay if open).
    pub fn render(&mut self, frame: &mut Frame) {
        self.buttons.clear();
        self.ranges_inner = None;
        self.settings_inner = None;
        self.table_inner = None;
        self.table_header = None;
        self.table_col_bounds.clear();

        match self.screen {
            Screen::Wizard => wizard::render(self, frame, frame.area()),
            Screen::Scanning => dashboard::render(self, frame, frame.area()),
        }

        if self.show_help {
            help::overlay(self, frame, frame.area());
        }
    }

    fn handle_scan_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('p') | KeyCode::Char(' ') => {
                let next = !self.paused.load(Ordering::Relaxed);
                self.paused.store(next, Ordering::Relaxed);
                if next {
                    self.toast("Paused");
                } else {
                    self.toast("Resumed");
                }
            }
            KeyCode::Char('s') | KeyCode::Char('S') => self.save(),
            KeyCode::Up if self.scroll > 0 => {
                self.scroll -= 1;
            }
            KeyCode::Down => self.scroll += 1,
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::PageDown => self.scroll += 10,
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => self.scroll = usize::MAX,
            _ => {}
        }
    }

    fn handle_mouse(&mut self, m: crossterm::event::MouseEvent) {
        use crossterm::event::{MouseButton, MouseEventKind};
        if self.show_help || self.edit_field.is_some() || self.custom_input_mode {
            return;
        }
        match m.kind {
            MouseEventKind::ScrollUp => {
                if self.screen == Screen::Scanning {
                    if self.scroll > 0 {
                        self.scroll -= 1;
                    }
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
                    self.scroll += 1;
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
                                let idx = (m.row - inner.y) as usize;
                                if idx < SettingField::ALL.len() {
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
                }
            }
            _ => {}
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
            ButtonAction::Quit => self.should_quit = true,
            ButtonAction::Save => self.save(),
            ButtonAction::PauseResume => {
                let next = !self.paused.load(Ordering::Relaxed);
                self.paused.store(next, Ordering::Relaxed);
            }
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
    use super::{ranked_export_results, ProbeResult};

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
}
