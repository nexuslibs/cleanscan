use std::{
    fs,
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ipnet::IpNet;
use std::str::FromStr;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::{scanner::ProbeResult, Args};

/// Which screen the TUI is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// CIDR selection screen shown before a scan when no targets are given.
    Setup,
    /// Live scanning dashboard.
    Scanning,
}

/// A selectable CIDR candidate in the setup screen.
struct CidrEntry {
    cidr: String,
    selected: bool,
}

pub struct App {
    args: Arc<Args>,
    phase: Phase,
    cidr_candidates: Vec<CidrEntry>,
    cursor: usize,
    input_mode: bool,
    input_buffer: String,
    results: Vec<ProbeResult>,
    total_targets: usize,
    pub scan_complete: bool,
    pub should_quit: bool,
    paused: Arc<AtomicBool>,
    message: Option<String>,
    start_time: Instant,
}

impl App {
    pub fn new(args: Arc<Args>, has_cli_targets: bool, paused: Arc<AtomicBool>) -> Self {
        let cidr_candidates = crate::scanner::DEFAULT_CLOUDFLARE_CIDRS
            .iter()
            .map(|c| CidrEntry {
                cidr: c.to_string(),
                selected: true,
            })
            .collect();

        Self {
            args,
            phase: if has_cli_targets {
                Phase::Scanning
            } else {
                Phase::Setup
            },
            cidr_candidates,
            cursor: 0,
            input_mode: false,
            input_buffer: String::new(),
            results: Vec::new(),
            total_targets: 0,
            scan_complete: false,
            should_quit: false,
            paused,
            message: None,
            start_time: Instant::now(),
        }
    }

    /// Switch from the setup screen to the scanning dashboard once targets are
    /// known. Resets per-scan state.
    pub fn begin_scan(&mut self, total: usize) {
        self.phase = Phase::Scanning;
        self.total_targets = total;
        self.scan_complete = false;
        self.results.clear();
        self.message = None;
        self.start_time = Instant::now();
    }

    pub fn add_result(&mut self, result: ProbeResult) {
        self.results.push(result);
        self.results.sort_by(|a, b| {
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
        });
    }

    pub fn render(&self, frame: &mut Frame) {
        if self.phase == Phase::Setup {
            self.render_setup(frame, frame.area());
            return;
        }

        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(area);

        self.render_header(frame, chunks[0]);
        self.render_progress(frame, chunks[1]);
        self.render_table(frame, chunks[2]);
        self.render_footer(frame, chunks[3]);
    }

    fn render_setup(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        let title_line = Line::from(format!(
            " cleanscan v{} — Select CIDRs to scan ",
            env!("CARGO_PKG_VERSION")
        ));
        let block = Block::default().borders(Borders::ALL);
        let paragraph = Paragraph::new(title_line)
            .block(block)
            .style(Style::default().fg(Color::Cyan));
        frame.render_widget(paragraph, chunks[0]);

        let items: Vec<Line> = self
            .cidr_candidates
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let mark = if e.selected { "[x]" } else { "[ ]" };
                let cursor = if i == self.cursor { "> " } else { "  " };
                let style = if i == self.cursor {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Line::from(format!("{}{} {}", cursor, mark, e.cidr)).style(style)
            })
            .collect();

        let list = Paragraph::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" CIDRs (space toggle, a add, Enter start, q quit) "),
        );
        frame.render_widget(list, chunks[1]);

        let input_line = if self.input_mode {
            format!("> {}_", self.input_buffer)
        } else {
            "  press 'a' to add a custom CIDR".to_string()
        };
        let input = Paragraph::new(input_line).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Add CIDR "),
        );
        frame.render_widget(input, chunks[2]);

        let text = self.message.clone().unwrap_or_else(|| {
            " ↑/↓ move • space toggle • a add • Enter start scan • q quit ".to_string()
        });
        let footer = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(footer, chunks[3]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let elapsed = self.start_time.elapsed();
        let elapsed_str = format!(
            "{:02}:{:02}",
            elapsed.as_secs() / 60,
            elapsed.as_secs() % 60
        );

        let status = if self.scan_complete {
            "DONE"
        } else if self.paused.load(Ordering::Relaxed) {
            "PAUSED"
        } else {
            "SCANNING"
        };

        let title_line = Line::from(vec![
            format!(" cleanscan v{} ", env!("CARGO_PKG_VERSION")).into(),
            format!("| {} | ", status).into(),
            format!("{}/{} targets | ", self.results.len(), self.total_targets).into(),
            format!("{} elapsed", elapsed_str).into(),
        ]);

        let block = Block::default().borders(Borders::ALL);
        let paragraph = Paragraph::new(title_line)
            .block(block)
            .style(Style::default().fg(Color::Cyan));
        frame.render_widget(paragraph, area);
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect) {
        let pct = if self.total_targets > 0 {
            (self.results.len() as f64 / self.total_targets as f64 * 100.0) as u16
        } else {
            0
        };

        let gauge = Gauge::default()
            .percent(pct)
            .label(format!("{pct}%"))
            .gauge_style(Style::default().fg(Color::Green));
        frame.render_widget(gauge, area);
    }

    fn render_table(&self, frame: &mut Frame, area: Rect) {
        // Reserve 3 rows for header + top/bottom borders
        let max_rows = (area.height.max(4) - 3) as usize;
        let display_count = self.args.top.min(max_rows);
        let show_results: Vec<_> = self.results.iter().take(display_count).collect();

        let header = Row::new(vec!["#", "IP", "OK", "Fail", "Avg", "P50", "P95", "Max"])
            .style(Style::default().fg(Color::Yellow).bold());

        let rows: Vec<Row> = show_results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                Row::new(vec![
                    (i + 1).to_string(),
                    r.ip.clone(),
                    r.ok.to_string(),
                    r.fail.to_string(),
                    format!("{:.1}ms", r.avg * 1000.0),
                    format!("{:.1}ms", r.p50 * 1000.0),
                    format!("{:.1}ms", r.p95 * 1000.0),
                    format!("{:.1}ms", r.max * 1000.0),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(4),
            Constraint::Length(16),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(" Results "));
        frame.render_widget(table, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let text = if self.scan_complete {
            " [q] quit  [s] save results"
        } else {
            " [q] quit  [p] pause/resume"
        };
        let message = self.message.as_deref().unwrap_or(text);
        let paragraph = Paragraph::new(message).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(paragraph, area);
    }

    /// Handle a key press while on the setup screen.
    ///
    /// Returns `Some(cidrs)` when the user confirms a selection that should be
    /// scanned; the caller is responsible for building targets and starting the
    /// scan. Returns `None` otherwise.
    pub fn handle_setup_key(&mut self, key: KeyCode) -> Option<Vec<String>> {
        if self.input_mode {
            match key {
                KeyCode::Enter => {
                    let s = self.input_buffer.trim().to_string();
                    if s.is_empty() {
                        self.input_mode = false;
                        self.input_buffer.clear();
                        return None;
                    }
                    match IpNet::from_str(&s) {
                        Ok(_) => {
                            self.cidr_candidates.push(CidrEntry {
                                cidr: s.clone(),
                                selected: true,
                            });
                            self.input_buffer.clear();
                            self.input_mode = false;
                            self.message = Some(format!("Added {}", s));
                        }
                        Err(e) => {
                            self.message = Some(format!("Invalid CIDR '{}': {}", s, e));
                        }
                    }
                    None
                }
                KeyCode::Esc => {
                    self.input_mode = false;
                    self.input_buffer.clear();
                    None
                }
                KeyCode::Backspace => {
                    self.input_buffer.pop();
                    None
                }
                KeyCode::Char(c) => {
                    self.input_buffer.push(c);
                    None
                }
                _ => None,
            }
        } else {
            match key {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    self.should_quit = true;
                    None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                    }
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.cidr_candidates.is_empty()
                        && self.cursor < self.cidr_candidates.len() - 1
                    {
                        self.cursor += 1;
                    }
                    None
                }
                KeyCode::Char(' ') => {
                    if let Some(e) = self.cidr_candidates.get_mut(self.cursor) {
                        e.selected = !e.selected;
                    }
                    None
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.input_mode = true;
                    self.input_buffer.clear();
                    None
                }
                KeyCode::Enter => {
                    let selected: Vec<String> = self
                        .cidr_candidates
                        .iter()
                        .filter(|e| e.selected)
                        .map(|e| e.cidr.clone())
                        .collect();
                    if selected.is_empty() {
                        self.message =
                            Some("Select at least one CIDR (space) before starting.".to_string());
                        None
                    } else {
                        Some(selected)
                    }
                }
                _ => None,
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.should_quit = true;
                false
            }
            KeyCode::Char('p') | KeyCode::Char(' ') => {
                let next = !self.paused.load(Ordering::Relaxed);
                self.paused.store(next, Ordering::Relaxed);
                self.message = None;
                true
            }
            KeyCode::Char('s') if self.scan_complete => {
                match self.save_to_file() {
                    Ok(name) => self.message = Some(format!("Results saved to {name}")),
                    Err(e) => self.message = Some(format!("Save failed: {e}")),
                }
                true
            }
            _ => true,
        }
    }

    fn save_to_file(&self) -> Result<String, io::Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let filename = format!("cleanscan_{ts}.tsv");
        let mut f = fs::File::create(&filename)?;
        writeln!(f, "rank\tip\tok\tfail\tavg\tp50\tp90\tp95\tmax")?;
        for (i, r) in self.results.iter().enumerate() {
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
}

/// Run the full TUI loop.
pub fn run_tui(args: Args) -> anyhow::Result<()> {
    let has_cli_targets = args.ips.is_some() || !args.cidr.is_empty();

    let args_arc = Arc::new(args);
    let (tx, rx) = std::sync::mpsc::channel::<ProbeResult>();
    let paused = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));

    let mut terminal = ratatui::init();
    // Ensure the terminal is always restored, even on early error returns.
    let _guard = RestoreGuard;
    let mut app = App::new(args_arc.clone(), has_cli_targets, paused.clone());

    // Spawns the background scanner thread for a concrete target list, using a
    // fresh tokio runtime. The thread is only created once targets are known
    // (immediately for CLI targets, or after the setup screen confirms).
    let spawn_scanner = |targets: Vec<String>| -> std::thread::JoinHandle<()> {
        let scanner_args = args_arc.clone();
        let scanner_paused = paused.clone();
        let scanner_cancel = cancel.clone();
        let scanner_tx = tx.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return;
                }
            };
            rt.block_on(crate::scanner::run_scan(
                targets,
                scanner_args,
                scanner_tx,
                scanner_cancel,
                scanner_paused,
            ));
        })
    };

    let mut scanner: Option<std::thread::JoinHandle<()>> = None;

    // CLI-provided targets start scanning immediately (legacy behavior).
    if has_cli_targets {
        let targets = crate::scanner::collect_targets(&args_arc)?;
        let total = targets.len();
        scanner = Some(spawn_scanner(targets));
        app.begin_scan(total);
    }

    let mut run = || -> anyhow::Result<()> {
        loop {
            // Drain available results from the scanner
            while let Ok(r) = rx.try_recv() {
                app.add_result(r);
            }

            // Check if the scanner thread has finished
            if !app.scan_complete
                && scanner.as_ref().is_some_and(|s| s.is_finished())
            {
                // Drain one more time to catch any results sent just before thread exit
                while let Ok(r) = rx.try_recv() {
                    app.add_result(r);
                }
                app.scan_complete = true;
            }

            terminal.draw(|f| app.render(f))?;

            // Handle keyboard input (non-blocking poll)
            if crossterm::event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        if app.phase == Phase::Setup {
                            if let Some(cidrs) = app.handle_setup_key(key.code) {
                                match crate::scanner::collect_from_cidrs(
                                    &cidrs,
                                    args_arc.sample_per_cidr,
                                ) {
                                    Ok(targets) => {
                                        let total = targets.len();
                                        scanner = Some(spawn_scanner(targets));
                                        app.begin_scan(total);
                                    }
                                    Err(e) => {
                                        app.message = Some(format!("Error: {e}"))
                                    }
                                }
                            }
                        } else if !app.handle_key(key.code) {
                            break;
                        }
                    }
                }
            }

            if app.should_quit {
                break;
            }
        }
        Ok(())
    };

    let result = run();

    // Signal cancellation so the scanner stops scheduling/awaiting probes and
    // joins promptly on quit.
    cancel.store(true, Ordering::Relaxed);
    if let Some(s) = scanner {
        let _ = s.join();
    }
    result
}

/// Restores the terminal when dropped, guaranteeing cleanup on every exit path.
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
