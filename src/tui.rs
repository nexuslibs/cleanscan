use std::{
    fs,
    io::{self, Write},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::{scanner::ProbeResult, Args};

pub struct App {
    args: Arc<Args>,
    results: Vec<ProbeResult>,
    total_targets: usize,
    pub scan_complete: bool,
    pub should_quit: bool,
    paused: Arc<AtomicBool>,
    message: Option<String>,
    start_time: Instant,
}

impl App {
    pub fn new(args: Arc<Args>, total_targets: usize, paused: Arc<AtomicBool>) -> Self {
        Self {
            args,
            results: Vec::new(),
            total_targets,
            scan_complete: false,
            should_quit: false,
            paused,
            message: None,
            start_time: Instant::now(),
        }
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
        let message = self
            .message
            .as_deref()
            .unwrap_or(text);
        let paragraph = Paragraph::new(message).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(paragraph, area);
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
    let targets = crate::scanner::collect_targets(&args)?;
    let total = targets.len();

    let (tx, rx) = std::sync::mpsc::channel::<ProbeResult>();
    let args_arc = Arc::new(args);

    let paused = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));

    // Spawn scanner on a background thread with its own tokio runtime
    let scanner_args = args_arc.clone();
    let scanner_paused = paused.clone();
    let scanner_cancel = cancel.clone();
    let scanner = std::thread::spawn(move || {
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
            tx,
            scanner_cancel,
            scanner_paused,
        ));
    });

    let mut terminal = ratatui::init();
    // Ensure the terminal is always restored, even on early error returns.
    let _guard = RestoreGuard;
    let mut app = App::new(args_arc, total, paused);

    let mut run = || -> anyhow::Result<()> {
        loop {
            // Drain available results from the scanner
            while let Ok(r) = rx.try_recv() {
                app.add_result(r);
            }

            // Check if the scanner thread has finished
            if !app.scan_complete && scanner.is_finished() {
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
                    if key.kind == KeyEventKind::Press && !app.handle_key(key.code) {
                        break;
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
    let _ = scanner.join();
    result
}

/// Restores the terminal when dropped, guaranteeing cleanup on every exit path.
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
