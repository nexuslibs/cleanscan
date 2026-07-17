use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Scrollbar, ScrollbarState, Table},
    Frame,
};

use crate::tui::theme;
use crate::tui::{App, ButtonAction};
use crate::scanner::ProbeResult;

const COLS: [&str; 9] = ["#", "IP", "OK", "Fail", "Avg", "P50", "P90", "P95", "Max"];
const WIDTHS: [Constraint; 9] = [
    Constraint::Length(5),
    Constraint::Length(34),
    Constraint::Length(5),
    Constraint::Length(6),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
];

/// Render the live scanning dashboard.
pub fn render(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(app, frame, chunks[0]);
    render_progress(app, frame, chunks[1]);
    render_table(app, frame, chunks[2]);
    render_footer(app, frame, chunks[3]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let elapsed = app.start_time.elapsed();
    let elapsed_str = format!("{:02}:{:02}", elapsed.as_secs() / 60, elapsed.as_secs() % 60);

    let status = if app.scan_complete {
        "DONE"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "PAUSED"
    } else {
        "SCANNING"
    };

    let passed = app.results.len();
    let total = app.total_targets;

    let spans = vec![
        Span::styled(
            format!(" cleanscan v{} ", env!("CARGO_PKG_VERSION")),
            theme::header_style(),
        ),
        Span::styled(format!("│ {} ", status), theme::status_style(status)),
        Span::raw(format!("│ {}/{} targets ", passed, total)),
        Span::raw(format!("│ {} elapsed", elapsed_str)),
    ];
    let line = Line::from(spans);
    let block = Block::default().borders(Borders::ALL);
    let para = Paragraph::new(line).block(block);
    frame.render_widget(para, area);
}

fn render_progress(app: &App, frame: &mut Frame, area: Rect) {
    let passed = app.results.len();
    let total = app.total_targets;
    let pct = if total > 0 {
        (passed as f64 / total as f64 * 100.0) as u16
    } else {
        0
    };

    let mut label = format!("{pct}%");
    if !app.scan_complete && total > 0 && passed > 0 {
        let elapsed = app.start_time.elapsed().as_secs_f64();
        let rate = passed as f64 / elapsed.max(0.001);
        let remaining = total - passed;
        let eta = (remaining as f64 / rate.max(0.001)).max(0.0);
        let eta_str = format!("{:02}:{:02}", eta as u64 / 60, eta as u64 % 60);
        label = format!("{}  ETA {}  ~{:.0}/s", pct, eta_str, rate);
    } else if app.scan_complete {
        label = format!("{}  complete", pct);
    }

    let gauge = Gauge::default()
        .percent(pct)
        .label(label)
        .gauge_style(theme::good_style());
    frame.render_widget(gauge, area);
}

fn render_table(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Results ");
    let inner = block.inner(area);
    let header_rect = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    app.table_header = Some(header_rect);

    // Compute column x-bounds for mouse header sorting.
    let mut bounds = Vec::new();
    let mut x = inner.x;
    for w in WIDTHS.iter() {
        if let Constraint::Length(len) = w {
            let len = (*len).min(inner.width.saturating_sub(x - inner.x));
            bounds.push((x, x + len));
            x += len;
        }
    }
    app.table_col_bounds = bounds;
    app.table_inner = Some(inner);

    let visible = inner.height.saturating_sub(1) as usize; // header row inside inner

    let display_len = app.sorted_results().len().min(app.config.top);
    let max_start = display_len.saturating_sub(visible);
    if app.scroll > max_start {
        app.scroll = max_start;
    }

    let sorted = app.sorted_results();
    let display: Vec<&ProbeResult> = sorted.iter().take(display_len).copied().collect();

    let start = app.scroll;
    let end = (start + visible).min(display.len());
    let page: Vec<&ProbeResult> = display[start..end].to_vec();

    let header_cells: Vec<Cell> = COLS
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == app.sort_col {
                theme::highlight_style()
            } else {
                theme::title_style()
            };
            Cell::from(format!(
                "{}{}",
                if i == app.sort_col {
                    if app.sort_asc {
                        "▲"
                    } else {
                        "▼"
                    }
                } else {
                    " "
                },
                c
            ))
            .style(style)
        })
        .collect();
    let header = Row::new(header_cells);

    let rows: Vec<Row> = page
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let rank = start + i + 1;
            let fail_style = if r.fail > 0 {
                theme::bad_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(rank.to_string()),
                Cell::from(r.ip.clone()),
                Cell::from(r.ok.to_string()),
                Cell::from(r.fail.to_string()).style(fail_style),
                Cell::from(fmt_ms(r.avg)).style(theme::latency_style(r.avg * 1000.0)),
                Cell::from(fmt_ms(r.p50)).style(theme::latency_style(r.p50 * 1000.0)),
                Cell::from(fmt_ms(r.p90)).style(theme::latency_style(r.p90 * 1000.0)),
                Cell::from(fmt_ms(r.p95)).style(theme::latency_style(r.p95 * 1000.0)),
                Cell::from(fmt_ms(r.max)).style(theme::latency_style(r.max * 1000.0)),
            ])
        })
        .collect();

    let table = Table::new(rows, WIDTHS)
        .header(header)
        .block(block);
    frame.render_widget(table, area);

    // Scrollbar reflects position within the displayed (top) results.
    if display.len() > visible {
        let mut state = ScrollbarState::new(display.len()).position(start);
        let scroll_area = Rect {
            x: area.x + area.width.saturating_sub(1),
            y: area.y + 1,
            width: 1,
            height: area.height.saturating_sub(2),
        };
        frame.render_stateful_widget(
            Scrollbar::new(ratatui::widgets::ScrollbarOrientation::VerticalRight),
            scroll_area,
            &mut state,
        );
    }
}

fn fmt_ms(sec: f64) -> String {
    format!("{:.1}ms", sec * 1000.0)
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(18),
            Constraint::Min(0),
            Constraint::Length(18),
        ])
        .split(area);

    let left_action = if app.scan_complete {
        ButtonAction::Save
    } else {
        ButtonAction::PauseResume
    };
    let left_label = if app.scan_complete {
        "Save (s)"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "Resume (p)"
    } else {
        "Pause (p)"
    };
    app.button(frame, chunks[0], left_label, left_action, false);

    app.button(frame, chunks[2], "Quit (q)", ButtonAction::Quit, false);

    let msg = app.visible_message().unwrap_or(if app.scan_complete {
        "Scan complete — ↑/↓ scroll, s save, q quit"
    } else {
        "↑/↓ scroll • space pause • s save • ? help • q quit"
    });
    let para = Paragraph::new(msg).style(theme::hint_style());
    frame.render_widget(para, chunks[1]);
}
