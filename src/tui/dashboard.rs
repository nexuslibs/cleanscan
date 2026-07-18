use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarState, Table},
    Frame,
};

use crate::scanner::ProbeResult;
use crate::tui::theme;
use crate::tui::{App, ButtonAction};

const COLS: [&str; 9] = ["#", "IP", "OK", "Fail", "Avg", "P50", "P90", "P95", "Max"];
const WIDTHS: [Constraint; 9] = [
    Constraint::Length(5),
    Constraint::Length(25),
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
            Constraint::Length(3), // Header
            Constraint::Length(6), // Stats panel
            Constraint::Min(1),    // Results table
            Constraint::Length(3), // Footer
        ])
        .split(area);

    render_header(app, frame, chunks[0]);
    render_stats_panel(app, frame, chunks[1]);
    render_table(app, frame, chunks[2]);
    render_footer(app, frame, chunks[3]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let elapsed = app.start_time.elapsed();
    let elapsed_str = format!(
        "{:02}:{:02}",
        elapsed.as_secs() / 60,
        elapsed.as_secs() % 60
    );

    let status = if app.scan_complete {
        "DONE"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "PAUSED"
    } else {
        "SCANNING"
    };

    let spans = vec![
        Span::styled(
            format!(" CLEANSCAN v{} ", env!("CARGO_PKG_VERSION")),
            theme::header_style(),
        ),
        Span::styled(format!("│ {} ", status), theme::status_style(status)),
        Span::raw(format!("│ Host: {} ", app.config.host)),
        Span::raw(format!("│ Path: {} ", app.config.path)),
        Span::styled(format!("│ elapsed {}", elapsed_str), theme::hint_style()),
    ];
    let line = Line::from(spans);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style());
    let para = Paragraph::new(line).block(block);
    frame.render_widget(para, area);
}

fn render_stats_panel(app: &App, frame: &mut Frame, area: Rect) {
    let col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(area);

    let passed = app.results.len();
    let total = app.total_targets;
    let pct = if total > 0 {
        (passed as f64 / total as f64 * 100.0) as u16
    } else {
        0
    };

    // Calculate rates and ETA
    let mut rate_str = "~0.0/s".to_string();
    let mut eta_str = "00:00".to_string();
    if !app.scan_complete && total > 0 && passed > 0 {
        let elapsed = app.start_time.elapsed().as_secs_f64();
        let rate = passed as f64 / elapsed.max(0.001);
        let remaining = total - passed;
        let eta = (remaining as f64 / rate.max(0.001)).max(0.0);
        rate_str = format!("{:.1}/s", rate);
        eta_str = format!("{:02}:{:02}", eta as u64 / 60, eta as u64 % 60);
    } else if app.scan_complete {
        rate_str = "Finished".to_string();
        eta_str = "--:--".to_string();
    }

    // Success rate calculation
    let mut total_probes_done = 0;
    let mut total_probes_ok = 0;
    for r in &app.results {
        total_probes_done += r.ok + r.fail;
        total_probes_ok += r.ok;
    }
    let success_rate = if total_probes_done > 0 {
        (total_probes_ok as f64 / total_probes_done as f64) * 100.0
    } else {
        0.0
    };

    // Panel 1: Progress & Success
    let progress_lines = vec![
        Line::from(vec![
            Span::styled("Progress : ", theme::title_style()),
            Span::raw(format!("{}/{} targets ({pct}%)", passed, total)),
        ]),
        Line::from(vec![
            Span::styled("Success  : ", theme::title_style()),
            Span::raw(format!(
                "{:.1}% ({} ok, {} fail)",
                success_rate,
                total_probes_ok,
                total_probes_done - total_probes_ok
            )),
        ]),
        Line::from(vec![
            Span::styled("Speed/ETA: ", theme::title_style()),
            Span::raw(format!("{} • ETA {}", rate_str, eta_str)),
        ]),
    ];
    let block_p1 = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(" Progress & Workers ");
    frame.render_widget(
        Paragraph::new(progress_lines).block(block_p1),
        col_chunks[0],
    );

    // Panel 2: Latency summary
    let ok_results: Vec<&ProbeResult> = app.results.iter().filter(|r| r.ok > 0).collect();
    let best_ip_str = if let Some(best) = ok_results
        .iter()
        .min_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap())
    {
        format!("{} ({:.1}ms)", best.ip, best.avg * 1000.0)
    } else {
        "None".to_string()
    };

    let avg_latency = if !ok_results.is_empty() {
        ok_results.iter().map(|r| r.avg).sum::<f64>() / ok_results.len() as f64
    } else {
        0.0
    };

    let median_latency = if !ok_results.is_empty() {
        median(ok_results.iter().map(|r| r.p50).collect())
    } else {
        0.0
    };

    let latency_lines = vec![
        Line::from(vec![
            Span::styled("Fastest Edge: ", theme::title_style()),
            Span::raw(best_ip_str),
        ]),
        Line::from(vec![
            Span::styled("Avg Latency : ", theme::title_style()),
            Span::raw(format!("{:.1}ms", avg_latency * 1000.0)),
        ]),
        Line::from(vec![
            Span::styled("Median (p50): ", theme::title_style()),
            Span::raw(format!("{:.1}ms", median_latency * 1000.0)),
        ]),
    ];
    let block_p2 = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(" Latency Metrics ");
    frame.render_widget(Paragraph::new(latency_lines).block(block_p2), col_chunks[1]);

    // Panel 3: Latency Distribution Bar Chart
    let total_ok = ok_results.len();
    let (mut exc, mut gd, mut fr, mut pr) = (0, 0, 0, 0);
    for r in &ok_results {
        let ms = r.avg * 1000.0;
        match latency_bucket(ms) {
            0 => exc += 1,
            1 => gd += 1,
            2 => fr += 1,
            _ => pr += 1,
        }
    }

    let make_bar = |count: usize| -> String {
        if total_ok == 0 {
            return String::new();
        }
        let pct = count as f64 / total_ok as f64;
        let bar_len = (pct * 8.0).round() as usize;
        "█".repeat(bar_len)
    };

    let distribution_lines = vec![
        Line::from(vec![
            Span::styled("  <80ms : ", theme::good_style()),
            Span::raw(format!("{:<8} ", make_bar(exc))),
            Span::styled(format!("{exc}"), theme::hint_style()),
        ]),
        Line::from(vec![
            Span::styled("150–200ms: ", theme::warn_style()),
            Span::raw(format!("{:<8} ", make_bar(gd))),
            Span::styled(format!("{gd}"), theme::hint_style()),
        ]),
        Line::from(vec![
            Span::styled("200-250 : ", theme::bad_style()),
            Span::raw(format!("{:<8} ", make_bar(fr))),
            Span::styled(format!("{fr}"), theme::hint_style()),
        ]),
        Line::from(vec![
            Span::styled("  ≥250ms: ", theme::bad_style()),
            Span::raw(format!("{:<8} ", make_bar(pr))),
            Span::styled(format!("{pr}"), theme::hint_style()),
        ]),
    ];
    let block_p3 = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(" Latency Spread ");
    frame.render_widget(
        Paragraph::new(distribution_lines).block(block_p3),
        col_chunks[2],
    );
}

fn render_table(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_active_style())
        .title(" Results ");
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
    for (i, w) in WIDTHS.iter().enumerate() {
        if let Constraint::Length(len) = w {
            let len = (*len).min(inner.width.saturating_sub(x - inner.x));
            bounds.push((x, x + len));
            x += len + u16::from(i + 1 < WIDTHS.len());
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

            // Highlight rank 1 (fastest IP) to make it look premium
            let is_first = app.sort_col == 4 && app.sort_asc && rank == 1;
            let (ip_text, rank_text) = if is_first {
                (format!("★ {}", r.ip), format!(" {rank}"))
            } else {
                (r.ip.clone(), rank.to_string())
            };

            let mut base_style = Style::default();
            if is_first {
                base_style = base_style.fg(Color::LightCyan).add_modifier(Modifier::BOLD);
            }

            Row::new(vec![
                Cell::from(rank_text).style(base_style),
                Cell::from(ip_text).style(base_style),
                Cell::from(r.ok.to_string()).style(base_style),
                Cell::from(r.fail.to_string()).style(if r.fail > 0 {
                    theme::bad_style()
                } else {
                    base_style
                }),
                Cell::from(fmt_ms(r.avg)).style(theme::latency_style(r.avg * 1000.0)),
                Cell::from(fmt_ms(r.p50)).style(theme::latency_style(r.p50 * 1000.0)),
                Cell::from(fmt_ms(r.p90)).style(theme::latency_style(r.p90 * 1000.0)),
                Cell::from(fmt_ms(r.p95)).style(theme::latency_style(r.p95 * 1000.0)),
                Cell::from(fmt_ms(r.max)).style(theme::latency_style(r.max * 1000.0)),
            ])
        })
        .collect();

    let table = Table::new(rows, WIDTHS).header(header).block(block);
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

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn latency_bucket(ms: f64) -> usize {
    if ms < theme::LATENCY_GOOD_MS {
        0
    } else if ms < theme::LATENCY_WARN_MS {
        1
    } else if ms < 250.0 {
        2
    } else {
        3
    }
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(18),
            Constraint::Length(20),
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

    if app.scan_complete {
        app.button(
            frame,
            chunks[1],
            "Speed test (v)",
            ButtonAction::SpeedTest,
            false,
        );
    }
    app.button(frame, chunks[3], "Quit (q)", ButtonAction::Quit, false);

    let msg = app.visible_message().unwrap_or(if app.scan_complete {
        "Scan complete — ↑/↓ scroll, s save, v speed test, q quit"
    } else {
        "↑/↓ scroll • space pause • ? help • q quit"
    });
    let para = Paragraph::new(msg).style(theme::hint_style());
    frame.render_widget(para, chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::{latency_bucket, median};

    #[test]
    fn median_averages_even_central_values() {
        assert_eq!(median(vec![4.0, 1.0, 3.0, 2.0]), 2.5);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), 2.0);
    }

    #[test]
    fn dashboard_bucket_matches_table_classification_at_200ms() {
        assert_eq!(latency_bucket(199.9), 1);
        assert_eq!(latency_bucket(200.0), 2);
        assert_eq!(latency_bucket(249.9), 2);
    }
}
