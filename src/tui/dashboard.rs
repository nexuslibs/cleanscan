use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Cell, LineGauge, Paragraph, Row, Scrollbar, ScrollbarState,
        Sparkline, Table,
    },
    Frame,
};

use crate::scanner::ProbeResult;
use crate::tui::theme;
use crate::tui::{widgets, App, ButtonAction, ButtonKind};

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
    if area.width < 80 || area.height < 24 {
        render_terminal_too_small(frame, area);
        return;
    }

    if area.width < 100 {
        render_compact(app, frame, area);
    } else {
        render_wide(app, frame, area);
    }

    if app.show_result_details {
        render_result_details(app, frame, area);
    }
}

fn render_wide(app: &mut App, frame: &mut Frame, area: Rect) {
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

fn render_terminal_too_small(frame: &mut Frame, area: Rect) {
    let block = widgets::panel_block("Terminal size", true);
    let lines = vec![
        Line::from(Span::styled(
            "cleanscan needs at least 80×24",
            theme::header_style(),
        )),
        Line::from("Resize the terminal to continue."),
        Line::from(Span::styled(
            format!("Current size: {}×{}", area.width, area.height),
            theme::hint_style(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(ratatui::layout::Alignment::Center)
            .block(block),
        area,
    );
}

fn render_compact(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(app, frame, chunks[0]);
    render_compact_stats(app, frame, chunks[1]);
    render_compact_table(app, frame, chunks[2]);
    render_compact_footer(app, frame, chunks[3]);
}

fn render_compact_stats(app: &App, frame: &mut Frame, area: Rect) {
    let total = app.total_targets;
    let done = app.results.len();
    let success = app.results.iter().map(|r| r.ok).sum::<usize>();
    let failures = app.results.iter().map(|r| r.fail).sum::<usize>();
    let ratio = if total > 0 {
        done as f64 / total as f64
    } else {
        0.0
    };
    let block = widgets::panel_block("Scan status", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(42),
            Constraint::Percentage(29),
            Constraint::Percentage(29),
        ])
        .split(inner);
    frame.render_widget(
        ratatui::widgets::LineGauge::default()
            .ratio(ratio.clamp(0.0, 1.0))
            .filled_style(theme::status_style("SCANNING"))
            .unfilled_style(theme::hint_style())
            .label(format!("{done}/{total}")),
        cols[0],
    );
    frame.render_widget(
        Paragraph::new(format!("{} ok", success)).style(theme::good_style()),
        cols[1],
    );
    frame.render_widget(
        Paragraph::new(format!("{} fail", failures)).style(if failures > 0 {
            theme::bad_style()
        } else {
            theme::hint_style()
        }),
        cols[2],
    );
}

fn render_compact_table(app: &mut App, frame: &mut Frame, area: Rect) {
    const COMPACT_WIDTHS: [Constraint; 6] = [
        Constraint::Length(5),
        Constraint::Min(15),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(10),
    ];
    let block = widgets::panel_block("Results — Enter details", app.focus_index == 0);
    let inner = block.inner(area);
    app.table_inner = Some(inner);
    let visible = inner.height.saturating_sub(1) as usize;
    let display_len = app.sorted_results().len().min(app.config.top);
    let max_start = display_len.saturating_sub(visible);
    app.result_cursor = app.result_cursor.min(display_len.saturating_sub(1));
    app.scroll = app.scroll.min(max_start);
    app.scroll = app
        .scroll
        .max(app.result_cursor.saturating_sub(visible.saturating_sub(1)))
        .min(app.result_cursor)
        .min(max_start);
    let sorted = app.sorted_results();
    let page = sorted.iter().skip(app.scroll).take(visible);
    let rows = page.enumerate().map(|(i, r)| {
        let index = app.scroll + i;
        let selected = index == app.result_cursor;
        let reliability = format!("{}/{}", r.ok, r.ok + r.fail);
        let status = if r.fail == 0 { "READY" } else { "DEGRADED" };
        Row::new(vec![
            Cell::from((index + 1).to_string()),
            Cell::from(r.ip.clone()),
            Cell::from(reliability),
            Cell::from(fmt_ms(r.avg)),
            Cell::from(fmt_ms(r.p95)),
            Cell::from(status).style(if r.fail == 0 {
                theme::good_style()
            } else {
                theme::warn_style()
            }),
        ])
        .style(if selected {
            theme::row_selected_style()
        } else if index % 2 == 1 {
            theme::row_alt_style()
        } else {
            Style::default()
        })
    });
    let table = Table::new(rows, COMPACT_WIDTHS)
        .header(
            Row::new(vec!["#", "IP", "Reliability", "Avg", "P95", "Status"])
                .style(theme::title_style()),
        )
        .block(block);
    frame.render_widget(table, area);
}

fn render_compact_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let hints: &[widgets::KeyHint] = if app.scan_complete {
        &[
            ("Tab", "focus"),
            ("↵", "details"),
            ("e", "export"),
            ("t", "speed test"),
            ("c", "copy"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("Tab", "focus"),
            ("↵", "details"),
            ("p", "pause"),
            ("c", "copy"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    widgets::status_bar(frame, area, hints, app.visible_message());
}

fn render_result_details(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(result) = app
        .sorted_results()
        .into_iter()
        .take(app.config.top)
        .nth(app.result_cursor)
    else {
        return;
    };
    let popup = crate::tui::centered(area, 64, 62);
    let inner = widgets::modal(frame, area, popup, " Selected edge details ");
    let lines = vec![
        Line::from(Span::styled(result.ip.clone(), theme::header_style())),
        Line::from(Span::styled("Latency profile", theme::subtitle_style())),
        Line::from(""),
        Line::from(format!(
            "Reliability : {}/{} successful",
            result.ok,
            result.ok + result.fail
        )),
        Line::from(format!("Average     : {}", fmt_ms(result.avg))),
        Line::from(format!("P50         : {}", fmt_ms(result.p50))),
        Line::from(format!("P90         : {}", fmt_ms(result.p90))),
        Line::from(format!("P95         : {}", fmt_ms(result.p95))),
        Line::from(format!("Max         : {}", fmt_ms(result.max))),
        Line::from(""),
        Line::from(Span::styled(
            "c copy • e export • t speed test • Esc close",
            theme::hint_style(),
        )),
    ];
    // The modal already draws a titled, bordered frame; render the body straight
    // into its inner rect so there is a single clean border (no nested panel).
    frame.render_widget(Paragraph::new(lines), inner);
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

    // A spinner reinforces the "live" state while scanning.
    let status_text = if status == "SCANNING" {
        format!("{} {}", widgets::spinner_frame(app.tick), status)
    } else {
        status.to_string()
    };

    widgets::app_header(
        frame,
        area,
        Some((&status_text, theme::status_style(status))),
        &[
            widgets::HeaderSegment::new("Host", app.config.host.clone()),
            widgets::HeaderSegment::new("Path", app.config.path.clone()),
            widgets::HeaderSegment::new("Elapsed", elapsed_str),
        ],
    );
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

    // Panel 1: Progress gauge + throughput / workers.
    let block_p1 = widgets::panel_block("Progress", false);
    let p1_inner = block_p1.inner(col_chunks[0]);
    frame.render_widget(block_p1, col_chunks[0]);
    let p1_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // gauge
            Constraint::Length(1), // success
            Constraint::Length(1), // rate / eta
            Constraint::Min(1),    // workers
        ])
        .split(p1_inner);

    let ratio = if total > 0 {
        (passed as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let gauge = LineGauge::default()
        .filled_style(if app.scan_complete {
            theme::good_style()
        } else {
            theme::status_style("SCANNING")
        })
        .unfilled_style(theme::hint_style())
        .label(Span::styled(
            format!("{passed}/{total} ({pct}%)"),
            theme::title_style(),
        ))
        .ratio(ratio);
    frame.render_widget(gauge, p1_rows[0]);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Success  : ", theme::title_style()),
            Span::raw(format!(
                "{:.1}% ({} ok, {} fail)",
                success_rate,
                total_probes_ok,
                total_probes_done - total_probes_ok
            )),
        ])),
        p1_rows[1],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Speed/ETA: ", theme::title_style()),
            Span::raw(format!("{} • ETA {}", rate_str, eta_str)),
        ])),
        p1_rows[2],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Workers  : ", theme::title_style()),
            Span::raw(format!(
                "{} concurrent • {} probes/IP",
                app.config.concurrency, app.config.probes
            )),
        ])),
        p1_rows[3],
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
    let block_p2 = widgets::panel_block("Latency & Throughput", false);
    let p2_inner = block_p2.inner(col_chunks[1]);
    frame.render_widget(block_p2, col_chunks[1]);
    let p2_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(p2_inner);
    frame.render_widget(Paragraph::new(latency_lines), p2_rows[0]);

    // Throughput sparkline (probes/sec), most recent samples fill the width.
    let spark_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(9), Constraint::Min(1)])
        .split(p2_rows[1]);
    frame.render_widget(
        Paragraph::new(Span::styled("Thrput/s:", theme::title_style())),
        spark_cols[0],
    );
    let spark_width = spark_cols[1].width as usize;
    let samples: &[u64] = if app.throughput.len() > spark_width {
        &app.throughput[app.throughput.len() - spark_width..]
    } else {
        &app.throughput
    };
    frame.render_widget(
        Sparkline::default()
            .data(samples)
            .style(theme::status_style("SCANNING")),
        spark_cols[1],
    );

    // Panel 3: Latency distribution as a horizontal bar chart.
    let total_ok = ok_results.len();
    let (mut exc, mut gd, mut fr, mut pr) = (0u64, 0u64, 0u64, 0u64);
    for r in &ok_results {
        let ms = r.avg * 1000.0;
        match latency_bucket(ms) {
            0 => exc += 1,
            1 => gd += 1,
            2 => fr += 1,
            _ => pr += 1,
        }
    }

    let bars = [
        ("<80ms", exc, theme::good_style()),
        ("80-200", gd, theme::warn_style()),
        ("200-250", fr, theme::bad_style()),
        ("≥250ms", pr, theme::bad_style()),
    ]
    .into_iter()
    .map(|(label, value, style)| {
        Bar::default()
            .value(value)
            .label(Line::from(label))
            .text_value(value.to_string())
            .style(style)
    })
    .collect::<Vec<_>>();

    let block_p3 = widgets::panel_block("Latency Spread", false);
    let chart = BarChart::default()
        .block(block_p3)
        .data(BarGroup::default().bars(&bars))
        .direction(Direction::Horizontal)
        .bar_width(1)
        .bar_gap(0)
        .max((total_ok as u64).max(1))
        .label_style(theme::hint_style());
    frame.render_widget(chart, col_chunks[2]);
}

fn render_table(app: &mut App, frame: &mut Frame, area: Rect) {
    // The table border reads as "focused" only when keyboard focus is actually
    // on the table (index 0); Tab-ing to a footer button releases it.
    let focused = app.focus_index == 0;
    let block = widgets::panel_block("Results", focused);
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
    app.result_cursor = app.result_cursor.min(display_len.saturating_sub(1));
    app.scroll = app
        .scroll
        .max(app.result_cursor.saturating_sub(visible.saturating_sub(1)))
        .min(app.result_cursor)
        .min(max_start);

    let sorted = app.sorted_results();
    let display: Vec<&ProbeResult> = sorted.iter().take(display_len).copied().collect();

    // The fastest successful edge by average latency, starred wherever it appears.
    let best_ip: Option<String> = {
        let mut v: Vec<&ProbeResult> = app.results.iter().filter(|r| r.ok > 0).collect();
        v.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap());
        v.first().map(|r| r.ip.clone())
    };

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
            let is_selected = start + i == app.result_cursor;

            // Star the fastest average-latency edge wherever it lands in the sort.
            let is_first = best_ip.as_deref() == Some(r.ip.as_str());
            let (ip_text, rank_text) = if is_first {
                (format!("★ {}", r.ip), format!(" {rank}"))
            } else {
                (r.ip.clone(), rank.to_string())
            };

            let base_style = if is_selected {
                theme::row_selected_style()
            } else if is_first {
                theme::best_style()
            } else {
                Style::default()
            };

            // Full-row background: selection wins, otherwise subtle zebra striping.
            let row_style = if is_selected {
                theme::row_selected_style()
            } else if (start + i) % 2 == 1 {
                theme::row_alt_style()
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(rank_text).style(base_style),
                Cell::from(ip_text).style(base_style),
                Cell::from(r.ok.to_string()).style(base_style),
                Cell::from(r.fail.to_string()).style(if is_selected {
                    base_style
                } else if r.fail > 0 {
                    theme::bad_style()
                } else {
                    base_style
                }),
                Cell::from(fmt_ms(r.avg)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.avg * 1000.0)
                }),
                Cell::from(fmt_ms(r.p50)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.p50 * 1000.0)
                }),
                Cell::from(fmt_ms(r.p90)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.p90 * 1000.0)
                }),
                Cell::from(fmt_ms(r.p95)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.p95 * 1000.0)
                }),
                Cell::from(fmt_ms(r.max)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.max * 1000.0)
                }),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(rows, WIDTHS).header(header).block(block);
    frame.render_widget(table, area);

    // Empty state: no successful results to show yet.
    if display.is_empty() {
        let msg = if app.scan_complete {
            "No successful IPs found — try widening the CIDR selection or raising timeouts."
        } else {
            "Probing edges… successful IPs will appear here as they respond."
        };
        let hint_area = Rect {
            x: inner.x,
            y: inner.y + (inner.height / 2).min(2),
            width: inner.width,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(msg)
                .style(theme::hint_style())
                .alignment(ratatui::layout::Alignment::Center),
            hint_area,
        );
    }

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
        "Export (e)"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "Resume (p)"
    } else {
        "Pause (p)"
    };
    let left_kind = if app.scan_complete {
        ButtonKind::Primary
    } else {
        ButtonKind::Secondary
    };
    app.button_ex(
        frame,
        chunks[0],
        left_label,
        left_action,
        left_kind,
        app.focus_index == 1,
    );

    if app.scan_complete {
        app.button_ex(
            frame,
            chunks[1],
            "Speed test (t)",
            ButtonAction::SpeedTest,
            ButtonKind::Primary,
            app.focus_index == 2,
        );
    }
    app.button_ex(
        frame,
        chunks[3],
        "Quit (q)",
        ButtonAction::Quit,
        ButtonKind::Secondary,
        app.focus_index == 4,
    );

    let hints: &[widgets::KeyHint] = if app.scan_complete {
        &[
            ("Tab", "focus"),
            ("↵", "details"),
            ("c", "copy"),
            ("e", "export"),
            ("t", "speed test"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("Tab", "focus"),
            ("↵", "details"),
            ("p", "pause"),
            ("c", "copy"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    widgets::status_bar(frame, chunks[2], hints, app.visible_message());
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
