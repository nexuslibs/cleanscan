use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Points},
        Axis, Bar, BarChart, BarGroup, Cell, Chart, Dataset, GraphType, LineGauge, Paragraph, Row,
        Scrollbar, ScrollbarState, Sparkline, Table, Tabs,
    },
    Frame,
};

use crate::scanner::{result_confidence, result_status, ProbeResult};
use crate::tui::theme;
use crate::tui::{modal_overlay, widgets, App, ButtonAction, ButtonKind};
use std::time::Duration;

pub const RESULT_COLUMNS: [&str; 14] = [
    "#",
    "IP",
    "Proto/port",
    "OK",
    "Fail",
    "Avg",
    "P50",
    "P90",
    "P95",
    "Max",
    "Colo",
    "Country",
    "Jitter",
    "Loss",
];
const WIDTHS: [Constraint; 14] = [
    Constraint::Length(5),
    Constraint::Length(42),
    Constraint::Length(8),
    Constraint::Length(5),
    Constraint::Length(6),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(10),
    Constraint::Length(7),
    Constraint::Length(14),
    Constraint::Length(9),
    Constraint::Length(7),
];

/// Render the live scanning dashboard.
pub fn render(app: &mut App, frame: &mut Frame, area: Rect, elapsed: Duration) {
    if area.width < 80 || area.height < 24 {
        render_terminal_too_small(frame, area);
        // Keep the result-details overlay's lifecycle running (so it can still
        // be dismissed with its close animation) even on a too-small terminal.
        render_result_details(app, frame, area, elapsed);
        return;
    }

    // The full 14-column table needs 153 (WIDTHS) + 13 column separators
    // + 2 border columns = 168 columns to render without clipping.
    if area.width < 168 {
        render_compact(app, frame, area);
    } else {
        render_wide(app, frame, area);
    }

    render_result_details(app, frame, area, elapsed);
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
    const COMPACT_WIDTHS: [Constraint; 8] = [
        Constraint::Length(5),
        Constraint::Min(15),
        Constraint::Length(7),
        Constraint::Length(14),
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
        let reliability = format!("{}/{}", r.ok, r.completed);
        let status = result_status(r);
        Row::new(vec![
            Cell::from((index + 1).to_string()),
            Cell::from(r.ip.clone()),
            Cell::from(r.colo.clone().unwrap_or_else(|| "—".to_string())),
            Cell::from(r.country.clone().unwrap_or_else(|| "—".to_string())),
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
            Row::new(vec![
                "#",
                "IP",
                "Colo",
                "Country",
                "Reliability",
                "Avg",
                "P95",
                "Status",
            ])
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
            ("f", "show failures"),
            ("r", "rerun targets"),
            ("n", "new sample"),
            ("m", "comparison export"),
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

fn render_result_details(app: &mut App, frame: &mut Frame, area: Rect, elapsed: Duration) {
    let tabs = [
        "Overview",
        "Diagnostics",
        "Distribution",
        "Speed",
        "Latency Map",
    ];
    app.detail_tab = app.detail_tab.min(tabs.len().saturating_sub(1));

    // Drive the overlay state machine before borrowing `app` immutably below
    // (the result lookup keeps `app` borrowed for the rest of the function).
    let overlay = modal_overlay(" Selected edge details ", 64, 62);
    if app.show_result_details {
        app.result_details_overlay.open();
    } else {
        app.result_details_overlay.close();
    }
    app.result_details_overlay.tick(elapsed);
    frame.render_stateful_widget(overlay, area, &mut app.result_details_overlay);
    let Some(inner) = app.result_details_overlay.inner_area() else {
        return;
    };

    let Some(result) = app
        .sorted_results()
        .into_iter()
        .take(app.config.top)
        .nth(app.result_cursor)
    else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            result.ip.clone(),
            theme::header_style(),
        ))),
        chunks[0],
    );
    frame.render_widget(
        Tabs::new(tabs)
            .select(app.detail_tab)
            .highlight_style(theme::highlight_style())
            .divider("│"),
        chunks[1],
    );

    match app.detail_tab {
        0 => {
            let lines = vec![
                Line::from(format!("Status      : {}", result_status(result))),
                Line::from(format!(
                    "Protocol    : {} (port {})",
                    result.protocol, result.port
                )),
                Line::from(format!(
                    "Colo        : {}",
                    result.colo.clone().unwrap_or_else(|| "unknown".to_string())
                )),
                Line::from(format!(
                    "Country     : {}",
                    result
                        .country
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string())
                )),
                Line::from(format!(
                    "Success     : {}/{} ({:.1}%)",
                    result.ok,
                    result.completed,
                    result.success_rate * 100.0
                )),
                Line::from(format!("Average     : {}", fmt_ms(result.avg))),
                Line::from(format!("P95         : {}", fmt_ms(result.p95))),
                Line::from(format!("Max         : {}", fmt_ms(result.max))),
                Line::from(format!(
                    "Jitter      : {} (σ {})",
                    fmt_ms(result.jitter),
                    fmt_ms(result.stddev)
                )),
                Line::from(format!(
                    "Loss        : {}/{} ({:.1}%)",
                    result.loss,
                    result.completed,
                    result.packet_loss * 100.0
                )),
                Line::from(format!(
                    "Scan        : {}",
                    if result.stopped_early {
                        "stopped early"
                    } else {
                        "full probe budget"
                    }
                )),
                Line::from(format!(
                    "Cold        : {}",
                    result
                        .cold_ms
                        .map(|ms| format!("{:.1}ms", ms))
                        .unwrap_or_else(|| "n/a".to_string())
                )),
                Line::from(format!("Confidence  : {}", result_confidence(result))),
                Line::from(format!(
                    "Score range : {:.4} – {:.4}",
                    result.min_score, result.max_score
                )),
                Line::from(format!("Decision    : {}", result.decision)),
            ];
            render_detail_text(frame, chunks[2], lines);
        }
        1 => {
            let mut lines = Vec::new();
            lines.push(Line::from(Span::styled(
                "Failure breakdown",
                theme::subtitle_style(),
            )));
            if result.failures.is_empty() {
                lines.push(Line::from("  No failed probes"));
            } else {
                let mut failures = std::collections::BTreeMap::<&str, usize>::new();
                for failure in &result.failures {
                    *failures.entry(failure.as_str()).or_default() += 1;
                }
                for (reason, count) in failures {
                    lines.push(Line::from(format!("  {reason:<24} {count}")));
                }
                for diagnostic in &result.diagnostics {
                    lines.push(Line::from(format!(
                        "  [{:?}/{:?}] {}{}",
                        diagnostic.category,
                        diagnostic.phase,
                        diagnostic.message,
                        diagnostic
                            .status
                            .map(|s| format!(" (HTTP {s})"))
                            .unwrap_or_default()
                    )));
                }
            }
            render_detail_text(frame, chunks[2], lines);
        }
        2 => render_latency_chart(frame, chunks[2], result),
        3 => {
            let Some(speed_result) = app.speed_results.iter().find(|speed| speed.ip == result.ip)
            else {
                render_detail_text(
                    frame,
                    chunks[2],
                    vec![Line::from(
                        "Run a speed test to populate throughput details.",
                    )],
                );
                return;
            };
            let mut lines = vec![Line::from(Span::styled(
                "Throughput",
                theme::subtitle_style(),
            ))];
            lines.push(Line::from(format!(
                "Download   : {}",
                format_speed_measurement(speed_result.download.as_ref())
            )));
            lines.push(Line::from(format!(
                "Upload     : {}",
                format_speed_measurement(speed_result.upload.as_ref())
            )));
            if let Some(error) = &speed_result.error {
                lines.push(Line::from(format!("Status     : {error}")));
            }
            render_detail_text(frame, chunks[2], lines);
        }
        _ => render_latency_map(frame, chunks[2], app),
    }
}

fn render_detail_text(frame: &mut Frame, area: Rect, mut lines: Vec<Line<'static>>) {
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "c copy • e export • t speed test • Esc close",
            theme::hint_style(),
        )),
    ]);
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_latency_chart(frame: &mut Frame, area: Rect, result: &ProbeResult) {
    if result.samples.is_empty() {
        render_detail_text(
            frame,
            area,
            vec![Line::from("No successful probe samples available.")],
        );
        return;
    }
    let points: Vec<(f64, f64)> = result
        .samples
        .iter()
        .enumerate()
        .map(|(index, seconds)| (index as f64 + 1.0, seconds * 1000.0))
        .collect();
    let max_y = points
        .iter()
        .map(|(_, value)| *value)
        .fold(1.0_f64, f64::max);
    let max_x = points.len().max(2) as f64;
    let chart = Chart::new(vec![Dataset::default()
        .name("latency ms")
        .graph_type(GraphType::Line)
        .marker(Marker::Braille)
        .style(theme::good_style())
        .data(&points)])
    .block(widgets::panel_block("Probe latency", false))
    .x_axis(
        Axis::default()
            .title("probe")
            .bounds([1.0, max_x])
            .labels(vec![
                Line::from("1"),
                Line::from(format!("{}", points.len())),
            ]),
    )
    .y_axis(
        Axis::default()
            .title("ms")
            .bounds([0.0, max_y])
            .labels(vec![Line::from("0"), Line::from(format!("{max_y:.0}"))]),
    );
    frame.render_widget(chart, area);
}

fn render_latency_map(frame: &mut Frame, area: Rect, app: &App) {
    let results = app
        .sorted_results()
        .into_iter()
        .take(app.config.top)
        .collect::<Vec<_>>();
    let selected_ip = results
        .get(app.result_cursor)
        .map(|result| result.ip.clone());
    let results = results
        .into_iter()
        .filter(|result| !(result.avg == 0.0 && result.ok == 0))
        .collect::<Vec<_>>();
    if results.is_empty() {
        frame.render_widget(
            Paragraph::new("No results available for the latency map.").style(theme::hint_style()),
            area,
        );
        return;
    }
    let points = results
        .iter()
        .enumerate()
        .map(|(index, result)| (index as f64 + 1.0, result.avg * 1000.0))
        .collect::<Vec<_>>();
    let selected = selected_latency_index(selected_ip.as_deref(), &results);
    let max_y = points
        .iter()
        .map(|(_, value)| *value)
        .fold(1.0_f64, f64::max);
    let palette = theme::palette();
    let regular = points
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != selected)
        .map(|(_, point)| *point)
        .collect::<Vec<_>>();
    let selected_point = selected.map(|index| [points[index]]);
    let canvas = Canvas::default()
        .block(widgets::panel_block(
            "Latency map — rank vs average ms",
            false,
        ))
        .x_bounds([1.0, points.len().max(2) as f64])
        .y_bounds([0.0, max_y])
        .marker(Marker::Braille)
        .paint(move |ctx| {
            if !regular.is_empty() {
                ctx.draw(&Points {
                    coords: &regular,
                    color: palette.info,
                });
            }
            if let Some(selected_point) = &selected_point {
                ctx.draw(&Points {
                    coords: selected_point,
                    color: palette.highlight,
                });
            }
        });
    frame.render_widget(canvas, area);
}

fn format_speed_measurement(value: Option<&crate::speed::SpeedMeasurement>) -> String {
    value
        .map(|measurement| {
            format!(
                "{:.2} Mbps (p10 {:.2} / p90 {:.2})",
                measurement.median_bytes_per_second * 8.0 / 1_000_000.0,
                measurement.p10_bytes_per_second * 8.0 / 1_000_000.0,
                measurement.p90_bytes_per_second * 8.0 / 1_000_000.0
            )
        })
        .unwrap_or_else(|| "—".to_string())
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let elapsed = app.start_time.elapsed();
    let elapsed_str = format!(
        "{:02}:{:02}",
        elapsed.as_secs() / 60,
        elapsed.as_secs() % 60
    );

    let status = if app.scan_complete && app.watch_due.is_some() {
        "WATCH"
    } else if app.scan_complete {
        "DONE"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "PAUSED"
    } else {
        "SCANNING"
    };

    // A spinner reinforces the "live" state while scanning.
    let status_text = if status == "SCANNING" {
        format!("{} {}", widgets::spinner_frame(app.tick), status)
    } else if status == "WATCH" {
        let remaining = app
            .watch_due
            .map(|due| {
                due.saturating_duration_since(std::time::Instant::now())
                    .as_secs()
            })
            .unwrap_or(0);
        format!("WATCH #{} ({}s)", app.watch_cycle, remaining)
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
    if app.scan_complete {
        render_decision_panel(app, frame, area);
        return;
    }
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
        total_probes_done += r.completed;
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
    let best_ip_str = if let Some(best) = ok_results.iter().min_by(|a, b| a.avg.total_cmp(&b.avg)) {
        format!("{} ({:.1}ms)", best.ip, best.avg * 1000.0)
    } else {
        "None".to_string()
    };

    let (avg_latency, median_latency) = latency_summary(&ok_results);

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

fn render_decision_panel(app: &App, frame: &mut Frame, area: Rect) {
    let ready = app
        .results
        .iter()
        .filter(|r| result_status(r) == "READY")
        .count();
    let degraded = app
        .results
        .iter()
        .filter(|r| result_status(r) == "DEGRADED")
        .count();
    let failed = app
        .results
        .iter()
        .filter(|r| result_status(r) == "FAILED")
        .count();
    let total: usize = app.results.iter().map(|r| r.completed).sum();
    let ok: usize = app.results.iter().map(|r| r.ok).sum();
    let rate = if total > 0 {
        ok as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    let mut candidates = app
        .results
        .iter()
        .filter(|result| result.ok > 0)
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| App::natural_cmp(a, b));
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("READY {ready}  "), theme::good_style()),
        Span::styled(format!("DEGRADED {degraded}  "), theme::warn_style()),
        Span::styled(format!("FAILED {failed}  "), theme::bad_style()),
        Span::raw(format!("{rate:.1}% probe success")),
    ])];
    if let Some(result) = candidates.first() {
        lines.push(Line::from(format!(
            "Recommended: {} • {} • p95 {} • jitter {} • loss {:.1}% • confidence {}",
            result.ip,
            result_status(result),
            fmt_ms(result.p95),
            fmt_ms(result.jitter),
            result.packet_loss * 100.0,
            result_confidence(result)
        )));
        let backups = candidates
            .iter()
            .skip(1)
            .take(2)
            .map(|r| r.ip.as_str())
            .collect::<Vec<_>>();
        if !backups.is_empty() {
            lines.push(Line::from(format!("Backups: {}", backups.join(" • "))));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No successful targets — press f to inspect failures",
            theme::warn_style(),
        )));
    }
    if let Some(alert) = &app.alert_message {
        lines.push(Line::from(Span::styled(
            format!("Alert: {alert}"),
            theme::bad_style(),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Ranking: recommendation score first, then success rate, p95, jitter, packet loss, and average latency • f: show failures",
        theme::hint_style(),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(widgets::panel_block("Scan result — decision view", false)),
        area,
    );
}

fn render_table(app: &mut App, frame: &mut Frame, area: Rect) {
    // The table border reads as "focused" only when keyboard focus is actually
    // on the table (index 0); Tab-ing to a footer button releases it.
    let focused = app.focus_index == 0;
    let block = widgets::panel_block("Results", focused);
    let inner = block.inner(area);
    let visible_columns = app.visible_result_columns();
    let visible_widths: Vec<Constraint> = visible_columns
        .iter()
        .map(|column| WIDTHS[*column])
        .collect();
    app.table_col_indices = visible_columns.clone();
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
    for (i, w) in visible_widths.iter().enumerate() {
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

    // The composite-score recommendation, starred wherever it appears.
    let best_ip = recommendation_ip(&app.results.iter().filter(|r| r.ok > 0).collect::<Vec<_>>());

    let start = app.scroll;
    let end = (start + visible).min(display.len());
    let page: Vec<&ProbeResult> = display[start..end].to_vec();

    let header_cells: Vec<Cell> = visible_columns
        .iter()
        .map(|column| {
            let i = *column;
            let c = RESULT_COLUMNS[i];
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

            // Star the composite-score recommendation wherever it lands in the sort.
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

            let cells = vec![
                Cell::from(rank_text).style(base_style),
                Cell::from(ip_text).style(base_style),
                Cell::from(format!("{}@{}", r.protocol, r.port)).style(base_style),
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
                Cell::from(r.colo.clone().unwrap_or_else(|| "—".to_string())).style(base_style),
                Cell::from(r.country.clone().unwrap_or_else(|| "—".to_string())).style(base_style),
                Cell::from(fmt_ms(r.jitter)).style(if is_selected {
                    base_style
                } else {
                    theme::latency_style(r.jitter * 1000.0)
                }),
                Cell::from(format!("{:.1}%", r.packet_loss * 100.0)).style(if is_selected {
                    base_style
                } else if r.loss > 0 {
                    theme::bad_style()
                } else {
                    base_style
                }),
            ];
            Row::new(
                cells
                    .into_iter()
                    .enumerate()
                    .filter(|(column, _)| app.column_visible(*column))
                    .map(|(_, cell)| cell)
                    .collect::<Vec<_>>(),
            )
            .style(row_style)
        })
        .collect();

    let table = Table::new(rows, visible_widths).header(header).block(block);
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
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn latency_summary(results: &[&ProbeResult]) -> (f64, f64) {
    let samples = results
        .iter()
        .flat_map(|result| result.samples.iter().copied())
        .collect::<Vec<_>>();
    if samples.is_empty() {
        (0.0, 0.0)
    } else {
        (
            samples.iter().sum::<f64>() / samples.len() as f64,
            median(samples),
        )
    }
}

fn recommendation_ip(results: &[&ProbeResult]) -> Option<String> {
    results
        .iter()
        .min_by(|a, b| App::natural_cmp(a, b))
        .map(|result| result.ip.clone())
}

fn selected_latency_index(selected_ip: Option<&str>, results: &[&ProbeResult]) -> Option<usize> {
    selected_ip.and_then(|ip| results.iter().position(|result| result.ip == ip))
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
        app.focus_index == if app.scan_complete { 3 } else { 2 },
    );

    let hints: &[widgets::KeyHint] = if app.scan_complete {
        &[
            ("Tab", "focus"),
            ("↵", "details"),
            ("c", "copy"),
            ("e", "export"),
            ("t", "speed test"),
            ("f", "show failures"),
            ("r", "rerun targets"),
            ("n", "new sample"),
            ("m", "comparison export"),
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
    use super::{
        latency_bucket, latency_summary, median, recommendation_ip, selected_latency_index,
    };
    use crate::scanner::ProbeResult;

    fn result(ip: &str, score: f64, samples: &[f64]) -> ProbeResult {
        ProbeResult {
            ip: ip.to_string(),
            port: 443,
            protocol: "h2".to_string(),
            ok: samples.len(),
            fail: 0,
            completed: samples.len(),
            avg: samples.iter().sum::<f64>() / samples.len().max(1) as f64,
            p50: 0.0,
            p90: 0.0,
            p95: 0.0,
            max: 0.0,
            jitter: 0.0,
            stddev: 0.0,
            loss: 0,
            packet_loss: 0.0,
            samples: samples.to_vec(),
            failures: Vec::new(),
            diagnostics: Vec::new(),
            success_rate: 1.0,
            score,
            colo: None,
            country: None,
            cold_ms: None,
            stopped_early: false,
            min_score: score,
            max_score: score,
            success_rate_lower: 1.0,
            success_rate_upper: 1.0,
            score_confidence: 0.95,
            decision: "competitive".to_string(),
            checks: Vec::new(),
            health_ok: true,
            port_results: Vec::new(),
        }
    }

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

    #[test]
    fn latency_summary_uses_all_raw_samples() {
        let first = result("192.0.2.1", 1.0, &[1.0]);
        let second = result("192.0.2.2", 0.5, &[3.0, 5.0, 7.0]);
        let refs = vec![&first, &second];
        assert_eq!(latency_summary(&refs), (4.0, 4.0));
    }

    #[test]
    fn recommendation_ip_uses_composite_score() {
        let fast = result("192.0.2.1", 1.0, &[1.0]);
        let recommended = result("192.0.2.2", 2.0, &[2.0]);
        let refs = vec![&fast, &recommended];
        assert_eq!(recommendation_ip(&refs).as_deref(), Some("192.0.2.2"));
    }

    #[test]
    fn filtered_selected_ip_does_not_fall_back_to_first_point() {
        let first = result("192.0.2.1", 1.0, &[1.0]);
        let second = result("192.0.2.2", 0.5, &[2.0]);
        let refs = vec![&first, &second];
        assert_eq!(selected_latency_index(Some("192.0.2.9"), &refs), None);
    }
}
