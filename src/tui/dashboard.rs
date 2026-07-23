use crate::scanner::{result_confidence, result_status, ProbeFailureCounts, ProbeResult};
use crate::tui::theme;
use crate::tui::{
    modal_overlay, widgets, App, ButtonAction, ButtonKind, RunKind, ScanDashboardView,
    ScanLifecycle, TargetStage,
};
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::Style,
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Points},
        Axis, Bar, BarChart, BarGroup, Cell, Chart, Dataset, GraphType, LineGauge, Paragraph, Row,
        Scrollbar, ScrollbarState, Sparkline, Table, Tabs, Wrap,
    },
    Frame,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
    let compact = area.width < 168;
    let minimum_height = if compact { 12 } else { 15 };
    if area.width < 72 || area.height < minimum_height {
        render_micro(app, frame, area);
        render_result_details(app, frame, area, elapsed);
        return;
    }

    // The full 14-column table needs 153 (WIDTHS) + 13 column separators
    // + 2 border columns = 168 columns to render without clipping.
    if compact {
        render_compact(app, frame, area);
    } else {
        render_wide(app, frame, area);
    }

    render_result_details(app, frame, area, elapsed);
}

/// Progressive fallback for very small terminals. It keeps the live scan,
/// selection, status, and quit affordances usable instead of replacing the
/// product with a resize warning.
fn render_micro(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(4),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(area);
    render_micro_header(app, frame, chunks[0]);
    render_compact_stats(app, frame, chunks[1]);

    if app.dashboard_view != ScanDashboardView::Results {
        render_scan_view(app, frame, chunks[2], true);
        let isolated_work = app.investigation.is_some() || app.pending_isolation.is_some();
        let hints: &[widgets::KeyHint] = if app.scan_complete && isolated_work {
            &[("x", "stop"), ("q", "quit"), ("p", "resume"), ("o", "view")]
        } else if app.scan_complete {
            &[("q", "quit"), ("o", "view"), ("↑/↓", "select")]
        } else {
            &[("x", "stop"), ("q", "quit"), ("p", "pause"), ("o", "view")]
        };
        widgets::status_bar(frame, chunks[3], hints, app.visible_message());
        return;
    }
    let block = widgets::panel_block("Results — Enter details", app.focus_index == 0);
    let inner = block.inner(chunks[2]);
    app.table_inner = Some(inner);
    app.table_header = Some(Rect::new(inner.x, inner.y, inner.width, 1));
    app.table_col_indices = vec![0, 1, 8];
    app.table_col_bounds = vec![
        (inner.x, inner.x.saturating_add(4)),
        (inner.x.saturating_add(4), inner.x.saturating_add(4 + 12)),
        (inner.right().saturating_sub(10), inner.right()),
    ];
    let visible = inner.height.saturating_sub(1) as usize;
    let display_len = app.sorted_results().len().min(app.config.top);
    app.result_cursor = app.result_cursor.min(display_len.saturating_sub(1));
    let max_start = display_len.saturating_sub(visible);
    app.scroll = app
        .scroll
        .max(app.result_cursor.saturating_sub(visible.saturating_sub(1)))
        .min(app.result_cursor)
        .min(max_start);
    let sorted = app.sorted_results();
    let rows = sorted
        .iter()
        .skip(app.scroll)
        .take(visible)
        .enumerate()
        .map(|(index, result)| {
            let status = result_status(result);
            let selected = app.scroll + index == app.result_cursor;
            Row::new(vec![
                Cell::from(format!("{}", app.scroll + index + 1)),
                Cell::from(result.ip.clone()),
                Cell::from(fmt_ms(result.p95)),
                Cell::from(status),
            ])
            .style(if selected {
                theme::row_selected_style()
            } else {
                Style::default()
            })
        });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Min(12),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(["#", "IP", "P95", "Status"]).style(theme::title_style()))
        .block(block),
        chunks[2],
    );
    let isolated_work = app.investigation.is_some() || app.pending_isolation.is_some();
    let hints: &[widgets::KeyHint] = if app.scan_complete && isolated_work {
        &[("x", "stop"), ("q", "quit"), ("p", "resume")]
    } else if app.scan_complete {
        &[
            ("q", "quit"),
            ("↑/↓", "select"),
            (widgets::enter_key(), "details"),
        ]
    } else {
        &[
            ("x", "stop"),
            ("q", "quit"),
            ("p", "pause"),
            ("↑/↓", "select"),
        ]
    };
    widgets::status_bar(frame, chunks[3], hints, app.visible_message());
}

fn render_micro_header(app: &App, frame: &mut Frame, area: Rect) {
    let status = match app.scan_lifecycle {
        ScanLifecycle::Completed => "DONE",
        ScanLifecycle::Paused => "PAUSED",
        ScanLifecycle::Cancelling => "CANCELLING",
        ScanLifecycle::Failed => "FAILED",
        ScanLifecycle::Cancelled => "CANCELLED",
        ScanLifecycle::Running => "SCANNING",
    };
    let status_text = if status == "SCANNING" {
        format!("{} {}", widgets::spinner_frame(app.tick), status)
    } else {
        status.to_string()
    };
    widgets::app_header(
        frame,
        area,
        Some((&status_text, theme::status_style(status))),
        &[],
    );
}

fn render_wide(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(7), // Stats panel + failure summary
            Constraint::Length(2), // Dashboard view tabs
            Constraint::Min(1),    // Results table
            Constraint::Length(4), // Footer: buttons + status bar
        ])
        .split(area);

    render_header(app, frame, chunks[0]);
    let stats = Layout::vertical([Constraint::Length(6), Constraint::Length(1)]).split(chunks[1]);
    render_stats_panel(app, frame, stats[0]);
    render_failure_summary(app, frame, stats[1]);
    render_scan_tabs(app, frame, chunks[2]);
    render_scan_view(app, frame, chunks[3], false);
    render_footer(app, frame, chunks[4]);
}

fn render_compact(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(4), // Footer: buttons + status bar
        ])
        .split(area);
    render_header(app, frame, chunks[0]);
    render_compact_stats(app, frame, chunks[1]);
    render_scan_tabs(app, frame, chunks[2]);
    render_scan_view(app, frame, chunks[3], true);
    render_compact_footer(app, frame, chunks[4]);
}

fn render_scan_tabs(app: &mut App, frame: &mut Frame, area: Rect) {
    let labels = ScanDashboardView::ALL
        .iter()
        .map(|view| view.label())
        .collect::<Vec<_>>();
    let selected = ScanDashboardView::ALL
        .iter()
        .position(|view| *view == app.dashboard_view)
        .unwrap_or(0);

    // Compute actual rendered tab widths: each tab is " label " (padding on both sides),
    // separated by "│" divider (1 char). Layout is: " label1 │ label2 │ label3 "
    let mut x_offset = area.x;
    app.dashboard_tabs = ScanDashboardView::ALL
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let label = view.label();
            // Tab width: 1 (left padding) + label length + 1 (right padding)
            let tab_width = 1 + label.len() as u16 + 1;
            // Add divider width (1 char) if not the last tab
            let width_with_divider = if index + 1 < ScanDashboardView::ALL.len() {
                tab_width + 1
            } else {
                tab_width
            };
            let rect = Rect::new(x_offset, area.y, width_with_divider, area.height);
            x_offset = x_offset.saturating_add(width_with_divider);
            (rect, *view)
        })
        .collect();

    frame.render_widget(
        Tabs::new(labels)
            .select(selected)
            .highlight_style(theme::highlight_style())
            .divider("│")
            .padding(" ", " "),
        area,
    );
}

fn render_scan_view(app: &mut App, frame: &mut Frame, area: Rect, compact: bool) {
    match app.dashboard_view {
        ScanDashboardView::Results if compact => render_compact_table(app, frame, area),
        ScanDashboardView::Results => render_table(app, frame, area),
        ScanDashboardView::LiveTargets => render_live_targets(app, frame, area, compact),
        ScanDashboardView::RunLog => render_run_log(app, frame, area, compact),
    }
}

fn render_compact_stats(app: &App, frame: &mut Frame, area: Rect) {
    let (done, total) = progress_counts(app);
    let (scanned, succeeded, failed, waiting) = unique_ip_counts(app);
    let ratio = if total > 0 {
        done as f64 / total as f64
    } else {
        0.0
    };
    let block = widgets::panel_block("Scan status", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(inner);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(rows[0]);
    frame.render_widget(
        ratatui::widgets::LineGauge::default()
            .ratio(ratio.clamp(0.0, 1.0))
            .filled_style(theme::status_style("SCANNING"))
            .unfilled_style(theme::hint_style())
            .label(format!("{done}/{total}")),
        cols[0],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "IPs {scanned}/{total} • ok {succeeded} • fail {failed} • wait {waiting} • {} • {} probes • {} active",
            phase_label(app.scan_progress.phase),
            app.scan_progress.probes_completed,
            app.scan_progress.active_probes
        ))
        .style(theme::hint_style()),
        cols[1],
    );
    render_failure_summary(app, frame, rows[1]);
}

fn render_failure_summary(app: &App, frame: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let counts = app.scan_progress.failure_counts;
    let has_failures = counts.request_timeout > 0
        || counts.connect_timeout > 0
        || counts.connection_tls > 0
        || counts.general_errors > 0;
    let inspectable = app.results.iter().any(|result| {
        result.fail > 0 || !result.failures.is_empty() || !result.diagnostics.is_empty()
    });
    let suffix = if !has_failures {
        ""
    } else if app.show_failures {
        " • Enter details"
    } else if inspectable {
        " • f inspect"
    } else {
        " • details pending"
    };
    let narrow_suffix = if has_failures && inspectable && !app.show_failures {
        " • f"
    } else {
        ""
    };
    let mode = if failure_summary_line(counts, FailureSummaryMode::Wide, suffix).width()
        <= area.width as usize
    {
        FailureSummaryMode::Wide
    } else if failure_summary_line(counts, FailureSummaryMode::Compact, suffix).width()
        <= area.width as usize
    {
        FailureSummaryMode::Compact
    } else if failure_summary_line(counts, FailureSummaryMode::Narrow, narrow_suffix).width()
        <= area.width as usize
    {
        FailureSummaryMode::Narrow
    } else {
        FailureSummaryMode::Shortest
    };
    let line = failure_summary_line(
        counts,
        mode,
        if matches!(mode, FailureSummaryMode::Narrow) {
            narrow_suffix
        } else if matches!(mode, FailureSummaryMode::Shortest) {
            ""
        } else {
            suffix
        },
    );
    frame.render_widget(Paragraph::new(line), area);
}

#[derive(Clone, Copy)]
enum FailureSummaryMode {
    Wide,
    Compact,
    Narrow,
    Shortest,
}

fn failure_summary_line(
    counts: ProbeFailureCounts,
    mode: FailureSummaryMode,
    suffix: &str,
) -> Line<'static> {
    let mut spans = Vec::new();
    macro_rules! label {
        ($text:expr) => {
            spans.push(Span::styled($text.to_string(), theme::hint_style()))
        };
    }
    macro_rules! count {
        ($value:expr, $style:expr) => {
            spans.push(Span::styled($value.to_string(), $style))
        };
    }
    match mode {
        FailureSummaryMode::Wide => {
            spans.push(Span::styled(
                "Probe failures:".to_string(),
                theme::title_style(),
            ));
            label!(" Request timeout ");
            count!(counts.request_timeout, theme::warn_style());
            label!(" • Connect timeout ");
            count!(counts.connect_timeout, theme::warn_style());
            label!(" • Connection/TLS ");
            count!(counts.connection_tls, theme::bad_style());
            label!(" • General errors ");
            count!(counts.general_errors, theme::bad_style());
        }
        FailureSummaryMode::Compact => {
            spans.push(Span::styled("Failures:".to_string(), theme::title_style()));
            label!(" Req TO ");
            count!(counts.request_timeout, theme::warn_style());
            label!(" • Conn TO ");
            count!(counts.connect_timeout, theme::warn_style());
            label!(" • Conn/TLS ");
            count!(counts.connection_tls, theme::bad_style());
            label!(" • Errors ");
            count!(counts.general_errors, theme::bad_style());
        }
        FailureSummaryMode::Narrow => {
            spans.push(Span::styled("F".to_string(), theme::title_style()));
            label!(" rTO:");
            count!(counts.request_timeout, theme::warn_style());
            label!(" cTO:");
            count!(counts.connect_timeout, theme::warn_style());
            label!(" net:");
            count!(counts.connection_tls, theme::bad_style());
            label!(" err:");
            count!(counts.general_errors, theme::bad_style());
        }
        FailureSummaryMode::Shortest => {
            spans.push(Span::styled("F".to_string(), theme::title_style()));
            label!(" r:");
            count!(counts.request_timeout, theme::warn_style());
            label!(" c:");
            count!(counts.connect_timeout, theme::warn_style());
            label!(" n:");
            count!(counts.connection_tls, theme::bad_style());
            label!(" e:");
            count!(counts.general_errors, theme::bad_style());
        }
    }
    if !suffix.is_empty() {
        label!(suffix);
    }
    Line::from(spans)
}

fn render_compact_table(app: &mut App, frame: &mut Frame, area: Rect) {
    const COMPACT_COLUMNS: [(Option<usize>, &str, Constraint); 4] = [
        (Some(0), "#", Constraint::Length(5)),
        (Some(1), "IP", Constraint::Min(15)),
        (Some(8), "P95", Constraint::Length(12)),
        (None, "Status", Constraint::Length(10)),
    ];
    let mut compact_columns = COMPACT_COLUMNS
        .iter()
        .filter(|(source, _, _)| source.is_none_or(|index| app.column_visible(index)))
        .collect::<Vec<_>>();
    if !compact_columns
        .iter()
        .any(|(source, _, _)| source.is_some())
    {
        compact_columns.push(&COMPACT_COLUMNS[1]);
    }
    let widths = compact_columns
        .iter()
        .map(|(_, _, width)| *width)
        .collect::<Vec<_>>();
    let block = widgets::panel_block("Results — Enter details", app.focus_index == 0);
    let inner = block.inner(area);
    let column_rects = Layout::horizontal(widths.clone())
        .flex(Flex::Start)
        .spacing(1)
        .split(inner);
    app.table_header = Some(Rect::new(inner.x, inner.y, inner.width, 1));
    app.table_col_indices = compact_columns
        .iter()
        .filter_map(|(source, _, _)| *source)
        .collect();
    app.table_col_bounds.clear();
    app.table_col_bounds = column_rects
        .iter()
        .map(|rect| (rect.x, rect.right()))
        .collect();
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
        let status = result_status(r);
        let cells = compact_columns
            .iter()
            .map(|(source, label, _)| match (source, *label) {
                (Some(0), _) => Cell::from((index + 1).to_string()),
                (Some(1), _) => Cell::from(r.ip.clone()),
                (Some(8), _) => Cell::from(fmt_ms(r.p95)),
                (None, _) => {
                    let marker = status_marker(status);
                    Cell::from(format!("{marker} {status}")).style(match marker {
                        "OK" => theme::good_style(),
                        "WARN" => theme::warn_style(),
                        _ => theme::bad_style(),
                    })
                }
                _ => Cell::from("—"),
            })
            .collect::<Vec<_>>();
        Row::new(cells).style(if selected {
            theme::row_selected_style()
        } else if index % 2 == 1 {
            theme::row_alt_style()
        } else {
            Style::default()
        })
    });
    let headers = compact_columns
        .iter()
        .map(|(_, label, _)| *label)
        .collect::<Vec<_>>();
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(theme::title_style()))
        .block(block);
    frame.render_widget(table, area);
}

fn render_compact_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(1)])
        .split(area);
    let buttons = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(15),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Min(0),
            Constraint::Length(15),
            Constraint::Length(10),
        ])
        .split(layout[0]);
    let isolated_work = app.investigation.is_some() || app.pending_isolation.is_some();
    if app.scan_complete && isolated_work {
        app.button_ex(
            frame,
            buttons[0],
            "Resume (p)",
            ButtonAction::PauseResume,
            ButtonKind::Secondary,
            app.focus_index == 1,
        );
        app.button_ex(
            frame,
            buttons[1],
            "Stop (x)",
            ButtonAction::StopKeepResults,
            ButtonKind::Secondary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            buttons[2],
            "Customize (w)",
            ButtonAction::CustomizeScan,
            ButtonKind::Primary,
            app.focus_index == 3,
        );
        app.button_ex(
            frame,
            buttons[5],
            "Quit (q)",
            ButtonAction::Quit,
            ButtonKind::Secondary,
            app.focus_index == 4,
        );
    } else if app.scan_complete {
        app.button_ex(
            frame,
            buttons[0],
            "Export (e)",
            ButtonAction::Save,
            ButtonKind::Secondary,
            app.focus_index == 1,
        );
        app.button_ex(
            frame,
            buttons[1],
            "Speed test (t)",
            ButtonAction::SpeedTest,
            ButtonKind::Secondary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            buttons[2],
            "Customize (w)",
            ButtonAction::CustomizeScan,
            ButtonKind::Primary,
            app.focus_index == 3,
        );
        app.button_ex(
            frame,
            buttons[5],
            "Quit (q)",
            ButtonAction::Quit,
            ButtonKind::Secondary,
            app.focus_index == 4,
        );
    } else {
        app.button_ex(
            frame,
            buttons[0],
            if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
                "Resume (p)"
            } else {
                "Pause sched (p)"
            },
            ButtonAction::PauseResume,
            ButtonKind::Secondary,
            app.focus_index == 1,
        );
        app.button_ex(
            frame,
            buttons[1],
            "Workers − (,)",
            ButtonAction::WorkerDown,
            ButtonKind::Secondary,
            false,
        );
        app.button_ex(
            frame,
            buttons[3],
            "Auto workers (0)",
            ButtonAction::WorkerAuto,
            ButtonKind::Secondary,
            false,
        );
        app.button_ex(
            frame,
            buttons[2],
            "Workers + (.)",
            ButtonAction::WorkerUp,
            ButtonKind::Secondary,
            false,
        );
        app.button_ex(
            frame,
            buttons[4],
            "Stop + keep (x)",
            ButtonAction::StopKeepResults,
            ButtonKind::Secondary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            buttons[5],
            "Quit (q)",
            ButtonAction::Quit,
            ButtonKind::Secondary,
            app.focus_index == 3,
        );
    }
    let hints: &[widgets::KeyHint] = if app.scan_complete && isolated_work {
        &[
            ("Tab", "focus"),
            ("p", "resume"),
            ("x", "stop"),
            ("w", "customize"),
            ("q", "quit"),
        ]
    } else if app.scan_complete {
        &[
            ("Tab", "focus"),
            (widgets::enter_key(), "details"),
            ("e", "export"),
            ("t", "speed"),
            ("f", "failures"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("Tab", "focus"),
            (widgets::enter_key(), "details"),
            ("o", "view"),
            ("Space", "select"),
            ("i", "isolate"),
            ("p", "pause scheduling"),
            ("x", "stop + keep"),
            ("w", "edit + restart"),
            ("[ ] , .", "workers"),
            ("0", "auto workers"),
            ("c", "copy"),
            ("/", "commands"),
            ("?", "help"),
            ("Esc", "cancel"),
            ("q", "quit"),
        ]
    };
    widgets::status_bar(frame, layout[1], hints, app.visible_message());
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

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    let Some(result) = app.sorted_results().into_iter().nth(app.result_cursor) else {
        if let Some(error) = &app.scan_error {
            render_detail_text(
                frame,
                chunks[2],
                vec![
                    Line::from(Span::styled("Scan worker failure", theme::subtitle_style())),
                    Line::from(error.clone()),
                ],
            );
        }
        return;
    };

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
            if result.failures.is_empty() && result.diagnostics.is_empty() {
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
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
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

    let status = match app.scan_lifecycle {
        ScanLifecycle::Completed if app.watch_due.is_some() => "WATCH",
        ScanLifecycle::Completed => "DONE",
        ScanLifecycle::Paused => "PAUSED",
        ScanLifecycle::Cancelling => "CANCELLING",
        ScanLifecycle::Failed => "FAILED",
        ScanLifecycle::Cancelled => "CANCELLED",
        ScanLifecycle::Running => "SCANNING",
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
            widgets::HeaderSegment::new("IP", app.system_network.public_ip_display()),
            widgets::HeaderSegment::new("ASN", app.system_network.asn_display()),
            widgets::HeaderSegment::new("ISP", app.system_network.isp_display()),
            widgets::HeaderSegment::new("Elapsed", elapsed_str),
        ],
    );
}

fn phase_label(phase: crate::scanner::ScanPhase) -> &'static str {
    match phase {
        crate::scanner::ScanPhase::Starting => "starting",
        crate::scanner::ScanPhase::WarmingUp => "warming up",
        crate::scanner::ScanPhase::Probing => "probing",
        crate::scanner::ScanPhase::Finalizing => "finalizing",
        crate::scanner::ScanPhase::Discovery => "discovery",
        crate::scanner::ScanPhase::Focus => "focus pass",
    }
}

fn progress_counts(app: &App) -> (usize, usize) {
    let completed = app.scan_progress.targets_completed;
    let total = app
        .total_targets
        .max(app.scan_progress.targets_total.unwrap_or(0))
        .max(completed);
    (completed.min(total), total)
}

fn unique_ip_counts(app: &App) -> (usize, usize, usize, usize) {
    // A result is terminal for a single port/check, not necessarily for the
    // IP. During multi-port, profile, or two-phase scans an all-failure
    // partial result must remain unresolved until the whole scan completes.
    let has_pending_ip_work =
        app.config.ports.len() > 1 || !app.config.health_checks.is_empty() || app.config.two_phase;
    let succeeded = app.scan_succeeded_ips.len();
    let failed = if has_pending_ip_work && !app.scan_complete {
        0
    } else {
        app.scan_result_ips.len().saturating_sub(succeeded)
    };
    let total = app
        .total_targets
        .max(app.scan_progress.targets_total.unwrap_or(0));
    let waiting = total.saturating_sub(app.scan_started_ips.len());
    // "Scanned" means work has started for the unique IP, including active
    // and warmup work. This keeps scanned + waiting == total.
    (app.scan_started_ips.len(), succeeded, failed, waiting)
}

fn render_stats_panel(app: &App, frame: &mut Frame, area: Rect) {
    if app.scan_complete && app.scan_lifecycle == ScanLifecycle::Completed {
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

    let (passed, total) = progress_counts(app);
    let (scanned_ips, succeeded_ips, failed_ips, waiting_ips) = unique_ip_counts(app);
    let pct = if total > 0 {
        (passed as f64 / total as f64 * 100.0) as u16
    } else {
        0
    };

    // Calculate rates and ETA
    let terminal_label = match app.scan_lifecycle {
        ScanLifecycle::Completed => Some("Finished"),
        ScanLifecycle::Failed => Some("Failed"),
        ScanLifecycle::Cancelled => Some("Cancelled"),
        ScanLifecycle::Cancelling => Some("Cancelling"),
        ScanLifecycle::Running | ScanLifecycle::Paused => None,
    };
    let terminal_style = match app.scan_lifecycle {
        ScanLifecycle::Completed => theme::good_style(),
        ScanLifecycle::Failed => theme::bad_style(),
        ScanLifecycle::Cancelled | ScanLifecycle::Cancelling => theme::warn_style(),
        ScanLifecycle::Running | ScanLifecycle::Paused => theme::status_style("SCANNING"),
    };
    let mut rate_str = "calculating".to_string();
    let mut eta_str = "--:--".to_string();
    if !app.scan_complete && total > 0 && app.scan_progress.probes_completed > 0 {
        let now = Instant::now();
        let (first_at, first_count) = app
            .probe_rate_history
            .first()
            .copied()
            .unwrap_or((app.start_time, 0));
        let elapsed = now
            .checked_duration_since(first_at)
            .unwrap_or_default()
            .as_secs_f64();
        let rate = app
            .scan_progress
            .probes_completed
            .saturating_sub(first_count) as f64
            / elapsed.max(0.001);
        let remaining = total.saturating_sub(passed);
        let target_rate = passed as f64 / elapsed.max(0.001);
        rate_str = format!("{:.1} probes/s", rate);
        if target_rate > 0.0 {
            let eta = (remaining as f64 / target_rate).max(0.0);
            eta_str = format!("{:02}:{:02}", eta as u64 / 60, eta as u64 % 60);
        }
    } else if let Some(label) = terminal_label {
        rate_str = label.to_string();
        eta_str = "--:--".to_string();
    }

    // Panel 1: Progress gauge + throughput / workers.
    let block_p1 = widgets::panel_block("Progress", false);
    let p1_inner = block_p1.inner(col_chunks[0]);
    frame.render_widget(block_p1, col_chunks[0]);
    let p1_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // gauge
            Constraint::Length(1), // unique IP counters
            Constraint::Length(1), // probe counters
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
        .filled_style(terminal_style)
        .unfilled_style(theme::hint_style())
        .label(Span::styled(
            format!("{passed}/{total} ({pct}%)"),
            theme::title_style(),
        ))
        .ratio(ratio);
    frame.render_widget(gauge, p1_rows[0]);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Unique IPs: ", theme::title_style()),
            Span::raw(format!(
                "{} scanned • {} succeeded • {} failed • {} waiting",
                scanned_ips, succeeded_ips, failed_ips, waiting_ips,
            )),
        ])),
        p1_rows[1],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Probes: ", theme::title_style()),
            Span::raw(format!(
                "{}/{} • {}/{} completed • {} active",
                passed,
                total,
                app.scan_progress.probes_completed,
                app.scan_progress.probes_started,
                app.scan_progress.active_probes,
            )),
        ])),
        p1_rows[2],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Activity / ETA: ", theme::title_style()),
            Span::raw(format!(
                "{} • {} • {}{}",
                phase_label(app.scan_progress.phase),
                rate_str,
                eta_str,
                app.scan_progress
                    .latest_target
                    .as_deref()
                    .map(|ip| format!(" • {}", ip))
                    .unwrap_or_default(),
            )),
        ])),
        p1_rows[3],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Workers  : ", theme::title_style()),
            Span::raw(format!(
                "{}{} concurrent • {} probes/IP",
                app.scan_progress
                    .current_workers
                    .unwrap_or(app.config.concurrency),
                if app.config.adaptive_concurrency {
                    format!(
                        " [{}–{}] adaptive",
                        app.config.min_concurrency, app.config.max_concurrency
                    )
                } else {
                    String::new()
                },
                app.config.probes
            )),
        ])),
        p1_rows[4],
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
    let block_p2 = widgets::subtle_panel_block("Latency & Throughput");
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

    // Panel 3: live outcome distribution and factual activity timing.
    if !app.scan_complete {
        let failures = app.scan_progress.failure_counts;
        let failure_total = failures
            .request_timeout
            .saturating_add(failures.connect_timeout)
            .saturating_add(failures.connection_tls)
            .saturating_add(failures.general_errors);
        let successes = app
            .scan_progress
            .probes_completed
            .saturating_sub(failure_total);
        let bars = [
            ("success", successes as u64, theme::good_style()),
            (
                "request timeout",
                failures.request_timeout as u64,
                theme::warn_style(),
            ),
            (
                "connect / TLS",
                failures
                    .connect_timeout
                    .saturating_add(failures.connection_tls) as u64,
                theme::bad_style(),
            ),
            (
                "other error",
                failures.general_errors as u64,
                theme::bad_style(),
            ),
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
        let block = widgets::subtle_panel_block("Probe Outcomes & Activity");
        let inner = block.inner(col_chunks[2]);
        frame.render_widget(block, col_chunks[2]);
        let rows = Layout::vertical([Constraint::Min(2), Constraint::Length(2)]).split(inner);
        frame.render_widget(
            BarChart::default()
                .data(BarGroup::default().bars(&bars))
                .direction(Direction::Horizontal)
                .bar_width(1)
                .bar_gap(0)
                .max(app.scan_progress.probes_completed.max(1) as u64)
                .label_style(theme::hint_style()),
            rows[0],
        );
        let now = Instant::now();
        let since_completion = app
            .last_completion_at
            .map(|at| format!("{} ago", format_duration(now.saturating_duration_since(at))))
            .unwrap_or_else(|| "none yet".to_string());
        let oldest = app
            .target_activity
            .values()
            .filter(|target| matches!(target.stage, TargetStage::WarmingUp | TargetStage::Probing))
            .filter_map(|target| target.first_activity)
            .min()
            .map(|at| format_duration(now.saturating_duration_since(at)))
            .unwrap_or_else(|| "—".to_string());
        let recent = app
            .scan_events
            .front()
            .map(|entry| entry.event.message.as_str())
            .unwrap_or("waiting for scanner activity");
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(format!(
                    "Last completion {since_completion} • oldest active {oldest}"
                )),
                Line::from(format!("Recent: {recent}")),
            ])
            .style(theme::hint_style()),
            rows[1],
        );
        return;
    }

    // Completed scans return to the latency distribution decision aid.
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

    let block_p3 = widgets::subtle_panel_block("Latency Spread");
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
                (
                    format!("{} {}", widgets::best_marker(), r.ip),
                    format!(" {rank}"),
                )
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
        } else if app.results.is_empty() {
            "Preparing probes… no target has completed yet."
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

fn render_live_targets(app: &mut App, frame: &mut Frame, area: Rect, compact: bool) {
    let micro = area.width < 72;
    let columns = if micro {
        vec![
            Constraint::Length(4),
            Constraint::Min(12),
            Constraint::Length(9),
            Constraint::Length(7),
        ]
    } else if compact {
        vec![
            Constraint::Length(4),
            Constraint::Min(16),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(8),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Min(18),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Min(24),
        ]
    };
    let panes = if compact {
        Layout::horizontal([Constraint::Percentage(100), Constraint::Length(0)]).split(area)
    } else {
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).split(area)
    };
    let query = if app.target_query.is_empty() {
        String::new()
    } else {
        format!(" • search {}", app.target_query)
    };
    let isolation = app
        .investigation
        .as_ref()
        .map(|investigation| {
            format!(
                " • isolated {} {}",
                investigation.target,
                investigation.activity.stage.label()
            )
        })
        .unwrap_or_default();
    let title = format!(
        "Live targets — filter {} • sort {}{}{}",
        app.target_filter.label(),
        app.target_sort.label(),
        query,
        isolation
    );
    let block = widgets::panel_block(&title, true);
    let inner = block.inner(panes[0]);
    app.table_inner = Some(inner);
    let visible = inner.height.saturating_sub(1) as usize;
    let target_ips = app.visible_target_ips();
    app.target_cursor = app.target_cursor.min(target_ips.len().saturating_sub(1));
    let max_start = target_ips.len().saturating_sub(visible);
    app.target_scroll = app
        .target_scroll
        .max(app.target_cursor.saturating_sub(visible.saturating_sub(1)))
        .min(app.target_cursor)
        .min(max_start);
    let start = app.target_scroll;
    app.target_render_start = start;
    let now = Instant::now();
    let rows = target_ips
        .iter()
        .skip(start)
        .take(visible)
        .enumerate()
        .filter_map(|(offset, ip)| {
            let target = app.target_activity.get(ip)?;
            let selected = start + offset == app.target_cursor;
            let marked = app.selected_targets.contains(&target.ip);
            let age = target
                .first_activity
                .map(|at| format_duration(now.saturating_duration_since(at)))
                .unwrap_or_else(|| "—".to_string());
            let idle = target
                .last_activity
                .map(|at| format_duration(now.saturating_duration_since(at)))
                .unwrap_or_else(|| "—".to_string());
            let mut cells = vec![
                Cell::from(if marked { "[x]" } else { "[ ]" }),
                Cell::from(target.ip.clone()),
                Cell::from(target.stage.label()),
            ];
            if micro {
                cells.push(Cell::from(age));
            } else {
                cells.push(Cell::from(format!(
                    "{}/{}",
                    target.probes_completed, target.probes_started
                )));
                cells.push(Cell::from(age));
            }
            if !compact && !micro {
                cells.push(Cell::from(idle));
                cells.push(Cell::from(target.last_outcome.clone()));
            }
            Some(Row::new(cells).style(if selected {
                theme::row_selected_style()
            } else {
                match target.stage {
                    TargetStage::Finalized if target.failures > 0 => theme::warn_style(),
                    TargetStage::Finalized => theme::good_style(),
                    _ => Style::default(),
                }
            }))
        });
    let headers = if micro {
        vec!["Sel", "IP", "Stage", "Age"]
    } else if compact {
        vec!["Sel", "IP", "Stage", "Done", "Age"]
    } else {
        vec![
            "Sel",
            "IP",
            "Stage",
            "Done/Start",
            "Age",
            "Idle",
            "Last event",
        ]
    };
    frame.render_widget(
        Table::new(rows, columns)
            .header(Row::new(headers).style(theme::title_style()))
            .block(block),
        panes[0],
    );

    if !compact {
        let selected = target_ips
            .get(app.target_cursor)
            .and_then(|ip| app.target_activity.get(ip));
        let mut lines = Vec::new();
        if let Some(target) = selected {
            lines.extend([
                Line::from(Span::styled(target.ip.clone(), theme::header_style())),
                Line::from(format!("Stage       : {}", target.stage.label())),
                Line::from(format!(
                    "Probe work  : {} started / {} completed / {} failed",
                    target.probes_started, target.probes_completed, target.failures
                )),
                Line::from(format!(
                    "Active for  : {}",
                    target
                        .first_activity
                        .map(|at| format_duration(now.saturating_duration_since(at)))
                        .unwrap_or_else(|| "not started".to_string())
                )),
                Line::from(format!(
                    "Last change : {} ago",
                    target
                        .last_activity
                        .map(|at| format_duration(now.saturating_duration_since(at)))
                        .unwrap_or_else(|| "—".to_string())
                )),
                Line::from(format!("Outcome     : {}", target.last_outcome)),
            ]);
            if let Some(investigation) = app
                .investigation
                .as_ref()
                .filter(|investigation| investigation.target == target.ip)
            {
                lines.extend([
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Isolated run #{}", investigation.id),
                        theme::subtitle_style(),
                    )),
                    Line::from(format!(
                        "{} • {} results • {} elapsed",
                        investigation.activity.stage.label(),
                        investigation.results.len(),
                        format_duration(investigation.started_at.elapsed())
                    )),
                    Line::from(format!(
                        "Last event   : {}",
                        investigation.activity.last_outcome
                    )),
                ]);
            }
            lines.extend([
                Line::from(""),
                Line::from(Span::styled(
                    "Recent primary scanner events",
                    theme::subtitle_style(),
                )),
            ]);
            for event in app
                .scan_events
                .iter()
                .filter(|entry| entry.event.target.as_deref() == Some(target.ip.as_str()))
                .take(6)
            {
                lines.push(Line::from(format!(
                    "{}  {}",
                    format_duration(event.elapsed),
                    event.event.message
                )));
            }
        } else {
            lines.push(Line::from("No target activity yet."));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(widgets::subtle_panel_block("Target inspector")),
            panes[1],
        );
    }
}

fn render_run_log(app: &mut App, frame: &mut Frame, area: Rect, compact: bool) {
    let micro = area.width < 72 || area.height < 12;
    let panes = if micro {
        Layout::horizontal([Constraint::Percentage(100), Constraint::Length(0)]).split(area)
    } else if compact {
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area)
    } else {
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area)
    };
    let table_block = widgets::panel_block("Session runs — newest first", true);
    let table_inner = table_block.inner(panes[0]);
    app.table_inner = Some(table_inner);
    let has_investigation = app.investigation.is_some();
    let total_runs = app.run_log_len();
    let visible = table_inner.height.saturating_sub(1) as usize;
    app.run_cursor = app.run_cursor.min(total_runs.saturating_sub(1));
    let max_start = total_runs.saturating_sub(visible);
    app.run_scroll = app
        .run_scroll
        .max(app.run_cursor.saturating_sub(visible.saturating_sub(1)))
        .min(app.run_cursor)
        .min(max_start);
    app.run_render_start = app.run_scroll;
    let current_status = match app.scan_lifecycle {
        ScanLifecycle::Running => "RUNNING",
        ScanLifecycle::Paused => "PAUSED",
        ScanLifecycle::Cancelling => "STOPPING",
        ScanLifecycle::Completed => "DONE",
        ScanLifecycle::Failed => "FAILED",
        ScanLifecycle::Cancelled => "STOPPED",
    };
    let row_for = |index: usize,
                   id: String,
                   kind: RunKind,
                   targets: usize,
                   results: usize,
                   elapsed: Duration,
                   state: &'static str| {
        let cells = if micro {
            vec![
                Cell::from(id),
                Cell::from(kind.label()),
                Cell::from(state),
                Cell::from(results.to_string()),
                Cell::from(format_duration(elapsed)),
            ]
        } else {
            vec![
                Cell::from(id),
                Cell::from(kind.label()),
                Cell::from(targets.to_string()),
                Cell::from(results.to_string()),
                Cell::from(format_duration(elapsed)),
                Cell::from(state),
            ]
        };
        Row::new(cells).style(if app.run_cursor == index {
            theme::row_selected_style()
        } else if index == 0 {
            theme::highlight_style()
        } else {
            Style::default()
        })
    };
    let mut rows = vec![row_for(
        0,
        format!("#{}", app.current_run_id),
        app.active_run_kind,
        app.active_targets.len(),
        app.results.len(),
        app.start_time.elapsed(),
        current_status,
    )];
    if let Some(investigation) = &app.investigation {
        rows.push(row_for(
            1,
            format!("#{}", investigation.id),
            RunKind::Investigation,
            1,
            investigation.results.len(),
            investigation.started_at.elapsed(),
            "RUNNING",
        ));
    }
    let history_offset = 1 + usize::from(has_investigation);
    rows.extend(app.run_history.iter().enumerate().map(|(index, run)| {
        row_for(
            index + history_offset,
            format!("#{}", run.id),
            run.kind,
            run.targets.len(),
            run.results.len(),
            run.elapsed,
            lifecycle_label(run.lifecycle),
        )
    }));
    let rows = rows
        .into_iter()
        .skip(app.run_scroll)
        .take(visible)
        .collect::<Vec<_>>();
    let (headers, widths) = if micro {
        (
            vec!["Run", "Kind", "State", "Results", "Elapsed"],
            vec![
                Constraint::Length(7),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Min(7),
            ],
        )
    } else {
        (
            vec!["Run", "Kind", "Targets", "Results", "Elapsed", "State"],
            vec![
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
    };
    frame.render_widget(
        Table::new(rows, widths)
            .header(Row::new(headers).style(theme::title_style()))
            .block(table_block),
        panes[0],
    );

    if micro {
        return;
    }

    let (id, source_run_id, kind, results, targets, elapsed) = if app.run_cursor == 0 {
        (
            app.current_run_id,
            app.current_source_run_id,
            app.active_run_kind,
            app.results.as_slice(),
            app.active_targets.as_slice(),
            app.start_time.elapsed(),
        )
    } else if app.run_cursor == 1 && has_investigation {
        let investigation = app
            .investigation
            .as_ref()
            .expect("active investigation checked");
        (
            investigation.id,
            Some(investigation.source_run_id),
            RunKind::Investigation,
            investigation.results.as_slice(),
            std::slice::from_ref(&investigation.target),
            investigation.started_at.elapsed(),
        )
    } else if let Some(run) = app.run_history.get(app.run_cursor - history_offset) {
        (
            run.id,
            run.source_run_id,
            run.kind,
            run.results.as_slice(),
            run.targets.as_slice(),
            run.elapsed,
        )
    } else {
        (
            app.current_run_id,
            app.current_source_run_id,
            RunKind::Full,
            app.results.as_slice(),
            app.active_targets.as_slice(),
            Duration::ZERO,
        )
    };
    let ok = results.iter().filter(|result| result.ok > 0).count();
    let failed = results.len().saturating_sub(ok);
    let mut lines = vec![
        Line::from(Span::styled(
            format!("#{id} {} run", kind.label()),
            theme::header_style(),
        )),
        Line::from(format!("Targets     : {}", targets.len())),
        Line::from(format!(
            "Results     : {} ({ok} responsive / {failed} failed)",
            results.len()
        )),
        Line::from(format!("Elapsed     : {}", format_duration(elapsed))),
    ];
    lines.push(Line::from(""));
    lines.extend(comparison_lines(app, id, source_run_id, results));
    lines.extend([
        Line::from(""),
        Line::from(format!("Retained runs: {}/10", app.run_history.len())),
        Line::from(format!("Retained events: {}/1000", app.scan_events.len())),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(widgets::subtle_panel_block("Run details & deltas")),
        panes[1],
    );
}

fn lifecycle_label(lifecycle: ScanLifecycle) -> &'static str {
    match lifecycle {
        ScanLifecycle::Completed => "DONE",
        ScanLifecycle::Cancelled => "STOPPED",
        ScanLifecycle::Failed => "FAILED",
        ScanLifecycle::Paused => "PAUSED",
        ScanLifecycle::Cancelling => "STOPPING",
        ScanLifecycle::Running => "RUNNING",
    }
}

fn canonical_results_by_ip(results: &[ProbeResult]) -> BTreeMap<&str, &ProbeResult> {
    let mut by_ip = BTreeMap::new();
    for result in results {
        let rank = (
            usize::from(!result.port_results.is_empty()),
            result.checks.len(),
            result.completed,
        );
        by_ip
            .entry(result.ip.as_str())
            .and_modify(|current: &mut &ProbeResult| {
                let current_rank = (
                    usize::from(!current.port_results.is_empty()),
                    current.checks.len(),
                    current.completed,
                );
                if rank > current_rank {
                    *current = result;
                }
            })
            .or_insert(result);
    }
    by_ip
}

fn comparison_lines(
    app: &App,
    run_id: u64,
    source_run_id: Option<u64>,
    results: &[ProbeResult],
) -> Vec<Line<'static>> {
    let Some(source_id) = source_run_id.filter(|source_id| *source_id != run_id) else {
        return vec![Line::from(Span::styled(
            "No source run is linked.",
            theme::hint_style(),
        ))];
    };
    let source_results = if source_id == app.current_run_id {
        Some(app.results.as_slice())
    } else {
        app.run_history
            .iter()
            .find(|run| run.id == source_id)
            .map(|run| run.results.as_slice())
    };
    let Some(source_results) = source_results else {
        return vec![Line::from(Span::styled(
            format!("Source run #{source_id} is no longer retained."),
            theme::hint_style(),
        ))];
    };
    let mut lines = vec![Line::from(Span::styled(
        format!("Compared with source run #{source_id}"),
        theme::subtitle_style(),
    ))];
    let source_by_ip = canonical_results_by_ip(source_results);
    let result_by_ip = canonical_results_by_ip(results);
    let mut matched = 0usize;
    for (ip, result) in result_by_ip {
        let Some(source) = source_by_ip.get(ip).copied() else {
            continue;
        };
        matched += 1;
        lines.push(Line::from(format!(
            "{}  avg {:+.1}ms • p95 {:+.1}ms • loss {:+.1}pp • success {:+.1}pp",
            ip,
            (result.avg - source.avg) * 1000.0,
            (result.p95 - source.p95) * 1000.0,
            (result.packet_loss - source.packet_loss) * 100.0,
            (result.success_rate - source.success_rate) * 100.0,
        )));
        lines.push(Line::from(format!(
            "  {}→{} • colo {}→{} • diagnostics {:+}",
            result_status(source),
            result_status(result),
            source.colo.as_deref().unwrap_or("—"),
            result.colo.as_deref().unwrap_or("—"),
            result.diagnostics.len() as isize - source.diagnostics.len() as isize,
        )));
    }
    if matched == 0 {
        lines.push(Line::from(Span::styled(
            "No matching IPs exist in the linked source run.",
            theme::hint_style(),
        )));
    } else {
        lines.insert(1, Line::from(format!("Matched IPs : {matched}")));
    }
    lines
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else if seconds > 0 {
        format!("{seconds}s")
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn fmt_ms(sec: f64) -> String {
    format!("{:.1}ms", sec * 1000.0)
}

fn status_marker(status: &str) -> &'static str {
    match status {
        "READY" | "HEALTHY" => "OK",
        "DEGRADED" | "SLOW" => "WARN",
        _ => "FAIL",
    }
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
    let footer_rows = Layout::vertical([Constraint::Length(3), Constraint::Length(1)]).split(area);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Min(0),
            Constraint::Length(18),
            Constraint::Length(12),
        ])
        .split(footer_rows[0]);

    let isolated_work = app.investigation.is_some() || app.pending_isolation.is_some();
    let left_action = if app.scan_complete && isolated_work {
        ButtonAction::PauseResume
    } else if app.scan_complete {
        ButtonAction::Save
    } else {
        ButtonAction::PauseResume
    };
    let left_label = if app.scan_complete && isolated_work {
        "Resume scheduling (p)"
    } else if app.scan_complete {
        "Export (e)"
    } else if app.paused.load(std::sync::atomic::Ordering::Relaxed) {
        "Resume (p)"
    } else {
        "Pause (p)"
    };
    let left_kind = if app.scan_complete && !isolated_work {
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

    if app.scan_complete && isolated_work {
        app.button_ex(
            frame,
            chunks[1],
            "Stop + keep (x)",
            ButtonAction::StopKeepResults,
            ButtonKind::Secondary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            chunks[2],
            "Customize (w)",
            ButtonAction::CustomizeScan,
            ButtonKind::Primary,
            app.focus_index == 3,
        );
    } else if app.scan_complete {
        app.button_ex(
            frame,
            chunks[1],
            "Speed test (t)",
            ButtonAction::SpeedTest,
            ButtonKind::Primary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            chunks[2],
            "Customize (w)",
            ButtonAction::CustomizeScan,
            ButtonKind::Primary,
            app.focus_index == 3,
        );
    } else {
        app.button_ex(
            frame,
            chunks[1],
            "Workers − (,)",
            ButtonAction::WorkerDown,
            ButtonKind::Secondary,
            false,
        );
        app.button_ex(
            frame,
            chunks[3],
            "Auto workers (0)",
            ButtonAction::WorkerAuto,
            ButtonKind::Secondary,
            false,
        );
        app.button_ex(
            frame,
            chunks[2],
            "Workers + (.)",
            ButtonAction::WorkerUp,
            ButtonKind::Secondary,
            false,
        );
    }
    if app.scan_complete {
        app.button_ex(
            frame,
            chunks[5],
            "Quit (q)",
            ButtonAction::Quit,
            ButtonKind::Secondary,
            app.focus_index == 4,
        );
    } else {
        app.button_ex(
            frame,
            chunks[4],
            "Stop + keep (x)",
            ButtonAction::StopKeepResults,
            ButtonKind::Secondary,
            app.focus_index == 2,
        );
        app.button_ex(
            frame,
            chunks[5],
            "Quit (q)",
            ButtonAction::Quit,
            ButtonKind::Secondary,
            app.focus_index == 3,
        );
    }

    let hints: &[widgets::KeyHint] = if app.scan_complete && isolated_work {
        &[
            ("Tab", "focus"),
            ("p", "resume scheduling"),
            ("x", "stop + keep"),
            ("w", "customize"),
            ("q", "quit"),
        ]
    } else if app.scan_complete {
        &[
            ("Tab", "focus"),
            (widgets::enter_key(), "details"),
            ("o", "view"),
            ("Space", "select"),
            ("R", "rerun selected"),
            ("c", "copy"),
            ("e", "export"),
            ("t", "speed test"),
            ("f", "show failures"),
            ("v", "columns"),
            ("r", "rerun targets"),
            ("n", "new sample"),
            ("m", "comparison export"),
            ("w", "customize"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("Tab", "focus"),
            (widgets::enter_key(), "details"),
            ("o", "view"),
            ("Space", "select"),
            ("i", "isolate"),
            ("p", "pause scheduling"),
            ("x", "stop + keep"),
            ("w", "edit + restart"),
            ("c", "copy"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    widgets::status_bar(frame, footer_rows[1], hints, app.visible_message());
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_results_by_ip, failure_summary_line, latency_bucket, latency_summary, median,
        recommendation_ip, selected_latency_index, unique_ip_counts, FailureSummaryMode,
    };
    use crate::config::AppConfig;
    use crate::scanner::{ProbeFailureCounts, ProbeResult};
    use crate::tui::{App, ScanLifecycle};
    use std::sync::{atomic::AtomicBool, Arc};

    #[test]
    fn failure_summary_uses_explicit_labels_and_exact_counts() {
        let counts = ProbeFailureCounts {
            request_timeout: 12,
            connect_timeout: 3,
            connection_tls: 2,
            general_errors: 4,
        };
        let text = "Probe failures: Request timeout 12 • Connect timeout 3 • Connection/TLS 2 • General errors 4";
        let line = failure_summary_line(counts, FailureSummaryMode::Wide, "");
        let rendered = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(rendered, text);
    }

    #[test]
    fn failure_summary_width_uses_terminal_cells_not_utf8_bytes() {
        let counts = ProbeFailureCounts {
            request_timeout: 12,
            connect_timeout: 3,
            connection_tls: 2,
            general_errors: 4,
        };
        let line = failure_summary_line(counts, FailureSummaryMode::Wide, "");
        let rendered = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(line.width() < rendered.len());
        assert_eq!(line.width(), rendered.chars().count());
    }

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
    fn comparison_canonicalization_emits_one_aggregate_result_per_ip() {
        let port_443 = result("192.0.2.1", 1.0, &[0.010, 0.011]);
        let mut aggregate = result("192.0.2.1", 1.0, &[0.010, 0.011, 0.020, 0.021]);
        aggregate.port = 8443;
        let port_8443 = result("192.0.2.1", 1.0, &[0.020, 0.021]);
        let results = vec![port_443, port_8443, aggregate];

        let canonical = canonical_results_by_ip(&results);
        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical["192.0.2.1"].completed, 4);
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

    #[test]
    fn unique_ip_counts_deduplicate_ports_and_defer_partial_failures() {
        let mut app = App::new(
            AppConfig {
                ports: vec![443, 8443],
                ..AppConfig::default()
            },
            false,
            Arc::new(AtomicBool::new(false)),
        );
        app.total_targets = 3;
        app.scan_started_ips
            .extend(["192.0.2.1".to_string(), "192.0.2.2".to_string()]);
        app.add_result(result("192.0.2.1", 1.0, &[0.1]));
        let mut second_port_success = result("192.0.2.1", 0.9, &[0.2]);
        second_port_success.port = 8443;
        app.add_result(second_port_success);
        let mut failed = result("192.0.2.2", 0.0, &[]);
        failed.ok = 0;
        failed.fail = 1;
        failed.completed = 1;
        failed.health_ok = false;
        app.add_result(failed);

        assert_eq!(unique_ip_counts(&app), (2, 1, 0, 1));

        app.scan_complete = true;
        app.scan_lifecycle = ScanLifecycle::Completed;
        assert_eq!(unique_ip_counts(&app), (2, 1, 1, 1));
    }

    #[test]
    fn unique_ip_counts_show_terminal_failure_for_single_port() {
        let mut app = App::new(
            AppConfig {
                ports: vec![443],
                ..AppConfig::default()
            },
            false,
            Arc::new(AtomicBool::new(false)),
        );
        app.total_targets = 1;
        app.scan_started_ips.insert("192.0.2.9".to_string());
        let mut failed = result("192.0.2.9", 0.0, &[]);
        failed.ok = 0;
        failed.fail = 1;
        failed.completed = 1;
        failed.health_ok = false;
        app.add_result(failed);
        assert_eq!(unique_ip_counts(&app), (1, 0, 1, 0));
    }

    #[test]
    fn unique_ip_success_wins_over_failure_across_ports() {
        let mut app = App::new(
            AppConfig {
                ports: vec![443, 8443],
                ..AppConfig::default()
            },
            false,
            Arc::new(AtomicBool::new(false)),
        );
        app.total_targets = 1;
        app.scan_started_ips.insert("192.0.2.10".to_string());
        let mut failed = result("192.0.2.10", 0.0, &[]);
        failed.ok = 0;
        failed.fail = 1;
        failed.completed = 1;
        failed.health_ok = false;
        app.add_result(failed);
        app.add_result(result("192.0.2.10", 1.0, &[0.1]));
        app.scan_complete = true;
        app.scan_lifecycle = ScanLifecycle::Completed;

        assert_eq!(unique_ip_counts(&app), (1, 1, 0, 0));
    }
}
