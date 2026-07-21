use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::speed::SpeedDirection;
use crate::tui::{theme, widgets, App, ButtonAction, ButtonKind, ScanLifecycle, Screen};

pub fn render(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(app, frame, chunks[0]);
    match app.screen {
        Screen::SpeedSelect => render_selection(app, frame, chunks[1]),
        Screen::SpeedTesting => render_testing(app, frame, chunks[1]),
        Screen::SpeedResults => render_results(app, frame, chunks[1]),
        _ => {}
    }
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let title = if app.scan_lifecycle == ScanLifecycle::Cancelling {
        "CANCELLING SPEED TESTS"
    } else {
        match app.screen {
            Screen::SpeedSelect => "SELECT SPEED TEST TARGETS",
            Screen::SpeedTesting => "RUNNING SPEED TESTS",
            Screen::SpeedResults => "SPEED TEST RESULTS",
            _ => "SPEED TEST",
        }
    };
    widgets::app_header(
        frame,
        area,
        Some((title, theme::highlight_style())),
        &[widgets::HeaderSegment::new("Host", app.config.host.clone())],
    );
}

fn render_selection(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);
    let block = widgets::panel_block(
        "Speed-test targets — click or Space to select",
        app.focus_index == 0,
    );
    let inner = block.inner(chunks[0]);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);
    let search_label = if app.speed_search_mode {
        format!(" Search: {}▌", app.speed_query)
    } else if app.speed_query.is_empty() {
        " Search: press / to filter by IP, status, or protocol".to_string()
    } else {
        format!(" Search: {}  (press / to edit)", app.speed_query)
    };
    frame.render_widget(
        Paragraph::new(search_label).style(if app.speed_search_mode {
            theme::title_style()
        } else {
            theme::hint_style()
        }),
        parts[0],
    );

    let indices = app.speed_visible_indices();
    let table_inner = parts[1];
    app.speed_table_header = Some(Rect::new(
        table_inner.x,
        table_inner.y,
        table_inner.width,
        1,
    ));
    app.speed_table_col_bounds.clear();
    let widths = [5u16, 25, 7, 11, 13, 13, 8];
    let mut x = table_inner.x;
    for (column, width) in widths.into_iter().enumerate() {
        let end = if column == widths.len() - 1 {
            table_inner.right()
        } else {
            x.saturating_add(width.min(table_inner.right().saturating_sub(x)))
        };
        app.speed_table_col_bounds.push((x, end));
        x = end;
    }
    app.speed_list_inner = Some(Rect::new(
        table_inner.x,
        table_inner.y.saturating_add(1),
        table_inner.width,
        table_inner.height.saturating_sub(1),
    ));

    frame.render_widget(block, chunks[0]);

    if indices.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                if app.speed_query.is_empty() {
                    "No scanned IPs available."
                } else {
                    "No targets match the current search."
                },
                theme::warn_style(),
            )),
            Line::from(Span::styled(
                "Only READY or DEGRADED targets can be selected for testing.",
                theme::hint_style(),
            )),
        ])
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(empty, table_inner);
    } else {
        let visible = table_inner.height.saturating_sub(1) as usize;
        app.speed_cursor = app.speed_cursor.min(indices.len().saturating_sub(1));
        let max_scroll = indices.len().saturating_sub(visible);
        app.scroll = app
            .scroll
            .max(app.speed_cursor.saturating_sub(visible.saturating_sub(1)))
            .min(app.speed_cursor)
            .min(max_scroll);
        app.speed_list_start = app.scroll;
        let rows = indices
            .iter()
            .skip(app.scroll)
            .take(visible)
            .enumerate()
            .map(|(row_index, result_index)| {
                let result = &app.results[*result_index];
                let selected = app.speed_selected.contains(&result.ip);
                let focused = app.scroll + row_index == app.speed_cursor;
                let style = if focused {
                    theme::row_selected_style()
                } else if result.ok == 0 {
                    theme::bad_style()
                } else if selected {
                    Style::default().fg(theme::palette().info)
                } else if (app.scroll + row_index) % 2 == 1 {
                    theme::row_alt_style()
                } else {
                    theme::hint_style()
                };
                Row::new(vec![
                    Cell::from(if result.ok > 0 {
                        if selected {
                            "[x]"
                        } else {
                            "[ ]"
                        }
                    } else {
                        " - "
                    }),
                    Cell::from(result.ip.clone()),
                    Cell::from(result.port.to_string()),
                    Cell::from(App::speed_status(result)),
                    Cell::from(format_latency(result.ok > 0, result.avg)),
                    Cell::from(format_latency(result.ok > 0, result.p95)),
                    Cell::from(result.protocol.clone()),
                ])
                .style(style)
            });
        let sort_marker = |column| {
            if app.speed_sort_col == column {
                if app.speed_sort_asc {
                    " ↑"
                } else {
                    " ↓"
                }
            } else {
                ""
            }
        };
        let header = Row::new(vec![
            "Sel".to_string(),
            format!("IP{}", sort_marker(0)),
            "Port".to_string(),
            format!("Status{}", sort_marker(1)),
            format!("Avg{}", sort_marker(2)),
            format!("P95{}", sort_marker(3)),
            format!("Proto{}", sort_marker(4)),
        ])
        .style(theme::title_style());
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(5),
                    Constraint::Length(25),
                    Constraint::Length(7),
                    Constraint::Length(11),
                    Constraint::Length(13),
                    Constraint::Length(13),
                    Constraint::Length(8),
                ],
            )
            .header(header),
            table_inner,
        );
    }

    render_options_panel(app, frame, chunks[1]);
}

fn render_options_panel(app: &mut App, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // info
            Constraint::Length(3), // direction buttons
            Constraint::Length(3), // select all / clear
            Constraint::Length(3), // start / back
        ])
        .split(area);

    let info = vec![
        Line::from(Span::styled(" SPEED TEST SETTINGS ", theme::header_style())),
        Line::from(""),
        Line::from(vec![
            Span::styled("Selected IPs : ", theme::title_style()),
            Span::raw(format!(
                "{} / {}",
                app.speed_selected.len(),
                app.speed_targets.len()
            )),
        ]),
        Line::from(vec![
            Span::styled("Payload      : ", theme::title_style()),
            Span::raw(format!(
                "{} MB",
                app.config.speed_payload_bytes / 1024 / 1024
            )),
        ]),
        Line::from(vec![
            Span::styled("Repetitions  : ", theme::title_style()),
            Span::raw(app.config.speed_repetitions.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Concurrency  : ", theme::title_style()),
            Span::raw(format!(
                "{} (effective: {})",
                app.config.concurrency,
                app.config.concurrency.clamp(1, 4)
            )),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("GET  {}", app.config.download_path),
            theme::hint_style(),
        )),
        Line::from(Span::styled(
            format!("POST {}", app.config.upload_path),
            theme::hint_style(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(info).block(widgets::panel_block("Options", false)),
        rows[0],
    );

    // Direction toggle buttons. The chosen direction is always rendered as a
    // filled Primary button; keyboard focus (Tab) highlights exactly one button
    // at a time, so "what is selected" and "what is focused" never conflate.
    let dir_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(rows[1]);
    let dir_button =
        |app: &mut App, frame: &mut Frame, rect, label, action, selected: bool, focused: bool| {
            let kind = if selected {
                ButtonKind::Primary
            } else {
                ButtonKind::Secondary
            };
            app.button_ex(frame, rect, label, action, kind, focused);
        };
    dir_button(
        app,
        frame,
        dir_cols[0],
        "Download",
        ButtonAction::SpeedDirDownload,
        app.speed_direction == SpeedDirection::Download,
        app.focus_index == 1,
    );
    dir_button(
        app,
        frame,
        dir_cols[1],
        "Upload",
        ButtonAction::SpeedDirUpload,
        app.speed_direction == SpeedDirection::Upload,
        app.focus_index == 2,
    );
    dir_button(
        app,
        frame,
        dir_cols[2],
        "Both",
        ButtonAction::SpeedDirBoth,
        app.speed_direction == SpeedDirection::Both,
        app.focus_index == 3,
    );

    let sel_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);
    app.button(
        frame,
        sel_cols[0],
        "Select all",
        ButtonAction::SpeedAll,
        app.focus_index == 4,
    );
    app.button(
        frame,
        sel_cols[1],
        "Clear",
        ButtonAction::SpeedClear,
        app.focus_index == 5,
    );

    let act_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[3]);
    let start_kind = if app.speed_selected.is_empty() {
        ButtonKind::Secondary
    } else {
        ButtonKind::Primary
    };
    app.button_ex(
        frame,
        act_cols[0],
        "Start ⏎",
        ButtonAction::SpeedStart,
        start_kind,
        app.focus_index == 6,
    );
    app.button(
        frame,
        act_cols[1],
        "Back",
        ButtonAction::SpeedBack,
        app.focus_index == 7,
    );
}

fn render_testing(app: &App, frame: &mut Frame, area: Rect) {
    let total = app.speed_selected.len();
    let done = app.speed_results.len();
    let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);

    let block = widgets::panel_block("Measuring", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(1), // gauge
            Constraint::Length(1), // elapsed
            Constraint::Length(1), // spacer
            Constraint::Min(1),    // note
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} ", widgets::spinner_frame(app.tick)),
                theme::status_style("SCANNING"),
            ),
            Span::styled("Testing selected IPs", theme::header_style()),
        ])),
        rows[0],
    );

    let ratio = if total > 0 {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    frame.render_widget(
        Gauge::default()
            .gauge_style(theme::status_style("SCANNING"))
            .ratio(ratio)
            .label(format!("{done}/{total} ({percent}%)")),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new(format!(
            "Elapsed: {}s",
            app.speed_start_time.elapsed().as_secs()
        )),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            "Each result streams a fixed payload and reports Mbps.",
            theme::hint_style(),
        )),
        rows[4],
    );
}

fn render_results(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = widgets::panel_block("Throughput", app.focus_index == 0);
    let visible = block.inner(area).height.saturating_sub(1) as usize;
    let max_scroll = app.speed_results.len().saturating_sub(visible);
    app.speed_result_cursor = app
        .speed_result_cursor
        .min(app.speed_results.len().saturating_sub(1));
    app.scroll = app
        .scroll
        .max(
            app.speed_result_cursor
                .saturating_sub(visible.saturating_sub(1)),
        )
        .min(app.speed_result_cursor)
        .min(max_scroll);
    let header = Row::new(vec![
        Cell::from("IP"),
        Cell::from("Port"),
        Cell::from("DL med [p10-p90]"),
        Cell::from("UL med [p10-p90]"),
        Cell::from("Status"),
    ])
    .style(theme::title_style());
    let rows = app
        .speed_results
        .iter()
        .skip(app.scroll)
        .take(visible)
        .enumerate()
        .map(|(index, result)| {
            let selected = app.scroll + index == app.speed_result_cursor;
            let status = result.error.as_deref().unwrap_or("OK");
            let mut row = Row::new(vec![
                Cell::from(result.ip.clone()),
                Cell::from(result.port.to_string()),
                Cell::from(format_measurement(result.download.as_ref())),
                Cell::from(format_measurement(result.upload.as_ref())),
                Cell::from(status.to_string()).style(if result.error.is_some() {
                    theme::bad_style()
                } else {
                    theme::good_style()
                }),
            ]);
            if selected {
                row = row.style(theme::row_selected_style());
            } else if (app.scroll + index) % 2 == 1 {
                row = row.style(theme::row_alt_style());
            }
            row
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(25),
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(block);
    frame.render_widget(table, area);
}

fn format_measurement(value: Option<&crate::speed::SpeedMeasurement>) -> String {
    value
        .map(|measurement| {
            let compact = |bytes_per_second: f64| {
                let mbps = bytes_per_second * 8.0 / 1_000_000.0;
                if mbps >= 1000.0 {
                    format!("{:.1}k", mbps / 1000.0)
                } else if mbps >= 100.0 {
                    format!("{:.0}", mbps)
                } else if mbps >= 10.0 {
                    format!("{:.1}", mbps)
                } else {
                    format!("{:.2}", mbps)
                }
            };
            format!(
                "{} ({}-{})",
                compact(measurement.median_bytes_per_second),
                compact(measurement.p10_bytes_per_second),
                compact(measurement.p90_bytes_per_second)
            )
        })
        .unwrap_or_else(|| "—".to_string())
}

fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let hints: &[widgets::KeyHint] = match app.screen {
        Screen::SpeedSelect => &[
            ("s", "reverse sort"),
            ("Tab", "focus"),
            ("Space", "select"),
            (widgets::enter_key(), "start"),
            ("/", "commands"),
            ("?", "help"),
            ("Esc", "back"),
        ],
        Screen::SpeedTesting => &[("Esc", "cancel"), ("q", "quit")],
        Screen::SpeedResults => &[
            ("Tab", "focus"),
            ("c", "copy"),
            ("Esc", "back"),
            ("/", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ],
        _ => &[],
    };
    widgets::status_bar(frame, area, hints, app.visible_message());
}

fn format_latency(successful: bool, seconds: f64) -> String {
    if successful {
        format!("{:.1} ms", seconds * 1000.0)
    } else {
        "—".to_string()
    }
}
