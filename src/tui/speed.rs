use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::speed::SpeedDirection;
use crate::tui::{theme, widgets, App, ButtonAction, ButtonKind, Screen};

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
    let title = match app.screen {
        Screen::SpeedSelect => "SELECT SPEED TEST TARGETS",
        Screen::SpeedTesting => "RUNNING SPEED TESTS",
        Screen::SpeedResults => "SPEED TEST RESULTS",
        _ => "SPEED TEST",
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
    let block = widgets::panel_block("Successful IPs — click or Space to select", true);
    let inner = block.inner(chunks[0]);
    app.speed_list_inner = Some(inner);

    if app.speed_targets.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "No successful IPs to test.",
                theme::warn_style(),
            )),
            Line::from(Span::styled(
                "Run a scan first, then pick the fastest edges here.",
                theme::hint_style(),
            )),
        ])
        .alignment(ratatui::layout::Alignment::Center)
        .block(block);
        frame.render_widget(empty, chunks[0]);
    } else {
        let visible = inner.height as usize;
        let start = app.speed_cursor.saturating_sub(visible.saturating_sub(1));
        app.speed_list_start = start;
        let rows = app
            .speed_targets
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, ip)| {
                let selected = app.speed_selected.contains(ip);
                let style = if index == app.speed_cursor {
                    theme::row_selected_style()
                } else if selected {
                    Style::default().fg(theme::palette().info)
                } else {
                    theme::hint_style()
                };
                Row::new(vec![
                    Cell::from(if selected { "[x]" } else { "[ ]" }),
                    Cell::from(ip.clone()),
                ])
                .style(style)
            });
        frame.render_widget(
            Table::new(rows, [Constraint::Length(5), Constraint::Min(1)]).block(block),
            chunks[0],
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

    // Direction toggle buttons (the active direction is rendered as primary).
    let dir_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(rows[1]);
    let dir_button = |app: &mut App, frame: &mut Frame, rect, label, action, active: bool| {
        let kind = if active {
            ButtonKind::Primary
        } else {
            ButtonKind::Secondary
        };
        app.button_ex(frame, rect, label, action, kind, active);
    };
    dir_button(
        app,
        frame,
        dir_cols[0],
        "Down (d)",
        ButtonAction::SpeedDirDownload,
        app.speed_direction == SpeedDirection::Download,
    );
    dir_button(
        app,
        frame,
        dir_cols[1],
        "Up (u)",
        ButtonAction::SpeedDirUpload,
        app.speed_direction == SpeedDirection::Upload,
    );
    dir_button(
        app,
        frame,
        dir_cols[2],
        "Both (b)",
        ButtonAction::SpeedDirBoth,
        app.speed_direction == SpeedDirection::Both,
    );

    let sel_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);
    app.button(frame, sel_cols[0], "All (a)", ButtonAction::SpeedAll, false);
    app.button(
        frame,
        sel_cols[1],
        "Clear (N)",
        ButtonAction::SpeedClear,
        false,
    );

    let act_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[3]);
    app.button_ex(
        frame,
        act_cols[0],
        "Start ⏎",
        ButtonAction::SpeedStart,
        ButtonKind::Primary,
        !app.speed_selected.is_empty(),
    );
    app.button(
        frame,
        act_cols[1],
        "Back (Esc)",
        ButtonAction::SpeedBack,
        false,
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
    let block = widgets::panel_block("Throughput", true);
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
        Cell::from("Download"),
        Cell::from("Upload"),
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
            format!(
                "{:.2} Mbps",
                measurement.bytes_per_second * 8.0 / 1_000_000.0
            )
        })
        .unwrap_or_else(|| "—".to_string())
}

fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let text = match app.screen {
        Screen::SpeedSelect => {
            "↑/↓ move • Space select • a all • N clear • d/u/b direction • Enter start • Esc back"
        }
        Screen::SpeedTesting => "Speed test running • q quit",
        Screen::SpeedResults => "↑/↓ select • c copy IP • Esc/B back to latency results • q quit",
        _ => "",
    };
    widgets::status_bar(frame, area, text, app.visible_message());
}
