use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::speed::SpeedDirection;
use crate::tui::{theme, App, Screen};

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
    let line = Line::from(vec![
        Span::styled(
            format!(" CLEANSCAN v{} ", env!("CARGO_PKG_VERSION")),
            theme::header_style(),
        ),
        Span::styled(format!("│ {title} "), theme::highlight_style()),
        Span::raw(format!("│ Host: {}", app.config.host)),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style()),
        ),
        area,
    );
}

fn render_selection(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_active_style())
        .title(" Successful IPs — Space select ");
    let inner = block.inner(chunks[0]);
    let visible = inner.height as usize;
    let start = app.speed_cursor.saturating_sub(visible.saturating_sub(1));
    let rows = app
        .speed_targets
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, ip)| {
            let selected = app.speed_selected.contains(ip);
            let style = if index == app.speed_cursor {
                theme::highlight_style()
            } else if selected {
                Style::default().fg(Color::LightCyan)
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

    let direction = match app.speed_direction {
        SpeedDirection::Download => "Download only",
        SpeedDirection::Upload => "Upload only",
        SpeedDirection::Both => "Download + upload",
    };
    let info = vec![
        Line::from(Span::styled(" SPEED TEST SETTINGS ", theme::header_style())),
        Line::from(""),
        Line::from(format!("Selected IPs : {}", app.speed_selected.len())),
        Line::from(format!("Direction    : {direction}")),
        Line::from(format!(
            "Payload      : {} MB",
            app.config.speed_payload_bytes / 1024 / 1024
        )),
        Line::from(format!("Repetitions  : {}", app.config.speed_repetitions)),
        Line::from(""),
        Line::from(format!("GET  {}", app.config.download_path)),
        Line::from(format!("POST {}", app.config.upload_path)),
        Line::from(""),
        Line::from(Span::styled(
            "n download  u upload  b both",
            theme::hint_style(),
        )),
        Line::from(Span::styled(
            "A all  D none  Enter start  Esc back",
            theme::hint_style(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(info).block(Block::default().borders(Borders::ALL).title(" Options ")),
        chunks[1],
    );
}

fn render_testing(app: &App, frame: &mut Frame, area: Rect) {
    let total = app.speed_selected.len();
    let done = app.speed_results.len();
    let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);
    let lines = vec![
        Line::from(Span::styled("Testing selected IPs", theme::header_style())),
        Line::from(format!("Progress: {done}/{total} ({percent}%)")),
        Line::from(format!(
            "Elapsed: {}s",
            app.speed_start_time.elapsed().as_secs()
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Each result streams a fixed payload and reports Mbps.",
            theme::hint_style(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Measuring ")),
        area,
    );
}

fn render_results(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Throughput ");
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
                row = row.style(theme::highlight_style());
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
        Screen::SpeedSelect => "↑/↓ move • Space select • Enter start • Esc back • q quit",
        Screen::SpeedTesting => "Speed test running • q quit",
        Screen::SpeedResults => "↑/↓ select • c copy IP • Esc/B back to latency results • q quit",
        _ => "",
    };
    frame.render_widget(Paragraph::new(text).style(theme::hint_style()), area);
}
