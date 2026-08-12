//! TLS fragment tester screens: profile selection, live progress, and a
//! per-profile results table. Probes follow xray's `freedom` fragment model —
//! each profile is a full xray `fragment` spec, and a "working" result means
//! TCP + TLS handshake + a 2xx HTTP response all succeeded.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Gauge, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::proxy::TLS_FRAGMENT_PRESETS;
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
        Screen::FragmentSelect => render_select(app, frame, chunks[1]),
        Screen::FragmentTesting => render_testing(app, frame, chunks[1]),
        Screen::FragmentResults => render_results(app, frame, chunks[1]),
        _ => {}
    }
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let title = match app.screen {
        Screen::FragmentSelect => "TLS FRAGMENT TESTER",
        Screen::FragmentTesting => "TESTING TLS FRAGMENTS",
        Screen::FragmentResults => "TLS FRAGMENT RESULTS",
        _ => "TLS FRAGMENT TESTER",
    };
    widgets::app_header(
        frame,
        area,
        Some((title, theme::highlight_style())),
        &[
            widgets::HeaderSegment::new("Host", app.config.host.clone()),
            widgets::HeaderSegment::new("IP", app.system_network.public_ip_display()),
            widgets::HeaderSegment::new("ASN", app.system_network.asn_display()),
            widgets::HeaderSegment::new("ISP", app.system_network.isp_display()),
        ],
    );
}

fn render_select(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);

    let block = widgets::panel_block(
        "Profiles (Enter IP, Space toggle, Enter toggles profile)",
        app.focus_index == 0,
    );
    let inner = block.inner(chunks[0]);
    frame.render_widget(block, chunks[0]);

    let visible = inner.height.saturating_sub(1) as usize;
    let total = TLS_FRAGMENT_PRESETS.len() + 1;
    let max_scroll = total.saturating_sub(visible);
    app.fragment_cursor = app.fragment_cursor.min(total.saturating_sub(1));
    app.scroll = app
        .scroll
        .max(
            app.fragment_cursor
                .saturating_sub(visible.saturating_sub(1)),
        )
        .min(app.fragment_cursor)
        .min(max_scroll);

    let mut rows: Vec<Line> = Vec::new();
    // Row 0: the target IP (edit with Enter while focused).
    let ip_value = if app.fragment_ip_editing {
        let (before, after) = app
            .edit_buffer
            .split_at(app.edit_caret.min(app.edit_buffer.len()));
        format!("{before}{after}_")
    } else if app.fragment_ip.is_empty() {
        "<empty — Enter to type an IP>".to_string()
    } else {
        app.fragment_ip.clone()
    };
    rows.push(Line::from(vec![
        Span::styled(
            if app.fragment_cursor == 0 {
                widgets::focus_marker()
            } else {
                " "
            },
            theme::row_selected_style(),
        ),
        Span::styled("Target IP", theme::title_style()),
        Span::raw(" = "),
        Span::styled(
            ip_value,
            if app.fragment_cursor == 0 || app.fragment_ip_editing {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
    ]));

    // Rows 1..: fragment profiles with enable toggles.
    for (index, (label, spec)) in TLS_FRAGMENT_PRESETS.iter().enumerate() {
        let row_index = index + 1;
        let enabled = app.fragment_enabled.get(index).copied().unwrap_or(true);
        let selected_row = app.fragment_cursor == row_index;
        let style = if selected_row {
            theme::row_selected_style()
        } else if (row_index % 2) == 0 {
            theme::row_alt_style()
        } else {
            Style::default().fg(theme::palette().subtitle)
        };
        let spec_text = match spec {
            Some(spec) => spec.xray_json(),
            None => "unfragmented control".to_string(),
        };
        rows.push(Line::from(vec![
            Span::styled(
                if selected_row {
                    widgets::focus_marker()
                } else {
                    " "
                },
                style,
            ),
            Span::styled(
                if enabled {
                    widgets::checkbox_checked_symbol()
                } else {
                    widgets::checkbox_unchecked_symbol()
                },
                style,
            ),
            Span::styled(format!(" {label:<24} "), style),
            Span::styled(spec_text, theme::hint_style()),
        ]));
    }

    // Scroll window into the visible area.
    let row_lines: Vec<Line> = rows
        .iter()
        .skip(app.scroll)
        .take(visible)
        .cloned()
        .collect();
    frame.render_widget(
        Paragraph::new(row_lines).wrap(Wrap { trim: false }),
        Rect {
            x: inner.x,
            y: inner.y.saturating_add(1),
            width: inner.width,
            height: inner.height.saturating_sub(1),
        },
    );

    render_select_panel(app, frame, chunks[1]);
    render_select_buttons(app, frame, area);
}

fn render_select_panel(app: &App, frame: &mut Frame, area: Rect) {
    let selected = app
        .fragment_enabled
        .iter()
        .filter(|enabled| **enabled)
        .count();
    let port = app.fragment_port;
    let info = vec![
        Line::from(Span::styled(" TARGET & PROBES ", theme::header_style())),
        Line::from(""),
        Line::from(vec![
            Span::styled("SNI / Host: ", theme::title_style()),
            Span::raw(if app.config.host.is_empty() {
                "<set in wizard>".to_string()
            } else {
                app.config.host.clone()
            }),
        ]),
        Line::from(vec![
            Span::styled("Port       : ", theme::title_style()),
            Span::raw(port.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Path       : ", theme::title_style()),
            Span::raw(app.config.path.clone()),
        ]),
        Line::from(vec![
            Span::styled("Timeout    : ", theme::title_style()),
            Span::raw(format!("{} ms", app.config.timeout_ms)),
        ]),
        Line::from(vec![
            Span::styled("Profiles   : ", theme::title_style()),
            Span::raw(format!(
                "{selected} / {} enabled",
                TLS_FRAGMENT_PRESETS.len()
            )),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Each profile performs a full TCP connect, a TLS handshake with the SNI above, and a GET request. A profile 'works' only when all three succeed — fragmenting the ClientHello past the DPI but leaving a dead edge is not enough.",
            theme::hint_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Profiles are xray freedom `fragment` settings; the winning profile is copied as ready-to-paste JSON.",
            theme::hint_style(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(info).block(widgets::subtle_panel_block("Context")),
        area,
    );
}

fn render_select_buttons(app: &mut App, frame: &mut Frame, body: Rect) {
    let buttons = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(Rect {
            x: body.x,
            y: body.y.saturating_add(body.height.saturating_sub(3)),
            width: body.width,
            height: 3,
        });
    let can_start = !app.fragment_ip.is_empty() && !app.config.host.is_empty();
    let start_kind = if can_start {
        ButtonKind::Primary
    } else {
        ButtonKind::Secondary
    };
    app.button_ex(
        frame,
        buttons[0],
        "Start ⏎",
        ButtonAction::FragmentStart,
        start_kind,
        app.focus_index == 1,
    );
    app.button(
        frame,
        buttons[1],
        "Back",
        ButtonAction::FragmentBack,
        app.focus_index == 2,
    );
}

fn render_testing(app: &App, frame: &mut Frame, area: Rect) {
    let total = app
        .fragment_enabled
        .iter()
        .filter(|enabled| **enabled)
        .count();
    let done = app.fragment_results.len();
    let percent = done
        .saturating_mul(100)
        .checked_div(total.max(1))
        .unwrap_or(0);

    let block = widgets::panel_block("Probing", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} ", widgets::spinner_frame(app.tick)),
                theme::status_style("SCANNING"),
            ),
            Span::styled("Testing fragment profiles", theme::header_style()),
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
            app.fragment_start_time.elapsed().as_secs()
        )),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            "Each profile opens a fresh TCP+TLS connection and issues an HTTP request.",
            theme::hint_style(),
        )),
        rows[3],
    );
}

fn render_results(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = widgets::panel_block(
        "Fragment profiles — working results are green",
        app.focus_index == 0,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Summary line: the first profile that fully worked.
    let first_working = app
        .fragment_results
        .iter()
        .find(|result| result.works())
        .map(|result| result.name)
        .unwrap_or("none");
    let summary_style = if first_working == "none" {
        theme::bad_style()
    } else {
        theme::good_style()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("First working profile: ", theme::title_style()),
            Span::styled(first_working, summary_style),
            Span::styled("   (c = copy its xray JSON)", theme::hint_style()),
        ])),
        Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: 1,
        },
    );

    let visible = inner.height.saturating_sub(2) as usize;
    let max_scroll = app.fragment_results.len().saturating_sub(visible);
    app.fragment_result_cursor = app
        .fragment_result_cursor
        .min(app.fragment_results.len().saturating_sub(1));
    app.scroll = app
        .scroll
        .max(
            app.fragment_result_cursor
                .saturating_sub(visible.saturating_sub(1)),
        )
        .min(app.fragment_result_cursor)
        .min(max_scroll);

    let header = Row::new(vec![
        Cell::from("Profile"),
        Cell::from("Spec (xray JSON)"),
        Cell::from("TCP"),
        Cell::from("TLS"),
        Cell::from("HTTP"),
        Cell::from("Colo"),
        Cell::from("ms"),
        Cell::from("Error"),
    ])
    .style(theme::title_style());

    let rows = app
        .fragment_results
        .iter()
        .skip(app.scroll)
        .take(visible)
        .enumerate()
        .map(|(index, result)| {
            let selected = app.scroll + index == app.fragment_result_cursor;
            let mut row = Row::new(vec![
                Cell::from(result.name),
                Cell::from(result.spec.as_deref().unwrap_or("off")),
                Cell::from(if result.tcp_ok { "yes" } else { "no" }),
                Cell::from(if result.tls_ok { "yes" } else { "no" }),
                Cell::from(match result.http_ok {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "-",
                }),
                Cell::from(result.colo.as_deref().unwrap_or("-")),
                Cell::from(format!("{:.0}", result.elapsed_ms)),
                Cell::from(result.error.as_deref().unwrap_or("")),
            ]);
            if selected {
                row = row.style(theme::row_selected_style());
            } else if (app.scroll + index) % 2 == 1 {
                row = row.style(theme::row_alt_style());
            }
            if result.works() {
                row = row.style(theme::good_style());
            } else if result.error.is_some() {
                row = row.style(theme::bad_style());
            }
            row
        });

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(34),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header);
    frame.render_widget(
        table,
        Rect {
            x: inner.x,
            y: inner.y.saturating_add(1),
            width: inner.width,
            height: inner.height.saturating_sub(1),
        },
    );

    render_results_buttons(app, frame, area);
}

fn render_results_buttons(app: &mut App, frame: &mut Frame, body: Rect) {
    let buttons = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(Rect {
            x: body.x,
            y: body.y.saturating_add(body.height.saturating_sub(3)),
            width: body.width,
            height: 3,
        });
    app.button(
        frame,
        buttons[0],
        "Copy JSON (c)",
        ButtonAction::FragmentCopy,
        app.focus_index == 1,
    );
    app.button(
        frame,
        buttons[1],
        "Back (Esc)",
        ButtonAction::FragmentBack,
        app.focus_index == 2,
    );
}

fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let hints: &[widgets::KeyHint] = match app.screen {
        Screen::FragmentSelect => &[
            ("↑ / ↓", "move"),
            ("Space", "toggle profile"),
            (widgets::enter_key(), "edit IP / start"),
            ("Tab", "focus"),
            ("?", "help"),
            ("Esc", "back"),
            ("q", "quit"),
        ],
        Screen::FragmentTesting => &[("Esc", "cancel"), ("q", "quit")],
        Screen::FragmentResults => &[
            ("↑ / ↓", "move"),
            ("c", "copy JSON"),
            ("Tab", "focus"),
            ("Esc", "back"),
            ("q", "quit"),
        ],
        _ => &[],
    };
    widgets::status_bar(frame, area, hints, app.visible_message());
}
