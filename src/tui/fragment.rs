//! TLS fragment tester screens: profile selection, live progress, and a
//! per-profile results table. Probes follow xray's `freedom` fragment model —
//! each profile is a full xray `fragment` spec, and a "working" result means
//! TCP + TLS handshake + a 2xx HTTP response all succeeded.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
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

/// Header for the fragment tester screens with the current stage title and
/// the required host, falling back to a warning when the host is unset.
fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let title = match app.screen {
        Screen::FragmentSelect => "TLS FRAGMENT TESTER",
        Screen::FragmentTesting => "TESTING TLS FRAGMENTS",
        Screen::FragmentResults => "TLS FRAGMENT RESULTS",
        _ => "TLS FRAGMENT TESTER",
    };
    let host_segment = if app.config.host.is_empty() {
        widgets::HeaderSegment {
            label: "Host".to_string(),
            value: "— REQUIRED".to_string(),
            style: theme::warn_style().add_modifier(Modifier::BOLD),
        }
    } else {
        widgets::HeaderSegment::new("Host", app.config.host.clone())
    };
    widgets::app_header(
        frame,
        area,
        Some((title, theme::highlight_style())),
        &[
            host_segment,
            widgets::HeaderSegment::new("IP", app.system_network.public_ip_display()),
            widgets::HeaderSegment::new("ASN", app.system_network.asn_display()),
            widgets::HeaderSegment::new("ISP", app.system_network.isp_display()),
        ],
    );
}

/// Profile selection screen: the editable target IP, the toggleable preset
/// list plus custom-JSON row, the context panel, and start/back buttons.
/// Physical height of a wrapped row at `width` columns (minimum 1). Uses
/// `Paragraph`'s own wrapping so the estimate matches what the selector
/// actually renders (word boundaries can make lines shorter than a plain
/// character-ceiling estimate).
fn wrapped_row_height(row: &Line, width: u16) -> usize {
    Paragraph::new(row.clone())
        .wrap(Wrap { trim: false })
        .line_count(width.max(1))
        .max(1)
}

/// Line offset where row `row_index` starts (sum of heights of all rows
/// before it), clamped to the last row when out of range.
fn cursor_line_offset(heights: &[usize], row_index: usize) -> usize {
    heights.iter().take(row_index.min(heights.len())).sum()
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

    // Effective visible window: the Paragraph is `inner.height - 1` lines
    // tall (one line of offset), but the Start/Back buttons are drawn over
    // the bottom two interior lines of the panel, so only that many minus
    // two lines can actually be seen by the user.
    let visible = inner.height.saturating_sub(3) as usize;
    // +1 for the IP row, +1 for the custom-JSON row.
    let total = TLS_FRAGMENT_PRESETS.len() + 2;
    app.fragment_cursor = app.fragment_cursor.min(total.saturating_sub(1));

    let mut rows: Vec<Line> = Vec::new();
    // Row 0: the target IP (edit with Enter while focused).
    let ip_value = if app.fragment_ip_editing {
        let (before, after) = app
            .edit_buffer
            .split_at(app.edit_caret.min(app.edit_buffer.len()));
        format!("{before}_{after}")
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
        } else if row_index.is_multiple_of(2) {
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

    // Last row: custom JSON entry (PattNG FinalMaskField analog).
    {
        let row_index = TLS_FRAGMENT_PRESETS.len() + 1;
        let enabled = app.fragment_custom_enabled;
        let selected_row = app.fragment_cursor == row_index;
        let style = if selected_row {
            theme::row_selected_style()
        } else if row_index.is_multiple_of(2) {
            theme::row_alt_style()
        } else {
            Style::default().fg(theme::palette().subtitle)
        };
        let spec_text = if app.fragment_custom_editing {
            let (before, after) = app
                .edit_buffer
                .split_at(app.edit_caret.min(app.edit_buffer.len()));
            format!("{before}_{after}")
        } else if app.fragment_custom_json.is_empty() {
            "<empty — Enter to paste JSON>".to_string()
        } else {
            app.fragment_custom_json.clone()
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
            Span::styled(" Custom (paste JSON) ", style),
            Span::styled(spec_text, theme::hint_style()),
        ]));
    }

    // Scroll window by physical lines so wrapped rows (whose JSON wraps to
    // multiple lines at narrow widths) don't push the cursor off screen.
    let heights: Vec<usize> = rows
        .iter()
        .map(|row| wrapped_row_height(row, inner.width))
        .collect();
    let total_lines: usize = heights.iter().sum();
    let max_scroll = total_lines.saturating_sub(visible);
    let cursor_start = cursor_line_offset(&heights, app.fragment_cursor);
    let cursor_height = heights
        .get(app.fragment_cursor)
        .copied()
        .unwrap_or(1)
        .max(1);
    let custom_row = TLS_FRAGMENT_PRESETS.len() + 1;
    let editing_cursor = (app.fragment_cursor == 0 && app.fragment_ip_editing)
        || (app.fragment_cursor == custom_row && app.fragment_custom_editing);
    let mut scroll = app.scroll.min(max_scroll);
    if cursor_height > visible {
        // The cursor row is taller than the viewport, so the whole row
        // cannot fit. Showing its end would drop the selection marker and
        // a caret near the start. Instead show the row start when browsing,
        // or the caret when editing (keeping the start too when the caret
        // is near it, so marker and caret stay together).
        if visible == 0 {
            scroll = cursor_start;
        } else if editing_cursor {
            // Prefix widths mirror the row spans above: marker + label
            // (IP row) or marker + checkbox + label (custom row).
            let prefix_width = if app.fragment_cursor == 0 { 13 } else { 25 };
            let (before, _) = app
                .edit_buffer
                .split_at(app.edit_caret.min(app.edit_buffer.len()));
            let width = usize::from(inner.width.max(1));
            let caret_column = prefix_width + before.chars().count();
            let caret_line = cursor_start + caret_column / width.max(1);
            if caret_line < scroll || caret_line >= scroll + visible {
                if caret_line < cursor_start + visible {
                    scroll = cursor_start;
                } else {
                    scroll = caret_line + 1 - visible;
                }
            }
        } else if cursor_start < scroll || cursor_start >= scroll + visible {
            scroll = cursor_start;
        }
    } else {
        // Keep the whole cursor row inside the visible window: scroll down
        // until its last line fits, or up to its first line when above.
        if cursor_start < scroll {
            scroll = cursor_start;
        }
        if cursor_start + cursor_height > scroll + visible {
            scroll = cursor_start + cursor_height - visible;
        }
    }
    app.scroll = scroll.min(max_scroll);
    // Pass every row to Paragraph and scroll by physical lines so partially
    // visible rows keep their place instead of restarting from line one.
    let row_lines = rows;
    frame.render_widget(
        Paragraph::new(row_lines)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll as u16, 0)),
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

/// Side context panel for profile selection: target host/port/path/timeout,
/// the enabled-profile count, and how a profile is judged working.
fn render_select_panel(app: &App, frame: &mut Frame, area: Rect) {
    let selected = app
        .fragment_enabled
        .iter()
        .filter(|enabled| **enabled)
        .count()
        + usize::from(app.fragment_custom_enabled);
    let total = TLS_FRAGMENT_PRESETS.len() + 1;
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
            Span::raw(format!("{selected} / {total} enabled")),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Each profile is probed three times (10-60 ms apart). A profile 'works' when a majority of attempts pass TCP + TLS + an HTTP 2xx response and the connection survives the idle hold — fragmenting the ClientHello past the DPI but leaving a dead edge is not enough.",
            theme::hint_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Profiles are xray freedom `fragment` settings; the winning profile is copied as ready-to-paste JSON.",
            theme::hint_style(),
        )),
        Line::from(Span::styled(
            " Note: the 0/104/1 PattNG recipe re-wraps the ClientHello with a zero-length TLS record, which only Cloudflare-style edges tolerate.",
            theme::hint_style(),
        )),
        Line::from(Span::styled(
            " Tip: press g on the results page to auto-test every profile on the selected IP.",
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

/// Live progress view while profiles are being probed: spinner, gauge,
/// elapsed time, and the majority-of-three verdicts note.
fn render_testing(app: &App, frame: &mut Frame, area: Rect) {
    let total = app
        .fragment_enabled
        .iter()
        .filter(|enabled| **enabled)
        .count()
        + usize::from(app.fragment_custom_enabled);
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
            "Each profile is probed three times; verdicts are majority-of-attempts.",
            theme::hint_style(),
        )),
        rows[3],
    );
}

/// Results table highlighting the working profiles, with the first working
/// recipe surfaced in the summary line for one-key copying.
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
        Cell::from("Stable"),
        Cell::from("Pass"),
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
            let row = Row::new(vec![
                Cell::from(result.name),
                Cell::from(result.spec.as_deref().unwrap_or("off")),
                Cell::from(if result.tcp_ok { "yes" } else { "no" }),
                Cell::from(if result.tls_ok { "yes" } else { "no" }),
                Cell::from(match result.http_ok {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "-",
                }),
                Cell::from(if result.long_tls_ok { "yes" } else { "no" }),
                Cell::from(if result.attempts == 0 {
                    "-".to_string()
                } else {
                    format!("{}/{}", result.passed, result.attempts)
                }),
                Cell::from(result.colo.as_deref().unwrap_or("-")),
                Cell::from(format!("{:.0}", result.elapsed_ms)),
                Cell::from(result.error.as_deref().unwrap_or("")),
            ]);
            let mut style = Style::default();
            if selected {
                style = style.patch(theme::row_selected_style());
            } else if (app.scroll + index) % 2 == 1 {
                style = style.patch(theme::row_alt_style());
            }
            if result.works() {
                style = style.patch(theme::good_style());
            } else if result.error.is_some() {
                style = style.patch(theme::bad_style());
            }
            row.style(style)
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
